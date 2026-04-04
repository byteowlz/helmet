use std::env;
use std::io::{self, BufRead, BufWriter, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use env_logger::fmt::WriteStyle;
use log::{LevelFilter, debug, info};

use helmet_core::paths::write_default_config;
use helmet_core::threats::Decision;
use helmet_core::{AppConfig, AppPaths, Guard, default_cache_dir, default_parallelism};

const APP_NAME: &str = env!("CARGO_PKG_NAME");

fn main() {
    if let Err(err) = try_main() {
        let _ = writeln!(io::stderr(), "{err:?}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();

    let mut ctx = RuntimeContext::new(cli.common.clone())?;
    ctx.init_logging()?;
    debug!("resolved paths: {:#?}", ctx.paths);

    match cli.command {
        Command::Scan(cmd) => handle_scan(&ctx, cmd),
        Command::Eval(cmd) => handle_eval(&ctx, cmd),
        Command::Run(cmd) => handle_run(&mut ctx, cmd),
        Command::Init(cmd) => handle_init(&ctx, cmd),
        Command::Config { command } => handle_config(&ctx, command),
        Command::Completions { shell } => handle_completions(shell),
    }
}

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Fast prompt injection detection CLI.",
    propagate_version = true
)]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Args)]
pub struct CommonOpts {
    /// Override the config file path
    #[arg(long, value_name = "PATH", global = true)]
    pub config: Option<PathBuf>,
    /// Reduce output to only errors
    #[arg(short, long, action = clap::ArgAction::SetTrue, global = true)]
    pub quiet: bool,
    /// Increase logging verbosity (stackable)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Enable debug logging (equivalent to -vv)
    #[arg(long, global = true)]
    pub debug: bool,
    /// Enable trace logging (overrides other levels)
    #[arg(long, global = true)]
    pub trace: bool,
    /// Output machine readable JSON
    #[arg(long, global = true, conflicts_with = "yaml")]
    pub json: bool,
    /// Output machine readable YAML
    #[arg(long, global = true)]
    pub yaml: bool,
    /// Disable ANSI colors in output
    #[arg(long = "no-color", global = true, conflicts_with = "color")]
    pub no_color: bool,
    /// Control color output (auto, always, never)
    #[arg(long, value_enum, default_value_t = ColorOption::Auto, global = true)]
    pub color: ColorOption,
    /// Do not change anything on disk
    #[arg(long = "dry-run", global = true)]
    pub dry_run: bool,
    /// Assume "yes" for interactive prompts
    #[arg(short = 'y', long = "yes", alias = "force", global = true)]
    pub assume_yes: bool,
    /// Never prompt for input; fail if confirmation would be required
    #[arg(long = "no-input", global = true)]
    pub no_input: bool,
    /// Maximum seconds to allow an operation to run
    #[arg(long = "timeout", value_name = "SECONDS", global = true)]
    pub timeout: Option<u64>,
    /// Override the degree of parallelism
    #[arg(long = "parallel", value_name = "N", global = true)]
    pub parallel: Option<usize>,
    /// Disable progress indicators
    #[arg(long = "no-progress", global = true)]
    pub no_progress: bool,
    /// Emit additional diagnostics for troubleshooting
    #[arg(long = "diagnostics", global = true)]
    pub diagnostics: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ColorOption {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan input for prompt injection. Reads stdin line-by-line or a single argument.
    Scan(ScanCommand),
    /// Evaluate a JSONL dataset and report detection metrics.
    Eval(EvalCommand),
    /// Execute the CLI's primary behavior
    Run(RunCommand),
    /// Create config directories and default files
    Init(InitCommand),
    /// Inspect and manage configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Generate shell completions
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

// ============================================================================
// Scan command
// ============================================================================

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PolicyPreset {
    /// Log only, pass everything through
    Monitor,
    /// Default: reject blocks, pass reviews
    Default,
    /// Reject blocks, redact reviews
    Strict,
    /// Reject everything that isn't clearly safe
    Paranoid,
    /// Strip attack patterns, pass cleaned text
    Sanitize,
}

#[derive(Debug, Clone, Args)]
struct ScanCommand {
    /// Text to scan (omit to read from stdin, one line per check)
    #[arg(value_name = "TEXT")]
    text: Option<String>,

    /// Read input from a file instead of stdin
    #[arg(short = 'f', long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Policy preset: monitor, default, strict, paranoid, sanitize
    #[arg(short = 'p', long, value_enum, default_value_t = PolicyPreset::Default)]
    policy: PolicyPreset,

    /// Only show blocked/review items (suppress ALLOW)
    #[arg(long)]
    threats_only: bool,

    /// Show score threshold used for decisions
    #[arg(long)]
    show_thresholds: bool,

    /// Output the policy result (action + output text) instead of the raw report
    #[arg(long)]
    apply: bool,
}

/// Compact scan result for streaming output
#[derive(serde::Serialize)]
struct ScanResult<'a> {
    decision: &'a str,
    score: f32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    patterns: Vec<&'a str>,
    latency_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a str>,
}

/// Compact policy result for streaming output
#[derive(serde::Serialize)]
struct PolicyStreamResult<'a> {
    action: &'a str,
    decision: &'a str,
    score: f32,
    output: &'a str,
    latency_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a str>,
}

fn resolve_policy(
    preset: PolicyPreset,
    base: &helmet_core::PolicyConfig,
) -> helmet_core::PolicyConfig {
    let mut policy = base.clone();
    match preset {
        PolicyPreset::Monitor => {
            policy.on_block = helmet_core::Action::Passthrough;
            policy.on_review = helmet_core::Action::Passthrough;
            policy.on_allow = helmet_core::Action::Passthrough;
            policy.log_all = true;
        }
        PolicyPreset::Default => {
            policy.on_block = helmet_core::Action::Reject;
            policy.on_review = helmet_core::Action::Passthrough;
            policy.on_allow = helmet_core::Action::Passthrough;
        }
        PolicyPreset::Strict => {
            policy.on_block = helmet_core::Action::Reject;
            policy.on_review = helmet_core::Action::Redact;
            policy.on_allow = helmet_core::Action::Passthrough;
        }
        PolicyPreset::Paranoid => {
            policy.on_block = helmet_core::Action::Reject;
            policy.on_review = helmet_core::Action::Reject;
            policy.on_allow = helmet_core::Action::Passthrough;
        }
        PolicyPreset::Sanitize => {
            policy.on_block = helmet_core::Action::Sanitize;
            policy.on_review = helmet_core::Action::Sanitize;
            policy.on_allow = helmet_core::Action::Passthrough;
        }
    }
    policy
}

fn handle_scan(ctx: &RuntimeContext, cmd: ScanCommand) -> Result<()> {
    let policy_config = resolve_policy(cmd.policy, &ctx.config.guard.policy);
    let guard = Guard::with_config_and_policy(ctx.config.guard.clone(), policy_config)
        .context("creating guard from config")?;

    // Single input mode - with policy applied if --apply
    if let Some(ref text) = cmd.text {
        if cmd.apply {
            let result = guard.check_and_apply(text);
            return print_policy_result(ctx, &result);
        }
        let report = guard.check(text);
        return print_scan_result(ctx, &report, Some(text), &cmd);
    }

    // File mode
    if let Some(ref path) = cmd.file {
        let file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let reader = io::BufReader::new(file);
        return stream_scan(ctx, &guard, reader, &cmd);
    }

    // Stdin streaming mode
    if io::stdin().is_terminal() {
        eprintln!("Reading from stdin (type input, one line per scan, Ctrl-D to end)");
    }
    let reader = io::BufReader::new(io::stdin().lock());
    stream_scan(ctx, &guard, reader, &cmd)
}

fn stream_scan<R: BufRead>(
    ctx: &RuntimeContext,
    guard: &Guard,
    reader: R,
    cmd: &ScanCommand,
) -> Result<()> {
    // Use BufWriter for low-latency line-buffered output
    let stdout = io::stdout().lock();
    let mut writer = BufWriter::with_capacity(8192, stdout);

    if cmd.show_thresholds {
        let _ = writeln!(
            writer,
            "# thresholds: block >= {:.2}, review >= {:.2}",
            ctx.config.guard.block_threshold, ctx.config.guard.review_threshold,
        );
    }

    let mut line_count: u64 = 0;
    let mut block_count: u64 = 0;
    let mut review_count: u64 = 0;
    let mut allow_count: u64 = 0;
    let total_start = Instant::now();

    for line_result in reader.lines() {
        let line = line_result.context("reading input line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let report = guard.check(trimmed);
        line_count += 1;

        match report.decision {
            Decision::Block => block_count += 1,
            Decision::Review => review_count += 1,
            Decision::Allow => allow_count += 1,
        }

        if cmd.threats_only && report.decision == Decision::Allow {
            continue;
        }

        if cmd.apply {
            let policy_result = guard.policy().apply(trimmed, &report);
            if ctx.common.json {
                let result = PolicyStreamResult {
                    action: match policy_result.action {
                        helmet_core::Action::Passthrough => "passthrough",
                        helmet_core::Action::Redact => "redact",
                        helmet_core::Action::Sanitize => "sanitize",
                        helmet_core::Action::Quarantine => "quarantine",
                        helmet_core::Action::Reject => "reject",
                    },
                    decision: match report.decision {
                        Decision::Allow => "ALLOW",
                        Decision::Review => "REVIEW",
                        Decision::Block => "BLOCK",
                    },
                    score: report.score,
                    output: &policy_result.output,
                    latency_us: report.latency.as_micros() as u64,
                    input: Some(trimmed),
                };

                serde_json::to_writer(&mut writer, &result).context("writing JSON output")?;
                let _ = writeln!(writer);
            } else {
                let decision_str = match report.decision {
                    Decision::Allow => "ALLOW ",
                    Decision::Review => "REVIEW",
                    Decision::Block => "BLOCK ",
                };
                let _ = writeln!(
                    writer,
                    "{} action={:?} score={:.3} latency={}us | {}",
                    decision_str,
                    policy_result.action,
                    report.score,
                    report.latency.as_micros(),
                    policy_result.output
                );
            }
        } else if ctx.common.json {
            let patterns: Vec<&str> = report
                .heuristic_result
                .matches
                .iter()
                .map(|m| m.pattern.description())
                .collect();

            let result = ScanResult {
                decision: match report.decision {
                    Decision::Allow => "ALLOW",
                    Decision::Review => "REVIEW",
                    Decision::Block => "BLOCK",
                },
                score: report.score,
                patterns,
                latency_us: report.latency.as_micros() as u64,
                input: Some(trimmed),
            };

            serde_json::to_writer(&mut writer, &result).context("writing JSON output")?;
            let _ = writeln!(writer);
        } else {
            let decision_str = match report.decision {
                Decision::Allow => "ALLOW ",
                Decision::Review => "REVIEW",
                Decision::Block => "BLOCK ",
            };
            let _ = write!(
                writer,
                "{} score={:.3} latency={}us",
                decision_str,
                report.score,
                report.latency.as_micros(),
            );
            if !report.heuristic_result.matches.is_empty() {
                let patterns: Vec<&str> = report
                    .heuristic_result
                    .matches
                    .iter()
                    .map(|m| m.pattern.description())
                    .collect();
                let _ = write!(writer, " patterns=[{}]", patterns.join(", "));
            }
            let truncated: String = trimmed.chars().take(80).collect();
            let ellipsis = if trimmed.len() > 80 { "..." } else { "" };
            let _ = writeln!(writer, " | {truncated}{ellipsis}");
        }

        // Flush after each line for low-latency streaming
        writer.flush().context("flushing output")?;
    }

    let total_elapsed = total_start.elapsed();

    // Print summary to stderr so it doesn't mix with streamed output
    if line_count > 0 && !ctx.common.quiet {
        let throughput = if total_elapsed.as_secs_f64() > 0.0 {
            line_count as f64 / total_elapsed.as_secs_f64()
        } else {
            0.0
        };
        eprintln!(
            "\n--- scanned {} lines in {:.1}ms ({:.0} lines/sec) ---",
            line_count,
            total_elapsed.as_secs_f64() * 1000.0,
            throughput,
        );
        eprintln!(
            "BLOCK: {}  REVIEW: {}  ALLOW: {}",
            block_count, review_count, allow_count,
        );
    }

    Ok(())
}

fn print_scan_result(
    ctx: &RuntimeContext,
    report: &helmet_core::threats::ThreatReport,
    input: Option<&str>,
    _cmd: &ScanCommand,
) -> Result<()> {
    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).context("serializing report to JSON")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(report).context("serializing report to YAML")?
        );
    } else {
        println!("Decision:  {}", report.decision);
        println!("Score:     {:.4}", report.score);
        println!("Latency:   {}us", report.latency.as_micros());

        if !report.heuristic_result.matches.is_empty() {
            println!("Patterns:");
            for m in &report.heuristic_result.matches {
                println!(
                    "  - {} (weight: {:.2}) matched: {:?}",
                    m.pattern.description(),
                    m.weight,
                    m.matched_text
                );
            }
        }

        let cs = &report.heuristic_result.category_scores;
        if cs.max_score() > 0.0 {
            println!("Categories:");
            if cs.instruction_override > 0.0 {
                println!("  instruction_override: {:.3}", cs.instruction_override);
            }
            if cs.role_confusion > 0.0 {
                println!("  role_confusion:       {:.3}", cs.role_confusion);
            }
            if cs.function_coercion > 0.0 {
                println!("  function_coercion:    {:.3}", cs.function_coercion);
            }
            if cs.encoded_content > 0.0 {
                println!("  encoded_content:      {:.3}", cs.encoded_content);
            }
            if cs.sensitive_keywords > 0.0 {
                println!("  sensitive_keywords:   {:.3}", cs.sensitive_keywords);
            }
        }

        if !report.obfuscation.is_clean() {
            println!("Obfuscation:");
            if report.obfuscation.zero_width_chars > 0 {
                println!(
                    "  zero_width_chars: {}",
                    report.obfuscation.zero_width_chars
                );
            }
            if report.obfuscation.bidi_controls > 0 {
                println!("  bidi_controls: {}", report.obfuscation.bidi_controls);
            }
            if report.obfuscation.homoglyphs_detected {
                println!("  homoglyphs: detected");
            }
            println!("  obfuscation_risk: {:.3}", report.obfuscation.risk_score());
        }

        if let Some(text) = input {
            let preview: String = text.chars().take(120).collect();
            let ellipsis = if text.len() > 120 { "..." } else { "" };
            println!("Input:     {preview}{ellipsis}");
        }
    }
    Ok(())
}

// ============================================================================
// Eval command
// ============================================================================

#[derive(Debug, Clone, Args)]
struct EvalCommand {
    /// Path to JSONL dataset file. Each line must have "text" and "label" (0=safe, 1=injection).
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,

    /// HuggingFace dataset name (datasets-server API)
    #[arg(long)]
    dataset: Option<String>,

    /// HuggingFace dataset config
    #[arg(long = "dataset-config", default_value = "default")]
    dataset_config: String,

    /// Dataset split (train/test)
    #[arg(long, default_value = "test")]
    split: String,

    /// Maximum number of samples to evaluate
    #[arg(short = 'n', long, value_name = "N")]
    limit: Option<usize>,

    /// Field name for input text
    #[arg(long, default_value = "text")]
    text_field: String,

    /// Field name for label (0=safe, 1=injection)
    #[arg(long, default_value = "label")]
    label_field: String,
}

#[derive(serde::Serialize)]
struct EvalMetrics {
    total: usize,
    true_positives: usize,
    true_negatives: usize,
    false_positives: usize,
    false_negatives: usize,
    accuracy: f64,
    precision: f64,
    recall: f64,
    f1: f64,
    false_positive_rate: f64,
    avg_latency_us: f64,
    throughput_lines_per_sec: f64,
    block_count: usize,
    review_count: usize,
    allow_count: usize,
}

fn print_policy_result(ctx: &RuntimeContext, result: &helmet_core::PolicyResult) -> Result<()> {
    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(result).context("serializing policy result to JSON")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(result).context("serializing policy result to YAML")?
        );
    } else {
        println!("Action:    {:?}", result.action);
        println!("Decision:  {}", result.decision);
        println!("Score:     {:.4}", result.score);
        println!("Output:    {}", result.output);
    }
    Ok(())
}

fn handle_eval(ctx: &RuntimeContext, cmd: EvalCommand) -> Result<()> {
    let guard =
        Guard::with_config(ctx.config.guard.clone()).context("creating guard from config")?;

    let source = EvalSource::from_command(&cmd)?;
    let rows = load_eval_rows(&source, &cmd)?;

    let mut total = 0usize;
    let mut tp = 0usize; // true positive: is_injection && detected
    let mut tn = 0usize; // true negative: safe && allowed
    let mut fp = 0usize; // false positive: safe but flagged/blocked
    let mut r#fn = 0usize; // false negative: injection but allowed
    let mut block_count = 0usize;
    let mut review_count = 0usize;
    let mut allow_count = 0usize;
    let mut total_latency_us = 0u64;
    let mut parse_errors = 0usize;

    let start = Instant::now();

    for (line_idx, row) in rows.into_iter().enumerate() {
        if let Some(limit) = cmd.limit
            && total >= limit
        {
            break;
        }

        let parsed = match row {
            Ok(value) => value,
            Err(err) => {
                parse_errors += 1;
                if ctx.common.verbose > 0 {
                    eprintln!("Parse error on line {}: {}", line_idx + 1, err);
                }
                continue;
            }
        };

        let text = match parsed.get(&cmd.text_field).and_then(|v| v.as_str()) {
            Some(t) => t,
            None => {
                parse_errors += 1;
                continue;
            }
        };

        // Support both integer labels and string labels
        let is_injection = match parsed.get(&cmd.label_field) {
            Some(serde_json::Value::Number(n)) => n.as_i64().unwrap_or(0) == 1,
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(s)) => {
                matches!(
                    s.as_str(),
                    "1" | "injection" | "true" | "malicious" | "attack"
                )
            }
            _ => {
                parse_errors += 1;
                continue;
            }
        };

        let report = guard.check(text);
        total += 1;
        total_latency_us += report.latency.as_micros() as u64;

        match report.decision {
            Decision::Block => block_count += 1,
            Decision::Review => review_count += 1,
            Decision::Allow => allow_count += 1,
        }

        // For metrics: BLOCK or REVIEW = detected, ALLOW = not detected
        let detected = report.decision != Decision::Allow;

        match (is_injection, detected) {
            (true, true) => tp += 1,
            (false, false) => tn += 1,
            (false, true) => fp += 1,
            (true, false) => r#fn += 1,
        }

        // Print false positives and false negatives for debugging
        if ctx.common.verbose > 0 {
            match (is_injection, detected) {
                (false, true) => {
                    let preview: String = text.chars().take(80).collect();
                    eprintln!("FP score={:.3} | {preview}", report.score);
                }
                (true, false) => {
                    let preview: String = text.chars().take(80).collect();
                    eprintln!("FN score={:.3} | {preview}", report.score);
                }
                _ => {}
            }
        }
    }

    let elapsed = start.elapsed();

    if total == 0 {
        return Err(anyhow!("no valid samples found in {}", source.label()));
    }

    let accuracy = (tp + tn) as f64 / total as f64;
    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };
    let recall = if tp + r#fn > 0 {
        tp as f64 / (tp + r#fn) as f64
    } else {
        0.0
    };
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    let fpr = if tn + fp > 0 {
        fp as f64 / (fp + tn) as f64
    } else {
        0.0
    };

    let metrics = EvalMetrics {
        total,
        true_positives: tp,
        true_negatives: tn,
        false_positives: fp,
        false_negatives: r#fn,
        accuracy,
        precision,
        recall,
        f1,
        false_positive_rate: fpr,
        avg_latency_us: total_latency_us as f64 / total as f64,
        throughput_lines_per_sec: total as f64 / elapsed.as_secs_f64(),
        block_count,
        review_count,
        allow_count,
    };

    if ctx.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&metrics).context("serializing metrics")?
        );
    } else if ctx.common.yaml {
        println!(
            "{}",
            serde_yaml::to_string(&metrics).context("serializing metrics")?
        );
    } else {
        println!("=== Helmet Evaluation: {} ===", source.label());
        println!();
        println!("Samples:     {} (parse errors: {})", total, parse_errors);
        println!(
            "Elapsed:     {:.1}ms ({:.0} lines/sec)",
            elapsed.as_secs_f64() * 1000.0,
            metrics.throughput_lines_per_sec
        );
        println!("Avg latency: {:.0}us per sample", metrics.avg_latency_us);
        println!();
        println!("--- Confusion Matrix ---");
        println!("                  Predicted");
        println!("               Threat   Safe");
        println!("  Actual Threat  {:>5}  {:>5}  (TP / FN)", tp, r#fn);
        println!("  Actual Safe    {:>5}  {:>5}  (FP / TN)", fp, tn);
        println!();
        println!("--- Metrics ---");
        println!("Accuracy:   {:.1}%", accuracy * 100.0);
        println!("Precision:  {:.1}%", precision * 100.0);
        println!("Recall:     {:.1}%", recall * 100.0);
        println!("F1 Score:   {:.3}", f1);
        println!("FPR:        {:.2}%", fpr * 100.0);
        println!();
        println!("--- Decision Distribution ---");
        println!("BLOCK:  {block_count}");
        println!("REVIEW: {review_count}");
        println!("ALLOW:  {allow_count}");
    }

    Ok(())
}

enum EvalSource {
    File(PathBuf),
    HuggingFace {
        dataset: String,
        config: String,
        split: String,
    },
}

impl EvalSource {
    fn from_command(cmd: &EvalCommand) -> Result<Self> {
        if let Some(ref dataset) = cmd.dataset {
            return Ok(Self::HuggingFace {
                dataset: dataset.clone(),
                config: cmd.dataset_config.clone(),
                split: cmd.split.clone(),
            });
        }

        if let Some(ref file) = cmd.file {
            return Ok(Self::File(file.clone()));
        }

        Err(anyhow!("provide either a JSONL file or --dataset"))
    }

    fn label(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::HuggingFace {
                dataset,
                config,
                split,
            } => format!("{dataset}:{config}:{split}"),
        }
    }
}

fn load_eval_rows(
    source: &EvalSource,
    cmd: &EvalCommand,
) -> Result<Vec<std::result::Result<serde_json::Value, anyhow::Error>>> {
    match source {
        EvalSource::File(path) => load_eval_rows_from_file(path),
        EvalSource::HuggingFace {
            dataset,
            config,
            split,
        } => load_eval_rows_from_hf(dataset, config, split, cmd.limit),
    }
}

fn load_eval_rows_from_file(
    path: &PathBuf,
) -> Result<Vec<std::result::Result<serde_json::Value, anyhow::Error>>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader = io::BufReader::new(file);

    let mut rows = Vec::new();
    for line in reader.lines() {
        let line = line.context("reading line")?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str(&line).map_err(|e| anyhow!("parsing JSONL: {}", e));
        rows.push(value);
    }

    Ok(rows)
}

fn load_eval_rows_from_hf(
    dataset: &str,
    config: &str,
    split: &str,
    limit: Option<usize>,
) -> Result<Vec<std::result::Result<serde_json::Value, anyhow::Error>>> {
    let limit = limit.unwrap_or(500);
    let url = format!(
        "https://datasets-server.huggingface.co/rows?dataset={}&config={}&split={}&offset=0&length={}",
        urlencoding::encode(dataset),
        urlencoding::encode(config),
        urlencoding::encode(split),
        limit,
    );

    let client = reqwest::blocking::Client::new();
    let response = client
        .get(&url)
        .send()
        .context("fetching dataset rows")?
        .error_for_status()
        .context("dataset server returned error")?;

    #[derive(serde::Deserialize)]
    struct RowsResponse {
        rows: Vec<RowItem>,
    }

    #[derive(serde::Deserialize)]
    struct RowItem {
        row: serde_json::Value,
    }

    let parsed: RowsResponse = response.json().context("parsing dataset response")?;
    let rows = parsed.rows.into_iter().map(|row| Ok(row.row)).collect();

    Ok(rows)
}

// ============================================================================
// Existing commands
// ============================================================================

#[derive(Debug, Clone, Args)]
struct RunCommand {
    /// Named task to execute
    #[arg(value_name = "TASK", default_value = "default")]
    task: String,
    /// Override the profile to run under
    #[arg(long, value_name = "PROFILE")]
    profile: Option<String>,
}

#[derive(Debug, Clone, Args)]
struct InitCommand {
    /// Recreate configuration even if it already exists
    #[arg(long = "force")]
    force: bool,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Output the effective configuration
    Show,
    /// Print the resolved config file path
    Path,
    /// Print all resolved paths (config, data, state, cache)
    Paths,
    /// Print the JSON schema for the config file
    Schema,
    /// Regenerate the default configuration file
    Reset,
}

#[derive(Debug, Clone)]
struct RuntimeContext {
    common: CommonOpts,
    paths: AppPaths,
    config: AppConfig,
}

impl RuntimeContext {
    fn new(common: CommonOpts) -> Result<Self> {
        let paths = AppPaths::discover(common.config.clone())?;
        let config = AppConfig::load(&paths, common.dry_run)?;
        let paths = paths.apply_overrides(&config)?;
        let ctx = Self {
            common,
            paths,
            config,
        };
        ctx.ensure_directories()?;
        Ok(ctx)
    }

    fn init_logging(&self) -> Result<()> {
        if self.common.quiet {
            log::set_max_level(LevelFilter::Off);
            return Ok(());
        }

        let mut builder =
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

        builder.filter_level(self.effective_log_level());

        let force_color = matches!(self.common.color, ColorOption::Always)
            || env::var_os("FORCE_COLOR").is_some();
        let disable_color = self.common.no_color
            || matches!(self.common.color, ColorOption::Never)
            || env::var_os("NO_COLOR").is_some()
            || (!force_color && !io::stderr().is_terminal());

        if disable_color {
            builder.write_style(WriteStyle::Never);
        } else if force_color {
            builder.write_style(WriteStyle::Always);
        } else {
            builder.write_style(WriteStyle::Auto);
        }

        if self.common.diagnostics {
            builder.format_timestamp_millis();
            builder.format_module_path(true);
            builder.format_target(true);
        }

        builder.try_init().or_else(|err| {
            if self.common.verbose > 0 {
                eprintln!("logger already initialized: {err}");
            }
            Ok(())
        })
    }

    fn effective_log_level(&self) -> LevelFilter {
        if self.common.trace {
            LevelFilter::Trace
        } else if self.common.debug {
            LevelFilter::Debug
        } else {
            match self.common.verbose {
                0 => LevelFilter::Info,
                1 => LevelFilter::Debug,
                _ => LevelFilter::Trace,
            }
        }
    }

    fn ensure_directories(&self) -> Result<()> {
        if self.common.dry_run {
            self.paths.log_dry_run();
            return Ok(());
        }
        self.paths.ensure_directories()
    }
}

fn handle_run(ctx: &mut RuntimeContext, cmd: RunCommand) -> Result<()> {
    let effective = ctx.config.clone().with_profile_override(cmd.profile);
    let output = if ctx.common.json {
        serde_json::to_string_pretty(&effective).context("serializing run output to JSON")?
    } else if ctx.common.yaml {
        serde_yaml::to_string(&effective).context("serializing run output to YAML")?
    } else {
        format!(
            "Running task '{}' with profile '{}' (parallelism: {})",
            cmd.task,
            effective.profile,
            effective
                .runtime
                .parallelism
                .unwrap_or_else(default_parallelism)
        )
    };

    println!("{output}");
    Ok(())
}

fn handle_init(ctx: &RuntimeContext, cmd: InitCommand) -> Result<()> {
    if ctx.paths.config_file.exists() && !(cmd.force || ctx.common.assume_yes) {
        return Err(anyhow!(
            "config already exists at {} (use --force to overwrite)",
            ctx.paths.config_file.display()
        ));
    }

    if ctx.common.dry_run {
        info!(
            "dry-run: would write default config to {}",
            ctx.paths.config_file.display()
        );
        return Ok(());
    }

    write_default_config(&ctx.paths.config_file)
}

fn handle_config(ctx: &RuntimeContext, command: ConfigCommand) -> Result<()> {
    match command {
        ConfigCommand::Show => {
            if ctx.common.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ctx.config)
                        .context("serializing config to JSON")?
                );
            } else if ctx.common.yaml {
                println!(
                    "{}",
                    serde_yaml::to_string(&ctx.config).context("serializing config to YAML")?
                );
            } else {
                println!("{:#?}", ctx.config);
            }
            Ok(())
        }
        ConfigCommand::Path => {
            println!("{}", ctx.paths.config_file.display());
            Ok(())
        }
        ConfigCommand::Paths => {
            let cache_dir = default_cache_dir()?;
            if ctx.common.json {
                let paths = serde_json::json!({
                    "config": ctx.paths.config_file,
                    "data": ctx.paths.data_dir,
                    "state": ctx.paths.state_dir,
                    "cache": cache_dir,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&paths).context("serializing paths to JSON")?
                );
            } else if ctx.common.yaml {
                let paths = serde_json::json!({
                    "config": ctx.paths.config_file,
                    "data": ctx.paths.data_dir,
                    "state": ctx.paths.state_dir,
                    "cache": cache_dir,
                });
                println!(
                    "{}",
                    serde_yaml::to_string(&paths).context("serializing paths to YAML")?
                );
            } else {
                println!("config: {}", ctx.paths.config_file.display());
                println!("data:   {}", ctx.paths.data_dir.display());
                println!("state:  {}", ctx.paths.state_dir.display());
                println!("cache:  {}", cache_dir.display());
            }
            Ok(())
        }
        ConfigCommand::Schema => {
            println!("{}", include_str!("../../../examples/config.schema.json"));
            Ok(())
        }
        ConfigCommand::Reset => {
            if ctx.common.dry_run {
                info!(
                    "dry-run: would reset config at {}",
                    ctx.paths.config_file.display()
                );
                return Ok(());
            }
            write_default_config(&ctx.paths.config_file)
        }
    }
}

fn handle_completions(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, APP_NAME, &mut io::stdout());
    Ok(())
}
