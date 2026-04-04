use std::collections::HashMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Parser};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

use helmet_core::policy::{PolicyConfig, PolicyEngine};
use helmet_core::{Action, AppConfig, AppPaths, Guard};

fn main() {
    if let Err(err) = try_main() {
        let _ = writeln!(io::stderr(), "{err:?}");
        std::process::exit(1);
    }
}

fn try_main() -> Result<()> {
    let cli = Cli::parse();
    let paths = AppPaths::discover(cli.common.config.clone())?;
    let config = AppConfig::load(&paths, false)?;

    let guard = Guard::with_config(config.guard.clone())?;
    let samples = load_samples(&cli, &guard)?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(config, samples, cli);
    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

#[derive(Debug, Parser)]
#[command(author, version, about = "Helmet TUI dataset playground")]
struct Cli {
    #[command(flatten)]
    common: CommonOpts,

    /// HuggingFace dataset name (datasets-server API)
    #[arg(long, default_value = "deepset/prompt-injections")]
    dataset: String,

    /// HuggingFace dataset config
    #[arg(long = "dataset-config", default_value = "default")]
    dataset_config: String,

    /// Dataset split (train/test)
    #[arg(long, default_value = "test")]
    split: String,

    /// Max samples to load
    #[arg(long, default_value_t = 50)]
    limit: usize,

    /// Load samples from JSONL file instead of HuggingFace
    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    /// Field name for text in JSONL file
    #[arg(long, default_value = "text")]
    text_field: String,
}

#[derive(Debug, Clone, Args)]
struct CommonOpts {
    /// Override the config file path
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[derive(Debug)]
enum AppMode {
    Normal,
    Help,
}

#[derive(Debug, Clone)]
struct Sample {
    text: String,
    decision: String,
    score: f32,
    patterns: Vec<String>,
    outputs: SampleOutputs,
}

#[derive(Debug, Clone)]
struct SampleOutputs {
    passthrough: String,
    sanitized: String,
    redacted: String,
    rejected: String,
}

struct App {
    config: AppConfig,
    mode: AppMode,
    selected_index: usize,
    samples: Vec<Sample>,
    status_message: String,
    dataset_label: String,
}

impl App {
    fn new(config: AppConfig, samples: Vec<Sample>, cli: Cli) -> Self {
        let dataset_label = if let Some(ref file) = cli.file {
            format!("file:{}", file.display())
        } else {
            format!("{}:{}:{}", cli.dataset, cli.dataset_config, cli.split)
        };

        Self {
            config,
            mode: AppMode::Normal,
            selected_index: 0,
            samples,
            status_message: "j/k to navigate, ? for help, q to quit".to_string(),
            dataset_label,
        }
    }

    fn next(&mut self) {
        if !self.samples.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.samples.len();
        }
    }

    fn previous(&mut self) {
        if !self.samples.is_empty() {
            self.selected_index = self
                .selected_index
                .checked_sub(1)
                .unwrap_or(self.samples.len() - 1);
        }
    }
}

fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            match &app.mode {
                AppMode::Normal => match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('?') => app.mode = AppMode::Help,
                    KeyCode::Char('j') | KeyCode::Down => app.next(),
                    KeyCode::Char('k') | KeyCode::Up => app.previous(),
                    _ => {}
                },
                AppMode::Help => match key.code {
                    KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
                        app.mode = AppMode::Normal
                    }
                    _ => {}
                },
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(f.area());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(22),
            Constraint::Percentage(38),
            Constraint::Percentage(40),
        ])
        .split(chunks[0]);

    draw_left_pane(f, app, main_chunks[0]);
    draw_middle_pane(f, app, main_chunks[1]);
    draw_right_pane(f, app, main_chunks[2]);
    draw_status_bar(f, app, chunks[1]);

    if matches!(app.mode, AppMode::Help) {
        draw_help_overlay(f);
    }
}

fn draw_left_pane(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().title(" Dataset ").borders(Borders::ALL);
    let mut lines = vec![
        Line::from(format!("Dataset: {}", app.dataset_label)),
        Line::from(format!("Samples: {}", app.samples.len())),
        Line::from(format!("Profile: {}", app.config.profile)),
        Line::from(""),
        Line::from("Keys:"),
        Line::from("  j/k  - move"),
        Line::from("  ?    - help"),
        Line::from("  q    - quit"),
    ];

    if let Some(sample) = app.samples.get(app.selected_index) {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "Decision: {} ({:.2})",
            sample.decision, sample.score
        )));
    }

    let paragraph = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn draw_middle_pane(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default().title(" Samples ").borders(Borders::ALL);
    let items: Vec<ListItem> = app
        .samples
        .iter()
        .enumerate()
        .map(|(i, sample)| {
            let preview: String = sample.text.chars().take(60).collect();
            let ellipsis = if sample.text.len() > 60 { "..." } else { "" };
            let title = format!("{:03} {}{}", i + 1, preview, ellipsis);
            let style = if i == app.selected_index {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            ListItem::new(title).style(style)
        })
        .collect();
    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

fn draw_right_pane(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(" Policy Outputs ")
        .borders(Borders::ALL);
    let content = if let Some(sample) = app.samples.get(app.selected_index) {
        let mut lines = Vec::new();
        lines.push(Line::from(format!(
            "Decision: {} | Score: {:.3}",
            sample.decision, sample.score
        )));
        if !sample.patterns.is_empty() {
            lines.push(Line::from(format!(
                "Patterns: {}",
                sample.patterns.join(", ")
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from("Original:"));
        lines.push(Line::from(sample.text.as_str()));
        lines.push(Line::from(""));
        lines.push(Line::from("Sanitized (sanitize):"));
        lines.push(Line::from(sample.outputs.sanitized.as_str()));
        lines.push(Line::from(""));
        lines.push(Line::from("Redacted (strict):"));
        lines.push(Line::from(sample.outputs.redacted.as_str()));
        lines.push(Line::from(""));
        lines.push(Line::from("Rejected (paranoid):"));
        lines.push(Line::from(sample.outputs.rejected.as_str()));
        lines.push(Line::from(""));
        lines.push(Line::from("Passthrough (monitor):"));
        lines.push(Line::from(sample.outputs.passthrough.as_str()));
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true })
    } else {
        Paragraph::new("No samples loaded").block(block)
    };

    f.render_widget(content, area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let mode_indicator = match app.mode {
        AppMode::Normal => Span::styled(
            " NORMAL ",
            Style::default().fg(Color::Black).bg(Color::Green),
        ),
        AppMode::Help => Span::styled(
            " HELP ",
            Style::default().fg(Color::Black).bg(Color::Yellow),
        ),
    };

    let status = Line::from(vec![
        mode_indicator,
        Span::raw(" "),
        Span::raw(&app.status_message),
    ]);

    f.render_widget(Paragraph::new(status), area);
}

fn draw_help_overlay(f: &mut Frame) {
    let area = centered_rect(60, 60, f.area());
    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::DarkGray));

    let help_text = vec![
        Line::from("Navigation:"),
        Line::from("  j/Down  - Move down"),
        Line::from("  k/Up    - Move up"),
        Line::from(""),
        Line::from("Outputs:"),
        Line::from("  Original text (left)"),
        Line::from("  Sanitized, Redacted, Rejected (right)"),
        Line::from(""),
        Line::from("Press Esc or ? to close"),
    ];

    let paragraph = Paragraph::new(help_text).block(block);
    f.render_widget(paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn load_samples(cli: &Cli, guard: &Guard) -> Result<Vec<Sample>> {
    let texts = if let Some(ref file) = cli.file {
        load_samples_from_file(file, &cli.text_field)?
    } else {
        fetch_hf_samples(&cli.dataset, &cli.dataset_config, &cli.split, cli.limit)?
    };

    let base_policy = guard.config().policy.clone();
    let policy_monitor = PolicyEngine::with_config(preset_policy(&base_policy, "monitor"));
    let policy_sanitize = PolicyEngine::with_config(preset_policy(&base_policy, "sanitize"));
    let policy_strict = PolicyEngine::with_config(preset_policy(&base_policy, "strict"));
    let policy_paranoid = PolicyEngine::with_config(preset_policy(&base_policy, "paranoid"));

    let samples = texts
        .into_iter()
        .map(|text| {
            let report = guard.check(&text);
            let patterns = report
                .heuristic_result
                .matches
                .iter()
                .map(|m| m.pattern.description().to_string())
                .collect();

            let passthrough = policy_monitor.apply(&text, &report).output;
            let sanitized = policy_sanitize.apply(&text, &report).output;
            let redacted = policy_strict.apply(&text, &report).output;
            let rejected = policy_paranoid.apply(&text, &report).output;

            Sample {
                text,
                decision: report.decision.to_string(),
                score: report.score,
                patterns,
                outputs: SampleOutputs {
                    passthrough,
                    sanitized,
                    redacted,
                    rejected,
                },
            }
        })
        .collect();

    Ok(samples)
}

fn load_samples_from_file(path: &PathBuf, text_field: &str) -> Result<Vec<String>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let reader = io::BufReader::new(file);

    let mut texts = Vec::new();
    for line in reader.lines() {
        let line = line.context("reading line")?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(&line).context("parsing JSONL")?;
        if let Some(text) = value.get(text_field).and_then(|v| v.as_str()) {
            texts.push(text.to_string());
        }
    }

    Ok(texts)
}

fn fetch_hf_samples(dataset: &str, config: &str, split: &str, limit: usize) -> Result<Vec<String>> {
    let client = reqwest::blocking::Client::new();
    let url = format!(
        "https://datasets-server.huggingface.co/rows?dataset={}&config={}&split={}&offset=0&length={}",
        urlencoding::encode(dataset),
        urlencoding::encode(config),
        urlencoding::encode(split),
        limit,
    );

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
        row: HashMap<String, serde_json::Value>,
    }

    let parsed: RowsResponse = response.json().context("parsing dataset response")?;
    let mut texts = Vec::new();

    for row in parsed.rows {
        if let Some(serde_json::Value::String(text)) = row.row.get("text") {
            texts.push(text.clone());
        }
    }

    Ok(texts)
}

fn preset_policy(base: &PolicyConfig, preset: &str) -> PolicyConfig {
    let mut policy = base.clone();
    match preset {
        "monitor" => {
            policy.on_block = Action::Passthrough;
            policy.on_review = Action::Passthrough;
            policy.on_allow = Action::Passthrough;
            policy.log_all = true;
        }
        "strict" => {
            policy.on_block = Action::Reject;
            policy.on_review = Action::Redact;
            policy.on_allow = Action::Passthrough;
        }
        "paranoid" => {
            policy.on_block = Action::Reject;
            policy.on_review = Action::Reject;
            policy.on_allow = Action::Passthrough;
        }
        "sanitize" => {
            policy.on_block = Action::Sanitize;
            policy.on_review = Action::Sanitize;
            policy.on_allow = Action::Passthrough;
        }
        _ => {
            policy.on_block = Action::Reject;
            policy.on_review = Action::Passthrough;
            policy.on_allow = Action::Passthrough;
        }
    }
    policy
}
