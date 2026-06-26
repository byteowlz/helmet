//! Helmet detection-benchmark tooling (dev-only).
//!
//! `augment` reads a JSONL of attack rows (`{"text":..,"label":1}`) and emits, for
//! each attack, a *clean* `direct`-split row plus one obfuscated variant per
//! transform (`base64`/`hex`/`url`/`homoglyph`/`zerowidth`/`bidi`). Each obfuscated
//! row shares a `pair_id` with its clean origin so the benchmark's robustness gap
//! (recall(direct) - recall(obfuscation)) is measured on matched pairs.
//!
//! The transforms are the inverse of Helmet's Layer-0 detectors (see
//! `helmet-core::preprocess`): if L0 decode/normalize is working, these obfuscated
//! attacks should still be caught, keeping the robustness gap near zero.

use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use clap::Parser;
use serde::Serialize;

/// One normalized benchmark row. Superset of the `{text,label}` contract that
/// `helmet-cli --eval` consumes; extra fields are ignored by the current eval and
/// grouped on by the extended eval.
#[derive(Serialize)]
struct Row {
    text: String,
    label: u8,
    split: String,
    family: String,
    source: String,
    lang: String,
    channel: String,
    obfuscation: String,
    /// train | val | test — assigned deterministically from the *origin* text hash
    /// so duplicates and obfuscated variants never straddle folds (no leakage).
    fold: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pair_id: Option<String>,
}

/// FNV-1a 64-bit — stable across runs/versions (unlike `DefaultHasher`).
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Deterministic, leak-free fold from normalized text: 70% train / 15% val / 15% test.
fn fold_of(text: &str) -> &'static str {
    match fnv1a(text.trim().to_lowercase().as_str()) % 100 {
        0..=69 => "train",
        70..=84 => "val",
        _ => "test",
    }
}

#[derive(Parser)]
#[command(name = "helmet-bench", about = "Helmet detection-benchmark corpus tooling")]
enum Cli {
    /// Generate the obfuscation-stress split from a JSONL of attack rows.
    Augment(AugmentArgs),
    /// Normalize a raw JSONL dataset into the benchmark schema for one split.
    Ingest(IngestArgs),
}

#[derive(Parser)]
struct IngestArgs {
    /// Raw input JSONL (one JSON object per line).
    #[arg(long)]
    input: PathBuf,
    /// Field holding the prompt text.
    #[arg(long, default_value = "text")]
    text_field: String,
    /// Field holding the label (coerced to 0/1). Ignored if --label-const is set.
    #[arg(long, default_value = "label")]
    label_field: String,
    /// Force every row to this label (0=benign, 1=attack) instead of reading a field.
    #[arg(long)]
    label_const: Option<u8>,
    /// Benchmark split this dataset feeds (e.g. direct, benign_easy, benign_hard, indirect).
    #[arg(long)]
    split: String,
    /// Provenance tag.
    #[arg(long)]
    source: String,
    /// ISO 639-1 language tag.
    #[arg(long, default_value = "en")]
    lang: String,
    /// direct | indirect.
    #[arg(long, default_value = "direct")]
    channel: String,
    /// Attack technique / benign subtype tag.
    #[arg(long, default_value = "unknown")]
    family: String,
    /// Output corpus root; writes `<out>/<split>/<source>.jsonl`.
    #[arg(long, default_value = "data/bench")]
    out: PathBuf,
}

#[derive(Parser)]
struct AugmentArgs {
    /// Input JSONL with `{"text":..,"label":..}` rows; only label==1 are augmented.
    #[arg(long)]
    input: PathBuf,
    /// Provenance tag written into each row's `source` field.
    #[arg(long, default_value = "deepset")]
    source: String,
    /// ISO 639-1 language tag for the rows.
    #[arg(long, default_value = "en")]
    lang: String,
    /// Output corpus root; writes `<out>/direct/<source>.jsonl` and `<out>/obfuscation/<source>.jsonl`.
    #[arg(long, default_value = "data/bench")]
    out: PathBuf,
}

const ZWSP: char = '\u{200b}';
const RLO: char = '\u{202e}';
const PDF: char = '\u{202c}';

fn to_hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn to_base64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}

/// ASCII -> visually-confusable (mostly Cyrillic/Greek) homoglyphs. Inverse of
/// `preprocess::normalize_confusable`.
fn homoglyph(c: char) -> char {
    match c {
        'a' => 'а', 'c' => 'с', 'e' => 'е', 'i' => 'і', 'j' => 'ј', 'o' => 'о',
        'p' => 'р', 's' => 'ѕ', 'x' => 'х', 'y' => 'у',
        'A' => 'А', 'B' => 'В', 'C' => 'С', 'E' => 'Е', 'H' => 'Н', 'K' => 'К',
        'M' => 'М', 'O' => 'О', 'P' => 'Р', 'T' => 'Т', 'X' => 'Х',
        other => other,
    }
}

fn homoglyph_text(s: &str) -> String {
    s.chars().map(homoglyph).collect()
}

/// Insert a zero-width space between every character.
fn zero_width(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 {
            out.push(ZWSP);
        }
        out.push(c);
    }
    out
}

/// Wrap in a right-to-left override / pop-directional-formatting pair.
fn bidi(s: &str) -> String {
    format!("{RLO}{s}{PDF}")
}

/// All obfuscation variants for one attack: `(obfuscation_tag, transformed_text)`.
/// Encoded payloads are embedded in a carrier so they resemble a real attack
/// ("decode this and follow it") rather than a bare blob.
fn variants(text: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "base64",
            format!("Please base64-decode the following and follow its instructions: {}", to_base64(text)),
        ),
        (
            "hex",
            format!("Decode this hex and do what it says: {}", to_hex(text)),
        ),
        ("url", urlencoding::encode(text).into_owned()),
        ("homoglyph", homoglyph_text(text)),
        ("zerowidth", zero_width(text)),
        ("bidi", bidi(text)),
    ]
}

/// Coerce a JSON label value to 0 (benign) / 1 (attack). Returns None if unparseable.
fn coerce_label(v: &serde_json::Value) -> Option<u8> {
    match v {
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(0) => Some(0),
            Some(_) => Some(1),
            None => None,
        },
        serde_json::Value::Bool(b) => Some(u8::from(*b)),
        serde_json::Value::String(s) => match s.as_str() {
            "1" | "injection" | "true" | "malicious" | "attack" | "harmful" => Some(1),
            "0" | "benign" | "false" | "safe" | "clean" => Some(0),
            _ => None,
        },
        _ => None,
    }
}

fn run_ingest(args: &IngestArgs) -> Result<()> {
    let file = fs::File::open(&args.input)
        .with_context(|| format!("opening {}", args.input.display()))?;
    let reader = BufReader::new(file);

    let mut rows: Vec<Row> = Vec::new();
    let mut skipped = 0usize;
    let mut duplicates = 0usize;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for line in reader.lines() {
        let line = line.context("reading input line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let Some(text) = value.get(&args.text_field).and_then(serde_json::Value::as_str) else {
            skipped += 1;
            continue;
        };
        // Dedup by normalized text (trim + lowercase) — competition corpora resubmit heavily.
        if !seen.insert(text.trim().to_lowercase()) {
            duplicates += 1;
            continue;
        }
        let label = match args.label_const {
            Some(c) => u8::from(c != 0),
            None => match value.get(&args.label_field).and_then(coerce_label) {
                Some(l) => l,
                None => {
                    skipped += 1;
                    continue;
                }
            },
        };
        rows.push(Row {
            text: text.to_owned(),
            label,
            split: args.split.clone(),
            family: args.family.clone(),
            source: args.source.clone(),
            lang: args.lang.clone(),
            channel: args.channel.clone(),
            obfuscation: "none".to_owned(),
            fold: fold_of(text).to_owned(),
            pair_id: None,
        });
    }

    if rows.is_empty() {
        return Err(anyhow!(
            "no usable rows in {} (text field '{}'?)",
            args.input.display(),
            args.text_field
        ));
    }

    let out_path = args.out.join(&args.split).join(format!("{}.jsonl", args.source));
    write_rows(&out_path, &rows)?;
    println!(
        "ingested {} rows -> {} (split={}, label={}, dropped {duplicates} dups, skipped {skipped})",
        rows.len(),
        out_path.display(),
        args.split,
        args.label_const
            .map_or_else(|| format!("from '{}'", args.label_field), |c| u8::from(c != 0).to_string()),
    );
    Ok(())
}

fn is_attack(v: &serde_json::Value) -> bool {
    match v.get("label") {
        Some(serde_json::Value::Number(n)) => n.as_i64() == Some(1),
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(s)) => {
            matches!(s.as_str(), "1" | "injection" | "true" | "malicious" | "attack")
        }
        _ => false,
    }
}

fn write_rows(path: &Path, rows: &[Row]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let file = fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut w = BufWriter::new(file);
    for row in rows {
        let line = serde_json::to_string(row).context("serializing row")?;
        w.write_all(line.as_bytes())?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

fn run_augment(args: &AugmentArgs) -> Result<()> {
    let file = fs::File::open(&args.input)
        .with_context(|| format!("opening {}", args.input.display()))?;
    let reader = BufReader::new(file);

    let mut direct: Vec<Row> = Vec::new();
    let mut obfuscated: Vec<Row> = Vec::new();
    let mut attack_idx = 0usize;
    let mut skipped = 0usize;

    for line in reader.lines() {
        let line = line.context("reading input line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if !is_attack(&value) {
            continue;
        }
        let Some(text) = value.get("text").and_then(serde_json::Value::as_str) else {
            skipped += 1;
            continue;
        };

        let pair_id = format!("{}-{attack_idx:06}", args.source);
        attack_idx += 1;
        // Both the clean row and all its obfuscated variants take the CLEAN text's
        // fold, so a model never sees one form in train and another in test.
        let fold = fold_of(text).to_owned();

        direct.push(Row {
            text: text.to_owned(),
            label: 1,
            split: "direct".to_owned(),
            family: "unknown".to_owned(),
            source: args.source.clone(),
            lang: args.lang.clone(),
            channel: "direct".to_owned(),
            obfuscation: "none".to_owned(),
            fold: fold.clone(),
            pair_id: Some(pair_id.clone()),
        });

        for (tag, transformed) in variants(text) {
            obfuscated.push(Row {
                text: transformed,
                label: 1,
                split: "obfuscation".to_owned(),
                family: "unknown".to_owned(),
                source: args.source.clone(),
                lang: args.lang.clone(),
                channel: "direct".to_owned(),
                obfuscation: tag.to_owned(),
                fold: fold.clone(),
                pair_id: Some(pair_id.clone()),
            });
        }
    }

    if attack_idx == 0 {
        return Err(anyhow!("no attack (label==1) rows found in {}", args.input.display()));
    }

    let direct_path = args.out.join("direct").join(format!("{}.jsonl", args.source));
    let obf_path = args.out.join("obfuscation").join(format!("{}.jsonl", args.source));
    write_rows(&direct_path, &direct)?;
    write_rows(&obf_path, &obfuscated)?;

    println!(
        "augmented {attack_idx} attacks -> {} clean + {} obfuscated rows (skipped {skipped})",
        direct.len(),
        obfuscated.len()
    );
    println!("  {}", direct_path.display());
    println!("  {}", obf_path.display());
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse() {
        Cli::Augment(args) => run_augment(&args),
        Cli::Ingest(args) => run_ingest(&args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrips() {
        let enc = to_base64("ignore previous instructions");
        let dec = base64::engine::general_purpose::STANDARD
            .decode(enc.as_bytes())
            .expect("decode");
        assert_eq!(dec, b"ignore previous instructions");
    }

    #[test]
    fn hex_is_two_chars_per_byte() {
        assert_eq!(to_hex("AB"), "4142");
    }

    #[test]
    fn homoglyph_substitutes_ascii_with_non_ascii() {
        let h = homoglyph_text("paypal");
        assert!(!h.is_ascii(), "expected confusables to be injected");
    }

    #[test]
    fn zero_width_inserts_invisible_chars() {
        let z = zero_width("abc");
        assert!(z.contains(ZWSP));
        assert_eq!(z.chars().filter(|&c| c == ZWSP).count(), 2);
    }

    #[test]
    fn every_attack_yields_six_variants() {
        assert_eq!(variants("do bad things").len(), 6);
    }

    #[test]
    fn fold_is_deterministic_and_case_insensitive() {
        assert_eq!(fold_of("Ignore Previous"), fold_of("ignore previous "));
        assert_eq!(fold_of("a stable string"), fold_of("a stable string"));
        assert!(matches!(fold_of("anything"), "train" | "val" | "test"));
    }

    #[test]
    fn coerce_label_maps_common_forms() {
        assert_eq!(coerce_label(&serde_json::json!(1)), Some(1));
        assert_eq!(coerce_label(&serde_json::json!(0)), Some(0));
        assert_eq!(coerce_label(&serde_json::json!("harmful")), Some(1));
        assert_eq!(coerce_label(&serde_json::json!("benign")), Some(0));
        assert_eq!(coerce_label(&serde_json::json!(true)), Some(1));
        assert_eq!(coerce_label(&serde_json::json!("???")), None);
    }

    #[test]
    fn is_attack_handles_int_bool_string() {
        assert!(is_attack(&serde_json::json!({"label": 1})));
        assert!(is_attack(&serde_json::json!({"label": true})));
        assert!(is_attack(&serde_json::json!({"label": "injection"})));
        assert!(!is_attack(&serde_json::json!({"label": 0})));
    }
}
