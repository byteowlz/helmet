//! Tests for configuration loading and defaults

use helmet_core::config::{AppConfig, GuardConfig};
use helmet_core::{APP_NAME, default_parallelism, env_prefix};

// ============================================================================
// App-level constants
// ============================================================================

#[test]
fn app_name_is_helmet() {
    assert_eq!(APP_NAME, "helmet");
}

#[test]
fn env_prefix_is_uppercase() {
    let prefix = env_prefix();
    assert_eq!(prefix, "HELMET");
}

#[test]
fn default_parallelism_is_positive() {
    let p = default_parallelism();
    assert!(p >= 1, "Parallelism should be at least 1, got {}", p);
}

// ============================================================================
// AppConfig defaults
// ============================================================================

#[test]
fn default_config_has_default_profile() {
    let config = AppConfig::default();
    assert_eq!(config.profile, "default");
}

#[test]
fn default_config_has_info_log_level() {
    let config = AppConfig::default();
    assert_eq!(config.logging.level, "info");
}

#[test]
fn default_config_has_no_log_file() {
    let config = AppConfig::default();
    assert!(config.logging.file.is_none());
}

#[test]
fn default_config_has_timeout() {
    let config = AppConfig::default();
    assert_eq!(config.runtime.timeout, Some(60));
}

#[test]
fn default_config_fail_fast_enabled() {
    let config = AppConfig::default();
    assert!(config.runtime.fail_fast);
}

#[test]
fn default_config_no_path_overrides() {
    let config = AppConfig::default();
    assert!(config.paths.data_dir.is_none());
    assert!(config.paths.state_dir.is_none());
}

#[test]
fn with_profile_override_replaces_profile() {
    let config = AppConfig::default().with_profile_override(Some("production".to_string()));
    assert_eq!(config.profile, "production");
}

#[test]
fn with_profile_override_none_keeps_default() {
    let config = AppConfig::default().with_profile_override(None);
    assert_eq!(config.profile, "default");
}

// ============================================================================
// GuardConfig defaults
// ============================================================================

#[test]
fn default_guard_config_thresholds() {
    let config = GuardConfig::default();
    assert!((config.block_threshold - 0.7).abs() < f32::EPSILON);
    assert!((config.review_threshold - 0.4).abs() < f32::EPSILON);
}

#[test]
fn default_guard_config_layer_settings() {
    let config = GuardConfig::default();
    assert!(
        config.enable_layer0,
        "Layer 0 (preprocessing) should be enabled by default"
    );
    assert!(
        config.enable_layer1,
        "Layer 1 (heuristics) should be enabled by default"
    );
    assert!(
        !config.enable_layer2,
        "Layer 2 (classifier) should be disabled by default"
    );
    assert!(
        !config.enable_layer3,
        "Layer 3 (LLM) should be disabled by default"
    );
}

#[test]
fn default_guard_config_no_custom_patterns() {
    let config = GuardConfig::default();
    assert!(config.custom_patterns.is_empty());
    assert!(config.ignore_patterns.is_empty());
}

#[test]
fn default_guard_weight_multiplier_is_one() {
    let config = GuardConfig::default();
    assert!((config.pattern_weight_multiplier - 1.0).abs() < f32::EPSILON);
}

#[test]
fn block_threshold_above_review_threshold() {
    let config = GuardConfig::default();
    assert!(
        config.block_threshold > config.review_threshold,
        "Block threshold ({}) should be > review threshold ({})",
        config.block_threshold,
        config.review_threshold
    );
}

// ============================================================================
// Config serialization
// ============================================================================

#[test]
fn config_serializes_to_toml() {
    let config = AppConfig::default();
    let toml_str = toml::to_string_pretty(&config);
    assert!(toml_str.is_ok(), "Config should serialize to TOML");
}

#[test]
fn config_serializes_to_json() {
    let config = AppConfig::default();
    let json = serde_json::to_string_pretty(&config);
    assert!(json.is_ok(), "Config should serialize to JSON");
}

#[test]
fn guard_config_serializes_roundtrip() {
    let original = GuardConfig {
        block_threshold: 0.8,
        review_threshold: 0.3,
        pattern_weight_multiplier: 1.5,
        enable_layer0: true,
        enable_layer1: true,
        enable_layer2: true,
        enable_layer3: false,
        custom_patterns: Vec::new(),
        ignore_patterns: vec!["test.*".to_string()],
        ..GuardConfig::default()
    };

    let json = serde_json::to_string(&original).expect("serialize");
    let back: GuardConfig = serde_json::from_str(&json).expect("deserialize");

    assert!((back.block_threshold - 0.8).abs() < f32::EPSILON);
    assert!((back.review_threshold - 0.3).abs() < f32::EPSILON);
    assert!(back.enable_layer2);
    assert!(!back.enable_layer3);
    assert_eq!(back.ignore_patterns.len(), 1);
}

// ============================================================================
// Config loading from path (with temp file)
// ============================================================================

#[test]
fn loads_config_from_valid_toml() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let config_path = dir.path().join("config.toml");

    std::fs::write(
        &config_path,
        r#"
profile = "test"

[logging]
level = "debug"

[runtime]
timeout = 30
fail_fast = false

[guard]
block_threshold = 0.8
review_threshold = 0.3
"#,
    )
    .expect("write config");

    let config = AppConfig::load_from_path(&config_path).expect("load config");
    assert_eq!(config.profile, "test");
    assert_eq!(config.logging.level, "debug");
    assert_eq!(config.runtime.timeout, Some(30));
    assert!(!config.runtime.fail_fast);
    assert!((config.guard.block_threshold - 0.8).abs() < f32::EPSILON);
}

#[test]
fn loads_defaults_when_file_missing() {
    let config = AppConfig::load_from_path(std::path::Path::new("/nonexistent/config.toml"));
    assert!(
        config.is_ok(),
        "Should fall back to defaults for missing file"
    );
    let config = config.expect("defaults");
    assert_eq!(config.profile, "default");
}

#[test]
fn partial_config_fills_defaults() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let config_path = dir.path().join("config.toml");

    std::fs::write(
        &config_path,
        r#"
profile = "custom"
"#,
    )
    .expect("write config");

    let config = AppConfig::load_from_path(&config_path).expect("load config");
    assert_eq!(config.profile, "custom");
    // Other fields should have defaults
    assert_eq!(config.logging.level, "info");
    assert_eq!(config.runtime.timeout, Some(60));
}
