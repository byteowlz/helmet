//! Configuration types and loading for the application.

use std::path::Path;

use anyhow::Result;
use config::{Config, Environment, File, FileFormat};
use serde::{Deserialize, Serialize};

use crate::paths::{expand_str_path, write_default_config};
use crate::policy::PolicyConfig;
use crate::{AppPaths, default_parallelism, env_prefix};

/// Main application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub profile: String,
    pub logging: LoggingConfig,
    pub runtime: RuntimeConfig,
    pub paths: PathsConfig,
    pub guard: GuardConfig,
}

impl AppConfig {
    /// Override the profile if a value is provided.
    #[must_use]
    pub fn with_profile_override(mut self, profile: Option<String>) -> Self {
        if let Some(profile) = profile {
            self.profile = profile;
        }
        self
    }

    /// Load configuration from file and environment, creating defaults if needed.
    ///
    /// # Errors
    /// Returns error if config loading or parsing fails
    pub fn load(paths: &AppPaths, dry_run: bool) -> Result<Self> {
        if !paths.config_file.exists() {
            if dry_run {
                log::info!(
                    "dry-run: would create default config at {}",
                    paths.config_file.display()
                );
            } else {
                write_default_config(&paths.config_file)?;
            }
        }

        Self::load_from_path(&paths.config_file)
    }

    /// Load configuration from a specific path.
    ///
    /// # Errors
    /// Returns error if config file is invalid
    pub fn load_from_path(config_file: &Path) -> Result<Self> {
        let env_prefix = env_prefix();
        let built = Config::builder()
            .set_default("profile", "default")?
            .set_default("logging.level", "info")?
            .set_default("runtime.parallelism", default_parallelism() as i64)?
            .set_default("runtime.timeout", 60_i64)?
            .set_default("runtime.fail_fast", true)?
            // Guard defaults
            .set_default("guard.block_threshold", 0.7)?
            .set_default("guard.review_threshold", 0.4)?
            .set_default("guard.pattern_weight_multiplier", 1.0)?
            .set_default("guard.enable_layer0", true)?
            .set_default("guard.enable_layer1", true)?
            .set_default("guard.enable_layer2", false)?
            .set_default("guard.enable_layer3", false)?
            .set_default("guard.max_input_tokens", 4096_i64)?
            .set_default("guard.max_decoded_bytes", 8192_i64)?
            .set_default("guard.max_decoded_segments", 32_i64)?
            .set_default("guard.strip_block_threshold", 24_i64)?
            .set_default("guard.encoded_block_threshold", 6_i64)?
            .set_default("guard.max_token_char_ratio", 1.8)?
            .add_source(
                File::from(config_file)
                    .format(FileFormat::Toml)
                    .required(false),
            )
            .add_source(Environment::with_prefix(env_prefix.as_str()).separator("__"))
            .build()?;

        let mut config: AppConfig = built.try_deserialize()?;

        if let Some(ref file) = config.logging.file {
            let expanded = expand_str_path(file)?;
            config.logging.file = Some(expanded.display().to_string());
        }

        Ok(config)
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            logging: LoggingConfig::default(),
            runtime: RuntimeConfig::default(),
            paths: PathsConfig::default(),
            guard: GuardConfig::default(),
        }
    }
}

/// Guard configuration for prompt injection detection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardConfig {
    /// Score threshold above which to block (0.0 - 1.0)
    pub block_threshold: f32,
    /// Score threshold above which to require review (0.0 - 1.0)
    pub review_threshold: f32,
    /// Multiplier for pattern weights (for tuning sensitivity)
    pub pattern_weight_multiplier: f32,
    /// Enable Layer 0 (preprocessing)
    pub enable_layer0: bool,
    /// Enable Layer 1 (heuristics)
    pub enable_layer1: bool,
    /// Enable Layer 2 (classifier) - requires mmry or local model
    pub enable_layer2: bool,
    /// Enable Layer 3 (LLM analysis) - requires API access
    pub enable_layer3: bool,
    /// Max token budget for deterministic layer input.
    pub max_input_tokens: usize,
    /// Max bytes to decode from suspicious encoded segments.
    pub max_decoded_bytes: usize,
    /// Max number of suspicious segments to decode and rescan.
    pub max_decoded_segments: usize,
    /// Hard block threshold for stripped invisible/control characters.
    pub strip_block_threshold: usize,
    /// Hard block threshold for encoded segments detected in a single payload.
    pub encoded_block_threshold: usize,
    /// Hard block threshold for estimated token-per-char ratio.
    pub max_token_char_ratio: f32,
    /// Custom patterns to add (regex)
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,
    /// Patterns to ignore (for reducing false positives)
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    /// Policy for what to do with detected threats
    #[serde(default)]
    pub policy: PolicyConfig,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            block_threshold: 0.7,
            review_threshold: 0.4,
            pattern_weight_multiplier: 1.0,
            enable_layer0: true,
            enable_layer1: true,
            enable_layer2: false,
            enable_layer3: false,
            max_input_tokens: 4096,
            max_decoded_bytes: 8192,
            max_decoded_segments: 32,
            strip_block_threshold: 24,
            encoded_block_threshold: 6,
            max_token_char_ratio: 1.8,
            custom_patterns: Vec::new(),
            ignore_patterns: Vec::new(),
            policy: PolicyConfig::default(),
        }
    }
}

/// Custom pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    /// Name for the pattern
    pub name: String,
    /// Regex pattern
    pub regex: String,
    /// Weight (0.0 - 1.0)
    pub weight: f32,
    /// Description
    #[serde(default)]
    pub description: Option<String>,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
        }
    }
}

/// Runtime behavior configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    pub parallelism: Option<usize>,
    pub timeout: Option<u64>,
    pub fail_fast: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            parallelism: None,
            timeout: Some(60),
            fail_fast: true,
        }
    }
}

/// Path override configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PathsConfig {
    pub data_dir: Option<String>,
    pub state_dir: Option<String>,
}
