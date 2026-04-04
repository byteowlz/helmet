//! Helmet - Fast prompt injection detection library
//!
//! A multi-layer defense system for detecting prompt injection attacks:
//! - Layer 0: Preprocessing (unicode normalization, encoding detection)
//! - Layer 1: Fast heuristics (regex patterns, keyword matching)
//! - Layer 2: Lightweight classifier (embedding + linear model)
//! - Layer 3: LLM analysis (optional, for edge cases)
//!
//! # Quick start
//!
//! ```rust,no_run
//! use helmet_core::{Guard, policy::PolicyEngine};
//!
//! let guard = Guard::new().unwrap();
//! let report = guard.check("user input here");
//!
//! // Apply a policy to decide what to do
//! let policy = PolicyEngine::new();
//! let result = policy.apply("user input here", &report);
//! // result.output is the safe output text
//! // result.action tells you what happened (Passthrough, Redact, Reject, etc.)
//! ```
//!
//! # Builder API
//!
//! ```rust,no_run
//! use helmet_core::GuardBuilder;
//! use helmet_core::policy::PolicyConfig;
//!
//! let guard = GuardBuilder::new()
//!     .block_threshold(0.8)
//!     .review_threshold(0.3)
//!     .add_pattern("internal_leak", r"(?:internal|confidential)\s+api", 0.9)
//!     .ignore_pattern(r"security\s+researcher")
//!     .policy(PolicyConfig::strict())
//!     .build()
//!     .unwrap();
//!
//! let result = guard.check_and_apply("user input");
//! ```

pub mod config;
pub mod error;
pub mod paths;
pub mod policy;

// Detection layers
pub mod heuristics;
pub mod preprocess;
pub mod threats;

// Re-exports
pub use config::{
    AppConfig, CustomPattern, GuardConfig, LoggingConfig, PathsConfig, RuntimeConfig,
};
pub use error::{CoreError, Result};
pub use heuristics::{HeuristicResult, HeuristicScanner, PatternMatch};
pub use paths::{AppPaths, default_cache_dir};
pub use policy::{Action, PolicyConfig, PolicyEngine, PolicyResult};
pub use preprocess::{CanonicalizedText, ObfuscationReport, Preprocessor};
pub use threats::{AttackPattern, Decision, DeterministicStats, ThreatCategory, ThreatReport};

/// Application name used for config directories and environment prefix.
pub const APP_NAME: &str = "helmet";

/// Returns the environment variable prefix for this application.
#[must_use]
pub fn env_prefix() -> String {
    APP_NAME
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Returns the default parallelism based on available CPU cores.
#[must_use]
pub fn default_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
}

/// Main guard interface for prompt injection detection
pub struct Guard {
    preprocessor: Preprocessor,
    scanner: HeuristicScanner,
    config: GuardConfig,
    policy: PolicyEngine,
}

impl Guard {
    /// Create a new Guard with default configuration
    ///
    /// # Errors
    /// Returns error if pattern compilation fails
    pub fn new() -> Result<Self> {
        Self::with_config(GuardConfig::default())
    }

    /// Create a new Guard with custom configuration
    ///
    /// # Errors
    /// Returns error if pattern compilation fails
    pub fn with_config(config: GuardConfig) -> Result<Self> {
        let preprocessor = Preprocessor::new();
        let scanner = HeuristicScanner::new(&config)?;
        let policy = PolicyEngine::with_config(config.policy.clone());

        Ok(Self {
            preprocessor,
            scanner,
            policy,
            config,
        })
    }

    /// Create a new Guard with custom configuration and policy
    ///
    /// # Errors
    /// Returns error if pattern compilation fails
    pub fn with_config_and_policy(
        config: GuardConfig,
        policy_config: PolicyConfig,
    ) -> Result<Self> {
        let preprocessor = Preprocessor::new();
        let scanner = HeuristicScanner::new(&config)?;

        Ok(Self {
            preprocessor,
            scanner,
            policy: PolicyEngine::with_config(policy_config),
            config,
        })
    }

    /// Check input for prompt injection attempts
    ///
    /// Returns a `ThreatReport` with the decision and details
    #[must_use]
    pub fn check(&self, input: &str) -> ThreatReport {
        let start = std::time::Instant::now();

        // Layer 0: Preprocessing
        let canonical = self.preprocessor.canonicalize(input);
        let mut reason_codes = Vec::new();

        let (budgeted_text, estimated_tokens, token_budget_truncated) = self
            .preprocessor
            .enforce_token_budget(&canonical.normalized, self.config.max_input_tokens);
        if token_budget_truncated {
            reason_codes.push("TOKEN_BUDGET_TRUNCATED".to_string());
        }

        let obfuscation = self.preprocessor.obfuscation_signals(&budgeted_text);

        // Layer 1: Heuristic scanning
        let heuristic_result = self.scanner.scan(&budgeted_text);

        let encoded_segments = obfuscation.base64_segments.len()
            + obfuscation.hex_segments.len()
            + obfuscation.url_encoded_segments.len();

        let decoded_segments = self.preprocessor.decode_suspicious_segments(
            &budgeted_text,
            &obfuscation,
            self.config.max_decoded_segments,
            self.config.max_decoded_bytes,
        );

        let mut decoded_max_score = 0.0f32;
        let mut decoded_flagged = 0usize;
        for segment in &decoded_segments {
            let decoded_scan = self.scanner.scan(&segment.decoded);
            if decoded_scan.score > 0.0 {
                decoded_flagged += 1;
                decoded_max_score = decoded_max_score.max(decoded_scan.score);
            }
        }
        if decoded_flagged > 0 {
            reason_codes.push("DECODED_SEGMENT_FLAGGED".to_string());
        }

        // Combine scores
        let obfuscation_score = obfuscation.risk_score();
        let base_score = (heuristic_result.score * 0.7) + (obfuscation_score * 0.3);
        let combined_score = base_score.max(decoded_max_score * 0.9).min(1.0);

        let token_char_ratio = if budgeted_text.is_empty() {
            0.0
        } else {
            estimated_tokens as f32 / budgeted_text.chars().count() as f32
        };

        // Deterministic hard stops
        let hard_block = canonical.stripped_chars >= self.config.strip_block_threshold
            || encoded_segments >= self.config.encoded_block_threshold
            || token_char_ratio > self.config.max_token_char_ratio;

        if canonical.stripped_chars >= self.config.strip_block_threshold {
            reason_codes.push("INVISIBLE_STRIP_THRESHOLD".to_string());
        }
        if encoded_segments >= self.config.encoded_block_threshold {
            reason_codes.push("ENCODED_SEGMENT_THRESHOLD".to_string());
        }
        if token_char_ratio > self.config.max_token_char_ratio {
            reason_codes.push("TOKEN_CHAR_RATIO_THRESHOLD".to_string());
        }

        // Make decision
        let decision = if hard_block || combined_score >= self.config.block_threshold {
            Decision::Block
        } else if combined_score >= self.config.review_threshold {
            Decision::Review
        } else {
            Decision::Allow
        };

        ThreatReport {
            decision,
            score: combined_score,
            deterministic_stats: DeterministicStats {
                stripped_chars: canonical.stripped_chars,
                estimated_tokens,
                token_budget_truncated,
                encoded_segments,
                decoded_segments_scanned: decoded_segments.len(),
                decoded_segments_flagged: decoded_flagged,
                token_char_ratio,
            },
            reason_codes,
            obfuscation,
            heuristic_result,
            latency: start.elapsed(),
            layers_run: vec![
                "preprocess".into(),
                "heuristics".into(),
                "decode_rescan".into(),
            ],
        }
    }

    /// Check input and apply the configured policy in one step
    ///
    /// Returns a `PolicyResult` with the action taken and the output text
    #[must_use]
    pub fn check_and_apply(&self, input: &str) -> PolicyResult {
        let report = self.check(input);
        self.policy.apply(input, &report)
    }

    /// Check with additional context (function name, user role, etc.)
    #[must_use]
    pub fn check_with_context(&self, input: &str, context: &AnalysisContext) -> ThreatReport {
        let mut report = self.check(input);

        // Boost score if context suggests higher risk
        if context.is_function_output {
            report.score *= 1.2;
            report.score = report.score.min(1.0);
        }

        // Re-evaluate decision with adjusted score
        report.decision = if report.score >= self.config.block_threshold {
            Decision::Block
        } else if report.score >= self.config.review_threshold {
            Decision::Review
        } else {
            Decision::Allow
        };

        report
    }

    /// Get a reference to the guard's policy engine
    #[must_use]
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Get a reference to the guard's configuration
    #[must_use]
    pub fn config(&self) -> &GuardConfig {
        &self.config
    }
}

/// Additional context for analysis
#[derive(Debug, Clone, Default)]
pub struct AnalysisContext {
    /// Name of the function that produced this output
    pub function_name: Option<String>,
    /// Whether this is output from a function (vs direct user input)
    pub is_function_output: bool,
    /// User's role/permissions
    pub user_role: Option<String>,
    /// Original user query that triggered this
    pub user_query: Option<String>,
}

/// Fluent builder for constructing a Guard with custom configuration
///
/// ```rust,no_run
/// use helmet_core::GuardBuilder;
/// use helmet_core::policy::PolicyConfig;
///
/// let guard = GuardBuilder::new()
///     .block_threshold(0.8)
///     .review_threshold(0.3)
///     .pattern_weight_multiplier(1.5)
///     .add_pattern("api_leak", r"internal\s+api\s+key", 0.9)
///     .ignore_pattern(r"penetration\s+test")
///     .policy(PolicyConfig::strict())
///     .build()
///     .unwrap();
/// ```
pub struct GuardBuilder {
    config: GuardConfig,
    policy_config: PolicyConfig,
    extra_patterns: Vec<CustomPattern>,
    extra_ignore: Vec<String>,
}

impl GuardBuilder {
    /// Create a new builder with default settings
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: GuardConfig::default(),
            policy_config: PolicyConfig::default(),
            extra_patterns: Vec::new(),
            extra_ignore: Vec::new(),
        }
    }

    /// Start from an existing GuardConfig
    #[must_use]
    pub fn from_config(config: GuardConfig) -> Self {
        Self {
            config,
            policy_config: PolicyConfig::default(),
            extra_patterns: Vec::new(),
            extra_ignore: Vec::new(),
        }
    }

    /// Set the block threshold (0.0 - 1.0)
    #[must_use]
    pub fn block_threshold(mut self, threshold: f32) -> Self {
        self.config.block_threshold = threshold;
        self
    }

    /// Set the review threshold (0.0 - 1.0)
    #[must_use]
    pub fn review_threshold(mut self, threshold: f32) -> Self {
        self.config.review_threshold = threshold;
        self
    }

    /// Set the pattern weight multiplier
    #[must_use]
    pub fn pattern_weight_multiplier(mut self, multiplier: f32) -> Self {
        self.config.pattern_weight_multiplier = multiplier;
        self
    }

    /// Add a custom detection pattern
    #[must_use]
    pub fn add_pattern(mut self, name: &str, regex: &str, weight: f32) -> Self {
        self.extra_patterns.push(CustomPattern {
            name: name.to_string(),
            regex: regex.to_string(),
            weight,
            description: None,
        });
        self
    }

    /// Add a pattern to ignore (for reducing false positives)
    #[must_use]
    pub fn ignore_pattern(mut self, regex: &str) -> Self {
        self.extra_ignore.push(regex.to_string());
        self
    }

    /// Set the policy configuration
    #[must_use]
    pub fn policy(mut self, policy: PolicyConfig) -> Self {
        self.policy_config = policy;
        self
    }

    /// Set the action for blocked inputs
    #[must_use]
    pub fn on_block(mut self, action: Action) -> Self {
        self.policy_config.on_block = action;
        self
    }

    /// Set the action for inputs requiring review
    #[must_use]
    pub fn on_review(mut self, action: Action) -> Self {
        self.policy_config.on_review = action;
        self
    }

    /// Set the rejection message
    #[must_use]
    pub fn reject_message(mut self, msg: &str) -> Self {
        self.policy_config.reject_message = msg.to_string();
        self
    }

    /// Set the redaction message
    #[must_use]
    pub fn redact_message(mut self, msg: &str) -> Self {
        self.policy_config.redact_message = msg.to_string();
        self
    }

    /// Load additional patterns from a TOML file
    ///
    /// Expected format:
    /// ```toml
    /// [[patterns]]
    /// name = "my_pattern"
    /// regex = "some\\s+regex"
    /// weight = 0.8
    /// description = "What this detects"
    /// ```
    ///
    /// # Errors
    /// Returns error if file cannot be read or parsed
    pub fn load_patterns_file(
        mut self,
        path: &std::path::Path,
    ) -> std::result::Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading pattern file {}: {}", path.display(), e))?;

        #[derive(serde::Deserialize)]
        struct PatternFile {
            #[serde(default)]
            patterns: Vec<CustomPattern>,
            #[serde(default)]
            ignore: Vec<String>,
        }

        let file: PatternFile = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("parsing pattern file {}: {}", path.display(), e))?;

        self.extra_patterns.extend(file.patterns);
        self.extra_ignore.extend(file.ignore);
        Ok(self)
    }

    /// Build the Guard
    ///
    /// # Errors
    /// Returns error if pattern compilation fails
    pub fn build(mut self) -> Result<Guard> {
        // Merge extra patterns/ignores into config
        self.config.custom_patterns.extend(self.extra_patterns);
        self.config.ignore_patterns.extend(self.extra_ignore);

        Guard::with_config_and_policy(self.config, self.policy_config)
    }
}

impl Default for GuardBuilder {
    fn default() -> Self {
        Self::new()
    }
}
