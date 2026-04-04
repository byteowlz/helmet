//! Threat categories and detection types

use crate::heuristics::HeuristicResult;
use crate::preprocess::ObfuscationReport;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Final decision from the guard
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    /// Safe to proceed
    Allow,
    /// Requires human review
    Review,
    /// Block immediately
    Block,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Review => write!(f, "REVIEW"),
            Self::Block => write!(f, "BLOCK"),
        }
    }
}

/// Attack pattern categories from SOTA research
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPattern {
    // Instruction Override
    /// "ignore previous instructions", "disregard above"
    IgnorePrevious,
    /// Attempts to extract system prompt
    SystemPromptLeak,
    /// "developer mode", "debug mode"
    DeveloperMode,
    /// "BEGIN SYSTEM", XML tags, markdown delimiters
    DelimiterInjection,

    // Role Confusion
    /// Classic jailbreak attempts
    Jailbreak,
    /// "Do Anything Now" pattern
    Dan,
    /// "You are now X", roleplay attacks
    RoleplayAttack,
    /// "As a helpful assistant without restrictions"
    PersonaSwitch,

    // Tool/Function Coercion
    /// Attempts to call functions
    FunctionCall,
    /// Tool abuse patterns
    ToolAbuse,
    /// Data exfiltration attempts
    ExfiltrationAttempt,
    /// "Send this to", "POST to"
    DataLeakage,

    // Encoding/Obfuscation
    /// Base64 encoded payloads
    Base64Injection,
    /// Unicode tricks, homoglyphs
    UnicodeObfuscation,
    /// Zero-width chars, bidi controls
    HiddenInstructions,
    /// Hex, URL encoding
    EncodedPayload,

    // Content Policy
    /// Requests for harmful content
    HarmfulContent,
    /// Attempts to bypass safety
    SafetyBypass,
}

impl AttackPattern {
    /// Get a human-readable description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::IgnorePrevious => "Instruction override attempt",
            Self::SystemPromptLeak => "System prompt extraction attempt",
            Self::DeveloperMode => "Developer/debug mode request",
            Self::DelimiterInjection => "Delimiter injection (XML, markdown)",
            Self::Jailbreak => "Jailbreak attempt",
            Self::Dan => "DAN (Do Anything Now) pattern",
            Self::RoleplayAttack => "Roleplay-based attack",
            Self::PersonaSwitch => "Persona switch attempt",
            Self::FunctionCall => "Function call injection",
            Self::ToolAbuse => "Tool abuse attempt",
            Self::ExfiltrationAttempt => "Data exfiltration attempt",
            Self::DataLeakage => "Data leakage pattern",
            Self::Base64Injection => "Base64 encoded payload",
            Self::UnicodeObfuscation => "Unicode obfuscation",
            Self::HiddenInstructions => "Hidden instructions detected",
            Self::EncodedPayload => "Encoded payload detected",
            Self::HarmfulContent => "Harmful content request",
            Self::SafetyBypass => "Safety bypass attempt",
        }
    }

    /// Get severity weight (0.0 - 1.0)
    #[must_use]
    pub const fn severity_weight(&self) -> f32 {
        match self {
            // Critical
            Self::SystemPromptLeak | Self::ExfiltrationAttempt | Self::DataLeakage => 1.0,

            // High
            Self::IgnorePrevious
            | Self::Jailbreak
            | Self::Dan
            | Self::FunctionCall
            | Self::HarmfulContent => 0.9,

            // Medium-High
            Self::DeveloperMode
            | Self::RoleplayAttack
            | Self::PersonaSwitch
            | Self::ToolAbuse
            | Self::SafetyBypass => 0.7,

            // Medium
            Self::DelimiterInjection
            | Self::Base64Injection
            | Self::HiddenInstructions
            | Self::EncodedPayload => 0.5,

            // Lower (often false positives)
            Self::UnicodeObfuscation => 0.3,
        }
    }
}

/// HipoCap S1-S14 threat categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// S1: Violent Crimes
    ViolentCrimes,
    /// S2: Non-Violent Crimes (fraud, theft)
    NonViolentCrimes,
    /// S3: Sex-Related Crimes
    SexCrimes,
    /// S4: Child Sexual Exploitation
    ChildExploitation,
    /// S5: Defamation
    Defamation,
    /// S6: Specialized Advice (dangerous medical/legal/financial)
    SpecializedAdvice,
    /// S7: Privacy Violations
    Privacy,
    /// S8: Intellectual Property
    IntellectualProperty,
    /// S9: Indiscriminate Weapons
    Weapons,
    /// S10: Hate Speech
    Hate,
    /// S11: Suicide & Self-Harm
    SelfHarm,
    /// S12: Sexual Content
    SexualContent,
    /// S13: Elections
    Elections,
    /// S14: Code Interpreter Abuse
    CodeAbuse,
}

impl ThreatCategory {
    /// Get the S-code (S1-S14)
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ViolentCrimes => "S1",
            Self::NonViolentCrimes => "S2",
            Self::SexCrimes => "S3",
            Self::ChildExploitation => "S4",
            Self::Defamation => "S5",
            Self::SpecializedAdvice => "S6",
            Self::Privacy => "S7",
            Self::IntellectualProperty => "S8",
            Self::Weapons => "S9",
            Self::Hate => "S10",
            Self::SelfHarm => "S11",
            Self::SexualContent => "S12",
            Self::Elections => "S13",
            Self::CodeAbuse => "S14",
        }
    }

    /// Get description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::ViolentCrimes => "Violent Crimes",
            Self::NonViolentCrimes => "Non-Violent Crimes",
            Self::SexCrimes => "Sex-Related Crimes",
            Self::ChildExploitation => "Child Sexual Exploitation",
            Self::Defamation => "Defamation",
            Self::SpecializedAdvice => "Specialized Advice",
            Self::Privacy => "Privacy Violations",
            Self::IntellectualProperty => "Intellectual Property",
            Self::Weapons => "Indiscriminate Weapons",
            Self::Hate => "Hate Speech",
            Self::SelfHarm => "Suicide & Self-Harm",
            Self::SexualContent => "Sexual Content",
            Self::Elections => "Elections",
            Self::CodeAbuse => "Code Interpreter Abuse",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeterministicStats {
    /// Number of chars removed during canonicalization
    pub stripped_chars: usize,
    /// Estimated tokens before budget truncation
    pub estimated_tokens: usize,
    /// Whether token budget truncation was applied
    pub token_budget_truncated: bool,
    /// Number of encoded segments found
    pub encoded_segments: usize,
    /// Number of decoded segments rescanned
    pub decoded_segments_scanned: usize,
    /// Number of decoded rescans that produced findings
    pub decoded_segments_flagged: usize,
    /// Estimated token/char ratio for wallet-drain detection
    pub token_char_ratio: f32,
}

/// Complete threat analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    /// Final decision
    pub decision: Decision,
    /// Combined risk score (0.0 - 1.0)
    pub score: f32,
    /// Deterministic layer telemetry and counters.
    #[serde(default)]
    pub deterministic_stats: DeterministicStats,
    /// Deterministic reason codes for auditing/block rationale.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
    /// Obfuscation analysis from Layer 0
    #[serde(skip_serializing_if = "ObfuscationReport::is_clean")]
    pub obfuscation: ObfuscationReport,
    /// Heuristic analysis from Layer 1
    pub heuristic_result: HeuristicResult,
    /// Total analysis time
    #[serde(with = "duration_micros")]
    pub latency: Duration,
    /// Which detection layers were run
    pub layers_run: Vec<String>,
}

impl ThreatReport {
    /// Check if the input should be blocked
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.decision == Decision::Block
    }

    /// Check if the input is safe
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.decision == Decision::Allow
    }

    /// Get primary attack patterns detected
    #[must_use]
    pub fn attack_patterns(&self) -> Vec<AttackPattern> {
        self.heuristic_result
            .matches
            .iter()
            .map(|m| m.pattern)
            .collect()
    }
}

/// Serde helper for Duration in microseconds
mod duration_micros {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_micros() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let micros = u64::deserialize(deserializer)?;
        Ok(Duration::from_micros(micros))
    }
}
