//! Tests for threat types, decisions, and report structure

use helmet_core::threats::{AttackPattern, Decision, ThreatCategory};

// ============================================================================
// Decision type
// ============================================================================

#[test]
fn decision_display() {
    assert_eq!(format!("{}", Decision::Allow), "ALLOW");
    assert_eq!(format!("{}", Decision::Review), "REVIEW");
    assert_eq!(format!("{}", Decision::Block), "BLOCK");
}

#[test]
fn decision_equality() {
    assert_eq!(Decision::Allow, Decision::Allow);
    assert_eq!(Decision::Block, Decision::Block);
    assert_ne!(Decision::Allow, Decision::Block);
}

#[test]
fn decision_serialization_roundtrip() {
    let decisions = [Decision::Allow, Decision::Review, Decision::Block];
    for d in &decisions {
        let json = serde_json::to_string(d).expect("serialize");
        let back: Decision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*d, back);
    }
}

#[test]
fn decision_serialization_screaming_snake_case() {
    let json = serde_json::to_string(&Decision::Allow).expect("serialize");
    assert_eq!(json, "\"ALLOW\"");
    let json = serde_json::to_string(&Decision::Review).expect("serialize");
    assert_eq!(json, "\"REVIEW\"");
    let json = serde_json::to_string(&Decision::Block).expect("serialize");
    assert_eq!(json, "\"BLOCK\"");
}

// ============================================================================
// AttackPattern descriptions and weights
// ============================================================================

#[test]
fn all_attack_patterns_have_descriptions() {
    let patterns = [
        AttackPattern::IgnorePrevious,
        AttackPattern::SystemPromptLeak,
        AttackPattern::DeveloperMode,
        AttackPattern::DelimiterInjection,
        AttackPattern::Jailbreak,
        AttackPattern::Dan,
        AttackPattern::RoleplayAttack,
        AttackPattern::PersonaSwitch,
        AttackPattern::FunctionCall,
        AttackPattern::ToolAbuse,
        AttackPattern::ExfiltrationAttempt,
        AttackPattern::DataLeakage,
        AttackPattern::Base64Injection,
        AttackPattern::UnicodeObfuscation,
        AttackPattern::HiddenInstructions,
        AttackPattern::EncodedPayload,
        AttackPattern::HarmfulContent,
        AttackPattern::SafetyBypass,
    ];

    for p in &patterns {
        let desc = p.description();
        assert!(!desc.is_empty(), "{:?} has empty description", p);
        assert!(desc.len() > 5, "{:?} description too short: {}", p, desc);
    }
}

#[test]
fn all_attack_patterns_have_valid_weights() {
    let patterns = [
        AttackPattern::IgnorePrevious,
        AttackPattern::SystemPromptLeak,
        AttackPattern::DeveloperMode,
        AttackPattern::DelimiterInjection,
        AttackPattern::Jailbreak,
        AttackPattern::Dan,
        AttackPattern::RoleplayAttack,
        AttackPattern::PersonaSwitch,
        AttackPattern::FunctionCall,
        AttackPattern::ToolAbuse,
        AttackPattern::ExfiltrationAttempt,
        AttackPattern::DataLeakage,
        AttackPattern::Base64Injection,
        AttackPattern::UnicodeObfuscation,
        AttackPattern::HiddenInstructions,
        AttackPattern::EncodedPayload,
        AttackPattern::HarmfulContent,
        AttackPattern::SafetyBypass,
    ];

    for p in &patterns {
        let w = p.severity_weight();
        assert!(
            (0.0..=1.0).contains(&w),
            "{:?} weight {} out of range",
            p,
            w
        );
    }
}

#[test]
fn critical_patterns_have_highest_weight() {
    assert_eq!(AttackPattern::SystemPromptLeak.severity_weight(), 1.0);
    assert_eq!(AttackPattern::ExfiltrationAttempt.severity_weight(), 1.0);
    assert_eq!(AttackPattern::DataLeakage.severity_weight(), 1.0);
}

#[test]
fn high_patterns_weight_above_medium() {
    let high = AttackPattern::IgnorePrevious.severity_weight();
    let medium = AttackPattern::DelimiterInjection.severity_weight();
    assert!(
        high > medium,
        "IgnorePrevious ({}) should be > DelimiterInjection ({})",
        high,
        medium
    );
}

#[test]
fn attack_pattern_serialization_roundtrip() {
    let patterns = [
        AttackPattern::IgnorePrevious,
        AttackPattern::Dan,
        AttackPattern::Base64Injection,
    ];

    for p in &patterns {
        let json = serde_json::to_string(p).expect("serialize");
        let back: AttackPattern = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*p, back);
    }
}

#[test]
fn attack_pattern_serializes_snake_case() {
    let json = serde_json::to_string(&AttackPattern::IgnorePrevious).expect("serialize");
    assert_eq!(json, "\"ignore_previous\"");

    let json = serde_json::to_string(&AttackPattern::SystemPromptLeak).expect("serialize");
    assert_eq!(json, "\"system_prompt_leak\"");
}

// ============================================================================
// ThreatCategory (S1-S14 from HipoCap)
// ============================================================================

#[test]
fn all_threat_categories_have_codes() {
    let categories = [
        ThreatCategory::ViolentCrimes,
        ThreatCategory::NonViolentCrimes,
        ThreatCategory::SexCrimes,
        ThreatCategory::ChildExploitation,
        ThreatCategory::Defamation,
        ThreatCategory::SpecializedAdvice,
        ThreatCategory::Privacy,
        ThreatCategory::IntellectualProperty,
        ThreatCategory::Weapons,
        ThreatCategory::Hate,
        ThreatCategory::SelfHarm,
        ThreatCategory::SexualContent,
        ThreatCategory::Elections,
        ThreatCategory::CodeAbuse,
    ];

    for (i, cat) in categories.iter().enumerate() {
        let code = cat.code();
        let expected = format!("S{}", i + 1);
        assert_eq!(code, expected, "{:?} has wrong code: {}", cat, code);
    }
}

#[test]
fn all_threat_categories_have_descriptions() {
    let categories = [
        ThreatCategory::ViolentCrimes,
        ThreatCategory::NonViolentCrimes,
        ThreatCategory::SexCrimes,
        ThreatCategory::ChildExploitation,
        ThreatCategory::Defamation,
        ThreatCategory::SpecializedAdvice,
        ThreatCategory::Privacy,
        ThreatCategory::IntellectualProperty,
        ThreatCategory::Weapons,
        ThreatCategory::Hate,
        ThreatCategory::SelfHarm,
        ThreatCategory::SexualContent,
        ThreatCategory::Elections,
        ThreatCategory::CodeAbuse,
    ];

    for cat in &categories {
        let desc = cat.description();
        assert!(!desc.is_empty(), "{:?} has empty description", cat);
    }
}

#[test]
fn threat_category_covers_all_14() {
    // Ensure we have exactly S1-S14
    assert_eq!(ThreatCategory::ViolentCrimes.code(), "S1");
    assert_eq!(ThreatCategory::CodeAbuse.code(), "S14");
}
