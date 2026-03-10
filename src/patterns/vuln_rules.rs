use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 10,
            Severity::High => 8,
            Severity::Medium => 5,
            Severity::Low => 3,
            Severity::Info => 1,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnCategory {
    Injection,
    XSS,
    CommandInjection,
    PathTraversal,
    InsecureDeserialization,
    HardcodedSecret,
    WeakCrypto,
    SSRF,
    XXE,
    BrokenAuth,
    InsecureFileOps,
    BufferOverflow,
    UseAfterFree,
    FormatString,
    RaceCondition,
    MemoryLeak,
    IntegerOverflow,
    InsecureRandom,
    OpenRedirect,
    CSRF,
    IDOR,
    InfoDisclosure,
    MassAssignment,
    InsecureDependency,
    PrivilegeEscalation,
    Misconfiguration,
    PrototypePollution,
    TemplateInjection,
    LDAPInjection,
    RegexDoS,
    InsecureTLS,
}

impl std::fmt::Display for VulnCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Clone)]
pub struct VulnRule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub category: VulnCategory,
    pub severity: Severity,
    pub pattern: &'static str,
    pub languages: &'static [&'static str],
    pub cwe: &'static str,
    pub remediation: &'static str,
    pub false_positive_hint: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub description: String,
    pub category: VulnCategory,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: usize,
    pub line_content: String,
    pub matched_text: String,
    pub cwe: String,
    pub remediation: String,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
    pub fingerprint: String,
    pub confidence: String,
}

pub struct CompiledRule {
    pub rule: &'static VulnRule,
    pub regex: Regex,
}

pub fn compile_rules(rules: &'static [VulnRule]) -> Vec<CompiledRule> {
    rules
        .iter()
        .filter_map(|r| {
            Regex::new(r.pattern).ok().map(|regex| CompiledRule {
                rule: r,
                regex,
            })
        })
        .collect()
}
