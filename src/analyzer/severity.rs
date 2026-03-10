use crate::patterns::vuln_rules::Severity;

impl Severity {
    pub fn color(&self) -> &str {
        match self {
            Severity::Critical => "red",
            Severity::High => "yellow",
            Severity::Medium => "cyan",
            Severity::Low => "blue",
            Severity::Info => "white",
        }
    }
}
