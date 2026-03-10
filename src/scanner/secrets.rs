use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    pub rule_name: String,
    pub file_path: String,
    pub line_number: usize,
    pub line_content: String,
    pub matched_text: String,
    pub severity: String,
    pub description: String,
}

pub struct SecretRule {
    pub name: &'static str,
    pub pattern: Regex,
    pub severity: &'static str,
    pub description: &'static str,
}

pub fn build_secret_rules() -> Vec<SecretRule> {
    vec![
        // API Keys
        SecretRule {
            name: "AWS Access Key",
            pattern: Regex::new(r"(?:AKIA|ASIA)[0-9A-Z]{16}").unwrap(),
            severity: "CRITICAL",
            description: "AWS Access Key ID found — full AWS account compromise",
        },
        SecretRule {
            name: "AWS Secret Key",
            pattern: Regex::new(r#"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key["\s:=]+[A-Za-z0-9/+=]{40}"#).unwrap(),
            severity: "CRITICAL",
            description: "AWS Secret Access Key — full AWS account compromise",
        },
        SecretRule {
            name: "GitHub Token",
            pattern: Regex::new(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}").unwrap(),
            severity: "CRITICAL",
            description: "GitHub Personal Access Token — repository/org compromise",
        },
        SecretRule {
            name: "GitHub OAuth",
            pattern: Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(),
            severity: "CRITICAL",
            description: "GitHub OAuth token",
        },
        SecretRule {
            name: "Google API Key",
            pattern: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(),
            severity: "HIGH",
            description: "Google API Key — potential GCP service abuse",
        },
        SecretRule {
            name: "Google OAuth",
            pattern: Regex::new(r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com").unwrap(),
            severity: "HIGH",
            description: "Google OAuth Client ID",
        },
        SecretRule {
            name: "Slack Token",
            pattern: Regex::new(r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*").unwrap(),
            severity: "CRITICAL",
            description: "Slack API Token — workspace access",
        },
        SecretRule {
            name: "Slack Webhook",
            pattern: Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}").unwrap(),
            severity: "HIGH",
            description: "Slack Webhook URL — channel abuse",
        },
        SecretRule {
            name: "Stripe Secret Key",
            pattern: Regex::new(r"sk_live_[0-9a-zA-Z]{24,}").unwrap(),
            severity: "CRITICAL",
            description: "Stripe Secret Key — payment infrastructure compromise",
        },
        SecretRule {
            name: "Stripe Publishable Key",
            pattern: Regex::new(r"pk_live_[0-9a-zA-Z]{24,}").unwrap(),
            severity: "MEDIUM",
            description: "Stripe Publishable Key (less sensitive but should be env var)",
        },
        SecretRule {
            name: "Twilio API Key",
            pattern: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
            severity: "HIGH",
            description: "Twilio API Key",
        },
        SecretRule {
            name: "SendGrid API Key",
            pattern: Regex::new(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}").unwrap(),
            severity: "HIGH",
            description: "SendGrid API Key — email service abuse",
        },
        SecretRule {
            name: "Mailgun API Key",
            pattern: Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap(),
            severity: "HIGH",
            description: "Mailgun API Key",
        },
        SecretRule {
            name: "Square Access Token",
            pattern: Regex::new(r"sq0atp-[0-9A-Za-z\-_]{22}").unwrap(),
            severity: "HIGH",
            description: "Square Access Token — payment compromise",
        },
        SecretRule {
            name: "Heroku API Key",
            pattern: Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").unwrap(),
            severity: "LOW",
            description: "Possible UUID/Heroku key (needs context verification)",
        },
        SecretRule {
            name: "Firebase URL",
            pattern: Regex::new(r"[a-z0-9-]+\.firebaseio\.com").unwrap(),
            severity: "MEDIUM",
            description: "Firebase Database URL — check database rules",
        },
        // Generic Secrets
        SecretRule {
            name: "Generic Password in Code",
            pattern: Regex::new(r#"(?i)(?:password|passwd|pwd|pass)\s*[:=]\s*["'][^"']{8,}["']"#).unwrap(),
            severity: "HIGH",
            description: "Hardcoded password in source code",
        },
        SecretRule {
            name: "Generic API Key",
            pattern: Regex::new(r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']"#).unwrap(),
            severity: "HIGH",
            description: "Hardcoded API key in source code",
        },
        SecretRule {
            name: "Generic Secret/Token",
            pattern: Regex::new(r#"(?i)(?:secret[_-]?key|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{16,}["']"#).unwrap(),
            severity: "HIGH",
            description: "Hardcoded secret or token in source code",
        },
        SecretRule {
            name: "Private Key Block",
            pattern: Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap(),
            severity: "CRITICAL",
            description: "Private key embedded in source — full key compromise",
        },
        SecretRule {
            name: "Connection String with Password",
            pattern: Regex::new(r#"(?i)(?:mongodb|mysql|postgres|redis|amqp|jdbc)[+a-z]*://[^:]+:[^@\s]{3,}@[^\s]+"#).unwrap(),
            severity: "CRITICAL",
            description: "Database connection string with embedded credentials",
        },
        SecretRule {
            name: "JWT Token",
            pattern: Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap(),
            severity: "HIGH",
            description: "JWT token hardcoded in source — session compromise",
        },
        // Cloud Provider Tokens
        SecretRule {
            name: "Azure Storage Key",
            pattern: Regex::new(r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*[A-Za-z0-9+/=]{44,}").unwrap(),
            severity: "CRITICAL",
            description: "Azure Storage Account Key",
        },
        SecretRule {
            name: "GCP Service Account",
            pattern: Regex::new(r#""type"\s*:\s*"service_account""#).unwrap(),
            severity: "CRITICAL",
            description: "GCP Service Account JSON key file — full project access",
        },
        SecretRule {
            name: "Telegram Bot Token",
            pattern: Regex::new(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}").unwrap(),
            severity: "HIGH",
            description: "Telegram Bot Token",
        },
        SecretRule {
            name: "Discord Bot Token",
            pattern: Regex::new(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}").unwrap(),
            severity: "HIGH",
            description: "Discord Bot Token",
        },
        // Infrastructure
        SecretRule {
            name: "SSH Password in Config",
            pattern: Regex::new(r#"(?i)sshpass\s+-p\s*["']?[^\s"']+"#).unwrap(),
            severity: "CRITICAL",
            description: "SSH password hardcoded in script",
        },
        SecretRule {
            name: ".env file reference with secrets",
            pattern: Regex::new(r#"(?i)(?:DB_PASSWORD|SECRET_KEY|API_SECRET|PRIVATE_KEY)\s*=\s*[^\s]{8,}"#).unwrap(),
            severity: "HIGH",
            description: "Secret value in environment config (check if .env is gitignored)",
        },
    ]
}

pub fn scan_for_secrets(file_path: &str, content: &str, rules: &[SecretRule]) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    // Skip binary-looking files and common false-positive paths
    let lower_path = file_path.to_lowercase();
    if lower_path.contains("node_modules")
        || lower_path.contains(".min.")
        || lower_path.contains("vendor/bundle")
        || lower_path.contains("__pycache__")
        || lower_path.ends_with(".lock")
        || lower_path.ends_with(".sum")
        || lower_path.ends_with(".svg")
        || lower_path.ends_with(".png")
        || lower_path.ends_with(".jpg")
        || lower_path.ends_with(".gif")
        || lower_path.ends_with(".ico")
        || lower_path.ends_with(".woff")
        || lower_path.ends_with(".ttf")
    {
        return findings;
    }

    for (i, line) in lines.iter().enumerate() {
        // Skip comments that are just documentation examples
        let trimmed = line.trim();
        if trimmed.starts_with("//") && trimmed.contains("example") {
            continue;
        }

        for rule in rules {
            if let Some(m) = rule.pattern.find(line) {
                // Redact the matched text for safety
                let matched = m.as_str();
                let redacted = {
                    let chars: Vec<char> = matched.chars().collect();
                    if chars.len() > 8 {
                        let prefix: String = chars[..4].iter().collect();
                        let suffix: String = chars[chars.len()-4..].iter().collect();
                        format!("{}...{}", prefix, suffix)
                    } else {
                        "***REDACTED***".to_string()
                    }
                };

                findings.push(SecretFinding {
                    rule_name: rule.name.to_string(),
                    file_path: file_path.to_string(),
                    line_number: i + 1,
                    line_content: redact_line(line),
                    matched_text: redacted,
                    severity: rule.severity.to_string(),
                    description: rule.description.to_string(),
                });
            }
        }
    }
    findings
}

fn redact_line(line: &str) -> String {
    // Show first 40 chars, redact rest if long
    let chars: Vec<char> = line.chars().collect();
    if chars.len() > 80 {
        let prefix: String = chars[..40].iter().collect();
        format!("{}...[REDACTED]", prefix)
    } else {
        line.to_string()
    }
}
