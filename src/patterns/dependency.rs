use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepFinding {
    pub file_path: String,
    pub package_manager: String,
    pub package_name: String,
    pub version: String,
    pub vulnerability: String,
    pub severity: String,
    pub advice: String,
}

pub struct DependencyScanner {
    known_vulns: HashMap<&'static str, Vec<KnownVuln>>,
    risky_patterns: Vec<RiskyDep>,
    // Pre-compiled regexes for dep file scanning
    re_npm: Regex,
    re_npm_lock: Regex,
    re_python: Regex,
    re_maven: Regex,
    re_gradle: Regex,
    re_go: Regex,
    re_gem: Regex,
    re_cargo: Regex,
    re_cargo2: Regex,
    re_composer: Regex,
}

struct KnownVuln {
    package: &'static str,
    affected_below: &'static str,
    cve: &'static str,
    severity: &'static str,
    description: &'static str,
}

struct RiskyDep {
    pattern: Regex,
    description: &'static str,
    severity: &'static str,
}

impl DependencyScanner {
    pub fn new() -> Self {
        let mut known_vulns: HashMap<&'static str, Vec<KnownVuln>> = HashMap::new();

        // NPM / JavaScript known vulnerable packages
        known_vulns.insert("npm", vec![
            KnownVuln { package: "lodash", affected_below: "4.17.21", cve: "CVE-2021-23337", severity: "HIGH", description: "Command Injection via template" },
            KnownVuln { package: "minimist", affected_below: "1.2.6", cve: "CVE-2021-44906", severity: "CRITICAL", description: "Prototype Pollution" },
            KnownVuln { package: "node-forge", affected_below: "1.3.0", cve: "CVE-2022-24771", severity: "HIGH", description: "Signature verification bypass" },
            KnownVuln { package: "express", affected_below: "4.19.2", cve: "CVE-2024-29041", severity: "MEDIUM", description: "Open Redirect" },
            KnownVuln { package: "jsonwebtoken", affected_below: "9.0.0", cve: "CVE-2022-23529", severity: "HIGH", description: "Insecure key handling" },
            KnownVuln { package: "tar", affected_below: "6.1.9", cve: "CVE-2021-37701", severity: "HIGH", description: "Arbitrary file creation/overwrite" },
            KnownVuln { package: "glob-parent", affected_below: "5.1.2", cve: "CVE-2020-28469", severity: "HIGH", description: "ReDoS" },
            KnownVuln { package: "axios", affected_below: "1.6.0", cve: "CVE-2023-45857", severity: "MEDIUM", description: "CSRF token exposure" },
            KnownVuln { package: "xml2js", affected_below: "0.5.0", cve: "CVE-2023-0842", severity: "MEDIUM", description: "Prototype pollution" },
            KnownVuln { package: "semver", affected_below: "7.5.2", cve: "CVE-2022-25883", severity: "MEDIUM", description: "ReDoS" },
            KnownVuln { package: "tough-cookie", affected_below: "4.1.3", cve: "CVE-2023-26136", severity: "MEDIUM", description: "Prototype pollution" },
            KnownVuln { package: "word-wrap", affected_below: "1.2.4", cve: "CVE-2023-26115", severity: "MEDIUM", description: "ReDoS" },
            KnownVuln { package: "serialize-javascript", affected_below: "3.1.0", cve: "CVE-2020-7660", severity: "CRITICAL", description: "Remote code execution" },
            KnownVuln { package: "underscore", affected_below: "1.13.6", cve: "CVE-2021-23358", severity: "HIGH", description: "Arbitrary code execution via template" },
        ]);

        // Python PyPI known vulnerable packages
        known_vulns.insert("pip", vec![
            KnownVuln { package: "django", affected_below: "4.2.11", cve: "CVE-2024-27351", severity: "HIGH", description: "ReDoS in truncatewords_html" },
            KnownVuln { package: "flask", affected_below: "2.3.2", cve: "CVE-2023-30861", severity: "HIGH", description: "Session cookie leak" },
            KnownVuln { package: "requests", affected_below: "2.31.0", cve: "CVE-2023-32681", severity: "MEDIUM", description: "Proxy auth credential leak" },
            KnownVuln { package: "pillow", affected_below: "10.0.1", cve: "CVE-2023-44271", severity: "HIGH", description: "Denial of service via image" },
            KnownVuln { package: "cryptography", affected_below: "42.0.0", cve: "CVE-2023-49083", severity: "HIGH", description: "NULL pointer dereference" },
            KnownVuln { package: "jinja2", affected_below: "3.1.3", cve: "CVE-2024-22195", severity: "MEDIUM", description: "XSS via xmlattr filter" },
            KnownVuln { package: "urllib3", affected_below: "2.0.7", cve: "CVE-2023-45803", severity: "MEDIUM", description: "Request body leak on redirect" },
            KnownVuln { package: "pyyaml", affected_below: "6.0.1", cve: "CVE-2020-14343", severity: "CRITICAL", description: "Arbitrary code execution" },
            KnownVuln { package: "paramiko", affected_below: "3.4.0", cve: "CVE-2023-48795", severity: "MEDIUM", description: "Terrapin SSH prefix truncation" },
            KnownVuln { package: "aiohttp", affected_below: "3.9.2", cve: "CVE-2024-23334", severity: "HIGH", description: "Path traversal in static routes" },
        ]);

        // Java/Maven known vulnerable packages
        known_vulns.insert("maven", vec![
            KnownVuln { package: "log4j-core", affected_below: "2.17.1", cve: "CVE-2021-44228", severity: "CRITICAL", description: "Log4Shell — Remote Code Execution" },
            KnownVuln { package: "spring-webmvc", affected_below: "5.3.28", cve: "CVE-2023-34053", severity: "HIGH", description: "DoS via HTTP request" },
            KnownVuln { package: "commons-text", affected_below: "1.10.0", cve: "CVE-2022-42889", severity: "CRITICAL", description: "Text4Shell — Remote Code Execution" },
            KnownVuln { package: "jackson-databind", affected_below: "2.15.3", cve: "CVE-2022-42003", severity: "HIGH", description: "Deserialization gadgets" },
            KnownVuln { package: "snakeyaml", affected_below: "2.0", cve: "CVE-2022-1471", severity: "CRITICAL", description: "Remote code execution" },
            KnownVuln { package: "gson", affected_below: "2.8.9", cve: "CVE-2022-25647", severity: "HIGH", description: "Deserialization of untrusted data" },
            KnownVuln { package: "commons-io", affected_below: "2.14.0", cve: "CVE-2024-47554", severity: "MEDIUM", description: "Denial of service" },
        ]);

        // Go known vulnerable packages
        known_vulns.insert("go", vec![
            KnownVuln { package: "golang.org/x/crypto", affected_below: "0.17.0", cve: "CVE-2023-48795", severity: "MEDIUM", description: "Terrapin SSH attack" },
            KnownVuln { package: "golang.org/x/net", affected_below: "0.23.0", cve: "CVE-2023-45288", severity: "HIGH", description: "HTTP/2 CONTINUATION flood" },
            KnownVuln { package: "github.com/gin-gonic/gin", affected_below: "1.9.1", cve: "CVE-2023-29401", severity: "MEDIUM", description: "Unsafe html render" },
        ]);

        // Ruby gems
        known_vulns.insert("gem", vec![
            KnownVuln { package: "rails", affected_below: "7.0.8", cve: "CVE-2023-38037", severity: "MEDIUM", description: "File disclosure in ActiveStorage" },
            KnownVuln { package: "nokogiri", affected_below: "1.16.2", cve: "CVE-2024-25062", severity: "HIGH", description: "Use-after-free in libxml2" },
            KnownVuln { package: "rack", affected_below: "3.0.9", cve: "CVE-2024-25126", severity: "MEDIUM", description: "ReDoS in content type" },
        ]);

        // Rust crates  
        known_vulns.insert("cargo", vec![
            KnownVuln { package: "hyper", affected_below: "1.4.0", cve: "CVE-2024-51996", severity: "MEDIUM", description: "HTTP request smuggling" },
            KnownVuln { package: "h2", affected_below: "0.4.4", cve: "CVE-2024-2653", severity: "HIGH", description: "HTTP/2 CONTINUATION flood" },
        ]);

        let risky_patterns = vec![
            RiskyDep {
                pattern: Regex::new(r#"(?i)(?:telnet|ftp[^s]|rsh|rlogin|rexec)"#).unwrap(),
                description: "Insecure protocol dependency (plaintext communication)",
                severity: "HIGH",
            },
            RiskyDep {
                pattern: Regex::new(r#"(?i)(?:mysql|mongodb|redis)\b"#).unwrap(),
                description: "Database driver detected — verify TLS/SSL is configured",
                severity: "MEDIUM",
            },
        ];

        Self {
            known_vulns,
            risky_patterns,
            re_npm: Regex::new(r#""([^"]+)"\s*:\s*"[~^]?(\d+\.\d+\.\d+[^"]*)""#).unwrap(),
            re_npm_lock: Regex::new(r#""([^"@]+)"\s*:\s*\{[^}]*"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)""#).unwrap(),
            re_python: Regex::new(r#"(?m)^\s*([a-zA-Z0-9_-]+)\s*(?:==|>=|<=|~=|!=)\s*(\d+\.\d+(?:\.\d+)?)"#).unwrap(),
            re_maven: Regex::new(r#"<artifactId>\s*([^<]+)\s*</artifactId>\s*(?:<[^>]+>[^<]*</[^>]+>\s*)*<version>\s*([^<]+)\s*</version>"#).unwrap(),
            re_gradle: Regex::new(r#"(?:implementation|compile|api|runtimeOnly)\s*['"(]([^:'"]+):([^:'"]+):([^'")\s]+)"#).unwrap(),
            re_go: Regex::new(r#"(?m)^\s*(\S+)\s+v(\d+\.\d+\.\d+)"#).unwrap(),
            re_gem: Regex::new(r#"(?m)gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"].*?(\d+\.\d+(?:\.\d+)?))?"#).unwrap(),
            re_cargo: Regex::new(r#"(?m)^(\w[\w-]*)\s*=\s*"(\d+\.\d+(?:\.\d+)?)""#).unwrap(),
            re_cargo2: Regex::new(r#"(?m)^(\w[\w-]*)\s*=\s*\{[^}]*version\s*=\s*"(\d+\.\d+(?:\.\d+)?)""#).unwrap(),
            re_composer: Regex::new(r#""([^"]+/[^"]+)"\s*:\s*"[~^]?(\d+\.\d+(?:\.\d+)?)""#).unwrap(),
        }
    }

    pub fn scan_file(&self, path: &Path, content: &str) -> Vec<DepFinding> {
        let mut findings = Vec::new();
        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
        let file_path_str = path.to_string_lossy().to_string();

        match file_name.as_ref() {
            "package.json" => self.scan_npm(&file_path_str, content, &mut findings),
            "package-lock.json" | "yarn.lock" | "pnpm-lock.yaml" =>
                self.scan_npm_lock(&file_path_str, content, &mut findings),
            "requirements.txt" | "Pipfile" | "Pipfile.lock" | "setup.py" | "setup.cfg" | "pyproject.toml" =>
                self.scan_python(&file_path_str, content, &mut findings),
            "pom.xml" =>
                self.scan_maven(&file_path_str, content, &mut findings),
            "build.gradle" | "build.gradle.kts" =>
                self.scan_gradle(&file_path_str, content, &mut findings),
            "go.mod" | "go.sum" =>
                self.scan_go(&file_path_str, content, &mut findings),
            "Gemfile" | "Gemfile.lock" =>
                self.scan_gem(&file_path_str, content, &mut findings),
            "Cargo.toml" | "Cargo.lock" =>
                self.scan_cargo(&file_path_str, content, &mut findings),
            "composer.json" | "composer.lock" =>
                self.scan_composer(&file_path_str, content, &mut findings),
            _ => {}
        }

        // Check for risky dependencies in any manifest/lock
        for pattern in &self.risky_patterns {
            for line in content.lines() {
                if pattern.pattern.is_match(line) {
                    findings.push(DepFinding {
                        file_path: file_path_str.clone(),
                        package_manager: "any".to_string(),
                        package_name: line.trim().to_string(),
                        version: "".to_string(),
                        vulnerability: pattern.description.to_string(),
                        severity: pattern.severity.to_string(),
                        advice: "Consider using secure alternatives".to_string(),
                    });
                }
            }
        }

        findings
    }

    fn check_known_vulns(&self, ecosystem: &str, file_path: &str, pkg: &str, version: &str, findings: &mut Vec<DepFinding>) {
        if let Some(vulns) = self.known_vulns.get(ecosystem) {
            let pkg_lower = pkg.to_lowercase();
            for vuln in vulns {
                if pkg_lower.contains(vuln.package) {
                    if version_is_below(version, vuln.affected_below) {
                        findings.push(DepFinding {
                            file_path: file_path.to_string(),
                            package_manager: ecosystem.to_string(),
                            package_name: pkg.to_string(),
                            version: version.to_string(),
                            vulnerability: format!("{} — {}", vuln.cve, vuln.description),
                            severity: vuln.severity.to_string(),
                            advice: format!("Upgrade to >= {}", vuln.affected_below),
                        });
                    }
                }
            }
        }
    }

    fn scan_npm(&self, file_path: &str, content: &str, findings: &mut Vec<DepFinding>) {
        for cap in self.re_npm.captures_iter(content) {
            let pkg = &cap[1];
            let version = &cap[2];
            self.check_known_vulns("npm", file_path, pkg, version, findings);
        }
    }

    fn scan_npm_lock(&self, file_path: &str, content: &str, findings: &mut Vec<DepFinding>) {
        for cap in self.re_npm_lock.captures_iter(content) {
            let pkg = &cap[1];
            let version = &cap[2];
            self.check_known_vulns("npm", file_path, pkg, version, findings);
        }
    }

    fn scan_python(&self, file_path: &str, content: &str, findings: &mut Vec<DepFinding>) {
        for cap in self.re_python.captures_iter(content) {
            let pkg = &cap[1];
            let version = &cap[2];
            self.check_known_vulns("pip", file_path, pkg, version, findings);
        }
    }

    fn scan_maven(&self, file_path: &str, content: &str, findings: &mut Vec<DepFinding>) {
        for cap in self.re_maven.captures_iter(content) {
            let pkg = &cap[1];
            let version = &cap[2];
            self.check_known_vulns("maven", file_path, pkg, version, findings);
        }
    }

    fn scan_gradle(&self, file_path: &str, content: &str, findings: &mut Vec<DepFinding>) {
        for cap in self.re_gradle.captures_iter(content) {
            let pkg = &cap[2];
            let version = &cap[3];
            self.check_known_vulns("maven", file_path, pkg, version, findings);
        }
    }

    fn scan_go(&self, file_path: &str, content: &str, findings: &mut Vec<DepFinding>) {
        for cap in self.re_go.captures_iter(content) {
            let pkg = &cap[1];
            let version = &cap[2];
            self.check_known_vulns("go", file_path, pkg, version, findings);
        }
    }

    fn scan_gem(&self, file_path: &str, content: &str, findings: &mut Vec<DepFinding>) {
        for cap in self.re_gem.captures_iter(content) {
            let pkg = &cap[1];
            let version = cap.get(2).map_or("unknown", |m| m.as_str());
            self.check_known_vulns("gem", file_path, pkg, version, findings);
        }
    }

    fn scan_cargo(&self, file_path: &str, content: &str, findings: &mut Vec<DepFinding>) {
        for cap in self.re_cargo.captures_iter(content) {
            let pkg = &cap[1];
            let version = &cap[2];
            self.check_known_vulns("cargo", file_path, pkg, version, findings);
        }
        for cap in self.re_cargo2.captures_iter(content) {
            let pkg = &cap[1];
            let version = &cap[2];
            self.check_known_vulns("cargo", file_path, pkg, version, findings);
        }
    }

    fn scan_composer(&self, _file_path: &str, content: &str, _findings: &mut Vec<DepFinding>) {
        for cap in self.re_composer.captures_iter(content) {
            let _pkg = &cap[1];
            let _version = &cap[2];
        }
    }
}

fn version_is_below(current: &str, threshold: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .filter_map(|p| p.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
            .collect()
    };
    let cur = parse(current);
    let thr = parse(threshold);
    for i in 0..cur.len().max(thr.len()) {
        let c = cur.get(i).copied().unwrap_or(0);
        let t = thr.get(i).copied().unwrap_or(0);
        if c < t { return true; }
        if c > t { return false; }
    }
    false
}
