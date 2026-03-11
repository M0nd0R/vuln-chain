use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::patterns::vuln_rules::Finding;
use crate::analyzer::taint::TaintFinding;

/// Vulnerability Chain Analyzer
/// Finds multi-step attack chains where one vulnerability enables or amplifies another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnChain {
    pub chain_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub attack_scenario: String,
    pub steps: Vec<ChainStep>,
    pub impact: String,
    pub cvss_estimate: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub step_number: usize,
    pub description: String,
    pub file_path: String,
    pub line_number: usize,
    pub vuln_type: String,
}

pub struct ChainAnalyzer;

impl ChainAnalyzer {
    pub fn new() -> Self { Self }

    pub fn analyze_chains(&self, findings: &[Finding], taint_findings: &[TaintFinding]) -> Vec<VulnChain> {
        let mut chains = Vec::new();
        let mut chain_id = 0;

        // Group findings by file for intra-file chain analysis
        let mut by_file: HashMap<String, Vec<&Finding>> = HashMap::new();
        for f in findings {
            by_file.entry(f.file_path.clone()).or_default().push(f);
        }

        // --- Chain Pattern 1: Input -> SQL/Command Injection (taint-confirmed) ---
        for taint in taint_findings {
            if taint.sink.sink_type == "sql_execution" || taint.sink.sink_type == "command_execution" {
                chain_id += 1;
                let sink_label = if taint.sink.sink_type == "sql_execution" { "SQL Injection" } else { "Command Injection" };
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: format!("Taint-confirmed {} via {}", sink_label, taint.source.source_type),
                    description: format!(
                        "User input from {} flows directly to {} without sanitization",
                        taint.source.source_type, taint.sink.sink_type
                    ),
                    severity: "CRITICAL".to_string(),
                    attack_scenario: format!(
                        "1. Attacker provides malicious input via {}\n\
                         2. Input stored in '{}' at line {}\n\
                         3. Tainted data reaches {} at line {}\n\
                         4. Attacker achieves {}",
                        taint.source.source_type,
                        taint.source.variable,
                        taint.source.line_number,
                        taint.sink.sink_type,
                        taint.sink.line_number,
                        if taint.sink.sink_type == "sql_execution" {
                            "data exfiltration / authentication bypass"
                        } else {
                            "remote code execution on the server"
                        }
                    ),
                    steps: vec![
                        ChainStep {
                            step_number: 1,
                            description: format!("Input received via {}", taint.source.source_type),
                            file_path: taint.file_path.clone(),
                            line_number: taint.source.line_number,
                            vuln_type: "taint_source".to_string(),
                        },
                        ChainStep {
                            step_number: 2,
                            description: format!("Tainted data flows to {}", taint.sink.sink_type),
                            file_path: taint.file_path.clone(),
                            line_number: taint.sink.line_number,
                            vuln_type: taint.sink.sink_type.clone(),
                        },
                    ],
                    impact: format!("{} — Allows attacker to execute arbitrary {} on the server",
                        sink_label,
                        if taint.sink.sink_type == "sql_execution" { "SQL queries" } else { "OS commands" }
                    ),
                    cvss_estimate: 9.8,
                });
            }
        }

        // --- Chain Pattern 2: SSRF -> Internal Service Access ---
        for (file, file_findings) in &by_file {
            let ssrf_findings: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "SSRF")
                .collect();
            let path_findings: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "PathTraversal")
                .collect();

            if !ssrf_findings.is_empty() {
                for ssrf in &ssrf_findings {
                    chain_id += 1;
                    let mut steps = vec![
                        ChainStep {
                            step_number: 1,
                            description: "SSRF allows attacker to make server-side requests".to_string(),
                            file_path: file.clone(),
                            line_number: ssrf.line_number,
                            vuln_type: "SSRF".to_string(),
                        },
                    ];

                    if !path_findings.is_empty() {
                        steps.push(ChainStep {
                            step_number: 2,
                            description: "Combined with path traversal for internal file read".to_string(),
                            file_path: file.clone(),
                            line_number: path_findings[0].line_number,
                            vuln_type: "PathTraversal".to_string(),
                        });
                    }

                    chains.push(VulnChain {
                        chain_id: format!("CHAIN-{:04}", chain_id),
                        title: "SSRF to Internal Service/Data Access".to_string(),
                        description: "Server-side request forgery can be leveraged to access internal services, cloud metadata, or local files".to_string(),
                        severity: "CRITICAL".to_string(),
                        attack_scenario: format!(
                            "1. Attacker exploits SSRF at line {} in {}\n\
                             2. Crafts request to http://169.254.169.254/latest/meta-data/ (AWS metadata)\n\
                             3. Retrieves IAM credentials or internal service tokens\n\
                             4. Pivots to internal network or escalates privileges",
                            ssrf.line_number, file
                        ),
                        steps,
                        impact: "Access to cloud metadata, internal services, credential theft".to_string(),
                        cvss_estimate: 9.1,
                    });
                }
            }
        }

        // --- Chain Pattern 3: XSS -> Session Hijacking / CSRF ---
        for (file, file_findings) in &by_file {
            let xss_findings: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "XSS")
                .collect();

            for xss in &xss_findings {
                chain_id += 1;
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "XSS to Account Takeover Chain".to_string(),
                    description: "Cross-site scripting can be used to steal session tokens and perform actions as the victim".to_string(),
                    severity: "HIGH".to_string(),
                    attack_scenario: format!(
                        "1. Attacker injects malicious script via XSS at line {} in {}\n\
                         2. Script executes in victim's browser context\n\
                         3. Steals session cookie (document.cookie) or localStorage tokens\n\
                         4. Attacker uses stolen session for account takeover\n\
                         5. Can also perform CSRF actions via the XSS payload",
                        xss.line_number, file
                    ),
                    steps: vec![
                        ChainStep {
                            step_number: 1,
                            description: "XSS injection point".to_string(),
                            file_path: file.clone(),
                            line_number: xss.line_number,
                            vuln_type: "XSS".to_string(),
                        },
                        ChainStep {
                            step_number: 2,
                            description: "Session theft via JavaScript".to_string(),
                            file_path: file.clone(),
                            line_number: xss.line_number,
                            vuln_type: "SessionHijacking".to_string(),
                        },
                    ],
                    impact: "Full account takeover, data theft, malware distribution".to_string(),
                    cvss_estimate: 8.1,
                });
            }
        }

        // --- Chain Pattern 4: Deserialization -> RCE ---
        // Only for languages that actually support gadget chains (Java, C#, Python, PHP, Ruby)
        // Go/Rust deserialization does NOT enable RCE — skip those.
        for (file, file_findings) in &by_file {
            let deser_findings: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "InsecureDeserialization")
                .filter(|f| {
                    // Only flag deserialization->RCE chains for languages with actual gadget chains
                    let ext = f.file_path.rsplit('.').next().unwrap_or("");
                    matches!(ext, "java" | "kt" | "py" | "rb" | "php" | "cs")
                })
                .collect();

            for deser in &deser_findings {
                chain_id += 1;
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "Insecure Deserialization to RCE".to_string(),
                    description: "Deserialization of untrusted data can lead to arbitrary code execution through gadget chains".to_string(),
                    severity: "CRITICAL".to_string(),
                    attack_scenario: format!(
                        "1. Attacker crafts malicious serialized payload with gadget chain\n\
                         2. Payload is sent to deserialization point at line {} in {}\n\
                         3. Gadget chain triggers arbitrary code execution\n\
                         4. Attacker gains full server control",
                        deser.line_number, file
                    ),
                    steps: vec![
                        ChainStep {
                            step_number: 1,
                            description: "Insecure deserialization endpoint".to_string(),
                            file_path: file.clone(),
                            line_number: deser.line_number,
                            vuln_type: "InsecureDeserialization".to_string(),
                        },
                        ChainStep {
                            step_number: 2,
                            description: "Gadget chain leads to code execution".to_string(),
                            file_path: file.clone(),
                            line_number: deser.line_number,
                            vuln_type: "RemoteCodeExecution".to_string(),
                        },
                    ],
                    impact: "Complete server compromise via arbitrary code execution".to_string(),
                    cvss_estimate: 9.8,
                });
            }
        }

        // --- Chain Pattern 5: Weak Crypto + Hardcoded Secrets ---
        // Only create this chain if both findings are from the same file or closely related
        // and the weak crypto finding isn't just an MD5 checksum (which is acceptable)
        let has_weak_crypto = findings.iter().any(|f| {
            let cat = format!("{}", f.category);
            cat == "WeakCrypto" && !f.line_content.to_lowercase().contains("checksum")
                && !f.line_content.to_lowercase().contains("hash")
                && !f.line_content.to_lowercase().contains("digest")
                && !f.line_content.to_lowercase().contains("etag")
        });
        let has_hardcoded = findings.iter().any(|f| format!("{}", f.category) == "HardcodedSecret");

        if has_weak_crypto && has_hardcoded {
            chain_id += 1;
            let crypto_f = match findings.iter().find(|f| format!("{}", f.category) == "WeakCrypto") {
                Some(f) => f,
                None => { /* guard passed but find failed — skip */ return chains; }
            };
            let secret_f = match findings.iter().find(|f| format!("{}", f.category) == "HardcodedSecret") {
                Some(f) => f,
                None => { return chains; }
            };

            chains.push(VulnChain {
                chain_id: format!("CHAIN-{:04}", chain_id),
                title: "Weak Crypto + Hardcoded Secrets → Data Breach".to_string(),
                description: "Combination of weak cryptographic algorithms and hardcoded secrets enables data decryption".to_string(),
                severity: "HIGH".to_string(),
                attack_scenario: format!(
                    "1. Attacker discovers hardcoded secret at line {} in {}\n\
                     2. Weak crypto algorithm at line {} in {} is easily broken\n\
                     3. Attacker decrypts stored data using the discovered key\n\
                     4. Sensitive data is exposed",
                    secret_f.line_number, secret_f.file_path,
                    crypto_f.line_number, crypto_f.file_path
                ),
                steps: vec![
                    ChainStep {
                        step_number: 1,
                        description: "Hardcoded secret discovered".to_string(),
                        file_path: secret_f.file_path.clone(),
                        line_number: secret_f.line_number,
                        vuln_type: "HardcodedSecret".to_string(),
                    },
                    ChainStep {
                        step_number: 2,
                        description: "Weak crypto allows key recovery/brute force".to_string(),
                        file_path: crypto_f.file_path.clone(),
                        line_number: crypto_f.line_number,
                        vuln_type: "WeakCrypto".to_string(),
                    },
                ],
                impact: "Sensitive data decryption and exposure".to_string(),
                cvss_estimate: 7.5,
            });
        }

        // --- Chain Pattern 6: XXE → SSRF → Internal Access ---
        for (file, file_findings) in &by_file {
            let xxe_findings: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "XXE")
                .collect();
            let ssrf_in_file: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "SSRF")
                .collect();

            if !xxe_findings.is_empty() && !ssrf_in_file.is_empty() {
                for xxe in &xxe_findings {
                    chain_id += 1;
                    chains.push(VulnChain {
                        chain_id: format!("CHAIN-{:04}", chain_id),
                        title: "XXE → SSRF → Internal Data Exfiltration".to_string(),
                        description: "XML External Entity processing enables server-side requests to internal services".to_string(),
                        severity: "CRITICAL".to_string(),
                        attack_scenario: format!(
                            "1. Attacker uploads crafted XML with external entity at line {} in {}\n\
                             2. XXE triggers server-side HTTP request (SSRF)\n\
                             3. Retrieves cloud metadata (169.254.169.254) or internal APIs\n\
                             4. Exfiltrates IAM credentials or sensitive configuration",
                            xxe.line_number, file
                        ),
                        steps: vec![
                            ChainStep { step_number: 1, description: "XXE injection via XML parser".to_string(),
                                file_path: file.clone(), line_number: xxe.line_number, vuln_type: "XXE".to_string() },
                            ChainStep { step_number: 2, description: "SSRF via external entity fetch".to_string(),
                                file_path: file.clone(), line_number: ssrf_in_file[0].line_number, vuln_type: "SSRF".to_string() },
                            ChainStep { step_number: 3, description: "Internal data exfiltration".to_string(),
                                file_path: file.clone(), line_number: xxe.line_number, vuln_type: "DataExfiltration".to_string() },
                        ],
                        impact: "Cloud credential theft, internal network mapping, data exfiltration".to_string(),
                        cvss_estimate: 9.6,
                    });
                }
            }
        }

        // --- Chain Pattern 7: Auth Bypass → Privilege Escalation ---
        for (file, file_findings) in &by_file {
            let auth_findings: Vec<_> = file_findings.iter()
                .filter(|f| {
                    let cat = format!("{}", f.category);
                    cat == "BrokenAuth" || cat == "Authentication"
                })
                .collect();
            let injection_findings: Vec<_> = file_findings.iter()
                .filter(|f| {
                    let cat = format!("{}", f.category);
                    cat == "SQLInjection" || cat == "CommandInjection"
                })
                .collect();

            for auth in &auth_findings {
                chain_id += 1;
                let mut steps = vec![
                    ChainStep { step_number: 1, description: "Authentication bypass".to_string(),
                        file_path: file.clone(), line_number: auth.line_number, vuln_type: "BrokenAuth".to_string() },
                    ChainStep { step_number: 2, description: "Access admin functionality".to_string(),
                        file_path: file.clone(), line_number: auth.line_number, vuln_type: "PrivilegeEscalation".to_string() },
                ];
                if !injection_findings.is_empty() {
                    steps.push(ChainStep { step_number: 3, description: "Leverage injection in admin context".to_string(),
                        file_path: file.clone(), line_number: injection_findings[0].line_number,
                        vuln_type: injection_findings[0].rule_id.clone() });
                }
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "Authentication Bypass → Privilege Escalation".to_string(),
                    description: "Weak authentication allows attacker to bypass login and escalate privileges".to_string(),
                    severity: "CRITICAL".to_string(),
                    attack_scenario: format!(
                        "1. Attacker exploits auth weakness at line {} in {}\n\
                         2. Gains access to authenticated/admin endpoints\n\
                         3. Escalates privileges to admin or superuser\n\
                         4. {}",
                        auth.line_number, file,
                        if !injection_findings.is_empty() { "Leverages injection for full system compromise" }
                        else { "Accesses sensitive admin operations" }
                    ),
                    steps,
                    impact: "Full admin access, data breach, system compromise".to_string(),
                    cvss_estimate: 9.4,
                });
            }
        }

        // --- Chain Pattern 8: Prototype Pollution → XSS/RCE ---
        for (file, file_findings) in &by_file {
            let proto_findings: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "PrototypePollution")
                .collect();

            for proto in &proto_findings {
                chain_id += 1;
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "Prototype Pollution → Remote Code Execution".to_string(),
                    description: "Object prototype manipulation can lead to denial of service, XSS, or server-side code execution".to_string(),
                    severity: "HIGH".to_string(),
                    attack_scenario: format!(
                        "1. Attacker pollutes Object.prototype via {} at line {} in {}\n\
                         2. Injected property propagates through application objects\n\
                         3. Polluted property triggers code execution in template engine or child_process\n\
                         4. Achieves RCE on Node.js server",
                        proto.rule_name, proto.line_number, file
                    ),
                    steps: vec![
                        ChainStep { step_number: 1, description: "Prototype pollution injection".to_string(),
                            file_path: file.clone(), line_number: proto.line_number, vuln_type: "PrototypePollution".to_string() },
                        ChainStep { step_number: 2, description: "Propagation to sensitive object".to_string(),
                            file_path: file.clone(), line_number: proto.line_number, vuln_type: "ObjectManipulation".to_string() },
                        ChainStep { step_number: 3, description: "Code execution via gadget".to_string(),
                            file_path: file.clone(), line_number: proto.line_number, vuln_type: "RemoteCodeExecution".to_string() },
                    ],
                    impact: "Server-side RCE, DoS, or client-side XSS".to_string(),
                    cvss_estimate: 8.6,
                });
            }
        }

        // --- Chain Pattern 9: Path Traversal → File Read → Credential Theft ---
        for (file, file_findings) in &by_file {
            let path_trav: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "PathTraversal")
                .collect();

            for pt in &path_trav {
                chain_id += 1;
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "Path Traversal → Sensitive File Read → Credential Theft".to_string(),
                    description: "Directory traversal allows reading arbitrary files including secrets and credentials".to_string(),
                    severity: "HIGH".to_string(),
                    attack_scenario: format!(
                        "1. Attacker exploits path traversal at line {} in {}\n\
                         2. Reads /etc/passwd, /etc/shadow, or .env files\n\
                         3. Extracts database credentials or API keys\n\
                         4. Pivots to database or external service access",
                        pt.line_number, file
                    ),
                    steps: vec![
                        ChainStep { step_number: 1, description: "Path traversal injection".to_string(),
                            file_path: file.clone(), line_number: pt.line_number, vuln_type: "PathTraversal".to_string() },
                        ChainStep { step_number: 2, description: "Read sensitive system/config files".to_string(),
                            file_path: file.clone(), line_number: pt.line_number, vuln_type: "FileRead".to_string() },
                        ChainStep { step_number: 3, description: "Extract and reuse credentials".to_string(),
                            file_path: file.clone(), line_number: pt.line_number, vuln_type: "CredentialTheft".to_string() },
                    ],
                    impact: "Credential theft, lateral movement, data breach".to_string(),
                    cvss_estimate: 8.2,
                });
            }
        }

        // --- Chain Pattern 10: Log Injection → Log Forging → SIEM Evasion ---
        for taint in taint_findings {
            if taint.sink.sink_type == "log_injection" {
                chain_id += 1;
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "Log Injection → Log Forging → SIEM Evasion".to_string(),
                    description: "Injecting crafted data into logs to forge entries, evade detection, or exploit log viewers".to_string(),
                    severity: "MEDIUM".to_string(),
                    attack_scenario: format!(
                        "1. Attacker injects newline/CRLF characters via {} at line {}\n\
                         2. Forges fake log entries (e.g., fake successful logins)\n\
                         3. Evades SIEM detection rules\n\
                         4. Could exploit log viewer XSS vulnerabilities",
                        taint.source.source_type, taint.source.line_number
                    ),
                    steps: vec![
                        ChainStep { step_number: 1, description: "Tainted input reaches logging".to_string(),
                            file_path: taint.file_path.clone(), line_number: taint.source.line_number, vuln_type: "TaintSource".to_string() },
                        ChainStep { step_number: 2, description: "Log injection at sink".to_string(),
                            file_path: taint.file_path.clone(), line_number: taint.sink.line_number, vuln_type: "LogInjection".to_string() },
                    ],
                    impact: "Log forging, SIEM evasion, potential log viewer exploitation".to_string(),
                    cvss_estimate: 5.3,
                });
            }
        }

        // --- Chain Pattern 11: Open Redirect → Phishing → OAuth Token Theft ---
        for (file, file_findings) in &by_file {
            let redirect_findings: Vec<_> = file_findings.iter()
                .filter(|f| format!("{}", f.category) == "OpenRedirect")
                .collect();

            for redir in &redirect_findings {
                chain_id += 1;
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "Open Redirect → Phishing → OAuth Token Theft".to_string(),
                    description: "Open redirect abused in OAuth flow to steal authorization codes or tokens".to_string(),
                    severity: "HIGH".to_string(),
                    attack_scenario: format!(
                        "1. Attacker crafts OAuth authorize URL with redirect_uri pointing to open redirect at line {} in {}\n\
                         2. User authenticates and OAuth provider redirects to the app\n\
                         3. App's open redirect forwards user+token to attacker's server\n\
                         4. Attacker captures OAuth code/token for account takeover",
                        redir.line_number, file
                    ),
                    steps: vec![
                        ChainStep { step_number: 1, description: "Open redirect vulnerability".to_string(),
                            file_path: file.clone(), line_number: redir.line_number, vuln_type: "OpenRedirect".to_string() },
                        ChainStep { step_number: 2, description: "OAuth flow manipulation".to_string(),
                            file_path: file.clone(), line_number: redir.line_number, vuln_type: "OAuthAbuse".to_string() },
                        ChainStep { step_number: 3, description: "Token/code theft via redirect".to_string(),
                            file_path: file.clone(), line_number: redir.line_number, vuln_type: "TokenTheft".to_string() },
                    ],
                    impact: "OAuth token theft, full account takeover".to_string(),
                    cvss_estimate: 8.0,
                });
            }
        }

        // --- Chain Pattern 12: Template Injection → RCE ---
        for taint in taint_findings {
            if taint.sink.sink_type == "template_injection" {
                chain_id += 1;
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "Server-Side Template Injection → Remote Code Execution".to_string(),
                    description: "User input flows into template rendering, enabling arbitrary code execution through template engine".to_string(),
                    severity: "CRITICAL".to_string(),
                    attack_scenario: format!(
                        "1. Attacker sends template expression (e.g., {{{{7*7}}}}) via {} at line {}\n\
                         2. Input rendered in server-side template at line {}\n\
                         3. Attacker escalates to {{{{config.__class__.__init__.__globals__['os'].popen('id').read()}}}}\n\
                         4. Achieves remote code execution on the server",
                        taint.source.source_type, taint.source.line_number, taint.sink.line_number
                    ),
                    steps: vec![
                        ChainStep { step_number: 1, description: "Tainted input from user".to_string(),
                            file_path: taint.file_path.clone(), line_number: taint.source.line_number, vuln_type: "TaintSource".to_string() },
                        ChainStep { step_number: 2, description: "Template injection at render point".to_string(),
                            file_path: taint.file_path.clone(), line_number: taint.sink.line_number, vuln_type: "TemplateInjection".to_string() },
                        ChainStep { step_number: 3, description: "Remote code execution via template engine".to_string(),
                            file_path: taint.file_path.clone(), line_number: taint.sink.line_number, vuln_type: "RemoteCodeExecution".to_string() },
                    ],
                    impact: "Full server compromise via RCE".to_string(),
                    cvss_estimate: 9.8,
                });
            }
        }

        // --- Cross-file chain: SQL Injection in one file + Authentication weakness in another ---
        let all_sqli: Vec<_> = findings.iter().filter(|f| format!("{}", f.category) == "SQLInjection").collect();
        let all_auth: Vec<_> = findings.iter().filter(|f| {
            let cat = format!("{}", f.category);
            cat == "BrokenAuth" || cat == "Authentication"
        }).collect();

        if !all_sqli.is_empty() && !all_auth.is_empty() {
            chain_id += 1;
            chains.push(VulnChain {
                chain_id: format!("CHAIN-{:04}", chain_id),
                title: "SQL Injection + Weak Auth → Complete Database Takeover".to_string(),
                description: "SQL injection combined with weak authentication enables full database access without valid credentials".to_string(),
                severity: "CRITICAL".to_string(),
                attack_scenario: format!(
                    "1. Exploit weak auth at {}:{} to gain basic access\n\
                     2. Use SQL injection at {}:{} to escalate to DBA\n\
                     3. Extract all database tables including user credentials\n\
                     4. Full data breach and potential lateral movement",
                    all_auth[0].file_path, all_auth[0].line_number,
                    all_sqli[0].file_path, all_sqli[0].line_number
                ),
                steps: vec![
                    ChainStep { step_number: 1, description: "Weak authentication bypass".to_string(),
                        file_path: all_auth[0].file_path.clone(), line_number: all_auth[0].line_number, vuln_type: "BrokenAuth".to_string() },
                    ChainStep { step_number: 2, description: "SQL injection for privilege escalation".to_string(),
                        file_path: all_sqli[0].file_path.clone(), line_number: all_sqli[0].line_number, vuln_type: "SQLInjection".to_string() },
                    ChainStep { step_number: 3, description: "Full database exfiltration".to_string(),
                        file_path: all_sqli[0].file_path.clone(), line_number: all_sqli[0].line_number, vuln_type: "DataExfiltration".to_string() },
                ],
                impact: "Complete database compromise, credential theft, lateral movement".to_string(),
                cvss_estimate: 9.9,
            });
        }

        // --- Chain Pattern 13: Auth Token in Plaintext Logs → Credential Theft ---
        // Correlates InfoDisclosure findings from mobile/JS log rules with credential theft potential.
        // adb logcat requires no root — any USB-trusted machine can read Android device logs.
        for (file, file_findings) in &by_file {
            let token_log_findings: Vec<_> = file_findings.iter()
                .filter(|f| {
                    let cat = format!("{}", f.category);
                    (cat == "InfoDisclosure" || cat == "Logging")
                        && (f.rule_id.starts_with("KT-LOG") || f.rule_id.starts_with("MOB-LOG")
                            || f.rule_id.starts_with("JS-LOG") || f.rule_id.starts_with("MOB-TOAST")
                            || f.rule_id == "COMP-MOB-001")
                })
                .collect();

            for log_f in &token_log_findings {
                chain_id += 1;
                let is_android = file.ends_with(".kt") || file.ends_with(".java");
                let is_ios = file.ends_with(".swift") || file.ends_with(".m") || file.ends_with(".mm");
                let platform_note = if is_android {
                    "adb logcat (no root required, works on any USB-trusted machine)"
                } else if is_ios {
                    "Console.app on connected Mac or idevicesyslog — log persists across sessions in debug builds"
                } else {
                    "browser devtools console or server-side log aggregation"
                };
                chains.push(VulnChain {
                    chain_id: format!("CHAIN-{:04}", chain_id),
                    title: "Auth Token in Plaintext Logs → Credential Theft".to_string(),
                    description: format!(
                        "An OAuth token (public_token/access_token/link_token) is written to system logs in {}. \
                        The token is readable without any exploit via {}.",
                        file, platform_note
                    ),
                    severity: "MEDIUM".to_string(),
                    attack_scenario: format!(
                        "1. Auth token logged at line {} in {}\n\
                         2. Attacker with physical/USB access reads log via {}\n\
                         3. Token captured in plaintext without exploit\n\
                         4. Token replayed against API for unauthorized account-level data access",
                        log_f.line_number, file, platform_note
                    ),
                    steps: vec![
                        ChainStep {
                            step_number: 1,
                            description: "OAuth token written to system log".to_string(),
                            file_path: file.clone(),
                            line_number: log_f.line_number,
                            vuln_type: "InfoDisclosure".to_string(),
                        },
                        ChainStep {
                            step_number: 2,
                            description: format!("Log read via {}", platform_note),
                            file_path: file.clone(),
                            line_number: log_f.line_number,
                            vuln_type: "LogExfiltration".to_string(),
                        },
                        ChainStep {
                            step_number: 3,
                            description: "Captured token replayed for unauthorized API access".to_string(),
                            file_path: file.clone(),
                            line_number: log_f.line_number,
                            vuln_type: "CredentialTheft".to_string(),
                        },
                    ],
                    impact: "OAuth token theft enabling read access to linked financial account data (CWE-532)".to_string(),
                    cvss_estimate: 6.5,
                });
            }
        }

        // Sort chains by severity
        chains.sort_by(|a, b| b.cvss_estimate.partial_cmp(&a.cvss_estimate).unwrap_or(std::cmp::Ordering::Equal));
        chains
    }
}
