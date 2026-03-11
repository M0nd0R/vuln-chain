use regex::Regex;
use serde::{Deserialize, Serialize};

/// Infrastructure-as-Code & Configuration Security Scanner
/// Scans Dockerfiles, Terraform, Kubernetes manifests, CI/CD configs, Nginx, etc.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IacFinding {
    pub rule_id: String,
    pub rule_name: String,
    pub description: String,
    pub severity: String,
    pub cwe: String,
    pub file_path: String,
    pub line_number: usize,
    pub line_content: String,
    pub category: String,
    pub remediation: String,
}

struct IacRule {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    severity: &'static str,
    cwe: &'static str,
    pattern: Regex,
    file_patterns: &'static [&'static str],
    category: &'static str,
    remediation: &'static str,
    negative_pattern: Option<Regex>,
}

pub struct IacScanner {
    rules: Vec<IacRule>,
}

impl IacScanner {
    pub fn new() -> Self {
        Self {
            rules: build_iac_rules(),
        }
    }

    pub fn scan(&self, file_path: &str, content: &str) -> Vec<IacFinding> {
        let mut findings = Vec::new();
        let lower_path = file_path.to_lowercase();
        let lines: Vec<&str> = content.lines().collect();

        for rule in &self.rules {
            let matches_file = rule.file_patterns.iter().any(|pat| {
                if pat.starts_with("*.") {
                    lower_path.ends_with(&pat[1..])
                } else {
                    lower_path.contains(&pat.to_lowercase())
                }
            });

            if !matches_file { continue; }

            for (i, line) in lines.iter().enumerate() {
                if rule.pattern.is_match(line) {
                    if let Some(ref neg) = rule.negative_pattern {
                        if neg.is_match(line) { continue; }
                    }
                    findings.push(IacFinding {
                        rule_id: rule.id.to_string(),
                        rule_name: rule.name.to_string(),
                        description: rule.description.to_string(),
                        severity: rule.severity.to_string(),
                        cwe: rule.cwe.to_string(),
                        file_path: file_path.to_string(),
                        line_number: i + 1,
                        line_content: line.to_string(),
                        category: rule.category.to_string(),
                        remediation: rule.remediation.to_string(),
                    });
                }
            }
        }

        // Multi-line context checks (e.g., Dockerfile missing USER, K8s missing securityContext)
        findings.extend(self.check_multiline_rules(file_path, content, &lower_path));

        findings
    }

    fn check_multiline_rules(&self, file_path: &str, content: &str, lower_path: &str) -> Vec<IacFinding> {
        let mut findings = Vec::new();

        // Dockerfile: missing USER instruction (running as root)
        if lower_path.contains("dockerfile") && !lower_path.ends_with(".md") {
            if !content.lines().any(|l| l.trim().starts_with("USER ") && !l.contains("root")) {
                findings.push(IacFinding {
                    rule_id: "IAC-DOCKER-010".into(),
                    rule_name: "Docker Container Running as Root".into(),
                    description: "No USER instruction — container runs as root by default".into(),
                    severity: "HIGH".into(), cwe: "CWE-250".into(),
                    file_path: file_path.into(), line_number: 1,
                    line_content: "Missing USER instruction".into(),
                    category: "Docker".into(),
                    remediation: "Add USER instruction: USER nonroot:nonroot".into(),
                });
            }
            // Dockerfile: missing HEALTHCHECK
            if !content.contains("HEALTHCHECK") {
                findings.push(IacFinding {
                    rule_id: "IAC-DOCKER-011".into(),
                    rule_name: "Missing HEALTHCHECK".into(),
                    description: "No HEALTHCHECK instruction — container health not monitored".into(),
                    severity: "LOW".into(), cwe: "CWE-693".into(),
                    file_path: file_path.into(), line_number: 1,
                    line_content: "Missing HEALTHCHECK instruction".into(),
                    category: "Docker".into(),
                    remediation: "Add HEALTHCHECK instruction for container orchestration".into(),
                });
            }
        }

        // Kubernetes: missing resource limits
        if (lower_path.ends_with(".yaml") || lower_path.ends_with(".yml"))
            && (content.contains("apiVersion:") && content.contains("kind:"))
        {
            if content.contains("containers:") && !content.contains("resources:") {
                findings.push(IacFinding {
                    rule_id: "IAC-K8S-010".into(),
                    rule_name: "K8s Missing Resource Limits".into(),
                    description: "Container spec without resource limits — DoS risk".into(),
                    severity: "MEDIUM".into(), cwe: "CWE-770".into(),
                    file_path: file_path.into(), line_number: 1,
                    line_content: "Missing resources: limits".into(),
                    category: "Kubernetes".into(),
                    remediation: "Add resources.limits.cpu and resources.limits.memory".into(),
                });
            }
            // Missing network policy
            if content.contains("kind: Deployment") || content.contains("kind: Pod") {
                if !content.contains("NetworkPolicy") {
                    findings.push(IacFinding {
                        rule_id: "IAC-K8S-011".into(),
                        rule_name: "K8s No Network Policy".into(),
                        description: "No network policy — unrestricted pod-to-pod communication".into(),
                        severity: "MEDIUM".into(), cwe: "CWE-284".into(),
                        file_path: file_path.into(), line_number: 1,
                        line_content: "No NetworkPolicy defined".into(),
                        category: "Kubernetes".into(),
                        remediation: "Define NetworkPolicy to restrict ingress/egress".into(),
                    });
                }
            }
        }

        // Terraform: missing encryption
        if lower_path.ends_with(".tf") {
            if content.contains("aws_s3_bucket") && !content.contains("server_side_encryption") && !content.contains("aws_s3_bucket_server_side_encryption") {
                findings.push(IacFinding {
                    rule_id: "IAC-TF-010".into(),
                    rule_name: "S3 Bucket Missing Encryption".into(),
                    description: "S3 bucket without server-side encryption configuration".into(),
                    severity: "HIGH".into(), cwe: "CWE-311".into(),
                    file_path: file_path.into(), line_number: 1,
                    line_content: "aws_s3_bucket without encryption".into(),
                    category: "Terraform".into(),
                    remediation: "Enable SSE-S3 or SSE-KMS encryption on all S3 buckets".into(),
                });
            }
            if content.contains("aws_s3_bucket") && !content.contains("versioning") {
                findings.push(IacFinding {
                    rule_id: "IAC-TF-011".into(),
                    rule_name: "S3 Bucket Missing Versioning".into(),
                    description: "S3 bucket without versioning — no recovery from accidental deletion".into(),
                    severity: "LOW".into(), cwe: "CWE-693".into(),
                    file_path: file_path.into(), line_number: 1,
                    line_content: "aws_s3_bucket without versioning".into(),
                    category: "Terraform".into(),
                    remediation: "Enable versioning on S3 buckets".into(),
                });
            }
        }

        findings
    }
}

fn build_iac_rules() -> Vec<IacRule> {
    vec![
        // ============== DOCKERFILE ==============
        IacRule {
            id: "IAC-DOCKER-001", name: "Docker FROM latest Tag",
            description: "Using :latest tag in FROM — non-reproducible builds",
            severity: "MEDIUM", cwe: "CWE-829",
            pattern: Regex::new(r"^\s*FROM\s+\w+(?:/\w+)?(?::latest|\s*$)").unwrap(),
            file_patterns: &["Dockerfile", "dockerfile", "*.dockerfile"],
            category: "Docker",
            remediation: "Pin specific image version: FROM python:3.12-slim",
            negative_pattern: Some(Regex::new(r"(?i)(?:scratch|AS\s+\w+)").unwrap()),
        },
        IacRule {
            id: "IAC-DOCKER-002", name: "Docker ADD Instead of COPY",
            description: "ADD can extract archives and fetch URLs — use COPY for plain files",
            severity: "LOW", cwe: "CWE-829",
            pattern: Regex::new(r"^\s*ADD\s+").unwrap(),
            file_patterns: &["Dockerfile", "dockerfile", "*.dockerfile"],
            category: "Docker",
            remediation: "Use COPY unless you need ADD's archive extraction or URL download",
            negative_pattern: Some(Regex::new(r"(?:https?://|--chown)").unwrap()),
        },
        IacRule {
            id: "IAC-DOCKER-003", name: "Docker Secrets in ENV",
            description: "Sensitive values in ENV — visible in image history",
            severity: "HIGH", cwe: "CWE-798",
            pattern: Regex::new(r#"(?i)^\s*ENV\s+(?:\w+\s+)?(?:.*(?:PASSWORD|SECRET|KEY|TOKEN|PRIVATE|CREDENTIAL|API_KEY)\s*=)"#).unwrap(),
            file_patterns: &["Dockerfile", "dockerfile", "*.dockerfile"],
            category: "Docker",
            remediation: "Use Docker secrets or --mount=type=secret for sensitive values",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-DOCKER-004", name: "Docker EXPOSE All Ports",
            description: "Exposing commonly sensitive ports (22 SSH, 3306 MySQL, 5432 PostgreSQL)",
            severity: "MEDIUM", cwe: "CWE-668",
            pattern: Regex::new(r"^\s*EXPOSE\s+(?:22|3306|5432|6379|27017|11211|9200|2375|2376)\b").unwrap(),
            file_patterns: &["Dockerfile", "dockerfile", "*.dockerfile"],
            category: "Docker",
            remediation: "Only expose application ports, not database/admin ports",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-DOCKER-005", name: "Docker apt-get without --no-install-recommends",
            description: "Installing unnecessary packages increases attack surface",
            severity: "LOW", cwe: "CWE-1104",
            pattern: Regex::new(r"apt-get\s+install").unwrap(),
            file_patterns: &["Dockerfile", "dockerfile", "*.dockerfile"],
            category: "Docker",
            remediation: "Use apt-get install --no-install-recommends",
            negative_pattern: Some(Regex::new(r"--no-install-recommends").unwrap()),
        },
        IacRule {
            id: "IAC-DOCKER-006", name: "Docker sudo Usage",
            description: "Using sudo in Dockerfile — better to switch USER",
            severity: "LOW", cwe: "CWE-250",
            pattern: Regex::new(r"^\s*RUN\s+.*\bsudo\b").unwrap(),
            file_patterns: &["Dockerfile", "dockerfile", "*.dockerfile"],
            category: "Docker",
            remediation: "Use USER instruction to switch users instead of sudo",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-DOCKER-007", name: "Docker Curl Pipe Shell",
            description: "Piping curl to shell — supply chain attack vector",
            severity: "HIGH", cwe: "CWE-829",
            pattern: Regex::new(r"(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh)").unwrap(),
            file_patterns: &["Dockerfile", "dockerfile", "*.dockerfile"],
            category: "Docker",
            remediation: "Download and verify scripts before executing. Use checksums".into(),
            negative_pattern: None,
        },

        // ============== DOCKER-COMPOSE ==============
        IacRule {
            id: "IAC-DC-001", name: "Docker-Compose Privileged Mode",
            description: "Container running in privileged mode — full host access",
            severity: "CRITICAL", cwe: "CWE-250",
            pattern: Regex::new(r"(?i)privileged\s*:\s*true").unwrap(),
            file_patterns: &["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
            category: "Docker",
            remediation: "Remove privileged: true. Use specific capabilities with cap_add",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-DC-002", name: "Docker-Compose Host Network Mode",
            description: "Container using host network — bypasses network isolation",
            severity: "HIGH", cwe: "CWE-668",
            pattern: Regex::new(r#"(?i)network_mode\s*:\s*["']?host"#).unwrap(),
            file_patterns: &["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
            category: "Docker",
            remediation: "Use bridge network mode with explicit port mapping",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-DC-003", name: "Docker-Compose Hardcoded Secrets",
            description: "Hardcoded passwords/secrets in docker-compose file",
            severity: "HIGH", cwe: "CWE-798",
            pattern: Regex::new(r#"(?i)(?:PASSWORD|SECRET|KEY|TOKEN)\s*[:=]\s*["'][^"'$\{]{4,}["']"#).unwrap(),
            file_patterns: &["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"],
            category: "Docker",
            remediation: "Use environment variables or Docker secrets: ${DB_PASSWORD}",
            negative_pattern: None,
        },

        // ============== TERRAFORM ==============
        IacRule {
            id: "IAC-TF-001", name: "Terraform Hardcoded Secret",
            description: "Sensitive value hardcoded in Terraform config",
            severity: "CRITICAL", cwe: "CWE-798",
            pattern: Regex::new(r#"(?i)(?:password|secret_key|access_key|token|private_key)\s*=\s*"[^$\{"][^"]{4,}""#).unwrap(),
            file_patterns: &["*.tf", "*.tfvars"],
            category: "Terraform",
            remediation: "Use variables with sensitive = true, or AWS Secrets Manager / Vault",
            negative_pattern: Some(Regex::new(r"(?i)(?:example|changeme|placeholder|TODO|FIXME)").unwrap()),
        },
        IacRule {
            id: "IAC-TF-002", name: "AWS Security Group Open to World",
            description: "Security group ingress rule open to 0.0.0.0/0",
            severity: "HIGH", cwe: "CWE-284",
            pattern: Regex::new(r#"cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]"#).unwrap(),
            file_patterns: &["*.tf"],
            category: "Terraform",
            remediation: "Restrict CIDR blocks to specific IP ranges",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-TF-003", name: "S3 Bucket Public Access",
            description: "S3 bucket configured for public access",
            severity: "CRITICAL", cwe: "CWE-284",
            pattern: Regex::new(r#"(?i)(?:acl\s*=\s*"public|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false)"#).unwrap(),
            file_patterns: &["*.tf"],
            category: "Terraform",
            remediation: "Set block_public_acls = true and block_public_policy = true",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-TF-004", name: "RDS Public Access",
            description: "RDS instance publicly accessible",
            severity: "CRITICAL", cwe: "CWE-284",
            pattern: Regex::new(r"(?i)publicly_accessible\s*=\s*true").unwrap(),
            file_patterns: &["*.tf"],
            category: "Terraform",
            remediation: "Set publicly_accessible = false for database instances",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-TF-005", name: "Terraform No Encryption at Rest",
            description: "Resource without encryption at rest",
            severity: "HIGH", cwe: "CWE-311",
            pattern: Regex::new(r#"(?i)(?:encrypted\s*=\s*false|storage_encrypted\s*=\s*false|kms_key_id\s*=\s*"")"#).unwrap(),
            file_patterns: &["*.tf"],
            category: "Terraform",
            remediation: "Enable encryption: encrypted = true, specify kms_key_id",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-TF-006", name: "IAM Wildcard Action",
            description: "IAM policy with wildcard (*) action — overly permissive",
            severity: "HIGH", cwe: "CWE-269",
            pattern: Regex::new(r#"(?i)(?:"Action"\s*:\s*"\*"|actions?\s*=\s*\[\s*"\*"\s*\])"#).unwrap(),
            file_patterns: &["*.tf", "*.json"],
            category: "Terraform",
            remediation: "Follow principle of least privilege — specify exact required actions",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-TF-007", name: "CloudTrail Logging Disabled",
            description: "CloudTrail logging not enabled — no audit trail",
            severity: "HIGH", cwe: "CWE-778",
            pattern: Regex::new(r"(?i)enable_logging\s*=\s*false").unwrap(),
            file_patterns: &["*.tf"],
            category: "Terraform",
            remediation: "Enable CloudTrail logging: enable_logging = true",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-TF-008", name: "Terraform HTTP Module Source",
            description: "Module sourced from HTTP URL — supply chain risk",
            severity: "HIGH", cwe: "CWE-829",
            pattern: Regex::new(r#"(?i)source\s*=\s*"http://"#).unwrap(),
            file_patterns: &["*.tf"],
            category: "Terraform",
            remediation: "Use HTTPS or Terraform Registry for module sources",
            negative_pattern: None,
        },

        // ============== KUBERNETES ==============
        IacRule {
            id: "IAC-K8S-001", name: "K8s Container Running as Root",
            description: "Container running as root user",
            severity: "HIGH", cwe: "CWE-250",
            pattern: Regex::new(r"(?i)runAsUser\s*:\s*0").unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Set runAsUser to non-zero, runAsNonRoot: true",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-K8S-002", name: "K8s Privileged Container",
            description: "Container running in privileged mode",
            severity: "CRITICAL", cwe: "CWE-250",
            pattern: Regex::new(r"(?i)privileged\s*:\s*true").unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Never use privileged: true. Add specific capabilities instead",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-K8S-003", name: "K8s hostPath Volume Mount",
            description: "Mounting host filesystem — container escape risk",
            severity: "HIGH", cwe: "CWE-250",
            pattern: Regex::new(r"(?i)hostPath\s*:").unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Use PersistentVolumeClaim instead of hostPath",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-K8S-004", name: "K8s Host Network",
            description: "Pod using host network namespace",
            severity: "HIGH", cwe: "CWE-668",
            pattern: Regex::new(r"(?i)hostNetwork\s*:\s*true").unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Use pod networking, not host networking",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-K8S-005", name: "K8s Default Namespace",
            description: "Resource deployed in default namespace",
            severity: "LOW", cwe: "CWE-668",
            pattern: Regex::new(r#"(?i)namespace\s*:\s*["']?default["']?"#).unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Use dedicated namespaces for workloads",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-K8S-006", name: "K8s Writable Root Filesystem",
            description: "Container filesystem is writable — easier to compromise",
            severity: "MEDIUM", cwe: "CWE-732",
            pattern: Regex::new(r"(?i)readOnlyRootFilesystem\s*:\s*false").unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Set readOnlyRootFilesystem: true, use emptyDir for writable paths",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-K8S-007", name: "K8s Secrets in Environment Variables",
            description: "K8s secrets passed as environment variables — visible in pod spec",
            severity: "MEDIUM", cwe: "CWE-312",
            pattern: Regex::new(r"(?i)secretKeyRef\s*:").unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Mount secrets as files instead of environment variables",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-K8S-008", name: "K8s Image Pull from Latest",
            description: "Container image using :latest tag",
            severity: "MEDIUM", cwe: "CWE-829",
            pattern: Regex::new(r"(?i)image\s*:\s*\S+:latest").unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Pin specific image versions with digest or semantic version",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-K8S-009", name: "K8s Capability ALL",
            description: "Container granted ALL capabilities",
            severity: "CRITICAL", cwe: "CWE-250",
            pattern: Regex::new(r"(?i)(?:add|capabilities)\s*:.*ALL").unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Kubernetes",
            remediation: "Drop ALL capabilities, add only specific needed ones",
            negative_pattern: Some(Regex::new(r"(?i)drop").unwrap()),
        },

        // ============== CI/CD ==============
        IacRule {
            id: "IAC-CI-001", name: "CI/CD Secret in Plaintext",
            description: "Secret value in CI/CD configuration",
            severity: "HIGH", cwe: "CWE-798",
            pattern: Regex::new(r#"(?i)(?:password|secret|token|key)\s*[:=]\s*["'][^$\{"\n]{8,}["']"#).unwrap(),
            file_patterns: &[".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".travis.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml"],
            category: "CI/CD",
            remediation: "Use encrypted CI/CD secrets: ${{ secrets.MY_SECRET }}",
            negative_pattern: Some(Regex::new(r"(?i)\$\{\{|%\{|\$\(").unwrap()),
        },
        IacRule {
            id: "IAC-CI-002", name: "GitHub Actions pull_request_target",
            description: "pull_request_target with checkout — enables privilege escalation",
            severity: "HIGH", cwe: "CWE-250",
            pattern: Regex::new(r"(?i)pull_request_target").unwrap(),
            file_patterns: &[".github/workflows"],
            category: "CI/CD",
            remediation: "Never checkout PR code with pull_request_target. Use pull_request event instead".into(),
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-CI-003", name: "GitHub Actions Script Injection",
            description: "User-controlled input in run: step — command injection",
            severity: "HIGH", cwe: "CWE-78",
            pattern: Regex::new(r"\$\{\{\s*(?:github\.event\.(?:issue|comment|review|pull_request)\.(?:body|title)|github\.head_ref)\s*\}\}").unwrap(),
            file_patterns: &[".github/workflows"],
            category: "CI/CD",
            remediation: "Store in env variable first, then reference: env: TITLE: ${{ github.event.issue.title }}",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-CI-004", name: "CI/CD Unsafe Checkout",
            description: "Checking out code with persist-credentials or fetching all history",
            severity: "MEDIUM", cwe: "CWE-250",
            pattern: Regex::new(r"(?i)persist-credentials\s*:\s*true").unwrap(),
            file_patterns: &[".github/workflows", ".gitlab-ci.yml"],
            category: "CI/CD",
            remediation: "Set persist-credentials: false to limit credential exposure",
            negative_pattern: None,
        },

        // ============== NGINX ==============
        IacRule {
            id: "IAC-NGX-001", name: "Nginx Server Tokens Exposed",
            description: "Nginx version exposed in headers",
            severity: "LOW", cwe: "CWE-200",
            pattern: Regex::new(r"(?i)server_tokens\s+on").unwrap(),
            file_patterns: &["nginx.conf", "*.nginx", "*.conf"],
            category: "Nginx",
            remediation: "Set server_tokens off; to hide version information",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-NGX-002", name: "Nginx Missing Security Headers",
            description: "Missing X-Frame-Options header — clickjacking risk",
            severity: "MEDIUM", cwe: "CWE-1021",
            pattern: Regex::new(r"(?i)^\s*server\s*\{").unwrap(),
            file_patterns: &["nginx.conf"],
            category: "Nginx",
            remediation: "Add: add_header X-Frame-Options DENY; add_header X-Content-Type-Options nosniff;",
            negative_pattern: Some(Regex::new(r"(?i)X-Frame-Options").unwrap()),
        },
        IacRule {
            id: "IAC-NGX-003", name: "Nginx Autoindex Enabled",
            description: "Directory listing enabled — information disclosure",
            severity: "MEDIUM", cwe: "CWE-548",
            pattern: Regex::new(r"(?i)autoindex\s+on").unwrap(),
            file_patterns: &["nginx.conf", "*.conf"],
            category: "Nginx",
            remediation: "Disable directory listing: autoindex off;",
            negative_pattern: None,
        },

        // ============== ANSIBLE ==============
        IacRule {
            id: "IAC-ANS-001", name: "Ansible Hardcoded Password",
            description: "Password hardcoded in Ansible playbook/vars",
            severity: "HIGH", cwe: "CWE-798",
            pattern: Regex::new(r#"(?i)(?:password|passwd|secret)\s*:\s*["']?[^{$\s][^\n"']{4,}"#).unwrap(),
            file_patterns: &["*.yaml", "*.yml"],
            category: "Ansible",
            remediation: "Use Ansible Vault for encrypting sensitive values",
            negative_pattern: Some(Regex::new(r"(?i)(?:\{\{|vault|lookup|vars\.)").unwrap()),
        },

        // ============== HELM ==============
        IacRule {
            id: "IAC-HELM-001", name: "Helm Chart Hardcoded Values",
            description: "Sensitive values hardcoded in Helm values",
            severity: "HIGH", cwe: "CWE-798",
            pattern: Regex::new(r#"(?i)(?:password|secret|token|key)\s*:\s*["']?[a-zA-Z0-9+/=_-]{8,}["']?"#).unwrap(),
            file_patterns: &["values.yaml", "values.yml"],
            category: "Helm",
            remediation: "Use Helm secrets plugin or reference external secret managers",
            negative_pattern: Some(Regex::new(r"(?i)(?:changeme|placeholder|TODO|FIXME|\{\{)").unwrap()),
        },

        // ============== SHELL SCRIPTS ==============
        IacRule {
            id: "IAC-SH-001", name: "Shell Script Secrets",
            description: "Hardcoded credentials in shell script",
            severity: "HIGH", cwe: "CWE-798",
            pattern: Regex::new(r#"(?i)(?:PASSWORD|SECRET|TOKEN|API_KEY|AWS_SECRET)\s*=\s*["'][^$\{]{4,}["']"#).unwrap(),
            file_patterns: &["*.sh", "*.bash", "*.zsh"],
            category: "Shell",
            remediation: "Use environment variables or a secrets manager",
            negative_pattern: Some(Regex::new(r"(?i)(?:example|demo|test|placeholder)").unwrap()),
        },
        IacRule {
            id: "IAC-SH-002", name: "Curl Insecure Flag",
            description: "curl with --insecure / -k flag — disables TLS verification",
            severity: "HIGH", cwe: "CWE-295",
            pattern: Regex::new(r"curl\s+.*(?:--insecure|-k)\s").unwrap(),
            file_patterns: &["*.sh", "*.bash", "*.zsh", "Dockerfile", "Makefile", "*.yaml", "*.yml"],
            category: "Shell",
            remediation: "Remove --insecure flag, use proper TLS certificates",
            negative_pattern: None,
        },

        // ============== ANDROID MANIFEST ==============
        IacRule {
            id: "IAC-ANDROID-001", name: "Android App Links Placeholder Domain",
            description: "App Links intent-filter uses a placeholder domain — autoVerify will always fail, allowing any app to intercept the intent and capture OAuth redirect data",
            severity: "HIGH", cwe: "CWE-926",
            pattern: Regex::new(r#"android:host\s*=\s*["'](?:your\.domain\.com|example\.com|domain\.com|yourapp\.com|your-domain\.com|placeholder\.com|<your[._-]?domain>)"#).unwrap(),
            file_patterns: &["AndroidManifest.xml", "*.xml"],
            category: "Android",
            remediation: "Replace placeholder domain with your verified app domain and host .well-known/assetlinks.json on that domain",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-ANDROID-002", name: "Android Backup Enabled",
            description: "android:allowBackup=true permits ADB backup of app data including stored tokens, cached credentials, and SharedPreferences",
            severity: "MEDIUM", cwe: "CWE-312",
            pattern: Regex::new(r#"android:allowBackup\s*=\s*["']true["']"#).unwrap(),
            file_patterns: &["AndroidManifest.xml"],
            category: "Android",
            remediation: "Set android:allowBackup=\"false\", or use android:fullBackupOnly=\"true\" with a backup_rules.xml that excludes sensitive files",
            negative_pattern: None,
        },
        IacRule {
            id: "IAC-ANDROID-003", name: "Android Cleartext Traffic Permitted",
            description: "android:usesCleartextTraffic=true allows unencrypted HTTP connections — credentials and tokens transmitted in plaintext are vulnerable to MITM interception",
            severity: "HIGH", cwe: "CWE-319",
            pattern: Regex::new(r#"android:usesCleartextTraffic\s*=\s*["']true["']"#).unwrap(),
            file_patterns: &["AndroidManifest.xml", "network_security_config.xml", "*.xml"],
            category: "Android",
            remediation: "Set android:usesCleartextTraffic=\"false\" and enforce HTTPS for all connections",
            negative_pattern: None,
        },
    ]
}
