<p align="center">
  <pre>
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║  ██║██╔══██╗██║████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██║     ███████║███████║██║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██╔══██║██╔══██║██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║██║  ██║██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝ ╚═══╝
  </pre>
</p>

<h1 align="center">VulnChain</h1>
<p align="center">
  <b>Deep Vulnerability Scanner & Attack Chain Analyzer</b><br>
  <i>Semgrep-style pattern matching + CodeQL-style data flow analysis — built in Rust</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" alt="Rust">
  <img src="https://img.shields.io/badge/rules-200%2B-blue?style=flat-square" alt="200+ Rules">
  <img src="https://img.shields.io/badge/languages-15%2B-green?style=flat-square" alt="15+ Languages">
  <img src="https://img.shields.io/badge/output-SARIF%20v2.1.0-purple?style=flat-square" alt="SARIF">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" alt="MIT">
</p>

---

## What is VulnChain?

VulnChain is a **fast, multi-engine static analysis security scanner** built in Rust. It combines the best ideas from Semgrep (pattern-based composite rules with AND/OR/NOT logic) and CodeQL (data flow graphs, taint tracking, source→sanitizer→sink path analysis) into a single blazing-fast binary.

It scans cloned repositories for **vulnerability patterns across 15+ programming languages**, performs **taint analysis**, **data flow tracking**, **secret detection**, **dependency auditing**, **IaC/config security scanning**, and builds **multi-step attack chain scenarios** showing how individual vulnerabilities can be chained together for maximum impact.

### Key Capabilities

| Engine | Inspired By | What It Does |
|--------|------------|--------------|
| **Pattern Scanner** | Semgrep | Regex-based vulnerability detection across 15+ languages |
| **Composite Rules** | Semgrep | AND/OR/NOT/Inside/NotInside multi-condition logic |
| **Data Flow Tracker** | CodeQL | Source→sink path analysis with intermediate step tracking |
| **Taint Analyzer** | CodeQL | Tracks tainted variables from user input to dangerous sinks |
| **Sanitizer Awareness** | Both | Excludes findings where proper sanitization is detected |
| **IaC Scanner** | Checkov/tfsec | Docker, Terraform, Kubernetes, CI/CD, Nginx config rules |
| **Secret Detector** | TruffleHog | API keys, tokens, passwords, AWS credentials |
| **Dependency Auditor** | npm audit | Known CVEs in npm, pip, maven, go, ruby, cargo packages |
| **Chain Analyzer** | Custom | Multi-step attack scenarios (SQLi→Data Breach, XXE→SSRF, etc.) |

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/vulnchain/vulnchain.git
cd vulnchain

# Build release binary
cargo build --release

# Binary is at ./target/release/vulnchain
```

### Usage

```bash
# Scan current directory
vulnchain

# Scan a specific path
vulnchain -t /path/to/repo

# Clone and scan a remote repository
vulnchain --clone https://github.com/user/repo

# Full scan with JSON + SARIF output
vulnchain -t /path/to/repo --output report.json --sarif report.sarif

# Quiet mode — only write reports, no terminal output
vulnchain -t /path/to/repo -q --output report.json --sarif report.sarif

# Filter by severity
vulnchain -t /path/to/repo -s critical

# Control parallelism
vulnchain -t /path/to/repo -j 8

# Skip IaC scanning
vulnchain -t /path/to/repo --no-iac
```

---

## CLI Reference

```
vulnchain [OPTIONS]

OPTIONS:
  -t, --target <PATH>        Path to repository/directory to scan [default: .]
  -o, --output <FILE>        Output JSON report to file
      --sarif <FILE>         Output SARIF v2.1.0 report (GitHub Code Scanning / VS Code)
  -s, --severity <LEVEL>     Minimum severity filter: critical, high, medium, low, info [default: low]
  -q, --quiet                Suppress terminal output (only write JSON/SARIF)
  -j, --threads <N>          Number of threads for parallel scanning (0 = auto) [default: 0]
  -c, --clone <URL>          Clone a git repository (--depth 1) and scan it
      --no-iac               Disable IaC/config security scanning
  -h, --help                 Print help
  -V, --version              Print version
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Non-critical findings present |
| `2` | Critical findings or attack chains detected |

---

## Analysis Engines

### 1. Pattern-Based Vulnerability Scanner

Scans source code using 148+ regex-based rules across 15+ languages, each mapped to CWE identifiers and OWASP categories.

**Supported Languages:**

| Language | Extensions | Rule Count |
|----------|-----------|------------|
| Python | `.py` | 25+ |
| JavaScript / TypeScript | `.js`, `.ts`, `.jsx`, `.tsx` | 30+ |
| Java / Kotlin | `.java`, `.kt` | 20+ |
| C / C++ | `.c`, `.cpp`, `.h`, `.hpp` | 15+ |
| Go | `.go` | 10+ |
| PHP | `.php` | 10+ |
| Ruby | `.rb` | 10+ |
| C# | `.cs` | 10+ |
| Rust | `.rs` | 5+ |
| Swift / Obj-C | `.swift`, `.m` | 5+ |
| Shell / Bash | `.sh`, `.bash` | 5+ |

**Vulnerability Categories (31):**

```
Injection          XSS                 CommandInjection     PathTraversal
InsecureDeser      HardcodedSecret     WeakCrypto           SSRF
XXE                BrokenAuth          InsecureFileOps      BufferOverflow
UseAfterFree       FormatString        RaceCondition        MemoryLeak
IntegerOverflow    InsecureRandom      OpenRedirect         CSRF
IDOR               InfoDisclosure      MassAssignment       InsecureDependency
PrivilegeEsc       Misconfiguration    PrototypePollution   TemplateInjection
LDAPInjection      RegexDoS            InsecureTLS
```

---

### 2. Composite Rule Engine (Semgrep-style)

**40+ composite rules** using multi-condition logic inspired by Semgrep's pattern operators:

```
Pattern        → Single regex match
And([...])     → ALL conditions must match on the same line
Or([...])      → At least ONE condition must match
Not(pattern)   → Pattern must NOT be present (false-positive reduction)
Inside(ctx)    → Match only if the line appears inside a specific context
NotInside(ctx) → Exclude matches that appear inside a certain context
```

**Example — SQL Injection with sanitizer awareness:**
```
Rule: COMP-SQLI-001
Condition: And([
  Pattern("execute.*(?:format|%s|\\+|f\")"),   ← SQL string construction
  Not("parameterized|placeholder|sanitize")     ← No sanitization present
])
```

**Coverage includes:**
- SQL/Command/Code Injection (with sanitizer checks)
- XSS (with framework-aware exclusions — React, Django auto-escaping)
- SSRF, XXE, Deserialization (with parser config checks)
- Auth/AuthZ issues (route handlers without middleware)
- Crypto weaknesses (hardcoded keys, ECB mode)
- Insecure configs (debug mode, CORS wildcard, cookie flags)
- IDOR, Open Redirect, Template Injection, Prototype Pollution
- Log Injection, Mass Assignment, ReDoS, File Upload

---

### 3. Data Flow Tracker (CodeQL-style)

Tracks data from **21 source patterns** through **assignments and transformations** to **12 sink categories**, with **sanitizer verification** at each step.

```
Source (line 7)  →  Assignment (line 8)  →  Sink (line 15)
  const id =        const query =           connection.query(
  req.query.id       "SELECT..." + id         query, ...)

Verdict: CRITICAL — No sanitization detected between source and sink
```

**Sources (21 patterns across 9 languages):**
- Python: `request.args`, `request.form`, `request.get_json()`
- JavaScript: `req.query`, `req.body`, `req.params`, DOM APIs, `process.env`
- Java: `request.getParameter()`, `@RequestParam`, `@PathVariable`
- PHP: `$_GET`, `$_POST`, `$_REQUEST`, `php://input`
- Go: `r.FormValue()`, `r.URL.Query()`, `c.Param()`
- Ruby: `params[]`, `request.body`
- C/C++: `fgets()`, `scanf()`, `recv()`, `getenv()`
- C#: `Request.Query`, `Request.Form`
- Rust: `std::env::args`, `req.`

**Sinks (12 categories):**
```
sql_execution       → CWE-89   (SQL Injection)
command_execution   → CWE-78   (OS Command Injection)
file_operations     → CWE-22   (Path Traversal)
ssrf                → CWE-918  (Server-Side Request Forgery)
code_execution      → CWE-94   (Code Injection)
deserialization     → CWE-502  (Insecure Deserialization)
xss / html_output   → CWE-79   (Cross-Site Scripting)
ldap_query          → CWE-90   (LDAP Injection)
open_redirect       → CWE-601  (URL Redirection)
template_injection  → CWE-1336 (Server-Side Template Injection)
xxe                 → CWE-611  (XML External Entity)
log_injection       → CWE-117  (Log Injection)
```

**Sanitizer Database (10 categories):**
XSS sanitizers, SQL parameterization, Command escaping, Path validation, URL validation, XXE prevention, Deserialization safeguards, CSRF tokens, Auth checks, Rate limiting.

---

### 4. Taint Analyzer

Classic taint analysis tracking variables from user-controlled sources to dangerous sinks within a single file. Identifies tainted variables, tracks assignments, and reports flows with confidence levels (HIGH/MEDIUM/LOW).

---

### 5. IaC / Config Security Scanner

**40+ rules** scanning infrastructure-as-code and configuration files:

| Category | File Types | Examples |
|----------|-----------|---------|
| **Docker** | `Dockerfile` | FROM :latest, secrets in ENV, running as root, missing HEALTHCHECK, ADD vs COPY, exposed ports |
| **Terraform** | `*.tf` | Missing encryption, public S3 buckets, open security groups, no logging, wildcard IAM |
| **Kubernetes** | `*.yaml`, `*.yml` | Privileged containers, hostNetwork, no resource limits, no securityContext, hostPath mounts |
| **CI/CD** | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile` | Secrets in env, pull_request_target, insecure curl pipes |
| **Nginx** | `nginx.conf` | server_tokens on, missing security headers, autoindex on |
| **Docker Compose** | `docker-compose.yml` | Privileged mode, host network, missing security_opt |
| **Ansible** | `*.yml` | become: true without become_user |
| **Helm** | `values.yaml` | Container running as root |
| **Shell** | `*.sh` | Command injection, curl pipe to shell, chmod 777, predictable temp files |

---

### 6. Secret Detection

**28+ patterns** detecting hardcoded secrets and credentials with automatic redaction in output:

- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- Google API Keys & Service Accounts
- Stripe API Keys (secret & publishable)
- Slack Bot/Webhook Tokens
- Auth0 Client Secrets
- Generic API Keys, Passwords, JWT Secrets
- Private Keys (RSA, DSA, EC, PGP)
- Connection Strings (database URLs)
- Bearer Tokens, Basic Auth

---

### 7. Dependency Vulnerability Scanner

Scans **9 package manifest formats** against a known CVE database:

| Package Manager | Manifest File |
|----------------|--------------|
| npm | `package.json` |
| pip | `requirements.txt` |
| Maven | `pom.xml` |
| Gradle | `build.gradle` |
| Go | `go.mod` |
| Ruby | `Gemfile` |
| Cargo (Rust) | `Cargo.toml` |
| Composer (PHP) | `composer.json` |
| Mix (Elixir) | `mix.exs` |

**39 known CVEs** tracked including lodash, minimist, express, jsonwebtoken, pyyaml, django, flask, requests, and more.

---

### 8. Attack Chain Analyzer

**13 chain patterns** that correlate individual findings into multi-step attack scenarios with CVSS score estimates:

| Chain | Severity | CVSS | Description |
|-------|----------|------|-------------|
| Taint → SQL Injection | CRITICAL | 9.8 | User input flows to SQL execution without sanitization |
| Taint → Command Injection | CRITICAL | 9.8 | User input flows to OS command execution |
| SSRF → Internal Access | CRITICAL | 9.1 | SSRF enables cloud metadata / internal service access |
| XXE → SSRF → Exfiltration | CRITICAL | 9.6 | XML external entity triggers server-side requests |
| Auth Bypass → Privilege Escalation | CRITICAL | 9.4 | Weak auth + injection = full system compromise |
| Deserialization → RCE | CRITICAL | 9.8 | Gadget chain achieves arbitrary code execution |
| Template Injection → RCE | CRITICAL | 9.8 | SSTI escalation to full code execution |
| SQL Injection + Weak Auth | CRITICAL | 9.9 | Combined SQLi and auth bypass = full DB takeover |
| XSS → Session Hijacking | HIGH | 8.1 | Script injection steals session cookies |
| Prototype Pollution → RCE | HIGH | 8.6 | Object pollution triggers code execution via gadget |
| Path Traversal → Credential Theft | HIGH | 8.2 | Directory traversal reads sensitive files |
| Open Redirect → OAuth Token Theft | HIGH | 8.0 | Redirect abuse in OAuth flow steals tokens |
| Log Injection → SIEM Evasion | MEDIUM | 5.3 | Crafted log entries evade detection |

---

## Output Formats

### Terminal Output

Rich colored terminal output with ASCII art banner, severity badges, attack scenarios, data flow visualizations, and remediation guidance.

```
  SCAN SUMMARY
  ├ Files scanned:       4
  ├ Lines scanned:       76
  ├ Code vulnerabilities: 5
  ├ Composite rule hits: 6
  ├ Data flow paths:     19
  ├ Secret leaks:        3
  ├ Dependency issues:   4
  ├ Taint flows:         3
  ├ IaC/Config issues:   6
  ╰ Attack chains:       4

  CRITICAL: 3 | HIGH: 1 | MEDIUM: 1 | LOW: 0 | INFO: 0
```

### JSON Report (`--output report.json`)

Full structured JSON report containing all findings, metadata, and attack chains — suitable for programmatic consumption and CI/CD integration.

### SARIF v2.1.0 (`--sarif report.sarif`)

Industry-standard [SARIF](https://sarifweb.azurewebsites.net/) output compatible with:
- **GitHub Code Scanning** — Upload via `github/codeql-action/upload-sarif`
- **VS Code** — SARIF Viewer extension for in-editor annotations
- **Azure DevOps** — Native SARIF support in pipelines
- **DefectDojo, SonarQube** — Import via SARIF adapters

Includes `codeFlows` for taint analysis results, showing the full source→sink data path in your IDE.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  vulnchain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install VulnChain
        run: |
          cargo install --path .

      - name: Run VulnChain
        run: vulnchain -t . --sarif results.sarif -q

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: rust:latest
  script:
    - cargo build --release
    - ./target/release/vulnchain -t . --output report.json --sarif report.sarif -q
  artifacts:
    reports:
      sast: report.sarif
    paths:
      - report.json
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
vulnchain -t . -s critical -q
if [ $? -eq 2 ]; then
  echo "CRITICAL vulnerabilities detected. Commit blocked."
  exit 1
fi
```

---

## Architecture

```
vulnchain
├── src/
│   ├── main.rs                    # CLI entry point (clap)
│   ├── scanner/
│   │   ├── engine.rs              # Scan orchestrator — parallel pipeline
│   │   ├── file_collector.rs      # File discovery (50+ extensions, .gitignore)
│   │   ├── secrets.rs             # Secret detection (28+ patterns)
│   │   └── iac.rs                 # IaC/config scanner (40+ rules)
│   ├── patterns/
│   │   ├── vuln_rules.rs          # Core types: Severity, VulnCategory, Finding
│   │   ├── language.rs            # Primary vulnerability rules (72 rules)
│   │   ├── language_extended.rs   # Extended rules (76+ rules)
│   │   └── dependency.rs          # Dependency CVE database (39 CVEs)
│   ├── dataflow/
│   │   ├── graph.rs               # Data flow graph with BFS pathfinding
│   │   ├── flow_tracker.rs        # Source→sink tracking (21 sources, 12 sinks)
│   │   ├── composite.rs           # Semgrep-style composite rules (40+ rules)
│   │   ├── sanitizers.rs          # Sanitizer database (10 categories)
│   │   └── scope.rs               # Scope analysis (function/class/try-catch)
│   ├── analyzer/
│   │   ├── taint.rs               # Classic taint analysis
│   │   ├── chain.rs               # Attack chain builder (13 patterns)
│   │   └── severity.rs            # Severity utilities
│   └── report/
│       ├── formatter.rs           # Terminal + JSON output
│       └── sarif.rs               # SARIF v2.1.0 output
├── Cargo.toml
└── README.md
```

**24 source files — ~6,600 lines of Rust**

### Scan Pipeline

```
                    ┌──────────────────┐
                    │   File Collector  │  Discovers source, config, dependency files
                    │  (.gitignore-aware)│  50+ extensions, skip node_modules/vendor
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼──────┐ ┌────▼─────┐ ┌──────▼──────┐
    │  Source Files   │ │ Dep Files│ │Config Files │
    │ (parallel scan) │ │  (CVEs)  │ │(secrets+IaC)│
    └───────┬────────┘ └────┬─────┘ └──────┬──────┘
            │               │              │
    ┌───────┴────────────┐  │              │
    │ Per-file (parallel):│  │              │
    │ • Pattern matching  │  │              │
    │ • Secret scanning   │  │              │
    │ • Taint analysis    │  │              │
    │ • Data flow tracking│  │              │
    │ • Composite rules   │  │              │
    └───────┬────────────┘  │              │
            │               │              │
            └───────────────┼──────────────┘
                            │
                  ┌─────────▼──────────┐
                  │  Chain Analyzer     │  Correlates findings into
                  │  (13 attack chains) │  multi-step attack scenarios
                  └─────────┬──────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
        ┌─────▼────┐  ┌────▼────┐  ┌─────▼─────┐
        │ Terminal  │  │  JSON   │  │  SARIF    │
        │ (colored) │  │ Report  │  │  v2.1.0   │
        └──────────┘  └─────────┘  └───────────┘
```

---

## Performance

VulnChain is built for speed with Rust and Rayon parallel processing:

- **Parallel scanning** — Source files scanned concurrently across all CPU cores
- **Compiled regex** — All patterns compiled once at startup (zero per-file overhead)
- **Single-pass analysis** — Pattern matching, taint analysis, data flow tracking, composite rules, and secret detection all run in a single file read
- **Minimal allocations** — Efficient string handling and static rule references

---

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `rayon` | 1.10 | Data-parallel scanning |
| `regex` | 1.11 | Pattern matching engine |
| `serde` + `serde_json` | 1.0 | JSON serialization |
| `clap` | 4.5 | CLI argument parsing |
| `walkdir` | 2.5 | Recursive directory traversal |
| `colored` | 2.1 | Terminal color output |
| `sha2` | 0.10 | Finding fingerprint hashing |
| `hex` | 0.4 | Hex encoding |
| `chrono` | 0.4 | Timestamps |
| `ignore` | 0.4 | `.gitignore` support |

**Zero runtime dependencies** — compiles to a single static binary.

---

## License

MIT

---

<p align="center">
  <b>VulnChain</b> — Find vulnerabilities. Trace data flows. Build attack chains.<br>
  <i>One binary. 200+ rules. 15+ languages. Zero dependencies at runtime.</i>
</p>
