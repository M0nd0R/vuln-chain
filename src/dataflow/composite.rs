use regex::Regex;
use serde::{Deserialize, Serialize};

/// Composite Rule Engine — inspired by Semgrep's multi-pattern rule system
/// Supports:
/// - `patterns` (AND): All patterns must match in the same scope
/// - `pattern-either` (OR): At least one pattern must match
/// - `pattern-not` (NOT): Pattern must NOT appear (false positive reduction)
/// - `pattern-inside` (CONTEXT): Match must be inside a given context
/// - `pattern-not-inside` (EXCLUDE CONTEXT): Match must NOT be inside context

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub cwe: String,
    pub owasp: String,
    pub languages: Vec<String>,
    pub condition: RuleCondition,
    pub remediation: String,
    pub category: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    /// Single pattern match
    Pattern(String),
    /// All conditions must match (AND)
    And(Vec<RuleCondition>),
    /// At least one condition must match (OR)
    Or(Vec<RuleCondition>),
    /// Pattern must NOT match — filters false positives
    Not(Box<RuleCondition>),
    /// Match must be inside this context (e.g., inside a specific function)
    Inside(String),
    /// Match must NOT be inside this context
    NotInside(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeFinding {
    pub rule_id: String,
    pub rule_name: String,
    pub description: String,
    pub severity: String,
    pub cwe: String,
    pub owasp: String,
    pub file_path: String,
    pub line_number: usize,
    pub line_content: String,
    pub confidence: String,
    pub category: String,
    pub remediation: String,
}

pub struct CompositeEngine {
    rules: Vec<CompiledComposite>,
}

struct CompiledComposite {
    rule: CompositeRule,
    compiled: CompiledCondition,
}

enum CompiledCondition {
    Pattern(Regex),
    And(Vec<CompiledCondition>),
    Or(Vec<CompiledCondition>),
    Not(Box<CompiledCondition>),
    Inside(Regex),
    NotInside(Regex),
}

impl CompositeEngine {
    pub fn new() -> Self {
        let mut rules = Vec::new();
        
        // Build all composite rules
        for rule in build_composite_rules() {
            if let Some(compiled) = compile_condition(&rule.condition) {
                rules.push(CompiledComposite { rule, compiled });
            }
        }

        Self { rules }
    }

    pub fn scan(&self, file_path: &str, content: &str, ext: &str) -> Vec<CompositeFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for cr in &self.rules {
            if !cr.rule.languages.iter().any(|l| l == ext) { continue; }

            for (i, line) in lines.iter().enumerate() {
                if evaluate_condition(&cr.compiled, line, &lines, i) {
                    findings.push(CompositeFinding {
                        rule_id: cr.rule.id.clone(),
                        rule_name: cr.rule.name.clone(),
                        description: cr.rule.description.clone(),
                        severity: cr.rule.severity.clone(),
                        cwe: cr.rule.cwe.clone(),
                        owasp: cr.rule.owasp.clone(),
                        file_path: file_path.to_string(),
                        line_number: i + 1,
                        line_content: line.to_string(),
                        confidence: cr.rule.confidence.clone(),
                        category: cr.rule.category.clone(),
                        remediation: cr.rule.remediation.clone(),
                    });
                }
            }
        }

        findings
    }
}

fn compile_condition(cond: &RuleCondition) -> Option<CompiledCondition> {
    match cond {
        RuleCondition::Pattern(p) => Regex::new(p).ok().map(CompiledCondition::Pattern),
        RuleCondition::And(conds) => {
            let compiled: Vec<_> = conds.iter().filter_map(compile_condition).collect();
            if compiled.is_empty() { None } else { Some(CompiledCondition::And(compiled)) }
        }
        RuleCondition::Or(conds) => {
            let compiled: Vec<_> = conds.iter().filter_map(compile_condition).collect();
            if compiled.is_empty() { None } else { Some(CompiledCondition::Or(compiled)) }
        }
        RuleCondition::Not(c) => compile_condition(c).map(|cc| CompiledCondition::Not(Box::new(cc))),
        RuleCondition::Inside(p) => Regex::new(p).ok().map(CompiledCondition::Inside),
        RuleCondition::NotInside(p) => Regex::new(p).ok().map(CompiledCondition::NotInside),
    }
}

fn evaluate_condition(cond: &CompiledCondition, line: &str, all_lines: &[&str], line_idx: usize) -> bool {
    match cond {
        CompiledCondition::Pattern(re) => re.is_match(line),
        CompiledCondition::And(conds) => conds.iter().all(|c| evaluate_condition(c, line, all_lines, line_idx)),
        CompiledCondition::Or(conds) => conds.iter().any(|c| evaluate_condition(c, line, all_lines, line_idx)),
        CompiledCondition::Not(c) => !evaluate_condition(c, line, all_lines, line_idx),
        CompiledCondition::Inside(re) => {
            // Check if any preceding line matches the "inside" context
            for i in (0..line_idx).rev() {
                if re.is_match(all_lines[i]) { return true; }
                // Stop at function boundaries
                if all_lines[i].trim().is_empty() && i + 5 < line_idx { break; }
            }
            false
        }
        CompiledCondition::NotInside(re) => {
            for i in (0..line_idx).rev() {
                if re.is_match(all_lines[i]) { return false; }
                if all_lines[i].trim().is_empty() && i + 5 < line_idx { break; }
            }
            true
        }
    }
}

/// Build all composite rules — Semgrep-inspired multi-pattern rules
fn build_composite_rules() -> Vec<CompositeRule> {
    vec![
        // === SQL Injection with context awareness ===
        CompositeRule {
            id: "COMP-SQLI-001".into(), name: "SQL Injection in Web Handler".into(),
            description: "SQL query with string formatting inside a web request handler".into(),
            severity: "CRITICAL".into(), cwe: "CWE-89".into(), owasp: "A03:2021".into(),
            languages: vec!["py".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r#"(?i)(?:execute|cursor\.execute|\.raw)\s*\(\s*(?:f["\']|.*%s|.*\.format)"#.into()),
                RuleCondition::Inside(r"(?i)(?:def\s+\w+.*request|@app\.route|@bp\.route|@api\.)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:parameterized|placeholder|prepared|\?\s*,)".into()))),
            ]),
            remediation: "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (id,))".into(),
            category: "Injection".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-SQLI-002".into(), name: "SQL Injection in Express Handler".into(),
            description: "String concatenation in SQL inside Express route handler".into(),
            severity: "CRITICAL".into(), cwe: "CWE-89".into(), owasp: "A03:2021".into(),
            languages: vec!["js".into(), "ts".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:\.query|\.execute|\.raw)\s*\(.*(?:\+|`\$\{)".into()),
                RuleCondition::Inside(r"(?:app|router)\.\s*(?:get|post|put|delete|patch|all)\s*\(".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:parameterized|placeholder|\?\s*,|\$\d+)".into()))),
            ]),
            remediation: "Use parameterized queries with placeholders".into(),
            category: "Injection".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-SQLI-003".into(), name: "SQL Injection in Spring Controller".into(),
            description: "String concatenation in SQL inside Spring endpoint".into(),
            severity: "CRITICAL".into(), cwe: "CWE-89".into(), owasp: "A03:2021".into(),
            languages: vec!["java".into(), "kt".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r#"(?i)(?:createQuery|createNativeQuery|nativeQuery|jdbcTemplate\.query)\s*\(.*\+"#.into()),
                RuleCondition::Inside(r"(?i)@(?:GetMapping|PostMapping|RequestMapping|PutMapping|DeleteMapping|Controller|RestController)".into()),
            ]),
            remediation: "Use JPA parameterized queries or PreparedStatement".into(),
            category: "Injection".into(), confidence: "HIGH".into(),
        },

        // === Command Injection with context ===
        CompositeRule {
            id: "COMP-CMDI-001".into(), name: "Command Injection in Web Handler".into(),
            description: "OS command execution with user input inside web handler".into(),
            severity: "CRITICAL".into(), cwe: "CWE-78".into(), owasp: "A03:2021".into(),
            languages: vec!["py".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen|check_output))\s*\(.*(?:request|input|param)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:shlex\.quote|shell=False|subprocess\.run\(\[)".into()))),
            ]),
            remediation: "Use subprocess with shell=False and shlex.quote()".into(),
            category: "CommandInjection".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-CMDI-002".into(), name: "Command Injection via child_process".into(),
            description: "Unsanitized input in child_process.exec".into(),
            severity: "CRITICAL".into(), cwe: "CWE-78".into(), owasp: "A03:2021".into(),
            languages: vec!["js".into(), "ts".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:exec|execSync|spawn)\s*\(.*(?:req\.|request\.|params|query|body|\$\{)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r#"(?i)(?:execFile|spawn\s*\(\s*['"][^'"]+['"]\s*,\s*\[)"#.into()))),
            ]),
            remediation: "Use execFile() or spawn() with array arguments instead of exec()".into(),
            category: "CommandInjection".into(), confidence: "HIGH".into(),
        },

        // === XSS with framework awareness ===
        CompositeRule {
            id: "COMP-XSS-001".into(), name: "React dangerouslySetInnerHTML".into(),
            description: "Using dangerouslySetInnerHTML with non-sanitized content".into(),
            severity: "HIGH".into(), cwe: "CWE-79".into(), owasp: "A03:2021".into(),
            languages: vec!["jsx".into(), "tsx".into(), "js".into(), "ts".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"dangerouslySetInnerHTML".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:DOMPurify|sanitize|sanitizeHtml|xss\()".into()))),
            ]),
            remediation: "Sanitize with DOMPurify: dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(content)}}".into(),
            category: "XSS".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-XSS-002".into(), name: "Django mark_safe with user data".into(),
            description: "mark_safe() or |safe filter on potentially user-controlled data".into(),
            severity: "HIGH".into(), cwe: "CWE-79".into(), owasp: "A03:2021".into(),
            languages: vec!["py".into()],
            condition: RuleCondition::Or(vec![
                RuleCondition::Pattern(r"mark_safe\s*\(.*(?:request|input|param|user|data|form)".into()),
                RuleCondition::Pattern(r"render_template_string\s*\(.*(?:request|input|param)".into()),
            ]),
            remediation: "Never use mark_safe() on user input. Use Django's auto-escaping".into(),
            category: "XSS".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-XSS-003".into(), name: "innerHTML Assignment".into(),
            description: "Direct innerHTML assignment without sanitization".into(),
            severity: "HIGH".into(), cwe: "CWE-79".into(), owasp: "A03:2021".into(),
            languages: vec!["js".into(), "ts".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"\.innerHTML\s*=".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:DOMPurify|sanitize|escape|encode)".into()))),
            ]),
            remediation: "Use textContent instead, or sanitize with DOMPurify".into(),
            category: "XSS".into(), confidence: "MEDIUM".into(),
        },

        // === SSRF with validation check ===
        CompositeRule {
            id: "COMP-SSRF-001".into(), name: "SSRF in Python Web App".into(),
            description: "HTTP request with user-controlled URL without validation".into(),
            severity: "HIGH".into(), cwe: "CWE-918".into(), owasp: "A10:2021".into(),
            languages: vec!["py".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)requests\.\w+\s*\(.*(?:request|param|user|input|url|data)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:is_safe_url|validate_url|allowed_hosts|urlparse|ALLOWED_HOSTS|whitelist)".into()))),
                RuleCondition::Inside(r"(?i)(?:def\s+\w+.*request|@app\.route|@bp\.route)".into()),
            ]),
            remediation: "Validate URLs against an allowlist, block internal IPs (127.0.0.1, 169.254.169.254, 10.0.0.0/8)".into(),
            category: "SSRF".into(), confidence: "HIGH".into(),
        },

        // === Insecure Deserialization with safe-load check ===
        CompositeRule {
            id: "COMP-DESER-001".into(), name: "Python yaml.load without SafeLoader".into(),
            description: "yaml.load() without SafeLoader allows arbitrary code execution".into(),
            severity: "CRITICAL".into(), cwe: "CWE-502".into(), owasp: "A08:2021".into(),
            languages: vec!["py".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"yaml\.load\s*\(".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:SafeLoader|safe_load|yaml\.CSafeLoader)".into()))),
            ]),
            remediation: "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)".into(),
            category: "InsecureDeserialization".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-DESER-002".into(), name: "Java Unsafe Deserialization".into(),
            description: "ObjectInputStream.readObject without type validation".into(),
            severity: "CRITICAL".into(), cwe: "CWE-502".into(), owasp: "A08:2021".into(),
            languages: vec!["java".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:readObject|readUnshared|ObjectInputStream|XStream\.fromXML|XMLDecoder)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:ObjectInputFilter|SerializationFilter|lookAheadObjectInputStream|ValidatingObjectInputStream)".into()))),
            ]),
            remediation: "Use ObjectInputFilter or ValidatingObjectInputStream to restrict allowed classes".into(),
            category: "InsecureDeserialization".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-DESER-003".into(), name: "Node.js Unsafe Deserialization".into(),
            description: "node-serialize or funcster deserialization of untrusted data".into(),
            severity: "CRITICAL".into(), cwe: "CWE-502".into(), owasp: "A08:2021".into(),
            languages: vec!["js".into(), "ts".into()],
            condition: RuleCondition::Or(vec![
                RuleCondition::Pattern(r"(?:node-serialize|serialize-javascript|funcster).*(?:unserialize|deserialize)".into()),
                RuleCondition::Pattern(r"(?:unserialize|deserialize)\(.*(?:req\.|request\.|body|query|param)".into()),
            ]),
            remediation: "Never deserialize untrusted data. Use JSON.parse() for data interchange".into(),
            category: "InsecureDeserialization".into(), confidence: "HIGH".into(),
        },

        // === XXE with parser config check ===
        CompositeRule {
            id: "COMP-XXE-001".into(), name: "XXE in Java XML Parser".into(),
            description: "XML parsing without disabling external entities".into(),
            severity: "HIGH".into(), cwe: "CWE-611".into(), owasp: "A05:2021".into(),
            languages: vec!["java".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SchemaFactory|TransformerFactory)\.new(?:Instance|Factory)?\(\)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:DISALLOW_DOCTYPE_DECL|disallow-doctype-decl|EXTERNAL_GENERAL_ENTITIES|XMLConstants\.ACCESS_EXTERNAL|setExpandEntityReferences\(false\))".into()))),
            ]),
            remediation: "Disable external entities: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)".into(),
            category: "XXE".into(), confidence: "MEDIUM".into(),
        },
        CompositeRule {
            id: "COMP-XXE-002".into(), name: "XXE in Python XML Parser".into(),
            description: "Using vulnerable XML parser instead of defusedxml".into(),
            severity: "HIGH".into(), cwe: "CWE-611".into(), owasp: "A05:2021".into(),
            languages: vec!["py".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax|lxml\.etree)\.(?:parse|fromstring|iterparse)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:defusedxml|resolve_entities\s*=\s*False|no_network|XMLParser\s*\(.*resolve_entities\s*=\s*False)".into()))),
            ]),
            remediation: "Use defusedxml library: import defusedxml.ElementTree as ET".into(),
            category: "XXE".into(), confidence: "MEDIUM".into(),
        },

        // === Path Traversal with sanitizer check ===
        CompositeRule {
            id: "COMP-PATH-001".into(), name: "Path Traversal in File Operations".into(),
            description: "User input used in file path without path sanitization".into(),
            severity: "HIGH".into(), cwe: "CWE-22".into(), owasp: "A01:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:open|readFile|writeFile|createReadStream|readFileSync)\s*\(.*(?:req\.|request\.|param|user|input|filename)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:realpath|resolve|basename|safe_join|secure_filename|canonicalize|normalize)".into()))),
            ]),
            remediation: "Validate path with realpath/resolve and ensure it stays within allowed directory".into(),
            category: "PathTraversal".into(), confidence: "HIGH".into(),
        },

        // === Authentication/Authorization ===
        CompositeRule {
            id: "COMP-AUTH-001".into(), name: "Missing Auth Check in API Handler".into(),
            description: "API endpoint handler without authentication decorator/middleware".into(),
            severity: "HIGH".into(), cwe: "CWE-306".into(), owasp: "A01:2021".into(),
            languages: vec!["py".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"@(?:app|bp)\.route\s*\(\s*.*(?:api|admin|user|account|profile|settings|delete|update|create)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:@login_required|@authenticated|@auth\.|@permission|@require|@jwt_required|@token_required|current_user)".into()))),
            ]),
            remediation: "Add authentication decorator: @login_required or custom auth middleware".into(),
            category: "BrokenAuth".into(), confidence: "MEDIUM".into(),
        },
        CompositeRule {
            id: "COMP-AUTH-002".into(), name: "Missing Auth in Express Route".into(),
            description: "Express route handler for sensitive endpoint without auth middleware".into(),
            severity: "HIGH".into(), cwe: "CWE-306".into(), owasp: "A01:2021".into(),
            languages: vec!["js".into(), "ts".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r#"(?:router|app)\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"].*(?:api|admin|user|account|profile|settings|delete|update|create)"#.into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:authenticate|isAuth|requireAuth|ensureAuth|passport\.authenticate|verifyToken|authMiddleware|protect|requireLogin|jwt)".into()))),
            ]),
            remediation: "Add authentication middleware to sensitive routes".into(),
            category: "BrokenAuth".into(), confidence: "MEDIUM".into(),
        },

        // === Crypto weaknesses ===
        CompositeRule {
            id: "COMP-CRYPTO-001".into(), name: "Hardcoded Encryption Key".into(),
            description: "Encryption using a hardcoded key value".into(),
            severity: "HIGH".into(), cwe: "CWE-321".into(), owasp: "A02:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "java".into(), "cs".into(), "go".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r#"(?i)(?:AES|DES|Cipher|encrypt|crypto|CryptoJS|createCipher)"#.into()),
                RuleCondition::Pattern(r#"(?i)(?:key|secret|password|iv)\s*[:=]\s*["'][^"']{4,}["']"#.into()),
            ]),
            remediation: "Use environment variables or a key management service for encryption keys".into(),
            category: "WeakCrypto".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-CRYPTO-002".into(), name: "ECB Mode Encryption".into(),
            description: "ECB mode provides no semantic security — identical blocks produce identical ciphertext".into(),
            severity: "HIGH".into(), cwe: "CWE-327".into(), owasp: "A02:2021".into(),
            languages: vec!["py".into(), "java".into(), "cs".into(), "go".into()],
            condition: RuleCondition::Or(vec![
                RuleCondition::Pattern(r"(?i)(?:MODE_ECB|AES/ECB|DES/ECB|CipherMode\.ECB|cipher\.NewECBEncrypter)".into()),
                RuleCondition::Pattern(r#"(?i)Cipher\.getInstance\s*\(\s*["'](?:AES|DES|DESede)["']\s*\)"#.into()),
            ]),
            remediation: "Use AES-GCM or AES-CBC with HMAC instead of ECB mode".into(),
            category: "WeakCrypto".into(), confidence: "HIGH".into(),
        },

        // === Insecure Configuration ===  
        CompositeRule {
            id: "COMP-CONF-001".into(), name: "Debug Mode in Production".into(),
            description: "Debug mode enabled — exposes sensitive information".into(),
            severity: "MEDIUM".into(), cwe: "CWE-489".into(), owasp: "A05:2021".into(),
            languages: vec!["py".into()],
            condition: RuleCondition::Or(vec![
                RuleCondition::Pattern(r"(?i)(?:DEBUG\s*=\s*True|app\.debug\s*=\s*True|app\.run\(.*debug\s*=\s*True)".into()),
                RuleCondition::Pattern(r"(?i)FLASK_DEBUG\s*=\s*1".into()),
            ]),
            remediation: "Set DEBUG = False in production configuration".into(),
            category: "Misconfiguration".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-CONF-002".into(), name: "CORS Allow All Origins".into(),
            description: "CORS configured to allow all origins — enables cross-origin attacks".into(),
            severity: "MEDIUM".into(), cwe: "CWE-942".into(), owasp: "A05:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "java".into(), "cs".into()],
            condition: RuleCondition::Or(vec![
                RuleCondition::Pattern(r#"(?i)(?:Access-Control-Allow-Origin|allowedOrigins?|origin)\s*[:=]\s*["']\*["']"#.into()),
                RuleCondition::Pattern(r"(?i)CORS\s*\(\s*\w*\s*\)".into()),
            ]),
            remediation: "Restrict CORS to specific trusted origins".into(),
            category: "Misconfiguration".into(), confidence: "MEDIUM".into(),
        },
        CompositeRule {
            id: "COMP-CONF-003".into(), name: "Insecure Cookie Configuration".into(),
            description: "Cookie set without Secure, HttpOnly, or SameSite flags".into(),
            severity: "MEDIUM".into(), cwe: "CWE-614".into(), owasp: "A05:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "java".into(), "rb".into(), "php".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:set_cookie|setCookie|addCookie|cookie\s*\(|document\.cookie\s*=|setcookie\s*\()".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:httponly|http_only|secure|samesite)".into()))),
            ]),
            remediation: "Set Secure, HttpOnly, and SameSite=Strict flags on all sensitive cookies".into(),
            category: "Misconfiguration".into(), confidence: "MEDIUM".into(),
        },

        // === Race Conditions ===
        CompositeRule {
            id: "COMP-RACE-001".into(), name: "TOCTOU Race Condition".into(),
            description: "Time-of-check/time-of-use race condition in file operations".into(),
            severity: "MEDIUM".into(), cwe: "CWE-367".into(), owasp: "A04:2021".into(),
            languages: vec!["py".into(), "c".into(), "cpp".into(), "go".into(), "rs".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:os\.path\.exists|os\.access|access\(|stat\(|Path\.exists|fs\.existsSync|fs\.accessSync)".into()),
                RuleCondition::Inside(r"(?i)(?:open\(|fopen|File\.open|fs\.readFile|fs\.writeFile)".into()),
            ]),
            remediation: "Use atomic operations or file locking instead of check-then-use patterns".into(),
            category: "RaceCondition".into(), confidence: "MEDIUM".into(),
        },

        // === Prototype Pollution ===
        CompositeRule {
            id: "COMP-PP-001".into(), name: "Prototype Pollution via Merge/Extend".into(),
            description: "Deep merge/extend of user-controlled objects enables prototype pollution".into(),
            severity: "HIGH".into(), cwe: "CWE-1321".into(), owasp: "A03:2021".into(),
            languages: vec!["js".into(), "ts".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:merge|extend|deepMerge|assign|defaultsDeep|lodash\.merge|_\.merge)\s*\(.*(?:req\.|request\.|body|query|param|user|input)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:Object\.freeze|Object\.seal|__proto__|constructor|prototype)".into()))),
            ]),
            remediation: "Validate input keys, filter __proto__ and constructor properties".into(),
            category: "PrototypePollution".into(), confidence: "MEDIUM".into(),
        },

        // === JWT Vulnerabilities ===
        CompositeRule {
            id: "COMP-JWT-001".into(), name: "JWT None Algorithm Attack".into(),
            description: "JWT verification that allows 'none' algorithm".into(),
            severity: "CRITICAL".into(), cwe: "CWE-345".into(), owasp: "A02:2021".into(),
            languages: vec!["js".into(), "ts".into(), "py".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:jwt\.verify|jwt\.decode|PyJWT\.decode|jose\.jwt\.decode)".into()),
                RuleCondition::Pattern(r#"(?i)(?:algorithms?\s*[:=]\s*\[.*["']none["']|verify\s*[:=]\s*(?:false|False)|options.*verify.*false)"#.into()),
            ]),
            remediation: "Always specify allowed algorithms and enable signature verification".into(),
            category: "BrokenAuth".into(), confidence: "HIGH".into(),
        },

        // === Open Redirect ===
        CompositeRule {
            id: "COMP-REDIR-001".into(), name: "Open Redirect".into(),
            description: "Redirect using user-controlled URL without validation".into(),
            severity: "MEDIUM".into(), cwe: "CWE-601".into(), owasp: "A01:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "java".into(), "rb".into(), "php".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r#"(?i)(?:redirect\(|res\.redirect|sendRedirect|Response\.Redirect|header\s*\(\s*['"]Location).*(?:req\.|request\.|param|query|url|next|return_to|redirect_uri|goto|target)"#.into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:is_safe_url|validate|allowed|whitelist|url_for|starts_with|startsWith)".into()))),
            ]),
            remediation: "Validate redirect URLs against an allowlist of paths/domains".into(),
            category: "OpenRedirect".into(), confidence: "MEDIUM".into(),
        },

        // === Mass Assignment ===
        CompositeRule {
            id: "COMP-MASS-001".into(), name: "Mass Assignment / Over-posting".into(),
            description: "Direct binding of request body to model without field filtering".into(),
            severity: "HIGH".into(), cwe: "CWE-915".into(), owasp: "A04:2021".into(),
            languages: vec!["rb".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:\.create\(params|\.update\(params|\.new\(params|assign_attributes\(params)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:permit|strong_param|require\(\.\w+\)\.permit)".into()))),
            ]),
            remediation: "Use strong parameters: params.require(:model).permit(:allowed_field1, :allowed_field2)".into(),
            category: "MassAssignment".into(), confidence: "HIGH".into(),
        },

        // === Log Injection ===
        CompositeRule {
            id: "COMP-LOG-001".into(), name: "Log Injection".into(),
            description: "User input logged without sanitization — enables log forging".into(),
            severity: "MEDIUM".into(), cwe: "CWE-117".into(), owasp: "A09:2021".into(),
            languages: vec!["java".into(), "py".into(), "js".into(), "ts".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:logger|log|LOG)\s*\.(?:info|warn|error|debug)\s*\(.*(?:req\.|request\.|getParameter|params|query|body|user_input)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:sanitize|encode|escape|replace\s*\(.*\\n|replace\s*\(.*\\r)".into()))),
            ]),
            remediation: "Sanitize log inputs: strip newlines and encode special characters".into(),
            category: "Injection".into(), confidence: "MEDIUM".into(),
        },

        // === Insecure Random ===
        CompositeRule {
            id: "COMP-RAND-001".into(), name: "Insecure Random for Security".into(),
            description: "Using non-cryptographic PRNG for security-sensitive operations".into(),
            severity: "HIGH".into(), cwe: "CWE-330".into(), owasp: "A02:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "java".into(), "go".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:random\.(?:randint|choice|random|shuffle)|Math\.random\(\)|java\.util\.Random|rand\.Intn|rand\.Int\(\))".into()),
                RuleCondition::Inside(r"(?i)(?:token|password|secret|key|salt|nonce|otp|csrf|session|auth|verify)".into()),
            ]),
            remediation: "Use secrets module (Python), crypto.randomBytes (Node.js), SecureRandom (Java)".into(),
            category: "InsecureRandom".into(), confidence: "HIGH".into(),
        },

        // === Template Injection ===
        CompositeRule {
            id: "COMP-SSTI-001".into(), name: "Server-Side Template Injection".into(),
            description: "User input rendered directly in template engine".into(),
            severity: "CRITICAL".into(), cwe: "CWE-1336".into(), owasp: "A03:2021".into(),
            languages: vec!["py".into(), "java".into(), "js".into(), "ts".into(), "rb".into()],
            condition: RuleCondition::Or(vec![
                RuleCondition::Pattern(r"(?i)render_template_string\s*\(.*(?:request|input|param|user|data)".into()),
                RuleCondition::Pattern(r"(?i)(?:Template|Environment\(|Jinja2)\s*\(.*(?:request|input|param|user|data)".into()),
                RuleCondition::Pattern(r"(?i)Velocity\.evaluate\s*\(.*(?:request|param|user)".into()),
                RuleCondition::Pattern(r"(?i)ERB\.new\s*\(.*(?:params|request|user)".into()),
            ]),
            remediation: "Never pass user input as template source. Pass as template variables instead".into(),
            category: "TemplateInjection".into(), confidence: "HIGH".into(),
        },

        // === IDOR ===
        CompositeRule {
            id: "COMP-IDOR-001".into(), name: "Insecure Direct Object Reference".into(),
            description: "Database query using user-provided ID without ownership check".into(),
            severity: "HIGH".into(), cwe: "CWE-639".into(), owasp: "A01:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "rb".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:find_by_id|findById|\.get\(|\.find\(|WHERE.*id\s*=).*(?:req\.|request\.|params|query)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:current_user|session\.user|auth|owner|belongs_to|authorize|permission|can\?)".into()))),
            ]),
            remediation: "Add ownership check: ensure the requested resource belongs to the authenticated user".into(),
            category: "IDOR".into(), confidence: "MEDIUM".into(),
        },

        // === Insecure File Upload ===
        CompositeRule {
            id: "COMP-UPLOAD-001".into(), name: "Insecure File Upload".into(),
            description: "File upload without content type or extension validation".into(),
            severity: "HIGH".into(), cwe: "CWE-434".into(), owasp: "A04:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "java".into(), "php".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:\.save\(|upload|multer|formidable|file\.write|move_uploaded_file|transferTo|\.files\[)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:content_type|mimetype|mime_type|extension|allowed_ext|ALLOWED_EXTENSIONS|fileFilter|accept|\.endsWith)".into()))),
            ]),
            remediation: "Validate file extension, content type, and size. Store outside web root".into(),
            category: "InsecureFileOps".into(), confidence: "MEDIUM".into(),
        },

        // === GraphQL Security ===
        CompositeRule {
            id: "COMP-GQL-001".into(), name: "GraphQL Introspection Enabled".into(),
            description: "GraphQL introspection enabled in production — schema disclosure".into(),
            severity: "MEDIUM".into(), cwe: "CWE-200".into(), owasp: "A05:2021".into(),
            languages: vec!["js".into(), "ts".into(), "py".into(), "java".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:introspection|__schema|schema.*introspection)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:introspection\s*[:=]\s*false|disable.*introspection)".into()))),
            ]),
            remediation: "Disable introspection in production: introspection: false".into(),
            category: "InfoDisclosure".into(), confidence: "LOW".into(),
        },

        // === NoSQL Injection ===
        CompositeRule {
            id: "COMP-NOSQL-001".into(), name: "NoSQL Injection".into(),
            description: "User input used directly in NoSQL query operators".into(),
            severity: "HIGH".into(), cwe: "CWE-943".into(), owasp: "A03:2021".into(),
            languages: vec!["js".into(), "ts".into(), "py".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:\.find\(|\.findOne\(|\.aggregate\(|\.updateOne\(|\.deleteOne\().*(?:req\.|request\.|body|query|param)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:sanitize|mongo-sanitize|express-mongo-sanitize|parseInt|ObjectId\()".into()))),
            ]),
            remediation: "Use mongo-sanitize and validate/cast input types before queries".into(),
            category: "Injection".into(), confidence: "MEDIUM".into(),
        },

        // === Regex DoS ===
        CompositeRule {
            id: "COMP-REDOS-001".into(), name: "ReDoS — Regex Denial of Service".into(),
            description: "Regex with catastrophic backtracking potential on user input".into(),
            severity: "MEDIUM".into(), cwe: "CWE-1333".into(), owasp: "A06:2021".into(),
            languages: vec!["js".into(), "ts".into(), "py".into(), "java".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?:new RegExp|re\.compile|Pattern\.compile)\s*\(.*(?:req\.|request\.|param|query|body|user|input)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:re2|safe-regex|timeout|deadline)".into()))),
            ]),
            remediation: "Use RE2 engine for user-supplied patterns, or set match timeout".into(),
            category: "RegexDoS".into(), confidence: "MEDIUM".into(),
        },

        // === Insecure TLS ===
        CompositeRule {
            id: "COMP-TLS-001".into(), name: "TLS Certificate Verification Disabled".into(),
            description: "SSL/TLS certificate verification disabled — enables MITM attacks".into(),
            severity: "HIGH".into(), cwe: "CWE-295".into(), owasp: "A07:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "java".into(), "go".into(), "rb".into()],
            condition: RuleCondition::Or(vec![
                RuleCondition::Pattern(r#"(?i)verify\s*[:=]\s*(?:False|false|0)"#.into()),
                RuleCondition::Pattern(r"(?i)(?:CERT_NONE|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|ssl_verify_peer\s*=>\s*false)".into()),
                RuleCondition::Pattern(r#"(?i)NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0"#.into()),
            ]),
            remediation: "Always verify TLS certificates. Use system CA bundle".into(),
            category: "InsecureTLS".into(), confidence: "HIGH".into(),
        },

        // === Hardcoded IPs/Hosts ===
        CompositeRule {
            id: "COMP-CONF-004".into(), name: "Binding to All Interfaces".into(),
            description: "Server binding to 0.0.0.0 exposes service to all network interfaces".into(),
            severity: "LOW".into(), cwe: "CWE-668".into(), owasp: "A05:2021".into(),
            languages: vec!["py".into(), "js".into(), "ts".into(), "go".into(), "java".into(), "rs".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r#"(?i)(?:host|bind|listen|address)\s*[:=]\s*["']0\.0\.0\.0["']"#.into()),
                RuleCondition::NotInside(r"(?i)(?:test|spec|example|demo|development|docker|container)".into()),
            ]),
            remediation: "Bind to 127.0.0.1 for local-only access, or use specific interface".into(),
            category: "Misconfiguration".into(), confidence: "LOW".into(),
        },

        // === PHP specific ===
        CompositeRule {
            id: "COMP-PHP-001".into(), name: "PHP Code Injection".into(),
            description: "PHP functions that execute arbitrary code from user input".into(),
            severity: "CRITICAL".into(), cwe: "CWE-94".into(), owasp: "A03:2021".into(),
            languages: vec!["php".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:eval|assert|preg_replace.*\/e|create_function|call_user_func|usort)\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:filter_var|filter_input|htmlspecialchars|intval|preg_match)".into()))),
            ]),
            remediation: "Never pass user input to code execution functions".into(),
            category: "Injection".into(), confidence: "HIGH".into(),
        },
        CompositeRule {
            id: "COMP-PHP-002".into(), name: "PHP File Inclusion".into(),
            description: "Local/Remote file inclusion via user-controlled path".into(),
            severity: "CRITICAL".into(), cwe: "CWE-98".into(), owasp: "A03:2021".into(),
            languages: vec!["php".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:basename|realpath|in_array|whitelist|allowed)".into()))),
            ]),
            remediation: "Use a whitelist of allowed files, never include user-controlled paths directly".into(),
            category: "Injection".into(), confidence: "HIGH".into(),
        },

        // === Go specific ===
        CompositeRule {
            id: "COMP-GO-001".into(), name: "Go SQL Injection".into(),
            description: "String formatting in Go SQL query without parameterization".into(),
            severity: "CRITICAL".into(), cwe: "CWE-89".into(), owasp: "A03:2021".into(),
            languages: vec!["go".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r"(?i)(?:db\.(?:Query|Exec|QueryRow)|tx\.(?:Query|Exec))\s*\(\s*(?:fmt\.Sprintf|.*\+)".into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"\$\d+|\\?".into()))),
            ]),
            remediation: "Use parameterized queries: db.Query(\"SELECT * FROM t WHERE id = $1\", id)".into(),
            category: "Injection".into(), confidence: "HIGH".into(),
        },

        // === C# specific ===
        CompositeRule {
            id: "COMP-CS-001".into(), name: "C# SQL Injection".into(),
            description: "String concatenation in SQL command".into(),
            severity: "CRITICAL".into(), cwe: "CWE-89".into(), owasp: "A03:2021".into(),
            languages: vec!["cs".into()],
            condition: RuleCondition::And(vec![
                RuleCondition::Pattern(r#"(?i)(?:SqlCommand|OleDbCommand|OracleCommand|NpgsqlCommand)\s*\(\s*["'].*\+"#.into()),
                RuleCondition::Not(Box::new(RuleCondition::Pattern(r"(?i)(?:SqlParameter|Parameters\.Add|AddWithValue|@\w+)".into()))),
            ]),
            remediation: "Use SqlParameter: cmd.Parameters.AddWithValue(\"@id\", id)".into(),
            category: "Injection".into(), confidence: "HIGH".into(),
        },
    ]
}
