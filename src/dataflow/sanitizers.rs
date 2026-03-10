use regex::Regex;

/// Known sanitizer patterns - inspired by Semgrep's pattern-not concept
/// When a sanitizer is found on the path, we downgrade the severity

pub struct SanitizerDB {
    pub sanitizers: Vec<SanitizerEntry>,
}

pub struct SanitizerEntry {
    pub pattern: Regex,
    pub category: &'static str,
    pub protects_against: &'static [&'static str],
    pub languages: &'static [&'static str],
}

impl SanitizerDB {
    pub fn new() -> Self {
        Self {
            sanitizers: vec![
                // XSS sanitizers
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:DOMPurify\.sanitize|sanitizeHtml|xss\(|escapeHtml|htmlspecialchars|html\.escape|cgi\.escape|ERB::Util\.html_escape|CGI\.escapeHTML|bleach\.clean|Markup\.escape|HtmlEncoder\.Default)").unwrap(),
                    category: "xss_sanitizer",
                    protects_against: &["XSS", "xss", "html_output"],
                    languages: &["js","ts","py","rb","php","cs","java"],
                },
                // SQL sanitizers
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:PreparedStatement|parameterized|placeholder|\?\s*,|%s.*bind|prepare\(|\.prepare|real_escape_string|quote\(|pg_escape|Arel\.sql|ActiveRecord::Base\.sanitize|SqlParameter)").unwrap(),
                    category: "sql_sanitizer",
                    protects_against: &["Injection", "sql_execution"],
                    languages: &["py","js","ts","java","rb","php","go","cs"],
                },
                // Command injection sanitizers
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:shlex\.quote|shellescape|escapeshellarg|escapeshellcmd|ProcessBuilder\(\)|execFile\(|\.arg\()").unwrap(),
                    category: "cmd_sanitizer",
                    protects_against: &["CommandInjection", "command_execution"],
                    languages: &["py","js","ts","java","rb","php","rs"],
                },
                // Path traversal sanitizers
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:os\.path\.basename|os\.path\.realpath|filepath\.Clean|filepath\.Base|Path\.GetFileName|secure_filename|safe_join|\.canonicalize\(\)|\.normalize\(\))").unwrap(),
                    category: "path_sanitizer",
                    protects_against: &["PathTraversal", "file_operation"],
                    languages: &["py","js","ts","go","rs","java","cs","rb"],
                },
                // URL validation
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:is_safe_url|validate_url|url\.Parse|urlparse|new URL\(|URL\.canParse|allowed_hosts|ALLOWED_HOSTS|url_has_allowed_host|is_valid_url)").unwrap(),
                    category: "url_validator",
                    protects_against: &["SSRF", "OpenRedirect", "ssrf", "open_redirect"],
                    languages: &["py","js","ts","java","go","rb","cs"],
                },
                // XXE prevention
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:DISALLOW_DOCTYPE_DECL|defusedxml|setFeature.*disallow|DtdProcessing\.Prohibit|XMLConstants\.FEATURE_SECURE_PROCESSING|setExpandEntityReferences\(false\)|resolve_entities\s*=\s*False)").unwrap(),
                    category: "xxe_prevention",
                    protects_against: &["XXE", "xxe"],
                    languages: &["py","java","cs","c","cpp"],
                },
                // Deserialization safe alternatives
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:safe_load|SafeLoader|JSON\.parse|json_decode|allowed_classes|ObjectInputFilter|SerializationBinder|TypeNameHandling\.None|System\.Text\.Json)").unwrap(),
                    category: "deser_sanitizer",
                    protects_against: &["InsecureDeserialization", "deserialization"],
                    languages: &["py","js","ts","java","rb","php","cs"],
                },
                // CSRF protection
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:csrf_token|csrf_protect|@csrf_exempt|CsrfViewMiddleware|__RequestVerificationToken|AntiForgeryToken|csrf_meta_tags|authenticity_token)").unwrap(),
                    category: "csrf_protection",
                    protects_against: &["CSRF"],
                    languages: &["py","js","ts","java","rb","cs","php"],
                },
                // Auth checks
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:@login_required|@authenticated|@authorize|RequireAuth|isAuthenticated|session\.user|currentUser|auth\.check|protect\(\)|ensureAuth)").unwrap(),
                    category: "auth_check",
                    protects_against: &["BrokenAuth", "IDOR", "PrivilegeEscalation"],
                    languages: &["py","js","ts","java","rb","cs","php","go"],
                },
                // Rate limiting
                SanitizerEntry {
                    pattern: Regex::new(r"(?i)(?:rateLimit|rate_limit|throttle|@throttle|RateLimiter|slowDown|express-rate-limit|django-ratelimit)").unwrap(),
                    category: "rate_limit",
                    protects_against: &["BruteForce", "DoS"],
                    languages: &["py","js","ts","java","rb","go"],
                },
            ],
        }
    }

    pub fn is_sanitized_for(&self, line: &str, ext: &str, vuln_type: &str) -> bool {
        for s in &self.sanitizers {
            if !s.languages.contains(&ext) { continue; }
            if !s.protects_against.iter().any(|p| vuln_type.contains(p)) { continue; }
            if s.pattern.is_match(line) {
                return true;
            }
        }
        false
    }
}
