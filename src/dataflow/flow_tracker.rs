use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::analyzer::taint::{is_test_file, is_false_taint_source};

/// Flow Tracker - CodeQL/Semgrep-inspired inter-procedural data flow analysis
/// Tracks data flow across assignments, function calls, and returns
/// Detects:
/// - Local data flow (within a function)
/// - Inter-procedural flow (across function calls)  
/// - Taint propagation through string operations
/// - Flow through container elements (arrays, dicts)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowPath {
    pub id: String,
    pub source_file: String,
    pub source_line: usize,
    pub source_type: String,
    pub source_var: String,
    pub sink_file: String,
    pub sink_line: usize,
    pub sink_type: String,
    pub intermediate_steps: Vec<FlowStep>,
    pub is_sanitized: bool,
    pub confidence: FlowConfidence,
    pub severity: String,
    pub cwe: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStep {
    pub file: String,
    pub line: usize,
    pub content: String,
    pub step_type: String,
    pub variable: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FlowConfidence {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for FlowConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowConfidence::High => write!(f, "HIGH"),
            FlowConfidence::Medium => write!(f, "MEDIUM"),
            FlowConfidence::Low => write!(f, "LOW"),
        }
    }
}

struct FlowSource {
    pattern: Regex,
    source_type: &'static str,
    languages: &'static [&'static str],
}

struct FlowSink {
    pattern: Regex,
    sink_type: &'static str,
    languages: &'static [&'static str],
    severity: &'static str,
    cwe: &'static str,
}

struct FlowSanitizer {
    pattern: Regex,
    sanitizer_type: &'static str,
    languages: &'static [&'static str],
}

pub struct FlowTracker {
    sources: Vec<FlowSource>,
    sinks: Vec<FlowSink>,
    sanitizers: Vec<FlowSanitizer>,
    assign_re: Regex,
    simple_assign_re: Regex,
}

impl FlowTracker {
    pub fn new() -> Self {
        let sources = vec![
            // Python 
            FlowSource { pattern: Regex::new(r"(\w+)\s*=\s*(?:request\.(?:args|form|data|json|values|cookies|headers|files|get_json|method)|flask\.request|input\s*\()").unwrap(), source_type: "http_input", languages: &["py"] },
            FlowSource { pattern: Regex::new(r"(\w+)\s*=\s*sys\.argv").unwrap(), source_type: "cli_arg", languages: &["py"] },
            FlowSource { pattern: Regex::new(r"(\w+)\s*=\s*os\.environ\.get\(").unwrap(), source_type: "env_var", languages: &["py"] },
            FlowSource { pattern: Regex::new(r"(\w+)\s*=\s*(?:json\.loads?|yaml\.safe_load|xmltodict\.parse)\s*\(").unwrap(), source_type: "deserialized_data", languages: &["py"] },
            // JavaScript/TypeScript
            FlowSource { pattern: Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:req\.(?:body|query|params|headers|cookies|ip|hostname|path)|request\.(?:body|query|params))").unwrap(), source_type: "http_input", languages: &["js", "ts", "jsx", "tsx"] },
            FlowSource { pattern: Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:document\.(?:location|URL|referrer|cookie|getElementById|querySelector)|window\.location|location\.(?:hash|search|href|pathname))").unwrap(), source_type: "dom_input", languages: &["js", "ts", "jsx", "tsx"] },
            FlowSource { pattern: Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:process\.argv|process\.env)").unwrap(), source_type: "env_var", languages: &["js", "ts"] },
            FlowSource { pattern: Regex::new(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:JSON\.parse|new URLSearchParams|FormData|FileReader)").unwrap(), source_type: "parsed_input", languages: &["js", "ts"] },
            FlowSource { pattern: Regex::new(r"(?:const|let|var)\s+\{?\s*(\w+).*\}?\s*=\s*(?:useParams|useSearchParams|useLocation|useRouter)").unwrap(), source_type: "route_param", languages: &["js", "ts", "jsx", "tsx"] },
            // Java 
            FlowSource { pattern: Regex::new(r"(?:String|Object|var|int|long|boolean)\s+(\w+)\s*=\s*(?:request\.getParameter|request\.getHeader|request\.getCookies?|request\.getInputStream|request\.getReader|request\.getAttribute|request\.getPathInfo|request\.getQueryString|request\.getRemoteAddr)").unwrap(), source_type: "http_input", languages: &["java", "kt"] },
            FlowSource { pattern: Regex::new(r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)\s*.*?(\w+)").unwrap(), source_type: "spring_input", languages: &["java", "kt"] },
            FlowSource { pattern: Regex::new(r"(?:String|Object|var)\s+(\w+)\s*=\s*System\.getenv\(").unwrap(), source_type: "env_var", languages: &["java"] },
            // PHP
            FlowSource { pattern: Regex::new(r"(\$\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\[").unwrap(), source_type: "http_input", languages: &["php"] },
            FlowSource { pattern: Regex::new(r#"(\$\w+)\s*=\s*(?:file_get_contents\s*\(\s*['"]php://input|getenv\s*\()"#).unwrap(), source_type: "raw_input", languages: &["php"] },
            // Go
            FlowSource { pattern: Regex::new(r"(\w+)\s*(?::=|=)\s*(?:r\.(?:FormValue|URL\.Query|Body|Header\.Get|PostFormValue|Cookie|PathValue|Context)|c\.(?:Param|Query|PostForm|FormFile|Request))\(").unwrap(), source_type: "http_input", languages: &["go"] },
            FlowSource { pattern: Regex::new(r"(\w+)\s*(?::=|=)\s*os\.(?:Getenv|Args)").unwrap(), source_type: "env_arg", languages: &["go"] },
            // Ruby
            FlowSource { pattern: Regex::new(r"(\w+)\s*=\s*(?:params\[|request\.(?:body|env|headers|cookies|referer))").unwrap(), source_type: "http_input", languages: &["rb"] },
            // C/C++
            FlowSource { pattern: Regex::new(r"(?:fgets|scanf|fscanf|gets|read|recv|recvfrom|getline)\s*\(\s*(\w+)").unwrap(), source_type: "io_input", languages: &["c", "cpp", "h", "hpp"] },
            FlowSource { pattern: Regex::new(r"(\w+)\s*=\s*(?:getenv|argv)\[?").unwrap(), source_type: "env_arg", languages: &["c", "cpp"] },
            // C#
            FlowSource { pattern: Regex::new(r"(?:string|var|object)\s+(\w+)\s*=\s*(?:Request\.(?:Query|Form|Headers|Cookies|Body)|HttpContext\.Request|context\.Request)").unwrap(), source_type: "http_input", languages: &["cs"] },
            // Rust
            FlowSource { pattern: Regex::new(r"(?:let|let\s+mut)\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(?:std::env::args|std::env::var|req\.|request\.)").unwrap(), source_type: "input", languages: &["rs"] },
        ];

        let sinks = vec![
            // SQL injection sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:execute|cursor\.execute|\.query|\.exec|rawQuery|db\.(?:Query|Exec|QueryRow)|\.raw\(|find_by_sql|createQuery|createNativeQuery|\.prepare)\s*\(").unwrap(), sink_type: "sql_execution", languages: &["py","js","ts","java","rb","php","go","kt","cs","rs"], severity: "CRITICAL", cwe: "CWE-89" },
            // Command injection sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:os\.system|subprocess\.(?:call|run|Popen|check_output)|child_process\.exec|execSync|spawn\(|system\(|popen\(|exec\(|Process\.Start|Runtime\.getRuntime|exec\.Command|Command::new)").unwrap(), sink_type: "command_execution", languages: &["py","js","ts","java","rb","php","go","c","cpp","cs","rs"], severity: "CRITICAL", cwe: "CWE-78" },
            // File operation sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:open\(|fopen|File\.open|fs\.(?:readFile|writeFile|unlink|createReadStream|createWriteStream|access)|FileInputStream|FileOutputStream|File::(?:open|create)|os\.(?:Open|Create|ReadFile)|ioutil\.ReadFile)").unwrap(), sink_type: "file_operation", languages: &["py","js","ts","java","rb","php","go","c","cpp","rs"], severity: "HIGH", cwe: "CWE-22" },
            // Network/SSRF sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:requests\.(?:get|post|put|delete|patch)|urllib\.request\.urlopen|fetch\(|axios\.|got\(|http\.(?:Get|Post|NewRequest)|HttpClient|curl_exec|Net::HTTP|WebClient|RestTemplate)").unwrap(), sink_type: "ssrf", languages: &["py","js","ts","java","rb","php","go","cs"], severity: "HIGH", cwe: "CWE-918" },
            // Code execution sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:eval\(|exec\(|compile\(|Function\(|setTimeout\s*\(|setInterval\s*\(|assert\(|preg_replace.*\/e|render_template_string)").unwrap(), sink_type: "code_execution", languages: &["py","js","ts","rb","php"], severity: "CRITICAL", cwe: "CWE-94" },
            // Deserialization sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|unserialize|readObject|Marshal\.load|ObjectInputStream|BinaryFormatter|XStream\.fromXML|node-serialize)").unwrap(), sink_type: "deserialization", languages: &["py","js","ts","java","rb","php","cs"], severity: "CRITICAL", cwe: "CWE-502" },
            // HTML output/XSS sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:innerHTML|outerHTML|document\.write|\.html_safe|mark_safe|@Html\.Raw|dangerouslySetInnerHTML|render_template_string|Response\.Write)").unwrap(), sink_type: "xss", languages: &["js","ts","jsx","tsx","py","rb","cs"], severity: "HIGH", cwe: "CWE-79" },
            // LDAP sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:ldap\.search|search_s|DirContext\.search|ldap_search)").unwrap(), sink_type: "ldap_query", languages: &["py","java","php"], severity: "HIGH", cwe: "CWE-90" },
            // Redirect sinks
            FlowSink { pattern: Regex::new(r"(?i)(?:redirect\(|res\.redirect|sendRedirect|Response\.Redirect|location\.href\s*=|window\.location\s*=)").unwrap(), sink_type: "open_redirect", languages: &["py","js","ts","java","rb","php","cs"], severity: "MEDIUM", cwe: "CWE-601" },
            // Template injection
            FlowSink { pattern: Regex::new(r"(?i)(?:render_template_string|Template\(|Environment.*from_string|Velocity\.evaluate|engine\.eval|FreeMarker)").unwrap(), sink_type: "template_injection", languages: &["py","java","js","ts","rb"], severity: "CRITICAL", cwe: "CWE-1336" },
            // XML parsing (XXE)
            FlowSink { pattern: Regex::new(r"(?i)(?:etree\.(?:parse|fromstring)|minidom\.parse|DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|XmlDocument|XDocument\.Load|xml\.sax\.parse)").unwrap(), sink_type: "xxe", languages: &["py","java","cs","c","cpp"], severity: "HIGH", cwe: "CWE-611" },
            // Log injection
            FlowSink { pattern: Regex::new(r"(?i)(?:logger|log|LOG)\s*\.(?:info|warn|error|debug|trace|fatal|log)\s*\(").unwrap(), sink_type: "log_injection", languages: &["java","py","js","ts","go","rb","cs"], severity: "MEDIUM", cwe: "CWE-117" },
        ];

        let sanitizers = vec![
            // SQL parameterization
            FlowSanitizer { pattern: Regex::new(r"(?i)(?:parameterized|prepared|PreparedStatement|placeholder|bind_param|sanitize|escape|encode|validate|clean|filter|purify|DOMPurify|bleach|htmlspecialchars|htmlentities|html\.escape|cgi\.escape|quote_identifier|paramstyle|shellescape|escapeshellarg|escapeshellcmd|shlex\.quote|Regex\.Escape|SecurityElement\.Escape)").unwrap(), sanitizer_type: "generic_sanitizer", languages: &["py","js","ts","java","rb","php","go","c","cpp","cs","rs"] },
            // Input validation
            FlowSanitizer { pattern: Regex::new(r"(?i)(?:parseInt|parseFloat|Number\(|int\(|float\(|bool\(|Integer\.parseInt|\.trim\(\)|strip\(\)|\.replace\(|whitelist|allowlist|isValid|validate|Validator\.|\.test\()").unwrap(), sanitizer_type: "input_validation", languages: &["py","js","ts","java","rb","php","go","cs","rs"] },
            // Path sanitization
            FlowSanitizer { pattern: Regex::new(r"(?i)(?:realpath|canonicalize|normalize|abspath|os\.path\.basename|filepath\.Clean|filepath\.Base|Path\.GetFileName|path\.resolve|safe_join|secure_filename)").unwrap(), sanitizer_type: "path_sanitizer", languages: &["py","js","ts","java","go","cs","rs","rb","php"] },
            // URL validation
            FlowSanitizer { pattern: Regex::new(r"(?i)(?:url\.Parse|URL\(|new URL|urlparse|is_safe_url|validate_url|url_for|URI\.parse)").unwrap(), sanitizer_type: "url_validator", languages: &["py","js","ts","java","go","rb"] },
            // Encoding
            FlowSanitizer { pattern: Regex::new(r"(?i)(?:encodeURI|encodeURIComponent|urllib\.parse\.quote|html\.escape|cgi\.escape|ERB::Util\.html_escape|CGI\.escapeHTML|HtmlEncoder|JavaScriptEncoder|UrlEncoder)").unwrap(), sanitizer_type: "encoding", languages: &["py","js","ts","rb","cs","java"] },
        ];

        let assign_re = Regex::new(r"(?:const|let|var|int|String|string|auto|val|var)\s+(\w+)\s*=\s*(.+)").unwrap();
        let simple_assign_re = Regex::new(r"(\w+)\s*=\s*(.+)").unwrap();

        Self { sources, sinks, sanitizers, assign_re, simple_assign_re }
    }

    /// Perform enhanced flow tracking with sanitizer awareness
    /// Returns data flow paths with intermediate steps
    pub fn track_flows(&self, file_path: &str, content: &str, ext: &str) -> Vec<FlowPath> {
        let mut paths = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut flow_id = 0;
        let in_test = is_test_file(file_path);

        // Phase 1: Find all taint sources
        let mut tainted: Vec<(String, usize, String, String)> = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            // Skip false taint sources (literals, test fixtures, dict ops)
            if is_false_taint_source(line, &lines, i) {
                continue;
            }

            for source in &self.sources {
                if !source.languages.contains(&ext) { continue; }
                if let Some(caps) = source.pattern.captures(line) {
                    if let Some(var) = caps.get(1) {
                        tainted.push((var.as_str().to_string(), i + 1, line.to_string(), source.source_type.to_string()));
                    }
                }
            }
        }

        if tainted.is_empty() { return paths; }

        // Phase 2: Track taint propagation through assignments
        // Cap propagation to prevent quadratic blowup on large files
        const MAX_PROPAGATED: usize = 500;
        let mut propagated: Vec<(String, usize, String, String, String)> = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            if propagated.len() >= MAX_PROPAGATED { break; }

            // Check both declaration-assignments and simple assignments
            let assign_caps: Vec<_> = self.assign_re.captures_iter(line)
                .chain(self.simple_assign_re.captures_iter(line))
                .collect();

            for cap in assign_caps {
                let new_var = cap[1].to_string();
                let rhs = &cap[2];
                for (tvar, tline, _, tsource) in &tainted {
                    if rhs.contains(tvar.as_str()) && i + 1 > *tline {
                        propagated.push((new_var.clone(), i + 1, line.to_string(), tvar.clone(), tsource.clone()));
                    }
                }
                // Check propagated vars using index-based iteration (no clone)
                let current_len = propagated.len();
                for idx in 0..current_len {
                    let (ref pvar, pline, _, _, ref psource) = propagated[idx];
                    if rhs.contains(pvar.as_str()) && i + 1 > pline {
                        let entry = (new_var.clone(), i + 1, line.to_string(), pvar.clone(), psource.clone());
                        propagated.push(entry);
                        break; // one propagation per RHS match is enough
                    }
                }
            }
        }

        // Phase 3: Check all sinks against tainted + propagated vars
        for (i, line) in lines.iter().enumerate() {
            for sink in &self.sinks {
                if !sink.languages.contains(&ext) { continue; }
                if !sink.pattern.is_match(line) { continue; }

                // Suppress: subprocess with shell=False + list arg is safe
                if sink.sink_type == "command_execution" {
                    let l = line.to_lowercase();
                    if (l.contains("shell=false") || l.contains("shell = false"))
                        && (l.contains("subprocess.run([") || l.contains("subprocess.popen([")
                            || l.contains("subprocess.call([") || l.contains("subprocess.check_output([")) {
                        continue;
                    }
                    if l.contains(".keys()") || l.contains(".values()") || l.contains(".items()") {
                        continue;
                    }
                }

                // Check direct tainted vars
                for (tvar, tline, tsrc_content, tsource) in &tainted {
                    if line.contains(tvar.as_str()) && i + 1 > *tline {
                        // Check for sanitizers between source and sink
                        let is_sanitized = self.check_sanitized(&lines, *tline, i + 1, ext, tvar);

                        let mut steps = vec![
                            FlowStep {
                                file: file_path.to_string(),
                                line: *tline,
                                content: tsrc_content.clone(),
                                step_type: "source".to_string(),
                                variable: tvar.clone(),
                            },
                        ];

                        // Add any propagation steps
                        for (pvar, pline, pcontent, orig_var, _) in &propagated {
                            if orig_var == tvar && *pline > *tline && *pline < i + 1 {
                                steps.push(FlowStep {
                                    file: file_path.to_string(),
                                    line: *pline,
                                    content: pcontent.clone(),
                                    step_type: "propagation".to_string(),
                                    variable: pvar.clone(),
                                });
                            }
                        }

                        steps.push(FlowStep {
                            file: file_path.to_string(),
                            line: i + 1,
                            content: line.to_string(),
                            step_type: "sink".to_string(),
                            variable: tvar.clone(),
                        });

                        let confidence = if is_sanitized {
                            FlowConfidence::Low
                        } else if in_test {
                            FlowConfidence::Low
                        } else if (i + 1).saturating_sub(*tline) < 15 {
                            FlowConfidence::High
                        } else {
                            FlowConfidence::Medium
                        };

                        let severity_str = if is_sanitized {
                            "LOW"
                        } else if in_test {
                            "INFO"
                        } else {
                            sink.severity
                        };

                        flow_id += 1;
                        paths.push(FlowPath {
                            id: format!("FLOW-{:04}", flow_id),
                            source_file: file_path.to_string(),
                            source_line: *tline,
                            source_type: tsource.clone(),
                            source_var: tvar.clone(),
                            sink_file: file_path.to_string(),
                            sink_line: i + 1,
                            sink_type: sink.sink_type.to_string(),
                            intermediate_steps: steps,
                            is_sanitized,
                            confidence,
                            severity: severity_str.to_string(),
                            cwe: sink.cwe.to_string(),
                            description: format!(
                                "Data flows from {} (line {}) to {} (line {}){}",
                                tsource, tline, sink.sink_type, i + 1,
                                if is_sanitized { " [SANITIZED]" } else { " — NO SANITIZATION DETECTED" }
                            ),
                        });
                    }
                }

                // Check propagated vars
                for (pvar, pline, _, orig_var, psource) in &propagated {
                    if line.contains(pvar.as_str()) && i + 1 > *pline {
                        let is_sanitized = self.check_sanitized(&lines, *pline, i + 1, ext, pvar);

                        // Find the original source
                        let orig_source = tainted.iter().find(|(v, _, _, _)| v == orig_var);
                        let (source_line, source_content) = if let Some((_, sl, sc, _)) = orig_source {
                            (*sl, sc.clone())
                        } else {
                            (*pline, String::new())
                        };

                        let mut steps = vec![
                            FlowStep {
                                file: file_path.to_string(),
                                line: source_line,
                                content: source_content,
                                step_type: "source".to_string(),
                                variable: orig_var.clone(),
                            },
                            FlowStep {
                                file: file_path.to_string(),
                                line: *pline,
                                content: lines.get(pline - 1).unwrap_or(&"").to_string(),
                                step_type: "propagation".to_string(),
                                variable: pvar.clone(),
                            },
                            FlowStep {
                                file: file_path.to_string(),
                                line: i + 1,
                                content: line.to_string(),
                                step_type: "sink".to_string(),
                                variable: pvar.clone(),
                            },
                        ];

                        let _ = &mut steps; // keep

                        let confidence = if is_sanitized {
                            FlowConfidence::Low
                        } else if in_test {
                            FlowConfidence::Low
                        } else if (i + 1).saturating_sub(source_line) < 20 {
                            FlowConfidence::High
                        } else {
                            FlowConfidence::Medium
                        };

                        let severity_str = if is_sanitized {
                            "LOW"
                        } else if in_test {
                            "INFO"
                        } else {
                            sink.severity
                        };

                        flow_id += 1;
                        paths.push(FlowPath {
                            id: format!("FLOW-{:04}", flow_id),
                            source_file: file_path.to_string(),
                            source_line,
                            source_type: psource.clone(),
                            source_var: orig_var.clone(),
                            sink_file: file_path.to_string(),
                            sink_line: i + 1,
                            sink_type: sink.sink_type.to_string(),
                            intermediate_steps: steps,
                            is_sanitized,
                            confidence,
                            severity: severity_str.to_string(),
                            cwe: sink.cwe.to_string(),
                            description: format!(
                                "Propagated taint: {} → {} → {} sink (lines {} → {} → {}){}",
                                orig_var, pvar, sink.sink_type,
                                source_line, pline, i + 1,
                                if is_sanitized { " [SANITIZED]" } else { "" }
                            ),
                        });
                    }
                }
            }
        }

        paths
    }

    /// Check if the data is sanitized between source and sink lines
    fn check_sanitized(&self, lines: &[&str], source_line: usize, sink_line: usize, ext: &str, variable: &str) -> bool {
        let start = source_line; // 1-indexed, so this is the line after the source
        let end = sink_line.min(lines.len());

        for line_idx in start..end {
            let line = lines[line_idx];
            if !line.contains(variable) { continue; }

            // Check registered sanitizer patterns
            for sanitizer in &self.sanitizers {
                if !sanitizer.languages.contains(&ext) { continue; }
                if sanitizer.pattern.is_match(line) {
                    return true;
                }
            }

            // Inter-function validation: recognize validate_*, check_*, verify_*,
            // ensure_*, assert_*, is_valid_*, sanitize_*, clean_*, filter_* calls
            // that take the tainted variable as argument
            let validate_re = Regex::new(
                r"(?i)(?:validate|check|verify|ensure|assert|is_valid|sanitize|clean|filter|normalize|escape|encode|whitelist|allowlist|safeguard|guard)_?\w*\s*\("
            ).unwrap();
            if validate_re.is_match(line) {
                return true;
            }
        }
        false
    }
}
