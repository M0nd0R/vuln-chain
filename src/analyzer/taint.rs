use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::dataflow::sanitizers::SanitizerDB;
use crate::dataflow::scope::ScopeAnalyzer;

/// Taint analysis: track data flow from sources (user input) to sinks (dangerous functions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFinding {
    pub file_path: String,
    pub source: TaintSource,
    pub sink: TaintSink,
    pub flow_description: String,
    pub severity: String,
    pub confidence: String,
    pub is_sanitized: bool,
    pub sanitizer_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub line_number: usize,
    pub line_content: String,
    pub source_type: String,
    pub variable: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSink {
    pub line_number: usize,
    pub line_content: String,
    pub sink_type: String,
}

struct SourcePattern {
    pattern: Regex,
    source_type: &'static str,
    languages: &'static [&'static str],
}

struct SinkPattern {
    pattern: Regex,
    sink_type: &'static str,
    languages: &'static [&'static str],
    severity: &'static str,
}

pub struct TaintAnalyzer {
    sources: Vec<SourcePattern>,
    sinks: Vec<SinkPattern>,
    sanitizer_db: SanitizerDB,
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        let sources = vec![
            // Python sources
            SourcePattern {
                pattern: Regex::new(r"(?i)(\w+)\s*=\s*(?:request\.(?:args|form|data|json|values|cookies|headers|files)|flask\.request|input\s*\()").unwrap(),
                source_type: "user_input",
                languages: &["py"],
            },
            SourcePattern {
                pattern: Regex::new(r"(?i)(\w+)\s*=\s*sys\.argv").unwrap(),
                source_type: "command_line_arg",
                languages: &["py"],
            },
            // JavaScript sources
            SourcePattern {
                pattern: Regex::new(r"(?i)(?:const|let|var)\s+(\w+)\s*=\s*(?:req\.(?:body|query|params|headers|cookies)|request\.(?:body|query|params))").unwrap(),
                source_type: "user_input",
                languages: &["js", "ts"],
            },
            SourcePattern {
                pattern: Regex::new(r"(?i)(?:const|let|var)\s+(\w+)\s*=\s*(?:document\.(?:location|URL|referrer|cookie)|window\.location|location\.(?:hash|search|href))").unwrap(),
                source_type: "dom_input",
                languages: &["js", "ts", "jsx", "tsx"],
            },
            SourcePattern {
                pattern: Regex::new(r"(?i)(?:const|let|var)\s+(\w+)\s*=\s*(?:process\.argv|process\.env)").unwrap(),
                source_type: "environment",
                languages: &["js", "ts"],
            },
            // Java sources
            SourcePattern {
                pattern: Regex::new(r"(?i)(?:String|Object|var)\s+(\w+)\s*=\s*(?:request\.getParameter|request\.getHeader|request\.getCookies|request\.getInputStream|request\.getReader)").unwrap(),
                source_type: "user_input",
                languages: &["java", "kt"],
            },
            // PHP sources
            SourcePattern {
                pattern: Regex::new(r"(?i)(\$\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\[").unwrap(),
                source_type: "user_input",
                languages: &["php"],
            },
            // Go sources
            SourcePattern {
                pattern: Regex::new(r"(?i)(\w+)\s*(?::=|=)\s*r\.(?:FormValue|URL\.Query|Body|Header\.Get|PostFormValue|Cookie)\(").unwrap(),
                source_type: "user_input",
                languages: &["go"],
            },
            // Ruby sources
            SourcePattern {
                pattern: Regex::new(r"(?i)(\w+)\s*=\s*params\[").unwrap(),
                source_type: "user_input",
                languages: &["rb"],
            },
            // C sources
            SourcePattern {
                pattern: Regex::new(r"(?i)(?:fgets|scanf|fscanf|gets|read|recv|recvfrom)\s*\(\s*(\w+)").unwrap(),
                source_type: "user_input",
                languages: &["c", "cpp", "h", "hpp"],
            },
        ];

        let sinks = vec![
            // SQL sinks
            SinkPattern {
                pattern: Regex::new(r"(?i)(?:execute|query|cursor\.execute|\.raw|db\.query|\.exec|rawQuery)\s*\(").unwrap(),
                sink_type: "sql_execution",
                languages: &["py", "js", "ts", "java", "rb", "php", "go", "kt"],
                severity: "CRITICAL",
            },
            // Command sinks
            SinkPattern {
                pattern: Regex::new(r"(?i)(?:os\.system|subprocess|exec|system|popen|child_process|Process\.Start|Runtime\.exec|exec\.Command)\s*\(").unwrap(),
                sink_type: "command_execution",
                languages: &["py", "js", "ts", "java", "rb", "php", "go", "c", "cpp", "cs", "kt"],
                severity: "CRITICAL",
            },
            // File sinks
            SinkPattern {
                pattern: Regex::new(r"(?i)(?:open|fopen|File\.open|fs\.readFile|fs\.writeFile|FileInputStream|FileOutputStream|File::open)\s*\(").unwrap(),
                sink_type: "file_operation",
                languages: &["py", "js", "ts", "java", "rb", "php", "go", "c", "cpp", "rs"],
                severity: "HIGH",
            },
            // Network sinks
            SinkPattern {
                pattern: Regex::new(r"(?i)(?:requests\.get|urllib|fetch|axios|http\.Get|HttpClient|curl_exec|Net::HTTP)\s*\(").unwrap(),
                sink_type: "network_request",
                languages: &["py", "js", "ts", "java", "rb", "php", "go"],
                severity: "HIGH",
            },
            // Code execution sinks
            SinkPattern {
                pattern: Regex::new(r"(?i)(?:eval|exec|compile|Function|setTimeout|setInterval|assert)\s*\(").unwrap(),
                sink_type: "code_execution",
                languages: &["py", "js", "ts", "rb", "php"],
                severity: "CRITICAL",
            },
            // Deserialization sinks
            SinkPattern {
                pattern: Regex::new(r"(?i)(?:pickle\.loads?|yaml\.load|unserialize|readObject|Marshal\.load|JSON\.parse)\s*\(").unwrap(),
                sink_type: "deserialization",
                languages: &["py", "js", "ts", "java", "rb", "php"],
                severity: "CRITICAL",
            },
            // HTML output sinks
            SinkPattern {
                pattern: Regex::new(r"(?i)(?:innerHTML|outerHTML|document\.write|\.html_safe|mark_safe|@Html\.Raw|render_template_string|dangerouslySetInnerHTML)\b").unwrap(),
                sink_type: "html_output",
                languages: &["js", "ts", "jsx", "tsx", "py", "rb", "cs"],
                severity: "HIGH",
            },
            // LDAP sinks
            SinkPattern {
                pattern: Regex::new(r"(?i)(?:ldap\.search|search_s|DirContext\.search)\s*\(").unwrap(),
                sink_type: "ldap_query",
                languages: &["py", "java"],
                severity: "HIGH",
            },
        ];

        Self { sources, sinks, sanitizer_db: SanitizerDB::new() }
    }

    pub fn analyze(&self, file_path: &str, content: &str, ext: &str) -> Vec<TaintFinding> {
        let mut findings = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // Phase 1: Find all taint sources in this file
        let mut tainted_vars: Vec<(String, usize, String, String)> = Vec::new(); // (var_name, line_num, line_content, source_type)

        for (i, line) in lines.iter().enumerate() {
            for source in &self.sources {
                if !source.languages.contains(&ext) {
                    continue;
                }
                if let Some(caps) = source.pattern.captures(line) {
                    if let Some(var) = caps.get(1) {
                        tainted_vars.push((
                            var.as_str().to_string(),
                            i + 1,
                            line.to_string(),
                            source.source_type.to_string(),
                        ));
                    }
                }
            }
        }

        if tainted_vars.is_empty() {
            return findings;
        }

        // Phase 2: Find sinks that reference tainted variables
        for (i, line) in lines.iter().enumerate() {
            for sink in &self.sinks {
                if !sink.languages.contains(&ext) {
                    continue;
                }
                if sink.pattern.is_match(line) {
                    // Check if any tainted variable flows to this sink
                    for (var_name, src_line, src_content, src_type) in &tainted_vars {
                        // The sink must be AFTER the source, and the variable must appear in the sink line
                        if i + 1 > *src_line && line.contains(var_name.as_str()) {
                            // Check for sanitization between source and sink
                            let mut is_sanitized = false;
                            let mut sanitizer_info = None;
                            for check_line_idx in *src_line..=i {
                                if check_line_idx < lines.len() {
                                    if self.sanitizer_db.is_sanitized_for(lines[check_line_idx], ext, sink.sink_type) {
                                        is_sanitized = true;
                                        sanitizer_info = Some(format!("Sanitizer at line {}: {}", check_line_idx + 1, lines[check_line_idx].trim()));
                                        break;
                                    }
                                }
                            }

                            // Check if the sink is inside a test function — lower confidence
                            let scope = ScopeAnalyzer::analyze_scope(&lines, i + 1, ext);
                            let confidence = if scope.is_in_test {
                                "LOW"
                            } else if is_sanitized {
                                "LOW"
                            } else if (i + 1) - src_line < 20 {
                                "HIGH"
                            } else {
                                "MEDIUM"
                            };

                            let severity = if is_sanitized {
                                "LOW" // Downgrade sanitized flows
                            } else {
                                sink.severity
                            };

                            findings.push(TaintFinding {
                                file_path: file_path.to_string(),
                                source: TaintSource {
                                    line_number: *src_line,
                                    line_content: src_content.clone(),
                                    source_type: src_type.clone(),
                                    variable: var_name.clone(),
                                },
                                sink: TaintSink {
                                    line_number: i + 1,
                                    line_content: line.to_string(),
                                    sink_type: sink.sink_type.to_string(),
                                },
                                flow_description: format!(
                                    "Tainted variable '{}' flows from {} (line {}) to {} (line {}){}",
                                    var_name, src_type, src_line, sink.sink_type, i + 1,
                                    if is_sanitized { " [SANITIZED]" } else { "" }
                                ),
                                severity: severity.to_string(),
                                confidence: confidence.to_string(),
                                is_sanitized,
                                sanitizer_info,
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}
