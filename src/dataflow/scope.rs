use regex::Regex;
use std::sync::OnceLock;
use std::collections::HashMap;

/// Scope analysis: determine what scope a line of code is in (function, class, block)
/// Used for context-aware matching (Semgrep's pattern-inside concept)

pub struct ScopeAnalyzer;

struct ScopeRegexes {
    class_re: Regex,
    loop_re: Regex,
    try_re: Regex,
    test_re: Regex,
    func_res: HashMap<&'static str, Regex>,
}

fn scope_regexes() -> &'static ScopeRegexes {
    static INSTANCE: OnceLock<ScopeRegexes> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let mut func_res = HashMap::new();
        let funcs: &[(&str, &str)] = &[
            ("py", r"^\s*(?:async\s+)?def\s+(\w+)"),
            ("js", r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()"),
            ("ts", r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()"),
            ("jsx", r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()"),
            ("tsx", r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\()"),
            ("java", r"(?:public|private|protected|static|void|int|String|async)\s+\w*\s*(\w+)\s*\("),
            ("kt", r"(?:public|private|protected|static|void|int|String|async)\s+\w*\s*(\w+)\s*\("),
            ("cs", r"(?:public|private|protected|static|void|int|String|async)\s+\w*\s*(\w+)\s*\("),
            ("go", r"func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)"),
            ("rb", r"def\s+(\w+)"),
            ("php", r"(?:function|public\s+function|private\s+function)\s+(\w+)"),
            ("rs", r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)"),
            ("c", r"(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{"),
            ("cpp", r"(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{"),
            ("h", r"(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{"),
            ("hpp", r"(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{"),
        ];
        for &(ext, pat) in funcs {
            func_res.insert(ext, Regex::new(pat).unwrap());
        }
        let default_func = Regex::new(r"(?:function|def|fn|func)\s+(\w+)").unwrap();
        func_res.insert("__default__", default_func);

        ScopeRegexes {
            class_re: Regex::new(r"(?i)(?:class|struct|interface|enum)\s+(\w+)").unwrap(),
            loop_re: Regex::new(r"(?i)^\s*(?:for|while|loop|do)\b").unwrap(),
            try_re: Regex::new(r"(?i)^\s*(?:try|catch|except|rescue|begin)\b").unwrap(),
            test_re: Regex::new(r"(?i)(?:test_|_test|spec_|_spec|Test\b|describe\(|it\(|@Test|#\[test\]|func Test)").unwrap(),
            func_res,
        }
    })
}

#[derive(Debug, Clone)]
pub struct ScopeInfo {
    pub function_name: Option<String>,
    pub class_name: Option<String>,
    pub is_in_try_catch: bool,
    pub is_in_loop: bool,
    pub is_in_test: bool,
    pub indent_level: usize,
}

impl ScopeAnalyzer {
    pub fn analyze_scope(lines: &[&str], target_line: usize, ext: &str) -> ScopeInfo {
        let mut function_name = None;
        let mut class_name = None;
        let mut is_in_try_catch = false;
        let mut is_in_loop = false;
        let mut is_in_test = false;

        let target_indent = if target_line > 0 && target_line <= lines.len() {
            count_indent(lines[target_line - 1])
        } else {
            0
        };

        let sr = scope_regexes();
        let func_re = sr.func_res.get(ext).unwrap_or_else(|| sr.func_res.get("__default__").unwrap());
        let class_re = &sr.class_re;
        let loop_re = &sr.loop_re;
        let try_re = &sr.try_re;
        let test_re = &sr.test_re;

        // Scan backwards from target line
        for i in (0..target_line.min(lines.len())).rev() {
            let line = lines[i];
            let indent = count_indent(line);

            if indent < target_indent || i == target_line - 1 {
                if try_re.is_match(line) { is_in_try_catch = true; }
                if loop_re.is_match(line) { is_in_loop = true; }
            }

            if indent <= target_indent || indent == 0 {
                if function_name.is_none() {
                    if let Some(caps) = func_re.captures(line) {
                        let name = caps.get(1).or(caps.get(2)).map(|m| m.as_str().to_string());
                        if let Some(ref n) = name {
                            if test_re.is_match(line) || test_re.is_match(n) {
                                is_in_test = true;
                            }
                        }
                        function_name = name;
                    }
                }
                if class_name.is_none() {
                    if let Some(caps) = class_re.captures(line) {
                        class_name = caps.get(1).map(|m| m.as_str().to_string());
                    }
                }
            }

            if function_name.is_some() && class_name.is_some() { break; }
        }

        ScopeInfo {
            function_name,
            class_name,
            is_in_try_catch,
            is_in_loop,
            is_in_test,
            indent_level: target_indent,
        }
    }
}

fn count_indent(line: &str) -> usize {
    let trimmed = line.trim_start();
    if trimmed.is_empty() { return 0; }
    let spaces = line.len() - trimmed.len();
    // Convert tabs to 4 spaces equivalent
    let tabs = line.chars().take(spaces).filter(|c| *c == '\t').count();
    spaces - tabs + tabs * 4
}
