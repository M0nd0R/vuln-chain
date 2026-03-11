use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::panic;

use crate::patterns::dependency::DependencyScanner;
use crate::patterns::language;
use crate::patterns::vuln_rules::{compile_rules, Finding, CompiledRule};
use crate::scanner::file_collector::{FileCollector, FileType};
use crate::scanner::secrets::{self, SecretFinding};
use crate::scanner::iac::{IacScanner, IacFinding};
use crate::analyzer::taint::{TaintAnalyzer, TaintFinding, is_test_file};
use crate::analyzer::chain::{ChainAnalyzer, VulnChain};
use crate::dataflow::flow_tracker::{FlowTracker, FlowPath};
use crate::dataflow::composite::{CompositeEngine, CompositeFinding};

/// Max lines per source file — skip files larger than this (likely generated)
const MAX_LINES_PER_FILE: usize = 50_000;
/// Batch size for chunked processing — controls memory pressure
const SCAN_BATCH_SIZE: usize = 100;
/// Max total findings per category to prevent OOM on huge repos
const MAX_FINDINGS: usize = 50_000;
const MAX_SECRETS: usize = 10_000;
const MAX_FLOWS: usize = 5_000;

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub secret_findings: Vec<SecretFinding>,
    pub dep_findings: Vec<crate::patterns::dependency::DepFinding>,
    pub taint_findings: Vec<TaintFinding>,
    pub vuln_chains: Vec<VulnChain>,
    pub flow_paths: Vec<FlowPath>,
    pub composite_findings: Vec<CompositeFinding>,
    pub iac_findings: Vec<IacFinding>,
    pub files_scanned: usize,
    pub lines_scanned: usize,
}

pub struct ScanEngine {
    compiled_rules: Vec<CompiledRule>,
    secret_rules: Vec<secrets::SecretRule>,
    dep_scanner: DependencyScanner,
    taint_analyzer: TaintAnalyzer,
    flow_tracker: FlowTracker,
    composite_engine: CompositeEngine,
    iac_scanner: IacScanner,
}

impl ScanEngine {
    pub fn new() -> Self {
        let all = language::all_rules();
        // Leak to get 'static lifetime — these rules live for the program's duration
        let static_rules: &'static [crate::patterns::vuln_rules::VulnRule] =
            Box::leak(all.iter().map(|r| (*r).clone()).collect::<Vec<_>>().into_boxed_slice());

        eprint!("  ├ Compiling {} vulnerability rules... ", static_rules.len());
        let compiled_rules = compile_rules(static_rules);
        eprintln!("done");

        eprint!("  ├ Loading secret patterns... ");
        let secret_rules = secrets::build_secret_rules();
        eprintln!("done ({})", secret_rules.len());

        eprint!("  ├ Loading taint/flow/composite engines... ");
        let taint_analyzer = TaintAnalyzer::new();
        let flow_tracker = FlowTracker::new();
        let composite_engine = CompositeEngine::new();
        eprintln!("done");

        eprint!("  ├ Loading IaC scanner... ");
        let iac_scanner = IacScanner::new();
        eprintln!("done");

        eprint!("  ╰ Loading dependency database... ");
        let dep_scanner = DependencyScanner::new();
        eprintln!("done");

        Self {
            compiled_rules,
            secret_rules,
            dep_scanner,
            taint_analyzer,
            flow_tracker,
            composite_engine,
            iac_scanner,
        }
    }

    pub fn scan(&self, target_path: &Path, include_tests: bool) -> ScanResult {
        let collector = FileCollector::new();
        let files = collector.collect(target_path);
        let total_files = files.len();
        let lines_count = Arc::new(AtomicUsize::new(0));
        let files_done = Arc::new(AtomicUsize::new(0));
        let files_skipped = Arc::new(AtomicUsize::new(0));

        eprintln!("[*] Collected {} files for scanning", total_files);

        // Partition files by type
        let (source_files, other_files): (Vec<_>, Vec<_>) =
            files.into_iter().partition(|f| f.file_type == FileType::Source);

        // Filter out test files if --include-tests is not set
        let source_files: Vec<_> = if include_tests {
            source_files
        } else {
            let (prod, test): (Vec<_>, Vec<_>) = source_files.into_iter()
                .partition(|f| !is_test_file(&f.path.to_string_lossy()));
            if !test.is_empty() {
                eprintln!("[*] Excluding {} test files (use --include-tests to scan them)", test.len());
            }
            prod
        };

        let (dep_files, config_files): (Vec<_>, Vec<_>) =
            other_files.into_iter().partition(|f| f.file_type == FileType::Dependency);

        // Aggregation containers
        let mut all_findings = Vec::new();
        let mut all_secrets = Vec::new();
        let mut all_taints = Vec::new();
        let mut all_flows = Vec::new();
        let mut all_composite = Vec::new();

        let total_source = source_files.len();
        eprintln!("[*] Scanning {} source files in batches of {}", total_source, SCAN_BATCH_SIZE);

        // --- Scan source files in batches for load balancing ---
        for (batch_idx, batch) in source_files.chunks(SCAN_BATCH_SIZE).enumerate() {
            let batch_start = batch_idx * SCAN_BATCH_SIZE;
            let _batch_end = (batch_start + batch.len()).min(total_source);

            let lines_ref = lines_count.clone();
            let done_ref = files_done.clone();
            let skip_ref = files_skipped.clone();

            let batch_results: Vec<(Vec<Finding>, Vec<SecretFinding>, Vec<TaintFinding>, Vec<FlowPath>, Vec<CompositeFinding>)> = batch
                .par_iter()
                .filter_map(|file| {
                    let path_str = file.path.to_string_lossy().to_string();

                    // Catch panics per-file so one bad file doesn't crash everything
                    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
                        self.scan_source_file(file, &lines_ref)
                    }));

                    let done_now = done_ref.fetch_add(1, Ordering::Relaxed) + 1;
                    // Live progress every 50 files
                    if done_now % 50 == 0 || done_now == total_source {
                        let pct = (done_now as f64 / total_source.max(1) as f64 * 100.0) as u8;
                        eprint!("\r  [{}%] {}/{} files scanned...", pct, done_now, total_source);
                    }

                    match result {
                        Ok(Some(r)) => Some(r),
                        Ok(None) => {
                            skip_ref.fetch_add(1, Ordering::Relaxed);
                            None
                        }
                        Err(_) => {
                            skip_ref.fetch_add(1, Ordering::Relaxed);
                            eprintln!("  [!] Skipped (panic): {}", path_str);
                            None
                        }
                    }
                })
                .collect();

            // Stream results into aggregators immediately (free batch memory)
            // Cap each category to prevent OOM on massive repos
            for (findings, secrets, taints, flows, composite) in batch_results {
                if all_findings.len() < MAX_FINDINGS { all_findings.extend(findings); }
                if all_secrets.len() < MAX_SECRETS { all_secrets.extend(secrets); }
                if all_taints.len() < MAX_FINDINGS { all_taints.extend(taints); }
                if all_flows.len() < MAX_FLOWS { all_flows.extend(flows); }
                if all_composite.len() < MAX_FINDINGS { all_composite.extend(composite); }
            }

            // End-of-batch summary
            let done = files_done.load(Ordering::Relaxed);
            let pct = (done as f64 / total_source.max(1) as f64 * 100.0) as u8;
            let total_findings = all_findings.len() + all_secrets.len() + all_taints.len() + all_flows.len() + all_composite.len();
            eprintln!("\r  [{}%] {}/{} source files scanned ({} findings so far)          ",
                pct, done, total_source, total_findings);
        }

        let skipped = files_skipped.load(Ordering::Relaxed);
        if skipped > 0 {
            eprintln!("  [*] Skipped {} files (too large, binary, or scan error)", skipped);
        }

        // --- Scan dependency files ---
        eprintln!("[*] Scanning {} dependency manifests", dep_files.len());
        let dep_results: Vec<Vec<crate::patterns::dependency::DepFinding>> = dep_files
            .par_iter()
            .filter_map(|file| {
                let content = fs::read_to_string(&file.path).ok()?;
                Some(self.dep_scanner.scan_file(&file.path, &content))
            })
            .collect();

        // --- Scan config files for secrets and IaC issues ---
        eprintln!("[*] Scanning {} config files", config_files.len());
        let config_results: Vec<(Vec<SecretFinding>, Vec<IacFinding>)> = config_files
            .par_iter()
            .filter_map(|file| {
                let content = fs::read_to_string(&file.path).ok()?;
                let path_str = file.path.to_string_lossy().to_string();
                let secret_findings = secrets::scan_for_secrets(&path_str, &content, &self.secret_rules);
                let iac_findings = self.iac_scanner.scan(&path_str, &content);
                Some((secret_findings, iac_findings))
            })
            .collect();

        // Aggregate remaining results
        let mut all_deps = Vec::new();
        for deps in dep_results {
            all_deps.extend(deps);
        }

        let mut all_iac = Vec::new();
        for (secrets, iac) in config_results {
            all_secrets.extend(secrets);
            all_iac.extend(iac);
        }

        // --- Vulnerability Chain Analysis ---
        eprintln!("[*] Analyzing attack chains...");
        let chain_analyzer = ChainAnalyzer::new();
        let vuln_chains = chain_analyzer.analyze_chains(&all_findings, &all_taints);

        // --- Deduplicate findings ---
        // Group by (rule_id, matched_text) and keep unique file locations
        eprintln!("[*] Deduplicating results...");
        let before_findings = all_findings.len();
        let before_secrets = all_secrets.len();
        dedup_findings(&mut all_findings);
        dedup_secrets(&mut all_secrets);

        // Cross-engine dedup: if a composite finding covers the same file:line as a
        // basic pattern finding, remove the basic one (composite is more specific)
        let composite_locations: std::collections::HashSet<String> = all_composite.iter()
            .map(|cf| format!("{}:{}", cf.file_path, cf.line_number))
            .collect();
        let before_cross = all_findings.len();
        all_findings.retain(|f| !composite_locations.contains(&format!("{}:{}", f.file_path, f.line_number)));
        let cross_deduped = before_cross - all_findings.len();

        let deduped_findings = before_findings - all_findings.len();
        let deduped_secrets = before_secrets - all_secrets.len();
        if deduped_findings + deduped_secrets > 0 {
            eprintln!("  [*] Removed {} duplicate findings ({} cross-engine), {} duplicate secrets",
                deduped_findings, cross_deduped, deduped_secrets);
        }

        // Sort by severity
        all_findings.sort_by(|a, b| b.severity.score().cmp(&a.severity.score()));

        ScanResult {
            findings: all_findings,
            secret_findings: all_secrets,
            dep_findings: all_deps,
            taint_findings: all_taints,
            vuln_chains,
            flow_paths: all_flows,
            composite_findings: all_composite,
            iac_findings: all_iac,
            files_scanned: total_files,
            lines_scanned: lines_count.load(Ordering::Relaxed),
        }
    }

    /// Scan a single source file — extracted for panic isolation
    fn scan_source_file(
        &self,
        file: &crate::scanner::file_collector::CollectedFile,
        lines_count: &Arc<AtomicUsize>,
    ) -> Option<(Vec<Finding>, Vec<SecretFinding>, Vec<TaintFinding>, Vec<FlowPath>, Vec<CompositeFinding>)> {
        let content = fs::read_to_string(&file.path).ok()?;
        let line_count = content.lines().count();
        lines_count.fetch_add(line_count, Ordering::Relaxed);

        // Skip extremely large files (generated code, data dumps)
        if line_count > MAX_LINES_PER_FILE {
            return None;
        }

        let ext = file.path.extension()?.to_string_lossy().to_lowercase();
        let path_str = file.path.to_string_lossy().to_string();

        // Skip development tool / test data paths that produce noisy false positives
        let lower_path = path_str.to_lowercase();
        if lower_path.contains("/testdata/")
            || lower_path.contains("/test/")
            || lower_path.contains("/tests/")
            || lower_path.contains("_test.go")
            || lower_path.contains(".test.js")
            || lower_path.contains(".test.ts")
            || lower_path.contains(".spec.js")
            || lower_path.contains(".spec.ts")
            || lower_path.contains("/examples/")
            || lower_path.contains("/example/")
            || lower_path.contains("/fixtures/")
            || lower_path.contains("/mock/")
            || lower_path.contains("/mocks/")
            || lower_path.ends_with("_test.py")
            || lower_path.contains("/test_")
        {
            // Don't skip entirely — but mark as test context (already handled by is_test_file)
        }

        // Skip minified JS files — client-side code with compressed patterns triggers FPs
        if lower_path.contains(".min.js") || lower_path.contains(".min.css") || lower_path.contains(".bundle.js") {
            return None;
        }

        let mut findings = Vec::new();

        // Pattern matching
        let lines: Vec<&str> = content.lines().collect();

        // Precompute comment lines to skip (eliminates FPs from code in comments/docs)
        let is_comment = precompute_comment_lines(&lines);

        for compiled in &self.compiled_rules {
            if !compiled.rule.languages.contains(&ext.as_str()) {
                continue;
            }
            for (i, line) in lines.iter().enumerate() {
                // Skip comment lines — code patterns in comments are not vulnerabilities
                if is_comment[i] {
                    continue;
                }
                if let Some(m) = compiled.regex.find(line) {
                    // UAF post-free scope check: only flag if pointer is used after free()
                    if compiled.rule.id == "C-UAF-001" {
                        if let Some(caps) = compiled.regex.captures(line) {
                            if let Some(ptr_match) = caps.get(1) {
                                let ptr_name = ptr_match.as_str();
                                if !is_used_after_free(&lines, i, ptr_name) {
                                    continue; // free() is the last use — not UAF
                                }
                            }
                        }
                    }

                    // C-MEM-002: suppress if NULL check follows within 3 lines
                    if compiled.rule.id == "C-MEM-002" {
                        let has_null_check = lines[i+1..lines.len().min(i+4)].iter().any(|next_line| {
                            let t = next_line.trim().to_lowercase();
                            t.contains("== null") || t.contains("!= null")
                                || t.contains("== 0") || t.contains("!= 0")
                                || t.contains("if (") || t.contains("if(")
                                || t.contains("== nullptr") || t.contains("!= nullptr")
                        });
                        if has_null_check {
                            continue; // Allocation is properly checked — not a vuln
                        }
                    }

                    // P7: Defensive code detection — skip if the matched code IS the defense
                    // e.g. containsDotDot(), sanitizePath(), validateInput() are defenses, not vulns
                    if is_defensive_code(line, compiled.rule.id) {
                        continue;
                    }

                    let mut hasher = Sha256::new();
                    hasher.update(format!("{}:{}:{}", compiled.rule.id, path_str, i + 1));
                    let hash = hex::encode(hasher.finalize());

                    let context_before: Vec<String> = lines[i.saturating_sub(3)..i]
                        .iter().map(|s| s.to_string()).collect();
                    let context_after: Vec<String> = lines[i+1..lines.len().min(i+4)]
                        .iter().map(|s| s.to_string()).collect();

                    findings.push(Finding {
                        rule_id: compiled.rule.id.to_string(),
                        rule_name: compiled.rule.name.to_string(),
                        description: compiled.rule.description.to_string(),
                        category: compiled.rule.category.clone(),
                        severity: compiled.rule.severity.clone(),
                        file_path: path_str.clone(),
                        line_number: i + 1,
                        line_content: line.to_string(),
                        matched_text: m.as_str().to_string(),
                        cwe: compiled.rule.cwe.to_string(),
                        remediation: compiled.rule.remediation.to_string(),
                        context_before,
                        context_after,
                        fingerprint: hash,
                        confidence: if crate::analyzer::taint::is_test_file(&path_str) {
                            "LOW".to_string()
                        } else {
                            "HIGH".to_string()
                        },
                    });
                }
            }
        }

        // Secret scanning
        let secret_findings = secrets::scan_for_secrets(&path_str, &content, &self.secret_rules);

        // Taint analysis
        let taint_findings = self.taint_analyzer.analyze(&path_str, &content, &ext);

        // Data flow analysis (CodeQL-style)
        let flow_paths = self.flow_tracker.track_flows(&path_str, &content, &ext);

        // Composite rule analysis (Semgrep-style)
        let composite_findings = self.composite_engine.scan(&path_str, &content, &ext);

        Some((findings, secret_findings, taint_findings, flow_paths, composite_findings))
    }
}

/// Deduplicate vulnerability findings: keep one per (rule_id, file_path, line_number)
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| {
        let key = format!("{}:{}:{}", f.rule_id, f.file_path, f.line_number);
        seen.insert(key)
    });
}

/// Deduplicate secrets: keep one per (rule_name, file_path, line_number)
fn dedup_secrets(secrets: &mut Vec<SecretFinding>) {
    let mut seen = std::collections::HashSet::new();
    secrets.retain(|s| {
        let key = format!("{}:{}:{}", s.rule_name, s.file_path, s.line_number);
        seen.insert(key)
    });
}

/// Check if a pointer is actually read/written AFTER the free() call in the same scope.
/// Returns true if the pointer is used after free (real UAF), false if free is safe (last use).
fn is_used_after_free(lines: &[&str], free_line_idx: usize, ptr_name: &str) -> bool {
    let free_indent = {
        let line = lines[free_line_idx];
        line.len() - line.trim_start().len()
    };

    // Scan forward from the free() line
    for j in (free_line_idx + 1)..lines.len() {
        let line = lines[j];
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let indent = line.len() - trimmed.len();

        // If we hit a closing brace or function/scope boundary at same or lesser indent, stop
        if indent <= free_indent && (trimmed == "}" || trimmed.starts_with("return") || trimmed.starts_with("void ")
            || trimmed.starts_with("int ") || trimmed.starts_with("static ")
            || trimmed.starts_with("char ") || trimmed.starts_with("struct ")) {
            break;
        }

        // Check if pointer is set to NULL immediately — safe pattern
        if trimmed.contains(ptr_name) && (trimmed.contains("= NULL") || trimmed.contains("= nullptr") || trimmed.contains("= 0")) {
            return false; // ptr is nullified — not UAF
        }

        // Check if pointer is used (read/write) after free
        if trimmed.contains(ptr_name) && !trimmed.starts_with("//") && !trimmed.starts_with("/*") {
            // Pointer appears on a subsequent line — potential UAF
            return true;
        }
    }

    false // free() is the last statement for this pointer — not UAF
}

/// Precompute which lines are comments (single-line or block) to skip during pattern matching.
/// Returns a Vec<bool> where true means the line is a comment and should be skipped.
fn precompute_comment_lines(lines: &[&str]) -> Vec<bool> {
    let mut is_comment = vec![false; lines.len()];
    let mut in_block = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if in_block {
            is_comment[i] = true;
            if trimmed.contains("*/") {
                in_block = false;
            }
            continue;
        }

        // Block comment start
        if trimmed.starts_with("/*") {
            is_comment[i] = true;
            if !trimmed.contains("*/") {
                in_block = true;
            }
            continue;
        }

        // Single-line comments for various languages
        if trimmed.starts_with("//")   // C, C++, Java, Go, JS, Rust, C#, Swift, Kotlin
            || trimmed.starts_with('#')  // Python, Ruby, Shell, Perl
            || trimmed.starts_with("--") // SQL, Haskell, Lua
            || trimmed.starts_with(";;") // Clojure, Lisp
        {
            is_comment[i] = true;
        }
    }

    is_comment
}

/// Detect if a matched line is actually defensive/security code rather than a vulnerability.
/// For example, a function named `containsDotDot` or `sanitizePath` IS the defense against
/// path traversal, not a path traversal vulnerability.
fn is_defensive_code(line: &str, rule_id: &str) -> bool {
    let lower = line.to_lowercase();

    // Defensive function names that indicate the code IS the security control
    let defensive_patterns = [
        "containsdotdot", "sanitize", "validate", "escape", "clean",
        "filter", "check", "verify", "guard", "protect", "secure",
        "normalize", "canonicalize", "whitelist", "allowlist", "blocklist",
        "denylist", "blacklist", "isvalid", "is_valid", "is_safe",
        "issafe", "isbad", "is_bad",
    ];

    // If the line defines or is inside a function that IS a security check, skip
    for pat in &defensive_patterns {
        if lower.contains(pat) {
            // Only suppress for rules where defensive code is commonly flagged
            match rule_id {
                "GO-PATH-001" | "GO-INJ-001" | "GO-CMD-001" | "GO-SSRF-001"
                | "GO-TMPL-001" | "GO-REDIR-001"
                | "C-CMD-001" | "C-FMT-001"
                | "PHP-INJ-001" | "PHP-INJ-002" | "PHP-XSS-001"
                | "RB-INJ-001" | "RB-CMD-001"
                | "JS-FILE-001" | "JS-SSRF-001"
                | "JAVA-SEC-001" | "JAVA-SEC-002"
                | "RS-PATH-001" | "RS-CMD-001"
                | "CS-INJ-001" | "CS-CMD-001" => return true,
                _ => {}
            }
        }
    }

    false
}
