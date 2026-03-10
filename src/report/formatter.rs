use colored::*;
use serde::Serialize;

use crate::scanner::engine::ScanResult;
use crate::dataflow::flow_tracker::FlowPath;
use crate::dataflow::composite::CompositeFinding;
use crate::scanner::iac::IacFinding;

#[derive(Serialize)]
struct JsonReport<'a> {
    summary: Summary,
    vulnerability_findings: &'a [crate::patterns::vuln_rules::Finding],
    secret_findings: &'a [crate::scanner::secrets::SecretFinding],
    dependency_findings: &'a [crate::patterns::dependency::DepFinding],
    taint_flows: &'a [crate::analyzer::taint::TaintFinding],
    data_flow_paths: &'a [FlowPath],
    composite_findings: &'a [CompositeFinding],
    iac_findings: &'a [IacFinding],
    vulnerability_chains: &'a [crate::analyzer::chain::VulnChain],
}

#[derive(Serialize)]
struct Summary {
    files_scanned: usize,
    lines_scanned: usize,
    total_vulnerabilities: usize,
    total_secrets: usize,
    total_dep_issues: usize,
    total_taint_flows: usize,
    total_flow_paths: usize,
    total_composite: usize,
    total_iac: usize,
    total_chains: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    info: usize,
}

pub fn print_report(result: &ScanResult) {
    let separator = "═".repeat(90);
    let thin_sep = "─".repeat(90);

    println!("\n{}", separator.bold().red());
    println!("{}", r#"
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗██╗  ██╗ █████╗ ██╗███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║  ██║██╔══██╗██║████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██║     ███████║███████║██║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██╔══██║██╔══██║██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║██║  ██║██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝ ╚═══╝
    "#.bold().red());
    println!("  {} Deep Vulnerability Scanner & Chain Analyzer", "VulnChain".bold().red());
    println!("{}\n", separator.bold().red());

    // Summary
    let critical = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Critical).count();
    let high = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::High).count();
    let medium = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Medium).count();
    let low = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Low).count();
    let info = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Info).count();

    println!("  {} {}", "SCAN SUMMARY".bold().underline(), "".dimmed());
    println!("  {} Files scanned:       {}", "├".dimmed(), result.files_scanned.to_string().bold());
    println!("  {} Lines scanned:       {}", "├".dimmed(), result.lines_scanned.to_string().bold());
    println!("  {} Code vulnerabilities: {}", "├".dimmed(), result.findings.len().to_string().bold().yellow());
    println!("  {} Composite rule hits: {}", "├".dimmed(), result.composite_findings.len().to_string().bold().yellow());
    println!("  {} Data flow paths:     {}", "├".dimmed(), result.flow_paths.len().to_string().bold().yellow());
    println!("  {} Secret leaks:        {}", "├".dimmed(), result.secret_findings.len().to_string().bold().red());
    println!("  {} Dependency issues:   {}", "├".dimmed(), result.dep_findings.len().to_string().bold().yellow());
    println!("  {} Taint flows (src→sink): {}", "├".dimmed(), result.taint_findings.len().to_string().bold().red());
    println!("  {} IaC/Config issues:   {}", "├".dimmed(), result.iac_findings.len().to_string().bold().yellow());
    println!("  {} Attack chains:       {}", "╰".dimmed(), result.vuln_chains.len().to_string().bold().red());
    println!();
    println!("  {} {} | {} {} | {} {} | {} {} | {} {}",
        "CRITICAL:".on_red().bold().white(), critical,
        "HIGH:".on_yellow().bold().black(), high,
        "MEDIUM:".on_cyan().bold().black(), medium,
        "LOW:".on_blue().bold().white(), low,
        "INFO:".dimmed(), info,
    );
    println!("\n{}", separator.bold().red());

    // =================== VULNERABILITY CHAINS ===================
    if !result.vuln_chains.is_empty() {
        println!("\n  {}\n", "⚡ VULNERABILITY CHAINS (Attack Scenarios)".bold().red().underline());
        for chain in &result.vuln_chains {
            let sev_colored = match chain.severity.as_str() {
                "CRITICAL" => chain.severity.on_red().bold().white().to_string(),
                "HIGH" => chain.severity.on_yellow().bold().black().to_string(),
                _ => chain.severity.bold().to_string(),
            };
            println!("  {} [{}] {} (CVSS ~{:.1})", "┌".red(), sev_colored, chain.title.bold(), chain.cvss_estimate);
            println!("  {} {}", "│".red(), chain.description.dimmed());
            println!("  {} {}", "│".red(), "Attack Scenario:".bold().yellow());
            for line in chain.attack_scenario.lines() {
                println!("  {}   {}", "│".red(), line);
            }
            println!("  {} {}", "│".red(), "Steps:".bold());
            for step in &chain.steps {
                println!("  {}   {}. {} → {}:{}", "│".red(),
                    step.step_number,
                    step.description,
                    step.file_path.dimmed(),
                    step.line_number);
            }
            println!("  {} {} {}", "╰".red(), "Impact:".bold().red(), chain.impact);
            println!();
        }
        println!("{}", thin_sep.dimmed());
    }

    // =================== TAINT FLOWS ===================
    if !result.taint_findings.is_empty() {
        println!("\n  {}\n", "🔗 TAINT ANALYSIS (Source → Sink Data Flows)".bold().yellow().underline());
        for (i, taint) in result.taint_findings.iter().enumerate().take(50) {
            let sev = match taint.severity.as_str() {
                "CRITICAL" => taint.severity.red().bold().to_string(),
                "HIGH" => taint.severity.yellow().bold().to_string(),
                _ => taint.severity.cyan().to_string(),
            };
            println!("  [{}] #{} [{}] Confidence: {}",
                sev, i + 1,
                taint.sink.sink_type.bold(),
                taint.confidence.bold());
            println!("    {} Source [L{}]: {} → var '{}'",
                "↓".green(),
                taint.source.line_number,
                taint.source.source_type.green(),
                taint.source.variable.bold());
            println!("    {} Sink   [L{}]: {}",
                "↓".red(),
                taint.sink.line_number,
                taint.sink.sink_type.red());
            println!("    File: {}", taint.file_path.dimmed());
            println!("    {}", taint.flow_description.dimmed());
            println!();
        }
        if result.taint_findings.len() > 50 {
            println!("    ... and {} more taint flows (see JSON report for full list)",
                result.taint_findings.len() - 50);
        }
        println!("{}", thin_sep.dimmed());
    }

    // =================== CODE VULNERABILITIES ===================
    if !result.findings.is_empty() {
        println!("\n  {}\n", "🔍 CODE VULNERABILITY FINDINGS".bold().yellow().underline());

        // Group findings by rule_name for cleaner output
        let mut by_rule: Vec<(String, Vec<&crate::patterns::vuln_rules::Finding>)> = Vec::new();
        let mut rule_order: Vec<String> = Vec::new();
        for f in &result.findings {
            if !rule_order.contains(&f.rule_name) {
                rule_order.push(f.rule_name.clone());
            }
        }
        for rule_name in &rule_order {
            let group: Vec<_> = result.findings.iter().filter(|f| &f.rule_name == rule_name).collect();
            by_rule.push((rule_name.clone(), group));
        }

        for (group_idx, (rule_name, group)) in by_rule.iter().enumerate() {
            let first = group[0];
            let sev = match first.severity {
                crate::patterns::vuln_rules::Severity::Critical => "CRITICAL".on_red().bold().white().to_string(),
                crate::patterns::vuln_rules::Severity::High => "HIGH".on_yellow().bold().black().to_string(),
                crate::patterns::vuln_rules::Severity::Medium => "MEDIUM".on_cyan().bold().black().to_string(),
                crate::patterns::vuln_rules::Severity::Low => "LOW".on_blue().bold().white().to_string(),
                crate::patterns::vuln_rules::Severity::Info => "INFO".dimmed().to_string(),
            };

            println!("  {} #{} [{}] {} ({} occurrences)", "┌".yellow(), group_idx + 1, sev, rule_name.bold(), group.len().to_string().bold());
            println!("  {} Rule: {} | {}", "│".yellow(), first.rule_id.dimmed(), first.cwe.cyan());
            println!("  {} {}", "│".yellow(), first.description);
            // Show up to 5 unique locations
            println!("  {} {}", "│".yellow(), "Locations:".bold());
            for f in group.iter().take(5) {
                println!("  {}   {}:{} → {}", "│".yellow(), f.file_path.dimmed(), f.line_number, f.matched_text.red());
            }
            if group.len() > 5 {
                println!("  {}   ... and {} more locations (see JSON report)", "│".yellow(), group.len() - 5);
            }
            println!("  {} {} {}", "╰".yellow(), "Fix:".bold().green(), first.remediation.green());
            println!();
        }
        println!("{}", thin_sep.dimmed());
    }

    // =================== COMPOSITE RULE FINDINGS (Semgrep-style) ===================
    if !result.composite_findings.is_empty() {
        println!("\n  {}\n", "🧩 COMPOSITE RULE FINDINGS (Semgrep-style AND/OR/NOT)".bold().magenta().underline());

        // Group by rule_name
        let mut rule_order: Vec<String> = Vec::new();
        for cf in &result.composite_findings {
            if !rule_order.contains(&cf.rule_name) {
                rule_order.push(cf.rule_name.clone());
            }
        }

        for (group_idx, rule_name) in rule_order.iter().enumerate() {
            let group: Vec<_> = result.composite_findings.iter()
                .filter(|cf| &cf.rule_name == rule_name)
                .collect();
            let first = group[0];
            let sev = match first.severity.as_str() {
                "CRITICAL" => "CRITICAL".on_red().bold().white().to_string(),
                "HIGH" => "HIGH".on_yellow().bold().black().to_string(),
                "MEDIUM" => "MEDIUM".on_cyan().bold().black().to_string(),
                _ => first.severity.cyan().to_string(),
            };
            println!("  {} #{} [{}] {} ({} occurrences)", "┌".magenta(), group_idx + 1, sev, rule_name.bold(), group.len().to_string().bold());
            println!("  {} {} | {} | {} | Confidence: {}", "│".magenta(), first.rule_id.dimmed(), first.cwe.cyan(), first.owasp.cyan(), first.confidence.bold());
            println!("  {} {}", "│".magenta(), first.description);
            println!("  {} {}", "│".magenta(), "Locations:".bold());
            for cf in group.iter().take(5) {
                println!("  {}   {}:{}", "│".magenta(), cf.file_path.dimmed(), cf.line_number);
            }
            if group.len() > 5 {
                println!("  {}   ... and {} more locations (see JSON report)", "│".magenta(), group.len() - 5);
            }
            println!("  {} {} {}", "╰".magenta(), "Fix:".bold().green(), first.remediation.green());
            println!();
        }
        println!("{}", thin_sep.dimmed());
    }

    // =================== DATA FLOW PATHS (CodeQL-style) ===================
    if !result.flow_paths.is_empty() {
        println!("\n  {}\n", "🔀 DATA FLOW PATHS (CodeQL-style source→sink tracking)".bold().cyan().underline());
        for (i, flow) in result.flow_paths.iter().enumerate().take(30) {
            if flow.is_sanitized { continue; }
            let sev = match flow.severity.as_str() {
                "CRITICAL" => "CRITICAL".on_red().bold().white().to_string(),
                "HIGH" => "HIGH".on_yellow().bold().black().to_string(),
                _ => flow.severity.cyan().to_string(),
            };
            println!("  [{}] #{} {} [Confidence: {}]", sev, i + 1, flow.description.bold(), flow.confidence);
            println!("    {} Source [L{}]: {} ({})", "↓".green(), flow.source_line, flow.source_var.green(), flow.source_type.dimmed());
            for step in &flow.intermediate_steps {
                println!("    {} Step   [L{}]: {}", "↓".cyan(), step.line, step.content);
            }
            println!("    {} Sink   [L{}]: {}", "↓".red(), flow.sink_line, flow.sink_type.red());
            println!("    {}", flow.cwe.cyan());
            println!();
        }
        let unsanitized = result.flow_paths.iter().filter(|f| !f.is_sanitized).count();
        if unsanitized > 30 {
            println!("    ... and {} more unsanitized flows (see JSON report)", unsanitized - 30);
        }
        let sanitized = result.flow_paths.iter().filter(|f| f.is_sanitized).count();
        if sanitized > 0 {
            println!("    ({} flows properly sanitized — excluded)", sanitized.to_string().green());
        }
        println!("{}", thin_sep.dimmed());
    }

    // =================== IaC / CONFIG SECURITY ===================
    if !result.iac_findings.is_empty() {
        println!("\n  {}\n", "🏗️  IaC / CONFIG SECURITY FINDINGS".bold().yellow().underline());
        for (i, iac) in result.iac_findings.iter().enumerate().take(50) {
            let sev = match iac.severity.as_str() {
                "CRITICAL" => "CRITICAL".on_red().bold().white().to_string(),
                "HIGH" => "HIGH".on_yellow().bold().black().to_string(),
                "MEDIUM" => "MEDIUM".on_cyan().bold().black().to_string(),
                _ => iac.severity.cyan().to_string(),
            };
            println!("  [{}] #{} {} [{}] ({})", sev, i + 1, iac.rule_name.bold(), iac.rule_id.dimmed(), iac.category.dimmed());
            println!("    {}", iac.description);
            println!("    File: {}:{}", iac.file_path.dimmed(), iac.line_number);
            println!("    {}", iac.cwe.cyan());
            println!("    {} {}", "Fix:".bold().green(), iac.remediation.green());
            println!();
        }
        if result.iac_findings.len() > 50 {
            println!("    ... and {} more IaC findings (see JSON report)", result.iac_findings.len() - 50);
        }
        println!("{}", thin_sep.dimmed());
    }

    // =================== SECRET FINDINGS ===================
    if !result.secret_findings.is_empty() {
        println!("\n  {}\n", "🔐 SECRET / CREDENTIAL LEAKS".bold().red().underline());

        // Group secrets by rule_name only for cleaner output
        let mut rule_order: Vec<String> = Vec::new();
        for s in &result.secret_findings {
            if !rule_order.contains(&s.rule_name) {
                rule_order.push(s.rule_name.clone());
            }
        }

        for (group_idx, rule_name) in rule_order.iter().enumerate() {
            let group: Vec<_> = result.secret_findings.iter()
                .filter(|s| &s.rule_name == rule_name)
                .collect();
            let first = group[0];
            let sev = match first.severity.as_str() {
                "CRITICAL" => "CRITICAL".on_red().bold().white().to_string(),
                "HIGH" => "HIGH".on_yellow().bold().black().to_string(),
                _ => first.severity.cyan().to_string(),
            };

            // Collect unique file paths
            let mut unique_files: Vec<String> = Vec::new();
            for s in &group {
                let loc = format!("{}:{}", s.file_path, s.line_number);
                if !unique_files.contains(&loc) {
                    unique_files.push(loc);
                }
            }

            println!("  [{}] #{} {} — {} ({} total, {} unique locations)",
                sev, group_idx + 1, first.rule_name.bold(), first.description,
                group.len().to_string().bold(), unique_files.len());
            // Show up to 3 unique file locations
            for loc in unique_files.iter().take(3) {
                println!("    → {}", loc.dimmed());
            }
            if unique_files.len() > 3 {
                println!("    ... and {} more locations", unique_files.len() - 3);
            }
            println!();
        }
        println!("{}", thin_sep.dimmed());
    }

    // =================== DEPENDENCY FINDINGS ===================
    if !result.dep_findings.is_empty() {
        println!("\n  {}\n", "📦 VULNERABLE DEPENDENCIES".bold().yellow().underline());

        // Group by (package_name, version, vulnerability)
        let mut dep_order: Vec<(String, String, String)> = Vec::new();
        for dep in &result.dep_findings {
            let key = (dep.package_name.clone(), dep.version.clone(), dep.vulnerability.clone());
            if !dep_order.contains(&key) {
                dep_order.push(key);
            }
        }

        for (group_idx, (pkg, ver, vuln)) in dep_order.iter().enumerate() {
            let group: Vec<_> = result.dep_findings.iter()
                .filter(|d| &d.package_name == pkg && &d.version == ver && &d.vulnerability == vuln)
                .collect();
            let first = group[0];
            let sev = match first.severity.as_str() {
                "CRITICAL" => "CRITICAL".on_red().bold().white().to_string(),
                "HIGH" => "HIGH".on_yellow().bold().black().to_string(),
                _ => first.severity.cyan().to_string(),
            };

            let files: Vec<String> = group.iter().map(|d| d.file_path.clone()).collect();
            if group.len() == 1 {
                println!("  [{}] #{} {}@{}", sev, group_idx + 1, pkg.bold(), ver);
            } else {
                println!("  [{}] #{} {}@{} (found in {} files)", sev, group_idx + 1, pkg.bold(), ver, group.len());
            }
            println!("    {}", vuln);
            for f in files.iter().take(3) {
                println!("    File: {} | Manager: {}", f.dimmed(), first.package_manager);
            }
            if files.len() > 3 {
                println!("    ... and {} more files", files.len() - 3);
            }
            println!("    Fix: {}", first.advice.green());
            println!();
        }
        println!("{}", thin_sep.dimmed());
    }

    // Final summary
    let total = result.findings.len() + result.secret_findings.len()
        + result.dep_findings.len() + result.taint_findings.len()
        + result.composite_findings.len() + result.flow_paths.iter().filter(|f| !f.is_sanitized).count()
        + result.iac_findings.len();
    println!("\n{}", separator.bold().red());
    if total == 0 {
        println!("  {} No vulnerabilities detected!", "✓".bold().green());
    } else {
        println!("  {} Total issues: {} | Chains: {} | Risk: {}",
            "⚠".bold().red(),
            total.to_string().bold().red(),
            result.vuln_chains.len().to_string().bold().yellow(),
            if critical > 0 { "CRITICAL".red().bold().to_string() }
            else if high > 0 { "HIGH".yellow().bold().to_string() }
            else { "MODERATE".cyan().to_string() }
        );
    }
    println!("{}\n", separator.bold().red());
}

pub fn export_json(result: &ScanResult) -> String {
    let critical = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Critical).count();
    let high = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::High).count();
    let medium = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Medium).count();
    let low = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Low).count();
    let info = result.findings.iter().filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Info).count();

    let report = JsonReport {
        summary: Summary {
            files_scanned: result.files_scanned,
            lines_scanned: result.lines_scanned,
            total_vulnerabilities: result.findings.len(),
            total_secrets: result.secret_findings.len(),
            total_dep_issues: result.dep_findings.len(),
            total_taint_flows: result.taint_findings.len(),
            total_flow_paths: result.flow_paths.len(),
            total_composite: result.composite_findings.len(),
            total_iac: result.iac_findings.len(),
            total_chains: result.vuln_chains.len(),
            critical,
            high,
            medium,
            low,
            info,
        },
        vulnerability_findings: &result.findings,
        secret_findings: &result.secret_findings,
        dependency_findings: &result.dep_findings,
        taint_flows: &result.taint_findings,
        data_flow_paths: &result.flow_paths,
        composite_findings: &result.composite_findings,
        iac_findings: &result.iac_findings,
        vulnerability_chains: &result.vuln_chains,
    };

    serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}
