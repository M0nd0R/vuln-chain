mod scanner;
mod patterns;
mod analyzer;
mod report;
mod dataflow;

use clap::Parser;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use crate::scanner::engine::ScanEngine;
use crate::report::formatter;
use crate::report::sarif;

#[derive(Parser, Debug)]
#[command(
    name = "vulnchain",
    about = "Deep vulnerability scanner & chain analyzer for open-source codebases",
    long_about = "VulnChain - A fast, deep vulnerability scanner built in Rust.\n\
                  Scans cloned repositories for vulnerability patterns across all major languages,\n\
                  performs taint analysis, data flow tracking, composite rule matching,\n\
                  secret detection, IaC security scanning, dependency auditing,\n\
                  and builds multi-step attack chain scenarios.\n\n\
                  Inspired by Semgrep & CodeQL — pattern-based + data-flow analysis.",
    version
)]
struct Args {
    /// Path to the repository/directory to scan
    #[arg(short, long, default_value = ".")]
    target: PathBuf,

    /// Output JSON report to file
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output SARIF report to file (for GitHub Code Scanning / VS Code)
    #[arg(long)]
    sarif: Option<PathBuf>,

    /// Only show findings at or above this severity (critical, high, medium, low, info)
    #[arg(short, long, default_value = "low")]
    severity: String,

    /// Suppress terminal output (only write JSON/SARIF)
    #[arg(short, long, default_value_t = false)]
    quiet: bool,

    /// Number of threads for parallel scanning (0 = auto)
    #[arg(short = 'j', long, default_value_t = 0)]
    threads: usize,

    /// Clone a git repository and scan it
    #[arg(short, long)]
    clone: Option<String>,

    /// Disable IaC/config security scanning
    #[arg(long, default_value_t = false)]
    no_iac: bool,

    /// Include test files in scan results (default: excluded)
    /// Test directories: _tests/, tests/, test/, __tests__/, spec/, fixtures/
    #[arg(long, default_value_t = false)]
    include_tests: bool,
}

fn main() {
    let args = Args::parse();

    let target = if let Some(repo_url) = &args.clone {
        // Clone the repo to a temp directory and scan
        let clone_dir = std::env::temp_dir().join("vulnchain_scan");
        if clone_dir.exists() {
            let _ = std::fs::remove_dir_all(&clone_dir);
        }

        eprintln!("[*] Cloning {} ...", repo_url);
        let status = process::Command::new("git")
            .args(["clone", "--depth", "1", repo_url, &clone_dir.to_string_lossy()])
            .status();

        match status {
            Ok(s) if s.success() => {
                eprintln!("[+] Clone complete: {}", clone_dir.display());
                clone_dir
            }
            _ => {
                eprintln!("[-] Failed to clone repository. Make sure git is installed.");
                process::exit(1);
            }
        }
    } else {
        let target = args.target.canonicalize().unwrap_or_else(|_| {
            eprintln!("[-] Target path does not exist: {}", args.target.display());
            process::exit(1);
        });
        target
    };

    if !target.exists() {
        eprintln!("[-] Target path does not exist: {}", target.display());
        process::exit(1);
    }

    // Configure thread pool
    if args.threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(args.threads)
            .build_global()
            .ok();
    }

    eprintln!("[*] Scanning: {}", target.display());
    let start = Instant::now();

    eprintln!("[*] Initializing scan engines...");
    let engine = ScanEngine::new();
    eprintln!("[*] Engines ready in {:.2}s", start.elapsed().as_secs_f64());
    let mut result = engine.scan(&target, args.include_tests);

    let elapsed = start.elapsed();
    eprintln!("[+] Scan completed in {:.2}s", elapsed.as_secs_f64());

    // Apply severity filter
    let min_score = match args.severity.to_lowercase().as_str() {
        "critical" => 10,
        "high" => 8,
        "medium" => 5,
        "low" => 3,
        "info" | _ => 1,
    };
    result.findings.retain(|f| f.severity.score() >= min_score);
    result.taint_findings.retain(|t| severity_score(&t.severity) >= min_score);
    result.flow_paths.retain(|f| severity_score(&f.severity) >= min_score);
    result.composite_findings.retain(|c| severity_score(&c.severity) >= min_score);
    result.iac_findings.retain(|i| severity_score(&i.severity) >= min_score);
    result.secret_findings.retain(|s| severity_score(&s.severity) >= min_score);
    result.dep_findings.retain(|d| severity_score(&d.severity) >= min_score);

    // Terminal report
    if !args.quiet {
        // If JSON/SARIF output is requested, print compact summary only to avoid
        // flooding the terminal — full details go to the file.
        if args.output.is_some() || args.sarif.is_some() {
            formatter::print_summary(&result);
        } else {
            formatter::print_report(&result);
        }
    }

    // JSON export
    if let Some(output_path) = &args.output {
        let json = formatter::export_json(&result);
        let abs_path = std::env::current_dir()
            .map(|cwd| cwd.join(output_path))
            .unwrap_or_else(|_| output_path.clone());
        match std::fs::write(&abs_path, &json) {
            Ok(_) => eprintln!("[+] JSON report written to: {}", abs_path.display()),
            Err(e) => eprintln!("[-] Failed to write JSON report: {}", e),
        }
    }

    // SARIF export
    if let Some(sarif_path) = &args.sarif {
        let sarif_output = sarif::generate_sarif(&result, &target.to_string_lossy());
        let abs_path = std::env::current_dir()
            .map(|cwd| cwd.join(sarif_path))
            .unwrap_or_else(|_| sarif_path.clone());
        match std::fs::write(&abs_path, &sarif_output) {
            Ok(_) => eprintln!("[+] SARIF report written to: {}", abs_path.display()),
            Err(e) => eprintln!("[-] Failed to write SARIF report: {}", e),
        }
    }

    // Exit code based on findings
    let critical = result.findings.iter()
        .filter(|f| f.severity == crate::patterns::vuln_rules::Severity::Critical)
        .count();
    if critical > 0 || !result.vuln_chains.is_empty() {
        process::exit(2); // Critical findings
    } else if !result.findings.is_empty() || !result.secret_findings.is_empty() {
        process::exit(1); // Non-critical findings
    }
}

fn severity_score(severity: &str) -> u8 {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => 10,
        "HIGH" => 8,
        "MEDIUM" => 5,
        "LOW" => 3,
        "INFO" => 1,
        _ => 1,
    }
}
