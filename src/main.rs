use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use npm_pre_scan::models::Verdict;
use npm_pre_scan::namespace::load_top_scoped_packages;
use npm_pre_scan::registry::get_package_info;
use npm_pre_scan::typosquat::load_top_packages;
use npm_pre_scan::{
    aggregate, run_full_local, run_full_registry, run_layer0, run_layer1, run_layer1_local,
    run_layer2_local, run_layer3_local, CheckResult, RiskReport,
};

#[derive(Parser, Debug)]
#[command(name = "npm-pre-scan", about = "npm supply-chain pre-scan (Layer 0 + 1 + 2 + 3)\n\nExit codes: 0=PASS  1=SUSPECT  2=BLOCK  3=ERROR")]
struct Cli {
    /// npm package name(s) to check (skip when using --local, --layer2, --layer3, or --full)
    packages: Vec<String>,

    /// Analyze a local package directory with Layer 1 only (no registry checks)
    #[arg(long, value_name = "DIR")]
    local: Option<PathBuf>,

    /// Analyze a local package directory with Layer 2 dynamic analysis (requires Docker)
    #[arg(long, value_name = "DIR")]
    layer2: Option<PathBuf>,

    /// Analyze a local package directory with Layer 3 condition-mutation analysis (requires Docker)
    #[arg(long, value_name = "DIR")]
    layer3: Option<PathBuf>,

    /// Full pipeline (L0+L1+L2+L3) with aggregate risk report; requires Docker.
    /// Accepts a package NAME (fetched from the npm registry) OR a local DIR
    /// (existing directory path — Layer 0 is skipped, no registry identity).
    #[arg(long, value_name = "NAME_OR_DIR")]
    full: Option<PathBuf>,

    /// Output raw JSON
    #[arg(long)]
    json: bool,

    /// Disable color output
    #[arg(long)]
    no_color: bool,

    /// Verbose progress output: per-layer/per-scenario status on stderr, and
    /// per-finding evidence (exact new DNS/connect/file/process events) in
    /// human-readable output. The evidence itself is always present in JSON
    /// output regardless of this flag.
    #[arg(long, short = 'v')]
    verbose: bool,
}

/// Render a Finding's `"evidence"` array (see `layer3::diff::evidence_lines`)
/// as indented lines, if present and non-empty. Verbose-only — callers gate
/// this behind `cli.verbose`.
fn print_evidence(f: &npm_pre_scan::Finding, indent: &str) {
    if let Some(evidence) = f.get("evidence").and_then(|v| v.as_array()) {
        for e in evidence {
            if let Some(s) = e.as_str() {
                println!("{}evidence: {}", indent, s);
            }
        }
    }
}

fn print_layer_result(layer: &str, result: &CheckResult, use_color: bool, verbose: bool) {
    let verdict_str = result.verdict.to_string();
    let colored_verdict = if use_color {
        match result.verdict {
            Verdict::Pass => verdict_str.green().to_string(),
            Verdict::Suspect => verdict_str.yellow().to_string(),
            Verdict::Block => verdict_str.red().to_string(),
            Verdict::Error => verdict_str.magenta().to_string(),
        }
    } else {
        verdict_str
    };

    println!("\n{}", "=".repeat(60));
    println!("Package : {}  [{}]", result.package, layer);
    println!("Verdict : {}", colored_verdict);
    println!("Score   : {}/100", result.score);

    if let Some(note) = &result.note {
        println!("Note    : {}", note);
    }

    if result.findings.is_empty() {
        println!("Findings: none");
    } else {
        println!("Findings: {}", result.findings.len());
        for f in &result.findings {
            let sev = f.get("severity").and_then(|v| v.as_str()).unwrap_or("?");
            let check = f.get("check").and_then(|v| v.as_str()).unwrap_or("unknown");
            let message = f.get("message").and_then(|v| v.as_str()).unwrap_or("");
            let colored_sev = if use_color {
                match sev {
                    "BLOCK" => sev.red().to_string(),
                    "SUSPECT" => sev.yellow().to_string(),
                    "INFO" => sev.cyan().to_string(),
                    _ => sev.to_string(),
                }
            } else {
                sev.to_string()
            };
            println!("  [{}] ({}) {}", colored_sev, check, message);
            if verbose {
                print_evidence(f, "      ");
            }
        }
    }
}

/// Lowercase status label for human output, matching the JSON `layer_status` value.
fn layer_status_label(status: npm_pre_scan::LayerStatus) -> &'static str {
    match status {
        npm_pre_scan::LayerStatus::Ran => "ran",
        npm_pre_scan::LayerStatus::Error => "error",
        npm_pre_scan::LayerStatus::NotRun => "not_run",
        npm_pre_scan::LayerStatus::Skipped => "skipped",
    }
}

fn print_report(report: &RiskReport, use_color: bool, verbose: bool) {
    let verdict_str = report.verdict.to_string();
    let colored_verdict = if use_color {
        match report.verdict {
            Verdict::Pass => verdict_str.green().to_string(),
            Verdict::Suspect => verdict_str.yellow().to_string(),
            Verdict::Block => verdict_str.red().to_string(),
            Verdict::Error => verdict_str.magenta().to_string(),
        }
    } else {
        verdict_str
    };

    println!("\n{}", "=".repeat(60));
    println!("Package    : {}", report.package);
    println!("Risk Score : {:.2}", report.risk_score);
    println!("Verdict    : {}", colored_verdict);
    if verbose {
        println!(
            "Layer status: L0={} L1={} L2={} L3={}",
            layer_status_label(report.layer_status[0]),
            layer_status_label(report.layer_status[1]),
            layer_status_label(report.layer_status[2]),
            layer_status_label(report.layer_status[3]),
        );
    }

    let print_detections = |label: &str, items: &[String]| {
        if !items.is_empty() {
            println!("{}:", label);
            for item in items {
                println!("  - {}", item);
            }
        }
    };
    print_detections("Layer 0", &report.detections.layer_0);
    print_detections("Layer 1", &report.detections.layer_1);
    print_detections("Layer 2", &report.detections.layer_2);
    print_detections("Layer 3", &report.detections.layer_3);

    if verbose {
        let print_evidence_list = |label: &str, items: &[String]| {
            if !items.is_empty() {
                println!("{} evidence:", label);
                for item in items {
                    println!("  - {}", item);
                }
            }
        };
        print_evidence_list("Layer 0", &report.evidence.layer_0);
        print_evidence_list("Layer 1", &report.evidence.layer_1);
        print_evidence_list("Layer 2", &report.evidence.layer_2);
        print_evidence_list("Layer 3", &report.evidence.layer_3);
    }
}

fn exit_code_for(verdict: &Verdict) -> i32 {
    match verdict {
        Verdict::Pass => 0,
        Verdict::Suspect => 1,
        Verdict::Block => 2,
        Verdict::Error => 3,
    }
}

fn main() {
    let cli = Cli::parse();

    // --local mode: Layer 1 only on a local directory
    if let Some(dir) = cli.local {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("local-package")
            .to_string();
        eprintln!("Scanning local dir as Layer 1: {} ({})", name, dir.display());
        if cli.verbose {
            eprintln!("[Layer 1] Running static analysis checks (install scripts, obfuscation, worm signature, version diff)...");
        }
        let result = run_layer1_local(&name, &dir);

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        } else {
            print_layer_result("Layer 1", &result, !cli.no_color, cli.verbose);
            println!();
        }

        std::process::exit(exit_code_for(&result.verdict));
    }

    // --layer2 mode: Layer 2 dynamic analysis on a local directory (requires Docker)
    if let Some(dir) = cli.layer2 {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("local-package")
            .to_string();
        eprintln!("Scanning local dir as Layer 2 (Docker): {} ({})", name, dir.display());
        if cli.verbose {
            eprintln!("[Layer 2] Building Docker image, running install+import baseline/real traces (4 container runs)...");
        }
        let result = run_layer2_local(&name, &dir);

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        } else {
            print_layer_result("Layer 2", &result, !cli.no_color, cli.verbose);
            println!();
        }

        std::process::exit(exit_code_for(&result.verdict));
    }

    // --layer3 mode: Layer 3 condition-mutation analysis on a local directory (requires Docker)
    if let Some(dir) = cli.layer3 {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("local-package")
            .to_string();
        eprintln!("Scanning local dir as Layer 3 (Docker): {} ({})", name, dir.display());
        if cli.verbose {
            eprintln!("[Layer 3] Building Docker image, running baseline + clock(D1) + env(D2) + fuzz(D3) scenarios...");
        }
        let result = run_layer3_local(&name, &dir);

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        } else {
            print_layer_result("Layer 3", &result, !cli.no_color, cli.verbose);
            println!();
        }

        std::process::exit(exit_code_for(&result.verdict));
    }

    // --full mode: full pipeline with aggregate risk report (requires Docker).
    // Accepts either an existing local directory (Layer 0 skipped — no
    // registry identity) or a package name (fetched from the npm registry,
    // all four layers run — the "unified single tool" path).
    if let Some(value) = cli.full {
        let report = if value.is_dir() {
            let name = value
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("local-package")
                .to_string();
            eprintln!(
                "Scanning local dir as full pipeline (L1+L2+L3, Docker): {} ({})",
                name,
                value.display()
            );
            if cli.verbose {
                eprintln!("[Layer 1] static analysis -> [Layer 2] dynamic (install+import, Docker) -> [Layer 3] condition mutation (clock/env/fuzz, Docker)");
            }
            run_full_local(&name, &value)
        } else {
            let name = value.to_string_lossy().to_string();
            eprintln!(
                "Scanning registry package as full pipeline (L0+L1+L2+L3, Docker): {}",
                name
            );
            if cli.verbose {
                eprintln!("[Layer 0] registry metadata -> [Layer 1] static analysis -> [Layer 2] dynamic (Docker) -> [Layer 3] condition mutation (Docker)");
            }
            run_full_registry(&name)
        };

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        } else {
            print_report(&report, !cli.no_color, cli.verbose);
            println!();
        }

        std::process::exit(exit_code_for(&report.verdict));
    }

    if cli.packages.is_empty() {
        eprintln!("Error: provide package name(s) or --local <dir> or --layer2 <dir> or --layer3 <dir> or --full <name|dir>");
        std::process::exit(1);
    }

    let top_packages = load_top_packages();
    let top_scoped = load_top_scoped_packages();

    // Third element: true iff Layer 1 was skipped specifically because Layer 0
    // was BLOCK (early-exit optimization) — distinct from "not run because the
    // package wasn't found on the registry", which is a genuine `NotRun`, not
    // a `Skipped`.
    let mut all_pairs: Vec<(CheckResult, Option<CheckResult>, bool)> = Vec::new();

    for pkg in &cli.packages {
        if cli.verbose {
            eprintln!("[Layer 0] Checking {} (metadata/registry checks)...", pkg);
        } else {
            eprintln!("Checking {} (Layer 0)...", pkg);
        }
        let l0 = run_layer0(pkg, &top_packages, &top_scoped);
        let l0_verdict = l0.verdict.clone();

        let mut l1_skipped_by_l0_block = false;
        let l1 = if l0_verdict == Verdict::Block {
            l1_skipped_by_l0_block = true;
            eprintln!("  → Layer 0 BLOCK — skipping Layer 1");
            None
        } else {
            if cli.verbose {
                eprintln!("[Layer 1] Checking {} (static analysis)...", pkg);
            } else {
                eprintln!("Checking {} (Layer 1)...", pkg);
            }
            match get_package_info(pkg) {
                None => {
                    eprintln!("  → Package not found on registry — skipping Layer 1");
                    None
                }
                Some(info) => Some(run_layer1(pkg, &info)),
            }
        };

        all_pairs.push((l0, l1, l1_skipped_by_l0_block));
    }

    let reports: Vec<RiskReport> = all_pairs
        .iter()
        .map(|(l0, l1, l1_skipped)| {
            let mut report = aggregate(&l0.package, [Some(l0), l1.as_ref(), None, None]);
            if *l1_skipped {
                report.mark_skipped(1);
            }
            report
        })
        .collect();

    if cli.json {
        let output = if reports.len() == 1 {
            serde_json::to_string_pretty(&reports[0]).unwrap_or_default()
        } else {
            serde_json::to_string_pretty(&reports).unwrap_or_default()
        };
        println!("{}", output);
    } else {
        for ((l0, l1, _), report) in all_pairs.iter().zip(reports.iter()) {
            print_layer_result("Layer 0", l0, !cli.no_color, cli.verbose);
            if let Some(l1r) = l1 {
                print_layer_result("Layer 1", l1r, !cli.no_color, cli.verbose);
            }
            print_report(report, !cli.no_color, cli.verbose);
        }
        println!();
    }

    // Roll up the worst verdict across all per-package reports (BLOCK>SUSPECT>ERROR>PASS).
    let final_worst = reports.iter().fold(Verdict::Pass, |acc, report| {
        match (&acc, &report.verdict) {
            (Verdict::Block, _) | (_, Verdict::Block) => Verdict::Block,
            (Verdict::Suspect, _) | (_, Verdict::Suspect) => Verdict::Suspect,
            (Verdict::Error, _) | (_, Verdict::Error) => Verdict::Error,
            _ => Verdict::Pass,
        }
    });

    std::process::exit(exit_code_for(&final_worst));
}
