use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use npm_pre_scan::models::Verdict;
use npm_pre_scan::namespace::load_top_scoped_packages;
use npm_pre_scan::registry::get_package_info;
use npm_pre_scan::typosquat::load_top_packages;
use npm_pre_scan::{
    aggregate, run_full_local, run_layer0, run_layer1, run_layer1_local, run_layer2_local,
    run_layer3_local, CheckResult, RiskReport,
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

    /// Full pipeline (L1+L2+L3) on a local dir with aggregate risk report; requires Docker
    #[arg(long, value_name = "DIR")]
    full: Option<PathBuf>,

    /// Output raw JSON
    #[arg(long)]
    json: bool,

    /// Disable color output
    #[arg(long)]
    no_color: bool,
}

fn print_layer_result(layer: &str, result: &CheckResult, use_color: bool) {
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
        }
    }
}

fn print_report(report: &RiskReport, use_color: bool) {
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
        let result = run_layer1_local(&name, &dir);

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        } else {
            print_layer_result("Layer 1", &result, !cli.no_color);
            println!();
        }

        let code = match result.verdict {
            Verdict::Pass => 0,
            Verdict::Suspect => 1,
            Verdict::Block => 2,
            Verdict::Error => 3,
        };
        std::process::exit(code);
    }

    // --layer2 mode: Layer 2 dynamic analysis on a local directory (requires Docker)
    if let Some(dir) = cli.layer2 {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("local-package")
            .to_string();
        eprintln!("Scanning local dir as Layer 2 (Docker): {} ({})", name, dir.display());
        let result = run_layer2_local(&name, &dir);

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        } else {
            print_layer_result("Layer 2", &result, !cli.no_color);
            println!();
        }

        let code = match result.verdict {
            Verdict::Pass => 0,
            Verdict::Suspect => 1,
            Verdict::Block => 2,
            Verdict::Error => 3,
        };
        std::process::exit(code);
    }

    // --layer3 mode: Layer 3 condition-mutation analysis on a local directory (requires Docker)
    if let Some(dir) = cli.layer3 {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("local-package")
            .to_string();
        eprintln!("Scanning local dir as Layer 3 (Docker): {} ({})", name, dir.display());
        let result = run_layer3_local(&name, &dir);

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        } else {
            print_layer_result("Layer 3", &result, !cli.no_color);
            println!();
        }

        let code = match result.verdict {
            Verdict::Pass => 0,
            Verdict::Suspect => 1,
            Verdict::Block => 2,
            Verdict::Error => 3,
        };
        std::process::exit(code);
    }

    // --full mode: full pipeline (L1+L2+L3) on a local directory with aggregate risk report (requires Docker)
    if let Some(dir) = cli.full {
        let name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("local-package")
            .to_string();
        eprintln!("Scanning local dir as full pipeline (L1+L2+L3, Docker): {} ({})", name, dir.display());
        let report = run_full_local(&name, &dir);

        if cli.json {
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
        } else {
            print_report(&report, !cli.no_color);
            println!();
        }

        std::process::exit(exit_code_for(&report.verdict));
    }

    if cli.packages.is_empty() {
        eprintln!("Error: provide package name(s) or --local <dir> or --layer2 <dir> or --layer3 <dir> or --full <dir>");
        std::process::exit(1);
    }

    let top_packages = load_top_packages();
    let top_scoped = load_top_scoped_packages();

    let mut all_pairs: Vec<(CheckResult, Option<CheckResult>)> = Vec::new();

    for pkg in &cli.packages {
        eprintln!("Checking {} (Layer 0)...", pkg);
        let l0 = run_layer0(pkg, &top_packages, &top_scoped);
        let l0_verdict = l0.verdict.clone();

        let l1 = if l0_verdict == Verdict::Block {
            eprintln!("  → Layer 0 BLOCK — skipping Layer 1");
            None
        } else {
            eprintln!("Checking {} (Layer 1)...", pkg);
            match get_package_info(pkg) {
                None => {
                    eprintln!("  → Package not found on registry — skipping Layer 1");
                    None
                }
                Some(info) => Some(run_layer1(pkg, &info)),
            }
        };

        all_pairs.push((l0, l1));
    }

    let reports: Vec<RiskReport> = all_pairs
        .iter()
        .map(|(l0, l1)| aggregate(&l0.package, [Some(l0), l1.as_ref(), None, None]))
        .collect();

    if cli.json {
        let output = if reports.len() == 1 {
            serde_json::to_string_pretty(&reports[0]).unwrap_or_default()
        } else {
            serde_json::to_string_pretty(&reports).unwrap_or_default()
        };
        println!("{}", output);
    } else {
        for ((l0, l1), report) in all_pairs.iter().zip(reports.iter()) {
            print_layer_result("Layer 0", l0, !cli.no_color);
            if let Some(l1r) = l1 {
                print_layer_result("Layer 1", l1r, !cli.no_color);
            }
            print_report(report, !cli.no_color);
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
