use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use npm_pre_scan::models::Verdict;
use npm_pre_scan::namespace::load_top_scoped_packages;
use npm_pre_scan::registry::get_package_info;
use npm_pre_scan::typosquat::load_top_packages;
use npm_pre_scan::{run_layer0, run_layer1, run_layer1_local, CheckResult};

#[derive(Parser, Debug)]
#[command(name = "npm-pre-scan", about = "npm supply-chain pre-scan (Layer 0 + 1)")]
struct Cli {
    /// npm package name(s) to check (skip when using --local)
    packages: Vec<String>,

    /// Analyze a local package directory with Layer 1 only (no registry checks)
    #[arg(long, value_name = "DIR")]
    local: Option<PathBuf>,

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

fn worst_verdict(results: &[&CheckResult]) -> Verdict {
    let mut worst = Verdict::Pass;
    for r in results {
        match r.verdict {
            Verdict::Block => return Verdict::Block,
            Verdict::Suspect => worst = Verdict::Suspect,
            Verdict::Error if worst == Verdict::Pass => worst = Verdict::Error,
            _ => {}
        }
    }
    worst
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

    if cli.packages.is_empty() {
        eprintln!("Error: provide package name(s) or --local <dir>");
        std::process::exit(1);
    }

    let top_packages = load_top_packages();
    let top_scoped = load_top_scoped_packages();

    let mut all_verdicts: Vec<Verdict> = Vec::new();
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

    if cli.json {
        // Emit array of {layer0, layer1} objects
        let out: Vec<serde_json::Value> = all_pairs
            .iter()
            .map(|(l0, l1)| {
                let mut obj = serde_json::Map::new();
                obj.insert("layer0".into(), serde_json::to_value(l0).unwrap_or_default());
                if let Some(l1r) = l1 {
                    obj.insert("layer1".into(), serde_json::to_value(l1r).unwrap_or_default());
                }
                serde_json::Value::Object(obj)
            })
            .collect();
        let output = if out.len() == 1 {
            serde_json::to_string_pretty(&out[0]).unwrap_or_default()
        } else {
            serde_json::to_string_pretty(&out).unwrap_or_default()
        };
        println!("{}", output);
    } else {
        for (l0, l1) in &all_pairs {
            print_layer_result("Layer 0", l0, !cli.no_color);
            if let Some(l1r) = l1 {
                print_layer_result("Layer 1", l1r, !cli.no_color);
            }
        }
        println!();
    }

    for (l0, l1) in &all_pairs {
        let refs: Vec<&CheckResult> = std::iter::once(l0)
            .chain(l1.as_ref())
            .collect();
        all_verdicts.push(worst_verdict(&refs));
    }

    let final_worst = all_verdicts.iter().fold(Verdict::Pass, |acc, v| {
        match (acc, v) {
            (Verdict::Block, _) | (_, Verdict::Block) => Verdict::Block,
            (Verdict::Suspect, _) | (_, Verdict::Suspect) => Verdict::Suspect,
            (Verdict::Error, _) | (_, Verdict::Error) => Verdict::Error,
            _ => Verdict::Pass,
        }
    });

    let code = match final_worst {
        Verdict::Pass => 0,
        Verdict::Suspect => 1,
        Verdict::Block => 2,
        Verdict::Error => 3,
    };
    std::process::exit(code);
}
