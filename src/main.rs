use clap::Parser;
use colored::Colorize;

use npm_pre_scan::models::Verdict;
use npm_pre_scan::namespace::load_top_scoped_packages;
use npm_pre_scan::typosquat::load_top_packages;
use npm_pre_scan::CheckResult;

#[derive(Parser, Debug)]
#[command(name = "npm-pre-scan", about = "npm pre-scan Layer 0 checker")]
struct Cli {
    /// npm package name(s) to check
    #[arg(required = true)]
    packages: Vec<String>,

    /// Output raw JSON
    #[arg(long)]
    json: bool,

    /// Disable color output
    #[arg(long)]
    no_color: bool,
}

fn print_result(result: &CheckResult, use_color: bool) {
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
    println!("Package : {}", result.package);
    println!("Verdict : {}", colored_verdict);

    if let Some(note) = &result.note {
        println!("Note    : {}", note);
    }

    if result.findings.is_empty() {
        println!("Findings: none");
    } else {
        println!("Findings: {}", result.findings.len());
        for f in &result.findings {
            let sev = f
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let check = f
                .get("check")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let message = f
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");

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

fn main() {
    let cli = Cli::parse();

    // Load data files once, reuse across all packages
    let top_packages = load_top_packages();
    let top_scoped = load_top_scoped_packages();

    let mut results: Vec<CheckResult> = Vec::new();
    for pkg in &cli.packages {
        eprintln!("Checking {}...", pkg);
        let result = npm_pre_scan::run_layer0(pkg, &top_packages, &top_scoped);
        results.push(result);
    }

    if cli.json {
        let output = if results.len() == 1 {
            serde_json::to_string_pretty(&results[0]).unwrap_or_default()
        } else {
            serde_json::to_string_pretty(&results).unwrap_or_default()
        };
        println!("{}", output);
    } else {
        for r in &results {
            print_result(r, !cli.no_color);
        }
        println!();
    }

    // Exit code: 0=all PASS, 1=any SUSPECT (no BLOCK), 2=any BLOCK
    let mut worst = Verdict::Pass;
    for r in &results {
        match r.verdict {
            Verdict::Block => {
                worst = Verdict::Block;
                break;
            }
            Verdict::Suspect => {
                worst = Verdict::Suspect;
            }
            _ => {}
        }
    }

    let code = match worst {
        Verdict::Pass => 0,
        Verdict::Suspect => 1,
        Verdict::Block => 2,
        Verdict::Error => 3,
    };
    std::process::exit(code);
}
