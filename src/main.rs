use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use npm_pre_scan::models::Verdict;
use npm_pre_scan::registry::get_package_info;
use npm_pre_scan::toplist;
use npm_pre_scan::{
    aggregate, run_full_local, run_full_registry_with_lists, run_layer0, run_layer1,
    run_layer1_local, run_layer2_local, run_layer3_local, CheckResult, RiskReport,
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

    /// Batch-evaluate a ground-truth corpus manifest and write result data
    /// (records.jsonl, results.csv, findings.csv, metrics.json). Repeatable —
    /// several manifests share one output directory and one metrics summary.
    /// See eval/README.md for the manifest format and the corpus.
    ///
    /// Exit codes differ from a normal scan: 0=complete, 4=completed but
    /// degraded (an entry errored, timed out, or a layer failed), 5=could not
    /// run (bad manifest, unwritable output directory). Codes 0-3 stay reserved
    /// for per-package verdicts, which are meaningless for a corpus that
    /// deliberately contains known-malicious entries.
    #[arg(long, value_name = "MANIFEST")]
    eval: Vec<PathBuf>,

    /// Output directory for --eval artifacts. Defaults to
    /// `eval/runs/<timestamp>`. Existing files are appended to, so a resumed or
    /// second batch adds rows without repeating the CSV headers.
    #[arg(long, value_name = "DIR")]
    out_dir: Option<PathBuf>,

    /// Ceiling on --eval scan depth: name-only (Layer 0 name checks, offline and
    /// reproducible) | registry (L0+L1) | full (all four layers) | auto (honour
    /// each manifest entry exactly). Effective layers per entry are the
    /// manifest's `layers` column intersected with this ceiling.
    #[arg(long, value_name = "MODE", default_value = "auto")]
    eval_mode: String,

    /// Wall-clock budget in seconds for each `docker run`. Unset means
    /// unbounded, which is the pre-existing behaviour — but one package whose
    /// `npm install` hangs will then stall an entire batch. Applies to any mode
    /// that reaches Layer 2 or 3 (also settable via
    /// `NPM_PRE_SCAN_DOCKER_TIMEOUT`).
    #[arg(long, value_name = "SECS")]
    docker_timeout: Option<u64>,

    /// Keep full `evidence` arrays in records.jsonl. Off by default: Layer 2/3
    /// diffs can attach hundreds of events per finding, and the count alone
    /// (`evidence_count`) is what the metrics use.
    #[arg(long)]
    eval_evidence: bool,

    /// Live-refresh the Layer 0 typosquat/namespace comparison lists from
    /// the npm search API before scanning (union-merged with the embedded
    /// snapshot; embedded coverage is never lost). Results are cached on
    /// disk for 24h (see `NPM_PRE_SCAN_CACHE_DIR`); a fresh cache is reused
    /// silently, a failed or rejected fetch falls back to a stale cache or
    /// the embedded lists alone (never changes a verdict, prints one
    /// `note:` line to stderr when it falls back). Default off, to keep
    /// scans reproducible and `cargo test` network-free. Can also be
    /// enabled via `NPM_PRE_SCAN_REFRESH_TOP=1` (or `true`).
    #[arg(long)]
    refresh_top: bool,
}

/// `true` if `--refresh-top` was passed, or `NPM_PRE_SCAN_REFRESH_TOP` is
/// set to `1` or `true` (case-insensitive).
fn refresh_top_enabled(cli_flag: bool) -> bool {
    if cli_flag {
        return true;
    }
    match std::env::var("NPM_PRE_SCAN_REFRESH_TOP") {
        Ok(v) => {
            let v = v.trim().to_lowercase();
            v == "1" || v == "true"
        }
        Err(_) => false,
    }
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

/// Exit code for a batch that could not run at all (bad manifest, unwritable
/// output directory). Deliberately outside 0-3, which carry per-package verdict
/// meaning — a corpus containing known-malicious entries would always exit 2
/// under that mapping, which is useless in CI and actively misleading.
const EXIT_BATCH_UNRUNNABLE: i32 = 5;
/// Exit code for a batch that finished with degraded entries: results are usable
/// but incomplete.
const EXIT_BATCH_DEGRADED: i32 = 4;

/// `--eval` mode: batch-scan a corpus and write result data. Ends the process.
fn run_eval(cli: &Cli, refresh: bool) -> ! {
    use npm_pre_scan::eval::runner::{run_batch, EvalConfig, EvalMode};

    if !cli.packages.is_empty() {
        eprintln!(
            "Error: --eval takes its targets from the manifest(s); remove the positional package name(s)"
        );
        std::process::exit(EXIT_BATCH_UNRUNNABLE);
    }

    let mode = match EvalMode::parse(&cli.eval_mode) {
        Some(m) => m,
        None => {
            eprintln!(
                "Error: unknown --eval-mode '{}' (expected name-only, registry, full or auto)",
                cli.eval_mode
            );
            std::process::exit(EXIT_BATCH_UNRUNNABLE);
        }
    };

    // The layer modules read the budget from the environment rather than taking
    // it as a parameter, so that adding it did not change their signatures or
    // every existing call site. Setting it here makes `--docker-timeout` apply to
    // the whole batch.
    if let Some(secs) = cli.docker_timeout {
        std::env::set_var(npm_pre_scan::docker::DOCKER_TIMEOUT_ENV, secs.to_string());
    }

    let out_dir = cli.out_dir.clone().unwrap_or_else(|| {
        // A timestamped directory per run, so successive runs never silently
        // append to each other's data.
        PathBuf::from("eval/runs").join(
            chrono::Utc::now()
                .format("%Y%m%dT%H%M%SZ")
                .to_string(),
        )
    });

    let cfg = EvalConfig {
        manifests: cli.eval.clone(),
        out_dir: out_dir.clone(),
        mode,
        docker_timeout_secs: cli.docker_timeout.or_else(npm_pre_scan::docker::docker_timeout_from_env),
        keep_evidence: cli.eval_evidence,
        refresh_top: refresh,
        base_dir: PathBuf::from("."),
        samples_dir: PathBuf::from("eval/samples"),
        verbose: cli.verbose,
    };

    eprintln!(
        "Evaluating {} manifest(s) in mode '{}' → {}",
        cfg.manifests.len(),
        mode.as_str(),
        out_dir.display()
    );

    match run_batch(&cfg) {
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(EXIT_BATCH_UNRUNNABLE);
        }
        Ok(outcome) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&outcome.metrics).unwrap_or_default()
                );
            } else {
                let mut stdout = std::io::stdout();
                let _ = npm_pre_scan::eval::metrics::render_summary(&mut stdout, &outcome.metrics);
            }

            // Never let a bounded run look like a complete one.
            if outcome.filtered_out > 0 {
                eprintln!(
                    "note: {} manifest entr{} had no applicable layer under mode '{}' and produced no record",
                    outcome.filtered_out,
                    if outcome.filtered_out == 1 { "y" } else { "ies" },
                    mode.as_str()
                );
            }
            eprintln!("Wrote records.jsonl, results.csv, findings.csv, metrics.json to {}", out_dir.display());

            if outcome.degraded {
                eprintln!("note: some entries were degraded (registry failure, timeout, or a layer error) — see `outcomes` in metrics.json");
                std::process::exit(EXIT_BATCH_DEGRADED);
            }
            std::process::exit(0);
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let refresh = refresh_top_enabled(cli.refresh_top);

    // --eval mode comes first so the five single-target modes below, each of
    // which exits on a per-package verdict, are left untouched.
    if !cli.eval.is_empty() {
        run_eval(&cli, refresh);
    }

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
            let (top_packages, top_scoped) = toplist::load_effective_lists(refresh);
            run_full_registry_with_lists(&name, &top_packages, &top_scoped)
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

    let (top_packages, top_scoped) = toplist::load_effective_lists(refresh);

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
