// Layer 3: dynamic condition mutation (Docker-based).
//
// Architecture: same "dumb container, smart Rust" split as Layer 2. The
// container (docker/run_layer3.sh) runs the package's import step under a
// clean baseline plus three mutated scenarios (clock, env, fuzz), capturing
// raw strace/dnsmasq logs per scenario. All parsing reuses
// `crate::layer2::profile`; each mutated scenario's profile is diffed against
// its baseline with `layer3::diff::diff_profiles`, and the diff is classified
// with `layer3::classify::classify_scenario` (which itself reuses
// `crate::layer2::classify::classify`).
//
// When Docker is absent, returns Verdict::Error with a descriptive note — no panic.

pub mod classify;
pub mod diff;

use crate::layer2::profile::{self, Layer2Profile};
use crate::models::{CheckResult, Finding, Verdict};
use std::path::Path;
use std::process::Command;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn error_result(package_name: &str, note: &str) -> CheckResult {
    CheckResult {
        package: package_name.to_string(),
        verdict: Verdict::Error,
        score: 0,
        findings: vec![],
        note: Some(note.to_string()),
    }
}

/// Read a scenario's strace + dns logs from `out_dir` and parse them into a
/// `Layer2Profile` tagged `phase = "import"` (Layer 3 only mutates the
/// import/use phase, so the import-side-effect classifier rules apply).
fn load_scenario_profile(out_dir: &Path, scenario: &str) -> Layer2Profile {
    let read_log = |filename: String| -> String {
        std::fs::read_to_string(out_dir.join(filename)).unwrap_or_default()
    };

    let strace_log = read_log(format!("strace_{}.log", scenario));
    let dns_log = read_log(format!("dns_{}.log", scenario));

    let mut prof = profile::parse_strace("import", &strace_log);
    prof.dns_queries.extend(profile::parse_dns(&dns_log));
    prof
}

/// Run Layer 3 dynamic condition-mutation analysis on a local package directory.
///
/// Requires Docker. If Docker is not on PATH, returns `Verdict::Error` with a
/// "Docker required for Layer 3" note (graceful degradation — no panic).
///
/// Runs `docker/run_layer3.sh` inside the shared Layer 2/3 image (overriding
/// the entrypoint), which captures a clean baseline plus three mutated
/// scenarios (clock/D1, env/D2, fuzz/D3) in ONE container. Each mutated
/// scenario's profile is diffed against its baseline and classified; Findings
/// are tagged `layer: 3` + `scenario` by `classify::classify_scenario`.
pub fn run_layer3_local(name: &str, dir: &Path) -> CheckResult {
    if !docker_available() {
        return error_result(name, "Docker required for Layer 3 — install Docker to enable dynamic analysis");
    }

    let dockerfile_dir = match locate_docker_dir() {
        Some(d) => d,
        None => {
            return error_result(name, "docker/ directory not found — run from the project root");
        }
    };

    // Build the shared Layer 2/3 image (Layer 3 overrides the entrypoint at run time).
    let image_tag = "npm-pre-scan-layer2:latest";
    let build_status = Command::new("docker")
        .args(["build", "-t", image_tag, &dockerfile_dir])
        .status();

    match build_status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            return error_result(name, &format!("Docker build failed (exit {})", s));
        }
        Err(e) => {
            return error_result(name, &format!("Docker build error: {}", e));
        }
    }

    // Create a temp dir for output
    let out_dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(e) => return error_result(name, &format!("Failed to create output tempdir: {}", e)),
    };

    let pkg_abs = match dir.canonicalize() {
        Ok(p) => p,
        Err(e) => return error_result(name, &format!("Cannot resolve package path: {}", e)),
    };

    // Run the container with the Layer 3 entrypoint: mount pkg read-only, out
    // writable, no network (dnsmasq inside the container handles DNS).
    let run_status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "--cap-add=SYS_PTRACE",
            "--entrypoint",
            "/run_layer3.sh",
            "-v",
            &format!("{}:/pkg:ro", pkg_abs.display()),
            "-v",
            &format!("{}:/out:rw", out_dir.path().display()),
            "-e",
            "PKG_DIR=/pkg",
            "-e",
            "OUT_DIR=/out",
            image_tag,
        ])
        .status();

    match run_status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            return error_result(name, &format!("Docker run failed (exit {})", s));
        }
        Err(e) => {
            return error_result(name, &format!("Docker run error: {}", e));
        }
    }

    // Load baseline + mutated scenario profiles.
    let baseline = load_scenario_profile(out_dir.path(), "baseline");
    let clock = load_scenario_profile(out_dir.path(), "clock");
    let env = load_scenario_profile(out_dir.path(), "env");
    let fuzz = load_scenario_profile(out_dir.path(), "fuzz");

    // Diff each mutated scenario against its matching baseline, then classify.
    let mut findings: Vec<Finding> = Vec::new();
    findings.extend(classify::classify_scenario(
        "D1",
        &diff::diff_profiles(&baseline, &clock),
    ));
    findings.extend(classify::classify_scenario(
        "D2",
        &diff::diff_profiles(&baseline, &env),
    ));
    // D3 diffs the fuzz run against the PLAIN-require baseline: plain require
    // leaves an API-gated payload dormant, whereas the fuzz harness calls the
    // export and fires it. The diff isolates exactly the trigger-on-use
    // behavior. (Merely invoking a benign function trips no classify rule, so
    // there is nothing for a "clean harness" baseline to cancel.)
    findings.extend(classify::classify_scenario(
        "D3",
        &diff::diff_profiles(&baseline, &fuzz),
    ));

    // Derive verdict from findings
    let verdict = if findings
        .iter()
        .any(|f| f.get("severity").and_then(|v| v.as_str()) == Some("BLOCK"))
    {
        Verdict::Block
    } else if findings
        .iter()
        .any(|f| f.get("severity").and_then(|v| v.as_str()) == Some("SUSPECT"))
    {
        Verdict::Suspect
    } else {
        Verdict::Pass
    };

    let score = crate::models::score_findings(&findings);
    CheckResult {
        package: name.to_string(),
        verdict,
        score,
        findings,
        note: None,
    }
}

/// Locate the `docker/` directory relative to the project root.
/// Searches from the current working directory upward (up to 4 levels).
fn locate_docker_dir() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    for ancestor in cwd.ancestors().take(4) {
        let candidate = ancestor.join("docker");
        if candidate.is_dir() && candidate.join("Dockerfile").exists() {
            return Some(candidate.display().to_string());
        }
    }
    None
}
