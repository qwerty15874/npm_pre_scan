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

use crate::docker::docker_available;
use crate::layer2::profile::{self, Layer2Profile};
use crate::models::{CheckResult, Finding, Verdict};
use std::path::Path;

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
///
/// A missing/unreadable log is distinct from a present-but-empty one: an
/// empty log legitimately means "no events of that kind occurred" and is
/// parsed as such, but a missing file means the scenario never ran or its
/// output couldn't be captured — silently substituting "" would misreport a
/// failed scenario as a clean (empty-diff) one. Returns `Err` with the
/// missing filename in that case.
fn load_scenario_profile(out_dir: &Path, scenario: &str) -> Result<Layer2Profile, String> {
    let read_log = |filename: String| -> Result<String, String> {
        std::fs::read_to_string(out_dir.join(&filename))
            .map_err(|e| format!("missing or unreadable log {}: {}", filename, e))
    };

    let strace_log = read_log(format!("strace_{}.log", scenario))?;
    let dns_log = read_log(format!("dns_{}.log", scenario))?;

    let mut prof = profile::parse_strace("import", &strace_log);
    prof.dns_queries.extend(profile::parse_dns(&dns_log));
    Ok(prof)
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

    // Preflight (SYS_PTRACE probe) + build of the shared Layer 2/3 image, memoized
    // once per process by `docker::ensure_layer_image` (Layer 3 overrides the
    // entrypoint at run time). Same rationale as Layer 2: a missing SYS_PTRACE
    // capability makes strace silently produce empty logs, which would read as
    // "no behavior change across scenarios" instead of "capture failed", so only
    // a confirmed denial stops the run.
    let image_tag = "npm-pre-scan-layer2:latest";
    if let Err(note) = crate::docker::ensure_layer_image(&dockerfile_dir, image_tag) {
        return error_result(name, &note);
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
    // writable, no network (dnsmasq inside the container handles DNS). Named so a
    // wall-clock timeout can force-remove it — see `docker::run_docker`.
    let container_name = crate::docker::container_name("l3");
    let pkg_mount = format!("{}:/pkg:ro", pkg_abs.display());
    let out_mount = format!("{}:/out:rw", out_dir.path().display());
    let argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        &container_name,
        "--network=none",
        "--cap-add=SYS_PTRACE",
        "--entrypoint",
        "/run_layer3.sh",
        "-v",
        &pkg_mount,
        "-v",
        &out_mount,
        "-e",
        "PKG_DIR=/pkg",
        "-e",
        "OUT_DIR=/out",
        image_tag,
    ];

    if let Err(note) = crate::docker::run_docker(
        &argv,
        crate::docker::docker_timeout_from_env(),
        Some(&container_name),
    ) {
        return error_result(name, &note);
    }

    // Load baseline + mutated scenario profiles. Any missing/unreadable log
    // aborts with Verdict::Error rather than silently treating the scenario
    // as empty (which would read as "no risk found" instead of "capture failed").
    let baseline = match load_scenario_profile(out_dir.path(), "baseline") {
        Ok(p) => p,
        Err(e) => return error_result(name, &e),
    };
    let clock = match load_scenario_profile(out_dir.path(), "clock") {
        Ok(p) => p,
        Err(e) => return error_result(name, &e),
    };
    let env = match load_scenario_profile(out_dir.path(), "env") {
        Ok(p) => p,
        Err(e) => return error_result(name, &e),
    };
    let fuzz = match load_scenario_profile(out_dir.path(), "fuzz") {
        Ok(p) => p,
        Err(e) => return error_result(name, &e),
    };

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
    let verdict = crate::models::verdict_from_findings(&findings);

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
