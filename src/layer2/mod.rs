// Layer 2: Dynamic analysis (Docker-based).
//
// Architecture: the container captures RAW logs only; all parsing + classification
// lives in pure Rust functions (profile.rs, classify.rs) that are unit-testable
// offline with recorded log fixtures.
//
// Baseline subtraction: to cancel npm/node's own toolchain reads (.npmrc,
// /etc/passwd) at the source, the container traces each phase (install,
// import) TWICE — an unmutated "baseline" run and the "real" run — and this
// module diffs real-vs-baseline (reusing Layer 3's `diff_profiles_phase`)
// before classifying. Only package-attributable behavior survives the diff.
//
// When Docker is absent, returns Verdict::Error with a descriptive note — no panic.

pub mod classify;
pub mod profile;

use crate::docker::docker_available;
use crate::layer3::diff::{diff_profiles_phase, evidence_lines};
use crate::models::{CheckResult, Finding, Verdict};
use profile::Layer2Profile;
use serde_json::{Map, Value};
use std::collections::HashSet;
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

/// Build a minimal Finding (used for the no-Docker path).
fn finding(severity: &str, message: &str) -> Finding {
    let mut m = Map::new();
    m.insert("check".into(), Value::String("layer2_dynamic".into()));
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("message".into(), Value::String(message.to_string()));
    m
}

/// Run Layer 2 dynamic analysis on a local package directory.
///
/// Requires Docker. If Docker is not on PATH, returns `Verdict::Error` with a
/// "Docker required for Layer 2" note (graceful degradation — no panic).
///
/// Otherwise builds the monitoring image from `docker/Dockerfile`, mounts `dir`
/// as `/pkg` (read-only) and a temp dir as `/out`, runs the container, reads
/// the raw strace + dns logs from `/out`, parses them into a `Layer2Profile`
/// via `profile::parse_strace`/`parse_dns`, classifies them into `Vec<Finding>`
/// via `classify::classify`, and derives a verdict.
pub fn run_layer2_local(name: &str, dir: &Path) -> CheckResult {
    run_layer2_vendored(name, dir, None)
}

/// Layer 2, with dependencies optionally vendored in from the host.
///
/// `vendor` points at a host directory containing a resolved `node_modules`;
/// the container copies it into the work tree before each install so both the
/// baseline and the real run see a byte-identical tree (see
/// `docker/run_layer2.sh`'s install-symmetry invariant).
pub fn run_layer2_vendored(name: &str, dir: &Path, vendor: Option<&Path>) -> CheckResult {
    if !docker_available() {
        return error_result(name, "Docker required for Layer 2 — install Docker to enable dynamic analysis");
    }

    let dockerfile_dir = match locate_docker_dir() {
        Some(d) => d,
        None => {
            return error_result(name, "docker/ directory not found — run from the project root");
        }
    };

    // Preflight (SYS_PTRACE probe) + image build, memoized once per process by
    // `docker::ensure_layer_image`. A missing SYS_PTRACE capability makes strace
    // silently produce empty logs inside the container (a known past failure
    // mode — see CLAUDE.md v10), which downstream would misread as "clean", so
    // only a confirmed *denial* stops the run; an inconclusive probe proceeds.
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

    // Run the container: mount pkg read-only, out writable, no network
    // (dnsmasq inside the container handles DNS — loopback only).
    //
    // The container is named so that a wall-clock timeout (see
    // `NPM_PRE_SCAN_DOCKER_TIMEOUT`) can force-remove it: signalling the attached
    // `docker run` client does not reliably stop the container it started.
    let container_name = crate::docker::container_name("l2");
    let pkg_mount = format!("{}:/pkg:ro", pkg_abs.display());
    let out_mount = format!("{}:/out:rw", out_dir.path().display());
    // Dependencies resolved on the host, mounted read-only. Without this the
    // container's `npm install --offline` under `--network=none` cannot fetch
    // anything, `require()` throws MODULE_NOT_FOUND, both are swallowed by
    // `|| true`, and the layer reports an empty profile indistinguishable from
    // a clean package — which is why the dynamic layers could only ever analyse
    // dependency-free packages.
    let vendor_mount = vendor.map(|v| format!("{}:/vendor:ro", v.display()));
    let mut argv: Vec<&str> = vec![
        "docker",
        "run",
        "--rm",
        "--name",
        &container_name,
        "--network=none",
        "--cap-add=SYS_PTRACE",
        "-v",
        &pkg_mount,
        "-v",
        &out_mount,
    ];
    if let Some(m) = vendor_mount.as_deref() {
        argv.extend(["-v", m, "-e", "VENDOR_DIR=/vendor"]);
    }
    argv.extend([
        "-e",
        "PKG_DIR=/pkg",
        "-e",
        "OUT_DIR=/out",
        image_tag,
    ]);

    if let Err(note) = crate::docker::run_docker(
        &argv,
        crate::docker::effective_docker_timeout(),
        Some(&container_name),
    ) {
        return error_result(name, &note);
    }

    // Read raw logs from /out. A missing/unreadable log is NOT the same as a
    // present-but-empty one: an empty log legitimately means "no events of
    // that kind occurred" and is parsed as such, but a missing file means the
    // container's capture step never ran or the host couldn't read it — in
    // that case, silently substituting "" would misreport a failed capture as
    // a clean scan. Surface it as Verdict::Error instead.
    let read_log = |filename: &str| -> Result<String, String> {
        std::fs::read_to_string(out_dir.path().join(filename))
            .map_err(|e| format!("missing or unreadable log {}: {}", filename, e))
    };

    // Load a run's (strace, dns) log pair into a `Layer2Profile` tagged with
    // `phase`. Each of the 4 runs (install_base, install_real, import_base,
    // import_real) gets its OWN dns log — the container restarts dnsmasq per
    // run so DNS queries don't bleed across runs.
    let load_run = |phase: &str, run: &str| -> Result<Layer2Profile, String> {
        let strace_log = read_log(&format!("strace_{}.log", run))?;
        let dns_log = read_log(&format!("dns_{}.log", run))?;
        let mut prof = profile::parse_strace(phase, &strace_log);
        prof.dns_queries.extend(profile::parse_dns(&dns_log));
        Ok(prof)
    };

    let install_base = match load_run("install", "install_base") {
        Ok(p) => p,
        Err(e) => return error_result(name, &e),
    };
    let install_real = match load_run("install", "install_real") {
        Ok(p) => p,
        Err(e) => return error_result(name, &e),
    };
    let import_base = match load_run("import", "import_base") {
        Ok(p) => p,
        Err(e) => return error_result(name, &e),
    };
    let import_real = match load_run("import", "import_real") {
        Ok(p) => p,
        Err(e) => return error_result(name, &e),
    };

    // Diff real-vs-baseline per phase (reusing Layer 3's diff engine): npm's
    // own `.npmrc`/`/etc/passwd` reads and registry DNS occur identically in
    // both baseline and real runs, so they cancel out here. Only the
    // package's own postinstall/import behavior survives into the diff.
    let install_diff = diff_profiles_phase(&install_base, &install_real, "install");
    let import_diff = diff_profiles_phase(&import_base, &import_real, "import");

    // Classify each diff (not the raw profiles) — ordinary file opens that
    // survive the diff (e.g. the package's own index.js, module-resolver
    // stats) produce no findings since `classify` only flags sensitive paths,
    // `.node` files, network activity, or unexpected processes.
    let mut findings: Vec<Finding> = Vec::new();
    findings.extend(attach_evidence(classify::classify(&install_diff), &install_diff));
    findings.extend(attach_evidence(classify::classify(&import_diff), &import_diff));
    dedup_findings(&mut findings);

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

/// Stamp every Finding in `findings` with an `"evidence"` array listing the
/// exact new events (`dns:...`, `connect:ip:port`, `proc:...`, `file:...`)
/// from the diff `Layer2Profile` that produced them (see
/// `layer3::diff::evidence_lines`). Visibility only — not read back into
/// classification or scoring. Always present in the JSON report; human
/// output renders it under `--verbose`.
fn attach_evidence(mut findings: Vec<Finding>, diff: &Layer2Profile) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }
    let evidence = evidence_lines(diff);
    for f in &mut findings {
        f.insert(
            "evidence".to_string(),
            Value::Array(evidence.iter().cloned().map(Value::String).collect()),
        );
    }
    findings
}

/// Remove duplicate findings, keyed by `(check, vector, destination|path|message)`.
/// The install and import diffs can independently surface the same underlying
/// event (e.g. a worm-egress DNS query logged in both phases' dns files), so
/// dedup before returning. Preserves first-seen order.
fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    findings.retain(|f| {
        let check = f.get("check").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let vector = f.get("vector").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let key3 = f
            .get("destination")
            .or_else(|| f.get("path"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| f.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string());
        seen.insert((check, vector, key3))
    });
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

// suppress unused-import warning for the no-Docker build
#[allow(dead_code)]
fn _use_finding() -> Finding {
    finding("INFO", "unused")
}
