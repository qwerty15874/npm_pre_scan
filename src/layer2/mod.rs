// Layer 2: Dynamic analysis (Docker-based).
//
// Architecture: the container captures RAW logs only; all parsing + classification
// lives in pure Rust functions (profile.rs, classify.rs) that are unit-testable
// offline with recorded log fixtures.
//
// When Docker is absent, returns Verdict::Error with a descriptive note — no panic.

pub mod classify;
pub mod profile;

use crate::models::{CheckResult, Finding, Verdict};
use serde_json::{Map, Value};
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
    if !docker_available() {
        return error_result(name, "Docker required for Layer 2 — install Docker to enable dynamic analysis");
    }

    let dockerfile_dir = match locate_docker_dir() {
        Some(d) => d,
        None => {
            return error_result(name, "docker/ directory not found — run from the project root");
        }
    };

    // Build the Layer 2 Docker image
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

    // Run the container: mount pkg read-only, out writable, no network
    // (dnsmasq inside the container handles DNS — loopback only)
    let run_status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
            "--cap-add=SYS_PTRACE",
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

    // Read raw logs from /out
    let read_log = |filename: &str| -> String {
        std::fs::read_to_string(out_dir.path().join(filename)).unwrap_or_default()
    };

    let strace_install = read_log("strace_install.log");
    let strace_import = read_log("strace_import.log");
    let dns_log = read_log("dns.log");

    // Parse logs into profiles
    let mut install_profile = profile::parse_strace("install", &strace_install);
    let mut import_profile = profile::parse_strace("import", &strace_import);

    // DNS queries are merged into both profiles (dnsmasq captures all phases)
    let dns_queries = profile::parse_dns(&dns_log);
    install_profile.dns_queries.extend(dns_queries.iter().cloned());
    import_profile.dns_queries.extend(dns_queries);

    // Classify both profiles
    let mut findings: Vec<Finding> = Vec::new();
    findings.extend(classify::classify(&install_profile));
    findings.extend(classify::classify(&import_profile));

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

// suppress unused-import warning for the no-Docker build
#[allow(dead_code)]
fn _use_finding() -> Finding {
    finding("INFO", "unused")
}
