// Layer 2: Dynamic analysis stub (Docker-based).
//
// Scaffolds worm-egress monitoring via Docker. Full dummy-package verification
// under Docker is deferred (noted as known limitation in CLAUDE.md).
//
// When Docker is absent, returns Verdict::Error with a descriptive note — no panic.

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
/// "Docker required for Layer 2" note (graceful stub — no panic).
///
/// Otherwise builds the monitoring image from `docker/Dockerfile`, mounts `dir`
/// as `/pkg` (read-only) and a temp dir as `/out`, runs the container, reads
/// `/out/layer2.json`, and maps worm-egress events to Findings.
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
    let run_status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network=none",
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

    // Read the output JSON
    let out_json_path = out_dir.path().join("layer2.json");
    let out_json: Value = match std::fs::read_to_string(&out_json_path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or(Value::Null),
        Err(e) => {
            return error_result(name, &format!("Failed to read layer2.json: {}", e));
        }
    };

    // Map egress events to findings
    let mut findings: Vec<Finding> = Vec::new();
    if let Some(events) = out_json.get("events").and_then(|v| v.as_array()) {
        for event in events {
            let severity = event
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("SUSPECT");
            let message = event
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown dynamic event");
            findings.push(finding(severity, message));
        }
    }

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
/// Searches from the current working directory upward (up to 3 levels).
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
