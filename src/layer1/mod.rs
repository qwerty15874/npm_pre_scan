mod checks;
mod tarball;
mod version_diff;

use crate::models::{score_findings, CheckResult, Finding, Verdict};
use std::collections::HashMap;
use serde_json::Value;
use std::path::Path;

fn aggregate_verdict(findings: &[Finding]) -> Verdict {
    for f in findings {
        if f.get("severity").and_then(|v| v.as_str()) == Some("BLOCK") {
            return Verdict::Block;
        }
    }
    for f in findings {
        if f.get("severity").and_then(|v| v.as_str()) == Some("SUSPECT") {
            return Verdict::Suspect;
        }
    }
    Verdict::Pass
}

fn build_result(package_name: &str, findings: Vec<Finding>) -> CheckResult {
    let verdict = aggregate_verdict(&findings);
    let score = score_findings(&findings);
    CheckResult {
        package: package_name.to_string(),
        verdict,
        score,
        findings,
        note: None,
    }
}

fn collect_dir_findings(pkg_json: &Value, dir: &Path) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    findings.extend(checks::check_install_scripts(pkg_json));
    findings.extend(checks::check_obfuscation(dir));
    findings.extend(checks::check_suspicious_strings(dir));
    findings.extend(checks::check_network_imports(dir));
    findings.extend(checks::check_dynamic_require(dir));
    findings
}

/// Run Layer 1 static analysis on an npm package from the registry.
pub fn run_layer1(package_name: &str, info: &Value) -> CheckResult {
    let pkg_json = tarball::get_latest_version_pkg_json(info).unwrap_or(Value::Null);

    let tarball_url = match tarball::get_tarball_url(info) {
        Some(url) => url,
        None => {
            return CheckResult {
                package: package_name.to_string(),
                verdict: Verdict::Error,
                score: 0,
                findings: vec![],
                note: Some("Could not determine tarball URL from registry metadata".to_string()),
            };
        }
    };

    let tmp = match tarball::download_and_extract(&tarball_url) {
        Ok(t) => t,
        Err(e) => {
            return CheckResult {
                package: package_name.to_string(),
                verdict: Verdict::Error,
                score: 0,
                findings: vec![],
                note: Some(format!("Tarball download/extraction failed: {}", e)),
            };
        }
    };

    let mut findings = collect_dir_findings(&pkg_json, tmp.path());
    findings.extend(version_diff::check_version_diff(info));
    build_result(package_name, findings)
}

/// Run the B3 version-diff check against two local directories (prev and latest).
/// Used by integration tests to verify the malicious-update detection without network access.
pub fn run_version_diff_local(prev_dir: &Path, latest_dir: &Path) -> Vec<Finding> {
    let prev_files: HashMap<String, String> = version_diff::js_contents(prev_dir);
    let latest_files: HashMap<String, String> = version_diff::js_contents(latest_dir);
    version_diff::diff_findings(&prev_files, &latest_files, "prev", "latest")
}

/// Run Layer 1 static analysis on a local package directory (for testing dummy packages).
/// Version-diff is skipped — no registry version history is available locally.
pub fn run_layer1_local(package_name: &str, dir: &Path) -> CheckResult {
    let pkg_json_path = dir.join("package.json");
    let pkg_json: Value = std::fs::read_to_string(&pkg_json_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);

    let findings = collect_dir_findings(&pkg_json, dir);
    build_result(package_name, findings)
}
