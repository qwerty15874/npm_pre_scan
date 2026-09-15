mod checks;
pub mod tarball;
mod version_diff;
mod worm_signature;

use crate::models::{score_findings, CheckResult, Finding, Verdict};
use std::collections::HashMap;
use serde_json::Value;
use std::path::Path;


fn build_result(package_name: &str, findings: Vec<Finding>) -> CheckResult {
    let verdict = crate::models::verdict_from_findings(&findings);
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
    findings.extend(checks::check_computed_load(dir));
    findings.extend(checks::check_capability_notes(dir));
    findings.extend(worm_signature::check_worm_signature(pkg_json, dir));
    findings
}

/// Run Layer 1 static analysis on an already-extracted package directory.
///
/// Shared by `run_layer1` (registry path: downloads first, then calls this)
/// and `report::run_full_registry` (which downloads once and reuses the same
/// extracted dir for Layer 1/2/3, avoiding a second download).
///
/// `pkg_json` is read from the registry `info` when available (the exact
/// published `package.json` for the latest version); otherwise falls back to
/// `dir/package.json` on disk. When `info` is `Some`, `version_diff::check_version_diff`
/// runs too (registry version history is available); when `None`, it is skipped
/// (mirrors `run_layer1_local`'s existing no-history behavior).
pub fn run_layer1_extracted(name: &str, dir: &Path, info: Option<&Value>) -> CheckResult {
    let pkg_json = match info.and_then(tarball::get_latest_version_pkg_json) {
        Some(v) => v,
        None => {
            let pkg_json_path = dir.join("package.json");
            std::fs::read_to_string(&pkg_json_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(Value::Null)
        }
    };

    let mut findings = collect_dir_findings(&pkg_json, dir);
    if let Some(info) = info {
        findings.extend(version_diff::check_version_diff(info));
    }
    build_result(name, findings)
}

/// Run Layer 1 static analysis on an npm package from the registry.
pub fn run_layer1(package_name: &str, info: &Value) -> CheckResult {
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

    run_layer1_extracted(package_name, tmp.path(), Some(info))
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
    run_layer1_local_inner(package_name, dir, None)
}

/// Run Layer 1 on `latest_dir`, additionally diffing it against `prev_dir` so
/// B3 (`version_diff`) has a path that needs no registry history.
///
/// `run_layer1_local` cannot do this — a lone directory carries no predecessor —
/// which is why B3 measured 0/1 in arms B, C and E despite the rule working and
/// a prev/latest fixture pair sitting in `dummy_packages/`. Its recall was
/// unmeasured, not zero.
pub fn run_layer1_local_paired(
    package_name: &str,
    prev_dir: &Path,
    latest_dir: &Path,
) -> CheckResult {
    run_layer1_local_inner(package_name, latest_dir, Some(prev_dir))
}

fn run_layer1_local_inner(package_name: &str, dir: &Path, prev_dir: Option<&Path>) -> CheckResult {
    let pkg_json_path = dir.join("package.json");
    let pkg_json: Value = std::fs::read_to_string(&pkg_json_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);

    let mut findings = collect_dir_findings(&pkg_json, dir);
    if let Some(prev) = prev_dir {
        findings.extend(run_version_diff_local(prev, dir));
    }
    build_result(package_name, findings)
}
