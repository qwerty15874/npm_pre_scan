mod checks;
mod tarball;

use crate::models::{CheckResult, Finding, Verdict};
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

/// Run Layer 1 static analysis on an npm package from the registry.
pub fn run_layer1(package_name: &str, info: &Value) -> CheckResult {
    let pkg_json = tarball::get_latest_version_pkg_json(info).unwrap_or(Value::Null);

    let tarball_url = match tarball::get_tarball_url(info) {
        Some(url) => url,
        None => {
            return CheckResult {
                package: package_name.to_string(),
                verdict: Verdict::Error,
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
                findings: vec![],
                note: Some(format!("Tarball download/extraction failed: {}", e)),
            };
        }
    };

    run_on_dir(package_name, &pkg_json, tmp.path())
}

/// Run Layer 1 static analysis on a local package directory (for testing dummy packages).
pub fn run_layer1_local(package_name: &str, dir: &Path) -> CheckResult {
    let pkg_json_path = dir.join("package.json");
    let pkg_json: Value = std::fs::read_to_string(&pkg_json_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);

    run_on_dir(package_name, &pkg_json, dir)
}

fn run_on_dir(package_name: &str, pkg_json: &Value, dir: &Path) -> CheckResult {
    let mut findings: Vec<Finding> = Vec::new();

    findings.extend(checks::check_install_scripts(pkg_json));
    findings.extend(checks::check_obfuscation(dir));
    findings.extend(checks::check_suspicious_strings(dir));
    findings.extend(checks::check_network_imports(dir));
    findings.extend(checks::check_dynamic_require(dir));

    let verdict = aggregate_verdict(&findings);
    CheckResult {
        package: package_name.to_string(),
        verdict,
        findings,
        note: None,
    }
}
