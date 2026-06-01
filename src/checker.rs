use serde_json::{Map, Value};

use crate::age_check::check_age_and_downloads;
use crate::maintainer::check_maintainer_change;
use crate::models::{score_findings, CheckResult, Finding, Verdict};
use crate::namespace::check_namespace_conflict;
use crate::registry::get_package_info;
use crate::typosquat::check_typosquat;

/// Aggregate a verdict from all findings.
/// BLOCK if any finding has severity BLOCK; SUSPECT if any SUSPECT (no BLOCK); else PASS.
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

/// Inject the `check` key into a raw finding map and push it onto findings.
fn push_finding(findings: &mut Vec<Finding>, check_name: &str, mut raw: Map<String, Value>) {
    raw.insert("check".into(), Value::String(check_name.to_string()));
    findings.push(raw);
}

/// Run all Layer 0 metadata checks for a single package name.
pub fn run_layer0(
    package_name: &str,
    top_packages: &[String],
    top_scoped: &[String],
) -> CheckResult {
    let mut findings: Vec<Finding> = Vec::new();

    // Check 1: Typosquatting
    if let Some(raw) = check_typosquat(package_name, top_packages) {
        push_finding(&mut findings, "typosquat", raw);
    }

    // Check 2: Namespace conflict
    if let Some(raw) = check_namespace_conflict(package_name, top_scoped) {
        push_finding(&mut findings, "namespace", raw);
    }

    // Fetch registry metadata for remaining checks
    let info = match get_package_info(package_name) {
        None => {
            let verdict = aggregate_verdict(&findings);
            let score = score_findings(&findings);
            return CheckResult {
                package: package_name.to_string(),
                verdict,
                score,
                findings,
                note: Some(
                    "Package not found on npm registry; registry-based checks skipped".to_string(),
                ),
            };
        }
        Some(v) => v,
    };

    // Check 3: Age + download spike
    if let Some(raw) = check_age_and_downloads(package_name, &info) {
        push_finding(&mut findings, "age_downloads", raw);
    }

    // Check 4: Maintainer change
    if let Some(raw) = check_maintainer_change(&info) {
        push_finding(&mut findings, "maintainer", raw);
    }

    // Check 5: Registry signature verification
    if let Some(raw) = crate::signatures::check_signatures(package_name, &info) {
        push_finding(&mut findings, "signatures", raw);
    }

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
