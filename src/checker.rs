use serde_json::{Map, Value};

use crate::age_check::check_age_and_downloads;
use crate::combosquat::check_combosquat;
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

/// Checks 1-3: the name-only checks. These compare the package *name* against
/// the embedded comparison lists and need no registry access at all, which is
/// what makes `run_layer0_name_only` possible.
fn name_findings(
    package_name: &str,
    top_packages: &[String],
    top_scoped: &[String],
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    // Check 1: Typosquatting
    if let Some(raw) = check_typosquat(package_name, top_packages) {
        push_finding(&mut findings, "typosquat", raw);
    }

    // Check 2: Namespace conflict
    if let Some(raw) = check_namespace_conflict(package_name, top_scoped) {
        push_finding(&mut findings, "namespace", raw);
    }

    // Check 3: Combosquatting (name-based, no registry needed)
    if let Some(raw) = check_combosquat(package_name, top_packages) {
        push_finding(&mut findings, "combosquat", raw);
    }

    findings
}

/// Run ONLY the name-based Layer 0 checks (A1 typosquat, A2 namespace, A4
/// combosquat), with no registry access whatsoever.
///
/// Exists for the evaluation harness's large-corpus sweep: a name-only pass over
/// hundreds of thousands of names costs zero HTTP requests and — since
/// `toplist::load_effective_lists(false)` also does no I/O — is byte-for-byte
/// reproducible. Going through `run_layer0` instead would issue roughly six
/// round trips per package (metadata, downloads, registry keys) and make the
/// result depend on registry state at scan time.
///
/// The note deliberately differs from `run_layer0`'s not-found note so a
/// consumer can distinguish "we chose not to ask the registry" from "the
/// registry said this package does not exist" — two facts that mean very
/// different things when scoring a detection.
pub fn run_layer0_name_only(
    package_name: &str,
    top_packages: &[String],
    top_scoped: &[String],
) -> CheckResult {
    let findings = name_findings(package_name, top_packages, top_scoped);
    CheckResult {
        package: package_name.to_string(),
        verdict: aggregate_verdict(&findings),
        score: score_findings(&findings),
        findings,
        note: Some("Name-only mode; registry-based checks not attempted".to_string()),
    }
}

/// Run all Layer 0 metadata checks for a single package name.
pub fn run_layer0(
    package_name: &str,
    top_packages: &[String],
    top_scoped: &[String],
) -> CheckResult {
    let mut findings: Vec<Finding> = name_findings(package_name, top_packages, top_scoped);

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

    // Check 4: Age + download spike
    if let Some(raw) = check_age_and_downloads(package_name, &info) {
        push_finding(&mut findings, "age_downloads", raw);
    }

    // Check 5: Maintainer change
    if let Some(raw) = check_maintainer_change(&info) {
        push_finding(&mut findings, "maintainer", raw);
    }

    // Check 6: Registry signature verification
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

#[cfg(test)]
mod tests {
    use super::*;

    // Small hand-built lists so these tests never touch data/*.txt and stay
    // independent of that file's contents.
    fn top() -> Vec<String> {
        ["express", "lodash", "cross-env", "d3"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn scoped() -> Vec<String> {
        vec!["@aws-sdk/client-s3".to_string()]
    }

    #[test]
    fn name_only_finds_the_same_name_based_findings_as_the_full_run() {
        // A typosquat is reachable from the name alone, so the name-only pass
        // must reach exactly the same conclusion as the networked one would.
        let r = run_layer0_name_only("expres", &top(), &scoped());
        assert_eq!(r.verdict, Verdict::Block);
        let checks: Vec<&str> = r
            .findings
            .iter()
            .filter_map(|f| f.get("check").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(checks, vec!["typosquat"]);
        assert_eq!(r.package, "expres");
        assert_eq!(r.score, score_findings(&r.findings));
    }

    #[test]
    fn name_only_runs_all_three_name_checks() {
        // A namespace conflict is check 2, not check 1 — proves the extraction
        // kept all three name-based checks, not just typosquat.
        let r = run_layer0_name_only("aws-sdk-client-s3", &top(), &scoped());
        assert_eq!(r.verdict, Verdict::Block);
        assert!(r
            .findings
            .iter()
            .any(|f| f.get("check").and_then(|v| v.as_str()) == Some("namespace")));
    }

    #[test]
    fn name_only_note_is_distinct_from_the_not_found_note() {
        // The harness relies on these two strings differing to tell "we didn't
        // ask" apart from "npm said no".
        let name_only = run_layer0_name_only("some-unremarkable-name", &top(), &scoped());
        let note = name_only.note.expect("name-only mode must annotate itself");
        assert!(note.contains("Name-only mode"));
        assert!(
            !note.contains("not found on npm registry"),
            "must not be confusable with the 404 note"
        );
    }

    #[test]
    fn a_clean_name_passes_with_no_findings() {
        let r = run_layer0_name_only("some-unremarkable-name", &top(), &scoped());
        assert_eq!(r.verdict, Verdict::Pass);
        assert!(r.findings.is_empty());
        assert_eq!(r.score, 0);
    }

    #[test]
    fn an_exact_popular_match_is_info_only_and_still_passes() {
        // Scanning a legitimate popular package yields an INFO A1 finding. It
        // must not raise the verdict, or every benign control in the evaluation
        // corpus would register as a false positive.
        let r = run_layer0_name_only("lodash", &top(), &scoped());
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(
            r.findings[0].get("severity").and_then(|v| v.as_str()),
            Some("INFO")
        );
    }

    #[test]
    fn aggregate_verdict_prefers_block_over_suspect() {
        let mk = |sev: &str| {
            let mut f = Map::new();
            f.insert("severity".into(), Value::String(sev.into()));
            f
        };
        assert_eq!(aggregate_verdict(&[mk("SUSPECT"), mk("BLOCK")]), Verdict::Block);
        assert_eq!(aggregate_verdict(&[mk("INFO"), mk("SUSPECT")]), Verdict::Suspect);
        assert_eq!(aggregate_verdict(&[mk("INFO")]), Verdict::Pass);
        assert_eq!(aggregate_verdict(&[]), Verdict::Pass);
    }
}
