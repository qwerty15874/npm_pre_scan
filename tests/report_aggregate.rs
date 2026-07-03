// Offline integration tests for risk-score aggregation (src/report.rs).
// Builds synthetic CheckResults and asserts aggregate()'s risk_score, verdict,
// and detections. Always run (no Docker required).

use npm_pre_scan::{aggregate, CheckResult, Finding, LayerStatus, Verdict};
use serde_json::{Map, Value};

fn finding(check: &str, severity: &str, message: &str) -> Finding {
    let mut m = Map::new();
    m.insert("check".into(), Value::String(check.to_string()));
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("message".into(), Value::String(message.to_string()));
    m
}

fn finding_with_vector(vector: &str, check: &str, severity: &str, message: &str) -> Finding {
    let mut m = finding(check, severity, message);
    m.insert("vector".into(), Value::String(vector.to_string()));
    m
}

/// Add an `"evidence"` array to an existing finding (composes with
/// `finding`/`finding_with_vector` for findings that need both).
fn with_evidence(mut f: Finding, evidence: &[&str]) -> Finding {
    f.insert(
        "evidence".into(),
        Value::Array(evidence.iter().map(|s| Value::String(s.to_string())).collect()),
    );
    f
}

fn result(package: &str, verdict: Verdict, score: u32, findings: Vec<Finding>) -> CheckResult {
    CheckResult {
        package: package.to_string(),
        verdict,
        score,
        findings,
        note: None,
    }
}

// End-to-end confirmed example: L0=15, L1=50, L2=100, L3=15 → risk_score 1.00, verdict BLOCK.
// L2 now runs at full weight (LAYER_WEIGHTS[2] = 1.0): baseline subtraction
// (real-vs-baseline diffing per phase) makes Layer 2 findings package-
// attributable, so its score-100 BLOCK zeroes the noisy-OR product outright
// (1 - .85*.50*0*.85 = 1.0) and, with the verdict cap also removed, propagates
// straight through to the aggregate verdict.
#[test]
fn end_to_end_confirmed_example_yields_1_00_block() {
    let l0 = result(
        "evil-pkg",
        Verdict::Suspect,
        15,
        vec![finding_with_vector("A1", "typosquat", "SUSPECT", "edit_dist=1 from 'express'")],
    );
    let l1 = result(
        "evil-pkg",
        Verdict::Block,
        50,
        vec![finding_with_vector("B2", "obfuscation", "BLOCK", "eval+base64 at index.js:12")],
    );
    let l2 = result(
        "evil-pkg",
        Verdict::Block,
        100,
        vec![with_evidence(
            finding_with_vector("B1", "install_script_exec", "BLOCK", "child process during install"),
            &["proc:/usr/bin/id"],
        )],
    );
    let l3 = result(
        "evil-pkg",
        Verdict::Suspect,
        15,
        vec![finding_with_vector("D1", "timebomb", "SUSPECT", "network activity after +90d")],
    );

    let report = aggregate("evil-pkg", [Some(&l0), Some(&l1), Some(&l2), Some(&l3)]);

    assert_eq!(report.package, "evil-pkg");
    assert_eq!(report.risk_score, 1.0);
    assert_eq!(report.verdict, Verdict::Block);
    assert_eq!(
        report.detections.layer_0,
        vec!["A1: typosquat (edit_dist=1 from 'express')"]
    );
    assert_eq!(
        report.detections.layer_1,
        vec!["B2: obfuscation (eval+base64 at index.js:12)"]
    );
    assert_eq!(
        report.detections.layer_2,
        vec!["B1: install_script_exec (child process during install)"]
    );
    assert_eq!(
        report.detections.layer_3,
        vec!["D1: timebomb (network activity after +90d)"]
    );
    // 4b: all four layers ran (none skipped/error/not-run) in this scenario.
    assert_eq!(
        report.layer_status,
        [LayerStatus::Ran, LayerStatus::Ran, LayerStatus::Ran, LayerStatus::Ran]
    );
    // 4a: the L2 finding's evidence flows through to the RiskReport-level evidence list.
    assert_eq!(report.evidence.layer_2, vec!["proc:/usr/bin/id".to_string()]);
    assert!(report.evidence.layer_0.is_empty());
    assert!(report.evidence.layer_1.is_empty());
    assert!(report.evidence.layer_3.is_empty());
}

#[test]
fn no_layers_ran_yields_zero_risk_pass_and_empty_detections() {
    let report = aggregate("clean-pkg", [None, None, None, None]);

    assert_eq!(report.risk_score, 0.0);
    assert_eq!(report.verdict, Verdict::Pass);
    assert!(report.detections.layer_0.is_empty());
    assert!(report.detections.layer_1.is_empty());
    assert!(report.detections.layer_2.is_empty());
    assert!(report.detections.layer_3.is_empty());
    // 4b: nothing ran, so every layer is NotRun.
    assert_eq!(
        report.layer_status,
        [LayerStatus::NotRun, LayerStatus::NotRun, LayerStatus::NotRun, LayerStatus::NotRun]
    );
}

#[test]
fn typical_name_scan_l0_pass_l1_suspect() {
    let l0 = result("some-pkg", Verdict::Pass, 0, vec![]);
    let l1 = result(
        "some-pkg",
        Verdict::Suspect,
        15,
        vec![finding("network_imports", "SUSPECT", "require('axios')")],
    );

    let report = aggregate("some-pkg", [Some(&l0), Some(&l1), None, None]);

    assert_eq!(report.risk_score, 0.15);
    assert_eq!(report.verdict, Verdict::Suspect);
    assert!(report.detections.layer_0.is_empty());
    assert_eq!(report.detections.layer_1, vec!["network_imports: require('axios')"]);
    assert!(report.detections.layer_2.is_empty());
    assert!(report.detections.layer_3.is_empty());
    // 4b: L0/L1 ran; L2/L3 were never invoked in the fast name-scan path (not skipped — just not applicable).
    assert_eq!(
        report.layer_status,
        [LayerStatus::Ran, LayerStatus::Ran, LayerStatus::NotRun, LayerStatus::NotRun]
    );
}

/// Simulates the real name-scan early-exit path in `main.rs`: Layer 0 is
/// BLOCK, so Layer 1 is deliberately not attempted, and the caller marks it
/// `Skipped` (not `NotRun`) after `aggregate()` returns — distinguishing
/// "the tool chose not to run this" from "this layer isn't applicable here".
#[test]
fn l0_block_early_exit_marks_l1_skipped_not_not_run() {
    let l0 = result(
        "evil-pkg",
        Verdict::Block,
        50,
        vec![finding_with_vector("A1", "typosquat", "BLOCK", "edit_dist=1 from 'express'")],
    );

    let mut report = aggregate("evil-pkg", [Some(&l0), None, None, None]);
    report.mark_skipped(1);

    assert_eq!(report.verdict, Verdict::Block);
    assert_eq!(
        report.layer_status,
        [LayerStatus::Ran, LayerStatus::Skipped, LayerStatus::NotRun, LayerStatus::NotRun]
    );
    // JSON round-trips the lowercase status strings correctly.
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["layer_status"],
        serde_json::json!(["ran", "skipped", "not_run", "not_run"])
    );
}

/// `run_full_local`-shaped case: Layer 0 genuinely never runs (a local
/// directory has no registry identity) — this is `NotRun`, never `Skipped`,
/// since nothing was short-circuited by an earlier layer's result.
#[test]
fn run_full_local_shape_l0_is_not_run_not_skipped() {
    let l1 = result("local-pkg", Verdict::Pass, 0, vec![]);
    let l2 = result("local-pkg", Verdict::Pass, 0, vec![]);
    let l3 = result("local-pkg", Verdict::Pass, 0, vec![]);

    let report = aggregate("local-pkg", [None, Some(&l1), Some(&l2), Some(&l3)]);

    assert_eq!(report.layer_status[0], LayerStatus::NotRun);
    assert_eq!(
        report.layer_status,
        [LayerStatus::NotRun, LayerStatus::Ran, LayerStatus::Ran, LayerStatus::Ran]
    );
}

#[test]
fn error_layer_excluded_from_risk_but_visible_in_detections_if_any() {
    let l1 = result("pkg", Verdict::Suspect, 50, vec![]);
    let l2 = result(
        "pkg",
        Verdict::Error,
        0,
        vec![finding("docker", "INFO", "Docker required for Layer 2")],
    );

    let report = aggregate("pkg", [None, Some(&l1), Some(&l2), None]);

    // Error layer contributes 0 to risk; only L1's 0.5 applies.
    assert_eq!(report.risk_score, 0.5);
    // Verdict is worst-of; Suspect outranks Error.
    assert_eq!(report.verdict, Verdict::Suspect);
    // Detections still surface the Error layer's findings (e.g. the Docker note-as-finding).
    assert_eq!(report.detections.layer_2, vec!["docker: Docker required for Layer 2"]);
    // 4b: L2's Verdict::Error result is reported as Error status, not Ran.
    assert_eq!(
        report.layer_status,
        [LayerStatus::NotRun, LayerStatus::Ran, LayerStatus::Error, LayerStatus::NotRun]
    );
}
