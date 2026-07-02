// Offline integration tests for risk-score aggregation (src/report.rs).
// Builds synthetic CheckResults and asserts aggregate()'s risk_score, verdict,
// and detections. Always run (no Docker required).

use npm_pre_scan::{aggregate, CheckResult, Finding, Verdict};
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

fn result(package: &str, verdict: Verdict, score: u32, findings: Vec<Finding>) -> CheckResult {
    CheckResult {
        package: package.to_string(),
        verdict,
        score,
        findings,
        note: None,
    }
}

// End-to-end confirmed example: L0=15, L1=50, L2=100, L3=15 → risk_score 0.82, verdict BLOCK.
#[test]
fn end_to_end_confirmed_example_yields_0_82_block() {
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
        Verdict::Suspect,
        100,
        vec![finding_with_vector("B1", "install_script_exec", "BLOCK", "child process during install")],
    );
    let l3 = result(
        "evil-pkg",
        Verdict::Suspect,
        15,
        vec![finding_with_vector("D1", "timebomb", "SUSPECT", "network activity after +90d")],
    );

    let report = aggregate("evil-pkg", [Some(&l0), Some(&l1), Some(&l2), Some(&l3)]);

    assert_eq!(report.package, "evil-pkg");
    assert_eq!(report.risk_score, 0.82);
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
}
