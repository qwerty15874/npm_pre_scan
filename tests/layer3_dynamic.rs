// Docker-gated integration tests for Layer 3 live condition-mutation analysis.
// All tests are marked #[ignore] — they require a Docker-capable environment.
// Run with: cargo test -- --ignored
//
// Working directory during `cargo test` is the package root (where Cargo.toml lives).

use std::path::Path;
use npm_pre_scan::run_layer3_local;
use npm_pre_scan::Verdict;

/// Live Layer 3 run on dummy_timebomb (D1 clock scenario) — requires Docker.
#[test]
#[ignore]
fn d1_timebomb_live_run() {
    let dir = Path::new("dummy_packages/dummy_timebomb");
    let result = run_layer3_local("dummy_timebomb", dir);
    assert!(
        result.verdict == Verdict::Block || result.verdict == Verdict::Suspect,
        "dummy_timebomb must produce BLOCK or SUSPECT; got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.get("scenario").and_then(|v| v.as_str()) == Some("D1")),
        "Expected a D1-scenario finding; findings: {:?}",
        result.findings
    );
}

/// Live Layer 3 run on dummy_env_triggered (D2 env scenario) — requires Docker.
#[test]
#[ignore]
fn d2_env_triggered_live_run() {
    let dir = Path::new("dummy_packages/dummy_env_triggered");
    let result = run_layer3_local("dummy_env_triggered", dir);
    assert!(
        result.verdict == Verdict::Block || result.verdict == Verdict::Suspect,
        "dummy_env_triggered must produce BLOCK or SUSPECT; got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.get("scenario").and_then(|v| v.as_str()) == Some("D2")),
        "Expected a D2-scenario finding; findings: {:?}",
        result.findings
    );
}

/// Live Layer 3 run on dummy_api_triggered (D3 fuzz scenario) — requires Docker.
#[test]
#[ignore]
fn d3_api_triggered_live_run() {
    let dir = Path::new("dummy_packages/dummy_api_triggered");
    let result = run_layer3_local("dummy_api_triggered", dir);
    assert!(
        result.verdict == Verdict::Block || result.verdict == Verdict::Suspect,
        "dummy_api_triggered must produce BLOCK or SUSPECT; got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.get("scenario").and_then(|v| v.as_str()) == Some("D3")),
        "Expected a D3-scenario finding; findings: {:?}",
        result.findings
    );
}

/// Benign control (payload-free pure export) — requires Docker.
/// Proves Layer 3's baseline-diff cancels toolchain + fuzz-harness noise: the
/// fuzz harness calls add() across the arg matrix, but add() has no observable
/// side effect, so every scenario diff is empty → PASS (no false positives).
#[test]
#[ignore]
fn benign_control_live_run() {
    let dir = Path::new("dummy_packages/dummy_benign_l3");
    let result = run_layer3_local("dummy_benign_l3", dir);
    assert_eq!(
        result.verdict,
        Verdict::Pass,
        "benign control must produce PASS (no false positives); got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
}
