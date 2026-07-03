// Live integration test for the registry full-pipeline orchestrator
// (run_full_registry: name -> registry lookup -> shared download -> L0+L1+L2+L3 -> aggregate).
// Marked #[ignore] — requires both network (registry lookup + tarball download)
// and a Docker-capable environment (Layer 2/3).
// Run with: cargo test -- --ignored

use npm_pre_scan::run_full_registry;

/// Smoke test: run the full registry pipeline on a well-known, tiny, dependency-free
/// package. This does not assert a specific verdict — the goal is only to confirm
/// the orchestrator wires Layer 0 (registry metadata) through the shared tarball
/// download to Layer 1 (static)/Layer 2 (dynamic)/Layer 3 (condition mutation)
/// without panicking, and returns a populated RiskReport.
#[test]
#[ignore]
fn is_odd_full_registry_pipeline_runs_without_panicking() {
    let report = run_full_registry("is-odd");

    assert_eq!(report.package, "is-odd");
    // risk_score must be a finite, non-negative fraction in [0, 1] (aggregate's contract).
    assert!(
        report.risk_score.is_finite() && (0.0..=1.0).contains(&report.risk_score),
        "risk_score out of expected [0,1] range: {}",
        report.risk_score
    );
    // Verdict must be one of the four known variants (compiles to an exhaustive
    // enum, so this mainly documents intent — the real assertion is "didn't panic").
    eprintln!(
        "is-odd full registry pipeline -> verdict={:?} risk_score={} detections={:?} layer_status={:?}",
        report.verdict, report.risk_score, report.detections, report.layer_status
    );
    // 4b: run_full_registry always attempts all four layers (unlike the
    // name-scan path, it never early-exits on an L0 BLOCK) — none should be
    // NotRun or Skipped for a package that resolves successfully on the
    // registry; each is either Ran or, only on a genuine failure, Error.
    for (i, status) in report.layer_status.iter().enumerate() {
        assert!(
            matches!(status, npm_pre_scan::LayerStatus::Ran | npm_pre_scan::LayerStatus::Error),
            "expected layer {} to be Ran or Error (run_full_registry attempts all four layers); got {:?}",
            i,
            status
        );
    }
}
