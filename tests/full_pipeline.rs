// Docker-gated integration tests for the full pipeline orchestrator
// (run_full_local: Layer 1 + Layer 2 + Layer 3 -> aggregate RiskReport).
// All tests are marked #[ignore] — they require a Docker-capable environment.
// Run with: cargo test -- --ignored
//
// Working directory during `cargo test` is the package root (where Cargo.toml lives).

use std::path::Path;

use npm_pre_scan::run_full_local;
use npm_pre_scan::Verdict;

/// Live full-pipeline run on dummy_timebomb (D1 condition-mutation vector) — requires Docker.
#[test]
#[ignore]
fn dummy_timebomb_full_pipeline_flags_risk() {
    let dir = Path::new("dummy_packages/dummy_timebomb");
    let report = run_full_local("dummy_timebomb", dir);

    assert!(
        report.risk_score > 0.0,
        "expected risk_score > 0.0; got {}",
        report.risk_score
    );
    assert!(
        report.verdict == Verdict::Block || report.verdict == Verdict::Suspect,
        "expected BLOCK or SUSPECT; got {:?}",
        report.verdict
    );
    assert!(
        !report.detections.layer_3.is_empty(),
        "expected non-empty layer_3 detections; got {:?}",
        report.detections.layer_3
    );
}

/// Benign control (payload-free pure export) — requires Docker.
/// Layer 2 fires sensitive_file_read on npm's OWN baseline reads (.npmrc during
/// `npm install`) — its documented over-approximation. The aggregate caps L2 at
/// SUSPECT, so the benign control lands on SUSPECT (from L2 noise only) while
/// L1 and L3 stay clean — proving the SUSPECT does NOT come from real payload.
#[test]
#[ignore]
fn dummy_benign_l3_full_pipeline_is_clean() {
    let dir = Path::new("dummy_packages/dummy_benign_l3");
    let report = run_full_local("dummy_benign_l3", dir);

    assert_eq!(
        report.verdict,
        Verdict::Suspect,
        "expected SUSPECT for benign control (L2 baseline noise, capped); got {:?} with detections: {:?}",
        report.verdict,
        report.detections
    );
    // The SUSPECT comes only from Layer 2's npm-install baseline noise: L1 and L3 are clean.
    assert!(
        report.detections.layer_1.is_empty(),
        "layer_1 must be clean for benign control; got {:?}",
        report.detections.layer_1
    );
    assert!(
        report.detections.layer_3.is_empty(),
        "layer_3 must be clean for benign control; got {:?}",
        report.detections.layer_3
    );
}
