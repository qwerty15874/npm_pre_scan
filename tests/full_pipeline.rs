// Docker-gated integration tests for the full pipeline orchestrator
// (run_full_local: Layer 1 + Layer 2 + Layer 3 -> aggregate RiskReport).
// All tests are marked #[ignore] — they require a Docker-capable environment.
// Run with: cargo test -- --ignored
//
// Working directory during `cargo test` is the package root (where Cargo.toml lives).

use std::path::Path;

use npm_pre_scan::run_full_local;
use npm_pre_scan::{LayerStatus, Verdict};

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
    // 4b: run_full_local skips Layer 0 (no registry identity for a local dir —
    // genuinely NotRun, not Skipped, since nothing short-circuited it); L1/L2/L3 all ran.
    assert_eq!(
        report.layer_status[0],
        LayerStatus::NotRun,
        "expected Layer 0 NotRun for run_full_local; got {:?}",
        report.layer_status[0]
    );
    assert_eq!(
        report.layer_status[3],
        LayerStatus::Ran,
        "expected Layer 3 Ran; got {:?}",
        report.layer_status[3]
    );
    // 4a: the D1 finding(s) carry evidence (the exact new event(s) under the clock scenario).
    assert!(
        !report.evidence.layer_3.is_empty(),
        "expected non-empty layer_3 evidence for a live D1 detection; got {:?}",
        report.evidence.layer_3
    );
}

/// Benign control (payload-free pure export) — requires Docker.
/// Layer 2 now diffs each phase's real run against its own pristine baseline
/// (see `layer2::mod::run_layer2_local`), which cancels npm's own toolchain
/// reads (.npmrc, /etc/passwd) at the source instead of just capping the
/// verdict — so a genuinely benign package's post-subtraction diff is empty
/// and the full pipeline now lands on a clean PASS across all four layers.
#[test]
#[ignore]
fn dummy_benign_l3_full_pipeline_is_clean() {
    let dir = Path::new("dummy_packages/dummy_benign_l3");
    let report = run_full_local("dummy_benign_l3", dir);

    assert_eq!(
        report.verdict,
        Verdict::Pass,
        "expected PASS for benign control (baseline subtraction removes npm toolchain noise); got {:?} with detections: {:?}",
        report.verdict,
        report.detections
    );
    assert!(
        report.detections.layer_1.is_empty(),
        "layer_1 must be clean for benign control; got {:?}",
        report.detections.layer_1
    );
    assert!(
        report.detections.layer_2.is_empty(),
        "layer_2 must be clean for benign control after baseline subtraction; got {:?}",
        report.detections.layer_2
    );
    assert!(
        report.detections.layer_3.is_empty(),
        "layer_3 must be clean for benign control; got {:?}",
        report.detections.layer_3
    );
    // 4b: the whole point of layer_status — L1/L2/L3 empty detections here mean
    // "ran and found nothing" (Ran), not "never executed" (NotRun). Only L0 is
    // genuinely NotRun (run_full_local has no registry identity for a local dir).
    assert_eq!(
        report.layer_status,
        [LayerStatus::NotRun, LayerStatus::Ran, LayerStatus::Ran, LayerStatus::Ran],
        "expected L0=not_run, L1-3=ran (clean) for the benign control; got {:?}",
        report.layer_status
    );
    // 4a: no findings anywhere means no evidence anywhere either.
    assert!(report.evidence.layer_1.is_empty());
    assert!(report.evidence.layer_2.is_empty());
    assert!(report.evidence.layer_3.is_empty());
}
