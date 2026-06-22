// Docker-gated integration tests for Layer 2 live dynamic analysis.
// All tests are marked #[ignore] — they require a Docker-capable environment.
// Run with: cargo test -- --ignored
//
// Working directory during `cargo test` is the package root (where Cargo.toml lives).

use std::path::Path;
use npm_pre_scan::run_layer2_local;
use npm_pre_scan::Verdict;

/// Live Layer 2 run on dummy_install_time (B1) — requires Docker.
#[test]
#[ignore]
fn b1_install_time_live_run() {
    let dir = Path::new("dummy_packages/dummy_install_time");
    let result = run_layer2_local("dummy_install_time", dir);
    assert!(
        result.verdict == Verdict::Block || result.verdict == Verdict::Suspect,
        "dummy_install_time must produce BLOCK or SUSPECT; got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
}

/// Live Layer 2 run on dummy_import_time (C1) — requires Docker.
#[test]
#[ignore]
fn c1_import_time_live_run() {
    let dir = Path::new("dummy_packages/dummy_import_time");
    let result = run_layer2_local("dummy_import_time", dir);
    assert!(
        result.verdict == Verdict::Block || result.verdict == Verdict::Suspect,
        "dummy_import_time must produce BLOCK or SUSPECT; got {:?}",
        result.verdict
    );
}

/// Live Layer 2 run on dummy_slow_exfil (C2) — requires Docker.
#[test]
#[ignore]
fn c2_slow_exfil_live_run() {
    let dir = Path::new("dummy_packages/dummy_slow_exfil");
    let result = run_layer2_local("dummy_slow_exfil", dir);
    assert!(
        result.verdict == Verdict::Block || result.verdict == Verdict::Suspect,
        "dummy_slow_exfil must produce BLOCK or SUSPECT; got {:?}",
        result.verdict
    );
}

/// Live Layer 2 run on dummy_binary (C3) — requires Docker.
#[test]
#[ignore]
fn c3_binary_live_run() {
    let dir = Path::new("dummy_packages/dummy_binary");
    let result = run_layer2_local("dummy_binary", dir);
    assert!(
        result.verdict == Verdict::Block || result.verdict == Verdict::Suspect,
        "dummy_binary must produce BLOCK or SUSPECT; got {:?}",
        result.verdict
    );
}

/// Live Layer 2 run on dummy_shai_hulud/infected (E1 worm egress) — requires Docker.
#[test]
#[ignore]
fn e1_worm_egress_live_run() {
    let dir = Path::new("dummy_packages/dummy_shai_hulud/infected");
    let result = run_layer2_local("dummy_shai_hulud_infected", dir);
    assert_eq!(
        result.verdict,
        Verdict::Block,
        "dummy_shai_hulud/infected must produce BLOCK; got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
}
