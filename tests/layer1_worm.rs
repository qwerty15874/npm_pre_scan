// Integration tests for Layer 1 worm-signature detection (E1: Shai-Hulud class).
// Tests run against files in dummy_packages/ (repo root) via relative paths.
// Working directory during `cargo test` is the package root (where Cargo.toml lives).

use std::path::Path;

use npm_pre_scan::layer1::run_version_diff_local;
use npm_pre_scan::{run_layer1_local, Verdict};

// E1: infected fixture must produce BLOCK with worm and ioc_hash aggregate findings.
#[test]
fn e1_shai_hulud_static_blocks() {
    let dir = Path::new("dummy_packages/dummy_shai_hulud/infected");
    let result = run_layer1_local("dummy_shai_hulud_infected", dir);
    assert_eq!(
        result.verdict,
        Verdict::Block,
        "dummy_shai_hulud/infected must produce BLOCK; got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
    assert!(
        result.findings.iter().any(|f| {
            f.get("check").and_then(|v| v.as_str()) == Some("worm_signature")
                && f.get("category").and_then(|v| v.as_str()) == Some("worm")
        }),
        "Expected a worm_signature finding with category='worm'; findings: {:?}",
        result.findings
    );
    assert!(
        result.findings.iter().any(|f| {
            f.get("check").and_then(|v| v.as_str()) == Some("worm_signature")
                && f.get("category").and_then(|v| v.as_str()) == Some("ioc_hash")
        }),
        "Expected a worm_signature finding with category='ioc_hash'; findings: {:?}",
        result.findings
    );
}

// E1: infected fixture must include a self_propagation finding.
#[test]
fn e1_shai_hulud_self_propagation_present() {
    let dir = Path::new("dummy_packages/dummy_shai_hulud/infected");
    let result = run_layer1_local("dummy_shai_hulud_infected", dir);
    assert!(
        result.findings.iter().any(|f| {
            f.get("check").and_then(|v| v.as_str()) == Some("worm_signature")
                && f.get("category").and_then(|v| v.as_str()) == Some("self_propagation")
        }),
        "Expected a worm_signature finding with category='self_propagation'; findings: {:?}",
        result.findings
    );
}

// E1 control: clean fixture must not produce BLOCK.
#[test]
fn e1_shai_hulud_clean_passes() {
    let dir = Path::new("dummy_packages/dummy_shai_hulud/clean");
    let result = run_layer1_local("dummy_shai_hulud_clean", dir);
    assert_ne!(
        result.verdict,
        Verdict::Block,
        "dummy_shai_hulud/clean must not produce BLOCK; got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
}

// E1 version-diff: worm introduced via a package update triggers BLOCK in diff check.
#[test]
fn e1_worm_via_update_blocks() {
    let clean = Path::new("dummy_packages/dummy_shai_hulud/clean");
    let infected = Path::new("dummy_packages/dummy_shai_hulud/infected");
    let findings = run_version_diff_local(clean, infected);
    assert!(
        !findings.is_empty(),
        "Expected findings from clean→infected diff; got none"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.get("severity").and_then(|v| v.as_str()) == Some("BLOCK")),
        "Expected at least one BLOCK finding from worm-via-update diff; got: {:?}",
        findings
    );
}
