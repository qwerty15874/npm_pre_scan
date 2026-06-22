// Integration tests for Layer 1 static analysis using on-disk dummy fixtures.
// Tests run against files in dummy_packages/ (repo root) via relative paths.
// Working directory during `cargo test` is the package root (where Cargo.toml lives).

use std::path::Path;

use npm_pre_scan::layer1::run_version_diff_local;
use npm_pre_scan::{run_layer1_local, Verdict};

// B2: Obfuscated package — eval(Buffer.from()) triggers BLOCK
#[test]
fn b2_obfuscated_dummy_blocks() {
    let dir = Path::new("dummy_packages/dummy_obfuscated");
    let result = run_layer1_local("dummy_obfuscated", dir);
    assert_eq!(
        result.verdict,
        Verdict::Block,
        "dummy_obfuscated must produce BLOCK; got {:?} with findings: {:?}",
        result.verdict,
        result.findings
    );
    assert!(
        result.findings.iter().any(|f| {
            f.get("check").and_then(|v| v.as_str()) == Some("obfuscation")
        }),
        "Expected an 'obfuscation' finding"
    );
}

// B2: obfuscated dummy also triggers install_script (postinstall)
#[test]
fn b2_obfuscated_dummy_has_install_script_finding() {
    let dir = Path::new("dummy_packages/dummy_obfuscated");
    let result = run_layer1_local("dummy_obfuscated", dir);
    assert!(
        result.findings.iter().any(|f| {
            f.get("check").and_then(|v| v.as_str()) == Some("install_script")
        }),
        "Expected an 'install_script' finding from postinstall"
    );
}

// B3: Malicious version update — diff between prev and latest detects eval(Buffer.from())
#[test]
fn b3_malicious_update_diff_blocks() {
    let prev = Path::new("dummy_packages/dummy_malicious_update/prev");
    let latest = Path::new("dummy_packages/dummy_malicious_update/latest");
    let findings = run_version_diff_local(prev, latest);
    assert!(
        !findings.is_empty(),
        "Expected at least one finding from the malicious update diff"
    );
    assert!(
        findings.iter().any(|f| {
            f.get("severity").and_then(|v| v.as_str()) == Some("BLOCK")
        }),
        "Expected a BLOCK finding for newly introduced eval(Buffer.from()); got: {:?}",
        findings
    );
}

// B3: prev-only run (same dir for both) produces no findings (no new code)
#[test]
fn b3_identical_dirs_produce_no_findings() {
    let prev = Path::new("dummy_packages/dummy_malicious_update/prev");
    let findings = run_version_diff_local(prev, prev);
    assert!(
        findings.is_empty(),
        "Diffing a directory against itself must yield no findings"
    );
}
