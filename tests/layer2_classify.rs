// Offline unit tests for Layer 2 classification logic.
// These tests feed recorded fixture logs through parse_* → classify and assert
// expected vector/severity. No Docker required — all I/O is local fixture files.
// Working directory during `cargo test` is the package root (where Cargo.toml lives).

use npm_pre_scan::layer2::classify::classify;
use npm_pre_scan::layer2::profile::{parse_dns, parse_strace};
use npm_pre_scan::Verdict;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/layer2/{}", name))
        .unwrap_or_else(|e| panic!("Could not read fixture {}: {}", name, e))
}

fn sev(findings: &[serde_json::Map<String, serde_json::Value>]) -> Vec<&str> {
    findings
        .iter()
        .filter_map(|f| f.get("severity").and_then(|v| v.as_str()))
        .collect()
}

fn checks(findings: &[serde_json::Map<String, serde_json::Value>]) -> Vec<&str> {
    findings
        .iter()
        .filter_map(|f| f.get("check").and_then(|v| v.as_str()))
        .collect()
}

fn vectors(findings: &[serde_json::Map<String, serde_json::Value>]) -> Vec<&str> {
    findings
        .iter()
        .filter_map(|f| f.get("vector").and_then(|v| v.as_str()))
        .collect()
}

fn verdict_from(findings: &[serde_json::Map<String, serde_json::Value>]) -> Verdict {
    if sev(findings).contains(&"BLOCK") {
        Verdict::Block
    } else if sev(findings).contains(&"SUSPECT") {
        Verdict::Suspect
    } else {
        Verdict::Pass
    }
}

// ── B1: install-time script execution ────────────────────────────────────────

/// B1: install phase spawning unexpected child process + network → BLOCK (B1 escalated)
#[test]
fn b1_install_time_child_with_network_blocks() {
    let log = fixture("install_time_strace.log");
    let profile = parse_strace("install", &log);
    let findings = classify(&profile);

    assert!(
        !findings.is_empty(),
        "Expected findings for install_time fixture; got none"
    );
    // The fixture has an unexpected child (/usr/bin/id) plus a connect → BLOCK
    assert!(
        sev(&findings).contains(&"BLOCK"),
        "Expected BLOCK finding; severities: {:?}",
        sev(&findings)
    );
    assert!(
        vectors(&findings).contains(&"B1"),
        "Expected B1 vector; vectors: {:?}",
        vectors(&findings)
    );
    assert_eq!(verdict_from(&findings), Verdict::Block);
}

/// B1: sensitive file (.npmrc) opened during install → BLOCK sensitive_file_read
#[test]
fn b1_install_time_npmrc_read_blocks() {
    let log = fixture("install_time_strace.log");
    let profile = parse_strace("install", &log);
    let findings = classify(&profile);

    assert!(
        checks(&findings).contains(&"sensitive_file_read"),
        "Expected sensitive_file_read finding; checks: {:?}",
        checks(&findings)
    );
}

// ── C1: import-time side effects ─────────────────────────────────────────────

/// C1: import phase making a network connection → SUSPECT C1
#[test]
fn c1_import_side_effect_suspect() {
    let log = fixture("import_time_strace.log");
    let profile = parse_strace("import", &log);
    let findings = classify(&profile);

    assert!(
        !findings.is_empty(),
        "Expected findings for import_time fixture; got none"
    );
    assert!(
        checks(&findings).contains(&"import_side_effect"),
        "Expected import_side_effect finding; checks: {:?}",
        checks(&findings)
    );
    assert!(
        vectors(&findings).contains(&"C1"),
        "Expected C1 vector; vectors: {:?}",
        vectors(&findings)
    );
    assert_eq!(verdict_from(&findings), Verdict::Suspect);
}

// ── C2: DNS tunneling ─────────────────────────────────────────────────────────

/// C2: many distinct DNS queries with long encoded labels → SUSPECT or BLOCK (C2)
#[test]
fn c2_slow_exfil_dns_tunneling_detected() {
    let log = fixture("slow_exfil_dns.log");
    let queries = parse_dns(&log);
    // Build a profile with just the DNS queries (import phase)
    let mut profile = npm_pre_scan::layer2::profile::Layer2Profile {
        phase: "import".to_string(),
        dns_queries: queries,
        ..Default::default()
    };
    // Ensure profile has no confounding fields
    profile.connects.clear();
    profile.processes.clear();
    profile.file_opens.clear();

    let findings = classify(&profile);

    assert!(
        !findings.is_empty(),
        "Expected findings for slow_exfil dns fixture; got none"
    );
    assert!(
        checks(&findings).contains(&"dns_tunneling"),
        "Expected dns_tunneling finding; checks: {:?}",
        checks(&findings)
    );
    assert!(
        vectors(&findings).contains(&"C2"),
        "Expected C2 vector; vectors: {:?}",
        vectors(&findings)
    );
    // Must be at least SUSPECT
    assert!(
        sev(&findings).iter().any(|&s| s == "SUSPECT" || s == "BLOCK"),
        "Expected SUSPECT or BLOCK; severities: {:?}",
        sev(&findings)
    );
}

// ── C3: hidden native binary ─────────────────────────────────────────────────

/// C3: .node file opened at import → SUSPECT C3
#[test]
fn c3_native_addon_suspect() {
    let log = fixture("binary_strace.log");
    let profile = parse_strace("import", &log);
    let findings = classify(&profile);

    assert!(
        !findings.is_empty(),
        "Expected findings for binary fixture; got none"
    );
    assert!(
        checks(&findings).contains(&"native_addon"),
        "Expected native_addon finding; checks: {:?}",
        checks(&findings)
    );
    assert!(
        vectors(&findings).contains(&"C3"),
        "Expected C3 vector; vectors: {:?}",
        vectors(&findings)
    );
    assert!(
        sev(&findings).contains(&"SUSPECT"),
        "Expected SUSPECT; severities: {:?}",
        sev(&findings)
    );
}

// ── E1: worm egress ───────────────────────────────────────────────────────────

/// E1: worm DNS queries (registry.npmjs.org, api.github.com, webhook.site) → BLOCK
#[test]
fn e1_worm_dns_egress_blocks() {
    let log = fixture("worm_egress_dns.log");
    let queries = parse_dns(&log);
    let profile = npm_pre_scan::layer2::profile::Layer2Profile {
        phase: "import".to_string(),
        dns_queries: queries,
        ..Default::default()
    };
    let findings = classify(&profile);

    assert!(
        sev(&findings).contains(&"BLOCK"),
        "Expected BLOCK for worm DNS egress; severities: {:?}",
        sev(&findings)
    );
    assert!(
        checks(&findings).contains(&"worm_egress"),
        "Expected worm_egress finding; checks: {:?}",
        checks(&findings)
    );
    assert_eq!(verdict_from(&findings), Verdict::Block);
}

/// E1: strace connect to 169.254.169.254 (cloud IMDS) → BLOCK
#[test]
fn e1_worm_imds_connect_blocks() {
    let log = fixture("worm_egress_strace.log");
    let profile = parse_strace("install", &log);
    let findings = classify(&profile);

    assert!(
        sev(&findings).contains(&"BLOCK"),
        "Expected BLOCK for IMDS connect; severities: {:?}",
        sev(&findings)
    );
    assert!(
        checks(&findings).contains(&"worm_egress"),
        "Expected worm_egress finding; checks: {:?}",
        checks(&findings)
    );
}

// ── Benign control ────────────────────────────────────────────────────────────

/// Benign package: no suspicious activity → PASS (no BLOCK or SUSPECT findings)
#[test]
fn benign_control_no_block_suspect() {
    let log = fixture("benign_strace.log");
    let profile = parse_strace("import", &log);
    let findings = classify(&profile);

    let has_block_or_suspect = sev(&findings)
        .iter()
        .any(|&s| s == "BLOCK" || s == "SUSPECT");
    assert!(
        !has_block_or_suspect,
        "Benign control must not produce BLOCK/SUSPECT findings; got: {:?}",
        findings
    );
    assert_eq!(verdict_from(&findings), Verdict::Pass);
}
