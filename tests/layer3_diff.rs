// Offline unit tests for Layer 3 diff + classify logic.
// These tests feed recorded baseline + mutated fixture logs through
// parse_strace/parse_dns → diff_profiles → classify_scenario and assert the
// mutated-only event is flagged with the right scenario/severity, and that
// shared baseline noise (.npmrc lookup, /etc/passwd read) is absent from the
// diff. No Docker required — all I/O is local fixture files.
//
// Working directory during `cargo test` is the package root (where Cargo.toml lives).

use npm_pre_scan::layer2::profile::{parse_dns, parse_strace, Layer2Profile};
use npm_pre_scan::layer3::classify::classify_scenario;
use npm_pre_scan::layer3::diff::diff_profiles;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/layer3/{}", name))
        .unwrap_or_else(|e| panic!("Could not read fixture {}: {}", name, e))
}

fn load_profile(strace_name: &str, dns_name: &str) -> Layer2Profile {
    let strace_log = fixture(strace_name);
    let dns_log = fixture(dns_name);
    let mut profile = parse_strace("import", &strace_log);
    profile.dns_queries.extend(parse_dns(&dns_log));
    profile
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

fn scenarios(findings: &[serde_json::Map<String, serde_json::Value>]) -> Vec<&str> {
    findings
        .iter()
        .filter_map(|f| f.get("scenario").and_then(|v| v.as_str()))
        .collect()
}

// ── D1: time-bomb (clock scenario) ──────────────────────────────────────────

#[test]
fn d1_timebomb_clock_scenario_flags_new_dns() {
    let baseline = load_profile("baseline_strace.log", "baseline_dns.log");
    let clock = load_profile("clock_strace.log", "clock_dns.log");

    let diff = diff_profiles(&baseline, &clock);
    // Shared baseline noise (.npmrc lookup, /etc/passwd read) must cancel out.
    assert!(
        diff.file_opens.is_empty(),
        "Expected no file_opens in diff (baseline noise should cancel); got: {:?}",
        diff.file_opens
    );
    // The mutated-only DNS query must survive the diff.
    assert_eq!(diff.dns_queries, vec!["evil.example.com".to_string()]);

    let findings = classify_scenario("D1", &diff);
    assert!(!findings.is_empty(), "Expected findings for D1 clock scenario");
    assert!(checks(&findings).iter().all(|&c| c == "timebomb"));
    assert!(scenarios(&findings).iter().all(|&s| s == "D1"));
    assert!(
        sev(&findings).iter().any(|&s| s == "SUSPECT" || s == "BLOCK"),
        "Expected SUSPECT or BLOCK; severities: {:?}",
        sev(&findings)
    );
}

// ── D2: environment-triggered (env scenario) ────────────────────────────────

#[test]
fn d2_env_triggered_scenario_flags_new_dns() {
    let baseline = load_profile("baseline_strace.log", "baseline_dns.log");
    let env = load_profile("env_strace.log", "env_dns.log");

    let diff = diff_profiles(&baseline, &env);
    assert!(
        diff.file_opens.is_empty(),
        "Expected no file_opens in diff (baseline noise should cancel); got: {:?}",
        diff.file_opens
    );
    assert_eq!(diff.dns_queries, vec!["evil.example.com".to_string()]);

    let findings = classify_scenario("D2", &diff);
    assert!(!findings.is_empty(), "Expected findings for D2 env scenario");
    assert!(checks(&findings).iter().all(|&c| c == "env_triggered"));
    assert!(scenarios(&findings).iter().all(|&s| s == "D2"));
    assert!(
        sev(&findings).iter().any(|&s| s == "SUSPECT" || s == "BLOCK"),
        "Expected SUSPECT or BLOCK; severities: {:?}",
        sev(&findings)
    );
}

// ── D3: trigger-on-use (fuzz scenario) ──────────────────────────────────────

#[test]
fn d3_trigger_on_use_fuzz_scenario_flags_new_dns() {
    // D3 diffs the fuzz run against the PLAIN-require baseline. Under plain
    // require the API-gated payload stays dormant (no DNS); the fuzz harness
    // enumerates and calls the exported `run()`, firing the DNS. The diff
    // isolates exactly that trigger-on-use behavior. (Merely calling a benign
    // function trips no classify rule, so there is nothing a "clean harness"
    // baseline would need to cancel.)
    let baseline = load_profile("baseline_strace.log", "baseline_dns.log");
    let fuzz = load_profile("fuzz_strace.log", "fuzz_dns.log");

    let diff = diff_profiles(&baseline, &fuzz);
    assert!(
        diff.file_opens.is_empty(),
        "Expected no file_opens in diff (baseline noise should cancel); got: {:?}",
        diff.file_opens
    );
    assert_eq!(diff.dns_queries, vec!["evil.example.com".to_string()]);

    let findings = classify_scenario("D3", &diff);
    assert!(!findings.is_empty(), "Expected findings for D3 fuzz scenario");
    assert!(checks(&findings).iter().all(|&c| c == "trigger_on_use"));
    assert!(scenarios(&findings).iter().all(|&s| s == "D3"));
    assert!(
        sev(&findings).iter().any(|&s| s == "SUSPECT" || s == "BLOCK"),
        "Expected SUSPECT or BLOCK; severities: {:?}",
        sev(&findings)
    );
}

// ── Baseline-noise cancellation (explicit, cross-scenario) ──────────────────

#[test]
fn shared_npmrc_and_passwd_noise_absent_from_all_diffs() {
    let baseline = load_profile("baseline_strace.log", "baseline_dns.log");
    let clock = load_profile("clock_strace.log", "clock_dns.log");
    let env = load_profile("env_strace.log", "env_dns.log");

    for (name, mutated) in [("clock", &clock), ("env", &env)] {
        let diff = diff_profiles(&baseline, mutated);
        assert!(
            !diff.file_opens.iter().any(|p| p.contains(".npmrc")),
            "{} diff must not contain .npmrc noise: {:?}",
            name,
            diff.file_opens
        );
        assert!(
            !diff.file_opens.iter().any(|p| p == "/etc/passwd"),
            "{} diff must not contain /etc/passwd noise: {:?}",
            name,
            diff.file_opens
        );
    }
}

// ── Benign control: identical baseline/mutated → no findings ───────────────

#[test]
fn identical_profiles_produce_no_findings() {
    let baseline = load_profile("baseline_strace.log", "baseline_dns.log");
    let baseline_again = load_profile("baseline_strace.log", "baseline_dns.log");

    let diff = diff_profiles(&baseline, &baseline_again);
    let findings = classify_scenario("D1", &diff);
    assert!(
        findings.is_empty(),
        "Identical baseline/mutated profiles must produce no findings; got: {:?}",
        findings
    );
}
