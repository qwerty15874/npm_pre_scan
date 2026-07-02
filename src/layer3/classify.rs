// Layer 3: scenario classification — thin wrapper around the existing Layer 2
// classifier. Reuses `crate::layer2::classify::classify` for all severity
// logic (egress hosts, sensitive reads, side effects, tunneling, native
// addons) so Layer 2 and Layer 3 never disagree about what counts as bad.
// This module only re-tags each Finding with the Layer 3 scenario metadata.

use serde_json::{json, Value};

use crate::layer2::classify::classify;
use crate::layer2::profile::Layer2Profile;
use crate::models::Finding;

/// Map a scenario id to its Layer 3 check name (used to replace the reused
/// `check` field so reports read as Layer 3 findings, not raw Layer 2 ones).
fn check_name_for(scenario: &str) -> &'static str {
    match scenario {
        "D1" => "timebomb",
        "D2" => "env_triggered",
        "D3" => "trigger_on_use",
        _ => "condition_mutation",
    }
}

/// Classify a scenario's diff profile (mutated-only events vs baseline) into
/// Layer 3 Findings. Reuses `classify::classify` for severity, then tags each
/// Finding with `layer: 3`, `scenario`, and a Layer-3-specific `check` name.
///
/// Empty diff (no new behavior under mutation) → empty vec, i.e. no finding.
pub fn classify_scenario(scenario: &str, diff: &Layer2Profile) -> Vec<Finding> {
    let mut findings = classify(diff);
    let check_name = check_name_for(scenario);

    for f in &mut findings {
        f.insert("layer".to_string(), json!(3));
        f.insert("scenario".to_string(), Value::String(scenario.to_string()));
        f.insert("check".to_string(), Value::String(check_name.to_string()));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(f: &Finding) -> &str {
        f.get("severity").and_then(|v| v.as_str()).unwrap_or("")
    }
    fn check(f: &Finding) -> &str {
        f.get("check").and_then(|v| v.as_str()).unwrap_or("")
    }
    fn scenario_of(f: &Finding) -> &str {
        f.get("scenario").and_then(|v| v.as_str()).unwrap_or("")
    }

    #[test]
    fn empty_diff_produces_no_findings() {
        let diff = Layer2Profile {
            phase: "import".to_string(),
            ..Default::default()
        };
        let findings = classify_scenario("D1", &diff);
        assert!(findings.is_empty());
    }

    #[test]
    fn d1_timebomb_dns_tagged_and_blocked() {
        let mut diff = Layer2Profile {
            phase: "import".to_string(),
            ..Default::default()
        };
        diff.dns_queries.push("evil.example.com".to_string());
        let findings = classify_scenario("D1", &diff);
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| check(f) == "timebomb"));
        assert!(findings.iter().all(|f| scenario_of(f) == "D1"));
        assert!(findings.iter().all(|f| f.get("layer").and_then(|v| v.as_i64()) == Some(3)));
        // C1 import-side-effect rule fires as SUSPECT for a bare network connect/dns.
        assert!(findings.iter().any(|f| sev(f) == "SUSPECT" || sev(f) == "BLOCK"));
    }

    #[test]
    fn d2_env_triggered_check_name() {
        let mut diff = Layer2Profile {
            phase: "import".to_string(),
            ..Default::default()
        };
        diff.dns_queries.push("evil.example.com".to_string());
        let findings = classify_scenario("D2", &diff);
        assert!(findings.iter().all(|f| check(f) == "env_triggered"));
        assert!(findings.iter().all(|f| scenario_of(f) == "D2"));
    }

    #[test]
    fn d3_trigger_on_use_check_name() {
        let mut diff = Layer2Profile {
            phase: "import".to_string(),
            ..Default::default()
        };
        diff.dns_queries.push("evil.example.com".to_string());
        let findings = classify_scenario("D3", &diff);
        assert!(findings.iter().all(|f| check(f) == "trigger_on_use"));
        assert!(findings.iter().all(|f| scenario_of(f) == "D3"));
    }
}
