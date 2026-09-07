use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A single finding from a check. Always contains "check", "severity", "message".
pub type Finding = Map<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Suspect,
    Block,
    Error,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Pass => write!(f, "PASS"),
            Verdict::Suspect => write!(f, "SUSPECT"),
            Verdict::Block => write!(f, "BLOCK"),
            Verdict::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResult {
    pub package: String,
    pub verdict: Verdict,
    /// Cumulative risk score (0–100), derived from finding severities.
    pub score: u32,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Worst-of-severity verdict over a finding set: BLOCK if any finding is BLOCK,
/// SUSPECT if any is SUSPECT and none is BLOCK, otherwise PASS.
///
/// **INFO never raises a verdict.** That is load-bearing, not incidental:
/// `typosquat::check_typosquat` returns INFO on an *exact* match against the
/// popular list, so every legitimate package in the benign corpus carries an A1
/// INFO finding. Counting those would report a ~100% false-positive rate that is
/// purely an artifact of the scoring rule.
///
/// This was four separate copies until v19 — `checker.rs`, `layer1/mod.rs`, and
/// inline in `layer2/mod.rs` and `layer3/mod.rs` — plus a fifth, unused
/// `report::worst_verdict`. They agreed, but nothing made them agree, and v19
/// changes severity semantics across several checks at once.
pub fn verdict_from_findings(findings: &[Finding]) -> Verdict {
    let sev = |f: &Finding| -> Option<String> {
        f.get("severity")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    if findings.iter().any(|f| sev(f).as_deref() == Some("BLOCK")) {
        return Verdict::Block;
    }
    if findings.iter().any(|f| sev(f).as_deref() == Some("SUSPECT")) {
        return Verdict::Suspect;
    }
    Verdict::Pass
}

/// Whether a finding is an *accusation* rather than a diagnostic note.
///
/// Findings whose severity is INFO are diagnostic notes, not accusations, and
/// must never turn an entry into a positive prediction. This matters concretely:
/// `typosquat::check_typosquat` returns an INFO finding for an *exact* match
/// against the popular-package list, so every legitimate parent package in the
/// benign arm carries an A1 INFO finding. Counting those as positives would
/// report a ~100% false-positive rate that is purely an artifact of the scoring
/// rule.
///
/// Lives here, beside [`verdict_from_findings`], because two independent
/// consumers must agree on it: the eval harness (`eval::record`) when scoring a
/// prediction, and `report::finish_scan` when deciding whether a finding is
/// corroborated. v19 collapsed four copies of the verdict rule for exactly this
/// reason — they agreed, but nothing made them agree.
pub fn is_accusing(f: &Finding) -> bool {
    matches!(
        f.get("severity").and_then(|v| v.as_str()),
        Some("BLOCK") | Some("SUSPECT")
    )
}

/// The `capability` key marks a finding as evidence of a *capability* rather
/// than an accusation: something a package can do, which plenty of legitimate
/// packages also do.
///
/// ## Why this tier exists (v19 — measured)
///
/// Comparing arm D (499 real malicious) against arm F (27 legitimate) showed
/// several Layer 1 rules carry no discriminating information at all, and two
/// that are *inverted* — they fire more often on legitimate packages than on
/// malware:
///
/// | rule | malicious | benign | lift |
/// |---|---|---|---|
/// | `suspicious_strings` on `process.env` | 36.3% | **44.4%** | 0.82 |
/// | `dynamic_require` | 7.6% | **14.8%** | 0.51 |
/// | `obfuscation` long-base64 literal | 8.6% | 7.4% | 1.16 |
/// | `maintainer` (A3) | — | 11.1% | 0 true positives, ever |
///
/// Reading `process.env` is what configuration *is*; a bundler emits
/// `require(variable)` by construction. As standalone accusations these are
/// noise, and `process.env` alone reached 12 of the 27 legitimate packages —
/// the single largest false-positive source in the tool.
///
/// They are not worthless, though: a package that reads the environment *and*
/// resolves modules dynamically *and* ships an encoded blob is a different
/// proposition from one that merely does any of those. So a capability finding
/// is INFO on its own and `report::finish_scan` escalates a package carrying
/// [`CAPABILITY_ESCALATION_THRESHOLD`] distinct capabilities to SUSPECT.
///
/// Count **distinct capability ids, not findings**: `obfuscation` and
/// `suspicious_strings` emit one finding per file, so counting findings would
/// let a single capability in three files trip a three-capability threshold.
pub const CAPABILITY_KEY: &str = "capability";

/// Distinct capabilities that must co-occur before a package is escalated.
///
/// Calibrated, not chosen: at 2 the arm D recall floor holds but arm F keeps
/// more false positives; at 3 the measured operating point is 87.4% recall /
/// 48.1% FPR. Raising it further stops recovering the malicious packages that
/// the demotions would otherwise lose.
pub const CAPABILITY_ESCALATION_THRESHOLD: usize = 3;

/// Distinct `capability` ids present in a finding set.
pub fn capabilities_of(findings: &[Finding]) -> std::collections::BTreeSet<String> {
    findings
        .iter()
        .filter_map(|f| f.get(CAPABILITY_KEY).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .collect()
}

/// Risk weight contributed by a single finding of the given severity.
fn severity_weight(severity: &str) -> u32 {
    match severity {
        "BLOCK" => 50,
        "SUSPECT" => 15,
        "INFO" => 2,
        _ => 0,
    }
}

/// Sum finding severities into a cumulative risk score, capped at 100.
pub fn score_findings(findings: &[Finding]) -> u32 {
    let total: u32 = findings
        .iter()
        .map(|f| f.get("severity").and_then(|v| v.as_str()).unwrap_or(""))
        .map(severity_weight)
        .sum();
    total.min(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: &str) -> Finding {
        let mut m = Map::new();
        m.insert("severity".into(), Value::String(severity.to_string()));
        m
    }

    #[test]
    fn severity_weights() {
        assert_eq!(severity_weight("BLOCK"), 50);
        assert_eq!(severity_weight("SUSPECT"), 15);
        assert_eq!(severity_weight("INFO"), 2);
        assert_eq!(severity_weight("unknown"), 0);
    }

    #[test]
    fn score_sums_and_caps() {
        assert_eq!(score_findings(&[]), 0);
        assert_eq!(score_findings(&[finding("SUSPECT"), finding("INFO")]), 17);
        // 3 BLOCKs = 150, capped at 100
        assert_eq!(
            score_findings(&[finding("BLOCK"), finding("BLOCK"), finding("BLOCK")]),
            100
        );
    }

    #[test]
    fn verdict_display() {
        assert_eq!(Verdict::Pass.to_string(), "PASS");
        assert_eq!(Verdict::Suspect.to_string(), "SUSPECT");
        assert_eq!(Verdict::Block.to_string(), "BLOCK");
        assert_eq!(Verdict::Error.to_string(), "ERROR");
    }
}
