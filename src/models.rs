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
