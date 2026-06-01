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
