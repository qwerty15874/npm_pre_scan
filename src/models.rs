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
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}
