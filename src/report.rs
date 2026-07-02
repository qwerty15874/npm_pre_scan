// Risk-score aggregation: a pure function over existing layer `CheckResult`s.
//
// Does NOT change any layer's detection logic or `score_findings` — it only
// combines already-computed verdicts/scores/findings into a single
// `RiskReport` matching the schema documented in CLAUDE.md.

use crate::models::{CheckResult, Finding, Verdict};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Per-layer weight applied to `score/100` before the noisy-OR combination.
/// Layer 2 is down-weighted to 0.5 to offset its documented over-approximation
/// (npm's own `.npmrc`/`/etc/passwd` baseline reads tend to push it toward BLOCK).
pub const LAYER_WEIGHTS: [f64; 4] = [1.0, 1.0, 0.5, 1.0];

#[derive(Debug, Serialize, Deserialize)]
pub struct Detections {
    pub layer_0: Vec<String>,
    pub layer_1: Vec<String>,
    pub layer_2: Vec<String>,
    pub layer_3: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskReport {
    pub package: String,
    pub risk_score: f64,
    pub verdict: Verdict,
    pub detections: Detections,
}

/// Format a single finding as a short human-readable summary string.
/// `"{vector}: {check} ({message})"` when a `vector` field is present,
/// else `"{check}: {message}"`. Defensive — never panics on missing fields.
fn finding_summary(f: &Finding) -> String {
    let check = f.get("check").and_then(|v| v.as_str()).unwrap_or("unknown");
    let message = f.get("message").and_then(|v| v.as_str()).unwrap_or("");
    match f.get("vector").and_then(|v| v.as_str()) {
        Some(vector) => format!("{}: {} ({})", vector, check, message),
        None => format!("{}: {}", check, message),
    }
}

/// Worst-of verdict across the given results (BLOCK > SUSPECT > ERROR > PASS).
pub fn worst_verdict(results: &[&CheckResult]) -> Verdict {
    let mut worst = Verdict::Pass;
    for r in results {
        match r.verdict {
            Verdict::Block => return Verdict::Block,
            Verdict::Suspect => worst = Verdict::Suspect,
            Verdict::Error if worst == Verdict::Pass => worst = Verdict::Error,
            _ => {}
        }
    }
    worst
}

/// Combine up to four layer `CheckResult`s (Layer 0..3, in order) into a
/// single `RiskReport`. `layers[i] == None` means that layer did not run.
///
/// `risk_score` is a weighted noisy-OR over the layers that ran and are not
/// `Verdict::Error` (an Error layer — e.g. Docker absent — contributes
/// nothing to risk, since it observed nothing). `verdict` is the worst-of
/// across all layers that ran (including Error layers, so a Docker-absent
/// run is still visible in the verdict).
pub fn aggregate(package: &str, layers: [Option<&CheckResult>; 4]) -> RiskReport {
    let mut risk = 1.0_f64;
    let mut any_contributed = false;

    for (i, layer) in layers.iter().enumerate() {
        if let Some(result) = layer {
            if result.verdict == Verdict::Error {
                continue;
            }
            let p = (LAYER_WEIGHTS[i] * (result.score as f64) / 100.0).clamp(0.0, 1.0);
            risk *= 1.0 - p;
            any_contributed = true;
        }
    }

    let risk_score = if any_contributed {
        let raw = 1.0 - risk;
        (raw * 100.0).round() / 100.0
    } else {
        0.0
    };

    // Worst-of verdict across the layers that ran, with ONE exception: Layer 2
    // (index 2) is capped at SUSPECT. Layer 2 over-approximates toward BLOCK —
    // every package that runs `npm install` trips its sensitive_file_read rule
    // on npm's own baseline reads (.npmrc, /etc/passwd via os.homedir()). It is
    // the low-precision, already-down-weighted layer, so it may raise the
    // aggregate verdict to SUSPECT but must never ALONE force BLOCK; a BLOCK
    // must come from L0/L1/L3. L2 findings still appear in `detections` and
    // still contribute to `risk_score` unchanged — this is a verdict-only cap.
    let mut verdict = Verdict::Pass;
    for (i, layer) in layers.iter().enumerate() {
        if let Some(r) = layer {
            let v = if i == 2 && r.verdict == Verdict::Block {
                Verdict::Suspect
            } else {
                r.verdict.clone()
            };
            match v {
                Verdict::Block => {
                    verdict = Verdict::Block;
                    break;
                }
                Verdict::Suspect => verdict = Verdict::Suspect,
                Verdict::Error if verdict == Verdict::Pass => verdict = Verdict::Error,
                _ => {}
            }
        }
    }

    let summarize = |layer: &Option<&CheckResult>| -> Vec<String> {
        match layer {
            Some(result) => result.findings.iter().map(finding_summary).collect(),
            None => Vec::new(),
        }
    };

    let detections = Detections {
        layer_0: summarize(&layers[0]),
        layer_1: summarize(&layers[1]),
        layer_2: summarize(&layers[2]),
        layer_3: summarize(&layers[3]),
    };

    RiskReport {
        package: package.to_string(),
        risk_score,
        verdict,
        detections,
    }
}

/// Run the full local pipeline (Layer 1 + Layer 2 + Layer 3) on a package
/// directory and aggregate into one `RiskReport`. Layer 0 is skipped — a
/// local directory has no registry identity (Layer 0 is name/metadata based).
pub fn run_full_local(name: &str, dir: &Path) -> RiskReport {
    let l1 = crate::run_layer1_local(name, dir);
    let l2 = crate::run_layer2_local(name, dir);
    let l3 = crate::run_layer3_local(name, dir);

    aggregate(name, [None, Some(&l1), Some(&l2), Some(&l3)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};

    fn finding(check: &str, severity: &str, message: &str) -> Finding {
        let mut m = Map::new();
        m.insert("check".into(), Value::String(check.to_string()));
        m.insert("severity".into(), Value::String(severity.to_string()));
        m.insert("message".into(), Value::String(message.to_string()));
        m
    }

    fn finding_with_vector(vector: &str, check: &str, severity: &str, message: &str) -> Finding {
        let mut m = finding(check, severity, message);
        m.insert("vector".into(), Value::String(vector.to_string()));
        m
    }

    fn result(verdict: Verdict, score: u32, findings: Vec<Finding>) -> CheckResult {
        CheckResult {
            package: "pkg".to_string(),
            verdict,
            score,
            findings,
            note: None,
        }
    }

    #[test]
    fn confirmed_example_l0_15_l1_50_l2_100_l3_15() {
        let l0 = result(Verdict::Suspect, 15, vec![finding("age_check", "SUSPECT", "new package")]);
        let l1 = result(Verdict::Block, 50, vec![finding("obfuscation", "BLOCK", "eval+base64")]);
        let l2 = result(Verdict::Suspect, 100, vec![finding("sensitive_file_read", "BLOCK", "/etc/passwd")]);
        let l3 = result(Verdict::Suspect, 15, vec![finding("timebomb", "SUSPECT", "network after +90d")]);

        let report = aggregate("pkg", [Some(&l0), Some(&l1), Some(&l2), Some(&l3)]);

        assert_eq!(report.risk_score, 0.82);
        assert_eq!(report.verdict, Verdict::Block);
    }

    #[test]
    fn layer2_block_alone_capped_at_suspect() {
        // Layer 2 over-approximates (npm's own .npmrc//etc/passwd baseline reads),
        // so an L2-only BLOCK must NOT force the aggregate verdict to BLOCK.
        let l2 = result(Verdict::Block, 100, vec![finding("sensitive_file_read", "BLOCK", "/work/.npmrc")]);
        let report = aggregate("pkg", [None, None, Some(&l2), None]);
        assert_eq!(report.verdict, Verdict::Suspect);
        // The finding still surfaces in detections and still drives risk_score.
        assert_eq!(report.detections.layer_2, vec!["sensitive_file_read: /work/.npmrc"]);
        assert_eq!(report.risk_score, 0.5); // 0.5 weight * 100/100
    }

    #[test]
    fn layer1_block_still_forces_aggregate_block() {
        // The cap is L2-specific: an L1 BLOCK still forces the aggregate to BLOCK.
        let l1 = result(Verdict::Block, 50, vec![finding("obfuscation", "BLOCK", "eval+base64")]);
        let report = aggregate("pkg", [None, Some(&l1), None, None]);
        assert_eq!(report.verdict, Verdict::Block);
    }

    #[test]
    fn all_none_yields_zero_risk_and_pass() {
        let report = aggregate("pkg", [None, None, None, None]);
        assert_eq!(report.risk_score, 0.0);
        assert_eq!(report.verdict, Verdict::Pass);
        assert!(report.detections.layer_0.is_empty());
        assert!(report.detections.layer_1.is_empty());
        assert!(report.detections.layer_2.is_empty());
        assert!(report.detections.layer_3.is_empty());
    }

    #[test]
    fn single_full_weight_layer_score_50_yields_half() {
        let l1 = result(Verdict::Suspect, 50, vec![]);
        let report = aggregate("pkg", [None, Some(&l1), None, None]);
        assert_eq!(report.risk_score, 0.5);
        assert_eq!(report.verdict, Verdict::Suspect);
    }

    #[test]
    fn error_layer_contributes_nothing_to_risk() {
        let l1 = result(Verdict::Suspect, 50, vec![]);
        let l2 = result(Verdict::Error, 0, vec![]);
        let report = aggregate("pkg", [None, Some(&l1), Some(&l2), None]);
        // Same as the single-layer case: L2's Error contributes no risk.
        assert_eq!(report.risk_score, 0.5);
        // Verdict is still worst-of INCLUDING the Error layer's presence,
        // but Suspect (from L1) outranks Error, so verdict stays Suspect.
        assert_eq!(report.verdict, Verdict::Suspect);
    }

    #[test]
    fn finding_summary_with_vector() {
        let f = finding_with_vector("D1", "timebomb", "SUSPECT", "network after +90d");
        assert_eq!(finding_summary(&f), "D1: timebomb (network after +90d)");
    }

    #[test]
    fn finding_summary_without_vector() {
        let f = finding("obfuscation", "BLOCK", "eval+base64");
        assert_eq!(finding_summary(&f), "obfuscation: eval+base64");
    }

    #[test]
    fn detections_map_findings_per_layer() {
        let l0 = result(Verdict::Suspect, 15, vec![finding_with_vector("A1", "typosquat", "SUSPECT", "edit_dist=1")]);
        let l1 = result(Verdict::Block, 50, vec![finding("obfuscation", "BLOCK", "eval+base64")]);

        let report = aggregate("pkg", [Some(&l0), Some(&l1), None, None]);

        assert_eq!(report.detections.layer_0, vec!["A1: typosquat (edit_dist=1)"]);
        assert_eq!(report.detections.layer_1, vec!["obfuscation: eval+base64"]);
        assert!(report.detections.layer_2.is_empty());
        assert!(report.detections.layer_3.is_empty());
    }
}
