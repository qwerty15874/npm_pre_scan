// Risk-score aggregation: a pure function over existing layer `CheckResult`s.
//
// Does NOT change any layer's detection logic or `score_findings` — it only
// combines already-computed verdicts/scores/findings into a single
// `RiskReport` matching the schema documented in CLAUDE.md.

use crate::models::{CheckResult, Finding, Verdict};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Per-layer weight applied to `score/100` before the noisy-OR combination.
/// Layer 2 now runs at full weight: baseline subtraction (real-vs-baseline
/// diffing per phase, see `layer2::mod::run_layer2_local`) cancels npm's own
/// `.npmrc`/`/etc/passwd` toolchain reads at the source, so Layer 2 findings
/// are package-attributable and no longer need down-weighting.
pub const LAYER_WEIGHTS: [f64; 4] = [1.0, 1.0, 1.0, 1.0];

#[derive(Debug, Serialize, Deserialize)]
pub struct Detections {
    pub layer_0: Vec<String>,
    pub layer_1: Vec<String>,
    pub layer_2: Vec<String>,
    pub layer_3: Vec<String>,
}

/// Per-layer execution status, so a JSON consumer can tell "empty because
/// clean" from "empty because it didn't run." Serializes to lowercase
/// strings matching the variant names.
///
/// - `Ran`      — the layer executed and produced a non-`Error` `CheckResult`
///   (its `detections` list may still be empty, meaning clean).
/// - `Error`    — the layer executed but returned `Verdict::Error` (e.g.
///   Docker absent, a missing/unreadable log).
/// - `NotRun`   — the layer was never attempted (`None` was passed to
///   `aggregate`), e.g. Layer 0 in `run_full_local` (no registry identity),
///   or Layer 2/3 in the fast name-scan path (Docker not invoked).
/// - `Skipped`  — the layer was intentionally not attempted because an
///   earlier layer's result made it unnecessary (early-exit optimization),
///   e.g. Layer 1 skipped in the name-scan path when Layer 0 is BLOCK. This
///   is distinct from `NotRun`: the caller knows *why* it didn't run and
///   must say so explicitly (see `RiskReport::mark_skipped`) — `aggregate`
///   cannot infer "skipped" from a bare `None`, since a `None` is
///   indistinguishable from "not applicable" or "not implemented for this
///   path" without that caller context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerStatus {
    Ran,
    Error,
    NotRun,
    Skipped,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RiskReport {
    pub package: String,
    pub risk_score: f64,
    pub verdict: Verdict,
    pub detections: Detections,
    /// Execution status for Layer 0..3, in order. See `LayerStatus`.
    pub layer_status: [LayerStatus; 4],
    /// Per-layer evidence lines (see `layer3::diff::evidence_lines`), flattened
    /// across all of that layer's findings — the exact new DNS/connect/file/
    /// process events behind each layer's detections, in the same per-layer
    /// shape as `detections`. Empty when a layer has no findings with
    /// evidence attached (e.g. Layer 0/1's static findings currently carry no
    /// `"evidence"` field — only Layer 2/3's diff-based findings do).
    /// Always populated in JSON; human output renders it only under
    /// `--verbose` (see `main::print_report`).
    pub evidence: Detections,
}

impl RiskReport {
    /// Override the status of layer `index` (0..3) to `Skipped`. For use by
    /// callers that know a layer was intentionally not attempted because an
    /// earlier layer's result made it unnecessary (e.g. the name-scan path
    /// in `main.rs` skipping Layer 1 when Layer 0 is BLOCK) — `aggregate`
    /// itself only ever sees a bare `None` for that layer and has no way to
    /// distinguish "skipped due to early-exit" from "not run for any other
    /// reason", so the caller must say so explicitly after the fact.
    ///
    /// No-op (silently ignored) if `index` is out of range, since this is a
    /// visibility-only annotation and must never panic the caller.
    pub fn mark_skipped(&mut self, index: usize) {
        if let Some(status) = self.layer_status.get_mut(index) {
            *status = LayerStatus::Skipped;
        }
    }
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

/// Extract a single finding's `"evidence"` array (see
/// `layer3::diff::evidence_lines`) as owned strings. Findings without an
/// `"evidence"` field (e.g. Layer 0/1's static checks) yield an empty Vec —
/// defensive, never panics.
fn finding_evidence(f: &Finding) -> Vec<String> {
    f.get("evidence")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
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

    // Worst-of verdict across the layers that ran. Layer 2 now propagates its
    // real verdict like every other layer — baseline subtraction (see
    // `LAYER_WEIGHTS` doc comment above) removed the over-approximation that
    // previously justified capping an L2-only BLOCK down to SUSPECT, so a
    // package-attributable L2 BLOCK now forces the aggregate to BLOCK too.
    let mut verdict = Verdict::Pass;
    for r in layers.iter().flatten() {
        match r.verdict {
            Verdict::Block => {
                verdict = Verdict::Block;
                break;
            }
            Verdict::Suspect => verdict = Verdict::Suspect,
            Verdict::Error if verdict == Verdict::Pass => verdict = Verdict::Error,
            _ => {}
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

    // Flatten each layer's per-finding evidence into one list per layer,
    // mirroring `detections`'s shape. A layer with no findings, or whose
    // findings carry no `"evidence"` field, yields an empty Vec.
    let evidence_summarize = |layer: &Option<&CheckResult>| -> Vec<String> {
        match layer {
            Some(result) => result.findings.iter().flat_map(finding_evidence).collect(),
            None => Vec::new(),
        }
    };

    let evidence = Detections {
        layer_0: evidence_summarize(&layers[0]),
        layer_1: evidence_summarize(&layers[1]),
        layer_2: evidence_summarize(&layers[2]),
        layer_3: evidence_summarize(&layers[3]),
    };

    // Derive per-layer status from what `aggregate` can see directly: `Some`
    // non-Error -> Ran, `Some` Error -> Error, `None` -> NotRun. `aggregate`
    // has no way to distinguish "not run because skipped by an earlier
    // layer's early-exit" from a bare `None` — callers that know that context
    // (e.g. the name-scan path skipping Layer 1 on an L0 BLOCK) must call
    // `RiskReport::mark_skipped` afterward to upgrade `NotRun` to `Skipped`.
    let status_for = |layer: &Option<&CheckResult>| -> LayerStatus {
        match layer {
            Some(result) if result.verdict == Verdict::Error => LayerStatus::Error,
            Some(_) => LayerStatus::Ran,
            None => LayerStatus::NotRun,
        }
    };
    let layer_status = [
        status_for(&layers[0]),
        status_for(&layers[1]),
        status_for(&layers[2]),
        status_for(&layers[3]),
    ];

    RiskReport {
        package: package.to_string(),
        risk_score,
        verdict,
        detections,
        layer_status,
        evidence,
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

/// Run the full pipeline (Layer 0 + Layer 1 + Layer 2 + Layer 3) on an npm
/// package fetched from the registry by name, and aggregate into one
/// `RiskReport`. This is the "unified single tool" path: unlike
/// `run_full_local` (which requires an already-extracted local dir and skips
/// Layer 0), this resolves the name against the registry, runs Layer 0
/// metadata checks, downloads the tarball ONCE, and reuses the same extracted
/// `package/` dir for Layer 1 (static), Layer 2 (dynamic), and Layer 3
/// (condition mutation) — avoiding a second download.
///
/// Failure handling (never panics):
/// - Package not found on the registry → `Verdict::Error` report with a note.
/// - Tarball URL missing from registry metadata, or download/extraction
///   fails → `Verdict::Error` report with a note. Layer 0's own result (which
///   did succeed) is still included, so a typosquat/namespace BLOCK from
///   Layer 0 is not lost just because the tarball couldn't be fetched.
pub fn run_full_registry(name: &str) -> RiskReport {
    let l0 = crate::run_layer0(
        name,
        &crate::typosquat::load_top_packages(),
        &crate::namespace::load_top_scoped_packages(),
    );

    let info = match crate::registry::get_package_info(name) {
        Some(info) => info,
        None => {
            let err = CheckResult {
                package: name.to_string(),
                verdict: Verdict::Error,
                score: 0,
                findings: vec![],
                note: Some(format!("Package '{}' not found on the npm registry", name)),
            };
            return aggregate(name, [Some(&l0), Some(&err), None, None]);
        }
    };

    let tarball_url = match crate::layer1::tarball::get_tarball_url(&info) {
        Some(url) => url,
        None => {
            let err = CheckResult {
                package: name.to_string(),
                verdict: Verdict::Error,
                score: 0,
                findings: vec![],
                note: Some("Could not determine tarball URL from registry metadata".to_string()),
            };
            return aggregate(name, [Some(&l0), Some(&err), None, None]);
        }
    };

    let tmp = match crate::layer1::tarball::download_and_extract(&tarball_url) {
        Ok(t) => t,
        Err(e) => {
            let err = CheckResult {
                package: name.to_string(),
                verdict: Verdict::Error,
                score: 0,
                findings: vec![],
                note: Some(format!("Tarball download/extraction failed: {}", e)),
            };
            return aggregate(name, [Some(&l0), Some(&err), None, None]);
        }
    };

    // npm tarballs unpack under a `package/` subdir.
    let pkgdir = tmp.path().join("package");

    let l1 = crate::layer1::run_layer1_extracted(name, &pkgdir, Some(&info));
    let l2 = crate::run_layer2_local(name, &pkgdir);
    let l3 = crate::run_layer3_local(name, &pkgdir);

    // `tmp` (the TempDir) is still in scope here and is dropped (cleaned up)
    // only after l1/l2/l3 have all finished reading from `pkgdir`.
    aggregate(name, [Some(&l0), Some(&l1), Some(&l2), Some(&l3)])
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

    fn finding_with_evidence(check: &str, severity: &str, message: &str, evidence: &[&str]) -> Finding {
        let mut m = finding(check, severity, message);
        m.insert(
            "evidence".into(),
            Value::Array(evidence.iter().map(|s| Value::String(s.to_string())).collect()),
        );
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
        // L2 weight is now 1.0 (baseline subtraction removed the over-approximation
        // that used to justify down-weighting), so an L2 score of 100 contributes
        // p=1.0 and zeroes the noisy-OR product: 1 - .85*.50*0*.85 = 1.0.
        let l0 = result(Verdict::Suspect, 15, vec![finding("age_check", "SUSPECT", "new package")]);
        let l1 = result(Verdict::Block, 50, vec![finding("obfuscation", "BLOCK", "eval+base64")]);
        let l2 = result(Verdict::Suspect, 100, vec![finding("sensitive_file_read", "BLOCK", "/etc/passwd")]);
        let l3 = result(Verdict::Suspect, 15, vec![finding("timebomb", "SUSPECT", "network after +90d")]);

        let report = aggregate("pkg", [Some(&l0), Some(&l1), Some(&l2), Some(&l3)]);

        assert_eq!(report.risk_score, 1.0);
        assert_eq!(report.verdict, Verdict::Block);
    }

    #[test]
    fn layer2_block_alone_forces_block() {
        // Baseline subtraction makes Layer 2 findings package-attributable, so
        // an L2-only BLOCK now forces the aggregate verdict to BLOCK, same as
        // every other layer — the old SUSPECT-cap is gone.
        let l2 = result(Verdict::Block, 100, vec![finding("sensitive_file_read", "BLOCK", "/work/secrets.json")]);
        let report = aggregate("pkg", [None, None, Some(&l2), None]);
        assert_eq!(report.verdict, Verdict::Block);
        // The finding still surfaces in detections and still drives risk_score.
        assert_eq!(report.detections.layer_2, vec!["sensitive_file_read: /work/secrets.json"]);
        assert_eq!(report.risk_score, 1.0); // 1.0 weight * 100/100
    }

    #[test]
    fn layer1_block_still_forces_aggregate_block() {
        // An L1 BLOCK still forces the aggregate to BLOCK (unaffected by the L2 cap removal).
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

    // ── 4b: layer_status ────────────────────────────────────────────────────

    #[test]
    fn layer_status_all_none_is_not_run() {
        let report = aggregate("pkg", [None, None, None, None]);
        assert_eq!(
            report.layer_status,
            [LayerStatus::NotRun, LayerStatus::NotRun, LayerStatus::NotRun, LayerStatus::NotRun]
        );
    }

    #[test]
    fn layer_status_some_non_error_is_ran() {
        let l0 = result(Verdict::Pass, 0, vec![]);
        let l1 = result(Verdict::Suspect, 15, vec![]);
        let report = aggregate("pkg", [Some(&l0), Some(&l1), None, None]);
        assert_eq!(report.layer_status[0], LayerStatus::Ran);
        assert_eq!(report.layer_status[1], LayerStatus::Ran);
        assert_eq!(report.layer_status[2], LayerStatus::NotRun);
        assert_eq!(report.layer_status[3], LayerStatus::NotRun);
    }

    #[test]
    fn layer_status_error_verdict_is_error_status() {
        let l2 = result(Verdict::Error, 0, vec![finding("docker", "INFO", "Docker required")]);
        let report = aggregate("pkg", [None, None, Some(&l2), None]);
        assert_eq!(report.layer_status[2], LayerStatus::Error);
        // Ran/NotRun for the rest, unaffected.
        assert_eq!(report.layer_status[0], LayerStatus::NotRun);
        assert_eq!(report.layer_status[1], LayerStatus::NotRun);
        assert_eq!(report.layer_status[3], LayerStatus::NotRun);
    }

    #[test]
    fn mark_skipped_overrides_not_run_to_skipped() {
        // Simulates the name-scan path: L0 BLOCK -> L1 deliberately not
        // attempted -> caller (main.rs) marks it Skipped after aggregate().
        let l0 = result(Verdict::Block, 50, vec![finding("typosquat", "BLOCK", "edit_dist=1")]);
        let mut report = aggregate("pkg", [Some(&l0), None, None, None]);
        assert_eq!(report.layer_status[1], LayerStatus::NotRun); // before the override
        report.mark_skipped(1);
        assert_eq!(report.layer_status[1], LayerStatus::Skipped);
        // Untouched indices and the rest of the report are unaffected.
        assert_eq!(report.layer_status[0], LayerStatus::Ran);
        assert_eq!(report.verdict, Verdict::Block);
    }

    #[test]
    fn mark_skipped_out_of_range_is_a_silent_no_op() {
        let mut report = aggregate("pkg", [None, None, None, None]);
        report.mark_skipped(99); // must not panic
        assert_eq!(
            report.layer_status,
            [LayerStatus::NotRun, LayerStatus::NotRun, LayerStatus::NotRun, LayerStatus::NotRun]
        );
    }

    #[test]
    fn layer_status_serializes_to_lowercase_strings() {
        let l0 = result(Verdict::Pass, 0, vec![]);
        let l2 = result(Verdict::Error, 0, vec![]);
        let mut report = aggregate("pkg", [Some(&l0), None, Some(&l2), None]);
        report.mark_skipped(1);
        let json = serde_json::to_value(&report).unwrap();
        let statuses = json.get("layer_status").and_then(|v| v.as_array()).unwrap();
        assert_eq!(statuses[0].as_str(), Some("ran"));
        assert_eq!(statuses[1].as_str(), Some("skipped"));
        assert_eq!(statuses[2].as_str(), Some("error"));
        assert_eq!(statuses[3].as_str(), Some("not_run"));
    }

    // ── 4a: evidence ────────────────────────────────────────────────────────

    #[test]
    fn evidence_flattened_per_layer_from_findings() {
        let l2 = result(
            Verdict::Block,
            100,
            vec![finding_with_evidence(
                "sensitive_file_read",
                "BLOCK",
                "/etc/passwd",
                &["file:/etc/passwd", "proc:/usr/bin/id"],
            )],
        );
        let report = aggregate("pkg", [None, None, Some(&l2), None]);
        assert_eq!(
            report.evidence.layer_2,
            vec!["file:/etc/passwd".to_string(), "proc:/usr/bin/id".to_string()]
        );
        assert!(report.evidence.layer_0.is_empty());
        assert!(report.evidence.layer_1.is_empty());
        assert!(report.evidence.layer_3.is_empty());
    }

    #[test]
    fn evidence_empty_when_finding_has_no_evidence_field() {
        // Layer 0/1 static findings currently carry no "evidence" field.
        let l0 = result(Verdict::Suspect, 15, vec![finding("age_check", "SUSPECT", "new package")]);
        let report = aggregate("pkg", [Some(&l0), None, None, None]);
        assert!(report.evidence.layer_0.is_empty());
    }

    #[test]
    fn evidence_concatenates_across_multiple_findings_in_one_layer() {
        let l3 = result(
            Verdict::Suspect,
            15,
            vec![
                finding_with_evidence("timebomb", "SUSPECT", "a", &["dns:evil1.example.com"]),
                finding_with_evidence("timebomb", "SUSPECT", "b", &["dns:evil2.example.com"]),
            ],
        );
        let report = aggregate("pkg", [None, None, None, Some(&l3)]);
        assert_eq!(
            report.evidence.layer_3,
            vec!["dns:evil1.example.com".to_string(), "dns:evil2.example.com".to_string()]
        );
    }
}
