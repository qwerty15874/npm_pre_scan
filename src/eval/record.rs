// Per-entry result records and the output writers.
//
// A `RiskReport` is what the tool tells a user; an `EvalRecord` is what an
// experiment needs. The two differ in three ways that matter:
//
//   1. `report::aggregate` discards `CheckResult.note`, which is the only place
//      the "package not found on the registry" fact survives.
//   2. It flattens findings to `"{vector}: {check} ({message})"` strings, so
//      severity and vector cannot be recovered without re-parsing prose.
//   3. It has no notion of ground truth, so nothing can be scored against it.
//
// So an `EvalRecord` keeps the raw `Finding` maps, the per-layer notes, the
// manifest's ground truth, and the derived classification side by side.
//
// Everything here is pure: writers take `impl Write`, so the tests exercise them
// against a `Vec<u8>` with no filesystem.

use serde::{Deserialize, Serialize};
use std::io::Write;

use crate::eval::corpus::CorpusEntry;
use crate::models::{Finding, Verdict};
use crate::report::LayerStatus;

/// Findings whose severity is INFO are diagnostic notes, not accusations, and
/// must never turn an entry into a positive prediction. This matters concretely:
/// `typosquat::check_typosquat` returns an INFO finding for an *exact* match
/// against the popular-package list, so every legitimate parent package in the
/// benign arm carries an A1 INFO finding. Counting those as positives would
/// report a ~100% false-positive rate that is purely an artifact of the scoring
/// rule.
fn is_accusing(f: &Finding) -> bool {
    matches!(
        f.get("severity").and_then(|v| v.as_str()),
        Some("BLOCK") | Some("SUSPECT")
    )
}

fn finding_str<'a>(f: &'a Finding, key: &str) -> Option<&'a str> {
    f.get(key).and_then(|v| v.as_str())
}

/// How an entry's prediction scored against its ground-truth label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    TruePositive,
    FalsePositive,
    TrueNegative,
    FalseNegative,
    /// Labelled malicious, predicted clean — but the corpus itself cannot
    /// deliver the malicious content, so this is not a detection failure.
    ///
    /// Applies to `kind=holder`: npm replaced the package with a security-holding
    /// stub, and where the original version numbers survive the content was
    /// republished defanged (verified 2026-07-30: the payload is literally
    /// `console.log('this package is no longer dangerous')`). A content-layer
    /// PASS on such a package is *correct*. Counted separately and kept out of
    /// recall's denominator so the artefact cannot masquerade as a miss —
    /// reporting it as an FN would understate recall by however many packages
    /// npm happened to take down.
    ArtifactFalseNegative,
    /// A layer errored, the registry failed, or the scan timed out. Excluded
    /// from all four confusion cells: we did not observe the package, so we
    /// learned nothing about the detector.
    Error,
    /// Not attempted — e.g. a `dir` entry whose directory is absent (the
    /// `dummy_packages/` tree is gitignored, so a fresh clone has none).
    Skipped,
}

impl Classification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Classification::TruePositive => "TP",
            Classification::FalsePositive => "FP",
            Classification::TrueNegative => "TN",
            Classification::FalseNegative => "FN",
            Classification::ArtifactFalseNegative => "ARTIFACT_FN",
            Classification::Error => "ERROR",
            Classification::Skipped => "SKIPPED",
        }
    }
}

/// Why an entry produced (or failed to produce) a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Scanned,
    /// A `dir` or `sample` entry whose content could not be located.
    SkippedMissing,
    /// The registry answered 404 — the package is genuinely gone.
    RegistryNotFound,
    /// The registry request failed (timeout, 5xx, malformed JSON). Distinct from
    /// `RegistryNotFound` on purpose: collapsing the two would let a transient
    /// network blip masquerade as "package removed" and silently corrupt recall.
    RegistryFailed,
    /// A layer exceeded its wall-clock budget.
    Timeout,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Scanned => "scanned",
            Outcome::SkippedMissing => "skipped_missing",
            Outcome::RegistryNotFound => "registry_not_found",
            Outcome::RegistryFailed => "registry_failed",
            Outcome::Timeout => "timeout",
        }
    }
}

/// Run-level provenance, so a result set can be reproduced or ruled out later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunProvenance {
    pub tool_version: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub eval_mode: String,
    pub manifests: Vec<String>,
    pub entry_count: usize,
    /// `None` means Docker was absent, which is itself a fact about the run.
    pub docker_version: Option<String>,
    pub ptrace_probe: String,
    pub docker_timeout_secs: Option<u64>,
    /// Whether the Layer 0 comparison lists were live-refreshed. When true the
    /// run is NOT reproducible, because the npm search API's results drift.
    pub top_list_refreshed: bool,
    /// Pins the exact Layer 0 corpus used, so an A1 result can be reproduced
    /// even after `data/top_packages.txt` changes.
    pub top_packages_len: usize,
    pub top_scoped_len: usize,
    pub host_os: String,
}

/// One layer's outcome, preserving what `RiskReport` drops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerRecord {
    pub status: LayerStatus,
    pub verdict: Option<Verdict>,
    pub score: Option<u32>,
    /// The `CheckResult.note` that `report::aggregate` throws away — the only
    /// carrier of "not found on the registry", "Docker required", and the
    /// name-only-mode marker.
    pub note: Option<String>,
    /// Raw finding maps, not summary strings. Retains `severity`, `vector`, and
    /// per-check extras (`closest`/`distance` on A1, `matched_popular`/
    /// `triggered_affix` on A4) that the weakness analysis needs to tell a
    /// threshold miss apart from a comparison-list gap.
    pub findings: Vec<Finding>,
    pub evidence_count: usize,
    pub ms: Option<u64>,
}

impl LayerRecord {
    pub fn not_run() -> Self {
        LayerRecord {
            status: LayerStatus::NotRun,
            verdict: None,
            score: None,
            note: None,
            findings: Vec::new(),
            evidence_count: 0,
            ms: None,
        }
    }

    pub fn skipped(reason: &str) -> Self {
        LayerRecord {
            status: LayerStatus::Skipped,
            note: Some(reason.to_string()),
            ..LayerRecord::not_run()
        }
    }

    /// Build from a layer's `CheckResult`. `keep_evidence` retains the (often
    /// large) `evidence` arrays; otherwise they are stripped and only counted,
    /// since they are diagnostic rather than metric-bearing and a Layer 2/3 diff
    /// can carry hundreds of entries per finding.
    pub fn from_check(
        result: &crate::models::CheckResult,
        ms: Option<u64>,
        keep_evidence: bool,
    ) -> Self {
        let evidence_count = result
            .findings
            .iter()
            .filter_map(|f| f.get("evidence").and_then(|v| v.as_array()))
            .map(|a| a.len())
            .sum();

        let findings = result
            .findings
            .iter()
            .map(|f| {
                if keep_evidence {
                    f.clone()
                } else {
                    let mut f = f.clone();
                    f.remove("evidence");
                    f
                }
            })
            .collect();

        LayerRecord {
            status: if result.verdict == Verdict::Error {
                LayerStatus::Error
            } else {
                LayerStatus::Ran
            },
            verdict: Some(result.verdict.clone()),
            score: Some(result.score),
            note: result.note.clone(),
            findings,
            evidence_count,
            ms,
        }
    }

    fn ran(&self) -> bool {
        self.status == LayerStatus::Ran
    }

    /// Findings that constitute an accusation (BLOCK or SUSPECT).
    fn accusations(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|f| is_accusing(f))
    }
}

/// One corpus entry's complete result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalRecord {
    // --- identity ---
    pub entry_id: String,
    pub kind: String,
    pub package: String,
    pub version: Option<String>,
    pub path: Option<String>,
    pub pinned: bool,
    /// For a version-pinned entry, which version Layer 0's *metadata* checks
    /// actually examined. Layer 0's age/maintainer/signature checks all key off
    /// `dist-tags.latest`, so a pinned entry gets pinned content but
    /// latest-based metadata. Recorded rather than silently conflated.
    pub l0_metadata_version: Option<String>,
    /// Dependency count from the scanned `package.json`, when one was on disk.
    pub declared_deps: Option<usize>,
    /// Whether Layer 2/3 observations for this entry can be trusted.
    ///
    /// The sandbox runs `npm install --offline` under `--network=none`, so
    /// dependencies cannot be fetched: a dependency-bearing package fails its
    /// install (swallowed by `|| true`), `require()` then throws
    /// `MODULE_NOT_FOUND` (swallowed by the try/catch), and the layer reports an
    /// empty profile that looks exactly like a clean package. Such entries are
    /// excluded from the dynamic denominators rather than counted as precision.
    pub dyn_valid: bool,

    // --- ground truth, verbatim from the manifest ---
    pub group: String,
    pub label: String,
    pub expected_vectors: Vec<String>,
    pub applicable_layers: Vec<u8>,
    pub effective_layers: Vec<u8>,

    // --- outcome ---
    pub outcome: Outcome,
    pub outcome_detail: Option<String>,
    pub registry_status: Option<String>,
    pub risk_score: Option<f64>,
    pub verdict: Option<Verdict>,
    pub layers: [LayerRecord; 4],

    // --- derived ---
    pub detected_vectors: Vec<String>,
    pub matched_expected: Vec<String>,
    pub missed_expected: Vec<String>,
    /// Detected minus expected. On a benign entry this names the rule that
    /// produced the false positive — the actionable half of an FP count.
    pub unexpected_vectors: Vec<String>,
    pub classification: Classification,
    /// The same scoring with only BLOCK treated as positive, so one run reports
    /// both operating points (BLOCK-only and BLOCK-or-SUSPECT) without rescanning.
    pub classification_block_only: Classification,
    pub note: Option<String>,
    pub total_ms: u64,
    pub scanned_at: String,
}

/// Inputs for `EvalRecord::build`, grouped to keep the call sites readable.
pub struct RecordInputs<'a> {
    pub entry: &'a CorpusEntry,
    pub effective_layers: Vec<u8>,
    pub layers: [LayerRecord; 4],
    pub risk_score: Option<f64>,
    pub verdict: Option<Verdict>,
    pub outcome: Outcome,
    pub outcome_detail: Option<String>,
    pub registry_status: Option<String>,
    pub declared_deps: Option<usize>,
    pub l0_metadata_version: Option<String>,
    pub total_ms: u64,
    pub scanned_at: String,
}

impl EvalRecord {
    /// Assemble a record and derive every scored field from the layer results
    /// plus the manifest's ground truth.
    pub fn build(input: RecordInputs<'_>) -> Self {
        let RecordInputs {
            entry,
            effective_layers,
            layers,
            risk_score,
            verdict,
            outcome,
            outcome_detail,
            registry_status,
            declared_deps,
            l0_metadata_version,
            total_ms,
            scanned_at,
        } = input;

        let mut detected_vectors: Vec<String> = Vec::new();
        for layer in &layers {
            for f in layer.accusations() {
                if let Some(v) = finding_str(f, "vector") {
                    if !detected_vectors.iter().any(|d| d == v) {
                        detected_vectors.push(v.to_string());
                    }
                }
            }
        }
        detected_vectors.sort();

        let matched_expected: Vec<String> = entry
            .vectors
            .iter()
            .filter(|v| detected_vectors.contains(v))
            .cloned()
            .collect();
        let missed_expected: Vec<String> = entry
            .vectors
            .iter()
            .filter(|v| !detected_vectors.contains(v))
            .cloned()
            .collect();
        let unexpected_vectors: Vec<String> = detected_vectors
            .iter()
            .filter(|v| !entry.vectors.contains(v))
            .cloned()
            .collect();

        let is_malicious = entry.label == crate::eval::corpus::Label::Malicious;
        let classification =
            classify(outcome, &layers, verdict.as_ref(), is_malicious, entry, false);
        let classification_block_only =
            classify(outcome, &layers, verdict.as_ref(), is_malicious, entry, true);

        // Dynamic observations are only trustworthy for a dependency-free
        // package (see the `dyn_valid` doc comment).
        let dyn_valid = declared_deps == Some(0);

        EvalRecord {
            entry_id: entry.entry_id(),
            kind: entry.kind.as_str().to_string(),
            package: entry.package.clone(),
            version: entry.version.clone(),
            path: entry.path.clone(),
            pinned: entry.version.is_some(),
            l0_metadata_version,
            declared_deps,
            dyn_valid,
            group: entry.group.as_str().to_string(),
            label: entry.label.as_str().to_string(),
            expected_vectors: entry.vectors.clone(),
            applicable_layers: entry.layers.clone(),
            effective_layers,
            outcome,
            outcome_detail,
            registry_status,
            risk_score,
            verdict,
            layers,
            detected_vectors,
            matched_expected,
            missed_expected,
            unexpected_vectors,
            classification,
            classification_block_only,
            note: entry.note.clone(),
            total_ms,
            scanned_at,
        }
    }

    /// Layers whose findings are admissible for this record. Layer 2 and 3 are
    /// dropped when `dyn_valid` is false.
    pub fn admissible_layers(&self) -> Vec<usize> {
        (0..4)
            .filter(|&i| self.layers[i].ran())
            .filter(|&i| i < 2 || self.dyn_valid)
            .collect()
    }
}

/// Score one prediction against its label.
///
/// `block_only` narrows "positive" from BLOCK-or-SUSPECT to BLOCK alone, giving
/// the stricter operating point.
fn classify(
    outcome: Outcome,
    layers: &[LayerRecord; 4],
    verdict: Option<&Verdict>,
    is_malicious: bool,
    entry: &CorpusEntry,
    block_only: bool,
) -> Classification {
    match outcome {
        Outcome::SkippedMissing => return Classification::Skipped,
        Outcome::RegistryFailed | Outcome::Timeout => return Classification::Error,
        Outcome::RegistryNotFound | Outcome::Scanned => {}
    }

    // Nothing observed the package at all — an Error, not a judgement. A layer
    // that merely returned Error alongside layers that did run is fine; what
    // disqualifies a record is having no successful layer.
    if !layers.iter().any(|l| l.ran()) {
        return Classification::Error;
    }

    let positive = match verdict {
        Some(Verdict::Block) => true,
        Some(Verdict::Suspect) => !block_only,
        _ => false,
    };

    if is_malicious {
        if positive {
            Classification::TruePositive
        } else if entry.kind == crate::eval::corpus::Kind::Holder {
            // The corpus cannot deliver this package's malicious content, so a
            // clean verdict is truthful rather than a miss.
            Classification::ArtifactFalseNegative
        } else {
            Classification::FalseNegative
        }
    } else if positive {
        Classification::FalsePositive
    } else {
        Classification::TrueNegative
    }
}

// ---------------------------------------------------------------------------
// Writers
// ---------------------------------------------------------------------------

/// Quote a CSV field only when it needs it.
///
/// The escaping surface is deliberately tiny: free-form text (a finding's
/// `message`) is never written to CSV — it lives only in `records.jsonl` — and
/// multi-valued columns join with `;` rather than `,` so they never need
/// quoting. That leaves the manifest's `note` column as the only field that can
/// contain a delimiter, which is why hand-rolling this beats taking on a CSV
/// dependency for a writer-only need.
pub fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn join(items: &[String]) -> String {
    items.join(";")
}

fn join_u8(items: &[u8]) -> String {
    items
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(";")
}

fn opt<T: ToString>(v: &Option<T>) -> String {
    v.as_ref().map(|x| x.to_string()).unwrap_or_default()
}

fn status_str(s: LayerStatus) -> &'static str {
    match s {
        LayerStatus::Ran => "ran",
        LayerStatus::Error => "error",
        LayerStatus::NotRun => "not_run",
        LayerStatus::Skipped => "skipped",
    }
}

/// Column names of `results.csv`, in order. The single source of truth for both
/// the header and the row writer, so the two cannot drift apart.
pub const RESULTS_COLUMNS: &[&str] = &[
    "entry_id",
    "kind",
    "package",
    "version",
    "path",
    "group",
    "label",
    "pinned",
    "declared_deps",
    "dyn_valid",
    "expected_vectors",
    "applicable_layers",
    "effective_layers",
    "outcome",
    "registry_status",
    "verdict",
    "risk_score",
    "classification",
    "classification_block_only",
    "l0_status",
    "l0_verdict",
    "l0_score",
    "l0_findings",
    "l0_ms",
    "l1_status",
    "l1_verdict",
    "l1_score",
    "l1_findings",
    "l1_ms",
    "l2_status",
    "l2_verdict",
    "l2_score",
    "l2_findings",
    "l2_ms",
    "l3_status",
    "l3_verdict",
    "l3_score",
    "l3_findings",
    "l3_ms",
    "detected_vectors",
    "matched_expected",
    "missed_expected",
    "unexpected_vectors",
    "total_ms",
    "note",
    "scanned_at",
];

/// Column names of `findings.csv` — the tidy/long form, one row per finding.
/// Nothing here can contain a comma, so no field ever needs quoting.
pub const FINDINGS_COLUMNS: &[&str] = &[
    "entry_id",
    "package",
    "group",
    "label",
    "layer",
    "check",
    "severity",
    "vector",
    "evidence_count",
];

pub fn write_results_header<W: Write>(w: &mut W) -> std::io::Result<()> {
    writeln!(w, "{}", RESULTS_COLUMNS.join(","))
}

pub fn write_findings_header<W: Write>(w: &mut W) -> std::io::Result<()> {
    writeln!(w, "{}", FINDINGS_COLUMNS.join(","))
}

/// One `results.csv` row. Field order and count must match `RESULTS_COLUMNS`;
/// `tests/eval_writers.rs` asserts that they do.
pub fn write_results_row<W: Write>(w: &mut W, r: &EvalRecord) -> std::io::Result<()> {
    let mut fields: Vec<String> = vec![
        r.entry_id.clone(),
        r.kind.clone(),
        r.package.clone(),
        r.version.clone().unwrap_or_default(),
        r.path.clone().unwrap_or_default(),
        r.group.clone(),
        r.label.clone(),
        r.pinned.to_string(),
        opt(&r.declared_deps),
        r.dyn_valid.to_string(),
        join(&r.expected_vectors),
        join_u8(&r.applicable_layers),
        join_u8(&r.effective_layers),
        r.outcome.as_str().to_string(),
        r.registry_status.clone().unwrap_or_default(),
        r.verdict.as_ref().map(|v| v.to_string()).unwrap_or_default(),
        r.risk_score.map(|s| format!("{:.2}", s)).unwrap_or_default(),
        r.classification.as_str().to_string(),
        r.classification_block_only.as_str().to_string(),
    ];

    for layer in &r.layers {
        fields.push(status_str(layer.status).to_string());
        fields.push(layer.verdict.as_ref().map(|v| v.to_string()).unwrap_or_default());
        fields.push(opt(&layer.score));
        fields.push(layer.findings.len().to_string());
        fields.push(opt(&layer.ms));
    }

    fields.extend([
        join(&r.detected_vectors),
        join(&r.matched_expected),
        join(&r.missed_expected),
        join(&r.unexpected_vectors),
        r.total_ms.to_string(),
        r.note.clone().unwrap_or_default(),
        r.scanned_at.clone(),
    ]);

    let escaped: Vec<String> = fields.iter().map(|f| csv_escape(f)).collect();
    writeln!(w, "{}", escaped.join(","))
}

/// One `findings.csv` row per finding across all four layers.
pub fn write_findings_rows<W: Write>(w: &mut W, r: &EvalRecord) -> std::io::Result<()> {
    for (idx, layer) in r.layers.iter().enumerate() {
        for f in &layer.findings {
            let evidence_count = f
                .get("evidence")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            writeln!(
                w,
                "{},{},{},{},{},{},{},{},{}",
                csv_escape(&r.entry_id),
                csv_escape(&r.package),
                r.group,
                r.label,
                idx,
                csv_escape(finding_str(f, "check").unwrap_or("unknown")),
                finding_str(f, "severity").unwrap_or("?"),
                finding_str(f, "vector").unwrap_or(""),
                evidence_count,
            )?;
        }
    }
    Ok(())
}

/// One `records.jsonl` line. Serialization failure is surfaced rather than
/// silently writing a truncated line.
pub fn write_jsonl_line<W: Write>(w: &mut W, r: &EvalRecord) -> std::io::Result<()> {
    let line = serde_json::to_string(r)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    writeln!(w, "{}", line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::corpus::parse_manifest;
    use serde_json::json;

    fn entry(line: &str) -> CorpusEntry {
        parse_manifest(line, "t").unwrap().into_iter().next().unwrap()
    }

    fn finding(check: &str, severity: &str, vector: &str) -> Finding {
        json!({"check": check, "severity": severity, "vector": vector, "message": "m"})
            .as_object()
            .unwrap()
            .clone()
    }

    fn layer_with(findings: Vec<Finding>, verdict: Verdict) -> LayerRecord {
        LayerRecord {
            status: LayerStatus::Ran,
            verdict: Some(verdict),
            score: Some(0),
            note: None,
            findings,
            evidence_count: 0,
            ms: Some(1),
        }
    }

    fn build(entry: &CorpusEntry, layers: [LayerRecord; 4], verdict: Verdict) -> EvalRecord {
        EvalRecord::build(RecordInputs {
            entry,
            effective_layers: entry.layers.clone(),
            layers,
            risk_score: Some(0.5),
            verdict: Some(verdict),
            outcome: Outcome::Scanned,
            outcome_detail: None,
            registry_status: Some("found".into()),
            declared_deps: Some(0),
            l0_metadata_version: None,
            total_ms: 5,
            scanned_at: "2026-07-30T00:00:00Z".into(),
        })
    }

    #[test]
    fn info_only_findings_do_not_make_a_positive() {
        assert!(!is_accusing(&finding("typosquat", "INFO", "A1")));
        assert!(is_accusing(&finding("typosquat", "SUSPECT", "A1")));
        assert!(is_accusing(&finding("typosquat", "BLOCK", "A1")));
    }

    #[test]
    fn a_benign_parent_with_an_a1_info_finding_is_a_true_negative() {
        // This is the exact shape produced by scanning `lodash`: an INFO A1
        // "exact match with a known popular package" finding and a PASS verdict.
        let e = entry("name\tlodash\tparent_benign\tbenign\t-\t0");
        let layers = [
            layer_with(vec![finding("typosquat", "INFO", "A1")], Verdict::Pass),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ];
        let r = build(&e, layers, Verdict::Pass);
        assert_eq!(r.classification, Classification::TrueNegative);
        assert!(r.detected_vectors.is_empty(), "INFO must not be a detection");
        assert!(r.unexpected_vectors.is_empty());
    }

    #[test]
    fn suspect_is_a_positive_normally_but_not_under_block_only() {
        let e = entry("name\tevil\tdummy\tmalicious\tA1\t0");
        let layers = [
            layer_with(vec![finding("typosquat", "SUSPECT", "A1")], Verdict::Suspect),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ];
        let r = build(&e, layers, Verdict::Suspect);
        assert_eq!(r.classification, Classification::TruePositive);
        assert_eq!(r.classification_block_only, Classification::FalseNegative);
        assert_eq!(r.matched_expected, vec!["A1"]);
        assert!(r.missed_expected.is_empty());
    }

    #[test]
    fn holder_kind_scoring_clean_is_an_artifact_not_a_miss() {
        let e = entry("holder\tffmepg\treal_malicious\tmalicious\tA1\t0");
        let layers = [
            layer_with(vec![], Verdict::Pass),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ];
        let r = build(&e, layers, Verdict::Pass);
        assert_eq!(r.classification, Classification::ArtifactFalseNegative);
        assert_eq!(r.missed_expected, vec!["A1"]);
    }

    #[test]
    fn a_holder_that_is_detected_is_still_a_true_positive() {
        let e = entry("holder\tcrossenv\treal_malicious\tmalicious\tA1\t0");
        let layers = [
            layer_with(vec![finding("typosquat", "BLOCK", "A1")], Verdict::Block),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ];
        let r = build(&e, layers, Verdict::Block);
        assert_eq!(r.classification, Classification::TruePositive);
        assert_eq!(r.classification_block_only, Classification::TruePositive);
    }

    #[test]
    fn a_malicious_non_holder_scoring_clean_is_a_real_false_negative() {
        let e = entry("name\td3.js\treal_malicious\tmalicious\tA1\t0");
        let layers = [
            layer_with(vec![], Verdict::Pass),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ];
        let r = build(&e, layers, Verdict::Pass);
        assert_eq!(r.classification, Classification::FalseNegative);
    }

    #[test]
    fn unexpected_vectors_name_the_rule_that_false_positived() {
        let e = entry("name\tfabric\tparent_benign\tbenign\t-\t0,1");
        let layers = [
            layer_with(vec![], Verdict::Pass),
            layer_with(vec![finding("install_script", "SUSPECT", "B1")], Verdict::Suspect),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ];
        let r = build(&e, layers, Verdict::Suspect);
        assert_eq!(r.classification, Classification::FalsePositive);
        assert_eq!(r.unexpected_vectors, vec!["B1"]);
    }

    #[test]
    fn a_record_with_no_layer_that_ran_is_an_error_not_a_verdict() {
        let e = entry("name\tgone\treal_malicious\tmalicious\tA1\t0");
        let mut errored = LayerRecord::not_run();
        errored.status = LayerStatus::Error;
        let layers = [errored, LayerRecord::not_run(), LayerRecord::not_run(), LayerRecord::not_run()];
        let r = build(&e, layers, Verdict::Error);
        assert_eq!(r.classification, Classification::Error);
    }

    #[test]
    fn registry_failure_and_timeout_are_errors_but_not_found_still_scores() {
        let e = entry("name\tgone\treal_malicious\tmalicious\tA1\t0");
        let ran = layer_with(vec![finding("typosquat", "BLOCK", "A1")], Verdict::Block);

        for outcome in [Outcome::RegistryFailed, Outcome::Timeout] {
            let r = EvalRecord::build(RecordInputs {
                entry: &e,
                effective_layers: vec![0],
                layers: [
                    layer_with(vec![finding("typosquat", "BLOCK", "A1")], Verdict::Block),
                    LayerRecord::not_run(),
                    LayerRecord::not_run(),
                    LayerRecord::not_run(),
                ],
                risk_score: None,
                verdict: Some(Verdict::Block),
                outcome,
                outcome_detail: None,
                registry_status: None,
                declared_deps: None,
                l0_metadata_version: None,
                total_ms: 1,
                scanned_at: "t".into(),
            });
            assert_eq!(r.classification, Classification::Error, "{:?}", outcome);
        }

        // A genuine 404 is not an error: the name-based checks still ran and
        // their verdict is meaningful.
        let r = EvalRecord::build(RecordInputs {
            entry: &e,
            effective_layers: vec![0],
            layers: [ran, LayerRecord::not_run(), LayerRecord::not_run(), LayerRecord::not_run()],
            risk_score: None,
            verdict: Some(Verdict::Block),
            outcome: Outcome::RegistryNotFound,
            outcome_detail: None,
            registry_status: Some("not_found".into()),
            declared_deps: None,
            l0_metadata_version: None,
            total_ms: 1,
            scanned_at: "t".into(),
        });
        assert_eq!(r.classification, Classification::TruePositive);
    }

    #[test]
    fn missing_directory_is_skipped_not_scored() {
        let e = entry("dir\tdummy_packages/absent\tdummy\tmalicious\tD1\t1,2,3");
        let r = EvalRecord::build(RecordInputs {
            entry: &e,
            effective_layers: vec![],
            layers: [
                LayerRecord::not_run(),
                LayerRecord::not_run(),
                LayerRecord::not_run(),
                LayerRecord::not_run(),
            ],
            risk_score: None,
            verdict: None,
            outcome: Outcome::SkippedMissing,
            outcome_detail: Some("directory not found".into()),
            registry_status: None,
            declared_deps: None,
            l0_metadata_version: None,
            total_ms: 0,
            scanned_at: "t".into(),
        });
        assert_eq!(r.classification, Classification::Skipped);
    }

    #[test]
    fn dyn_valid_requires_a_dependency_free_package() {
        let e = entry("name\tjquery\tparent_benign\tbenign\t-\t0,1,2,3");
        let layers = || {
            [
                layer_with(vec![], Verdict::Pass),
                layer_with(vec![], Verdict::Pass),
                layer_with(vec![], Verdict::Pass),
                layer_with(vec![], Verdict::Pass),
            ]
        };
        let mk = |deps: Option<usize>| {
            EvalRecord::build(RecordInputs {
                entry: &e,
                effective_layers: vec![0, 1, 2, 3],
                layers: layers(),
                risk_score: Some(0.0),
                verdict: Some(Verdict::Pass),
                outcome: Outcome::Scanned,
                outcome_detail: None,
                registry_status: Some("found".into()),
                declared_deps: deps,
                l0_metadata_version: None,
                total_ms: 1,
                scanned_at: "t".into(),
            })
        };

        let free = mk(Some(0));
        assert!(free.dyn_valid);
        assert_eq!(free.admissible_layers(), vec![0, 1, 2, 3]);

        // With dependencies the sandbox cannot install them, so L2/L3 saw
        // nothing and their clean result must not be admitted as precision.
        let heavy = mk(Some(28));
        assert!(!heavy.dyn_valid);
        assert_eq!(heavy.admissible_layers(), vec![0, 1]);

        // Unknown dependency count is treated as untrustworthy, not as zero.
        assert!(!mk(None).dyn_valid);
    }

    #[test]
    fn evidence_is_stripped_but_counted_unless_retained() {
        let mut f = finding("import_side_effect", "SUSPECT", "C1");
        f.insert("evidence".into(), json!(["dns:a.example", "dns:b.example"]));
        let result = crate::models::CheckResult {
            package: "p".into(),
            verdict: Verdict::Suspect,
            score: 15,
            findings: vec![f],
            note: None,
        };

        let stripped = LayerRecord::from_check(&result, Some(9), false);
        assert_eq!(stripped.evidence_count, 2);
        assert!(!stripped.findings[0].contains_key("evidence"));
        assert_eq!(stripped.ms, Some(9));

        let kept = LayerRecord::from_check(&result, None, true);
        assert_eq!(kept.evidence_count, 2);
        assert_eq!(kept.findings[0]["evidence"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn from_check_maps_an_error_verdict_to_error_status_and_keeps_the_note() {
        let result = crate::models::CheckResult {
            package: "p".into(),
            verdict: Verdict::Error,
            score: 0,
            findings: vec![],
            note: Some("Docker required for Layer 2".into()),
        };
        let lr = LayerRecord::from_check(&result, None, false);
        assert_eq!(lr.status, LayerStatus::Error);
        assert_eq!(lr.note.as_deref(), Some("Docker required for Layer 2"));
        assert!(!lr.ran());
    }

    #[test]
    fn csv_escape_only_quotes_when_needed() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape(""), "");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("two\nlines"), "\"two\nlines\"");
        assert_eq!(csv_escape("cr\rhere"), "\"cr\rhere\"");
        // Semicolons are the multi-value separator precisely so they don't quote.
        assert_eq!(csv_escape("A1;B2"), "A1;B2");
    }
}
