// Metric rollups over a set of `EvalRecord`s. Pure — no I/O, no clock.
//
// Two design rules run through this module:
//
//   1. **Every rate is an `Option<f64>`.** A zero denominator serializes to
//      `null`, never to `0.0`. A false-positive rate of "0.0" and "we had no
//      benign entries to test" are wildly different claims, and a paper that
//      conflates them is making an unsupported one.
//
//   2. **Only observations we actually made are counted.** Records whose scan
//      errored, timed out, or was skipped are tallied separately and kept out of
//      the confusion matrix; artefact false negatives (see
//      `Classification::ArtifactFalseNegative`) are kept out of recall's
//      denominator. Layer 2/3 statistics additionally admit only records where
//      `dyn_valid` holds, since a dependency-bearing package produces an empty
//      behaviour profile that is indistinguishable from a clean one.

use serde::{Deserialize, Serialize};

use crate::eval::record::{Classification, EvalRecord, RunProvenance};
use crate::models::Verdict;
use crate::report::LayerStatus;

/// A confusion matrix plus the three buckets that must not be folded into it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Confusion {
    pub true_positive: usize,
    pub false_positive: usize,
    pub true_negative: usize,
    pub false_negative: usize,
    /// Labelled malicious and scored clean, but the corpus could not supply the
    /// malicious content (npm defanged the takedown stub). Excluded from recall.
    pub artifact_fn: usize,
    pub error: usize,
    pub skipped: usize,
}

fn ratio(num: usize, den: usize) -> Option<f64> {
    if den == 0 {
        None
    } else {
        Some(num as f64 / den as f64)
    }
}

impl Confusion {
    pub fn add(&mut self, c: Classification) {
        match c {
            Classification::TruePositive => self.true_positive += 1,
            Classification::FalsePositive => self.false_positive += 1,
            Classification::TrueNegative => self.true_negative += 1,
            Classification::FalseNegative => self.false_negative += 1,
            Classification::ArtifactFalseNegative => self.artifact_fn += 1,
            Classification::Error => self.error += 1,
            Classification::Skipped => self.skipped += 1,
        }
    }

    /// TP / (TP + FN). `artifact_fn` is deliberately absent from the
    /// denominator — including it would penalise the detector for npm having
    /// removed the malicious code before we could scan it.
    pub fn recall(&self) -> Option<f64> {
        ratio(self.true_positive, self.true_positive + self.false_negative)
    }

    pub fn precision(&self) -> Option<f64> {
        ratio(self.true_positive, self.true_positive + self.false_positive)
    }

    /// FP / (FP + TN) — the false-positive rate over benign entries.
    pub fn fpr(&self) -> Option<f64> {
        ratio(self.false_positive, self.false_positive + self.true_negative)
    }

    pub fn f1(&self) -> Option<f64> {
        let (p, r) = (self.precision()?, self.recall()?);
        if p + r == 0.0 {
            None
        } else {
            Some(2.0 * p * r / (p + r))
        }
    }

    pub fn accuracy(&self) -> Option<f64> {
        let correct = self.true_positive + self.true_negative;
        let total = correct + self.false_positive + self.false_negative;
        ratio(correct, total)
    }

    /// Entries that landed in one of the four cells, i.e. the sample size the
    /// rates above are computed over.
    pub fn scored(&self) -> usize {
        self.true_positive + self.false_positive + self.true_negative + self.false_negative
    }
}

/// The rates, materialised for serialization. Kept separate from `Confusion` so
/// the counts stay a plain data struct and the derived values are computed once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rates {
    pub scored: usize,
    pub recall: Option<f64>,
    pub precision: Option<f64>,
    pub fpr: Option<f64>,
    pub f1: Option<f64>,
    pub accuracy: Option<f64>,
}

impl From<&Confusion> for Rates {
    fn from(c: &Confusion) -> Self {
        Rates {
            scored: c.scored(),
            recall: c.recall(),
            precision: c.precision(),
            fpr: c.fpr(),
            f1: c.f1(),
            accuracy: c.accuracy(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMetrics {
    pub group: String,
    pub confusion: Confusion,
    pub rates: Rates,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerMetrics {
    pub layer: u8,
    pub ran: usize,
    pub error: usize,
    pub not_run: usize,
    pub skipped: usize,
    pub block: usize,
    pub suspect: usize,
    pub pass: usize,
    pub finding_count: usize,
    /// True positives where this layer was the ONLY one that accused the
    /// package. The directly useful answer to "which layer earns its keep":
    /// a layer with a high detection count but zero sole detections is adding
    /// cost without adding coverage.
    pub sole_detector: usize,
    /// Accusations raised on entries labelled benign — this layer's contribution
    /// to the false-positive rate.
    pub false_hits: usize,
    pub ms_p50: u64,
    pub ms_p90: u64,
    pub ms_max: u64,
    /// Records excluded from this layer's statistics because `dyn_valid` was
    /// false (dependencies could not be installed in the offline sandbox, so the
    /// observation was vacuous). Always 0 for layers 0 and 1.
    pub excluded_not_dyn_valid: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorMetrics {
    pub vector: String,
    /// Entries whose manifest declared this vector as ground truth.
    pub expected: usize,
    /// Of those, how many the detector actually flagged with this vector.
    pub detected: usize,
    pub missed: usize,
    pub recall: Option<f64>,
    /// Times this vector fired on an entry labelled benign. Turns a raw FP count
    /// into a named, actionable rule.
    pub false_hits: usize,
    /// Times this vector fired at all, including on entries that did not declare
    /// it (the corpus mostly cannot declare vectors — see eval/README.md).
    pub total_fires: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingSummary {
    pub total_ms: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub max: u64,
    /// The ten slowest entries, so a pathological package is named rather than
    /// buried in a percentile.
    pub slowest: Vec<(String, u64)>,
}

/// Counts of every non-scored outcome, so a run's completeness is legible
/// without post-processing `records.jsonl`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OutcomeCounts {
    pub scanned: usize,
    pub skipped_missing: usize,
    pub registry_not_found: usize,
    pub registry_failed: usize,
    /// Records DISQUALIFIED by a wall-clock kill — i.e. the timeout left
    /// nothing observed at all.
    ///
    /// Deliberately **not** "records in which some layer timed out". A package
    /// whose dynamic layers were killed but whose Layer 0/1 produced a sound
    /// verdict is still scored, because dropping it would silently shrink a
    /// denominator: `shadowsocks` times out in both dynamic layers, yet its
    /// Layer 1 `shell_exfil` finding is a genuine arm F false positive, and
    /// excluding it would have improved the headline FPR by losing a false
    /// positive to a Docker stall.
    ///
    /// Layer-level stalls are visible instead in `dyn_valid` (false whenever a
    /// dynamic layer was killed), in the per-layer `note`, and in the record's
    /// `outcome_detail` — all in `records.jsonl`.
    pub timeout: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub provenance: RunProvenance,
    pub record_count: usize,
    pub outcomes: OutcomeCounts,
    pub overall: Confusion,
    pub overall_rates: Rates,
    /// The stricter operating point: only BLOCK counts as a positive.
    pub overall_block_only: Confusion,
    pub overall_block_only_rates: Rates,
    pub by_group: Vec<GroupMetrics>,
    pub by_layer: Vec<LayerMetrics>,
    pub by_vector: Vec<VectorMetrics>,
    pub timing: TimingSummary,
}

/// Nearest-rank percentile over an already-sorted slice. Hand-rolled to avoid a
/// dependency for six lines of arithmetic.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p.clamp(0.0, 1.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn is_accusing(f: &crate::models::Finding) -> bool {
    matches!(
        f.get("severity").and_then(|v| v.as_str()),
        Some("BLOCK") | Some("SUSPECT")
    )
}

/// Layers whose findings this record contributes, given `dyn_valid`.
fn layer_admissible(r: &EvalRecord, layer: usize) -> bool {
    layer < 2 || r.dyn_valid
}

pub fn compute(records: &[EvalRecord], provenance: RunProvenance) -> MetricsSummary {
    let mut overall = Confusion::default();
    let mut overall_block_only = Confusion::default();
    let mut outcomes = OutcomeCounts::default();

    for r in records {
        overall.add(r.classification);
        overall_block_only.add(r.classification_block_only);
        match r.outcome {
            crate::eval::record::Outcome::Scanned => outcomes.scanned += 1,
            crate::eval::record::Outcome::SkippedMissing => outcomes.skipped_missing += 1,
            crate::eval::record::Outcome::RegistryNotFound => outcomes.registry_not_found += 1,
            crate::eval::record::Outcome::RegistryFailed => outcomes.registry_failed += 1,
            crate::eval::record::Outcome::Timeout => outcomes.timeout += 1,
        }
    }

    // --- per group, in first-seen order so output ordering is deterministic ---
    let mut by_group: Vec<GroupMetrics> = Vec::new();
    for r in records {
        match by_group.iter_mut().find(|g| g.group == r.group) {
            Some(g) => g.confusion.add(r.classification),
            None => {
                let mut confusion = Confusion::default();
                confusion.add(r.classification);
                by_group.push(GroupMetrics {
                    group: r.group.clone(),
                    rates: Rates::from(&confusion),
                    confusion,
                });
            }
        }
    }
    for g in &mut by_group {
        g.rates = Rates::from(&g.confusion);
    }

    // --- per layer -----------------------------------------------------------
    let mut by_layer = Vec::with_capacity(4);
    for layer in 0..4usize {
        let mut m = LayerMetrics {
            layer: layer as u8,
            ran: 0,
            error: 0,
            not_run: 0,
            skipped: 0,
            block: 0,
            suspect: 0,
            pass: 0,
            finding_count: 0,
            sole_detector: 0,
            false_hits: 0,
            ms_p50: 0,
            ms_p90: 0,
            ms_max: 0,
            excluded_not_dyn_valid: 0,
        };
        let mut times: Vec<u64> = Vec::new();

        for r in records {
            let lr = &r.layers[layer];

            // Status tallies describe execution, so they count regardless of
            // whether the *observation* is admissible.
            match lr.status {
                LayerStatus::Ran => m.ran += 1,
                LayerStatus::Error => m.error += 1,
                LayerStatus::NotRun => m.not_run += 1,
                LayerStatus::Skipped => m.skipped += 1,
            }
            if let Some(ms) = lr.ms {
                times.push(ms);
            }
            if lr.status != LayerStatus::Ran {
                continue;
            }
            if !layer_admissible(r, layer) {
                m.excluded_not_dyn_valid += 1;
                continue;
            }

            match lr.verdict {
                Some(Verdict::Block) => m.block += 1,
                Some(Verdict::Suspect) => m.suspect += 1,
                Some(Verdict::Pass) => m.pass += 1,
                _ => {}
            }
            m.finding_count += lr.findings.len();

            let accuses = lr.findings.iter().any(is_accusing);
            if accuses && r.label == "benign" {
                m.false_hits += 1;
            }
            if accuses && r.classification == Classification::TruePositive {
                let others = r
                    .admissible_layers()
                    .into_iter()
                    .filter(|&i| i != layer)
                    .any(|i| r.layers[i].findings.iter().any(is_accusing));
                if !others {
                    m.sole_detector += 1;
                }
            }
        }

        times.sort_unstable();
        m.ms_p50 = percentile(&times, 0.50);
        m.ms_p90 = percentile(&times, 0.90);
        m.ms_max = times.last().copied().unwrap_or(0);
        by_layer.push(m);
    }

    // --- per vector ----------------------------------------------------------
    let mut by_vector: Vec<VectorMetrics> = crate::eval::corpus::VECTORS
        .iter()
        .map(|v| VectorMetrics {
            vector: v.to_string(),
            expected: 0,
            detected: 0,
            missed: 0,
            recall: None,
            false_hits: 0,
            total_fires: 0,
        })
        .collect();

    for r in records {
        for v in &mut by_vector {
            let expected = r.expected_vectors.contains(&v.vector);
            let fired = r.detected_vectors.contains(&v.vector);
            if expected {
                v.expected += 1;
                if fired {
                    v.detected += 1;
                } else {
                    v.missed += 1;
                }
            }
            if fired {
                v.total_fires += 1;
                if r.label == "benign" {
                    v.false_hits += 1;
                }
            }
        }
    }
    for v in &mut by_vector {
        v.recall = ratio(v.detected, v.expected);
    }

    // --- timing --------------------------------------------------------------
    let mut times: Vec<u64> = records.iter().map(|r| r.total_ms).collect();
    let total_ms = times.iter().sum();
    times.sort_unstable();

    let mut slowest: Vec<(String, u64)> = records
        .iter()
        .map(|r| (r.entry_id.clone(), r.total_ms))
        .collect();
    // Sort descending by time, tie-broken by id so the output is deterministic.
    slowest.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    slowest.truncate(10);

    let timing = TimingSummary {
        total_ms,
        p50: percentile(&times, 0.50),
        p90: percentile(&times, 0.90),
        p99: percentile(&times, 0.99),
        max: times.last().copied().unwrap_or(0),
        slowest,
    };

    MetricsSummary {
        provenance,
        record_count: records.len(),
        outcomes,
        overall_rates: Rates::from(&overall),
        overall_block_only_rates: Rates::from(&overall_block_only),
        overall,
        overall_block_only,
        by_group,
        by_layer,
        by_vector,
        timing,
    }
}

/// Human-readable end-of-run summary. Plain `writeln!` in the style of
/// `main::print_report` — no table or colour dependency.
pub fn render_summary<W: std::io::Write>(w: &mut W, m: &MetricsSummary) -> std::io::Result<()> {
    let pct = |v: Option<f64>| match v {
        Some(x) => format!("{:.1}%", x * 100.0),
        None => "n/a".to_string(),
    };

    writeln!(w, "\n{}", "=".repeat(72))?;
    writeln!(w, "EVALUATION SUMMARY  ({} records)", m.record_count)?;
    writeln!(w, "{}", "=".repeat(72))?;
    writeln!(
        w,
        "mode={}  tool={}  started={}",
        m.provenance.eval_mode, m.provenance.tool_version, m.provenance.started_at
    )?;
    writeln!(
        w,
        "lists: {} unscoped / {} scoped (refreshed={})",
        m.provenance.top_packages_len, m.provenance.top_scoped_len, m.provenance.top_list_refreshed
    )?;

    writeln!(w, "\nOutcomes: scanned={} not_found={} failed={} timeout={} skipped_missing={}",
        m.outcomes.scanned,
        m.outcomes.registry_not_found,
        m.outcomes.registry_failed,
        m.outcomes.timeout,
        m.outcomes.skipped_missing
    )?;

    let c = &m.overall;
    writeln!(
        w,
        "\nOverall (BLOCK or SUSPECT = positive), n={}:",
        c.scored()
    )?;
    writeln!(
        w,
        "  TP={} FP={} TN={} FN={}   (artifact_fn={} error={} skipped={})",
        c.true_positive,
        c.false_positive,
        c.true_negative,
        c.false_negative,
        c.artifact_fn,
        c.error,
        c.skipped
    )?;
    writeln!(
        w,
        "  recall={}  precision={}  FPR={}  F1={}",
        pct(c.recall()),
        pct(c.precision()),
        pct(c.fpr()),
        pct(c.f1())
    )?;

    let b = &m.overall_block_only;
    writeln!(
        w,
        "\nBLOCK-only operating point: TP={} FN={} recall={}  FPR={}",
        b.true_positive,
        b.false_negative,
        pct(b.recall()),
        pct(b.fpr())
    )?;

    writeln!(w, "\nBy group:")?;
    writeln!(
        w,
        "  {:<16} {:>4} {:>4} {:>4} {:>4} {:>6} {:>9} {:>8}",
        "group", "TP", "FP", "TN", "FN", "artFN", "recall", "FPR"
    )?;
    for g in &m.by_group {
        let gc = &g.confusion;
        writeln!(
            w,
            "  {:<16} {:>4} {:>4} {:>4} {:>4} {:>6} {:>9} {:>8}",
            g.group,
            gc.true_positive,
            gc.false_positive,
            gc.true_negative,
            gc.false_negative,
            gc.artifact_fn,
            pct(gc.recall()),
            pct(gc.fpr())
        )?;
    }

    writeln!(w, "\nBy layer:")?;
    writeln!(
        w,
        "  {:<6} {:>5} {:>6} {:>6} {:>8} {:>8} {:>6} {:>10} {:>9}",
        "layer", "ran", "block", "susp", "findings", "soleDet", "FPs", "excl(dep)", "p90 ms"
    )?;
    for l in &m.by_layer {
        writeln!(
            w,
            "  L{:<5} {:>5} {:>6} {:>6} {:>8} {:>8} {:>6} {:>10} {:>9}",
            l.layer,
            l.ran,
            l.block,
            l.suspect,
            l.finding_count,
            l.sole_detector,
            l.false_hits,
            l.excluded_not_dyn_valid,
            l.ms_p90
        )?;
    }

    let active: Vec<&VectorMetrics> = m
        .by_vector
        .iter()
        .filter(|v| v.expected > 0 || v.total_fires > 0)
        .collect();
    if !active.is_empty() {
        writeln!(w, "\nBy vector (only vectors expected or fired):")?;
        writeln!(
            w,
            "  {:<8} {:>8} {:>8} {:>7} {:>9} {:>7} {:>10}",
            "vector", "expected", "detected", "missed", "recall", "fires", "falseHits"
        )?;
        for v in active {
            writeln!(
                w,
                "  {:<8} {:>8} {:>8} {:>7} {:>9} {:>7} {:>10}",
                v.vector,
                v.expected,
                v.detected,
                v.missed,
                pct(v.recall),
                v.total_fires,
                v.false_hits
            )?;
        }
    }

    writeln!(
        w,
        "\nTiming: total={:.1}s  p50={}ms  p90={}ms  p99={}ms  max={}ms",
        m.timing.total_ms as f64 / 1000.0,
        m.timing.p50,
        m.timing.p90,
        m.timing.p99,
        m.timing.max
    )?;
    if let Some((slow_id, slow_ms)) = m.timing.slowest.first() {
        if *slow_ms > 0 {
            writeln!(w, "Slowest: {} ({}ms)", slow_id, slow_ms)?;
        }
    }
    writeln!(w)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_handles_empty_single_odd_and_even() {
        assert_eq!(percentile(&[], 0.5), 0);
        assert_eq!(percentile(&[7], 0.5), 7);
        assert_eq!(percentile(&[7], 0.99), 7);
        // odd length: 5 elements, p50 -> rank round(0.5*4)=2 -> 30
        assert_eq!(percentile(&[10, 20, 30, 40, 50], 0.50), 30);
        assert_eq!(percentile(&[10, 20, 30, 40, 50], 0.90), 50);
        assert_eq!(percentile(&[10, 20, 30, 40, 50], 0.0), 10);
        // even length: 4 elements, p50 -> rank round(0.5*3)=2 -> 30
        assert_eq!(percentile(&[10, 20, 30, 40], 0.50), 30);
        assert_eq!(percentile(&[10, 20, 30, 40], 1.0), 40);
    }

    #[test]
    fn zero_denominators_are_none_never_zero() {
        let empty = Confusion::default();
        assert_eq!(empty.recall(), None);
        assert_eq!(empty.precision(), None);
        assert_eq!(empty.fpr(), None);
        assert_eq!(empty.f1(), None);
        assert_eq!(empty.accuracy(), None);
        assert_eq!(empty.scored(), 0);

        // Only benign entries: recall is undefined, FPR is defined.
        let benign_only = Confusion {
            true_negative: 5,
            ..Default::default()
        };
        assert_eq!(benign_only.recall(), None);
        assert_eq!(benign_only.fpr(), Some(0.0));
    }

    #[test]
    fn artifact_fn_is_outside_recalls_denominator() {
        let mut c = Confusion::default();
        c.add(Classification::TruePositive);
        c.add(Classification::ArtifactFalseNegative);
        c.add(Classification::ArtifactFalseNegative);
        // 1 TP, 0 real FN -> perfect recall despite two unscannable entries.
        assert_eq!(c.recall(), Some(1.0));
        assert_eq!(c.artifact_fn, 2);
        assert_eq!(c.scored(), 1);

        c.add(Classification::FalseNegative);
        assert_eq!(c.recall(), Some(0.5));
    }

    #[test]
    fn rates_are_exact_on_a_hand_computed_matrix() {
        let c = Confusion {
            true_positive: 6,
            false_positive: 2,
            true_negative: 8,
            false_negative: 4,
            ..Default::default()
        };
        assert_eq!(c.recall(), Some(0.6)); // 6/10
        assert_eq!(c.precision(), Some(0.75)); // 6/8
        assert_eq!(c.fpr(), Some(0.2)); // 2/10
        assert_eq!(c.accuracy(), Some(0.7)); // 14/20
        let f1 = c.f1().unwrap();
        assert!((f1 - 0.666_666_666).abs() < 1e-6, "f1 was {}", f1);
    }

    #[test]
    fn errors_and_skips_stay_out_of_every_cell() {
        let mut c = Confusion::default();
        c.add(Classification::Error);
        c.add(Classification::Skipped);
        assert_eq!(c.scored(), 0);
        assert_eq!(c.recall(), None);
        assert_eq!(c.error, 1);
        assert_eq!(c.skipped, 1);
    }
}
