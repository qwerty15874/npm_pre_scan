// The batch driver: read manifests, scan each entry, stream result data out.
//
// Structure follows one rule — the per-entry scan is a *pure-ish* function that
// returns an `EvalRecord`, and the file writing is a separate loop around it.
// That keeps the scoring logic testable without a filesystem (see
// `scan_entry_name_only`, exercised directly by tests/eval_offline_l0.rs) and
// keeps the durability concern in one place.
//
// Output is written incrementally and flushed after every entry. A batch over a
// 200k-name corpus that dies at entry 190,000 must leave 189,999 usable records
// on disk, not an empty file.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::eval::corpus::{merge_manifests, parse_manifest, CorpusEntry, Kind, ManifestError};
use crate::eval::metrics::{compute, MetricsSummary};
use crate::eval::record::{
    write_findings_header, write_findings_rows, write_jsonl_line, write_results_header,
    write_results_row, EvalRecord, LayerRecord, Outcome, RecordInputs, RunProvenance,
};
use crate::models::Verdict;
use crate::report::{FullScan, LayerMask};

/// The ceiling on how deep a batch scans, independent of what each manifest
/// entry asks for. Effective layers = manifest entry ∩ this ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalMode {
    /// Layer 0's name checks only. Zero network, zero Docker, reproducible.
    NameOnly,
    /// Layer 0 + Layer 1: registry metadata and static analysis. No Docker.
    Registry,
    /// Everything the manifest asks for, up to all four layers.
    Full,
    /// No ceiling — honour each entry's `layers` column exactly.
    Auto,
}

impl EvalMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "name-only" => Some(EvalMode::NameOnly),
            "registry" => Some(EvalMode::Registry),
            "full" => Some(EvalMode::Full),
            "auto" => Some(EvalMode::Auto),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            EvalMode::NameOnly => "name-only",
            EvalMode::Registry => "registry",
            EvalMode::Full => "full",
            EvalMode::Auto => "auto",
        }
    }

    fn ceiling(&self) -> LayerMask {
        match self {
            EvalMode::NameOnly => LayerMask([true, false, false, false]),
            EvalMode::Registry => LayerMask([true, true, false, false]),
            EvalMode::Full | EvalMode::Auto => LayerMask::ALL,
        }
    }

    /// True when no layer in the ceiling needs the network or Docker.
    fn is_offline(&self) -> bool {
        matches!(self, EvalMode::NameOnly)
    }
}

pub struct EvalConfig {
    pub manifests: Vec<PathBuf>,
    pub out_dir: PathBuf,
    pub mode: EvalMode,
    pub docker_timeout_secs: Option<u64>,
    pub keep_evidence: bool,
    pub refresh_top: bool,
    /// Root the `dir` manifest entries are resolved against (the package root
    /// during normal use).
    pub base_dir: PathBuf,
    /// Where to fetch and cache DataDog sample zips.
    pub samples_dir: PathBuf,
    pub verbose: bool,
}

/// Why a batch could not run at all, or how completely it did.
#[derive(Debug)]
pub enum BatchError {
    /// A manifest could not be read or parsed. Fatal: a manifest that silently
    /// shrinks corrupts every denominator computed from it.
    Manifest(Vec<ManifestError>),
    Io(String),
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchError::Manifest(errs) => {
                writeln!(f, "{} manifest problem(s):", errs.len())?;
                for e in errs {
                    writeln!(f, "{}", e)?;
                }
                Ok(())
            }
            BatchError::Io(msg) => write!(f, "{}", msg),
        }
    }
}

pub struct BatchOutcome {
    pub metrics: MetricsSummary,
    /// Entries the mode ceiling left with nothing to run. Reported rather than
    /// silently dropped, so a run can never look more complete than it was.
    pub filtered_out: usize,
    /// True when at least one entry errored, timed out, or had a layer fail —
    /// the results are usable but incomplete.
    pub degraded: bool,
}

/// Append-mode output files, with the header written only on creation.
struct Writers {
    records: BufWriter<File>,
    results: BufWriter<File>,
    findings: BufWriter<File>,
}

fn open_append(path: &Path) -> std::io::Result<(File, bool)> {
    let existed = path.exists() && std::fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false);
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok((file, existed))
}

impl Writers {
    fn open(out_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(out_dir)?;

        let (records, _) = open_append(&out_dir.join("records.jsonl"))?;
        let (results, results_existed) = open_append(&out_dir.join("results.csv"))?;
        let (findings, findings_existed) = open_append(&out_dir.join("findings.csv"))?;

        let mut w = Writers {
            records: BufWriter::new(records),
            results: BufWriter::new(results),
            findings: BufWriter::new(findings),
        };
        if !results_existed {
            write_results_header(&mut w.results)?;
        }
        if !findings_existed {
            write_findings_header(&mut w.findings)?;
        }
        Ok(w)
    }

    /// Write one record and flush, so a crash costs at most the current entry.
    fn write(&mut self, r: &EvalRecord) -> std::io::Result<()> {
        write_jsonl_line(&mut self.records, r)?;
        write_results_row(&mut self.results, r)?;
        write_findings_rows(&mut self.findings, r)?;
        self.records.flush()?;
        self.results.flush()?;
        self.findings.flush()
    }
}

/// Turn a `FullScan` plus its entry into a record.
fn record_from_scan(
    entry: &CorpusEntry,
    effective: &LayerMask,
    scan: FullScan,
    keep_evidence: bool,
    total_ms: u64,
    scanned_at: String,
) -> EvalRecord {
    let FullScan {
        report,
        layers,
        layer_ms,
        registry_status,
        declared_deps,
    } = scan;

    let mut layer_records = [
        LayerRecord::not_run(),
        LayerRecord::not_run(),
        LayerRecord::not_run(),
        LayerRecord::not_run(),
    ];
    for (i, slot) in layer_records.iter_mut().enumerate() {
        *slot = match &layers[i] {
            Some(result) => LayerRecord::from_check(result, layer_ms[i], keep_evidence),
            None if !effective.wants(i) => {
                LayerRecord::skipped("not requested for this entry in this mode")
            }
            None => LayerRecord::not_run(),
        };
    }

    // A layer whose result carries the "not found on the npm registry" note tells
    // us the package is gone; a fetch that *failed* is a different fact entirely
    // and must not be scored (see `registry::FetchStatus`).
    let outcome = match &registry_status {
        Some(crate::registry::FetchStatus::NotFound) => Outcome::RegistryNotFound,
        Some(crate::registry::FetchStatus::Failed(_)) => Outcome::RegistryFailed,
        _ => Outcome::Scanned,
    };
    let outcome_detail = match &registry_status {
        Some(crate::registry::FetchStatus::Failed(reason)) => Some(reason.clone()),
        _ => None,
    };

    // A pinned scan reads pinned content but latest-based Layer 0 metadata.
    let l0_metadata_version = if entry.version.is_some() && effective.wants(0) {
        Some("latest".to_string())
    } else {
        None
    };

    EvalRecord::build(RecordInputs {
        entry,
        effective_layers: effective.indices(),
        layers: layer_records,
        risk_score: Some(report.risk_score),
        verdict: Some(report.verdict),
        outcome,
        outcome_detail,
        registry_status: registry_status.as_ref().map(|s| s.as_str().to_string()),
        declared_deps,
        l0_metadata_version,
        total_ms,
        scanned_at,
    })
}

/// Build a record for an entry that could not be reached at all.
fn unscannable(entry: &CorpusEntry, outcome: Outcome, detail: &str, scanned_at: String) -> EvalRecord {
    EvalRecord::build(RecordInputs {
        entry,
        effective_layers: Vec::new(),
        layers: [
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        risk_score: None,
        verdict: None,
        outcome,
        outcome_detail: Some(detail.to_string()),
        registry_status: None,
        declared_deps: None,
        l0_metadata_version: None,
        total_ms: 0,
        scanned_at,
    })
}

/// Scan one entry using ONLY the offline name checks.
///
/// The pure seam of the harness: no network, no filesystem, no Docker, no clock
/// beyond the caller-supplied timestamp. Everything the name-only arm measures
/// goes through here, which is why it can be driven directly from a test.
pub fn scan_entry_name_only(
    entry: &CorpusEntry,
    top_packages: &[String],
    top_scoped: &[String],
    scanned_at: &str,
) -> EvalRecord {
    let started = Instant::now();
    let l0 = crate::run_layer0_name_only(&entry.package, top_packages, top_scoped);
    let ms = started.elapsed().as_millis() as u64;

    let report = crate::aggregate(&entry.package, [Some(&l0), None, None, None]);
    let layers = [
        LayerRecord::from_check(&l0, Some(ms), false),
        LayerRecord::skipped("name-only mode"),
        LayerRecord::skipped("name-only mode"),
        LayerRecord::skipped("name-only mode"),
    ];

    EvalRecord::build(RecordInputs {
        entry,
        effective_layers: vec![0],
        layers,
        risk_score: Some(report.risk_score),
        verdict: Some(report.verdict),
        outcome: Outcome::Scanned,
        outcome_detail: None,
        // We never asked the registry, so there is no status to report — that is
        // distinct from having asked and been told "not found".
        registry_status: None,
        declared_deps: None,
        l0_metadata_version: None,
        total_ms: ms,
        scanned_at: scanned_at.to_string(),
    })
}

/// Scan one entry at the requested depth.
fn scan_entry(
    entry: &CorpusEntry,
    effective: &LayerMask,
    cfg: &EvalConfig,
    top_packages: &[String],
    top_scoped: &[String],
    scanned_at: &str,
) -> EvalRecord {
    let started = Instant::now();

    // In name-only mode a registry-identity entry takes the fully offline path.
    // Other modes fall through to the registry path even when only Layer 0 is
    // requested, because there the metadata checks are wanted too.
    if cfg.mode.is_offline()
        && entry.kind.has_registry_identity()
        && effective.indices() == vec![0]
    {
        return scan_entry_name_only(entry, top_packages, top_scoped, scanned_at);
    }

    match entry.kind {
        Kind::Name | Kind::Holder | Kind::Version => {
            let scan = crate::run_full_registry_collect(
                &entry.package,
                entry.version.as_deref(),
                top_packages,
                top_scoped,
                *effective,
            );
            record_from_scan(
                entry,
                effective,
                scan,
                cfg.keep_evidence,
                started.elapsed().as_millis() as u64,
                scanned_at.to_string(),
            )
        }

        Kind::Dir => {
            let dir = cfg.base_dir.join(entry.path.as_deref().unwrap_or_default());
            if !dir.is_dir() {
                return unscannable(
                    entry,
                    Outcome::SkippedMissing,
                    &format!("directory not found: {}", dir.display()),
                    scanned_at.to_string(),
                );
            }
            let scan = crate::run_full_local_collect(&entry.package, &dir, *effective);
            record_from_scan(
                entry,
                effective,
                scan,
                cfg.keep_evidence,
                started.elapsed().as_millis() as u64,
                scanned_at.to_string(),
            )
        }

        Kind::Sample => {
            let sample_path = entry.path.as_deref().unwrap_or_default();
            match crate::eval::samples::prepare(sample_path, &cfg.samples_dir) {
                Ok(prepared) => {
                    let scan =
                        crate::run_full_local_collect(&entry.package, prepared.dir(), *effective);
                    record_from_scan(
                        entry,
                        effective,
                        scan,
                        cfg.keep_evidence,
                        started.elapsed().as_millis() as u64,
                        scanned_at.to_string(),
                    )
                }
                Err(e) => unscannable(
                    entry,
                    Outcome::SkippedMissing,
                    &format!("sample unavailable: {}", e),
                    scanned_at.to_string(),
                ),
            }
        }
    }
}

/// Read and parse every manifest, or return all problems found across all of
/// them.
fn load_corpus(manifests: &[PathBuf]) -> Result<Vec<CorpusEntry>, BatchError> {
    let mut parsed = Vec::new();
    let mut errors = Vec::new();

    for path in manifests {
        let display = path.display().to_string();
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                errors.push(ManifestError {
                    path: display,
                    line_no: 0,
                    line: String::new(),
                    reason: format!("could not read manifest: {}", e),
                });
                continue;
            }
        };
        match parse_manifest(&text, &display) {
            Ok(entries) => parsed.push(entries),
            Err(mut errs) => errors.append(&mut errs),
        }
    }

    if !errors.is_empty() {
        return Err(BatchError::Manifest(errors));
    }
    merge_manifests(parsed).map_err(BatchError::Manifest)
}

/// Run a batch and write its artifacts.
pub fn run_batch(cfg: &EvalConfig) -> Result<BatchOutcome, BatchError> {
    let entries = load_corpus(&cfg.manifests)?;
    let started_at = chrono::Utc::now();

    let (top_packages, top_scoped) = crate::toplist::load_effective_lists(cfg.refresh_top);

    // Probe Docker once per run rather than once per package. Skipped entirely
    // when the mode's ceiling cannot reach a dynamic layer.
    let needs_docker = cfg.mode.ceiling().wants(2) || cfg.mode.ceiling().wants(3);
    let (docker_version, ptrace_probe) = if needs_docker {
        let version = crate::docker::docker_version();
        let probe = match crate::docker::check_ptrace_capability() {
            crate::docker::PtraceProbe::Granted => "granted",
            crate::docker::PtraceProbe::Denied(_) => "denied",
            crate::docker::PtraceProbe::Unknown(_) => "unknown",
        };
        (version, probe.to_string())
    } else {
        (None, "not_probed".to_string())
    };

    let ceiling = cfg.mode.ceiling();
    let mut records: Vec<EvalRecord> = Vec::with_capacity(entries.len());
    let mut writers = Writers::open(&cfg.out_dir).map_err(|e| {
        BatchError::Io(format!(
            "could not open output files in {}: {}",
            cfg.out_dir.display(),
            e
        ))
    })?;

    let mut filtered_out = 0usize;
    let total = entries.len();

    for (idx, entry) in entries.iter().enumerate() {
        let effective = LayerMask::from_indices(&entry.layers).intersect(&ceiling);
        if effective.is_empty() {
            // Nothing to run for this entry at this depth. Not an error and not a
            // result — counted and reported so the run's coverage is legible.
            filtered_out += 1;
            continue;
        }

        if cfg.verbose {
            eprintln!(
                "[eval {}/{}] {} (layers {:?})",
                idx + 1,
                total,
                entry.entry_id(),
                effective.indices()
            );
        } else if total > 5000 && idx % 10_000 == 0 && idx > 0 {
            // A 200k-name sweep is otherwise silent for minutes.
            eprintln!("[eval] {}/{} entries", idx, total);
        }

        let scanned_at = chrono::Utc::now().to_rfc3339();
        let record = scan_entry(
            entry,
            &effective,
            cfg,
            &top_packages,
            &top_scoped,
            &scanned_at,
        );

        writers.write(&record).map_err(|e| {
            BatchError::Io(format!("could not write record for {}: {}", record.entry_id, e))
        })?;
        records.push(record);
    }

    let degraded = records.iter().any(|r| {
        r.outcome != Outcome::Scanned
            || r.layers
                .iter()
                .any(|l| l.verdict.as_ref() == Some(&Verdict::Error))
    });

    let provenance = RunProvenance {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: Some(chrono::Utc::now().to_rfc3339()),
        eval_mode: cfg.mode.as_str().to_string(),
        manifests: cfg
            .manifests
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        entry_count: total,
        docker_version,
        ptrace_probe,
        docker_timeout_secs: cfg.docker_timeout_secs,
        top_list_refreshed: cfg.refresh_top,
        top_packages_len: top_packages.len(),
        top_scoped_len: top_scoped.len(),
        host_os: std::env::consts::OS.to_string(),
    };

    let metrics = compute(&records, provenance);

    let metrics_path = cfg.out_dir.join("metrics.json");
    let json = serde_json::to_string_pretty(&metrics)
        .map_err(|e| BatchError::Io(format!("could not serialize metrics: {}", e)))?;
    std::fs::write(&metrics_path, json).map_err(|e| {
        BatchError::Io(format!(
            "could not write {}: {}",
            metrics_path.display(),
            e
        ))
    })?;

    Ok(BatchOutcome {
        metrics,
        filtered_out,
        degraded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_parses_and_round_trips() {
        for s in ["name-only", "registry", "full", "auto"] {
            assert_eq!(EvalMode::parse(s).unwrap().as_str(), s);
        }
        assert!(EvalMode::parse("everything").is_none());
        assert!(EvalMode::parse("").is_none());
    }

    #[test]
    fn ceilings_match_what_each_mode_can_actually_reach() {
        assert_eq!(EvalMode::NameOnly.ceiling().indices(), vec![0]);
        assert_eq!(EvalMode::Registry.ceiling().indices(), vec![0, 1]);
        assert_eq!(EvalMode::Full.ceiling().indices(), vec![0, 1, 2, 3]);
        assert_eq!(EvalMode::Auto.ceiling().indices(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn only_name_only_mode_avoids_the_network() {
        assert!(EvalMode::NameOnly.is_offline());
        assert!(!EvalMode::Registry.is_offline());
        assert!(!EvalMode::Full.is_offline());
        assert!(!EvalMode::Auto.is_offline());
    }

    #[test]
    fn the_ceiling_rule_leaves_local_entries_with_nothing_under_name_only() {
        // A dir entry requests layers 1-3; the name-only ceiling permits only 0.
        // Such entries must be filtered and counted, never scored as clean.
        let requested = LayerMask::from_indices(&[1, 2, 3]);
        assert!(requested.intersect(&EvalMode::NameOnly.ceiling()).is_empty());
        assert_eq!(
            requested.intersect(&EvalMode::Registry.ceiling()).indices(),
            vec![1]
        );
        assert_eq!(
            requested.intersect(&EvalMode::Full.ceiling()).indices(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn manifest_errors_render_with_their_location() {
        let err = BatchError::Manifest(vec![ManifestError {
            path: "m.tsv".into(),
            line_no: 7,
            line: "bad line".into(),
            reason: "unknown kind 'x'".into(),
        }]);
        let text = err.to_string();
        assert!(text.contains("m.tsv:7"));
        assert!(text.contains("unknown kind 'x'"));
        assert!(text.contains("1 manifest problem"));
    }
}
