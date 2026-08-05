// Docker-gated integration tests for the full evaluation batch path.
//
// Working directory during `cargo test` is the package root (where Cargo.toml
// lives). These tests are `#[ignore]`d — run them with
// `cargo test --test eval_batch_docker -- --ignored` on a Docker-capable host.
// They need `dummy_packages/` (gitignored), like the other dummy-driven tests.
//
// The point of these is to prove the batch driver produces the same verdicts as
// the single-package path and that its bookkeeping is honest — in particular that
// the memoized one-time image build did not cause a layer to be silently skipped.

use std::path::{Path, PathBuf};

use npm_pre_scan::eval::metrics::MetricsSummary;
use npm_pre_scan::eval::record::{Classification, EvalRecord, Outcome};
use npm_pre_scan::eval::runner::{run_batch, EvalConfig, EvalMode};
use npm_pre_scan::report::LayerStatus;

fn config(manifest: &str, mode: EvalMode, out: &Path) -> EvalConfig {
    EvalConfig {
        manifests: vec![PathBuf::from(manifest)],
        out_dir: out.to_path_buf(),
        mode,
        docker_timeout_secs: Some(900),
        keep_evidence: false,
        refresh_top: false,
        base_dir: PathBuf::from("."),
        samples_dir: PathBuf::from("eval/samples"),
        verbose: false,
    }
}

/// Write a temporary manifest and return its path inside `dir`.
fn write_manifest(dir: &std::path::Path, body: &str) -> String {
    let path = dir.join("manifest.tsv");
    std::fs::write(&path, body).expect("could not write test manifest");
    path.display().to_string()
}

fn read_records(out: &Path) -> Vec<EvalRecord> {
    let text = std::fs::read_to_string(out.join("records.jsonl")).expect("records.jsonl missing");
    text.lines()
        .map(|l| serde_json::from_str(l).expect("a records.jsonl line failed to parse"))
        .collect()
}

#[test]
#[ignore]
fn batch_over_two_dummies_scores_one_tp_and_one_tn() {
    if !npm_pre_scan::docker::docker_available() {
        eprintln!("skipping: docker not available");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");

    // dummy_timebomb is only detectable by Layer 3's clock mutation, and
    // dummy_benign_l3 must stay clean through all three layers — together they
    // exercise both directions of the dynamic path in one batch.
    let manifest = write_manifest(
        tmp.path(),
        "dir\tdummy_packages/dummy_timebomb\tdummy\tmalicious\tD1\t1,2,3\ttime bomb\n\
         dir\tdummy_packages/dummy_benign_l3\tdummy\tbenign\t-\t1,2,3\tprecision control\n",
    );

    let mut cfg = config(&manifest, EvalMode::Full, &out);
    cfg.manifests = vec![PathBuf::from(&manifest)];
    let outcome = run_batch(&cfg).expect("batch must run");

    assert_eq!(outcome.metrics.record_count, 2);
    assert_eq!(outcome.filtered_out, 0);

    let records = read_records(&out);
    let timebomb = records
        .iter()
        .find(|r| r.package == "dummy_timebomb")
        .expect("no timebomb record");
    let benign = records
        .iter()
        .find(|r| r.package == "dummy_benign_l3")
        .expect("no benign record");

    assert_eq!(
        timebomb.classification,
        Classification::TruePositive,
        "timebomb was not detected: verdict={:?} detected={:?}",
        timebomb.verdict,
        timebomb.detected_vectors
    );
    assert_eq!(
        benign.classification,
        Classification::TrueNegative,
        "benign control false-positived: detections={:?}",
        benign.detected_vectors
    );

    // Both dummies are dependency-free, so their dynamic results are admissible
    // — if this fails, the run measured nothing about Layers 2/3.
    for r in [timebomb, benign] {
        assert_eq!(r.declared_deps, Some(0), "{} should be dep-free", r.package);
        assert!(r.dyn_valid, "{} dynamic result should be admissible", r.package);
        assert_eq!(r.admissible_layers(), vec![1, 2, 3]);
    }
}

#[test]
#[ignore]
fn the_memoized_image_build_does_not_skip_a_layer_on_later_entries() {
    if !npm_pre_scan::docker::docker_available() {
        eprintln!("skipping: docker not available");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");

    // Two entries in one process: the second must get the same layer coverage as
    // the first even though `ensure_layer_image` only builds once.
    let manifest = write_manifest(
        tmp.path(),
        "dir\tdummy_packages/dummy_benign_l3\tdummy\tbenign\t-\t1,2,3\tfirst\n\
         dir\tdummy_packages/dummy_import_time\tdummy\tmalicious\tC1\t1,2,3\tsecond\n",
    );

    let outcome = run_batch(&config(&manifest, EvalMode::Full, &out)).expect("batch must run");

    // Every layer must have RUN for both entries, not errored or been skipped.
    for layer in 1..4usize {
        let m = &outcome.metrics.by_layer[layer];
        assert_eq!(
            m.ran, 2,
            "layer {} ran {} times, expected 2 (error={} skipped={} not_run={})",
            layer, m.ran, m.error, m.skipped, m.not_run
        );
        assert_eq!(m.error, 0, "layer {} errored", layer);
    }

    let records = read_records(&out);
    for r in &records {
        assert_eq!(r.layers[0].status, LayerStatus::Skipped, "local entries have no L0");
        for layer in 1..4 {
            assert_eq!(
                r.layers[layer].status,
                LayerStatus::Ran,
                "{} layer {} did not run: {:?}",
                r.package,
                layer,
                r.layers[layer].note
            );
        }
        // Timings prove the layers actually executed rather than short-circuiting.
        assert!(
            r.layers[2].ms.unwrap_or(0) > 0,
            "{} layer 2 reported no elapsed time",
            r.package
        );
        assert!(r.total_ms > 0);
    }

    // dummy_import_time does its DNS lookup at import, which is Layer 2's job.
    let import_time = records
        .iter()
        .find(|r| r.package == "dummy_import_time")
        .unwrap();
    assert_eq!(import_time.classification, Classification::TruePositive);
    assert!(
        import_time.detected_vectors.contains(&"C1".to_string()),
        "expected C1, got {:?}",
        import_time.detected_vectors
    );
}

#[test]
#[ignore]
fn metrics_json_is_written_and_readable_back() {
    if !npm_pre_scan::docker::docker_available() {
        eprintln!("skipping: docker not available");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let manifest = write_manifest(
        tmp.path(),
        "dir\tdummy_packages/dummy_benign_l3\tdummy\tbenign\t-\t1\tstatic only\n",
    );

    run_batch(&config(&manifest, EvalMode::Full, &out)).expect("batch must run");

    let text = std::fs::read_to_string(out.join("metrics.json")).expect("metrics.json missing");
    let m: MetricsSummary = serde_json::from_str(&text).expect("metrics.json must round-trip");

    assert_eq!(m.record_count, 1);
    assert_eq!(m.provenance.eval_mode, "full");
    assert_eq!(m.provenance.tool_version, env!("CARGO_PKG_VERSION"));
    assert!(m.provenance.docker_version.is_some(), "docker version not recorded");
    assert!(m.provenance.finished_at.is_some());
    // What this actually guards is that the runner recorded the EMBEDDED list,
    // not a `--refresh-top` sweep (asserted on the next line). Comparing against
    // the embedded list's own length rather than a hard-coded count keeps that
    // guarantee without breaking every time the curated list is edited — v18
    // added five "absent parent" names and moved it 1137 -> 1142.
    assert_eq!(
        m.provenance.top_packages_len,
        npm_pre_scan::typosquat::load_top_packages().len()
    );
    assert!(m.provenance.top_packages_len > 1000, "list looks truncated");
    assert!(!m.provenance.top_list_refreshed);
    assert_eq!(m.provenance.docker_timeout_secs, Some(900));

    // The manifest asked for Layer 1 only, so 2 and 3 must be Skipped rather
    // than silently reported as clean.
    let records = read_records(&out);
    assert_eq!(records[0].effective_layers, vec![1]);
    assert_eq!(records[0].layers[1].status, LayerStatus::Ran);
    for layer in [2, 3] {
        assert_eq!(records[0].layers[layer].status, LayerStatus::Skipped);
    }

    // All three data files exist and the CSVs have exactly one header row.
    for name in ["records.jsonl", "results.csv", "findings.csv"] {
        assert!(out.join(name).is_file(), "{} missing", name);
    }
    let results = std::fs::read_to_string(out.join("results.csv")).unwrap();
    assert_eq!(
        results.lines().filter(|l| l.starts_with("entry_id,")).count(),
        1
    );
    assert_eq!(results.lines().count(), 2, "header + one row");
}

#[test]
#[ignore]
fn a_missing_directory_is_skipped_rather_than_scored() {
    // No Docker needed: the entry is skipped before any layer runs. Kept in this
    // file because it shares the batch-driver setup.
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    let manifest = write_manifest(
        tmp.path(),
        "dir\tdummy_packages/definitely_not_present\tdummy\tmalicious\tD1\t1,2,3\tabsent\n",
    );

    let outcome = run_batch(&config(&manifest, EvalMode::Full, &out)).expect("batch must run");

    let records = read_records(&out);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].outcome, Outcome::SkippedMissing);
    assert_eq!(records[0].classification, Classification::Skipped);
    // A skipped entry must not land in any confusion cell.
    assert_eq!(outcome.metrics.overall.scored(), 0);
    assert_eq!(outcome.metrics.overall.skipped, 1);
    assert_eq!(outcome.metrics.overall_rates.recall, None);
    assert!(outcome.degraded, "a skipped entry means the run was incomplete");
}

#[test]
#[ignore]
fn a_real_datadog_sample_runs_end_to_end() {
    // Needs network (to fetch the sample) as well as Docker. Fetches ONE small
    // real malicious package, scans it in the sandbox, and asserts the harness
    // records a detection. The sample stays encrypted at rest under
    // eval/samples/ and is extracted only into a TempDir — see
    // src/eval/samples.rs for the safety rules.
    if !npm_pre_scan::docker::docker_available() {
        eprintln!("skipping: docker not available");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");

    // perfetto-dev: a 2.6 KB malicious_intent sample whose postinstall exfiltrates
    // hostname and platform over HTTPS. Dependency-free, so its dynamic result is
    // admissible.
    let manifest = write_manifest(
        tmp.path(),
        "sample\tmalicious_intent/perfetto-dev/1.0.0/2025-09-13-perfetto-dev-v1.0.0.zip\tdatadog\tmalicious\tB1\t1,2,3\treal install-time exfiltration\n",
    );

    let outcome = run_batch(&config(&manifest, EvalMode::Full, &out)).expect("batch must run");
    let records = read_records(&out);
    assert_eq!(records.len(), 1);
    let r = &records[0];

    if r.outcome == Outcome::SkippedMissing {
        eprintln!("skipping: sample could not be fetched ({:?})", r.outcome_detail);
        return;
    }

    assert_eq!(r.package, "perfetto-dev");
    assert_eq!(r.version.as_deref(), Some("1.0.0"));
    assert_eq!(
        r.classification,
        Classification::TruePositive,
        "real malware went undetected: verdict={:?} detections={:?}",
        r.verdict,
        r.detected_vectors
    );
    assert!(
        !r.detected_vectors.is_empty(),
        "a detection must name at least one vector"
    );
    assert_eq!(outcome.metrics.overall.true_positive, 1);
}
