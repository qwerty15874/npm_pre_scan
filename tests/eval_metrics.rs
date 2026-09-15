// Integration tests for the evaluation metric rollups.
//
// Working directory during `cargo test` is the package root (where Cargo.toml
// lives). These tests build synthetic `EvalRecord`s — the same approach
// tests/report_aggregate.rs takes with synthetic `CheckResult`s — so the metric
// arithmetic is verified without a corpus, the registry, or Docker.

use npm_pre_scan::eval::corpus::{parse_manifest, CorpusEntry};
use npm_pre_scan::eval::metrics::{compute, percentile, Confusion};
use npm_pre_scan::eval::record::{
    Classification, EvalRecord, LayerRecord, Outcome, RecordInputs, RunProvenance,
};
use npm_pre_scan::models::{CheckResult, Finding, Verdict};
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

fn layer(findings: Vec<Finding>, verdict: Verdict, ms: u64) -> LayerRecord {
    let score = if findings.is_empty() { 0 } else { 50 };
    LayerRecord::from_check(
        &CheckResult {
            package: "p".into(),
            verdict,
            score,
            findings,
            note: None,
        },
        Some(ms),
        false,
    )
}

/// Build a record with an explicit per-layer layout.
fn record(
    line: &str,
    layers: [LayerRecord; 4],
    verdict: Verdict,
    deps: Option<usize>,
    total_ms: u64,
) -> EvalRecord {
    let e = entry(line);
    EvalRecord::build(RecordInputs {
        effective_layers: e.layers.clone(),
        entry: &e,
        layers,
        risk_score: Some(0.5),
        verdict: Some(verdict),
        outcome: Outcome::Scanned,
        outcome_detail: None,
        registry_status: Some("found".into()),
        declared_deps: deps,
        vendored: false,
        l0_metadata_version: None,
        total_ms,
        scanned_at: "2026-07-30T00:00:00Z".into(),
    })
}

/// A malicious entry detected at Layer 0 only.
fn tp_l0(name: &str) -> EvalRecord {
    record(
        &format!("name\t{}\treal_malicious\tmalicious\tA1\t0", name),
        [
            layer(vec![finding("typosquat", "BLOCK", "A1")], Verdict::Block, 10),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        Verdict::Block,
        None,
        10,
    )
}

/// A benign entry that nothing accuses.
fn tn(name: &str, ms: u64) -> EvalRecord {
    record(
        &format!("name\t{}\tparent_benign\tbenign\t-\t0", name),
        [
            layer(vec![], Verdict::Pass, ms),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        Verdict::Pass,
        None,
        ms,
    )
}

fn provenance() -> RunProvenance {
    RunProvenance {
        tool_version: "test".into(),
        started_at: "2026-07-30T00:00:00Z".into(),
        finished_at: None,
        eval_mode: "name-only".into(),
        manifests: vec!["t".into()],
        entry_count: 0,
        docker_version: None,
        ptrace_probe: "not_probed".into(),
        docker_timeout_secs: None,
        top_list_refreshed: false,
        top_packages_len: 1137,
        top_scoped_len: 94,
        host_os: "linux".into(),
    }
}

#[test]
fn hand_computed_confusion_matrix_over_six_records() {
    let records = vec![
        tp_l0("expres"),  // TP
        tp_l0("lodahs"),  // TP
        tn("lodash", 5),  // TN
        tn("express", 5), // TN
        // FN: malicious, nothing fires
        record(
            "name\td3.js\treal_malicious\tmalicious\tA1\t0",
            [
                layer(vec![], Verdict::Pass, 5),
                LayerRecord::not_run(),
                LayerRecord::not_run(),
                LayerRecord::not_run(),
            ],
            Verdict::Pass,
            None,
            5,
        ),
        // FP: benign, a rule fires
        record(
            "name\tfabric\tparent_benign\tbenign\t-\t0",
            [
                layer(vec![finding("combosquat", "SUSPECT", "A4")], Verdict::Suspect, 5),
                LayerRecord::not_run(),
                LayerRecord::not_run(),
                LayerRecord::not_run(),
            ],
            Verdict::Suspect,
            None,
            5,
        ),
    ];

    let m = compute(&records, provenance());
    assert_eq!(m.record_count, 6);
    assert_eq!(m.overall.true_positive, 2);
    assert_eq!(m.overall.true_negative, 2);
    assert_eq!(m.overall.false_negative, 1);
    assert_eq!(m.overall.false_positive, 1);
    assert_eq!(m.overall.scored(), 6);

    assert_eq!(m.overall_rates.recall, Some(2.0 / 3.0));
    assert_eq!(m.overall_rates.precision, Some(2.0 / 3.0));
    assert_eq!(m.overall_rates.fpr, Some(1.0 / 3.0));
    assert_eq!(m.outcomes.scanned, 6);

    // Groups are reported separately and must not blend.
    let real = m.by_group.iter().find(|g| g.group == "real_malicious").unwrap();
    assert_eq!(real.confusion.true_positive, 2);
    assert_eq!(real.confusion.false_negative, 1);
    let benign = m.by_group.iter().find(|g| g.group == "parent_benign").unwrap();
    assert_eq!(benign.confusion.false_positive, 1);
    assert_eq!(benign.rates.fpr, Some(1.0 / 3.0));
    assert_eq!(benign.rates.recall, None, "a benign-only group has no recall");
}

#[test]
fn artifact_false_negatives_are_reported_but_excluded_from_recall() {
    let holder = record(
        "holder\tffmepg\treal_malicious\tmalicious\tA1\t0",
        [
            layer(vec![], Verdict::Pass, 5),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        Verdict::Pass,
        None,
        5,
    );
    assert_eq!(holder.classification, Classification::ArtifactFalseNegative);

    let m = compute(&[tp_l0("crossenv"), holder], provenance());
    assert_eq!(m.overall.artifact_fn, 1);
    assert_eq!(m.overall.false_negative, 0);
    // 1 TP, 0 real FN — the unscannable entry must not drag recall to 50%.
    assert_eq!(m.overall_rates.recall, Some(1.0));
    assert_eq!(m.overall.scored(), 1);
}

#[test]
fn suspect_records_flip_to_false_negative_at_the_block_only_operating_point() {
    let r = record(
        "name\tsuspicious-pkg\tdummy\tmalicious\tA4\t0",
        [
            layer(vec![finding("combosquat", "SUSPECT", "A4")], Verdict::Suspect, 5),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        Verdict::Suspect,
        None,
        5,
    );
    let m = compute(&[r], provenance());
    assert_eq!(m.overall.true_positive, 1);
    assert_eq!(m.overall.false_negative, 0);
    assert_eq!(m.overall_block_only.true_positive, 0);
    assert_eq!(m.overall_block_only.false_negative, 1);
    assert_eq!(m.overall_rates.recall, Some(1.0));
    assert_eq!(m.overall_block_only_rates.recall, Some(0.0));
}

#[test]
fn sole_detector_credits_only_the_layer_that_caught_it_alone() {
    // Layer 3 alone catches a time bomb: L1 and L2 are clean.
    let l3_only = record(
        "dir\tdummy_packages/dummy_timebomb\tdummy\tmalicious\tD1\t1,2,3",
        [
            LayerRecord::not_run(),
            layer(vec![], Verdict::Pass, 20),
            layer(vec![], Verdict::Pass, 30),
            layer(vec![finding("timebomb", "SUSPECT", "D1")], Verdict::Suspect, 40),
        ],
        Verdict::Suspect,
        Some(0),
        90,
    );
    // Both L1 and L2 catch this one, so neither is a sole detector.
    let both = record(
        "dir\tdummy_packages/dummy_obfuscated\tdummy\tmalicious\tB2\t1,2,3",
        [
            LayerRecord::not_run(),
            layer(vec![finding("obfuscation", "BLOCK", "B2")], Verdict::Block, 20),
            layer(vec![finding("install_script_exec", "BLOCK", "B1")], Verdict::Block, 30),
            layer(vec![], Verdict::Pass, 40),
        ],
        Verdict::Block,
        Some(0),
        90,
    );

    let m = compute(&[l3_only, both], provenance());
    let l = |n: usize| &m.by_layer[n];
    assert_eq!(l(3).sole_detector, 1, "L3 caught the timebomb alone");
    assert_eq!(l(1).sole_detector, 0, "L1 was never the only detector");
    assert_eq!(l(2).sole_detector, 0, "L2 was never the only detector");
    assert_eq!(l(0).sole_detector, 0);

    assert_eq!(l(1).ran, 2);
    assert_eq!(l(1).block, 1);
    assert_eq!(l(3).suspect, 1);
    assert_eq!(l(0).not_run, 2);
}

#[test]
fn dependency_bearing_records_are_excluded_from_dynamic_layer_stats() {
    // express has 28 dependencies: the offline sandbox cannot install them, so
    // its empty L2/L3 profile is vacuous and must not be counted as precision.
    let heavy = record(
        "name\texpress\tparent_benign\tbenign\t-\t0,1,2,3",
        [
            layer(vec![], Verdict::Pass, 5),
            layer(vec![], Verdict::Pass, 10),
            layer(vec![], Verdict::Pass, 20),
            layer(vec![], Verdict::Pass, 30),
        ],
        Verdict::Pass,
        Some(28),
        65,
    );
    assert!(!heavy.dyn_valid);
    assert_eq!(heavy.admissible_layers(), vec![0, 1]);

    let light = record(
        "name\tjquery\tparent_benign\tbenign\t-\t0,1,2,3",
        [
            layer(vec![], Verdict::Pass, 5),
            layer(vec![], Verdict::Pass, 10),
            layer(vec![], Verdict::Pass, 20),
            layer(vec![], Verdict::Pass, 30),
        ],
        Verdict::Pass,
        Some(0),
        65,
    );
    assert!(light.dyn_valid);

    let m = compute(&[heavy, light], provenance());
    // Execution status counts both; the observation counts only the valid one.
    assert_eq!(m.by_layer[2].ran, 2);
    assert_eq!(m.by_layer[2].pass, 1);
    assert_eq!(m.by_layer[2].excluded_not_dyn_valid, 1);
    // Layers 0 and 1 never exclude anything.
    assert_eq!(m.by_layer[0].excluded_not_dyn_valid, 0);
    assert_eq!(m.by_layer[1].excluded_not_dyn_valid, 0);
}

#[test]
fn per_vector_recall_and_false_hits_are_tracked_separately() {
    let detected = record(
        "name\texpres\tdummy\tmalicious\tA1\t0",
        [
            layer(vec![finding("typosquat", "BLOCK", "A1")], Verdict::Block, 5),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        Verdict::Block,
        None,
        5,
    );
    let missed = record(
        "name\td3.js\tdummy\tmalicious\tA1\t0",
        [
            layer(vec![], Verdict::Pass, 5),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        Verdict::Pass,
        None,
        5,
    );
    // A4 fires on a benign package: a false hit, and it was never expected.
    let false_hit = record(
        "name\tsome-legit-pkg\tparent_benign\tbenign\t-\t0",
        [
            layer(vec![finding("combosquat", "SUSPECT", "A4")], Verdict::Suspect, 5),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        Verdict::Suspect,
        None,
        5,
    );

    let m = compute(&[detected, missed, false_hit], provenance());
    let a1 = m.by_vector.iter().find(|v| v.vector == "A1").unwrap();
    assert_eq!(a1.expected, 2);
    assert_eq!(a1.detected, 1);
    assert_eq!(a1.missed, 1);
    assert_eq!(a1.recall, Some(0.5));
    assert_eq!(a1.false_hits, 0);

    let a4 = m.by_vector.iter().find(|v| v.vector == "A4").unwrap();
    assert_eq!(a4.expected, 0, "no entry declared A4");
    assert_eq!(a4.recall, None, "undefined, not zero");
    assert_eq!(a4.total_fires, 1);
    assert_eq!(a4.false_hits, 1);

    // A vector nobody expected and nobody fired stays fully zeroed.
    let e1 = m.by_vector.iter().find(|v| v.vector == "E1").unwrap();
    assert_eq!((e1.expected, e1.total_fires, e1.recall), (0, 0, None));
}

#[test]
fn timing_percentiles_and_slowest_list_are_deterministic() {
    let records: Vec<EvalRecord> = (1..=10)
        .map(|i| tn(&format!("pkg-{}", i), (i * 100) as u64))
        .collect();
    let m = compute(&records, provenance());
    assert_eq!(m.timing.total_ms, 5500);
    assert_eq!(m.timing.max, 1000);
    assert_eq!(m.timing.p50, percentile(&(1..=10).map(|i| i * 100).collect::<Vec<u64>>(), 0.5));
    assert_eq!(m.timing.slowest.len(), 10);
    assert_eq!(m.timing.slowest[0].1, 1000);
    // Descending order.
    assert!(m.timing.slowest.windows(2).all(|w| w[0].1 >= w[1].1));
}

#[test]
fn an_empty_record_set_yields_nulls_not_zeroes() {
    let m = compute(&[], provenance());
    assert_eq!(m.record_count, 0);
    assert_eq!(m.overall_rates.recall, None);
    assert_eq!(m.overall_rates.fpr, None);
    assert_eq!(m.overall_rates.f1, None);
    assert!(m.by_group.is_empty());
    assert_eq!(m.by_layer.len(), 4, "layer rows exist even with no data");
    assert_eq!(m.timing.total_ms, 0);

    // The distinction must survive serialization: null, never 0.0.
    let json = serde_json::to_string(&m.overall_rates).unwrap();
    assert!(json.contains("\"recall\":null"), "got {}", json);
    assert!(!json.contains("\"recall\":0"), "got {}", json);
}

#[test]
fn metrics_summary_round_trips_through_json() {
    let m = compute(&[tp_l0("expres"), tn("lodash", 5)], provenance());
    let json = serde_json::to_string(&m).unwrap();
    let back: npm_pre_scan::eval::metrics::MetricsSummary =
        serde_json::from_str(&json).expect("metrics.json must be readable back");
    assert_eq!(back.record_count, 2);
    assert_eq!(back.overall.true_positive, 1);
    assert_eq!(back.overall.true_negative, 1);
}

#[test]
fn summary_renders_without_panicking_and_names_the_key_numbers() {
    let m = compute(&[tp_l0("expres"), tn("lodash", 5)], provenance());
    let mut out = Vec::new();
    npm_pre_scan::eval::metrics::render_summary(&mut out, &m).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("EVALUATION SUMMARY"));
    assert!(text.contains("recall="));
    assert!(text.contains("BLOCK-only"));
    assert!(text.contains("real_malicious"));

    // An undefined rate must render as n/a rather than a misleading 0.0%.
    let empty = compute(&[], provenance());
    let mut out = Vec::new();
    npm_pre_scan::eval::metrics::render_summary(&mut out, &empty).unwrap();
    assert!(String::from_utf8(out).unwrap().contains("n/a"));
}

#[test]
fn confusion_add_maps_every_classification_to_its_own_bucket() {
    let mut c = Confusion::default();
    for cls in [
        Classification::TruePositive,
        Classification::FalsePositive,
        Classification::TrueNegative,
        Classification::FalseNegative,
        Classification::ArtifactFalseNegative,
        Classification::Error,
        Classification::Skipped,
    ] {
        c.add(cls);
    }
    assert_eq!(
        (
            c.true_positive,
            c.false_positive,
            c.true_negative,
            c.false_negative,
            c.artifact_fn,
            c.error,
            c.skipped
        ),
        (1, 1, 1, 1, 1, 1, 1)
    );
    assert_eq!(c.scored(), 4, "only the four cells are scored");
}
