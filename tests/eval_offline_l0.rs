// Integration tests for the offline Layer 0 name-only evaluation path.
//
// Working directory during `cargo test` is the package root (where Cargo.toml
// lives). Nothing here touches the network, Docker, or the filesystem: the
// name-only scan is driven through `scan_entry_name_only` with hand-built
// comparison lists, so the assertions describe the detector's behaviour and not
// the current contents of data/top_packages.txt.
//
// Several tests here deliberately assert that the detector MISSES something.
// Those are not aspirational — they pin current behaviour so the harness is
// demonstrably capable of surfacing the gap rather than hiding it. If a later
// change closes one of these gaps, the test should fail and be updated to the
// new (better) behaviour along with the experiment report.

use npm_pre_scan::eval::corpus::{parse_manifest, CorpusEntry};
use npm_pre_scan::eval::metrics::compute;
use npm_pre_scan::eval::record::{Classification, Outcome, RunProvenance};
use npm_pre_scan::eval::runner::scan_entry_name_only;
use npm_pre_scan::models::Verdict;
use npm_pre_scan::report::LayerStatus;

/// The 2017 typosquat campaign's parents, as a stand-in comparison corpus.
fn top() -> Vec<String> {
    [
        "express",
        "lodash",
        "cross-env",
        "babel-cli",
        "d3",
        "jquery",
        "mongoose",
        "mysql",
        "node-sass",
        "sqlite3",
        "nodemailer",
        "http-proxy",
        "grunt-cli",
        "chalk",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn scoped() -> Vec<String> {
    ["@aws-sdk/client-s3", "@babel/core"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn entry(line: &str) -> CorpusEntry {
    parse_manifest(line, "t")
        .unwrap_or_else(|e| panic!("bad test manifest line: {:?}", e))
        .into_iter()
        .next()
        .unwrap()
}

fn scan(line: &str) -> npm_pre_scan::eval::record::EvalRecord {
    scan_entry_name_only(&entry(line), &top(), &scoped(), "2026-07-30T00:00:00Z")
}

fn malicious(name: &str) -> npm_pre_scan::eval::record::EvalRecord {
    scan(&format!(
        "name\t{}\treal_malicious\tmalicious\tA1\t0",
        name
    ))
}

fn benign(name: &str) -> npm_pre_scan::eval::record::EvalRecord {
    scan(&format!("name\t{}\tparent_benign\tbenign\t-\t0", name))
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
        top_packages_len: 14,
        top_scoped_len: 2,
        host_os: "linux".into(),
    }
}

#[test]
fn a_one_character_typosquat_is_detected_and_scored_a_true_positive() {
    let r = malicious("expres");
    assert_eq!(r.verdict, Some(Verdict::Block));
    assert_eq!(r.classification, Classification::TruePositive);
    assert_eq!(r.detected_vectors, vec!["A1"]);
    assert_eq!(r.matched_expected, vec!["A1"]);
    assert!(r.missed_expected.is_empty());
    assert_eq!(r.outcome, Outcome::Scanned);
}

#[test]
fn the_legitimate_parent_is_a_true_negative_despite_its_info_finding() {
    // Scanning a popular package produces an INFO "exact match" A1 finding. If
    // that counted as a detection, every benign control would read as a false
    // positive and the measured FPR would be meaningless.
    let r = benign("cross-env");
    assert_eq!(r.verdict, Some(Verdict::Pass));
    assert_eq!(r.classification, Classification::TrueNegative);
    assert_eq!(r.layers[0].findings.len(), 1, "the INFO finding is recorded");
    assert_eq!(
        r.layers[0].findings[0]["severity"].as_str(),
        Some("INFO")
    );
    assert!(
        r.detected_vectors.is_empty(),
        "an INFO finding must not register as a detection"
    );
    assert!(r.unexpected_vectors.is_empty());
}

#[test]
fn the_name_only_path_never_asks_the_registry() {
    let r = malicious("expres");
    // No registry status at all — distinct from having asked and been told
    // "not found", which is what `Outcome::RegistryNotFound` means.
    assert_eq!(r.registry_status, None);
    assert_eq!(r.effective_layers, vec![0]);
    assert_eq!(r.layers[0].status, LayerStatus::Ran);
    for i in 1..4 {
        assert_eq!(r.layers[i].status, LayerStatus::Skipped);
        assert_eq!(
            r.layers[i].note.as_deref(),
            Some("name-only mode"),
            "layer {} must say why it did not run",
            i
        );
    }
    // The Layer 0 note marks the mode, so a record cannot be mistaken for a
    // full registry-backed scan after the fact.
    assert!(r.layers[0]
        .note
        .as_deref()
        .unwrap()
        .contains("Name-only mode"));
}

#[test]
fn dependency_free_claims_are_never_made_in_name_only_mode() {
    // Nothing was extracted, so the dependency count is unknown — and unknown
    // must not be treated as zero, or Layer 2/3 records would later be admitted
    // on the strength of a value nobody measured.
    let r = malicious("expres");
    assert_eq!(r.declared_deps, None);
    assert!(!r.dyn_valid);
    assert_eq!(r.admissible_layers(), vec![0]);
}

#[test]
fn js_suffix_typosquats_are_detected_as_suffix_squats() {
    // WAS a documented gap (v17): `typosquat::bare_name` stripped only the
    // `@scope/` prefix, so `d3.js` sat at Levenshtein distance 3 from `d3` and no
    // A1 finding fired. That accounted for 9 of the 21 measured A1 misses.
    //
    // v18 folds a trailing `.js`/`-js`/`_js` for the DISTANCE comparison only.
    // The ordering matters: folding before the exact-match test would make
    // `jquery.js` compare equal to `jquery` and return INFO, downgrading a real
    // 2017-campaign typosquat into a note that the package is popular. A name
    // that matches only after folding is reported as a suffix squat instead.
    for name in [
        "d3.js",
        "jquery.js",
        "cross-env.js",
        "http-proxy.js",
        "nodemailer.js",
    ] {
        let r = malicious(name);
        assert_eq!(
            r.classification,
            Classification::TruePositive,
            "{name} should now be caught as a suffix squat"
        );
        assert_eq!(r.detected_vectors, vec!["A1"], "{name}");
        assert!(r.missed_expected.is_empty(), "{name}");
        assert_eq!(r.verdict, Some(Verdict::Block), "{name}");

        let f = &r.layers[0].findings[0];
        assert_eq!(f["distance"].as_u64(), Some(0), "{name}");
        assert!(
            f["message"].as_str().is_some_and(|m| m.contains("Suffix squat")),
            "{name}: {f:?}"
        );
    }
}

#[test]
fn a_genuine_package_is_not_turned_into_a_suffix_squat() {
    // The counterpart FP control for the rule above: the real package must keep
    // its INFO-only exact match and must not be dragged into a BLOCK.
    let r = benign("jquery");
    assert_eq!(r.verdict, Some(Verdict::Pass));
    assert_eq!(r.classification, Classification::TrueNegative);
    assert_eq!(
        r.layers[0].findings[0]["severity"].as_str(),
        Some("INFO"),
        "an exact match is INFO, never a squat"
    );
}

#[test]
fn a_short_name_two_edits_away_is_no_longer_accused() {
    // v17 measured `smb`→`pm2` as an accidental "hit" — two edits on a 3-char
    // name is coincidence, not a typo, and it inflated the honest A1 count from
    // 7/30 to 9/30. The distance-2 branch now carries the same length guard the
    // distance-1 branch always had.
    let r = scan("name\tsmb\treal_malicious\tmalicious\tA1\t0");
    assert!(
        r.layers[0].findings.is_empty(),
        "expected no A1 accusation on a 3-char name; got {:?}",
        r.layers[0].findings
    );
}

#[test]
fn a_typosquat_of_an_absent_parent_cannot_be_detected() {
    // `ffmepg` is one character from `ffmpeg`, but `ffmpeg` is not in the
    // comparison list, so there is nothing for it to be near. This is a
    // corpus-coverage miss, independent of the algorithm gap above — and the
    // metrics must be able to tell the two causes apart.
    let r = malicious("ffmepg");
    assert_eq!(r.classification, Classification::FalseNegative);
    assert!(r.layers[0].findings.is_empty(), "no finding at all, not even INFO");

    // Contrast: the same shape of typo against a parent that IS in the list.
    let detectable = malicious("mongose");
    assert_eq!(detectable.classification, Classification::TruePositive);
    // The A1 finding names what it matched and how far away it was, which is
    // what lets the report separate "threshold too tight" from "parent absent".
    let f = &detectable.layers[0].findings[0];
    assert_eq!(f["closest"].as_str(), Some("mongoose"));
    assert_eq!(f["distance"].as_u64(), Some(1));
}

#[test]
fn a_namespace_conflict_is_detected_from_the_name_alone() {
    let r = scan("name\taws-sdk-client-s3\treal_malicious\tmalicious\tA2\t0");
    assert_eq!(r.verdict, Some(Verdict::Block));
    assert_eq!(r.classification, Classification::TruePositive);
    assert_eq!(r.detected_vectors, vec!["A2"]);
}

#[test]
fn a_holder_entry_that_goes_undetected_is_an_artifact_not_a_miss() {
    // Same undetected name, but declared as a takedown stub: the corpus cannot
    // deliver its malicious content, so this is ARTIFACT_FN and stays out of
    // recall's denominator.
    let r = scan("holder\tffmepg\treal_malicious\tmalicious\tA1\t0");
    assert_eq!(r.classification, Classification::ArtifactFalseNegative);

    let as_plain_name = malicious("ffmepg");
    assert_eq!(as_plain_name.classification, Classification::FalseNegative);
}

#[test]
fn a_completely_unrelated_name_produces_no_findings() {
    let r = scan("name\tzzz-some-unique-thing\tdummy\tbenign\t-\t0");
    assert_eq!(r.verdict, Some(Verdict::Pass));
    assert!(r.layers[0].findings.is_empty());
    assert_eq!(r.risk_score, Some(0.0));
    assert_eq!(r.classification, Classification::TrueNegative);
}

#[test]
fn a_small_arm_a_style_sweep_produces_coherent_metrics() {
    // A miniature version of the real arm A: real malicious names plus their
    // legitimate parents, scored together.
    let records = vec![
        malicious("expres"),   // TP
        malicious("mongose"),  // TP
        malicious("lodahs"),   // TP
        malicious("d3.js"),    // TP since v18 — suffix squat (was FN)
        malicious("ffmepg"),   // FN — parent absent from THIS test's list
        benign("express"),     // TN
        benign("lodash"),      // TN
        benign("d3"),          // TN
    ];

    let m = compute(&records, provenance());
    assert_eq!(m.record_count, 8);
    assert_eq!(m.overall.true_positive, 4);
    assert_eq!(m.overall.false_negative, 1);
    assert_eq!(m.overall.true_negative, 3);
    assert_eq!(
        m.overall.false_positive, 0,
        "no legitimate parent may be flagged"
    );
    assert_eq!(m.overall_rates.recall, Some(0.8));
    assert_eq!(m.overall_rates.fpr, Some(0.0));

    // Layer 0 did all the work, so it is the sole detector for every hit.
    assert_eq!(m.by_layer[0].ran, 8);
    assert_eq!(m.by_layer[0].sole_detector, 4);
    assert_eq!(m.by_layer[0].false_hits, 0);
    for i in 1..4 {
        assert_eq!(m.by_layer[i].ran, 0);
        assert_eq!(m.by_layer[i].skipped, 8);
    }

    // Per-vector A1 recall matches the overall figure here, since A1 is the only
    // declared vector.
    let a1 = m.by_vector.iter().find(|v| v.vector == "A1").unwrap();
    assert_eq!((a1.expected, a1.detected, a1.missed), (5, 4, 1));
    assert_eq!(a1.recall, Some(0.8));
    assert_eq!(a1.false_hits, 0);
}

#[test]
fn scanning_the_same_entry_twice_yields_identical_scored_output() {
    // Reproducibility is the point of the offline mode: with fixed lists, the
    // scored fields must not vary between runs. (Timings legitimately do.)
    let a = malicious("expres");
    let b = malicious("expres");
    assert_eq!(a.verdict, b.verdict);
    assert_eq!(a.risk_score, b.risk_score);
    assert_eq!(a.classification, b.classification);
    assert_eq!(a.detected_vectors, b.detected_vectors);
    assert_eq!(
        serde_json::to_value(&a.layers[0].findings).unwrap(),
        serde_json::to_value(&b.layers[0].findings).unwrap()
    );
}
