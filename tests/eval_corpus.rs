// Integration tests for the evaluation corpus manifest parser.
//
// Working directory during `cargo test` is the package root (where Cargo.toml
// lives), matching every other integration test in this repo.
//
// These tests read the real checked-in manifests as well as a fixture, so a
// hand-edit that breaks a manifest fails the suite rather than silently
// shrinking a metric denominator at experiment time.

use npm_pre_scan::eval::corpus::{
    merge_manifests, parse_manifest, CorpusEntry, Group, Kind, Label, VECTORS,
};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/eval/{}", name))
        .unwrap_or_else(|e| panic!("Could not read fixture {}: {}", name, e))
}

fn manifest(name: &str) -> Vec<CorpusEntry> {
    let path = format!("eval/corpus/{}", name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Could not read manifest {}: {}", path, e));
    parse_manifest(&text, &path).unwrap_or_else(|errs| {
        let rendered: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
        panic!("{} failed to parse:\n{}", path, rendered.join("\n"));
    })
}

#[test]
fn fixture_exercises_every_kind() {
    let entries = parse_manifest(&fixture("corpus_sample.tsv"), "corpus_sample.tsv")
        .expect("fixture must parse");

    let kinds: Vec<Kind> = entries.iter().map(|e| e.kind).collect();
    for k in Kind::ALL {
        assert!(kinds.contains(k), "fixture is missing kind {:?}", k);
    }

    // The leading-tab row proves line-level trimming happens before the split.
    assert!(entries.iter().any(|e| e.package == "leading-tab-is-trimmed"));

    // Both no-note forms (6 columns, and a `-` 7th) yield None.
    assert!(entries
        .iter()
        .any(|e| e.package == "cross-env" && e.note.is_none()));
    assert!(entries
        .iter()
        .any(|e| e.package == "infected" && e.note.is_none()));
}

#[test]
fn fixture_derives_identities_correctly() {
    let entries = parse_manifest(&fixture("corpus_sample.tsv"), "f").unwrap();

    let v = entries.iter().find(|e| e.kind == Kind::Version).unwrap();
    assert_eq!(v.package, "crossenv");
    assert_eq!(v.version.as_deref(), Some("1.0.1"));
    assert_eq!(v.vectors, vec!["A1", "B1"]);
    assert_eq!(v.layers, vec![0, 1]);

    let s = entries.iter().find(|e| e.kind == Kind::Sample).unwrap();
    assert_eq!(s.package, "evil-pkg");
    assert_eq!(s.version.as_deref(), Some("1.0.0"));

    let d = entries
        .iter()
        .find(|e| e.kind == Kind::Dir && e.package == "dummy_benign_l3")
        .unwrap();
    assert_eq!(d.label, Label::Benign);
    assert!(d.vectors.is_empty());
    assert_eq!(d.layers, vec![1, 2, 3]);

    // A `pair` splits into prev/latest and takes its name from the directory the
    // two share, not from the literal "latest" segment.
    let p = entries.iter().find(|e| e.kind == Kind::Pair).unwrap();
    assert_eq!(p.package, "dummy_malicious_update");
    assert_eq!(
        p.path.as_deref(),
        Some("dummy_packages/dummy_malicious_update/latest"),
        "`path` must hold the version under test"
    );
    assert_eq!(
        p.path_prev.as_deref(),
        Some("dummy_packages/dummy_malicious_update/prev"),
        "`path_prev` must hold the predecessor"
    );
    assert_eq!(p.vectors, vec!["B3"]);
    assert_eq!(p.entry_id(), "pair:dummy_packages/dummy_malicious_update/latest");
}

#[test]
fn a_malformed_pair_is_a_parse_error_not_a_half_scan() {
    // Every one of these would otherwise diff against nothing and report the
    // whole package as newly introduced — a fabricated B3 rather than a miss.
    for bad in [
        "pair\tonly-one-dir\tdummy\tmalicious\tB3\t1",
        "pair\t::latest\tdummy\tmalicious\tB3\t1",
        "pair\tprev::\tdummy\tmalicious\tB3\t1",
        "pair\tsame::same\tdummy\tmalicious\tB3\t1",
    ] {
        assert!(
            parse_manifest(bad, "f").is_err(),
            "should not parse: {}",
            bad
        );
    }
}

/// A `pair` has no registry identity, so asking for Layer 0 is a manifest
/// mistake — the same rule `dir` and `sample` already carry.
#[test]
fn a_pair_may_not_request_layer_zero() {
    let line = "pair\ta::b\tdummy\tmalicious\tB3\t0,1";
    assert!(parse_manifest(line, "f").is_err());
}

#[test]
fn all_checked_in_manifests_parse() {
    for name in [
        "dummies.tsv",
        "real_malicious_holders.tsv",
        "parent_benign.tsv",
        "datadog_static.tsv",
        "datadog_dynamic.tsv",
        // v22 benign-control corpora for the DataDog arms.
        "datadog_compromised.tsv",
        "datadog_clean.tsv",
        "datadog_intent.tsv",
        "top_benign.tsv",
    ] {
        let entries = manifest(name);
        assert!(!entries.is_empty(), "{} parsed to zero entries", name);
    }
}

/// The compromised/intent split must partition `datadog_static.tsv` exactly —
/// no entry invented, none dropped. Splitting a scored corpus by hand is how a
/// denominator silently changes.
#[test]
fn the_datadog_split_partitions_the_original_corpus() {
    let whole = manifest("datadog_static.tsv");
    let comp = manifest("datadog_compromised.tsv");
    let intent = manifest("datadog_intent.tsv");
    assert_eq!(
        comp.len() + intent.len(),
        whole.len(),
        "split must cover every entry exactly once"
    );
    let ids = |v: &[CorpusEntry]| -> std::collections::BTreeSet<String> {
        v.iter().map(|e| e.entry_id()).collect()
    };
    let mut union = ids(&comp);
    union.extend(ids(&intent));
    assert_eq!(union, ids(&whole), "split must contain the same entry ids");
}

/// Every benign control must actually be labelled benign and carry no expected
/// vector — a control that claims a detection is not a control.
#[test]
fn the_benign_controls_are_benign_and_claim_nothing() {
    for name in ["datadog_clean.tsv", "top_benign.tsv"] {
        let entries = manifest(name);
        assert!(
            entries.iter().all(|e| e.label == Label::Benign),
            "{} must be entirely benign",
            name
        );
        assert!(
            entries.iter().all(|e| e.group == Group::BenignControl),
            "{} must carry group=benign_control so it cannot blend with parent_benign",
            name
        );
        assert!(
            entries.iter().all(|e| e.vectors.is_empty()),
            "{}: every flag here is a false positive, so no entry may expect a vector",
            name
        );
        assert!(
            entries.iter().all(|e| e.layers == vec![1]),
            "{} must be scored at layer 1 only, matching its malicious counterpart",
            name
        );
    }
}

#[test]
fn the_curated_manifests_merge_without_duplicate_ids() {
    // These five are meant to be usable together in one run, so a collision
    // between them would double-count an entry in every metric.
    let parsed = vec![
        manifest("dummies.tsv"),
        manifest("real_malicious_holders.tsv"),
        manifest("parent_benign.tsv"),
        manifest("datadog_static.tsv"),
        manifest("datadog_dynamic.tsv"),
    ];
    let merged = merge_manifests(parsed).unwrap_or_else(|errs| {
        let rendered: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
        panic!("manifests collide:\n{}", rendered.join("\n"));
    });
    assert!(merged.len() > 600, "expected the full corpus, got {}", merged.len());
}

#[test]
fn dummies_manifest_covers_every_vector_the_tool_claims() {
    // CLAUDE.md's coverage matrix asserts every in-scope vector maps to a layer.
    // The dummy corpus is where that claim is exercised, so a vector present in
    // the matrix but absent here means the experiment cannot measure it.
    let entries = manifest("dummies.tsv");
    let covered: Vec<&str> = entries
        .iter()
        .flat_map(|e| e.vectors.iter().map(|v| v.as_str()))
        .collect();
    for v in ["A1", "A2", "A4", "B1", "B2", "B3", "B4", "C1", "C2", "C3", "D1", "D2", "D3", "E1"] {
        assert!(covered.contains(&v), "dummies.tsv does not cover vector {}", v);
    }
    // A3 (maintainer change) and META are registry-metadata-only: they cannot be
    // expressed as a local dummy directory, which is why they are absent here.
    assert!(!covered.contains(&"A3"));
}

#[test]
fn dummies_manifest_has_benign_precision_controls() {
    let entries = manifest("dummies.tsv");
    let benign: Vec<&str> = entries
        .iter()
        .filter(|e| e.label == Label::Benign)
        .map(|e| e.package.as_str())
        .collect();
    assert!(benign.contains(&"dummy_benign_l3"), "missing the primary control");
    assert!(benign.len() >= 3, "too few precision controls: {:?}", benign);
}

#[test]
fn parent_benign_is_entirely_benign_and_all_registry_names() {
    let entries = manifest("parent_benign.tsv");
    assert!(entries.iter().all(|e| e.label == Label::Benign));
    assert!(entries.iter().all(|e| e.group == Group::ParentBenign));
    assert!(entries.iter().all(|e| e.kind == Kind::Name));
    // Every flag in this group is a false positive, so no entry may declare an
    // expected vector.
    assert!(entries.iter().all(|e| e.vectors.is_empty()));
    // The dynamic false-positive arm needs entries that actually reach L2/L3.
    let dynamic = entries.iter().filter(|e| e.layers.contains(&2)).count();
    assert!(dynamic >= 8, "only {} entries reach layer 2", dynamic);
}

#[test]
fn holders_manifest_marks_takedown_stubs_as_holder_kind() {
    let entries = manifest("real_malicious_holders.tsv");
    let holders = entries.iter().filter(|e| e.kind == Kind::Holder).count();
    assert!(holders >= 25, "expected the 2017 campaign as holders, got {}", holders);

    // A security-holder stub serves no real content, so requesting content
    // layers for one would produce a meaningless ARTIFACT_FN at extra cost.
    for e in entries.iter().filter(|e| e.kind == Kind::Holder) {
        assert_eq!(e.layers, vec![0], "{} should be layer 0 only", e.package);
    }

    // The three reclaimed names are benign today, so a flag on them is a
    // genuine false positive and they must be labelled accordingly.
    for name in ["mariadb", "opencv.js", "openssl.js"] {
        let e = entries.iter().find(|e| e.package == name).unwrap();
        assert_eq!(e.label, Label::Benign, "{} must be labelled benign", name);
    }
}

#[test]
fn datadog_manifests_never_invent_vector_ground_truth() {
    // The dataset carries no per-sample vector taxonomy. Only entries whose
    // vector is attributable to a published incident may declare one.
    let statics = manifest("datadog_static.tsv");
    assert!(
        statics.iter().all(|e| e.vectors.is_empty()),
        "the stratified sample must not claim vectors"
    );
    assert!(statics.iter().all(|e| e.layers == vec![1]));

    let dynamics = manifest("datadog_dynamic.tsv");
    let labelled = dynamics.iter().filter(|e| !e.vectors.is_empty()).count();
    assert!(labelled >= 4, "expected the published incidents to be labelled");
    assert!(
        labelled < dynamics.len(),
        "unattributable samples must keep vectors as '-'"
    );
    assert!(dynamics.iter().all(|e| e.layers == vec![1, 2, 3]));

    // The incidents this tool was specifically built for must be present.
    let ids: Vec<&str> = dynamics.iter().map(|e| e.package.as_str()).collect();
    assert!(ids.contains(&"@ctrl/tinycolor"), "missing the Shai-Hulud sample");
}

#[test]
fn every_manifest_vector_is_a_known_tag() {
    for name in [
        "dummies.tsv",
        "real_malicious_holders.tsv",
        "datadog_dynamic.tsv",
    ] {
        for e in manifest(name) {
            for v in &e.vectors {
                assert!(
                    VECTORS.contains(&v.as_str()),
                    "{}: unknown vector {}",
                    name,
                    v
                );
            }
        }
    }
}
