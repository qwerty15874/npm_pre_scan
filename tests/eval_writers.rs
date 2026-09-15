// Integration tests for the evaluation output writers.
//
// Working directory during `cargo test` is the package root (where Cargo.toml
// lives). Writers take `impl Write`, so everything here writes into a `Vec<u8>`
// and touches no filesystem.
//
// The load-bearing test is `results_row_field_count_matches_the_header`: the CSV
// writer is hand-rolled over a 45-column layout, and a row that silently drifts
// out of alignment with the header would shift every downstream column without
// any error.

use npm_pre_scan::eval::corpus::{parse_manifest, CorpusEntry};
use npm_pre_scan::eval::record::{
    csv_escape, write_findings_header, write_findings_rows, write_jsonl_line, write_results_header,
    write_results_row, EvalRecord, LayerRecord, Outcome, RecordInputs, FINDINGS_COLUMNS,
    RESULTS_COLUMNS,
};
use npm_pre_scan::models::{CheckResult, Finding, Verdict};
use serde_json::json;

fn entry(line: &str) -> CorpusEntry {
    parse_manifest(line, "t").unwrap().into_iter().next().unwrap()
}

fn finding(check: &str, severity: &str, vector: &str) -> Finding {
    json!({"check": check, "severity": severity, "vector": vector, "message": "a, message"})
        .as_object()
        .unwrap()
        .clone()
}

fn layer(findings: Vec<Finding>, verdict: Verdict, ms: u64) -> LayerRecord {
    LayerRecord::from_check(
        &CheckResult {
            package: "p".into(),
            verdict,
            score: 50,
            findings,
            note: Some("a note, with a comma".into()),
        },
        Some(ms),
        false,
    )
}

/// A record populated on every layer, with awkward text in the note column.
fn full_record() -> EvalRecord {
    let e = entry(
        "dir\tdummy_packages/dummy_timebomb\tdummy\tmalicious\tD1,B4\t1,2,3\tnote, with \"quotes\"",
    );
    EvalRecord::build(RecordInputs {
        effective_layers: vec![1, 2, 3],
        entry: &e,
        layers: [
            LayerRecord::skipped("no registry identity"),
            layer(vec![finding("obfuscation", "BLOCK", "B2")], Verdict::Block, 11),
            layer(vec![finding("mass_deletion", "BLOCK", "B4")], Verdict::Block, 22),
            layer(vec![finding("timebomb", "SUSPECT", "D1")], Verdict::Suspect, 33),
        ],
        risk_score: Some(0.876),
        verdict: Some(Verdict::Block),
        outcome: Outcome::Scanned,
        outcome_detail: None,
        registry_status: None,
        declared_deps: Some(0),
        vendored: false,
        l0_metadata_version: None,
        total_ms: 66,
        scanned_at: "2026-07-30T12:00:00Z".into(),
    })
}

/// Split a CSV line into fields, honouring double-quoted fields that may
/// themselves contain commas and escaped quotes. Deliberately a separate
/// implementation from the writer, so the test is a real check rather than a
/// restatement.
fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

#[test]
fn results_row_field_count_matches_the_header() {
    let r = full_record();
    let mut out = Vec::new();
    write_results_header(&mut out).unwrap();
    write_results_row(&mut out, &r).unwrap();
    let text = String::from_utf8(out).unwrap();

    let mut lines = text.lines();
    let header = split_csv(lines.next().unwrap());
    let row = split_csv(lines.next().unwrap());

    assert_eq!(header.len(), RESULTS_COLUMNS.len());
    assert_eq!(
        row.len(),
        header.len(),
        "row has {} fields but the header has {}",
        row.len(),
        header.len()
    );
    assert_eq!(header, RESULTS_COLUMNS.iter().map(|s| s.to_string()).collect::<Vec<_>>());
}

#[test]
fn results_row_puts_each_value_under_its_own_column() {
    let r = full_record();
    let mut out = Vec::new();
    write_results_header(&mut out).unwrap();
    write_results_row(&mut out, &r).unwrap();
    let text = String::from_utf8(out).unwrap();
    let mut lines = text.lines();
    let header = split_csv(lines.next().unwrap());
    let row = split_csv(lines.next().unwrap());
    let get = |name: &str| {
        let idx = header.iter().position(|h| h == name).expect(name);
        row[idx].clone()
    };

    assert_eq!(get("kind"), "dir");
    assert_eq!(get("package"), "dummy_timebomb");
    assert_eq!(get("group"), "dummy");
    assert_eq!(get("label"), "malicious");
    assert_eq!(get("verdict"), "BLOCK");
    assert_eq!(get("risk_score"), "0.88", "risk score is rounded to 2dp");
    assert_eq!(get("classification"), "TP");
    assert_eq!(get("dyn_valid"), "true");
    assert_eq!(get("declared_deps"), "0");

    // Multi-valued columns use ';' so they never need quoting.
    assert_eq!(get("expected_vectors"), "D1;B4");
    assert_eq!(get("effective_layers"), "1;2;3");
    assert_eq!(get("detected_vectors"), "B2;B4;D1");
    assert_eq!(get("matched_expected"), "D1;B4");
    assert_eq!(get("unexpected_vectors"), "B2");

    // Layer 0 was skipped; layers 1-3 ran with their own timings.
    assert_eq!(get("l0_status"), "skipped");
    assert_eq!(get("l0_verdict"), "");
    assert_eq!(get("l1_status"), "ran");
    assert_eq!(get("l1_ms"), "11");
    assert_eq!(get("l2_ms"), "22");
    assert_eq!(get("l3_ms"), "33");
    assert_eq!(get("l3_verdict"), "SUSPECT");

    // The one field that can contain a delimiter survives a round trip.
    assert_eq!(get("note"), "note, with \"quotes\"");
}

#[test]
fn absent_optional_values_render_as_empty_not_as_none() {
    let e = entry("name\tgone\treal_malicious\tmalicious\tA1\t0");
    let r = EvalRecord::build(RecordInputs {
        effective_layers: vec![0],
        entry: &e,
        layers: [
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        risk_score: None,
        verdict: None,
        outcome: Outcome::RegistryFailed,
        outcome_detail: Some("timed out".into()),
        registry_status: Some("failed".into()),
        declared_deps: None,
        vendored: false,
        l0_metadata_version: None,
        total_ms: 0,
        scanned_at: "t".into(),
    });

    let mut out = Vec::new();
    write_results_header(&mut out).unwrap();
    write_results_row(&mut out, &r).unwrap();
    let text = String::from_utf8(out).unwrap();
    let mut lines = text.lines();
    let header = split_csv(lines.next().unwrap());
    let row = split_csv(lines.next().unwrap());

    assert_eq!(row.len(), header.len());
    let get = |name: &str| row[header.iter().position(|h| h == name).unwrap()].clone();
    assert_eq!(get("risk_score"), "");
    assert_eq!(get("verdict"), "");
    assert_eq!(get("declared_deps"), "");
    assert_eq!(get("version"), "");
    assert_eq!(get("path"), "");
    assert_eq!(get("classification"), "ERROR");
    assert!(!text.contains("None"), "Option debug output leaked into the CSV");
}

#[test]
fn findings_csv_emits_one_row_per_finding_tagged_with_its_layer() {
    let r = full_record();
    let mut out = Vec::new();
    write_findings_header(&mut out).unwrap();
    write_findings_rows(&mut out, &r).unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(lines[0], FINDINGS_COLUMNS.join(","));
    assert_eq!(lines.len(), 4, "header + one row per finding");
    for line in &lines[1..] {
        assert_eq!(
            split_csv(line).len(),
            FINDINGS_COLUMNS.len(),
            "bad field count in {}",
            line
        );
    }

    // The layer column must carry the layer index, which is what makes
    // per-layer attribution possible from this file alone.
    assert!(lines[1].contains(",1,obfuscation,BLOCK,B2,"));
    assert!(lines[2].contains(",2,mass_deletion,BLOCK,B4,"));
    assert!(lines[3].contains(",3,timebomb,SUSPECT,D1,"));
}

#[test]
fn findings_csv_is_empty_for_a_clean_record() {
    let e = entry("name\tlodash\tparent_benign\tbenign\t-\t0");
    let r = EvalRecord::build(RecordInputs {
        effective_layers: vec![0],
        entry: &e,
        layers: [
            layer(vec![], Verdict::Pass, 1),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
            LayerRecord::not_run(),
        ],
        risk_score: Some(0.0),
        verdict: Some(Verdict::Pass),
        outcome: Outcome::Scanned,
        outcome_detail: None,
        registry_status: Some("found".into()),
        declared_deps: Some(0),
        vendored: false,
        l0_metadata_version: None,
        total_ms: 1,
        scanned_at: "t".into(),
    });

    let mut out = Vec::new();
    write_findings_rows(&mut out, &r).unwrap();
    assert!(out.is_empty(), "a clean record must emit no finding rows");
}

#[test]
fn every_jsonl_line_round_trips_back_into_a_record() {
    let records = vec![full_record(), full_record()];
    let mut out = Vec::new();
    for r in &records {
        write_jsonl_line(&mut out, r).unwrap();
    }
    let text = String::from_utf8(out).unwrap();

    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        // One record per line, no embedded newlines — the whole point of JSONL.
        assert!(!line.is_empty());
        let back: EvalRecord =
            serde_json::from_str(line).expect("records.jsonl must be readable back");
        assert_eq!(back.entry_id, records[0].entry_id);
        assert_eq!(back.classification, records[0].classification);
        assert_eq!(back.layers[3].findings.len(), 1);
        // The raw finding maps survive, which is what per-vector analysis needs.
        assert_eq!(
            back.layers[3].findings[0]["severity"].as_str(),
            Some("SUSPECT")
        );
        assert_eq!(back.layers[0].note.as_deref(), Some("no registry identity"));
    }
}

#[test]
fn appending_a_second_batch_does_not_repeat_the_header() {
    // Mirrors the runner's append behaviour: the header is written only when the
    // file is newly created, so a resumed or second batch must not re-emit it.
    let r = full_record();
    let mut file = Vec::new();
    write_results_header(&mut file).unwrap();
    write_results_row(&mut file, &r).unwrap();

    // Second batch: file already non-empty, so only rows are appended.
    write_results_row(&mut file, &r).unwrap();

    let text = String::from_utf8(file).unwrap();
    assert_eq!(
        text.lines().filter(|l| l.starts_with("entry_id,")).count(),
        1,
        "header appeared more than once"
    );
    assert_eq!(text.lines().count(), 3);
}

#[test]
fn csv_escape_quotes_exactly_when_required() {
    assert_eq!(csv_escape("plain"), "plain");
    assert_eq!(csv_escape(""), "");
    assert_eq!(csv_escape("A1;B2"), "A1;B2");
    assert_eq!(csv_escape("has,comma"), "\"has,comma\"");
    assert_eq!(csv_escape("has\"quote"), "\"has\"\"quote\"");
    assert_eq!(csv_escape("has\nnewline"), "\"has\nnewline\"");
    assert_eq!(csv_escape("has\rcr"), "\"has\rcr\"");
    // Round trip through the independent parser.
    for s in ["plain", "a,b", "say \"hi\"", "multi\nline", ""] {
        assert_eq!(split_csv(&csv_escape(s))[0], s, "failed on {:?}", s);
    }
}

#[test]
fn a_message_containing_a_comma_never_reaches_the_csv() {
    // Free text lives only in records.jsonl. This is the invariant that keeps
    // the hand-rolled writer's escaping surface small enough to trust.
    let r = full_record();
    let mut out = Vec::new();
    write_results_row(&mut out, &r).unwrap();
    write_findings_rows(&mut out, &r).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(
        !text.contains("a, message"),
        "a finding message leaked into a CSV: {}",
        text
    );

    // ...but it is present in the JSONL.
    let mut jsonl = Vec::new();
    write_jsonl_line(&mut jsonl, &r).unwrap();
    assert!(String::from_utf8(jsonl).unwrap().contains("a, message"));
}
