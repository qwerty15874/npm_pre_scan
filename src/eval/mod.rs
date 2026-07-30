// Evaluation harness: batch-scan a ground-truth corpus and emit result data.
//
// The detector itself answers "is this package malicious?". This module answers
// "how often is the detector right?", which the project could not previously
// state — every prior verification used a dummy package authored here, which
// confirms a layer works as designed but yields no recall figure, no
// false-positive rate, and no evidence about which layer earns its keep.
//
// Layout:
//   corpus   — parse ground-truth TSV manifests            [pure]
//   record   — per-entry result records + JSONL/CSV writers [pure]
//   metrics  — confusion matrices and per-layer/per-vector rollups [pure]
//
// Everything except the runner is pure and network-free, so the metric maths is
// unit-testable without Docker, without the registry, and without a corpus on
// disk. See eval/README.md for the corpus and the safety posture around the
// live-malware samples.

pub mod corpus;
pub mod metrics;
pub mod record;
pub mod runner;
pub mod samples;
