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

/// Which layers a caller wants run. `[bool; 4]`, indexed Layer 0..3.
///
/// Exists so a batch caller can request a subset (e.g. static layers only for a
/// package whose dependencies the offline sandbox cannot install) without a
/// separate entry point per combination. A layer that is masked off is reported
/// as `LayerStatus::Skipped` via the existing `RiskReport::mark_skipped`, which
/// is exactly the "intentionally not attempted" case that status was added for —
/// distinct from `NotRun`, which means nobody said why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayerMask(pub [bool; 4]);

impl LayerMask {
    pub const ALL: LayerMask = LayerMask([true; 4]);

    /// Build from a manifest's `layers` column (a list of layer indices).
    pub fn from_indices(indices: &[u8]) -> Self {
        let mut mask = [false; 4];
        for &i in indices {
            if let Some(slot) = mask.get_mut(i as usize) {
                *slot = true;
            }
        }
        LayerMask(mask)
    }

    pub fn wants(&self, layer: usize) -> bool {
        self.0.get(layer).copied().unwrap_or(false)
    }

    /// Layers present in both masks — used to combine a per-entry request with a
    /// run-wide ceiling.
    pub fn intersect(&self, other: &LayerMask) -> LayerMask {
        let mut out = [false; 4];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.0[i] && other.0[i];
        }
        LayerMask(out)
    }

    pub fn indices(&self) -> Vec<u8> {
        (0..4).filter(|&i| self.0[i]).map(|i| i as u8).collect()
    }

    pub fn is_empty(&self) -> bool {
        !self.0.iter().any(|&b| b)
    }
}

/// A full-pipeline scan that keeps everything, not just the aggregate.
///
/// `aggregate` is lossy by design — it discards each layer's `note` and flattens
/// findings into `"{vector}: {check} ({message})"` strings. That is the right
/// shape for a user-facing report and the wrong shape for measurement, where the
/// severity, the vector tag, and the "not found on the registry" note all need
/// to survive. So this carries the four `CheckResult`s alongside the report.
///
/// `CheckResult` is deliberately still not `Clone`: `aggregate` borrows the four
/// results and returns an owned `RiskReport`, so the borrows end at that call and
/// the results can simply be moved in afterwards.
pub struct FullScan {
    pub report: RiskReport,
    /// Layer 0..3 results. `None` where the layer was not attempted.
    pub layers: [Option<CheckResult>; 4],
    /// Wall-clock milliseconds per layer, measured around each layer call.
    pub layer_ms: [Option<u64>; 4],
    /// Why the registry metadata fetch succeeded or failed, for registry-mode
    /// scans. `None` for local scans, which never ask.
    pub registry_status: Option<crate::registry::FetchStatus>,
    /// Dependency count from the scanned `package.json`, when one was readable.
    /// The offline sandbox cannot install dependencies, so a caller needs this to
    /// know whether a Layer 2/3 result means anything.
    pub declared_deps: Option<usize>,
    /// Whether dependencies were resolved on the host and mounted into the
    /// dynamic layers. A dependency-bearing package is analysable when this is
    /// true and is not when it is false, which is what a caller needs in order
    /// to decide whether a Layer 2/3 silence is evidence.
    pub vendored: bool,
}

/// Time one layer, or skip it if the mask says so.
fn run_timed<F>(mask: LayerMask, layer: usize, f: F) -> (Option<CheckResult>, Option<u64>)
where
    F: FnOnce() -> CheckResult,
{
    if !mask.wants(layer) {
        return (None, None);
    }
    let started = std::time::Instant::now();
    let result = f();
    (Some(result), Some(started.elapsed().as_millis() as u64))
}

/// Read the dependency count from a package directory's `package.json`.
/// Best-effort: `None` when the file is absent or unreadable.
fn read_declared_deps(dir: &Path) -> Option<usize> {
    let text = std::fs::read_to_string(dir.join("package.json")).ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    Some(
        json.get("dependencies")
            .and_then(|d| d.as_object())
            .map(|o| o.len())
            .unwrap_or(0),
    )
}

/// Assemble a `FullScan` from already-computed layer results.
///
/// `requested` is what the caller asked for; `applicable` is what this scan path
/// could ever run. A layer that is applicable but not requested was
/// *intentionally declined*, which is `Skipped`. A layer that is not applicable
/// at all stays `NotRun` — for a local directory scan, Layer 0 has no registry
/// Per-scan context that is not a layer result: where the metadata came from,
/// and what it said. All three are `Option` because each entry point knows a
/// different subset — a local directory has no registry document at all.
struct ScanContext {
    registry_status: Option<crate::registry::FetchStatus>,
    declared_deps: Option<usize>,
    /// Whether host-vendored dependencies were mounted for the dynamic layers.
    vendored: bool,
    /// Whether the package is itself established (`crate::checker::is_established`).
    /// `None` means it was never asked, which never demotes anything — see
    /// [`demote_sole_network_import`].
    established: Option<bool>,
}

/// name to work with, so calling it "skipped" would imply a choice nobody made.
/// `tests/full_pipeline.rs` asserts exactly this distinction.
fn finish_scan(
    name: &str,
    requested: LayerMask,
    applicable: LayerMask,
    layers: [Option<CheckResult>; 4],
    layer_ms: [Option<u64>; 4],
    ctx: ScanContext,
) -> FullScan {
    let ScanContext {
        registry_status,
        declared_deps,
        vendored,
        established,
    } = ctx;

    let mut layers = layers;
    demote_sole_network_import(&mut layers, established);
    demote_self_referential_d3(&mut layers, name);

    let mut report = aggregate(
        name,
        [
            layers[0].as_ref(),
            layers[1].as_ref(),
            layers[2].as_ref(),
            layers[3].as_ref(),
        ],
    );
    // A layer this path *could* have run but the caller masked off was
    // intentionally not attempted, which is `Skipped`. One that was never
    // applicable stays `NotRun`.
    for (i, layer) in layers.iter().enumerate() {
        if layer.is_none() && applicable.wants(i) && !requested.wants(i) {
            report.mark_skipped(i);
        }
    }
    FullScan {
        report,
        layers,
        layer_ms,
        registry_status,
        declared_deps,
        vendored,
    }
}

/// Demote a **sole, uncorroborated** `network_imports` accusation on an
/// **established** package to a capability.
///
/// ## Why not simply demote the rule
///
/// `network_imports` discriminates. Measured arm D (499 real malicious) against
/// arm F (27 legitimate): 174/499 (34.9%) vs 4/27 (14.8%), **lift 2.35** —
/// comparable to `shell_exfil` (lift ~4.3), which v19 deliberately kept at
/// SUSPECT. A wholesale demotion to a capability would throw that away.
///
/// But every legitimate package it fires on is a library whose *purpose* is
/// network I/O (`axios`, `http-proxy`, `nodemailer`, `proxy`), and as a **sole**
/// signal the rule inverts: sole accuser on 13 malicious samples but on 3 of 27
/// legitimate ones. Importing `http` is the textbook "has the capability" versus
/// "abuses it" problem, and one import cannot tell them apart.
///
/// ## Why establishment, and why `Option<bool>`
///
/// Solitude alone is not enough: demoting on solitude everywhere costs arm D 19
/// records (437 -> 418, 83.8%) and arm E one (39 -> 38, 95.0%), **breaking both
/// recall floors**. The establishment gate confines the demotion to the registry
/// path, and the three-state `Option` is the load-bearing part:
///
/// - `Some(true)`  — asked, and the package is established. Demote.
/// - `Some(false)` — asked, and it is fresh. Keep the accusation.
/// - `None`        — never asked (local directory, or a pinned scan). Keep it.
///
/// *Absence of evidence of establishment is not evidence of establishment.* All
/// 539 arm D/E entries are local samples with no registry document, so the guard
/// is structurally incapable of firing there and the floors hold by construction
/// rather than by calibration luck.
///
/// ## Why this is safe for a compromised established package
///
/// That class — `ansi-styles@6.2.2`, the Sept-2025 chalk/debug crypto clipper —
/// is the most dangerous one, and suppressing a signal for established packages
/// could plausibly weaken it. It does not, and the reason is structural rather
/// than lucky: **`version_diff` is a built-in veto.** It emits SUSPECT for a
/// *newly introduced* network import (`layer1::version_diff`), and it runs on
/// exactly the path where this guard is active. So the guard only ever suppresses
/// an import that is **not new**; if a compromise *adds* network I/O — the
/// definition of the attack class — solitude is broken and the guard stands down.
///
/// (`ansi-styles@6.2.2` confirms it twice over: its only finding is an
/// `obfuscation` BLOCK for 314 distinct `_0x…` identifiers, and `network_imports`
/// never fires on it at all — the clipper hooks browser globals.)
///
/// ## Why here and not in `aggregate`
///
/// `aggregate` borrows the `CheckResult`s immutably and returns a `RiskReport`,
/// which has no findings list — only `Detections` (`Vec<String>`). `finish_scan`
/// *owns* the four results, so it can rewrite a finding before aggregating.
///
/// That distinction is load-bearing for the evaluation harness, which reads
/// `classification` from `RiskReport.verdict` but `detected_vectors`,
/// `by_vector` and `by_layer.sole_detector` from **per-finding severity** via
/// [`crate::models::is_accusing`]. Changing the verdict alone would move the
/// confusion matrix while leaving every per-vector metric flat. Rewriting the
/// real finding keeps them consistent.
fn demote_sole_network_import(layers: &mut [Option<CheckResult>; 4], established: Option<bool>) {
    use serde_json::Value;

    if established != Some(true) {
        return;
    }

    let is_net =
        |f: &Finding| f.get("check").and_then(|v| v.as_str()) == Some("network_imports");

    // Pass 1: borrow only (`CheckResult` is not `Clone`). Any *other* accusation
    // means the import is corroborated and must keep its severity.
    let mut found = false;
    for r in layers.iter().flatten() {
        for f in r.findings.iter().filter(|f| crate::models::is_accusing(f)) {
            if is_net(f) {
                found = true;
            } else {
                return;
            }
        }
    }
    if !found {
        return;
    }

    // Pass 2: rewrite, then recompute the host layer's verdict and score.
    // `aggregate` takes worst-of over LAYER verdicts, not over findings — omit
    // this and the layer stays SUSPECT and the demotion is invisible.
    for r in layers.iter_mut().flatten() {
        let mut touched = false;
        for f in r
            .findings
            .iter_mut()
            .filter(|f| is_net(f) && crate::models::is_accusing(f))
        {
            let original = f
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("network-capable module imported")
                .to_string();
            f.insert("severity".into(), Value::String("INFO".into()));
            f.insert(
                crate::models::CAPABILITY_KEY.into(),
                Value::String("network-io".into()),
            );
            f.insert("downgraded_established".into(), Value::Bool(true));
            f.insert(
                "message".into(),
                Value::String(format!(
                    "{} — downgraded: this is the only accusation against an \
                     established package, and a network import is what such a \
                     library is for. A newly *introduced* network import would \
                     be reported by version_diff instead",
                    original
                )),
            );
            touched = true;
        }
        if touched {
            r.verdict = crate::models::verdict_from_findings(&r.findings);
            r.score = crate::models::score_findings(&r.findings);
        }
    }
}

/// Demote a D3 (`trigger_on_use`) accusation whose every observed side effect
/// points back at the package itself — its own API host, or its own binary.
///
/// D3's premise is structurally weak in a way no threshold fixes: the Layer 3
/// fuzz scenario *invokes the package's exports*, so for any library whose
/// purpose is network I/O, "an export touched the network" is behaviour the
/// harness caused and then reported as suspicious. Measured on `nodemailer`,
/// whose exports are fuzzed and whose only egress is:
///
/// ```text
/// dns:api.nodemailer.com
/// connect:127.0.0.1:65535      <- the in-container sinkhole, not a real peer
/// ```
///
/// The discriminator is the one `eval/REPORT.md` asks for — an egress host
/// *unrelated to the package's stated purpose* — read from the evidence the
/// finding already carries. `api.nodemailer.com` is related; the D3 fixture's
/// `evil.example.com` is not, so `dummy_api_triggered` keeps its detection and
/// arm C's only D3 true positive survives.
///
/// Deliberately narrow, on three axes:
/// - only findings that came from a bare `import_side_effect` (hence
///   [`crate::layer3::classify::L2_CHECK_KEY`]); a credential read or a
///   sensitive write reaching D3 is untouched;
/// - only when EVERY resolved name is self-referential, so one unrelated
///   lookup alongside a related one still accuses;
/// - only when every connect is loopback. Under `--network=none` the sinkhole
///   answers 127.0.0.1, so a real beacon still shows its `dns:` line — a
///   connect to anything else means this rule has no business demoting.
fn demote_self_referential_d3(layers: &mut [Option<CheckResult>; 4], package: &str) {
    use serde_json::Value;

    let Some(token) = identity_token(package) else {
        return;
    };

    let is_bare_d3 = |f: &Finding| {
        f.get("vector").and_then(|v| v.as_str()) == Some("D3")
            && f.get(crate::layer3::classify::L2_CHECK_KEY)
                .and_then(|v| v.as_str())
                == Some("import_side_effect")
    };

    for r in layers.iter_mut().flatten() {
        let mut touched = false;
        for f in r
            .findings
            .iter_mut()
            .filter(|f| is_bare_d3(f) && crate::models::is_accusing(f))
        {
            if !side_effects_are_self_referential(f, &token) {
                continue;
            }
            let original = f
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("import-phase side effect")
                .to_string();
            f.insert("severity".into(), Value::String("INFO".into()));
            f.insert(
                crate::models::CAPABILITY_KEY.into(),
                Value::String("network-io".into()),
            );
            f.insert("downgraded_self_referential".into(), Value::Bool(true));
            f.insert(
                "message".into(),
                Value::String(format!(
                    "{} — downgraded: the fuzz scenario invoked this package's own \
                     exports and the only egress was to a host bearing its own name, \
                     so the harness caused the behaviour it would otherwise report. \
                     An unrelated host, an IP literal, an encoded DNS label or a \
                     credential read would all still accuse",
                    original
                )),
            );
            touched = true;
        }
        if touched {
            r.verdict = crate::models::verdict_from_findings(&r.findings);
            r.score = crate::models::score_findings(&r.findings);
        }
    }
}

/// The comparable form of a package name: scope dropped, non-alphanumerics
/// removed, lowercased. `@ctrl/tinycolor` -> `tinycolor`. `None` when nothing
/// usable remains, or when the token is too short to be evidence of anything
/// (a two-character name would match far too many hostnames).
fn identity_token(package: &str) -> Option<String> {
    let bare = package.rsplit('/').next().unwrap_or(package);
    let token: String = bare
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase();
    (token.len() >= 4).then_some(token)
}

/// Whether everything a finding observed points back at the package itself.
///
/// Covers both dimensions the same structural failure shows up in, each
/// measured on a real arm F false positive:
///
/// - **network** — `nodemailer`, whose fuzzed exports resolved
///   `api.nodemailer.com` and connected only to the sinkhole;
/// - **process** — `ffmpeg`, whose fuzzed exports spawned `/bin/ffmpeg`,
///   `/usr/bin/ffmpeg`, `/usr/local/bin/ffmpeg` … a PATH search for the one
///   binary the package exists to run.
///
/// Both are the harness causing the behaviour it then reports. `ffmpeg` only
/// became visible once item 8 let the dynamic layers reach it, which is a
/// coverage result, not a regression.
///
/// Vacuously false when nothing was observed — this rule exists to explain
/// activity, not silence.
fn side_effects_are_self_referential(f: &Finding, token: &str) -> bool {
    // A BLOCK `import_side_effect` means a sensitive read was involved, which
    // also raises its own `sensitive_file_read` finding. Never excused here.
    if f.get("severity").and_then(|v| v.as_str()) != Some("SUSPECT") {
        return false;
    }
    let Some(evidence) = f.get("evidence").and_then(|v| v.as_array()) else {
        return false;
    };
    let lines: Vec<&str> = evidence.iter().filter_map(|v| v.as_str()).collect();
    let of = |p: &'static str| -> Vec<&str> {
        lines.iter().filter_map(|l| l.strip_prefix(p)).collect()
    };

    let (dns, connects, procs) = (of("dns:"), of("connect:"), of("proc:"));
    if dns.is_empty() && connects.is_empty() && procs.is_empty() {
        return false;
    }

    // Any durable write or delete is outside this rule's remit. The container's
    // own scaffolding — libfaketime's /dev/shm segments and the fuzzer's temp
    // files — is not the package's doing and must not block the demotion.
    let ephemeral = |p: &str| {
        p.starts_with("/dev/shm/") || p.starts_with("/tmp/") || p == "/dev/null"
    };

    dns.iter().all(|host| host_matches_identity(host, token))
        && connects.iter().all(|c| is_loopback_connect(c))
        && procs.iter().all(|p| proc_matches_identity(p, token))
        && of("write:").iter().all(|p| ephemeral(p))
        && of("delete:").iter().all(|p| ephemeral(p))
}

/// A spawned executable belongs to the package when its basename carries the
/// identity token — `/usr/bin/ffmpeg` for `ffmpeg`. Basename rather than whole
/// path, so a payload cannot qualify by living in a conveniently-named
/// directory.
fn proc_matches_identity(path: &str, token: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    let base: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_lowercase();
    base.contains(token)
}

/// A hostname belongs to the package when one of its labels contains the
/// identity token — `api.nodemailer.com` for `nodemailer`. Label-wise rather
/// than a bare substring test so `nodemailer.evil.com` still matches (the label
/// is the package's) while a token buried in an unrelated TLD-ish string does
/// not slip through on punctuation alone.
fn host_matches_identity(host: &str, token: &str) -> bool {
    host.split('.').any(|label| {
        let label: String = label
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase();
        label.contains(token)
    })
}

/// `connect:<addr>:<port>` where the address is loopback. Everything else —
/// including any public or link-local literal — is left to accuse.
fn is_loopback_connect(connect: &str) -> bool {
    let addr = match connect.rsplit_once(':') {
        Some((a, _port)) => a,
        None => connect,
    };
    let addr = addr.trim_matches(|c| c == '[' || c == ']');
    addr == "::1" || addr.strip_prefix("127.").is_some_and(|r| !r.is_empty())
}

/// Aggregate a default name scan (Layer 0 + Layer 1) into a `RiskReport`.
///
/// The default CLI path (`npm-pre-scan <pkg>`) does not go through
/// [`finish_scan`]: it has no tarball, no Layer 2/3, and its own
/// `mark_skipped(1)` semantics for Layer 0's early exit, which
/// `tests/full_pipeline.rs` pins. It must still get `finish_scan`'s post-passes,
/// or the *primary* command would keep reporting a false positive that `--full`
/// no longer reports. (The capability-cluster escalation had exactly this
/// asymmetry, and it went unnoticed for a whole release.)
///
/// Returns the layer results back to the caller because they may have been
/// rewritten in place and `CheckResult` is not `Clone`. The CLI prints each
/// layer's findings separately, so a demotion has to be visible *there* too —
/// not only in the aggregate verdict.
///
/// `info` is the registry document when one was fetched. `None` means it was
/// never asked for, which never demotes.
pub fn aggregate_name_scan(
    l0: CheckResult,
    l1: Option<CheckResult>,
    l1_skipped_by_l0_block: bool,
    info: Option<&serde_json::Value>,
) -> (CheckResult, Option<CheckResult>, RiskReport) {
    let established = info.map(crate::checker::is_established);
    let name = l0.package.clone();

    let mut layers = [Some(l0), l1, None, None];
    demote_sole_network_import(&mut layers, established);

    let mut report = aggregate(&name, [layers[0].as_ref(), layers[1].as_ref(), None, None]);
    if l1_skipped_by_l0_block {
        report.mark_skipped(1);
    }

    let [l0, l1, _, _] = layers;
    (
        l0.expect("Layer 0 result is always present on the name-scan path"),
        l1,
        report,
    )
}

/// Wall-clock budget for host-side dependency resolution, in seconds. A stalled
/// `npm install` must not become a new way to hang a batch — the very failure
/// the per-package Docker budget exists to prevent.
const VENDOR_TIMEOUT_SECS: u64 = 300;

/// Resolve a package's dependencies on the host so the offline sandbox can load
/// them, returning the directory holding the resulting `node_modules`.
///
/// npm does the resolution — hand-rolling one would be a second, worse npm —
/// with `--ignore-scripts` so that nothing from the package or its dependency
/// tree executes on the host. Install-hook behaviour is exactly what Layer 2
/// exists to observe, and it must be observed inside the container.
///
/// Only `package.json` (and any lockfile) is copied across: npm resolves from
/// the manifest, and copying the package's own code would put it on the host's
/// install path for no benefit.
///
/// `None` means "run the layers exactly as before" — either there is nothing to
/// vendor or resolution failed. A failure is never fatal to the scan; it just
/// leaves the pre-existing coverage gap in place for that package.
fn vendor_dependencies(dir: &Path) -> Option<tempfile::TempDir> {
    if read_declared_deps(dir).unwrap_or(0) == 0 {
        return None;
    }
    let vendor = tempfile::TempDir::new().ok()?;
    std::fs::copy(dir.join("package.json"), vendor.path().join("package.json")).ok()?;
    let lock = dir.join("package-lock.json");
    if lock.is_file() {
        let _ = std::fs::copy(&lock, vendor.path().join("package-lock.json"));
    }

    let argv = crate::docker::timeout_argv(
        Some(VENDOR_TIMEOUT_SECS),
        &[
            "npm",
            "install",
            "--ignore-scripts",
            "--omit=dev",
            "--no-audit",
            "--no-fund",
            "--loglevel=error",
        ],
    );
    let (program, args) = argv.split_first()?;
    let status = std::process::Command::new(program)
        .args(args)
        .current_dir(vendor.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;

    (status.success() && vendor.path().join("node_modules").is_dir()).then_some(vendor)
}

/// Run the local pipeline over a package directory, keeping per-layer detail.
/// Layer 0 is never run — a local directory has no registry identity.
pub fn run_full_local_collect(name: &str, dir: &Path, mask: LayerMask) -> FullScan {
    // Layer 0 is not applicable to a local directory (no registry identity), so
    // it is neither requested nor reported as a deliberate skip.
    const APPLICABLE: LayerMask = LayerMask([false, true, true, true]);
    let mask = mask.intersect(&APPLICABLE);

    let (l1, t1) = run_timed(mask, 1, || crate::run_layer1_local(name, dir));
    // Resolve dependencies on the host only when a dynamic layer will actually
    // use them; a Layer 0/1 scan must not pay for an `npm install`.
    let vendor = (mask.wants(2) || mask.wants(3))
        .then(|| vendor_dependencies(dir))
        .flatten();
    let vendor_path = vendor.as_ref().map(|v| v.path());
    // One budget spans BOTH dynamic layers, so a package that stalls in each
    // cannot cost twice the configured wall (see `docker::PACKAGE_TIMEOUT_ENV`).
    crate::docker::start_package_budget();
    let (l2, t2) = run_timed(mask, 2, || crate::run_layer2_vendored(name, dir, vendor_path));
    let (l3, t3) = run_timed(mask, 3, || crate::run_layer3_vendored(name, dir, vendor_path));
    crate::docker::clear_package_budget();

    finish_scan(
        name,
        mask,
        APPLICABLE,
        [None, l1, l2, l3],
        [None, t1, t2, t3],
        ScanContext {
            registry_status: None,
            declared_deps: read_declared_deps(dir),
            vendored: vendor.is_some(),
            // No registry document for a local directory, so establishment is
            // unknown. `None` never demotes — this is what keeps the arm D/E
            // recall floors intact by construction.
            established: None,
        },
    )
}

/// Run the local pipeline over a prev/latest directory pair.
///
/// Identical to `run_full_local_collect` on `latest`, except that Layer 1 also
/// receives the `version_diff` (B3) findings from the transition. That check is
/// the only one that needs two versions, and no other corpus shape can supply
/// them — see `eval::corpus::Kind::Pair`.
pub fn run_pair_local_collect(
    name: &str,
    prev_dir: &Path,
    latest_dir: &Path,
    mask: LayerMask,
) -> FullScan {
    const APPLICABLE: LayerMask = LayerMask([false, true, true, true]);
    let mask = mask.intersect(&APPLICABLE);

    let (l1, t1) = run_timed(mask, 1, || {
        crate::run_layer1_local_paired(name, prev_dir, latest_dir)
    });
    let vendor = (mask.wants(2) || mask.wants(3))
        .then(|| vendor_dependencies(latest_dir))
        .flatten();
    let vendor_path = vendor.as_ref().map(|v| v.path());
    crate::docker::start_package_budget();
    let (l2, t2) = run_timed(mask, 2, || {
        crate::run_layer2_vendored(name, latest_dir, vendor_path)
    });
    let (l3, t3) = run_timed(mask, 3, || {
        crate::run_layer3_vendored(name, latest_dir, vendor_path)
    });
    crate::docker::clear_package_budget();

    finish_scan(
        name,
        mask,
        APPLICABLE,
        [None, l1, l2, l3],
        [None, t1, t2, t3],
        ScanContext {
            registry_status: None,
            declared_deps: read_declared_deps(latest_dir),
            vendored: vendor.is_some(),
            established: None,
        },
    )
}

/// Run the full local pipeline (Layer 1 + Layer 2 + Layer 3) on a package
/// directory and aggregate into one `RiskReport`. Layer 0 is skipped — a
/// local directory has no registry identity (Layer 0 is name/metadata based).
pub fn run_full_local(name: &str, dir: &Path) -> RiskReport {
    run_full_local_collect(name, dir, LayerMask::ALL).report
}

/// Run the full pipeline (Layer 0 + Layer 1 + Layer 2 + Layer 3) on an npm
/// package fetched from the registry by name, and aggregate into one
/// `RiskReport`, using the embedded Layer 0 comparison lists
/// (`typosquat::load_top_packages()` / `namespace::load_top_scoped_packages()`).
///
/// Thin wrapper over `run_full_registry_with_lists` — preserves the API used
/// by `tests/full_registry.rs` and the crate-root re-export for callers that
/// don't care about `--refresh-top` (i.e. every caller except `main.rs`'s
/// `--full <name>` branch, which computes the effective lists once via
/// `toplist::load_effective_lists` and calls `run_full_registry_with_lists`
/// directly, so a refreshed sweep isn't fetched twice).
pub fn run_full_registry(name: &str) -> RiskReport {
    run_full_registry_with_lists(
        name,
        &crate::typosquat::load_top_packages(),
        &crate::namespace::load_top_scoped_packages(),
    )
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
/// `top_packages` / `top_scoped` are the Layer 0 comparison lists to use —
/// passed in by the caller (rather than loaded internally) so `main.rs` can
/// compute them once via `toplist::load_effective_lists(refresh)` and share
/// them across the whole run instead of fetching/loading twice.
///
/// Failure handling (never panics):
/// - Package not found on the registry → `Verdict::Error` report with a note.
/// - Tarball URL missing from registry metadata, or download/extraction
///   fails → `Verdict::Error` report with a note. Layer 0's own result (which
///   did succeed) is still included, so a typosquat/namespace BLOCK from
///   Layer 0 is not lost just because the tarball couldn't be fetched.
pub fn run_full_registry_with_lists(name: &str, top_packages: &[String], top_scoped: &[String]) -> RiskReport {
    run_full_registry_collect(name, None, top_packages, top_scoped, LayerMask::ALL).report
}

/// Run the registry pipeline, keeping per-layer detail, and optionally pinning a
/// specific version instead of `dist-tags.latest`.
///
/// **Version pinning.** `version = Some(v)` resolves the tarball via
/// `tarball::get_version_tarball_url` and passes `info: None` to
/// `run_layer1_extracted`. Passing `None` is deliberate and does two necessary
/// things: the `package.json` used for install-script detection comes from the
/// *pinned tarball's own* content rather than from the latest release, and
/// `check_version_diff` is skipped — which it must be, because it diffs the two
/// *most recently published* versions, and for a historical pin (or a package npm
/// has since replaced with a security stub) that comparison is meaningless.
///
/// Known limitation, recorded rather than papered over: Layer 0's registry checks
/// (`age_check`, `maintainer`, `signatures`) all key off `dist-tags.latest`, so a
/// pinned entry gets pinned *content* and latest-based *metadata*. Threading a
/// version through those three modules is a larger change than this measurement
/// needs, so the caller reports `l0_metadata_version` instead.
///
/// Failure handling matches `run_full_registry_with_lists` exactly: every failure
/// path still yields a `FullScan` whose Layer 1 slot carries a `Verdict::Error`
/// result with an explanatory note, so Layer 0's verdict is never lost just
/// because the tarball could not be fetched.
pub fn run_full_registry_collect(
    name: &str,
    version: Option<&str>,
    top_packages: &[String],
    top_scoped: &[String],
    mask: LayerMask,
) -> FullScan {
    let (l0, t0) = run_timed(mask, 0, || crate::run_layer0(name, top_packages, top_scoped));

    // Bail out with just Layer 0 when no content layer was requested — this also
    // avoids a pointless metadata fetch and tarball download.
    if !(mask.wants(1) || mask.wants(2) || mask.wants(3)) {
        return finish_scan(
            name,
            mask,
            LayerMask::ALL,
            [l0, None, None, None],
            [t0, None, None, None],
            ScanContext {
                registry_status: None,
                declared_deps: None,
                vendored: false,
                established: None,
            },
        );
    }

    let err_scan = |l0: Option<CheckResult>,
                    t0: Option<u64>,
                    status: Option<crate::registry::FetchStatus>,
                    note: String| {
        let err = CheckResult {
            package: name.to_string(),
            verdict: Verdict::Error,
            score: 0,
            findings: vec![],
            note: Some(note),
        };
        finish_scan(
            name,
            mask,
            LayerMask::ALL,
            [l0, Some(err), None, None],
            [t0, None, None, None],
            ScanContext {
                registry_status: status,
                declared_deps: None,
                vendored: false,
                established: None,
            },
        )
    };

    let (status, info) = crate::registry::fetch_package_info(name);
    let info = match info {
        Some(info) => info,
        None => {
            let note = match &status {
                crate::registry::FetchStatus::NotFound => {
                    format!("Package '{}' not found on the npm registry", name)
                }
                crate::registry::FetchStatus::Failed(reason) => format!(
                    "Registry metadata fetch failed for '{}': {}",
                    name, reason
                ),
                // `Found` with no document cannot happen, but assume nothing.
                crate::registry::FetchStatus::Found => {
                    format!("Registry returned no metadata for '{}'", name)
                }
            };
            return err_scan(l0, t0, Some(status), note);
        }
    };

    let tarball_url = match version {
        Some(v) => crate::layer1::tarball::get_version_tarball_url(&info, v),
        None => crate::layer1::tarball::get_tarball_url(&info),
    };
    let tarball_url = match tarball_url {
        Some(url) => url,
        None => {
            let note = match version {
                Some(v) => format!(
                    "Version '{}' not present in registry metadata for '{}'",
                    v, name
                ),
                None => "Could not determine tarball URL from registry metadata".to_string(),
            };
            return err_scan(l0, t0, Some(status), note);
        }
    };

    let tmp = match crate::layer1::tarball::download_and_extract(&tarball_url) {
        Ok(t) => t,
        Err(e) => {
            return err_scan(
                l0,
                t0,
                Some(status),
                format!("Tarball download/extraction failed: {}", e),
            )
        }
    };

    // npm tarballs unpack under a `package/` subdir.
    let pkgdir = tmp.path().join("package");

    // A pinned scan reads its metadata from the extracted tarball (see the doc
    // comment above); an unpinned one reuses the registry document it already has.
    let l1_info = if version.is_some() { None } else { Some(&info) };

    let (l1, t1) = run_timed(mask, 1, || {
        crate::layer1::run_layer1_extracted(name, &pkgdir, l1_info)
    });
    let vendor = (mask.wants(2) || mask.wants(3))
        .then(|| vendor_dependencies(&pkgdir))
        .flatten();
    let vendor_path = vendor.as_ref().map(|v| v.path());
    // One budget spans BOTH dynamic layers (see the local path above).
    crate::docker::start_package_budget();
    let (l2, t2) = run_timed(mask, 2, || crate::run_layer2_vendored(name, &pkgdir, vendor_path));
    let (l3, t3) = run_timed(mask, 3, || crate::run_layer3_vendored(name, &pkgdir, vendor_path));
    crate::docker::clear_package_budget();

    let declared_deps = read_declared_deps(&pkgdir);

    // `tmp` (the TempDir) is still in scope here and is dropped (cleaned up)
    // only after l1/l2/l3 have all finished reading from `pkgdir`.
    finish_scan(
        name,
        mask,
        LayerMask::ALL,
        [l0, l1, l2, l3],
        [t0, t1, t2, t3],
        ScanContext {
            registry_status: Some(status),
            declared_deps,
            vendored: vendor.is_some(),
            // The guard's safety rests on `version_diff` breaking solitude when
            // the network capability is newly introduced, and `version_diff` is
            // skipped for a pinned scan (see `l1_info` above) — so a pinned scan
            // does not get the guard either.
            established: version.is_none().then(|| crate::checker::is_established(&info)),
        },
    )
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

#[cfg(test)]
mod layer_mask_tests {
    use super::*;

    #[test]
    fn all_wants_every_layer() {
        for i in 0..4 {
            assert!(LayerMask::ALL.wants(i));
        }
        assert!(!LayerMask::ALL.is_empty());
        assert_eq!(LayerMask::ALL.indices(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn from_indices_round_trips_and_ignores_out_of_range() {
        let m = LayerMask::from_indices(&[1, 3]);
        assert_eq!(m.indices(), vec![1, 3]);
        assert!(!m.wants(0));
        assert!(m.wants(1));
        assert!(!m.wants(2));
        assert!(m.wants(3));
        // A layer index the manifest parser would have rejected must not panic
        // here either — this mask is built from data.
        assert_eq!(LayerMask::from_indices(&[7]).indices(), Vec::<u8>::new());
        assert!(LayerMask::from_indices(&[]).is_empty());
    }

    #[test]
    fn intersect_is_the_ceiling_rule() {
        // The manifest asks for 0..3; a name-only run ceiling permits only 0.
        let requested = LayerMask::from_indices(&[0, 1, 2, 3]);
        let ceiling = LayerMask::from_indices(&[0]);
        assert_eq!(requested.intersect(&ceiling).indices(), vec![0]);
        // A dir entry asking for 1..3 under a name-only ceiling has nothing left.
        assert!(LayerMask::from_indices(&[1, 2, 3])
            .intersect(&ceiling)
            .is_empty());
        // Intersection is commutative.
        assert_eq!(
            requested.intersect(&ceiling),
            ceiling.intersect(&requested)
        );
    }

    #[test]
    fn a_masked_off_layer_is_reported_skipped_not_not_run() {
        // `Skipped` means "intentionally not attempted"; `NotRun` means nobody
        // said why. A caller-supplied mask is the former.
        let l0 = CheckResult {
            package: "p".into(),
            verdict: Verdict::Pass,
            score: 0,
            findings: vec![],
            note: None,
        };
        let scan = finish_scan(
            "p",
            LayerMask::from_indices(&[0]),
            LayerMask::ALL,
            [Some(l0), None, None, None],
            [Some(1), None, None, None],
            ScanContext {
                registry_status: None,
                declared_deps: None,
                vendored: false,
                established: None,
            },
        );
        assert_eq!(scan.report.layer_status[0], LayerStatus::Ran);
        for i in 1..4 {
            assert_eq!(
                scan.report.layer_status[i],
                LayerStatus::Skipped,
                "layer {} should be skipped",
                i
            );
        }
        assert_eq!(scan.layer_ms[0], Some(1));
    }

    #[test]
    fn run_full_local_collect_never_runs_layer_zero_even_if_asked() {
        // A local directory has no registry identity. Requesting layer 0 for one
        // is a caller error that must not turn into a bogus Layer 0 result.
        let mask = LayerMask::ALL;
        let masked = mask.intersect(&LayerMask([false, true, true, true]));
        assert!(!masked.wants(0));
        assert_eq!(masked.indices(), vec![1, 2, 3]);
    }

    #[test]
    fn read_declared_deps_counts_dependencies_and_tolerates_absence() {
        let dir = tempfile::tempdir().unwrap();
        // No package.json at all.
        assert_eq!(read_declared_deps(dir.path()), None);

        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","dependencies":{"a":"1","b":"2"}}"#,
        )
        .unwrap();
        assert_eq!(read_declared_deps(dir.path()), Some(2));

        // A package with no `dependencies` key declares zero, which is the case
        // that makes dynamic analysis meaningful in the offline sandbox.
        std::fs::write(dir.path().join("package.json"), r#"{"name":"p"}"#).unwrap();
        assert_eq!(read_declared_deps(dir.path()), Some(0));

        // Malformed JSON must not panic.
        std::fs::write(dir.path().join("package.json"), "{not json").unwrap();
        assert_eq!(read_declared_deps(dir.path()), None);
    }
}


/// The v20 network-import guard. Replaces `mod capability_cluster_tests`, whose
/// rule was removed as refuted — see [`crate::models::CAPABILITY_KEY`].
#[cfg(test)]
mod vendor_tests {
    use super::*;

    /// Host-side dependency resolution, the mechanism item 8 rests on.
    ///
    /// `#[ignore]`d because it reaches the live registry — the same convention
    /// the Docker-gated tests use. Run with:
    /// `cargo test --lib vendor_tests -- --ignored`
    #[test]
    #[ignore]
    fn vendoring_resolves_a_dependency_tree_without_running_scripts() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"vendor-probe","version":"1.0.0","dependencies":{"debug":"^4.3.4"}}"#,
        )
        .unwrap();

        let vendored = vendor_dependencies(dir.path()).expect("debug must resolve");
        let modules = vendored.path().join("node_modules");
        assert!(modules.join("debug").is_dir(), "the direct dependency");
        assert!(
            modules.join("ms").is_dir(),
            "and its transitive one — a tree, not just the top level"
        );
    }

    /// A package with nothing to vendor must not pay for an `npm install`, and
    /// must keep behaving exactly as it did before item 8.
    #[test]
    fn a_dependency_free_package_is_not_vendored() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"leaf","version":"1.0.0"}"#,
        )
        .unwrap();
        assert!(vendor_dependencies(dir.path()).is_none());
    }

    /// An unreadable or absent manifest is not a crash and not a vendoring:
    /// the layers simply run as they always did.
    #[test]
    fn a_missing_manifest_vendors_nothing() {
        let dir = tempfile::TempDir::new().unwrap();
        assert!(vendor_dependencies(dir.path()).is_none());
    }
}

#[cfg(test)]
mod d3_self_reference_guard_tests {
    use super::*;
    use crate::layer3::classify::L2_CHECK_KEY;
    use crate::models::{CheckResult, Finding, Verdict, CAPABILITY_KEY};
    use serde_json::Value;

    /// A Layer 3 D3 finding in the shape `classify_scenario` actually emits.
    fn d3(evidence: &[&str]) -> Finding {
        let mut f = Finding::new();
        f.insert("check".into(), Value::String("trigger_on_use".into()));
        f.insert(L2_CHECK_KEY.into(), Value::String("import_side_effect".into()));
        f.insert("severity".into(), Value::String("SUSPECT".into()));
        f.insert("vector".into(), Value::String("D3".into()));
        f.insert("scenario".into(), Value::String("D3".into()));
        f.insert(
            "message".into(),
            Value::String("Import-phase side effect detected: network activity".into()),
        );
        f.insert(
            "evidence".into(),
            Value::Array(evidence.iter().map(|e| Value::String((*e).into())).collect()),
        );
        f
    }

    fn layers_with(f: Finding) -> [Option<CheckResult>; 4] {
        let findings = vec![f];
        [
            None,
            None,
            None,
            Some(CheckResult {
                package: "p".into(),
                verdict: crate::models::verdict_from_findings(&findings),
                score: crate::models::score_findings(&findings),
                findings,
                note: None,
            }),
        ]
    }

    fn sev(layers: &[Option<CheckResult>; 4]) -> Option<String> {
        layers[3].as_ref()?.findings[0]
            .get("severity")?
            .as_str()
            .map(|s| s.to_string())
    }

    /// The measured false positive, captured from a live run on 2026-09-15:
    /// the fuzz scenario invoked `nodemailer`'s exports, one resolved
    /// `api.nodemailer.com`, and the only connect was the container's own
    /// sinkhole. The harness caused the behaviour it reported.
    #[test]
    fn nodemailers_own_api_host_is_not_an_accusation() {
        let mut layers = layers_with(d3(&[
            "file:/fuzz_exports.js",
            "dns:api.nodemailer.com",
            "connect:127.0.0.1:65535",
        ]));
        demote_self_referential_d3(&mut layers, "nodemailer");

        assert_eq!(sev(&layers).as_deref(), Some("INFO"));
        assert_eq!(layers[3].as_ref().unwrap().verdict, Verdict::Pass);
        assert!(layers[3].as_ref().unwrap().findings[0].contains_key(CAPABILITY_KEY));
    }

    /// The class this must never weaken, and the reason the literal form of
    /// item 7 was rejected: `dummy_api_triggered` beacons to a host that is
    /// nothing to do with it. It trips none of Layer 2's "stronger sub-signals"
    /// — one query, a 4-character label, no IP literal, no credential read — so
    /// a strong-signal requirement would have deleted arm C's only D3 true
    /// positive. Relatedness keeps it.
    #[test]
    fn an_unrelated_host_still_accuses() {
        let mut layers = layers_with(d3(&["dns:evil.example.com", "connect:127.0.0.1:1"]));
        demote_self_referential_d3(&mut layers, "dummy_api_triggered");

        assert_eq!(sev(&layers).as_deref(), Some("SUSPECT"));
        assert_eq!(layers[3].as_ref().unwrap().verdict, Verdict::Suspect);
    }

    /// The second measured instance of the same defect, captured live on
    /// 2026-09-15 and only visible once item 8 let the dynamic layers reach a
    /// dependency-declaring package: `ffmpeg`'s fuzzed exports spawn
    /// `/bin/ffmpeg`, `/usr/bin/ffmpeg`, `/usr/local/bin/ffmpeg` … a PATH
    /// search for the one binary the package exists to run. The /dev/shm
    /// entries are libfaketime's and the fuzzer's own scaffolding.
    #[test]
    fn ffmpeg_spawning_its_own_binary_is_not_an_accusation() {
        let mut f = d3(&[
            "proc:/bin/ffmpeg",
            "proc:/usr/local/bin/ffmpeg",
            "proc:/usr/bin/ffmpeg",
            "file:/fuzz_exports.js",
            "write:/dev/shm/faketime_shm_60",
            "delete:/dev/shm/tmp-630642191",
        ]);
        f.insert(
            "message".into(),
            Value::String("Import-phase side effect detected: child process spawned".into()),
        );
        let mut layers = layers_with(f);
        demote_self_referential_d3(&mut layers, "ffmpeg");
        assert_eq!(sev(&layers).as_deref(), Some("INFO"));
    }

    /// The class this must never absorb: spawning a shell is not the package
    /// doing its job, however related everything else looks.
    #[test]
    fn spawning_an_unrelated_binary_still_accuses() {
        let mut layers = layers_with(d3(&["proc:/usr/bin/ffmpeg", "proc:/bin/sh"]));
        demote_self_referential_d3(&mut layers, "ffmpeg");
        assert_eq!(sev(&layers).as_deref(), Some("SUSPECT"));
    }

    /// A durable write is outside the rule's remit even when the process and
    /// network evidence is entirely self-referential.
    #[test]
    fn a_durable_write_blocks_the_demotion() {
        let mut layers = layers_with(d3(&[
            "proc:/usr/bin/ffmpeg",
            "write:/root/.bashrc",
        ]));
        demote_self_referential_d3(&mut layers, "ffmpeg");
        assert_eq!(sev(&layers).as_deref(), Some("SUSPECT"));
    }

    /// A BLOCK-severity side effect means a sensitive read was involved; it
    /// raises its own finding and is never excused here.
    #[test]
    fn a_block_severity_side_effect_is_never_demoted() {
        let mut f = d3(&["proc:/usr/bin/ffmpeg"]);
        f.insert("severity".into(), Value::String("BLOCK".into()));
        let mut layers = layers_with(f);
        demote_self_referential_d3(&mut layers, "ffmpeg");
        assert_eq!(sev(&layers).as_deref(), Some("BLOCK"));
    }

    #[test]
    fn proc_matching_uses_the_basename_not_the_directory() {
        assert!(proc_matches_identity("/usr/bin/ffmpeg", "ffmpeg"));
        assert!(proc_matches_identity("/bin/ffmpeg", "ffmpeg"));
        // A payload cannot qualify by sitting in a conveniently-named directory.
        assert!(!proc_matches_identity("/opt/ffmpeg/bin/sh", "ffmpeg"));
        assert!(!proc_matches_identity("/bin/curl", "ffmpeg"));
    }

    /// One unrelated lookup alongside a related one is still an accusation —
    /// exfiltration next to a legitimate API call must not hide behind it.
    #[test]
    fn a_related_host_does_not_excuse_an_unrelated_one() {
        let mut layers = layers_with(d3(&[
            "dns:api.nodemailer.com",
            "dns:attacker.example.net",
            "connect:127.0.0.1:65535",
        ]));
        demote_self_referential_d3(&mut layers, "nodemailer");
        assert_eq!(sev(&layers).as_deref(), Some("SUSPECT"));
    }

    /// A connect to anything but loopback is outside this rule's remit: the
    /// sinkhole answers 127.0.0.1, so a real peer address means the premise
    /// ("we only saw the package call its own API") does not hold.
    #[test]
    fn a_non_loopback_connect_is_never_demoted() {
        let mut layers = layers_with(d3(&[
            "dns:api.nodemailer.com",
            "connect:8.8.8.8:53",
        ]));
        demote_self_referential_d3(&mut layers, "nodemailer");
        assert_eq!(sev(&layers).as_deref(), Some("SUSPECT"));
    }

    /// Only a bare `import_side_effect` is in scope. A credential read that
    /// reaches D3 keeps its severity however related the host looks.
    #[test]
    fn a_stronger_layer2_signal_reaching_d3_is_untouched() {
        let mut f = d3(&["dns:api.nodemailer.com", "file:/etc/shadow"]);
        f.insert(L2_CHECK_KEY.into(), Value::String("sensitive_file_read".into()));
        f.insert("severity".into(), Value::String("BLOCK".into()));
        let mut layers = layers_with(f);
        demote_self_referential_d3(&mut layers, "nodemailer");
        assert_eq!(sev(&layers).as_deref(), Some("BLOCK"));
    }

    /// No network evidence at all is not an excuse — the rule exists to explain
    /// egress, so with none to explain it must do nothing.
    #[test]
    fn a_finding_with_no_network_evidence_is_left_alone() {
        let mut layers = layers_with(d3(&["write:/work/out.txt"]));
        demote_self_referential_d3(&mut layers, "nodemailer");
        assert_eq!(sev(&layers).as_deref(), Some("SUSPECT"));
    }

    #[test]
    fn identity_tokens_drop_scopes_and_reject_short_names() {
        assert_eq!(identity_token("@ctrl/tinycolor").as_deref(), Some("tinycolor"));
        assert_eq!(identity_token("node-ipc").as_deref(), Some("nodeipc"));
        // Too short to be evidence: a 2-3 char token matches far too much.
        assert_eq!(identity_token("ms"), None);
        assert_eq!(identity_token("d3"), None);
    }

    #[test]
    fn host_matching_is_label_wise() {
        assert!(host_matches_identity("api.nodemailer.com", "nodemailer"));
        assert!(host_matches_identity("nodemailer.com", "nodemailer"));
        // A package's own name as the label, even under a hostile parent, is
        // still its own name — solitude is not this rule's job to enforce.
        assert!(host_matches_identity("nodemailer.evil.com", "nodemailer"));
        assert!(!host_matches_identity("evil.example.com", "dummyapitriggered"));
        assert!(!host_matches_identity("example.com", "nodemailer"));
    }

    #[test]
    fn loopback_detection_covers_the_sinkhole_and_nothing_else() {
        assert!(is_loopback_connect("127.0.0.1:65535"));
        assert!(is_loopback_connect("127.1.2.3:80"));
        assert!(is_loopback_connect("[::1]:443"));
        assert!(!is_loopback_connect("8.8.8.8:53"));
        assert!(!is_loopback_connect("169.254.169.254:80"));
        assert!(!is_loopback_connect("1270.0.0.1:80"));
    }
}

#[cfg(test)]
mod network_import_guard_tests {
    use super::*;
    use crate::models::{CheckResult, Finding, Verdict, CAPABILITY_KEY};
    use serde_json::Value;

    /// A finding in the shape `check_network_imports` actually emits.
    fn net_import() -> Finding {
        let mut f = Finding::new();
        f.insert("check".into(), Value::String("network_imports".into()));
        f.insert("severity".into(), Value::String("SUSPECT".into()));
        f.insert("vector".into(), Value::String("B2".into()));
        f.insert(
            "message".into(),
            Value::String("Network-capable module imported in 1 file(s)".into()),
        );
        f
    }

    fn other(check: &str, severity: &str, message: &str) -> Finding {
        let mut f = Finding::new();
        f.insert("check".into(), Value::String(check.into()));
        f.insert("severity".into(), Value::String(severity.into()));
        f.insert("vector".into(), Value::String("B2".into()));
        f.insert("message".into(), Value::String(message.into()));
        f
    }

    fn result(findings: Vec<Finding>) -> CheckResult {
        CheckResult {
            package: "p".into(),
            verdict: crate::models::verdict_from_findings(&findings),
            score: crate::models::score_findings(&findings),
            findings,
            note: None,
        }
    }

    /// Layer 1 only, which is the shape every case here needs.
    fn layers_with(findings: Vec<Finding>) -> [Option<CheckResult>; 4] {
        [None, Some(result(findings)), None, None]
    }

    fn sev_of(f: &Finding) -> Option<&str> {
        f.get("severity").and_then(|v| v.as_str())
    }

    #[test]
    fn sole_network_import_on_an_established_package_becomes_a_capability() {
        let mut layers = layers_with(vec![net_import()]);
        demote_sole_network_import(&mut layers, Some(true));

        let l1 = layers[1].as_ref().unwrap();
        let f = &l1.findings[0];
        assert_eq!(sev_of(f), Some("INFO"), "got: {f:?}");
        assert_eq!(
            f.get(CAPABILITY_KEY).and_then(|v| v.as_str()),
            Some("network-io"),
            "the capability id is what marks it non-accusing; got: {f:?}"
        );
        assert_eq!(
            f.get("downgraded_established").and_then(|v| v.as_bool()),
            Some(true),
            "the marker is what makes an arm F run self-verifying; got: {f:?}"
        );
        assert!(
            f.get("message")
                .and_then(|v| v.as_str())
                .unwrap()
                .contains("Network-capable module imported in 1 file(s)"),
            "the original message must be preserved; got: {f:?}"
        );
        // Recomputing the host layer is mandatory: `aggregate` takes worst-of
        // over LAYER verdicts, not over findings.
        assert_eq!(l1.verdict, Verdict::Pass, "layer verdict must be recomputed");
        assert_eq!(l1.score, 2, "score must be recomputed to the INFO weight");
    }

    /// arm E's `libxmljs2qwerty` property: corroborated, so it stands.
    #[test]
    fn a_corroborated_network_import_keeps_its_severity() {
        let mut layers = layers_with(vec![
            net_import(),
            other("suspicious_strings", "SUSPECT", "os.homedir() reference"),
        ]);
        demote_sole_network_import(&mut layers, Some(true));

        let l1 = layers[1].as_ref().unwrap();
        assert_eq!(sev_of(&l1.findings[0]), Some("SUSPECT"), "{:?}", l1.findings);
        assert_eq!(l1.verdict, Verdict::Suspect);
    }

    /// The class the guard must never weaken: a COMPROMISED ESTABLISHED package.
    /// `ansi-styles@6.2.2`, the Sept-2025 chalk/debug crypto clipper, is
    /// established and would pass the establishment gate — but it carries an
    /// `obfuscation` BLOCK (314 distinct `_0x…` identifiers), so solitude fails
    /// and nothing is demoted.
    #[test]
    fn a_compromised_established_package_keeps_its_network_import() {
        let mut layers = layers_with(vec![
            net_import(),
            other("obfuscation", "BLOCK", "Hex-identifier obfuscation: 314 distinct"),
        ]);
        demote_sole_network_import(&mut layers, Some(true));

        let l1 = layers[1].as_ref().unwrap();
        assert_eq!(sev_of(&l1.findings[0]), Some("SUSPECT"), "{:?}", l1.findings);
        assert_eq!(sev_of(&l1.findings[1]), Some("BLOCK"), "{:?}", l1.findings);
        assert_eq!(l1.verdict, Verdict::Block);
    }

    /// Pins the veto the guard's safety argument rests on. `version_diff` fires
    /// SUSPECT for a *newly introduced* network import, which breaks solitude —
    /// so a compromise that ADDS network I/O is never suppressed. A future
    /// change to `version_diff` must fail here rather than in an arm run.
    #[test]
    fn a_newly_introduced_network_import_keeps_its_severity() {
        let mut layers = layers_with(vec![
            net_import(),
            other("version_diff", "SUSPECT", "Newly introduced network import"),
        ]);
        demote_sole_network_import(&mut layers, Some(true));

        assert_eq!(
            sev_of(&layers[1].as_ref().unwrap().findings[0]),
            Some("SUSPECT")
        );
    }

    /// `Some(false)` — asked, and the package is fresh. The spam-name property.
    #[test]
    fn a_fresh_package_keeps_its_sole_network_import() {
        let mut layers = layers_with(vec![net_import()]);
        demote_sole_network_import(&mut layers, Some(false));
        assert_eq!(
            sev_of(&layers[1].as_ref().unwrap().findings[0]),
            Some("SUSPECT")
        );
    }

    /// `None` — never asked. This is the arm D/E recall-floor property: all 539
    /// malicious sample entries take the local path and have no registry
    /// document, so the guard is structurally incapable of firing on them.
    #[test]
    fn without_registry_metadata_the_guard_never_fires() {
        let mut layers = layers_with(vec![net_import()]);
        demote_sole_network_import(&mut layers, None);
        assert_eq!(
            sev_of(&layers[1].as_ref().unwrap().findings[0]),
            Some("SUSPECT")
        );
    }

    /// The guard is not a general amnesty for established packages.
    #[test]
    fn the_guard_touches_only_network_imports() {
        let mut layers = layers_with(vec![other(
            "shell_exfil",
            "SUSPECT",
            "child_process spawning a shell",
        )]);
        demote_sole_network_import(&mut layers, Some(true));
        assert_eq!(
            sev_of(&layers[1].as_ref().unwrap().findings[0]),
            Some("SUSPECT")
        );
    }

    /// Pins the recall-floor MECHANISM at the pipeline level, not just the
    /// helper: that `run_full_local_collect` passes `established: None`. Arms D
    /// and E depend on exactly this. Offline — Layer 1 only, no Docker.
    #[test]
    fn the_local_pipeline_never_demotes_a_network_import() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"p","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("index.js"),
            "const axios = require('axios');\nmodule.exports = axios;\n",
        )
        .unwrap();

        let scan = run_full_local_collect("p", dir.path(), LayerMask::from_indices(&[1]));
        let l1 = scan.layers[1].as_ref().expect("Layer 1 ran");
        let net: Vec<_> = l1
            .findings
            .iter()
            .filter(|f| f.get("check").and_then(|v| v.as_str()) == Some("network_imports"))
            .collect();
        assert_eq!(net.len(), 1, "expected the network_imports finding: {:?}", l1.findings);
        assert_eq!(
            sev_of(net[0]),
            Some("SUSPECT"),
            "a local scan has no establishment evidence and must not demote"
        );
        assert_eq!(scan.report.verdict, Verdict::Suspect);
    }

    /// Negative regression: the refuted conjunction rule must stay gone. Four
    /// distinct capabilities used to escalate to a synthetic SUSPECT.
    #[test]
    fn the_capability_cluster_escalation_stays_removed() {
        fn cap(check: &str, id: &str) -> Finding {
            let mut f = Finding::new();
            f.insert("check".into(), Value::String(check.into()));
            f.insert("severity".into(), Value::String("INFO".into()));
            f.insert("vector".into(), Value::String("B2".into()));
            f.insert("message".into(), Value::String(format!("{check} capability")));
            f.insert(CAPABILITY_KEY.into(), Value::String(id.into()));
            f
        }
        let l1 = result(vec![
            cap("suspicious_strings", "env-read"),
            cap("dynamic_require", "dynamic-require"),
            cap("obfuscation", "encoded-blob"),
            cap("install_script", "install-hook"),
        ]);
        let scan = finish_scan(
            "p",
            LayerMask::from_indices(&[1]),
            LayerMask([false, true, true, true]),
            [None, Some(l1), None, None],
            [None, Some(1), None, None],
            ScanContext {
                registry_status: None,
                declared_deps: None,
                vendored: false,
                established: None,
            },
        );
        let l1 = scan.layers[1].as_ref().unwrap();
        assert!(
            !l1.findings
                .iter()
                .any(|f| f.get("check").and_then(|v| v.as_str()) == Some("capability_cluster")),
            "the conjunction rule was refuted (lift 0.11) — do not reintroduce it: {:?}",
            l1.findings
        );
        assert_eq!(
            scan.report.verdict,
            Verdict::Pass,
            "four capabilities alone must not accuse"
        );
    }
}
