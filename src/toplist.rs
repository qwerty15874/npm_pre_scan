// Live-refresh of the Layer 0 comparison lists (`--refresh-top`).
//
// The Layer 0 typosquat/namespace/combosquat checks (`typosquat.rs`,
// `namespace.rs`, `combosquat.rs`) compare candidate names against two
// static, compiled-in snapshots (`data/top_packages.txt`,
// `data/top_scoped_packages.txt`). This module optionally augments those
// snapshots with a live sweep of the npm search API, so newly-popular
// packages get squat protection without a manual re-curation + rebuild.
//
// Design in one paragraph: sweep ~24 curated 2-letter seeds against
// `GET /-/v1/search`, one page of 250 each; harvest `(name, weekly_downloads)`
// pairs (the API's own popularity ranking is relevance-dominated and not
// trusted — `downloads.weekly` is the real signal); dedup + floor-filter +
// rank client-side; split by `@` scope; union the result INTO the embedded
// snapshot (embedded-first, so a bad/empty fetch can never shrink coverage);
// cache the fetched lists on disk for 24h. Opt-in only (`--refresh-top` /
// `NPM_PRE_SCAN_REFRESH_TOP`) — `load_effective_lists(false)` is
// byte-identical to today's behavior with zero filesystem or network access,
// so it does not affect the default scan path or `cargo test`.
//
// Everything below the constants is split into two halves: pure functions
// (parsing/ranking/merging/rendering — all unit-tested against a recorded
// fixture, no I/O) and I/O + orchestration (cache dir resolution, reading/
// writing the cache, the seed sweep itself, and `load_effective_lists`, the
// public entry point). No test in `mod tests` constructs a `reqwest::Client`
// or calls `fetch_top_names`/`registry::fetch_search_page` — same offline
// convention as `registry.rs`'s own fetchers.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use serde_json::Value;

/// Curated 2-letter high-frequency search seeds. Verified live 2026-07-12:
/// the npm search API's `text` param must be 2-64 chars (single letters and
/// `text=*` both fail with `ERR_TEXT_LENGTH`), and there is no working
/// match-all trick — but popular packages reliably float into **page 1** of
/// a search for common short prefixes even though the API's own popularity
/// score is otherwise relevance-dominated (page 2+ was empirically junk for
/// a sampled seed). ~24 seeds, one page each, is the sweep.
const SEEDS: &[&str] = &[
    "re", "la", "co", "in", "st", "an", "de", "ma", "pr", "se", "te", "ve", "no", "li", "ba", "fi",
    "mo", "pa", "ch", "ge", "un", "we", "ex", "pl",
];

/// One page per seed. npm's search API accepts `size` up to 250 (verified).
const PAGE_SIZE: usize = 250;
/// Minimum weekly downloads (per `downloads.weekly`) to accept a fetched name.
const MIN_WEEKLY: u64 = 500_000;
/// Hard cap on the number of fetched names kept after ranking.
const MAX_FETCHED: usize = 1500;
/// Sanity guard: a sweep is accepted only if at least this many names clear
/// `MIN_WEEKLY`. Protects against silently harvesting garbage if the API's
/// response shape drifts out from under `parse_search_page`. The union-merge
/// below already bounds the downside of a bad sweep at "no improvement over
/// the embedded snapshot" — this guard means we don't even try to use one.
const MIN_ACCEPT: usize = 200;
/// On-disk cache freshness window.
const CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Sleep between seed requests. Not just a courtesy: measured live
/// 2026-07-12, the npm search API rate-limits with HTTP 429 behind a
/// short-window token bucket (~10-request burst, then 429s carrying
/// `retry-after: 0` — i.e. a fast-refilling bucket, not a long lockout). At
/// 150ms spacing the sweep died around seed #11; at 1.2s spacing 15/15
/// requests succeeded, even immediately after triggering 429s. The sweep
/// runs at most once per 24h (a fresh cache skips it entirely), so the ~29s
/// of wall time this spacing costs is acceptable.
const INTER_REQUEST_SLEEP: Duration = Duration::from_millis(1200);
/// Sleep before retrying a failed seed request. Longer than
/// `INTER_REQUEST_SLEEP`, so a 429 that slipped through the inter-request
/// spacing has had comfortably more than one bucket-refill window (see
/// `INTER_REQUEST_SLEEP`) to clear before the retry.
const RETRY_SLEEP: Duration = Duration::from_secs(2);
/// Total attempts per seed (1 initial + 2 retries) before the whole sweep
/// aborts. A transient 429 clears on the first retry after `RETRY_SLEEP`; a
/// seed still failing after 3 attempts spread over ~4s is a genuine
/// network/API problem, and aborting (rather than skipping the seed) keeps
/// the `MIN_ACCEPT` sanity guard honest — a partial sweep isn't a
/// trustworthy sample.
const MAX_ATTEMPTS_PER_SEED: usize = 3;

// ─────────────────────────────────────────────────────────────────────────
// Pure functions (no I/O) — unit-tested against tests/fixtures/toplist/
// ─────────────────────────────────────────────────────────────────────────

/// Parse one npm search-API response body into `(name, weekly_downloads)`
/// pairs: `objects[].package.name` + `objects[].downloads.weekly`.
///
/// `None` on shape mismatch: malformed JSON, or a missing `objects` array —
/// either means the API contract changed and the sweep should abort rather
/// than silently harvest garbage. An empty `objects` array is a valid (if
/// useless) page and yields `Some(vec![])`. An object missing the
/// `downloads` key entirely (observed live — see the fixture's `co-prompt`
/// entry) yields `weekly = 0` rather than being dropped; an object missing
/// `package.name` is skipped (defensive — not observed live, but a name-less
/// entry can't be ranked or merged).
pub(crate) fn parse_search_page(body: &str) -> Option<Vec<(String, u64)>> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    let objects = parsed.get("objects")?.as_array()?;

    let mut out = Vec::with_capacity(objects.len());
    for obj in objects {
        let name = match obj
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
        {
            Some(n) => n.to_string(),
            None => continue,
        };
        let weekly = obj
            .get("downloads")
            .and_then(|d| d.get("weekly"))
            .and_then(|w| w.as_u64())
            .unwrap_or(0);
        out.push((name, weekly));
    }
    Some(out)
}

/// Dedup `harvested` by name (max `weekly` wins on a repeat — the same
/// popular package can surface from more than one seed's page), filter to
/// `weekly >= floor`, sort descending by weekly (ties broken by name for
/// determinism), and truncate to `cap` entries.
pub(crate) fn rank_and_floor(harvested: Vec<(String, u64)>, floor: u64, cap: usize) -> Vec<String> {
    let mut best: HashMap<String, u64> = HashMap::new();
    for (name, weekly) in harvested {
        best.entry(name)
            .and_modify(|w| {
                if weekly > *w {
                    *w = weekly;
                }
            })
            .or_insert(weekly);
    }

    let mut ranked: Vec<(String, u64)> = best.into_iter().filter(|(_, w)| *w >= floor).collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked.truncate(cap);

    ranked.into_iter().map(|(name, _)| name).collect()
}

/// Split fetched names into `(unscoped, scoped)` by `@` prefix, then drop
/// any scoped name whose flattened form (`namespace::normalize`) also
/// appears in the fetched unscoped set. Rationale: a popular flat twin
/// (`babel-core` alongside `@babel/core`) means legitimate coexistence in
/// the ecosystem, not a namespace-squatting attempt — adding `@babel/core`
/// to the scoped list under those conditions would make `babel-core` trip
/// `check_namespace_conflict` as a false positive the moment this sweep ran.
pub(crate) fn split_and_filter_scoped(names: &[String]) -> (Vec<String>, Vec<String>) {
    let mut unscoped = Vec::new();
    let mut scoped = Vec::new();
    for name in names {
        if name.starts_with('@') {
            scoped.push(name.clone());
        } else {
            unscoped.push(name.clone());
        }
    }

    let unscoped_flat: HashSet<String> = unscoped
        .iter()
        .map(|n| crate::namespace::normalize(n))
        .collect();
    scoped.retain(|s| !unscoped_flat.contains(&crate::namespace::normalize(s)));

    (unscoped, scoped)
}

/// Union of `embedded` and `fetched`: embedded order preserved, unseen
/// fetched names appended (in their given order); case-insensitive dedup
/// keeps the embedded casing. A bad or empty fetch can therefore never
/// shrink or reorder the embedded coverage — it can only append to it. Order
/// matters beyond cosmetics: `check_typosquat`'s first-min-wins loop over
/// `top_packages` is order-dependent for tie-breaking among equidistant
/// matches, so the curated snapshot must stay a stable prefix.
pub(crate) fn merge_top(embedded: &[String], fetched: &[String]) -> Vec<String> {
    let mut seen: HashSet<String> = embedded.iter().map(|s| s.to_lowercase()).collect();
    let mut out = embedded.to_vec();
    for name in fetched {
        if seen.insert(name.to_lowercase()) {
            out.push(name.clone());
        }
    }
    out
}

/// `true` if `mtime` is within `ttl` of `now`. A future `mtime` (clock skew —
/// `now.duration_since(mtime)` errors because `mtime > now`) is treated as
/// fresh, not stale: a skewed clock is not evidence the cache is old.
pub(crate) fn cache_is_fresh(mtime: SystemTime, now: SystemTime, ttl: Duration) -> bool {
    match now.duration_since(mtime) {
        Ok(age) => age < ttl,
        Err(_) => true,
    }
}

/// Render a list of names as the on-disk cache format: a header comment
/// recording the fetch time (RFC3339), then one name per line — the same
/// one-per-line `#`-comment format as the embedded `data/*.txt` files (see
/// `typosquat::load_top_packages`), so `parse_lines` can read either.
pub(crate) fn render_cache(names: &[String], fetched_at: DateTime<Utc>) -> String {
    let mut out = format!(
        "# npm-pre-scan live-refresh cache\n# Fetched at: {}\n",
        fetched_at.to_rfc3339()
    );
    for name in names {
        out.push_str(name);
        out.push('\n');
    }
    out
}

/// Parse the on-disk cache format (also valid for the embedded `data/*.txt`
/// format): one name per line, blank lines and `#`-comments skipped.
/// Mirrors `typosquat::load_top_packages`'s rules exactly — case- and
/// order-preserving. Deliberately NOT `runtime_lists::merge_lines`, which
/// lowercases into an unordered `HashSet` (wrong here: `merge_top`'s
/// case-preservation and `check_typosquat`'s order-dependent tie-break both
/// need the original case and order intact).
pub(crate) fn parse_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────
// I/O + orchestration
// ─────────────────────────────────────────────────────────────────────────

const UNSCOPED_FILE: &str = "top_packages.txt";
const SCOPED_FILE: &str = "top_scoped_packages.txt";

/// Resolve the on-disk cache directory: `$NPM_PRE_SCAN_CACHE_DIR` >
/// `$XDG_CACHE_HOME` > `$HOME/.cache`, always with an `npm-pre-scan`
/// subdirectory appended. `None` if none of the three env vars are set (or
/// all are empty) — callers must treat that as "fetch still works, just
/// uncached," never as an error.
fn cache_dir() -> Option<PathBuf> {
    let base = ["NPM_PRE_SCAN_CACHE_DIR", "XDG_CACHE_HOME"]
        .iter()
        .find_map(|key| std::env::var(key).ok().filter(|v| !v.is_empty()))
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|v| !v.is_empty())
                .map(|home| PathBuf::from(home).join(".cache"))
        })?;
    Some(base.join("npm-pre-scan"))
}

/// Read both cache files out of `dir`. `None` if either is missing or
/// unreadable — a partial cache (one file present, one absent) is treated
/// the same as no cache, since `load_effective_lists` always writes/reads
/// them as a pair.
fn read_cache(dir: &Path) -> Option<(Vec<String>, Vec<String>)> {
    let unscoped = fs::read_to_string(dir.join(UNSCOPED_FILE)).ok()?;
    let scoped = fs::read_to_string(dir.join(SCOPED_FILE)).ok()?;
    Some((parse_lines(&unscoped), parse_lines(&scoped)))
}

/// mtime of the cache, taken from the unscoped file (written atomically
/// alongside the scoped file by `write_cache`, so they always share a fetch
/// timestamp). `None` if the file doesn't exist or its metadata is unreadable.
fn cache_mtime(dir: &Path) -> Option<SystemTime> {
    fs::metadata(dir.join(UNSCOPED_FILE)).ok()?.modified().ok()
}

/// Write one cache file atomically: render to a `.tmp` sibling, then
/// `fs::rename` over the final path (rename is atomic on the same
/// filesystem, so a reader never observes a partially-written file).
fn write_one(dir: &Path, filename: &str, names: &[String], fetched_at: DateTime<Utc>) -> std::io::Result<()> {
    let body = render_cache(names, fetched_at);
    let tmp_path = dir.join(format!("{}.tmp", filename));
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(body.as_bytes())?;
    }
    fs::rename(&tmp_path, dir.join(filename))
}

/// Write both cache files into `dir`, creating it (and parents) if needed.
/// Best-effort: any I/O failure (unwritable/nonexistent cache dir, disk
/// full, ...) is silently swallowed — a cache write failure must never fail
/// a scan, it just means "uncached this time," same as no resolvable
/// `cache_dir()` at all.
fn write_cache(dir: &Path, unscoped: &[String], scoped: &[String]) {
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let fetched_at = Utc::now();
    let _ = write_one(dir, UNSCOPED_FILE, unscoped, fetched_at);
    let _ = write_one(dir, SCOPED_FILE, scoped, fetched_at);
}

/// Run `attempt` up to `max_attempts` times, sleeping `retry_sleep` before
/// each retry, returning the first `Some` (or `None` once attempts are
/// exhausted). Factored out of `fetch_top_names` — and parameterized on the
/// sleep duration — so the retry policy itself is unit-testable offline with
/// a counting closure and a zero sleep, per the no-network test convention
/// (the real caller wraps `registry::fetch_search_page`).
fn with_retry<T>(
    max_attempts: usize,
    retry_sleep: Duration,
    mut attempt: impl FnMut() -> Option<T>,
) -> Option<T> {
    for i in 0..max_attempts {
        if i > 0 {
            std::thread::sleep(retry_sleep);
        }
        if let Some(value) = attempt() {
            return Some(value);
        }
    }
    None
}

/// Sweep all `SEEDS`, one page of `PAGE_SIZE` each, via
/// `registry::fetch_search_page`, `INTER_REQUEST_SLEEP` apart. Each seed
/// gets up to `MAX_ATTEMPTS_PER_SEED` attempts (`RETRY_SLEEP` apart) to
/// absorb transient 429s from the API's token-bucket rate limit (see the
/// constants' doc comments for the measured behavior); a seed that exhausts
/// its retries aborts the whole sweep — a partial sweep isn't a trustworthy
/// sample for the `MIN_ACCEPT` sanity guard downstream. Parse failures are
/// NOT retried (a shape mismatch is deterministic; retrying can't fix it).
fn fetch_top_names() -> Option<Vec<(String, u64)>> {
    let mut harvested = Vec::new();
    for (i, seed) in SEEDS.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(INTER_REQUEST_SLEEP);
        }
        let body = with_retry(MAX_ATTEMPTS_PER_SEED, RETRY_SLEEP, || {
            crate::registry::fetch_search_page(seed, PAGE_SIZE)
        })?;
        let page = parse_search_page(&body)?;
        harvested.extend(page);
    }
    Some(harvested)
}

/// Fall back to a stale cache if one is present at `dir` (any age —
/// freshness was already ruled out by the caller before reaching this
/// point), else the embedded lists as-is. Returns whether a stale cache was
/// actually used, so the caller can phrase its one stderr `note:` line
/// accurately. Never panics; a corrupt/unreadable stale cache silently falls
/// through to embedded-only.
fn fallback_lists(
    dir: Option<&Path>,
    embedded_unscoped: Vec<String>,
    embedded_scoped: Vec<String>,
) -> (Vec<String>, Vec<String>, bool) {
    if let Some(d) = dir {
        if let Some((unscoped, scoped)) = read_cache(d) {
            return (
                merge_top(&embedded_unscoped, &unscoped),
                merge_top(&embedded_scoped, &scoped),
                true,
            );
        }
    }
    (embedded_unscoped, embedded_scoped, false)
}

/// Compute the effective (embedded ∪ fetched) top-package lists used by
/// Layer 0's typosquat/namespace/combosquat checks.
///
/// `refresh == false`: byte-identical to today's behavior —
/// `typosquat::load_top_packages()` + `namespace::load_top_scoped_packages()`
/// — zero filesystem or network access. This is the default, and what every
/// offline test exercises.
///
/// `refresh == true` follows a failure ladder that can never make a scan
/// worse, error, or panic:
///   1. A fresh on-disk cache (mtime < 24h old) is used as-is — no network
///      call, no stderr output (the silent cache-hit path).
///   2. Otherwise, attempt a fresh sweep. On success (passing the
///      `MIN_ACCEPT` sanity floor), write the new cache and merge it in.
///   3. If the sweep fails outright (network/API error) or is rejected by
///      the sanity guard, fall back to a stale cache if one exists, else the
///      embedded lists alone — either way, print exactly one `note: ...`
///      line to stderr, so a scan that silently used a different list than
///      expected still has a paper trail.
pub fn load_effective_lists(refresh: bool) -> (Vec<String>, Vec<String>) {
    let embedded_unscoped = crate::typosquat::load_top_packages();
    let embedded_scoped = crate::namespace::load_top_scoped_packages();

    if !refresh {
        return (embedded_unscoped, embedded_scoped);
    }

    let dir = cache_dir();

    if let Some(fresh) = dir.as_deref().and_then(|d| {
        let mtime = cache_mtime(d)?;
        cache_is_fresh(mtime, SystemTime::now(), CACHE_TTL)
            .then(|| read_cache(d))
            .flatten()
    }) {
        let (unscoped, scoped) = fresh;
        return (
            merge_top(&embedded_unscoped, &unscoped),
            merge_top(&embedded_scoped, &scoped),
        );
    }

    match fetch_top_names() {
        Some(harvested) => {
            let ranked = rank_and_floor(harvested, MIN_WEEKLY, MAX_FETCHED);
            if ranked.len() < MIN_ACCEPT {
                let (unscoped, scoped, used_stale) =
                    fallback_lists(dir.as_deref(), embedded_unscoped, embedded_scoped);
                eprintln!(
                    "note: live top-package refresh rejected ({} names cleared the {}/week floor, need >= {}); using {}",
                    ranked.len(),
                    MIN_WEEKLY,
                    MIN_ACCEPT,
                    if used_stale { "stale on-disk cache" } else { "embedded lists only" }
                );
                return (unscoped, scoped);
            }
            let (unscoped, scoped) = split_and_filter_scoped(&ranked);
            if let Some(d) = dir.as_deref() {
                write_cache(d, &unscoped, &scoped);
            }
            (
                merge_top(&embedded_unscoped, &unscoped),
                merge_top(&embedded_scoped, &scoped),
            )
        }
        None => {
            let (unscoped, scoped, used_stale) =
                fallback_lists(dir.as_deref(), embedded_unscoped, embedded_scoped);
            eprintln!(
                "note: live top-package refresh failed (network or API error); using {}",
                if used_stale { "stale on-disk cache" } else { "embedded lists only" }
            );
            (unscoped, scoped)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/toplist/search_page.json");

    // ── parse_search_page ───────────────────────────────────────────────

    #[test]
    fn parse_search_page_fixture_yields_expected_pairs() {
        let pairs = parse_search_page(FIXTURE).unwrap();
        assert_eq!(
            pairs,
            vec![
                ("co".to_string(), 33699572),
                ("co-body".to_string(), 1926673),
                ("co-bluebird".to_string(), 158220),
                ("@types/co-body".to_string(), 594603),
                ("co-prompt".to_string(), 0), // missing `downloads` key -> weekly=0
                ("co-use".to_string(), 187666),
            ]
        );
    }

    #[test]
    fn parse_search_page_malformed_json_is_none() {
        assert!(parse_search_page("{ not valid json").is_none());
    }

    #[test]
    fn parse_search_page_missing_objects_is_none() {
        assert!(parse_search_page(r#"{"total": 0}"#).is_none());
    }

    #[test]
    fn parse_search_page_empty_objects_is_some_empty() {
        assert_eq!(parse_search_page(r#"{"objects": []}"#), Some(vec![]));
    }

    #[test]
    fn parse_search_page_missing_downloads_is_weekly_zero() {
        let body = r#"{"objects": [{"package": {"name": "foo"}}]}"#;
        assert_eq!(parse_search_page(body), Some(vec![("foo".to_string(), 0)]));
    }

    #[test]
    fn parse_search_page_missing_package_name_is_skipped() {
        let body = r#"{"objects": [{"score": {}}, {"package": {"name": "bar"}, "downloads": {"weekly": 5}}]}"#;
        assert_eq!(parse_search_page(body), Some(vec![("bar".to_string(), 5)]));
    }

    // ── rank_and_floor ──────────────────────────────────────────────────

    #[test]
    fn rank_and_floor_filters_below_floor() {
        let harvested = vec![("a".to_string(), 1000), ("b".to_string(), 100)];
        assert_eq!(rank_and_floor(harvested, 500, 10), vec!["a".to_string()]);
    }

    #[test]
    fn rank_and_floor_sorts_descending() {
        let harvested = vec![
            ("low".to_string(), 600),
            ("high".to_string(), 900),
            ("mid".to_string(), 700),
        ];
        assert_eq!(
            rank_and_floor(harvested, 500, 10),
            vec!["high".to_string(), "mid".to_string(), "low".to_string()]
        );
    }

    #[test]
    fn rank_and_floor_dedup_keeps_max_weekly() {
        let harvested = vec![("a".to_string(), 600), ("a".to_string(), 900)];
        let ranked = rank_and_floor(harvested, 500, 10);
        assert_eq!(ranked, vec!["a".to_string()]);
    }

    #[test]
    fn rank_and_floor_truncates_to_cap() {
        let harvested: Vec<(String, u64)> = (0..10).map(|i| (format!("pkg{}", i), 1000 - i as u64)).collect();
        let ranked = rank_and_floor(harvested, 0, 3);
        assert_eq!(ranked.len(), 3);
        assert_eq!(ranked, vec!["pkg0".to_string(), "pkg1".to_string(), "pkg2".to_string()]);
    }

    // ── split_and_filter_scoped ─────────────────────────────────────────

    #[test]
    fn split_and_filter_scoped_drops_scoped_with_flat_twin_in_unscoped() {
        let names = vec!["babel-core".to_string(), "@babel/core".to_string()];
        let (unscoped, scoped) = split_and_filter_scoped(&names);
        assert_eq!(unscoped, vec!["babel-core".to_string()]);
        assert!(scoped.is_empty(), "expected @babel/core dropped (flat twin present): {:?}", scoped);
    }

    #[test]
    fn split_and_filter_scoped_keeps_scoped_without_flat_twin() {
        let names = vec!["lodash".to_string(), "@babel/core".to_string()];
        let (unscoped, scoped) = split_and_filter_scoped(&names);
        assert_eq!(unscoped, vec!["lodash".to_string()]);
        assert_eq!(scoped, vec!["@babel/core".to_string()]);
    }

    // ── merge_top ───────────────────────────────────────────────────────

    #[test]
    fn merge_top_embedded_first_order() {
        let embedded = vec!["lodash".to_string(), "express".to_string()];
        let fetched = vec!["newpkg".to_string()];
        assert_eq!(
            merge_top(&embedded, &fetched),
            vec!["lodash".to_string(), "express".to_string(), "newpkg".to_string()]
        );
    }

    #[test]
    fn merge_top_case_insensitive_dedup_keeps_embedded_casing() {
        let embedded = vec!["Lodash".to_string()];
        let fetched = vec!["lodash".to_string(), "newpkg".to_string()];
        assert_eq!(
            merge_top(&embedded, &fetched),
            vec!["Lodash".to_string(), "newpkg".to_string()]
        );
    }

    #[test]
    fn merge_top_empty_fetched_is_identity() {
        let embedded = vec!["lodash".to_string(), "express".to_string()];
        assert_eq!(merge_top(&embedded, &[]), embedded);
    }

    // ── cache_is_fresh ──────────────────────────────────────────────────

    #[test]
    fn cache_is_fresh_within_1h_is_fresh() {
        let now = SystemTime::now();
        let mtime = now - Duration::from_secs(3600);
        assert!(cache_is_fresh(mtime, now, CACHE_TTL));
    }

    #[test]
    fn cache_is_fresh_25h_old_is_stale() {
        let now = SystemTime::now();
        let mtime = now - Duration::from_secs(25 * 3600);
        assert!(!cache_is_fresh(mtime, now, CACHE_TTL));
    }

    #[test]
    fn cache_is_fresh_future_mtime_is_fresh() {
        let now = SystemTime::now();
        let mtime = now + Duration::from_secs(3600);
        assert!(cache_is_fresh(mtime, now, CACHE_TTL));
    }

    // ── render_cache / parse_lines round-trip ──────────────────────────

    #[test]
    fn render_cache_parse_lines_round_trip_preserves_order_and_case() {
        let names = vec!["Lodash".to_string(), "co-body".to_string(), "@babel/Core".to_string()];
        let fetched_at = Utc::now();
        let rendered = render_cache(&names, fetched_at);
        assert!(rendered.starts_with('#'), "expected a leading comment header");
        let parsed = parse_lines(&rendered);
        assert_eq!(parsed, names);
    }

    #[test]
    fn parse_lines_skips_comments_and_blank_lines() {
        let text = "# header\n\nlodash\n  \n# another comment\nexpress\n";
        assert_eq!(parse_lines(text), vec!["lodash".to_string(), "express".to_string()]);
    }

    // ── write_cache atomicity ───────────────────────────────────────────

    #[test]
    fn write_cache_is_atomic_and_parses_back() {
        let tmp = std::env::temp_dir().join(format!(
            "npm-pre-scan-toplist-test-{}-{}",
            std::process::id(),
            "write_cache_is_atomic_and_parses_back"
        ));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let unscoped = vec!["lodash".to_string(), "newpkg".to_string()];
        let scoped = vec!["@babel/core".to_string()];
        write_cache(&tmp, &unscoped, &scoped);

        // No .tmp files left behind.
        let leftover_tmp: Vec<_> = fs::read_dir(&tmp)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftover_tmp.is_empty(), "leftover .tmp files: {:?}", leftover_tmp);

        let (read_unscoped, read_scoped) = read_cache(&tmp).unwrap();
        assert_eq!(read_unscoped, unscoped);
        assert_eq!(read_scoped, scoped);

        let _ = fs::remove_dir_all(&tmp);
    }

    // ── regression guard ────────────────────────────────────────────────

    #[test]
    fn load_effective_lists_false_matches_embedded_loaders_exactly() {
        let (unscoped, scoped) = load_effective_lists(false);
        assert_eq!(unscoped, crate::typosquat::load_top_packages());
        assert_eq!(scoped, crate::namespace::load_top_scoped_packages());
    }

    // ── sanity guard ────────────────────────────────────────────────────

    #[test]
    fn sweep_rejected_when_below_min_accept() {
        // 3 names clear a floor of 0 -- far below MIN_ACCEPT (200) -- so a
        // caller wired this through the same acceptance check used by
        // load_effective_lists must reject the sweep.
        let harvested = vec![("a".to_string(), 10), ("b".to_string(), 20), ("c".to_string(), 30)];
        let ranked = rank_and_floor(harvested, 0, MAX_FETCHED);
        assert!(ranked.len() < MIN_ACCEPT);
    }

    // ── with_retry ──────────────────────────────────────────────────────
    // All tests use Duration::ZERO so nothing actually sleeps; the closures
    // stand in for `fetch_search_page` per the no-network convention.

    #[test]
    fn with_retry_first_success_makes_one_attempt() {
        let mut attempts = 0;
        let result = with_retry(3, Duration::ZERO, || {
            attempts += 1;
            Some("ok")
        });
        assert_eq!(result, Some("ok"));
        assert_eq!(attempts, 1);
    }

    #[test]
    fn with_retry_recovers_from_transient_failures() {
        // Fails twice (a 429 burst), succeeds on the 3rd and final attempt.
        let mut attempts = 0;
        let result = with_retry(3, Duration::ZERO, || {
            attempts += 1;
            (attempts == 3).then_some("ok")
        });
        assert_eq!(result, Some("ok"));
        assert_eq!(attempts, 3);
    }

    #[test]
    fn with_retry_exhausted_attempts_is_none() {
        let mut attempts = 0;
        let result: Option<&str> = with_retry(3, Duration::ZERO, || {
            attempts += 1;
            None
        });
        assert_eq!(result, None);
        assert_eq!(attempts, 3, "must stop at exactly max_attempts");
    }
}
