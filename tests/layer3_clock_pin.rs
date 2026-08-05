//! Offline guard for the Layer 3 pinned-clock invariant (D1).
//!
//! Layer 3 is purely differential: a D1 finding exists only when the clock
//! scenario produces behaviour the baseline did not. Before v18 the baseline ran
//! on the real wall clock, so once a fixture's trigger date passed, the payload
//! fired in BOTH runs, the diff came back empty, and D1 detection silently
//! dropped to zero. `dummy_timebomb` (trigger 2026-09-01) was ~4 weeks from
//! doing exactly that.
//!
//! `docker/run_layer3.sh` now pins both ends. The invariant is:
//!
//!     FAKETIME_BASE  <  every fixture trigger date  <  FAKETIME_CLOCK
//!
//! These tests are OFFLINE and unconditional on purpose. The live D1 tests
//! (`layer3_dynamic::d1_timebomb_live_run`, `full_pipeline::dummy_timebomb_*`)
//! do fail loudly when the invariant breaks — but they are `#[ignore]`d and
//! Docker-gated, so nothing would surface a drift until someone next ran the
//! ignored suite. A plain `cargo test` must catch it.

use std::path::Path;

const SCRIPT: &str = include_str!("../docker/run_layer3.sh");

/// Pull `NAME="@YYYY-MM-DD HH:MM:SS"` out of the script and return the date part.
///
/// Deliberately parses the shell source rather than importing a Rust constant:
/// the value that actually reaches the container is the one in the script, and a
/// duplicated Rust copy could drift from it without anything noticing.
fn faketime_date(var: &str) -> String {
    let needle = format!("{var}=\"@");
    let line = SCRIPT
        .lines()
        .find(|l| l.trim_start().starts_with(&needle))
        .unwrap_or_else(|| panic!("{var} not found in docker/run_layer3.sh"));
    let after = line.split_once("=\"@").expect("malformed assignment").1;
    let value = after.split_once('"').expect("unterminated string").0;
    // "2026-09-29 00:00:00" -> "2026-09-29"; lexicographic order is chronological
    // for zero-padded ISO dates, which is all the ordering assertions need.
    value
        .split_whitespace()
        .next()
        .expect("empty FAKETIME value")
        .to_string()
}

fn days_between(earlier: &str, later: &str) -> i64 {
    let parse = |d: &str| {
        chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
            .unwrap_or_else(|e| panic!("unparseable date {d:?}: {e}"))
    };
    (parse(later) - parse(earlier)).num_days()
}

#[test]
fn baseline_clock_is_pinned_not_wall_clock() {
    // The whole point: baseline must NOT run on the real clock. If someone drops
    // the LD_PRELOAD from the baseline scenario, D1 becomes date-dependent again.
    let baseline_block = SCRIPT
        .split("strace_baseline.log")
        .nth(1)
        .expect("baseline scenario not found in run_layer3.sh");
    let invocation = &baseline_block[..baseline_block.find("stop_dns").unwrap_or(baseline_block.len())];
    assert!(
        invocation.contains("FAKETIME=\"$FAKETIME_BASE\""),
        "baseline scenario must run under the pinned FAKETIME_BASE, not the real \
         wall clock — otherwise an already-triggered time bomb fires in both runs \
         and the D1 diff is empty. Invocation was:\n{invocation}"
    );
    assert!(
        invocation.contains("LD_PRELOAD=\"$FAKETIME_LIB\""),
        "baseline scenario must LD_PRELOAD libfaketime for the pin to take effect"
    );
}

#[test]
fn clock_scenario_is_after_baseline_by_a_wide_margin() {
    let base = faketime_date("FAKETIME_BASE");
    let clock = faketime_date("FAKETIME_CLOCK");
    let delta = days_between(&base, &clock);
    assert!(
        delta >= 30,
        "FAKETIME_CLOCK ({clock}) must be at least 30 days after FAKETIME_BASE \
         ({base}) to leave room for fixture trigger dates; got {delta} days"
    );
}

#[test]
fn dummy_timebomb_trigger_sits_inside_the_pinned_window() {
    // dummy_packages/ is gitignored and absent on a fresh clone — skip rather
    // than fail, matching how the other dummy-backed tests behave.
    let fixture = Path::new("dummy_packages/dummy_timebomb/index.js");
    let Ok(src) = std::fs::read_to_string(fixture) else {
        eprintln!("skipping: {} not present (gitignored fixture)", fixture.display());
        return;
    };

    // const TRIGGER = new Date('2026-09-01T00:00:00Z');
    let trigger = src
        .split_once("new Date('")
        .and_then(|(_, rest)| rest.split_once('\''))
        .map(|(d, _)| d[..10].to_string())
        .expect("could not find a `new Date('…')` trigger literal in dummy_timebomb/index.js");

    let base = faketime_date("FAKETIME_BASE");
    let clock = faketime_date("FAKETIME_CLOCK");

    assert!(
        days_between(&base, &trigger) > 0,
        "dummy_timebomb triggers at {trigger}, which is not after FAKETIME_BASE \
         ({base}) — the payload would fire in the baseline run too, the D1 diff \
         would be empty, and D1 detection would silently read zero"
    );
    assert!(
        days_between(&trigger, &clock) > 0,
        "dummy_timebomb triggers at {trigger}, which is not before FAKETIME_CLOCK \
         ({clock}) — the clock scenario would never reach the trigger, so D1 would \
         detect nothing"
    );
}
