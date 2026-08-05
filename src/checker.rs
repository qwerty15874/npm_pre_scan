use serde_json::{Map, Value};

use crate::age_check::check_age_and_downloads;
use crate::combosquat::check_combosquat;
use crate::maintainer::check_maintainer_change;
use crate::models::{score_findings, CheckResult, Finding, Verdict};
use crate::namespace::check_namespace_conflict;
use crate::registry::get_package_info;
use crate::typosquat::check_typosquat;

/// Aggregate a verdict from all findings.
/// BLOCK if any finding has severity BLOCK; SUSPECT if any SUSPECT (no BLOCK); else PASS.
fn aggregate_verdict(findings: &[Finding]) -> Verdict {
    for f in findings {
        if f.get("severity").and_then(|v| v.as_str()) == Some("BLOCK") {
            return Verdict::Block;
        }
    }
    for f in findings {
        if f.get("severity").and_then(|v| v.as_str()) == Some("SUSPECT") {
            return Verdict::Suspect;
        }
    }
    Verdict::Pass
}

/// Inject the `check` key into a raw finding map and push it onto findings.
fn push_finding(findings: &mut Vec<Finding>, check_name: &str, mut raw: Map<String, Value>) {
    raw.insert("check".into(), Value::String(check_name.to_string()));
    findings.push(raw);
}

/// Checks 1-3: the name-only checks. These compare the package *name* against
/// the embedded comparison lists and need no registry access at all, which is
/// what makes `run_layer0_name_only` possible.
fn name_findings(
    package_name: &str,
    top_packages: &[String],
    top_scoped: &[String],
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    // Check 1: Typosquatting
    if let Some(raw) = check_typosquat(package_name, top_packages) {
        push_finding(&mut findings, "typosquat", raw);
    }

    // Check 2: Namespace conflict
    if let Some(raw) = check_namespace_conflict(package_name, top_scoped) {
        push_finding(&mut findings, "namespace", raw);
    }

    // Check 3: Combosquatting (name-based, no registry needed)
    if let Some(raw) = check_combosquat(package_name, top_packages) {
        push_finding(&mut findings, "combosquat", raw);
    }

    findings
}

/// Run ONLY the name-based Layer 0 checks (A1 typosquat, A2 namespace, A4
/// combosquat), with no registry access whatsoever.
///
/// Exists for the evaluation harness's large-corpus sweep: a name-only pass over
/// hundreds of thousands of names costs zero HTTP requests and — since
/// `toplist::load_effective_lists(false)` also does no I/O — is byte-for-byte
/// reproducible. Going through `run_layer0` instead would issue roughly six
/// round trips per package (metadata, downloads, registry keys) and make the
/// result depend on registry state at scan time.
///
/// The note deliberately differs from `run_layer0`'s not-found note so a
/// consumer can distinguish "we chose not to ask the registry" from "the
/// registry said this package does not exist" — two facts that mean very
/// different things when scoring a detection.
pub fn run_layer0_name_only(
    package_name: &str,
    top_packages: &[String],
    top_scoped: &[String],
) -> CheckResult {
    let findings = name_findings(package_name, top_packages, top_scoped);
    CheckResult {
        package: package_name.to_string(),
        verdict: aggregate_verdict(&findings),
        score: score_findings(&findings),
        findings,
        note: Some("Name-only mode; registry-based checks not attempted".to_string()),
    }
}

/// A package is "established" if it has been maintained long enough and often
/// enough that it cannot plausibly be an attacker's impersonation of something
/// else.
///
/// Both inputs come from the registry `info` already fetched by `run_layer0` —
/// no extra HTTP. `registry::get_downloads` is deliberately NOT consulted: it
/// costs a round trip per call, and `check_age_and_downloads` only pays that on
/// the `age < 7 days` path.
///
/// ## Calibration (v18, measured against the real registry)
///
/// **Age alone does not discriminate at all**, which was a surprise and is worth
/// recording so nobody tries it again. The 2017-campaign squats are as old as
/// their victims — they were registered years ago and simply left in place:
///
/// | | age (days) | versions |
/// |---|---|---|
/// | squats (`expres`, `crossenv`, `mongose`, `babelcli`, `jquery.js`, `nodesass`, `d3.js`, `gruntcli`, `mysqljs`, `sqliter`, `smb`) | 3302–5046 | **3–5** |
/// | legitimate (`babel-cli`, `sqlite`, `express`, `lodash`, `d3`, `mongoose`, `node-sass`, …) | 3931–5705 | **10–2898** |
///
/// **Version count separates cleanly.** A squatter publishes two or three
/// placeholder versions and stops; a real package accretes releases for years.
/// The threshold sits at 10 — twice the largest squat observed (`expres`, 5) and
/// at or below every legitimate package in the benign corpus that the name
/// checks accuse.
///
/// The age condition is kept as a second gate even though it is not the
/// discriminating one: a brand-new package that publishes 10 versions in a day
/// is itself a squatter pattern, and requiring both closes that hole cheaply.
///
/// Caught by running the tool rather than by reasoning: an earlier draft used
/// `>= 5` versions and downgraded `expres` — a genuine typosquat and a true
/// positive in arm B — into an INFO. See `an_old_squat_with_few_versions_is_not_established`.
const ESTABLISHED_MIN_AGE_DAYS: f64 = 365.0;
const ESTABLISHED_MIN_VERSIONS: usize = 10;

fn is_established(info: &Value) -> bool {
    let old_enough = crate::registry::get_package_age_days(info)
        .is_some_and(|d| d >= ESTABLISHED_MIN_AGE_DAYS);
    let version_count = info
        .get("versions")
        .and_then(|v| v.as_object())
        .map_or(0, |m| m.len());
    old_enough && version_count >= ESTABLISHED_MIN_VERSIONS
}

/// Downgrade name-based BLOCKs (A1 typosquat, A2 namespace) to INFO when the
/// accused package is itself established.
///
/// ## Why (v18 — measured defect, fixed)
///
/// The name checks answer "does this name resemble a popular package?", which is
/// the right question for a name nobody has seen before and the wrong one for a
/// package that has existed for years. v17 measured both failure modes on real
/// packages: `sqlite` (a real package, distance 1 from `sqlite3`) and `babel-cli`
/// (flattens to the same form as `@babel/cli`) were both hard-BLOCK'd.
///
/// A typosquat's whole business model requires the name to be new — it exists to
/// catch a typo before anyone notices. Six years of history and 30 published
/// versions is dispositive evidence against that.
///
/// Downgraded to INFO rather than dropped, so the resemblance stays visible in
/// the report and in `findings.csv`; INFO carries weight 2 and never moves a
/// verdict.
///
/// This runs ONLY on the registry path. `run_layer0_name_only` has no `info` and
/// must stay network-free (that contract is what makes the 216k-name arm A sweep
/// run in 43.7 s), so a name-only scan still reports the raw name verdict. Where
/// a specific package is a recurring false positive in that mode, the fix is to
/// add its parent to `data/top_packages.txt` — as v18 did for `sqlite`.
fn downgrade_established_name_blocks(package_name: &str, findings: &mut [Finding], info: &Value) {
    if !is_established(info) {
        return;
    }
    for f in findings.iter_mut() {
        let is_name_check = matches!(
            f.get("check").and_then(|v| v.as_str()),
            Some("typosquat") | Some("namespace")
        );
        let is_block = f.get("severity").and_then(|v| v.as_str()) == Some("BLOCK");
        if !(is_name_check && is_block) {
            continue;
        }
        f.insert("severity".into(), Value::String("INFO".into()));
        f.insert("downgraded_established".into(), Value::Bool(true));
        let original = f
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("name resemblance")
            .to_string();
        f.insert(
            "message".into(),
            Value::String(format!(
                "{} — downgraded: '{}' is itself an established package \
                 (published ≥{:.0} days ago with ≥{} versions), so the name \
                 resemblance is not an impersonation",
                original, package_name, ESTABLISHED_MIN_AGE_DAYS, ESTABLISHED_MIN_VERSIONS
            )),
        );
    }
}

/// Run all Layer 0 metadata checks for a single package name.
pub fn run_layer0(
    package_name: &str,
    top_packages: &[String],
    top_scoped: &[String],
) -> CheckResult {
    let mut findings: Vec<Finding> = name_findings(package_name, top_packages, top_scoped);

    // Fetch registry metadata for remaining checks
    let info = match get_package_info(package_name) {
        None => {
            let verdict = aggregate_verdict(&findings);
            let score = score_findings(&findings);
            return CheckResult {
                package: package_name.to_string(),
                verdict,
                score,
                findings,
                note: Some(
                    "Package not found on npm registry; registry-based checks skipped".to_string(),
                ),
            };
        }
        Some(v) => v,
    };

    // Post-pass on checks 1-2, now that registry metadata is available: an
    // established package is not impersonating anything. Runs before the verdict
    // is aggregated so the downgrade actually takes effect.
    downgrade_established_name_blocks(package_name, &mut findings, &info);

    // Check 4: Age + download spike
    if let Some(raw) = check_age_and_downloads(package_name, &info) {
        push_finding(&mut findings, "age_downloads", raw);
    }

    // Check 5: Maintainer change
    if let Some(raw) = check_maintainer_change(&info) {
        push_finding(&mut findings, "maintainer", raw);
    }

    // Check 6: Registry signature verification
    if let Some(raw) = crate::signatures::check_signatures(package_name, &info) {
        push_finding(&mut findings, "signatures", raw);
    }

    let verdict = aggregate_verdict(&findings);
    let score = score_findings(&findings);
    CheckResult {
        package: package_name.to_string(),
        verdict,
        score,
        findings,
        note: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small hand-built lists so these tests never touch data/*.txt and stay
    // independent of that file's contents.
    fn top() -> Vec<String> {
        ["express", "lodash", "cross-env", "d3"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn scoped() -> Vec<String> {
        vec!["@aws-sdk/client-s3".to_string()]
    }

    #[test]
    fn name_only_finds_the_same_name_based_findings_as_the_full_run() {
        // A typosquat is reachable from the name alone, so the name-only pass
        // must reach exactly the same conclusion as the networked one would.
        let r = run_layer0_name_only("expres", &top(), &scoped());
        assert_eq!(r.verdict, Verdict::Block);
        let checks: Vec<&str> = r
            .findings
            .iter()
            .filter_map(|f| f.get("check").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(checks, vec!["typosquat"]);
        assert_eq!(r.package, "expres");
        assert_eq!(r.score, score_findings(&r.findings));
    }

    #[test]
    fn name_only_runs_all_three_name_checks() {
        // A namespace conflict is check 2, not check 1 — proves the extraction
        // kept all three name-based checks, not just typosquat.
        let r = run_layer0_name_only("aws-sdk-client-s3", &top(), &scoped());
        assert_eq!(r.verdict, Verdict::Block);
        assert!(r
            .findings
            .iter()
            .any(|f| f.get("check").and_then(|v| v.as_str()) == Some("namespace")));
    }

    #[test]
    fn name_only_note_is_distinct_from_the_not_found_note() {
        // The harness relies on these two strings differing to tell "we didn't
        // ask" apart from "npm said no".
        let name_only = run_layer0_name_only("some-unremarkable-name", &top(), &scoped());
        let note = name_only.note.expect("name-only mode must annotate itself");
        assert!(note.contains("Name-only mode"));
        assert!(
            !note.contains("not found on npm registry"),
            "must not be confusable with the 404 note"
        );
    }

    #[test]
    fn a_clean_name_passes_with_no_findings() {
        let r = run_layer0_name_only("some-unremarkable-name", &top(), &scoped());
        assert_eq!(r.verdict, Verdict::Pass);
        assert!(r.findings.is_empty());
        assert_eq!(r.score, 0);
    }

    #[test]
    fn an_exact_popular_match_is_info_only_and_still_passes() {
        // Scanning a legitimate popular package yields an INFO A1 finding. It
        // must not raise the verdict, or every benign control in the evaluation
        // corpus would register as a false positive.
        let r = run_layer0_name_only("lodash", &top(), &scoped());
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(
            r.findings[0].get("severity").and_then(|v| v.as_str()),
            Some("INFO")
        );
    }

    #[test]
    fn aggregate_verdict_prefers_block_over_suspect() {
        let mk = |sev: &str| {
            let mut f = Map::new();
            f.insert("severity".into(), Value::String(sev.into()));
            f
        };
        assert_eq!(aggregate_verdict(&[mk("SUSPECT"), mk("BLOCK")]), Verdict::Block);
        assert_eq!(aggregate_verdict(&[mk("INFO"), mk("SUSPECT")]), Verdict::Suspect);
        assert_eq!(aggregate_verdict(&[mk("INFO")]), Verdict::Pass);
        assert_eq!(aggregate_verdict(&[]), Verdict::Pass);
    }

    // ── Established-package guard (v18) ────────────────────────────────────────
    // Pins the fix for `sqlite` (A1) and `babel-cli` (A2), both hard-BLOCK'd in
    // v17 for resembling a package they have coexisted with for years.

    /// Registry `info` for a package `age_days` old with `versions` releases.
    fn info_aged(age_days: i64, versions: usize) -> Value {
        let created = chrono::Utc::now() - chrono::Duration::days(age_days);
        let mut vmap = Map::new();
        for i in 0..versions {
            vmap.insert(format!("1.0.{i}"), serde_json::json!({}));
        }
        serde_json::json!({
            "time": { "created": created.to_rfc3339() },
            "versions": Value::Object(vmap),
        })
    }

    fn name_block(check: &str) -> Finding {
        let mut f = Map::new();
        f.insert("check".into(), Value::String(check.into()));
        f.insert("severity".into(), Value::String("BLOCK".into()));
        f.insert("vector".into(), Value::String("A1".into()));
        f.insert("message".into(), Value::String("Very likely typosquat of 'x'".into()));
        f
    }

    fn sev_of(f: &Finding) -> Option<&str> {
        f.get("severity").and_then(|v| v.as_str())
    }

    #[test]
    fn established_package_name_block_is_downgraded_to_info() {
        for check in ["typosquat", "namespace"] {
            let mut findings = vec![name_block(check)];
            downgrade_established_name_blocks("sqlite", &mut findings, &info_aged(2000, 30));
            assert_eq!(sev_of(&findings[0]), Some("INFO"), "{check}: {findings:?}");
            assert_eq!(
                findings[0].get("downgraded_established").and_then(|v| v.as_bool()),
                Some(true)
            );
            // The original reason must survive in the message, not be replaced.
            assert!(findings[0]
                .get("message")
                .and_then(|v| v.as_str())
                .is_some_and(|m| m.contains("Very likely typosquat")));
        }
    }

    #[test]
    fn a_brand_new_package_is_still_blocked() {
        let mut findings = vec![name_block("typosquat")];
        downgrade_established_name_blocks("expresss", &mut findings, &info_aged(2, 1));
        assert_eq!(
            sev_of(&findings[0]),
            Some("BLOCK"),
            "a two-day-old name is exactly what A1 exists to catch"
        );
    }

    /// Both conditions are required — age alone is not enough (a squatter can
    /// register a name and sit on it), and neither is version count.
    #[test]
    fn establishment_requires_both_age_and_versions() {
        assert!(is_established(&info_aged(2000, 30)));
        assert!(!is_established(&info_aged(2000, 1)), "old but never developed");
        assert!(!is_established(&info_aged(10, 30)), "many versions, but brand new");
        assert!(!is_established(&serde_json::json!({})), "no metadata at all");
    }

    /// REGRESSION. The v18 draft used `>= 5` versions and downgraded `expres` —
    /// a real 2017-campaign typosquat and a true positive in arm B — to INFO.
    ///
    /// Age cannot catch this: `expres` was registered in 2012 and is OLDER than
    /// several of the legitimate packages the guard exists to protect. What
    /// separates them is release history — every measured squat has 3–5
    /// versions, every legitimate package 10 or more.
    #[test]
    fn an_old_squat_with_few_versions_is_not_established() {
        // expres: created 2012-10-10, 5 versions (measured 2026-08-04).
        assert!(
            !is_established(&info_aged(5046, 5)),
            "a 14-year-old name with 5 versions is a parked squat, not a maintained package"
        );
        // The other campaign names, all 3–4 versions and ~9 years old.
        for versions in [3, 4] {
            assert!(!is_established(&info_aged(3303, versions)));
        }
        // babel-cli: created 2015, 75 versions — the package the guard is FOR.
        assert!(is_established(&info_aged(3931, 75)));
    }

    /// End-to-end through the post-pass, not just the predicate.
    #[test]
    fn an_old_squat_keeps_its_block() {
        let mut findings = vec![name_block("typosquat")];
        downgrade_established_name_blocks("expres", &mut findings, &info_aged(5046, 5));
        assert_eq!(
            sev_of(&findings[0]),
            Some("BLOCK"),
            "expres must stay a true positive"
        );
    }

    /// The guard is scoped to the NAME checks. A content or signature BLOCK must
    /// survive it — age says nothing about whether a package was compromised.
    #[test]
    fn established_guard_does_not_touch_other_checks() {
        let mut sig = name_block("signatures");
        sig.insert("message".into(), Value::String("Invalid registry signature".into()));
        let mut findings = vec![sig];
        downgrade_established_name_blocks("lodash", &mut findings, &info_aged(3000, 100));
        assert_eq!(
            sev_of(&findings[0]),
            Some("BLOCK"),
            "a tampered signature on an old package is still tampering"
        );
    }

    /// SUSPECT-level name findings are left alone: the guard exists to stop
    /// refusing an install, not to hide the resemblance.
    #[test]
    fn established_guard_only_touches_blocks() {
        let mut f = name_block("typosquat");
        f.insert("severity".into(), Value::String("SUSPECT".into()));
        let mut findings = vec![f];
        downgrade_established_name_blocks("sqlite", &mut findings, &info_aged(2000, 30));
        assert_eq!(sev_of(&findings[0]), Some("SUSPECT"));
    }
}
