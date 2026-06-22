use serde_json::{Map, Value};
use std::collections::HashSet;

use crate::typosquat::bare_name;

// Affixes that appear in real attacks but almost never in legitimate ecosystem packages.
// Deliberately excludes: core, cli, api, sdk, lib, utils — too common in legit packages.
const SUSPICIOUS_AFFIXES: &[&str] = &[
    "fix", "patch", "update", "secure", "official", "real", "true",
    "genuine", "safe", "trusted", "pro", "plus", "hack", "inject",
    "exploit", "evil", "malicious",
];

/// Check if `name` is a combosquat of any popular package.
///
/// Combosquatting: the candidate name contains a popular package name as a complete
/// token (split on `-`, `_`, `.`) and has at least one additional token that is a
/// known suspicious affix (`fix`, `patch`, `official`, …). This catches names like
/// `lodash-utils-fix` or `express-official` while leaving legitimate ecosystem forks
/// like `express-session` or `react-router` silent.
///
/// Always SUSPECT — never BLOCK (heuristic is inherently probabilistic).
pub fn check_combosquat(name: &str, top_packages: &[String]) -> Option<Map<String, Value>> {
    let bare = bare_name(name);

    // Need at least 2 tokens — single-token names cannot be combosquats.
    let tokens: Vec<&str> = bare.split(|c| c == '-' || c == '_' || c == '.').collect();
    if tokens.len() < 2 {
        return None;
    }

    // Build a set of popular bare names (all single-token per the data file).
    let popular_set: HashSet<&str> = top_packages.iter().map(|p| bare_name(p)).collect();

    // Skip if the candidate IS already a popular package (emits INFO in typosquat check).
    if popular_set.contains(bare) {
        return None;
    }

    // Find any single token that exactly matches a popular package.
    let matched_popular = tokens.iter().find(|&&t| popular_set.contains(t)).copied()?;

    // Remaining tokens (everything that is not the matched popular token).
    let extra_tokens: Vec<&str> = tokens
        .iter()
        .filter(|&&t| t != matched_popular)
        .copied()
        .collect();

    // At least one extra token must be a suspicious affix to suppress false-positives
    // on legitimate packages like `express-session` or `react-router`.
    let triggered_affix = extra_tokens
        .iter()
        .find(|&&t| SUSPICIOUS_AFFIXES.contains(&t))
        .copied()?;

    let mut f = Map::new();
    f.insert("severity".into(), Value::String("SUSPECT".into()));
    f.insert(
        "matched_popular".into(),
        Value::String(matched_popular.to_string()),
    );
    f.insert(
        "triggered_affix".into(),
        Value::String(triggered_affix.to_string()),
    );
    f.insert(
        "message".into(),
        Value::String(format!(
            "Possible combosquat: contains popular package '{}' with suspicious affix '{}'",
            matched_popular, triggered_affix
        )),
    );
    Some(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn top() -> Vec<String> {
        ["express", "lodash", "react", "chalk"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn sev(f: &Map<String, Value>) -> &str {
        f.get("severity").and_then(|v| v.as_str()).unwrap_or("?")
    }

    #[test]
    fn detects_popular_token_with_fix_affix() {
        let f = check_combosquat("lodash-utils-fix", &top()).unwrap();
        assert_eq!(sev(&f), "SUSPECT");
        assert_eq!(
            f.get("matched_popular").and_then(|v| v.as_str()),
            Some("lodash")
        );
    }

    #[test]
    fn detects_popular_token_with_official_affix() {
        let f = check_combosquat("express-official", &top()).unwrap();
        assert_eq!(sev(&f), "SUSPECT");
        assert_eq!(
            f.get("matched_popular").and_then(|v| v.as_str()),
            Some("express")
        );
    }

    #[test]
    fn detects_patch_affix() {
        let f = check_combosquat("react-patch", &top()).unwrap();
        assert_eq!(sev(&f), "SUSPECT");
    }

    #[test]
    fn legitimate_express_session_passes() {
        // "session" is not a suspicious affix
        assert!(check_combosquat("express-session", &top()).is_none());
    }

    #[test]
    fn legitimate_react_router_passes() {
        // "router" is not a suspicious affix
        assert!(check_combosquat("react-router", &top()).is_none());
    }

    #[test]
    fn exact_match_is_skipped() {
        // "express" is in top_packages — already handled by typosquat INFO
        assert!(check_combosquat("express", &top()).is_none());
    }

    #[test]
    fn single_token_never_triggers() {
        assert!(check_combosquat("lodash", &top()).is_none());
        assert!(check_combosquat("foobar", &top()).is_none());
    }

    #[test]
    fn unrelated_multi_token_name_is_clean() {
        assert!(check_combosquat("totally-unrelated-xyz", &top()).is_none());
    }

    #[test]
    fn scoped_input_strips_scope_before_check() {
        // @evil/lodash-fix → bare = lodash-fix → lodash token matches, fix suspicious
        let f = check_combosquat("@evil/lodash-fix", &top()).unwrap();
        assert_eq!(sev(&f), "SUSPECT");
    }
}
