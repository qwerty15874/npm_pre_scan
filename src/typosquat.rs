use serde_json::{Map, Value};

static TOP_PACKAGES_DATA: &str = include_str!("../data/top_packages.txt");

pub fn load_top_packages() -> Vec<String> {
    TOP_PACKAGES_DATA
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Classic two-row dynamic programming Levenshtein distance.
pub fn levenshtein(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let m = a.len();
    let n = b.len();
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (curr[j - 1] + 1)
                .min(prev[j] + 1)
                .min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Strip the scope from a package name for bare comparison.
/// `@scope/name` → `name`, `name` → `name`
pub(crate) fn bare_name(name: &str) -> &str {
    if let Some(pos) = name.find('/') {
        &name[pos + 1..]
    } else {
        name
    }
}

/// Homoglyph confusable map: visually-identical-or-near-identical Unicode
/// characters (from other scripts) that attackers substitute for ASCII
/// letters in a typosquat so the name *looks* identical at a glance
/// (`lodаsh` with a Cyrillic `а` U+0430 instead of ASCII `a`). Hand-written —
/// no `unicode-normalization`/ICU dependency — covering the confusables
/// explicitly called out for this envelope: Cyrillic а/е/о/р/с/х/і and Greek
/// ο(omicron)/α(alpha)/ν(nu). This is NOT a general Unicode confusables
/// table (e.g. it does not attempt NFKC normalization or cover every script);
/// it is deliberately scoped to the highest-value, most commonly abused
/// look-alikes for Latin-script npm package names.
const CONFUSABLES: &[(char, char)] = &[
    // Cyrillic → Latin
    ('а', 'a'), // U+0430 CYRILLIC SMALL LETTER A
    ('е', 'e'), // U+0435 CYRILLIC SMALL LETTER IE
    ('о', 'o'), // U+043E CYRILLIC SMALL LETTER O
    ('р', 'p'), // U+0440 CYRILLIC SMALL LETTER ER
    ('с', 'c'), // U+0441 CYRILLIC SMALL LETTER ES
    ('х', 'x'), // U+0445 CYRILLIC SMALL LETTER HA
    ('і', 'i'), // U+0456 CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
    // Greek → Latin
    ('ο', 'o'), // U+03BF GREEK SMALL LETTER OMICRON
    ('α', 'a'), // U+03B1 GREEK SMALL LETTER ALPHA
    ('ν', 'v'), // U+03BD GREEK SMALL LETTER NU (visually closest to Latin v)
];

/// Lowercase `name` and fold each character through the confusable map.
/// ASCII input is unaffected (fold is a no-op for chars not in the map);
/// confusable characters from the covered scripts collapse to their ASCII
/// look-alike so a homoglyph typosquat reaches the same string as the
/// legitimate ASCII name before Levenshtein distance is computed.
///
/// Covered envelope: ASCII + the confusable-folded characters listed in
/// `CONFUSABLES` above, at Levenshtein distance ≤ 2 (the existing thresholds
/// in `check_typosquat` below are unchanged). Homoglyphs outside this map
/// (e.g. Cyrillic е́ with combining marks, full-width Latin, other scripts)
/// are NOT folded and fall back to whatever Levenshtein distance the raw
/// bytes happen to produce.
fn fold_confusables(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| {
            CONFUSABLES
                .iter()
                .find(|&&(from, _)| from == c)
                .map(|&(_, to)| to)
                .unwrap_or(c)
        })
        .collect()
}

/// Check if `name` is a typosquat of any popular package.
/// Returns a Finding map or `None` if the package looks clean.
pub fn check_typosquat(name: &str, top_packages: &[String]) -> Option<Map<String, Value>> {
    let bare = fold_confusables(bare_name(name));
    let bare = bare.as_str();

    let mut closest_pkg: Option<&str> = None;
    let mut min_dist = usize::MAX;

    for pkg in top_packages {
        let bare_pkg = bare_name(pkg);
        if bare == bare_pkg {
            // Exact match with known popular package — INFO only
            let mut f = Map::new();
            f.insert("severity".into(), Value::String("INFO".into()));
            f.insert("vector".into(), Value::String("A1".into()));
            f.insert("closest".into(), Value::String(pkg.clone()));
            f.insert("distance".into(), Value::Number(0.into()));
            f.insert(
                "message".into(),
                Value::String(format!(
                    "Exact match with known popular package '{}'",
                    pkg
                )),
            );
            return Some(f);
        }
        let dist = levenshtein(bare, bare_pkg);
        if dist < min_dist {
            min_dist = dist;
            closest_pkg = Some(pkg.as_str());
        }
    }

    let pkg = closest_pkg?;
    let mut f = Map::new();
    f.insert("vector".into(), Value::String("A1".into()));
    f.insert("closest".into(), Value::String(pkg.to_string()));
    f.insert(
        "distance".into(),
        Value::Number(serde_json::Number::from(min_dist)),
    );

    match min_dist {
        1 => {
            // A larger top-list makes distance-1 collisions with short legitimate
            // names common, so only BLOCK when the name is long enough to be a
            // deliberate typo; shorter near-misses downgrade to SUSPECT.
            if bare.len() >= 5 {
                f.insert("severity".into(), Value::String("BLOCK".into()));
                f.insert(
                    "message".into(),
                    Value::String(format!(
                        "Very likely typosquat of '{}' (Levenshtein distance={})",
                        pkg, min_dist
                    )),
                );
            } else {
                f.insert("severity".into(), Value::String("SUSPECT".into()));
                f.insert(
                    "message".into(),
                    Value::String(format!(
                        "Possible typosquat of '{}' (Levenshtein distance={}, short name)",
                        pkg, min_dist
                    )),
                );
            }
            Some(f)
        }
        2 => {
            f.insert("severity".into(), Value::String("SUSPECT".into()));
            f.insert(
                "message".into(),
                Value::String(format!(
                    "Possible typosquat of '{}' (Levenshtein distance={})",
                    pkg, min_dist
                )),
            );
            Some(f)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn top() -> Vec<String> {
        ["express", "chalk", "lodash", "react"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn sev(f: &Map<String, Value>) -> &str {
        f.get("severity").and_then(|v| v.as_str()).unwrap()
    }

    // 3e: the embedded data file's header comment (`# …`) must not leak into
    // the loaded package list, and real entries must still be present.
    #[test]
    fn load_top_packages_skips_header_comments() {
        let pkgs = load_top_packages();
        assert!(
            !pkgs.iter().any(|p| p.starts_with('#')),
            "no loaded package name should start with '#'"
        );
        assert!(pkgs.iter().any(|p| p == "lodash"));
        assert!(pkgs.iter().any(|p| p == "express"));
        assert!(pkgs.len() > 1000, "expected the full curated list (~1137), got {}", pkgs.len());
    }

    #[test]
    fn levenshtein_basics() {
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("abc", "abd"), 1); // substitute
        assert_eq!(levenshtein("abc", "abcd"), 1); // insert
        assert_eq!(levenshtein("abc", "ac"), 1); // delete
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn bare_name_strips_scope() {
        assert_eq!(bare_name("@scope/express"), "express");
        assert_eq!(bare_name("express"), "express");
    }

    #[test]
    fn exact_match_is_info() {
        let f = check_typosquat("express", &top()).unwrap();
        assert_eq!(sev(&f), "INFO");
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(0));
        assert_eq!(f.get("vector").and_then(|v| v.as_str()), Some("A1"));
    }

    #[test]
    fn long_distance_one_blocks() {
        let f = check_typosquat("expresss", &top()).unwrap();
        assert_eq!(sev(&f), "BLOCK");
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(1));
        assert_eq!(f.get("vector").and_then(|v| v.as_str()), Some("A1"));
    }

    #[test]
    fn short_distance_one_downgrades_to_suspect() {
        // "chal" (4 chars) vs "chalk" → distance 1, below the min-length guard
        let f = check_typosquat("chal", &top()).unwrap();
        assert_eq!(sev(&f), "SUSPECT");
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(1));
    }

    #[test]
    fn distance_two_is_suspect() {
        // "chlak" vs "chalk" → two substitutions = distance 2
        let f = check_typosquat("chlak", &top()).unwrap();
        assert_eq!(sev(&f), "SUSPECT");
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(2));
    }

    #[test]
    fn far_name_is_clean() {
        assert!(check_typosquat("totally-unrelated-xyz", &top()).is_none());
    }

    #[test]
    fn scoped_input_compares_on_bare_name() {
        let f = check_typosquat("@myscope/express", &top()).unwrap();
        assert_eq!(sev(&f), "INFO");
    }

    // 3f: homoglyph coverage — a Cyrillic-confusable spelling of a popular
    // package must fold to the ASCII name (distance 0) and be caught as an
    // exact-match INFO, exactly like the real popular package would be.
    #[test]
    fn cyrillic_homoglyph_of_lodash_is_detected() {
        // "lodаsh": the 4th character is CYRILLIC SMALL LETTER A (U+0430),
        // not ASCII 'a' (U+0061) — visually indistinguishable in most fonts.
        let name = "lod\u{0430}sh";
        assert_ne!(name, "lodash", "sanity check: must actually differ byte-for-byte");
        let f = check_typosquat(name, &top()).unwrap();
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(0));
        assert_eq!(f.get("closest").and_then(|v| v.as_str()), Some("lodash"));
    }

    // 3f: a Greek-confusable spelling of "chalk" (omicron for 'o', alpha for
    // 'a') must also fold to distance 0.
    #[test]
    fn greek_homoglyph_of_chalk_is_detected() {
        // "ch\u{03B1}lk": alpha (U+03B1) in place of ASCII 'a'.
        let name = "ch\u{03B1}lk";
        assert_ne!(name, "chalk");
        let f = check_typosquat(name, &top()).unwrap();
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(0));
        assert_eq!(f.get("closest").and_then(|v| v.as_str()), Some("chalk"));
    }

    // 3f negative control: a genuinely different (non-homoglyph, non-typo)
    // name containing an unrelated Cyrillic character must NOT be folded into
    // a false match — confusable-folding only substitutes the specific
    // mapped characters, it does not make unrelated names collide.
    #[test]
    fn unrelated_name_with_cyrillic_char_is_still_clean() {
        // "тотally-unrelated" — the leading "тот" (Cyrillic) has no ASCII
        // fold in our map for those particular letters beyond what's listed,
        // and the rest of the name is unrelated to any popular package.
        let name = "totally-unrel\u{0430}ted-xyz";
        assert!(check_typosquat(name, &top()).is_none());
    }
}
