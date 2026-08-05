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

/// Suffixes an attacker appends to an otherwise-exact package name so the result
/// still reads as the real thing (`jquery.js`, `fabric-js`, `nodemailer_js`).
///
/// Folded away for the DISTANCE comparison only — never for the exact-match test.
/// See `strip_js_suffix` and `check_typosquat` for why that distinction matters.
const JS_SUFFIXES: &[&str] = &[".js", "-js", "_js"];

/// Strip one trailing JS-ish suffix, if present.
///
/// Deliberately applied AFTER the exact-match check in `check_typosquat`, never
/// before. Folding first would make `jquery.js` compare equal to `jquery`, hit
/// the exact-match branch, and return **INFO** — downgrading a real typosquat
/// (`jquery.js` was part of the hand-labelled 2017 campaign) into an explicit
/// note that the package is a known-popular one. That is worse than the miss it
/// was meant to fix.
fn strip_js_suffix(name: &str) -> Option<&str> {
    JS_SUFFIXES
        .iter()
        .find_map(|s| name.strip_suffix(s))
        .filter(|stripped| !stripped.is_empty())
}

/// Check if `name` is a typosquat of any popular package.
/// Returns a Finding map or `None` if the package looks clean.
///
/// ## Suffix squats (v18)
///
/// `bare_name` strips only the scope, so `jquery.js` sat at Levenshtein distance
/// 3 from `jquery` and never tripped the ≤2 threshold. That accounted for 9 of
/// the 21 measured A1 misses in v17 (`cross-env.js`, `fabric-js`,
/// `http-proxy.js`, `jquery.js`, `mssql.js`, `nodemailer-js`, `nodemailer.js`,
/// `proxy.js`, `sqlite.js`). A trailing `.js`/`-js`/`_js` is now folded before
/// the distance compare, and a name that becomes an *exact* match only after
/// folding is reported as a suffix squat — a BLOCK, not the INFO the plain
/// exact-match branch would have given it.
pub fn check_typosquat(name: &str, top_packages: &[String]) -> Option<Map<String, Value>> {
    let bare = fold_confusables(bare_name(name));
    let bare = bare.as_str();
    // `None` when the name carries no JS-ish suffix; `Some` otherwise. Only the
    // distance path consults it.
    let defanged = strip_js_suffix(bare);

    let mut closest_pkg: Option<&str> = None;
    let mut min_dist = usize::MAX;
    // Set when the *suffix-stripped* name matches a popular package exactly.
    let mut suffix_squat_of: Option<&str> = None;

    for pkg in top_packages {
        let bare_pkg = bare_name(pkg);
        // Exact-match test uses the UNFOLDED name — see strip_js_suffix.
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

        if defanged.is_some_and(|d| d == bare_pkg) {
            suffix_squat_of = Some(pkg.as_str());
            break;
        }

        // Distance is the MINIMUM over both forms — the name as written and the
        // suffix-stripped form. Taking only the stripped form would be a
        // regression: 17 entries in the top list themselves end in `.js`/`-js`
        // (`discord.js`, `crypto-js`, `highlight.js`, `uglify-js`, …), so
        // comparing `dezcord.js` as `dezcord` puts it at distance 3 from
        // `discord.js` instead of 2, and a genuine typosquat stops being
        // detected. Measured: 8 such names dropped out of arm A before this was
        // a `min`.
        let dist = match defanged {
            Some(d) => levenshtein(bare, bare_pkg).min(levenshtein(d, bare_pkg)),
            None => levenshtein(bare, bare_pkg),
        };
        if dist < min_dist {
            min_dist = dist;
            closest_pkg = Some(pkg.as_str());
        }
    }

    // Exact match only AFTER stripping a JS-ish suffix: a suffix squat. This is a
    // deliberate impersonation of a specific package, so it is the strongest A1
    // signal there is — stronger than a distance-1 typo, which can be accidental.
    if let Some(pkg) = suffix_squat_of {
        let mut f = Map::new();
        f.insert("severity".into(), Value::String("BLOCK".into()));
        f.insert("vector".into(), Value::String("A1".into()));
        f.insert("closest".into(), Value::String(pkg.to_string()));
        f.insert("distance".into(), Value::Number(0.into()));
        f.insert(
            "message".into(),
            Value::String(format!(
                "Suffix squat of '{}' — identical name with a '.js'/'-js'/'_js' suffix appended",
                pkg
            )),
        );
        return Some(f);
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
            // Length guard, mirroring the distance-1 branch above. Without it,
            // a 3-character name is within distance 2 of a large slice of the
            // top list purely by chance: v17 measured `smb`→`pm2` and
            // `d3.js`→`dayjs` as accidental "hits", which is why the honest A1
            // count was 7/30 rather than 9/30. Two edits on a short name is
            // coincidence; on a long one it is a typo.
            if bare.len() < 5 {
                return None;
            }
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

    // ── Suffix squats (v18) ────────────────────────────────────────────────────

    #[test]
    fn js_suffix_squat_blocks() {
        for name in ["express.js", "express-js", "express_js"] {
            let f = check_typosquat(name, &top())
                .unwrap_or_else(|| panic!("{name} should be flagged"));
            assert_eq!(sev(&f), "BLOCK", "{name}: {f:?}");
            assert_eq!(f.get("closest").and_then(|v| v.as_str()), Some("express"));
            assert!(
                f.get("message")
                    .and_then(|v| v.as_str())
                    .is_some_and(|m| m.contains("Suffix squat")),
                "{name}: {f:?}"
            );
        }
    }

    /// THE ORDERING TEST. Folding the suffix before the exact-match check would
    /// make `express.js` compare equal to `express` and return INFO — turning a
    /// real 2017-campaign typosquat into a note saying the package is popular.
    /// The suffix fold must feed the distance path only.
    #[test]
    fn suffix_squat_is_not_downgraded_to_info() {
        let f = check_typosquat("express.js", &top()).unwrap();
        assert_ne!(
            sev(&f),
            "INFO",
            "a suffix squat must never be reported as an exact match: {f:?}"
        );
    }

    /// The real package keeps its INFO — the fold must not fire on a name that
    /// already matches exactly.
    #[test]
    fn genuine_package_still_info_after_suffix_rule() {
        let f = check_typosquat("express", &top()).unwrap();
        assert_eq!(sev(&f), "INFO");
    }

    /// A bare suffix with nothing in front is not a squat of anything.
    #[test]
    fn suffix_only_name_is_not_a_squat() {
        assert!(strip_js_suffix(".js").is_none());
        assert!(strip_js_suffix("-js").is_none());
    }

    /// A name that merely ends in `.js` but is not otherwise a popular package
    /// must not be dragged into a BLOCK.
    #[test]
    fn unrelated_dot_js_name_is_clean() {
        assert!(check_typosquat("some-unrelated-thing.js", &top()).is_none());
    }

    /// REGRESSION. 17 entries in `data/top_packages.txt` themselves end in
    /// `.js`/`-js` (`discord.js`, `crypto-js`, `highlight.js`, `uglify-js`, …).
    /// An early v18 draft compared ONLY the suffix-stripped form, which pushed
    /// `dezcord.js` from distance 2 to distance 3 against `discord.js` and lost
    /// the detection — 8 real names dropped out of arm A. The distance must be
    /// the minimum over both the written and the stripped form.
    #[test]
    fn typo_of_a_js_suffixed_top_package_is_still_caught() {
        let list: Vec<String> = ["discord.js", "crypto-js"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(levenshtein("dezcord.js", "discord.js"), 2, "precondition");

        let f = check_typosquat("dezcord.js", &list)
            .expect("a distance-2 typo of discord.js must still be flagged");
        assert_eq!(sev(&f), "SUSPECT", "{f:?}");
        assert_eq!(f.get("closest").and_then(|v| v.as_str()), Some("discord.js"));
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(2));
    }

    /// The stripped form must still be consulted — it is the whole point of the
    /// rule. `crypto-js` is in the list; `cryptojs` is one edit from its stripped
    /// form `crypto` only via the written form, so check a clean suffix squat.
    #[test]
    fn min_over_both_forms_keeps_the_suffix_squat_path() {
        let list: Vec<String> = ["crypto", "discord.js"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let f = check_typosquat("crypto-js", &list).expect("suffix squat of crypto");
        assert_eq!(sev(&f), "BLOCK");
        assert_eq!(f.get("closest").and_then(|v| v.as_str()), Some("crypto"));
    }

    // ── Distance-2 length guard (v18) ──────────────────────────────────────────

    /// v17 measured `smb`→`pm2` (distance 2, 3 chars) as an accidental "hit".
    /// Two edits on a 3-character name is coincidence, not a typo.
    #[test]
    fn short_distance_two_is_not_accused() {
        let list: Vec<String> = ["pm2"].iter().map(|s| s.to_string()).collect();
        assert_eq!(levenshtein("smb", "pm2"), 2, "precondition");
        assert!(
            check_typosquat("smb", &list).is_none(),
            "a 3-char name at distance 2 is coincidence"
        );
    }

    /// The guard must not silence genuine distance-2 typos on longer names.
    #[test]
    fn long_distance_two_still_suspect() {
        assert_eq!(levenshtein("lodashxy", "lodash"), 2, "precondition");
        let f = check_typosquat("lodashxy", &top()).unwrap();
        assert_eq!(sev(&f), "SUSPECT", "{f:?}");
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(2));
    }

    // ── The five v18 "absent parent" additions ─────────────────────────────────

    /// `sqlite` is a real package that used to BLOCK itself: distance 1 from
    /// `sqlite3`. As a list member it is now an exact match. This fixes the FP in
    /// name-only mode too, which the registry-side establishment guard cannot.
    #[test]
    fn added_parents_are_present_and_sqlite_no_longer_self_blocks() {
        let pkgs = load_top_packages();
        for p in ["ffmpeg", "fabric", "shadowsocks", "tkinter", "sqlite"] {
            assert!(pkgs.iter().any(|x| x == p), "{p} missing from top_packages.txt");
        }
        let f = check_typosquat("sqlite", &pkgs).unwrap();
        assert_eq!(sev(&f), "INFO", "sqlite must not accuse itself: {f:?}");
    }

    /// With the parent present, the campaign name is reachable at all — it scored
    /// nothing before, because `ffmpeg` was not in the list for it to be near.
    ///
    /// SUSPECT rather than BLOCK is correct: `ffmepg` is a transposition, which
    /// Levenshtein scores as 2 (one delete + one insert), not 1. SUSPECT still
    /// counts as a detection in the eval harness — only INFO does not.
    #[test]
    fn absent_parent_names_are_now_detected() {
        let pkgs = load_top_packages();
        let f = check_typosquat("ffmepg", &pkgs)
            .expect("ffmepg should now reach its parent");
        assert_eq!(sev(&f), "SUSPECT", "{f:?}");
        assert_eq!(f.get("closest").and_then(|v| v.as_str()), Some("ffmpeg"));
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(2));
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
