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

/// Check if `name` is a typosquat of any popular package.
/// Returns a Finding map or `None` if the package looks clean.
pub fn check_typosquat(name: &str, top_packages: &[String]) -> Option<Map<String, Value>> {
    let bare = bare_name(name);

    let mut closest_pkg: Option<&str> = None;
    let mut min_dist = usize::MAX;

    for pkg in top_packages {
        let bare_pkg = bare_name(pkg);
        if bare == bare_pkg {
            // Exact match with known popular package — INFO only
            let mut f = Map::new();
            f.insert("severity".into(), Value::String("INFO".into()));
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
    }

    #[test]
    fn long_distance_one_blocks() {
        let f = check_typosquat("expresss", &top()).unwrap();
        assert_eq!(sev(&f), "BLOCK");
        assert_eq!(f.get("distance").unwrap().as_u64(), Some(1));
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
}
