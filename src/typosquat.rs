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
fn bare_name(name: &str) -> &str {
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
