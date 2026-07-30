use serde_json::{Map, Value};

static TOP_SCOPED_DATA: &str = include_str!("../data/top_scoped_packages.txt");

pub fn load_top_scoped_packages() -> Vec<String> {
    TOP_SCOPED_DATA
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Normalize a package name for namespace conflict comparison.
/// `@aws-sdk/client-s3` → `aws-sdk-client-s3` (lowercased)
///
/// `pub(crate)` (not private) so `toplist::split_and_filter_scoped` can reuse
/// the exact same flattening rule when filtering fetched scoped names against
/// the fetched unscoped set — two independent flattening implementations
/// would risk drifting apart.
pub(crate) fn normalize(pkg: &str) -> String {
    let stripped = if pkg.starts_with('@') {
        pkg.trim_start_matches('@')
    } else {
        pkg
    };
    stripped.replace('/', "-").to_lowercase()
}

/// Detect if an unscoped package name conflicts with a popular scoped package.
/// Only applies to unscoped packages (those not starting with `@`).
pub fn check_namespace_conflict(name: &str, top_scoped: &[String]) -> Option<Map<String, Value>> {
    // Only unscoped packages can shadow scoped ones
    if name.starts_with('@') {
        return None;
    }

    let name_norm = normalize(name);

    for scoped_pkg in top_scoped {
        if normalize(scoped_pkg) == name_norm {
            let mut f = Map::new();
            f.insert("severity".into(), Value::String("BLOCK".into()));
            f.insert("vector".into(), Value::String("A2".into()));
            f.insert(
                "message".into(),
                Value::String(format!(
                    "Name '{}' conflicts with popular scoped package '{}' (possible namespace confusion attack)",
                    name, scoped_pkg
                )),
            );
            f.insert(
                "conflicting_scoped".into(),
                Value::String(scoped_pkg.clone()),
            );
            return Some(f);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scoped() -> Vec<String> {
        ["@aws-sdk/client-s3", "@babel/core"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    // 3e: the embedded data file's header comment (`# …`) must not leak into
    // the loaded scoped-package list, and real entries must still be present.
    #[test]
    fn load_top_scoped_packages_skips_header_comments() {
        let pkgs = load_top_scoped_packages();
        assert!(
            !pkgs.iter().any(|p| p.starts_with('#')),
            "no loaded scoped package name should start with '#'"
        );
        assert!(pkgs.iter().any(|p| p == "@angular/core"));
        assert!(pkgs.iter().any(|p| p == "@babel/core"));
        assert!(pkgs.len() > 80, "expected the full curated list (~94), got {}", pkgs.len());
    }

    #[test]
    fn normalize_flattens_scope() {
        assert_eq!(normalize("@aws-sdk/client-s3"), "aws-sdk-client-s3");
        assert_eq!(normalize("Express"), "express");
    }

    #[test]
    fn unscoped_shadowing_a_scoped_pkg_blocks() {
        let f = check_namespace_conflict("aws-sdk-client-s3", &scoped()).unwrap();
        assert_eq!(f.get("severity").and_then(|v| v.as_str()), Some("BLOCK"));
        assert_eq!(
            f.get("conflicting_scoped").and_then(|v| v.as_str()),
            Some("@aws-sdk/client-s3")
        );
        assert_eq!(f.get("vector").and_then(|v| v.as_str()), Some("A2"));
    }

    #[test]
    fn scoped_input_never_conflicts() {
        assert!(check_namespace_conflict("@aws-sdk/client-s3", &scoped()).is_none());
    }

    #[test]
    fn unrelated_name_is_clean() {
        assert!(check_namespace_conflict("my-cool-pkg", &scoped()).is_none());
    }
}
