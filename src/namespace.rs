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
fn normalize(pkg: &str) -> String {
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
