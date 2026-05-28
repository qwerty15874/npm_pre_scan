use serde_json::{Map, Value};

static TOP_SCOPED_DATA: &str = include_str!("../layer0/data/top_scoped_packages.txt");

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
