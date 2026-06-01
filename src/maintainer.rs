use chrono::{DateTime, TimeZone, Utc};
use serde_json::{Map, Value};
use std::collections::HashSet;

const MAINTAINER_CHANGE_WINDOW_DAYS: i64 = 30;

fn extract_maintainer_names(maintainers: &Value) -> HashSet<String> {
    let mut result = HashSet::new();
    if let Some(arr) = maintainers.as_array() {
        for m in arr {
            let name = if let Some(obj) = m.as_object() {
                obj.get("name").and_then(|v| v.as_str()).unwrap_or("")
            } else if let Some(s) = m.as_str() {
                s
            } else {
                ""
            };
            if !name.is_empty() {
                result.insert(name.to_string());
            }
        }
    }
    result
}

fn parse_version_time(time_data: &Value, version: &str) -> DateTime<Utc> {
    let ts = time_data
        .get(version)
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let normalized = ts.replace('Z', "+00:00");
    DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc.timestamp_opt(0, 0).single().unwrap_or(DateTime::<Utc>::MIN_UTC))
}

/// Detect if the latest version introduced new maintainers compared to the first version.
/// Only flags if the latest version was published within the last 30 days.
pub fn check_maintainer_change(info: &Value) -> Option<Map<String, Value>> {
    let versions = info.get("versions")?.as_object()?;
    let time_data = info.get("time")?;

    if versions.len() < 2 {
        return None;
    }

    // Sort versions by publish timestamp
    let mut version_keys: Vec<&str> = versions.keys().map(|k| k.as_str()).collect();
    version_keys.sort_by_key(|v| parse_version_time(time_data, v));

    let first_version = version_keys.first()?;
    let latest_version = version_keys.last()?;

    let first_maintainers = extract_maintainer_names(
        versions
            .get(*first_version)
            .and_then(|v| v.get("maintainers"))
            .unwrap_or(&Value::Null),
    );
    let latest_maintainers = extract_maintainer_names(
        versions
            .get(*latest_version)
            .and_then(|v| v.get("maintainers"))
            .unwrap_or(&Value::Null),
    );

    let new_maintainers: HashSet<&String> =
        latest_maintainers.difference(&first_maintainers).collect();

    if new_maintainers.is_empty() {
        return None;
    }

    // Only flag if latest version was published recently
    let latest_time = parse_version_time(time_data, latest_version);
    let cutoff = Utc::now() - chrono::Duration::days(MAINTAINER_CHANGE_WINDOW_DAYS);
    if latest_time < cutoff {
        return None;
    }

    let mut new_sorted: Vec<String> = new_maintainers.into_iter().cloned().collect();
    new_sorted.sort();
    let mut first_sorted: Vec<String> = first_maintainers.into_iter().collect();
    first_sorted.sort();
    let mut latest_sorted: Vec<String> = latest_maintainers.into_iter().collect();
    latest_sorted.sort();

    let mut f = Map::new();
    f.insert("severity".into(), Value::String("SUSPECT".into()));
    f.insert(
        "message".into(),
        Value::String(format!(
            "New maintainer(s) appeared in latest version '{}': {}",
            latest_version,
            new_sorted.join(", ")
        )),
    );
    f.insert(
        "first_maintainers".into(),
        Value::Array(first_sorted.into_iter().map(Value::String).collect()),
    );
    f.insert(
        "latest_maintainers".into(),
        Value::Array(latest_sorted.into_iter().map(Value::String).collect()),
    );
    f.insert(
        "new_maintainers".into(),
        Value::Array(new_sorted.into_iter().map(Value::String).collect()),
    );
    f.insert(
        "latest_version".into(),
        Value::String(latest_version.to_string()),
    );
    Some(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn iso(dt: DateTime<Utc>) -> String {
        dt.to_rfc3339()
    }

    #[test]
    fn new_maintainer_recent_is_suspect() {
        let now = iso(Utc::now());
        let old = iso(Utc::now() - chrono::Duration::days(400));
        let info = json!({
            "time": { "1.0.0": old, "2.0.0": now },
            "versions": {
                "1.0.0": { "maintainers": [{ "name": "alice" }] },
                "2.0.0": { "maintainers": [{ "name": "alice" }, { "name": "mallory" }] }
            }
        });
        let f = check_maintainer_change(&info).unwrap();
        assert_eq!(f.get("severity").and_then(|v| v.as_str()), Some("SUSPECT"));
        assert!(f.get("message").unwrap().as_str().unwrap().contains("mallory"));
    }

    #[test]
    fn unchanged_maintainers_is_none() {
        let now = iso(Utc::now());
        let old = iso(Utc::now() - chrono::Duration::days(400));
        let info = json!({
            "time": { "1.0.0": old, "2.0.0": now },
            "versions": {
                "1.0.0": { "maintainers": [{ "name": "alice" }] },
                "2.0.0": { "maintainers": [{ "name": "alice" }] }
            }
        });
        assert!(check_maintainer_change(&info).is_none());
    }

    #[test]
    fn change_outside_window_is_none() {
        let old1 = iso(Utc::now() - chrono::Duration::days(400));
        let old2 = iso(Utc::now() - chrono::Duration::days(200));
        let info = json!({
            "time": { "1.0.0": old1, "2.0.0": old2 },
            "versions": {
                "1.0.0": { "maintainers": [{ "name": "alice" }] },
                "2.0.0": { "maintainers": [{ "name": "alice" }, { "name": "mallory" }] }
            }
        });
        assert!(check_maintainer_change(&info).is_none());
    }

    #[test]
    fn single_version_is_none() {
        let info = json!({
            "time": { "1.0.0": iso(Utc::now()) },
            "versions": { "1.0.0": { "maintainers": [{ "name": "alice" }] } }
        });
        assert!(check_maintainer_change(&info).is_none());
    }
}
