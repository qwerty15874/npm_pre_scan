use serde_json::{Map, Value};

use crate::registry::{get_downloads, get_package_age_days};

const NEW_PACKAGE_DAYS: f64 = 7.0;
const DOWNLOAD_SPIKE_RATIO: f64 = 5.0;
const DOWNLOAD_SPIKE_MIN: u64 = 1000;

/// Check if a new package has an unusual download spike.
/// Returns a Finding map or `None` if no concern detected.
pub fn check_age_and_downloads(name: &str, info: &Value) -> Option<Map<String, Value>> {
    let age_days = get_package_age_days(info)?;

    if age_days >= NEW_PACKAGE_DAYS {
        return None;
    }

    // New package — check for download spike
    let weekly = get_downloads(name, "last-week");
    let monthly = get_downloads(name, "last-month");

    let age_rounded = (age_days * 10.0).round() / 10.0;

    let mut base = Map::new();
    base.insert(
        "age_days".into(),
        Value::Number(
            serde_json::Number::from_f64(age_rounded).unwrap_or(serde_json::Number::from(0)),
        ),
    );
    base.insert(
        "weekly_downloads".into(),
        match weekly {
            Some(n) => Value::Number(n.into()),
            None => Value::Null,
        },
    );
    base.insert(
        "monthly_downloads".into(),
        match monthly {
            Some(n) => Value::Number(n.into()),
            None => Value::Null,
        },
    );

    if let (Some(w), Some(m)) = (weekly, monthly) {
        if m > 0 {
            let expected_weekly = m as f64 / 4.0;
            if w >= DOWNLOAD_SPIKE_MIN && (w as f64) / expected_weekly >= DOWNLOAD_SPIKE_RATIO {
                base.insert("severity".into(), Value::String("SUSPECT".into()));
                base.insert(
                    "message".into(),
                    Value::String(format!(
                        "Package is {} days old with unusual download spike ({} weekly vs ~{} expected)",
                        age_rounded, w, expected_weekly as u64
                    )),
                );
                return Some(base);
            }
        }
    }

    // Still new but no spike — INFO
    base.insert("severity".into(), Value::String("INFO".into()));
    base.insert(
        "message".into(),
        Value::String(format!("Package is very new ({} days old)", age_rounded)),
    );
    Some(base)
}
