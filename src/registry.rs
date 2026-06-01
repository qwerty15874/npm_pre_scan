use reqwest::blocking::Client;
use serde_json::Value;

const REGISTRY_BASE: &str = "https://registry.npmjs.org";
const DOWNLOADS_BASE: &str = "https://api.npmjs.org/downloads/point";

/// URL-encode a package name: `@` → `%40`, `/` → `%2F`
fn encode_name(name: &str) -> String {
    name.replace('@', "%40").replace('/', "%2F")
}

fn make_client() -> Option<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("npm-pre-scan/0.1")
        .build()
        .ok()
}

/// Fetch full package metadata from the npm registry.
/// Returns `None` on 404 or any network/parse error.
pub fn get_package_info(name: &str) -> Option<Value> {
    let client = make_client()?;
    let url = format!("{}/{}", REGISTRY_BASE, encode_name(name));
    let resp = client.get(&url).send().ok()?;
    if resp.status().as_u16() == 404 {
        return None;
    }
    if !resp.status().is_success() {
        return None;
    }
    resp.json().ok()
}

/// Fetch download count for a package over a given period (e.g. "last-week", "last-month").
/// Returns `None` on any error.
pub fn get_downloads(name: &str, period: &str) -> Option<u64> {
    let client = make_client()?;
    let url = format!("{}/{}/{}", DOWNLOADS_BASE, period, encode_name(name));
    let resp = client.get(&url).send().ok()?;
    if resp.status().as_u16() == 404 {
        return None;
    }
    if !resp.status().is_success() {
        return None;
    }
    let data: Value = resp.json().ok()?;
    data.get("downloads")?.as_u64()
}

/// Fetch the npm registry's public signing keys.
/// GET https://registry.npmjs.org/-/npm/v1/keys → returns the `keys` array.
/// Best-effort: `None` on any network/parse error.
pub fn get_registry_keys() -> Option<Vec<Value>> {
    let client = make_client()?;
    let url = format!("{}/-/npm/v1/keys", REGISTRY_BASE);
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let data: Value = resp.json().ok()?;
    data.get("keys")?.as_array().cloned()
}

/// Parse the `time.created` field from package info and return age in days.
/// Returns `None` if the field is missing or unparseable.
pub fn get_package_age_days(info: &Value) -> Option<f64> {
    let created_str = info.get("time")?.get("created")?.as_str()?;
    // Replace trailing Z with +00:00 for RFC3339 parsing
    let normalized = created_str.replace('Z', "+00:00");
    let created = chrono::DateTime::parse_from_rfc3339(&normalized).ok()?;
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(created);
    Some(duration.num_seconds() as f64 / 86400.0)
}
