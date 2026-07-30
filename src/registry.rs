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

/// Why a metadata fetch produced (or failed to produce) a document.
///
/// `get_package_info` collapses every failure mode to `None`, which is fine for
/// a scan — either way there is no metadata to check — but not for measurement:
/// a transient timeout that looks identical to a 404 silently becomes "this
/// package was removed", and any recall figure computed over such a run is
/// wrong. `fetch_package_info` keeps the two apart so the evaluation harness can
/// exclude genuine failures instead of scoring them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchStatus {
    Found,
    /// The registry answered 404 — the package really is not there.
    NotFound,
    /// The request could not be completed: network error, non-404 error status,
    /// or a body that would not parse. Carries a short reason for the record.
    Failed(String),
}

impl FetchStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FetchStatus::Found => "found",
            FetchStatus::NotFound => "not_found",
            FetchStatus::Failed(_) => "failed",
        }
    }
}

/// Fetch full package metadata, reporting *why* it failed.
///
/// The `Option` is `Some` only for `Found`, so callers that do not care about the
/// distinction can keep using `get_package_info`.
pub fn fetch_package_info(name: &str) -> (FetchStatus, Option<Value>) {
    let client = match make_client() {
        Some(c) => c,
        None => return (FetchStatus::Failed("could not build HTTP client".into()), None),
    };
    let url = format!("{}/{}", REGISTRY_BASE, encode_name(name));
    let resp = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            let reason = if e.is_timeout() {
                "request timed out".to_string()
            } else {
                format!("request failed: {}", e)
            };
            return (FetchStatus::Failed(reason), None);
        }
    };
    let status = resp.status();
    if status.as_u16() == 404 {
        return (FetchStatus::NotFound, None);
    }
    if !status.is_success() {
        return (
            FetchStatus::Failed(format!("http {}", status.as_u16())),
            None,
        );
    }
    match resp.json() {
        Ok(v) => (FetchStatus::Found, Some(v)),
        Err(e) => (FetchStatus::Failed(format!("parse failed: {}", e)), None),
    }
}

/// Fetch full package metadata from the npm registry.
/// Returns `None` on 404 or any network/parse error.
pub fn get_package_info(name: &str) -> Option<Value> {
    fetch_package_info(name).1
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

/// Fetch one page of the npm registry search API for a given seed text.
/// `GET {REGISTRY_BASE}/-/v1/search?text=<seed>&popularity=1.0&quality=0.0&maintenance=0.0&size=<size>`.
/// Returns the raw response body (parsing happens in `toplist.rs`, so it can
/// be exercised against a recorded fixture without a network round-trip).
/// `None` on any network/HTTP error — never panics.
pub(crate) fn fetch_search_page(seed: &str, size: usize) -> Option<String> {
    let client = make_client()?;
    let url = format!(
        "{}/-/v1/search?text={}&popularity=1.0&quality=0.0&maintenance=0.0&size={}",
        REGISTRY_BASE, seed, size
    );
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.text().ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    // No test here constructs a `Client` or touches the network — the same
    // convention the rest of this module and `toplist.rs` follow.

    #[test]
    fn encode_name_escapes_scope_separators() {
        assert_eq!(encode_name("lodash"), "lodash");
        assert_eq!(encode_name("@aws-sdk/client-s3"), "%40aws-sdk%2Fclient-s3");
    }

    #[test]
    fn fetch_status_labels_are_stable() {
        // These strings land in results.csv, so they are part of the output
        // contract rather than incidental debug text.
        assert_eq!(FetchStatus::Found.as_str(), "found");
        assert_eq!(FetchStatus::NotFound.as_str(), "not_found");
        assert_eq!(FetchStatus::Failed("http 503".into()).as_str(), "failed");
    }

    #[test]
    fn fetch_status_distinguishes_absence_from_failure() {
        // The whole point of the enum: these two must never compare equal, or a
        // timeout would be scored as "the package was removed".
        assert_ne!(FetchStatus::NotFound, FetchStatus::Failed("timeout".into()));
        assert_ne!(FetchStatus::Found, FetchStatus::NotFound);
        // The reason is preserved for the record.
        match FetchStatus::Failed("http 503".into()) {
            FetchStatus::Failed(reason) => assert_eq!(reason, "http 503"),
            other => panic!("expected Failed, got {:?}", other),
        }
    }
}
