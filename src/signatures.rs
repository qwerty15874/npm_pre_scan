use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde_json::{Map, Value};

use crate::models::Finding;
use crate::registry::get_registry_keys;

fn finding(severity: &str, message: &str) -> Finding {
    let mut m = Map::new();
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("message".into(), Value::String(message.to_string()));
    m
}

/// Resolve the latest version: prefer `dist-tags.latest`, else the time-sorted last version.
fn latest_version(info: &Value) -> Option<String> {
    if let Some(v) = info
        .get("dist-tags")
        .and_then(|t| t.get("latest"))
        .and_then(|v| v.as_str())
    {
        return Some(v.to_string());
    }
    let versions = info.get("versions")?.as_object()?;
    let time = info.get("time");
    let mut keys: Vec<&String> = versions.keys().collect();
    keys.sort_by(|a, b| {
        let ta = time.and_then(|t| t.get(*a)).and_then(|v| v.as_str()).unwrap_or("");
        let tb = time.and_then(|t| t.get(*b)).and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });
    keys.last().map(|s| s.to_string())
}

/// A registry key is expired if its `expires` (ISO-8601) is in the past.
/// `null`/missing/unparseable → treated as not expired.
fn key_expired(key: &Value) -> bool {
    match key.get("expires").and_then(|v| v.as_str()) {
        None => false,
        Some(exp) => {
            let normalized = exp.replace('Z', "+00:00");
            match chrono::DateTime::parse_from_rfc3339(&normalized) {
                Ok(dt) => dt < chrono::Utc::now(),
                Err(_) => false,
            }
        }
    }
}

/// Verify the npm registry's ECDSA-P256 signature on the latest published version
/// (equivalent to `npm audit signatures`).
///
/// - valid signature → `None` (clean; no score noise)
/// - `dist.signatures` missing → SUSPECT (version not signed)
/// - present-but-invalid, or no valid/unexpired key → BLOCK (possible tampering)
/// - no SRI integrity, or registry keys unfetchable → `None` (best-effort; never false-BLOCK)
pub fn check_signatures(package_name: &str, info: &Value) -> Option<Finding> {
    let version = latest_version(info)?;
    let dist = info.get("versions")?.get(&version)?.get("dist")?;

    let integrity = match dist.get("integrity").and_then(|v| v.as_str()) {
        Some(i) => i,
        None => return None,
    };

    let signatures = match dist.get("signatures").and_then(|v| v.as_array()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return Some(finding(
                "SUSPECT",
                &format!(
                    "Package version {}@{} is not signed by the registry",
                    package_name, version
                ),
            ));
        }
    };

    let keys = get_registry_keys()?;
    let payload = format!("{}@{}:{}", package_name, version, integrity);

    for sig_entry in signatures {
        let keyid = sig_entry.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
        let sig_b64 = sig_entry.get("sig").and_then(|v| v.as_str()).unwrap_or("");

        let key = keys.iter().find(|k| {
            k.get("keyid").and_then(|v| v.as_str()) == Some(keyid) && !key_expired(k)
        });
        let key = match key {
            Some(k) => k,
            None => continue,
        };

        let key_b64 = key.get("key").and_then(|v| v.as_str()).unwrap_or("");
        let der = match base64::engine::general_purpose::STANDARD.decode(key_b64) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let verifying_key = match VerifyingKey::from_public_key_der(&der) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(sig_b64) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let signature = match Signature::from_der(&sig_bytes)
            .or_else(|_| Signature::from_slice(&sig_bytes))
        {
            Ok(s) => s,
            Err(_) => continue,
        };

        return if verifying_key.verify(payload.as_bytes(), &signature).is_ok() {
            None
        } else {
            Some(finding(
                "BLOCK",
                &format!(
                    "Invalid registry signature on {}@{} — possible tampering",
                    package_name, version
                ),
            ))
        };
    }

    Some(finding(
        "BLOCK",
        &format!(
            "Could not verify registry signature on {}@{} (no valid/unexpired signing key)",
            package_name, version
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unsigned_version_is_suspect() {
        let info = json!({
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": { "dist": { "integrity": "sha512-abc" } }
            }
        });
        let f = check_signatures("pkg", &info).expect("expected a finding");
        assert_eq!(f.get("severity").and_then(|v| v.as_str()), Some("SUSPECT"));
    }

    #[test]
    fn no_integrity_is_skipped() {
        let info = json!({
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "dist": {} } }
        });
        assert!(check_signatures("pkg", &info).is_none());
    }
}
