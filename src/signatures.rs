use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde_json::{Map, Value};

use crate::models::Finding;
use crate::registry::get_registry_keys;

// Registry-signature verification has no clean Ladisa taxonomy vector — it's
// a heuristic/metadata signal (npm's own signing infrastructure), not a
// distinct attack vector — so every finding here is tagged "META".
fn finding(severity: &str, message: &str) -> Finding {
    let mut m = Map::new();
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("vector".into(), Value::String("META".into()));
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
/// - signature verifies under an unexpired key → `None` (clean; no score noise)
/// - signature verifies under an **expired** key → INFO (see below)
/// - signature present and verification **fails** → BLOCK (genuine tampering signal)
/// - no key in the registry key set matches the signature's keyid → SUSPECT
///   (unverifiable, which is not the same as tampered)
/// - `dist.signatures` missing → SUSPECT (version not signed)
/// - no SRI integrity → `None` (nothing to verify against; best-effort, never false-BLOCK)
/// - registry keys unfetchable (network/parse error) → INFO note ("signature
///   verification skipped — registry keys unavailable"). This is deliberately
///   NOT `None`: a silent `None` here is indistinguishable from "verified
///   clean", so a genuinely unsigned/tampered package would look identical to
///   a properly signed one whenever the keys endpoint has a transient failure.
///   INFO does not affect the aggregate verdict (never false-BLOCK/SUSPECT)
///   but is visible in findings/score.
///
/// ## Why expiry is INFO and not BLOCK (v18 — measured defect, fixed)
///
/// npm rotated its registry signing key; the old key
/// `SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA` expired 2025-01-29.
/// This function used to select the verifying key with
/// `keyid matches && !key_expired(k)`, so for any package not republished since
/// the rotation the lookup found nothing, skipped every signature, and returned
/// an unconditional BLOCK — **without ever checking the signature**.
///
/// v17 measured the cost: 11 of 27 legitimate popular packages BLOCK'd
/// (`ms`, `mysql`, `d3`, `ffmpeg`, `http-proxy`, `node-sass`, `grunt-cli`,
/// `babel-cli`, `escape-string-regexp`, `shadowsocks`, `sqlite`), 11 of the 12
/// BLOCK-level false positives in the whole arm, and worsening with time as more
/// keys age out. It also fabricated recall: 23 of arm B's 32 "true positives"
/// were this check firing on npm's own security-holding stubs.
///
/// An expired key is not evidence of tampering — it means the signature was made
/// before a rotation, which is the normal state of any package that has not been
/// republished. `npm audit signatures` does not reject on a rotated key either.
/// So: verify against the key that **actually signed**, and reserve BLOCK for a
/// signature that verifies and *fails*.
pub fn check_signatures(package_name: &str, info: &Value) -> Option<Finding> {
    let version = latest_version(info)?;
    let dist = info.get("versions")?.get(&version)?.get("dist")?;

    let integrity = dist.get("integrity").and_then(|v| v.as_str())?;

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

    let keys = match get_registry_keys() {
        Some(k) => k,
        None => {
            return Some(finding(
                "INFO",
                "Signature verification skipped — registry keys unavailable (network or parse error)",
            ));
        }
    };

    verify_against_keys(package_name, &version, integrity, signatures, &keys)
}

/// The verification core, split out from [`check_signatures`] so the key set can
/// be injected. `check_signatures` fetches the keys over the network, which makes
/// the severity ladder — the part that was actually wrong — untestable offline.
/// Same wrapper-plus-core shape as `report::run_full_registry_with_lists`.
pub(crate) fn verify_against_keys(
    package_name: &str,
    version: &str,
    integrity: &str,
    signatures: &[Value],
    keys: &[Value],
) -> Option<Finding> {
    let payload = format!("{}@{}:{}", package_name, version, integrity);

    for sig_entry in signatures {
        let keyid = sig_entry.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
        let sig_b64 = sig_entry.get("sig").and_then(|v| v.as_str()).unwrap_or("");

        // Look up the key that ACTUALLY SIGNED this entry, expired or not. The
        // expiry check deliberately does NOT gate this lookup — see the function
        // doc comment. Filtering here is what produced the v17 time bomb.
        let key = keys
            .iter()
            .find(|k| k.get("keyid").and_then(|v| v.as_str()) == Some(keyid));
        let key = match key {
            Some(k) => k,
            None => continue,
        };
        let expired = key_expired(key);

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
            if expired {
                // The signature is genuine; the key it was made with has since
                // been rotated out. Informational, never a verdict.
                Some(finding(
                    "INFO",
                    &format!(
                        "Registry signature on {}@{} verifies against an expired-but-valid \
                         signing key ({}) — the package predates a key rotation, which is \
                         not evidence of tampering",
                        package_name, version, keyid
                    ),
                ))
            } else {
                None
            }
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

    // Every signature entry either names a keyid the registry does not publish,
    // or carries a key/signature we could not decode. That is unverifiable, not
    // tampered — SUSPECT, not BLOCK.
    Some(finding(
        "SUSPECT",
        &format!(
            "Could not verify registry signature on {}@{} — no published registry key \
             matches the signature's keyid",
            package_name, version
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;
    use serde_json::json;

    // ── Pinning tests for the expired-key ladder (v18) ─────────────────────────
    //
    // The v17 defect was silent and time-dependent: `check_signatures` filtered
    // expired keys out of the lookup, never verified anything, and returned an
    // unconditional BLOCK. Nothing failed — the tool just started blocking more
    // packages every month. These tests pin the distinction so it cannot regress
    // back, and they use REAL ECDSA-P256 material so the verification itself is
    // exercised rather than mocked.

    /// Deterministic (RFC6979) signing key from fixed bytes — no RNG, so the
    /// whole suite stays byte-reproducible and network-free.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32].into()).expect("valid P-256 scalar")
    }

    /// The registry's key-set entry shape: `{keyid, keytype, scheme, key, expires}`.
    fn registry_key(keyid: &str, expires: Value) -> Value {
        let der = signing_key()
            .verifying_key()
            .to_public_key_der()
            .expect("DER encode");
        json!({
            "keyid": keyid,
            "keytype": "ecdsa-sha2-nistp256",
            "scheme": "ecdsa-sha2-nistp256",
            "key": base64::engine::general_purpose::STANDARD.encode(der.as_bytes()),
            "expires": expires,
        })
    }

    /// A signature entry over the registry's canonical `name@version:integrity`.
    fn signature_entry(keyid: &str, package: &str, version: &str, integrity: &str) -> Value {
        let payload = format!("{}@{}:{}", package, version, integrity);
        let sig: p256::ecdsa::Signature = signing_key().sign(payload.as_bytes());
        json!({
            "keyid": keyid,
            "sig": base64::engine::general_purpose::STANDARD.encode(sig.to_der().as_bytes()),
        })
    }

    const INTEGRITY: &str = "sha512-deadbeef";

    fn severity_of(f: &Option<Finding>) -> Option<&str> {
        f.as_ref()?.get("severity")?.as_str()
    }

    #[test]
    fn valid_signature_under_unexpired_key_is_clean() {
        let keys = vec![registry_key("k1", json!(null))];
        let sigs = vec![signature_entry("k1", "pkg", "1.0.0", INTEGRITY)];
        let out = verify_against_keys("pkg", "1.0.0", INTEGRITY, &sigs, &keys);
        assert!(out.is_none(), "expected no finding, got {out:?}");
    }

    /// THE REGRESSION TEST. npm's old key expired 2025-01-29; every package not
    /// republished since is still signed with it. That must be INFO, never BLOCK
    /// — it accounted for 11 of the 12 BLOCK-level false positives in arm F.
    #[test]
    fn valid_signature_under_expired_key_is_info_not_block() {
        let keys = vec![registry_key("k1", json!("2025-01-29T00:00:00.000Z"))];
        let sigs = vec![signature_entry("k1", "pkg", "1.0.0", INTEGRITY)];
        let out = verify_against_keys("pkg", "1.0.0", INTEGRITY, &sigs, &keys);
        assert_eq!(
            severity_of(&out),
            Some("INFO"),
            "a genuine signature made before a key rotation is not tampering; got {out:?}"
        );
    }

    /// The signal BLOCK is actually for: the signature does not verify.
    #[test]
    fn signature_that_fails_verification_blocks() {
        let keys = vec![registry_key("k1", json!(null))];
        // Signed over a DIFFERENT integrity than the one we verify against —
        // i.e. the tarball changed after signing.
        let sigs = vec![signature_entry("k1", "pkg", "1.0.0", "sha512-somethingelse")];
        let out = verify_against_keys("pkg", "1.0.0", INTEGRITY, &sigs, &keys);
        assert_eq!(severity_of(&out), Some("BLOCK"), "got {out:?}");
    }

    /// Tampering is still caught when the signing key has ALSO expired — expiry
    /// must soften the clean path, not the failure path.
    #[test]
    fn failed_verification_still_blocks_even_when_key_expired() {
        let keys = vec![registry_key("k1", json!("2025-01-29T00:00:00.000Z"))];
        let sigs = vec![signature_entry("k1", "pkg", "1.0.0", "sha512-somethingelse")];
        let out = verify_against_keys("pkg", "1.0.0", INTEGRITY, &sigs, &keys);
        assert_eq!(severity_of(&out), Some("BLOCK"), "got {out:?}");
    }

    /// A keyid the registry does not publish is unverifiable, not tampered.
    #[test]
    fn unknown_keyid_is_suspect_not_block() {
        let keys = vec![registry_key("k1", json!(null))];
        let sigs = vec![signature_entry("unpublished-keyid", "pkg", "1.0.0", INTEGRITY)];
        let out = verify_against_keys("pkg", "1.0.0", INTEGRITY, &sigs, &keys);
        assert_eq!(severity_of(&out), Some("SUSPECT"), "got {out:?}");
    }

    /// The exact v17 shape: the signing key is expired AND an unexpired
    /// replacement key exists (npm's rotation). The old behaviour skipped the
    /// expired key, matched nothing, and BLOCK'd.
    #[test]
    fn rotated_key_set_does_not_block_a_package_signed_before_rotation() {
        let keys = vec![
            registry_key("old-key", json!("2025-01-29T00:00:00.000Z")),
            registry_key("new-key", json!(null)),
        ];
        let sigs = vec![signature_entry("old-key", "ms", "2.1.3", INTEGRITY)];
        let out = verify_against_keys("ms", "2.1.3", INTEGRITY, &sigs, &keys);
        assert_ne!(
            severity_of(&out),
            Some("BLOCK"),
            "this is the v17 time bomb — a package predating npm's key rotation \
             must not be BLOCK'd; got {out:?}"
        );
        assert_eq!(severity_of(&out), Some("INFO"));
    }

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
        assert_eq!(f.get("vector").and_then(|v| v.as_str()), Some("META"));
    }

    #[test]
    fn no_integrity_is_skipped() {
        let info = json!({
            "dist-tags": { "latest": "1.0.0" },
            "versions": { "1.0.0": { "dist": {} } }
        });
        assert!(check_signatures("pkg", &info).is_none());
    }

    #[test]
    fn key_expiry() {
        let past = json!({ "expires": "2000-01-01T00:00:00.000Z" });
        let future = json!({ "expires": "2999-01-01T00:00:00.000Z" });
        let null = json!({ "expires": null });
        let missing = json!({});
        assert!(key_expired(&past));
        assert!(!key_expired(&future));
        assert!(!key_expired(&null));
        assert!(!key_expired(&missing));
    }

    #[test]
    fn latest_version_prefers_dist_tag() {
        let info = json!({
            "dist-tags": { "latest": "2.0.0" },
            "versions": { "1.0.0": {}, "2.0.0": {} }
        });
        assert_eq!(latest_version(&info).as_deref(), Some("2.0.0"));
    }

    #[test]
    fn latest_version_falls_back_to_time_sort() {
        let info = json!({
            "time": { "1.0.0": "2020-01-01T00:00:00Z", "1.5.0": "2022-01-01T00:00:00Z" },
            "versions": { "1.0.0": {}, "1.5.0": {} }
        });
        assert_eq!(latest_version(&info).as_deref(), Some("1.5.0"));
    }
}
