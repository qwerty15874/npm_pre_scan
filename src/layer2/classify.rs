// Layer 2: classification of a Layer2Profile into Findings.
// Pure function — no I/O, no Docker required. Unit-testable with fixture profiles.

use serde_json::{Map, Value};

use super::profile::Layer2Profile;

type Finding = Map<String, Value>;

fn finding(check: &str, severity: &str, message: &str, phase: &str, vector: &str) -> Finding {
    let mut m = Map::new();
    m.insert("check".into(), Value::String(check.to_string()));
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("message".into(), Value::String(message.to_string()));
    m.insert("phase".into(), Value::String(phase.to_string()));
    m.insert("vector".into(), Value::String(vector.to_string()));
    m
}

/// Worm egress destinations (E1) — any DNS query or connect to these signals BLOCK.
const WORM_EGRESS_HOSTNAMES: &[&str] = &[
    "registry.npmjs.org",
    "api.github.com",
    "webhook.site",
];
const WORM_EGRESS_IP: &str = "169.254.169.254";

/// Sensitive file paths that indicate credential/config theft.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/.ssh/",
    ".npmrc",
    ".aws/credentials",
    ".git-credentials",
];

/// DNS tunneling thresholds.
/// High distinct-qname count is suspicious; very high or long-label is BLOCK.
const DNS_TUNNEL_SUSPECT_COUNT: usize = 10;
const DNS_TUNNEL_BLOCK_COUNT: usize = 30;
/// Labels longer than this threshold (in chars) suggest data encoding.
const DNS_LABEL_LONG: usize = 20;

/// Classify a `Layer2Profile` into a list of Findings following the Layer 2 detection rules.
///
/// Rules:
///   E1 worm egress  — DNS / connect to registry.npmjs.org, api.github.com, webhook.site, 169.254.169.254 → BLOCK
///   B1 install script (child process during install phase + network/sensitive file)                       → SUSPECT / BLOCK
///   sensitive file read (/etc/passwd, /etc/shadow, ~/.ssh, .npmrc, .aws/credentials, .git-credentials)   → BLOCK
///   C1 import-time side effects (net / process spawn / file-write during import phase)                    → SUSPECT / BLOCK
///   C2 DNS tunneling (many distinct qnames, or long encoded labels, or many TXT)                          → SUSPECT / BLOCK
///   C3 hidden native binary (.node opened at import)                                                      → SUSPECT
pub fn classify(profile: &Layer2Profile) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let phase = profile.phase.as_str();

    // ── E1: worm egress ──────────────────────────────────────────────────────
    for qname in &profile.dns_queries {
        let lower = qname.to_lowercase();
        for &ioc in WORM_EGRESS_HOSTNAMES {
            if lower == ioc || lower.ends_with(&format!(".{}", ioc)) {
                let mut f = finding(
                    "worm_egress",
                    "BLOCK",
                    &format!("Worm egress DNS query detected: {}", qname),
                    phase,
                    "E1",
                );
                f.insert("destination".into(), Value::String(qname.clone()));
                findings.push(f);
            }
        }
    }
    for (ip, port) in &profile.connects {
        if ip == WORM_EGRESS_IP {
            let mut f = finding(
                "worm_egress",
                "BLOCK",
                &format!("Worm egress connect to cloud IMDS: {}:{}", ip, port),
                phase,
                "E1",
            );
            f.insert("destination".into(), Value::String(format!("{}:{}", ip, port)));
            findings.push(f);
        }
    }

    // ── Sensitive file read ──────────────────────────────────────────────────
    for path in &profile.file_opens {
        if is_sensitive_path(path) {
            let mut f = finding(
                "sensitive_file_read",
                "BLOCK",
                &format!("Sensitive file opened: {}", path),
                phase,
                "B1",
            );
            f.insert("path".into(), Value::String(path.clone()));
            findings.push(f);
        }
    }

    // ── B1: install-phase child process ──────────────────────────────────────
    if phase == "install" && !profile.processes.is_empty() {
        // Skip the top-level npm/node invocations — only flag unexpected extra processes
        let unexpected: Vec<&String> = profile
            .processes
            .iter()
            .filter(|p| !is_expected_npm_process(p))
            .collect();
        if !unexpected.is_empty() {
            // Escalate to BLOCK if the process also made network connections or read sensitive files
            let has_network = !profile.connects.is_empty() || !profile.dns_queries.is_empty();
            let has_sensitive = profile.file_opens.iter().any(|p| is_sensitive_path(p));
            let severity = if has_network || has_sensitive {
                "BLOCK"
            } else {
                "SUSPECT"
            };
            let mut f = finding(
                "install_script_exec",
                severity,
                &format!(
                    "Install phase spawned unexpected child process(es): {}",
                    unexpected
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                phase,
                "B1",
            );
            f.insert(
                "processes".into(),
                Value::Array(
                    unexpected
                        .into_iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                ),
            );
            findings.push(f);
        }
    }

    // ── C1: import-phase side effects ─────────────────────────────────────────
    if phase == "import" {
        let has_network = !profile.connects.is_empty() || !profile.dns_queries.is_empty();
        // Only flag unexpected processes (filter out the top-level node runner itself)
        let unexpected_import: Vec<&String> = profile
            .processes
            .iter()
            .filter(|p| !is_expected_npm_process(p))
            .collect();
        let has_process = !unexpected_import.is_empty();
        let has_sensitive = profile.file_opens.iter().any(|p| is_sensitive_path(p));

        if has_network || has_process || has_sensitive {
            let severity = if has_sensitive { "BLOCK" } else { "SUSPECT" };
            let details = [
                if has_network { Some("network activity") } else { None },
                if has_process { Some("child process spawned") } else { None },
                if has_sensitive { Some("sensitive file read") } else { None },
            ]
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
            findings.push(finding(
                "import_side_effect",
                severity,
                &format!("Import-phase side effect detected: {}", details),
                phase,
                "C1",
            ));
        }
    }

    // ── C2: DNS tunneling ────────────────────────────────────────────────────
    if !profile.dns_queries.is_empty() {
        let distinct: std::collections::HashSet<&String> =
            profile.dns_queries.iter().collect();
        let count = distinct.len();

        // Check for long base32/hex-looking labels (data encoding)
        let has_encoded_label = profile.dns_queries.iter().any(|q| {
            q.split('.').any(|label| {
                label.len() > DNS_LABEL_LONG
                    && label
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            })
        });

        if count >= DNS_TUNNEL_BLOCK_COUNT || (count >= DNS_TUNNEL_SUSPECT_COUNT && has_encoded_label) {
            let mut f = finding(
                "dns_tunneling",
                "BLOCK",
                &format!(
                    "DNS tunneling detected: {} distinct queries{}",
                    count,
                    if has_encoded_label { " with encoded labels" } else { "" }
                ),
                phase,
                "C2",
            );
            f.insert("distinct_query_count".into(), Value::Number(count.into()));
            findings.push(f);
        } else if count >= DNS_TUNNEL_SUSPECT_COUNT || has_encoded_label {
            let mut f = finding(
                "dns_tunneling",
                "SUSPECT",
                &format!(
                    "Possible DNS tunneling: {} distinct queries{}",
                    count,
                    if has_encoded_label { " with encoded labels" } else { "" }
                ),
                phase,
                "C2",
            );
            f.insert("distinct_query_count".into(), Value::Number(count.into()));
            findings.push(f);
        }
    }

    // ── C3: hidden native binary (.node loaded at import) ────────────────────
    if !profile.native_modules.is_empty() {
        let mut f = finding(
            "native_addon",
            "SUSPECT",
            &format!(
                "Native addon loaded: {}",
                profile.native_modules.join(", ")
            ),
            phase,
            "C3",
        );
        f.insert(
            "modules".into(),
            Value::Array(
                profile
                    .native_modules
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        findings.push(f);
    }

    findings
}

/// Return true if `path` matches any known-sensitive file pattern.
fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS
        .iter()
        .any(|&pattern| path.contains(pattern))
}

/// Return true for top-level npm/node processes that are expected during `npm install`.
fn is_expected_npm_process(cmd: &str) -> bool {
    let basename = cmd.rsplit('/').next().unwrap_or(cmd);
    matches!(
        basename,
        "npm" | "npm-cli.js" | "node" | "npx" | "sh" | "bash" | "dash"
    )
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(f: &Finding) -> &str {
        f.get("severity").and_then(|v| v.as_str()).unwrap_or("")
    }
    fn check(f: &Finding) -> &str {
        f.get("check").and_then(|v| v.as_str()).unwrap_or("")
    }
    fn vector(f: &Finding) -> &str {
        f.get("vector").and_then(|v| v.as_str()).unwrap_or("")
    }

    fn profile_with_phase(phase: &str) -> Layer2Profile {
        Layer2Profile {
            phase: phase.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn e1_worm_dns_blocks() {
        let mut p = profile_with_phase("install");
        p.dns_queries.push("api.github.com".to_string());
        let f = classify(&p);
        assert!(f.iter().any(|f| sev(f) == "BLOCK" && check(f) == "worm_egress"));
    }

    #[test]
    fn e1_worm_connect_imds_blocks() {
        let mut p = profile_with_phase("import");
        p.connects.push(("169.254.169.254".to_string(), 80));
        let f = classify(&p);
        assert!(f.iter().any(|f| sev(f) == "BLOCK" && check(f) == "worm_egress"));
    }

    #[test]
    fn sensitive_file_blocks() {
        let mut p = profile_with_phase("install");
        p.file_opens.push("/etc/passwd".to_string());
        let f = classify(&p);
        assert!(f.iter().any(|f| sev(f) == "BLOCK" && check(f) == "sensitive_file_read"));
    }

    #[test]
    fn b1_install_child_process_suspect() {
        let mut p = profile_with_phase("install");
        p.processes.push("/usr/bin/curl".to_string());
        let f = classify(&p);
        assert!(f.iter().any(|f| check(f) == "install_script_exec" && vector(f) == "B1"));
    }

    #[test]
    fn b1_install_child_process_with_network_blocks() {
        let mut p = profile_with_phase("install");
        p.processes.push("/usr/bin/curl".to_string());
        p.connects.push(("1.2.3.4".to_string(), 443));
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "install_script_exec" && sev(f) == "BLOCK"));
    }

    #[test]
    fn c1_import_side_effect_suspect() {
        let mut p = profile_with_phase("import");
        p.connects.push(("5.6.7.8".to_string(), 80));
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "import_side_effect" && sev(f) == "SUSPECT"));
    }

    #[test]
    fn c1_import_side_effect_sensitive_blocks() {
        let mut p = profile_with_phase("import");
        p.file_opens.push("/etc/shadow".to_string());
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "import_side_effect" && sev(f) == "BLOCK"));
    }

    #[test]
    fn c2_dns_tunneling_many_queries_suspect() {
        let mut p = profile_with_phase("import");
        for i in 0..15 {
            p.dns_queries.push(format!("sub{}.example.com", i));
        }
        let f = classify(&p);
        assert!(f.iter().any(|f| check(f) == "dns_tunneling"));
    }

    #[test]
    fn c2_dns_tunneling_encoded_labels_suspect() {
        let mut p = profile_with_phase("import");
        p.dns_queries
            .push("aGVsbG8gd29ybGQgZm9vYmFy.exfil.c2.io".to_string());
        let f = classify(&p);
        assert!(f.iter().any(|f| check(f) == "dns_tunneling" && vector(f) == "C2"));
    }

    #[test]
    fn c3_native_addon_suspect() {
        let mut p = profile_with_phase("import");
        p.native_modules.push("/pkg/build/addon.node".to_string());
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "native_addon" && sev(f) == "SUSPECT" && vector(f) == "C3"));
    }

    #[test]
    fn benign_profile_no_findings() {
        let p = profile_with_phase("import");
        let f = classify(&p);
        assert!(f.is_empty(), "Benign profile must produce no findings");
    }
}
