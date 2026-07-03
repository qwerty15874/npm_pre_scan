// Layer 2: classification of a Layer2Profile into Findings.
// Pure function — no I/O, no Docker required. Unit-testable with fixture profiles.

use std::collections::HashSet;
use std::sync::OnceLock;

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
/// Embedded defaults, one hostname per line (same format as data/worm_iocs.txt).
/// Operators may extend this list at runtime via NPM_PRE_SCAN_EGRESS_HOSTS
/// (merged with, never replacing, these defaults — see runtime_lists.rs).
const WORM_EGRESS_HOSTS_EMBEDDED: &str = "registry.npmjs.org\napi.github.com\nwebhook.site\n";
const WORM_EGRESS_IP: &str = "169.254.169.254";

/// Merged (embedded + optional runtime file) worm egress hostnames, computed once.
fn egress_hosts() -> &'static HashSet<String> {
    static EGRESS_HOSTS: OnceLock<HashSet<String>> = OnceLock::new();
    EGRESS_HOSTS.get_or_init(|| {
        crate::runtime_lists::merge_runtime_lines(
            WORM_EGRESS_HOSTS_EMBEDDED,
            "NPM_PRE_SCAN_EGRESS_HOSTS",
        )
    })
}

/// Sensitive file paths that indicate credential/config theft.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/.ssh/",
    ".npmrc",
    ".aws/credentials",
    ".git-credentials",
];

/// Sensitive file WRITE targets — credential/persistence tampering. Kept
/// separate from `SENSITIVE_PATHS` so a mere READ of e.g. `.bashrc` isn't
/// newly flagged; only a write/modify to these paths is.
const SENSITIVE_WRITE_PATHS: &[&str] = &[
    ".npmrc",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    "authorized_keys",
    "/.ssh/",
    "/node_modules/.bin",
    "crontab",
    "/etc/cron",
    "/.git/hooks/",
];

/// Minimum number of file deletions to be treated as wiper behavior rather
/// than incidental cleanup.
const WIPER_DELETE_THRESHOLD: usize = 20;

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

    // Writes/deletes to ephemeral or system scratch locations (/tmp, /dev incl.
    // /dev/shm, /proc, /sys, /run, /var/tmp) are never package-attributable
    // persistence or wiper behavior. Filtering them here is what keeps the
    // Layer 3 clock scenario honest: libfaketime (LD_PRELOAD'd only in the
    // mutated clock run, not the baseline) writes/unlinks its own
    // /dev/shm/faketime_* shm+sem files, which would otherwise survive the
    // baseline diff and false-positive a benign package as an import side
    // effect. It also focuses wiper detection on meaningful files rather than
    // a package's own /tmp scratch.
    let meaningful_writes: Vec<&String> = profile
        .file_writes
        .iter()
        .filter(|p| !is_ephemeral_or_system_path(p))
        .collect();
    let meaningful_deletes: Vec<&String> = profile
        .file_deletes
        .iter()
        .filter(|p| !is_ephemeral_or_system_path(p))
        .collect();

    // ── E1: worm egress ──────────────────────────────────────────────────────
    for qname in &profile.dns_queries {
        let lower = qname.to_lowercase();
        for ioc in egress_hosts() {
            if lower == *ioc || lower.ends_with(&format!(".{}", ioc)) {
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
        } else if is_public_ip(ip) {
            let mut f = finding(
                "ip_literal_egress",
                "SUSPECT",
                &format!(
                    "Connect to hardcoded public IP {}:{} (DNS-sinkhole-bypassing C2 intent)",
                    ip, port
                ),
                phase,
                "C1",
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

    // ── B4: sensitive file write / persistence tampering ─────────────────────
    for path in &meaningful_writes {
        if is_sensitive_write_path(path) {
            let mut f = finding(
                "sensitive_file_write",
                "BLOCK",
                &format!("Sensitive file written/modified: {}", path),
                phase,
                "B4",
            );
            f.insert("path".into(), Value::String((*path).clone()));
            findings.push(f);
        }
    }

    // ── B4: mass deletion (wiper behavior) ────────────────────────────────────
    if meaningful_deletes.len() >= WIPER_DELETE_THRESHOLD {
        let mut f = finding(
            "mass_deletion",
            "BLOCK",
            &format!(
                "Mass file deletion detected: {} files unlinked (wiper behavior)",
                meaningful_deletes.len()
            ),
            phase,
            "B4",
        );
        f.insert(
            "delete_count".into(),
            Value::Number(meaningful_deletes.len().into()),
        );
        findings.push(f);
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
            // Escalate to BLOCK if the process also made network connections, read
            // sensitive files, wrote/modified a sensitive persistence target, or
            // performed mass deletion (wiper behavior).
            let has_network = !profile.connects.is_empty() || !profile.dns_queries.is_empty();
            let has_sensitive = profile.file_opens.iter().any(|p| is_sensitive_path(p));
            let has_sensitive_write = meaningful_writes.iter().any(|p| is_sensitive_write_path(p));
            let has_mass_deletion = meaningful_deletes.len() >= WIPER_DELETE_THRESHOLD;
            let severity = if has_network || has_sensitive || has_sensitive_write || has_mass_deletion {
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
        let has_write = !meaningful_writes.is_empty();
        let has_delete = !meaningful_deletes.is_empty();

        if has_network || has_process || has_sensitive || has_write || has_delete {
            // BLOCK reserved for has_sensitive — a sensitive write already BLOCKs
            // via the sensitive_file_write rule above; a bare write/delete during
            // import stays SUSPECT here.
            let severity = if has_sensitive { "BLOCK" } else { "SUSPECT" };
            let details = [
                if has_network { Some("network activity") } else { None },
                if has_process { Some("child process spawned") } else { None },
                if has_sensitive { Some("sensitive file read") } else { None },
                if has_write { Some("file write") } else { None },
                if has_delete { Some("file deletion") } else { None },
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

/// Return true if `path` is an ephemeral or system scratch location whose
/// writes/deletes are never package-attributable persistence or wiper behavior
/// (also filters the Layer 3 clock scenario's own libfaketime /dev/shm
/// artifacts, which appear only in the mutated run and not the baseline).
fn is_ephemeral_or_system_path(path: &str) -> bool {
    const EPHEMERAL_PREFIXES: &[&str] = &[
        "/tmp/",
        "/dev/",
        "/proc/",
        "/sys/",
        "/run/",
        "/var/tmp/",
        "/var/cache/",
    ];
    EPHEMERAL_PREFIXES.iter().any(|p| path.starts_with(p))
        || path.contains("/faketime")
        || path == "/etc/localtime"
}

/// Return true if `path` matches a known credential/persistence WRITE target.
fn is_sensitive_write_path(path: &str) -> bool {
    SENSITIVE_WRITE_PATHS
        .iter()
        .any(|&pattern| path.contains(pattern))
}

/// Return true if `ip` is a public (routable, non-reserved) IPv4 address.
/// IPv6 and unparseable input return false (not flagged by this rule).
fn is_public_ip(ip: &str) -> bool {
    let addr: std::net::Ipv4Addr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    if addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_unspecified()
        || addr.is_broadcast()
        || addr.is_documentation()
    {
        return false;
    }
    // CGNAT range 100.64.0.0/10 — not covered by std's is_private/is_link_local.
    let octets = addr.octets();
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return false;
    }
    true
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
        let mut p = profile_with_phase("import");
        // Empty write/delete vecs must stay clean too.
        assert!(p.file_writes.is_empty());
        assert!(p.file_deletes.is_empty());
        let f = classify(&p);
        assert!(f.is_empty(), "Benign profile must produce no findings");
        // Explicitly confirm classify with untouched write/delete fields is still clean.
        p.file_opens.push("/work/index.js".to_string());
        let f = classify(&p);
        assert!(f.is_empty(), "Benign profile with only ordinary file opens must produce no findings");
    }

    // ── B4: sensitive file write / persistence tampering ─────────────────────

    #[test]
    fn b4_sensitive_write_bashrc_blocks() {
        let mut p = profile_with_phase("import");
        p.file_writes.push("/root/.bashrc".to_string());
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "sensitive_file_write" && sev(f) == "BLOCK" && vector(f) == "B4"));
    }

    #[test]
    fn b4_read_of_bashrc_not_flagged() {
        // A mere READ of .bashrc (in file_opens, not file_writes) must NOT be
        // flagged by the sensitive_file_write rule.
        let mut p = profile_with_phase("import");
        p.file_opens.push("/root/.bashrc".to_string());
        let f = classify(&p);
        assert!(!f.iter().any(|f| check(f) == "sensitive_file_write"));
    }

    #[test]
    fn b4_mass_deletion_blocks() {
        let mut p = profile_with_phase("import");
        for i in 0..25 {
            p.file_deletes.push(format!("/work/victim{}", i));
        }
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "mass_deletion" && sev(f) == "BLOCK" && vector(f) == "B4"));
    }

    #[test]
    fn b4_few_deletions_no_mass_deletion_finding() {
        let mut p = profile_with_phase("import");
        for i in 0..5 {
            p.file_deletes.push(format!("/work/tmp{}", i));
        }
        let f = classify(&p);
        assert!(!f.iter().any(|f| check(f) == "mass_deletion"));
    }

    #[test]
    fn c1_non_sensitive_write_during_import_suspect() {
        let mut p = profile_with_phase("import");
        p.file_writes.push("/work/output.txt".to_string());
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "import_side_effect" && sev(f) == "SUSPECT" && vector(f) == "C1"));
    }

    // ── C1 (TASK 1b): IP-literal egress ───────────────────────────────────────

    #[test]
    fn ip_literal_egress_public_ip_suspect() {
        let mut p = profile_with_phase("import");
        p.connects.push(("8.8.8.8".to_string(), 443));
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "ip_literal_egress" && sev(f) == "SUSPECT" && vector(f) == "C1"));
    }

    #[test]
    fn ip_literal_egress_private_ips_not_flagged() {
        for ip in ["10.0.0.5", "192.168.1.1", "172.16.0.1", "127.0.0.1", "100.64.0.1"] {
            let mut p = profile_with_phase("import");
            p.connects.push((ip.to_string(), 443));
            let f = classify(&p);
            assert!(
                !f.iter().any(|f| check(f) == "ip_literal_egress"),
                "{} must not be flagged as ip_literal_egress",
                ip
            );
        }
    }

    #[test]
    fn worm_egress_imds_ip_not_downgraded_to_ip_literal() {
        let mut p = profile_with_phase("import");
        p.connects.push(("169.254.169.254".to_string(), 80));
        let f = classify(&p);
        assert!(f
            .iter()
            .any(|f| check(f) == "worm_egress" && sev(f) == "BLOCK"));
        assert!(!f.iter().any(|f| check(f) == "ip_literal_egress"));
    }
}
