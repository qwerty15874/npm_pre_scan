// Layer 2: behavior profile — pure parsing functions.
// Local test module; no Docker required to run tests.

use serde::{Deserialize, Serialize};

/// Captured behavior of a package across the install and import phases.
/// Produced by `parse_strace` + `parse_dns`; consumed by `classify`.
/// Serializable so Layer 3 can use it as a baseline for diffing.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Layer2Profile {
    /// Which phase this profile represents ("install" or "import").
    pub phase: String,
    /// Child processes spawned (execve command strings).
    pub processes: Vec<String>,
    /// Filesystem paths opened (openat).
    pub file_opens: Vec<String>,
    /// TCP/UDP connect destinations (ip, port).
    pub connects: Vec<(String, u16)>,
    /// DNS query names logged by dnsmasq.
    pub dns_queries: Vec<String>,
    /// Native addon paths opened or dlopen'd (*.node files).
    pub native_modules: Vec<String>,
}

/// Parse a strace log (output of `strace -f -e trace=execve,openat,connect`) into a
/// `Layer2Profile` for the given `phase` label ("install" or "import").
///
/// Pure function — no I/O. Suitable for unit testing with recorded fixture strings.
pub fn parse_strace(phase: &str, log: &str) -> Layer2Profile {
    let mut profile = Layer2Profile {
        phase: phase.to_string(),
        ..Default::default()
    };

    for line in log.lines() {
        // execve("path", [...], ...) — child process spawned
        if let Some(cmd) = parse_execve(line) {
            profile.processes.push(cmd);
        }
        // openat(AT_FDCWD, "path", ...) — file opened
        if let Some(path) = parse_openat(line) {
            if path.ends_with(".node") {
                profile.native_modules.push(path.clone());
            }
            profile.file_opens.push(path);
        }
        // connect(fd, {sa_family=AF_INET, sin_addr="1.2.3.4", sin_port=htons(443)}, ...)
        if let Some((ip, port)) = parse_connect(line) {
            profile.connects.push((ip, port));
        }
    }

    profile
}

/// Parse a dnsmasq query log into a list of queried hostnames.
///
/// dnsmasq line format (--log-queries):
///   `dnsmasq[PID]: query[A] example.com from 127.0.0.1`
///   `dnsmasq[PID]: query[TXT] foo.bar.com from 127.0.0.1`
///
/// Pure function — no I/O.
pub fn parse_dns(log: &str) -> Vec<String> {
    let mut queries = Vec::new();
    for line in log.lines() {
        if let Some(qname) = parse_dns_line(line) {
            queries.push(qname);
        }
    }
    queries
}

// ── internal parsers ──────────────────────────────────────────────────────────

/// Extract command string from an execve strace line.
/// Handles: `execve("/usr/bin/sh", ["sh", "-c", "..."], ...)` and
///           `<pid>  execve(...` (with leading PID from -f flag).
fn parse_execve(line: &str) -> Option<String> {
    let rest = skip_pid_prefix(line);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("execve(")?;
    // First argument is the executable path (quoted string)
    let path = extract_quoted(rest)?;
    Some(path)
}

/// Extract file path from an openat strace line.
/// Format: `openat(AT_FDCWD, "/path/to/file", O_RDONLY)`
fn parse_openat(line: &str) -> Option<String> {
    let rest = skip_pid_prefix(line);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("openat(")?;
    // Skip the first argument (dirfd, e.g. "AT_FDCWD, ")
    let after_comma = rest.find(',')? + 1;
    let rest = rest[after_comma..].trim_start();
    extract_quoted(rest)
}

/// Extract (ip, port) from a connect() strace line.
/// Format: `connect(fd, {sa_family=AF_INET, sin_addr="1.2.3.4", sin_port=htons(443)}, 16)`
fn parse_connect(line: &str) -> Option<(String, u16)> {
    let rest = skip_pid_prefix(line);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("connect(")?;

    // sin_addr="..."
    let addr_start = rest.find("sin_addr=")?;
    let after_addr = &rest[addr_start + "sin_addr=".len()..];
    let ip = extract_quoted(after_addr)?;

    // sin_port=htons(NNN)
    let port_start = rest.find("sin_port=htons(")?;
    let after_port = &rest[port_start + "sin_port=htons(".len()..];
    let port_end = after_port.find(')')?;
    let port: u16 = after_port[..port_end].trim().parse().ok()?;

    Some((ip, port))
}

/// Extract qname from a dnsmasq log line.
fn parse_dns_line(line: &str) -> Option<String> {
    // Pattern: "query[A] <qname> from"
    let bracket_close = line.find("] ")?;
    let after_type = line[bracket_close + 2..].trim_start();
    // qname ends at " from "
    let from_pos = after_type.find(" from ")?;
    // Only consider lines that contain "query["
    if !line.contains("query[") {
        return None;
    }
    let qname = after_type[..from_pos].trim().to_string();
    if qname.is_empty() {
        return None;
    }
    Some(qname)
}

/// Strip leading PID / timestamp prefix that `strace -f` emits.
/// e.g. `1234  execve(...)` → `execve(...)`, or `[pid 1234] execve(...)` → `execve(...)`.
fn skip_pid_prefix(line: &str) -> &str {
    // "[pid NNN] ..."
    if let Some(rest) = line.strip_prefix('[') {
        if let Some(idx) = rest.find("] ") {
            return &rest[idx + 2..];
        }
    }
    // "NNN  ..." (numeric pid followed by whitespace)
    let trimmed = line.trim_start();
    let end = trimmed.find(|c: char| !c.is_ascii_digit()).unwrap_or(0);
    if end > 0 {
        let after = trimmed[end..].trim_start();
        // Make sure the remainder looks like a syscall (starts with a letter)
        if after.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return after;
        }
    }
    line
}

/// Extract the content of the first double-quoted string at the start of `s`.
fn extract_quoted(s: &str) -> Option<String> {
    let s = s.trim_start();
    let s = s.strip_prefix('"')?;
    // Find closing quote, respecting simple backslash escapes
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    loop {
        match chars.next()? {
            '"' => return Some(result),
            '\\' => {
                // skip escaped char
                if let Some(c) = chars.next() {
                    result.push(c);
                }
            }
            c => result.push(c),
        }
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_execve_basic() {
        let line = r#"execve("/bin/sh", ["sh", "-c", "id"], 0x7f /*  env  */)"#;
        assert_eq!(parse_execve(line), Some("/bin/sh".to_string()));
    }

    #[test]
    fn parse_execve_with_pid() {
        let line = r#"1234  execve("/usr/bin/node", ["node", "index.js"], 0x0)"#;
        assert_eq!(parse_execve(line), Some("/usr/bin/node".to_string()));
    }

    #[test]
    fn parse_openat_basic() {
        let line = r#"openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3"#;
        assert_eq!(parse_openat(line), Some("/etc/passwd".to_string()));
    }

    #[test]
    fn parse_openat_node_file() {
        let line = r#"openat(AT_FDCWD, "/pkg/build/addon.node", O_RDONLY) = 5"#;
        let path = parse_openat(line).unwrap();
        assert_eq!(path, "/pkg/build/addon.node");
    }

    #[test]
    fn parse_connect_ipv4() {
        let line = r#"connect(4, {sa_family=AF_INET, sin_addr="1.2.3.4", sin_port=htons(443)}, 16) = 0"#;
        assert_eq!(parse_connect(line), Some(("1.2.3.4".to_string(), 443)));
    }

    #[test]
    fn parse_dns_line_basic() {
        let line = "dnsmasq[42]: query[A] api.github.com from 127.0.0.1";
        assert_eq!(parse_dns_line(line), Some("api.github.com".to_string()));
    }

    #[test]
    fn parse_dns_line_txt() {
        let line = "dnsmasq[42]: query[TXT] aGVsbG8gd29ybGQ.exfil.example.com from 127.0.0.1";
        assert_eq!(
            parse_dns_line(line),
            Some("aGVsbG8gd29ybGQ.exfil.example.com".to_string())
        );
    }

    #[test]
    fn parse_strace_collects_fields() {
        let log = concat!(
            "execve(\"/bin/sh\", [\"sh\",\"-c\",\"id\"], 0x0)\n",
            "openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3\n",
            "openat(AT_FDCWD, \"/pkg/addon.node\", O_RDONLY) = 5\n",
            "connect(4, {sa_family=AF_INET, sin_addr=\"1.2.3.4\", sin_port=htons(80)}, 16) = 0\n",
        );
        let p = parse_strace("install", log);
        assert_eq!(p.phase, "install");
        assert!(p.processes.contains(&"/bin/sh".to_string()));
        assert!(p.file_opens.contains(&"/etc/passwd".to_string()));
        assert!(p.native_modules.contains(&"/pkg/addon.node".to_string()));
        assert!(p.connects.contains(&("1.2.3.4".to_string(), 80)));
    }

    #[test]
    fn parse_dns_multiple_queries() {
        let log = concat!(
            "dnsmasq[1]: query[A] registry.npmjs.org from 127.0.0.1\n",
            "dnsmasq[1]: query[TXT] aabbccdd.c2.example.com from 127.0.0.1\n",
        );
        let q = parse_dns(log);
        assert_eq!(q.len(), 2);
        assert!(q.contains(&"registry.npmjs.org".to_string()));
        assert!(q.contains(&"aabbccdd.c2.example.com".to_string()));
    }
}
