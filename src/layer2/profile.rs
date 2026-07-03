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
    /// Paths written to: opened with a write flag, chmod'd, or a rename destination.
    #[serde(default)]
    pub file_writes: Vec<String>,
    /// Paths deleted: unlink/unlinkat targets and rename SOURCE paths.
    #[serde(default)]
    pub file_deletes: Vec<String>,
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
        // openat(AT_FDCWD, "path", ...) or open("path", ...) — file opened.
        // musl libc (alpine) and older glibc emit the plain `open` syscall, so we
        // must parse both forms or file-based detection (C3, sensitive reads) is blind.
        if let Some(path) = parse_openat(line).or_else(|| parse_open(line)) {
            if path.ends_with(".node") {
                profile.native_modules.push(path.clone());
            }
            if open_is_write(line) {
                profile.file_writes.push(path.clone());
            }
            profile.file_opens.push(path);
        }
        // connect(fd, {sa_family=AF_INET, sin_addr="1.2.3.4", sin_port=htons(443)}, ...)
        if let Some((ip, port)) = parse_connect(line) {
            profile.connects.push((ip, port));
        }
        // unlink("path") / unlinkat(AT_FDCWD, "path", flags) — file deleted.
        if let Some(path) = parse_unlink(line) {
            profile.file_deletes.push(path);
        }
        // rename("old","new") / renameat(...) / renameat2(...) — source deleted, dest written.
        if let Some((src, dst)) = parse_rename(line) {
            profile.file_deletes.push(src);
            profile.file_writes.push(dst);
        }
        // chmod("path", mode) / fchmodat(AT_FDCWD, "path", mode, flags) — file modified.
        if let Some(path) = parse_chmod(line) {
            profile.file_writes.push(path);
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

/// Extract file path from a plain `open` strace line.
/// Format: `open("/path/to/file", O_RDONLY|O_CLOEXEC) = 3`
/// The `"open("` prefix does not match `"openat("` (5th char differs), so the two
/// parsers are mutually exclusive per line.
fn parse_open(line: &str) -> Option<String> {
    let rest = skip_pid_prefix(line);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("open(")?;
    // First argument is the path (quoted string) — no dirfd for plain open().
    extract_quoted(rest)
}

/// Return true if an open/openat strace line's flags indicate a write-capable
/// open (as opposed to a plain read). Scoped to a single line so an unrelated
/// line mentioning one of these tokens elsewhere can't cross-contaminate.
fn open_is_write(line: &str) -> bool {
    line.contains("O_WRONLY") || line.contains("O_RDWR") || line.contains("O_CREAT") || line.contains("O_TRUNC")
}

/// Extract the deleted path from an unlink/unlinkat strace line.
/// Format: `unlink("/path")` or `unlinkat(AT_FDCWD, "/path", 0)`.
fn parse_unlink(line: &str) -> Option<String> {
    let rest = skip_pid_prefix(line);
    let rest = rest.trim_start();
    if let Some(rest) = rest.strip_prefix("unlinkat(") {
        // Skip the first argument (dirfd, e.g. "AT_FDCWD, ")
        let after_comma = rest.find(',')? + 1;
        let rest = rest[after_comma..].trim_start();
        return extract_quoted(rest);
    }
    let rest = rest.strip_prefix("unlink(")?;
    extract_quoted(rest)
}

/// Extract (source, dest) paths from a rename/renameat/renameat2 strace line.
/// Format: `rename("/a","/b")`, `renameat(AT_FDCWD,"/a",AT_FDCWD,"/b")`, or
/// `renameat2(AT_FDCWD,"/a",AT_FDCWD,"/b",0)`. Takes the FIRST and LAST quoted
/// strings on the line (the two paths), skipping any dirfd arguments in between.
fn parse_rename(line: &str) -> Option<(String, String)> {
    let rest = skip_pid_prefix(line);
    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix("renameat2(")
        .or_else(|| rest.strip_prefix("renameat("))
        .or_else(|| rest.strip_prefix("rename("))?;

    let paths = extract_all_quoted(rest);
    if paths.len() < 2 {
        return None;
    }
    Some((paths[0].clone(), paths[paths.len() - 1].clone()))
}

/// Extract the modified path from a chmod/fchmodat strace line.
/// Format: `chmod("/path", 0755)` or `fchmodat(AT_FDCWD, "/path", 0755, 0)`.
fn parse_chmod(line: &str) -> Option<String> {
    let rest = skip_pid_prefix(line);
    let rest = rest.trim_start();
    if let Some(rest) = rest.strip_prefix("fchmodat(") {
        let after_comma = rest.find(',')? + 1;
        let rest = rest[after_comma..].trim_start();
        return extract_quoted(rest);
    }
    let rest = rest.strip_prefix("chmod(")?;
    extract_quoted(rest)
}

/// Extract (ip, port) from a connect() strace line.
/// Format: `connect(fd, {sa_family=AF_INET, sin_addr="1.2.3.4", sin_port=htons(443)}, 16)`
fn parse_connect(line: &str) -> Option<(String, u16)> {
    let rest = skip_pid_prefix(line);
    let rest = rest.trim_start();
    let rest = rest.strip_prefix("connect(")?;

    // strace renders the address as either `sin_addr="1.2.3.4"` (older) or
    // `sin_addr=inet_addr("1.2.3.4")` (modern, what current strace on
    // node:lts-alpine actually emits). In BOTH forms the IP is the first
    // double-quoted string after `sin_addr=`, so skip to that first quote.
    let addr_start = rest.find("sin_addr=")?;
    let after_addr = &rest[addr_start + "sin_addr=".len()..];
    let quote = after_addr.find('"')?;
    let ip = extract_quoted(&after_addr[quote..])?;

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

/// Extract the content of every double-quoted string found in `s`, in order.
/// Used by `parse_rename` to pull both the source and destination path out of
/// a line that may have dirfd arguments (e.g. `AT_FDCWD`) interspersed.
fn extract_all_quoted(s: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut cursor = s;
    while let Some(quote_start) = cursor.find('"') {
        let after_quote = &cursor[quote_start..];
        match extract_quoted(after_quote) {
            Some(path) => {
                // Advance past the closing quote of this match.
                let body = &after_quote[1..];
                let mut end = body.len();
                let mut chars = body.char_indices();
                while let Some((i, c)) = chars.next() {
                    if c == '\\' {
                        chars.next();
                        continue;
                    }
                    if c == '"' {
                        end = i;
                        break;
                    }
                }
                results.push(path);
                cursor = &body[(end + 1).min(body.len())..];
            }
            None => break,
        }
    }
    results
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
    fn parse_open_musl_style() {
        // musl/alpine node emits the plain `open` syscall (no dirfd).
        let line = r#"43    open("/etc/hostname", O_RDONLY|O_CLOEXEC) = 17"#;
        assert_eq!(parse_open(line), Some("/etc/hostname".to_string()));
        // `open(` must NOT match `openat(` lines.
        let at = r#"openat(AT_FDCWD, "/x", O_RDONLY) = 3"#;
        assert_eq!(parse_open(at), None);
    }

    #[test]
    fn parse_strace_collects_plain_open_node_file() {
        let log = "12    open(\"/work/build/addon.node\", O_RDONLY|O_CLOEXEC) = 7\n";
        let p = parse_strace("import", log);
        assert!(p.native_modules.contains(&"/work/build/addon.node".to_string()));
        assert!(p.file_opens.contains(&"/work/build/addon.node".to_string()));
    }

    #[test]
    fn parse_connect_ipv4() {
        let line = r#"connect(4, {sa_family=AF_INET, sin_addr="1.2.3.4", sin_port=htons(443)}, 16) = 0"#;
        assert_eq!(parse_connect(line), Some(("1.2.3.4".to_string(), 443)));
    }

    #[test]
    fn parse_connect_inet_addr_form() {
        // Modern strace (node:lts-alpine) wraps the address in inet_addr(...) and
        // may emit sin_port BEFORE sin_addr. Both must parse.
        let line = r#"[pid    11] connect(18, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16) = -1 ENETUNREACH (Network unreachable)"#;
        assert_eq!(parse_connect(line), Some(("8.8.8.8".to_string(), 443)));
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

    // ── file_writes / file_deletes ─────────────────────────────────────────

    #[test]
    fn write_open_lands_in_file_writes_and_file_opens() {
        let log = r#"openat(AT_FDCWD, "/root/.bashrc", O_WRONLY|O_CREAT, 0644) = 4"#;
        let p = parse_strace("import", log);
        assert!(p.file_writes.contains(&"/root/.bashrc".to_string()));
        assert!(p.file_opens.contains(&"/root/.bashrc".to_string()));
    }

    #[test]
    fn read_open_does_not_land_in_file_writes() {
        // Negative control: a read-only open must NOT appear in file_writes.
        let log = r#"openat(AT_FDCWD, "/root/.bashrc", O_RDONLY) = 4"#;
        let p = parse_strace("import", log);
        assert!(p.file_opens.contains(&"/root/.bashrc".to_string()));
        assert!(!p.file_writes.contains(&"/root/.bashrc".to_string()));
    }

    #[test]
    fn parse_unlink_basic() {
        let line = r#"unlink("/tmp/victim1") = 0"#;
        assert_eq!(parse_unlink(line), Some("/tmp/victim1".to_string()));
    }

    #[test]
    fn parse_unlinkat_basic() {
        let line = r#"unlinkat(AT_FDCWD, "/tmp/victim2", 0) = 0"#;
        assert_eq!(parse_unlink(line), Some("/tmp/victim2".to_string()));
    }

    #[test]
    fn parse_rename_basic() {
        let line = r#"rename("/tmp/a", "/tmp/b") = 0"#;
        assert_eq!(
            parse_rename(line),
            Some(("/tmp/a".to_string(), "/tmp/b".to_string()))
        );
    }

    #[test]
    fn parse_renameat_skips_dirfds() {
        let line = r#"renameat(AT_FDCWD, "/tmp/a", AT_FDCWD, "/tmp/b") = 0"#;
        assert_eq!(
            parse_rename(line),
            Some(("/tmp/a".to_string(), "/tmp/b".to_string()))
        );
    }

    #[test]
    fn parse_renameat2_skips_dirfds_and_flags() {
        let line = r#"renameat2(AT_FDCWD, "/tmp/a", AT_FDCWD, "/tmp/b", 0) = 0"#;
        assert_eq!(
            parse_rename(line),
            Some(("/tmp/a".to_string(), "/tmp/b".to_string()))
        );
    }

    #[test]
    fn rename_source_and_dest_land_in_deletes_and_writes() {
        let log = "rename(\"/tmp/a\", \"/tmp/b\") = 0\n";
        let p = parse_strace("import", log);
        assert!(p.file_deletes.contains(&"/tmp/a".to_string()));
        assert!(p.file_writes.contains(&"/tmp/b".to_string()));
    }

    #[test]
    fn parse_chmod_basic() {
        let line = r#"chmod("/tmp/a", 0755) = 0"#;
        assert_eq!(parse_chmod(line), Some("/tmp/a".to_string()));
    }

    #[test]
    fn parse_fchmodat_skips_dirfd() {
        let line = r#"fchmodat(AT_FDCWD, "/tmp/a", 0755, 0) = 0"#;
        assert_eq!(parse_chmod(line), Some("/tmp/a".to_string()));
    }

    #[test]
    fn chmod_lands_in_file_writes() {
        let log = "chmod(\"/tmp/a\", 0755) = 0\n";
        let p = parse_strace("import", log);
        assert!(p.file_writes.contains(&"/tmp/a".to_string()));
    }

    #[test]
    fn parse_strace_collects_write_and_delete_fields_with_pid_prefixes() {
        let log = concat!(
            "4001  openat(AT_FDCWD, \"/root/.bashrc\", O_WRONLY|O_APPEND|O_CREAT, 0644) = 4\n",
            "4001  unlinkat(AT_FDCWD, \"/tmp/victim\", 0) = 0\n",
            "4001  renameat(AT_FDCWD, \"/tmp/old\", AT_FDCWD, \"/tmp/new\") = 0\n",
            "4001  fchmodat(AT_FDCWD, \"/tmp/new\", 0755, 0) = 0\n",
        );
        let p = parse_strace("import", log);
        assert!(p.file_writes.contains(&"/root/.bashrc".to_string()));
        assert!(p.file_deletes.contains(&"/tmp/victim".to_string()));
        assert!(p.file_deletes.contains(&"/tmp/old".to_string()));
        assert!(p.file_writes.contains(&"/tmp/new".to_string()));
    }
}
