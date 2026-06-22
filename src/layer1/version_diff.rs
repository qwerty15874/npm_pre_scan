use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use walkdir::WalkDir;

use super::tarball;

type Finding = Map<String, Value>;

fn finding(severity: &str, message: &str, file: &str, prev: &str, latest: &str) -> Finding {
    let mut m = Map::new();
    m.insert("check".into(), Value::String("version_diff".into()));
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("message".into(), Value::String(message.to_string()));
    m.insert("file".into(), Value::String(file.to_string()));
    m.insert("prev_version".into(), Value::String(prev.to_string()));
    m.insert("latest_version".into(), Value::String(latest.to_string()));
    m
}

/// Version keys sorted by publish time (ISO-8601 strings sort chronologically).
fn sorted_versions(info: &Value) -> Vec<String> {
    let versions = match info.get("versions").and_then(|v| v.as_object()) {
        Some(v) => v,
        None => return vec![],
    };
    let time = info.get("time");
    let mut keys: Vec<String> = versions.keys().cloned().collect();
    keys.sort_by(|a, b| {
        let ta = time.and_then(|t| t.get(a)).and_then(|v| v.as_str()).unwrap_or("");
        let tb = time.and_then(|t| t.get(b)).and_then(|v| v.as_str()).unwrap_or("");
        ta.cmp(tb)
    });
    keys
}

/// Map of relative .js path → file contents under `dir`.
const JS_EXTENSIONS: &[&str] = &["js", "cjs", "mjs", "ts", "tsx", "jsx"];

pub(crate) fn js_contents(dir: &Path) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();
        if p.extension()
            .and_then(|e| e.to_str())
            .map(|e| JS_EXTENSIONS.contains(&e))
            .unwrap_or(false)
        {
            if let Ok(content) = std::fs::read_to_string(p) {
                let rel = p.strip_prefix(dir).unwrap_or(p).display().to_string();
                map.insert(rel, content);
            }
        }
    }
    map
}

/// Lines present in `latest` but not in `prev` (trimmed line-set difference).
/// If `prev` is None the file is brand new, so all of its content counts as added.
fn added_text(prev: Option<&String>, latest: &str) -> String {
    match prev {
        None => latest.to_string(),
        Some(prev_content) => {
            let prev_set: HashSet<&str> = prev_content.lines().map(|l| l.trim()).collect();
            latest
                .lines()
                .filter(|l| !prev_set.contains(l.trim()))
                .collect::<Vec<_>>()
                .join("\n")
        }
    }
}

/// Scan the line-set difference between two sets of JS files and return findings
/// for newly introduced suspicious patterns. This is the pure, testable core of
/// the B3 (malicious version update) check.
pub(crate) fn diff_findings(
    prev_files: &HashMap<String, String>,
    latest_files: &HashMap<String, String>,
    prev_v: &str,
    latest_v: &str,
) -> Vec<Finding> {
    let re_eval_buf = Regex::new(r"eval\s*\(\s*Buffer\.from\s*\(").unwrap();
    let re_eval = Regex::new(r"eval\s*\(").unwrap();
    let re_sensitive = Regex::new(r"/etc/passwd|/etc/shadow|~/\.ssh|/\.ssh/").unwrap();
    let re_net = Regex::new(
        r#"require\s*\(\s*['"](?:axios|node-fetch|cross-fetch|https?|got|superagent|request)['"]\s*\)"#,
    )
    .unwrap();
    let re_env = Regex::new(r"process\.env\b").unwrap();
    // Worm-class indicators (E1 — self-propagating worm via update)
    let re_worm = Regex::new(
        r"npm\s+publish\b|_authToken|NPM_TOKEN|webhook\.site|169\.254\.169\.254|trufflehog|shai.hulud",
    )
    .unwrap();

    let mut findings = Vec::new();
    for (file, latest_content) in latest_files {
        let added = added_text(prev_files.get(file), latest_content);
        if added.trim().is_empty() {
            continue;
        }
        let origin = if prev_files.contains_key(file) {
            "added code"
        } else {
            "new file"
        };

        if re_eval_buf.is_match(&added) {
            findings.push(finding(
                "BLOCK",
                &format!("Newly introduced eval(Buffer.from()) in {} ({})", file, origin),
                file,
                prev_v,
                latest_v,
            ));
        } else if re_eval.is_match(&added) {
            findings.push(finding(
                "SUSPECT",
                &format!("Newly introduced eval() in {} ({})", file, origin),
                file,
                prev_v,
                latest_v,
            ));
        }

        if re_sensitive.is_match(&added) {
            findings.push(finding(
                "BLOCK",
                &format!("Newly introduced sensitive-path reference in {} ({})", file, origin),
                file,
                prev_v,
                latest_v,
            ));
        }

        if re_net.is_match(&added) {
            findings.push(finding(
                "SUSPECT",
                &format!("Newly introduced network import in {} ({})", file, origin),
                file,
                prev_v,
                latest_v,
            ));
        }

        if re_env.is_match(&added) {
            findings.push(finding(
                "SUSPECT",
                &format!("Newly introduced process.env access in {} ({})", file, origin),
                file,
                prev_v,
                latest_v,
            ));
        }

        if re_worm.is_match(&added) {
            findings.push(finding(
                "BLOCK",
                &format!("Newly introduced worm-class indicator in {} ({})", file, origin),
                file,
                prev_v,
                latest_v,
            ));
        }
    }

    findings
}

/// Compare the latest published version against the previous one and flag
/// suspicious code that was newly introduced. Best-effort: returns no findings
/// if the package has fewer than two versions or tarballs can't be fetched.
pub fn check_version_diff(info: &Value) -> Vec<Finding> {
    let versions = sorted_versions(info);
    if versions.len() < 2 {
        return vec![];
    }
    let prev_v = &versions[versions.len() - 2];
    let latest_v = &versions[versions.len() - 1];

    let prev_url = match tarball::get_version_tarball_url(info, prev_v) {
        Some(u) => u,
        None => return vec![],
    };
    let latest_url = match tarball::get_version_tarball_url(info, latest_v) {
        Some(u) => u,
        None => return vec![],
    };

    let prev_dir = match tarball::download_and_extract(&prev_url) {
        Ok(d) => d,
        Err(_) => return vec![],
    };
    let latest_dir = match tarball::download_and_extract(&latest_url) {
        Ok(d) => d,
        Err(_) => return vec![],
    };

    let prev_files = js_contents(prev_dir.path());
    let latest_files = js_contents(latest_dir.path());

    diff_findings(&prev_files, &latest_files, prev_v, latest_v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_file_counts_all_as_added() {
        let latest = "line one\nline two";
        assert_eq!(added_text(None, latest), latest);
    }

    #[test]
    fn only_genuinely_new_lines_returned() {
        let prev = "shared a\nshared b".to_string();
        let latest = "shared a\nshared b\neval(payload)";
        assert_eq!(added_text(Some(&prev), latest), "eval(payload)");
    }

    #[test]
    fn no_added_lines_is_empty() {
        let prev = "x\ny".to_string();
        let latest = "x\ny";
        assert_eq!(added_text(Some(&prev), latest), "");
    }
}
