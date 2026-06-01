use regex::Regex;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

type Finding = Map<String, Value>;

fn finding(check: &str, severity: &str, message: &str) -> Finding {
    let mut m = Map::new();
    m.insert("check".into(), Value::String(check.to_string()));
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("message".into(), Value::String(message.to_string()));
    m
}

const JS_EXTENSIONS: &[&str] = &["js", "cjs", "mjs", "ts", "tsx", "jsx"];

fn js_files(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| JS_EXTENSIONS.contains(&ext))
                .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn rel(dir: &Path, path: &Path) -> String {
    path.strip_prefix(dir)
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Check package.json for install-time lifecycle scripts (preinstall/install/postinstall).
pub fn check_install_scripts(pkg_json: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(scripts) = pkg_json.get("scripts") else {
        return findings;
    };
    let present: Vec<&str> = ["preinstall", "install", "postinstall"]
        .iter()
        .copied()
        .filter(|&k| scripts.get(k).is_some())
        .collect();
    if !present.is_empty() {
        let mut f = finding(
            "install_script",
            "SUSPECT",
            &format!("Install lifecycle script(s) present: {}", present.join(", ")),
        );
        f.insert(
            "scripts".into(),
            Value::Array(present.iter().map(|&s| Value::String(s.to_string())).collect()),
        );
        findings.push(f);
    }
    findings
}

/// Scan .js files for obfuscation indicators (eval+Buffer.from, bare eval, hex sequences, long base64).
pub fn check_obfuscation(dir: &Path) -> Vec<Finding> {
    let re_eval_buf = Regex::new(r"eval\s*\(\s*Buffer\.from\s*\(").unwrap();
    let re_eval = Regex::new(r"eval\s*\(").unwrap();
    let re_hex = Regex::new(r"(?:\\x[0-9a-fA-F]{2}){4,}").unwrap();
    let re_b64 = Regex::new(r#"['"][A-Za-z0-9+/]{100,}={0,2}['"]"#).unwrap();

    let mut findings = Vec::new();
    for path in js_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let file = rel(dir, &path);

        if re_eval_buf.is_match(&content) {
            let mut f = finding(
                "obfuscation",
                "BLOCK",
                "eval(Buffer.from()) detected — base64-obfuscated payload",
            );
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        } else if re_eval.is_match(&content) {
            let mut f = finding("obfuscation", "SUSPECT", "eval() call detected");
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        }

        if re_hex.is_match(&content) {
            let mut f = finding("obfuscation", "SUSPECT", "Hex-encoded string sequence detected");
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        }

        if re_b64.is_match(&content) {
            let mut f = finding(
                "obfuscation",
                "SUSPECT",
                "Long base64-like string literal detected (possible encoded payload)",
            );
            f.insert("file".into(), Value::String(file));
            findings.push(f);
        }
    }
    findings
}

/// Scan .js files for sensitive path/env references (/etc/passwd, ~/.ssh, process.env, etc.).
pub fn check_suspicious_strings(dir: &Path) -> Vec<Finding> {
    let patterns: &[(&str, &str, &str)] = &[
        (r"/etc/passwd", "BLOCK", "References /etc/passwd"),
        (r"/etc/shadow", "BLOCK", "References /etc/shadow"),
        (r"~/\.ssh|/\.ssh/", "BLOCK", "References SSH directory (~/.ssh)"),
        (r"process\.env\b", "SUSPECT", "Reads environment variables (process.env)"),
        (r"os\.homedir\(\)", "SUSPECT", "Reads home directory path (os.homedir())"),
    ];

    let compiled: Vec<(Regex, &str, &str)> = patterns
        .iter()
        .filter_map(|(pat, sev, msg)| Regex::new(pat).ok().map(|re| (re, *sev, *msg)))
        .collect();

    let mut findings = Vec::new();
    for path in js_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let file = rel(dir, &path);
        for (re, sev, msg) in &compiled {
            if re.is_match(&content) {
                let mut f = finding("suspicious_strings", sev, msg);
                f.insert("file".into(), Value::String(file.clone()));
                findings.push(f);
            }
        }
    }
    findings
}

/// Scan .js files for network-capable module imports (axios, node-fetch, https, http, etc.).
pub fn check_network_imports(dir: &Path) -> Vec<Finding> {
    const MOD: &str = "axios|node-fetch|cross-fetch|https?|got|superagent|request";
    let patterns = [
        format!(r#"require\s*\(\s*['"](?:{MOD})['"]\s*\)"#),
        format!(r#"import\s+[^;]*?from\s*['"](?:{MOD})['"]"#),
        format!(r#"import\s*['"](?:{MOD})['"]"#),
        format!(r#"import\s*\(\s*['"](?:{MOD})['"]\s*\)"#),
    ];
    let res: Vec<Regex> = patterns.iter().map(|p| Regex::new(p).unwrap()).collect();

    let mut hit_files: Vec<String> = Vec::new();
    for path in js_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        if res.iter().any(|re| re.is_match(&content)) {
            hit_files.push(rel(dir, &path));
        }
    }

    if hit_files.is_empty() {
        return vec![];
    }
    let mut f = finding(
        "network_imports",
        "SUSPECT",
        &format!("Network-capable module imported in {} file(s)", hit_files.len()),
    );
    f.insert(
        "files".into(),
        Value::Array(hit_files.into_iter().map(Value::String).collect()),
    );
    vec![f]
}

/// Scan .js files for dynamic require(variable) — require called with a non-literal argument.
pub fn check_dynamic_require(dir: &Path) -> Vec<Finding> {
    let re = Regex::new(r#"require\(\s*[^'")\s][^)]*\)"#).unwrap();

    let mut findings = Vec::new();
    for path in js_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        if re.is_match(&content) {
            let mut f = finding(
                "dynamic_require",
                "SUSPECT",
                "Dynamic require(variable) pattern — module loaded at runtime from a variable",
            );
            f.insert("file".into(), Value::String(rel(dir, &path)));
            findings.push(f);
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    fn dir_with(files: &[(&str, &str)]) -> TempDir {
        let tmp = TempDir::new().unwrap();
        for (name, content) in files {
            fs::write(tmp.path().join(name), content).unwrap();
        }
        tmp
    }

    fn sevs(findings: &[Finding]) -> Vec<String> {
        findings
            .iter()
            .map(|f| f.get("severity").and_then(|v| v.as_str()).unwrap_or("").to_string())
            .collect()
    }

    #[test]
    fn install_scripts_detected() {
        let pkg = json!({ "scripts": { "postinstall": "node x.js" } });
        assert_eq!(sevs(&check_install_scripts(&pkg)), vec!["SUSPECT"]);
        let clean = json!({ "scripts": { "test": "jest" } });
        assert!(check_install_scripts(&clean).is_empty());
        let none = json!({});
        assert!(check_install_scripts(&none).is_empty());
    }

    #[test]
    fn obfuscation_eval_buffer_blocks() {
        let d = dir_with(&[("a.js", "const x = eval(Buffer.from('aaa','base64'));")]);
        let f = check_obfuscation(d.path());
        assert!(sevs(&f).contains(&"BLOCK".to_string()));
    }

    #[test]
    fn obfuscation_bare_eval_is_suspect() {
        let d = dir_with(&[("a.js", "eval(userInput);")]);
        let f = check_obfuscation(d.path());
        assert_eq!(sevs(&f), vec!["SUSPECT"]);
    }

    #[test]
    fn suspicious_strings_etc_passwd_blocks() {
        let d = dir_with(&[("a.js", "fs.readFileSync('/etc/passwd');")]);
        let f = check_suspicious_strings(d.path());
        assert!(sevs(&f).contains(&"BLOCK".to_string()));
    }

    #[test]
    fn suspicious_strings_env_is_suspect() {
        let d = dir_with(&[("a.js", "const t = process.env.TOKEN;")]);
        let f = check_suspicious_strings(d.path());
        assert!(sevs(&f).contains(&"SUSPECT".to_string()));
    }

    #[test]
    fn network_imports_cjs_and_esm() {
        let d = dir_with(&[
            ("a.js", "const ax = require('axios');"),
            ("b.mjs", "import axios from 'axios';"),
        ]);
        let f = check_network_imports(d.path());
        assert_eq!(f.len(), 1);
        let files = f[0].get("files").unwrap().as_array().unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn network_imports_clean() {
        let d = dir_with(&[("a.js", "const path = require('path');")]);
        assert!(check_network_imports(d.path()).is_empty());
    }

    #[test]
    fn dynamic_require_positive() {
        let d = dir_with(&[("a.js", "const m = require(name);")]);
        assert_eq!(sevs(&check_dynamic_require(d.path())), vec!["SUSPECT"]);
        let d2 = dir_with(&[("b.js", "require(a + b);")]);
        assert_eq!(sevs(&check_dynamic_require(d2.path())), vec!["SUSPECT"]);
    }

    #[test]
    fn dynamic_require_negative() {
        let d = dir_with(&[("a.js", "require('fs');\nrequire();\nconst p = require('path');")]);
        assert!(check_dynamic_require(d.path()).is_empty());
    }
}
