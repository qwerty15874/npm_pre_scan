// Fetching and extracting DataDog malware samples for the evaluation harness.
//
// ============================== SAFETY =====================================
// Everything this module handles is ACTIVELY MALICIOUS code published by real
// threat actors. The rules it enforces:
//
//   * Zips are cached ENCRYPTED at rest under a gitignored directory. The
//     password is `infected`, as published by the dataset — it exists to stop
//     antivirus and casual `unzip` from touching the contents, not as a secret.
//   * Extraction goes into a `TempDir` that is dropped as soon as the scan
//     finishes. Plaintext malware never persists.
//   * Nothing here executes anything. Execution happens only inside the
//     existing container (`--network=none`, DNS sinkhole, read-only `/pkg`),
//     which is what Layers 2 and 3 already do for every package.
//   * Path traversal is rejected explicitly (see `is_safe_component`) — an
//     archive from a hostile source is exactly the place a `../../` entry would
//     show up, and `zip`'s convenience extractor is not something to trust with
//     attacker-controlled names.
// ===========================================================================
//
// The dataset stores each sample as `<category>/<pkgdir>/<version>/<file>.zip`
// under `samples/npm/`, and the archive's internal layout is
// `tmp/<random>/<package-name>/package/…` plus a sibling `package_info-*.json`.
// So the scannable npm package root is the `package/` directory inside, which
// `find_package_root` locates rather than assuming a fixed depth.

use std::io::Read;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

const RAW_BASE: &str =
    "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm";

/// The dataset's published archive password. Not a secret — see the module note.
const ZIP_PASSWORD: &[u8] = b"infected";

/// An extracted sample, scannable for as long as this value is alive. Dropping it
/// deletes the plaintext.
#[derive(Debug)]
pub struct PreparedSample {
    _tmp: TempDir,
    package_dir: PathBuf,
}

impl PreparedSample {
    /// The npm package root (the directory holding `package.json`).
    pub fn dir(&self) -> &Path {
        &self.package_dir
    }
}

/// Reject anything that could escape the extraction root: absolute paths, `..`,
/// Windows drive prefixes, and empty components.
fn is_safe_component(component: &str) -> bool {
    !component.is_empty()
        && component != ".."
        && component != "."
        && !component.contains('\0')
        && !component.contains(':')
}

/// Validate an archive member name and return it as a relative path, or `None` if
/// it is unsafe.
fn safe_relative_path(name: &str) -> Option<PathBuf> {
    if name.starts_with('/') || name.starts_with('\\') {
        return None;
    }
    let mut out = PathBuf::new();
    for component in name.split(['/', '\\']) {
        if component.is_empty() {
            // A trailing slash on a directory entry is normal.
            continue;
        }
        if !is_safe_component(component) {
            return None;
        }
        out.push(component);
    }
    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Local cache path for a sample, mirroring the dataset's own layout so the cache
/// is self-describing.
fn cache_path(sample_path: &str, samples_dir: &Path) -> Option<PathBuf> {
    let rel = safe_relative_path(sample_path)?;
    Some(samples_dir.join(rel))
}

/// Download a sample zip into the cache if it is not already there.
fn ensure_cached(sample_path: &str, samples_dir: &Path) -> Result<PathBuf, String> {
    let dest = cache_path(sample_path, samples_dir)
        .ok_or_else(|| format!("unsafe sample path: {}", sample_path))?;

    if dest.is_file() && std::fs::metadata(&dest).map(|m| m.len() > 0).unwrap_or(false) {
        return Ok(dest);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("could not create {}: {}", parent.display(), e))?;
    }

    let url = format!("{}/{}", RAW_BASE, sample_path);
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(concat!("npm-pre-scan/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("could not build HTTP client: {}", e))?;

    let resp = client
        .get(&url)
        .send()
        .map_err(|e| format!("download failed: {}", e))?;
    if !resp.status().is_success() {
        return Err(format!("download failed: http {}", resp.status().as_u16()));
    }
    let bytes = resp
        .bytes()
        .map_err(|e| format!("download failed while reading body: {}", e))?;
    if bytes.is_empty() {
        return Err("downloaded sample was empty".to_string());
    }

    // Write via a temporary name and rename, so an interrupted download can never
    // leave a truncated zip in the cache to be reused later.
    let tmp = dest.with_extension("zip.part");
    std::fs::write(&tmp, &bytes).map_err(|e| format!("could not write cache file: {}", e))?;
    std::fs::rename(&tmp, &dest).map_err(|e| format!("could not finalize cache file: {}", e))?;
    Ok(dest)
}

/// Locate the npm package root inside an extracted sample: the shallowest
/// directory that directly contains a `package.json`.
///
/// Searched rather than assumed, because the archive preserves whatever absolute
/// temp path the collector happened to use. That depth varies a lot: Linux-
/// collected samples nest under `tmp/<random>/<name>/package/` (depth 4), while
/// macOS-collected ones nest under
/// `var/folders/<a>/<b>/T/<random>/<name>/package/` (depth 7). An earlier
/// `max_depth(8)` silently skipped 38 of 499 samples in one run — a harness bug
/// that looked exactly like a corpus gap, so the bound is now well clear of any
/// plausible layout.
const MAX_SEARCH_DEPTH: usize = 24;

fn find_package_root(root: &Path) -> Option<PathBuf> {
    let mut best: Option<(usize, PathBuf)> = None;
    for entry in walkdir::WalkDir::new(root)
        .max_depth(MAX_SEARCH_DEPTH)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() || entry.file_name() != "package.json" {
            continue;
        }
        let Some(dir) = entry.path().parent() else {
            continue;
        };
        let depth = dir.components().count();
        if best.as_ref().is_none_or(|(d, _)| depth < *d) {
            best = Some((depth, dir.to_path_buf()));
        }
    }
    best.map(|(_, p)| p)
}

/// Extract an encrypted sample zip into `dest`.
///
/// Uses ZipCrypto decryption (`legacy-zip`), which is what the dataset's archives
/// use. Members are written one at a time through `safe_relative_path` instead of
/// via a bulk extractor, so a malicious member name cannot write outside `dest`.
fn extract_encrypted(zip_path: &Path, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(zip_path)
        .map_err(|e| format!("could not open {}: {}", zip_path.display(), e))?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))
        .map_err(|e| format!("not a readable zip: {}", e))?;

    let mut wrote_any = false;
    for i in 0..archive.len() {
        // `by_index_decrypt` handles both encrypted and stored-plaintext members,
        // which matters because these archives leave directory entries unencrypted.
        let mut member = match archive.by_index_decrypt(i, ZIP_PASSWORD) {
            Ok(m) => m,
            Err(e) => return Err(format!("could not decrypt member {}: {}", i, e)),
        };

        let name = member.name().to_string();
        if member.is_dir() {
            continue;
        }
        let Some(rel) = safe_relative_path(&name) else {
            // A traversal attempt is worth surfacing, not silently skipping.
            return Err(format!("archive member escapes the extraction root: {}", name));
        };
        let out_path = dest.join(rel);
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("could not create {}: {}", parent.display(), e))?;
        }

        let mut buf = Vec::new();
        member
            .read_to_end(&mut buf)
            .map_err(|e| format!("could not read member {}: {}", name, e))?;
        std::fs::write(&out_path, &buf)
            .map_err(|e| format!("could not write {}: {}", out_path.display(), e))?;
        wrote_any = true;
    }

    if wrote_any {
        Ok(())
    } else {
        Err("archive contained no files".to_string())
    }
}

/// Fetch (if needed) and extract a sample, returning a scannable package root.
///
/// The returned `PreparedSample` owns the temporary directory: the plaintext
/// exists only while the caller holds it.
pub fn prepare(sample_path: &str, samples_dir: &Path) -> Result<PreparedSample, String> {
    let zip_path = ensure_cached(sample_path, samples_dir)?;

    let tmp = TempDir::new().map_err(|e| format!("could not create temp dir: {}", e))?;
    extract_encrypted(&zip_path, tmp.path())?;

    let package_dir = find_package_root(tmp.path())
        .ok_or_else(|| "no package.json found in the extracted sample".to_string())?;

    Ok(PreparedSample {
        _tmp: tmp,
        package_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // No test here downloads anything — the network path is exercised by the
    // Docker-gated integration test, matching this repo's convention of keeping
    // `cargo test` offline.

    #[test]
    fn safe_relative_path_accepts_ordinary_member_names() {
        assert_eq!(
            safe_relative_path("tmp/abc/pkg/package/index.js"),
            Some(PathBuf::from("tmp/abc/pkg/package/index.js"))
        );
        // A trailing slash (directory entry) is normal and must not be rejected.
        assert_eq!(
            safe_relative_path("tmp/abc/"),
            Some(PathBuf::from("tmp/abc"))
        );
    }

    #[test]
    fn safe_relative_path_rejects_traversal_and_absolute_paths() {
        // These are exactly the member names a hostile archive would use.
        for bad in [
            "../escape.js",
            "tmp/../../escape.js",
            "/etc/passwd",
            "\\windows\\system32",
            "C:/windows",
            "tmp/..",
            "",
        ] {
            assert_eq!(safe_relative_path(bad), None, "accepted unsafe path {:?}", bad);
        }
    }

    #[test]
    fn is_safe_component_rejects_dots_nulls_and_drive_letters() {
        assert!(is_safe_component("package"));
        assert!(is_safe_component("index.js"));
        assert!(is_safe_component("@scope"));
        assert!(!is_safe_component(".."));
        assert!(!is_safe_component("."));
        assert!(!is_safe_component(""));
        assert!(!is_safe_component("a\0b"));
        assert!(!is_safe_component("C:"));
    }

    #[test]
    fn cache_path_mirrors_the_dataset_layout_under_the_samples_dir() {
        let dir = Path::new("/tmp/samples");
        assert_eq!(
            cache_path("malicious_intent/evil/1.0.0/2025-01-01-evil-v1.0.0.zip", dir),
            Some(PathBuf::from(
                "/tmp/samples/malicious_intent/evil/1.0.0/2025-01-01-evil-v1.0.0.zip"
            ))
        );
        // An unsafe sample path must not resolve to a cache location at all.
        assert_eq!(cache_path("../../etc/passwd", dir), None);
    }

    #[test]
    fn find_package_root_picks_the_shallowest_package_json() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();

        // Mirrors the real archive shape, plus a nested node_modules package.json
        // that must NOT win.
        let outer = root.join("tmp/abc123/evil-pkg/package");
        let inner = outer.join("node_modules/dep");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::write(outer.join("package.json"), "{}").unwrap();
        std::fs::write(inner.join("package.json"), "{}").unwrap();

        assert_eq!(find_package_root(root), Some(outer));
    }

    #[test]
    fn find_package_root_reaches_the_macos_collected_layout() {
        // Samples collected on macOS keep the collector's absolute temp path,
        // which is three components deeper than the Linux one. A depth bound
        // that stops short of this silently skips those samples and looks like a
        // corpus gap rather than a harness bug.
        let tmp = TempDir::new().unwrap();
        let deep = tmp
            .path()
            .join("var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmp2a0zq42w/vinext-monorepo/package");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("package.json"), "{}").unwrap();
        assert_eq!(find_package_root(tmp.path()), Some(deep));
    }

    #[test]
    fn find_package_root_returns_none_when_there_is_no_package() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("readme.txt"), "hi").unwrap();
        assert_eq!(find_package_root(tmp.path()), None);
    }

    #[test]
    fn extract_reports_a_useful_error_for_a_non_zip() {
        let tmp = TempDir::new().unwrap();
        let fake = tmp.path().join("not.zip");
        std::fs::write(&fake, b"definitely not a zip archive").unwrap();
        let dest = TempDir::new().unwrap();
        let err = extract_encrypted(&fake, dest.path()).unwrap_err();
        assert!(err.contains("not a readable zip"), "got: {}", err);
    }

    #[test]
    fn prepare_fails_cleanly_when_the_sample_path_is_unsafe() {
        let dir = TempDir::new().unwrap();
        let err = prepare("../../etc/passwd", dir.path()).unwrap_err();
        assert!(err.contains("unsafe sample path"), "got: {}", err);
    }
}
