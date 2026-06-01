use anyhow::Result;
use flate2::read::GzDecoder;
use serde_json::Value;
use std::io::Cursor;
use tar::Archive;
use tempfile::TempDir;

pub fn get_tarball_url(info: &Value) -> Option<String> {
    let latest = info.get("dist-tags")?.get("latest")?.as_str()?;
    info.get("versions")?
        .get(latest)?
        .get("dist")?
        .get("tarball")?
        .as_str()
        .map(|s| s.to_string())
}

pub fn get_latest_version_pkg_json(info: &Value) -> Option<Value> {
    let latest = info.get("dist-tags")?.get("latest")?.as_str()?;
    Some(info.get("versions")?.get(latest)?.clone())
}

/// Tarball URL for a specific version.
pub fn get_version_tarball_url(info: &Value, version: &str) -> Option<String> {
    info.get("versions")?
        .get(version)?
        .get("dist")?
        .get("tarball")?
        .as_str()
        .map(|s| s.to_string())
}

pub fn download_and_extract(tarball_url: &str) -> Result<TempDir> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent("npm-pre-scan/0.1")
        .build()?;

    let bytes = client.get(tarball_url).send()?.bytes()?;
    let tmp = TempDir::new()?;

    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(gz);
    archive.unpack(tmp.path())?;

    Ok(tmp)
}
