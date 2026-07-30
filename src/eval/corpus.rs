// Corpus manifest parsing for the evaluation harness.
//
// A manifest is a tab-separated ground-truth file (see eval/README.md). The line
// discipline matches the existing `data/*.txt` lists — trim, skip blank, skip
// `#` — but a manifest carries six or seven columns instead of one bare name.
//
// This module is pure: no filesystem, no network, no clock. `parse_manifest`
// takes the text and a display path (for error messages) and returns either the
// entries or *every* malformed line, so one run surfaces all manifest problems
// rather than one per attempt.
//
// Parse errors are fatal to a batch by design (see `EvalError` handling in
// `runner`). A manifest that silently shrinks corrupts the denominators of every
// metric computed from it — the same reasoning behind `toplist::MIN_ACCEPT`
// rejecting a short sweep instead of accepting partial coverage.

use std::collections::HashMap;
use std::fmt;

/// Every attack-vector tag a finding may carry, and therefore the only values
/// accepted in a manifest's `vectors` column. Mirrors the `vector` field set
/// emitted across `checker`/`layer1`/`layer2`/`layer3` (see CLAUDE.md's coverage
/// matrix). Validating against a closed set means a typo (`Z9`, `A11`) is a
/// parse error rather than a vector that silently never matches and quietly
/// reports zero recall.
pub const VECTORS: &[&str] = &[
    "A1", "A2", "A3", "A4", "META", "B1", "B2", "B3", "B4", "C1", "C2", "C3", "D1", "D2", "D3",
    "E1",
];

/// How a corpus entry is reached by the scanner.
///
/// The first three are execution paths; `Holder` and `Sample` additionally carry
/// ground-truth meaning that must NOT be inferred at scan time (see the
/// `Holder` doc below).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Registry name, scanned at `dist-tags.latest`.
    Name,
    /// `name@version` — tarball pinned via `tarball::get_version_tarball_url`.
    Version,
    /// Local directory. Layer 0 never applies (no registry identity, matching
    /// `report::run_full_local`).
    Dir,
    /// A registry name npm replaced with a *security holding* stub. The registry
    /// answers HTTP 200, but the content is either absent or (verified
    /// 2026-07-30) republished defanged, so a content-layer PASS is truthful
    /// rather than a miss and is classified `ARTIFACT_FN`.
    ///
    /// This is a manifest annotation on purpose. Sniffing it at runtime (e.g.
    /// `description == "security holding package"`) would let the harness decide
    /// its own ground truth, which is how an evaluation ends up grading itself.
    Holder,
    /// A path under `samples/npm/` in the DataDog dataset, fetched as an
    /// encrypted zip.
    Sample,
}

impl Kind {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "name" => Some(Kind::Name),
            "version" => Some(Kind::Version),
            "dir" => Some(Kind::Dir),
            "holder" => Some(Kind::Holder),
            "sample" => Some(Kind::Sample),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Name => "name",
            Kind::Version => "version",
            Kind::Dir => "dir",
            Kind::Holder => "holder",
            Kind::Sample => "sample",
        }
    }

    /// True when the entry has a registry identity, i.e. Layer 0 is applicable.
    /// `Dir` and `Sample` come from local content with no name to look up.
    pub fn has_registry_identity(&self) -> bool {
        matches!(self, Kind::Name | Kind::Version | Kind::Holder)
    }
}

/// Which corpus bucket an entry belongs to. Reported separately in the metrics
/// so "recall on real malware" and "recall on our own dummies" never blend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    RealMalicious,
    Dummy,
    ParentBenign,
    Datadog,
}

impl Group {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "real_malicious" => Some(Group::RealMalicious),
            "dummy" => Some(Group::Dummy),
            "parent_benign" => Some(Group::ParentBenign),
            "datadog" => Some(Group::Datadog),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Group::RealMalicious => "real_malicious",
            Group::Dummy => "dummy",
            Group::ParentBenign => "parent_benign",
            Group::Datadog => "datadog",
        }
    }
}

/// The ground truth. Deliberately independent of `Group`: `dummy_benign_l3` is
/// `Dummy`/`Benign`, and the three reclaimed 2017-campaign names are
/// `RealMalicious`/`Benign`. Keeping the axes separate is what lets per-group
/// metrics be computed without special-casing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Malicious,
    Benign,
}

impl Label {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "malicious" => Some(Label::Malicious),
            "benign" => Some(Label::Benign),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Label::Malicious => "malicious",
            Label::Benign => "benign",
        }
    }
}

/// One ground-truth corpus entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusEntry {
    pub kind: Kind,
    /// The raw `id` column, verbatim. Interpretation depends on `kind`; use
    /// `package`/`version`/`path` for the parsed forms.
    pub id: String,
    pub group: Group,
    pub label: Label,
    /// Expected vectors, validated against `VECTORS`. Empty for `-`.
    pub vectors: Vec<String>,
    /// Applicable layers, sorted and deduplicated. Empty for `-`.
    pub layers: Vec<u8>,
    pub note: Option<String>,
    /// Package name: `id` for `Name`/`Holder`, the part before the final `@` for
    /// `Version`, the trailing path component for `Dir`, and the
    /// `@scope@name` → `@scope/name` decoded directory for `Sample`.
    pub package: String,
    /// Pinned version, for `Version` and `Sample` only.
    pub version: Option<String>,
    /// Filesystem or dataset path, for `Dir` and `Sample` only.
    pub path: Option<String>,
    /// Manifest this entry came from, and its 1-based line number. Carried so a
    /// record can be traced back to the line that produced it.
    pub source: String,
    pub line_no: usize,
}

impl CorpusEntry {
    /// Stable identifier used as the primary key across all output artifacts.
    /// Namespaced by kind so a local directory and a registry name of the same
    /// spelling cannot collide.
    pub fn entry_id(&self) -> String {
        match self.kind {
            Kind::Name | Kind::Holder => self.package.clone(),
            Kind::Version => format!("{}@{}", self.package, self.version.as_deref().unwrap_or("")),
            Kind::Dir => format!("dir:{}", self.path.as_deref().unwrap_or("")),
            Kind::Sample => format!("sample:{}", self.path.as_deref().unwrap_or("")),
        }
    }
}

/// A malformed manifest line, with enough context to fix it without re-running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub path: String,
    pub line_no: usize,
    pub line: String,
    pub reason: String,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}: {}\n  | {}",
            self.path, self.line_no, self.reason, self.line
        )
    }
}

/// Split a comma-separated column, honouring `-` as "empty".
fn split_list(field: &str) -> Vec<&str> {
    if field == "-" {
        return Vec::new();
    }
    field
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_vectors(field: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for tok in split_list(field) {
        if !VECTORS.contains(&tok) {
            return Err(format!(
                "unknown vector '{}' (expected one of {})",
                tok,
                VECTORS.join(", ")
            ));
        }
        if !out.iter().any(|v| v == tok) {
            out.push(tok.to_string());
        }
    }
    Ok(out)
}

fn parse_layers(field: &str) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new();
    for tok in split_list(field) {
        let n: u8 = match tok.parse() {
            Ok(n) if n <= 3 => n,
            _ => return Err(format!("invalid layer '{}' (expected 0, 1, 2 or 3)", tok)),
        };
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// Decode the DataDog dataset's flattened scope form: the directory component is
/// `@scope@name` while the zip *filename* uses `@scope_name`. Storing the full
/// path in the manifest and decoding the directory here avoids reconstructing a
/// filename from a package name (which that inconsistency makes lossy).
fn decode_sample_dir(dir: &str) -> String {
    match dir.strip_prefix('@') {
        Some(rest) => match rest.split_once('@') {
            Some((scope, name)) => format!("@{}/{}", scope, name),
            None => dir.to_string(),
        },
        None => dir.to_string(),
    }
}

/// Derive `package` / `version` / `path` from `kind` and the `id` column.
fn derive_identity(
    kind: Kind,
    id: &str,
) -> Result<(String, Option<String>, Option<String>), String> {
    match kind {
        Kind::Name | Kind::Holder => Ok((id.to_string(), None, None)),

        Kind::Version => {
            // Split on the LAST '@' so scoped names survive: `@scope/name@1.2.3`.
            let at = id.rfind('@').filter(|&i| i > 0);
            match at {
                Some(i) => {
                    let (name, ver) = (&id[..i], &id[i + 1..]);
                    if name.is_empty() || ver.is_empty() {
                        Err("expected 'name@version'".to_string())
                    } else {
                        Ok((name.to_string(), Some(ver.to_string()), None))
                    }
                }
                None => Err("expected 'name@version' (no '@' found)".to_string()),
            }
        }

        Kind::Dir => {
            let name = id
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "empty directory path".to_string())?;
            Ok((name.to_string(), None, Some(id.to_string())))
        }

        Kind::Sample => {
            // <category>/<pkgdir>/<version>/<file>.zip
            let parts: Vec<&str> = id.split('/').collect();
            if parts.len() < 4 || !id.ends_with(".zip") {
                return Err(
                    "expected '<category>/<package>/<version>/<file>.zip'".to_string()
                );
            }
            Ok((
                decode_sample_dir(parts[1]),
                Some(parts[2].to_string()),
                Some(id.to_string()),
            ))
        }
    }
}

/// Parse one manifest. Returns every malformed line rather than stopping at the
/// first, so a single run tells the operator everything that needs fixing.
///
/// `path` is used only for error messages and provenance — this function does no
/// I/O.
pub fn parse_manifest(text: &str, path: &str) -> Result<Vec<CorpusEntry>, Vec<ManifestError>> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut err = |reason: String| {
            errors.push(ManifestError {
                path: path.to_string(),
                line_no,
                line: line.to_string(),
                reason,
            });
        };

        let fields: Vec<&str> = line.split('\t').map(|f| f.trim()).collect();
        if fields.len() < 6 || fields.len() > 7 {
            err(format!(
                "expected 6 or 7 tab-separated columns (kind id group label vectors layers [note]), found {}",
                fields.len()
            ));
            continue;
        }

        let kind = match Kind::parse(fields[0]) {
            Some(k) => k,
            None => {
                err(format!(
                    "unknown kind '{}' (expected name, version, dir, holder or sample)",
                    fields[0]
                ));
                continue;
            }
        };
        let id = fields[1];
        if id.is_empty() {
            err("empty id".to_string());
            continue;
        }
        let group = match Group::parse(fields[2]) {
            Some(g) => g,
            None => {
                err(format!(
                    "unknown group '{}' (expected real_malicious, dummy, parent_benign or datadog)",
                    fields[2]
                ));
                continue;
            }
        };
        let label = match Label::parse(fields[3]) {
            Some(l) => l,
            None => {
                err(format!(
                    "unknown label '{}' (expected malicious or benign)",
                    fields[3]
                ));
                continue;
            }
        };
        let vectors = match parse_vectors(fields[4]) {
            Ok(v) => v,
            Err(e) => {
                err(e);
                continue;
            }
        };
        let layers = match parse_layers(fields[5]) {
            Ok(l) => l,
            Err(e) => {
                err(e);
                continue;
            }
        };
        let (package, version, entry_path) = match derive_identity(kind, id) {
            Ok(t) => t,
            Err(e) => {
                err(format!("bad id '{}': {}", id, e));
                continue;
            }
        };

        // A `dir` or `sample` entry has no name to look up, so requesting Layer 0
        // for it is a manifest mistake rather than something to silently drop.
        if !kind.has_registry_identity() && layers.contains(&0) {
            err(format!(
                "kind '{}' has no registry identity, so layer 0 is not applicable",
                kind.as_str()
            ));
            continue;
        }

        let note = fields
            .get(6)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && *s != "-")
            .map(|s| s.to_string());

        entries.push(CorpusEntry {
            kind,
            id: id.to_string(),
            group,
            label,
            vectors,
            layers,
            note,
            package,
            version,
            path: entry_path,
            source: path.to_string(),
            line_no,
        });
    }

    if errors.is_empty() {
        Ok(entries)
    } else {
        Err(errors)
    }
}

/// Concatenate several already-parsed manifests, rejecting duplicate
/// `entry_id`s. A duplicate would be counted twice in every metric, so it is an
/// error rather than something to deduplicate silently.
pub fn merge_manifests(
    parsed: Vec<Vec<CorpusEntry>>,
) -> Result<Vec<CorpusEntry>, Vec<ManifestError>> {
    let mut out: Vec<CorpusEntry> = Vec::new();
    let mut errors = Vec::new();
    // Keyed lookup rather than a linear scan: the largest manifest holds ~217k
    // entries, where an O(n²) duplicate check would run for hours.
    let mut seen: HashMap<String, (String, usize)> = HashMap::new();

    for entries in parsed {
        for entry in entries {
            let id = entry.entry_id();
            if let Some((prev_source, prev_line)) = seen.get(&id) {
                errors.push(ManifestError {
                    path: entry.source.clone(),
                    line_no: entry.line_no,
                    line: entry.id.clone(),
                    reason: format!(
                        "duplicate entry_id '{}' (already defined at {}:{})",
                        id, prev_source, prev_line
                    ),
                });
                continue;
            }
            seen.insert(id, (entry.source.clone(), entry.line_no));
            out.push(entry);
        }
    }

    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_name_entry() {
        let e = &parse_manifest(
            "name\texpres\tdummy\tmalicious\tA1\t0\tnote here",
            "m.tsv",
        )
        .unwrap()[0];
        assert_eq!(e.kind, Kind::Name);
        assert_eq!(e.package, "expres");
        assert_eq!(e.group, Group::Dummy);
        assert_eq!(e.label, Label::Malicious);
        assert_eq!(e.vectors, vec!["A1"]);
        assert_eq!(e.layers, vec![0]);
        assert_eq!(e.note.as_deref(), Some("note here"));
        assert_eq!(e.line_no, 1);
        assert_eq!(e.entry_id(), "expres");
    }

    #[test]
    fn note_column_is_optional_and_dash_means_none() {
        let entries =
            parse_manifest("name\ta\tdummy\tbenign\t-\t0\nname\tb\tdummy\tbenign\t-\t0\t-", "m")
                .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.note.is_none()));
        assert!(entries.iter().all(|e| e.vectors.is_empty()));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let text = "# header\n\n   \nname\ta\tdummy\tbenign\t-\t0\n# trailing\n";
        let entries = parse_manifest(text, "m").unwrap();
        assert_eq!(entries.len(), 1);
        // Line number is the real file line, not the index among data rows.
        assert_eq!(entries[0].line_no, 4);
    }

    #[test]
    fn version_kind_splits_on_the_last_at_so_scopes_survive() {
        let e = &parse_manifest("version\t@ctrl/tinycolor@4.1.1\tdatadog\tmalicious\tE1\t1", "m")
            .unwrap()[0];
        assert_eq!(e.package, "@ctrl/tinycolor");
        assert_eq!(e.version.as_deref(), Some("4.1.1"));
        assert_eq!(e.entry_id(), "@ctrl/tinycolor@4.1.1");
    }

    #[test]
    fn dir_kind_takes_the_trailing_component_as_the_package_name() {
        let e = &parse_manifest(
            "dir\tdummy_packages/dummy_shai_hulud/infected\tdummy\tmalicious\tE1\t1,2,3",
            "m",
        )
        .unwrap()[0];
        assert_eq!(e.package, "infected");
        assert_eq!(e.path.as_deref(), Some("dummy_packages/dummy_shai_hulud/infected"));
        assert_eq!(e.entry_id(), "dir:dummy_packages/dummy_shai_hulud/infected");
    }

    #[test]
    fn sample_kind_decodes_the_flattened_scope_form() {
        let e = &parse_manifest(
            "sample\tcompromised_lib/@ctrl@tinycolor/4.1.1/2025-09-15-@ctrl_tinycolor-v4.1.1.zip\tdatadog\tmalicious\tE1\t1,2,3",
            "m",
        )
        .unwrap()[0];
        assert_eq!(e.package, "@ctrl/tinycolor");
        assert_eq!(e.version.as_deref(), Some("4.1.1"));
        assert!(e.entry_id().starts_with("sample:compromised_lib/"));
    }

    #[test]
    fn unscoped_sample_dir_is_left_alone() {
        let e = &parse_manifest(
            "sample\tmalicious_intent/evil/1.0.0/2025-01-01-evil-v1.0.0.zip\tdatadog\tmalicious\t-\t1",
            "m",
        )
        .unwrap()[0];
        assert_eq!(e.package, "evil");
    }

    #[test]
    fn layers_are_sorted_and_deduplicated() {
        let e = &parse_manifest("name\ta\tdummy\tbenign\t-\t3,1,0,1", "m").unwrap()[0];
        assert_eq!(e.layers, vec![0, 1, 3]);
    }

    #[test]
    fn vectors_are_deduplicated_preserving_first_occurrence() {
        let e = &parse_manifest("name\ta\tdummy\tmalicious\tB2,A1,B2\t0", "m").unwrap()[0];
        assert_eq!(e.vectors, vec!["B2", "A1"]);
    }

    #[test]
    fn wrong_column_count_errors_with_the_line_number() {
        let errs = parse_manifest("# ok\nname\ta\tdummy\tbenign\t-", "m.tsv").unwrap_err();
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].line_no, 2);
        assert!(errs[0].reason.contains("6 or 7"));
        assert_eq!(errs[0].path, "m.tsv");
    }

    #[test]
    fn too_many_columns_also_errors() {
        let errs = parse_manifest("name\ta\tdummy\tbenign\t-\t0\tnote\textra", "m").unwrap_err();
        assert!(errs[0].reason.contains("found 8"));
    }

    #[test]
    fn unknown_kind_group_and_label_each_error() {
        for (line, needle) in [
            ("tarball\ta\tdummy\tbenign\t-\t0", "unknown kind"),
            ("name\ta\tmystery\tbenign\t-\t0", "unknown group"),
            ("name\ta\tdummy\tperhaps\t-\t0", "unknown label"),
        ] {
            let errs = parse_manifest(line, "m").unwrap_err();
            assert!(
                errs[0].reason.contains(needle),
                "{} did not report {}",
                line,
                needle
            );
        }
    }

    #[test]
    fn unknown_vector_token_is_a_parse_error_not_a_silent_zero() {
        let errs = parse_manifest("name\ta\tdummy\tmalicious\tZ9\t0", "m").unwrap_err();
        assert!(errs[0].reason.contains("unknown vector 'Z9'"));
    }

    #[test]
    fn out_of_range_layer_errors() {
        let errs = parse_manifest("name\ta\tdummy\tbenign\t-\t4", "m").unwrap_err();
        assert!(errs[0].reason.contains("invalid layer '4'"));
    }

    #[test]
    fn layer_zero_on_a_local_kind_is_rejected() {
        let errs = parse_manifest("dir\tsome/dir\tdummy\tbenign\t-\t0,1", "m").unwrap_err();
        assert!(errs[0].reason.contains("no registry identity"));
    }

    #[test]
    fn malformed_version_and_sample_ids_error() {
        let errs = parse_manifest("version\tnoversion\tdummy\tmalicious\t-\t1", "m").unwrap_err();
        assert!(errs[0].reason.contains("name@version"));
        let errs = parse_manifest("sample\ttoo/short\tdatadog\tmalicious\t-\t1", "m").unwrap_err();
        assert!(errs[0].reason.contains(".zip"));
    }

    #[test]
    fn every_bad_line_is_reported_not_just_the_first() {
        let text = "name\ta\tnope\tbenign\t-\t0\nname\tb\tdummy\tmalicious\tZ9\t0\nname\tc\tdummy\tbenign\t-\t9";
        let errs = parse_manifest(text, "m").unwrap_err();
        assert_eq!(errs.len(), 3);
        assert_eq!(
            errs.iter().map(|e| e.line_no).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn merge_rejects_a_duplicate_entry_id_across_manifests() {
        let a = parse_manifest("name\tdup\tdummy\tmalicious\t-\t0", "a.tsv").unwrap();
        let b = parse_manifest("name\tdup\tparent_benign\tbenign\t-\t0", "b.tsv").unwrap();
        let errs = merge_manifests(vec![a, b]).unwrap_err();
        assert_eq!(errs.len(), 1);
        assert!(errs[0].reason.contains("duplicate entry_id 'dup'"));
        assert!(errs[0].reason.contains("a.tsv:1"));
    }

    #[test]
    fn merge_keeps_distinct_kinds_of_the_same_spelling_apart() {
        let a = parse_manifest("name\tlodash\tparent_benign\tbenign\t-\t0", "a").unwrap();
        let b = parse_manifest("dir\tsomewhere/lodash\tdummy\tbenign\t-\t1", "b").unwrap();
        let merged = merge_manifests(vec![a, b]).unwrap();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn kind_registry_identity_matches_the_scan_paths() {
        assert!(Kind::Name.has_registry_identity());
        assert!(Kind::Version.has_registry_identity());
        assert!(Kind::Holder.has_registry_identity());
        assert!(!Kind::Dir.has_registry_identity());
        assert!(!Kind::Sample.has_registry_identity());
    }

    #[test]
    fn every_vector_tag_round_trips() {
        for v in VECTORS {
            let line = format!("name\ta\tdummy\tmalicious\t{}\t0", v);
            assert_eq!(parse_manifest(&line, "m").unwrap()[0].vectors, vec![*v]);
        }
    }
}
