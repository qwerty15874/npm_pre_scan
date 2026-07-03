// Optional runtime extensibility for detection lists.
//
// Operators can extend two compiled-in detection lists WITHOUT recompiling by
// pointing an env var at a plain-text file (same one-per-line, `#`-comment
// format as data/worm_iocs.txt). The runtime file is MERGED with the embedded
// defaults, never replaces them. Missing/unreadable file = silently ignored —
// a bad runtime file must never break a scan.

use std::collections::HashSet;

/// Parse `embedded` and (if present) `extra` with identical rules — split
/// lines, trim, skip empty lines and `#`-comments, lowercase — and union them
/// into one set. Pure, no I/O; this is the unit-tested core.
pub(crate) fn merge_lines(embedded: &str, extra: Option<&str>) -> HashSet<String> {
    fn parse(text: &str, out: &mut HashSet<String>) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            out.insert(line.to_lowercase());
        }
    }

    let mut out = HashSet::new();
    parse(embedded, &mut out);
    if let Some(extra) = extra {
        parse(extra, &mut out);
    }
    out
}

/// Read the file pointed to by `env_key` (if set) and merge its contents with
/// `embedded`. Any error (env var unset, file missing/unreadable) is treated
/// as "no extra file" — this function never panics and never errors.
pub fn merge_runtime_lines(embedded: &str, env_key: &str) -> HashSet<String> {
    let extra = std::env::var(env_key)
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok());
    merge_lines(embedded, extra.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_only_no_extra() {
        let set = merge_lines("aaa\nbbb\n", None);
        assert_eq!(set.len(), 2);
        assert!(set.contains("aaa"));
        assert!(set.contains("bbb"));
    }

    #[test]
    fn embedded_plus_extra_union() {
        let set = merge_lines("aaa\nbbb\n", Some("ccc\nddd\n"));
        assert_eq!(set.len(), 4);
        for v in ["aaa", "bbb", "ccc", "ddd"] {
            assert!(set.contains(v), "missing {}", v);
        }
    }

    #[test]
    fn extra_comments_and_blank_lines_skipped() {
        let set = merge_lines("aaa\n", Some("# a comment\n\n   \nbbb\n#another\n"));
        assert_eq!(set.len(), 2);
        assert!(set.contains("aaa"));
        assert!(set.contains("bbb"));
        assert!(!set.iter().any(|s| s.starts_with('#')));
    }

    #[test]
    fn case_folding_applies_to_both_sources() {
        let set = merge_lines("AAA\n", Some("BbB\n"));
        assert!(set.contains("aaa"));
        assert!(set.contains("bbb"));
        assert!(!set.contains("AAA"));
        assert!(!set.contains("BbB"));
    }

    #[test]
    fn empty_extra_string_contributes_nothing() {
        let set = merge_lines("aaa\n", Some(""));
        assert_eq!(set.len(), 1);
        assert!(set.contains("aaa"));
    }

    #[test]
    fn none_extra_same_as_embedded_only() {
        let with_none = merge_lines("aaa\nbbb\n", None);
        let with_empty = merge_lines("aaa\nbbb\n", Some(""));
        assert_eq!(with_none, with_empty);
    }
}
