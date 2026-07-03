// Layer 3: profile diffing — pure function, no I/O.
//
// Diffs a mutated-scenario `Layer2Profile` against a clean baseline profile
// captured in the same container run, returning only the events that are new
// under mutation. This is what turns "everything npm/node does anyway" into
// "what changed because we lied about the clock / environment / API usage" —
// and it also cancels Layer 2's known toolchain noise (`.npmrc`, `/etc/passwd`
// reads happen in both baseline and mutated, so they subtract out).

use std::collections::HashSet;

use crate::layer2::profile::Layer2Profile;

/// Normalize a filesystem path before differencing so nondeterministic paths
/// (tmp dirs, PIDs, npm cache dirs, npm debug logs, lockfile temp names) don't
/// create false "new events" between baseline and mutated/real runs.
fn normalize_path(path: &str) -> String {
    // /proc/<pid>/... -> /proc/PID/...
    if let Some(rest) = path.strip_prefix("/proc/") {
        if let Some(slash) = rest.find('/') {
            let (pid, tail) = rest.split_at(slash);
            if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
                return format!("/proc/PID{}", tail);
            }
        }
    }
    // /tmp/<anything> -> /tmp/TMP (temp dirs are randomly named per run)
    if path.starts_with("/tmp/") {
        return "/tmp/TMP".to_string();
    }
    // npm cache / npx temp dirs, e.g. /root/.npm/_cacache/..., /home/*/.npm/...
    if path.contains("/.npm/_cacache/") {
        return "/NPM_CACHE".to_string();
    }
    // npm debug logs, e.g. /root/.npm/_logs/2026-07-01T12_00_00_000Z-debug-0.log
    // — timestamped per invocation, never the same name twice.
    if path.contains("/.npm/_logs/") {
        return "/NPM_LOGS".to_string();
    }
    // npm's lockfile / temp lock artifacts written during `npm install`, e.g.
    // node_modules/.package-lock.json, .package-lock.json.<random>.tmp — the
    // random suffix (or even just presence/absence timing) makes these
    // nondeterministic between the baseline and real install runs.
    if path.contains("package-lock.json") {
        return "/PACKAGE_LOCK".to_string();
    }
    // npm's node_modules atomic-install staging dirs, e.g.
    // node_modules/.foo-a1b2c3d4/... — npm installs each package into a
    // randomly-suffixed staging directory before an atomic rename into place.
    // Fold any ".<name>-<random>" path segment under node_modules to a stable
    // token so this write/rename churn cancels between baseline and real runs.
    if path.contains("/node_modules/") {
        if let Some(folded) = fold_node_modules_staging_segment(path) {
            return folded;
        }
    }
    // Generic temp-file suffixes some installers/editors use for atomic
    // writes (e.g. `foo.tmp`, `foo~`) — the base name varies per run.
    if path.ends_with(".tmp") || path.ends_with('~') {
        return "/TMP_SUFFIXED".to_string();
    }
    path.to_string()
}

/// Fold a `.<name>-<random>` staging-directory segment under `node_modules`
/// (npm's atomic-install pattern) to a stable token. Returns `None` if no
/// path segment matches the pattern (dotfile followed by a `-` and a
/// hex/alphanumeric suffix), leaving the path unnormalized by this rule.
fn fold_node_modules_staging_segment(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').collect();
    let mut folded = false;
    let normalized: Vec<String> = segments
        .into_iter()
        .map(|seg| {
            if seg.starts_with('.') && seg.contains('-') && seg.len() > 1 {
                let after_dot = &seg[1..];
                // Require the segment to look like "name-randomsuffix": at
                // least one '-' separating a name from an alphanumeric tail.
                if let Some(dash) = after_dot.rfind('-') {
                    let suffix = &after_dot[dash + 1..];
                    if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_alphanumeric()) {
                        folded = true;
                        return "STAGING".to_string();
                    }
                }
            }
            seg.to_string()
        })
        .collect();
    if folded {
        Some(normalized.join("/"))
    } else {
        None
    }
}

fn normalized_set<'a, I: IntoIterator<Item = &'a String>>(items: I) -> HashSet<String> {
    items.into_iter().map(|s| normalize_path(s)).collect()
}

fn plain_set<'a, I: IntoIterator<Item = &'a String>>(items: I) -> HashSet<String> {
    items.into_iter().cloned().collect()
}

/// Return only the events present in `mutated` but absent from `baseline`.
/// Every field is compared as a set (order/duplicates don't matter); the
/// result is packed into a synthetic `Layer2Profile` with `phase = "import"`
/// so it can be run straight through `classify::classify`.
///
/// This is a back-compatible wrapper over `diff_profiles_phase` — all existing
/// Layer 3 callers (which only ever diff import-phase scenarios) are unchanged.
pub fn diff_profiles(baseline: &Layer2Profile, mutated: &Layer2Profile) -> Layer2Profile {
    diff_profiles_phase(baseline, mutated, "import")
}

/// Return only the events present in `mutated` but absent from `baseline`,
/// tagging the result with the given `phase` ("install" or "import") instead
/// of hardcoding "import". This is what lets Layer 2's baseline-subtraction
/// (Phase 2) diff install-phase runs and get a `phase == "install"` profile
/// back, so `classify::classify` applies the correct phase-dependent rules
/// (B1 for install, C1 for import).
///
/// Every field is compared as a set (order/duplicates don't matter).
pub fn diff_profiles_phase(
    baseline: &Layer2Profile,
    mutated: &Layer2Profile,
    phase: &str,
) -> Layer2Profile {
    let baseline_files = normalized_set(&baseline.file_opens);
    let mutated_files = normalized_set(&mutated.file_opens);
    let file_opens: Vec<String> = mutated_files
        .difference(&baseline_files)
        .cloned()
        .collect();

    let baseline_native = normalized_set(&baseline.native_modules);
    let mutated_native = normalized_set(&mutated.native_modules);
    let native_modules: Vec<String> = mutated_native
        .difference(&baseline_native)
        .cloned()
        .collect();

    let baseline_processes = plain_set(&baseline.processes);
    let mutated_processes = plain_set(&mutated.processes);
    let processes: Vec<String> = mutated_processes
        .difference(&baseline_processes)
        .cloned()
        .collect();

    let baseline_dns: HashSet<String> = baseline.dns_queries.iter().cloned().collect();
    let mutated_dns: HashSet<String> = mutated.dns_queries.iter().cloned().collect();
    let dns_queries: Vec<String> = mutated_dns.difference(&baseline_dns).cloned().collect();

    let baseline_connects: HashSet<(String, u16)> = baseline.connects.iter().cloned().collect();
    let mutated_connects: HashSet<(String, u16)> = mutated.connects.iter().cloned().collect();
    let connects: Vec<(String, u16)> = mutated_connects
        .difference(&baseline_connects)
        .cloned()
        .collect();

    let baseline_writes = normalized_set(&baseline.file_writes);
    let mutated_writes = normalized_set(&mutated.file_writes);
    let file_writes: Vec<String> = mutated_writes
        .difference(&baseline_writes)
        .cloned()
        .collect();

    let baseline_deletes = normalized_set(&baseline.file_deletes);
    let mutated_deletes = normalized_set(&mutated.file_deletes);
    let file_deletes: Vec<String> = mutated_deletes
        .difference(&baseline_deletes)
        .cloned()
        .collect();

    Layer2Profile {
        phase: phase.to_string(),
        processes,
        file_opens,
        connects,
        dns_queries,
        native_modules,
        file_writes,
        file_deletes,
    }
}

/// Maximum number of evidence lines attached to a Finding. The underlying
/// diff can be large (e.g. a wide DNS-tunneling fan-out); bounding this keeps
/// the JSON report and `--verbose` output readable.
const EVIDENCE_CAP: usize = 20;

/// Render a diff `Layer2Profile` (the output of `diff_profiles`/
/// `diff_profiles_phase` — i.e. only the NEW events under mutation or vs.
/// baseline) as a flat, human-readable evidence list: `"dns:evil.example.com"`,
/// `"connect:1.2.3.4:443"`, `"proc:/usr/bin/id"`, `"file:/etc/passwd"`,
/// `"write:/root/.bashrc"`, `"delete:/tmp/victim"`.
///
/// Pure/visibility-only: this does not feed back into classification or
/// scoring — it exists so a Finding can show WHICH exact new event triggered
/// it, instead of just the aggregate severity. Bounded to `EVIDENCE_CAP`
/// entries (processes, then file opens, then writes, then deletes, then dns
/// queries, then connects, in that order) so a large diff doesn't blow up
/// the report.
pub fn evidence_lines(diff: &Layer2Profile) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    lines.extend(diff.processes.iter().map(|p| format!("proc:{}", p)));
    lines.extend(diff.file_opens.iter().map(|p| format!("file:{}", p)));
    lines.extend(diff.file_writes.iter().map(|p| format!("write:{}", p)));
    lines.extend(diff.file_deletes.iter().map(|p| format!("delete:{}", p)));
    lines.extend(diff.dns_queries.iter().map(|q| format!("dns:{}", q)));
    lines.extend(
        diff.connects
            .iter()
            .map(|(ip, port)| format!("connect:{}:{}", ip, port)),
    );
    lines.truncate(EVIDENCE_CAP);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_profile() -> Layer2Profile {
        Layer2Profile {
            phase: "import".to_string(),
            processes: vec!["/usr/bin/node".to_string()],
            file_opens: vec!["/work/.npmrc".to_string(), "/etc/passwd".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn shared_noise_is_not_in_diff() {
        let baseline = base_profile();
        let mutated = base_profile(); // identical — pure toolchain noise
        let diff = diff_profiles(&baseline, &mutated);
        assert!(diff.file_opens.is_empty());
        assert!(diff.processes.is_empty());
        assert!(diff.dns_queries.is_empty());
        assert!(diff.connects.is_empty());
        assert!(diff.native_modules.is_empty());
    }

    #[test]
    fn mutated_only_dns_query_is_in_diff() {
        let baseline = base_profile();
        let mut mutated = base_profile();
        mutated.dns_queries.push("evil.example.com".to_string());
        let diff = diff_profiles(&baseline, &mutated);
        assert_eq!(diff.dns_queries, vec!["evil.example.com".to_string()]);
        // Shared noise still excluded.
        assert!(diff.file_opens.is_empty());
    }

    #[test]
    fn mutated_only_connect_is_in_diff() {
        let baseline = base_profile();
        let mut mutated = base_profile();
        mutated.connects.push(("5.6.7.8".to_string(), 443));
        let diff = diff_profiles(&baseline, &mutated);
        assert_eq!(diff.connects, vec![("5.6.7.8".to_string(), 443)]);
    }

    #[test]
    fn mutated_only_process_is_in_diff() {
        let baseline = base_profile();
        let mut mutated = base_profile();
        mutated.processes.push("/usr/bin/curl".to_string());
        let diff = diff_profiles(&baseline, &mutated);
        assert_eq!(diff.processes, vec!["/usr/bin/curl".to_string()]);
    }

    #[test]
    fn mutated_only_native_module_is_in_diff() {
        let baseline = base_profile();
        let mut mutated = base_profile();
        mutated.native_modules.push("/work/build/addon.node".to_string());
        let diff = diff_profiles(&baseline, &mutated);
        assert_eq!(diff.native_modules, vec!["/work/build/addon.node".to_string()]);
    }

    #[test]
    fn diff_phase_is_always_import() {
        let baseline = Layer2Profile {
            phase: "install".to_string(),
            ..Default::default()
        };
        let mutated = Layer2Profile {
            phase: "install".to_string(),
            ..Default::default()
        };
        let diff = diff_profiles(&baseline, &mutated);
        assert_eq!(diff.phase, "import");
    }

    #[test]
    fn tmp_paths_normalize_and_cancel() {
        let mut baseline = base_profile();
        baseline.file_opens.push("/tmp/abc123/foo.tmp".to_string());
        let mut mutated = base_profile();
        mutated.file_opens.push("/tmp/xyz789/foo.tmp".to_string());
        let diff = diff_profiles(&baseline, &mutated);
        assert!(
            diff.file_opens.is_empty(),
            "differently-named tmp dirs must normalize to the same token: {:?}",
            diff.file_opens
        );
    }

    #[test]
    fn proc_pid_paths_normalize_and_cancel() {
        let mut baseline = base_profile();
        baseline.file_opens.push("/proc/1111/status".to_string());
        let mut mutated = base_profile();
        mutated.file_opens.push("/proc/2222/status".to_string());
        let diff = diff_profiles(&baseline, &mutated);
        assert!(
            diff.file_opens.is_empty(),
            "different PIDs must normalize to the same token: {:?}",
            diff.file_opens
        );
    }

    #[test]
    fn npm_logs_paths_normalize_and_cancel() {
        let mut baseline = base_profile();
        baseline
            .file_opens
            .push("/root/.npm/_logs/2026-07-01T12_00_00_000Z-debug-0.log".to_string());
        let mut mutated = base_profile();
        mutated
            .file_opens
            .push("/root/.npm/_logs/2026-07-01T12_00_01_999Z-debug-0.log".to_string());
        let diff = diff_profiles(&baseline, &mutated);
        assert!(
            diff.file_opens.is_empty(),
            "differently-timestamped npm debug logs must normalize to the same token: {:?}",
            diff.file_opens
        );
    }

    #[test]
    fn package_lock_paths_normalize_and_cancel() {
        let mut baseline = base_profile();
        baseline
            .file_opens
            .push("/work/node_modules/.package-lock.json".to_string());
        let mut mutated = base_profile();
        mutated
            .file_opens
            .push("/work/.package-lock.json.4821.tmp".to_string());
        let diff = diff_profiles(&baseline, &mutated);
        assert!(
            diff.file_opens.is_empty(),
            "differently-named package-lock temp files must normalize to the same token: {:?}",
            diff.file_opens
        );
    }

    #[test]
    fn diff_profiles_phase_install_tags_phase() {
        let baseline = Layer2Profile {
            phase: "install".to_string(),
            ..Default::default()
        };
        let mut mutated = Layer2Profile {
            phase: "install".to_string(),
            ..Default::default()
        };
        mutated.processes.push("/usr/bin/curl".to_string());
        let diff = diff_profiles_phase(&baseline, &mutated, "install");
        assert_eq!(diff.phase, "install");
        assert_eq!(diff.processes, vec!["/usr/bin/curl".to_string()]);
    }

    #[test]
    fn diff_profiles_phase_import_matches_diff_profiles() {
        let baseline = base_profile();
        let mut mutated = base_profile();
        mutated.dns_queries.push("evil.example.com".to_string());
        let via_phase = diff_profiles_phase(&baseline, &mutated, "import");
        let via_wrapper = diff_profiles(&baseline, &mutated);
        assert_eq!(via_phase.phase, via_wrapper.phase);
        assert_eq!(via_phase.dns_queries, via_wrapper.dns_queries);
    }

    #[test]
    fn evidence_lines_formats_each_kind() {
        let mut diff = Layer2Profile {
            phase: "import".to_string(),
            ..Default::default()
        };
        diff.processes.push("/usr/bin/id".to_string());
        diff.file_opens.push("/etc/passwd".to_string());
        diff.file_writes.push("/root/.bashrc".to_string());
        diff.file_deletes.push("/tmp/victim".to_string());
        diff.dns_queries.push("evil.example.com".to_string());
        diff.connects.push(("1.2.3.4".to_string(), 443));

        let lines = evidence_lines(&diff);
        assert_eq!(
            lines,
            vec![
                "proc:/usr/bin/id".to_string(),
                "file:/etc/passwd".to_string(),
                "write:/root/.bashrc".to_string(),
                "delete:/tmp/victim".to_string(),
                "dns:evil.example.com".to_string(),
                "connect:1.2.3.4:443".to_string(),
            ]
        );
    }

    #[test]
    fn evidence_lines_empty_diff_is_empty() {
        let diff = Layer2Profile {
            phase: "import".to_string(),
            ..Default::default()
        };
        assert!(evidence_lines(&diff).is_empty());
    }

    #[test]
    fn evidence_lines_capped_at_20() {
        let mut diff = Layer2Profile {
            phase: "import".to_string(),
            ..Default::default()
        };
        for i in 0..50 {
            diff.dns_queries.push(format!("q{}.example.com", i));
        }
        let lines = evidence_lines(&diff);
        assert_eq!(lines.len(), EVIDENCE_CAP);
    }

    // ── file_writes / file_deletes diffing + normalization ──────────────────

    #[test]
    fn identical_writes_and_deletes_cancel() {
        let mut baseline = base_profile();
        baseline.file_writes.push("/work/node_modules/.package-lock.json".to_string());
        baseline.file_deletes.push("/tmp/npm-install-1234/tmp".to_string());
        let mut mutated = base_profile();
        mutated.file_writes.push("/work/node_modules/.package-lock.json".to_string());
        mutated.file_deletes.push("/tmp/npm-install-5678/tmp".to_string());

        let diff = diff_profiles(&baseline, &mutated);
        assert!(
            diff.file_writes.is_empty(),
            "identical logical writes must cancel: {:?}",
            diff.file_writes
        );
        assert!(
            diff.file_deletes.is_empty(),
            "tmp-dir deletes must normalize and cancel: {:?}",
            diff.file_deletes
        );
    }

    #[test]
    fn node_modules_staging_dir_writes_cancel() {
        let mut baseline = base_profile();
        baseline
            .file_writes
            .push("/work/node_modules/.foo-a1b2c3d4/package.json".to_string());
        let mut mutated = base_profile();
        mutated
            .file_writes
            .push("/work/node_modules/.foo-e5f6a7b8/package.json".to_string());

        let diff = diff_profiles(&baseline, &mutated);
        assert!(
            diff.file_writes.is_empty(),
            "differently-suffixed node_modules staging dirs must normalize and cancel: {:?}",
            diff.file_writes
        );
    }

    #[test]
    fn mutated_only_bashrc_write_survives_diff() {
        let baseline = base_profile();
        let mut mutated = base_profile();
        mutated.file_writes.push("/root/.bashrc".to_string());

        let diff = diff_profiles(&baseline, &mutated);
        assert_eq!(diff.file_writes, vec!["/root/.bashrc".to_string()]);
    }

    #[test]
    fn wiper_style_deletes_only_in_mutated_survive_diff() {
        let baseline = base_profile();
        let mut mutated = base_profile();
        for i in 0..25 {
            mutated.file_deletes.push(format!("/work/victim{}", i));
        }

        let diff = diff_profiles(&baseline, &mutated);
        assert_eq!(diff.file_deletes.len(), 25);
    }

    #[test]
    fn tmp_suffixed_paths_normalize_and_cancel() {
        let mut baseline = base_profile();
        baseline.file_writes.push("/work/foo.tmp".to_string());
        let mut mutated = base_profile();
        mutated.file_writes.push("/work/bar.tmp".to_string());

        let diff = diff_profiles(&baseline, &mutated);
        assert!(
            diff.file_writes.is_empty(),
            "differently-named .tmp files must normalize to the same token: {:?}",
            diff.file_writes
        );
    }
}
