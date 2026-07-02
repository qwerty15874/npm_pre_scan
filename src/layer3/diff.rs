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
/// (tmp dirs, PIDs, npm cache dirs) don't create false "new events" between
/// baseline and mutated runs.
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
    path.to_string()
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
pub fn diff_profiles(baseline: &Layer2Profile, mutated: &Layer2Profile) -> Layer2Profile {
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

    Layer2Profile {
        phase: "import".to_string(),
        processes,
        file_opens,
        connects,
        dns_queries,
        native_modules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_profile() -> Layer2Profile {
        Layer2Profile {
            phase: "import".to_string(),
            processes: vec!["/usr/bin/node".to_string()],
            file_opens: vec!["/work/.npmrc".to_string(), "/etc/passwd".to_string()],
            connects: vec![],
            dns_queries: vec![],
            native_modules: vec![],
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
}
