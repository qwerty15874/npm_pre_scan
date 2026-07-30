// Shared Docker preflight helpers used by Layer 2 and Layer 3.
//
// Both dynamic layers need to know (a) whether `docker` is usable at all, and
// (b) whether the container runtime will actually grant `--cap-add=SYS_PTRACE`
// (strace inside the container silently produces empty logs without it — a
// known past failure mode, see CLAUDE.md v10). Centralized here instead of
// duplicated per-layer.

use std::process::Command;
use std::sync::OnceLock;

/// The `docker --version` string, or `None` if the CLI is absent or failing.
/// Recorded in evaluation provenance, where "which Docker produced these
/// numbers" is part of the result.
pub fn docker_version() -> Option<String> {
    let output = Command::new("docker").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// True if the `docker` CLI is present and responds to `docker --version`.
pub fn docker_available() -> bool {
    docker_version().is_some()
}

/// Outcome of the cheap `SYS_PTRACE` capability probe.
#[derive(Debug, PartialEq, Eq)]
pub enum PtraceProbe {
    /// The probe container ran successfully with `--cap-add=SYS_PTRACE`.
    Granted,
    /// Docker explicitly ran the probe and reported the capability is not
    /// usable (e.g. a hardened daemon config, gVisor/rootless restrictions,
    /// seccomp policy). This is a real, actionable signal.
    Denied(String),
    /// The probe itself could not be evaluated for a reason unrelated to the
    /// capability (image not cached, no network to pull it, `docker run`
    /// failed to start, etc.). This is NOT evidence that the capability is
    /// missing — callers should treat it as "unknown" and proceed with the
    /// real run rather than block on it.
    Unknown(String),
}

/// Cheaply probe whether the Docker daemon will grant `--cap-add=SYS_PTRACE`
/// to containers, without building or mounting the project image. Runs a
/// throwaway container against a tiny, near-universally-cached image.
///
/// This is a best-effort preflight, not a hard gate: only `Denied` is an
/// actionable failure signal (surface it and stop, since the real run would
/// just yield empty strace logs and a misleading false-PASS). `Unknown`
/// should NOT block the real run — the probe can fail for reasons that don't
/// reflect the actual capability (no network, image not pulled, etc.).
pub fn check_ptrace_capability() -> PtraceProbe {
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--cap-add=SYS_PTRACE",
            "--entrypoint",
            "true",
            "busybox:latest",
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => PtraceProbe::Granted,
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            // Only treat this as a genuine denial if Docker's own message
            // names the capability; anything else (e.g. image pull failure)
            // is an unrelated probe failure, not a capability denial.
            if stderr.to_lowercase().contains("ptrace")
                || stderr.to_lowercase().contains("cap")
                || stderr.to_lowercase().contains("permission denied")
                || stderr.to_lowercase().contains("operation not permitted")
            {
                PtraceProbe::Denied(format!(
                    "Docker denied --cap-add=SYS_PTRACE (needed for strace-based analysis): {}",
                    stderr
                ))
            } else {
                PtraceProbe::Unknown(format!(
                    "SYS_PTRACE probe container exited non-zero for an unrelated reason: {}",
                    stderr
                ))
            }
        }
        Err(e) => PtraceProbe::Unknown(format!(
            "Could not run the SYS_PTRACE probe container (docker run failed to start: {})",
            e
        )),
    }
}

/// Memoized outcome of the ptrace probe plus the image build, so both happen at
/// most once per process.
static LAYER_IMAGE: OnceLock<Result<(), String>> = OnceLock::new();

/// Ensure the shared analysis image exists, probing `SYS_PTRACE` first — once per
/// process, whatever the call count.
///
/// Both dynamic layers used to run the probe and `docker build` themselves, so a
/// single `--full` scan spent three probes and three builds round-tripping the
/// daemon, and a batch over N packages spent 2N of each. The builds are cache
/// hits, but each still ships the build context and waits on the daemon. The
/// memoized outcome is deliberately the *whole* result, failure included: if the
/// image cannot be built, retrying it per package would just be slow in a
/// different way.
///
/// The tool is single-threaded and blocking, so a `OnceLock` is all the
/// synchronization this needs.
pub fn ensure_layer_image(dockerfile_dir: &str, tag: &str) -> Result<(), String> {
    LAYER_IMAGE
        .get_or_init(|| {
            // Only a confirmed denial is fatal. An inconclusive probe can fail
            // for reasons the real run won't hit (image not cached, no network),
            // so it must not block — same policy as before this was centralized.
            if let PtraceProbe::Denied(note) = check_ptrace_capability() {
                return Err(format!("Docker preflight failed: {}", note));
            }
            match Command::new("docker")
                .args(["build", "-t", tag, dockerfile_dir])
                .status()
            {
                Ok(s) if s.success() => Ok(()),
                Ok(s) => Err(format!("Docker build failed (exit {})", s)),
                Err(e) => Err(format!("Docker build error: {}", e)),
            }
        })
        .clone()
}

/// Wrap `argv` in coreutils `timeout` when a budget is given; return it unchanged
/// otherwise.
///
/// `docker run` is the only unbounded operation in the pipeline — the HTTP paths
/// already carry timeouts (10s in `registry`, 60s in `tarball`), and
/// `Command::status()` blocks forever. A package whose `npm install` or `require`
/// hangs would otherwise stall a whole batch with no bound.
///
/// `timeout` is an acceptable dependency here: this is a Linux/WSL-only tool that
/// already shells out to `docker`, and `docker/run_layer3.sh` already uses
/// `timeout 30` internally. `-k 5` sends SIGKILL five seconds after SIGTERM in
/// case the client ignores the first signal.
pub fn timeout_argv(secs: Option<u64>, argv: &[&str]) -> Vec<String> {
    match secs {
        None => argv.iter().map(|s| s.to_string()).collect(),
        Some(s) => {
            let mut out = vec![
                "timeout".to_string(),
                "-k".to_string(),
                "5".to_string(),
                s.to_string(),
            ];
            out.extend(argv.iter().map(|a| a.to_string()));
            out
        }
    }
}

/// Env var carrying the per-`docker run` wall-clock budget, in seconds.
///
/// Read here rather than threaded through `run_layer2_local`/`run_layer3_local`,
/// because changing those signatures would ripple through every caller and the
/// Docker-gated tests for a purely operational knob. This also matches the
/// existing convention for runtime configuration in this crate
/// (`NPM_PRE_SCAN_IOCS`, `NPM_PRE_SCAN_EGRESS_HOSTS`, `NPM_PRE_SCAN_REFRESH_TOP`).
/// `--docker-timeout` sets it for the process.
pub const DOCKER_TIMEOUT_ENV: &str = "NPM_PRE_SCAN_DOCKER_TIMEOUT";

/// The configured per-run budget, or `None` for unbounded (the default, which
/// preserves the tool's pre-existing behaviour exactly). A malformed or
/// non-positive value is treated as unset rather than as an error, since this is
/// an operational hint and must never be the reason a scan refuses to start.
pub fn docker_timeout_from_env() -> Option<u64> {
    std::env::var(DOCKER_TIMEOUT_ENV)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|&s| s > 0)
}

/// A unique container name for one analysis run, so a timed-out container can be
/// force-removed by name. Process id plus a monotonic counter — unique within and
/// across concurrent processes, with no dependency on a clock or RNG.
pub fn container_name(layer: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "npm-pre-scan-{}-{}-{}",
        layer,
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// `timeout`'s exit status when it had to kill the command.
const TIMEOUT_EXIT_CODE: i32 = 124;

/// Run a docker command, optionally time-bounded.
///
/// On timeout the container is force-removed by name before returning. This
/// matters: signalling the *attached `docker run` client* does not reliably stop
/// the container it started, so without the explicit `docker rm -f` a timed-out
/// analysis would leave a container running — holding its mounts and skewing
/// every subsequent measurement in the batch.
///
/// `container_name` is only used for that cleanup, so it may be `None` when no
/// timeout is in play.
pub fn run_docker(
    argv: &[&str],
    secs: Option<u64>,
    container_name: Option<&str>,
) -> Result<(), String> {
    let full = timeout_argv(secs, argv);
    let (program, args) = full.split_first().expect("argv is never empty");

    let status = Command::new(program).args(args).status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => {
            if s.code() == Some(TIMEOUT_EXIT_CODE) {
                if let Some(cname) = container_name {
                    // Best-effort: the container may already be gone.
                    let _ = Command::new("docker").args(["rm", "-f", cname]).output();
                }
                Err(format!(
                    "docker run exceeded its {}s wall-clock budget and was killed",
                    secs.unwrap_or(0)
                ))
            } else {
                Err(format!("Docker run failed (exit {})", s))
            }
        }
        Err(e) => Err(format!("Docker run error: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_available_does_not_panic() {
        // Whatever the environment, this must return a bool without panicking.
        let _ = docker_available();
    }

    #[test]
    fn docker_version_does_not_panic() {
        let _ = docker_version();
    }

    #[test]
    fn timeout_argv_without_a_budget_is_the_identity() {
        // The default path must be byte-identical to invoking docker directly, so
        // adding this helper cannot change existing behaviour.
        let argv = ["docker", "run", "--rm", "busybox:latest"];
        assert_eq!(
            timeout_argv(None, &argv),
            vec!["docker", "run", "--rm", "busybox:latest"]
        );
    }

    #[test]
    fn timeout_argv_with_a_budget_prefixes_coreutils_timeout() {
        let argv = ["docker", "run", "--rm", "busybox:latest"];
        assert_eq!(
            timeout_argv(Some(900), &argv),
            vec![
                "timeout",
                "-k",
                "5",
                "900",
                "docker",
                "run",
                "--rm",
                "busybox:latest"
            ]
        );
        // The wrapped command must survive intact and in order.
        let wrapped = timeout_argv(Some(1), &argv);
        assert_eq!(&wrapped[4..], &["docker", "run", "--rm", "busybox:latest"]);
    }

    #[test]
    fn timeout_argv_preserves_a_single_element_argv() {
        assert_eq!(timeout_argv(None, &["docker"]), vec!["docker"]);
        assert_eq!(
            timeout_argv(Some(30), &["docker"]),
            vec!["timeout", "-k", "5", "30", "docker"]
        );
    }

    // `ensure_layer_image` is deliberately NOT unit-tested: it would invoke
    // `docker build` (making `cargo test` depend on Docker, which this repo
    // avoids) and would poison the process-wide `OnceLock` for any later caller.
    // It is covered by the Docker-gated integration tests instead.
}
