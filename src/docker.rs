// Shared Docker preflight helpers used by Layer 2 and Layer 3.
//
// Both dynamic layers need to know (a) whether `docker` is usable at all, and
// (b) whether the container runtime will actually grant `--cap-add=SYS_PTRACE`
// (strace inside the container silently produces empty logs without it — a
// known past failure mode, see CLAUDE.md v10). Centralized here instead of
// duplicated per-layer.

use std::os::unix::process::ExitStatusExt;
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

/// Env var carrying the per-PACKAGE wall-clock budget, in seconds.
///
/// `DOCKER_TIMEOUT_ENV` bounds ONE `docker run`, so a package that stalls in
/// both dynamic layers costs twice that — `shadowsocks` burned 2 x 605 s of arm
/// F's 24-minute total against a 600 s per-run budget, 84% of the arm, for no
/// finding. This bounds the package instead, and the two compose: each run gets
/// the smaller of the per-run budget and whatever is left of the package's.
pub const PACKAGE_TIMEOUT_ENV: &str = "NPM_PRE_SCAN_PACKAGE_TIMEOUT";

/// The configured per-package budget, or `None` for unbounded. Same
/// treat-garbage-as-unset rule as `docker_timeout_from_env`.
pub fn package_timeout_from_env() -> Option<u64> {
    std::env::var(PACKAGE_TIMEOUT_ENV)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|&s| s > 0)
}

thread_local! {
    /// When the current package's dynamic budget runs out. Thread-local because
    /// the scan is strictly sequential (no rayon, no spawned threads), so there
    /// is exactly one package in flight per thread.
    static PACKAGE_DEADLINE: std::cell::Cell<Option<std::time::Instant>> =
        const { std::cell::Cell::new(None) };
}

/// Open a per-package budget. Called once before a package's dynamic layers.
pub fn start_package_budget() {
    PACKAGE_DEADLINE.with(|d| {
        d.set(
            package_timeout_from_env()
                .map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s)),
        )
    });
}

/// Close the current package's budget, so a later un-budgeted run is unbounded
/// rather than inheriting a stale deadline.
pub fn clear_package_budget() {
    PACKAGE_DEADLINE.with(|d| d.set(None));
}

/// Seconds left on the package budget, clamped to at least 1.
///
/// The clamp is load-bearing, not cosmetic: `timeout 0 CMD` means **no timeout**
/// in GNU coreutils, so letting an exhausted budget reach the command line as
/// `0` would turn the tightest case into an unbounded run — the precise
/// opposite of the intent.
fn package_budget_remaining() -> Option<u64> {
    PACKAGE_DEADLINE
        .with(|d| d.get())
        .map(|deadline| remaining_secs(deadline, std::time::Instant::now()))
}

/// Whole seconds from `now` to `deadline`, never below 1. Split out from
/// `package_budget_remaining` so the clamp is testable without a clock.
fn remaining_secs(deadline: std::time::Instant, now: std::time::Instant) -> u64 {
    deadline.saturating_duration_since(now).as_secs().max(1)
}

/// The budget for the next `docker run`: the per-run budget, further clamped by
/// whatever remains of the per-package budget. Either may be absent.
pub fn effective_docker_timeout() -> Option<u64> {
    combine_budgets(docker_timeout_from_env(), package_budget_remaining())
}

/// Smaller-of, treating absent as unbounded. Pure, so the composition rule is
/// pinned without touching the process environment.
fn combine_budgets(per_run: Option<u64>, remaining: Option<u64>) -> Option<u64> {
    match (per_run, remaining) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
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

/// `timeout`'s exit status when it gave up within its grace period.
const TIMEOUT_EXIT_CODE: i32 = 124;

/// The signal `-k` escalates to. Spelled out rather than pulled from `libc`,
/// which this crate does not otherwise depend on.
const SIGKILL: i32 = 9;

/// Marker substring carried by every wall-clock-budget failure note.
///
/// The evaluation harness classifies a run's `Outcome` from the layer note, and
/// matching on this constant keeps it from re-deriving the exit-status rules
/// below (which is how they came to disagree in the first place).
pub const TIMEOUT_NOTE_MARKER: &str = "wall-clock budget";

/// The note a budget kill produces.
pub fn timeout_note(secs: Option<u64>) -> String {
    match secs {
        Some(s) => format!(
            "docker run exceeded its {}s wall-clock budget and was killed",
            s
        ),
        None => "docker run exceeded its wall-clock budget and was killed".to_string(),
    }
}

/// Whether an exit status means "the wall-clock budget killed this run".
///
/// There are **two** shapes, and testing only the first is why `shadowsocks`
/// was mis-recorded in the v20 arm F run: both its layers were killed at 605 s
/// yet each was filed as a generic error (`l2_status=error`, note
/// `Docker run failed (exit signal: 9 (SIGKILL))`) and `metrics.json` still
/// reported `"timeout": 0`.
///
/// * `timeout` gave up inside its grace period → it exits **124**.
/// * The command ignored SIGTERM and `-k 5` escalated → GNU `timeout` re-raises
///   that same signal **on itself** so the caller can observe a signal death.
///   `ExitStatus::code()` is then `None`, never `Some(124)`.
///
/// The signal shape is attributed to the budget only when one was configured.
/// With no `-k` in play a SIGKILL belongs to somebody else — an OOM kill, an
/// operator — and must keep reporting as a plain error.
fn is_timeout_status(code: Option<i32>, signal: Option<i32>, secs: Option<u64>) -> bool {
    code == Some(TIMEOUT_EXIT_CODE) || (secs.is_some() && signal == Some(SIGKILL))
}

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
            if is_timeout_status(s.code(), s.signal(), secs) {
                if let Some(cname) = container_name {
                    // Best-effort: the container may already be gone.
                    let _ = Command::new("docker").args(["rm", "-f", cname]).output();
                }
                Err(timeout_note(secs))
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

    /// The shape that actually occurred and was mis-filed: `timeout -k 5`
    /// escalated to SIGKILL, GNU `timeout` re-raised it on itself, so `code()`
    /// is `None`. `shadowsocks` hit this in BOTH layers of the v20 arm F run
    /// (605011 ms and 605016 ms against a 600 s budget) and each was recorded
    /// as a generic error, leaving `metrics.json` claiming `"timeout": 0`.
    #[test]
    fn a_kill_escalation_under_a_budget_is_a_timeout() {
        assert!(
            is_timeout_status(None, Some(SIGKILL), Some(600)),
            "SIGKILL with a configured budget is the -k escalation path"
        );
    }

    /// The documented shape: `timeout` gave up inside its grace period.
    #[test]
    fn exit_124_is_a_timeout_with_or_without_a_budget() {
        assert!(is_timeout_status(Some(TIMEOUT_EXIT_CODE), None, Some(600)));
        assert!(is_timeout_status(Some(TIMEOUT_EXIT_CODE), None, None));
    }

    /// The class this must never absorb: with no budget configured there is no
    /// `-k` in play, so a SIGKILL came from somewhere else (an OOM kill, an
    /// operator) and must keep reporting as a plain error rather than being
    /// silently relabelled a timeout.
    #[test]
    fn a_kill_without_a_budget_is_not_a_timeout() {
        assert!(!is_timeout_status(None, Some(SIGKILL), None));
    }

    #[test]
    fn an_ordinary_nonzero_exit_is_not_a_timeout() {
        assert!(!is_timeout_status(Some(1), None, Some(600)));
        assert!(!is_timeout_status(Some(125), None, Some(600)));
        // SIGTERM alone is not the escalation — `-k` kills with SIGKILL.
        assert!(!is_timeout_status(None, Some(15), Some(600)));
    }

    /// Every budget-kill note must carry the marker the eval harness matches on,
    /// so `Outcome::Timeout` cannot drift away from what `run_docker` produces.
    #[test]
    fn every_timeout_note_carries_the_harness_marker() {
        assert!(timeout_note(Some(600)).contains(TIMEOUT_NOTE_MARKER));
        assert!(timeout_note(None).contains(TIMEOUT_NOTE_MARKER));
        assert!(
            timeout_note(Some(600)).contains("600s"),
            "the budget belongs in the note: {}",
            timeout_note(Some(600))
        );
    }

    /// An exhausted package budget must still ask for at least one second.
    /// `timeout 0 CMD` means **no timeout** in GNU coreutils, so letting a spent
    /// budget reach the command line as `0` would make the tightest case
    /// unbounded — the exact opposite of what the budget is for.
    #[test]
    fn an_exhausted_package_budget_never_reaches_the_command_line_as_zero() {
        let now = std::time::Instant::now();
        let already_past = now - std::time::Duration::from_secs(30);
        assert_eq!(remaining_secs(already_past, now), 1);
        assert_eq!(remaining_secs(now, now), 1);
    }

    #[test]
    fn remaining_secs_counts_down_toward_the_deadline() {
        let now = std::time::Instant::now();
        let deadline = now + std::time::Duration::from_secs(120);
        assert_eq!(remaining_secs(deadline, now), 120);
    }

    /// The composition rule: each run gets the smaller of the two budgets, and
    /// an absent budget means unbounded on that axis rather than zero.
    #[test]
    fn a_run_gets_the_smaller_of_the_run_and_package_budgets() {
        assert_eq!(combine_budgets(Some(600), Some(90)), Some(90));
        assert_eq!(combine_budgets(Some(60), Some(900)), Some(60));
        assert_eq!(combine_budgets(Some(600), None), Some(600));
        assert_eq!(combine_budgets(None, Some(90)), Some(90));
        assert_eq!(combine_budgets(None, None), None);
    }

    // `ensure_layer_image` is deliberately NOT unit-tested: it would invoke
    // `docker build` (making `cargo test` depend on Docker, which this repo
    // avoids) and would poison the process-wide `OnceLock` for any later caller.
    // It is covered by the Docker-gated integration tests instead.
}
