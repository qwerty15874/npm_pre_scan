// Shared Docker preflight helpers used by Layer 2 and Layer 3.
//
// Both dynamic layers need to know (a) whether `docker` is usable at all, and
// (b) whether the container runtime will actually grant `--cap-add=SYS_PTRACE`
// (strace inside the container silently produces empty logs without it — a
// known past failure mode, see CLAUDE.md v10). Centralized here instead of
// duplicated per-layer.

use std::process::Command;

/// True if the `docker` CLI is present and responds to `docker --version`.
pub fn docker_available() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_available_does_not_panic() {
        // Whatever the environment, this must return a bool without panicking.
        let _ = docker_available();
    }
}
