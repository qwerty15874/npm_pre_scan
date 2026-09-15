#!/bin/sh
# Layer 3 dynamic condition-mutation entrypoint.
# Runs inside a network-isolated Docker container (--network=none) with:
#   /pkg  mounted read-only  — package under analysis
#   /out  mounted writable   — raw log output for the Rust parser
#
# Runs the package's import step under several mutated runtime conditions
# (clock, environment, API fuzzing) plus a clean baseline, each producing its
# own raw strace + dnsmasq log pair. All parsing/diffing/classification happens
# in Rust (src/layer3/*) — this script only captures raw logs, exactly like
# Layer 2's run_layer2.sh.
#
# Output files (per scenario: baseline, baseline_fuzz, clock, env, fuzz):
#   /out/strace_<scenario>.log
#   /out/dns_<scenario>.log
#
# Network model: --network=none + in-container dnsmasq sinkhole, restarted per
# scenario so each scenario's DNS log only contains its own queries.

set -e

PKG_DIR="${PKG_DIR:-/pkg}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR=/work

# Hydrate $WORK_DIR from the read-only package mount, plus any host-vendored
# dependencies.
#
# Dependencies are resolved on the HOST (where network access already happens
# for the tarball) and mounted read-only at $VENDOR_DIR, because this container
# runs with --network=none and `npm install --offline` can therefore fetch
# nothing. Without them a dependency-bearing package fails its install,
# `require()` throws MODULE_NOT_FOUND, both are swallowed by `|| true`, and the
# layer reports an empty profile that looks exactly like a clean package.
#
# Layer 3 builds the work tree once and runs all four scenarios against it, so
# every scenario sees the same vendored tree by construction. (Layer 2 rebuilds
# between its two installs and calls this at each rebuild, for the same reason.)
# Copied rather than symlinked so npm may rewrite the tree without touching the
# read-only mount.
hydrate_work_dir() {
    cp -r "$PKG_DIR" "$WORK_DIR"
    if [ -n "${VENDOR_DIR:-}" ] && [ -d "$VENDOR_DIR/node_modules" ]; then
        cp -r "$VENDOR_DIR/node_modules" "$WORK_DIR/node_modules"
    fi
}

# strace syscall set — same as Layer 2 (musl/alpine emits plain `open`, not just `openat`).
# unlink/unlinkat/rename*/chmod/fchmodat add write/delete visibility (wipers,
# persistence-file drops, node_modules pollution) without tracing bare `write`
# (which would blow up log volume).
STRACE_SYSCALLS="execve,open,openat,openat2,connect,unlink,unlinkat,rename,renameat,renameat2,chmod,fchmodat"

# ── Pinned clocks (D1) ─────────────────────────────────────────────────────────
# EVERY scenario runs under libfaketime at a PINNED absolute date, not the real
# wall clock. This is what makes D1 detection time-invariant.
#
# Why: Layer 3 is purely differential. If the baseline ran on the real clock, a
# date-gated payload whose trigger date has already PASSED would fire in the
# baseline too, the diff would come back empty, and D1 detection would silently
# drop to zero — with no failure anywhere to say so. That is exactly what would
# have happened to dummy_timebomb (trigger 2026-09-01) once the host date
# crossed it. Re-dating the fixture only buys a year; pinning both ends fixes it
# for good.
#
# INVARIANT: FAKETIME_BASE < every fixture trigger date < FAKETIME_CLOCK.
# tests/layer3_clock_pin.rs parses these two lines and enforces the ordering
# offline, because the live D1 tests are #[ignore]d and would not catch a drift
# until someone next ran the Docker suite.
FAKETIME_BASE="@2026-07-01 00:00:00"
FAKETIME_CLOCK="@2026-09-29 00:00:00"
FAKETIME_LIB=/usr/lib/faketime/libfaketime.so.1

mkdir -p "$OUT_DIR"

echo "Layer 3: starting condition-mutation analysis of $PKG_DIR" >&2

# Copy the package into a writable working dir (host mount stays read-only).
hydrate_work_dir

# Silence npm's own registry/telemetry contact — same as Layer 2 — so only the
# package's own behavior is observed.
export npm_config_registry="http://127.0.0.1:4873"
export npm_config_audit=false
export npm_config_fund=false
export npm_config_update_notifier=false
export NO_UPDATE_NOTIFIER=1

# npm install ONCE, unmutated, up front — node_modules must exist before any
# scenario runs. Not traced (Layer 3 only mutates the import/use phase).
cd "$WORK_DIR"
npm install --ignore-scripts=false --no-audit --no-fund --offline >/dev/null 2>&1 || true

echo "Layer 3: install phase complete (unmutated, untraced)" >&2

# start_dns <scenario>: (re)start dnsmasq sinkhole logging to a per-scenario file.
start_dns() {
    scenario="$1"
    dnsmasq \
        --no-daemon \
        --listen-address=127.0.0.1 \
        --bind-interfaces \
        --address=/#/127.0.0.1 \
        --no-resolv \
        --log-queries \
        --log-facility="$OUT_DIR/dns_${scenario}.log" &
    DNSMASQ_PID=$!
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    sleep 1
}

# stop_dns: SIGTERM the current dnsmasq before starting the next scenario.
stop_dns() {
    kill "$DNSMASQ_PID" 2>/dev/null || true
    wait "$DNSMASQ_PID" 2>/dev/null || true
}

# run_scenario <scenario> <env-prefix-args...> -- <command...>
# Runs the import step under strace with the given env, writing
# strace_<scenario>.log. Uses `env` so extra vars/unsets are scenario-local.

# ── Scenario: baseline (clean env, real clock, plain require) ───────────────────
# Reference for ALL three mutated scenarios: D1 (clock) and D2 (env) diff their
# mutated require against it, and D3 (fuzz) diffs against it too — plain require
# leaves an API-gated payload dormant, so the fuzz harness calling the export is
# exactly the new behavior D3 isolates.
#
# NOTE: node is launched via a bare `env` prefix so the process/file-open
# signature matches the clock/env scenarios (which necessarily use `env` to set
# LD_PRELOAD/FAKETIME/unset CI). Without this symmetry the `env` exec itself
# would appear as a NEW "child process" in every mutated diff → false SUSPECT.
#
# The same symmetry argument now applies to libfaketime: it is LD_PRELOAD'd in
# EVERY scenario (at FAKETIME_BASE here, FAKETIME_CLOCK in the clock scenario),
# so the loader's own opens and its /dev/shm/faketime_* artifacts appear on both
# sides of every diff and cancel. (layer2::classify::is_ephemeral_or_system_path
# already filters those artifacts, so this is belt-and-braces — but it also means
# the ONLY difference between baseline and clock is the date itself.)
start_dns baseline
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_baseline.log" \
    env LD_PRELOAD="$FAKETIME_LIB" FAKETIME="$FAKETIME_BASE" \
    node -e "try { require('$WORK_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true
stop_dns
echo "Layer 3: baseline scenario complete (clock pinned $FAKETIME_BASE)" >&2

# ── Scenario: clock — libfaketime, pinned FAKETIME_CLOCK (+90d from base) ───────
# The mutation is the DATE and nothing else: same LD_PRELOAD, same env, same
# command as baseline. Anything in this diff was caused by moving the clock.
start_dns clock
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_clock.log" \
    env LD_PRELOAD="$FAKETIME_LIB" FAKETIME="$FAKETIME_CLOCK" \
    node -e "try { require('$WORK_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true
stop_dns
echo "Layer 3: clock scenario complete (clock pinned $FAKETIME_CLOCK)" >&2

# ── Scenario: env — spoof a developer machine, strip CI signals ─────────────────
# NODE_ENV=production and TERM=xterm-256color widen the developer-machine spoof
# to also catch payloads gated on NODE_ENV or TTY presence, not just CI vars.
# Clock stays at FAKETIME_BASE so this scenario's diff isolates the ENV change.
start_dns env
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_env.log" \
    env -u CI -u GITHUB_ACTIONS -u CONTINUOUS_INTEGRATION HOME=/home/developer USER=dev NODE_ENV=production TERM=xterm-256color \
    LD_PRELOAD="$FAKETIME_LIB" FAKETIME="$FAKETIME_BASE" \
    node -e "try { require('$WORK_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true
stop_dns
echo "Layer 3: env scenario complete" >&2

# ── Scenario: fuzz — enumerate + invoke exported API surface ────────────────────
# `env` prefix kept symmetric with baseline/clock/env (see baseline note).
# Clock stays at FAKETIME_BASE so this scenario's diff isolates the API calls.
start_dns fuzz
timeout 30 strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_fuzz.log" \
    env LD_PRELOAD="$FAKETIME_LIB" FAKETIME="$FAKETIME_BASE" \
    node /fuzz_exports.js "$WORK_DIR" 2>&1 || true
stop_dns
echo "Layer 3: fuzz scenario complete" >&2

# Make all raw logs readable by the host user (dnsmasq writes 0640 as its own user).
# Non-fatal (logs may still be usable), but a failure here is worth a loud
# warning since it can silently degrade detection — don't let it pass quietly.
if ! chmod -R a+r "$OUT_DIR" 2>/tmp/chmod_err; then
    echo "WARNING: chmod -R a+r \"$OUT_DIR\" failed — host-side log parser may hit permission errors: $(cat /tmp/chmod_err 2>/dev/null)" >&2
fi

echo "Layer 3: analysis complete, logs in $OUT_DIR" >&2
