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

# strace syscall set — same as Layer 2 (musl/alpine emits plain `open`, not just `openat`).
STRACE_SYSCALLS="execve,open,openat,openat2,connect"

mkdir -p "$OUT_DIR"

echo "Layer 3: starting condition-mutation analysis of $PKG_DIR" >&2

# Copy the package into a writable working dir (host mount stays read-only).
cp -r "$PKG_DIR" "$WORK_DIR"

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
start_dns baseline
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_baseline.log" \
    env node -e "try { require('$WORK_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true
stop_dns
echo "Layer 3: baseline scenario complete" >&2

# ── Scenario: clock — libfaketime, absolute +90d from 2026-07-01 ────────────────
start_dns clock
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_clock.log" \
    env LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1 FAKETIME="@2026-09-29 00:00:00" \
    node -e "try { require('$WORK_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true
stop_dns
echo "Layer 3: clock scenario complete" >&2

# ── Scenario: env — spoof a developer machine, strip CI signals ─────────────────
start_dns env
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_env.log" \
    env -u CI -u GITHUB_ACTIONS -u CONTINUOUS_INTEGRATION HOME=/home/developer USER=dev \
    node -e "try { require('$WORK_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true
stop_dns
echo "Layer 3: env scenario complete" >&2

# ── Scenario: fuzz — enumerate + invoke exported API surface ────────────────────
# `env` prefix kept symmetric with baseline/clock/env (see baseline note).
start_dns fuzz
timeout 30 strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_fuzz.log" \
    env node /fuzz_exports.js "$WORK_DIR" 2>&1 || true
stop_dns
echo "Layer 3: fuzz scenario complete" >&2

# Make all raw logs readable by the host user (dnsmasq writes 0640 as its own user).
chmod -R a+r "$OUT_DIR" 2>/dev/null || true

echo "Layer 3: analysis complete, logs in $OUT_DIR" >&2
