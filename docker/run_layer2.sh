#!/bin/sh
# Layer 2 dynamic analysis entrypoint.
# Runs inside a network-isolated Docker container (--network=none) with:
#   /pkg  mounted read-only  — package under analysis
#   /out  mounted writable   — raw log output for the Rust parser
#
# Produces raw logs only; all parsing, baseline-subtraction diffing, and
# classification happens in Rust (src/layer2/mod.rs, profile.rs, classify.rs
# via src/layer3/diff.rs's diff_profiles_phase).
#
# Baseline subtraction: to cancel npm/node's own toolchain reads (.npmrc,
# /etc/passwd) at the source, each phase (install, import) is traced TWICE —
# once as an unmutated "baseline" and once as the "real" run — so the Rust
# side can diff real-vs-baseline and keep only package-attributable behavior.
#
# Both install runs execute in the SAME path (/work), each starting pristine
# (the tree is reset between them). Same path is required so CWD-relative reads
# like a project-level .npmrc log identical absolute paths in both runs and thus
# cancel in the set-difference (a /work_base vs /work split would leak
# /work/.npmrc as a phantom sensitive_file_read → false BLOCK). See the install
# section below for the full rationale.
#
# Output files (4 traced runs, each with its own dnsmasq log):
#   /out/strace_install_base.log  + /out/dns_install_base.log  — baseline install (pristine /work, --ignore-scripts)
#   /out/strace_install_real.log  + /out/dns_install_real.log  — real install     (pristine /work reset, scripts enabled)
#   /out/strace_import_base.log   + /out/dns_import_base.log   — baseline import  (node -e "0", no require)
#   /out/strace_import_real.log   + /out/dns_import_real.log   — real import      (node -e "require(...)")
#
# Network model: --network=none + in-container dnsmasq sinkhole, restarted per
# run (mirrors run_layer3.sh's start_dns/stop_dns) so each run's DNS log only
# contains its own queries.
# dnsmasq binds to 127.0.0.1, resolves everything to loopback (address=/#/127.0.0.1),
# logs all queries. /etc/resolv.conf points to 127.0.0.1.
# Nothing leaves the host; every DNS query name is still logged.

set -e

PKG_DIR="${PKG_DIR:-/pkg}"
OUT_DIR="${OUT_DIR:-/out}"
WORK_DIR=/work

# strace syscall set. NOTE: alpine's musl (and older glibc) emit the plain `open`
# syscall, not `openat`, so both must be traced or file-based detection is blind.
STRACE_SYSCALLS="execve,open,openat,openat2,connect"

mkdir -p "$OUT_DIR"

echo "Layer 2: starting dynamic analysis of $PKG_DIR" >&2

# Silence npm's own registry/telemetry contact so ONLY the package's behavior is
# observed. Without this, npm resolves registry.npmjs.org (even with --offline),
# which the DNS sinkhole logs and Layer 2 would flag as egress for every package.
export npm_config_registry="http://127.0.0.1:4873"
export npm_config_audit=false
export npm_config_fund=false
export npm_config_update_notifier=false
export NO_UPDATE_NOTIFIER=1

# start_dns <run>: (re)start dnsmasq sinkhole logging to a per-run file.
start_dns() {
    run="$1"
    dnsmasq \
        --no-daemon \
        --listen-address=127.0.0.1 \
        --bind-interfaces \
        --address=/#/127.0.0.1 \
        --no-resolv \
        --log-queries \
        --log-facility="$OUT_DIR/dns_${run}.log" &
    DNSMASQ_PID=$!
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    sleep 1
}

# stop_dns: SIGTERM the current dnsmasq before starting the next run.
stop_dns() {
    kill "$DNSMASQ_PID" 2>/dev/null || true
    wait "$DNSMASQ_PID" 2>/dev/null || true
}

# Both install runs happen in the SAME path ($WORK_DIR), each starting from a
# fresh pristine copy (the real run resets the tree between them). Two invariants
# must BOTH hold and this satisfies them at once:
#   1. Each install starts PRISTINE — never over an already-installed tree, or
#      the baseline would be a no-op and the real-vs-baseline diff would explode
#      into false positives (every real-install file write/read would look "new").
#   2. Same CWD for both — npm reads a project-level `.npmrc` relative to its CWD,
#      so running baseline in /work_base and real in /work would log DIFFERENT
#      absolute paths (/work_base/.npmrc vs /work/.npmrc) that do NOT cancel in the
#      set-difference → a phantom `sensitive_file_read` on /work/.npmrc → false
#      BLOCK for benign packages. Sharing $WORK_DIR makes every CWD-relative read
#      (.npmrc, package.json, node_modules/…) byte-identical between the two runs,
#      so they cancel.

# ── Run 1: install baseline (pristine, scripts disabled) ──────────────────────
cp -r "$PKG_DIR" "$WORK_DIR"
cd "$WORK_DIR"
start_dns install_base
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_install_base.log" \
    npm install --ignore-scripts --no-audit --no-fund --offline 2>&1 || true
stop_dns
echo "Layer 2: install baseline complete" >&2

# ── Run 2: install real (reset to pristine in the SAME path, scripts enabled) ─
# Reset $WORK_DIR to a fresh copy so this run also starts pristine (invariant 1)
# while keeping the identical path (invariant 2). This is the actual install a
# consumer would run.
rm -rf "$WORK_DIR"
cp -r "$PKG_DIR" "$WORK_DIR"
cd "$WORK_DIR"
start_dns install_real
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_install_real.log" \
    npm install --ignore-scripts=false --no-audit --no-fund --offline 2>&1 || true
stop_dns
echo "Layer 2: install real complete" >&2

# ── Run 3: import baseline ───────────────────────────────────────────────────
# In $WORK_DIR (already installed by the real install above — import doesn't
# mutate node_modules, so the two import runs can safely share it). `node -e
# "0"` starts the same node runtime with no require() of the package, giving
# the "what does node's own startup touch" reference.
start_dns import_base
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_import_base.log" \
    node -e "0" 2>&1 || true
stop_dns
echo "Layer 2: import baseline complete" >&2

# ── Run 4: import real ───────────────────────────────────────────────────────
# Same $WORK_DIR, this time actually require()-ing the package.
start_dns import_real
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_import_real.log" \
    node -e "try { require('$WORK_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true
stop_dns
echo "Layer 2: import real complete" >&2

# Make all raw logs readable by the host user. dnsmasq creates dns_*.log as
# 0640 owned by its own (syslog) user; without this the host-side Rust parser
# gets EACCES and silently sees an empty DNS log (breaking C1/C2/E1 detection).
# Non-fatal (logs may still be usable), but a failure here is worth a loud
# warning since it can silently degrade detection — don't let it pass quietly.
if ! chmod -R a+r "$OUT_DIR" 2>/tmp/chmod_err; then
    echo "WARNING: chmod -R a+r \"$OUT_DIR\" failed — host-side log parser may hit permission errors: $(cat /tmp/chmod_err 2>/dev/null)" >&2
fi

echo "Layer 2: analysis complete, logs in $OUT_DIR" >&2
