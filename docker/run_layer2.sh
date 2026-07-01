#!/bin/sh
# Layer 2 dynamic analysis entrypoint.
# Runs inside a network-isolated Docker container (--network=none) with:
#   /pkg  mounted read-only  — package under analysis
#   /out  mounted writable   — raw log output for the Rust parser
#
# Produces raw logs only; all parsing and classification happens in Rust.
# Output files:
#   /out/strace_install.log  — strace of npm install phase
#   /out/strace_import.log   — strace of node require() phase
#   /out/dns.log             — dnsmasq query log (all phases)
#
# Network model: --network=none + in-container dnsmasq sinkhole.
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

# Step 1: Start dnsmasq as DNS sinkhole (log all queries, resolve everything to loopback)
dnsmasq \
    --no-daemon \
    --listen-address=127.0.0.1 \
    --bind-interfaces \
    --address=/#/127.0.0.1 \
    --no-resolv \
    --log-queries \
    --log-facility="$OUT_DIR/dns.log" &
DNSMASQ_PID=$!

# Point resolver at dnsmasq
echo "nameserver 127.0.0.1" > /etc/resolv.conf

# Give dnsmasq a moment to start
sleep 1

# Step 2: Start tcpdump on loopback in background (supplemental capture)
tcpdump -w "$OUT_DIR/capture.pcap" -i lo 2>/dev/null &
TCPDUMP_PID=$!

# Copy the package into a writable working dir. The host mount ($PKG_DIR) stays
# read-only for host protection; npm install must write (node_modules, package-lock)
# and run lifecycle scripts inside the disposable container.
cp -r "$PKG_DIR" "$WORK_DIR"

# Silence npm's own registry/telemetry contact so ONLY the package's behavior is
# observed. Without this, npm resolves registry.npmjs.org (even with --offline),
# which the DNS sinkhole logs and Layer 2 would flag as egress for every package.
export npm_config_registry="http://127.0.0.1:4873"
export npm_config_audit=false
export npm_config_fund=false
export npm_config_update_notifier=false
export NO_UPDATE_NOTIFIER=1

# Step 3: npm install under strace (install phase). --offline: no network fetches.
cd "$WORK_DIR"
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_install.log" \
    npm install --ignore-scripts=false --no-audit --no-fund --offline 2>&1 || true

echo "Layer 2: install phase complete" >&2

# Step 4: node require() under strace (import phase)
strace -f \
    -e trace="$STRACE_SYSCALLS" \
    -o "$OUT_DIR/strace_import.log" \
    node -e "try { require('$WORK_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true

echo "Layer 2: import phase complete" >&2

# Step 5: Stop background processes
kill "$TCPDUMP_PID" 2>/dev/null || true
kill "$DNSMASQ_PID" 2>/dev/null || true
sleep 1

# Make all raw logs readable by the host user. dnsmasq creates dns.log as
# 0640 owned by its own (syslog) user; without this the host-side Rust parser
# gets EACCES and silently sees an empty DNS log (breaking C1/C2/E1 detection).
chmod -R a+r "$OUT_DIR" 2>/dev/null || true

echo "Layer 2: analysis complete, logs in $OUT_DIR" >&2
