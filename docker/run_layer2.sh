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

# Step 3: npm install under strace (install phase)
cd "$PKG_DIR"
strace -f \
    -e trace=execve,openat,connect \
    -o "$OUT_DIR/strace_install.log" \
    npm install --ignore-scripts=false 2>&1 || true

echo "Layer 2: install phase complete" >&2

# Step 4: node require() under strace (import phase)
strace -f \
    -e trace=execve,openat,connect \
    -o "$OUT_DIR/strace_import.log" \
    node -e "try { require('$PKG_DIR'); } catch(e) { process.stderr.write('require error: ' + e.message + '\n'); }" 2>&1 || true

echo "Layer 2: import phase complete" >&2

# Step 5: Stop background processes
kill "$TCPDUMP_PID" 2>/dev/null || true
kill "$DNSMASQ_PID" 2>/dev/null || true
sleep 1

echo "Layer 2: analysis complete, logs in $OUT_DIR" >&2
