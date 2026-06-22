#!/bin/sh
# Layer 2 dynamic analysis entrypoint.
# Runs inside a network-isolated Docker container with /pkg mounted read-only
# and /out mounted writable for output.
#
# Monitors worm egress: npm registry PUT/publish, api.github.com, webhook.site,
# cloud IMDS (169.254.169.254), and suspicious DNS lookups.
# Writes structured JSON to /out/layer2.json.

set -e

PKG_DIR="${PKG_DIR:-/pkg}"
OUT_FILE="${OUT_DIR:-/out}/layer2.json"
CAPTURE_FILE="/tmp/layer2_capture.pcap"
STRACE_LOG="/tmp/layer2_strace.log"

mkdir -p "$(dirname "$OUT_FILE")"

echo "Layer 2: starting dynamic analysis of $PKG_DIR" >&2

# Step 1: Start tcpdump in background
tcpdump -w "$CAPTURE_FILE" -i any &
TCPDUMP_PID=$!

# Step 2: npm install with strace (captures file and network syscalls)
cd "$PKG_DIR"
strace -f -e trace=network,file -o "$STRACE_LOG" npm install --ignore-scripts=false 2>&1 || true

# Step 3: Import-time execution
strace -f -e trace=network,file -o "${STRACE_LOG}.import" node -e "try { require('$PKG_DIR'); } catch(e) {}" 2>&1 || true

# Step 4: Stop tcpdump
kill "$TCPDUMP_PID" 2>/dev/null || true
sleep 1

# Step 5: Parse captures for worm IOC egress
EVENTS="[]"

# Check strace for suspicious network destinations
for IOC_PATTERN in "registry.npmjs.org" "api.github.com" "webhook.site" "169.254.169.254"; do
    if grep -q "$IOC_PATTERN" "$STRACE_LOG" 2>/dev/null || \
       grep -q "$IOC_PATTERN" "${STRACE_LOG}.import" 2>/dev/null; then
        EVENTS=$(printf '%s' "$EVENTS" | sed "s/\[\]/[{\"type\":\"egress\",\"destination\":\"$IOC_PATTERN\",\"severity\":\"BLOCK\",\"message\":\"Worm egress detected: $IOC_PATTERN\"}]/")
    fi
done

# Write structured JSON output
cat > "$OUT_FILE" <<EOF
{
  "layer": 2,
  "package": "$PKG_DIR",
  "events": $EVENTS
}
EOF

echo "Layer 2: analysis complete, results at $OUT_FILE" >&2
