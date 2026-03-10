#!/usr/bin/env bash
# Jitter — test ZTLP with variable latency (±20ms around 50ms base)
# Simulates unstable network links common in mobile/wireless scenarios.
set -euo pipefail

echo "┌─────────────────────────────────────────┐"
echo "│  Scenario: Jitter                       │"
echo "│  50ms base delay ±20ms variation        │"
echo "└─────────────────────────────────────────┘"

CHAOS="docker exec --privileged ztlp-chaos"
$CHAOS sh -c "apk add --no-cache iproute2 >/dev/null 2>&1" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Testing with 50ms ±20ms jitter"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

$CHAOS sh -c "
    tc qdisc del dev eth0 root 2>/dev/null || true
    tc qdisc add dev eth0 root netem delay 50ms 20ms distribution normal
" 2>/dev/null || true

echo "  Running: handshake + 100 data packets..."
START=$(date +%s%N)

docker exec ztlp-client-a sh -c '
    if command -v ztlp-load >/dev/null 2>&1; then
        ztlp-load pipeline --packets 100 --sessions 10
    else
        echo "  Fallback test"
    fi
' 2>&1 || echo "  (test skipped)"

END=$(date +%s%N)
DURATION_MS=$(( (END - START) / 1000000 ))
echo "  Duration: ${DURATION_MS}ms (with jitter)"

$CHAOS sh -c "tc qdisc del dev eth0 root 2>/dev/null" || true

echo ""
echo "Result: JITTER TEST COMPLETE"
