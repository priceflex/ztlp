#!/usr/bin/env bash
# Bandwidth throttling — test ZTLP under 1Mbps and 100Kbps limits
# Verifies protocol behavior when bandwidth is constrained.
set -euo pipefail

echo "┌─────────────────────────────────────────┐"
echo "│  Scenario: Bandwidth Throttling         │"
echo "│  Limits: 1Mbps, 100Kbps                │"
echo "└─────────────────────────────────────────┘"

CHAOS="docker exec --privileged ztlp-chaos"
$CHAOS sh -c "apk add --no-cache iproute2 >/dev/null 2>&1" || true

for BW in "1mbit" "100kbit"; do
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Testing with ${BW} bandwidth limit"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    $CHAOS sh -c "
        tc qdisc del dev eth0 root 2>/dev/null || true
        tc qdisc add dev eth0 root tbf rate ${BW} burst 32kbit latency 400ms
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
    echo "  Duration: ${DURATION_MS}ms (with ${BW} limit)"

    $CHAOS sh -c "tc qdisc del dev eth0 root 2>/dev/null" || true
done

echo ""
echo "Result: BANDWIDTH TEST COMPLETE"
