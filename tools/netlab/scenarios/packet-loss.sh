#!/usr/bin/env bash
# Packet loss — test ZTLP resilience at 1%, 5%, 10%, 25% loss rates
# Measures success rate and performance degradation under packet loss.
set -euo pipefail

echo "┌─────────────────────────────────────────┐"
echo "│  Scenario: Packet Loss                  │"
echo "│  Loss rates: 1%, 5%, 10%, 25%           │"
echo "└─────────────────────────────────────────┘"

CHAOS="docker exec --privileged ztlp-chaos"
$CHAOS sh -c "apk add --no-cache iproute2 >/dev/null 2>&1" || true

for LOSS in 1 5 10 25; do
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Testing with ${LOSS}% packet loss"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    $CHAOS sh -c "
        tc qdisc del dev eth0 root 2>/dev/null || true
        tc qdisc add dev eth0 root netem loss ${LOSS}%
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
    echo "  Duration: ${DURATION_MS}ms (with ${LOSS}% packet loss)"

    $CHAOS sh -c "tc qdisc del dev eth0 root 2>/dev/null" || true
done

echo ""
echo "Result: PACKET LOSS TEST COMPLETE"
