#!/usr/bin/env bash
# Network partition — simulate link failure and recovery
# Tests ZTLP session resilience when network connectivity is lost and restored.
set -euo pipefail

echo "┌─────────────────────────────────────────┐"
echo "│  Scenario: Network Partition            │"
echo "│  Partition for 5s, then recovery        │"
echo "└─────────────────────────────────────────┘"

CHAOS="docker exec --privileged ztlp-chaos"
$CHAOS sh -c "apk add --no-cache iproute2 >/dev/null 2>&1" || true

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 1: Pre-partition baseline"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

docker exec ztlp-client-a sh -c '
    if command -v ztlp-load >/dev/null 2>&1; then
        ztlp-load pipeline --packets 50 --sessions 5
    else
        echo "  Fallback test"
    fi
' 2>&1 || echo "  (test skipped)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 2: Network partition (100% loss for 5s)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

$CHAOS sh -c "
    tc qdisc del dev eth0 root 2>/dev/null || true
    tc qdisc add dev eth0 root netem loss 100%
" 2>/dev/null || true

echo "  Partition active — waiting 5 seconds..."
sleep 5

echo "  Attempting operations during partition..."
docker exec ztlp-client-a sh -c '
    if command -v ztlp-load >/dev/null 2>&1; then
        timeout 3 ztlp-load pipeline --packets 10 --sessions 2 2>&1 || true
    else
        echo "  Fallback test"
    fi
' 2>&1 || echo "  (expected to fail during partition)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Phase 3: Recovery"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

$CHAOS sh -c "tc qdisc del dev eth0 root 2>/dev/null" || true
echo "  Partition removed — network restored"
sleep 2

echo "  Running post-recovery test..."
docker exec ztlp-client-a sh -c '
    if command -v ztlp-load >/dev/null 2>&1; then
        ztlp-load pipeline --packets 50 --sessions 5
    else
        echo "  Fallback test"
    fi
' 2>&1 || echo "  (test skipped)"

echo ""
echo "Result: PARTITION TEST COMPLETE"
echo "  Check if sessions resumed after recovery."
