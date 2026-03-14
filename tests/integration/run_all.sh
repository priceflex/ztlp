#!/usr/bin/env bash
# run_all.sh — Run all ZTLP integration tests
#
# Usage:
#   ./run_all.sh              # Run all tests
#   ./run_all.sh quick        # Skip long-running tests (>60s)
#   ZTLP=/path/to/ztlp ./run_all.sh  # Custom binary path
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export ZTLP="${ZTLP:-$(cd "$SCRIPT_DIR/../../proto" && pwd)/target/release/ztlp}"
MODE="${1:-full}"

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0
RESULTS=()

run_test() {
    local name="$1"
    local script="$2"
    local skip_in_quick="${3:-no}"

    TOTAL=$((TOTAL+1))

    if [ "$MODE" = "quick" ] && [ "$skip_in_quick" = "yes" ]; then
        echo "⏭  SKIP: $name (quick mode)"
        SKIPPED=$((SKIPPED+1))
        RESULTS+=("SKIP  $name")
        return
    fi

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "▶ Running: $name"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    START=$(date +%s%N)
    if bash "$script"; then
        END=$(date +%s%N)
        ELAPSED_MS=$(( (END - START) / 1000000 ))
        echo "✅ PASS: $name (${ELAPSED_MS}ms)"
        PASSED=$((PASSED+1))
        RESULTS+=("PASS  $name (${ELAPSED_MS}ms)")
    else
        END=$(date +%s%N)
        ELAPSED_MS=$(( (END - START) / 1000000 ))
        echo "❌ FAIL: $name (${ELAPSED_MS}ms)"
        FAILED=$((FAILED+1))
        RESULTS+=("FAIL  $name (${ELAPSED_MS}ms)")
    fi
}

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║             ZTLP Integration Test Suite                         ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
echo "║ Binary: $ZTLP"
echo "║ Mode:   $MODE"
echo "╚═══════════════════════════════════════════════════════════════════╝"

if [ ! -x "$ZTLP" ]; then
    echo ""
    echo "ERROR: ztlp binary not found at $ZTLP"
    echo "Build with: cd proto && cargo build --release"
    exit 1
fi

# ── Run tests ────────────────────────────────────────────────────────────
run_test "Full E2E Tunnel"            "$SCRIPT_DIR/test_full_tunnel.sh"       "no"
run_test "Policy Rejection"           "$SCRIPT_DIR/test_policy_rejection.sh"  "no"
run_test "Relay Failover"             "$SCRIPT_DIR/test_relay_failover.sh"    "no"
run_test "Multi-Session Stress (50)"  "$SCRIPT_DIR/test_multi_session.sh"     "no"
run_test "Connection Storm (100)"     "$SCRIPT_DIR/test_connection_storm.sh"  "no"
run_test "Long-Running Session"       "$SCRIPT_DIR/test_long_session.sh"      "yes"

# ── Summary ──────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║                      Test Summary                               ║"
echo "╠═══════════════════════════════════════════════════════════════════╣"
for result in "${RESULTS[@]}"; do
    printf "║  %-63s║\n" "$result"
done
echo "╠═══════════════════════════════════════════════════════════════════╣"
printf "║  Total: %-4d  Passed: %-4d  Failed: %-4d  Skipped: %-4d       ║\n" \
    "$TOTAL" "$PASSED" "$FAILED" "$SKIPPED"
echo "╚═══════════════════════════════════════════════════════════════════╝"

if [ $FAILED -gt 0 ]; then
    exit 1
fi
exit 0
