#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 03: Extreme Latency — 2000ms RTT
# ─────────────────────────────────────────────────────────────
# Simulates satellite-link or extreme WAN conditions.
# Tests whether Noise_XX handshake completes at all and
# if congestion control adapts to extreme RTT.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-03.txt"

echo "━━━ Scenario 03: Extreme Latency (2000ms RTT) ━━━"

START=$(date +%s)
netem_reset

# 1000ms each direction = 2000ms RTT
netem_apply "delay 1000ms"

write_scenario_header "$RESULT_FILE" 3 "extreme-latency" "2000ms RTT (1000ms one-way delay)"

# Longer timeouts for extreme latency
results=$(run_scenario_tests 120 600)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Extreme latency complete ($(( END - START ))s)"
cat "$RESULT_FILE"
