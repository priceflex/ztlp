#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 02: High Latency — 500ms RTT
# ─────────────────────────────────────────────────────────────
# Tests ZTLP congestion control and handshake timeout handling
# with 250ms one-way delay (500ms RTT).

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-02.txt"

echo "━━━ Scenario 02: High Latency (500ms RTT) ━━━"

START=$(date +%s)
netem_reset

# 250ms each direction = 500ms RTT
netem_apply "delay 250ms"

write_scenario_header "$RESULT_FILE" 2 "high-latency" "500ms RTT (250ms one-way delay)"

results=$(run_scenario_tests 60 300)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ High latency complete ($(( END - START ))s)"
cat "$RESULT_FILE"
