#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 08: Reordering — 25% packet reorder
# ─────────────────────────────────────────────────────────────
# 25% of packets arrive out of order with 50% correlation.
# Tests ZTLP's sequence number handling, receive buffer,
# and SACK-based reordering tolerance.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-08.txt"

echo "━━━ Scenario 08: Reordering (25% reorder) ━━━"

START=$(date +%s)
export CURRENT_SCENARIO_ID=8
netem_reset

# 25% reorder with 50% correlation, 10ms delay on reordered packets
netem_apply "delay 10ms reorder 25% 50%"

write_scenario_header "$RESULT_FILE" 8 "reordering" "25% packet reordering with 50% correlation"

results=$(run_scenario_tests 60 300)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Reordering complete ($(( END - START ))s)"
cat "$RESULT_FILE"
