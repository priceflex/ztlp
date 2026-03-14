#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 04: Jitter Storm — 50ms ±200ms jitter
# ─────────────────────────────────────────────────────────────
# Extreme timing variation. Tests ZTLP's ability to handle
# wildly out-of-order packets and variable RTT estimation.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-04.txt"

echo "━━━ Scenario 04: Jitter Storm (50ms ±200ms) ━━━"

START=$(date +%s)
netem_reset

# 50ms base delay with ±200ms jitter, normal distribution
netem_apply "delay 50ms 200ms distribution normal"

write_scenario_header "$RESULT_FILE" 4 "jitter-storm" "50ms base delay with ±200ms jitter (normal distribution)"

results=$(run_scenario_tests 60 300)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Jitter storm complete ($(( END - START ))s)"
cat "$RESULT_FILE"
