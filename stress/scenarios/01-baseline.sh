#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 01: Baseline — Clean network, no impairment
# ─────────────────────────────────────────────────────────────
# Establishes baseline measurements for comparison.
# All subsequent scenarios are judged against these numbers.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-01.txt"

echo "━━━ Scenario 01: Baseline (no impairment) ━━━"

START=$(date +%s)
export CURRENT_SCENARIO_ID=1

# Ensure clean slate
netem_reset

write_scenario_header "$RESULT_FILE" 1 "baseline" "Clean network — no impairment"

# Run all tests
results=$(run_scenario_tests 30 120)
append_results "$RESULT_FILE" "$results"

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Baseline complete ($(( END - START ))s)"
cat "$RESULT_FILE"
