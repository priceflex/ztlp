#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 11: Combined Hell
# 200ms delay + 10% loss + 5% corruption + jitter
# ─────────────────────────────────────────────────────────────
# The kitchen sink. Multiple impairments stacked together.
# This is what a truly terrible network looks like.
# Tests ZTLP's resilience when everything is going wrong.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-11.txt"

echo "━━━ Scenario 11: Combined Hell ━━━"

START=$(date +%s)
netem_reset

# 200ms delay ±50ms jitter + 10% loss + 5% corruption
netem_apply "delay 200ms 50ms loss 10% corrupt 5%"

write_scenario_header "$RESULT_FILE" 11 "combined-hell" "200ms delay + 50ms jitter + 10% loss + 5% corruption"

results=$(run_scenario_tests 90 600)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Combined hell complete ($(( END - START ))s)"
cat "$RESULT_FILE"
