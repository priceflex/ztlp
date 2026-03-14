#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 06: Burst Loss — Gilbert-Elliott correlated loss
# ─────────────────────────────────────────────────────────────
# 10% loss with 25% correlation — models bursty real-world loss
# where packet losses tend to cluster together.
# Tests ZTLP SACK and selective retransmission.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-06.txt"

echo "━━━ Scenario 06: Burst Loss (10% + 25% correlation) ━━━"

START=$(date +%s)
netem_reset

# 10% loss with 25% correlation (Gilbert-Elliott model)
netem_apply "loss 10% 25%"

write_scenario_header "$RESULT_FILE" 6 "burst-loss" "10% packet loss with 25% correlation (Gilbert-Elliott bursty model)"

results=$(run_scenario_tests 60 300)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Burst loss complete ($(( END - START ))s)"
cat "$RESULT_FILE"
