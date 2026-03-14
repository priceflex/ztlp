#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 07: Corruption — 5% bit corruption
# ─────────────────────────────────────────────────────────────
# Corrupts 5% of packets at the bit level. Tests ZTLP's
# integrity checks (AEAD cipher MAC validation) and packet
# rejection/retransmission behavior.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-07.txt"

echo "━━━ Scenario 07: Corruption (5% bit corruption) ━━━"

START=$(date +%s)
export CURRENT_SCENARIO_ID=7
netem_reset

# 5% bit-level corruption
netem_apply "corrupt 5%"

write_scenario_header "$RESULT_FILE" 7 "corruption" "5% bit-level packet corruption (tests AEAD integrity)"

results=$(run_scenario_tests 60 300)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Corruption complete ($(( END - START ))s)"
cat "$RESULT_FILE"
