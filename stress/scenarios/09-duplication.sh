#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 09: Duplication — 10% packet duplication
# ─────────────────────────────────────────────────────────────
# 10% of packets are duplicated. Tests ZTLP's anti-replay
# window and deduplication logic. Duplicate encrypted packets
# should be silently dropped.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-09.txt"

echo "━━━ Scenario 09: Duplication (10% duplicate) ━━━"

START=$(date +%s)
export CURRENT_SCENARIO_ID=9
netem_reset

# 10% packet duplication
netem_apply "duplicate 10%"

write_scenario_header "$RESULT_FILE" 9 "duplication" "10% packet duplication (tests anti-replay window)"

results=$(run_scenario_tests 60 300)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Duplication complete ($(( END - START ))s)"
cat "$RESULT_FILE"
