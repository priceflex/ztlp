#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 13: Asymmetric — Different impairment per direction
# ─────────────────────────────────────────────────────────────
# Client→Server: 20ms delay, 1% loss (decent uplink)
# Server→Client: 300ms delay, 15% loss (terrible downlink)
# Common in mobile/satellite where download is much worse.
# Tests ZTLP's handling of asymmetric path characteristics.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-13.txt"

echo "━━━ Scenario 13: Asymmetric Impairment ━━━"

START=$(date +%s)
netem_reset

# Server-facing interface: affects client→server traffic
netem_apply_direction "server" "delay 20ms loss 1%"

# Client-facing interface: affects server→client traffic
netem_apply_direction "client" "delay 300ms loss 15%"

write_scenario_header "$RESULT_FILE" 13 "asymmetric" "Asymmetric: uplink 20ms/1% loss, downlink 300ms/15% loss"

results=$(run_scenario_tests 90 600)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Asymmetric complete ($(( END - START ))s)"
cat "$RESULT_FILE"
