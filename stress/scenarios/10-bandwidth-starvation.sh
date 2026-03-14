#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 10: Bandwidth Starvation — 56kbps, 256kbps, 1Mbps
# ─────────────────────────────────────────────────────────────
# Progressively tests extreme bandwidth constraints.
# Uses HTB for rate limiting with small netem delay.
# The 1Mbps level is used for the main measurements.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-10.txt"

echo "━━━ Scenario 10: Bandwidth Starvation ━━━"

START=$(date +%s)
export CURRENT_SCENARIO_ID=10
netem_reset

write_scenario_header "$RESULT_FILE" 10 "bandwidth-starvation" "Bandwidth limiting: 56kbps, 256kbps, 1Mbps"

# Test each bandwidth level with a quick handshake + 1MB transfer
for rate in "56kbit" "256kbit" "1mbit"; do
    echo "  → Testing at ${rate}..."
    netem_reset
    sleep 1

    netem_bandwidth "$rate" "delay 20ms"

    tunnel_stop
    sleep 1

    hs=$(measure_handshake 90)
    echo "bw_${rate}_handshake_ms=$hs" >> "$RESULT_FILE"

    if [ "$hs" != "TIMEOUT" ]; then
        sleep 1
        echo_result=$(test_ssh_echo)
        echo "bw_${rate}_ssh_echo=$echo_result" >> "$RESULT_FILE"

        # 1MB transfer only (larger transfers at 56kbit would take forever)
        tunnel_stop; sleep 1; tunnel_start 90
        sleep 1
        result=$(measure_transfer 1 300)
        t=$(echo "$result" | awk '{print $1}')
        tp=$(echo "$result" | awk '{print $2}')
        ck=$(echo "$result" | awk '{print $3}')
        echo "bw_${rate}_1mb_time_ms=$t" >> "$RESULT_FILE"
        echo "bw_${rate}_1mb_throughput_mbps=$tp" >> "$RESULT_FILE"
        echo "bw_${rate}_1mb_checksum=$ck" >> "$RESULT_FILE"
    else
        echo "bw_${rate}_ssh_echo=FAIL" >> "$RESULT_FILE"
        echo "bw_${rate}_1mb_time_ms=TIMEOUT" >> "$RESULT_FILE"
        echo "bw_${rate}_1mb_throughput_mbps=0" >> "$RESULT_FILE"
        echo "bw_${rate}_1mb_checksum=FAIL" >> "$RESULT_FILE"
    fi
done

# Full test suite at 1Mbps
netem_reset
sleep 1
netem_bandwidth "1mbit" "delay 20ms"
results=$(run_scenario_tests 90 600)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Bandwidth starvation complete ($(( END - START ))s)"
cat "$RESULT_FILE"
