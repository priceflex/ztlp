#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 14: Traffic Flood — iperf3 background flood
# ─────────────────────────────────────────────────────────────
# Runs iperf3 flood traffic alongside ZTLP tunnel traffic,
# saturating the network path. Tests ZTLP's ability to
# compete for bandwidth and maintain throughput under load.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-14.txt"

echo "━━━ Scenario 14: Traffic Flood (iperf3 background) ━━━"

START=$(date +%s)
netem_reset

write_scenario_header "$RESULT_FILE" 14 "traffic-flood" "iperf3 background traffic flood competing for bandwidth"

# Start baseline tunnel first
echo "  → Starting tunnel before flood..."
hs=$(measure_handshake 30)
echo "handshake_time_ms=$hs" >> "$RESULT_FILE"

if [ "$hs" = "TIMEOUT" ]; then
    echo "ssh_echo=FAIL" >> "$RESULT_FILE"
    for size in 1 10 50; do
        echo "scp_${size}mb_time_ms=TIMEOUT" >> "$RESULT_FILE"
        echo "scp_${size}mb_throughput_mbps=0" >> "$RESULT_FILE"
        echo "scp_${size}mb_checksum=FAIL" >> "$RESULT_FILE"
    done
    echo "retransmit_count=0" >> "$RESULT_FILE"
else
    sleep 1
    echo_result=$(test_ssh_echo)
    echo "ssh_echo=$echo_result" >> "$RESULT_FILE"

    # Now start the flood
    echo "  → Starting iperf3 flood..."
    netem_start_flood "100M"
    sleep 3  # Let flood ramp up

    # Run transfers during flood
    for size in 1 10 50; do
        tunnel_stop; sleep 1
        if tunnel_start 60; then
            sleep 1
            result=$(measure_transfer "$size" 300)
            t=$(echo "$result" | awk '{print $1}')
            tp=$(echo "$result" | awk '{print $2}')
            ck=$(echo "$result" | awk '{print $3}')
        else
            t="TIMEOUT"; tp="0"; ck="FAIL"
        fi
        echo "scp_${size}mb_time_ms=$t" >> "$RESULT_FILE"
        echo "scp_${size}mb_throughput_mbps=$tp" >> "$RESULT_FILE"
        echo "scp_${size}mb_checksum=$ck" >> "$RESULT_FILE"
    done

    echo "retransmit_count=$(count_retransmits)" >> "$RESULT_FILE"

    netem_stop_flood
fi

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Traffic flood complete ($(( END - START ))s)"
cat "$RESULT_FILE"
