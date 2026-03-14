#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 12: Flapping Link — Up/down every 5 seconds
# ─────────────────────────────────────────────────────────────
# Toggles iptables FORWARD DROP every 5 seconds, simulating
# an unstable link that keeps going down and recovering.
# Tests ZTLP session persistence and reconnection.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-12.txt"

echo "━━━ Scenario 12: Flapping Link (5s up/down) ━━━"

START=$(date +%s)
export CURRENT_SCENARIO_ID=12
netem_reset

write_scenario_header "$RESULT_FILE" 12 "flapping-link" "Link up/down every 5 seconds via iptables FORWARD DROP toggle"

# Start the flapping AFTER handshake so we can at least connect
echo "  → Establishing initial tunnel..."
hs=$(measure_handshake 30)
echo "handshake_time_ms=$hs" >> "$RESULT_FILE"

if [ "$hs" = "TIMEOUT" ]; then
    echo "ssh_echo=FAIL" >> "$RESULT_FILE"
    echo "scp_1mb_time_ms=TIMEOUT" >> "$RESULT_FILE"
    echo "scp_1mb_throughput_mbps=0" >> "$RESULT_FILE"
    echo "scp_1mb_checksum=FAIL" >> "$RESULT_FILE"
    echo "scp_10mb_time_ms=TIMEOUT" >> "$RESULT_FILE"
    echo "scp_10mb_throughput_mbps=0" >> "$RESULT_FILE"
    echo "scp_10mb_checksum=FAIL" >> "$RESULT_FILE"
    echo "scp_50mb_time_ms=TIMEOUT" >> "$RESULT_FILE"
    echo "scp_50mb_throughput_mbps=0" >> "$RESULT_FILE"
    echo "scp_50mb_checksum=FAIL" >> "$RESULT_FILE"
    echo "retransmit_count=0" >> "$RESULT_FILE"
else
    # SSH echo before flapping starts
    sleep 1
    echo_result=$(test_ssh_echo)
    echo "ssh_echo=$echo_result" >> "$RESULT_FILE"

    # Now start flapping
    echo "  → Starting link flapping..."
    netem_start_flapping 5

    # Attempt transfers during flapping (will be slow/interrupted)
    for size in 1 10 50; do
        tunnel_stop; sleep 1
        if tunnel_start 45; then
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

    netem_stop_flapping
fi

# Collect debug logs for analysis
collect_scenario_logs 12 "$RESULTS_DIR"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Flapping link complete ($(( END - START ))s)"
cat "$RESULT_FILE"
