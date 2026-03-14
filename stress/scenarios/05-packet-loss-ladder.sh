#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 05: Packet Loss Ladder — 1%, 5%, 10%, 25%, 50%
# ─────────────────────────────────────────────────────────────
# Progressive packet loss test. Runs abbreviated tests at each
# loss level to find the breaking point of ZTLP reliability.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-05.txt"

echo "━━━ Scenario 05: Packet Loss Ladder ━━━"

START=$(date +%s)
export CURRENT_SCENARIO_ID=5
netem_reset

write_scenario_header "$RESULT_FILE" 5 "packet-loss-ladder" "Progressive packet loss: 1%, 5%, 10%, 25%, 50%"

# Track the worst result across all loss levels
worst_verdict="PASS"

for loss_pct in 1 5 10 25 50; do
    echo "  → Testing ${loss_pct}% packet loss..."
    netem_reset
    sleep 1

    netem_apply "loss ${loss_pct}%"

    # Start fresh tunnel
    tunnel_stop
    sleep 1

    hs=$(measure_handshake 60)
    echo "loss_${loss_pct}_handshake_ms=$hs" >> "$RESULT_FILE"

    if [ "$hs" != "TIMEOUT" ]; then
        sleep 1
        echo_result=$(test_ssh_echo)
        echo "loss_${loss_pct}_ssh_echo=$echo_result" >> "$RESULT_FILE"

        # Quick 1MB transfer as canary
        tunnel_stop; sleep 1; tunnel_start 60
        sleep 1
        result=$(measure_transfer 1 120)
        t=$(echo "$result" | awk '{print $1}')
        tp=$(echo "$result" | awk '{print $2}')
        ck=$(echo "$result" | awk '{print $3}')
        echo "loss_${loss_pct}_1mb_time_ms=$t" >> "$RESULT_FILE"
        echo "loss_${loss_pct}_1mb_throughput_mbps=$tp" >> "$RESULT_FILE"
        echo "loss_${loss_pct}_1mb_checksum=$ck" >> "$RESULT_FILE"
    else
        echo "loss_${loss_pct}_ssh_echo=FAIL" >> "$RESULT_FILE"
        echo "loss_${loss_pct}_1mb_time_ms=TIMEOUT" >> "$RESULT_FILE"
        echo "loss_${loss_pct}_1mb_throughput_mbps=0" >> "$RESULT_FILE"
        echo "loss_${loss_pct}_1mb_checksum=FAIL" >> "$RESULT_FILE"
    fi
done

# Use the 10% loss level as the representative for the main results
netem_reset
sleep 1
netem_apply "loss 10%"
results=$(run_scenario_tests 60 300)
append_results "$RESULT_FILE" "$results"

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Packet loss ladder complete ($(( END - START ))s)"
cat "$RESULT_FILE"
