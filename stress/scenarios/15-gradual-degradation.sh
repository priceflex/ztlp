#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 15: Gradual Degradation — Worsening over 60 seconds
# ─────────────────────────────────────────────────────────────
# Network starts clean and progressively degrades:
#   0s:  0ms delay, 0% loss
#  15s:  125ms delay, 6% loss, 50ms jitter
#  30s:  250ms delay, 12% loss, 100ms jitter
#  45s:  375ms delay, 18% loss, 150ms jitter
#  60s:  500ms delay, 25% loss, 200ms jitter
#
# Tests ZTLP's adaptive congestion control as conditions worsen.
# Transfers run concurrently with degradation.

set -eo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/netem.sh"
source "$SCRIPT_DIR/../lib/metrics.sh"
source "$SCRIPT_DIR/../lib/report.sh"

RESULTS_DIR="${RESULTS_DIR:-.}"
RESULT_FILE="${RESULTS_DIR}/scenario-15.txt"

echo "━━━ Scenario 15: Gradual Degradation (60s ramp) ━━━"

START=$(date +%s)
netem_reset

write_scenario_header "$RESULT_FILE" 15 "gradual-degradation" "Network degrades from clean to 500ms/25% loss over 60 seconds"

# Start with clean network for handshake
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

    # Start gradual degradation in background (60 seconds)
    echo "  → Starting gradual degradation..."
    netem_start_degradation 60

    # Run transfers during degradation
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

    # Measure recovery after degradation ends
    echo "  → Measuring recovery..."
    netem_reset
    sleep 1
    recovery=$(measure_recovery 30)
    echo "recovery_time_ms=$recovery" >> "$RESULT_FILE"
fi

netem_reset

END=$(date +%s)
write_scenario_duration "$RESULT_FILE" "$START" "$END"

echo "  ✓ Gradual degradation complete ($(( END - START ))s)"
cat "$RESULT_FILE"
