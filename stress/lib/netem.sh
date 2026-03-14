#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Stress Test — Impairment Control Library
# ─────────────────────────────────────────────────────────────
#
# Controls the userspace impairment proxy running in the
# stress-impairment container. The proxy reads its config from
# /tmp/impairment.json and applies impairments in userspace
# (latency, jitter, loss, corruption, reorder, duplicate, rate limit).
#
# Falls back to iptables for packet loss if proxy isn't running.
#
# Source this: source "$(dirname "$0")/../lib/netem.sh"

IMPAIRMENT_CONTAINER="${IMPAIRMENT_CONTAINER:-stress-impairment}"

# ── Proxy Management ────────────────────────────────────────

# Check if the impairment proxy is running
proxy_running() {
    docker exec "$IMPAIRMENT_CONTAINER" pgrep -f "impairment-proxy" &>/dev/null
}

# Start the impairment proxy
proxy_start() {
    if proxy_running; then
        return 0
    fi
    echo "  [netem] Starting impairment proxy..."
    docker exec -d "$IMPAIRMENT_CONTAINER" python3 /usr/local/bin/impairment-proxy \
        --port 23095 \
        --server-addr 172.30.2.40 \
        --server-port 23095 \
        2>/tmp/proxy-stderr.log
    sleep 1
    if proxy_running; then
        echo "  [netem] Proxy started"
    else
        echo "  [netem] WARNING: Proxy failed to start, falling back to iptables"
    fi
}

# ── Reset ────────────────────────────────────────────────────

# Remove ALL impairments
netem_reset() {
    # Reset proxy config to passthrough
    docker exec "$IMPAIRMENT_CONTAINER" bash -c '
        echo "{\"enabled\": false}" > /tmp/impairment.json
    ' 2>/dev/null || true

    # Also clean up any iptables rules from flapping
    docker exec "$IMPAIRMENT_CONTAINER" iptables -D FORWARD -j DROP 2>/dev/null || true
    docker exec "$IMPAIRMENT_CONTAINER" iptables -D FORWARD -j DROP 2>/dev/null || true
    docker exec "$IMPAIRMENT_CONTAINER" iptables -D FORWARD -j DROP 2>/dev/null || true

    # Kill any background impairment processes (flapping, degradation)
    docker exec "$IMPAIRMENT_CONTAINER" bash -c '
        [ -f /tmp/impairment-loop.pid ] && kill $(cat /tmp/impairment-loop.pid) 2>/dev/null; rm -f /tmp/impairment-loop.pid
        [ -f /tmp/flood.pid ] && kill $(cat /tmp/flood.pid) 2>/dev/null; rm -f /tmp/flood.pid
    ' 2>/dev/null || true
    docker exec stress-client bash -c '
        [ -f /tmp/flood.pid ] && kill $(cat /tmp/flood.pid) 2>/dev/null; rm -f /tmp/flood.pid
    ' 2>/dev/null || true
}

# ── Apply Impairment via Proxy Config ────────────────────────

# Write impairment config JSON to the proxy
# Usage: netem_apply_config '{"delay_ms": 500, "loss_pct": 10}'
netem_apply_config() {
    local json="$1"
    docker exec "$IMPAIRMENT_CONTAINER" bash -c "echo '${json}' > /tmp/impairment.json"
}

# ── Convenience Functions ────────────────────────────────────

# Apply symmetric impairment (both directions)
# Usage: netem_apply "delay 500ms" or netem_apply "loss 10%"
# This is a compatibility shim that translates tc-netem-style args to proxy config
netem_apply() {
    local rule="$1"
    local delay_ms=0
    local jitter_ms=0
    local loss_pct=0
    local loss_corr=0
    local corrupt_pct=0
    local reorder_pct=0
    local dup_pct=0

    # Parse tc-netem-style arguments
    local args=($rule)
    local i=0
    while [ $i -lt ${#args[@]} ]; do
        case "${args[$i]}" in
            delay)
                i=$((i+1))
                delay_ms=$(echo "${args[$i]}" | sed 's/ms$//')
                # Check for jitter
                if [ $((i+1)) -lt ${#args[@]} ] && echo "${args[$((i+1))]}" | grep -qE '^[0-9]+ms$'; then
                    i=$((i+1))
                    jitter_ms=$(echo "${args[$i]}" | sed 's/ms$//')
                fi
                # Check for distribution keyword
                if [ $((i+1)) -lt ${#args[@]} ] && [ "${args[$((i+1))]}" = "distribution" ]; then
                    i=$((i+2))  # skip "distribution normal"
                fi
                ;;
            loss)
                i=$((i+1))
                loss_pct=$(echo "${args[$i]}" | sed 's/%$//')
                # Check for correlation
                if [ $((i+1)) -lt ${#args[@]} ] && echo "${args[$((i+1))]}" | grep -qE '^[0-9]+%?$'; then
                    i=$((i+1))
                    loss_corr=$(echo "${args[$i]}" | sed 's/%$//')
                fi
                ;;
            corrupt)
                i=$((i+1))
                corrupt_pct=$(echo "${args[$i]}" | sed 's/%$//')
                ;;
            reorder)
                i=$((i+1))
                reorder_pct=$(echo "${args[$i]}" | sed 's/%$//')
                ;;
            duplicate)
                i=$((i+1))
                dup_pct=$(echo "${args[$i]}" | sed 's/%$//')
                ;;
        esac
        i=$((i+1))
    done

    netem_apply_config "{
        \"enabled\": true,
        \"delay_ms\": $delay_ms,
        \"jitter_ms\": $jitter_ms,
        \"loss_pct\": $loss_pct,
        \"loss_correlation\": $loss_corr,
        \"corrupt_pct\": $corrupt_pct,
        \"reorder_pct\": $reorder_pct,
        \"duplicate_pct\": $dup_pct,
        \"direction\": \"both\"
    }"
}

# Apply impairment to ONE direction only
# Usage: netem_apply_direction "upstream" "delay 500ms"
#   "upstream" = client→server
#   "downstream" = server→client
netem_apply_direction() {
    local direction="$1"
    local rule="$2"

    # Parse the rule into proxy config
    local delay_ms=0 jitter_ms=0 loss_pct=0 corrupt_pct=0 reorder_pct=0 dup_pct=0

    local args=($rule)
    local i=0
    while [ $i -lt ${#args[@]} ]; do
        case "${args[$i]}" in
            delay) i=$((i+1)); delay_ms=$(echo "${args[$i]}" | sed 's/ms$//') 
                   if [ $((i+1)) -lt ${#args[@]} ] && echo "${args[$((i+1))]}" | grep -qE '^[0-9]+ms$'; then
                       i=$((i+1)); jitter_ms=$(echo "${args[$i]}" | sed 's/ms$//')
                   fi ;;
            loss) i=$((i+1)); loss_pct=$(echo "${args[$i]}" | sed 's/%$//') ;;
            corrupt) i=$((i+1)); corrupt_pct=$(echo "${args[$i]}" | sed 's/%$//') ;;
            reorder) i=$((i+1)); reorder_pct=$(echo "${args[$i]}" | sed 's/%$//') ;;
            duplicate) i=$((i+1)); dup_pct=$(echo "${args[$i]}" | sed 's/%$//') ;;
        esac
        i=$((i+1))
    done

    netem_apply_config "{
        \"enabled\": true,
        \"delay_ms\": $delay_ms,
        \"jitter_ms\": $jitter_ms,
        \"loss_pct\": $loss_pct,
        \"corrupt_pct\": $corrupt_pct,
        \"reorder_pct\": $reorder_pct,
        \"duplicate_pct\": $dup_pct,
        \"direction\": \"$direction\"
    }"
}

# ── Bandwidth Limiting ───────────────────────────────────────

# Apply bandwidth limit
# Usage: netem_bandwidth "256kbit" ["delay 50ms"]
netem_bandwidth() {
    local rate="$1"
    local extra="${2:-}"
    local delay_ms=0 jitter_ms=0

    # Parse rate to kbps
    local rate_kbps=0
    if echo "$rate" | grep -qE 'kbit$'; then
        rate_kbps=$(echo "$rate" | sed 's/kbit$//')
    elif echo "$rate" | grep -qE 'mbit$'; then
        rate_kbps=$(( $(echo "$rate" | sed 's/mbit$//') * 1000 ))
    elif echo "$rate" | grep -qE 'kbps$'; then
        rate_kbps=$(( $(echo "$rate" | sed 's/kbps$//') * 8 ))
    fi

    # Parse optional extra netem params
    if [ -n "$extra" ]; then
        local args=($extra)
        local i=0
        while [ $i -lt ${#args[@]} ]; do
            case "${args[$i]}" in
                delay) i=$((i+1)); delay_ms=$(echo "${args[$i]}" | sed 's/ms$//') ;;
            esac
            i=$((i+1))
        done
    fi

    netem_apply_config "{
        \"enabled\": true,
        \"delay_ms\": $delay_ms,
        \"jitter_ms\": $jitter_ms,
        \"rate_kbps\": $rate_kbps,
        \"direction\": \"both\"
    }"
}

# ── Flapping Link ────────────────────────────────────────────

# Start a background loop that toggles link up/down via iptables
# Usage: netem_start_flapping <interval_seconds>
netem_start_flapping() {
    local interval="${1:-5}"
    docker exec -d "$IMPAIRMENT_CONTAINER" bash -c "
        echo \$\$ > /tmp/impairment-loop.pid
        while true; do
            iptables -A FORWARD -j DROP
            sleep $interval
            iptables -D FORWARD -j DROP
            sleep $interval
        done
    "
}

# Stop flapping
netem_stop_flapping() {
    docker exec "$IMPAIRMENT_CONTAINER" bash -c '
        if [ -f /tmp/impairment-loop.pid ]; then
            kill $(cat /tmp/impairment-loop.pid) 2>/dev/null || true
            rm -f /tmp/impairment-loop.pid
        fi
        iptables -D FORWARD -j DROP 2>/dev/null || true
    '
}

# ── Traffic Flood ────────────────────────────────────────────

# Start iperf3 flood
netem_start_flood() {
    local bandwidth="${1:-100M}"
    docker exec -d stress-client bash -c "
        iperf3 -c 172.30.1.100 -t 120 -b $bandwidth > /dev/null 2>&1 &
        echo \$! > /tmp/flood.pid
    " 2>/dev/null || true
}

netem_stop_flood() {
    docker exec stress-client bash -c '
        [ -f /tmp/flood.pid ] && kill $(cat /tmp/flood.pid) 2>/dev/null || true
        rm -f /tmp/flood.pid
    ' 2>/dev/null || true
}

# ── Gradual Degradation ──────────────────────────────────────

# Start a background loop that gradually worsens conditions
# Usage: netem_start_degradation <total_seconds>
netem_start_degradation() {
    local total_secs="${1:-60}"

    docker exec -d "$IMPAIRMENT_CONTAINER" bash -c "
        echo \$\$ > /tmp/impairment-loop.pid
        TOTAL=$total_secs
        STEP=5
        ELAPSED=0
        while [ \$ELAPSED -lt \$TOTAL ]; do
            PCT=\$(( ELAPSED * 100 / TOTAL ))
            DELAY=\$(( PCT * 5 ))          # 0 → 500ms
            LOSS=\$(( PCT / 4 ))           # 0 → 25%
            JITTER=\$(( PCT * 2 ))         # 0 → 200ms
            echo '{\"enabled\": true, \"delay_ms\": '\$DELAY', \"jitter_ms\": '\$JITTER', \"loss_pct\": '\$LOSS', \"direction\": \"both\"}' > /tmp/impairment.json
            sleep \$STEP
            ELAPSED=\$(( ELAPSED + STEP ))
        done
    "
}

# ── Status ───────────────────────────────────────────────────

# Show current impairment state
netem_status() {
    echo "── Proxy Config ──"
    docker exec "$IMPAIRMENT_CONTAINER" cat /tmp/impairment.json 2>/dev/null || echo "(no config)"
    echo ""
    echo "── Proxy Metrics ──"
    docker exec "$IMPAIRMENT_CONTAINER" cat /tmp/impairment-metrics.json 2>/dev/null || echo "(no metrics)"
    echo ""
    echo "── iptables ──"
    docker exec "$IMPAIRMENT_CONTAINER" iptables -L FORWARD -n 2>/dev/null || true
}
