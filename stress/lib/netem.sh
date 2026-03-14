#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Stress Test — tc netem helper functions
# ─────────────────────────────────────────────────────────────
#
# All functions operate on the stress-impairment container.
# Interface discovery uses /tmp/client_iface and /tmp/server_iface
# written by the impairment entrypoint.
#
# Source this: source "$(dirname "$0")/../lib/netem.sh"

IMPAIRMENT_CONTAINER="${IMPAIRMENT_CONTAINER:-stress-impairment}"

# ── Interface Discovery ──────────────────────────────────────

# Get the client-facing interface name inside the impairment container
impairment_client_iface() {
    docker exec "$IMPAIRMENT_CONTAINER" cat /tmp/client_iface 2>/dev/null
}

# Get the server-facing interface name inside the impairment container
impairment_server_iface() {
    docker exec "$IMPAIRMENT_CONTAINER" cat /tmp/server_iface 2>/dev/null
}

# ── Reset ────────────────────────────────────────────────────

# Remove ALL tc rules and iptables impairments
netem_reset() {
    local client_if server_if
    client_if=$(impairment_client_iface)
    server_if=$(impairment_server_iface)

    for iface in "$client_if" "$server_if"; do
        [ -z "$iface" ] && continue
        docker exec "$IMPAIRMENT_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true
    done

    # Restore forwarding (in case flapping test dropped it)
    docker exec "$IMPAIRMENT_CONTAINER" iptables -D FORWARD -j DROP 2>/dev/null || true
    docker exec "$IMPAIRMENT_CONTAINER" iptables -D FORWARD -j DROP 2>/dev/null || true
    docker exec "$IMPAIRMENT_CONTAINER" iptables -D FORWARD -j DROP 2>/dev/null || true

    # Kill any background impairment processes (flapping, flood, etc.)
    docker exec "$IMPAIRMENT_CONTAINER" pkill -f "impairment-loop" 2>/dev/null || true
    docker exec "$IMPAIRMENT_CONTAINER" pkill -f "iperf3 -c" 2>/dev/null || true
}

# ── Simple netem ─────────────────────────────────────────────

# Apply netem to BOTH directions (symmetric)
# Usage: netem_apply "delay 500ms" or "loss 10%" or "delay 200ms 50ms loss 10%"
netem_apply() {
    local rule="$1"
    local client_if server_if
    client_if=$(impairment_client_iface)
    server_if=$(impairment_server_iface)

    for iface in "$client_if" "$server_if"; do
        [ -z "$iface" ] && continue
        docker exec "$IMPAIRMENT_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true
        docker exec "$IMPAIRMENT_CONTAINER" tc qdisc add dev "$iface" root netem $rule
    done
}

# Apply netem to ONE direction only
# Usage: netem_apply_direction "client" "delay 500ms"
#   "client" = affects traffic toward client (server→client)
#   "server" = affects traffic toward server (client→server)
netem_apply_direction() {
    local direction="$1"
    local rule="$2"
    local iface

    if [ "$direction" = "client" ]; then
        iface=$(impairment_client_iface)
    else
        iface=$(impairment_server_iface)
    fi

    [ -z "$iface" ] && return 1
    docker exec "$IMPAIRMENT_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true
    docker exec "$IMPAIRMENT_CONTAINER" tc qdisc add dev "$iface" root netem $rule
}

# ── Bandwidth Limiting (HTB + netem) ─────────────────────────

# Apply bandwidth limit with optional netem on top
# Usage: netem_bandwidth "256kbit" ["delay 50ms"]
netem_bandwidth() {
    local rate="$1"
    local netem_rule="${2:-}"
    local client_if server_if
    client_if=$(impairment_client_iface)
    server_if=$(impairment_server_iface)

    for iface in "$client_if" "$server_if"; do
        [ -z "$iface" ] && continue
        docker exec "$IMPAIRMENT_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true
        docker exec "$IMPAIRMENT_CONTAINER" tc qdisc add dev "$iface" root handle 1: htb default 12
        docker exec "$IMPAIRMENT_CONTAINER" tc class add dev "$iface" parent 1: classid 1:12 htb rate "$rate"
        if [ -n "$netem_rule" ]; then
            docker exec "$IMPAIRMENT_CONTAINER" tc qdisc add dev "$iface" parent 1:12 netem $netem_rule
        fi
    done
}

# ── Flapping Link ────────────────────────────────────────────

# Start a background loop that toggles link up/down
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

# Start iperf3 flood from client to impairment node
# Usage: netem_start_flood [bandwidth]
netem_start_flood() {
    local bandwidth="${1:-100M}"
    # iperf3 server is already running on impairment node
    docker exec -d "$IMPAIRMENT_CONTAINER" bash -c "
        iperf3 -c 172.30.1.100 -t 120 -b $bandwidth --logfile /tmp/flood.log &
        echo \$! > /tmp/flood.pid
    " 2>/dev/null || true
    # Also flood from the client container if available
    docker exec -d stress-client bash -c "
        iperf3 -c 172.30.1.100 -t 120 -b $bandwidth > /dev/null 2>&1 &
        echo \$! > /tmp/flood.pid
    " 2>/dev/null || true
}

# Stop flood
netem_stop_flood() {
    docker exec "$IMPAIRMENT_CONTAINER" bash -c '
        [ -f /tmp/flood.pid ] && kill $(cat /tmp/flood.pid) 2>/dev/null || true
        rm -f /tmp/flood.pid
    ' 2>/dev/null || true
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
    local client_if server_if
    client_if=$(impairment_client_iface)
    server_if=$(impairment_server_iface)

    docker exec -d "$IMPAIRMENT_CONTAINER" bash -c "
        echo \$\$ > /tmp/impairment-loop.pid
        TOTAL=$total_secs
        STEP=5
        ELAPSED=0
        CLIENT_IF='$client_if'
        SERVER_IF='$server_if'
        while [ \$ELAPSED -lt \$TOTAL ]; do
            PCT=\$(( ELAPSED * 100 / TOTAL ))
            DELAY=\$(( PCT * 5 ))          # 0 → 500ms
            LOSS=\$(( PCT / 4 ))           # 0 → 25%
            JITTER=\$(( PCT * 2 ))         # 0 → 200ms
            for iface in \$CLIENT_IF \$SERVER_IF; do
                tc qdisc del dev \$iface root 2>/dev/null || true
                tc qdisc add dev \$iface root netem delay \${DELAY}ms \${JITTER}ms loss \${LOSS}%
            done
            sleep \$STEP
            ELAPSED=\$(( ELAPSED + STEP ))
        done
    "
}

# ── Status ───────────────────────────────────────────────────

# Show current tc and iptables state on the impairment node
netem_status() {
    echo "── tc qdisc ──"
    docker exec "$IMPAIRMENT_CONTAINER" tc qdisc show 2>/dev/null || true
    echo "── iptables ──"
    docker exec "$IMPAIRMENT_CONTAINER" iptables -L FORWARD -n 2>/dev/null || true
}
