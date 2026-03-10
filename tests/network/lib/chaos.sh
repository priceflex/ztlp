#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Network Tests — Chaos / Network Impairment Functions
# ─────────────────────────────────────────────────────────────
#
# Source this file from test scenarios:
#   source "$(dirname "$0")/../lib/chaos.sh"
#
# All functions operate via the chaos container (ztlp-test-chaos)
# which has NET_ADMIN capability and is connected to all networks.
#
# Uses `tc` (traffic control) and `iptables` for impairment.

CHAOS_CONTAINER="ztlp-test-chaos"

# ── Interface Discovery ──────────────────────────────────────

# Get the network interface for a specific Docker network inside the chaos container
# Usage: chaos_get_iface <network_suffix>
# Example: chaos_get_iface "frontend" → returns "eth0" or similar
chaos_get_iface() {
    local network_suffix="$1"
    # Docker networks will show up as ethN interfaces. We find them by
    # checking which interface has an IP in the expected subnet.
    local subnet=""
    case "$network_suffix" in
        frontend) subnet="172.28.1" ;;
        backend)  subnet="172.28.2" ;;
        infra)    subnet="172.28.3" ;;
        *)
            log_warn "Unknown network suffix: $network_suffix"
            return 1
            ;;
    esac

    docker exec "$CHAOS_CONTAINER" bash -c \
        "ip -4 addr show | grep '$subnet' | awk '{print \$NF}'" 2>/dev/null
}

# ── Latency Injection ────────────────────────────────────────

# Add latency to a network
# Usage: chaos_add_latency <network_suffix> <latency_ms> [jitter_ms]
# Example: chaos_add_latency frontend 100 10
chaos_add_latency() {
    local network="$1"
    local latency_ms="$2"
    local jitter_ms="${3:-0}"

    local iface
    iface=$(chaos_get_iface "$network")
    if [[ -z "$iface" ]]; then
        log_warn "Could not find interface for network $network"
        return 1
    fi

    log_info "Adding ${latency_ms}ms latency (±${jitter_ms}ms jitter) to $network ($iface)"

    # Remove existing qdisc if any
    docker exec "$CHAOS_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true

    if [[ "$jitter_ms" -gt 0 ]]; then
        docker exec "$CHAOS_CONTAINER" tc qdisc add dev "$iface" root netem \
            delay "${latency_ms}ms" "${jitter_ms}ms" distribution normal
    else
        docker exec "$CHAOS_CONTAINER" tc qdisc add dev "$iface" root netem \
            delay "${latency_ms}ms"
    fi
}

# ── Packet Loss Injection ────────────────────────────────────

# Add packet loss to a network
# Usage: chaos_add_loss <network_suffix> <loss_percent>
# Example: chaos_add_loss frontend 5
chaos_add_loss() {
    local network="$1"
    local loss_pct="$2"

    local iface
    iface=$(chaos_get_iface "$network")
    if [[ -z "$iface" ]]; then
        log_warn "Could not find interface for network $network"
        return 1
    fi

    log_info "Adding ${loss_pct}% packet loss to $network ($iface)"

    # Remove existing qdisc if any
    docker exec "$CHAOS_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true

    docker exec "$CHAOS_CONTAINER" tc qdisc add dev "$iface" root netem \
        loss "${loss_pct}%"
}

# Add both latency and packet loss
# Usage: chaos_add_impairment <network_suffix> <latency_ms> <loss_percent>
chaos_add_impairment() {
    local network="$1"
    local latency_ms="$2"
    local loss_pct="$3"

    local iface
    iface=$(chaos_get_iface "$network")
    if [[ -z "$iface" ]]; then
        log_warn "Could not find interface for network $network"
        return 1
    fi

    log_info "Adding ${latency_ms}ms latency + ${loss_pct}% loss to $network ($iface)"

    docker exec "$CHAOS_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true

    docker exec "$CHAOS_CONTAINER" tc qdisc add dev "$iface" root netem \
        delay "${latency_ms}ms" loss "${loss_pct}%"
}

# ── Network Partitioning ─────────────────────────────────────

# Block all traffic between chaos container and a specific host/network
# Usage: chaos_partition <target_host>
# Example: chaos_partition relay
chaos_partition() {
    local target="$1"

    log_info "Creating network partition: blocking traffic to $target"

    # Resolve target IP from within the chaos container
    local target_ip
    target_ip=$(docker exec "$CHAOS_CONTAINER" getent hosts "$target" 2>/dev/null | awk '{print $1}')

    if [[ -z "$target_ip" ]]; then
        log_warn "Cannot resolve $target — trying direct IP"
        target_ip="$target"
    fi

    docker exec "$CHAOS_CONTAINER" iptables -A OUTPUT -d "$target_ip" -j DROP
    docker exec "$CHAOS_CONTAINER" iptables -A INPUT -s "$target_ip" -j DROP
    log_info "Partition active: $target ($target_ip) is unreachable"
}

# Block traffic between two containers (via the chaos container's iptables)
# This blocks FORWARDED traffic — useful when chaos sits in the path
# Usage: chaos_partition_between <host_a> <host_b>
chaos_partition_between() {
    local host_a="$1"
    local host_b="$2"

    log_info "Creating partition between $host_a and $host_b"

    local ip_a ip_b
    ip_a=$(docker exec "$CHAOS_CONTAINER" getent hosts "$host_a" 2>/dev/null | awk '{print $1}' || echo "$host_a")
    ip_b=$(docker exec "$CHAOS_CONTAINER" getent hosts "$host_b" 2>/dev/null | awk '{print $1}' || echo "$host_b")

    # Use the chaos container to add DROP rules for the relevant interface
    # Since chaos is on all networks, it can block traffic it sees
    docker exec "$CHAOS_CONTAINER" iptables -A FORWARD -s "$ip_a" -d "$ip_b" -j DROP 2>/dev/null || true
    docker exec "$CHAOS_CONTAINER" iptables -A FORWARD -s "$ip_b" -d "$ip_a" -j DROP 2>/dev/null || true

    log_info "Partition active between $host_a ($ip_a) and $host_b ($ip_b)"
}

# ── Healing ──────────────────────────────────────────────────

# Remove all network impairments from a network
# Usage: chaos_heal <network_suffix>
chaos_heal() {
    local network="$1"

    local iface
    iface=$(chaos_get_iface "$network")
    if [[ -z "$iface" ]]; then
        log_warn "Could not find interface for network $network"
        return 0  # Not a failure — maybe nothing to heal
    fi

    log_info "Healing network impairments on $network ($iface)"
    docker exec "$CHAOS_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true
}

# Remove all network impairments from all networks
# Usage: chaos_heal_all
chaos_heal_all() {
    log_info "Healing all network impairments"

    for network in frontend backend infra; do
        chaos_heal "$network"
    done

    # Flush iptables rules
    docker exec "$CHAOS_CONTAINER" iptables -F 2>/dev/null || true
    docker exec "$CHAOS_CONTAINER" iptables -F FORWARD 2>/dev/null || true

    log_info "All impairments removed"
}

# ── Status ───────────────────────────────────────────────────

# Show current tc qdisc settings on all interfaces
chaos_status() {
    log_info "Current chaos status:"
    docker exec "$CHAOS_CONTAINER" bash -c '
        echo "=== TC Qdiscs ==="
        for iface in $(ip link show | grep -E "^[0-9]+" | awk -F: "{print \$2}" | tr -d " "); do
            qdisc=$(tc qdisc show dev "$iface" 2>/dev/null | grep -v "^$")
            if [[ -n "$qdisc" ]]; then
                echo "  $iface: $qdisc"
            fi
        done
        echo "=== IPTables ==="
        iptables -L -n 2>/dev/null | grep -v "^Chain\|^target\|^$" | head -20
    ' 2>/dev/null || log_warn "Could not get chaos status"
}

# ── Bandwidth Limiting ───────────────────────────────────────

# Limit bandwidth on a network
# Usage: chaos_limit_bandwidth <network_suffix> <rate>
# Example: chaos_limit_bandwidth frontend 1mbit
chaos_limit_bandwidth() {
    local network="$1"
    local rate="$2"

    local iface
    iface=$(chaos_get_iface "$network")
    if [[ -z "$iface" ]]; then
        log_warn "Could not find interface for network $network"
        return 1
    fi

    log_info "Limiting bandwidth to $rate on $network ($iface)"

    docker exec "$CHAOS_CONTAINER" tc qdisc del dev "$iface" root 2>/dev/null || true
    docker exec "$CHAOS_CONTAINER" tc qdisc add dev "$iface" root tbf \
        rate "$rate" burst 32kbit latency 400ms
}
