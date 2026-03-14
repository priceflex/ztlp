#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ZTLP Stress Test: Impairment Node Entrypoint
# Sets up IP forwarding between client-net and server-net so
# all traffic between client and server passes through this node.
# tc netem rules applied here affect the tunnel traffic.
# ─────────────────────────────────────────────────────────────
set -e

echo "═══════════════════════════════════════════════════════"
echo "  ZTLP Impairment Node"
echo "═══════════════════════════════════════════════════════"

# Enable IP forwarding (may already be set via Docker sysctls)
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then
    echo "  ✓ IP forwarding enabled"
else
    echo "  ⚠ Could not enable IP forwarding — check container sysctls"
fi

# Discover interfaces by subnet
CLIENT_IFACE=""
SERVER_IFACE=""

for iface in $(ip -4 -o addr show | awk '{print $2}' | sort -u); do
    addr=$(ip -4 -o addr show dev "$iface" 2>/dev/null | awk '{print $4}' | head -1)
    case "$addr" in
        172.30.1.*)
            CLIENT_IFACE="$iface"
            echo "  ✓ Client-facing interface: $iface ($addr)"
            ;;
        172.30.2.*)
            SERVER_IFACE="$iface"
            echo "  ✓ Server-facing interface: $iface ($addr)"
            ;;
    esac
done

if [ -z "$CLIENT_IFACE" ] || [ -z "$SERVER_IFACE" ]; then
    echo "  ✗ ERROR: Could not discover both interfaces"
    echo "  Client: ${CLIENT_IFACE:-NOT FOUND}"
    echo "  Server: ${SERVER_IFACE:-NOT FOUND}"
    ip -4 addr show
    exit 1
fi

# Save interface names for external scripts
echo "$CLIENT_IFACE" > /tmp/client_iface
echo "$SERVER_IFACE" > /tmp/server_iface

# Enable forwarding between subnets via iptables
iptables -A FORWARD -i "$CLIENT_IFACE" -o "$SERVER_IFACE" -j ACCEPT
iptables -A FORWARD -i "$SERVER_IFACE" -o "$CLIENT_IFACE" -j ACCEPT
iptables -t nat -A POSTROUTING -o "$SERVER_IFACE" -j MASQUERADE
iptables -t nat -A POSTROUTING -o "$CLIENT_IFACE" -j MASQUERADE
echo "  ✓ iptables forwarding rules set"

# Start iperf3 server in background (for traffic flood scenario)
iperf3 -s -D --logfile /tmp/iperf3.log 2>/dev/null || true
echo "  ✓ iperf3 server running"

# Write default impairment config (passthrough)
echo '{"enabled": false}' > /tmp/impairment.json

# Start the userspace impairment proxy
# Client connects to us on :23095, we forward to server at 172.30.2.40:23095
echo "  → Starting impairment proxy..."
python3 /usr/local/bin/impairment-proxy \
    --port 23095 \
    --server-addr 172.30.2.40 \
    --server-port 23095 &
PROXY_PID=$!
echo "  ✓ Impairment proxy started (PID $PROXY_PID)"

echo ""
echo "  Impairment node ready"
echo "  Client iface: $CLIENT_IFACE"
echo "  Server iface: $SERVER_IFACE"
echo "  Proxy: :23095 → 172.30.2.40:23095"
echo "═══════════════════════════════════════════════════════"

# Keep alive via proxy
wait $PROXY_PID
