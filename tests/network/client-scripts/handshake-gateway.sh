#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Perform Noise_XX handshake with the ZTLP Gateway
# Runs INSIDE a client container
# ─────────────────────────────────────────────────────────────
#
# Usage: handshake-gateway.sh [gateway_host] [gateway_port]
#
# Performs the three-message Noise_XX handshake:
#   1. Client → Gateway: HELLO (ephemeral key)
#   2. Gateway → Client: HELLO_ACK (encrypted identity)
#   3. Client → Gateway: HELLO_COMPLETE (encrypted identity)
#
# Uses the ztlp-node binary in initiator mode.
#
# Outputs:
#   HANDSHAKE=success|fail|timeout
#   ELAPSED_MS=<ms>
#   PEER_NODE_ID=<hex>

set -euo pipefail

GATEWAY_HOST="${1:-${GATEWAY_HOST:-gateway}}"
GATEWAY_PORT="${2:-${GATEWAY_PORT:-23097}}"

IDENTITY_FILE="/tmp/ztlp-handshake-identity.json"

# Run ztlp-node in initiator mode with a timeout
# It will attempt a Noise_XX handshake with the gateway
START_MS=$(date +%s%3N)

HANDSHAKE_OUTPUT=$(timeout 15 ztlp-node \
    --identity "$IDENTITY_FILE" \
    --connect "${GATEWAY_HOST}:${GATEWAY_PORT}" \
    --handshake-timeout 10 \
    2>&1) || {
    EXIT_CODE=$?
    END_MS=$(date +%s%3N)
    ELAPSED=$((END_MS - START_MS))
    if [[ $EXIT_CODE -eq 124 ]]; then
        echo "HANDSHAKE=timeout"
    else
        echo "HANDSHAKE=fail"
    fi
    echo "ELAPSED_MS=$ELAPSED"
    echo "OUTPUT=${HANDSHAKE_OUTPUT:0:500}"
    exit $EXIT_CODE
}

END_MS=$(date +%s%3N)
ELAPSED=$((END_MS - START_MS))

# Check if handshake succeeded (look for success indicators in output)
if echo "$HANDSHAKE_OUTPUT" | grep -qi "handshake complete\|session established\|✓"; then
    echo "HANDSHAKE=success"
else
    echo "HANDSHAKE=unknown"
fi

echo "ELAPSED_MS=$ELAPSED"

# Try to extract peer node ID from output
PEER_ID=$(echo "$HANDSHAKE_OUTPUT" | grep -oP 'peer.*?([0-9a-f]{32,})' | head -1 || echo "")
if [[ -n "$PEER_ID" ]]; then
    echo "PEER_NODE_ID=$PEER_ID"
fi

echo "OUTPUT_LINES=$(echo "$HANDSHAKE_OUTPUT" | wc -l)"
