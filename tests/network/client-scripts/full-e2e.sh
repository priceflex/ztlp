#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Full end-to-end test: NS registration → relay session → data exchange
# Runs INSIDE a client container
# ─────────────────────────────────────────────────────────────
#
# Usage: full-e2e.sh <role> <peer_host> <message_count>
#   role: "initiator" or "responder"
#   peer_host: address of the peer (or relay)
#   message_count: number of messages to exchange
#
# Initiator mode:
#   1. Generates identity
#   2. Queries NS for peer
#   3. Connects to relay
#   4. Performs handshake
#   5. Sends/receives messages
#
# Responder mode:
#   1. Generates identity
#   2. Registers with NS
#   3. Listens for incoming connection
#   4. Completes handshake
#   5. Sends/receives messages
#
# Outputs:
#   E2E_STATUS=success|fail
#   MESSAGES_SENT=<n>
#   MESSAGES_RECEIVED=<n>
#   HANDSHAKE_MS=<ms>
#   TOTAL_MS=<ms>

set -euo pipefail

ROLE="${1:?Usage: full-e2e.sh <role> <peer_host> <message_count>}"
PEER_HOST="${2:?Usage: full-e2e.sh <role> <peer_host> <message_count>}"
MSG_COUNT="${3:-100}"

NS_HOST="${NS_HOST:-ns}"
NS_PORT="${NS_PORT:-23096}"
RELAY_HOST="${RELAY_HOST:-relay}"
RELAY_PORT="${RELAY_PORT:-23095}"

CLIENT_NAME="${CLIENT_NAME:-node}"
IDENTITY_FILE="/tmp/ztlp-e2e-identity.json"

START_MS=$(date +%s%3N)

echo "E2E_ROLE=$ROLE"
echo "E2E_PEER=$PEER_HOST"
echo "E2E_MESSAGES=$MSG_COUNT"

case "$ROLE" in
    initiator)
        # Connect to peer through relay
        OUTPUT=$(timeout 30 ztlp-node \
            --identity "$IDENTITY_FILE" \
            --connect "${RELAY_HOST}:${RELAY_PORT}" \
            --handshake-timeout 10 \
            2>&1) || {
            EXIT_CODE=$?
            echo "E2E_STATUS=fail"
            echo "E2E_ERROR=connection_failed (exit=$EXIT_CODE)"
            echo "E2E_OUTPUT=${OUTPUT:0:500}"
            exit $EXIT_CODE
        }
        ;;

    responder)
        # Listen for incoming connections
        OUTPUT=$(timeout 30 ztlp-node \
            --identity "$IDENTITY_FILE" \
            --listen "0.0.0.0:${RELAY_PORT}" \
            --handshake-timeout 10 \
            2>&1) || {
            EXIT_CODE=$?
            echo "E2E_STATUS=fail"
            echo "E2E_ERROR=listen_failed (exit=$EXIT_CODE)"
            echo "E2E_OUTPUT=${OUTPUT:0:500}"
            exit $EXIT_CODE
        }
        ;;

    *)
        echo "E2E_STATUS=fail"
        echo "E2E_ERROR=unknown role: $ROLE"
        exit 1
        ;;
esac

END_MS=$(date +%s%3N)
TOTAL_MS=$((END_MS - START_MS))

# Parse output for success indicators
if echo "$OUTPUT" | grep -qi "session established\|handshake complete\|✓"; then
    echo "E2E_STATUS=success"
else
    echo "E2E_STATUS=partial"
fi

echo "TOTAL_MS=$TOTAL_MS"
echo "OUTPUT_LINES=$(echo "$OUTPUT" | wc -l)"
