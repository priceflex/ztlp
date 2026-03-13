#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ZTLP Full-Stack: Server (listener) entrypoint
# Generates identity, registers with NS, then listens for
# incoming ZTLP connections and forwards to backend SSH.
# ─────────────────────────────────────────────────────────────
set -e

ZONE="${ZTLP_ZONE:-fullstack.ztlp}"
SERVER_NAME="${ZTLP_SERVER_NAME:-server.${ZONE}}"
NS_SERVER="${ZTLP_NS_SERVER:-ns:23096}"
BIND_ADDR="${ZTLP_BIND_ADDR:-0.0.0.0:23095}"
BACKEND="${ZTLP_BACKEND:-backend:22}"
KEY_DIR="/home/ztlp/.ztlp"
KEY_FILE="${KEY_DIR}/server-identity.json"

echo "═══════════════════════════════════════════════════════"
echo "  ZTLP Server — Full-Stack Test"
echo "═══════════════════════════════════════════════════════"
echo "  Zone:       ${ZONE}"
echo "  Name:       ${SERVER_NAME}"
echo "  NS Server:  ${NS_SERVER}"
echo "  Bind:       ${BIND_ADDR}"
echo "  Backend:    ssh://${BACKEND}"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Step 1: Generate identity (if not already present) ──────
mkdir -p "${KEY_DIR}"
if [ ! -f "${KEY_FILE}" ]; then
    echo "→ Generating server identity..."
    ztlp keygen --output "${KEY_FILE}"
    echo "  ✓ Identity saved to ${KEY_FILE}"
else
    echo "→ Using existing identity: ${KEY_FILE}"
fi
echo ""

# ── Step 2: Wait for NS to be ready ────────────────────────
echo "→ Waiting for NS server at ${NS_SERVER}..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    # Send a dummy lookup — any response (including "not found") means NS is alive
    if timeout 2 ztlp ns lookup "test.${ZONE}" --ns-server "${NS_SERVER}" 2>&1 | grep -qiE "not found|found|KEY|SVC|record|error|No records"; then
        echo "  ✓ NS server is responding"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    echo "    waiting... (${WAITED}s)"
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "  ⚠ NS server not responding after ${MAX_WAIT}s — proceeding anyway"
fi
echo ""

# ── Step 3: Register with NS ───────────────────────────────
echo "→ Registering server identity with NS..."
# Register KEY + SVC records. The SVC address tells clients how to reach us.
# We advertise our Docker IP so the client can connect directly.
OUR_IP=$(hostname -i 2>/dev/null || echo "0.0.0.0")
SVC_ADDR="${OUR_IP}:23095"

ztlp ns register \
    --name "${SERVER_NAME}" \
    --zone "${ZONE}" \
    --key "${KEY_FILE}" \
    --ns-server "${NS_SERVER}" \
    --address "${SVC_ADDR}" \
    2>&1 || echo "  ⚠ Registration may have failed — continuing anyway"
echo ""

# ── Step 4: Start listening ─────────────────────────────────
echo "→ Starting ZTLP listener..."
echo "  Forwarding service 'ssh' → ${BACKEND}"
echo "  Listening on ${BIND_ADDR}"
echo "  Advertised address: ${SVC_ADDR}"
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Server is LIVE — waiting for client connections"
echo "═══════════════════════════════════════════════════════"
echo ""

exec ztlp listen \
    --bind "${BIND_ADDR}" \
    --key "${KEY_FILE}" \
    --forward "ssh:${BACKEND}" \
    --gateway
