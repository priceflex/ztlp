#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ZTLP Full-Stack: Server (listener) entrypoint
# Generates identity, registers with NS, then listens for
# incoming ZTLP connections and forwards to backend SSH.
# ─────────────────────────────────────────────────────────────
set -eo pipefail

# ── Verbose debug logging ───────────────────────────────────
ts() { date "+%H:%M:%S.%3N"; }
log() { echo "[$(ts)] [server] $*"; }
dbg() { echo "[$(ts)] [server] [DEBUG] $*"; }

ZONE="${ZTLP_ZONE:-fullstack.ztlp}"
SERVER_NAME="${ZTLP_SERVER_NAME:-server.${ZONE}}"
NS_SERVER="${ZTLP_NS_SERVER:-ns:23096}"
BIND_ADDR="${ZTLP_BIND_ADDR:-0.0.0.0:23095}"
BACKEND="${ZTLP_BACKEND:-backend:22}"
HTTP_BACKEND="${ZTLP_HTTP_BACKEND:-backend:8080}"

# Resolve hostname to IP for --forward args (ztlp needs IP:PORT)
resolve_backend() {
    local addr="$1"
    local host="${addr%%:*}"
    local port="${addr##*:}"
    local ip
    ip=$(getent hosts "$host" 2>/dev/null | awk '{print $1; exit}')
    if [ -n "$ip" ]; then
        echo "${ip}:${port}"
    else
        echo "$addr"
    fi
}
KEY_DIR="/home/ztlp/.ztlp"
KEY_FILE="${KEY_DIR}/server-identity.json"

log "═══════════════════════════════════════════════════════"
log "  ZTLP Server — Full-Stack Test (DEBUG MODE)"
log "═══════════════════════════════════════════════════════"
log "  Version:    $(ztlp --version 2>&1 || echo 'unknown')"
log "  Zone:       ${ZONE}"
log "  Name:       ${SERVER_NAME}"
log "  NS Server:  ${NS_SERVER}"
log "  Bind:       ${BIND_ADDR}"
log "  Backend:    ssh://${BACKEND}, http://${HTTP_BACKEND}"
log "  RUST_LOG:   ${RUST_LOG:-not set}"
log "═══════════════════════════════════════════════════════"

# ── Step 1: Generate identity ───────────────────────────────
mkdir -p "${KEY_DIR}"
if [ ! -f "${KEY_FILE}" ]; then
    log "→ Generating server identity..."
    ztlp keygen --output "${KEY_FILE}" 2>&1
    log "  ✓ Identity saved to ${KEY_FILE}"
else
    log "→ Using existing identity: ${KEY_FILE}"
fi

# Show identity info
dbg "Identity file contents:"
cat "${KEY_FILE}" 2>&1 | head -5

# ── Step 2: Wait for NS to be ready ────────────────────────
log "→ Waiting for NS server at ${NS_SERVER}..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    dbg "  NS probe attempt at ${WAITED}s..."
    NS_RESULT=$(timeout 3 ztlp ns lookup "test.${ZONE}" --ns-server "${NS_SERVER}" 2>&1) || true
    dbg "  NS response: ${NS_RESULT}"

    if echo "${NS_RESULT}" | grep -qiE "not found|found|KEY|SVC|record|error|No records"; then
        log "  ✓ NS server is responding (${WAITED}s)"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    log "  ⚠ NS server not responding after ${MAX_WAIT}s — proceeding anyway"
fi

# ── Step 3: Register with NS ───────────────────────────────
OUR_IP=$(hostname -i 2>/dev/null || echo "0.0.0.0")
SVC_ADDR="${OUR_IP}:23095"
log "→ Registering server identity with NS..."
dbg "  Our IP: ${OUR_IP}, SVC address: ${SVC_ADDR}"

REG_OUTPUT=$(ztlp ns register \
    --name "${SERVER_NAME}" \
    --zone "${ZONE}" \
    --key "${KEY_FILE}" \
    --ns-server "${NS_SERVER}" \
    --address "${SVC_ADDR}" \
    2>&1) || true
log "  Registration output: ${REG_OUTPUT}"

# Verify registration
dbg "→ Verifying registration..."
VERIFY=$(timeout 3 ztlp ns lookup "${SERVER_NAME}" --ns-server "${NS_SERVER}" 2>&1) || true
dbg "  Lookup result: ${VERIFY}"

# ── Step 4: Start listening ─────────────────────────────────
log "→ Starting ZTLP listener with DEBUG output..."
# Resolve backends to IPs
BACKEND_RESOLVED=$(resolve_backend "${BACKEND}")
HTTP_BACKEND_RESOLVED=$(resolve_backend "${HTTP_BACKEND}")

log "  Command: ztlp listen --bind ${BIND_ADDR} --key ${KEY_FILE} --forward ssh:${BACKEND_RESOLVED} --forward http:${HTTP_BACKEND_RESOLVED} --ns-server ${NS_SERVER} --gateway -vv"
log ""
log "═══════════════════════════════════════════════════════"
log "  Server is LIVE — waiting for client connections"
log "═══════════════════════════════════════════════════════"
log ""

exec ztlp listen \
    --bind "${BIND_ADDR}" \
    --key "${KEY_FILE}" \
    --forward "ssh:${BACKEND_RESOLVED}" \
    --forward "http:${HTTP_BACKEND_RESOLVED}" \
    --ns-server "${NS_SERVER}" \
    --gateway \
    -vv
