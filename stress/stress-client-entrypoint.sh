#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ZTLP Stress Test: Client entrypoint
# Registers with NS, sets up routing through impairment node,
# then stays alive for the stress test runner.
# ─────────────────────────────────────────────────────────────
set -eo pipefail

ts() { date "+%H:%M:%S.%3N"; }
log() { echo "[$(ts)] [client] $*"; }

ZONE="${ZTLP_ZONE:-stress.ztlp}"
CLIENT_NAME="${ZTLP_CLIENT_NAME:-client.${ZONE}}"
SERVER_NAME="${ZTLP_SERVER_NAME:-server.${ZONE}}"
NS_SERVER="${ZTLP_NS_SERVER:-172.30.1.10:23096}"
KEY_DIR="/home/ztlp/.ztlp"
KEY_FILE="${KEY_DIR}/client-identity.json"
LOCAL_PORT="${ZTLP_LOCAL_PORT:-2222}"

log "═══════════════════════════════════════════════════════"
log "  ZTLP Stress Test Client"
log "═══════════════════════════════════════════════════════"
log "  Version:     $(ztlp --version 2>&1 || echo 'unknown')"
log "  Zone:        ${ZONE}"
log "  NS Server:   ${NS_SERVER}"
log "═══════════════════════════════════════════════════════"

# ── Step 1: Generate identity ───────────────────────────────
mkdir -p "${KEY_DIR}"
if [ ! -f "${KEY_FILE}" ]; then
    log "→ Generating client identity..."
    ztlp keygen --output "${KEY_FILE}" 2>&1
    log "  ✓ Identity saved"
fi

# ── Step 2: Wait for NS ────────────────────────────────────
log "→ Waiting for NS server..."
for i in $(seq 1 30); do
    NS_RESULT=$(timeout 3 ztlp ns lookup "test.${ZONE}" --ns-server "${NS_SERVER}" 2>&1) || true
    if echo "${NS_RESULT}" | grep -qiE "not found|found|KEY|SVC|record|No records"; then
        log "  ✓ NS responding (${i}s)"
        break
    fi
    sleep 2
done

# ── Step 3: Register with NS ───────────────────────────────
log "→ Registering client identity..."
ztlp ns register --name "${CLIENT_NAME}" --zone "${ZONE}" --key "${KEY_FILE}" --ns-server "${NS_SERVER}" 2>&1 || true

# ── Step 4: Wait for server registration ───────────────────
log "→ Waiting for server in NS..."
for i in $(seq 1 60); do
    NS_OUTPUT=$(timeout 3 ztlp ns lookup "${SERVER_NAME}" --ns-server "${NS_SERVER}" 2>&1) || true
    if echo "${NS_OUTPUT}" | grep -qiE "KEY|SVC|Ed25519"; then
        log "  ✓ Server found in NS (${i}s)"
        break
    fi
    sleep 3
done

log ""
log "  Client ready — waiting for stress test commands"
log "  Run scenarios via: docker exec stress-client /scenario.sh"
log "═══════════════════════════════════════════════════════"

# Keep alive for stress test runner
exec sleep infinity
