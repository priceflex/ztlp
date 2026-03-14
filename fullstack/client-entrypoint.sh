#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ZTLP Full-Stack: Client entrypoint (DEBUG MODE)
# Generates identity, registers with NS, resolves the server
# via NS, connects through ZTLP tunnel, runs SSH + SCP tests.
# ─────────────────────────────────────────────────────────────
set -eo pipefail

# ── Verbose debug logging ───────────────────────────────────
ts() { date "+%H:%M:%S.%3N"; }
log() { echo "[$(ts)] [client] $*"; }
dbg() { echo "[$(ts)] [client] [DEBUG] $*"; }

ZONE="${ZTLP_ZONE:-fullstack.ztlp}"
CLIENT_NAME="${ZTLP_CLIENT_NAME:-client.${ZONE}}"
SERVER_NAME="${ZTLP_SERVER_NAME:-server.${ZONE}}"
NS_SERVER="${ZTLP_NS_SERVER:-ns:23096}"
KEY_DIR="/home/ztlp/.ztlp"
KEY_FILE="${KEY_DIR}/client-identity.json"
LOCAL_PORT="${ZTLP_LOCAL_PORT:-2222}"
BENCHMARK="${ZTLP_BENCHMARK:-true}"

log "═══════════════════════════════════════════════════════"
log "  ZTLP Client — Full-Stack Test (DEBUG MODE)"
log "═══════════════════════════════════════════════════════"
log "  Version:     $(ztlp --version 2>&1 || echo 'unknown')"
log "  Zone:        ${ZONE}"
log "  Client Name: ${CLIENT_NAME}"
log "  Server Name: ${SERVER_NAME}"
log "  NS Server:   ${NS_SERVER}"
log "  Local Port:  ${LOCAL_PORT}"
log "  Benchmark:   ${BENCHMARK}"
log "  RUST_LOG:    ${RUST_LOG:-not set}"
log "═══════════════════════════════════════════════════════"

# ── Step 1: Generate identity ───────────────────────────────
mkdir -p "${KEY_DIR}"
if [ ! -f "${KEY_FILE}" ]; then
    log "→ Generating client identity..."
    ztlp keygen --output "${KEY_FILE}" 2>&1
    log "  ✓ Identity saved to ${KEY_FILE}"
else
    log "→ Using existing identity: ${KEY_FILE}"
fi
dbg "Identity file:"
cat "${KEY_FILE}" 2>&1 | head -5

# ── Step 2: Wait for NS ────────────────────────────────────
log "→ Waiting for NS server at ${NS_SERVER}..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    dbg "  NS probe attempt at ${WAITED}s..."
    NS_RESULT=$(timeout 3 ztlp ns lookup "test.${ZONE}" --ns-server "${NS_SERVER}" 2>&1) || true
    dbg "  NS response: ${NS_RESULT}"
    if echo "${NS_RESULT}" | grep -qiE "not found|found|KEY|SVC|record|No records"; then
        log "  ✓ NS server is responding (${WAITED}s)"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    log "  ⚠ NS server not responding after ${MAX_WAIT}s"
fi

# ── Step 3: Register client with NS ────────────────────────
log "→ Registering client identity with NS..."
REG_OUTPUT=$(ztlp ns register \
    --name "${CLIENT_NAME}" \
    --zone "${ZONE}" \
    --key "${KEY_FILE}" \
    --ns-server "${NS_SERVER}" \
    2>&1) || true
log "  Registration output: ${REG_OUTPUT}"

# ── Step 4: Wait for server to register and resolve it ──────
log "→ Waiting for server '${SERVER_NAME}' to register with NS..."
SERVER_ADDR=""
MAX_WAIT=120
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    NS_OUTPUT=$(timeout 3 ztlp ns lookup "${SERVER_NAME}" --ns-server "${NS_SERVER}" 2>&1) || true
    dbg "  NS lookup for ${SERVER_NAME}: ${NS_OUTPUT}"

    # Look for SVC record with an address
    if echo "${NS_OUTPUT}" | grep -qiE "SVC|address"; then
        SERVER_ADDR=$(echo "${NS_OUTPUT}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -1)
        if [ -n "${SERVER_ADDR}" ]; then
            log "  ✓ Server resolved via SVC: ${SERVER_ADDR}"
            break
        fi
    fi

    # Check for KEY record (server registered but no SVC)
    if echo "${NS_OUTPUT}" | grep -qiE "KEY|key.*record|Ed25519"; then
        log "  ✓ Server KEY found in NS (no SVC record — using Docker hostname)"
        SERVER_ADDR="server:23095"
        break
    fi

    sleep 3
    WAITED=$((WAITED + 3))
    dbg "  waiting for server registration... (${WAITED}s/${MAX_WAIT}s)"
done

if [ -z "${SERVER_ADDR}" ]; then
    log "  ⚠ Could not resolve server from NS — falling back to Docker hostname"
    SERVER_ADDR="server:23095"
fi

# ── Step 5: Connect to server via ZTLP ──────────────────────
log "═══════════════════════════════════════════════════════"
log "  Connecting to server"
log "═══════════════════════════════════════════════════════"
log "  Target:     ${SERVER_ADDR}"
log "  Local port: ${LOCAL_PORT} → SSH"
log "  Command: ztlp connect ${SERVER_ADDR} --key ${KEY_FILE} --service ssh -L ${LOCAL_PORT}:127.0.0.1:22 -vv"

# Start the tunnel in the background, capture stderr for debug
ztlp connect "${SERVER_ADDR}" \
    --key "${KEY_FILE}" \
    --service ssh \
    -L "${LOCAL_PORT}:127.0.0.1:22" \
    -vv \
    2>&1 | while IFS= read -r line; do
        echo "[$(date '+%H:%M:%S.%3N')] [tunnel] ${line}"
    done &
TUNNEL_PID=$!
dbg "Tunnel started as PID ${TUNNEL_PID}"

# Wait for the tunnel to be ready
log "→ Waiting for tunnel to establish (TCP listener on :${LOCAL_PORT})..."
MAX_WAIT=30
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if ss -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}" || \
       netstat -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}"; then
        log "  ✓ Tunnel is active on localhost:${LOCAL_PORT} (${WAITED}s)"
        break
    fi
    # Check if tunnel process died
    if ! kill -0 $TUNNEL_PID 2>/dev/null; then
        log "  ✗ Tunnel process (PID ${TUNNEL_PID}) exited unexpectedly!"
        dbg "  Attempting to get exit code..."
        wait $TUNNEL_PID 2>/dev/null
        EXIT_CODE=$?
        log "  ✗ Tunnel exit code: ${EXIT_CODE}"
        exit 1
    fi
    sleep 1
    WAITED=$((WAITED + 1))
    if [ $((WAITED % 5)) -eq 0 ]; then
        dbg "  Still waiting for port ${LOCAL_PORT}... (${WAITED}s)"
        dbg "  ss -tlnp output: $(ss -tlnp 2>/dev/null | grep -E '${LOCAL_PORT}|LISTEN' | head -3)"
        dbg "  Tunnel PID ${TUNNEL_PID} alive: $(kill -0 $TUNNEL_PID 2>/dev/null && echo 'yes' || echo 'no')"
    fi
done

if [ $WAITED -ge $MAX_WAIT ]; then
    log "  ✗ Tunnel didn't establish within ${MAX_WAIT}s"
    dbg "  Final ss output: $(ss -tlnp 2>/dev/null)"
    dbg "  Final process check: $(ps aux | grep ztlp | head -5)"
    kill $TUNNEL_PID 2>/dev/null || true
    exit 1
fi

# Give the tunnel a moment to stabilize
sleep 2
log ""

# ── Step 6: Run tests ───────────────────────────────────────
log "═══════════════════════════════════════════════════════"
log "  Running Tests"
log "═══════════════════════════════════════════════════════"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o KexAlgorithms=curve25519-sha256 -p ${LOCAL_PORT}"
SCP_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o KexAlgorithms=curve25519-sha256 -P ${LOCAL_PORT}"

# Test 1: SSH echo
log "→ Test 1: SSH echo through ZTLP tunnel..."
dbg "  Running: sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 'echo ZTLP_OK'"
RESULT=$(sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "echo ZTLP_OK" 2>&1) || true
dbg "  Raw result: '${RESULT}'"
if echo "${RESULT}" | grep -q "ZTLP_OK"; then
    log "  ✓ SSH echo: PASS"
else
    log "  ✗ SSH echo: FAIL (got: '${RESULT}')"
    log ""
    log "  Debug: trying verbose SSH..."
    sshpass -e ssh -vvv ${SSH_OPTS} testuser@127.0.0.1 "echo ZTLP_OK" 2>&1 | tail -40
    log ""
    log "  Debug: tunnel process status..."
    kill -0 $TUNNEL_PID 2>/dev/null && log "  Tunnel PID $TUNNEL_PID is alive" || log "  Tunnel PID $TUNNEL_PID is DEAD"
    dbg "  Port status: $(ss -tlnp 2>/dev/null | grep ${LOCAL_PORT})"
fi

# Test 2: Remote command execution
log "→ Test 2: Remote hostname through tunnel..."
HOSTNAME_RESULT=$(sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "hostname" 2>/dev/null) || true
dbg "  Raw result: '${HOSTNAME_RESULT}'"
if [ "$HOSTNAME_RESULT" = "backend" ]; then
    log "  ✓ Remote hostname: '${HOSTNAME_RESULT}' — confirmed backend"
else
    log "  ⚠ Remote hostname: '${HOSTNAME_RESULT}' (expected 'backend')"
fi

# Test 3: Verify tunnel crypto
log "→ Test 3: Remote uname through tunnel..."
UNAME_RESULT=$(sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "uname -a" 2>/dev/null) || true
if [ -n "$UNAME_RESULT" ]; then
    log "  ✓ Remote uname: ${UNAME_RESULT}"
else
    log "  ✗ Could not execute remote command"
fi

# ── Step 7: SCP Benchmarks ──────────────────────────────────
if [ "${BENCHMARK}" = "true" ]; then
    log ""
    log "═══════════════════════════════════════════════════════"
    log "  SCP Benchmark (through ZTLP tunnel)"
    log "═══════════════════════════════════════════════════════"

    mkdir -p /tmp/ztlp-bench

    PASS=0
    FAIL=0

    for SIZE in 1 5 10 50; do
        FILE="/tmp/ztlp-bench/test-${SIZE}MB.bin"
        dd if=/dev/urandom of="${FILE}" bs=1M count=${SIZE} 2>/dev/null
        MD5_ORIG=$(md5sum "${FILE}" | awk '{print $1}')

        log "→ SCP round-trip ${SIZE}MB through ZTLP tunnel..."
        dbg "  Upload starting..."
        START=$(date +%s%N)
        if sshpass -e scp ${SCP_OPTS} "${FILE}" testuser@127.0.0.1:/tmp/test-recv.bin 2>/dev/null; then
            UPLOAD_END=$(date +%s%N)
            dbg "  Upload done, downloading back..."

            if sshpass -e scp ${SCP_OPTS} testuser@127.0.0.1:/tmp/test-recv.bin /tmp/ztlp-bench/test-recv.bin 2>/dev/null; then
                END=$(date +%s%N)
                MD5_RECV=$(md5sum /tmp/ztlp-bench/test-recv.bin | awk '{print $1}')

                UPLOAD_MS=$(( (UPLOAD_END - START) / 1000000 ))
                TOTAL_MS=$(( (END - START) / 1000000 ))
                if [ $UPLOAD_MS -gt 0 ]; then
                    UPLOAD_SPEED=$(echo "scale=1; ${SIZE}*1000/${UPLOAD_MS}" | bc 2>/dev/null || echo "?")
                else
                    UPLOAD_SPEED="∞"
                fi
                if [ $TOTAL_MS -gt 0 ]; then
                    TOTAL_S=$(echo "scale=2; ${TOTAL_MS}/1000" | bc 2>/dev/null || echo "${TOTAL_MS}ms")
                else
                    TOTAL_S="<1ms"
                fi

                if [ "${MD5_ORIG}" = "${MD5_RECV}" ]; then
                    log "  ✓ ${SIZE}MB: upload ${UPLOAD_MS}ms (${UPLOAD_SPEED} MB/s), round-trip ${TOTAL_S}s — checksum ✓"
                    PASS=$((PASS + 1))
                else
                    log "  ✗ ${SIZE}MB: CHECKSUM MISMATCH!"
                    log "    sent:     ${MD5_ORIG}"
                    log "    received: ${MD5_RECV}"
                    FAIL=$((FAIL + 1))
                fi
            else
                log "  ✗ ${SIZE}MB: upload OK but download failed"
                FAIL=$((FAIL + 1))
            fi
        else
            log "  ✗ ${SIZE}MB: SCP upload failed"
            dbg "  Tunnel alive: $(kill -0 $TUNNEL_PID 2>/dev/null && echo 'yes' || echo 'no')"
            FAIL=$((FAIL + 1))
        fi

        # Clean up
        sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "rm -f /tmp/test-recv.bin" 2>/dev/null || true
        rm -f /tmp/ztlp-bench/test-recv.bin
    done

    log ""
    log "═══════════════════════════════════════════════════════"
    log "  Benchmark Results: ${PASS} passed, ${FAIL} failed"
    log "═══════════════════════════════════════════════════════"
fi

log ""
log "═══════════════════════════════════════════════════════"
log "  Full-Stack Test Complete"
log "═══════════════════════════════════════════════════════"
log ""
log "  Tunnel still active on localhost:${LOCAL_PORT}"
log "  To connect manually:"
log "    docker exec -it ztlp-client sshpass -e ssh -p ${LOCAL_PORT} -o StrictHostKeyChecking=no testuser@127.0.0.1"

# Keep tunnel running for manual testing
wait $TUNNEL_PID
