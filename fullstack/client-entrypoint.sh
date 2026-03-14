#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ZTLP Full-Stack: Client entrypoint (DEBUG MODE)
# ─────────────────────────────────────────────────────────────
set -eo pipefail

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
log "  NS Server:   ${NS_SERVER}"
log "  RUST_LOG:    ${RUST_LOG:-not set}"
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
        log "  ✓ NS responding"
        break
    fi
    sleep 2
done

# ── Step 3: Register with NS ───────────────────────────────
log "→ Registering client identity..."
ztlp ns register --name "${CLIENT_NAME}" --zone "${ZONE}" --key "${KEY_FILE}" --ns-server "${NS_SERVER}" 2>&1 || true

# ── Step 4: Resolve server ──────────────────────────────────
log "→ Resolving server..."
SERVER_ADDR=""
for i in $(seq 1 40); do
    NS_OUTPUT=$(timeout 3 ztlp ns lookup "${SERVER_NAME}" --ns-server "${NS_SERVER}" 2>&1) || true
    if echo "${NS_OUTPUT}" | grep -qiE "KEY|SVC|Ed25519"; then
        SERVER_ADDR="server:23095"
        log "  ✓ Server found in NS"
        break
    fi
    sleep 3
done
SERVER_ADDR="${SERVER_ADDR:-server:23095}"

# ── Step 5: Start tunnel ───────────────────────────────────
log "═══════════════════════════════════════════════════════"
log "  Starting ZTLP Tunnel"
log "═══════════════════════════════════════════════════════"

ztlp connect "${SERVER_ADDR}" \
    --key "${KEY_FILE}" \
    --service ssh \
    -L "${LOCAL_PORT}:127.0.0.1:22" \
    -vv \
    2>&1 | while IFS= read -r line; do
        echo "[$(date '+%H:%M:%S.%3N')] [tunnel] ${line}"
    done &
TUNNEL_PID=$!

log "→ Waiting for tunnel on :${LOCAL_PORT}..."
for i in $(seq 1 30); do
    if ss -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}"; then
        log "  ✓ Tunnel active (${i}s)"
        break
    fi
    if ! kill -0 $TUNNEL_PID 2>/dev/null; then
        log "  ✗ Tunnel died!"
        exit 1
    fi
    sleep 1
done
sleep 2

# ── Step 6: Tests (single SSH session for everything) ───────
log "═══════════════════════════════════════════════════════"
log "  Running Tests (single SSH session)"
log "═══════════════════════════════════════════════════════"
log ""
log "  NOTE: ZTLP tunnel bridges ONE TCP connection."
log "  All tests use a single persistent SSH session."

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o KexAlgorithms=curve25519-sha256 -p ${LOCAL_PORT}"

# Test 1: SSH echo
log "→ Test 1: SSH echo..."
RESULT=$(sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "echo ZTLP_OK" 2>&1) || true
if echo "${RESULT}" | grep -q "ZTLP_OK"; then
    log "  ✓ SSH echo: PASS"
else
    log "  ✗ SSH echo: FAIL (got: '${RESULT}')"
fi

# After the SSH session closes, the tunnel bridge ends.
# We need a NEW tunnel for the next test since the bridge is one-shot.
# Kill the old tunnel, start a new one.

kill $TUNNEL_PID 2>/dev/null || true
sleep 1

# ── Step 7: Benchmarks (each gets its own tunnel) ──────────
if [ "${BENCHMARK}" = "true" ]; then
    log ""
    log "═══════════════════════════════════════════════════════"
    log "  Benchmark: File Transfer via SSH"
    log "═══════════════════════════════════════════════════════"
    log "  Each transfer uses a fresh ZTLP tunnel"

    mkdir -p /tmp/ztlp-bench
    PASS=0
    FAIL=0

    for SIZE in 1 5 10; do
        FILE="/tmp/ztlp-bench/test-${SIZE}MB.bin"
        dd if=/dev/urandom of="${FILE}" bs=1M count=${SIZE} 2>/dev/null
        MD5_ORIG=$(md5sum "${FILE}" | awk '{print $1}')

        log "→ ${SIZE}MB round-trip through ZTLP tunnel..."

        # Start fresh tunnel for this transfer
        ztlp connect "${SERVER_ADDR}" \
            --key "${KEY_FILE}" \
            --service ssh \
            -L "${LOCAL_PORT}:127.0.0.1:22" \
            -vv 2>&1 | while IFS= read -r line; do
                echo "[$(date '+%H:%M:%S.%3N')] [tunnel] ${line}"
            done &
        BENCH_TUNNEL_PID=$!
        
        # Wait for tunnel
        for j in $(seq 1 15); do
            if ss -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}"; then break; fi
            sleep 1
        done
        sleep 1

        START=$(date +%s%N)
        
        # Upload via ssh pipe (single connection)
        dbg "  Uploading ${SIZE}MB..."
        if sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 \
            "cat > /tmp/test-recv.bin && md5sum /tmp/test-recv.bin | awk '{print \$1}'" \
            < "${FILE}" > /tmp/ztlp-bench/remote-md5.txt 2>/dev/null; then
            
            END=$(date +%s%N)
            REMOTE_MD5=$(cat /tmp/ztlp-bench/remote-md5.txt 2>/dev/null | tr -d '[:space:]')
            TOTAL_MS=$(( (END - START) / 1000000 ))
            
            if [ $TOTAL_MS -gt 0 ]; then
                SPEED=$(echo "scale=1; ${SIZE}*1000/${TOTAL_MS}" | bc 2>/dev/null || echo "?")
            else
                SPEED="∞"
            fi

            if [ "${MD5_ORIG}" = "${REMOTE_MD5}" ]; then
                log "  ✓ ${SIZE}MB: ${TOTAL_MS}ms (${SPEED} MB/s) — checksum ✓"
                PASS=$((PASS + 1))
            else
                log "  ✗ ${SIZE}MB: CHECKSUM MISMATCH (local=${MD5_ORIG} remote=${REMOTE_MD5})"
                FAIL=$((FAIL + 1))
            fi
        else
            log "  ✗ ${SIZE}MB: transfer failed"
            FAIL=$((FAIL + 1))
        fi

        # Kill this tunnel before next iteration
        kill $BENCH_TUNNEL_PID 2>/dev/null || true
        sleep 1
    done

    log ""
    log "═══════════════════════════════════════════════════════"
    log "  Benchmark Results: ${PASS} passed, ${FAIL} failed"
    log "═══════════════════════════════════════════════════════"
fi

log ""
log "═══════════════════════════════════════════════════════"
log "  Full-Stack Test Complete!"
log "═══════════════════════════════════════════════════════"

# Keep alive for manual testing
log "  Starting idle tunnel for manual access..."
ztlp connect "${SERVER_ADDR}" \
    --key "${KEY_FILE}" \
    --service ssh \
    -L "${LOCAL_PORT}:127.0.0.1:22" \
    -vv 2>&1 | while IFS= read -r line; do
        echo "[$(date '+%H:%M:%S.%3N')] [tunnel] ${line}"
    done &
FINAL_TUNNEL=$!
log "  Tunnel active — docker exec -it ztlp-client sshpass -e ssh -p ${LOCAL_PORT} -o StrictHostKeyChecking=no testuser@127.0.0.1"
wait $FINAL_TUNNEL
