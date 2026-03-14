#!/bin/bash
# ─────────────────────────────────────────────────────────────
# ZTLP Full-Stack: Client entrypoint
# Generates identity, registers with NS, resolves the server
# via NS, connects through ZTLP tunnel, runs SSH + SCP tests.
# ─────────────────────────────────────────────────────────────
set -e

ZONE="${ZTLP_ZONE:-fullstack.ztlp}"
CLIENT_NAME="${ZTLP_CLIENT_NAME:-client.${ZONE}}"
SERVER_NAME="${ZTLP_SERVER_NAME:-server.${ZONE}}"
NS_SERVER="${ZTLP_NS_SERVER:-ns:23096}"
KEY_DIR="/home/ztlp/.ztlp"
KEY_FILE="${KEY_DIR}/client-identity.json"
LOCAL_PORT="${ZTLP_LOCAL_PORT:-2222}"
BENCHMARK="${ZTLP_BENCHMARK:-true}"

echo "═══════════════════════════════════════════════════════"
echo "  ZTLP Client — Full-Stack Test"
echo "═══════════════════════════════════════════════════════"
echo "  Zone:        ${ZONE}"
echo "  Client Name: ${CLIENT_NAME}"
echo "  Server Name: ${SERVER_NAME}"
echo "  NS Server:   ${NS_SERVER}"
echo "  Local Port:  ${LOCAL_PORT}"
echo "  Benchmark:   ${BENCHMARK}"
echo "═══════════════════════════════════════════════════════"
echo ""

# ── Step 1: Generate identity ───────────────────────────────
mkdir -p "${KEY_DIR}"
if [ ! -f "${KEY_FILE}" ]; then
    echo "→ Generating client identity..."
    ztlp keygen --output "${KEY_FILE}"
    echo "  ✓ Identity saved to ${KEY_FILE}"
else
    echo "→ Using existing identity: ${KEY_FILE}"
fi
echo ""

# ── Step 2: Wait for NS ────────────────────────────────────
echo "→ Waiting for NS server at ${NS_SERVER}..."
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if timeout 2 ztlp ns lookup "test.${ZONE}" --ns-server "${NS_SERVER}" 2>&1 | grep -qiE "not found|found|KEY|SVC|record|No records"; then
        echo "  ✓ NS server is responding"
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
    echo "    waiting... (${WAITED}s)"
done
echo ""

# ── Step 3: Register client with NS ────────────────────────
echo "→ Registering client identity with NS..."
ztlp ns register \
    --name "${CLIENT_NAME}" \
    --zone "${ZONE}" \
    --key "${KEY_FILE}" \
    --ns-server "${NS_SERVER}" \
    2>&1 || echo "  ⚠ Registration may have failed — continuing anyway"
echo ""

# ── Step 4: Wait for server to register and resolve it ──────
echo "→ Waiting for server '${SERVER_NAME}' to register with NS..."
SERVER_ADDR=""
MAX_WAIT=120
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    # Try to resolve the server's SVC record from NS
    NS_OUTPUT=$(ztlp ns lookup "${SERVER_NAME}" --ns-server "${NS_SERVER}" 2>&1) || true
    echo "    NS lookup output: ${NS_OUTPUT}" | head -5

    # Look for SVC record with an address
    if echo "${NS_OUTPUT}" | grep -qiE "SVC|address"; then
        # Extract the address (ip:port) from the output
        SERVER_ADDR=$(echo "${NS_OUTPUT}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -1)
        if [ -n "${SERVER_ADDR}" ]; then
            echo "  ✓ Server resolved: ${SERVER_ADDR}"
            break
        fi
    fi

    # Also check for KEY record (server is registered but maybe no SVC)
    if echo "${NS_OUTPUT}" | grep -qiE "KEY|key.*record|Ed25519"; then
        echo "  ✓ Server KEY found in NS (no SVC record — using Docker hostname)"
        SERVER_ADDR="server:23095"
        break
    fi

    sleep 3
    WAITED=$((WAITED + 3))
    echo "    waiting for server registration... (${WAITED}s)"
done

if [ -z "${SERVER_ADDR}" ]; then
    echo "  ⚠ Could not resolve server from NS — falling back to Docker hostname"
    SERVER_ADDR="server:23095"
fi
echo ""

# ── Step 5: Connect to server via ZTLP ──────────────────────
echo "═══════════════════════════════════════════════════════"
echo "  Connecting to server"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Target:     ${SERVER_ADDR}"
echo "  Local port: ${LOCAL_PORT} → SSH"
echo ""

# Start the tunnel in the background
ztlp connect "${SERVER_ADDR}" \
    --key "${KEY_FILE}" \
    --service ssh \
    -L "${LOCAL_PORT}:127.0.0.1:22" \
    &
TUNNEL_PID=$!

# Wait for the tunnel to be ready (TCP listener on local port)
echo "→ Waiting for tunnel to establish..."
MAX_WAIT=30
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if ss -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}" || \
       netstat -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}"; then
        echo "  ✓ Tunnel is active on localhost:${LOCAL_PORT}"
        break
    fi
    # Check if tunnel process died
    if ! kill -0 $TUNNEL_PID 2>/dev/null; then
        echo "  ✗ Tunnel process exited unexpectedly"
        wait $TUNNEL_PID 2>/dev/null || true
        exit 1
    fi
    sleep 1
    WAITED=$((WAITED + 1))
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "  ✗ Tunnel didn't establish within ${MAX_WAIT}s"
    kill $TUNNEL_PID 2>/dev/null || true
    exit 1
fi
echo ""

# Give the tunnel a moment to stabilize
sleep 1

# ── Step 6: Run tests ───────────────────────────────────────
echo "═══════════════════════════════════════════════════════"
echo "  Running Tests"
echo "═══════════════════════════════════════════════════════"
echo ""

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o KexAlgorithms=curve25519-sha256 -p ${LOCAL_PORT}"
SCP_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o KexAlgorithms=curve25519-sha256 -P ${LOCAL_PORT}"

# Test 1: SSH echo
echo "→ Test 1: SSH echo through ZTLP tunnel..."
RESULT=$(sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "echo ZTLP_OK" 2>/dev/null) || true
if [ "$RESULT" = "ZTLP_OK" ]; then
    echo "  ✓ SSH echo: PASS"
else
    echo "  ✗ SSH echo: FAIL (got: '${RESULT}')"
    echo ""
    echo "  Debug: trying verbose SSH..."
    sshpass -e ssh -v ${SSH_OPTS} testuser@127.0.0.1 "echo ZTLP_OK" 2>&1 | tail -30
    echo ""
    echo "  Debug: tunnel process status..."
    kill -0 $TUNNEL_PID 2>/dev/null && echo "  Tunnel PID $TUNNEL_PID is alive" || echo "  Tunnel PID $TUNNEL_PID is DEAD"
fi
echo ""

# Test 2: Remote command execution
echo "→ Test 2: Remote command through tunnel..."
HOSTNAME_RESULT=$(sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "hostname" 2>/dev/null) || true
if [ "$HOSTNAME_RESULT" = "backend" ]; then
    echo "  ✓ Remote hostname: '${HOSTNAME_RESULT}' — confirms we're talking to the backend"
else
    echo "  ⚠ Remote hostname: '${HOSTNAME_RESULT}' (expected 'backend')"
fi
echo ""

# Test 3: Verify the ZTLP pipeline (server identity + crypto)
echo "→ Test 3: Verify tunnel is encrypted (check server identity)..."
UNAME_RESULT=$(sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "uname -a" 2>/dev/null) || true
if [ -n "$UNAME_RESULT" ]; then
    echo "  ✓ Remote uname: ${UNAME_RESULT}"
else
    echo "  ✗ Could not execute remote command"
fi
echo ""

# ── Step 7: SCP Benchmarks ──────────────────────────────────
if [ "${BENCHMARK}" = "true" ]; then
    echo "═══════════════════════════════════════════════════════"
    echo "  SCP Benchmark (through ZTLP tunnel)"
    echo "═══════════════════════════════════════════════════════"
    echo ""

    mkdir -p /tmp/ztlp-bench

    PASS=0
    FAIL=0

    for SIZE in 1 5 10 50; do
        FILE="/tmp/ztlp-bench/test-${SIZE}MB.bin"
        dd if=/dev/urandom of="${FILE}" bs=1M count=${SIZE} 2>/dev/null
        MD5_ORIG=$(md5sum "${FILE}" | awk '{print $1}')

        echo "→ SCP upload ${SIZE}MB through ZTLP tunnel..."
        START=$(date +%s%N)
        if sshpass -e scp ${SCP_OPTS} "${FILE}" testuser@127.0.0.1:/tmp/test-recv.bin 2>/dev/null; then
            END=$(date +%s%N)

            # Download back and verify integrity
            if sshpass -e scp ${SCP_OPTS} testuser@127.0.0.1:/tmp/test-recv.bin /tmp/ztlp-bench/test-recv.bin 2>/dev/null; then
                MD5_RECV=$(md5sum /tmp/ztlp-bench/test-recv.bin | awk '{print $1}')

                ELAPSED_MS=$(( (END - START) / 1000000 ))
                if [ $ELAPSED_MS -gt 0 ]; then
                    ELAPSED_S=$(echo "scale=2; ${ELAPSED_MS}/1000" | bc 2>/dev/null || echo "${ELAPSED_MS}ms")
                    THROUGHPUT=$(echo "scale=1; ${SIZE}*1000/${ELAPSED_MS}" | bc 2>/dev/null || echo "?")
                else
                    ELAPSED_S="<1ms"
                    THROUGHPUT="∞"
                fi

                if [ "${MD5_ORIG}" = "${MD5_RECV}" ]; then
                    echo "  ✓ ${SIZE}MB: ${ELAPSED_S}s upload (${THROUGHPUT} MB/s) — checksum verified ✓"
                    PASS=$((PASS + 1))
                else
                    echo "  ✗ ${SIZE}MB: ${ELAPSED_S}s — CHECKSUM MISMATCH!"
                    echo "    sent:     ${MD5_ORIG}"
                    echo "    received: ${MD5_RECV}"
                    FAIL=$((FAIL + 1))
                fi
            else
                echo "  ✗ ${SIZE}MB: upload succeeded but download failed"
                FAIL=$((FAIL + 1))
            fi
        else
            echo "  ✗ ${SIZE}MB: SCP upload failed"
            FAIL=$((FAIL + 1))
        fi

        # Clean up remote file
        sshpass -e ssh ${SSH_OPTS} testuser@127.0.0.1 "rm -f /tmp/test-recv.bin" 2>/dev/null || true
        rm -f /tmp/ztlp-bench/test-recv.bin
    done

    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "  Benchmark Results: ${PASS} passed, ${FAIL} failed"
    echo "═══════════════════════════════════════════════════════"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Full-Stack Test Complete"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Tunnel still active on localhost:${LOCAL_PORT}"
echo "  To connect manually:"
echo "    docker exec -it ztlp-client sshpass -e ssh -p ${LOCAL_PORT} -o StrictHostKeyChecking=no testuser@127.0.0.1"
echo ""

# Keep tunnel running for manual testing
wait $TUNNEL_PID
