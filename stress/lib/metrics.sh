#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Stress Test — Measurement & Collection Functions
# ─────────────────────────────────────────────────────────────
#
# Handles tunnel lifecycle and measurement collection.
# Each test gets a fresh ZTLP tunnel for each operation.
#
# Source this: source "$(dirname "$0")/../lib/metrics.sh"

CLIENT_CONTAINER="${CLIENT_CONTAINER:-stress-client}"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30 -o KexAlgorithms=curve25519-sha256 -o ServerAliveInterval=10 -o ServerAliveCountMax=3"
LOCAL_PORT="${ZTLP_LOCAL_PORT:-2222}"

# ── Tunnel Management ────────────────────────────────────────

# Start a fresh ZTLP tunnel inside the client container
# Returns 0 on success, 1 on timeout
tunnel_start() {
    local timeout="${1:-30}"

    # Kill any existing tunnel
    tunnel_stop

    # Start tunnel in background
    docker exec -d "$CLIENT_CONTAINER" bash -c '
        KEY_FILE="/home/ztlp/.ztlp/client-identity.json"
        SERVER_ADDR="${ZTLP_SERVER_ADDR:-172.30.2.40:23095}"
        LOCAL_PORT="${ZTLP_LOCAL_PORT:-2222}"
        exec ztlp connect "$SERVER_ADDR" \
            --key "$KEY_FILE" \
            --service ssh \
            -L "${LOCAL_PORT}:127.0.0.1:22" \
            -vv > /tmp/tunnel.log 2>&1
    '

    # Wait for tunnel to come up
    local waited=0
    while [ $waited -lt "$timeout" ]; do
        if docker exec "$CLIENT_CONTAINER" ss -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}"; then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# Stop the ZTLP tunnel
tunnel_stop() {
    docker exec "$CLIENT_CONTAINER" pkill -f "ztlp connect" 2>/dev/null || true
    sleep 1
    docker exec "$CLIENT_CONTAINER" pkill -9 -f "ztlp connect" 2>/dev/null || true
    sleep 0.5
}

# Get tunnel log output
tunnel_log() {
    docker exec "$CLIENT_CONTAINER" cat /tmp/tunnel.log 2>/dev/null || true
}

# ── Handshake Measurement ────────────────────────────────────

# Measure time to establish a ZTLP tunnel (Noise_XX handshake)
# Outputs time in milliseconds
measure_handshake() {
    local timeout="${1:-60}"
    tunnel_stop

    local start_ns end_ns
    start_ns=$(date +%s%N)

    docker exec -d "$CLIENT_CONTAINER" bash -c '
        KEY_FILE="/home/ztlp/.ztlp/client-identity.json"
        SERVER_ADDR="${ZTLP_SERVER_ADDR:-172.30.2.40:23095}"
        LOCAL_PORT="${ZTLP_LOCAL_PORT:-2222}"
        exec ztlp connect "$SERVER_ADDR" \
            --key "$KEY_FILE" \
            --service ssh \
            -L "${LOCAL_PORT}:127.0.0.1:22" \
            -vv > /tmp/tunnel.log 2>&1
    '

    local waited=0
    while [ $waited -lt "$timeout" ]; do
        if docker exec "$CLIENT_CONTAINER" ss -tlnp 2>/dev/null | grep -q ":${LOCAL_PORT}"; then
            end_ns=$(date +%s%N)
            local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
            echo "$elapsed_ms"
            return 0
        fi
        sleep 0.5
        waited=$((waited + 1))
    done

    echo "TIMEOUT"
    return 1
}

# ── SSH Echo Test ────────────────────────────────────────────

# Run SSH echo test through the tunnel
# Returns "PASS" or "FAIL"
test_ssh_echo() {
    local result
    result=$(docker exec -e SSHPASS=ztlptest "$CLIENT_CONTAINER" \
        sshpass -e ssh $SSH_OPTS -p "$LOCAL_PORT" testuser@127.0.0.1 \
        "echo ZTLP_STRESS_OK" 2>&1) || true

    if echo "$result" | grep -q "ZTLP_STRESS_OK"; then
        echo "PASS"
    else
        echo "FAIL"
    fi
}

# ── File Transfer Measurement ────────────────────────────────

# Transfer a file via SCP through the ZTLP tunnel and measure
# Usage: measure_transfer <size_mb>
# Outputs: "time_ms throughput_mbps checksum_ok"
measure_transfer() {
    local size_mb="$1"
    local timeout="${2:-300}"

    # Generate test file inside client container
    docker exec "$CLIENT_CONTAINER" bash -c "
        dd if=/dev/urandom of=/tmp/test-${size_mb}MB.bin bs=1M count=${size_mb} 2>/dev/null
        md5sum /tmp/test-${size_mb}MB.bin | awk '{print \$1}' > /tmp/test-${size_mb}MB.md5
    "

    local local_md5
    local_md5=$(docker exec "$CLIENT_CONTAINER" cat /tmp/test-${size_mb}MB.md5 2>/dev/null)

    # Transfer via SSH pipe (single connection)
    local start_ns end_ns
    start_ns=$(date +%s%N)

    local remote_md5
    remote_md5=$(docker exec -e SSHPASS=ztlptest "$CLIENT_CONTAINER" \
        timeout "$timeout" bash -c "
            sshpass -e ssh $SSH_OPTS -p $LOCAL_PORT testuser@127.0.0.1 \
                'cat > /tmp/test-recv.bin && md5sum /tmp/test-recv.bin | awk \"{print \\\$1}\"' \
                < /tmp/test-${size_mb}MB.bin
        " 2>/dev/null) || true

    end_ns=$(date +%s%N)

    if [ -z "$remote_md5" ]; then
        echo "TIMEOUT 0 FAIL"
        return 1
    fi

    remote_md5=$(echo "$remote_md5" | tr -d '[:space:]')
    local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

    local throughput="0"
    if [ "$elapsed_ms" -gt 0 ]; then
        throughput=$(echo "scale=2; ${size_mb} * 8 / (${elapsed_ms} / 1000)" | bc 2>/dev/null || echo "0")
    fi

    local checksum="FAIL"
    if [ "$local_md5" = "$remote_md5" ]; then
        checksum="PASS"
    fi

    echo "${elapsed_ms} ${throughput} ${checksum}"
}

# ── Recovery Measurement ─────────────────────────────────────

# Measure how long it takes to recover after impairment removal
# Assumes impairment is currently active; caller removes it, then we check
measure_recovery() {
    local timeout="${1:-30}"
    local start_ns end_ns
    start_ns=$(date +%s%N)

    local waited=0
    while [ $waited -lt "$timeout" ]; do
        local result
        result=$(docker exec -e SSHPASS=ztlptest "$CLIENT_CONTAINER" \
            timeout 5 sshpass -e ssh $SSH_OPTS -p "$LOCAL_PORT" testuser@127.0.0.1 \
            "echo RECOVERED" 2>&1) || true

        if echo "$result" | grep -q "RECOVERED"; then
            end_ns=$(date +%s%N)
            local elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
            echo "$elapsed_ms"
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done

    echo "TIMEOUT"
    return 1
}

# ── Retransmit Counter ───────────────────────────────────────

# Count ZTLP retransmits from tunnel log
count_retransmits() {
    local count
    count=$(docker exec "$CLIENT_CONTAINER" grep -ci "retransmit\|resend\|retry\|re-send" /tmp/tunnel.log 2>/dev/null || echo "0")
    echo "$count"
}

# ── Full Scenario Runner ─────────────────────────────────────

# Run a complete scenario test cycle:
#   1. Fresh tunnel + handshake measurement
#   2. SSH echo test
#   3. SCP transfers (1MB, 10MB, 50MB)
#   4. Collect retransmit count
#
# Output is a series of key=value lines
run_scenario_tests() {
    local handshake_timeout="${1:-60}"
    local transfer_timeout="${2:-300}"

    echo "handshake_time_ms=$(measure_handshake "$handshake_timeout")"

    # Small pause for tunnel stabilization
    sleep 2

    echo "ssh_echo=$(test_ssh_echo)"

    # We need fresh tunnels per transfer since SSH closes the bridge
    for size in 1 10 50; do
        # Kill old tunnel, start fresh
        tunnel_stop
        sleep 1

        if tunnel_start "$handshake_timeout"; then
            sleep 1
            local result
            result=$(measure_transfer "$size" "$transfer_timeout")
            local time_ms=$(echo "$result" | awk '{print $1}')
            local throughput=$(echo "$result" | awk '{print $2}')
            local checksum=$(echo "$result" | awk '{print $3}')
            echo "scp_${size}mb_time_ms=${time_ms}"
            echo "scp_${size}mb_throughput_mbps=${throughput}"
            echo "scp_${size}mb_checksum=${checksum}"
        else
            echo "scp_${size}mb_time_ms=TIMEOUT"
            echo "scp_${size}mb_throughput_mbps=0"
            echo "scp_${size}mb_checksum=FAIL"
        fi
    done

    echo "retransmit_count=$(count_retransmits)"
}
