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
SERVER_CONTAINER="${SERVER_CONTAINER:-stress-server}"
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

# ── Log Collection ───────────────────────────────────────────

# Collect all logs for a scenario and save to results directory
# Usage: collect_scenario_logs <scenario_id> <results_dir>
collect_scenario_logs() {
    local scenario_id="$1"
    local results_dir="${2:-${RESULTS_DIR:-.}}"
    local log_dir="${results_dir}/logs/scenario-${scenario_id}"

    mkdir -p "$log_dir"

    # Client tunnel log (ZTLP debug output — handshake, congestion, retransmit, SACK, etc.)
    docker exec "$CLIENT_CONTAINER" cat /tmp/tunnel.log > "${log_dir}/client-tunnel.log" 2>/dev/null || true

    # Server container logs (ZTLP listener debug output)
    docker logs "$SERVER_CONTAINER" > "${log_dir}/server.log" 2>&1 || true

    # NS container logs
    docker logs stress-ns > "${log_dir}/ns.log" 2>&1 || true

    # Impairment node state (tc rules + iptables at time of collection)
    docker exec stress-impairment bash -c '
        echo "=== tc qdisc ==="
        tc qdisc show 2>/dev/null
        echo ""
        echo "=== tc -s qdisc ==="
        tc -s qdisc show 2>/dev/null
        echo ""
        echo "=== iptables ==="
        iptables -L -n -v 2>/dev/null
        echo ""
        echo "=== ip route ==="
        ip route show 2>/dev/null
    ' > "${log_dir}/impairment-state.log" 2>/dev/null || true

    # Extract key metrics from client tunnel log for quick analysis
    if [ -f "${log_dir}/client-tunnel.log" ]; then
        {
            echo "=== Handshake Events ==="
            grep -iE "handshake|noise|initiator|responder" "${log_dir}/client-tunnel.log" | head -50

            echo ""
            echo "=== Congestion Control ==="
            grep -iE "congestion|cwnd|window|backoff|rtt|srtt" "${log_dir}/client-tunnel.log" | head -100

            echo ""
            echo "=== Retransmissions ==="
            grep -iE "retransmit|resend|retry|re-send|nack|timeout" "${log_dir}/client-tunnel.log" | head -100

            echo ""
            echo "=== SACK ==="
            grep -iE "sack|selective.ack|gap|missing" "${log_dir}/client-tunnel.log" | head -50

            echo ""
            echo "=== Anti-Replay ==="
            grep -iE "replay|duplicate|anti.replay|window.*shift" "${log_dir}/client-tunnel.log" | head -50

            echo ""
            echo "=== PMTU ==="
            grep -iE "pmtu|mtu|fragment|too.large" "${log_dir}/client-tunnel.log" | head -50

            echo ""
            echo "=== Rekey ==="
            grep -iE "rekey|rotate|new.key|session.key" "${log_dir}/client-tunnel.log" | head -50

            echo ""
            echo "=== Errors/Warnings ==="
            grep -iE "error|warn|fail|drop|reject|corrupt" "${log_dir}/client-tunnel.log" | head -100

            echo ""
            echo "=== Summary Stats ==="
            echo "Total log lines: $(wc -l < "${log_dir}/client-tunnel.log")"
            echo "Handshake events: $(grep -ciE "handshake|noise" "${log_dir}/client-tunnel.log" || echo 0)"
            echo "Retransmissions: $(grep -ciE "retransmit|resend|retry" "${log_dir}/client-tunnel.log" || echo 0)"
            echo "SACK events: $(grep -ciE "sack|selective" "${log_dir}/client-tunnel.log" || echo 0)"
            echo "Anti-replay drops: $(grep -ciE "replay|duplicate" "${log_dir}/client-tunnel.log" || echo 0)"
            echo "Errors: $(grep -ciE "error|fail" "${log_dir}/client-tunnel.log" || echo 0)"
        } > "${log_dir}/analysis-summary.txt" 2>/dev/null || true
    fi
}

# Collect tc statistics from impairment node (packet counts, drops, etc.)
# Usage: collect_tc_stats
collect_tc_stats() {
    docker exec stress-impairment tc -s qdisc show 2>/dev/null || true
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

    # Collect debug logs for post-mortem analysis
    if [ -n "${CURRENT_SCENARIO_ID:-}" ]; then
        collect_scenario_logs "$CURRENT_SCENARIO_ID" "${RESULTS_DIR:-.}"
    fi
}
