#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Network Tests — Common Functions
# ─────────────────────────────────────────────────────────────
#
# Source this file from test scenarios:
#   source "$(dirname "$0")/../lib/common.sh"

set -euo pipefail

# ── Paths ────────────────────────────────────────────────────
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$(cd "$TESTS_DIR/../.." && pwd)"
RESULTS_DIR="$TESTS_DIR/results"
COMPOSE_FILE="$TESTS_DIR/docker-compose.test.yml"
COMPOSE="docker compose -f $COMPOSE_FILE"

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Logging ──────────────────────────────────────────────────
log_info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_pass()    { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_fail()    { echo -e "${RED}[FAIL]${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_step()    { echo -e "${CYAN}[STEP]${NC}  $*"; }
log_header()  { echo -e "\n${BOLD}━━━ $* ━━━${NC}"; }

# ── Test Tracking ────────────────────────────────────────────
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
TEST_START_TIME=""
SCENARIO_NAME="${SCENARIO_NAME:-unknown}"

start_scenario() {
    SCENARIO_NAME="$1"
    TEST_START_TIME=$(date +%s)
    echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║  Scenario: $SCENARIO_NAME${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

end_scenario() {
    local end_time
    end_time=$(date +%s)
    local elapsed=$((end_time - TEST_START_TIME))
    local total=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))

    echo
    echo -e "${BOLD}━━━ Results: $SCENARIO_NAME ━━━${NC}"
    echo -e "  Total:   $total"
    echo -e "  ${GREEN}Passed:  $TESTS_PASSED${NC}"
    echo -e "  ${RED}Failed:  $TESTS_FAILED${NC}"
    echo -e "  ${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
    echo -e "  Time:    ${elapsed}s"
    echo

    # Write result file
    mkdir -p "$RESULTS_DIR"
    local result_file="$RESULTS_DIR/${SCENARIO_NAME}.result"
    local status="PASS"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        status="FAIL"
    fi
    cat > "$result_file" <<EOF
scenario=$SCENARIO_NAME
status=$status
passed=$TESTS_PASSED
failed=$TESTS_FAILED
skipped=$TESTS_SKIPPED
elapsed=${elapsed}s
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ✗ SCENARIO FAILED: $SCENARIO_NAME${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
        return 1
    else
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  ✓ SCENARIO PASSED: $SCENARIO_NAME${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
        return 0
    fi
}

record_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    log_pass "$*"
}

record_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    log_fail "$*"
}

record_skip() {
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    log_warn "SKIP: $*"
}

# ── Service Utilities ────────────────────────────────────────

# Wait for a container's UDP port to be reachable
# Usage: wait_for_service <container> <port> [timeout_seconds]
wait_for_service() {
    local container="$1"
    local port="$2"
    local timeout="${3:-30}"
    local elapsed=0

    log_info "Waiting for $container:$port (timeout: ${timeout}s)..."
    while [[ $elapsed -lt $timeout ]]; do
        # Send a ZTLP invalid query (0xFF) and see if we get a response
        if docker exec "$container" bash -c \
            "echo -ne '\xff' | timeout 1 bash -c 'cat > /dev/udp/127.0.0.1/$port' 2>/dev/null"; then
            log_info "$container:$port is reachable"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    log_warn "$container:$port not reachable after ${timeout}s"
    return 1
}

# Wait for a TCP port to be reachable
# Usage: wait_for_tcp <container> <host> <port> [timeout_seconds]
wait_for_tcp() {
    local container="$1"
    local host="$2"
    local port="$3"
    local timeout="${4:-30}"
    local elapsed=0

    log_info "Waiting for TCP $host:$port via $container (timeout: ${timeout}s)..."
    while [[ $elapsed -lt $timeout ]]; do
        if docker exec "$container" bash -c \
            "timeout 1 bash -c 'echo > /dev/tcp/$host/$port' 2>/dev/null"; then
            log_info "TCP $host:$port is reachable"
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    log_warn "TCP $host:$port not reachable after ${timeout}s"
    return 1
}

# Check if all test containers are running
check_containers_running() {
    local containers=("ztlp-test-ns" "ztlp-test-relay" "ztlp-test-gateway" "ztlp-test-client-a" "ztlp-test-client-b" "ztlp-test-echo" "ztlp-test-chaos")
    local all_ok=true

    for c in "${containers[@]}"; do
        if ! docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q "true"; then
            log_warn "Container $c is not running"
            all_ok=false
        fi
    done

    if $all_ok; then
        log_info "All containers are running"
        return 0
    else
        return 1
    fi
}

# Execute a command inside a client container
# Usage: exec_client <a|b> <command...>
exec_client() {
    local which="$1"
    shift
    local container="ztlp-test-client-$which"
    docker exec "$container" "$@"
}

# Execute a script inside a client container
# Usage: exec_client_script <a|b> <script_name> [args...]
exec_client_script() {
    local which="$1"
    local script="$2"
    shift 2
    local container="ztlp-test-client-$which"
    docker exec "$container" bash "/scripts/$script" "$@"
}

# Execute a command on the chaos container
# Usage: exec_chaos <command...>
exec_chaos() {
    docker exec ztlp-test-chaos "$@"
}

# ── ZTLP Packet Helpers ─────────────────────────────────────

# Send a raw UDP packet using Python (available in chaos container)
# Usage: send_udp_packet <container> <host> <port> <hex_data>
send_udp_packet() {
    local container="$1"
    local host="$2"
    local port="$3"
    local hex_data="$4"

    docker exec "$container" python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
data = bytes.fromhex('$hex_data')
s.sendto(data, ('$host', $port))
try:
    resp, _ = s.recvfrom(4096)
    sys.stdout.buffer.write(resp)
except socket.timeout:
    sys.exit(1)
finally:
    s.close()
"
}

# Send a ZTLP NS query from a container
# Usage: send_ns_query <container> <ns_host> <ns_port> <name> <type_byte>
# Returns: raw response bytes (binary)
send_ns_query() {
    local container="$1"
    local ns_host="$2"
    local ns_port="$3"
    local name="$4"
    local type_byte="$5"

    docker exec "$container" python3 -c "
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
name_bytes = b'$name'
name_len = len(name_bytes)
query = struct.pack('!BH', 0x01, name_len) + name_bytes + bytes([int('$type_byte', 0)])
s.sendto(query, ('$ns_host', $ns_port))
try:
    resp, _ = s.recvfrom(4096)
    # Print first byte as hex status
    print(f'STATUS:0x{resp[0]:02x}')
    print(f'LENGTH:{len(resp)}')
    sys.stdout.buffer.write(b'')
except socket.timeout:
    print('STATUS:TIMEOUT')
    sys.exit(1)
finally:
    s.close()
"
}

# Send a ZTLP NS query by public key from a container
# Usage: send_ns_pubkey_query <container> <ns_host> <ns_port> <pubkey_hex>
send_ns_pubkey_query() {
    local container="$1"
    local ns_host="$2"
    local ns_port="$3"
    local pubkey_hex="$4"

    docker exec "$container" python3 -c "
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
pk_bytes = b'$pubkey_hex'
pk_len = len(pk_bytes)
query = struct.pack('!BH', 0x05, pk_len) + pk_bytes
s.sendto(query, ('$ns_host', $ns_port))
try:
    resp, _ = s.recvfrom(4096)
    print(f'STATUS:0x{resp[0]:02x}')
    print(f'LENGTH:{len(resp)}')
except socket.timeout:
    print('STATUS:TIMEOUT')
    sys.exit(1)
finally:
    s.close()
"
}

# ── Docker Compose Helpers ───────────────────────────────────

# Bring up all test services
compose_up() {
    log_info "Starting test environment..."
    $COMPOSE up -d --build --wait 2>&1 | tail -5
    log_info "Test environment started"
}

# Tear down all test services
compose_down() {
    log_info "Tearing down test environment..."
    $COMPOSE down -v --remove-orphans 2>&1 | tail -3
    log_info "Test environment stopped"
}

# Restart a specific service
compose_restart() {
    local service="$1"
    log_info "Restarting $service..."
    $COMPOSE restart "$service"
    log_info "$service restarted"
}

# Get logs from a service
compose_logs() {
    local service="$1"
    local lines="${2:-50}"
    $COMPOSE logs --tail="$lines" "$service"
}

# ── Timing Helpers ───────────────────────────────────────────

# Get current time in milliseconds
now_ms() {
    date +%s%3N
}

# Measure execution time of a command
# Usage: measure_time <command...>
# Outputs: elapsed_ms on stdout
measure_time() {
    local start end elapsed
    start=$(now_ms)
    "$@"
    local exit_code=$?
    end=$(now_ms)
    elapsed=$((end - start))
    echo "ELAPSED_MS:$elapsed"
    return $exit_code
}
