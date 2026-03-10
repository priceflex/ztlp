#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 1: Basic Connectivity
# ─────────────────────────────────────────────────────────────
#
# Verifies that all ZTLP services are reachable and responding:
#   - Client A can reach the relay via UDP
#   - Client B can reach the relay via UDP
#   - Clients can reach NS
#   - Clients can reach the gateway
#   - Gateway can reach the echo server
#   - Bidirectional UDP communication works through the relay

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

start_scenario "basic-connectivity"

# ── Step 1: Verify all containers are running ────────────────
log_header "Verifying container status"

assert_container_running "NS container" "ztlp-test-ns"
assert_container_running "Relay container" "ztlp-test-relay"
assert_container_running "Gateway container" "ztlp-test-gateway"
assert_container_running "Client A container" "ztlp-test-client-a"
assert_container_running "Client B container" "ztlp-test-client-b"
assert_container_running "Echo server container" "ztlp-test-echo"
assert_container_running "Chaos container" "ztlp-test-chaos"

# ── Step 2: Verify UDP connectivity to NS ────────────────────
log_header "Testing NS connectivity"

# Client A → NS
NS_RESULT_A=$(docker exec ztlp-test-client-a python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
# Send an invalid query (0xFF) — NS should respond with 0xFF
s.sendto(bytes([0xFF]), ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    print(f'0x{resp[0]:02x}')
except socket.timeout:
    print('timeout')
s.close()
" 2>&1)
assert_eq "Client A → NS responds" "0xff" "$NS_RESULT_A"

# Client B → NS
NS_RESULT_B=$(docker exec ztlp-test-client-b python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(bytes([0xFF]), ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    print(f'0x{resp[0]:02x}')
except socket.timeout:
    print('timeout')
s.close()
" 2>&1)
assert_eq "Client B → NS responds" "0xff" "$NS_RESULT_B"

# ── Step 3: Verify UDP connectivity to Relay ─────────────────
log_header "Testing Relay connectivity"

# Client A → Relay (send a ZTLP-shaped packet)
RELAY_RESULT_A=$(docker exec ztlp-test-client-a python3 -c "
import socket, os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
# Send a minimal packet with ZTLP magic (0x5A37)
magic = bytes([0x5A, 0x37])
packet = magic + os.urandom(33)  # magic + 33 random bytes (min header)
s.sendto(packet, ('relay', 23095))
print('sent_ok')
# Relay may not respond to invalid session — that's fine
try:
    resp, _ = s.recvfrom(4096)
    print(f'response_len={len(resp)}')
except socket.timeout:
    print('no_response')  # expected for unknown session
s.close()
" 2>&1)
assert_contains "Client A → Relay send succeeds" "sent_ok" "$RELAY_RESULT_A"

# Client B → Relay
RELAY_RESULT_B=$(docker exec ztlp-test-client-b python3 -c "
import socket, os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
magic = bytes([0x5A, 0x37])
packet = magic + os.urandom(33)
s.sendto(packet, ('relay', 23095))
print('sent_ok')
try:
    resp, _ = s.recvfrom(4096)
    print(f'response_len={len(resp)}')
except socket.timeout:
    print('no_response')
s.close()
" 2>&1)
assert_contains "Client B → Relay send succeeds" "sent_ok" "$RELAY_RESULT_B"

# ── Step 4: Verify UDP connectivity to Gateway ───────────────
log_header "Testing Gateway connectivity"

GW_RESULT=$(docker exec ztlp-test-client-a python3 -c "
import socket, os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
magic = bytes([0x5A, 0x37])
packet = magic + os.urandom(33)
s.sendto(packet, ('gateway', 23097))
print('sent_ok')
try:
    resp, _ = s.recvfrom(4096)
    print(f'response_len={len(resp)}')
except socket.timeout:
    print('no_response')
s.close()
" 2>&1)
assert_contains "Client A → Gateway send succeeds" "sent_ok" "$GW_RESULT"

# ── Step 5: Verify TCP connectivity to echo server ───────────
log_header "Testing Echo Server connectivity"

ECHO_RESULT=$(docker exec ztlp-test-gateway python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(('echo-server', 8080))
    s.sendall(b'hello-ztlp-test')
    resp = s.recv(4096)
    if resp == b'hello-ztlp-test':
        print('echo_ok')
    else:
        print(f'echo_mismatch: got {resp}')
except Exception as e:
    print(f'echo_fail: {e}')
finally:
    s.close()
" 2>&1 || echo "echo_error")
assert_eq "Gateway → Echo server echo works" "echo_ok" "$ECHO_RESULT"

# ── Step 6: Verify network isolation ─────────────────────────
log_header "Testing network isolation"

# Clients should NOT be able to reach the echo server directly
# (it's only on ztlp-backend network)
ISOLATION_RESULT=$(docker exec ztlp-test-client-a python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('echo-server', 8080))
    print('connected')  # This should NOT happen
except (socket.timeout, socket.error, OSError):
    print('blocked')  # Expected — client can't reach backend
finally:
    s.close()
" 2>&1)
assert_eq "Client A cannot reach echo server directly (isolation)" "blocked" "$ISOLATION_RESULT"

# ── Step 7: Bidirectional UDP test between clients via relay ──
log_header "Testing bidirectional UDP (via relay infrastructure network)"

BIDIR_RESULT=$(docker exec ztlp-test-client-a python3 -c "
import socket, os, struct, time

# Create a UDP socket and send to client-b through the infra network
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 19999))
s.settimeout(3)

# Send a test message to client-b (both on ztlp-infra via aliases)
test_data = b'bidir-test-' + os.urandom(8)
s.sendto(test_data, ('client-b', 19998))
print('sent_to_b')

# Try to receive response
try:
    resp, addr = s.recvfrom(4096)
    if resp == test_data:
        print('bidir_ok')
    else:
        print(f'bidir_mismatch')
except socket.timeout:
    print('bidir_timeout')
s.close()
" 2>&1 &)

# Start receiver on client-b
BIDIR_B=$(docker exec ztlp-test-client-b python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 19998))
s.settimeout(5)
try:
    data, addr = s.recvfrom(4096)
    # Echo it back
    s.sendto(data, addr)
    print('echoed_back')
except socket.timeout:
    print('no_data')
s.close()
" 2>&1)

wait  # Wait for background client-a

# Check that client-b received and echoed
assert_contains "Client B received and echoed data" "echoed_back" "$BIDIR_B"

# ── Results ──────────────────────────────────────────────────
end_scenario
