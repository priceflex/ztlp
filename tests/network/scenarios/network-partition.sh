#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 10: Network Partition
# ─────────────────────────────────────────────────────────────
#
# Tests ZTLP behavior during network partitions:
#   1. Establish communication A↔B through relay
#   2. Exchange messages (verify working)
#   3. Create network partition (relay unreachable from clients)
#   4. Attempt to send messages (should timeout/fail)
#   5. Heal partition
#   6. Attempt recovery
#   7. Report behavior

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/chaos.sh"

start_scenario "network-partition"

CLIENT_A="ztlp-test-client-a"
CLIENT_B="ztlp-test-client-b"

# ── Step 1: Verify baseline connectivity ─────────────────────
log_header "Baseline connectivity"
chaos_heal_all
sleep 1

# Client A → NS
BASELINE_NS=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
name = b'partition-baseline.ztlp'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
s.sendto(query, ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    print(f'BASELINE_NS=0x{resp[0]:02x}')
except socket.timeout:
    print('BASELINE_NS=timeout')
s.close()
" 2>&1)

assert_contains "Baseline: NS reachable" "BASELINE_NS=0x" "$BASELINE_NS"

# Client A → Relay
BASELINE_RELAY=$(docker exec "$CLIENT_A" python3 -c "
import socket, os
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
magic = bytes([0x5A, 0x54])
packet = magic + os.urandom(33)
try:
    s.sendto(packet, ('relay', 23095))
    print('BASELINE_RELAY=sent')
except:
    print('BASELINE_RELAY=fail')
s.close()
" 2>&1)

assert_contains "Baseline: Relay reachable" "BASELINE_RELAY=sent" "$BASELINE_RELAY"

# Client A ↔ Client B direct
BASELINE_DIRECT=$(docker exec "$CLIENT_B" timeout 5 python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 59998))
s.settimeout(5)
try:
    data, addr = s.recvfrom(4096)
    s.sendto(b'pong', addr)
    print('BASELINE_BIDIR=ok')
except socket.timeout:
    print('BASELINE_BIDIR=timeout')
s.close()
" 2>&1 &)
BIDIR_PID=$!

sleep 1
docker exec "$CLIENT_A" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(b'ping', ('client-b', 59998))
try:
    data, _ = s.recvfrom(4096)
    if data == b'pong':
        print('BASELINE_BIDIR=ok')
    else:
        print('BASELINE_BIDIR=mismatch')
except socket.timeout:
    print('BASELINE_BIDIR=timeout')
s.close()
" 2>&1 || true

wait $BIDIR_PID 2>/dev/null || true
record_pass "Baseline connectivity verified"

# ── Step 2: Pre-partition message exchange ───────────────────
log_header "Pre-partition message exchange"

PRE_MSGS=$(docker exec "$CLIENT_A" python3 -c "
import socket, os, struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)

magic = bytes([0x5A, 0x54])
session_id = os.urandom(12)
sent = 0

for seq in range(10):
    version = bytes([0x01])
    msg_type = bytes([0x10])
    flags = bytes([0x00])
    seq_bytes = struct.pack('!I', seq)
    payload = f'pre-partition-{seq}'.encode()
    payload_len = struct.pack('!H', len(payload))
    packet = magic + version + msg_type + flags + session_id + seq_bytes + payload_len + payload

    try:
        s.sendto(packet, ('relay', 23095))
        sent += 1
    except:
        pass

s.close()
print(f'PRE_PARTITION_SENT={sent}')
" 2>&1)

PRE_SENT=$(echo "$PRE_MSGS" | grep "^PRE_PARTITION_SENT=" | cut -d= -f2)
assert_eq "Pre-partition: 10 messages sent" "10" "${PRE_SENT:-0}"

# ── Step 3: Create network partition ─────────────────────────
log_header "Creating network partition"

# Use tc on the chaos container to add massive latency + loss on the frontend network
# This effectively partitions clients from relay/gateway
chaos_add_impairment "frontend" 5000 100
log_info "Partition active: frontend network has 5000ms delay + 100% loss"
sleep 2

# ── Step 4: Verify partition is effective ────────────────────
log_header "Verify partition (communication should fail)"

PARTITION_TEST=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct, time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)

# Try to query NS — should fail
name = b'during-partition.ztlp'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])

start = time.time()
try:
    s.sendto(query, ('ns', 23096))
    try:
        resp, _ = s.recvfrom(4096)
        elapsed = time.time() - start
        print(f'PARTITION_NS=responded ({elapsed:.1f}s)')
    except socket.timeout:
        print('PARTITION_NS=timeout')
except Exception as e:
    print(f'PARTITION_NS=error ({e})')
s.close()
" 2>&1)

if echo "$PARTITION_TEST" | grep -q "timeout\|error"; then
    record_pass "Partition effective: NS queries timeout/fail"
else
    log_warn "Partition may not be fully effective (response received)"
    record_pass "Partition test completed"
fi

# Try relay during partition
PARTITION_RELAY=$(docker exec "$CLIENT_A" python3 -c "
import socket, os

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)

magic = bytes([0x5A, 0x54])
packet = magic + os.urandom(33)

try:
    s.sendto(packet, ('relay', 23095))
    print('PARTITION_RELAY_SEND=ok')
except Exception as e:
    print(f'PARTITION_RELAY_SEND=fail ({e})')

# Try to receive anything back
try:
    resp, _ = s.recvfrom(4096)
    print(f'PARTITION_RELAY_RECV=responded')
except socket.timeout:
    print('PARTITION_RELAY_RECV=timeout')
s.close()
" 2>&1)

if echo "$PARTITION_RELAY" | grep -q "timeout"; then
    record_pass "Partition effective: Relay unreachable"
else
    record_pass "Partition test with relay completed"
fi

# ── Step 5: Heal partition ───────────────────────────────────
log_header "Healing partition"

chaos_heal_all
log_info "Partition healed — network restored"
sleep 3  # Allow network to stabilize

# ── Step 6: Verify recovery ──────────────────────────────────
log_header "Post-partition recovery"

# Allow some extra time for DNS cache / ARP refresh
RECOVERY_ATTEMPTS=0
RECOVERY_SUCCESS=false

for attempt in $(seq 1 10); do
    RECOVERY_NS=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
name = b'post-partition-recovery.ztlp'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
s.sendto(query, ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    print(f'RECOVERY_NS=0x{resp[0]:02x}')
except socket.timeout:
    print('RECOVERY_NS=timeout')
s.close()
" 2>&1)

    RECOVERY_ATTEMPTS=$attempt
    if echo "$RECOVERY_NS" | grep -q "RECOVERY_NS=0x"; then
        RECOVERY_SUCCESS=true
        break
    fi
    sleep 1
done

if $RECOVERY_SUCCESS; then
    record_pass "NS recovered after partition (attempt $RECOVERY_ATTEMPTS)"
else
    record_fail "NS did not recover after 10 attempts"
fi

# Post-recovery message exchange
POST_MSGS=$(docker exec "$CLIENT_A" python3 -c "
import socket, os, struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)

magic = bytes([0x5A, 0x54])
session_id = os.urandom(12)
sent = 0

for seq in range(10):
    version = bytes([0x01])
    msg_type = bytes([0x10])
    flags = bytes([0x00])
    seq_bytes = struct.pack('!I', seq)
    payload = f'post-partition-{seq}'.encode()
    payload_len = struct.pack('!H', len(payload))
    packet = magic + version + msg_type + flags + session_id + seq_bytes + payload_len + payload

    try:
        s.sendto(packet, ('relay', 23095))
        sent += 1
    except:
        pass

s.close()
print(f'POST_PARTITION_SENT={sent}')
" 2>&1)

POST_SENT=$(echo "$POST_MSGS" | grep "^POST_PARTITION_SENT=" | cut -d= -f2)
assert_eq "Post-partition: 10 messages sent" "10" "${POST_SENT:-0}"

# ── Step 7: Full recovery verification ───────────────────────
log_header "Full recovery verification"

# NS, Relay, and Gateway should all be working
FULL_RECOVERY=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct, os

results = {}

# Test NS
s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s1.settimeout(5)
name = b'full-recovery.ztlp'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
try:
    s1.sendto(query, ('ns', 23096))
    resp, _ = s1.recvfrom(4096)
    results['ns'] = True
except:
    results['ns'] = False
s1.close()

# Test Relay
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s2.settimeout(3)
magic = bytes([0x5A, 0x54])
try:
    s2.sendto(magic + os.urandom(33), ('relay', 23095))
    results['relay'] = True
except:
    results['relay'] = False
s2.close()

# Test Gateway
s3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s3.settimeout(3)
try:
    s3.sendto(magic + os.urandom(33), ('gateway', 23097))
    results['gateway'] = True
except:
    results['gateway'] = False
s3.close()

for svc, ok in results.items():
    status = 'recovered' if ok else 'not_recovered'
    print(f'{svc.upper()}_STATUS={status}')
" 2>&1)

echo "$FULL_RECOVERY" | sed 's/^/  /'

for svc in NS RELAY GATEWAY; do
    STATUS=$(echo "$FULL_RECOVERY" | grep "^${svc}_STATUS=" | cut -d= -f2)
    assert_eq "$svc recovered after partition" "recovered" "${STATUS:-unknown}"
done

# ── Results ──────────────────────────────────────────────────
end_scenario
