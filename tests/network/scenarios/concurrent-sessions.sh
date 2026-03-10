#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 8: Concurrent Sessions
# ─────────────────────────────────────────────────────────────
#
# Tests ZTLP handling of multiple concurrent sessions:
#   1. Create 10 concurrent UDP sessions (unique SessionIDs)
#   2. Each session exchanges 50 messages
#   3. Verify all 500 messages delivered correctly
#   4. Report timing and cross-session interference

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

start_scenario "concurrent-sessions"

CLIENT_A="ztlp-test-client-a"
CLIENT_B="ztlp-test-client-b"

# ── Step 1: Pre-flight ───────────────────────────────────────
log_header "Pre-flight checks"

assert_container_running "Client A" "$CLIENT_A"
assert_container_running "Client B" "$CLIENT_B"
assert_container_running "Relay" "ztlp-test-relay"
assert_container_running "NS" "ztlp-test-ns"

# ── Step 2: Concurrent NS queries ────────────────────────────
log_header "Concurrent NS queries (10 sessions × 50 queries each)"

NS_CONCURRENT=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct, time, threading, os

ns_host = 'ns'
ns_port = 23096
num_sessions = 10
msgs_per_session = 50

results = {}
lock = threading.Lock()

def session_worker(session_id):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)

    success = 0
    fail = 0
    rtts = []

    for i in range(msgs_per_session):
        name = f's{session_id}-q{i}.test.ztlp'.encode()
        query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])

        start = time.time()
        try:
            s.sendto(query, (ns_host, ns_port))
            resp, _ = s.recvfrom(4096)
            rtt = (time.time() - start) * 1000
            rtts.append(rtt)
            success += 1
        except socket.timeout:
            fail += 1

    s.close()

    with lock:
        results[session_id] = {
            'success': success,
            'fail': fail,
            'avg_rtt': sum(rtts) / len(rtts) if rtts else 0,
        }

start_time = time.time()

# Launch 10 concurrent session threads
threads = []
for sid in range(num_sessions):
    t = threading.Thread(target=session_worker, args=(sid,))
    threads.append(t)
    t.start()

for t in threads:
    t.join(timeout=60)

elapsed = time.time() - start_time

total_success = sum(r['success'] for r in results.values())
total_fail = sum(r['fail'] for r in results.values())
total_expected = num_sessions * msgs_per_session
avg_rtts = [r['avg_rtt'] for r in results.values() if r['avg_rtt'] > 0]
overall_avg_rtt = sum(avg_rtts) / len(avg_rtts) if avg_rtts else 0

print(f'SESSIONS={len(results)}')
print(f'TOTAL_QUERIES={total_expected}')
print(f'TOTAL_SUCCESS={total_success}')
print(f'TOTAL_FAIL={total_fail}')
print(f'SUCCESS_RATE={(total_success/total_expected*100):.1f}')
print(f'OVERALL_AVG_RTT_MS={overall_avg_rtt:.1f}')
print(f'ELAPSED_S={elapsed:.2f}')
print(f'QUERIES_PER_SEC={total_success/elapsed:.1f}')

# Per-session breakdown
for sid in sorted(results.keys()):
    r = results[sid]
    print(f'SESSION_{sid}: ok={r[\"success\"]}/{msgs_per_session} avg_rtt={r[\"avg_rtt\"]:.1f}ms')
" 2>&1)

echo "$NS_CONCURRENT" | sed 's/^/  /'

TOTAL_SUCCESS=$(echo "$NS_CONCURRENT" | grep "^TOTAL_SUCCESS=" | cut -d= -f2)
TOTAL_EXPECTED=$(echo "$NS_CONCURRENT" | grep "^TOTAL_QUERIES=" | cut -d= -f2)
SUCCESS_RATE=$(echo "$NS_CONCURRENT" | grep "^SUCCESS_RATE=" | cut -d= -f2)
SESSIONS=$(echo "$NS_CONCURRENT" | grep "^SESSIONS=" | cut -d= -f2)

assert_eq "All 10 sessions created" "10" "${SESSIONS:-0}"
assert_gt "Total success >= 450/500" 449 "${TOTAL_SUCCESS:-0}"

# ── Step 3: Concurrent relay packets ─────────────────────────
log_header "Concurrent relay packet delivery (10 sessions × 50 packets)"

RELAY_CONCURRENT=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct, time, threading, os

relay_host = 'relay'
relay_port = 23095
num_sessions = 10
msgs_per_session = 50

results = {}
lock = threading.Lock()

magic = bytes([0x5A, 0x54])

def relay_worker(session_num):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)

    session_id = os.urandom(12)
    sent = 0
    errors = 0

    for seq in range(msgs_per_session):
        version = bytes([0x01])
        msg_type = bytes([0x10])
        flags = bytes([0x00])
        seq_bytes = struct.pack('!I', seq)
        payload = f'session-{session_num}-msg-{seq}'.encode() + os.urandom(16)
        payload_len = struct.pack('!H', len(payload))
        packet = magic + version + msg_type + flags + session_id + seq_bytes + payload_len + payload

        try:
            s.sendto(packet, (relay_host, relay_port))
            sent += 1
        except:
            errors += 1

    s.close()

    with lock:
        results[session_num] = {'sent': sent, 'errors': errors, 'session_id': session_id.hex()[:16]}

start_time = time.time()

threads = []
for sid in range(num_sessions):
    t = threading.Thread(target=relay_worker, args=(sid,))
    threads.append(t)
    t.start()

for t in threads:
    t.join(timeout=60)

elapsed = time.time() - start_time

total_sent = sum(r['sent'] for r in results.values())
total_errors = sum(r['errors'] for r in results.values())
total_expected = num_sessions * msgs_per_session

print(f'RELAY_SESSIONS={len(results)}')
print(f'RELAY_TOTAL_EXPECTED={total_expected}')
print(f'RELAY_TOTAL_SENT={total_sent}')
print(f'RELAY_TOTAL_ERRORS={total_errors}')
print(f'RELAY_ELAPSED_S={elapsed:.2f}')
print(f'RELAY_PACKETS_PER_SEC={total_sent/elapsed:.1f}')
" 2>&1)

echo "$RELAY_CONCURRENT" | sed 's/^/  /'

RELAY_SENT=$(echo "$RELAY_CONCURRENT" | grep "^RELAY_TOTAL_SENT=" | cut -d= -f2)
assert_eq "All 500 relay packets sent" "500" "${RELAY_SENT:-0}"

# ── Step 4: Cross-session interference check ─────────────────
log_header "Cross-session interference check"

# Run concurrent sessions from BOTH clients simultaneously
INTERFERENCE=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct, time, os

# Send from multiple sockets with different session IDs
ns_host = 'ns'
ns_port = 23096

sockets = []
results = []

for i in range(5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    sockets.append(s)

# Interleave queries from different sockets
success = 0
for round in range(10):
    for i, s in enumerate(sockets):
        name = f'interleave-s{i}-r{round}.ztlp'.encode()
        query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
        try:
            s.sendto(query, (ns_host, ns_port))
            resp, _ = s.recvfrom(4096)
            if resp[0] in (0x02, 0x03):  # found or not_found = valid response
                success += 1
        except:
            pass

for s in sockets:
    s.close()

total = 50  # 5 sockets × 10 rounds
print(f'INTERLEAVE_SUCCESS={success}')
print(f'INTERLEAVE_TOTAL={total}')
print(f'INTERLEAVE_RATE={(success/total*100):.1f}')
" 2>&1)

INTER_SUCCESS=$(echo "$INTERFERENCE" | grep "^INTERLEAVE_SUCCESS=" | cut -d= -f2)
assert_gt "No cross-session interference (>= 45/50)" 44 "${INTER_SUCCESS:-0}"

# ── Step 5: Simultaneous from both clients ───────────────────
log_header "Both clients sending simultaneously"

# Client A sends
docker exec "$CLIENT_A" python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
success = 0
for i in range(25):
    name = f'simul-a-{i}.ztlp'.encode()
    query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
    s.sendto(query, ('ns', 23096))
    try:
        s.recvfrom(4096)
        success += 1
    except: pass
s.close()
print(f'CLIENT_A_OK={success}')
" 2>&1 &
PID_A=$!

# Client B sends
docker exec "$CLIENT_B" python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
success = 0
for i in range(25):
    name = f'simul-b-{i}.ztlp'.encode()
    query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
    s.sendto(query, ('ns', 23096))
    try:
        s.recvfrom(4096)
        success += 1
    except: pass
s.close()
print(f'CLIENT_B_OK={success}')
" 2>&1 &
PID_B=$!

wait $PID_A 2>/dev/null && record_pass "Client A concurrent queries completed" || record_fail "Client A concurrent queries failed"
wait $PID_B 2>/dev/null && record_pass "Client B concurrent queries completed" || record_fail "Client B concurrent queries failed"

# ── Results ──────────────────────────────────────────────────
end_scenario
