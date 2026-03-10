#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 3: NS Resolution
# ─────────────────────────────────────────────────────────────
#
# Tests ZTLP-NS name resolution:
#   1. Query NS for a bootstrap name
#   2. Query for a non-existent name (should return not_found)
#   3. Query by public key (type 0x05)
#   4. Verify NS response format
#   5. Test zone delegation queries

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

start_scenario "ns-resolution"

NS_CONTAINER="ztlp-test-ns"
CLIENT_A="ztlp-test-client-a"
CLIENT_B="ztlp-test-client-b"

# ── Step 1: Verify NS is responding ──────────────────────────
log_header "NS Health Check"

NS_HEALTH=$(docker exec "$CLIENT_A" python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.sendto(bytes([0xFF]), ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    print(f'response=0x{resp[0]:02x}')
    print(f'length={len(resp)}')
except socket.timeout:
    print('response=timeout')
s.close()
" 2>&1)

assert_contains "NS responds to queries" "response=0xff" "$NS_HEALTH"

# ── Step 2: Query for a known bootstrap name ─────────────────
log_header "Query for bootstrap records"

# NS should have bootstrap records from startup
BOOTSTRAP_RESULT=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

# Query for bootstrap type (type byte 6)
name = b'bootstrap.ztlp'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([6])

s.sendto(query, ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    status = resp[0]
    print(f'STATUS=0x{status:02x}')
    print(f'LENGTH={len(resp)}')
    if status == 0x02:
        print('RESULT=found')
    elif status == 0x03:
        print('RESULT=not_found')
    elif status == 0x04:
        print('RESULT=revoked')
    else:
        print(f'RESULT=other')
except socket.timeout:
    print('STATUS=timeout')
s.close()
" 2>&1)

echo "  Bootstrap query result:"
echo "$BOOTSTRAP_RESULT" | sed 's/^/    /'

# Bootstrap might or might not exist depending on NS config
if echo "$BOOTSTRAP_RESULT" | grep -q "STATUS=0x02\|STATUS=0x03"; then
    record_pass "NS responded correctly to bootstrap query"
else
    record_fail "NS did not respond to bootstrap query"
fi

# ── Step 3: Query for a non-existent name ────────────────────
log_header "Query for non-existent name"

NOTFOUND_RESULT=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

# Query for a name that definitely doesn't exist
name = b'this.does.not.exist.ztlp'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])  # KEY type

s.sendto(query, ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    status = resp[0]
    print(f'STATUS=0x{status:02x}')
    if status == 0x03:
        print('RESULT=not_found')
    elif status == 0x02:
        print('RESULT=found')  # unexpected
    else:
        print(f'RESULT=other_0x{status:02x}')
except socket.timeout:
    print('STATUS=timeout')
s.close()
" 2>&1)

NOTFOUND_STATUS=$(echo "$NOTFOUND_RESULT" | grep "^RESULT=" | cut -d= -f2)
assert_eq "Non-existent name returns not_found" "not_found" "$NOTFOUND_STATUS"

# ── Step 4: Query by public key (type 0x05) ──────────────────
log_header "Query by public key"

PUBKEY_RESULT=$(docker exec "$CLIENT_B" python3 -c "
import socket, struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

# Query by a random public key (should return not_found)
pk_hex = b'deadbeef' * 8  # 64-char hex string
query = struct.pack('!BH', 0x05, len(pk_hex)) + pk_hex

s.sendto(query, ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    status = resp[0]
    print(f'STATUS=0x{status:02x}')
    print(f'LENGTH={len(resp)}')
    if status == 0x03:
        print('RESULT=not_found')
    elif status == 0x02:
        print('RESULT=found')
    elif status == 0x04:
        print('RESULT=revoked')
    else:
        print(f'RESULT=other')
except socket.timeout:
    print('STATUS=timeout')
s.close()
" 2>&1)

PUBKEY_STATUS=$(echo "$PUBKEY_RESULT" | grep "^RESULT=" | cut -d= -f2)
assert_eq "Unknown pubkey returns not_found" "not_found" "$PUBKEY_STATUS"

# ── Step 5: Query for different record types ─────────────────
log_header "Query different record types"

for type_name in "key:1" "svc:2" "relay:3" "policy:4"; do
    IFS=: read -r tname tbyte <<< "$type_name"

    TYPE_RESULT=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

name = b'test.ztlp'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([$tbyte])

s.sendto(query, ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    status = resp[0]
    print(f'STATUS=0x{status:02x}')
except socket.timeout:
    print('STATUS=timeout')
s.close()
" 2>&1)

    STATUS_CODE=$(echo "$TYPE_RESULT" | grep "^STATUS=" | cut -d= -f2)
    if [[ "$STATUS_CODE" == "0x02" || "$STATUS_CODE" == "0x03" ]]; then
        record_pass "NS handles $tname (type $tbyte) query correctly"
    elif [[ "$STATUS_CODE" == "timeout" ]]; then
        record_fail "NS timed out on $tname (type $tbyte) query"
    else
        record_pass "NS responded to $tname (type $tbyte) query: $STATUS_CODE"
    fi
done

# ── Step 6: Invalid query format ─────────────────────────────
log_header "Invalid query handling"

INVALID_RESULT=$(docker exec "$CLIENT_A" python3 -c "
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

# Send completely malformed data
s.sendto(b'\x99\x88\x77', ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    print(f'STATUS=0x{resp[0]:02x}')
except socket.timeout:
    print('STATUS=timeout')
s.close()
" 2>&1)

INVALID_STATUS=$(echo "$INVALID_RESULT" | grep "^STATUS=" | cut -d= -f2)
assert_eq "Invalid query returns 0xFF" "0xff" "$INVALID_STATUS"

# ── Step 7: Zone delegation query ────────────────────────────
log_header "Zone delegation queries"

# Query for names in sub-zones
ZONE_RESULT=$(docker exec "$CLIENT_A" python3 -c "
import socket, struct

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

# Query for a name under a sub-zone
name = b'node1.office.acme.ztlp'
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])  # KEY type

s.sendto(query, ('ns', 23096))
try:
    resp, _ = s.recvfrom(4096)
    status = resp[0]
    print(f'STATUS=0x{status:02x}')
    if status == 0x03:
        print('RESULT=not_found')
    elif status == 0x02:
        print('RESULT=found')
    else:
        print(f'RESULT=other')
except socket.timeout:
    print('STATUS=timeout')
s.close()
" 2>&1)

# Sub-zone queries should at least get a proper response (not_found is OK)
ZONE_STATUS=$(echo "$ZONE_RESULT" | grep "^STATUS=" | cut -d= -f2)
if [[ "$ZONE_STATUS" == "0x02" || "$ZONE_STATUS" == "0x03" ]]; then
    record_pass "Sub-zone query handled correctly"
else
    record_fail "Sub-zone query: unexpected status $ZONE_STATUS"
fi

# ── Step 8: Concurrent queries from both clients ─────────────
log_header "Concurrent NS queries"

# Fire queries from both clients simultaneously
docker exec "$CLIENT_A" python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
for i in range(10):
    name = f'concurrent-test-{i}.ztlp'.encode()
    query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
    s.sendto(query, ('ns', 23096))
    resp, _ = s.recvfrom(4096)
print('QUERIES_A=10')
s.close()
" 2>&1 &
PID_A=$!

docker exec "$CLIENT_B" python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
for i in range(10):
    name = f'concurrent-test-b-{i}.ztlp'.encode()
    query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])
    s.sendto(query, ('ns', 23096))
    resp, _ = s.recvfrom(4096)
print('QUERIES_B=10')
s.close()
" 2>&1 &
PID_B=$!

wait $PID_A 2>/dev/null && record_pass "Client A: 10 concurrent queries succeeded" || record_fail "Client A: concurrent queries failed"
wait $PID_B 2>/dev/null && record_pass "Client B: 10 concurrent queries succeeded" || record_fail "Client B: concurrent queries failed"

# ── Results ──────────────────────────────────────────────────
end_scenario
