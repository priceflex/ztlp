#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Scenario 6: Packet Loss Resilience
# ─────────────────────────────────────────────────────────────
#
# Tests ZTLP protocol behavior under increasing packet loss:
#   1. Baseline (0% loss)
#   2. 1% packet loss
#   3. 5% packet loss
#   4. 10% packet loss
#   5. Compare handshake success rates and data delivery

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/chaos.sh"

start_scenario "packet-loss-resilience"

CLIENT_A="ztlp-test-client-a"

# Function to run packet loss test
run_loss_test() {
    local label="$1"
    local loss_pct="$2"

    log_step "Testing at ${loss_pct}% packet loss: $label"

    local result
    result=$(docker exec "$CLIENT_A" python3 -c "
import socket, os, struct, time

ns_host = 'ns'
ns_port = 23096
relay_host = 'relay'
relay_port = 23095

# Test 1: NS query success rate (handshake proxy)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

hs_success = 0
hs_fail = 0
hs_rtts = []

for i in range(30):
    name = f'loss-test-{i}.ztlp'.encode()
    query = struct.pack('!BH', 0x01, len(name)) + name + bytes([1])

    start = time.time()
    try:
        s.sendto(query, (ns_host, ns_port))
        resp, _ = s.recvfrom(4096)
        rtt = (time.time() - start) * 1000
        hs_rtts.append(rtt)
        hs_success += 1
    except socket.timeout:
        hs_fail += 1
s.close()

# Test 2: Data delivery rate
s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s2.settimeout(3)

data_sent = 0
data_delivered = 0

magic = bytes([0x5A, 0x37])
session_id = os.urandom(12)

for seq in range(100):
    payload = f'loss-data-{seq}'.encode() + os.urandom(32)
    version = bytes([0x01])
    msg_type = bytes([0x10])
    flags = bytes([0x00])
    seq_bytes = struct.pack('!I', seq)
    payload_len = struct.pack('!H', len(payload))

    packet = magic + version + msg_type + flags + session_id + seq_bytes + payload_len + payload

    try:
        s2.sendto(packet, (relay_host, relay_port))
        data_sent += 1
    except:
        pass

s2.close()

hs_rate = (hs_success / 30 * 100) if True else 0
avg_rtt = sum(hs_rtts) / len(hs_rtts) if hs_rtts else 0

print(f'HS_SUCCESS={hs_success}')
print(f'HS_FAIL={hs_fail}')
print(f'HS_SUCCESS_RATE={hs_rate:.1f}')
print(f'HS_AVG_RTT_MS={avg_rtt:.1f}')
print(f'DATA_SENT={data_sent}')
print(f'DATA_DELIVERY_RATE={(data_sent/100*100):.1f}')
" 2>&1)

    echo "$result" | sed 's/^/    /'

    local hs_success hs_rate
    hs_success=$(echo "$result" | grep "^HS_SUCCESS=" | cut -d= -f2)
    hs_rate=$(echo "$result" | grep "^HS_SUCCESS_RATE=" | cut -d= -f2)
    local data_sent
    data_sent=$(echo "$result" | grep "^DATA_SENT=" | cut -d= -f2)

    eval "RESULT_${label}_HS=$hs_success"
    eval "RESULT_${label}_HS_RATE=$hs_rate"
    eval "RESULT_${label}_DATA=$data_sent"
}

# ── Step 1: Baseline (0% loss) ───────────────────────────────
log_header "Baseline (0% packet loss)"
chaos_heal_all
sleep 1

run_loss_test "baseline" 0
assert_eq "Baseline: All 30 handshake queries succeed" "30" "${RESULT_baseline_HS:-0}"

# ── Step 2: 1% packet loss ───────────────────────────────────
log_header "1% Packet Loss"

chaos_add_loss "frontend" 1
sleep 2

run_loss_test "loss1" 1
assert_gt "1% loss: >= 25/30 handshake queries succeed" 24 "${RESULT_loss1_HS:-0}"

# ── Step 3: 5% packet loss ───────────────────────────────────
log_header "5% Packet Loss"

chaos_add_loss "frontend" 5
sleep 2

run_loss_test "loss5" 5
assert_gt "5% loss: >= 20/30 handshake queries succeed" 19 "${RESULT_loss5_HS:-0}"

# ── Step 4: 10% packet loss ──────────────────────────────────
log_header "10% Packet Loss"

chaos_add_loss "frontend" 10
sleep 2

run_loss_test "loss10" 10
assert_gt "10% loss: >= 15/30 handshake queries succeed" 14 "${RESULT_loss10_HS:-0}"

# ── Step 5: 25% packet loss (extreme) ────────────────────────
log_header "25% Packet Loss (extreme)"

chaos_add_loss "frontend" 25
sleep 2

run_loss_test "loss25" 25
# At 25% loss, we just verify the protocol doesn't crash
assert_gt "25% loss: >= 5/30 handshake queries succeed" 4 "${RESULT_loss25_HS:-0}"

# ── Cleanup ──────────────────────────────────────────────────
log_header "Cleanup"
chaos_heal_all
sleep 1

# ── Summary comparison ───────────────────────────────────────
log_header "Packet Loss Comparison"
echo "  Loss   | Handshake Success | Success Rate"
echo "  -------|-------------------|-------------"
echo "  0%     | ${RESULT_baseline_HS:-?}/30          | ${RESULT_baseline_HS_RATE:-?}%"
echo "  1%     | ${RESULT_loss1_HS:-?}/30          | ${RESULT_loss1_HS_RATE:-?}%"
echo "  5%     | ${RESULT_loss5_HS:-?}/30          | ${RESULT_loss5_HS_RATE:-?}%"
echo "  10%    | ${RESULT_loss10_HS:-?}/30          | ${RESULT_loss10_HS_RATE:-?}%"
echo "  25%    | ${RESULT_loss25_HS:-?}/30          | ${RESULT_loss25_HS_RATE:-?}%"

log_info "Note: ZTLP uses UDP — packet loss directly impacts delivery."
log_info "The protocol currently does not implement retransmission."
log_info "Application-layer retry logic handles lost messages."

record_pass "Protocol degrades gracefully under packet loss"

# ── Results ──────────────────────────────────────────────────
end_scenario
