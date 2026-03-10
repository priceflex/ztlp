#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Send N data packets through a ZTLP session
# Runs INSIDE a client container
# ─────────────────────────────────────────────────────────────
#
# Usage: send-data.sh <target_host> <target_port> <count> [payload_size]
#
# Sends ZTLP-formatted data packets via UDP and counts responses.
#
# Outputs:
#   SENT=<count>
#   RECEIVED=<count>
#   LOST=<count>
#   LOSS_PERCENT=<pct>
#   AVG_RTT_MS=<ms>

set -euo pipefail

TARGET_HOST="${1:?Usage: send-data.sh <target_host> <target_port> <count> [payload_size]}"
TARGET_PORT="${2:?Usage: send-data.sh <target_host> <target_port> <count> [payload_size]}"
COUNT="${3:-10}"
PAYLOAD_SIZE="${4:-64}"

python3 -c "
import socket, struct, time, sys, os

target_host = '$TARGET_HOST'
target_port = $TARGET_PORT
count = $COUNT
payload_size = $PAYLOAD_SIZE

# ZTLP magic bytes: 0x5A, 0x37 ('Z7')
magic = bytes([0x5A, 0x37])

# Build data packets
# Data header: magic(2) + version(1) + msg_type(1) + flags(1) + session_id(12) + sequence(4) + payload_len(2)
# MsgType 0x10 = DATA
session_id = os.urandom(12)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)

sent = 0
received = 0
rtts = []

for seq in range(count):
    version = bytes([0x01])
    msg_type = bytes([0x10])  # DATA
    flags = bytes([0x00])
    seq_bytes = struct.pack('!I', seq)
    payload = os.urandom(payload_size)
    payload_len = struct.pack('!H', len(payload))

    packet = magic + version + msg_type + flags + session_id + seq_bytes + payload_len + payload

    start = time.time()
    try:
        s.sendto(packet, (target_host, target_port))
        sent += 1
        try:
            resp, _ = s.recvfrom(4096)
            rtt = (time.time() - start) * 1000
            received += 1
            rtts.append(rtt)
        except socket.timeout:
            pass
    except Exception as e:
        print(f'ERROR: packet {seq}: {e}', file=sys.stderr)

s.close()

lost = sent - received
loss_pct = (lost / sent * 100) if sent > 0 else 0
avg_rtt = sum(rtts) / len(rtts) if rtts else 0

print(f'SENT={sent}')
print(f'RECEIVED={received}')
print(f'LOST={lost}')
print(f'LOSS_PERCENT={loss_pct:.1f}')
print(f'AVG_RTT_MS={avg_rtt:.1f}')
"
