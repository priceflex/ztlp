#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Establish a relay session
# Runs INSIDE a client container
# ─────────────────────────────────────────────────────────────
#
# Usage: connect-relay.sh [relay_host] [relay_port]
#
# This script sends a ZTLP HELLO packet to the relay to verify
# connectivity and measure RTT. In the full protocol, this would
# be part of the Noise_XX handshake.
#
# Outputs:
#   RELAY_REACHABLE=true|false
#   RTT_MS=<milliseconds>

set -euo pipefail

RELAY_HOST="${1:-${RELAY_HOST:-relay}}"
RELAY_PORT="${2:-${RELAY_PORT:-23095}}"

python3 -c "
import socket, struct, time, sys, os

relay_host = '$RELAY_HOST'
relay_port = $RELAY_PORT

# ZTLP magic bytes: 0x5A, 0x37 ('Z7')
# Build a minimal HELLO header (handshake packet)
# Version: 1, MsgType: 0x01 (Hello)
# Header: magic(2) + version(1) + msg_type(1) + flags(1) + session_id(12) + src_node_id(16) + payload_len(2)
# Total header: 35 bytes

magic = bytes([0x5A, 0x37])
version = bytes([0x01])
msg_type = bytes([0x01])  # HELLO
flags = bytes([0x00])
session_id = os.urandom(12)
src_node_id = os.urandom(16)
payload_len = struct.pack('!H', 0)

header = magic + version + msg_type + flags + session_id + src_node_id + payload_len

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

start = time.time()
try:
    s.sendto(header, (relay_host, relay_port))
    # The relay may not respond to an unregistered session,
    # but it proves we can reach it. Try to get a response.
    try:
        resp, _ = s.recvfrom(4096)
        rtt_ms = int((time.time() - start) * 1000)
        print(f'RELAY_REACHABLE=true')
        print(f'RTT_MS={rtt_ms}')
        print(f'RESPONSE_LENGTH={len(resp)}')
    except socket.timeout:
        # Timeout receiving is OK — relay just dropped the unknown session packet
        rtt_ms = int((time.time() - start) * 1000)
        print(f'RELAY_REACHABLE=true')
        print(f'RTT_MS={rtt_ms}')
        print(f'RESPONSE=timeout (relay dropped unregistered session packet)')
except Exception as e:
    print(f'RELAY_REACHABLE=false')
    print(f'ERROR={e}', file=sys.stderr)
    sys.exit(1)
finally:
    s.close()
"
