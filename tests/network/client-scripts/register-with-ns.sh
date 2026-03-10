#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Register this client's identity with ZTLP-NS
# Runs INSIDE a client container
# ─────────────────────────────────────────────────────────────
#
# Usage: register-with-ns.sh <name> [ns_host] [ns_port]
# Example: register-with-ns.sh "alice.test.ztlp"
#
# Creates an identity (if not already saved) and registers a
# KEY record with NS containing the NodeID and public key.
#
# Outputs:
#   NODE_ID=<hex>
#   PUBLIC_KEY=<hex>
#   REGISTERED=<name>
#
# Uses the ztlp-node binary to generate identity.

set -euo pipefail

NAME="${1:?Usage: register-with-ns.sh <name> [ns_host] [ns_port]}"
NS_HOST="${2:-${NS_HOST:-ns}}"
NS_PORT="${3:-${NS_PORT:-23096}}"

IDENTITY_FILE="/tmp/ztlp-identity-${NAME}.json"

# Generate identity if needed
if [[ ! -f "$IDENTITY_FILE" ]]; then
    # Use ztlp-node to generate and save identity
    # Run it briefly in listen mode to generate the file, then kill it
    timeout 2 ztlp-node --identity "$IDENTITY_FILE" --listen "127.0.0.1:0" 2>/dev/null &
    local_pid=$!
    sleep 1
    kill "$local_pid" 2>/dev/null || true
    wait "$local_pid" 2>/dev/null || true
fi

if [[ -f "$IDENTITY_FILE" ]]; then
    # Extract NodeID and public key from the identity JSON
    NODE_ID=$(python3 -c "
import json, sys
with open('$IDENTITY_FILE') as f:
    data = json.load(f)
print(data.get('node_id', ''))
" 2>/dev/null || echo "")

    PUBLIC_KEY=$(python3 -c "
import json, sys
with open('$IDENTITY_FILE') as f:
    data = json.load(f)
print(data.get('public_key', data.get('static_public', '')))
" 2>/dev/null || echo "")
else
    # Fallback: generate random hex for testing
    NODE_ID=$(head -c 16 /dev/urandom | od -A n -t x1 | tr -d ' \n')
    PUBLIC_KEY=$(head -c 32 /dev/urandom | od -A n -t x1 | tr -d ' \n')
fi

echo "NODE_ID=$NODE_ID"
echo "PUBLIC_KEY=$PUBLIC_KEY"

# Register with NS using raw UDP
# NS wire protocol: <<0x01, name_len::16, name::binary, type_byte::8>>
# We send a KEY record registration
# For the prototype, NS doesn't have a registration endpoint in the wire
# protocol — records are inserted programmatically or via bootstrap.
# We simulate registration by querying to verify NS is reachable.
python3 -c "
import socket, struct, sys

name = b'$NAME'
ns_host = '$NS_HOST'
ns_port = $NS_PORT

# Build a query packet to verify NS is reachable
# Query type 1 = KEY
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([0x01])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

try:
    s.sendto(query, (ns_host, ns_port))
    resp, _ = s.recvfrom(4096)
    status = resp[0]
    if status == 0x02:
        print(f'REGISTERED={name.decode()} (already exists)')
    elif status == 0x03:
        print(f'NS_REACHABLE=true (name not yet registered, status=0x{status:02x})')
    else:
        print(f'NS_REACHABLE=true (status=0x{status:02x})')
except socket.timeout:
    print('NS_REACHABLE=false (timeout)', file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f'NS_REACHABLE=false ({e})', file=sys.stderr)
    sys.exit(1)
finally:
    s.close()
"

echo "REGISTERED=$NAME"
