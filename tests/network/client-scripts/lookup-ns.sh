#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Look up a name via ZTLP-NS
# Runs INSIDE a client container
# ─────────────────────────────────────────────────────────────
#
# Usage: lookup-ns.sh <name> [type] [ns_host] [ns_port]
# Example: lookup-ns.sh "alice.test.ztlp" key
#
# Types: key(1), svc(2), relay(3), policy(4), revoke(5), bootstrap(6)
#
# Outputs:
#   STATUS=found|not_found|revoked|invalid|timeout
#   RESPONSE_LENGTH=<bytes>

set -euo pipefail

NAME="${1:?Usage: lookup-ns.sh <name> [type] [ns_host] [ns_port]}"
TYPE="${2:-key}"
NS_HOST="${3:-${NS_HOST:-ns}}"
NS_PORT="${4:-${NS_PORT:-23096}}"

# Map type name to byte
case "$TYPE" in
    key)       TYPE_BYTE=1 ;;
    svc)       TYPE_BYTE=2 ;;
    relay)     TYPE_BYTE=3 ;;
    policy)    TYPE_BYTE=4 ;;
    revoke)    TYPE_BYTE=5 ;;
    bootstrap) TYPE_BYTE=6 ;;
    *)         TYPE_BYTE=1 ;;
esac

python3 -c "
import socket, struct, sys

name = b'$NAME'
ns_host = '$NS_HOST'
ns_port = $NS_PORT
type_byte = $TYPE_BYTE

# Build NS query: <<0x01, name_len::16, name::binary, type_byte::8>>
query = struct.pack('!BH', 0x01, len(name)) + name + bytes([type_byte])

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)

try:
    s.sendto(query, (ns_host, ns_port))
    resp, _ = s.recvfrom(4096)
    status_byte = resp[0]

    if status_byte == 0x02:
        print('STATUS=found')
    elif status_byte == 0x03:
        print('STATUS=not_found')
    elif status_byte == 0x04:
        print('STATUS=revoked')
    elif status_byte == 0xFF:
        print('STATUS=invalid')
    else:
        print(f'STATUS=unknown_0x{status_byte:02x}')

    print(f'RESPONSE_LENGTH={len(resp)}')
    print(f'RESPONSE_HEX={resp.hex()}')

except socket.timeout:
    print('STATUS=timeout')
    sys.exit(1)
except Exception as e:
    print(f'STATUS=error ({e})', file=sys.stderr)
    sys.exit(1)
finally:
    s.close()
"
