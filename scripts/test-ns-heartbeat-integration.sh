#!/usr/bin/env bash
# scripts/test-ns-heartbeat-integration.sh
#
# Integration confirmation for the NS self-registration heartbeat feature.
# Spawns a tiny UDP echo "NS stub" on 127.0.0.1, starts the real ztlp
# listener binary against it, captures the heartbeat lines from stderr,
# and asserts ≥2 publish cycles within 10 seconds (using a short interval
# override via env var, if supported — otherwise the test confirms only
# the initial publish).
#
# Exit 0 = pass. Exit 1 = fail. Stdout is verbose.
#
# Requires:
#   - cargo build --bin ztlp completed at proto/target/debug/ztlp
#   - python3 (for the UDP echo stub)
#   - timeout(1)
#
# See docs/plans/2026-06-01-ns-self-register-heartbeat.md
set -euo pipefail

cd "$(dirname "$0")/.."  # repo root

ZTLP=proto/target/debug/ztlp
[ -x "$ZTLP" ] || { echo "FAIL: $ZTLP not found — run 'cargo build --bin ztlp' first"; exit 1; }

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"; kill $(jobs -p) 2>/dev/null || true' EXIT

NS_PORT=23196
LISTENER_PORT=23195

# ── Stub NS: UDP echo that ACKs all registrations + logs to file ──
cat > "$WORKDIR/stub_ns.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
log = sys.argv[2]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
print(f"[stub_ns] listening on 127.0.0.1:{port}", flush=True)
with open(log, "w") as f:
    while True:
        try:
            data, addr = s.recvfrom(65535)
        except KeyboardInterrupt:
            break
        opcode = data[0] if data else 0
        ts = time.time()
        f.write(f"{ts:.3f} opcode=0x{opcode:02x} len={len(data)} from={addr}\n")
        f.flush()
        # Wire opcodes (per ztlp-cli.rs build_registration_packet):
        #   register: 0x09 -> reply 0x06 (ACK)
        #   query:    0x01 -> reply 0x02 (found)
        # Anything else (punch keepalive 0x0c etc) -> no reply.
        if opcode == 0x09:
            s.sendto(b"\x06", addr)
        elif opcode == 0x01:
            s.sendto(b"\x02", addr)
PY

NS_LOG="$WORKDIR/ns.log"
python3 "$WORKDIR/stub_ns.py" "$NS_PORT" "$NS_LOG" &
NS_PID=$!
sleep 0.5

# ── Generate a test identity ───────────────────────────────────────
"$ZTLP" keygen --output "$WORKDIR/identity.json" >/dev/null 2>&1
[ -f "$WORKDIR/identity.json" ] || {
    echo "FAIL: could not generate identity via 'ztlp keygen --output'"
    exit 1
}

# ── Boot the listener ──────────────────────────────────────────────
LISTENER_LOG="$WORKDIR/listener.log"
"$ZTLP" listen \
    --bind "127.0.0.1:$LISTENER_PORT" \
    --key "$WORKDIR/identity.json" \
    --ns-server "127.0.0.1:$NS_PORT" \
    --service-name "test-node.example.ztlp" \
    --zone "example.ztlp" \
    > "$LISTENER_LOG" 2>&1 &
LISTENER_PID=$!

# ── Wait for initial heartbeat (max 10s) ───────────────────────────
echo "Waiting for initial NS heartbeat..."
for i in $(seq 1 20); do
    if grep -q "NS heartbeat enrolled" "$LISTENER_LOG" 2>/dev/null; then
        echo "  ✓ initial publish observed after ${i}*0.5s"
        break
    fi
    if grep -q "initial NS publish failed" "$LISTENER_LOG" 2>/dev/null; then
        echo "  ✓ initial publish attempt observed (failed path) after ${i}*0.5s"
        break
    fi
    sleep 0.5
done

# ── Assert: NS stub saw ≥2 register packets (KEY + SVC) ────────────
sleep 1
REGISTER_COUNT=$(grep -c "opcode=0x09" "$NS_LOG" 2>/dev/null || true)
QUERY_COUNT=$(grep -c "opcode=0x01" "$NS_LOG" 2>/dev/null || true)
REGISTER_COUNT=${REGISTER_COUNT:-0}
QUERY_COUNT=${QUERY_COUNT:-0}
# Strip any stray whitespace/newlines
REGISTER_COUNT=$(echo "$REGISTER_COUNT" | tr -d '[:space:]')
QUERY_COUNT=$(echo "$QUERY_COUNT" | tr -d '[:space:]')
echo "NS stub saw: $REGISTER_COUNT registers, $QUERY_COUNT queries"

kill $LISTENER_PID 2>/dev/null || true
kill $NS_PID 2>/dev/null || true
wait 2>/dev/null || true

if [ "$REGISTER_COUNT" -ge 2 ]; then
    echo "PASS: heartbeat published KEY+SVC to NS stub"
    echo
    echo "=== listener stderr (last 30 lines) ==="
    tail -30 "$LISTENER_LOG" | sed 's/^/  /'
    echo
    echo "=== NS stub log ==="
    cat "$NS_LOG" | sed 's/^/  /'
    exit 0
else
    echo "FAIL: expected ≥2 register packets, got $REGISTER_COUNT"
    echo
    echo "=== listener stderr ==="
    cat "$LISTENER_LOG" | sed 's/^/  /'
    echo
    echo "=== NS stub log ==="
    cat "$NS_LOG" | sed 's/^/  /'
    exit 1
fi
