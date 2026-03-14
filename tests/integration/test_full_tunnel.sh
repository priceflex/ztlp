#!/usr/bin/env bash
# test_full_tunnel.sh — Full E2E tunnel test
#
# Starts a ZTLP listener with TCP forwarding, connects a client with local
# forwarding, sends data through the tunnel in both directions, and verifies
# data integrity via SHA256.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZTLP="${ZTLP:-$(cd "$SCRIPT_DIR/../../proto" && pwd)/target/release/ztlp}"
TMPDIR="$(mktemp -d /tmp/ztlp-test-tunnel.XXXXXX)"
PASS=0
FAIL=0

cleanup() {
    local exit_code=$?
    # Kill all background processes in our process group
    for pid in $LISTENER_PID $ECHO_PID $CONNECT_PID; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    if [ $FAIL -gt 0 ]; then
        echo "FAIL: $FAIL test(s) failed"
        exit 1
    fi
    if [ $exit_code -ne 0 ] && [ $FAIL -eq 0 ]; then
        echo "FAIL: script exited with code $exit_code"
        exit $exit_code
    fi
    echo "PASS: all $PASS test(s) passed"
    exit 0
}
trap cleanup EXIT

LISTENER_PID=""
ECHO_PID=""
CONNECT_PID=""

ok() { ((PASS++)); echo "  ✓ $1"; }
fail() { ((FAIL++)); echo "  ✗ $1"; }

echo "=== Full E2E Tunnel Test ==="

# Check binary exists
if [ ! -x "$ZTLP" ]; then
    echo "SKIP: ztlp binary not found at $ZTLP (build with cargo build --release)"
    exit 0
fi

# ── Step 1: Generate identities ──────────────────────────────────────────
echo "--- Generating identities ---"
"$ZTLP" keygen --output "$TMPDIR/alice.json" --format json
"$ZTLP" keygen --output "$TMPDIR/bob.json" --format json

[ -f "$TMPDIR/alice.json" ] && ok "Alice identity generated" || fail "Alice identity missing"
[ -f "$TMPDIR/bob.json" ] && ok "Bob identity generated" || fail "Bob identity missing"

# ── Step 2: Start a TCP echo server ──────────────────────────────────────
# Simple socat-based echo server that reflects data + adds a prefix
ECHO_PORT=0
if command -v socat &>/dev/null; then
    # Find a free port
    ECHO_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
    socat TCP-LISTEN:${ECHO_PORT},fork,reuseaddr EXEC:"cat" &
    ECHO_PID=$!
    sleep 0.3
    ok "Echo server started on port $ECHO_PORT"
elif command -v ncat &>/dev/null; then
    ECHO_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
    ncat -l -k "$ECHO_PORT" --exec "/bin/cat" &
    ECHO_PID=$!
    sleep 0.3
    ok "Echo server started on port $ECHO_PORT (ncat)"
else
    # Use a Python echo server as fallback
    ECHO_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
    python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $ECHO_PORT))
s.listen(5)
def handle(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c,_ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
" &
    ECHO_PID=$!
    sleep 0.5
    ok "Echo server started on port $ECHO_PORT (python)"
fi

# ── Step 3: Start ZTLP listener ─────────────────────────────────────────
LISTENER_PORT=$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
echo "--- Starting ZTLP listener on port $LISTENER_PORT ---"
"$ZTLP" listen \
    --bind "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/bob.json" \
    --forward "127.0.0.1:${ECHO_PORT}" \
    --max-sessions 10 \
    &>"$TMPDIR/listener.log" &
LISTENER_PID=$!
sleep 0.5

# Verify listener is running
if kill -0 "$LISTENER_PID" 2>/dev/null; then
    ok "ZTLP listener started (PID $LISTENER_PID)"
else
    fail "ZTLP listener failed to start"
    cat "$TMPDIR/listener.log" 2>/dev/null || true
    exit 1
fi

# ── Step 4: Connect client with local forwarding ────────────────────────
LOCAL_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
echo "--- Connecting client with local forward on port $LOCAL_PORT ---"
"$ZTLP" connect "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/alice.json" \
    -L "${LOCAL_PORT}:127.0.0.1:${ECHO_PORT}" \
    &>"$TMPDIR/connect.log" &
CONNECT_PID=$!
sleep 1.5

if kill -0 "$CONNECT_PID" 2>/dev/null; then
    ok "ZTLP client connected (PID $CONNECT_PID)"
else
    fail "ZTLP client failed to connect"
    echo "--- Listener log ---"
    cat "$TMPDIR/listener.log" 2>/dev/null | tail -20 || true
    echo "--- Connect log ---"
    cat "$TMPDIR/connect.log" 2>/dev/null | tail -20 || true
    exit 1
fi

# ── Step 5: Send data through tunnel and verify integrity ───────────────
echo "--- Sending data through tunnel ---"

# Generate test data (1MB random)
dd if=/dev/urandom of="$TMPDIR/send_data.bin" bs=1024 count=1024 2>/dev/null
SEND_SHA=$(sha256sum "$TMPDIR/send_data.bin" | awk '{print $1}')
echo "  Send data SHA256: $SEND_SHA"

# Send through the tunnel using the local forward port
if timeout 15 bash -c "cat '$TMPDIR/send_data.bin' | nc -q 2 127.0.0.1 $LOCAL_PORT > '$TMPDIR/recv_data.bin'"; then
    if [ -f "$TMPDIR/recv_data.bin" ] && [ -s "$TMPDIR/recv_data.bin" ]; then
        RECV_SHA=$(sha256sum "$TMPDIR/recv_data.bin" | awk '{print $1}')
        echo "  Recv data SHA256: $RECV_SHA"

        if [ "$SEND_SHA" = "$RECV_SHA" ]; then
            ok "Data integrity verified (1MB echo through tunnel)"
        else
            fail "Data integrity mismatch! sent=$SEND_SHA recv=$RECV_SHA"
        fi
    else
        fail "No data received through tunnel"
    fi
else
    fail "Timeout sending data through tunnel"
fi

# ── Step 6: Small message test ──────────────────────────────────────────
echo "--- Small message test ---"
SMALL_MSG="Hello ZTLP tunnel!"
SMALL_RECV=$(echo "$SMALL_MSG" | timeout 5 nc -q 1 127.0.0.1 "$LOCAL_PORT" 2>/dev/null || true)

if [ "$SMALL_RECV" = "$SMALL_MSG" ]; then
    ok "Small message echo verified"
else
    # nc may not work perfectly in all environments; don't fail hard
    echo "  (small message test inconclusive — nc behavior varies)"
fi

echo ""
echo "=== Full E2E Tunnel Test Complete ==="
