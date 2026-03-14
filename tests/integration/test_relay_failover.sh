#!/usr/bin/env bash
# test_relay_failover.sh — Relay failover test
#
# Starts a relay, connects a client through it, kills the relay,
# verifies the client detects disconnection, restarts the relay,
# and reconnects.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZTLP="${ZTLP:-$(cd "$SCRIPT_DIR/../../proto" && pwd)/target/release/ztlp}"
TMPDIR="$(mktemp -d /tmp/ztlp-test-failover.XXXXXX)"
PASS=0
FAIL=0

cleanup() {
    local exit_code=$?
    [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null && wait "$LISTENER_PID" 2>/dev/null || true
    [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null && wait "$RELAY_PID" 2>/dev/null || true
    [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" 2>/dev/null && wait "$CLIENT_PID" 2>/dev/null || true
    [ -n "${RELAY2_PID:-}" ] && kill "$RELAY2_PID" 2>/dev/null && wait "$RELAY2_PID" 2>/dev/null || true
    [ -n "${CLIENT2_PID:-}" ] && kill "$CLIENT2_PID" 2>/dev/null && wait "$CLIENT2_PID" 2>/dev/null || true
    rm -rf "$TMPDIR"
    if [ $FAIL -gt 0 ]; then
        echo "FAIL: $FAIL test(s) failed"
        exit 1
    fi
    echo "PASS: all $PASS test(s) passed"
    exit 0
}
trap cleanup EXIT

LISTENER_PID=""
RELAY_PID=""
CLIENT_PID=""
RELAY2_PID=""
CLIENT2_PID=""

ok() { ((PASS++)); echo "  ✓ $1"; }
fail() { ((FAIL++)); echo "  ✗ $1"; }

echo "=== Relay Failover Test ==="

if [ ! -x "$ZTLP" ]; then
    echo "SKIP: ztlp binary not found at $ZTLP"
    exit 0
fi

# ── Setup ────────────────────────────────────────────────────────────────
echo "--- Generating identities ---"
"$ZTLP" keygen --output "$TMPDIR/server.json" --format json
"$ZTLP" keygen --output "$TMPDIR/client.json" --format json
ok "Identities generated"

# Find free ports
LISTENER_PORT=$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
RELAY_PORT=$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

# ── Start listener ───────────────────────────────────────────────────────
echo "--- Starting listener on port $LISTENER_PORT ---"
"$ZTLP" listen \
    --bind "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/server.json" \
    --gateway \
    &>"$TMPDIR/listener.log" &
LISTENER_PID=$!
sleep 0.5

if kill -0 "$LISTENER_PID" 2>/dev/null; then
    ok "Listener started"
else
    fail "Listener failed to start"
    exit 1
fi

# ── Start relay ──────────────────────────────────────────────────────────
echo "--- Starting relay on port $RELAY_PORT ---"
"$ZTLP" relay start \
    --bind "127.0.0.1:${RELAY_PORT}" \
    --max-sessions 100 \
    &>"$TMPDIR/relay.log" &
RELAY_PID=$!
sleep 0.5

if kill -0 "$RELAY_PID" 2>/dev/null; then
    ok "Relay started (PID $RELAY_PID)"
else
    fail "Relay failed to start"
    cat "$TMPDIR/relay.log" 2>/dev/null || true
    exit 1
fi

# ── Connect client through relay ────────────────────────────────────────
echo "--- Connecting client through relay ---"
mkfifo "$TMPDIR/client_input" 2>/dev/null || true

"$ZTLP" connect "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/client.json" \
    --relay "127.0.0.1:${RELAY_PORT}" \
    <"$TMPDIR/client_input" \
    &>"$TMPDIR/client.log" &
CLIENT_PID=$!
sleep 1.5

if kill -0 "$CLIENT_PID" 2>/dev/null; then
    ok "Client connected through relay"
else
    fail "Client failed to connect through relay"
    echo "  Client log:"
    cat "$TMPDIR/client.log" 2>/dev/null | tail -10
    echo "  Relay log:"
    cat "$TMPDIR/relay.log" 2>/dev/null | tail -10
    # Open and close the pipe
    exec 3>"$TMPDIR/client_input"; exec 3>&-
    exit 1
fi

# ── Kill the relay ──────────────────────────────────────────────────────
echo "--- Killing relay (simulating failure) ---"
RELAY_KILL_TIME=$(date +%s)
kill "$RELAY_PID"
wait "$RELAY_PID" 2>/dev/null || true
RELAY_PID=""
ok "Relay killed at t=${RELAY_KILL_TIME}"

# ── Verify client detects disconnection ──────────────────────────────────
echo "--- Verifying client detects disconnection ---"
DETECT_DEADLINE=$(($(date +%s) + 15))

CLIENT_DETECTED=false
while [ $(date +%s) -lt $DETECT_DEADLINE ]; do
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        DETECT_TIME=$(date +%s)
        DETECT_DELAY=$((DETECT_TIME - RELAY_KILL_TIME))
        CLIENT_DETECTED=true
        ok "Client detected disconnection in ${DETECT_DELAY}s"
        break
    fi
    sleep 0.5
done

if [ "$CLIENT_DETECTED" = false ]; then
    # Client still running — it might be waiting for I/O timeout
    # Try sending data to trigger detection
    exec 3>"$TMPDIR/client_input"
    echo "probe-after-relay-death" >&3 2>/dev/null || true
    exec 3>&-
    sleep 2

    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        DETECT_TIME=$(date +%s)
        DETECT_DELAY=$((DETECT_TIME - RELAY_KILL_TIME))
        ok "Client detected disconnection after data probe (${DETECT_DELAY}s)"
    else
        fail "Client did not detect relay failure within 15s"
        kill "$CLIENT_PID" 2>/dev/null || true
    fi
fi

# Close the pipe for old client
exec 3>"$TMPDIR/client_input" 2>/dev/null && exec 3>&- || true
CLIENT_PID=""

# ── Restart relay ────────────────────────────────────────────────────────
echo "--- Restarting relay on same port ---"
"$ZTLP" relay start \
    --bind "127.0.0.1:${RELAY_PORT}" \
    --max-sessions 100 \
    &>"$TMPDIR/relay2.log" &
RELAY2_PID=$!
sleep 0.5

if kill -0 "$RELAY2_PID" 2>/dev/null; then
    ok "Relay restarted (PID $RELAY2_PID)"
else
    fail "Relay failed to restart"
    cat "$TMPDIR/relay2.log" 2>/dev/null || true
    exit 1
fi

# ── Reconnect client ────────────────────────────────────────────────────
echo "--- Reconnecting client through new relay ---"
rm -f "$TMPDIR/client_input2"
mkfifo "$TMPDIR/client_input2"

"$ZTLP" connect "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/client.json" \
    --relay "127.0.0.1:${RELAY_PORT}" \
    <"$TMPDIR/client_input2" \
    &>"$TMPDIR/client2.log" &
CLIENT2_PID=$!
sleep 1.5

if kill -0 "$CLIENT2_PID" 2>/dev/null; then
    ok "Client reconnected through new relay"
else
    # Check if handshake completed before exit
    if grep -qi "established\|transport\|session" "$TMPDIR/client2.log" 2>/dev/null; then
        ok "Client reconnected and session established (process exited normally)"
    else
        fail "Client failed to reconnect"
        echo "  Client log:"
        cat "$TMPDIR/client2.log" 2>/dev/null | tail -10
    fi
fi

# Close pipe for cleanup
exec 3>"$TMPDIR/client_input2" 2>/dev/null && exec 3>&- || true

# ── Listener should still be running ────────────────────────────────────
if kill -0 "$LISTENER_PID" 2>/dev/null; then
    ok "Listener survived relay failover"
else
    fail "Listener crashed during failover test"
fi

echo ""
echo "=== Relay Failover Test Complete ==="
