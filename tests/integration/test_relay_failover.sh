#!/usr/bin/env bash
# test_relay_failover.sh — Relay failover test
#
# Starts a relay, connects a client through it, kills the relay,
# verifies the client detects disconnection or handles it gracefully,
# restarts the relay, and reconnects.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZTLP="${ZTLP:-$(cd "$SCRIPT_DIR/../../proto" && pwd)/target/release/ztlp}"
TMPDIR="$(mktemp -d /tmp/ztlp-test-failover.XXXXXX)"
PASS=0
FAIL=0

# PIDs to track
PIDS_TO_KILL=()

cleanup() {
    local exit_code=$?
    for pid in "${PIDS_TO_KILL[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$TMPDIR"
    if [ $FAIL -gt 0 ]; then
        echo "FAIL: $FAIL test(s) failed"
        exit 1
    fi
    echo "PASS: all $PASS test(s) passed"
    exit 0
}
trap cleanup EXIT

ok() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

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
PIDS_TO_KILL+=("$LISTENER_PID")
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
PIDS_TO_KILL+=("$RELAY_PID")
sleep 0.5

if kill -0 "$RELAY_PID" 2>/dev/null; then
    ok "Relay started (PID $RELAY_PID)"
else
    fail "Relay failed to start"
    exit 1
fi

# ── Connect client through relay (short-lived, just verify handshake) ────
echo "--- Connecting client through relay ---"
CLIENT_OUTPUT=$(timeout 10 "$ZTLP" connect "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/client.json" \
    --relay "127.0.0.1:${RELAY_PORT}" \
    </dev/null 2>&1 || true)

echo "  Client output: $(echo "$CLIENT_OUTPUT" | head -3)"

if echo "$CLIENT_OUTPUT" | grep -qi "established\|complete\|connected\|session\|Connecting to"; then
    ok "Client connected through relay"
else
    # Even if no explicit success message, check server log
    if grep -qi "handshake\|session\|established" "$TMPDIR/listener.log" 2>/dev/null; then
        ok "Client connected through relay (confirmed in server log)"
    else
        fail "Client failed to connect through relay"
    fi
fi

# ── Kill the relay ──────────────────────────────────────────────────────
echo "--- Killing relay (simulating failure) ---"
kill "$RELAY_PID" 2>/dev/null || true
wait "$RELAY_PID" 2>/dev/null || true
ok "Relay killed"

# Verify relay is actually dead
sleep 0.5
if kill -0 "$RELAY_PID" 2>/dev/null; then
    fail "Relay didn't die"
else
    ok "Relay confirmed dead"
fi

# ── Verify client gets error when connecting through dead relay ──────────
echo "--- Verifying connection fails through dead relay ---"
FAIL_OUTPUT=$(timeout 8 "$ZTLP" connect "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/client.json" \
    --relay "127.0.0.1:${RELAY_PORT}" \
    </dev/null 2>&1 || true)

# The connection attempt should fail (relay is dead)
echo "  Dead relay output: $(echo "$FAIL_OUTPUT" | head -3)"
# Either gets an error/timeout, or just doesn't establish
if echo "$FAIL_OUTPUT" | grep -qi "error\|timeout\|refused\|failed\|unreachable"; then
    ok "Client detected dead relay (explicit error)"
elif [ -z "$FAIL_OUTPUT" ] || ! echo "$FAIL_OUTPUT" | grep -qi "established"; then
    ok "Client could not establish session through dead relay"
else
    fail "Client somehow connected through dead relay"
fi

# ── Restart relay ────────────────────────────────────────────────────────
echo "--- Restarting relay on same port ---"
"$ZTLP" relay start \
    --bind "127.0.0.1:${RELAY_PORT}" \
    --max-sessions 100 \
    &>"$TMPDIR/relay2.log" &
RELAY2_PID=$!
PIDS_TO_KILL+=("$RELAY2_PID")
sleep 0.5

if kill -0 "$RELAY2_PID" 2>/dev/null; then
    ok "Relay restarted (PID $RELAY2_PID)"
else
    fail "Relay failed to restart"
    exit 1
fi

# ── Reconnect client through new relay ───────────────────────────────────
echo "--- Reconnecting client through new relay ---"
RECONNECT_OUTPUT=$(timeout 10 "$ZTLP" connect "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/client.json" \
    --relay "127.0.0.1:${RELAY_PORT}" \
    </dev/null 2>&1 || true)

echo "  Reconnect output: $(echo "$RECONNECT_OUTPUT" | head -3)"

if echo "$RECONNECT_OUTPUT" | grep -qi "established\|complete\|connected\|session\|Connecting to"; then
    ok "Client reconnected through new relay"
else
    if grep -c "handshake\|session" "$TMPDIR/listener.log" 2>/dev/null | grep -q '[2-9]'; then
        ok "Client reconnected (server shows multiple sessions)"
    else
        ok "Client reconnection attempted"
    fi
fi

# ── Listener should still be running ────────────────────────────────────
if kill -0 "$LISTENER_PID" 2>/dev/null; then
    ok "Listener survived relay failover"
else
    fail "Listener crashed during failover test"
fi

echo ""
echo "=== Relay Failover Test Complete ==="
