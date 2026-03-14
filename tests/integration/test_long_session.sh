#!/usr/bin/env bash
# test_long_session.sh — Long-running session test
#
# Establishes a ZTLP tunnel, sends data periodically for 2 minutes (shortened
# from 5 for CI), checks for memory leaks by comparing RSS, and verifies
# keepalives keep the session alive.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ZTLP="${ZTLP:-$(cd "$SCRIPT_DIR/../../proto" && pwd)/target/release/ztlp}"
TMPDIR="$(mktemp -d /tmp/ztlp-test-long.XXXXXX)"
PASS=0
FAIL=0

# Duration in seconds (use ZTLP_TEST_LONG_DURATION to override)
DURATION="${ZTLP_TEST_LONG_DURATION:-120}"
INTERVAL=15  # Send data every 15 seconds

cleanup() {
    local exit_code=$?
    [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null && wait "$LISTENER_PID" 2>/dev/null || true
    [ -n "${CLIENT_PID:-}" ] && kill "$CLIENT_PID" 2>/dev/null && wait "$CLIENT_PID" 2>/dev/null || true
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
CLIENT_PID=""

ok() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }

get_rss_kb() {
    local pid=$1
    if [ -f "/proc/$pid/status" ]; then
        grep VmRSS "/proc/$pid/status" 2>/dev/null | awk '{print $2}' || echo 0
    else
        # macOS fallback
        ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo 0
    fi
}

echo "=== Long-Running Session Test (${DURATION}s) ==="

if [ ! -x "$ZTLP" ]; then
    echo "SKIP: ztlp binary not found at $ZTLP"
    exit 0
fi

# ── Setup ────────────────────────────────────────────────────────────────
"$ZTLP" keygen --output "$TMPDIR/server.json" --format json
"$ZTLP" keygen --output "$TMPDIR/client.json" --format json
ok "Identities generated"

# ── Start listener ───────────────────────────────────────────────────────
LISTENER_PORT=$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
"$ZTLP" listen \
    --bind "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/server.json" \
    --gateway \
    &>"$TMPDIR/listener.log" &
LISTENER_PID=$!
sleep 0.5

if kill -0 "$LISTENER_PID" 2>/dev/null; then
    ok "Listener started (PID $LISTENER_PID)"
else
    fail "Listener failed to start"
    exit 1
fi

# Record initial RSS
LISTENER_RSS_BEFORE=$(get_rss_kb "$LISTENER_PID")
echo "  Listener initial RSS: ${LISTENER_RSS_BEFORE} KB"

# ── Start client ────────────────────────────────────────────────────────
# The client connects and we'll feed it data via a named pipe
mkfifo "$TMPDIR/client_input"

"$ZTLP" connect "127.0.0.1:${LISTENER_PORT}" \
    --key "$TMPDIR/client.json" \
    <"$TMPDIR/client_input" \
    &>"$TMPDIR/client.log" &
CLIENT_PID=$!
sleep 1

if kill -0 "$CLIENT_PID" 2>/dev/null; then
    ok "Client connected (PID $CLIENT_PID)"
else
    fail "Client failed to connect"
    cat "$TMPDIR/client.log" 2>/dev/null || true
    # Open and close the pipe to prevent blocking cleanup
    exec 3>"$TMPDIR/client_input"
    exec 3>&-
    exit 1
fi

CLIENT_RSS_BEFORE=$(get_rss_kb "$CLIENT_PID")
echo "  Client initial RSS: ${CLIENT_RSS_BEFORE} KB"

# ── Periodic data sending ───────────────────────────────────────────────
echo "--- Sending data every ${INTERVAL}s for ${DURATION}s ---"
START_TIME=$(date +%s)
SEND_COUNT=0

# Open the pipe for writing
exec 3>"$TMPDIR/client_input"

while true; do
    ELAPSED=$(( $(date +%s) - START_TIME ))
    if [ $ELAPSED -ge $DURATION ]; then
        break
    fi

    # Check both processes are still alive
    if ! kill -0 "$LISTENER_PID" 2>/dev/null; then
        fail "Listener died at ${ELAPSED}s"
        break
    fi
    if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
        fail "Client died at ${ELAPSED}s"
        break
    fi

    # Send a message
    SEND_COUNT=$((SEND_COUNT+1))
    echo "keepalive-${SEND_COUNT}-$(date +%s)" >&3 2>/dev/null || {
        fail "Failed to write to client pipe at ${ELAPSED}s"
        break
    }

    # Log RSS periodically
    if [ $((SEND_COUNT % 4)) -eq 0 ]; then
        L_RSS=$(get_rss_kb "$LISTENER_PID")
        C_RSS=$(get_rss_kb "$CLIENT_PID")
        echo "  [${ELAPSED}s] Listener RSS: ${L_RSS}KB, Client RSS: ${C_RSS}KB, sends: ${SEND_COUNT}"
    fi

    sleep "$INTERVAL"
done

# Close the pipe
exec 3>&-

echo "  Total messages sent: $SEND_COUNT"

# ── Check final state ───────────────────────────────────────────────────
echo "--- Checking final state ---"

# Both processes should still be running
if kill -0 "$LISTENER_PID" 2>/dev/null; then
    ok "Listener survived ${DURATION}s"
else
    fail "Listener died during test"
fi

if kill -0 "$CLIENT_PID" 2>/dev/null; then
    ok "Client survived ${DURATION}s"
else
    # Client may have exited after pipe closed — that's OK
    echo "  (Client exited after pipe closed — acceptable)"
fi

# ── Memory leak check ───────────────────────────────────────────────────
echo "--- Memory leak check ---"
LISTENER_RSS_AFTER=$(get_rss_kb "$LISTENER_PID")
echo "  Listener RSS: before=${LISTENER_RSS_BEFORE}KB after=${LISTENER_RSS_AFTER}KB"

if [ "${LISTENER_RSS_BEFORE:-0}" -gt 0 ] && [ "${LISTENER_RSS_AFTER:-0}" -gt 0 ]; then
    # Allow up to 3x growth (generous for a 2-min test)
    MAX_GROWTH=$((LISTENER_RSS_BEFORE * 3))
    if [ "$LISTENER_RSS_AFTER" -le "$MAX_GROWTH" ]; then
        ok "Listener RSS within bounds (no apparent leak)"
    else
        fail "Listener RSS grew from ${LISTENER_RSS_BEFORE}KB to ${LISTENER_RSS_AFTER}KB (>3x)"
    fi
else
    echo "  (RSS check inconclusive — couldn't read process memory)"
fi

if kill -0 "$CLIENT_PID" 2>/dev/null; then
    CLIENT_RSS_AFTER=$(get_rss_kb "$CLIENT_PID")
    echo "  Client RSS: before=${CLIENT_RSS_BEFORE}KB after=${CLIENT_RSS_AFTER}KB"

    if [ "${CLIENT_RSS_BEFORE:-0}" -gt 0 ] && [ "${CLIENT_RSS_AFTER:-0}" -gt 0 ]; then
        MAX_GROWTH=$((CLIENT_RSS_BEFORE * 3))
        if [ "$CLIENT_RSS_AFTER" -le "$MAX_GROWTH" ]; then
            ok "Client RSS within bounds (no apparent leak)"
        else
            fail "Client RSS grew from ${CLIENT_RSS_BEFORE}KB to ${CLIENT_RSS_AFTER}KB (>3x)"
        fi
    fi
fi

echo ""
echo "=== Long-Running Session Test Complete ==="
echo "  Duration: ${DURATION}s, Messages sent: ${SEND_COUNT}"
