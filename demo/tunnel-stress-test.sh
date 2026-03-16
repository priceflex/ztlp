#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# tunnel-stress-test.sh — Reproduce intermittent SCP tunnel stalls
#
# Sets up a minimal ZTLP tunnel environment and hammers it with
# repeated SCP transfers, capturing full debug logs for analysis.
#
# Usage:
#   ./tunnel-stress-test.sh                    # 20 iterations, 10MB
#   ./tunnel-stress-test.sh --iterations 50    # 50 iterations
#   ./tunnel-stress-test.sh --size 50          # 50MB test file
#   ./tunnel-stress-test.sh --cleanup          # Remove artifacts
#
# Output:
#   /tmp/ztlp-stress/logs/              — per-iteration debug logs
#   /tmp/ztlp-stress/logs/summary.txt   — pass/fail/stall summary
#
# Requires: ztlp binary in PATH or $ZTLP_BIN
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
ITERATIONS=20
FILE_SIZE_MB=10
TIMEOUT_SECS=60          # per-SCP timeout — anything over this = stall
STRESS_DIR="/tmp/ztlp-stress"
LOG_DIR="$STRESS_DIR/logs"
ZTLP_PORT=23095
TUNNEL_LOCAL_PORT=2222
SSH_PORT=22
ZTLP_BIN="${ZTLP_BIN:-ztlp}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "  ${CYAN}ℹ${RESET} $1"; }
success() { echo -e "  ${GREEN}✓${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; }

# ── Parse arguments ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --size)       FILE_SIZE_MB="$2"; shift 2 ;;
        --timeout)    TIMEOUT_SECS="$2"; shift 2 ;;
        --port)       ZTLP_PORT="$2"; shift 2 ;;
        --cleanup)
            echo "Cleaning up stress test artifacts..."
            # Remove demo SSH key from authorized_keys
            if [[ -f "$HOME/.ssh/authorized_keys" ]]; then
                grep -v "ztlp-stress-temp" "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.tmp" 2>/dev/null || true
                mv "$HOME/.ssh/authorized_keys.tmp" "$HOME/.ssh/authorized_keys" 2>/dev/null || true
            fi
            rm -rf "$STRESS_DIR"
            echo "Done."
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [--iterations N] [--size MB] [--timeout SECS] [--port PORT] [--cleanup]"
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# ── Cleanup trap ─────────────────────────────────────────────────────
PIDS=()
cleanup() {
    echo -e "\n${DIM}Cleaning up...${RESET}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    # Remove demo SSH key
    if [[ -f "$HOME/.ssh/authorized_keys" ]]; then
        grep -v "ztlp-stress-temp" "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/authorized_keys.tmp" 2>/dev/null || true
        mv "$HOME/.ssh/authorized_keys.tmp" "$HOME/.ssh/authorized_keys" 2>/dev/null || true
        echo -e "  ${GREEN}✓${RESET} Removed stress-test SSH key from authorized_keys"
    fi
    echo -e "${GREEN}✓${RESET} Cleanup done."
}
trap cleanup EXIT

# ── Pre-flight ───────────────────────────────────────────────────────
echo -e "\n${BOLD}ZTLP Tunnel Stress Test${RESET}"
echo -e "${DIM}Iterations: $ITERATIONS | File size: ${FILE_SIZE_MB}MB | Timeout: ${TIMEOUT_SECS}s${RESET}\n"

command -v "$ZTLP_BIN" >/dev/null 2>&1 || { fail "ztlp binary not found (set ZTLP_BIN)"; exit 1; }
info "Using: $($ZTLP_BIN --version 2>&1 || echo 'unknown version')"

mkdir -p "$STRESS_DIR" "$LOG_DIR"

# ── Generate SSH keypair ─────────────────────────────────────────────
SSH_KEY="$STRESS_DIR/stress_ssh_key"
if [[ ! -f "$SSH_KEY" ]]; then
    ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q -C "ztlp-stress-temp"
    success "Generated temporary SSH keypair"
fi

mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
if ! grep -qF "ztlp-stress-temp" "$HOME/.ssh/authorized_keys" 2>/dev/null; then
    cat "$SSH_KEY.pub" >> "$HOME/.ssh/authorized_keys"
    success "Added stress-test key to ~/.ssh/authorized_keys"
fi

warn "${BOLD}⚠ SECURITY:${RESET} Temporary SSH key in ~/.ssh/authorized_keys."
warn "  Auto-removed on exit. If script crashes: ${CYAN}$0 --cleanup${RESET}"
echo ""

# ── Generate identities ─────────────────────────────────────────────
info "Generating ZTLP identities..."
SERVER_ID="$STRESS_DIR/server.json"
CLIENT_ID="$STRESS_DIR/client.json"

$ZTLP_BIN keygen --output "$SERVER_ID" 2>/dev/null
$ZTLP_BIN keygen --output "$CLIENT_ID" 2>/dev/null
success "Server + client identities generated"

# ── Kill lingering ZTLP processes on our ports ──────────────────────
# Previous demo/test runs may have left orphaned ztlp processes holding
# the ZTLP port or tunnel port. Kill them before starting fresh.
for check_port in "$ZTLP_PORT" "$TUNNEL_LOCAL_PORT"; do
    EXISTING_PID=$(ss -tlnp 2>/dev/null | grep ":${check_port} " | grep -oP 'pid=\K[0-9]+' | head -1 || true)
    if [[ -n "$EXISTING_PID" ]]; then
        warn "Killing existing process on port $check_port (PID $EXISTING_PID)"
        kill "$EXISTING_PID" 2>/dev/null || true
        sleep 1
    fi
done
# Also check for ztlp processes by binary name (not pkill -f which
# would match this shell script's arguments and kill us).
for stale_pid in $(pgrep -x "ztlp" 2>/dev/null || true); do
    warn "Killing stale ztlp process (PID $stale_pid)"
    kill "$stale_pid" 2>/dev/null || true
done
sleep 0.5

# ── Start listener ───────────────────────────────────────────────────
info "Starting ZTLP listener (forwarding to localhost:$SSH_PORT)..."
RUST_LOG=ztlp_proto=debug,ztlp=debug \
ZTLP_DEBUG=1 \
  $ZTLP_BIN listen \
    --key "$SERVER_ID" \
    --bind "0.0.0.0:$ZTLP_PORT" \
    --forward "127.0.0.1:$SSH_PORT" \
    > "$LOG_DIR/listener.log" 2>&1 &
PIDS+=($!)
sleep 1
success "Listener running (PID ${PIDS[-1]})"

# ── Start client tunnel ─────────────────────────────────────────────
info "Starting ZTLP client tunnel (localhost:$TUNNEL_LOCAL_PORT → tunnel)..."
RUST_LOG=ztlp_proto=debug,ztlp=debug \
ZTLP_DEBUG=1 \
  $ZTLP_BIN connect \
    "127.0.0.1:$ZTLP_PORT" \
    --key "$CLIENT_ID" \
    -L "$TUNNEL_LOCAL_PORT:127.0.0.1:$SSH_PORT" \
    > "$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=($CLIENT_PID)
sleep 2

# Verify client process is still alive (may have crashed on bind)
if ! kill -0 "$CLIENT_PID" 2>/dev/null; then
    fail "Client tunnel process died on startup — check $LOG_DIR/client.log"
    tail -20 "$LOG_DIR/client.log"
    exit 1
fi
success "Client tunnel running (PID $CLIENT_PID)"

# Verify tunnel is up
if ! ss -tlnp 2>/dev/null | grep -q ":$TUNNEL_LOCAL_PORT" && \
   ! netstat -tlnp 2>/dev/null | grep -q ":$TUNNEL_LOCAL_PORT"; then
    fail "Tunnel port $TUNNEL_LOCAL_PORT not listening — check $LOG_DIR/client.log"
    tail -20 "$LOG_DIR/client.log"
    exit 1
fi
success "Tunnel port $TUNNEL_LOCAL_PORT confirmed listening"

# ── Generate test file ───────────────────────────────────────────────
TEST_FILE="$STRESS_DIR/testfile.bin"
info "Generating ${FILE_SIZE_MB}MB test file..."
dd if=/dev/urandom of="$TEST_FILE" bs=1M count="$FILE_SIZE_MB" status=none 2>/dev/null
TEST_HASH=$(sha256sum "$TEST_FILE" | awk '{print $1}')
success "Test file ready (SHA256: ${TEST_HASH:0:16}...)"

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD} Starting $ITERATIONS SCP iterations (${FILE_SIZE_MB}MB each)${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""

# ── Main loop ────────────────────────────────────────────────────────
PASS=0
FAIL=0
STALL=0
SUMMARY="$LOG_DIR/summary.txt"
echo "# ZTLP Tunnel Stress Test — $(date -u '+%Y-%m-%d %H:%M:%S UTC')" > "$SUMMARY"
echo "# Iterations: $ITERATIONS | File: ${FILE_SIZE_MB}MB | Timeout: ${TIMEOUT_SECS}s" >> "$SUMMARY"
echo "# ztlp version: $($ZTLP_BIN --version 2>&1 || echo 'unknown')" >> "$SUMMARY"
echo "" >> "$SUMMARY"

SCP_OPTS="-i $SSH_KEY -P $TUNNEL_LOCAL_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o KexAlgorithms=curve25519-sha256"

for i in $(seq 1 "$ITERATIONS"); do
    ITER_LOG="$LOG_DIR/iter-$(printf '%03d' "$i").log"
    DEST_FILE="$STRESS_DIR/received_${i}.bin"

    printf "  [%3d/%d] SCP ${FILE_SIZE_MB}MB through tunnel... " "$i" "$ITERATIONS"

    # Snapshot listener + client log positions before this iteration
    LISTENER_LINES_BEFORE=$(wc -l < "$LOG_DIR/listener.log" 2>/dev/null || echo 0)
    CLIENT_LINES_BEFORE=$(wc -l < "$LOG_DIR/client.log" 2>/dev/null || echo 0)

    START_TS=$(date +%s%N)

    # Run SCP with timeout
    if timeout "$TIMEOUT_SECS" scp $SCP_OPTS "$TEST_FILE" "$(whoami)@127.0.0.1:$DEST_FILE" > "$ITER_LOG" 2>&1; then
        END_TS=$(date +%s%N)
        ELAPSED_MS=$(( (END_TS - START_TS) / 1000000 ))

        # Verify integrity
        if [[ -f "$DEST_FILE" ]]; then
            RECV_HASH=$(sha256sum "$DEST_FILE" | awk '{print $1}')
            if [[ "$RECV_HASH" == "$TEST_HASH" ]]; then
                echo -e "${GREEN}PASS${RESET} (${ELAPSED_MS}ms)"
                echo "PASS  iter=$i  time_ms=$ELAPSED_MS  hash_ok=true" >> "$SUMMARY"
                PASS=$((PASS + 1))
            else
                echo -e "${RED}FAIL${RESET} (hash mismatch! ${ELAPSED_MS}ms)"
                echo "FAIL  iter=$i  time_ms=$ELAPSED_MS  hash_ok=false  expected=${TEST_HASH:0:16}  got=${RECV_HASH:0:16}" >> "$SUMMARY"
                FAIL=$((FAIL + 1))
            fi
            rm -f "$DEST_FILE"
        else
            echo -e "${RED}FAIL${RESET} (file not created, ${ELAPSED_MS}ms)"
            echo "FAIL  iter=$i  time_ms=$ELAPSED_MS  no_output_file=true" >> "$SUMMARY"
            FAIL=$((FAIL + 1))
        fi
    else
        EXIT_CODE=$?
        END_TS=$(date +%s%N)
        ELAPSED_MS=$(( (END_TS - START_TS) / 1000000 ))

        if [[ $EXIT_CODE -eq 124 ]]; then
            echo -e "${RED}STALL${RESET} (timed out after ${TIMEOUT_SECS}s)"
            echo "STALL iter=$i  time_ms=$ELAPSED_MS  timeout=${TIMEOUT_SECS}s" >> "$SUMMARY"
            STALL=$((STALL + 1))
        else
            echo -e "${RED}FAIL${RESET} (exit code $EXIT_CODE, ${ELAPSED_MS}ms)"
            echo "FAIL  iter=$i  time_ms=$ELAPSED_MS  exit_code=$EXIT_CODE" >> "$SUMMARY"
            FAIL=$((FAIL + 1))
        fi
        rm -f "$DEST_FILE"
    fi

    # Capture listener + client logs for this iteration
    {
        echo "=== ITERATION $i ==="
        echo "--- LISTENER LOG (new lines) ---"
        tail -n "+$((LISTENER_LINES_BEFORE + 1))" "$LOG_DIR/listener.log" 2>/dev/null || echo "(no new lines)"
        echo ""
        echo "--- CLIENT LOG (new lines) ---"
        tail -n "+$((CLIENT_LINES_BEFORE + 1))" "$LOG_DIR/client.log" 2>/dev/null || echo "(no new lines)"
        echo ""
    } >> "$ITER_LOG"

    # Small delay between iterations to let TCP state settle
    sleep 0.5
done

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo -e "${BOLD} Results${RESET}"
echo -e "${BOLD}═══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${GREEN}PASS:${RESET}  $PASS / $ITERATIONS"
echo -e "  ${RED}FAIL:${RESET}  $FAIL / $ITERATIONS"
echo -e "  ${YELLOW}STALL:${RESET} $STALL / $ITERATIONS"
echo ""
echo -e "  ${DIM}Logs:    $LOG_DIR/${RESET}"
echo -e "  ${DIM}Summary: $SUMMARY${RESET}"
echo ""

echo "" >> "$SUMMARY"
echo "# TOTALS: pass=$PASS fail=$FAIL stall=$STALL total=$ITERATIONS" >> "$SUMMARY"

if [[ $STALL -gt 0 ]]; then
    warn "Found $STALL stalls! Check per-iteration logs in $LOG_DIR/iter-*.log"
    warn "Full listener log: $LOG_DIR/listener.log"
    warn "Full client log:   $LOG_DIR/client.log"
fi

if [[ $FAIL -gt 0 || $STALL -gt 0 ]]; then
    exit 1
fi
