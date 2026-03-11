#!/usr/bin/env bash
# ============================================================================
# ZTLP SSH Tunnel Demo
# ============================================================================
#
# Demonstrates end-to-end: keygen → NS register → listen with SSH forward →
# connect with local port forwarding → SSH through the encrypted ZTLP tunnel.
#
# Requirements:
#   - ztlp binary (v0.2.1+) in PATH or ./ztlp
#   - ZTLP-NS server running (Elixir) — or pass --skip-ns to use raw IPs
#   - SSH server running on localhost:22 (or set SSH_PORT)
#   - sshpass (optional, for automated SSH login — otherwise interactive)
#
# Usage:
#   ./ssh-tunnel-demo.sh                    # Full demo with NS
#   ./ssh-tunnel-demo.sh --skip-ns          # Skip NS, use raw IP
#   ./ssh-tunnel-demo.sh --cleanup          # Remove demo artifacts
#   SSH_USER=steve SSH_PORT=22 ./ssh-tunnel-demo.sh
#
# ============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

ZTLP="${ZTLP_BIN:-ztlp}"
DEMO_DIR="${DEMO_DIR:-/tmp/ztlp-demo}"
NS_SERVER="${NS_SERVER:-127.0.0.1:5353}"
LISTEN_PORT="${LISTEN_PORT:-23095}"
TUNNEL_LOCAL_PORT="${TUNNEL_LOCAL_PORT:-2222}"
SSH_PORT="${SSH_PORT:-22}"
SSH_USER="${SSH_USER:-$(whoami)}"
DEMO_NAME="${DEMO_NAME:-demo-server.tunnel.ztlp}"
DEMO_ZONE="${DEMO_ZONE:-tunnel.ztlp}"
SKIP_NS="${SKIP_NS:-false}"

# Parse args
for arg in "$@"; do
    case "$arg" in
        --skip-ns) SKIP_NS=true ;;
        --cleanup) rm -rf "$DEMO_DIR"; echo "✓ Cleaned up $DEMO_DIR"; exit 0 ;;
        --help|-h)
            sed -n '2,/^# ===/p' "$0" | head -n -1 | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
    esac
done

# ── Colors & Helpers ─────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

banner()  { echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════${RESET}"; echo -e "${BOLD}  $1${RESET}"; echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════${RESET}\n"; }
step()    { echo -e "${GREEN}▶${RESET} ${BOLD}$1${RESET}"; }
info()    { echo -e "  ${CYAN}ℹ${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $1"; }
success() { echo -e "  ${GREEN}✓${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; exit 1; }
dimcmd()  { echo -e "  ${DIM}\$ $1${RESET}"; }
pause()   { echo -e "\n${DIM}  Press Enter to continue...${RESET}"; read -r; }

# Cleanup background processes on exit
PIDS=()
cleanup() {
    echo -e "\n${DIM}Cleaning up...${RESET}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    echo -e "${GREEN}✓${RESET} Demo processes stopped."
}
trap cleanup EXIT

# ── Preflight Checks ────────────────────────────────────────────────────────

banner "ZTLP SSH Tunnel Demo"

step "Preflight checks"

# Check ztlp binary
if command -v "$ZTLP" &>/dev/null; then
    ZTLP_VERSION=$("$ZTLP" --version 2>&1 || echo "unknown")
    success "ztlp binary found: $ZTLP_VERSION"
elif [[ -x "./ztlp" ]]; then
    ZTLP="./ztlp"
    ZTLP_VERSION=$("$ZTLP" --version 2>&1 || echo "unknown")
    success "ztlp binary found (local): $ZTLP_VERSION"
else
    fail "ztlp binary not found. Download from: https://github.com/priceflex/ztlp/releases"
fi

# Check SSH server
if nc -z 127.0.0.1 "$SSH_PORT" 2>/dev/null; then
    success "SSH server running on port $SSH_PORT"
else
    fail "SSH server not running on port $SSH_PORT. Start sshd first."
fi

# Check NS server (unless skipping)
if [[ "$SKIP_NS" != "true" ]]; then
    if nc -zu 127.0.0.1 "${NS_SERVER##*:}" 2>/dev/null; then
        success "NS server reachable at $NS_SERVER"
    else
        warn "NS server not reachable at $NS_SERVER"
        warn "Falling back to raw IP mode (equivalent to --skip-ns)"
        SKIP_NS=true
    fi
fi

# Create demo directory
mkdir -p "$DEMO_DIR"
success "Demo directory: $DEMO_DIR"

# ════════════════════════════════════════════════════════════════════════════
# ACT 1 — Generate Identities
# ════════════════════════════════════════════════════════════════════════════

banner "Act 1 — Generate Identities"

step "Generating server identity (Bob)"
dimcmd "$ZTLP keygen --output $DEMO_DIR/server.json"
"$ZTLP" keygen --output "$DEMO_DIR/server.json" 2>&1 | sed 's/^/  /'
echo

step "Generating client identity (Alice)"
dimcmd "$ZTLP keygen --output $DEMO_DIR/client.json"
"$ZTLP" keygen --output "$DEMO_DIR/client.json" 2>&1 | sed 's/^/  /'
echo

success "Two identities generated — cryptographic, not IP-based"

pause

# ════════════════════════════════════════════════════════════════════════════
# ACT 2 — Register with ZTLP-NS (optional)
# ════════════════════════════════════════════════════════════════════════════

if [[ "$SKIP_NS" != "true" ]]; then
    banner "Act 2 — Register with ZTLP-NS"

    step "Registering server identity + endpoint"
    dimcmd "$ZTLP ns register --name $DEMO_NAME --zone $DEMO_ZONE --key $DEMO_DIR/server.json --address 127.0.0.1:$LISTEN_PORT --ns-server $NS_SERVER"
    "$ZTLP" ns register \
        --name "$DEMO_NAME" \
        --zone "$DEMO_ZONE" \
        --key "$DEMO_DIR/server.json" \
        --address "127.0.0.1:$LISTEN_PORT" \
        --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /'
    echo

    step "Verifying registration"
    dimcmd "$ZTLP ns lookup $DEMO_NAME --ns-server $NS_SERVER"
    "$ZTLP" ns lookup "$DEMO_NAME" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /'
    echo

    success "Name registered — $DEMO_NAME → 127.0.0.1:$LISTEN_PORT"
    CONNECT_TARGET="$DEMO_NAME"
    NS_FLAG="--ns-server $NS_SERVER"

    pause
else
    info "Skipping NS registration (--skip-ns or NS unreachable)"
    CONNECT_TARGET="127.0.0.1:$LISTEN_PORT"
    NS_FLAG=""
fi

# ════════════════════════════════════════════════════════════════════════════
# ACT 3 — Start ZTLP Server (SSH Forward)
# ════════════════════════════════════════════════════════════════════════════

banner "Act 3 — Start ZTLP Server (SSH Forward)"

info "The server listens for ZTLP connections and forwards"
info "authenticated sessions to the local SSH server."
info "Port 22 stays invisible — only ZTLP port $LISTEN_PORT is exposed."
echo

step "Starting ZTLP listener with SSH forward"
dimcmd "$ZTLP listen --key $DEMO_DIR/server.json --bind 0.0.0.0:$LISTEN_PORT --forward 127.0.0.1:$SSH_PORT"

"$ZTLP" listen \
    --key "$DEMO_DIR/server.json" \
    --bind "0.0.0.0:$LISTEN_PORT" \
    --forward "127.0.0.1:$SSH_PORT" &
SERVER_PID=$!
PIDS+=("$SERVER_PID")

# Give server time to bind
sleep 1

if kill -0 "$SERVER_PID" 2>/dev/null; then
    success "Server listening on port $LISTEN_PORT → forwards to SSH on $SSH_PORT"
else
    fail "Server failed to start. Check if port $LISTEN_PORT is already in use."
fi

pause

# ════════════════════════════════════════════════════════════════════════════
# ACT 4 — Open ZTLP Tunnel (Client Side)
# ════════════════════════════════════════════════════════════════════════════

banner "Act 4 — Open ZTLP Tunnel"

info "The client connects to the server (by name or IP),"
info "performs a Noise_XX handshake, and opens a local port"
info "that tunnels through the encrypted ZTLP session to SSH."
echo

step "Opening ZTLP tunnel: localhost:$TUNNEL_LOCAL_PORT → ZTLP → SSH"
if [[ -n "$NS_FLAG" ]]; then
    dimcmd "$ZTLP connect $CONNECT_TARGET --key $DEMO_DIR/client.json $NS_FLAG -L $TUNNEL_LOCAL_PORT:127.0.0.1:$SSH_PORT"
else
    dimcmd "$ZTLP connect $CONNECT_TARGET --key $DEMO_DIR/client.json -L $TUNNEL_LOCAL_PORT:127.0.0.1:$SSH_PORT"
fi

# shellcheck disable=SC2086
"$ZTLP" connect "$CONNECT_TARGET" \
    --key "$DEMO_DIR/client.json" \
    $NS_FLAG \
    -L "$TUNNEL_LOCAL_PORT:127.0.0.1:$SSH_PORT" &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")

# Wait for tunnel to establish
sleep 2

if kill -0 "$CLIENT_PID" 2>/dev/null; then
    success "Tunnel established!"
    info "Local port $TUNNEL_LOCAL_PORT → ZTLP encrypted tunnel → SSH on $SSH_PORT"
else
    fail "Client failed to connect. Is the server running?"
fi

pause

# ════════════════════════════════════════════════════════════════════════════
# ACT 5 — SSH Through the Tunnel
# ════════════════════════════════════════════════════════════════════════════

banner "Act 5 — SSH Through the ZTLP Tunnel"

info "Now we SSH through the tunnel. The SSH connection travels:"
info "  ssh → localhost:$TUNNEL_LOCAL_PORT → [ZTLP encrypted] → localhost:$SSH_PORT"
echo
info "The SSH server sees a connection from localhost."
info "An attacker scanning the network sees only ZTLP port $LISTEN_PORT."
info "Port 22 is invisible. Brute-force is structurally impossible."
echo

step "Connecting via SSH through the ZTLP tunnel"
dimcmd "ssh -p $TUNNEL_LOCAL_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_USER@127.0.0.1"
echo
echo -e "${BOLD}${GREEN}  ┌─────────────────────────────────────────────────┐${RESET}"
echo -e "${BOLD}${GREEN}  │  You're now in an interactive SSH session       │${RESET}"
echo -e "${BOLD}${GREEN}  │  tunneled through ZTLP encryption.              │${RESET}"
echo -e "${BOLD}${GREEN}  │                                                 │${RESET}"
echo -e "${BOLD}${GREEN}  │  Try: whoami, hostname, uname -a                │${RESET}"
echo -e "${BOLD}${GREEN}  │  Type 'exit' to return to the demo.             │${RESET}"
echo -e "${BOLD}${GREEN}  └─────────────────────────────────────────────────┘${RESET}"
echo

ssh -p "$TUNNEL_LOCAL_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR \
    "$SSH_USER@127.0.0.1" || warn "SSH session ended"

echo

# ════════════════════════════════════════════════════════════════════════════
# ACT 6 — Proof: Port 22 is Invisible
# ════════════════════════════════════════════════════════════════════════════

banner "Act 6 — The Attack Surface"

step "What an attacker sees scanning this machine:"
echo

info "Scanning for SSH (port 22 from outside)..."
dimcmd "nc -z -w1 127.0.0.1 $SSH_PORT && echo 'OPEN' || echo 'CLOSED/FILTERED'"

# In a real demo with firewall rules, port 22 would be closed.
# For localhost demo, SSH is technically reachable — explain the concept.
if nc -z -w1 127.0.0.1 "$SSH_PORT" 2>/dev/null; then
    warn "Port $SSH_PORT is reachable (localhost demo — no firewall rules applied)"
    info "In production, you'd firewall port 22 and ONLY expose ZTLP port $LISTEN_PORT"
    info "Unauthorized packets hitting $LISTEN_PORT are rejected in ~19 nanoseconds"
else
    success "Port $SSH_PORT is CLOSED — invisible to scanners"
fi
echo

info "The key insight:"
echo -e "  ${BOLD}• Port 22 → firewalled, invisible${RESET}"
echo -e "  ${BOLD}• Port $LISTEN_PORT → ZTLP only, 19ns reject for bad packets${RESET}"
echo -e "  ${BOLD}• SSH brute-force → structurally impossible${RESET}"
echo -e "  ${BOLD}• Valid ZTLP identity required to even reach SSH${RESET}"

# ════════════════════════════════════════════════════════════════════════════
# Closing
# ════════════════════════════════════════════════════════════════════════════

banner "Demo Complete"

echo -e "  ${BOLD}ZTLP — Zero Trust Layer Protocol${RESET}"
echo -e "  ${DIM}ztlp.org | Apache 2.0${RESET}"
echo
echo -e "  ${CYAN}What you just saw:${RESET}"
echo -e "    1. Generated cryptographic identities (not IP-based)"
if [[ "$SKIP_NS" != "true" ]]; then
echo -e "    2. Registered with ZTLP-NS (signed namespace)"
echo -e "    3. Server listened with SSH forward (port 22 hidden)"
echo -e "    4. Client connected by name → ZTLP tunnel opened"
echo -e "    5. SSH session through end-to-end encrypted tunnel"
echo -e "    6. Attack surface: only ZTLP port exposed, 19ns rejection"
else
echo -e "    2. Server listened with SSH forward (port 22 hidden)"
echo -e "    3. Client connected → ZTLP tunnel opened"
echo -e "    4. SSH session through end-to-end encrypted tunnel"
echo -e "    5. Attack surface: only ZTLP port exposed, 19ns rejection"
fi
echo
echo -e "  ${DIM}Demo artifacts in: $DEMO_DIR${RESET}"
echo -e "  ${DIM}Run with --cleanup to remove.${RESET}"
echo
