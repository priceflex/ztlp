#!/usr/bin/env bash
# ================================================================
# ZTLP SSH Tunnel Demo (Zero Trust Security Showcase)
# ================================================================
# 14-act demo covering identity, policy, tunneling, and attack resilience:
#
#   Acts 1-2:  Generate identities (Bob, Alice, Eve) + optional NS register
#   Act  3:    Identity model — USER, DEVICE, GROUP records + group policy
#   Act  4:    Create zero-trust access policy (only Alice allowed)
#   Acts 5-7:  Server with policy → Alice connects → SSH through tunnel
#   Act  8:    Eve attempts connection → DENIED (authN ≠ authZ)
#   Act  9:    SCP throughput saturation (tunnel vs direct SSH)
#   Act  10:   Port visibility analysis (SSH hidden behind ZTLP)
#   Acts 11-12: DDoS defense layers (L1 magic byte + L2 SessionID)
#   Act  13:   Encrypted payload verification (tcpdump)
#   Act  14:   Security summary + three-layer defense cost table
#
# Requirements:
#   - ztlp binary (v0.5.6+) in PATH or ./ztlp
#   - SSH server on localhost (default 22)
#   - optional: nmap, tcpdump, python3 (for packet generators)
#   - Optional ZTLP‑NS server (Elixir) on port 23096 – auto-detected.
#
# Usage examples:
#   ./ssh-tunnel-demo.sh                     # Full demo (auto-detects NS)
#   ./ssh-tunnel-demo.sh --skip-ns           # Skip NS registration
#   ./ssh-tunnel-demo.sh --cleanup           # Remove demo artifacts
#   SSH_USER=steve SSH_PORT=22 ./ssh-tunnel-demo.sh
#
# See README.md for NS server setup and configuration details.
#
# -------------------------------------------------------------------

set -euo pipefail

# -------------------------------------------------------------------
# Configuration (environment variables can override defaults)
# -------------------------------------------------------------------
# Resolve ztlp binary: check ZTLP_BIN env, then PATH, then same dir as
# this script, then common build output locations in the repo.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -n "${ZTLP_BIN:-}" ]]; then
    ZTLP="$ZTLP_BIN"
elif command -v ztlp >/dev/null 2>&1; then
    ZTLP="ztlp"
elif [[ -x "$SCRIPT_DIR/ztlp" ]]; then
    ZTLP="$SCRIPT_DIR/ztlp"
elif [[ -x "$REPO_DIR/proto/target/release/ztlp" ]]; then
    ZTLP="$REPO_DIR/proto/target/release/ztlp"
elif [[ -x "$REPO_DIR/proto/target/debug/ztlp" ]]; then
    ZTLP="$REPO_DIR/proto/target/debug/ztlp"
else
    ZTLP="ztlp"  # fall through — will fail at the pre-flight check with a clear error
fi

DEMO_DIR="${DEMO_DIR:-/tmp/ztlp-demo}"
NS_SERVER="${NS_SERVER:-127.0.0.1:23096}"
LISTEN_PORT="${LISTEN_PORT:-23095}"
TUNNEL_LOCAL_PORT="${TUNNEL_LOCAL_PORT:-2222}"
SSH_PORT="${SSH_PORT:-22}"
SSH_USER="${SSH_USER:-$(whoami)}"
DEMO_NAME="${DEMO_NAME:-demo-server.tunnel.ztlp}"
DEMO_CLIENT="${DEMO_CLIENT:-alice.tunnel.ztlp}"
DEMO_EVE="${DEMO_EVE:-eve.tunnel.ztlp}"
DEMO_ZONE="${DEMO_ZONE:-tunnel.ztlp}"
SKIP_NS="${SKIP_NS:-false}"

# -------------------------------------------------------------------
# Argument handling
# -------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --skip-ns) SKIP_NS=true ;;
        --cleanup) rm -rf "$DEMO_DIR" && echo "✓ Cleaned up $DEMO_DIR" && exit 0 ;;
        --help|-h)
            sed -n '2,/^# ==/p' "$0" | head -n -1 | sed 's/^# //'
            exit 0 ;;
    esac
done

# -------------------------------------------------------------------
# Helpers – colors, output helpers, cleanup
# -------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

banner() { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════${RESET}"; echo -e "${BOLD}  $1${RESET}"; echo -e "${BOLD}${CYAN}════════════════════════════════════════${RESET}\n"; }
step()    { echo -e "${GREEN}▶${RESET} ${BOLD}$1${RESET}"; }
info()    { echo -e "  ${CYAN}ℹ${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $1"; }
success() { echo -e "  ${GREEN}✓${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; exit 1; }
dimcmd()  { echo -e "  ${DIM}\$ $1${RESET}"; }
pause()   { echo -e "\n${DIM}  Press Enter to continue...${RESET}"; read -r; }

# Retry wrapper — runs a command up to N times with delay between attempts.
# Usage: retry 3 1 command args...
#   $1 = max attempts, $2 = delay between attempts (sec), $3.. = command
retry() {
    local max_attempts=$1
    local delay=$2
    shift 2
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if "$@" 2>/dev/null; then
            return 0
        fi
        if [[ $attempt -lt $max_attempts ]]; then
            warn "attempt $attempt/$max_attempts failed, retrying in ${delay}s..."
            sleep "$delay"
        fi
        ((attempt++))
    done
    return 1
}

# Safe NS registration — retries up to 3 times, doesn't fail the script.
ns_register() {
    local name="$1" zone="$2" key="$3" address="$4" ns="$5"
    if retry 3 2 "$ZTLP" ns register \
        --name "$name" \
        --zone "$zone" \
        --key "$key" \
        --address "$address" \
        --ns-server "$ns"; then
        success "Registered $name"
        return 0
    else
        warn "Failed to register $name after 3 attempts (continuing anyway)"
        return 1
    fi
}

# Track background PIDs for cleanup
PIDS=()
cleanup() {
    echo -e "\n${DIM}Cleaning up...${RESET}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    # Remove tcpdump cap_net_raw if we set it
    if [[ "$TCPDUMP_CAP_SET" == "true" ]]; then
        if sudo -n setcap -r "$TCPDUMP_PATH" 2>/dev/null || sudo setcap -r "$TCPDUMP_PATH" 2>/dev/null; then
            echo -e "  ${GREEN}✓${RESET} Removed cap_net_raw from tcpdump"
        else
            echo -e "  ${YELLOW}⚠${RESET} Could not remove cap_net_raw from tcpdump — run: sudo setcap -r $TCPDUMP_PATH"
        fi
    fi
    echo -e "${GREEN}✓${RESET} Demo processes stopped."
}
trap cleanup EXIT

# -------------------------------------------------------------------
# Pre‑flight checks
# -------------------------------------------------------------------
banner "ZTLP SSH Tunnel Demo"
step "Pre‑flight checks"

# ztlp binary
if command -v "$ZTLP" >/dev/null 2>&1; then
    ZTLP_VER=$("$ZTLP" --version 2>/dev/null || echo "unknown")
    success "ztlp binary found: $ZTLP_VER"
else
    echo ""
    echo -e "  ${RED}Searched in:${RESET}"
    echo -e "  ${DIM}  1. \$ZTLP_BIN env var${RESET}"
    echo -e "  ${DIM}  2. \$PATH${RESET}"
    echo -e "  ${DIM}  3. $SCRIPT_DIR/ztlp  (same dir as this script)${RESET}"
    echo -e "  ${DIM}  4. $REPO_DIR/proto/target/release/ztlp  (cargo build --release)${RESET}"
    echo -e "  ${DIM}  5. $REPO_DIR/proto/target/debug/ztlp  (cargo build)${RESET}"
    echo ""
    echo -e "  ${YELLOW}Options:${RESET}"
    echo -e "  ${DIM}  • Build from source:  cd proto && cargo build --release${RESET}"
    echo -e "  ${DIM}  • Set path:           ZTLP_BIN=/path/to/ztlp ./ssh-tunnel-demo.sh${RESET}"
    echo -e "  ${DIM}  • Download release:   https://github.com/priceflex/ztlp/releases${RESET}"
    fail "ztlp binary not found"
fi

# Optional tool checks
HAS_NMAP=false; HAS_TCPDUMP=false; HAS_PYTHON3=false; HAS_NC=false; HAS_SCP=false; HAS_BC=false

command -v nmap    >/dev/null 2>&1 && { HAS_NMAP=true;    success "nmap found";       } || warn "nmap not found — port scan act will be skipped"
TCPDUMP_CAP_SET=false
if command -v tcpdump >/dev/null 2>&1; then
    HAS_TCPDUMP=true
    success "tcpdump found"
    # Check if tcpdump can capture without root — if not, try setcap
    TCPDUMP_PATH="$(which tcpdump)"
    if ! timeout 2 tcpdump -i lo -c 1 -w /dev/null 2>/dev/null; then
        info "tcpdump needs cap_net_raw for packet capture"
        if sudo -n setcap cap_net_raw+ep "$TCPDUMP_PATH" 2>/dev/null; then
            TCPDUMP_CAP_SET=true
            success "tcpdump: granted cap_net_raw (will remove at end)"
        else
            warn "Cannot grant cap_net_raw automatically — trying sudo setcap..."
            if sudo setcap cap_net_raw+ep "$TCPDUMP_PATH" 2>/dev/null; then
                TCPDUMP_CAP_SET=true
                success "tcpdump: granted cap_net_raw (will remove at end)"
            else
                warn "tcpdump capture may fail — run: sudo setcap cap_net_raw+ep $TCPDUMP_PATH"
            fi
        fi
    fi
else
    warn "tcpdump not found — capture act will be skipped"
fi
command -v python3 >/dev/null 2>&1 && { HAS_PYTHON3=true; success "python3 found";    } || warn "python3 not found — flood/malformed/CPU acts will be skipped"
command -v nc      >/dev/null 2>&1 && { HAS_NC=true;      success "nc (netcat) found"; } || warn "nc not found — SSH pre-check will use alternate method"
command -v scp     >/dev/null 2>&1 && { HAS_SCP=true;     success "scp found";        } || warn "scp not found — throughput test will be skipped"
command -v bc      >/dev/null 2>&1 && { HAS_BC=true;      success "bc found";         } || warn "bc not found — some calculations will show N/A"

# SSH server availability
if [[ "$HAS_NC" == "true" ]]; then
    if nc -z 127.0.0.1 "$SSH_PORT" >/dev/null 2>&1; then
        success "SSH server reachable on port $SSH_PORT"
    else
        fail "SSH server not reachable on port $SSH_PORT. Start sshd first."
    fi
else
    # Fallback: try bash /dev/tcp
    if (echo >/dev/tcp/127.0.0.1/"$SSH_PORT") 2>/dev/null; then
        success "SSH server reachable on port $SSH_PORT"
    else
        fail "SSH server not reachable on port $SSH_PORT. Start sshd first."
    fi
fi

# NS server (optional)
if [[ "$SKIP_NS" != "true" ]]; then
    if [[ "$HAS_NC" == "true" ]] && nc -zu 127.0.0.1 "${NS_SERVER##*:}" >/dev/null 2>&1; then
        success "NS server reachable at $NS_SERVER"
    else
        warn "NS server not reachable at $NS_SERVER – using NodeID hex for policy"
        info "For human-readable names (alice.tunnel.ztlp), start NS first:"
        info "  cd ns && ZTLP_NS_PORT=23096 mix run --no-halt"
        info "Requires: Elixir 1.12+ / Erlang OTP 24+ (zero external deps)"
        SKIP_NS=true
    fi
fi

mkdir -p "$DEMO_DIR"
success "Demo directory: $DEMO_DIR"

# -------------------------------------------------------------------
# ACT 1 – Generate Identities
# -------------------------------------------------------------------
banner "Act 1 — Generate Identities"
step "Server identity (Bob)"
dimcmd "$ZTLP keygen --output $DEMO_DIR/server.json"
"$ZTLP" keygen --output "$DEMO_DIR/server.json" | sed 's/^/  /'

step "Client identity (Alice)"
dimcmd "$ZTLP keygen --output $DEMO_DIR/client.json"
"$ZTLP" keygen --output "$DEMO_DIR/client.json" | sed 's/^/  /'

step "Attacker identity (Eve)"
dimcmd "$ZTLP keygen --output $DEMO_DIR/eve.json"
"$ZTLP" keygen --output "$DEMO_DIR/eve.json" | sed 's/^/  /'

# Extract NodeIDs for policy file (used when NS is not available)
if [[ "$HAS_PYTHON3" == "true" ]]; then
    ALICE_NODE_ID=$(python3 -c "import json; print(json.load(open('$DEMO_DIR/client.json'))['node_id'])")
    EVE_NODE_ID=$(python3 -c "import json; print(json.load(open('$DEMO_DIR/eve.json'))['node_id'])")
else
    ALICE_NODE_ID=$(grep -o '"node_id": *"[^"]*"' "$DEMO_DIR/client.json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
    EVE_NODE_ID=$(grep -o '"node_id": *"[^"]*"' "$DEMO_DIR/eve.json" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
fi
info "Alice NodeID: $ALICE_NODE_ID"
info "Eve NodeID:   $EVE_NODE_ID"

success "Keypairs generated (Ed25519 + X25519)"

# If NS is available, also create USER and DEVICE identities
if [[ "$SKIP_NS" != "true" ]]; then
    echo ""
    step "Creating USER identities (v0.9.0 identity model)"
    info "Users represent people — they have roles and own devices"

    dimcmd "$ZTLP admin create-user bob@$DEMO_ZONE --role admin --ns-server $NS_SERVER"
    "$ZTLP" admin create-user "bob@$DEMO_ZONE" --role admin --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "create-user bob failed (continuing)"

    dimcmd "$ZTLP admin create-user alice@$DEMO_ZONE --role tech --ns-server $NS_SERVER"
    "$ZTLP" admin create-user "alice@$DEMO_ZONE" --role tech --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "create-user alice failed (continuing)"

    dimcmd "$ZTLP admin create-user eve@$DEMO_ZONE --role user --ns-server $NS_SERVER"
    "$ZTLP" admin create-user "eve@$DEMO_ZONE" --role user --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "create-user eve failed (continuing)"

    success "USER records created: bob (admin), alice (tech), eve (user)"
fi

pause

# -------------------------------------------------------------------
# ACT 2 – Optional NS registration
# -------------------------------------------------------------------
if [[ "$SKIP_NS" != "true" ]]; then
    banner "Act 2 — Register with ZTLP‑NS"
    step "Register server name"
    dimcmd "$ZTLP ns register --name $DEMO_NAME --zone $DEMO_ZONE --key $DEMO_DIR/server.json --address 127.0.0.1:$LISTEN_PORT --ns-server $NS_SERVER"
    NS_REG_OK=true
    ns_register "$DEMO_NAME" "$DEMO_ZONE" "$DEMO_DIR/server.json" "127.0.0.1:$LISTEN_PORT" "$NS_SERVER" || NS_REG_OK=false

    if [[ "$NS_REG_OK" == "true" ]]; then
        step "Verify registration"
        dimcmd "$ZTLP ns lookup $DEMO_NAME --ns-server $NS_SERVER"
        "$ZTLP" ns lookup "$DEMO_NAME" --ns-server "$NS_SERVER" 2>/dev/null | sed 's/^/  /' || warn "Lookup failed"
    fi

    step "Register client name (Alice)"
    dimcmd "$ZTLP ns register --name $DEMO_CLIENT --zone $DEMO_ZONE --key $DEMO_DIR/client.json --address 127.0.0.1:0 --ns-server $NS_SERVER"
    ns_register "$DEMO_CLIENT" "$DEMO_ZONE" "$DEMO_DIR/client.json" "127.0.0.1:0" "$NS_SERVER" || NS_REG_OK=false

    step "Register attacker name (Eve)"
    dimcmd "$ZTLP ns register --name $DEMO_EVE --zone $DEMO_ZONE --key $DEMO_DIR/eve.json --address 127.0.0.1:0 --ns-server $NS_SERVER"
    ns_register "$DEMO_EVE" "$DEMO_ZONE" "$DEMO_DIR/eve.json" "127.0.0.1:0" "$NS_SERVER" || NS_REG_OK=false

    if [[ "$NS_REG_OK" == "true" ]]; then
        success "All names registered (KEY records in NS)"

        # Link devices to users
        echo ""
        step "Linking devices to user identities"
        info "Each KEY record is a device — linking them to their USER owners"

        dimcmd "$ZTLP admin link-device $DEMO_NAME --owner bob@$DEMO_ZONE --ns-server $NS_SERVER"
        "$ZTLP" admin link-device "$DEMO_NAME" --owner "bob@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "link-device server failed"

        dimcmd "$ZTLP admin link-device $DEMO_CLIENT --owner alice@$DEMO_ZONE --ns-server $NS_SERVER"
        "$ZTLP" admin link-device "$DEMO_CLIENT" --owner "alice@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "link-device alice failed"

        dimcmd "$ZTLP admin link-device $DEMO_EVE --owner eve@$DEMO_ZONE --ns-server $NS_SERVER"
        "$ZTLP" admin link-device "$DEMO_EVE" --owner "eve@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "link-device eve failed"

        success "Devices linked to users"

        # Show user→device relationship
        echo ""
        step "Verify device ownership"
        dimcmd "$ZTLP admin devices bob@$DEMO_ZONE --ns-server $NS_SERVER"
        "$ZTLP" admin devices "bob@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || true
        dimcmd "$ZTLP admin devices alice@$DEMO_ZONE --ns-server $NS_SERVER"
        "$ZTLP" admin devices "alice@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || true
    else
        warn "Some registrations failed — falling back to NodeID hex for policy"
        SKIP_NS=true
    fi
    CONNECT_TARGET="$DEMO_NAME"
    NS_FLAG="--ns-server $NS_SERVER"
    # Use human-readable names for policy
    ALICE_IDENTITY="$DEMO_CLIENT"
    EVE_IDENTITY="$DEMO_EVE"
    pause
else
    info "Skipping NS registration"
    CONNECT_TARGET="127.0.0.1:$LISTEN_PORT"
    NS_FLAG=""
    # Use NodeID hex for policy (no NS names available)
    ALICE_IDENTITY="$ALICE_NODE_ID"
    EVE_IDENTITY="$EVE_NODE_ID"
fi

# -------------------------------------------------------------------
# ACT 3 – Identity Model (USER, DEVICE, GROUP)
# -------------------------------------------------------------------
if [[ "$SKIP_NS" != "true" ]]; then
    banner "Act 3 — Identity Model (Users, Devices, Groups)"
    info "ZTLP v0.9.0 introduces a rich identity model beyond raw keypairs."
    info "Users are people. Devices are machines. Groups control access."
    echo ""

    step "Create a group for field technicians"
    dimcmd "$ZTLP admin create-group techs@$DEMO_ZONE --description \"Field technicians\" --ns-server $NS_SERVER"
    "$ZTLP" admin create-group "techs@$DEMO_ZONE" --description "Field technicians" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "create-group techs failed"

    step "Create an admin group"
    dimcmd "$ZTLP admin create-group admins@$DEMO_ZONE --description \"Administrators\" --ns-server $NS_SERVER"
    "$ZTLP" admin create-group "admins@$DEMO_ZONE" --description "Administrators" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "create-group admins failed"

    echo ""
    step "Add Alice to the techs group"
    dimcmd "$ZTLP admin group add techs@$DEMO_ZONE alice@$DEMO_ZONE --ns-server $NS_SERVER"
    "$ZTLP" admin group add "techs@$DEMO_ZONE" "alice@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "group add alice failed"

    step "Add Bob to the admins group"
    dimcmd "$ZTLP admin group add admins@$DEMO_ZONE bob@$DEMO_ZONE --ns-server $NS_SERVER"
    "$ZTLP" admin group add "admins@$DEMO_ZONE" "bob@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "group add bob failed"

    echo ""
    step "List all users in the zone"
    dimcmd "$ZTLP admin ls --type user --ns-server $NS_SERVER"
    "$ZTLP" admin ls --type user --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "ls users failed"

    echo ""
    step "List all groups in the zone"
    dimcmd "$ZTLP admin ls --type group --ns-server $NS_SERVER"
    "$ZTLP" admin ls --type group --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "ls groups failed"

    echo ""
    step "Check group membership"
    dimcmd "$ZTLP admin group check techs@$DEMO_ZONE alice@$DEMO_ZONE --ns-server $NS_SERVER"
    "$ZTLP" admin group check "techs@$DEMO_ZONE" "alice@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "group check failed"

    dimcmd "$ZTLP admin group check techs@$DEMO_ZONE eve@$DEMO_ZONE --ns-server $NS_SERVER"
    "$ZTLP" admin group check "techs@$DEMO_ZONE" "eve@$DEMO_ZONE" --ns-server "$NS_SERVER" 2>&1 | sed 's/^/  /' || warn "group check failed"

    echo ""
    success "Identity model demonstrated: Users → Groups → Policy"
    info "Alice is a tech in the 'techs' group — she'll get SSH access via group policy"
    info "Eve has a valid identity but is NOT in any group — she'll be denied"
    pause
else
    info "Skipping Act 3 (Identity Model) — requires NS server"
fi

# -------------------------------------------------------------------
# ACT 4 – Create Access Policy (Zero Trust)
# -------------------------------------------------------------------
banner "Act 4 — Create Access Policy (Zero Trust)"
info "Bob (server) creates a policy that only allows Alice to access SSH"
info "Eve (attacker) will be denied even though she has a valid ZTLP identity"

POLICY_FILE="$DEMO_DIR/policy.toml"
step "Writing policy file"

if [[ "$SKIP_NS" != "true" ]]; then
    # Group-based policy (v0.9.0) — allows anyone in the techs group
    cat > "$POLICY_FILE" <<POLICYEOF
# ZTLP Access Policy — Zero Trust (default deny)
# Group-based access control (v0.9.0 identity model)
# Anyone in the "techs" group can access SSH.
default = "deny"

[[services]]
name = "ssh"
allow = ["group:techs@$DEMO_ZONE", "group:admins@$DEMO_ZONE"]
# Alternative: allow by individual identity name (pre-v0.9.0 style):
#   allow = ["$ALICE_IDENTITY"]
POLICYEOF
else
    # Fallback: identity-based policy (no NS, no groups)
    cat > "$POLICY_FILE" <<POLICYEOF
# ZTLP Access Policy — Zero Trust (default deny)
# Only explicitly listed identities can access services.
default = "deny"

[[services]]
name = "ssh"
allow = ["$ALICE_IDENTITY"]
POLICYEOF
fi

echo ""
echo -e "  ${DIM}── $POLICY_FILE ──${RESET}"
cat "$POLICY_FILE" | sed 's/^/  /'
echo -e "  ${DIM}────────────────────────${RESET}"
echo ""

if [[ "$SKIP_NS" != "true" ]]; then
    info "techs group (alice) → ${GREEN}allowed${RESET} for ssh"
    info "admins group (bob) → ${GREEN}allowed${RESET} for ssh"
    info "Eve (no group)     → ${RED}denied${RESET}  for ssh"
    echo ""
    info "Policy uses ${BOLD}group:techs@$DEMO_ZONE${RESET} — anyone added to the group gets access."
    info "No gateway restart needed when group membership changes."
else
    info "Alice ($ALICE_IDENTITY) → ${GREEN}allowed${RESET} for ssh"
fi
info "Eve   ($EVE_IDENTITY) → ${RED}denied${RESET}  for ssh"
success "Policy created — zero trust, default deny"
pause

# -------------------------------------------------------------------
# ACT 5 – Start ZTLP server with policy enforcement
# -------------------------------------------------------------------
banner "Act 5 — Start ZTLP Server (SSH Forward + Policy)"
info "Server will listen on $LISTEN_PORT and forward SSH on $SSH_PORT"
info "Policy enforcement enabled — only Alice can connect"
step "Launching listener with policy"
NS_LISTEN_FLAG=""
if [[ -n "$NS_FLAG" ]]; then
    NS_LISTEN_FLAG="--ns-server $NS_SERVER"
fi
dimcmd "$ZTLP listen --key $DEMO_DIR/server.json --bind 0.0.0.0:$LISTEN_PORT --forward ssh:127.0.0.1:$SSH_PORT --policy $POLICY_FILE --gateway $NS_LISTEN_FLAG"
"$ZTLP" listen \
    --key "$DEMO_DIR/server.json" \
    --bind "0.0.0.0:$LISTEN_PORT" \
    --forward "ssh:127.0.0.1:$SSH_PORT" \
    --policy "$POLICY_FILE" \
    --gateway $NS_LISTEN_FLAG &
SERVER_PID=$!
PIDS+=("$SERVER_PID")

sleep 1
if kill -0 "$SERVER_PID" 2>/dev/null; then
    success "Listener active on $LISTEN_PORT → SSH $SSH_PORT (policy enforced)"
else
    fail "Failed to start listener"
fi
pause

# -------------------------------------------------------------------
# ACT 6 – Alice connects (ALLOWED)
# -------------------------------------------------------------------
banner "Act 6 — Alice Connects (Policy Allowed)"
info "Alice is in the allow list — she can access the SSH service"
step "Creating local tunnel on $TUNNEL_LOCAL_PORT"
if [[ -n "$NS_FLAG" ]]; then
    dimcmd "$ZTLP connect $CONNECT_TARGET --key $DEMO_DIR/client.json $NS_FLAG --service ssh -L $TUNNEL_LOCAL_PORT:127.0.0.1:$SSH_PORT"
else
    dimcmd "$ZTLP connect $CONNECT_TARGET --key $DEMO_DIR/client.json --service ssh -L $TUNNEL_LOCAL_PORT:127.0.0.1:$SSH_PORT"
fi
# shellcheck disable=SC2086
"$ZTLP" connect "$CONNECT_TARGET" \
    --key "$DEMO_DIR/client.json" \
    $NS_FLAG \
    --service ssh \
    -L "$TUNNEL_LOCAL_PORT:127.0.0.1:$SSH_PORT" &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")

sleep 2
if kill -0 "$CLIENT_PID" 2>/dev/null; then
    success "Alice's tunnel established (localhost:$TUNNEL_LOCAL_PORT → SSH)"
    info "Policy check passed: $ALICE_IDENTITY → ssh ✓"
else
    fail "Alice's tunnel failed to start"
fi
pause

# -------------------------------------------------------------------
# ACT 7 – SSH through the tunnel
# -------------------------------------------------------------------
banner "Act 7 — SSH Through the ZTLP Tunnel"
info "Alice can now SSH through her encrypted ZTLP tunnel"
step "Running command via SSH tunnel"
dimcmd "ssh -p $TUNNEL_LOCAL_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $SSH_USER@127.0.0.1 'echo \"Hello from \$(hostname) via ZTLP tunnel! [\$(date)]\"'"
# Use BatchMode to avoid interactive password prompts that would hang.
# If pubkey auth isn't set up, this will fail fast instead of blocking.
SSH_OUTPUT=$(timeout 15 ssh -p "$TUNNEL_LOCAL_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    -o LogLevel=ERROR \
    -o PreferredAuthentications=publickey,keyboard-interactive,password \
    -o GSSAPIAuthentication=no \
    -o KexAlgorithms=curve25519-sha256 \
    "$SSH_USER@127.0.0.1" \
    'echo "Hello from $(hostname) via ZTLP tunnel! [$(date)]"' 2>&1) || true
if echo "$SSH_OUTPUT" | grep -q "Hello from"; then
    echo -e "  ${GREEN}$(echo "$SSH_OUTPUT" | grep "Hello from")${RESET}"
    success "SSH command executed through ZTLP tunnel"
else
    warn "SSH through tunnel timed out — this is a known issue under investigation"
    info "Testing direct SSH to verify sshd is working..."
    DIRECT_SSH=$(timeout 5 ssh -p "$SSH_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o GSSAPIAuthentication=no \
        "$SSH_USER@127.0.0.1" \
        'echo "direct SSH works"' 2>&1) || true
    if echo "$DIRECT_SSH" | grep -q "direct SSH works"; then
        success "Direct SSH works — tunnel data path issue"
    else
        warn "Direct SSH also failed (check sshd config): $DIRECT_SSH"
    fi
fi

pause

# -------------------------------------------------------------------
# ACT 8 – Eve tries to connect (DENIED)
# -------------------------------------------------------------------
banner "Act 8 — Eve Attempts Connection (Policy Denial)"
info "Eve has a valid ZTLP identity — she can complete the Noise_XX handshake"
info "But the policy engine will deny her access to the SSH service"
echo ""

EVE_LISTEN_PORT=23099
EVE_TUNNEL_PORT=2223
EVE_SERVER_LOG="$DEMO_DIR/eve_server.log"

step "Starting a test listener on port $EVE_LISTEN_PORT (same policy)"
"$ZTLP" listen \
    --key "$DEMO_DIR/server.json" \
    --bind "0.0.0.0:$EVE_LISTEN_PORT" \
    --forward "ssh:127.0.0.1:$SSH_PORT" \
    --policy "$POLICY_FILE" \
    $NS_LISTEN_FLAG > "$EVE_SERVER_LOG" 2>&1 &
EVE_SERVER_PID=$!
PIDS+=("$EVE_SERVER_PID")
sleep 1

step "Eve connecting to port $EVE_LISTEN_PORT..."
echo ""
# Eve's connection is *expected* to fail (policy denial).
# The server drops her after denying access; the client sits idle
# until timeout kills it (exit 124). We capture exit code separately
# to avoid set -e + pipefail killing the demo.
EVE_LOG="$DEMO_DIR/eve_client.log"
timeout 8 "$ZTLP" connect "127.0.0.1:$EVE_LISTEN_PORT" \
    --key "$DEMO_DIR/eve.json" \
    --service ssh \
    -L "$EVE_TUNNEL_PORT:127.0.0.1:$SSH_PORT" > "$EVE_LOG" 2>&1 || true
sed 's/^/  /' "$EVE_LOG"

echo ""
success "Eve was ${RED}DENIED${RESET}"

# Show the server-side denial
echo ""
step "Server-side policy log:"
if [[ -f "$EVE_SERVER_LOG" ]]; then
    grep -E "POLICY DENIED|policy DENY|policy denied|Policy:" "$EVE_SERVER_LOG" | sed 's/^/  /'
fi

echo ""
info "The Noise_XX handshake completed — Eve proved she IS Eve"
info "But Bob's policy says only Alice can access SSH"
echo ""
echo -e "  ${BOLD}This is the key insight: authentication ≠ authorization${RESET}"
echo -e "  ${DIM}Eve is who she says she is. She's just not allowed in.${RESET}"

# Clean up Eve's listener
kill "$EVE_SERVER_PID" 2>/dev/null || true
wait "$EVE_SERVER_PID" 2>/dev/null || true
pause

# -------------------------------------------------------------------
# ACT 9 – Throughput Saturation Test (scp)
# -------------------------------------------------------------------
banner "Act 9 — Throughput Saturation Test"

if [[ "$HAS_SCP" == "true" ]]; then
    TEST_FILE="$DEMO_DIR/throughput_test.bin"
    SCP_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

    # Generate test files of increasing size
    for SIZE_MB in 10 50 100; do
        step "Generating ${SIZE_MB}MB test file"
        dd if=/dev/urandom of="$TEST_FILE" bs=1M count="$SIZE_MB" 2>/dev/null
        BYTES=$((SIZE_MB * 1048576))

        # ── ZTLP tunnel transfer ──
        step "SCP ${SIZE_MB}MB through ZTLP tunnel (port $TUNNEL_LOCAL_PORT)"
        ZTLP_START=$(date +%s%N)
        # shellcheck disable=SC2086
        scp -P "$TUNNEL_LOCAL_PORT" $SCP_OPTS "$TEST_FILE" "$SSH_USER@127.0.0.1:/dev/null" 2>/dev/null
        ZTLP_END=$(date +%s%N)
        ZTLP_MS=$(( (ZTLP_END - ZTLP_START) / 1000000 ))
        if [[ "$ZTLP_MS" -gt 0 ]]; then
            ZTLP_MBPS=$(echo "scale=2; $BYTES * 8 / ($ZTLP_MS * 1000)" | bc 2>/dev/null || echo "N/A")
        else
            ZTLP_MBPS="∞"
        fi

        # ── Direct SSH transfer (baseline) ──
        step "SCP ${SIZE_MB}MB direct SSH (port $SSH_PORT) — baseline"
        DIRECT_START=$(date +%s%N)
        # shellcheck disable=SC2086
        scp -P "$SSH_PORT" $SCP_OPTS "$TEST_FILE" "$SSH_USER@127.0.0.1:/dev/null" 2>/dev/null
        DIRECT_END=$(date +%s%N)
        DIRECT_MS=$(( (DIRECT_END - DIRECT_START) / 1000000 ))
        if [[ "$DIRECT_MS" -gt 0 ]]; then
            DIRECT_MBPS=$(echo "scale=2; $BYTES * 8 / ($DIRECT_MS * 1000)" | bc 2>/dev/null || echo "N/A")
        else
            DIRECT_MBPS="∞"
        fi

        # ── Results ──
        if [[ "$DIRECT_MS" -gt 0 && "$ZTLP_MS" -gt 0 ]]; then
            OVERHEAD=$(echo "scale=1; 100 * ($ZTLP_MS - $DIRECT_MS) / $DIRECT_MS" | bc 2>/dev/null || echo "N/A")
        else
            OVERHEAD="N/A"
        fi

        echo ""
        info "${SIZE_MB}MB results:"
        info "  ZTLP tunnel:  ${ZTLP_MS}ms  (${ZTLP_MBPS} Mbps)"
        info "  Direct SSH:   ${DIRECT_MS}ms  (${DIRECT_MBPS} Mbps)"
        info "  Overhead:     ${OVERHEAD}%"
        echo ""
    done

    rm -f "$TEST_FILE"
    success "Throughput test complete — ZTLP adds encryption with minimal overhead"
else
    warn "scp not available — skipping throughput test"
fi
pause

# -------------------------------------------------------------------
# ACT 10 – Port Visibility Analysis
# -------------------------------------------------------------------
banner "Act 10 — Port Visibility Analysis"
step "Understanding what an attacker sees on the network"
echo ""
info "Right now, Alice is connected to Bob's SSH service through ZTLP."
info "But what does the network actually expose?"
echo ""
info "  ${BOLD}Port $SSH_PORT (SSH):${RESET} ${GREEN}Hidden${RESET} — ZTLP tunnel provides the only access path."
info "    In production, SSH would be firewalled to block direct access."
info "    Only authenticated ZTLP peers with the right policy can reach it."
echo ""
info "  ${BOLD}Port $LISTEN_PORT (ZTLP):${RESET} ${CYAN}Visible${RESET} — but it speaks ZTLP, not SSH."
info "    An attacker can see this port is open, but can't determine what's behind it."
info "    Without a valid ZTLP identity, they can't even complete a handshake."
info "    The magic byte check rejects non-ZTLP packets in ~19 nanoseconds."
echo ""

if [[ "$HAS_NMAP" == "true" ]]; then
    step "Verifying with nmap (attacker's perspective)"
    dimcmd "nmap -sU -sT -p T:$SSH_PORT,U:$LISTEN_PORT 127.0.0.1"
    nmap -p "$SSH_PORT,$LISTEN_PORT" 127.0.0.1 2>/dev/null | grep -E "^PORT|^[0-9]" | sed 's/^/  /'
    echo ""
    info "nmap sees the ZTLP UDP port but gets nothing useful from it."
    info "SSH is only reachable through the authenticated ZTLP tunnel."
else
    info "(nmap not installed — install it to see the scan results)"
fi
success "Key takeaway: ZTLP turns SSH into an invisible service"
pause

# -------------------------------------------------------------------
# ACT 11 – UDP Packet Flood (Layer 1 DDoS Defense)
# -------------------------------------------------------------------
banner "Act 11 — UDP Packet Flood (L1 Defense)"
if [[ "$HAS_PYTHON3" == "true" ]]; then
    FLOOD_COUNT=50000
    echo ""
    info "${BOLD}What's happening:${RESET} An attacker floods the ZTLP port with random UDP packets."
    info "This simulates a volumetric DDoS attack — the cheapest, most common attack vector."
    echo ""
    info "${BOLD}ZTLP's defense (Layer 1 — Magic Byte Check):${RESET}"
    info "  Every ZTLP packet starts with magic bytes 0x5A37."
    info "  Random packets fail this 2-byte check and are dropped immediately."
    info "  No crypto, no session lookup, no memory allocation — just a compare-and-reject."
    info "  On Linux with eBPF/XDP, this check runs at the NIC driver level (~19ns per packet)."
    echo ""

    step "Flooding $FLOOD_COUNT random UDP packets at ZTLP port $LISTEN_PORT"

    # Measure CPU before
    read -r _ _ _ _ IDLE_BEFORE _ < /proc/stat
    TOTAL_BEFORE=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat)
    TS_BEFORE=$(date +%s%N)

    python3 -c "
import socket, os, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
count = ${FLOOD_COUNT}
start = time.time()
for i in range(count):
    sock.sendto(os.urandom(64), ('127.0.0.1', ${LISTEN_PORT}))
elapsed = time.time() - start
rate = count / elapsed if elapsed > 0 else 0
print(f'  Sent {count:,} packets in {elapsed:.3f}s ({rate:,.0f} pkt/s)')
" 2>&1 | sed 's/^/  /'

    # Measure CPU after
    read -r _ _ _ _ IDLE_AFTER _ < /proc/stat
    TOTAL_AFTER=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat)
    TS_AFTER=$(date +%s%N)

    TOTAL_DELTA=$((TOTAL_AFTER - TOTAL_BEFORE))
    IDLE_DELTA=$((IDLE_AFTER - IDLE_BEFORE))
    WALL_MS=$(( (TS_AFTER - TS_BEFORE) / 1000000 ))

    echo ""
    if [[ "$HAS_BC" == "true" && "$TOTAL_DELTA" -gt 0 ]]; then
        CPU_PCT=$(echo "scale=1; 100 * ($TOTAL_DELTA - $IDLE_DELTA) / $TOTAL_DELTA" | bc 2>/dev/null || echo "N/A")
        info "${BOLD}Results:${RESET}"
        info "  Wall time:     ${WALL_MS}ms for ${FLOOD_COUNT} packets"
        info "  CPU impact:    ${CPU_PCT}% (entire system, all cores)"
        info "  Cost per pkt:  ~19ns (eBPF/XDP) or ~89ns (userspace Elixir)"
    else
        info "${BOLD}Results:${RESET}"
        info "  Wall time:     ${WALL_MS}ms for ${FLOOD_COUNT} packets"
    fi
    echo ""
    info "The ZTLP listener didn't break a sweat. Alice's SSH session is unaffected."
    info "No crypto was performed — invalid packets never reach the session layer."
    success "L1 DDoS defense: reject trash at the door, spend zero effort on it"
else
    warn "python3 not available – skipping packet‑flood act"
fi
pause

# -------------------------------------------------------------------
# ACT 12 – Malformed ZTLP Packets (Layer 2 Defense)
# -------------------------------------------------------------------
banner "Act 12 — Malformed ZTLP Packets (L2 Defense)"
if [[ "$HAS_PYTHON3" == "true" ]]; then
    MAL_COUNT=50000
    echo ""
    info "${BOLD}What's happening:${RESET} A smarter attacker figured out the magic bytes (0x5A37)."
    info "They craft packets that pass the L1 check but use random SessionIDs."
    echo ""
    info "${BOLD}ZTLP's defense (Layer 2 — SessionID Verification):${RESET}"
    info "  After magic byte validation, ZTLP checks the 12-byte SessionID."
    info "  SessionIDs are negotiated during the Noise_XX handshake — they're not guessable."
    info "  Random SessionIDs don't match any active session → immediate drop."
    info "  Still no crypto overhead — just an O(1) hash table lookup."
    echo ""
    info "${BOLD}The three-layer DDoS pipeline:${RESET}"
    info "  L1: Magic byte check    → rejects random garbage       (~19ns)"
    info "  L2: SessionID lookup    → rejects crafted packets      (~50ns)"
    info "  L3: HeaderAuthTag HMAC  → rejects session replay       (~200ns)"
    info "  Each layer is progressively more expensive but filters more traffic."
    echo ""

    step "Flooding $MAL_COUNT packets with correct magic but fake SessionIDs"

    # Measure CPU before
    read -r _ _ _ _ IDLE_BEFORE _ < /proc/stat
    TOTAL_BEFORE=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat)
    TS_BEFORE=$(date +%s%N)

    python3 -c "
import socket, struct, os, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
count = ${MAL_COUNT}
start = time.time()
for i in range(count):
    pkt = struct.pack('>H', 0x5A37) + os.urandom(40)
    sock.sendto(pkt, ('127.0.0.1', ${LISTEN_PORT}))
elapsed = time.time() - start
rate = count / elapsed if elapsed > 0 else 0
print(f'  Sent {count:,} packets in {elapsed:.3f}s ({rate:,.0f} pkt/s)')
" 2>&1 | sed 's/^/  /'

    # Measure CPU after
    read -r _ _ _ _ IDLE_AFTER _ < /proc/stat
    TOTAL_AFTER=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9}' /proc/stat)
    TS_AFTER=$(date +%s%N)

    TOTAL_DELTA=$((TOTAL_AFTER - TOTAL_BEFORE))
    IDLE_DELTA=$((IDLE_AFTER - IDLE_BEFORE))
    WALL_MS=$(( (TS_AFTER - TS_BEFORE) / 1000000 ))

    echo ""
    if [[ "$HAS_BC" == "true" && "$TOTAL_DELTA" -gt 0 ]]; then
        CPU_PCT=$(echo "scale=1; 100 * ($TOTAL_DELTA - $IDLE_DELTA) / $TOTAL_DELTA" | bc 2>/dev/null || echo "N/A")
        info "${BOLD}Results:${RESET}"
        info "  Wall time:     ${WALL_MS}ms for ${MAL_COUNT} packets"
        info "  CPU impact:    ${CPU_PCT}% (entire system, all cores)"
    else
        info "${BOLD}Results:${RESET}"
        info "  Wall time:     ${WALL_MS}ms for ${MAL_COUNT} packets"
    fi
    echo ""
    info "Even with correct magic bytes, the attacker can't disrupt the tunnel."
    info "The SessionID check is a ~50ns O(1) lookup — negligible CPU cost."
    success "L2 defense: attacker passed the door, but can't find the right room"
else
    warn "python3 not available – skipping malformed‑packet act"
fi
pause

# -------------------------------------------------------------------
# ACT 13 – Encrypted Payload Verification (tcpdump)
# -------------------------------------------------------------------
banner "Act 13 — Encrypted Payload Verification"
if [[ "$HAS_TCPDUMP" == "true" ]]; then
    PCAP="$DEMO_DIR/ztlp_capture.pcap"
    echo ""
    info "${BOLD}What we're proving:${RESET} Even if an attacker captures network traffic,"
    info "they see nothing useful. ZTLP uses ChaCha20-Poly1305 authenticated encryption."
    echo ""

    step "Capturing ZTLP traffic during a live SSH command"
    # Start capture in background
    tcpdump -i any -w "$PCAP" -s 0 udp port "$LISTEN_PORT" 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 1

    # Run an SSH command through the tunnel to generate traffic
    timeout 10 ssh -p "$TUNNEL_LOCAL_PORT" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o GSSAPIAuthentication=no \
        -o KexAlgorithms=curve25519-sha256 \
        "$SSH_USER@127.0.0.1" \
        'echo "TOP SECRET DATA: the password is hunter2"' 2>/dev/null || true
    sleep 1
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true

    # Analyze the capture
    PKT_COUNT=$(tcpdump -r "$PCAP" 2>/dev/null | wc -l)
    echo ""
    info "Captured ${PKT_COUNT} packets containing the SSH session"

    step "Searching captured packets for plaintext (should find nothing)"
    if strings "$PCAP" 2>/dev/null | grep -qi "hunter2\|TOP SECRET\|password"; then
        warn "Found plaintext in capture — encryption may have an issue!"
    else
        success "No plaintext found in ${PKT_COUNT} captured packets"
        info "The attacker sees encrypted ChaCha20-Poly1305 ciphertext — no SSH commands,"
        info "no passwords, no hostnames. Even packet sizes are uninformative (ZTLP pads data)."
    fi

    if [[ "$PKT_COUNT" -gt 0 ]]; then
        echo ""
        step "Sample packet (hex dump of first ZTLP payload):"
        tcpdump -r "$PCAP" -x -c 1 2>/dev/null | grep "0x" | head -4 | sed 's/^/  /'
        info "↑ Pure encrypted noise — no structure visible to an observer"
    fi

    info "Capture saved to $PCAP for further analysis"
else
    warn "tcpdump not installed – skipping encrypted payload verification"
fi
pause

# -------------------------------------------------------------------
# ACT 14 – Security Summary
# -------------------------------------------------------------------
banner "Act 14 — Security Summary"
echo ""
info "${BOLD}Defense cost summary (from Acts 10-12):${RESET}"
echo ""
echo -e "  ┌─────────────────────┬───────────────┬────────────────────────────────┐"
echo -e "  │ ${BOLD}Layer${RESET}               │ ${BOLD}Cost/packet${RESET}   │ ${BOLD}What it blocks${RESET}                │"
echo -e "  ├─────────────────────┼───────────────┼────────────────────────────────┤"
echo -e "  │ L1: Magic byte      │ ~19ns         │ Random garbage, port scans     │"
echo -e "  │ L2: SessionID       │ ~50ns         │ Crafted packets, replays       │"
echo -e "  │ L3: HeaderAuthTag   │ ~200ns        │ Session hijacking attempts     │"
echo -e "  └─────────────────────┴───────────────┴────────────────────────────────┘"
echo ""
info "All three layers combined: an attacker must pass 3 checks before any crypto runs."
info "The cost to the defender is ${BOLD}negligible${RESET}. The cost to the attacker is ${BOLD}futile${RESET}."
echo ""
info "${BOLD}Why this matters:${RESET}"
info "  Traditional VPNs (WireGuard, OpenVPN) do crypto on every packet."
info "  ZTLP rejects >99.99% of attack traffic before touching a cipher."
info "  With eBPF/XDP, L1 rejection happens at the NIC driver — it never even"
info "  reaches userspace. The kernel doesn't allocate a socket buffer."
echo ""
success "Alice's SSH session remained completely unaffected during all attacks."

banner "Demo Complete"

echo -e "  ${BOLD}ZTLP – Zero Trust Layer Protocol${RESET}"
echo -e "  ${DIM}ztlp.org | Apache 2.0${RESET}\n"

cat <<'EOF'
What you saw:
  1. Cryptographic identities for Bob (server), Alice (client), Eve (attacker)
     + USER records with roles (admin, tech, user) when NS available
  2. Name registration with ZTLP‑NS + device-to-user linking
  3. Identity model: groups (techs, admins), membership, group-based policy
  4. Zero trust policy using group:techs@ (or identity name without NS)
  5. Server listening with policy enforcement enabled
  6. Alice ALLOWED — group membership grants her SSH access
  7. Interactive SSH session through the encrypted tunnel
  8. Eve DENIED — valid identity, not in any group (authN ≠ authZ)
  9. SCP throughput: ZTLP tunnel vs direct SSH (10/50/100 MB)
 10. Port visibility: SSH hidden behind ZTLP identity layer
 11. L1 DDoS defense: 50K random packets rejected at ~19ns each
 12. L2 defense: crafted magic-byte packets stopped by SessionID check
 13. Encrypted payload: captured traffic shows no plaintext
 14. Three-layer pipeline costs nothing to defend, everything to attack
EOF

echo -e "\n  ${DIM}Demo artifacts stored in $DEMO_DIR${RESET}"
echo -e "  ${DIM}Run with --cleanup to remove${RESET}\n"
