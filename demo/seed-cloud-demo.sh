#!/usr/bin/env bash
# ==============================================================================
# ZTLP DEF CON demo — one-shot seed/bringup script for the CLOUD stack
# (ztlp-defcon-demo-vm on AWS Lightsail, 44.240.16.59)
# ==============================================================================
# Run this ON THE CLOUD BOX after `docker compose up -d --build` to seed NS
# with the dashboard SVC record. Idempotent — safe to re-run after any NS
# restart (NS is RAM-only; every restart wipes all records).
#
# Usage:
#   ssh -i ~/.ssh/ztlp-defcon-demo.pem ubuntu@44.240.16.59
#   cd ~/ztlp/demo && ./seed-cloud-demo.sh
#
# What it does:
#   1. Brings the compose stack up (build + start, idempotent)
#   2. Waits for NS to report healthy
#   3. Generates a server identity (once) and registers the dashboard SVC record
#   4. Verifies end-to-end: NS lookup + direct dashboard HTTP health check
# ==============================================================================
set -euo pipefail

COMPOSE_FILE="defcon-cloud-compose.yml"
ZTLP_BIN="${HOME}/ztlp-bin"
ZONE="defcon.ztlp"
NS_ADDR="127.0.0.1:23096"
GATEWAY_ADDR="127.0.0.1:23097"
DASHBOARD_NAME="demo-dashboard.${ZONE}"
CA_DIR="/var/lib/ztlp/ca"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
step()    { echo -e "${GREEN}▶${RESET} ${BOLD}$1${RESET}"; }
info()    { echo -e "  ${CYAN}ℹ${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; }
success() { echo -e "  ${GREEN}✓${RESET} $1"; }

if [[ ! -f "$COMPOSE_FILE" ]]; then
    fail "Run this from the demo/ directory (compose file not found: $COMPOSE_FILE)"
    exit 1
fi

# ------------------------------------------------------------------
step "Pre-flight: CA dir + binary"
# ------------------------------------------------------------------
sudo mkdir -p "$CA_DIR"
sudo chmod 777 "$CA_DIR"
success "CA dir ready: $CA_DIR (world-writable — demo only, NS auto-init needs write access)"

if [[ ! -x "$ZTLP_BIN" ]]; then
    fail "$ZTLP_BIN not found. Copy the prebuilt binary here first:"
    echo "    scp -i ~/.ssh/ztlp-defcon-demo.pem <hermes-vm>:/home/trs/ztlp/proto/target/release/ztlp ubuntu@<this-box>:~/ztlp-bin"
    exit 1
fi
success "ztlp binary: $($ZTLP_BIN --version)"

# ------------------------------------------------------------------
step "Bringing up the stack (build + start, idempotent)"
# ------------------------------------------------------------------
sudo docker compose -f "$COMPOSE_FILE" up -d --build
echo ""

# ------------------------------------------------------------------
step "Waiting for NS to become healthy"
# ------------------------------------------------------------------
WAITED=0
MAX_WAIT=90
while [[ $WAITED -lt $MAX_WAIT ]]; do
    STATUS=$(sudo docker inspect --format='{{.State.Health.Status}}' ztlp-ns-defcon 2>/dev/null || echo "unknown")
    if [[ "$STATUS" == "healthy" ]]; then
        success "NS healthy (${WAITED}s)"
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
done
if [[ $WAITED -ge $MAX_WAIT ]]; then
    fail "NS did not become healthy within ${MAX_WAIT}s — check: sudo docker compose -f $COMPOSE_FILE logs ns"
    exit 1
fi

# ------------------------------------------------------------------
step "Verifying CA auto-init (the #1 source of wasted time — see skill notes)"
# ------------------------------------------------------------------
# NS can report container-healthy BEFORE CA auto-init finishes (health
# check hits an HTTP/RPC endpoint that's up well before the CA generation
# step completes a few seconds later) — poll instead of checking once.
CA_WAITED=0
CA_OK=false
while [[ $CA_WAITED -lt 30 ]]; do
    if sudo docker compose -f "$COMPOSE_FILE" logs ns 2>&1 | grep -qE "CA auto-initialized|CA loaded from filesystem"; then
        CA_OK=true
        break
    fi
    sleep 2
    CA_WAITED=$((CA_WAITED + 2))
done
if [[ "$CA_OK" == "true" ]]; then
    success "CA ready (${CA_WAITED}s) — $(sudo docker compose -f "$COMPOSE_FILE" logs ns 2>&1 | grep -oE 'CA auto-initialized[^"]*|CA loaded from filesystem[^"]*' | tail -1)"
else
    fail "CA did NOT auto-init within 30s. Common cause: missing ZTLP_CA_PASSPHRASE env var on the ns service."
    sudo docker compose -f "$COMPOSE_FILE" logs ns 2>&1 | grep -iE "CertAuthority|passphrase" | tail -5
    exit 1
fi

if sudo docker compose -f "$COMPOSE_FILE" logs gateway 2>&1 | grep -q "All certs provisioned"; then
    success "Gateway: all certs provisioned"
else
    warn "Gateway hasn't confirmed cert provisioning yet — may still be retrying (30s backoff). Check:"
    echo "    sudo docker compose -f $COMPOSE_FILE logs gateway | grep -i cert"
fi
echo ""

# ------------------------------------------------------------------
step "Identity: generate once, persist across re-seeds"
# ------------------------------------------------------------------
mkdir -p "$HOME/.ztlp"
if [[ ! -f "$HOME/.ztlp/identity.json" ]]; then
    "$ZTLP_BIN" keygen --output "$HOME/.ztlp/identity.json"
    success "Generated new server identity"
else
    info "Reusing existing identity: $HOME/.ztlp/identity.json"
fi
echo ""

# ------------------------------------------------------------------
step "Seeding NS: dashboard SVC record (RAM-only — redo after every NS restart)"
# ------------------------------------------------------------------
"$ZTLP_BIN" ns register --name "$DASHBOARD_NAME" --zone "$ZONE" \
    --key "$HOME/.ztlp/identity.json" --ns-server "$NS_ADDR" --address "$GATEWAY_ADDR"
echo ""

# ------------------------------------------------------------------
step "Verify: NS lookup + direct dashboard health"
# ------------------------------------------------------------------
"$ZTLP_BIN" ns lookup "$DASHBOARD_NAME" --ns-server "$NS_ADDR" 2>&1 | grep -E "Record found|Name:|Signature:" || {
    fail "NS lookup failed — record not found after registration"
    exit 1
}

HEALTH=$(curl -s -m 5 http://localhost:8420/api/health || echo "FAILED")
if [[ "$HEALTH" == *"ok"* ]]; then
    success "Dashboard direct health check: $HEALTH"
else
    fail "Dashboard health check failed: $HEALTH"
    exit 1
fi
echo ""

# ------------------------------------------------------------------
success "Stack is up and seeded."
# ------------------------------------------------------------------
PUBLIC_IP=$(curl -s -m 5 https://checkip.amazonaws.com 2>/dev/null || echo "<this-box-public-ip>")
cat <<EOF

  From a CLIENT machine (laptop), point the ztlp agent at this box:
    ztlp admin enroll --zone ${ZONE} --ns-server ${PUBLIC_IP}:23096 \\
      --relay ${PUBLIC_IP}:23095 --gateway ${PUBLIC_IP}:23097 --expires 24h
    ztlp setup --token '<token-from-above>' --yes
    ztlp agent start --foreground -vvv

  Verify from the client (after DNS is routed to the agent — see
  ztlp-defcon-demo-recovery / ztlp-fullstack-stack-bringup skills for the
  systemd-resolved DNS setup dance, including the 127.0.0.53-port-collision
  and '#' vs ':' separator pitfalls found live 2026-09-11/12):
    curl -sk https://${DASHBOARD_NAME}/

  Direct (no tunnel, sanity only — will show all ZTLP headers as empty):
    curl -s http://${PUBLIC_IP}:8420/

  Re-run this script any time after 'docker compose down' + 'up' to re-seed
  NS (records are RAM-only and wiped on every NS restart).
EOF
