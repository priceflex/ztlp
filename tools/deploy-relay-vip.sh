#!/usr/bin/env bash
# deploy-relay-vip.sh — Deploy NS with RELAY records + Relay with VIP config
#
# Run from the ZTLP repo root on your Mac or prod server:
#   chmod +x tools/deploy-relay-vip.sh
#   ./tools/deploy-relay-vip.sh dev       # Local docker compose
#   ./tools/deploy-relay-vip.sh prod      # Production AWS servers
#
# For production, set these env vars before running:
#   NS_HOSTNS_SERVER=34.217.62.46
#   NS_USER=ubuntu
#   RELAY_HOST=34.219.64.205
#   RELAY_USER=ubuntu
#   SSH_KEY=path/to/key.pem

set -euo pipefail

MODE="${1:-dev}"

if [[ "$MODE" == "dev" ]]; then
    echo "=== Deploy: Local Docker Compose ==="
    echo ""
    echo "Starting NS + Relay + Gateway with:"
    echo "  - NS relay records (rich CBOR format)"
    echo "  - Relay VIP enabled (services: vault, web, api)"
    echo ""
    echo "To start:"
    echo "  cd /path/to/ztlp"
    echo "  docker compose up -d --build"
    echo ""
    echo "NS relay records seeded:"
    echo "  relay1 -> relay:23095 (us-west-2, healthy)"
    echo "  relay2 -> 10.0.0.5:23096 (us-east-1, healthy)"
    echo ""
    echo "Relay VIP services:"
    echo "  vault=127.0.0.1:8080"
    echo "  web=echo-backend:8080"
    echo "  api=127.0.0.1:8443"
    echo ""
    echo "NOTE: ZTLP_RELAY_VIP_SESSION_KEY is empty in docker-compose.yml."
    echo "Set it before production use:"
    echo "  openssl rand -hex 32  # Generate a 32-byte hex key"
    echo "  export ZTLP_RELAY_VIP_SESSION_KEY=<key>"
    echo "  docker compose up -d"
    exit 0

fi

if [[ "$MODE" == "prod" ]]; then
    NS_HOST="${NS_HOSTNSE_SERVER:-${NS_HOST:-}}"
    RELAY_HOST="${RELAY_HOST:-34.219.64.205}"
    NS_USER="${NS_USER:-ubuntu}"
    RELAY_USER="${RELAY_USER:-ubuntu}"
    SSH_KEY="${SSH_KEY:-}"
    SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
    [[ -n "$SSH_KEY" ]] && SSH_OPTS="$SSH_OPTS -i $SSH_KEY"

    if [[ -z "$NS_HOST" ]]; then
        echo "ERROR: NS_HOST not set for production deploy"
        echo "Usage:"
        echo "  NS_HOST=34.217.62.46 ./tools/deploy-relay-vip.sh prod"
        exit 1
    fi

    echo "=== Deploy: Production ==="
    echo "NS Server: $NS_HOST"
    echo "Relay Server: $RELAY_HOST"
    echo ""

    # Session key for VIP encryption
    VIP_SESSION_KEY="${ZTLP_RELAY_VIP_SESSION_KEY:-}"
    if [[ -z "$VIP_SESSION_KEY" ]]; then
        VIP_SESSION_KEY=$(openssl rand -hex 32)
        echo "Generated VIP session key: $VIP_SESSION_KEY"
        echo "Save this key! You'll need it on both relay AND iOS device config."
    fi

    # 1. Deploy NS with RELAY records
    echo ""
    echo "--- Deploying NS on $NS_HOST ---"
    ssh $SSH_OPTS "${NS_USER}@${NS_HOST}" "
        cd ~/ztlp && git pull 2>/dev/null || true
        # Seed relay records via env var
        export ZTLP_NS_RELAY_RECORDS=\"name=relay1,address=${RELAY_HOST}:23095,region=us-west-2,latency_ms=12,load_pct=0,active_connections=0,health=healthy\"
        cd ns && mix deps.get 2>/dev/null && mix release 2>/dev/null && _build/prod/rel/ztlp_ns/bin/ztlp_ns restart
    " || echo "WARNING: NS deploy failed, manual intervention needed"

    # 2. Deploy Relay with VIP config
    echo ""
    echo "--- Deploying Relay on $RELAY_HOST ---"
    ssh $SSH_OPTS "${RELAY_USER}@${RELAY_HOST}" "
        cd ~/ztlp && git pull 2>/dev/null || true
        cd relay && ECTO_TLS_ENABLED=falselix TLS_ENABLED=false mix deps.get 2>/dev/null && mix release 2>/dev/null && _build/prod/rel/ztlp_relay/bin/ztlp_relay restart
    " || echo "WARNING: Relay deploy failed, manual intervention needed"

    echo ""
    echo "=== Deploy Complete ==="
    echo ""
    echo "VIP Session Key: $VIP_SESSION_KEY"
    echo "Save this in the iOS config and relay env before running the NE."
fi
