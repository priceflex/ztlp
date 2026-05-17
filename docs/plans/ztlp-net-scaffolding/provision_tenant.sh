#!/bin/bash
set -e

# ztlp.net SaaS Orchestrator — Tenant Provisioning Script
# This script spins up a pristine ZTLP-secured Docker stack for a new endpoint.

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <tenant_domain> <admin_name> <admin_email>"
    echo "Example: $0 acmecorp.ztlp 'Alice Smith' alice@acmecorp.com"
    exit 1
fi

TENANT_DOMAIN=$1
ADMIN_NAME=$2
ADMIN_EMAIL=$3

# Simple logic to convert a domain (e.g. acmecorp.ztlp) into a safe directory slug
TENANT_SLUG=$(echo "$TENANT_DOMAIN" | tr '.' '-')
TENANT_DIR="/home/trs/ztlp/tenants/$TENANT_SLUG"

echo "================================================="
echo " Provisioning ZTLP.net Tenant: $TENANT_DOMAIN"
echo " Administrator: $ADMIN_NAME ($ADMIN_EMAIL)"
echo " Directory: $TENANT_DIR"
echo "================================================="

mkdir -p "$TENANT_DIR"
cd "$TENANT_DIR"

# 1. Allocate Ports
# In a real environment, we would use a persistent state manager (like etcd/Redis) to find free ports.
# For scaffolding, we bind specific available base ports.
BASE_PORT=$(( 20000 + (RANDOM % 10000) ))
NS_PORT=$BASE_PORT
RELAY_PORT=$((BASE_PORT + 1))
GATEWAY_PORT=$((BASE_PORT + 2))
BOOTSTRAP_WEB_PORT=$((BASE_PORT + 3))

echo "[*] Assigned Ports:"
echo "    - NS:      $NS_PORT"
echo "    - Relay:   $RELAY_PORT"
echo "    - Gateway: $GATEWAY_PORT"
echo "    - UI (int):$BOOTSTRAP_WEB_PORT"

# 2. Generate Tenant Master Keys (`ztlp keygen`)
echo "[*] Generating tenant master keys..."
# Note: Ensure the ztlp Rust binary is compiled and available on PATH
# ztlp keygen --output "$TENANT_DIR/root_key.json" --format json
# We mock this for the scaffolding script's execution:
ROOT_PRIV="priv_$(openssl rand -hex 16)"
ROOT_PUB="pub_$(openssl rand -hex 16)"
echo "{\"private_key\": \"$ROOT_PRIV\", \"public_key\": \"$ROOT_PUB\"}" > "$TENANT_DIR/root_key.json"

# 3. Write Tenant Docker Compose 
echo "[*] Bootstrapping Docker Compose File..."

cat <<COMPOSE_EOF > "$TENANT_DIR/docker-compose.yml"
version: '3.8'

services:
  ns:
    image: ztlp-ns:latest
    container_name: ztlp-ns-$TENANT_SLUG
    ports:
      - "$NS_PORT:23096/udp"
    environment:
      ZTLP_NS_PORT: "23096"
      ZTLP_NS_STORAGE_MODE: "disc_copies"
      ZTLP_ROOT_KEY_PUB: "$ROOT_PUB"
    volumes:
      - ./ns_data:/var/lib/ztlp

  relay:
    image: ztlp-relay:latest
    container_name: ztlp-relay-$TENANT_SLUG
    ports:
      - "$RELAY_PORT:23095/udp"
    environment:
      ZTLP_RELAY_NS_SERVER: "ns:23096"
    depends_on:
      - ns

  gateway:
    image: ztlp-gateway:latest
    container_name: ztlp-gateway-$TENANT_SLUG
    ports:
      - "$GATEWAY_PORT:23097/udp"
    environment:
      ZTLP_GATEWAY_NS_HOST: "ns"
      ZTLP_GATEWAY_NS_PORT: "23096"
      ZTLP_HEADER_HMAC_SECRET: "\${HMAC_SECRET}"
      ZTLP_GATEWAY_BACKENDS: "auth:bootstrap:3000"
      ZTLP_GATEWAY_POLICIES: "*:auth" # Defaulting for the onboarding period
      ZTLP_TRUST_ANCHOR: "$ROOT_PUB"
    depends_on:
      - ns
      - bootstrap

  bootstrap:
    image: priceflex/ztlp-bootstrap:latest
    container_name: ztlp-bootstrap-$TENANT_SLUG
    environment:
      - RAILS_ENV=production
      - DATABASE_PATH=/data/production.sqlite3
      - ZTLP_ORCHESTRATOR_ONBOARDING=true # Bypasses standard omniauth for X-ZTLP headers
    volumes:
      - ./bootstrap_data:/data
COMPOSE_EOF

echo "[*] Stack definition saved."

# 4. Generate the one-time Super Admin Onboarding URI
# This replicates logic from the TokenGenerator but is handled orchestrator-side.
# The `expires` field is hardcoded to 1 hour from now.
TOKEN_ID=$(openssl rand -hex 4)
EXPIRES=$(date -d "+1 hour" +%s)
URI="ztlp://enroll/?zone=$TENANT_DOMAIN&ns=$(curl -s ifconfig.me):$NS_PORT&relay=$(curl -s ifconfig.me):$RELAY_PORT&token=$TOKEN_ID&expires=$EXPIRES"

echo "================================================="
echo " SUCCESS! TENANT IS READY."
echo ""
echo " Run the following to start the network:"
echo "   docker-compose -f $TENANT_DIR/docker-compose.yml up -d"
echo ""
echo " Deliver this URI to exactly ONE device for the super-admin:"
echo " -> $URI"
echo "================================================="
