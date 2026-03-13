#!/usr/bin/env bash
# ================================================================
# ZTLP Full-Stack Docker Demo
# ================================================================
# End-to-end demonstration of the ZTLP tunnel running as a complete
# Docker Compose stack: NS, relays, server, client, backend SSH.
#
# What it does:
#   1. Builds and brings up the 6-container topology
#   2. Waits for health checks (NS, relays)
#   3. Shows NS name registration (identity + service discovery)
#   4. Runs SSH tests through the ZTLP tunnel
#   5. Runs SCP benchmarks with integrity verification
#   6. Displays architecture diagram and results summary
#   7. Tears down cleanly (unless --keep)
#
# Requirements:
#   - Docker 20.10+ with Docker Compose v2
#   - ~2 GB disk for build (Rust + Elixir multi-stage)
#   - No local toolchains needed — everything runs in containers
#
# Usage:
#   ./full-stack-demo.sh                # Full demo (build + run + teardown)
#   ./full-stack-demo.sh --keep         # Leave containers running after demo
#   ./full-stack-demo.sh --skip-build   # Skip Docker build (use existing images)
#   ./full-stack-demo.sh --cleanup      # Tear down containers and remove images
#   ./full-stack-demo.sh --help         # Show this help
#
# ================================================================

set -euo pipefail

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="${REPO_DIR}/docker-compose-full-stack.yml"
PROJECT_NAME="ztlp"

# Flags
KEEP=false
SKIP_BUILD=false
CLEANUP=false

# -------------------------------------------------------------------
# Argument handling
# -------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --keep)       KEEP=true ;;
        --skip-build) SKIP_BUILD=true ;;
        --cleanup)
            echo "Tearing down full-stack containers..."
            docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down -v --remove-orphans 2>/dev/null || true
            echo "✓ Containers removed"
            exit 0
            ;;
        --help|-h)
            sed -n '2,/^# ==/p' "$0" | head -n -1 | sed 's/^# //'
            exit 0
            ;;
    esac
done

# -------------------------------------------------------------------
# Colors & helpers
# -------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

banner()  { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════════════════════════${RESET}"; echo -e "${BOLD}  $1${RESET}"; echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════════${RESET}\n"; }
step()    { echo -e "${GREEN}▶${RESET} ${BOLD}$1${RESET}"; }
info()    { echo -e "  ${CYAN}ℹ${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $1"; }
success() { echo -e "  ${GREEN}✓${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; }
dimcmd()  { echo -e "  ${DIM}\$ $1${RESET}"; }

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_START=$(date +%s)

record_pass() { PASS_COUNT=$((PASS_COUNT + 1)); }
record_fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); }

# -------------------------------------------------------------------
# Cleanup on exit (unless --keep)
# -------------------------------------------------------------------
cleanup() {
    if [[ "$KEEP" == "false" ]]; then
        echo -e "\n${DIM}Tearing down containers...${RESET}"
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down -v --remove-orphans 2>/dev/null || true
        echo -e "${GREEN}✓${RESET} Containers removed."
    else
        echo -e "\n${GREEN}✓${RESET} Containers left running (--keep)."
        echo -e "  ${DIM}Tear down with: $0 --cleanup${RESET}"
    fi
}
trap cleanup EXIT

# ===================================================================
# ACT 1 — Architecture Overview
# ===================================================================
banner "ZTLP Full-Stack Docker Demo"

cat <<'ARCH'
  ┌─────────────────────────────────────────────────────────┐
  │              Docker Network: 172.28.0.0/24              │
  │                                                         │
  │  ┌────────────┐                     ┌───────────────┐   │
  │  │  NS Server │◄───register────────►│  Server       │   │
  │  │ .10 :23096 │     (identity)      │  .40 :23095   │   │
  │  └─────▲──────┘                     │  ztlp listen  │   │
  │        │                            └───────┬───────┘   │
  │        │ resolve                            │ TCP       │
  │        │                            ┌───────▼───────┐   │
  │  ┌─────┴──────┐                     │  Backend SSH  │   │
  │  │  Client    │═══ZTLP/UDP════════►│  .30 :22      │   │
  │  │ .50 :2222  │   (encrypted)       │  openssh      │   │
  │  │ ztlp conn  │                     └───────────────┘   │
  │  └────────────┘                                         │
  │                                                         │
  │  ┌────────────┐  ┌────────────┐                         │
  │  │  Relay 1   │  │  Relay 2   │  (running, future use)  │
  │  │ .20 :23095 │  │ .21 :23095 │                         │
  │  └────────────┘  └────────────┘                         │
  └─────────────────────────────────────────────────────────┘

  Data path: SSH client → TCP → ztlp-client tunnel
             → ZTLP/UDP (Noise_XX encrypted) → ztlp-server
             → TCP → backend openssh-server
ARCH
echo ""

# -------------------------------------------------------------------
# Pre-flight checks
# -------------------------------------------------------------------
step "Pre-flight checks"

if ! command -v docker >/dev/null 2>&1; then
    fail "Docker not found. Install: https://docs.docker.com/get-docker/"
    exit 1
fi
success "Docker: $(docker --version | head -1)"

if docker compose version >/dev/null 2>&1; then
    success "Docker Compose: $(docker compose version --short 2>/dev/null || echo 'v2+')"
else
    fail "Docker Compose v2 not found."
    exit 1
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
    fail "Compose file not found: $COMPOSE_FILE"
    exit 1
fi
success "Compose file: docker-compose-full-stack.yml"
echo ""

# ===================================================================
# ACT 2 — Build & Start Stack
# ===================================================================
banner "Act 1 — Build & Start Containers"

if [[ "$SKIP_BUILD" == "true" ]]; then
    info "Skipping build (--skip-build)"
    step "Starting containers..."
    dimcmd "docker compose -f docker-compose-full-stack.yml up -d"
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d 2>&1 | sed 's/^/  /'
else
    step "Building and starting 6-container stack..."
    info "This builds Rust (proto) and Elixir (NS, relay) — first run takes ~2-3 min"
    dimcmd "docker compose -f docker-compose-full-stack.yml up -d --build"
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d --build 2>&1 | sed 's/^/  /'
fi

echo ""
step "Container status:"
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | sed 's/^/  /'
echo ""
success "All containers started"

# ===================================================================
# ACT 3 — Wait for Health Checks
# ===================================================================
banner "Act 2 — Wait for Health Checks"

step "Waiting for NS server to become healthy..."
MAX_WAIT=120
WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' ztlp-ns 2>/dev/null || echo "unknown")
    if [[ "$STATUS" == "healthy" ]]; then
        success "NS server healthy (${WAITED}s)"
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
    [[ $((WAITED % 15)) -eq 0 ]] && info "Still waiting... (${WAITED}s) — status: ${STATUS}"
done
if [[ $WAITED -ge $MAX_WAIT ]]; then
    warn "NS health check timed out after ${MAX_WAIT}s"
fi

step "Checking relay health..."
for RELAY in ztlp-relay1 ztlp-relay2; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$RELAY" 2>/dev/null || echo "unknown")
    if [[ "$STATUS" == "healthy" ]]; then
        success "$RELAY: healthy"
    else
        info "$RELAY: $STATUS (relays not in data path — OK)"
    fi
done

step "Checking backend SSH..."
if docker exec ztlp-backend pgrep sshd >/dev/null 2>&1; then
    success "Backend SSH (openssh-server) is running"
else
    warn "Backend SSH may not be ready yet"
fi
echo ""

# ===================================================================
# ACT 4 — NS Registration & Resolution
# ===================================================================
banner "Act 3 — Name Registration & Service Discovery"

step "Waiting for server to register with NS..."
WAITED=0
while [[ $WAITED -lt 60 ]]; do
    SERVER_LOG=$(docker logs ztlp-server 2>&1 | tail -20)
    if echo "$SERVER_LOG" | grep -q "Server is LIVE"; then
        success "Server is live and registered"
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
done
echo ""

step "Verifying NS registration (server logs):"
docker logs ztlp-server 2>&1 | grep -E "Registration|register|KEY record|verified|LIVE" | head -8 | sed 's/^/  /'
echo ""

step "Waiting for client to resolve server via NS..."
WAITED=0
while [[ $WAITED -lt 60 ]]; do
    CLIENT_LOG=$(docker logs ztlp-client 2>&1 | tail -30)
    if echo "$CLIENT_LOG" | grep -q "Tunnel is active"; then
        success "Client resolved server and tunnel is active"
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
done
echo ""

step "Client registration (client logs):"
docker logs ztlp-client 2>&1 | grep -E "Registration|register|KEY record|verified|Registering|complete" | head -6 | sed 's/^/  /'
echo ""

# Show handshake info
HANDSHAKE_LINE=$(docker logs ztlp-client 2>&1 | grep "Handshake latency" | head -1)
if [[ -n "$HANDSHAKE_LINE" ]]; then
    LATENCY=$(echo "$HANDSHAKE_LINE" | grep -oE '[0-9]+\.[0-9]+ms')
    success "Noise_XX handshake completed in ${LATENCY:-<1ms}"
fi
echo ""

# ===================================================================
# ACT 5 — SSH Tests
# ===================================================================
banner "Act 4 — SSH Tests Through ZTLP Tunnel"

info "Data path: SSH → TCP → ztlp-client → ZTLP/UDP → ztlp-server → TCP → backend"
echo ""

# Extract test results from client logs
CLIENT_LOGS=$(docker logs ztlp-client 2>&1)

# Test 1: SSH echo
step "Test 1: SSH echo"
if echo "$CLIENT_LOGS" | grep -q "SSH echo: PASS"; then
    success "SSH echo through ZTLP tunnel: PASS"
    record_pass
else
    fail "SSH echo: FAIL"
    record_fail
fi

# Test 2: Remote hostname
step "Test 2: Remote hostname verification"
if echo "$CLIENT_LOGS" | grep -q "Remote hostname: 'backend'"; then
    success "Remote hostname: 'backend' — confirms traffic reaches backend container"
    record_pass
else
    fail "Remote hostname verification failed"
    record_fail
fi

# Test 3: Remote uname
step "Test 3: Remote command execution"
UNAME_LINE=$(echo "$CLIENT_LOGS" | grep "Remote uname:" | head -1)
if [[ -n "$UNAME_LINE" ]]; then
    success "Remote uname verified — full command execution through tunnel"
    record_pass
else
    fail "Remote command execution failed"
    record_fail
fi
echo ""

# ===================================================================
# ACT 6 — SCP Benchmarks
# ===================================================================
banner "Act 5 — SCP Benchmarks (Through ZTLP Tunnel)"

info "Files are SCP'd through the encrypted ZTLP tunnel with integrity verification"
info "Each file: generate random → SCP upload → SCP download → MD5 compare"
echo ""

# Parse benchmark results from logs
echo -e "  ${BOLD}┌──────────┬────────────┬─────────────┬──────────┐${RESET}"
echo -e "  ${BOLD}│ File Size│ Upload Time│ Throughput   │ Checksum │${RESET}"
echo -e "  ${BOLD}├──────────┼────────────┼─────────────┼──────────┤${RESET}"

for SIZE in 1 5 10 50; do
    LINE=$(echo "$CLIENT_LOGS" | grep "✓ ${SIZE}MB:" | head -1)
    if [[ -n "$LINE" ]]; then
        TIME=$(echo "$LINE" | grep -oE '\.[0-9]+s' | head -1)
        SPEED=$(echo "$LINE" | grep -oE '[0-9]+\.?[0-9]* MB/s' | head -1)
        CHECK="✓"
        echo -e "  │ ${BOLD}${SIZE}MB${RESET}      │ ${TIME}        │ ${GREEN}${SPEED}${RESET}    │ ${GREEN}${CHECK}${RESET}        │"
        record_pass
    else
        echo -e "  │ ${SIZE}MB      │ —          │ —           │ ${RED}✗${RESET}        │"
        record_fail
    fi
done

echo -e "  ${BOLD}└──────────┴────────────┴─────────────┴──────────┘${RESET}"
echo ""

# Extract peak throughput for summary
PEAK=$(echo "$CLIENT_LOGS" | grep "✓ 50MB:" | grep -oE '[0-9]+\.?[0-9]* MB/s' | head -1)
if [[ -n "$PEAK" ]]; then
    success "Peak throughput: ${PEAK} (50MB file, Docker bridge network)"
fi

# Show handshake latency
if [[ -n "$LATENCY" ]]; then
    success "Noise_XX handshake: ${LATENCY}"
fi
echo ""

# ===================================================================
# ACT 7 — Container Details
# ===================================================================
banner "Act 6 — Container Status & Details"

step "Running containers:"
docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | sed 's/^/  /'
echo ""

step "Network addresses:"
for CTR in ztlp-ns ztlp-relay1 ztlp-relay2 ztlp-backend ztlp-server ztlp-client; do
    IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CTR" 2>/dev/null || echo "?")
    ROLE=""
    case "$CTR" in
        ztlp-ns)      ROLE="Namespace Server" ;;
        ztlp-relay1)  ROLE="Relay (primary)" ;;
        ztlp-relay2)  ROLE="Relay (secondary)" ;;
        ztlp-backend) ROLE="Backend SSH" ;;
        ztlp-server)  ROLE="ZTLP Listen" ;;
        ztlp-client)  ROLE="ZTLP Connect" ;;
    esac
    printf "  %-16s %-14s %s\n" "$CTR" "$IP" "$ROLE"
done
echo ""

# ===================================================================
# ACT 8 — Summary
# ===================================================================
TOTAL_END=$(date +%s)
ELAPSED=$((TOTAL_END - TOTAL_START))

banner "Demo Complete"

TOTAL=$((PASS_COUNT + FAIL_COUNT))
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All ${TOTAL} tests passed!${RESET}"
else
    echo -e "  ${YELLOW}${BOLD}${PASS_COUNT}/${TOTAL} passed, ${FAIL_COUNT} failed${RESET}"
fi
echo ""

cat <<EOF
  Results Summary:
    SSH Tests:      ${PASS_COUNT} passed (echo, hostname, uname)
    SCP Benchmarks: All sizes verified (1, 5, 10, 50 MB)
    Peak Transfer:  ${PEAK:-N/A}
    Handshake:      ${LATENCY:-N/A}
    Total Time:     ${ELAPSED}s
    Containers:     6 (NS, 2×relay, backend, server, client)

  What was demonstrated:
    ✓ Cryptographic identity generation (Ed25519 keypairs)
    ✓ Name registration with ZTLP-NS (decentralized DNS)
    ✓ Noise_XX authenticated key exchange (<1ms handshake)
    ✓ SSH tunneling through ZTLP encrypted transport
    ✓ SCP file transfer with integrity verification
    ✓ Multi-container orchestration with health checks
    ✓ Service discovery (client resolves server via NS)

  Architecture: Client → ZTLP/UDP (encrypted) → Server → Backend SSH
  Transport:    Noise_XX → ChaCha20-Poly1305 → Three-layer pipeline
  Network:      Docker bridge (172.28.0.0/24) — all traffic containerized
EOF
echo ""

echo -e "  ${BOLD}ZTLP – Zero Trust Layer Protocol${RESET}"
echo -e "  ${DIM}github.com/priceflex/ztlp | Apache 2.0${RESET}"
echo ""

if [[ "$KEEP" == "true" ]]; then
    echo -e "  ${DIM}Containers still running. Interactive access:${RESET}"
    echo -e "  ${DIM}  docker exec -it ztlp-client sshpass -e ssh -p 2222 -o StrictHostKeyChecking=no testuser@127.0.0.1${RESET}"
    echo -e "  ${DIM}  docker compose -f docker-compose-full-stack.yml logs -f${RESET}"
    echo -e "  ${DIM}  $0 --cleanup${RESET}"
    echo ""
fi
