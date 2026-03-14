#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Extreme Network Stress Test — Master Runner
# ─────────────────────────────────────────────────────────────
#
# Usage:
#   ./stress/run-stress-tests.sh               # Run all 15 scenarios
#   ./stress/run-stress-tests.sh --scenario 3   # Run just scenario 3
#   ./stress/run-stress-tests.sh --keep          # Leave containers running
#   ./stress/run-stress-tests.sh --skip-build    # Skip Docker build step
#
# Results are written to stress/results/
# ─────────────────────────────────────────────────────────────
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

# Source report library for summary generation
source "$SCRIPT_DIR/lib/report.sh"

# ── Parse Arguments ──────────────────────────────────────────

SCENARIO=""
KEEP=false
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario|-s)
            SCENARIO="$2"
            shift 2
            ;;
        --keep|-k)
            KEEP=true
            shift
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --scenario N, -s N   Run only scenario N (1-15)"
            echo "  --keep, -k           Leave containers running after tests"
            echo "  --skip-build         Skip Docker image build"
            echo "  --help, -h           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Banner ───────────────────────────────────────────────────

echo -e "${BOLD}${CYAN}"
cat << 'BANNER'

    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   ███████╗████████╗██╗     ██████╗                        ║
    ║   ╚══███╔╝╚══██╔══╝██║     ██╔══██╗                       ║
    ║     ███╔╝    ██║   ██║     ██████╔╝                       ║
    ║    ███╔╝     ██║   ██║     ██╔═══╝                        ║
    ║   ███████╗   ██║   ███████╗██║                            ║
    ║   ╚══════╝   ╚═╝   ╚══════╝╚═╝                            ║
    ║                                                           ║
    ║   E X T R E M E   N E T W O R K   S T R E S S   T E S T ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝

BANNER
echo -e "${NC}"

echo -e "  ${BOLD}Date:${NC}     $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo -e "  ${BOLD}Host:${NC}     $(hostname)"
echo -e "  ${BOLD}Compose:${NC}  $COMPOSE_FILE"
echo ""

# ── Prepare Results Directory ────────────────────────────────

mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR"/scenario-*.txt 2>/dev/null || true

# ── Build & Start Environment ────────────────────────────────

cd "$REPO_DIR"

if [ "$SKIP_BUILD" = false ]; then
    echo -e "${BOLD}━━━ Building Docker images...${NC}"
    docker compose -f "$COMPOSE_FILE" build 2>&1 | tail -5
    echo -e "  ${GREEN}✓${NC} Build complete"
    echo ""
fi

echo -e "${BOLD}━━━ Starting environment...${NC}"
docker compose -f "$COMPOSE_FILE" up -d 2>&1
echo -e "  ${GREEN}✓${NC} Containers started"

# Wait for NS healthcheck
echo -e "  → Waiting for NS to be healthy..."
for i in $(seq 1 60); do
    status=$(docker inspect --format='{{.State.Health.Status}}' stress-ns 2>/dev/null || echo "unknown")
    if [ "$status" = "healthy" ]; then
        echo -e "  ${GREEN}✓${NC} NS healthy (${i}s)"
        break
    fi
    sleep 2
done

# Wait for impairment node to discover interfaces
echo -e "  → Waiting for impairment node..."
for i in $(seq 1 30); do
    if docker exec stress-impairment cat /tmp/client_iface &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Impairment node ready"
        break
    fi
    sleep 1
done

# Set up routing: client routes to server-net through impairment node
echo -e "  → Configuring routes through impairment node..."
docker exec stress-client ip route add 172.30.2.0/24 via 172.30.1.100 2>/dev/null || true
docker exec stress-server ip route add 172.30.1.0/24 via 172.30.2.100 2>/dev/null || true
echo -e "  ${GREEN}✓${NC} Routes configured"

# Wait for server to register with NS
echo -e "  → Waiting for server registration..."
for i in $(seq 1 60); do
    if docker exec stress-client bash -c 'timeout 3 ztlp ns lookup "server.stress.ztlp" --ns-server "172.30.1.10:23096" 2>&1' | grep -qiE "KEY|SVC|Ed25519"; then
        echo -e "  ${GREEN}✓${NC} Server registered in NS (${i}s)"
        break
    fi
    sleep 2
done

echo ""
echo -e "${BOLD}━━━ Environment Ready ━━━${NC}"
echo ""

# ── Run Scenarios ────────────────────────────────────────────

TOTAL_START=$(date +%s)

if [ -n "$SCENARIO" ]; then
    # Run single scenario
    PADDED=$(printf "%02d" "$SCENARIO")
    SCENARIO_SCRIPT="$SCRIPT_DIR/scenarios/${PADDED}-*.sh"
    SCENARIO_FILE=$(ls $SCENARIO_SCRIPT 2>/dev/null | head -1)

    if [ -z "$SCENARIO_FILE" ] || [ ! -f "$SCENARIO_FILE" ]; then
        echo -e "${RED}ERROR: Scenario $SCENARIO not found${NC}"
        exit 1
    fi

    echo -e "${BOLD}Running scenario $SCENARIO: $(basename "$SCENARIO_FILE")${NC}"
    echo ""
    RESULTS_DIR="$RESULTS_DIR" bash "$SCENARIO_FILE"
else
    # Run all scenarios
    echo -e "${BOLD}Running all 15 scenarios...${NC}"
    echo -e "  ${YELLOW}Estimated time: ~15–25 minutes${NC}"
    echo ""

    for scenario_file in "$SCRIPT_DIR"/scenarios/[0-9]*.sh; do
        [ -f "$scenario_file" ] || continue
        num=$(basename "$scenario_file" | cut -d- -f1)
        name=$(basename "$scenario_file" .sh | cut -d- -f2-)

        echo ""
        echo -e "${BOLD}${BLUE}┌────────────────────────────────────────────────────┐${NC}"
        echo -e "${BOLD}${BLUE}│  Scenario ${num}: ${name}${NC}"
        echo -e "${BOLD}${BLUE}└────────────────────────────────────────────────────┘${NC}"

        RESULTS_DIR="$RESULTS_DIR" bash "$scenario_file" || {
            echo -e "  ${RED}✗ Scenario ${num} failed with exit code $?${NC}"
        }
    done
fi

TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))

# ── Generate Reports ─────────────────────────────────────────

echo ""
echo -e "${BOLD}━━━ Generating Reports ━━━${NC}"

print_summary_table "$RESULTS_DIR"
generate_json "$RESULTS_DIR" "$RESULTS_DIR/results.json"

echo -e "  ${GREEN}✓${NC} Results written to: $RESULTS_DIR/results.json"
echo -e "  ${GREEN}✓${NC} Debug logs saved to: $RESULTS_DIR/logs/"
echo -e "  ${BOLD}Total time:${NC} $((TOTAL_ELAPSED / 60))m $((TOTAL_ELAPSED % 60))s"

# Log collection summary
if [ -d "$RESULTS_DIR/logs" ]; then
    LOG_COUNT=$(find "$RESULTS_DIR/logs" -name "*.log" 2>/dev/null | wc -l)
    ANALYSIS_COUNT=$(find "$RESULTS_DIR/logs" -name "analysis-summary.txt" 2>/dev/null | wc -l)
    echo -e "  ${BOLD}Logs:${NC} ${LOG_COUNT} log files, ${ANALYSIS_COUNT} analysis summaries"
    echo ""
    echo -e "  ${BOLD}Per-scenario log analysis:${NC}"
    for summary in "$RESULTS_DIR/logs"/scenario-*/analysis-summary.txt; do
        [ -f "$summary" ] || continue
        SCENARIO_DIR=$(dirname "$summary")
        SCENARIO_NAME=$(basename "$SCENARIO_DIR")
        RETRANSMITS=$(grep "Retransmissions:" "$summary" 2>/dev/null | awk '{print $NF}')
        ERRORS=$(grep "Errors:" "$summary" 2>/dev/null | awk '{print $NF}')
        REPLAYS=$(grep "Anti-replay drops:" "$summary" 2>/dev/null | awk '{print $NF}')
        echo -e "    ${SCENARIO_NAME}: retransmits=${RETRANSMITS:-0} errors=${ERRORS:-0} replay_drops=${REPLAYS:-0}"
    done
fi
echo ""

# ── Cleanup ──────────────────────────────────────────────────

if [ "$KEEP" = false ]; then
    echo -e "${BOLD}━━━ Stopping environment...${NC}"
    cd "$REPO_DIR"
    docker compose -f "$COMPOSE_FILE" down -v 2>&1
    echo -e "  ${GREEN}✓${NC} Environment stopped"
else
    echo -e "${YELLOW}  --keep specified: containers still running${NC}"
    echo -e "  Stop with: docker compose -f $COMPOSE_FILE down -v"
fi

echo ""
echo -e "${BOLD}${GREEN}Done! 🎉${NC}"
