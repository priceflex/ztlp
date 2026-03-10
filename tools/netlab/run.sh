#!/usr/bin/env bash
# ztlp-netlab — ZTLP Network Test Lab Orchestrator
#
# Usage:
#   ./run.sh                    # Run all scenarios
#   ./run.sh normal             # Run a specific scenario
#   ./run.sh --build            # Rebuild containers first
#   ./run.sh --teardown         # Stop and remove containers
#   ./run.sh --list             # List available scenarios
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$SCRIPT_DIR/scenarios"
RESULTS_DIR="$SCRIPT_DIR/results"
COMPOSE="docker compose -f $SCRIPT_DIR/docker-compose.yml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${CYAN}[netlab]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
fail() { echo -e "${RED}[ FAIL ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }

usage() {
    echo "Usage: $0 [OPTIONS] [SCENARIO...]"
    echo ""
    echo "ZTLP Network Test Lab — simulate real network conditions"
    echo ""
    echo "Options:"
    echo "  --build       Rebuild all containers before running"
    echo "  --teardown    Stop and remove all containers"
    echo "  --list        List available scenarios"
    echo "  --help        Show this help"
    echo ""
    echo "Scenarios:"
    for f in "$SCENARIO_DIR"/*.sh; do
        name="$(basename "$f" .sh)"
        desc="$(head -3 "$f" | grep '^# ' | tail -1 | sed 's/^# //')"
        printf "  %-16s %s\n" "$name" "$desc"
    done
    echo ""
    echo "If no scenario is specified, all scenarios run sequentially."
}

list_scenarios() {
    echo -e "${BOLD}Available scenarios:${NC}"
    echo ""
    for f in "$SCENARIO_DIR"/*.sh; do
        name="$(basename "$f" .sh)"
        desc="$(head -3 "$f" | grep '^# ' | tail -1 | sed 's/^# //')"
        printf "  ${CYAN}%-16s${NC} %s\n" "$name" "$desc"
    done
}

start_topology() {
    log "Starting ZTLP network topology..."
    $COMPOSE up -d 2>&1 | sed 's/^/  /'
    log "Waiting for services to be ready..."
    sleep 5
    ok "Topology started"
}

stop_topology() {
    log "Stopping ZTLP network topology..."
    $COMPOSE down -v 2>&1 | sed 's/^/  /'
    ok "Topology stopped"
}

run_scenario() {
    local scenario="$1"
    local script="$SCENARIO_DIR/${scenario}.sh"

    if [[ ! -f "$script" ]]; then
        fail "Scenario not found: $scenario"
        return 1
    fi

    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Scenario: ${CYAN}${scenario}${NC}"
    echo -e "${BOLD}════════════════════════════════════════════════════${NC}"

    mkdir -p "$RESULTS_DIR"
    local result_file="$RESULTS_DIR/${scenario}_$(date +%Y%m%d_%H%M%S).json"

    # Source the scenario (it should define run_test function)
    if bash "$script" 2>&1 | tee "$result_file.log"; then
        ok "Scenario '$scenario' completed"
    else
        fail "Scenario '$scenario' failed"
    fi
}

reset_network() {
    # Clear any tc rules on the chaos container
    $COMPOSE exec -T chaos sh -c '
        for iface in $(ip -o link show | awk -F: "{print \$2}" | tr -d " "); do
            tc qdisc del dev "$iface" root 2>/dev/null || true
        done
    ' 2>/dev/null || true
}

apply_impairment() {
    local iface="${1:-eth0}"
    local rule="$2"
    log "Applying network impairment: $rule"
    $COMPOSE exec -T chaos sh -c "
        apk add --no-cache iproute2 2>/dev/null || true
        tc qdisc del dev $iface root 2>/dev/null || true
        tc qdisc add dev $iface root netem $rule
    " 2>&1 | sed 's/^/  /'
}

run_basic_test() {
    # Run basic operations: attempt to send HELLO + data packets + query NS
    local label="${1:-baseline}"
    local start_time
    start_time=$(date +%s%N)

    log "Running basic test: $label"

    # Send packets from client-a through the relay
    $COMPOSE exec -T client-a sh -c '
        # Send 100 data packets via the load tool
        if command -v ztlp-load >/dev/null 2>&1; then
            ztlp-load pipeline --packets 100 --sessions 10 2>&1
        else
            echo "ztlp-load not available in container, using basic UDP test"
            echo "5a37100b00000000000000000000000000000000000000000000000000000000000000000000000000000000" | \
                xxd -r -p | nc -u -w1 172.28.0.10 4433 2>/dev/null || true
            echo "Basic UDP send completed"
        fi
    ' 2>&1 | sed 's/^/  /'

    local end_time
    end_time=$(date +%s%N)
    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    log "Test '$label' completed in ${duration_ms}ms"
}

# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────

BUILD=false
TEARDOWN=false
SCENARIOS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)    BUILD=true; shift ;;
        --teardown) stop_topology; exit 0 ;;
        --list)     list_scenarios; exit 0 ;;
        --help|-h)  usage; exit 0 ;;
        *)          SCENARIOS+=("$1"); shift ;;
    esac
done

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║        ZTLP Network Test Lab (netlab)           ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# Build if requested
if $BUILD; then
    log "Building containers..."
    $COMPOSE build 2>&1 | sed 's/^/  /'
fi

# Start topology
start_topology

# Export functions for scenario scripts
export -f log ok fail warn run_basic_test apply_impairment reset_network
export COMPOSE RESULTS_DIR

# Run scenarios
if [[ ${#SCENARIOS[@]} -eq 0 ]]; then
    # Run all scenarios
    for f in "$SCENARIO_DIR"/*.sh; do
        name="$(basename "$f" .sh)"
        reset_network
        run_scenario "$name"
    done
else
    for scenario in "${SCENARIOS[@]}"; do
        reset_network
        run_scenario "$scenario"
    done
fi

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
log "All scenarios complete. Results in $RESULTS_DIR/"
echo -e "${BOLD}════════════════════════════════════════════════════${NC}"

# Cleanup
log "Stopping topology..."
stop_topology
