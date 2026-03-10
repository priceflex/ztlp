#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ZTLP Network Test Runner
# ─────────────────────────────────────────────────────────────
#
# Orchestrates all network test scenarios:
#   1. Builds Docker images
#   2. Starts the test environment
#   3. Runs scenarios (sequential or parallel)
#   4. Collects results
#   5. Generates summary report
#   6. Tears down containers
#
# Usage:
#   ./run-all.sh                    # Run all scenarios
#   ./run-all.sh --scenario basic-connectivity
#   ./run-all.sh --keep             # Don't tear down after tests
#   ./run-all.sh --verbose          # Show all container logs
#   ./run-all.sh --parallel         # Run independent scenarios in parallel
#   ./run-all.sh --no-build         # Skip Docker build step

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.test.yml"
COMPOSE="docker compose -f $COMPOSE_FILE"

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Options ──────────────────────────────────────────────────
SCENARIO=""
KEEP=false
VERBOSE=false
PARALLEL=false
NO_BUILD=false

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
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --parallel|-p)
            PARALLEL=true
            shift
            ;;
        --no-build)
            NO_BUILD=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --scenario, -s <name>  Run a single scenario"
            echo "  --keep, -k             Don't tear down after tests"
            echo "  --verbose, -v          Show all container logs"
            echo "  --parallel, -p         Run independent scenarios in parallel"
            echo "  --no-build             Skip Docker image build"
            echo "  --help, -h             Show this help"
            echo ""
            echo "Available scenarios:"
            for f in "$SCRIPT_DIR/scenarios/"*.sh; do
                echo "  $(basename "$f" .sh)"
            done
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Scenario list ────────────────────────────────────────────
ALL_SCENARIOS=(
    "basic-connectivity"
    "handshake-through-gateway"
    "ns-resolution"
    "full-stack-e2e"
    "latency-resilience"
    "packet-loss-resilience"
    "reconnection"
    "concurrent-sessions"
    "gateway-policy"
    "network-partition"
)

# Scenarios that are safe to run in parallel (no side effects on shared state)
PARALLEL_GROUP_1=("basic-connectivity" "ns-resolution" "concurrent-sessions")
PARALLEL_GROUP_2=("handshake-through-gateway" "gateway-policy")
# These must run sequentially (they modify network/restart services):
SEQUENTIAL=("full-stack-e2e" "latency-resilience" "packet-loss-resilience" "reconnection" "network-partition")

# ── Banner ───────────────────────────────────────────────────
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           ZTLP Network Test Suite                           ║"
echo "║           Docker-based Integration Tests                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  Project:    $PROJECT_DIR"
echo "  Compose:    $COMPOSE_FILE"
echo "  Results:    $RESULTS_DIR"
echo "  Timestamp:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

# ── Prepare results directory ────────────────────────────────
mkdir -p "$RESULTS_DIR"
rm -f "$RESULTS_DIR"/*.result 2>/dev/null || true

OVERALL_START=$(date +%s)

# ── Step 1: Build ────────────────────────────────────────────
if ! $NO_BUILD; then
    echo -e "${BOLD}━━━ Building Docker images ━━━${NC}"
    if $VERBOSE; then
        $COMPOSE build 2>&1
    else
        $COMPOSE build 2>&1 | tail -10
    fi
    echo -e "${GREEN}  ✓ Images built${NC}"
    echo
fi

# ── Step 2: Start environment ────────────────────────────────
echo -e "${BOLD}━━━ Starting test environment ━━━${NC}"
$COMPOSE up -d 2>&1 | tail -5
echo

# Wait for services to be healthy
echo -e "${BLUE}  Waiting for services to initialize...${NC}"
WAIT_START=$(date +%s)
MAX_WAIT=120

while true; do
    ELAPSED=$(( $(date +%s) - WAIT_START ))
    if [[ $ELAPSED -gt $MAX_WAIT ]]; then
        echo -e "${RED}  ✗ Timeout waiting for services ($MAX_WAIT seconds)${NC}"
        echo "  Container status:"
        $COMPOSE ps 2>&1 | sed 's/^/    /'
        if ! $KEEP; then
            $COMPOSE down -v --remove-orphans 2>&1 | tail -3
        fi
        exit 1
    fi

    # Check if NS is healthy (it's the gatekeeper)
    if docker inspect -f '{{.State.Health.Status}}' ztlp-test-ns 2>/dev/null | grep -q "healthy"; then
        break
    fi

    sleep 2
    echo -ne "\r${BLUE}  Waiting... (${ELAPSED}s)${NC}    "
done

echo -e "\r${GREEN}  ✓ All services ready${NC}              "
echo

if $VERBOSE; then
    echo -e "${BOLD}━━━ Container status ━━━${NC}"
    $COMPOSE ps 2>&1 | sed 's/^/  /'
    echo
fi

# ── Step 3: Run scenarios ────────────────────────────────────
run_scenario() {
    local name="$1"
    local script="$SCRIPT_DIR/scenarios/${name}.sh"

    if [[ ! -f "$script" ]]; then
        echo -e "${RED}  ✗ Scenario not found: $name${NC}"
        return 1
    fi

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}  Running: $name${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    local start end elapsed exit_code
    start=$(date +%s)

    bash "$script" || exit_code=$?
    exit_code=${exit_code:-0}

    end=$(date +%s)
    elapsed=$((end - start))

    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}  ✓ $name PASSED (${elapsed}s)${NC}"
    else
        echo -e "${RED}  ✗ $name FAILED (${elapsed}s, exit=$exit_code)${NC}"
    fi
    echo

    return $exit_code
}

SCENARIOS_PASSED=0
SCENARIOS_FAILED=0
SCENARIOS_SKIPPED=0
FAILED_SCENARIOS=()

if [[ -n "$SCENARIO" ]]; then
    # Run a single scenario
    if run_scenario "$SCENARIO"; then
        SCENARIOS_PASSED=$((SCENARIOS_PASSED + 1))
    else
        SCENARIOS_FAILED=$((SCENARIOS_FAILED + 1))
        FAILED_SCENARIOS+=("$SCENARIO")
    fi
elif $PARALLEL; then
    echo -e "${BOLD}━━━ Running parallel scenarios ━━━${NC}"
    echo

    # Group 1: parallel
    echo -e "${CYAN}  Parallel group 1: ${PARALLEL_GROUP_1[*]}${NC}"
    PIDS=()
    for s in "${PARALLEL_GROUP_1[@]}"; do
        run_scenario "$s" &
        PIDS+=($!)
    done
    for i in "${!PIDS[@]}"; do
        if wait "${PIDS[$i]}" 2>/dev/null; then
            SCENARIOS_PASSED=$((SCENARIOS_PASSED + 1))
        else
            SCENARIOS_FAILED=$((SCENARIOS_FAILED + 1))
            FAILED_SCENARIOS+=("${PARALLEL_GROUP_1[$i]}")
        fi
    done

    # Group 2: parallel
    echo -e "${CYAN}  Parallel group 2: ${PARALLEL_GROUP_2[*]}${NC}"
    PIDS=()
    for s in "${PARALLEL_GROUP_2[@]}"; do
        run_scenario "$s" &
        PIDS+=($!)
    done
    for i in "${!PIDS[@]}"; do
        if wait "${PIDS[$i]}" 2>/dev/null; then
            SCENARIOS_PASSED=$((SCENARIOS_PASSED + 1))
        else
            SCENARIOS_FAILED=$((SCENARIOS_FAILED + 1))
            FAILED_SCENARIOS+=("${PARALLEL_GROUP_2[$i]}")
        fi
    done

    # Sequential group
    echo -e "${CYAN}  Sequential scenarios: ${SEQUENTIAL[*]}${NC}"
    for s in "${SEQUENTIAL[@]}"; do
        if run_scenario "$s"; then
            SCENARIOS_PASSED=$((SCENARIOS_PASSED + 1))
        else
            SCENARIOS_FAILED=$((SCENARIOS_FAILED + 1))
            FAILED_SCENARIOS+=("$s")
        fi
    done
else
    # Sequential: run all scenarios in order
    for s in "${ALL_SCENARIOS[@]}"; do
        if run_scenario "$s"; then
            SCENARIOS_PASSED=$((SCENARIOS_PASSED + 1))
        else
            SCENARIOS_FAILED=$((SCENARIOS_FAILED + 1))
            FAILED_SCENARIOS+=("$s")
        fi
    done
fi

# ── Step 4: Collect logs (if verbose) ────────────────────────
if $VERBOSE; then
    echo -e "${BOLD}━━━ Service Logs ━━━${NC}"
    for svc in ns relay gateway; do
        echo -e "${CYAN}  --- $svc ---${NC}"
        $COMPOSE logs --tail=30 "$svc" 2>&1 | sed 's/^/  /'
        echo
    done
fi

# ── Step 5: Summary report ───────────────────────────────────
OVERALL_END=$(date +%s)
OVERALL_ELAPSED=$((OVERALL_END - OVERALL_START))
TOTAL=$((SCENARIOS_PASSED + SCENARIOS_FAILED + SCENARIOS_SKIPPED))

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   TEST SUITE SUMMARY                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo -e "║  Total scenarios:  $TOTAL${NC}"
echo -e "${GREEN}║  Passed:           $SCENARIOS_PASSED${NC}"
echo -e "${RED}║  Failed:           $SCENARIOS_FAILED${NC}"
echo -e "${YELLOW}║  Skipped:          $SCENARIOS_SKIPPED${NC}"
echo -e "${BOLD}║  Total time:       ${OVERALL_ELAPSED}s${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"

if [[ ${#FAILED_SCENARIOS[@]} -gt 0 ]]; then
    echo
    echo -e "${RED}  Failed scenarios:${NC}"
    for s in "${FAILED_SCENARIOS[@]}"; do
        echo -e "${RED}    ✗ $s${NC}"
    done
fi

# Write summary report
SUMMARY_FILE="$RESULTS_DIR/summary.txt"
cat > "$SUMMARY_FILE" <<EOF
ZTLP Network Test Suite Summary
================================
Date:     $(date -u +%Y-%m-%dT%H:%M:%SZ)
Duration: ${OVERALL_ELAPSED}s
Total:    $TOTAL
Passed:   $SCENARIOS_PASSED
Failed:   $SCENARIOS_FAILED
Skipped:  $SCENARIOS_SKIPPED

Per-scenario results:
EOF

for f in "$RESULTS_DIR"/*.result; do
    if [[ -f "$f" ]]; then
        echo "---" >> "$SUMMARY_FILE"
        cat "$f" >> "$SUMMARY_FILE"
    fi
done

echo "" >> "$SUMMARY_FILE"
if [[ ${#FAILED_SCENARIOS[@]} -gt 0 ]]; then
    echo "Failed:" >> "$SUMMARY_FILE"
    for s in "${FAILED_SCENARIOS[@]}"; do
        echo "  - $s" >> "$SUMMARY_FILE"
    done
fi

echo
echo -e "${BLUE}  Results saved to: $RESULTS_DIR/${NC}"
echo -e "${BLUE}  Summary: $SUMMARY_FILE${NC}"

# ── Step 6: Teardown ─────────────────────────────────────────
if $KEEP; then
    echo
    echo -e "${YELLOW}  --keep: Containers are still running.${NC}"
    echo -e "${YELLOW}  To stop: $COMPOSE down -v --remove-orphans${NC}"
else
    echo
    echo -e "${BLUE}  Tearing down test environment...${NC}"
    $COMPOSE down -v --remove-orphans 2>&1 | tail -3
    echo -e "${GREEN}  ✓ Cleanup complete${NC}"
fi

# Exit with failure if any scenario failed
if [[ $SCENARIOS_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
