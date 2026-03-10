# ZTLP Network Test Suite

Docker-based integration tests for the ZTLP protocol stack. Tests real network communication between all ZTLP components: NS, Relay, Gateway, and Rust clients.

## Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │              ztlp-infra (172.28.3.0/24)             │
                    │                                                      │
                    │  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
                    │  │    NS    │  │  Relay   │  │ Gateway  │          │
                    │  │  :23096  │  │  :23095  │  │  :23097  │          │
                    │  │  (UDP)   │  │  (UDP)   │  │  (UDP)   │          │
                    │  └──────────┘  └──────────┘  └────┬─────┘          │
                    │       │              │             │                 │
┌───────────────────┼───────┼──────────────┼─────────────┼─────────────────┼──┐
│                   │       │              │             │                 │  │
│  ztlp-frontend    │  ┌────┴────┐    ┌────┴────┐       │                 │  │
│  (172.28.1.0/24)  │  │Client A │    │Client B │       │                 │  │
│                   │  │ (Rust)  │    │ (Rust)  │       │                 │  │
│                   │  └─────────┘    └─────────┘       │                 │  │
│                   │                                    │                 │  │
└───────────────────┼────────────────────────────────────┼─────────────────┼──┘
                    │                                    │                 │
                    │           ┌─────────────────────────┼──┐             │
                    │           │  ztlp-backend            │ │             │
                    │           │  (172.28.2.0/24)         │ │             │
                    │           │                          │ │             │
                    │           │  ┌──────────────────┐   │ │             │
                    │           │  │   Echo Server    │   │ │             │
                    │           │  │   :8080 (TCP)    │   │ │             │
                    │           │  └──────────────────┘   │ │             │
                    │           └──────────────────────────┘ │             │
                    │                                        │             │
                    │  ┌─────────────────────────────────────┘             │
                    │  │  Chaos Container (NET_ADMIN)                      │
                    │  │  Connected to ALL networks                        │
                    │  │  Uses tc/iptables for impairment                  │
                    │  └──────────────────────────────────────────────────┘│
                    └──────────────────────────────────────────────────────┘
```

### Networks

| Network | Subnet | Services |
|---|---|---|
| `ztlp-frontend` | 172.28.1.0/24 | Clients, Relay, Gateway, Chaos |
| `ztlp-backend` | 172.28.2.0/24 | Gateway, Echo Server, Chaos |
| `ztlp-infra` | 172.28.3.0/24 | NS, Relay, Gateway, Clients, Chaos |

This separation ensures:
- Clients can reach Relay/Gateway but NOT the Echo Server directly
- Gateway bridges frontend↔backend (it's the only service on both)
- Infrastructure communication happens on a dedicated network

## Prerequisites

- Docker 20.10+ with Compose v2
- ~2GB disk for images
- ~512MB RAM for all containers
- Linux host recommended (UDP port mapping is most reliable)

## Quick Start

```bash
# Run all tests
cd ztlp
./tests/network/run-all.sh

# Run a single scenario
./tests/network/run-all.sh --scenario basic-connectivity

# Run with verbose logging
./tests/network/run-all.sh --verbose

# Keep containers running after tests (for debugging)
./tests/network/run-all.sh --keep

# Run independent scenarios in parallel
./tests/network/run-all.sh --parallel

# Skip rebuilding Docker images
./tests/network/run-all.sh --no-build
```

### Manual Docker Compose

```bash
# Start the test environment
docker compose -f tests/network/docker-compose.test.yml up -d --build

# Run a scenario manually
bash tests/network/scenarios/basic-connectivity.sh

# Check container status
docker compose -f tests/network/docker-compose.test.yml ps

# View logs
docker compose -f tests/network/docker-compose.test.yml logs -f relay

# Tear down
docker compose -f tests/network/docker-compose.test.yml down -v
```

## Scenarios

### 1. Basic Connectivity (`basic-connectivity.sh`)
Verifies all services are running and reachable:
- UDP connectivity to NS, Relay, Gateway
- TCP echo server works
- Network isolation (clients can't reach backend directly)
- Bidirectional UDP between clients

### 2. Handshake Through Gateway (`handshake-through-gateway.sh`)
Tests Noise_XX handshake with the gateway:
- 3-message Noise_XX exchange
- Data forwarding through gateway to echo server
- Handshake latency measurement

### 3. NS Resolution (`ns-resolution.sh`)
Tests ZTLP-NS name resolution:
- Bootstrap record queries
- Not-found responses
- Public key queries (type 0x05)
- All record types (KEY, SVC, RELAY, POLICY)
- Invalid query handling
- Zone delegation
- Concurrent queries

### 4. Full Stack E2E (`full-stack-e2e.sh`)
**The critical test** — proves everything works together:
- NS registration and lookup
- Relay session establishment
- Noise_XX handshake through relay
- 100-message exchange
- Round-trip verification

### 5. Latency Resilience (`latency-resilience.sh`)
Tests protocol under increasing network latency:
- Baseline (0ms) → 50ms → 200ms → 500ms
- Measures NS query success rate and RTT at each level
- Verifies graceful degradation

### 6. Packet Loss Resilience (`packet-loss-resilience.sh`)
Tests protocol under increasing packet loss:
- Baseline (0%) → 1% → 5% → 10% → 25%
- Measures handshake success rate and data delivery
- Documents UDP-unreliable behavior

### 7. Reconnection (`reconnection.sh`)
Tests behavior when the relay is killed and restarted:
- Pre-restart communication
- Relay stop/start
- Communication during outage
- Post-restart recovery
- New session establishment

### 8. Concurrent Sessions (`concurrent-sessions.sh`)
Tests handling of multiple simultaneous sessions:
- 10 concurrent sessions × 50 messages each
- Cross-session interference detection
- Both clients sending simultaneously
- Throughput measurement

### 9. Gateway Policy (`gateway-policy.sh`)
Tests the gateway's access control:
- Default policies (allow :all for "web", restricted "ssh")
- Allowed zone connection attempt
- Denied zone rejection
- Backend isolation verification
- Rapid connection attempt handling

### 10. Network Partition (`network-partition.sh`)
Tests behavior during and after network partitions:
- Baseline verification
- Partition creation (via tc on chaos container)
- Communication failure during partition
- Partition healing
- Recovery verification

## Directory Structure

```
tests/network/
├── docker-compose.test.yml    # Test environment definition
├── run-all.sh                 # Master test runner
├── README.md                  # This file
├── dockerfiles/               # Dockerfiles for test-specific containers
│   ├── Dockerfile.echo        # TCP echo server
│   ├── Dockerfile.chaos       # Network chaos container
│   ├── echo_server.py         # Echo server implementation
│   └── chaos-entrypoint.sh    # Chaos container entrypoint
├── scenarios/                 # Test scenarios (one per file)
│   ├── basic-connectivity.sh
│   ├── handshake-through-gateway.sh
│   ├── ns-resolution.sh
│   ├── full-stack-e2e.sh
│   ├── latency-resilience.sh
│   ├── packet-loss-resilience.sh
│   ├── reconnection.sh
│   ├── concurrent-sessions.sh
│   ├── gateway-policy.sh
│   └── network-partition.sh
├── lib/                       # Shared helper libraries
│   ├── common.sh              # Common functions, logging, compose helpers
│   ├── assert.sh              # Test assertions
│   └── chaos.sh               # Network impairment functions
├── client-scripts/            # Scripts that run inside client containers
│   ├── register-with-ns.sh
│   ├── lookup-ns.sh
│   ├── connect-relay.sh
│   ├── send-data.sh
│   ├── handshake-gateway.sh
│   └── full-e2e.sh
└── results/                   # Test results (generated)
    ├── summary.txt
    └── *.result
```

## Adding New Scenarios

1. Create `tests/network/scenarios/my-scenario.sh`
2. Source the shared libraries:
   ```bash
   SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
   source "$SCRIPT_DIR/../lib/common.sh"
   source "$SCRIPT_DIR/../lib/assert.sh"
   # source "$SCRIPT_DIR/../lib/chaos.sh"  # if needed
   ```
3. Use `start_scenario "my-scenario"` and `end_scenario`
4. Use assertions: `assert_eq`, `assert_contains`, `assert_gt`, etc.
5. Record results: `record_pass`, `record_fail`, `record_skip`
6. Add to `ALL_SCENARIOS` array in `run-all.sh`
7. Make executable: `chmod +x tests/network/scenarios/my-scenario.sh`

### Template

```bash
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

start_scenario "my-scenario"

log_header "Step 1: Do something"
RESULT=$(docker exec ztlp-test-client-a ...)
assert_eq "Something works" "expected" "$RESULT"

end_scenario
```

## Troubleshooting

### Build failures
```bash
# Rebuild from scratch
docker compose -f tests/network/docker-compose.test.yml build --no-cache
```

### NS healthcheck failing
The NS takes ~15s to start (Elixir compilation). Increase the healthcheck `start_period` if needed. Check logs:
```bash
docker logs ztlp-test-ns
```

### "Address already in use"
Port conflicts with the production docker-compose. Stop production first:
```bash
docker compose down  # stops production
docker compose -f tests/network/docker-compose.test.yml up -d
```

### Chaos container can't shape traffic
Ensure the chaos container has `NET_ADMIN` capability. Check:
```bash
docker exec ztlp-test-chaos tc qdisc show
```

### Containers can't resolve hostnames
Docker's internal DNS should resolve service names. Verify:
```bash
docker exec ztlp-test-client-a getent hosts relay
docker exec ztlp-test-client-a getent hosts ns
```

### Tests timing out
- Increase timeouts in scenario scripts
- Check if services are actually running: `docker compose -f tests/network/docker-compose.test.yml ps`
- Check logs: `docker compose -f tests/network/docker-compose.test.yml logs`

### Running on macOS/Windows
Docker Desktop's UDP port mapping can be unreliable. The test suite uses container-to-container networking (no host port mapping needed), so it should work. If not, ensure Docker Desktop has sufficient resources allocated.
