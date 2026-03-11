# ZTLP Docker Packaging

Run the full ZTLP prototype stack with Docker Compose — no local Elixir/Rust toolchains required. All Elixir services are built as proper OTP releases (small runtime images, health checks, graceful shutdown).

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 20.10+
- [Docker Compose](https://docs.docker.com/compose/install/) v2 (bundled with Docker Desktop)

## Quick Start

```bash
git clone https://github.com/priceflex/ztlp.git
cd ztlp
docker compose up --build
```

This starts:
- **NS** (namespace server) on UDP 23096 + metrics on 9103
- **Relay** on UDP 23095 + metrics on 9101
- **Gateway** on UDP 23097 + metrics on 9102
- **Echo Backend** (test TCP echo) on TCP 8080

```bash
docker compose up -d --build       # Background
docker compose ps                  # Check health
docker compose logs -f relay       # Follow logs
```

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      Docker Network (bridge)                      │
│                                                                   │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐  │
│  │     NS       │   │    Relay     │   │   Echo Backend       │  │
│  │ :23096 (UDP) │   │ :23095 (UDP) │   │   :8080 (TCP)        │  │
│  │ :9103 (HTTP) │   │ :9101 (HTTP) │   └──────────▲───────────┘  │
│  └──────▲───────┘   └──────────────┘               │              │
│         │                                          │              │
│  ┌──────┴──────────────────────────────────────────┤              │
│  │                  Gateway                        │              │
│  │              :23097 (UDP)                       │              │
│  │              :9102 (HTTP)                       │              │
│  └─────────────────────────────────────────────────┘              │
└───────────────────────────────────────────────────────────────────┘
        ▲
        │ UDP
┌───────┴──────┐
│  ztlp CLI    │   docker run --rm --network host ztlp-proto
│  (Rust)      │   ztlp connect / listen / relay / ns / gateway
└──────────────┘
```

## Building Individual Images

```bash
docker build -t ztlp-ns      ./ns
docker build -t ztlp-relay   ./relay
docker build -t ztlp-gateway -f gateway/Dockerfile .    # context = repo root
docker build -t ztlp-proto   ./proto
```

All Elixir images use multi-stage builds: compile with `elixir:1.12.3-otp-24`, then copy the OTP release into `debian:bullseye-slim` (~80MB runtime).

## Using the Rust CLI

```bash
# Build
docker build -t ztlp-proto ./proto

# Generate a keypair
docker run --rm ztlp-proto keygen

# Connect to the relay
docker run --rm --network host ztlp-proto connect --relay-addr 127.0.0.1:23095

# Inspect a packet (hex)
docker run --rm ztlp-proto ztlp-inspect --hex "5a37..."

# Interactive shell
docker run --rm -it --entrypoint /bin/bash ztlp-proto
```

The proto image includes: `ztlp` (unified CLI), `ztlp-inspect`, `ztlp-load`, `ztlp-fuzz`, `ztlp-throughput`.

## Configuration Reference

All services are configured via environment variables. Set them in `docker-compose.yml` or override at runtime.

### Namespace Server (NS)

| Variable | Default | Description |
|---|---|---|
| `ZTLP_NS_PORT` | `23096` | UDP listen port |
| `ZTLP_NS_MAX_RECORDS` | `100000` | Max records in namespace store |
| `ZTLP_NS_STORAGE_MODE` | `ram_copies` | Mnesia storage: `ram_copies` or `disc_copies` |
| `ZTLP_NS_MNESIA_DIR` | `/app/data` | Mnesia data directory (for disc_copies) |
| `ZTLP_NS_METRICS_ENABLED` | `true` | Enable Prometheus metrics endpoint |
| `ZTLP_NS_METRICS_PORT` | `9103` | Metrics HTTP port |
| `ZTLP_NS_RATE_LIMIT_PER_SEC` | `100` | Per-IP query rate limit |
| `ZTLP_NS_RATE_LIMIT_BURST` | `200` | Rate limit burst allowance |
| `ZTLP_NS_SEED_NODES` | *(none)* | Comma-separated Erlang node names for federation |
| `ZTLP_NS_NODE_NAME` | *(none)* | Erlang node name (e.g. `ns1@hostname`) |
| `ZTLP_LOG_FORMAT` | `json` | Log format: `json`, `structured`, or `console` |
| `ZTLP_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

### Relay

| Variable | Default | Description |
|---|---|---|
| `ZTLP_RELAY_PORT` | `23095` | UDP listen port |
| `ZTLP_RELAY_MAX_SESSIONS` | `10000` | Max concurrent relay sessions |
| `ZTLP_RELAY_SESSION_TIMEOUT_MS` | `300000` | Session inactivity timeout (ms) |
| `ZTLP_RELAY_METRICS_ENABLED` | `true` | Enable Prometheus metrics endpoint |
| `ZTLP_RELAY_METRICS_PORT` | `9101` | Metrics HTTP port |
| `ZTLP_RELAY_BACKPRESSURE_SOFT_PCT` | `80` | Soft backpressure threshold (%) |
| `ZTLP_RELAY_BACKPRESSURE_HARD_PCT` | `95` | Hard backpressure threshold (%) |
| `ZTLP_RELAY_MESH_ENABLED` | `false` | Enable relay mesh networking |
| `ZTLP_RELAY_MESH_PORT` | `23098` | Mesh inter-relay UDP port |
| `ZTLP_RELAY_MESH_SEED_NODES` | *(none)* | Comma-separated `host:port` of mesh peers |
| `ZTLP_LOG_FORMAT` | `json` | Log format |
| `ZTLP_LOG_LEVEL` | `info` | Log level |

### Gateway

| Variable | Default | Description |
|---|---|---|
| `ZTLP_GATEWAY_PORT` | `23097` | UDP listen port |
| `ZTLP_GATEWAY_NS_HOST` | *(none)* | Hostname of NS service |
| `ZTLP_GATEWAY_NS_PORT` | *(none)* | Port of NS service |
| `ZTLP_GATEWAY_MAX_SESSIONS` | `10000` | Max concurrent gateway sessions |
| `ZTLP_GATEWAY_SESSION_TIMEOUT_MS` | `300000` | Session timeout (ms) |
| `ZTLP_GATEWAY_METRICS_ENABLED` | `true` | Enable Prometheus metrics endpoint |
| `ZTLP_GATEWAY_METRICS_PORT` | `9102` | Metrics HTTP port |
| `ZTLP_GATEWAY_CIRCUIT_BREAKER_THRESHOLD` | `5` | Failures before circuit opens |
| `ZTLP_GATEWAY_CIRCUIT_BREAKER_TIMEOUT_MS` | `30000` | Circuit breaker recovery timeout |
| `ZTLP_GATEWAY_BACKEND_HOST` | *(none)* | Backend TCP service hostname |
| `ZTLP_GATEWAY_BACKEND_PORT` | *(none)* | Backend TCP service port |
| `ZTLP_LOG_FORMAT` | `json` | Log format |
| `ZTLP_LOG_LEVEL` | `info` | Log level |

### Shared

| Variable | Default | Description |
|---|---|---|
| `RELEASE_COOKIE` | *(per-service)* | Erlang distribution cookie (must match for clustering) |

## Relay Mesh

Run a 3-relay mesh with consistent-hash routing and PathScore health monitoring:

```bash
docker compose -f docker-compose.yml -f docker-compose.mesh.yml up --build
```

This starts:
- **relay** (primary) — :23095, mesh :23098, metrics :9101
- **relay2** — :23195, mesh :23198, metrics :9111
- **relay3** — :23295, mesh :23298, metrics :9121

All three auto-discover each other via seed nodes and form a hash ring. Sessions are routed to the optimal relay based on SessionID hash, with automatic failover if a relay goes down.

```bash
# Watch mesh formation
docker compose -f docker-compose.yml -f docker-compose.mesh.yml logs -f relay relay2 relay3

# Kill a relay to test failover
docker compose -f docker-compose.yml -f docker-compose.mesh.yml stop relay2
```

## NS Federation

Run a 3-node federated namespace cluster with Mnesia replication:

```bash
docker compose -f docker-compose.yml -f docker-compose.federation.yml up --build
```

This starts:
- **ns** (ns1) — :23096, metrics :9103, persistent volume
- **ns2** — :23196, metrics :9113, persistent volume
- **ns3** — :23296, metrics :9123, persistent volume

Records written to any node replicate eagerly to all others. Merkle-tree anti-entropy runs every 30 seconds to catch any missed updates. Conflict resolution: revocation always wins → higher serial wins → signature must verify.

```bash
# Check cluster membership
docker exec ztlp-ns /app/bin/ztlp_ns rpc "ZtlpNs.Cluster.members()"

# Test partition recovery
docker network disconnect ztlp_default ztlp-ns-2
sleep 30
docker network connect ztlp_default ztlp-ns-2
# Anti-entropy will sync missed records within 30s
```

## Monitoring with Prometheus

All services expose Prometheus-compatible metrics endpoints. Example `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'ztlp-ns'
    static_configs:
      - targets: ['localhost:9103']

  - job_name: 'ztlp-relay'
    static_configs:
      - targets: ['localhost:9101']
    # For mesh: add relay2 (9111) and relay3 (9121)

  - job_name: 'ztlp-gateway'
    static_configs:
      - targets: ['localhost:9102']
```

Key metrics:
- `ztlp_relay_sessions_active` — current relay sessions
- `ztlp_relay_backpressure_state` — 0=normal, 1=soft, 2=hard
- `ztlp_relay_packets_forwarded_total` — relay throughput
- `ztlp_gateway_circuit_breaker_state` — per-backend: 0=closed, 1=half-open, 2=open
- `ztlp_gateway_handshakes_total` — completed Noise_XX handshakes
- `ztlp_ns_records_total` — namespace records stored
- `ztlp_ns_queries_total` — query throughput
- `ztlp_ns_rate_limited_total` — rejected queries (rate limit)

A pre-built Grafana dashboard is available at `docs/grafana-dashboard.json`.

## JSON Log Format

All services default to JSON logging in Docker. Example output:

```json
{"timestamp":"2026-03-11T18:00:00.000Z","level":"info","module":"ZtlpRelay.UdpListener","event":"session_created","session_id":"a1b2c3...","peer":"10.0.0.5:44821"}
{"timestamp":"2026-03-11T18:00:00.001Z","level":"info","module":"ZtlpRelay.Pipeline","event":"packet_admitted","layer":"L3_auth","session_id":"a1b2c3..."}
```

Switch to human-readable console format for debugging:

```bash
ZTLP_LOG_FORMAT=console docker compose up relay
```

## Health Checks

Each Elixir service includes a health check that verifies the BEAM VM is running and responsive via OTP release RPC. Docker reports health status:

```bash
$ docker compose ps
NAME             STATUS                    PORTS
ztlp-ns          Up 5 minutes (healthy)    23096/udp, 9103/tcp
ztlp-relay       Up 5 minutes (healthy)    23095/udp, 9101/tcp
ztlp-gateway     Up 5 minutes (healthy)    23097/udp, 9102/tcp
```

The gateway uses `depends_on: ns: condition: service_healthy` — it won't start until NS passes its health check.

## Running Tests in Containers

```bash
# NS tests
docker run --rm $(docker build -q --target builder ./ns) mix test

# Relay tests
docker run --rm $(docker build -q --target builder ./relay) mix test

# Gateway tests (needs NS for integration tests)
docker build -f gateway/Dockerfile --target builder -t ztlp-gateway-test . && \
  docker run --rm -e MIX_ENV=test ztlp-gateway-test mix test

# Rust tests
docker build --target test -t ztlp-proto-test ./proto && \
  docker run --rm ztlp-proto-test
```

## Production Deployment Notes

These Docker images are **production-ready**:

1. **OTP releases** — Elixir services compile to standalone BEAM releases (no Mix/Hex at runtime). Small `debian:bullseye-slim` base (~80MB).
2. **Non-root** — All services run as the `ztlp` system user.
3. **Health checks** — Built into every Dockerfile. Use with orchestrators (Kubernetes, Nomad, Swarm).
4. **JSON logging** — Default format. Ships to any log aggregator (ELK, Loki, CloudWatch).
5. **Prometheus metrics** — Scrape endpoints on every service.
6. **Resource limits** — Set in compose via `deploy.resources.limits`.
7. **Graceful shutdown** — OTP releases handle SIGTERM cleanly (drain sessions, flush state).

For Kubernetes, convert the compose services to Deployments with:
- UDP `hostPort` or `LoadBalancer` for client-facing ports
- `ClusterIP` services for inter-component traffic (NS↔gateway, relay mesh)
- `PersistentVolumeClaim` for NS disc_copies data
- Prometheus `ServiceMonitor` CRDs for metrics scraping

## Troubleshooting

### Health check failing

```bash
# Check logs for crash reason
docker compose logs ns

# Manual health check
docker exec ztlp-ns /app/bin/ztlp_ns rpc "IO.puts(:ok)"
```

### UDP ports not reachable

Docker maps UDP ports explicitly. Verify:

```bash
docker compose ps    # Check PORTS column
sudo ss -ulnp | grep -E '2309[567]'
```

On macOS/Windows with Docker Desktop, UDP port forwarding can be unreliable. Use `--network host` on Linux.

### "Address already in use"

```bash
sudo ss -ulnp | grep -E '2309[567]'
# Kill the conflicting process, then retry
```

### Mnesia errors in federation mode

Mnesia `disc_copies` requires Erlang distribution (named nodes). Ensure:
- `ZTLP_NS_NODE_NAME` is set and unique per node
- All nodes can resolve each other's hostnames
- `RELEASE_COOKIE` matches across all nodes in the cluster

### Rebuilding from scratch

```bash
docker compose down -v    # -v removes volumes (Mnesia data!)
docker compose build --no-cache
docker compose up
```
