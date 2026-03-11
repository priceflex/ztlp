# Docker & Deployment

Run the full ZTLP stack with Docker Compose — no local Elixir or Rust toolchains required. All Elixir services are built as proper OTP releases with health checks, metrics, and graceful shutdown.

## Quick Start

```bash
git clone https://github.com/priceflex/ztlp.git
cd ztlp
docker compose up --build
```

This starts four services:

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| **NS** (Namespace) | 23096 | UDP | ZTLP-NS name resolution, Ed25519-signed records |
| **Relay** | 23095 | UDP | Session routing, mesh support, RAT admission |
| **Gateway** | 23097 | UDP | Bidirectional ZTLP↔TCP bridge, policy engine |
| **Echo Backend** | 8080 | TCP | Test echo server for gateway demos |

Each Elixir service also exposes a Prometheus metrics endpoint (relay: 9101, gateway: 9102, ns: 9103).

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
│  ztlp CLI    │   (host or another container)
│  (Rust/Go)   │
└──────────────┘
```

## Docker Compose Commands

```bash
docker compose up -d --build       # Start in background
docker compose ps                  # Check health status
docker compose logs -f relay       # Follow relay logs
docker compose down                # Stop everything
```

## Building Individual Images

```bash
docker build -t ztlp-ns      ./ns
docker build -t ztlp-relay   ./relay
docker build -t ztlp-gateway ./gateway
docker build -t ztlp-proto   ./proto    # Rust CLI + tools
```

## Configuration

All services are configured via environment variables:

### Relay

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTLP_LISTEN_PORT` | `23095` | UDP listen port |
| `ZTLP_MESH_ENABLED` | `false` | Enable relay mesh mode |
| `ZTLP_MESH_PEERS` | — | Comma-separated mesh peer addresses |
| `ZTLP_NS_SERVER` | — | NS server for relay discovery |
| `ZTLP_METRICS_PORT` | `9101` | Prometheus metrics port |

### Gateway

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTLP_LISTEN_PORT` | `23097` | UDP listen port |
| `ZTLP_BACKEND` | `127.0.0.1:8080` | TCP backend address |
| `ZTLP_POLICY_FILE` | — | Path to policy YAML |
| `ZTLP_NS_SERVER` | — | NS server for identity resolution |
| `ZTLP_METRICS_PORT` | `9102` | Prometheus metrics port |

### NS (Namespace)

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTLP_NS_PORT` | `23096` | UDP listen port |
| `ZTLP_STORAGE_MODE` | `disc_copies` | Mnesia storage: `ram_copies` or `disc_copies` |
| `ZTLP_FEDERATION_PEERS` | — | Comma-separated federation peer addresses |
| `ZTLP_METRICS_PORT` | `9103` | Prometheus metrics port |

## Prometheus Metrics

All services expose Prometheus-compatible metrics. A pre-built Grafana dashboard with 9 panels is included at `docs/grafana-dashboard.json`.

Key metrics:
- `ztlp_packets_received_total` — packets by type and result
- `ztlp_pipeline_rejections_total` — by layer (L1/L2/L3)
- `ztlp_handshake_duration_seconds` — Noise_XX timing histogram
- `ztlp_active_sessions` — current session gauge
- `ztlp_relay_mesh_peers` — mesh peer count
- `ztlp_ns_records_total` — namespace record count
- `ztlp_federation_sync_total` — anti-entropy sync events

## OTP Releases & Hot Upgrades

All Elixir services are built as OTP releases with:
- **Minimal runtime images** — no build tools in production
- **Health checks** — Docker `HEALTHCHECK` via HTTP endpoint
- **Graceful shutdown** — proper SIGTERM handling, session drain
- **Hot upgrades** — appup templates for zero-downtime deployment

## Docker Compose Overlays

Additional compose files for specific configurations:

```bash
# Mesh mode: 3-relay mesh with automatic discovery
docker compose -f docker-compose.yml -f docker-compose.mesh.yml up

# Federation: multi-NS cluster with anti-entropy
docker compose -f docker-compose.yml -f docker-compose.federation.yml up
```

## Production Deployment

For production, you'll want:

1. **Firewall rules** — expose only the ZTLP UDP port, block everything else
2. **Identity management** — generate and distribute identities securely (see [Key Management Guide](https://github.com/priceflex/ztlp/blob/main/docs/KEY-MANAGEMENT.md))
3. **Monitoring** — connect Prometheus to metrics endpoints, import the Grafana dashboard
4. **TLS for metrics** — reverse-proxy metrics endpoints if exposed externally
5. **Resource limits** — set appropriate CPU/memory limits in compose or Kubernetes

## Performance

Benchmarked on standard cloud instances:

| Metric | Value |
|--------|-------|
| L1 reject (magic check) | **19ns** (Rust) / **89ns** (Elixir) |
| Noise_XX handshake | **299µs** (Rust) / **471µs** (Elixir) |
| Gateway data throughput | **669K ops/sec** |
| Relay forwarding | **233K pkt/sec** |
| Mesh overhead | **3.2%** |
| RAT issue rate | **275K/sec** |
| RAT verify rate | **393K/sec** |

---

Full Docker documentation: [`DOCKER.md`](https://github.com/priceflex/ztlp/blob/main/DOCKER.md)  
Operations runbook: [`docs/OPS-RUNBOOK.md`](https://github.com/priceflex/ztlp/blob/main/docs/OPS-RUNBOOK.md)  
Key management: [`docs/KEY-MANAGEMENT.md`](https://github.com/priceflex/ztlp/blob/main/docs/KEY-MANAGEMENT.md)
