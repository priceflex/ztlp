# ZTLP Docker Packaging

Run the full ZTLP prototype stack with Docker Compose — no local Elixir/Rust toolchains required.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 20.10+
- [Docker Compose](https://docs.docker.com/compose/install/) v2 (bundled with Docker Desktop)

## Quick Start

```bash
# Clone and start everything
git clone https://github.com/priceflex/ztlp.git
cd ztlp
docker compose up --build
```

This starts all services:
- **NS** (namespace server) on UDP 23096
- **Relay** on UDP 23095
- **Gateway** on UDP 23097
- **Echo Backend** (test TCP echo) on TCP 8080

To run in the background:

```bash
docker compose up -d --build
docker compose logs -f   # follow logs
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network (bridge)                    │
│                                                              │
│  ┌──────────┐     ┌──────────┐     ┌──────────────────┐     │
│  │   NS     │     │  Relay   │     │  Echo Backend    │     │
│  │ :23096   │◄────│          │     │  :8080 (TCP)     │     │
│  │  (UDP)   │     │ :23095   │     └────────▲─────────┘     │
│  └────▲─────┘     │  (UDP)   │              │               │
│       │           └──────────┘              │               │
│       │                                     │               │
│  ┌────┴──────────────────────────────────────┐              │
│  │              Gateway                      │              │
│  │              :23097 (UDP)                 │              │
│  └──────────────────────────────────────────┘              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
        ▲
        │ UDP
┌───────┴──────┐
│  Proto CLI   │   (ztlp-node, ztlp-demo, ztlp-relay-demo)
│  (Rust)      │   Runs on host or in container
└──────────────┘
```

## Building Individual Images

```bash
docker build -t ztlp-ns      ./ns
docker build -t ztlp-relay   ./relay
docker build -t ztlp-gateway ./gateway
docker build -t ztlp-proto   ./proto
```

## Configuration

All services are configured via environment variables. Values set in the environment override application defaults.

### Namespace Server (NS)

| Variable | Default | Description |
|---|---|---|
| `ZTLP_NS_PORT` | `23096` | UDP listen port |
| `ZTLP_NS_MAX_RECORDS` | `100000` | Maximum records in the namespace store |

### Relay

| Variable | Default | Description |
|---|---|---|
| `ZTLP_RELAY_PORT` | `23095` | UDP listen port |
| `ZTLP_RELAY_MAX_SESSIONS` | `10000` | Maximum concurrent relay sessions |
| `ZTLP_RELAY_SESSION_TIMEOUT_MS` | `300000` | Session inactivity timeout (ms) |

### Gateway

| Variable | Default | Description |
|---|---|---|
| `ZTLP_GATEWAY_PORT` | `23097` | UDP listen port |
| `ZTLP_GATEWAY_NS_HOST` | *(none)* | Hostname of the NS service |
| `ZTLP_GATEWAY_NS_PORT` | *(none)* | Port of the NS service |
| `ZTLP_GATEWAY_MAX_SESSIONS` | `10000` | Maximum concurrent gateway sessions |

### Custom Port Example

```bash
docker compose up -d
# Or override at runtime:
ZTLP_RELAY_PORT=9000 docker compose up relay
```

## Testing with the Rust Client

Build and run the proto container interactively:

```bash
# Build the client image
docker build -t ztlp-proto ./proto

# Run ztlp-demo against the relay
docker run --rm --network host ztlp-proto \
  ztlp-demo --relay-addr 127.0.0.1:23095

# Or use the relay demo
docker run --rm --network host ztlp-proto \
  ztlp-relay-demo --relay-addr 127.0.0.1:23095

# Interactive shell in the container
docker run --rm -it --entrypoint /bin/bash ztlp-proto
```

When services run inside Docker Compose, use `--network` to join the compose network:

```bash
docker run --rm --network ztlp_default ztlp-proto \
  ztlp-demo --relay-addr relay:23095
```

## Running Tests in Containers

```bash
# Elixir components — NS and Relay
docker run --rm ztlp-ns mix test
docker run --rm ztlp-relay mix test

# Gateway tests (need MIX_ENV=test for NS integration tests)
docker run --rm -e MIX_ENV=test ztlp-gateway mix test

# Rust component — build the test target, then run
docker build --target test -t ztlp-proto-test ./proto
docker run --rm ztlp-proto-test
```

## Persistent Volumes

The prototype is stateless — no volumes are required. The NS store, relay sessions, and gateway sessions are all in-memory. Restarting a container resets its state.

For a future production deployment, you might want:
- Volume for NS persistent storage (if implemented)
- Volume for audit logs from the gateway

## Production Deployment Notes

This Docker setup is designed for **development and prototyping**. For production:

1. **Use multi-stage builds for Elixir** — The current images include the full Elixir toolchain for simplicity. A production setup would use Mix releases with a minimal Debian/Alpine runtime stage.
2. **TLS termination** — Add a reverse proxy (nginx, Caddy, Traefik) for TLS on control-plane endpoints.
3. **Resource limits** — Add `deploy.resources.limits` in compose for memory/CPU caps.
4. **Health checks** — Add `healthcheck` blocks to each service.
5. **Logging** — Configure a log driver (json-file with rotation, or ship to a log aggregator).
6. **Secrets management** — Use Docker secrets or a vault for any cryptographic material.

Example resource limits:

```yaml
services:
  ns:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
```

## Troubleshooting

### Build fails with "mix: command not found"

Ensure you're using the correct Elixir base image. The Dockerfiles use `elixir:1.12.3-otp-24`.

### UDP ports not reachable

Docker maps UDP ports explicitly. Verify with:

```bash
docker compose ps
# Check the PORTS column shows udp mappings
```

On macOS/Windows with Docker Desktop, UDP port forwarding can be flaky. Try `--network host` on Linux.

### "Address already in use"

Another process is using the port. Check with:

```bash
sudo ss -ulnp | grep -E '2309[567]'
```

### Container exits immediately

Check logs:

```bash
docker compose logs ns
docker compose logs relay
docker compose logs gateway
```

The Elixir services use `--no-halt` to keep running. If they crash on startup, it's likely a config or compilation issue.

### Rebuilding from scratch

```bash
docker compose down
docker compose build --no-cache
docker compose up
```
