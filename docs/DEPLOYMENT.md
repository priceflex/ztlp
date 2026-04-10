# ZTLP MSP Deployment Guide

> A step-by-step guide for Managed Service Providers (MSPs) to deploy ZTLP
> and protect any internally-hosted web application with zero-trust security.

**Version:** 0.6.0  
**Last updated:** 2026-03-15  
**Audience:** MSP engineers, IT administrators, security architects

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Architecture](#3-architecture)
4. [Step 1: Initialize Your Zone](#step-1-initialize-your-zone)
5. [Step 2: Deploy NS Server](#step-2-deploy-ns-server)
6. [Step 3: Deploy Gateway](#step-3-deploy-gateway)
7. [Step 4: Protect Your Web App](#step-4-protect-your-web-app)
8. [Step 5: Create Admin User](#step-5-create-admin-user)
9. [Step 6: Set Up Groups](#step-6-set-up-groups)
10. [Step 7: Enroll Technicians](#step-7-enroll-technicians)
11. [Step 8: Enroll Customer Devices](#step-8-enroll-customer-devices)
12. [Step 9: Verify](#step-9-verify)
13. [Day 2 Operations](#day-2-operations)
14. [Security Checklist](#security-checklist)
15. [Troubleshooting](#troubleshooting)
16. [Quick Reference](#quick-reference)

---

## 1. Overview

### What is ZTLP?

**Zero Trust Layer Protocol (ZTLP)** is a network protocol that makes your
internal applications invisible to the public internet. Unlike traditional
VPNs, ZTLP operates at the UDP layer with cryptographic identity
verification — no IP-based trust, no exposed HTTP ports, no attack surface.

### What does this guide cover?

This guide walks you through deploying ZTLP to protect a web application
for one of your MSP clients. By the end, you will have:

- A **namespace server (NS)** for identity registration and discovery
- A **gateway** that proxies authenticated traffic to your web application
- An **identity model** with users, devices, and groups
- A **default-deny policy** that only allows authorized personnel access
- **Enrollment tokens** for onboarding new technicians and customer devices
- A **Docker Compose** setup that exposes zero HTTP ports to the internet

### Why ZTLP for MSPs?

| Traditional VPN | ZTLP |
|-----------------|------|
| IP-based trust — anyone on the VPN sees everything | Identity-based — each person/device has a cryptographic identity |
| Exposed management ports (443, 22, etc.) | Only UDP port exposed; services invisible to scanners |
| Flat network after connection | Per-service authorization with group-based policy |
| VPN concentrator as single point of failure | Lightweight relay + gateway architecture |
| Complex client configuration | Single enrollment token → automatic setup |
| Credential sharing (shared PSK, group passwords) | Per-device X25519 keys, per-user Ed25519 signing keys |

### How it works

1. **Every entity gets a cryptographic identity** — devices get X25519 key pairs,
   users get Ed25519 signing keys, groups collect users into policy targets.

2. **The NS server is the source of truth** — it stores identity records (DEVICE,
   USER, GROUP), resolves names to addresses, and verifies signatures.

3. **The gateway enforces policy** — when a client connects, the gateway:
   - Completes a Noise_XX handshake (mutual authentication)
   - Looks up the client's identity in NS
   - Checks group membership against the access policy
   - Forwards traffic to the backend application (or rejects it)

4. **No exposed HTTP** — your web application sits on an internal Docker network
   with no port bindings. The only way in is through an authenticated ZTLP tunnel.

---

## 2. Prerequisites

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| NS Server | 1 vCPU, 512 MB RAM | 2 vCPU, 1 GB RAM |
| Gateway | 2 vCPU, 1 GB RAM | 4 vCPU, 2 GB RAM |
| Relay (optional) | 2 vCPU, 1 GB RAM | 4 vCPU, 2 GB RAM |

All components can run on a single machine for small deployments (<50 devices).

### Software

- **Docker** 20.10+ and **Docker Compose** v2
- **A domain name** (e.g., `clients.yourcompany.ztlp` — this is a logical zone
  name, not a DNS domain; no DNS registration required)
- **The `ztlp` CLI** — download from
  [GitHub Releases](https://github.com/priceflex/ztlp/releases) or build from source:

```bash
cd proto && cargo build --release
# Binary at: proto/target/release/ztlp
sudo cp proto/target/release/ztlp /usr/local/bin/
```

### Network

- **One UDP port** open on the gateway host (default: `23095`)
- **One UDP port** open on the NS server (default: `23096`)
- Internal network connectivity between gateway and your web application

> **Important:** No TCP/HTTP ports need to be exposed. That's the point.

### Verify your setup

```bash
# Check Docker
docker --version
docker compose version

# Check ztlp CLI
ztlp --version

# Check that you can run Docker containers
docker run --rm alpine echo "Docker works"
```

---

## 3. Architecture

```
                         Internet
                            │
                    ┌───────┴───────┐
                    │  Firewall     │
                    │  UDP 23095 ✓  │
                    │  TCP 80/443 ✗ │  ← HTTP ports CLOSED
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────────┐
              │             │                  │
   ┌──────────▼──┐  ┌──────▼──────┐  ┌───────▼───────┐
   │  NS Server  │  │   Gateway   │  │  Relay        │
   │  UDP 23096  │  │  UDP 23095  │  │  UDP 23095    │
   │             │  │             │  │  (optional)   │
   │  Identity   │  │  Policy     │  │  NAT traverse │
   │  Registry   │  │  Enforce    │  │  Packet fwd   │
   └──────┬──────┘  └──────┬──────┘  └───────────────┘
          │                │
          │         ┌──────▼──────┐
          │         │  Internal   │
          │         │  Network    │
          │         │  (Docker)   │
          │         └──────┬──────┘
          │                │
          │         ┌──────▼──────┐
          │         │  Your Web   │
          │         │  App        │
          │         │  (no ports  │
          │         │   exposed)  │
          │         └─────────────┘
          │
   ┌──────┴──────────────────────────┐
   │         ZTLP Clients            │
   │                                 │
   │  ┌─────────┐  ┌─────────┐      │
   │  │ Tech    │  │ Customer │      │
   │  │ Laptop  │  │ Device   │      │
   │  │         │  │          │      │
   │  │ User:   │  │ Device:  │      │
   │  │ alice@  │  │ kiosk-01 │      │
   │  │ acme    │  │ .acme    │      │
   │  └─────────┘  └──────────┘      │
   └──────────────────────────────────┘
```

### Component Overview

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **NS Server** | Elixir/OTP | Identity registry, name resolution, record signing |
| **Gateway** | Elixir/OTP | Policy enforcement, backend proxying, session management |
| **Relay** | Rust or Elixir | NAT traversal, packet forwarding (never decrypts traffic) |
| **ztlp CLI** | Rust | Identity management, enrollment, admin operations, tunneling |
| **Your App** | Anything | The web application you're protecting |

### Data Flow

1. Client runs `ztlp connect gateway.clients.acme.ztlp --service web`
2. ZTLP CLI resolves the name via NS → gets gateway's address
3. Client ↔ Gateway: Noise_XX handshake (mutual authentication)
4. Gateway looks up client's public key in NS → gets registered identity
5. Gateway evaluates policy: is this identity allowed for the `web` service?
6. If allowed: gateway opens TCP connection to the backend web app
7. Client's HTTP traffic flows through the encrypted ZTLP tunnel to the app
8. If denied: gateway sends REJECT frame, connection closed

---

## Step 1: Initialize Your Zone

A **zone** is your namespace — the equivalent of a DNS domain for ZTLP. All
identities in your deployment live under this zone.

### Choose your zone name

Convention: `<client-name>.<your-company>.ztlp`

Examples:
- `clients.techrockstars.ztlp` — all Tech Rockstars clients
- `acme.techrockstars.ztlp` — ACME Corp (one specific client)
- `office.acme.ztlp` — ACME Corp's office network

### Generate the zone signing key

The zone signing key is an Ed25519 key that signs all records in the zone.
Only the holder of this key can create, modify, or revoke identities.

```bash
# Create the zone and generate the enrollment secret
ztlp admin init-zone --zone clients.techrockstars.ztlp

# Optionally specify where to save the secret
ztlp admin init-zone \
  --zone clients.techrockstars.ztlp \
  --secret-output /etc/ztlp/zone.key
```

This generates:
- A **zone enrollment secret** (32 random bytes) saved to `~/.ztlp/zone.key`
  (or the path you specified with `--secret-output`)
- Zone metadata stored in `~/.ztlp/` for subsequent commands

> **⚠ Security:** The zone signing key is the root of trust for your
> entire deployment. Store it securely. Back it up offline. Do not put it
> in a Docker image or commit it to git.

### Generate your admin identity

```bash
# Generate your personal admin identity
ztlp keygen --output ~/.ztlp/identity.json
```

This creates an identity file containing:
- A 128-bit **NodeID** (unique identifier)
- An **X25519** key pair (for Noise_XX handshakes)
- An **Ed25519** key pair (for signing NS records)

The identity file is saved with restrictive permissions (`0600`).

---

## Step 2: Deploy NS Server

The NS server is the identity registry for your zone. It stores DEVICE,
USER, and GROUP records, resolves names, and verifies Ed25519 signatures.

### Option A: Docker (Recommended)

Create a directory for your ZTLP deployment:

```bash
mkdir -p /opt/ztlp && cd /opt/ztlp
```

Run the NS server:

```bash
docker run -d \
  --name ztlp-ns \
  --restart unless-stopped \
  -p 23096:23096/udp \
  -p 9103:9103 \
  -e ZTLP_NS_PORT=23096 \
  -e ZTLP_NS_MAX_RECORDS=100000 \
  -e ZTLP_NS_STORAGE_MODE=disc_copies \
  -e ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true \
  -e ZTLP_LOG_FORMAT=json \
  -e ZTLP_LOG_LEVEL=info \
  -e ZTLP_NS_METRICS_ENABLED=true \
  -e ZTLP_NS_METRICS_PORT=9103 \
  -e ZTLP_NS_RATE_LIMIT_PER_SEC=100 \
  -e ZTLP_NS_RATE_LIMIT_BURST=200 \
  -v ztlp-ns-data:/app/data \
  ztlp/ns:latest
```

### Option B: Build from source

```bash
cd ns
docker build -t ztlp-ns .
docker run -d --name ztlp-ns \
  -p 23096:23096/udp \
  -e ZTLP_NS_PORT=23096 \
  -e ZTLP_NS_STORAGE_MODE=disc_copies \
  -e ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true \
  ztlp-ns
```

### Option C: Run directly with Elixir

```bash
cd ns
ZTLP_NS_PORT=23096 \
ZTLP_NS_STORAGE_MODE=disc_copies \
ZTLP_NS_REQUIRE_REGISTRATION_AUTH=true \
mix run --no-halt
```

Requires Elixir 1.12+ / Erlang OTP 24+.

### NS Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTLP_NS_PORT` | `23096` | UDP listen port |
| `ZTLP_NS_MAX_RECORDS` | `100000` | Maximum stored records |
| `ZTLP_NS_STORAGE_MODE` | `disc_copies` | Mnesia storage mode: `disc_copies` (persistent) or `ram_copies` (volatile) |
| `ZTLP_NS_REQUIRE_REGISTRATION_AUTH` | `false` | Require Ed25519 signatures for record registration. **Set to `true` in production.** |
| `ZTLP_NS_RATE_LIMIT_PER_SEC` | `100` | Query rate limit (per source IP) |
| `ZTLP_NS_RATE_LIMIT_BURST` | `200` | Burst allowance for rate limiter |
| `ZTLP_NS_METRICS_ENABLED` | `false` | Enable Prometheus metrics endpoint |
| `ZTLP_NS_METRICS_PORT` | `9103` | Prometheus metrics port |
| `ZTLP_NS_MNESIA_DIR` | Mnesia default | Directory for data persistence |
| `ZTLP_LOG_FORMAT` | `text` | Log format: `text` or `json` |
| `ZTLP_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `ZTLP_ENROLLMENT_SECRET` | none | 64 hex chars — zone enrollment secret (alternative to file-based secret) |

### Verify NS is running

```bash
# Check container health
docker inspect --format='{{.State.Health.Status}}' ztlp-ns

# Test name resolution (should return "not found" since no records exist yet)
ztlp ns lookup test.clients.techrockstars.ztlp --ns-server 127.0.0.1:23096
```

### Register your admin identity with NS

```bash
ztlp ns register \
  --name admin.clients.techrockstars.ztlp \
  --zone clients.techrockstars.ztlp \
  --key ~/.ztlp/identity.json \
  --address 0.0.0.0:0 \
  --ns-server 127.0.0.1:23096
```

### DNS TXT records for discovery (optional)

To enable auto-discovery (so clients don't need to specify `--ns-server`
manually), add a DNS TXT record for your zone:

```
_ztlp.clients.techrockstars.ztlp  TXT  "ns=YOUR_NS_SERVER_IP:23096"
```

This allows clients to discover the NS server automatically by zone name.

---

## Step 3: Deploy Gateway

The gateway is the access point for your protected application. It terminates
ZTLP tunnels, enforces access policy, and forwards traffic to backend services.

### Create the policy file

The gateway uses a TOML policy file to decide who can access what.
Start with a **default-deny** policy:

```bash
mkdir -p /opt/ztlp/config
cat > /opt/ztlp/config/policy.toml << 'EOF'
# ZTLP Gateway Access Policy
# Default: deny all access. Only explicitly listed identities are allowed.
default = "deny"

# Web application — accessible by the admins and techs groups
[[services]]
name = "web"
allow = [
  "admins@clients.techrockstars.ztlp",
  "techs@clients.techrockstars.ztlp",
]

# SSH — admin group only
[[services]]
name = "ssh"
allow = [
  "admins@clients.techrockstars.ztlp",
]
EOF
```

### Generate a gateway identity

```bash
ztlp keygen --output /opt/ztlp/config/gateway-identity.json
```

### Register the gateway with NS

```bash
ztlp ns register \
  --name gateway.clients.techrockstars.ztlp \
  --zone clients.techrockstars.ztlp \
  --key /opt/ztlp/config/gateway-identity.json \
  --address YOUR_GATEWAY_IP:23095 \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Run the gateway

The gateway uses the `ztlp listen` command in gateway mode, forwarding
to your backend services:

```bash
docker run -d \
  --name ztlp-gateway \
  --restart unless-stopped \
  --network ztlp-internal \
  -p 23095:23095/udp \
  -v /opt/ztlp/config:/etc/ztlp:ro \
  -e ZTLP_GATEWAY_PORT=23095 \
  -e ZTLP_GATEWAY_NS_HOST=YOUR_NS_SERVER_IP \
  -e ZTLP_GATEWAY_NS_PORT=23096 \
  -e ZTLP_GATEWAY_MAX_SESSIONS=10000 \
  -e ZTLP_GATEWAY_BACKEND_HOST=your-app \
  -e ZTLP_GATEWAY_BACKEND_PORT=8080 \
  -e ZTLP_LOG_FORMAT=json \
  -e ZTLP_LOG_LEVEL=info \
  -e ZTLP_GATEWAY_METRICS_ENABLED=true \
  -e ZTLP_GATEWAY_METRICS_PORT=9102 \
  -e ZTLP_GATEWAY_CIRCUIT_BREAKER_THRESHOLD=5 \
  -e ZTLP_GATEWAY_CIRCUIT_BREAKER_TIMEOUT_MS=30000 \
  ztlp/gateway:latest
```

Or with the CLI directly (useful for testing):

```bash
ztlp listen \
  --bind 0.0.0.0:23095 \
  --key /opt/ztlp/config/gateway-identity.json \
  --gateway \
  --forward web:your-app-host:8080 \
  --forward ssh:your-app-host:22 \
  --policy /opt/ztlp/config/policy.toml \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --max-sessions 10000
```

### Gateway Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTLP_GATEWAY_PORT` | `23097` | UDP listen port |
| `ZTLP_GATEWAY_NS_HOST` | — | NS server hostname/IP |
| `ZTLP_GATEWAY_NS_PORT` | `23096` | NS server port |
| `ZTLP_GATEWAY_MAX_SESSIONS` | `10000` | Maximum concurrent sessions |
| `ZTLP_GATEWAY_BACKEND_HOST` | — | Default backend host |
| `ZTLP_GATEWAY_BACKEND_PORT` | — | Default backend port |
| `ZTLP_GATEWAY_METRICS_ENABLED` | `false` | Enable Prometheus metrics |
| `ZTLP_GATEWAY_METRICS_PORT` | `9102` | Prometheus metrics port |
| `ZTLP_GATEWAY_CIRCUIT_BREAKER_THRESHOLD` | `5` | Failed requests before circuit opens |
| `ZTLP_GATEWAY_CIRCUIT_BREAKER_TIMEOUT_MS` | `30000` | Circuit breaker recovery timeout |
| `ZTLP_LOG_FORMAT` | `text` | `text` or `json` |
| `ZTLP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

---

## Step 4: Protect Your Web App

This is the complete Docker Compose template that puts it all together.
Your web application sits on an internal network with **no exposed ports**.
The only way in is through the ZTLP gateway.

### Production Docker Compose

Create `docker-compose.yml`:

```yaml
# ─────────────────────────────────────────────────────────────
# ZTLP Production Stack — Protect any web application
# ─────────────────────────────────────────────────────────────
#
# Usage:
#   docker compose up -d              # Start all services
#   docker compose logs -f gateway    # Follow gateway logs
#   docker compose ps                 # Check health
#
# Only port exposed: 23095/udp (ZTLP gateway)
# Your web app has ZERO exposed ports.

services:
  # ── Namespace Server ─────────────────────────────────────
  ns:
    image: ztlp/ns:latest
    # Or build from source:
    # build: ./ns
    container_name: ztlp-ns
    ports:
      - "23096:23096/udp"
      - "9103:9103"              # Prometheus metrics (optional)
    environment:
      ZTLP_NS_PORT: "23096"
      ZTLP_NS_MAX_RECORDS: "100000"
      ZTLP_NS_STORAGE_MODE: "disc_copies"
      ZTLP_NS_REQUIRE_REGISTRATION_AUTH: "true"
      ZTLP_LOG_FORMAT: "json"
      ZTLP_LOG_LEVEL: "info"
      ZTLP_NS_METRICS_ENABLED: "true"
      ZTLP_NS_METRICS_PORT: "9103"
      ZTLP_NS_RATE_LIMIT_PER_SEC: "100"
      ZTLP_NS_RATE_LIMIT_BURST: "200"
    volumes:
      - ns-data:/app/data
    healthcheck:
      test: ["CMD", "/app/healthcheck.sh"]
      interval: 30s
      timeout: 5s
      retries: 3
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M

  # ── Gateway ──────────────────────────────────────────────
  gateway:
    image: ztlp/gateway:latest
    # Or build from source:
    # build:
    #   context: .
    #   dockerfile: gateway/Dockerfile
    container_name: ztlp-gateway
    ports:
      - "23095:23095/udp"        # Only ZTLP — no HTTP exposed!
      - "9102:9102"              # Prometheus metrics (optional)
    depends_on:
      ns:
        condition: service_healthy
    environment:
      ZTLP_GATEWAY_PORT: "23095"
      ZTLP_GATEWAY_NS_HOST: "ns"
      ZTLP_GATEWAY_NS_PORT: "23096"
      ZTLP_GATEWAY_MAX_SESSIONS: "10000"
      ZTLP_GATEWAY_BACKEND_HOST: "your-app"
      ZTLP_GATEWAY_BACKEND_PORT: "8080"
      ZTLP_LOG_FORMAT: "json"
      ZTLP_LOG_LEVEL: "info"
      ZTLP_GATEWAY_METRICS_ENABLED: "true"
      ZTLP_GATEWAY_METRICS_PORT: "9102"
      ZTLP_GATEWAY_CIRCUIT_BREAKER_THRESHOLD: "5"
      ZTLP_GATEWAY_CIRCUIT_BREAKER_TIMEOUT_MS: "30000"
    volumes:
      - ./config/policy.toml:/etc/ztlp/policy.toml:ro
      - ./config/gateway-identity.json:/etc/ztlp/identity.json:ro
    healthcheck:
      test: ["CMD", "/app/healthcheck.sh"]
      interval: 30s
      timeout: 5s
      retries: 3
    restart: unless-stopped
    networks:
      - default
      - internal
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G

  # ── Relay (optional — for NAT traversal) ─────────────────
  relay:
    image: ztlp/relay:latest
    # Or build from source:
    # build: ./relay
    container_name: ztlp-relay
    ports:
      - "23098:23095/udp"        # Different host port to avoid conflict with gateway
      - "9101:9101"              # Prometheus metrics
    environment:
      ZTLP_RELAY_PORT: "23095"
      ZTLP_RELAY_MAX_SESSIONS: "10000"
      ZTLP_RELAY_SESSION_TIMEOUT_MS: "300000"
      ZTLP_LOG_FORMAT: "json"
      ZTLP_LOG_LEVEL: "info"
      ZTLP_RELAY_METRICS_ENABLED: "true"
      ZTLP_RELAY_METRICS_PORT: "9101"
      ZTLP_RELAY_BACKPRESSURE_SOFT_PCT: "80"
      ZTLP_RELAY_BACKPRESSURE_HARD_PCT: "95"
    healthcheck:
      test: ["CMD", "/app/healthcheck.sh"]
      interval: 30s
      timeout: 5s
      retries: 3
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
    profiles:
      - with-relay               # Only starts with: docker compose --profile with-relay up

  # ── Your Web Application ─────────────────────────────────
  # Replace this with your actual application.
  your-app:
    image: your-app:latest       # ← Replace with your app image
    container_name: your-app
    # ⚠ NO ports: section — this app is NOT exposed to the internet!
    # It is only reachable through the ZTLP gateway.
    environment:
      # Your app's environment variables
      DATABASE_URL: "postgres://db:5432/app"
      RAILS_ENV: "production"
    networks:
      - internal
    restart: unless-stopped

  # ── Database (example) ───────────────────────────────────
  db:
    image: postgres:16-alpine
    container_name: your-app-db
    # ⚠ NO ports: — database only accessible on internal network
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: app
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    volumes:
      - db-data:/var/lib/postgresql/data
    networks:
      - internal
    restart: unless-stopped
    secrets:
      - db_password

networks:
  internal:
    internal: true               # No external access — isolated network

volumes:
  ns-data:
  db-data:

secrets:
  db_password:
    file: ./secrets/db_password.txt
```

### Relay Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZTLP_RELAY_PORT` | `23095` | UDP listen port |
| `ZTLP_RELAY_MAX_SESSIONS` | `10000` | Maximum concurrent forwarding sessions |
| `ZTLP_RELAY_SESSION_TIMEOUT_MS` | `300000` | Session idle timeout (5 minutes) |
| `ZTLP_RELAY_METRICS_ENABLED` | `false` | Enable Prometheus metrics |
| `ZTLP_RELAY_METRICS_PORT` | `9101` | Prometheus metrics port |
| `ZTLP_RELAY_BACKPRESSURE_SOFT_PCT` | `80` | Soft limit — begin dropping low-priority traffic |
| `ZTLP_RELAY_BACKPRESSURE_HARD_PCT` | `95` | Hard limit — reject new sessions |
| `ZTLP_LOG_FORMAT` | `text` | `text` or `json` |
| `ZTLP_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

### Deploy

```bash
cd /opt/ztlp

# Create secrets directory
mkdir -p secrets
echo "your-db-password" > secrets/db_password.txt
chmod 600 secrets/db_password.txt

# Create config directory (policy and identity from Steps 1-3)
mkdir -p config
# policy.toml and gateway-identity.json should already be here from Step 3

# Start the stack
docker compose up -d

# Check everything is healthy
docker compose ps

# Follow logs
docker compose logs -f gateway
```

### What's exposed?

After deployment, a port scan of your server shows:

| Port | Protocol | Status | Service |
|------|----------|--------|---------|
| 23095 | UDP | Open | ZTLP Gateway — encrypted, identity-required |
| 23096 | UDP | Open | ZTLP NS — rate-limited, auth-required |
| 80 | TCP | **Closed** | — |
| 443 | TCP | **Closed** | — |
| 8080 | TCP | **Closed** | Your app — internal only |
| 5432 | TCP | **Closed** | Database — internal only |

---

## Step 5: Create Admin User

Now that the infrastructure is running, create identity records for your team.

### Create the admin user

```bash
ztlp admin create-user admin@clients.techrockstars.ztlp \
  --role admin \
  --email admin@techrockstars.com \
  --ns-server YOUR_NS_SERVER_IP:23096
```

This registers a USER record in the NS server with the `admin` role.

### Available roles

| Role | Description | Typical use |
|------|-------------|-------------|
| `admin` | Full access — can create users, groups, and enrollment tokens | MSP owner, lead engineer |
| `tech` | Technician access — can connect to client services | Field technicians |
| `user` | Basic access — standard user | Customer employees, limited-access accounts |

### Verify the admin user

```bash
# Look up the user record
ztlp ns lookup admin@clients.techrockstars.ztlp --ns-server YOUR_NS_SERVER_IP:23096

# List all users in the zone
ztlp admin ls --type user --zone clients.techrockstars.ztlp --ns-server YOUR_NS_SERVER_IP:23096
```

---

## Step 6: Set Up Groups

Groups are the backbone of ZTLP access control. Instead of listing individual
identities in your policy, you list groups — then add/remove members as needed.

### Create groups

```bash
# Admins group — MSP owners and senior engineers
ztlp admin create-group admins@clients.techrockstars.ztlp \
  --description "MSP administrators — full access" \
  --ns-server YOUR_NS_SERVER_IP:23096

# Technicians group — field techs who access client systems
ztlp admin create-group techs@clients.techrockstars.ztlp \
  --description "Field technicians — service access" \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Add the admin user to groups

```bash
# Add admin to the admins group
ztlp admin group add admins@clients.techrockstars.ztlp \
  admin@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096

# Admin should also be in the techs group (admins can do everything techs can)
ztlp admin group add techs@clients.techrockstars.ztlp \
  admin@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Verify groups

```bash
# List all groups
ztlp admin groups --ns-server YOUR_NS_SERVER_IP:23096

# List members of a specific group
ztlp admin group members admins@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096

# Check if a user is in a group
ztlp admin group check admins@clients.techrockstars.ztlp \
  admin@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Update the gateway policy

Now update your `policy.toml` to use group-based access control:

```toml
# ZTLP Gateway Access Policy
# Default-deny: only explicitly allowed identities can connect.
default = "deny"

# Web application — accessible by admins and techs
[[services]]
name = "web"
allow = [
  "admins@clients.techrockstars.ztlp",
  "techs@clients.techrockstars.ztlp",
]

# SSH management — admin group only
[[services]]
name = "ssh"
allow = [
  "admins@clients.techrockstars.ztlp",
]

# Database access — admin group only
[[services]]
name = "db"
allow = [
  "admins@clients.techrockstars.ztlp",
]
```

Restart the gateway to pick up the new policy:

```bash
docker compose restart gateway
```

---

## Step 7: Enroll Technicians

### Create user accounts for technicians

For each technician on your team:

```bash
# Create Alice's user account
ztlp admin create-user alice@clients.techrockstars.ztlp \
  --role tech \
  --email alice@techrockstars.com \
  --ns-server YOUR_NS_SERVER_IP:23096

# Create Bob's user account
ztlp admin create-user bob@clients.techrockstars.ztlp \
  --role tech \
  --email bob@techrockstars.com \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Add technicians to the techs group

```bash
ztlp admin group add techs@clients.techrockstars.ztlp \
  alice@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096

ztlp admin group add techs@clients.techrockstars.ztlp \
  bob@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Generate enrollment tokens for their devices

Each technician needs to enroll their device(s). Generate single-use enrollment
tokens with a short expiry:

```bash
# Generate a single-use token that expires in 24 hours
ztlp admin enroll \
  --zone clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --relay YOUR_RELAY_IP:23095 \
  --expires 24h \
  --max-uses 1
```

This outputs a token like:

```
ztlp://enroll/AQtvZmZpY2UudGVjaHJvY2tzdGFycy56dGxw...
```

### Generate tokens with QR codes

For mobile or in-person distribution:

```bash
ztlp admin enroll \
  --zone clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --relay YOUR_RELAY_IP:23095 \
  --expires 24h \
  --max-uses 1 \
  --qr
```

This prints the token as a QR code in the terminal that can be scanned with a
phone camera.

### Generate batch tokens

For onboarding multiple technicians at once:

```bash
# Generate 10 single-use tokens, valid for 7 days
ztlp admin enroll \
  --zone clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --relay YOUR_RELAY_IP:23095 \
  --expires 7d \
  --max-uses 1 \
  --count 10
```

### Technician enrollment (on their device)

Send the token to the technician. They run:

```bash
# Install ztlp CLI (download from releases or package manager)
# Then enroll:
ztlp setup --token "ztlp://enroll/AQtvZmZpY2UudGVjaHJvY2tzdGFycy56dGxw..."
```

Or with options:

```bash
ztlp setup \
  --token "ztlp://enroll/AQtvZmZpY2UudGVjaHJvY2tzdGFycy56dGxw..." \
  --name alice-laptop.clients.techrockstars.ztlp \
  --type device \
  --owner alice@clients.techrockstars.ztlp
```

This:
1. Generates a new device identity (`~/.ztlp/identity.json`)
2. Registers the device with the NS server
3. Saves the network configuration for future connections
4. Links the device to the owner user

### Link device to user (admin-side, if not done during enrollment)

```bash
ztlp admin link-device alice-laptop.clients.techrockstars.ztlp \
  --owner alice@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Verify technician devices

```bash
# List all devices owned by alice
ztlp admin devices alice@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096

# List all devices in the zone
ztlp admin ls --type device --zone clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

---

## Step 8: Enroll Customer Devices

Customer devices (kiosks, shared workstations, IoT endpoints) follow the same
pattern but may not be linked to a specific user.

### Generate enrollment tokens for customer devices

```bash
# Short-lived tokens for on-site enrollment
ztlp admin enroll \
  --zone clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --relay YOUR_RELAY_IP:23095 \
  --expires 1h \
  --max-uses 1 \
  --qr
```

### Customer device enrollment

On the customer's device:

```bash
# Scan QR code or paste the token
ztlp setup \
  --token "ztlp://enroll/..." \
  --name kiosk-01.clients.techrockstars.ztlp \
  --type device
```

### Self-service enrollment for customer employees

For customer organizations that want to manage their own device enrollment:

1. Generate a multi-use token with longer expiry:

```bash
ztlp admin enroll \
  --zone clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --relay YOUR_RELAY_IP:23095 \
  --expires 30d \
  --max-uses 50
```

2. Share the token with the customer's IT contact.

3. They distribute it to their employees, who self-enroll with:

```bash
ztlp setup --token "ztlp://enroll/..."
```

> **⚠ Security note:** Multi-use tokens with long expiry are convenient but
> weaker. Prefer single-use tokens with 24h expiry when possible. Monitor
> enrollment activity with `ztlp admin audit`.

---

## Step 9: Verify

### Test connectivity

From an enrolled technician's device:

```bash
# Connect to the web application through ZTLP
ztlp connect gateway.clients.techrockstars.ztlp \
  --key ~/.ztlp/identity.json \
  --service web \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  -L 8080:127.0.0.1:8080
```

Then open `http://localhost:8080` in a browser — you're accessing the web app
through an encrypted ZTLP tunnel.

### Test policy enforcement

Try connecting with a device that isn't in any allowed group:

```bash
# Generate a rogue identity
ztlp keygen --output /tmp/rogue.json

# Try to connect — should be denied
ztlp connect gateway.clients.techrockstars.ztlp \
  --key /tmp/rogue.json \
  --service web \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  -L 8080:127.0.0.1:8080
# → Expected: POLICY DENIED
```

### Check the audit log

```bash
# View all identity operations from the last 24 hours
ztlp admin audit --since 24h --ns-server YOUR_NS_SERVER_IP:23096

# View audit log as JSON (for scripting/monitoring)
ztlp admin audit --since 24h --json --ns-server YOUR_NS_SERVER_IP:23096

# Filter by name pattern
ztlp admin audit --since 24h --name "alice@*" --ns-server YOUR_NS_SERVER_IP:23096
```

### Verify the full identity hierarchy

```bash
# List all entities
ztlp admin ls --ns-server YOUR_NS_SERVER_IP:23096

# List by type
ztlp admin ls --type user --ns-server YOUR_NS_SERVER_IP:23096
ztlp admin ls --type device --ns-server YOUR_NS_SERVER_IP:23096
ztlp admin ls --type group --ns-server YOUR_NS_SERVER_IP:23096

# Check group membership
ztlp admin group members techs@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Run the SSH tunnel demo (optional)

For a comprehensive end-to-end test including attack resilience:

```bash
cd demo
./ssh-tunnel-demo.sh
```

This runs a 13-act demonstration covering identity generation, policy
enforcement, tunnel throughput, port invisibility, and DDoS resistance.

---

## Day 2 Operations

### Revoke a device (stolen/lost laptop)

```bash
ztlp admin revoke laptop-01.clients.techrockstars.ztlp \
  --reason "stolen device" \
  --ns-server YOUR_NS_SERVER_IP:23096
```

This immediately:
- Registers a REVOKE record in the NS server
- Blocks future handshakes from the revoked identity
- Prevents re-registration of the revoked name
- The gateway will reject the next connection attempt

### Revoke a user (employee departure)

```bash
ztlp admin revoke alice@clients.techrockstars.ztlp \
  --reason "left company" \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Offboard an employee (complete process)

```bash
# 1. Revoke the user
ztlp admin revoke alice@clients.techrockstars.ztlp \
  --reason "left company" \
  --ns-server YOUR_NS_SERVER_IP:23096

# 2. Remove from all groups
ztlp admin group remove techs@clients.techrockstars.ztlp \
  alice@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096

# 3. Revoke all their devices
ztlp admin devices alice@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
# For each device returned:
ztlp admin revoke alice-laptop.clients.techrockstars.ztlp \
  --reason "owner offboarded" \
  --ns-server YOUR_NS_SERVER_IP:23096

# 4. Verify
ztlp admin audit --since 1h --name "alice@*" --ns-server YOUR_NS_SERVER_IP:23096
```

### Rotate the zone signing key

Rotate the zone signing key periodically (recommended: every 90 days):

```bash
ztlp admin rotate-zone-key
```

This generates a new zone signing key and re-signs all records in the zone.

### Export the zone signing key (for backup)

```bash
# Export in PEM format
ztlp admin export-zone-key --format pem

# Export in hex format
ztlp admin export-zone-key --format hex

# Export as JSON
ztlp admin export-zone-key --format pem --json
```

### Add a new device for an existing user

```bash
# Generate enrollment token
ztlp admin enroll \
  --zone clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096 \
  --relay YOUR_RELAY_IP:23095 \
  --expires 24h \
  --max-uses 1

# On the new device:
ztlp setup \
  --token "ztlp://enroll/..." \
  --name alice-phone.clients.techrockstars.ztlp \
  --type device \
  --owner alice@clients.techrockstars.ztlp

# Admin links the device (if owner wasn't specified during setup)
ztlp admin link-device alice-phone.clients.techrockstars.ztlp \
  --owner alice@clients.techrockstars.ztlp \
  --ns-server YOUR_NS_SERVER_IP:23096
```

### Monitor with audit log

Set up periodic audit checks:

```bash
# Recent activity (last hour)
ztlp admin audit --since 1h --ns-server YOUR_NS_SERVER_IP:23096

# All activity today
ztlp admin audit --since 24h --ns-server YOUR_NS_SERVER_IP:23096

# Last week
ztlp admin audit --since 7d --ns-server YOUR_NS_SERVER_IP:23096

# Filter by specific entity
ztlp admin audit --since 7d --name "alice@*" --ns-server YOUR_NS_SERVER_IP:23096

# JSON output for automated monitoring
ztlp admin audit --since 1h --json --ns-server YOUR_NS_SERVER_IP:23096
```

### System tuning for optimal performance

```bash
# Check current system settings
ztlp tune

# Apply optimal UDP buffer sizes (requires root)
sudo ztlp tune --apply

# Apply and persist across reboots
sudo ztlp tune --apply --persist
```

This increases UDP socket buffer limits (rmem_max/wmem_max) to 7 MB, matching
WireGuard's recommended configuration for high-throughput tunnels.

### Credential renewal

ZTLP identities use long-lived cryptographic keys. However, the enrollment
tokens and session keys are ephemeral:

- **Enrollment tokens** expire based on `--expires` duration
- **Session keys** are negotiated per-connection via Noise_XX (perfect forward secrecy)
- **Zone signing keys** should be rotated every 90 days with `ztlp admin rotate-zone-key`

See [docs/CREDENTIAL-RENEWAL.md](docs/CREDENTIAL-RENEWAL.md) for the
complete credential lifecycle reference.

---

## Security Checklist

Use this checklist before declaring your deployment production-ready.

### Identity & Keys

- [ ] Zone signing key stored securely (not in Docker image, not in git)
- [ ] Zone signing key backed up offline (hardware security module or encrypted USB)
- [ ] `ZTLP_NS_REQUIRE_REGISTRATION_AUTH` set to `true` (prevents unsigned record creation)
- [ ] All records signed with zone key
- [ ] Admin identity key file has `0600` permissions
- [ ] Zone signing key rotation scheduled (every 90 days)

### Access Control

- [ ] Gateway policy is **default-deny** (`default = "deny"` in policy.toml)
- [ ] Services are explicitly listed with allowed groups/identities
- [ ] No wildcard allow rules in production
- [ ] Group membership regularly audited
- [ ] Former employees/contractors revoked

### Enrollment

- [ ] Enrollment tokens are **single-use** (`--max-uses 1`)
- [ ] Enrollment tokens have **short TTL** (`--expires 24h` or less for individuals)
- [ ] Multi-use tokens (for batch enrollment) are monitored and expired promptly
- [ ] Token distribution uses secure channels (not plaintext email)

### Network

- [ ] NS server not exposed to public internet (or behind firewall with IP allowlist)
- [ ] Only UDP ports 23095 (gateway) and 23096 (NS) are open
- [ ] All HTTP/TCP ports for backend apps are **firewalled or unexposed**
- [ ] Internal Docker network used (`internal: true`)
- [ ] Prometheus metrics ports (9101-9103) only accessible from monitoring network

### Revocation

- [ ] Revocation checked on every connection (gateway queries NS for REVOKE records)
- [ ] Stolen/lost device revocation procedure documented and tested
- [ ] Employee offboarding procedure includes ZTLP identity revocation

### Monitoring

- [ ] Audit log reviewed regularly (`ztlp admin audit --since 24h`)
- [ ] Prometheus metrics collected (gateway sessions, NS queries, relay traffic)
- [ ] Alerting configured for:
  - [ ] High session count (approaching `ZTLP_GATEWAY_MAX_SESSIONS`)
  - [ ] Failed authentication attempts
  - [ ] Policy denial spikes
  - [ ] NS server unreachable from gateway

### Operational

- [ ] Docker containers set to `restart: unless-stopped`
- [ ] Resource limits set for all containers (`deploy.resources.limits`)
- [ ] Health checks configured for all services
- [ ] Log aggregation configured (`ZTLP_LOG_FORMAT=json` for structured logging)
- [ ] Backup strategy for NS data volume
- [ ] Disaster recovery procedure documented

---

## Troubleshooting

### Connection refused / timeout

**Symptom:** `ztlp connect` hangs or times out.

**Check:**
```bash
# Is the gateway running?
docker compose ps gateway

# Can you reach the gateway port?
nc -zu GATEWAY_IP 23095 && echo "reachable" || echo "blocked"

# Is the NS server reachable?
ztlp ns lookup gateway.clients.techrockstars.ztlp --ns-server NS_IP:23096
```

**Common causes:**
- Firewall blocking UDP port 23095
- Gateway not bound to the correct interface
- NS server down → name resolution fails

### Policy denied

**Symptom:** `POLICY DENIED: <identity> denied access to service '<name>'`

**Check:**
```bash
# Is the user in the correct group?
ztlp admin group check techs@clients.techrockstars.ztlp \
  alice@clients.techrockstars.ztlp \
  --ns-server NS_IP:23096

# Is the group listed in the policy?
cat /opt/ztlp/config/policy.toml

# Is the user's identity correctly registered?
ztlp admin ls --type user --zone clients.techrockstars.ztlp \
  --ns-server NS_IP:23096
```

**Common causes:**
- User not added to the group referenced in policy
- Policy file uses incorrect group name
- Gateway hasn't reloaded the policy (restart gateway)
- User's device identity doesn't match what NS has registered

### Handshake failed

**Symptom:** `handshake failed: no HELLO_ACK after retransmits`

**Check:**
```bash
# Test raw UDP connectivity
ztlp ping GATEWAY_IP:23095 --count 3

# Check gateway logs
docker compose logs gateway | tail -20
```

**Common causes:**
- UDP packets being silently dropped by an intermediate firewall
- Gateway overloaded (check `ZTLP_GATEWAY_MAX_SESSIONS`)
- Identity key file corrupt or wrong format

### NS lookup fails

**Symptom:** `could not resolve 'name': no SVC record in ZTLP-NS`

**Check:**
```bash
# Direct NS query
ztlp ns lookup name.zone.ztlp --ns-server NS_IP:23096

# Check NS health
docker inspect --format='{{.State.Health.Status}}' ztlp-ns

# Check NS logs
docker compose logs ns | tail -20
```

**Common causes:**
- NS server not running or unhealthy
- Record not registered (run `ztlp ns register` first)
- Wrong NS server address in `--ns-server` flag
- Registration auth enabled but record wasn't signed

### Enrollment token rejected

**Symptom:** `ztlp setup --token ...` fails during enrollment.

**Common causes:**
- Token expired (check `--expires` duration)
- Token already used (single-use tokens consumed after first use)
- NS server address in token is unreachable from client network
- Zone enrollment secret mismatch (re-run `ztlp admin init-zone`)

### Gateway can't reach backend

**Symptom:** Clients connect to gateway but get no response from the web app.

**Check:**
```bash
# Is the backend running?
docker compose ps your-app

# Can the gateway reach the backend on the internal network?
docker compose exec gateway curl -s http://your-app:8080/ || echo "unreachable"

# Are they on the same Docker network?
docker network inspect ztlp_internal
```

**Common causes:**
- Backend container not running or unhealthy
- Gateway and backend not on the same Docker network
- Wrong `ZTLP_GATEWAY_BACKEND_HOST` or `ZTLP_GATEWAY_BACKEND_PORT`

### Performance issues

**Symptom:** High latency or low throughput through the tunnel.

**Fix:**
```bash
# Check and apply system tuning
ztlp tune

# Apply optimal settings
sudo ztlp tune --apply --persist
```

This increases UDP socket buffer sizes. Also check:
- Gateway CPU/memory usage (`docker stats ztlp-gateway`)
- Network bandwidth between client and gateway
- Backend application response time (the bottleneck may not be ZTLP)

---

## Quick Reference

### Identity Management

```bash
# Generate identity
ztlp keygen --output ~/.ztlp/identity.json
ztlp keygen --output identity.json --format hex

# Register with NS
ztlp ns register --name NAME --zone ZONE --key KEY_FILE --ns-server NS --address ADDR
ztlp ns lookup NAME --ns-server NS
ztlp ns pubkey PUBLIC_KEY_HEX --ns-server NS
```

### Admin — Users

```bash
ztlp admin create-user NAME --role admin|tech|user [--email EMAIL] [--ns-server NS]
ztlp admin ls --type user [--zone ZONE] [--ns-server NS] [--json]
ztlp admin devices USER_NAME [--ns-server NS] [--json]
ztlp admin link-device DEVICE_NAME --owner USER_NAME [--ns-server NS]
ztlp admin revoke NAME --reason "REASON" [--ns-server NS]
```

### Admin — Groups

```bash
ztlp admin create-group NAME [--description DESC] [--ns-server NS]
ztlp admin groups [--ns-server NS] [--json]
ztlp admin group add GROUP MEMBER [--ns-server NS]
ztlp admin group remove GROUP MEMBER [--ns-server NS]
ztlp admin group members GROUP [--ns-server NS] [--json]
ztlp admin group check GROUP USER [--ns-server NS]
```

### Admin — Zones & Enrollment

```bash
ztlp admin init-zone --zone ZONE [--secret-output PATH]
ztlp admin enroll --zone ZONE --ns-server NS --relay RELAY [--gateway GW] \
  [--expires 24h] [--max-uses 1] [--count N] [--qr] [--secret PATH]
ztlp admin rotate-zone-key [--json]
ztlp admin export-zone-key [--format pem|hex] [--json]
```

### Admin — Monitoring

```bash
ztlp admin audit [--since 24h] [--name "pattern*"] [--ns-server NS] [--json]
ztlp admin ls [--type device|user|key|group] [--zone ZONE] [--ns-server NS] [--json]
```

### Connectivity

```bash
# Connect to a service via gateway
ztlp connect TARGET --key KEY_FILE --service SERVICE --ns-server NS \
  [-L LOCAL_PORT:REMOTE_HOST:REMOTE_PORT]

# Listen for connections (gateway mode)
ztlp listen --bind 0.0.0.0:23095 --key KEY_FILE --gateway \
  --forward SERVICE:HOST:PORT [--forward SERVICE2:HOST2:PORT2] \
  --policy POLICY_FILE --ns-server NS --max-sessions N

# Ping a ZTLP endpoint
ztlp ping TARGET [--ns-server NS] [--count N] [--interval MS]

# SSH ProxyCommand
ztlp proxy HOSTNAME PORT [--key KEY_FILE] [--ns-server NS]

# Start relay
ztlp relay start [--bind 0.0.0.0:23095] [--max-sessions 10000]
ztlp relay status [--target ADDR]
```

### Setup & Enrollment

```bash
# Interactive setup wizard
ztlp setup

# Enroll with token
ztlp setup --token "ztlp://enroll/..." [--name NAME] [--type device|user] [--owner OWNER] [-y]
```

### System

```bash
# Check/apply performance tuning
ztlp tune
sudo ztlp tune --apply [--persist]

# Packet inspection
ztlp inspect HEX_BYTES
ztlp inspect --file capture.bin

# Token operations
ztlp token inspect HEX
ztlp token verify HEX --secret SECRET_HEX
ztlp token issue --node-id NODE_ID --secret SECRET [--ttl SECS]

# Agent daemon
ztlp agent start [--foreground] [--config PATH]
ztlp agent stop
ztlp agent status
ztlp agent tunnels
ztlp agent dns
ztlp agent flush-dns
sudo ztlp agent dns-setup [--zones ZONE1,ZONE2]
sudo ztlp agent dns-teardown
sudo ztlp agent install [--binary PATH]

# Service status
ztlp status [--target ADDR]
```

### SSH Integration

Configure SSH to use ZTLP automatically by adding to `~/.ssh/config`:

```
Host *.ztlp
    ProxyCommand ztlp proxy %h %p
```

Then connect as usual:

```bash
ssh user@server.clients.techrockstars.ztlp
```

### Config File

ZTLP reads optional config from `~/.ztlp/config.toml`:

```toml
# Default identity file
identity = "~/.ztlp/identity.json"

# Default NS server
ns_server = "10.0.0.5:23096"

# Default gateway
gateway = "10.0.0.5:23095"

# Default relay
relay = "10.0.0.5:23095"

[transport]
# GSO mode: "auto", "enabled", or "disabled"
gso = "auto"
```

---

## Appendix A: Complete MSP Deployment Script

Here's a condensed script that performs the entire setup. Replace the
placeholder values with your actual configuration.

```bash
#!/usr/bin/env bash
set -euo pipefail

# ─── Configuration ─────────────────────────────────────────
ZONE="clients.techrockstars.ztlp"
NS_SERVER="10.0.0.5:23096"
RELAY_ADDR="10.0.0.5:23095"
GATEWAY_ADDR="10.0.0.5:23095"
CONFIG_DIR="/opt/ztlp/config"

# ─── Step 1: Initialize zone ──────────────────────────────
echo "→ Initializing zone: $ZONE"
ztlp admin init-zone --zone "$ZONE" --secret-output "$CONFIG_DIR/zone.key"

# ─── Step 2: Generate gateway identity ────────────────────
echo "→ Generating gateway identity"
ztlp keygen --output "$CONFIG_DIR/gateway-identity.json"

# ─── Step 3: Register gateway with NS ────────────────────
echo "→ Registering gateway"
ztlp ns register \
  --name "gateway.$ZONE" \
  --zone "$ZONE" \
  --key "$CONFIG_DIR/gateway-identity.json" \
  --address "$GATEWAY_ADDR" \
  --ns-server "$NS_SERVER"

# ─── Step 4: Create admin user ───────────────────────────
echo "→ Creating admin user"
ztlp admin create-user "admin@$ZONE" \
  --role admin \
  --email admin@techrockstars.com \
  --ns-server "$NS_SERVER"

# ─── Step 5: Create groups ───────────────────────────────
echo "→ Creating groups"
ztlp admin create-group "admins@$ZONE" \
  --description "MSP administrators" \
  --ns-server "$NS_SERVER"

ztlp admin create-group "techs@$ZONE" \
  --description "Field technicians" \
  --ns-server "$NS_SERVER"

# ─── Step 6: Assign admin to groups ──────────────────────
echo "→ Assigning admin to groups"
ztlp admin group add "admins@$ZONE" "admin@$ZONE" --ns-server "$NS_SERVER"
ztlp admin group add "techs@$ZONE" "admin@$ZONE" --ns-server "$NS_SERVER"

# ─── Step 7: Create policy ───────────────────────────────
echo "→ Writing access policy"
cat > "$CONFIG_DIR/policy.toml" << EOF
default = "deny"

[[services]]
name = "web"
allow = ["admins@$ZONE", "techs@$ZONE"]

[[services]]
name = "ssh"
allow = ["admins@$ZONE"]
EOF

# ─── Step 8: Generate enrollment token ───────────────────
echo "→ Generating enrollment token"
ztlp admin enroll \
  --zone "$ZONE" \
  --ns-server "$NS_SERVER" \
  --relay "$RELAY_ADDR" \
  --expires 24h \
  --max-uses 1

# ─── Step 9: Start services ──────────────────────────────
echo "→ Starting Docker Compose stack"
docker compose up -d

echo ""
echo "✓ ZTLP deployment complete!"
echo "  Zone:    $ZONE"
echo "  NS:      $NS_SERVER"
echo "  Gateway: $GATEWAY_ADDR"
echo ""
echo "Next steps:"
echo "  1. Distribute enrollment tokens to technicians"
echo "  2. Enroll technician devices: ztlp setup --token <token>"
echo "  3. Test connectivity: ztlp connect gateway.$ZONE --service web"
echo "  4. Review audit log: ztlp admin audit --since 1h"
```

---

## Appendix B: Multi-Client Architecture

For MSPs managing multiple clients, create separate zones per client:

```
techrockstars.ztlp
├── acme.techrockstars.ztlp      ← ACME Corp
│   ├── admins@acme.techrockstars.ztlp
│   ├── techs@acme.techrockstars.ztlp
│   └── devices...
├── bigco.techrockstars.ztlp     ← BigCo Inc
│   ├── admins@bigco.techrockstars.ztlp
│   ├── techs@bigco.techrockstars.ztlp
│   └── devices...
└── internal.techrockstars.ztlp  ← Your own internal network
    ├── admins@internal.techrockstars.ztlp
    └── devices...
```

Each client zone has:
- Its own NS registration (can share the NS server)
- Its own gateway and policy
- Its own enrollment tokens
- Isolated identity namespace — ACME users can't access BigCo services

### Per-client Docker Compose

For each client, deploy a separate gateway:

```yaml
services:
  gateway-acme:
    image: ztlp/gateway:latest
    ports:
      - "23100:23095/udp"
    environment:
      ZTLP_GATEWAY_BACKEND_HOST: "acme-app"
      ZTLP_GATEWAY_BACKEND_PORT: "8080"
    volumes:
      - ./acme/policy.toml:/etc/ztlp/policy.toml:ro

  gateway-bigco:
    image: ztlp/gateway:latest
    ports:
      - "23101:23095/udp"
    environment:
      ZTLP_GATEWAY_BACKEND_HOST: "bigco-app"
      ZTLP_GATEWAY_BACKEND_PORT: "8080"
    volumes:
      - ./bigco/policy.toml:/etc/ztlp/policy.toml:ro
```

---

*For the complete identity model reference, see [IDENTITY.md](IDENTITY.md).*  
*For credential lifecycle details, see [docs/CREDENTIAL-RENEWAL.md](docs/CREDENTIAL-RENEWAL.md).*  
*For the demo walkthrough, see [demo/README.md](demo/README.md).*
