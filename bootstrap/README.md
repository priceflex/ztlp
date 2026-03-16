# ZTLP Bootstrap Server

Web-based control plane for deploying [ZTLP (Zero Trust Layer Protocol)](https://github.com/priceflex/ztlp) across distributed machines.

## What It Does

1. **Create networks** — Define ZTLP zones with enrollment secrets
2. **Add machines** — Register servers with SSH credentials (encrypted at rest)
3. **Assign roles** — NS, Relay, and/or Gateway per machine
4. **Deploy** — SSH into machines, install Docker, pull ZTLP images, generate configs, start containers
5. **Enroll devices** — Generate enrollment tokens with QR codes for `ztlp setup --token`
6. **Monitor** — Health checks, deployment logs, audit trail

## Stack

- **Ruby on Rails 7.1** with SQLite
- **Hotwire (Turbo + Stimulus)** for live updates
- **Tailwind CSS** via CDN
- **net-ssh** for SSH provisioning
- **rqrcode** for QR code generation
- Active Record Encryption for SSH keys at rest

## Quick Start

```bash
bundle install
bin/rails db:create db:migrate
bin/rails server
```

Visit `http://localhost:3000`

## Architecture

```
Network (zone + secrets)
  └── Machine (hostname, IP, SSH creds, roles)
  │     └── Deployment (component, status, log, container ID)
  │     └── HealthCheck (per-component status, metrics, container state)
  │     └── Gateway Sidecar (ZTLP-native metrics access)
  └── EnrollmentToken (URI, QR, usage tracking)
  └── Identity (ZtlpUser, ZtlpGroup, ZtlpDevice)

AuditLog + Alert (all actions tracked, status change alerts)
```

### Services

- **SshProvisioner** — SSH into machines, install Docker, deploy components + gateway sidecars, generate configs
- **HealthChecker** — Container status, port checks, Prometheus metrics (via ZTLP tunnel or SSH fallback), resource usage
- **ZtlpTunnel** — Opens encrypted ZTLP tunnels to gateway sidecars for metrics collection (dogfooding)
- **ZtlpConnectivity** — Handshake-only connectivity check (green/yellow/red dots on dashboard)
- **TokenGenerator** — Creates enrollment tokens with QR codes

### ZTLP Components

| Component | Container | Ports | Gateway Sidecar |
|-----------|-----------|-------|-----------------|
| NS | ztlp-ns | 23096/udp, 9103/tcp (metrics) | :23098/udp |
| Relay | ztlp-relay | 23095/udp, 23096/udp (mesh), 9101/tcp (metrics) | :23099/udp |
| Gateway | ztlp-gateway | 23098/tcp, 9102/tcp (metrics) | — (is the gateway) |

> **Note:** Relay uses a different sidecar port (23099) than NS (23098) to avoid
> HELLO routing ambiguity. See [docs/ZTLP-TUNNEL-ARCHITECTURE.md](docs/ZTLP-TUNNEL-ARCHITECTURE.md)
> for the full explanation.

## Tests

```bash
bin/rails test
# 543 tests, ~1467 assertions
```

## Build Phases

- [x] **Phase A** — Rails scaffold, models, SSH provisioner, controllers, views, tests
- [ ] **Phase B** — Web UI wizard with Turbo Streams for live deploy logs
- [ ] **Phase C** — Health monitoring dashboard, periodic checks

## Security

- SSH private keys encrypted at rest via Active Record Encryption
- Keys only decrypted in memory during SSH sessions
- Full audit log of every action (SSH connections, deploys, token generation)
- Docker images from `priceflex/ztlp-*` registry

## License

Copyright © 2026 Tech Rockstars / ZTLP.org. All rights reserved.
