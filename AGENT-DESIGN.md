# ZTLP Agent — Design Document

**Date:** 2026-03-13
**Status:** Ready for implementation
**Scope:** Background daemon with DNS resolver, TCP proxy, SSH integration, credential renewal

---

## Table of Contents

1. [Overview](#1-overview)
2. [User Experience](#2-user-experience)
3. [Architecture](#3-architecture)
4. [DNS Resolver](#4-dns-resolver)
5. [Custom Domain Support](#5-custom-domain-support)
6. [TCP Proxy & Tunnel Manager](#6-tcp-proxy--tunnel-manager)
7. [SSH ProxyCommand](#7-ssh-proxycommand)
8. [Credential Renewal](#8-credential-renewal)
9. [Configuration](#9-configuration)
10. [CLI Interface](#10-cli-interface)
11. [Systemd Integration](#11-systemd-integration)
12. [Wire Protocol Extensions](#12-wire-protocol-extensions)
13. [Implementation Phases](#13-implementation-phases)
14. [File Layout](#14-file-layout)

---

## 1. Overview

The ZTLP Agent is a background daemon that makes ZTLP connections seamless and transparent. Instead of manually running `ztlp connect` with IP addresses and port forwards, users simply use ZTLP names (or custom domain names) as if they were regular hostnames:

```bash
ssh user@myserver.corp.ztlp
curl https://webapp.corp.ztlp
psql -h db.corp.ztlp
scp file.txt user@nas.internal.techrockstars.com:~/
```

The agent handles DNS resolution, tunnel establishment, authentication, encryption, policy enforcement, and credential lifecycle — all transparently.

### Design Principles

- **Zero-config after enrollment** — `ztlp setup` + `ztlp agent start` and you're done
- **Works with any TCP application** — not just SSH
- **Custom domains** — companies use their own domain names, ZTLP handles identity underneath
- **Auto-reconnect** — tunnels recover from network changes (Wi-Fi→cellular, IP changes)
- **Credential lifecycle** — auto-renew certs, refresh NS records, rotate keys
- **Minimal privileges** — runs as unprivileged user (DNS on 127.0.0.53:5353, no TUN required)
- **Pure Rust** — single binary, no external dependencies at runtime

---

## 2. User Experience

### First-time setup

```bash
# Enroll the device (interactive or with token)
ztlp setup --token ztlp://enroll/AQtvZm...

# Start the agent
ztlp agent start

# That's it. Everything works now.
```

### Daily usage

```bash
# SSH into a server by ZTLP name
ssh admin@fileserver.techrockstars.ztlp

# SSH into a server by custom domain
ssh admin@fileserver.internal.techrockstars.com

# Copy files
scp report.pdf admin@nas.corp.ztlp:~/documents/

# Connect to a database
psql -h db.corp.ztlp -U app

# HTTP requests
curl https://dashboard.corp.ztlp/api/status

# Check tunnel status
ztlp agent status
```

### What happens under the hood (SSH example)

```
1. User runs: ssh admin@fileserver.techrockstars.ztlp
2. SSH resolves hostname → hits agent's DNS resolver (127.0.0.53)
3. Agent queries ZTLP-NS for "fileserver.techrockstars.ztlp"
4. NS returns: NodeID, X25519 pubkey, endpoints (IP:port)
5. Agent allocates virtual IP (e.g. 127.100.0.1) → maps to ZTLP tunnel
6. DNS returns 127.100.0.1 to SSH
7. SSH connects to 127.100.0.1:22
8. Agent intercepts → establishes Noise_XX tunnel to fileserver
9. Policy check: is this node allowed to reach fileserver's SSH?
10. Tunnel established → TCP traffic flows encrypted through ZTLP
11. SSH session works normally (authentication, shell, etc.)
```

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     ztlp-agent                          │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ DNS Resolver  │  │  TCP Proxy   │  │   Renewal    │  │
│  │ 127.0.0.53   │  │  (listener)  │  │   Daemon     │  │
│  │ :5353 (UDP)   │  │              │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                  │          │
│  ┌──────┴─────────────────┴──────────────────┴───────┐  │
│  │              Tunnel Manager                       │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐             │  │
│  │  │Tunnel #1│ │Tunnel #2│ │Tunnel #3│  ...         │  │
│  │  │ peer A  │ │ peer B  │ │ peer C  │              │  │
│  │  └─────────┘ └─────────┘ └─────────┘             │  │
│  └───────────────────────┬───────────────────────────┘  │
│                          │                              │
│  ┌───────────────────────┴───────────────────────────┐  │
│  │              NS Client (cached)                   │  │
│  │  ZTLP-NS queries, name resolution, pubkey lookup  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
         │                    │
    UDP :23095           UDP :23096
    (ZTLP tunnels)       (NS queries)
         │                    │
    ┌────┴────┐          ┌────┴────┐
    │  Peers  │          │  NS     │
    │ Relays  │          │ Servers │
    │Gateways │          │         │
    └─────────┘          └─────────┘
```

### Components

| Component | Responsibility |
|-----------|---------------|
| **DNS Resolver** | Intercepts `*.ztlp` and custom domain queries, returns virtual IPs |
| **TCP Proxy** | Listens on virtual IPs, forwards TCP connections through ZTLP tunnels |
| **Tunnel Manager** | Establishes, maintains, and pools ZTLP tunnels to peers |
| **NS Client** | Resolves ZTLP names to NodeIDs/endpoints, caches with TTL |
| **Renewal Daemon** | Auto-renews certificates, refreshes NS records, rotates keys |
| **Config Watcher** | Watches `agent.toml` for changes, hot-reloads |

---

## 4. DNS Resolver

### Binding

The agent runs a lightweight DNS server on `127.0.0.53:5353` (UDP + TCP).

**Why 5353?** Port 53 requires root. Using 5353 keeps the agent unprivileged. The system's `/etc/resolv.conf` or systemd-resolved is configured to use the agent for ZTLP zones only.

### Resolution flow

```
Query: fileserver.techrockstars.ztlp A?
  │
  ├─ Is it a *.ztlp name?
  │   YES → Query ZTLP-NS
  │         ├─ Found → Allocate virtual IP, return A record
  │         └─ Not found → Return NXDOMAIN
  │
  ├─ Is it a custom domain (matches dns.zones config)?
  │   YES → Map to ZTLP zone (via dns.domain_map)
  │         → Query ZTLP-NS for mapped name
  │         ├─ Found → Allocate virtual IP, return A record
  │         └─ Not found → Return NXDOMAIN
  │
  └─ Neither → Forward to upstream DNS (system default)
```

### Virtual IP allocation

The agent maintains a pool of virtual IPs in the `127.0.0.0/8` loopback range (or optionally `100.64.0.0/10` CGNAT range):

```
127.100.0.1  ←→  fileserver.techrockstars.ztlp
127.100.0.2  ←→  db.techrockstars.ztlp
127.100.0.3  ←→  nas.acme.techrockstars.ztlp
```

- Virtual IPs are allocated on first DNS query and cached with the NS record TTL
- The TCP proxy listens on each allocated virtual IP
- When the TTL expires and no active tunnels exist, the IP is released back to the pool
- Pool range is configurable (default: `127.100.0.0/16` = 65,534 addresses)

### DNS record types

| Query Type | Response |
|-----------|----------|
| A | Virtual IPv4 from pool |
| AAAA | Not supported initially (IPv4-mapped IPv6 possible later) |
| SRV | If ZTLP-NS has service records, return port info |
| TXT | ZTLP metadata (NodeID, zone, capabilities) |
| Any other | NXDOMAIN or forward upstream |

### System DNS integration

**Option 1: systemd-resolved (recommended for Linux)**
```bash
# /etc/systemd/resolved.conf.d/ztlp.conf
[Resolve]
DNS=127.0.0.53:5353
Domains=~ztlp ~internal.techrockstars.com
```

**Option 2: /etc/resolv.conf (simple)**
```
# Managed by ztlp-agent
nameserver 127.0.0.53
```

**Option 3: NetworkManager**
```bash
nmcli connection modify <conn> ipv4.dns "127.0.0.53"
nmcli connection modify <conn> ipv4.dns-search "ztlp"
```

**macOS:**
```bash
# /etc/resolver/ztlp
nameserver 127.0.0.53
port 5353
```

The `ztlp agent start` command auto-configures the appropriate method and `ztlp agent stop` restores the original config.

---

## 5. Custom Domain Support

### The problem

Companies want to use their own domains, not `*.ztlp`. A managed IT provider like Tech Rockstars wants:

```
fileserver.internal.techrockstars.com  (not fileserver.techrockstars.ztlp)
dc1.internal.acmecorp.com             (not dc1.acme.techrockstars.ztlp)
```

### Solution: Zone mapping

The agent maps custom domain suffixes to ZTLP zones:

```toml
[dns.domain_map]
"internal.techrockstars.com" = "techrockstars.ztlp"
"vpn.acmecorp.com" = "acme.techrockstars.ztlp"
```

**Resolution:**
```
fileserver.internal.techrockstars.com
  → strip "internal.techrockstars.com"
  → prefix = "fileserver"
  → ZTLP name = "fileserver.techrockstars.ztlp"
  → Query ZTLP-NS
```

### DNS TXT discovery (automatic mapping)

Companies can publish a TXT record in public DNS to enable automatic discovery:

```dns
_ztlp.internal.techrockstars.com  IN TXT  "v=ztlp1 zone=techrockstars.ztlp ns=ns.techrockstars.com:23096"
```

When the agent encounters an unknown domain, it checks for a `_ztlp` TXT record:

```
1. Query: server1.unknown-company.com
2. Agent checks: not in dns.zones, not in dns.domain_map
3. Agent queries public DNS: _ztlp.unknown-company.com TXT?
4. Gets: "v=ztlp1 zone=corp.unknown-company.ztlp ns=203.0.113.5:23096"
5. Now knows: strip "unknown-company.com", use zone "corp.unknown-company.ztlp"
6. Queries the discovered NS server
7. Caches the mapping for future lookups
```

This means a new client just adds a TXT record to their DNS and all ZTLP agents can discover them automatically.

### MSP multi-tenant example

Tech Rockstars manages 50 clients. Each client gets:

```toml
# Steve's agent config (manages all clients)
[dns.domain_map]
"internal.techrockstars.com" = "techrockstars.ztlp"
"internal.acmecorp.com" = "acme.techrockstars.ztlp"
"internal.widgetinc.com" = "widget.techrockstars.ztlp"
"internal.biglaw.com" = "biglaw.techrockstars.ztlp"
# ... 50 clients
```

Or with TXT discovery, Steve just adds `_ztlp` records to each client's DNS and the agent auto-discovers all of them.

**Client employees** only see their own domain:
```toml
# Acme Corp employee's agent config
[dns.domain_map]
"internal.acmecorp.com" = "acme.techrockstars.ztlp"
```

They type `ssh user@fileserver.internal.acmecorp.com` and it just works. They never see or know about `techrockstars.ztlp`.

---

## 6. TCP Proxy & Tunnel Manager

### TCP Proxy

For each virtual IP allocated by the DNS resolver, the agent spawns a TCP listener:

```
127.100.0.1:* → Tunnel to fileserver.techrockstars.ztlp
127.100.0.2:* → Tunnel to db.techrockstars.ztlp
```

The proxy accepts any TCP connection to the virtual IP on any port. The destination port is forwarded transparently through the ZTLP tunnel.

**Connection flow:**
```
1. App connects to 127.100.0.1:22 (SSH)
2. TCP proxy accepts the connection
3. Looks up 127.100.0.1 → fileserver.techrockstars.ztlp
4. Asks Tunnel Manager for a tunnel to that peer
5. Sends service request: "forward TCP port 22"
6. Bidirectional pipe: App ←TCP→ Proxy ←ZTLP→ Peer ←TCP→ Service
```

### Tunnel Manager

Manages the lifecycle of ZTLP tunnels:

- **On-demand creation** — tunnels are established when first needed
- **Connection pooling** — multiple TCP connections to the same peer share one ZTLP tunnel (multiplexed via FRAME_RESET stream IDs)
- **Idle timeout** — tunnels with no active streams close after configurable timeout (default: 5 minutes)
- **Auto-reconnect** — if a tunnel drops, retry with exponential backoff (1s, 2s, 4s, ... 60s max)
- **Health monitoring** — periodic keepalive pings, detect dead tunnels early
- **Relay fallback** — if direct connection fails, try via relay mesh

**Tunnel states:**
```
Idle → Connecting → Handshaking → Active → Draining → Closed
                                    ↓
                               Reconnecting (on failure)
```

### Stream multiplexing

Multiple TCP connections through one ZTLP tunnel use stream IDs:

```
Stream 0: SSH session (port 22)
Stream 1: SCP transfer (port 22, second connection)
Stream 2: HTTPS request (port 443)
```

Each stream maps to a TCP connection on both sides. The existing FRAME_RESET mechanism (0x04) is extended to support stream open/close.

---

## 7. SSH ProxyCommand

For immediate SSH integration without the full DNS/proxy stack:

```bash
# ~/.ssh/config
Host *.ztlp
    ProxyCommand ztlp proxy %h %p

Host *.internal.techrockstars.com
    ProxyCommand ztlp proxy %h %p
```

### `ztlp proxy` command

A lightweight stdin/stdout proxy for use as SSH ProxyCommand:

```bash
ztlp proxy fileserver.techrockstars.ztlp 22
```

1. Resolves the ZTLP name (via NS or agent's cache)
2. Establishes Noise_XX tunnel
3. Requests TCP forward to port 22
4. Pipes stdin/stdout through the tunnel
5. Exits when the connection closes

**Advantages:**
- Works immediately, no DNS resolver needed
- No virtual IPs, no TCP proxy
- SSH handles all the multiplexing (SSH channels)

**Limitations:**
- SSH only (not generic TCP)
- New handshake per SSH connection (no pooling)
- Requires SSH config entry

### Agent-aware mode

When the agent is running, `ztlp proxy` connects through the agent's tunnel manager instead of establishing its own tunnel:

```
ztlp proxy --agent fileserver.techrockstars.ztlp 22
```

This reuses existing tunnels and benefits from connection pooling.

---

## 8. Credential Renewal

The agent handles all credential lifecycle automatically:

### Certificate renewal

```
Certificate lifetime: 90 days (configurable)
Renewal window: opens at 1/3 (30 days), recommended at 2/3 (60 days)
Check interval: 1 hour

1. Agent checks cert expiry on startup and every hour
2. When cert is in renewal window → send RENEW (0x09) to NS
3. NS verifies current cert is valid + not revoked
4. NS issues new cert with fresh expiry
5. Agent saves new cert, continues using it
6. If renewal fails → retry with backoff, warn at 80% lifetime, error at 90%
```

### NS record refresh

```
KEY record TTL: 86,400s (24h)
SVC record TTL: 86,400s (24h)
Refresh at: 75% of TTL (±10% jitter to prevent thundering herd)

1. Agent re-publishes its KEY and SVC records before TTL expiry
2. Signed with current Ed25519 key
3. Jitter prevents all nodes refreshing simultaneously
```

### Session key rotation

```
Session keys: derived during Noise_XX, valid for 24h
Rotation: ratchet new keys using HKDF over existing session + fresh entropy

1. For long-lived tunnels (>24h), initiate key rotation
2. Both sides derive new keys from existing session
3. Seamless transition, no tunnel interruption
```

---

## 9. Configuration

### `~/.ztlp/agent.toml`

```toml
# ═══════════════════════════════════════════════════════════
# ZTLP Agent Configuration
# ═══════════════════════════════════════════════════════════

[identity]
# Path to identity file (created by `ztlp setup`)
path = "~/.ztlp/identity.json"

# ── DNS Resolver ──────────────────────────────────────────

[dns]
# Listen address for DNS resolver
listen = "127.0.0.53:5353"

# Enable DNS resolver (disable if using ProxyCommand only)
enabled = true

# Upstream DNS for non-ZTLP queries
upstream = "1.1.1.1:53"

# Virtual IP pool for ZTLP hosts
vip_range = "127.100.0.0/16"

# ZTLP zones to handle (*.ztlp is always included)
zones = [
    "internal.techrockstars.com",
    "vpn.acmecorp.com",
]

# Auto-discover ZTLP zones via _ztlp TXT records
auto_discover = true

# Map custom domains to ZTLP zones
[dns.domain_map]
"internal.techrockstars.com" = "techrockstars.ztlp"
"vpn.acmecorp.com" = "acme.techrockstars.ztlp"

# ── Namespace Servers ─────────────────────────────────────

[ns]
# Primary NS server (auto-discovered from enrollment if not set)
servers = ["ns.techrockstars.com:23096"]

# Query timeout
timeout_ms = 2000

# Cache TTL override (0 = use record TTL)
cache_ttl_override = 0

# ── Tunnels ───────────────────────────────────────────────

[tunnel]
# Local bind address for ZTLP UDP
bind = "0.0.0.0:0"

# Idle tunnel timeout (close tunnels with no active streams)
idle_timeout = "5m"

# Keepalive interval
keepalive_interval = "30s"

# Auto-reconnect on tunnel failure
auto_reconnect = true

# Reconnect backoff (initial, max)
reconnect_backoff_initial = "1s"
reconnect_backoff_max = "60s"

# Prefer relay (always route through relay, even if direct is possible)
prefer_relay = false

# Relay servers (auto-discovered from NS if not set)
relays = []

# Maximum concurrent tunnels
max_tunnels = 256

# ── Credential Renewal ────────────────────────────────────

[renewal]
# Enable automatic credential renewal
enabled = true

# Check interval
check_interval = "1h"

# Certificate renewal threshold (fraction of lifetime)
cert_threshold = 0.67

# NS record refresh at fraction of TTL
ns_refresh_threshold = 0.75

# Jitter ratio for NS refresh (prevents thundering herd)
ns_refresh_jitter = 0.10

# ── Logging ───────────────────────────────────────────────

[log]
# Log level: error, warn, info, debug, trace
level = "info"

# Log file (empty = stderr)
file = "~/.ztlp/agent.log"

# Structured JSON logging
json = false

# ── Health Reporting ──────────────────────────────────────

[health]
# Report to bootstrap server (optional)
enabled = false
bootstrap_url = ""
report_interval = "5m"
```

---

## 10. CLI Interface

### Agent management

```bash
# Start the agent (daemonizes by default)
ztlp agent start
ztlp agent start --foreground    # stay in foreground (for systemd)

# Stop the agent
ztlp agent stop

# Restart
ztlp agent restart

# Status — shows tunnels, DNS cache, credentials
ztlp agent status

# Detailed tunnel info
ztlp agent tunnels

# DNS cache
ztlp agent dns

# Flush DNS cache
ztlp agent flush-dns

# Follow agent logs
ztlp agent logs
ztlp agent logs --follow

# Install systemd service
ztlp agent install
ztlp agent uninstall

# Configure system DNS to use agent
ztlp agent dns-setup
ztlp agent dns-teardown
```

### Status output example

```
$ ztlp agent status
ZTLP Agent v0.6.0
  Status:     running (pid 4821, uptime 3d 14h)
  Identity:   a7f3...8b21 (admin.techrockstars.ztlp)
  NS Server:  ns.techrockstars.com:23096 (healthy, 12ms RTT)

Credentials:
  Certificate:  valid (expires in 62d, auto-renew in 32d)
  KEY record:   published (TTL 24h, refresh in 6h)
  SVC record:   published (TTL 24h, refresh in 18h)

Tunnels (3 active):
  fileserver.techrockstars.ztlp    127.100.0.1    direct   2 streams   14ms RTT
  db.techrockstars.ztlp            127.100.0.2    direct   1 stream    8ms RTT
  dc1.acme.techrockstars.ztlp      127.100.0.3    relay    1 stream    45ms RTT

DNS Cache (12 entries, 3 active):
  fileserver.techrockstars.ztlp    → 127.100.0.1   TTL 23h
  db.techrockstars.ztlp            → 127.100.0.2   TTL 22h
  dc1.acme.techrockstars.ztlp      → 127.100.0.3   TTL 3500s
  ...
```

### SSH ProxyCommand

```bash
# Direct use
ztlp proxy fileserver.techrockstars.ztlp 22

# In SSH config
Host *.ztlp *.internal.techrockstars.com
    ProxyCommand ztlp proxy %h %p
```

---

## 11. Systemd Integration

### Service unit

```ini
# /etc/systemd/system/ztlp-agent.service

[Unit]
Description=ZTLP Agent — Encrypted Network Overlay
Documentation=https://ztlp.org/docs/agent
After=network-online.target systemd-resolved.service
Wants=network-online.target

[Service]
Type=notify
User=ztlp
Group=ztlp
ExecStart=/usr/local/bin/ztlp agent start --foreground
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/usr/local/bin/ztlp agent stop
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/ztlp /run/ztlp
PrivateTmp=yes
ProtectKernelTunables=yes

# Allow binding to DNS port
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Watchdog
WatchdogSec=60

[Install]
WantedBy=multi-user.target
```

### Installation

```bash
# ztlp agent install does:
1. Creates ztlp user/group (if not exists)
2. Copies identity + config to /var/lib/ztlp/
3. Installs systemd unit
4. Configures DNS (systemd-resolved or /etc/resolv.conf)
5. Enables + starts the service
```

---

## 12. Wire Protocol Extensions

### Stream multiplexing

Extend the tunnel protocol with stream management:

```
STREAM_OPEN (0x05):
  <<0x05, stream_id::32, port::16>>

STREAM_DATA (0x06):
  <<0x06, stream_id::32, data::binary>>

STREAM_CLOSE (0x07):
  <<0x07, stream_id::32>>

STREAM_RESET (existing 0x04, repurposed):
  <<0x04, stream_id::32>>  (stream_id=0 means reset entire session)
```

### Agent control socket

The agent exposes a Unix socket for CLI communication:

```
/run/ztlp/agent.sock (or ~/.ztlp/agent.sock)

Commands (JSON over Unix socket):
  {"cmd": "status"}
  {"cmd": "tunnels"}
  {"cmd": "dns_cache"}
  {"cmd": "flush_dns"}
  {"cmd": "connect", "name": "fileserver.techrockstars.ztlp"}
  {"cmd": "disconnect", "name": "fileserver.techrockstars.ztlp"}
```

---

## 13. Implementation Phases

### Phase A — SSH ProxyCommand + NS Resolution (MVP)
**Estimated: 1-2 days**

Smallest useful thing: `ztlp proxy` command that makes SSH work with ZTLP names.

- [ ] `ztlp proxy <name> <port>` — stdin/stdout proxy
- [ ] NS resolution with caching (reuse existing NsClient code)
- [ ] Custom domain → ZTLP zone mapping (static config)
- [ ] SSH config example in docs

**After this phase:**
```bash
# Works!
ssh -o ProxyCommand="ztlp proxy %h %p" user@server.corp.ztlp
```

### Phase B — Agent Daemon + DNS Resolver
**Estimated: 2-3 days**

Background daemon with DNS resolution → virtual IP → TCP proxy.

- [ ] Agent daemon (start/stop/status, PID file, Unix control socket)
- [ ] DNS resolver (UDP, `*.ztlp` + custom zones)
- [ ] Virtual IP allocator (127.100.0.0/16 pool)
- [ ] TCP proxy (per-VIP listeners, forward through tunnel)
- [ ] System DNS configuration (systemd-resolved, /etc/resolv.conf, macOS /etc/resolver)
- [ ] `ztlp agent start/stop/status/dns-setup/dns-teardown`

**After this phase:**
```bash
ztlp agent start
ssh user@server.corp.ztlp          # Just works
psql -h db.corp.ztlp               # Just works
curl https://app.corp.ztlp         # Just works
```

### Phase C — Tunnel Management + Auto-Reconnect
**Estimated: 2-3 days**

Production-grade tunnel lifecycle.

- [ ] Connection pooling (multiple streams per tunnel)
- [ ] Stream multiplexing (STREAM_OPEN/DATA/CLOSE wire types)
- [ ] Idle timeout + cleanup
- [ ] Auto-reconnect with exponential backoff
- [ ] Keepalive pings + dead tunnel detection
- [ ] Relay fallback when direct fails
- [ ] `ztlp agent tunnels` command

### Phase D — Credential Renewal + Health
**Estimated: 1-2 days**

Automatic credential lifecycle.

- [ ] Certificate expiry monitoring + RENEW
- [ ] NS record auto-refresh (KEY + SVC at 75% TTL)
- [ ] Config hot-reload (watch agent.toml)
- [ ] Health reporting to bootstrap server (optional)
- [ ] `ztlp agent logs` command

### Phase E — DNS TXT Discovery + Systemd + Polish
**Estimated: 1-2 days**

Enterprise features and packaging.

- [ ] `_ztlp` TXT record auto-discovery
- [ ] Systemd unit + `ztlp agent install`
- [ ] macOS LaunchAgent support
- [ ] DNS cache flush command
- [ ] Agent-aware `ztlp proxy` (reuse tunnels)
- [ ] Comprehensive tests

### Total: ~7-12 days

---

## 14. File Layout

### Source files (in `proto/src/`)

```
proto/src/
├── agent/
│   ├── mod.rs              — Agent daemon main loop
│   ├── config.rs           — Agent config parsing (TOML)
│   ├── control.rs          — Unix socket control interface
│   ├── dns.rs              — DNS resolver (UDP server, *.ztlp handling)
│   ├── domain_map.rs       — Custom domain → ZTLP zone mapping
│   ├── proxy.rs            — TCP proxy (VIP listeners, tunnel forwarding)
│   ├── tunnel_manager.rs   — Tunnel lifecycle, pooling, reconnect
│   ├── vip_pool.rs         — Virtual IP allocator
│   ├── renewal.rs          — Credential renewal daemon
│   └── dns_setup.rs        — System DNS configuration helpers
├── bin/
│   ├── ztlp-cli.rs         — Main CLI (add agent + proxy subcommands)
│   └── ...
└── ...
```

### Runtime files

```
~/.ztlp/
├── identity.json           — Node identity (NodeID, keys)
├── agent.toml              — Agent configuration
├── agent.log               — Agent log file
├── agent.pid               — PID file (when daemonized)
├── agent.sock              — Unix control socket
├── config.toml             — CLI config (existing)
├── cert.json               — Current certificate
└── cache/
    ├── dns.json            — DNS cache (persisted across restarts)
    └── tunnels.json        — Known peer endpoints (warm reconnect)
```

---

## Design Decisions & Rationale

### Why loopback VIPs instead of TUN/TAP?

TUN/TAP (WireGuard-style) requires root/CAP_NET_ADMIN and is more complex to implement correctly across platforms. Loopback VIPs work unprivileged, support any TCP application, and are simpler. TUN/TAP can be added later for UDP support and true VPN mode.

### Why not just ProxyCommand?

ProxyCommand only works for SSH. The DNS + TCP proxy approach works for any TCP application — databases, HTTP, RDP, FTP, anything. ProxyCommand is included as a quick-start option that works before the full agent is set up.

### Why 127.100.0.0/16?

The 127.0.0.0/8 range is fully routable on loopback on Linux and macOS. Using the 127.100.x.x sub-range avoids conflicts with 127.0.0.1 (localhost). 65,534 addresses is more than enough for any deployment.

### Why custom domains matter for MSPs

Managed service providers manage dozens of companies. Each company's employees should see their own domain names, not the MSP's internal namespace. Custom domain mapping lets the MSP run one ZTLP infrastructure while each client sees a branded experience.
