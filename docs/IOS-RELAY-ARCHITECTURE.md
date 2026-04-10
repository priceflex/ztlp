# iOS Relay Architecture Specification

**Created:** 2026-04-10
**Status:** DECIDED — replacing VIP-proxy-on-phone approach
**Affects:** iOS Network Extension only (desktop/server clients unchanged)
**Replaces:** IOS-MEMORY-OPTIMIZATION.md Option 3 (XPC split) — relay is the chosen path

---

## Problem Statement

iOS Network Extensions have a hard 15MB resident memory limit enforced by
jetsam. The VIP proxy (5 NWListeners on ports 80/443/8080/8443/8200) costs
5-8MB of the 18-21MB NE footprint — the single biggest actionable memory
consumer. Even after stripping tokio (TEXT 8.4MB → 1.65MB), capping buffers,
and reducing worker threads, the NE still hits 18-21MB because of the
Swift-side NWListener/NWConnection overhead during bulk transfers.

Multiple tunnels to different backends multiply the problem — each destination
requires its own TCP connection lifecycle, encryption state, and routing logic
inside the NE.

## Decision

Move ALL VIP proxy / TCP termination to a dedicated iPhone Relay server.
The NE becomes a pure packet encryptor/decryptor — just packetFlow + one
UDP tunnel. This is the Tailscale DERP / WireGuard relay model.

**iPhone-only architecture.** Desktop and server clients continue to use
direct tunnels with local VIP proxies. This relay exists specifically because
of the 15MB NE limit.

---

## Architecture

### Before (Multi-Tunnel, Memory-Heavy)

```
iPhone NE (18-21MB)
├── NWListener :80  ──→ ZTLP Tunnel 1 ──→ Gateway ──→ Backend A
├── NWListener :443 ──→ ZTLP Tunnel 2 ──→ Gateway ──→ Backend B
├── NWListener :8080──→ ZTLP Tunnel 3 ──→ Gateway ──→ Backend C
├── NWListener :8443──→ ZTLP Tunnel 4 ──→ Gateway ──→ Backend D
└── NWListener :8200──→ ZTLP Tunnel 5 ──→ Gateway ──→ Backend E

5 NWListeners + 5 tunnels = 5-8MB overhead
```

### After (Single Tunnel + Relay, Memory-Light)

```
iPhone NE (~10-13MB)
└── Single NWConnection (UDP) ──→ ONE ZTLP tunnel ──→ iPhone Relay
                                                        │
                                           Relay handles VIP proxy:
                                           ├── TCP :80  ──→ Backend A
                                           ├── TCP :443 ──→ Backend B
                                           ├── TCP :8080──→ Backend C
                                           ├── TCP :8443──→ Backend D
                                           └── TCP :8200──→ Backend E
```

---

## Packet Routing (Secure Path)

### Phone → Relay → Backend

```
1. Phone app makes TCP connection to virtual IP (e.g., 127.0.55.1:443)

2. NE captures packet via NEPacketTunnelProvider.packetFlow

3. NE wraps in ZTLP frame with service routing tag:
   - Frame header: SessionID + destination VIP/port + data_seq
   - Frame payload: encrypted with Noise_XX session key (phone ↔ relay)

4. NE sends via single NWConnection UDP socket to relay

5. Relay receives encrypted ZTLP frame
   - Decrypts with Noise_XX session key
   - Reads service routing tag (dest VIP/port)
   - Looks up: VIP 127.0.55.1:443 → backend "vaultwarden" at 10.x.x.x:8080
   - Opens TCP connection to that backend
   - Bridges: ZTLP tunnel ←→ TCP connection to backend

6. Backend receives plain TCP connection from relay (or TLS if backend requires it)
```

### Backend → Relay → Phone

```
1. Backend sends TCP response

2. Relay receives on TCP socket

3. Relay encrypts with Noise_XX session key (same phone ↔ relay session)

4. Relay sends via UDP back to phone

5. NE decrypts frame, injects into packetFlow

6. Phone app receives data on its original TCP connection
```

### ACK Flow (Separate ACK Socket)

The dual-socket architecture is preserved. The phone uses:
- **Data socket** (NWConnection): receives DATA frames from relay
- **ACK socket** (NWConnection, separate fd): sends ACKs back to relay

The relay routes by SessionID (not IP:port), so ACKs from the separate
socket are correctly associated with the same session. The relay does NOT
update peer_a for ACK-only packets — this prevents the port flip-flop bug.

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| End-to-end encryption (phone ↔ relay) | Noise_XX handshake, ChaCha20-Poly1305 |
| Forward secrecy | Noise_XX provides FS per session |
| Integrity | BLAKE2s HeaderAuthTag on every frame |
| Anti-replay | Monotonic data_seq + sliding window |
| Relay can't forge packets | Relay doesn't have phone's static key |
| Backend traffic | Relay → backend can be TLS (recommended) |
| Session isolation | Each phone gets unique SessionID after Noise_XX |

### What the Relay CAN See
- SessionID (routing metadata)
- Destination VIP/port (routing metadata)
- Packet sizes and timing (traffic analysis)
- Decrypted payload (it terminates the tunnel)

### What the Relay CANNOT See
- Phone's long-term static private key
- Other sessions from the same phone
- Desktop/server client traffic (those bypass the relay)

### Defense-in-Depth: Relay → Backend TLS
The relay decrypts phone traffic to route it, but the next hop (relay →
backend) should use TLS. This means:
- Phone ↔ Relay: ZTLP Noise_XX encrypted
- Relay ↔ Backend: TLS encrypted
- Relay acts as a TLS-terminating reverse proxy (can see plaintext)

For environments where the relay must NOT see plaintext, a future upgrade
path is phone ↔ relay (encrypted) ↔ gateway (encrypted) ↔ backend, where
the relay only sees encrypted gateway frames. This is NOT the initial design.

---

## Relay Selection (NS-Driven)

### How the Phone Discovers Relays

```
1. NE calls ztlp_ns_resolve_relays_sync(zone) → [RelayInfo]

2. RelayInfo fields:
   - relay_id:       unique identifier
   - address:        IP:port for ZTLP tunnel
   - region:         geographic region tag
   - latency_ms:     measured round-trip time
   - load_pct:       CPU/connection utilization (0-100)
   - active_connections: current client count
   - health:         Healthy | Degraded | Offline

3. Selection algorithm (pure computation, testable on Linux):
   a. Filter: only health == Healthy
   b. Score:  latency_ms * (1 + load_pct/100)  — penalize loaded relays
   c. Pick:   lowest score
   d. Tiebreak: same region as gateway, then fewest active_connections
```

### Failover

```
1. Relay drops connection or misses keepalives (5s timeout)

2. NE re-queries NS for updated relay list

3. Picks next-best relay by selection algorithm

4. Opens new Noise_XX tunnel to new relay

5. All VIP connections re-establish through new relay
   (TCP connections to backends are lost — apps must reconnect)
```

### Adding New Relays

```
1. Deploy relay binary + config to new server

2. Relay registers with NS on startup (Ed25519 auth)

3. NS adds to relay list with health=Healthy

4. iPhones auto-discover on next NS query — zero NE code changes
```

---

## Memory Budget (After Relay Migration)

```
FIXED COSTS (~9-12 MB):
  Rust staticlib (TEXT 1.65MB + DATA + heap):     ~4-6 MB
    - snow (Noise), chacha20poly1305, FFI surface
    - packet router, mux framing, crypto context
  Swift runtime (metadata, ARC, libSwiftCore):    ~2-3 MB
  Foundation framework (Data, Date, UserDefaults): ~1 MB
  Network.framework (loaded by NWConnection):     ~1-2 MB

REMOVED by relay migration:
  5 NWListener instances (ports 80/443/8080/8443/8200): -1-2 MB
  VIP proxy code and state:                           -1-2 MB
  Per-connection NWConnection TLS state:              -0.5-1 MB
  TOTAL REMOVED:                                      -5-8 MB

VARIABLE COSTS (~0.5 MB):
  Single NWConnection (UDP tunnel):              ~0.2 MB
  ACK NWConnection (separate fd):                ~0.1 MB
  actionBuffer (PacketTunnelProvider):           256 KB
  Encrypt/decrypt buffers:                       ~12 KB
  seenSequences Set<UInt64> (2K entries):        ~32 KB

ESTIMATED TOTAL: ~10-13 MB (under 15MB with 2-5MB headroom)
```

---

## Relay Server Requirements

The iPhone Relay is a NEW server component (or an extension of the existing
ZTLP relay). It must:

1. **Accept ZTLP tunnels from iPhones** — Noise_XX handshake, same as gateway
2. **Terminate TCP connections to backends** — relay acts as TCP client
3. **Bridge ZTLP frames ↔ TCP sockets** — read from tunnel, write to TCP (and vice versa)
4. **Service routing table** — map VIP/port to backend address
   ```
   127.0.55.1:443  → vaultwarden.local:8080
   127.0.55.2:80   → internal-api.local:3000
   127.0.55.3:8200 → admin-panel.local:8200
   ```
5. **Report health to NS** — latency, load, active connections
6. **No memory constraint** — full server, can scale horizontally
7. **Session-ID routing** — same as existing relay, never update peer_a for ACK-only packets

### Relay Configuration (YAML/TOML)

```yaml
# iphone-relay.yaml
listen: "0.0.0.0:23095"          # ZTLP tunnel endpoint for iPhones
ns_server: "34.217.62.46:23096"  # NS for registration + health reports

vip_routes:
  # VIP address       → backend address
  "127.0.55.1:443":   "10.0.0.5:8080"   # Vaultwarden
  "127.0.55.2:80":    "10.0.0.6:3000"   # Internal API
  "127.0.55.3:8200":  "10.0.0.7:8200"   # Admin panel

# Default: if no VIP match, route by SNI/Host header (future)
default_backend: "10.0.0.5:8080"

# Health reporting
health_report_interval: 30s
max_concurrent_iphone_connections: 1000

# TLS to backends (recommended)
backend_tls: true
backend_tls_verify: true
```

---

## Impact on Existing Components

| Component | Change Required |
|-----------|----------------|
| **NE (PacketTunnelProvider.swift)** | Remove VipProxy, NWListeners. Add relay selection, single tunnel |
| **NE (Rust FFI)** | Remove vip.rs dependency. Add ztlp_ns_resolve_relays_sync |
| **ZTLP Relay (Elixir)** | Add iPhone relay mode: TCP termination, VIP routing, service bridge |
| **ZTLP NS (Elixir)** | Add RELAY record type (type 3) — already implemented |
| **Gateway** | No change — iPhones no longer connect directly to gateway |
| **macOS app** | No change — desktop clients keep local VIP proxy |
| **Linux harness** | Simpler NE = simpler harness. No VIP proxy to simulate |

---

## Implementation Phases

### Phase 1: Relay TCP Termination (2-3 days)
- Add VIP routing table to relay config
- Implement TCP connection lifecycle on relay
- Bridge ZTLP frames ↔ TCP sockets
- Test with single iPhone client

### Phase 2: NE Relay Selection (1-2 days)
- Remove VipProxy + NWListeners from PacketTunnelProvider
- Add ztlp_ns_resolve_relays_sync call on tunnel start
- Implement relay selection algorithm
- Single NWConnection tunnel to chosen relay

### Phase 3: Failover + Health (1-2 days)
- Keepalive timeout → relay failover
- Re-query NS on relay drop
- Health reporting from relay to NS
- Load-based relay selection

### Phase 4: Production Hardening (1-2 days)
- Backend TLS (relay → backend)
- Connection pooling on relay
- Metrics (Prometheus) for relay TCP connections
- Horizontal scaling (multiple relays behind NS)

---

## Tradeoffs

| Tradeoff | Acceptance Rationale |
|----------|---------------------|
| +1 hop latency for iPhone VIP traffic | Under 15MB is hard requirement; added latency is ~20-50ms |
| Relay sees decrypted traffic | Relay → backend TLS provides second layer; defense-in-depth |
| TCP connections lost on relay failover | Apps auto-reconnect; same as any network change on iOS |
| Relay is a single point of failure | NS-driven relay selection + multiple relays mitigates |
| More server infrastructure | Servers have no memory limit; iPhones do. Trade is correct |

---

## Future Upgrade Paths

1. **Double-encrypt (phone → relay → gateway)**: Relay only sees encrypted
   gateway frames, not plaintext. Requires gateway to also run VIP proxy.
   More latency but relay sees nothing.

2. **QUIC relay**: Replace TCP termination with QUIC for multiplexed streams
   without head-of-line blocking.

3. **Relay mesh for iPhones**: Multiple relays in different regions, phone
   picks geographically closest (NS already supports this).
