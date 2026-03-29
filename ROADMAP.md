# ZTLP Feature Roadmap

> Last updated: 2026-03-29 | Current release: v0.17.0

## Current State

ZTLP v0.17.0 is a working zero-trust tunnel with macOS and iOS clients, Elixir gateway/relay/NS infrastructure, eBPF packet filter, and a full PKI system. The iOS app connects to a gateway via relay over encrypted UDP, multiplexes TCP streams, and routes traffic through a VIP subnet (`10.122.0.0/16`) via a userspace TCP/IP stack.

### What's Working (v0.17.0)
- **iOS app** with NetworkExtension packet tunnel, VIP routing, enrollment, CA cert install flow
- **macOS app** with loopback VIP proxy, pf port redirection, menu bar UI
- **Elixir gateway** with AIMD congestion control, TLS termination, session dedup, keepalive handling
- **Elixir relay** with mesh routing, admission tokens, multi-hop forwarding
- **ZTLP-NS** with CA auto-init, cert issuance, zone delegation, federation stubs
- **Rust client** with SendController (cwnd-gated uploads), Noise_XX handshake, mux streams
- **eBPF/XDP** packet filter with dual-port support

### iOS Benchmark Results (cellular, via relay)

| Benchmark | Result | Status |
|---|---|---|
| HTTP Ping | 94-97ms | ✅ |
| GET 1KB | 95-97ms | ✅ |
| GET 10KB | 100-101ms | ✅ |
| GET 100KB | 133-207ms | ✅ |
| GET 1MB | 701ms, 1.3 MB/s | ✅ |
| Download 5MB | 3.5s, 1.4 MB/s | ✅ |
| POST 1KB | 95-96ms | ✅ |
| POST 100KB | 192-262ms | ✅ |
| Upload 1MB | 5.5s, 0.2 MB/s | ✅ (conservative) |
| Concurrent 5x GET | 108ms | ✅ |
| TTFB | 96ms | ✅ |

### Test Counts
- **844 Rust tests**, 0 failures
- **573 gateway tests**, 0 failures
- **726 NS tests**, 0 failures
- **284 relay tests**, 0 failures
- **2,427 total**, 0 failures

---

## 🔴 Phase 0 — Production Hardening (BLOCKING — Do Before Users)

Must fix before real users touch this. These are operational/data-safety issues, not features.

### 0.1 NS Data Persistence ⚠️ CRITICAL
Mnesia is `ram_copies` — all NS records (service registrations, zone delegations) are lost on container restart. CA keys live at `/home/ztlp/.ztlp/ca/` inside the container filesystem — lost on container recreation (`docker pull` + `docker run`).

**Impact:** Container recreation = new CA key = every enrolled device must re-install CA cert.

**Fix:**
- Mount `/home/ztlp/.ztlp` to a host volume (`-v ztlp-ns-data:/home/ztlp/.ztlp`)
- Switch Mnesia to `disc_copies` (`ZTLP_NS_STORAGE_MODE=disc_copies`)
- Backup CA keys to encrypted offsite storage

### 0.2 Zone Delegation Re-Bootstrap ⚠️ CRITICAL
Gateway bootstraps zone delegation key on first startup, sets `zone_bootstrapped: true`, never re-checks. If NS restarts after the gateway, zone key is lost → all service registrations rejected as "unauthorized" → NS lookups fail → clients can't discover services.

**Impact:** NS restart silently breaks all service discovery. No error on the phone — just timeouts.

**Fix:** Gateway ServiceRegistrar should verify zone key exists before each registration cycle (query NS for zone KEY record, re-bootstrap if missing). Alternatively, NS persists records to disk (see 0.1).

### 0.3 Echo Server Persistence
HTTP echo server is a bare `python3 /tmp/http-echo.py` process. Dies on reboot, no restart policy.

**Fix:** Containerize with Docker (add to gateway host's compose) or create a systemd service with `Restart=always`.

### 0.4 Gateway Log Verbosity
18K+ log lines in 11 hours. Every FRAME_DATA, decrypted byte count, and forwarded payload logged at `info` level. In production with real traffic, this will fill disk in days.

**Fix:** Change data-path logging (`FRAME_DATA`, `Decrypted`, `Forwarding`) to `debug` level. Keep handshake, session lifecycle, errors, and policy decisions at `info`.

### 0.5 Firewall Exposed Ports
- Prometheus metrics on `0.0.0.0:9102` — publicly scrapable
- Echo server on `0.0.0.0:8180` — publicly accessible (meant for tunnel-only access)

**Fix:** Bind metrics to `127.0.0.1:9102`. Bind echo server to `172.18.0.1:8180` (Docker bridge only) or firewall with iptables.

### 0.6 CA Key Security
Root CA private key encrypted with default passphrase, stored on container filesystem. No HSM, no KMS.

**Fix (short-term):** Strong passphrase via `ZTLP_CA_KEY_PASSPHRASE` env var. Volume-mount CA directory (see 0.1).
**Fix (long-term):** AWS KMS, HashiCorp Vault, or hardware HSM for CA signing operations.

### 0.7 TLS Cert Renewal Resilience
Cert renewal timer hardcoded to 3.5 days. If NS is unreachable when renewal fires, no retry — certs expire, all HTTPS connections fail.

**Fix:** Exponential backoff retry on renewal failure. Grace period: continue serving with existing cert until expiry. Alert on failed renewal.

### 0.8 Version Bump & Release
Current codebase has ~15 commits since v0.14.0 with major features (SendController, packet router, PKI, iOS integration, gateway hardening). Need a proper release.

**Fix:** Bump to v0.18.0, update CHANGELOG.md, tag, push, CI build.

### 0.9 Unified Audit & Logging Dashboard
All ZTLP components (gateway, relay, NS, agents/clients) ship structured audit events to a central collector. Searchable by date/time, hostname, username, service, event type, and free-text details. Single-page HTML dashboard served from the gateway.

**Full spec:** [`docs/UNIFIED-AUDIT.md`](docs/UNIFIED-AUDIT.md)

**Summary:**
- Audit Collector GenServer on gateway with Mnesia persistence
- Wire protocol `0x15` for event submission from remote components
- HTTP query API (`/audit/events`, `/audit/stats`, `/audit/dashboard`)
- Standard event envelope (ts, component, hostname, username, event, level, details)
- 50+ event types across gateway, NS, relay, and client
- Configurable retention (default 30 days), rate limiting, auth
- 5 implementation phases: collector → reporters → client reporting → dashboard UI → retention

---

## Phase 1 — Gateway Stream Concurrency ✅ DONE

**Goal:** 95%+ success rate at concurrency 20. **Achieved: 100% at concurrency 5 on cellular.**

### 1.1 ✅ AIMD Congestion Control (replaced fixed window)
Gateway `session.ex` now has TCP-like AIMD: IW=64, max_cwnd=256, ssthresh=128, burst=8, pacing=1ms. Slow start → congestion avoidance. RTT estimation with Karn's algorithm. Retransmit with exponential backoff.

### 1.2 ✅ Client-Side SendController
`send_controller.rs` (453 lines, 10 tests) wraps `AdvancedCongestionController` with send buffer, cwnd-gated flushing, ACK processing, retransmission. Integrated into VIP proxy upload path.

### 1.3 ✅ Session Deduplication
Secondary ETS table prevents zombie session accumulation from phone reconnects. Old session killed on new HELLO from same `{ip, port}`.

### 1.4 ✅ Keepalive Handling
1-byte `0x01` frames reset idle timer without forwarding to backends. Prevents Vaultwarden close → drain → session death cycle.

### Remaining
- **1.5 Async FRAME_OPEN** — Still synchronous backend connect in `handle_tunnel_frame/2`. Not yet a bottleneck at current concurrency levels but will be at 10+.
- **1.6 Out-of-order packet acceptance** — Gateway uses strictly-greater seq check, drops reordered packets. Needs sliding window for cellular reliability.

---

## Phase 2 — Connection Pooling & Keep-Alive (Medium Impact, Low Effort)

**Goal:** Reduce per-request latency from 141ms to under 50ms for repeat requests.

### 2.1 Gateway Backend Connection Pool
Each FRAME_OPEN creates a new TCP connection to the backend and tears it down on FRAME_CLOSE. For HTTP/1.1 keep-alive workloads, this is wasteful.

**Fix:** Pool backend connections per `{host, port}`. Reuse idle connections for new streams. Configurable pool size (default 8 per backend). Idle timeout 60s.

### 2.2 Client-Side HTTP Keep-Alive
The VIP proxy closes the ZTLP stream when the TCP connection closes. For HTTP/1.1, the browser keeps the connection open for subsequent requests.

**Fix:** Detect HTTP/1.1 response completion (Content-Length or chunked transfer-encoding terminator) and keep the stream open for the next request on the same TCP connection. Avoids FRAME_OPEN/CLOSE overhead for every request.

### 2.3 ZTLP Stream Reuse Protocol
New frame type: `FRAME_STREAM_RESET (0x09)` — resets a stream's state without closing/reopening. Gateway reuses the same backend TCP connection.

**Expected result:** Repeat-request latency drops to ~30-50ms (skip handshake + backend connect).

---

## Phase 3 — UDP Transport Improvements (High Impact, High Effort)

**Goal:** Reliable 50+ MB/s throughput, robust packet loss recovery.

### 3.1 Selective ACK (SACK)
Current ACK is cumulative — the client ACKs the highest contiguous sequence received. If packet 5 is lost but 6-20 arrive, the client can only ACK 4. The gateway retransmits 5, but doesn't know 6-20 arrived.

**Fix:** SACK blocks in ACK frames: `[FRAME_ACK | cumulative_ack(8) | sack_count(1) | sack_ranges...]`. Gateway skips retransmitting already-received packets. Estimated: ~400 lines across gateway + client.

### 3.2 BBR-Style Congestion Control
Current congestion control is AIMD (additive increase, multiplicative decrease). It's conservative — a single packet loss halves the window.

**Fix:** Implement BBR (Bottleneck Bandwidth and RTT) or COPA. Model the bottleneck bandwidth and RTT independently. Maintain throughput through mild packet loss (common on mobile/Wi-Fi).

### 3.3 FEC (Forward Error Correction)
For lossy links (cellular, long-haul Wi-Fi), retransmission adds full RTT latency.

**Fix:** Reed-Solomon or XOR-based FEC. Send N data packets + K parity packets. Receiver reconstructs any K lost packets without retransmission. Configurable redundancy ratio (default 10%). Bypass for LAN/wired connections.

### 3.4 Path MTU Discovery
Current: hardcoded 1200-byte payloads. Many paths support 1400+ bytes.

**Fix:** PLPMTUD (RFC 8899). Probe with increasing sizes, track per-path MTU. Fall back on ICMP fragmentation-needed. Automatic — no user config.

**Expected result:** 50+ MB/s sustained, <5% throughput loss on 1% packet loss networks.

---

## Phase 4 — Multi-Service & Multi-Gateway (Medium Impact, High Effort)

**Goal:** Production multi-tenant deployment.

### 4.1 Service Registry in ZTLP-NS
Currently, services are hardcoded in the client config (e.g., `beta → vaultwarden`). Move to dynamic service discovery via ZTLP-NS.

**Fix:** New NS record type `SRV (0x06)` — maps service names to gateway endpoints. Client queries NS for `beta.techrockstars.ztlp`, gets `gateway=34.219.64.205:23095, backend=127.0.0.1:8080`. VIP proxy auto-configures from NS records.

### 4.2 Multi-Gateway Failover
Single gateway = single point of failure. Add gateway redundancy.

**Fix:** Client maintains connections to 2+ gateways. Health-check via keepalive. Failover in <2s. Stream migration: client sends FRAME_MIGRATE to new gateway with session token, new gateway resumes from last ACK.

### 4.3 Split Tunneling
Currently all traffic to `.ztlp` domains goes through the tunnel. Some services (low-security internal tools) could go direct.

**Fix:** Per-service routing policy in NS records: `tunnel` (encrypted), `direct` (plaintext TCP), `mesh` (via relay). Client enforces policy.

### 4.4 Gateway Horizontal Scaling
Single gateway process = single-machine limit (~10K concurrent sessions estimated).

**Fix:** Gateway cluster with consistent hash ring (reuse relay mesh code). Session affinity by NodeID hash. Graceful migration on scale-in.

**Expected result:** Multi-service deployment with automatic failover and service discovery.

---

## Phase 5 — Mobile Clients (Mostly Done)

**Goal:** iOS and Android apps with the same VIP proxy architecture.

### 5.1 ✅ iOS App (SwiftUI + NetworkExtension)
Full iOS app with:
- `NEPacketTunnelProvider` with VIP routing via `packet_router.rs` (2,030 lines, 35 tests)
- VIP subnet `10.122.0.0/16` — each service gets a unique IP (e.g., `10.122.0.2` = vault, `10.122.0.3` = http)
- Enrollment flow with QR scan + NS zone registration
- CA certificate installation via `.mobileconfig` profile (Home screen card + Settings section)
- In-app benchmark suite (14 local + 11 HTTP benchmarks)
- 112 unit tests (100 passing, 12 pre-existing Keychain simulator failures)
- Services view, connection status, traffic stats, tunnel logs

### 5.2 Android App (Kotlin + VpnService) — NOT STARTED
JNI bindings to `libztlp_proto.so`. Android VpnService for tun interface. Can reuse `packet_router.rs` directly.

### 5.3 ✅ Shared Tunnel Core
`packet_router.rs` is platform-agnostic (only iOS wired up). Desktop agent uses separate `127.100.0.x` VIP pool. Android would use same router via `VpnService.Builder`.

### Remaining iOS Work
- **5.4 On-demand VPN rules** — auto-connect when accessing `.ztlp` domains
- **5.5 Battery optimization** — keepalive interval tuning, background task scheduling
- **5.6 Split tunneling** — only route `.ztlp` traffic through tunnel, direct for everything else
- **5.7 App Store preparation** — proper code signing, TestFlight distribution, privacy manifest

---

## Phase 6 — Security Hardening for Production (Partially Done)

**Goal:** Defense-in-depth beyond the current Noise_XX + ChaCha20 baseline.

### 6.1 ✅ PKI / Certificate Authority
- NS acts as CA (RSA-4096 root + intermediate, auto-init on startup)
- Gateway auto-provisions TLS certs from NS via UDP `0x14` protocol
- TLS termination at gateway for HTTPS services (per-stream, using Erlang `:ssl`)
- iOS CA cert enrollment via `.mobileconfig` profile

### 6.2 ✅ Device Enrollment
- `ztlp setup` CLI wizard with QR code support
- ENROLL wire protocol (0x07/0x08) with HMAC-BLAKE2s tokens
- iOS enrollment flow with zone registration

### 6.3 ✅ Structured Audit Logging
- JSON structured logging across all components (NS, gateway, relay)
- Audit trail for registrations, policy decisions, session lifecycle

### 6.4 Certificate Pinning — NOT STARTED
Pin the gateway's static public key in the client config. Reject connections to unknown gateways even if Noise handshake succeeds. ~50 lines.

### 6.5 Key Rotation — NOT STARTED
Rotate session keys every 2^32 packets or 24 hours (whichever first). New frame type: `FRAME_REKEY (0x0A)`. Both sides derive new keys from the current ones via HKDF. Zero-downtime — no reconnect needed.

### 6.6 Mutual Device Attestation — NOT STARTED
Extend enrollment to verify device identity on every connection:
- macOS: Secure Enclave attestation
- iOS: DeviceCheck / App Attest
- Android: Play Integrity / Key Attestation

### 6.7 Post-Quantum Readiness — NOT STARTED
Current Noise_XX uses X25519 for key exchange. Add hybrid PQ mode: X25519 + ML-KEM-768 (Kyber). Key sizes increase but tunnel overhead stays the same after handshake.

---

## Phase 7 — Operational Excellence (Medium Impact, Low-Medium Effort)

### 7.1 Prometheus/Grafana Metrics (Client)
Export client-side metrics: tunnel uptime, reconnect count, stream count, latency histogram, bytes transferred. macOS menu bar shows real-time stats.

### 7.2 Auto-Update (macOS)
Sparkle framework for macOS app auto-update. Check GitHub releases, download DMG, prompt install. Background check every 6 hours.

### 7.3 Admin Dashboard
Web UI for gateway operators. Real-time connected clients, stream activity, bandwidth, per-service health. Built with Phoenix LiveView — zero additional dependencies.

### 7.4 Config Hot-Reload
Gateway config changes without restart. Watch config file, apply changes to routing table, backend pool, and policy engine. SIGHUP trigger.

---

## Priority Matrix

| Phase | Impact | Effort | Priority | Status |
|---|---|---|---|---|
| **0: Production Hardening** | Critical | Low-Medium | 🔴 BLOCKING | 0/9 done |
| **1: Gateway Concurrency** | High | Medium | ✅ Mostly Done | 4/6 done |
| **2: Connection Pooling** | Medium | Low | 🟡 Do Soon | 0/3 done |
| **5: Mobile (iOS)** | High | Very High | ✅ Mostly Done | 3/7 done |
| **6: Security Hardening** | Critical | Medium | 🟡 Partially Done | 3/7 done |
| **3: UDP Transport** | High | High | 🟢 Steady | 0/4 done |
| **7: Ops Excellence** | Medium | Low-Medium | 🟢 Steady | 0/4 done |
| **4: Multi-Service** | Medium | High | 🔵 Later | 0/4 done |
| **5: Mobile (Android)** | High | High | 🔵 Later | 0/1 done |

---

## Quick Wins (can ship in a day each)

1. **NS data persistence** (Phase 0.1) — volume mount + disc_copies, prevents CA key loss
2. **Gateway log levels** (Phase 0.4) — change data-path to debug, immediate disk savings
3. **Firewall exposed ports** (Phase 0.5) — iptables rules, 10 minutes
4. **Zone re-bootstrap** (Phase 0.2) — check zone key each registration cycle, ~30 lines
5. **Echo server systemd** (Phase 0.3) — systemd unit file, 5 minutes
6. **Version bump** (Phase 0.8) — tag v0.18.0, update changelog
7. **Unified audit spec** (Phase 0.9) — spec written ([`docs/UNIFIED-AUDIT.md`](docs/UNIFIED-AUDIT.md)), build when ready
8. **Certificate pinning** (Phase 6.4) — ~50 lines, significant security improvement
9. **Backend connection pool** (Phase 2.1) — cuts repeat latency in half
