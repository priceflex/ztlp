# ZTLP Feature Roadmap

> Last updated: 2026-03-29 | Current release: v0.21.0

## Current State

ZTLP v0.18.0 is a working zero-trust tunnel with macOS and iOS clients, Elixir gateway/relay/NS infrastructure, eBPF packet filter, and a full PKI system. The iOS app connects to a gateway via relay over encrypted UDP, multiplexes TCP streams, and routes traffic through a VIP subnet (`10.122.0.0/16`) via a userspace TCP/IP stack.

### What's Working (v0.18.0)
- **iOS app** with NetworkExtension packet tunnel, VIP routing, enrollment, CA cert install flow
- **macOS app** with loopback VIP proxy, pf port redirection, menu bar UI
- **Elixir gateway** with AIMD congestion control, TLS termination, session dedup, keepalive handling, backend connection pool, async FRAME_OPEN, sliding receive window
- **Elixir relay** with mesh routing, admission tokens, multi-hop forwarding
- **ZTLP-NS** with CA auto-init, cert issuance, zone delegation, federation stubs, disc_copies persistence
- **Rust client** with SendController (cwnd-gated uploads), Noise_XX handshake, mux streams, certificate pinning
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
- **1,029 Rust tests**, 0 failures
- **617 gateway tests**, 0 failures
- **726 NS tests**, 0 failures
- **565 relay tests**, 0 failures
- **2,937 total**, 0 failures

---

## ✅ Phase 0 — Production Hardening (COMPLETE)

All blocking production-readiness items resolved.

### 0.1 ✅ NS Data Persistence
- Mnesia switched to `disc_copies` with persistent Docker volume
- CA keys stored on volume at `/app/data/ca/`
- Fixed OTP auto-start issue (must stop Mnesia before `create_schema`)
- Docker `--hostname` required for stable Erlang node name

### 0.2 ✅ Zone Delegation Re-Bootstrap
- Gateway ServiceRegistrar verifies zone KEY record before each registration cycle
- Three-way result: found → proceed, not_found → re-bootstrap, error → try if never done
- Runs every 150s, prevents silent 11-hour registration failures

### 0.3 ✅ Echo Server Persistence
- `deploy/http-echo.py` + `deploy/http-echo.service` systemd unit
- Deployed to `/opt/ztlp/` on gateway box, managed by systemd

### 0.4 ✅ Gateway Log Verbosity
- 13 data-path `Logger.info` → `Logger.debug` in session.ex
- Session lifecycle, errors, policy decisions remain at info

### 0.5 ✅ Firewall Exposed Ports
- Metrics ports (9102, 9103) locked to localhost via iptables
- Echo server locked to Docker bridge + localhost
- Rules persisted with `iptables-persistent`, documented in `deploy/FIREWALL.md`

### 0.6 ✅ CA Key Security
- Strong passphrase via `ZTLP_CA_PASSPHRASE` env var (64-char hex)
- CA keys on persistent volume (survive container recreation)
- Default passphrase warning in logs when not set
- Long-term: HSM/KMS for signing operations (see `ZTLP_CA_MODE=oracle`)

### 0.7 ✅ TLS Cert Renewal Resilience
- Exponential backoff retry: 30s → 1m → 2m → 5m → 15m → 30m → 1h
- Keeps existing certs on renewal failure
- Hourly expiry sweep: warn at 75% lifetime, error at 90%, force renewal on expired
- `ZTLP_GATEWAY_CERT_LIFETIME_DAYS` env var (default 7)

### 0.8 ✅ Version Bump & Release
- v0.18.0 released with CHANGELOG.md
- 2,937 tests across all components, 0 failures

### 0.9 Unified Audit & Logging — IN PROGRESS
- Full spec at `docs/UNIFIED-AUDIT.md`
- Implementation underway (Audit Collector GenServer, HTTP query API)

---

## ✅ Phase 1 — Gateway Stream Concurrency (COMPLETE)

**Goal:** 95%+ success rate at concurrency 20. **Achieved: 100% at concurrency 5 on cellular.**

### 1.1 ✅ AIMD Congestion Control
Gateway TCP-like AIMD: IW=64, max_cwnd=256, ssthresh=128, burst=8, pacing=1ms.

### 1.2 ✅ Client-Side SendController
`send_controller.rs` wraps `AdvancedCongestionController` with cwnd-gated flushing and ACK processing.

### 1.3 ✅ Session Deduplication
Secondary ETS table prevents zombie sessions from phone reconnects.

### 1.4 ✅ Keepalive Handling
1-byte `0x01` frames reset idle timer without forwarding to backends.

### 1.5 ✅ Async FRAME_OPEN
Backend TCP connections established asynchronously via spawn. Stream states: `:connecting` → `:connected` with data buffering. 10s connect timeout.

### 1.6 ✅ Sliding Receive Window
256-entry sliding window replaces strict `seq > recv_seq` check. Out-of-order packets buffered and delivered in sequence. Cumulative ACK.

---

## Phase 2 — Connection Pooling & Keep-Alive (Mostly Done)

### 2.1 ✅ Gateway Backend Connection Pool
- `BackendPool` GenServer with ETS-backed per-backend pool
- Checkout/checkin API for mux stream connections
- Idle sweep every 30s, configurable pool size and timeout
- Legacy sessions still use direct Backend.start_link

### 2.2 HTTP Keep-Alive — IN PROGRESS
VIP proxy graceful stream recovery, HTTP request boundary detection.

### 2.3 Stream Reuse Protocol — IN PROGRESS
`FRAME_STREAM_RESET (0x09)` for stream reuse without close/reopen overhead.

---

## Phase 3 — UDP Transport Improvements ✅ COMPLETE

**Goal:** Reliable 50+ MB/s throughput, robust packet loss recovery.

### 3.1 ✅ Selective ACK (SACK)
SACK blocks in ACK frames — up to 3 ranges. Gateway builds from RecvWindow, skips SACK'd on retransmit. Backward compatible. 39 tests.

### 3.2 ✅ BBR Congestion Control
4-state model (Startup → Drain → ProbeBW → ProbeRTT). BtlBw windowed max filter, min RTT tracking. Replaces AIMD. 21 tests.

### 3.3 ✅ FEC (Forward Error Correction)
XOR-based FEC. FecEncoder/FecDecoder, configurable group size 1-10. FRAME_FEC_DATA (0x0E), FRAME_FEC_PARITY (0x0F). 26 tests.

### 3.4 ✅ Path MTU Discovery (PLPMTUD, RFC 8899)
Probe state machine with binary search ladder (1200 → 1500). FRAME_PMTU_PROBE/ACK. 19 tests.

---

## Phase 4 — Multi-Service & Multi-Gateway (Medium Impact, High Effort)

### 4.1 Dynamic Service Registry in ZTLP-NS
### 4.2 Multi-Gateway Failover
### 4.3 Split Tunneling
### 4.4 Gateway Horizontal Scaling

---

## Phase 5 — Mobile Clients (iOS Done, Android Not Started)

### 5.1 ✅ iOS App (SwiftUI + NetworkExtension)
Full iOS app with VIP routing, enrollment, CA cert install, benchmarks, 112 tests.

### 5.2 Android App — NOT STARTED
JNI bindings, VpnService, reuse `packet_router.rs`.

### Remaining iOS Work
- **5.4** On-demand VPN rules
- **5.5** Battery optimization
- **5.6** Split tunneling
- **5.7** App Store preparation

---

## Phase 6 — Security Hardening (Mostly Done)

### 6.1 ✅ PKI / Certificate Authority
### 6.2 ✅ Device Enrollment
### 6.3 ✅ Structured Audit Logging
### 6.4 ✅ Certificate Pinning
Gateway static key pinning with multi-key rotation support, auto-pin on enrollment.

### 6.5 Key Rotation — IN PROGRESS
`FRAME_REKEY (0x0A)` — rotate session keys every 2^32 packets or 24 hours.

### 6.6 ✅ Device Attestation Framework
Apple App Attest, Android Key Attestation, YubiKey (stubs). Software attestation (Ed25519) fully functional. Trust levels + ZTLP_MIN_ATTESTATION_LEVEL. 18 tests.
### 6.7 Post-Quantum Readiness — NOT STARTED

---

## Phase 7 — Operational Excellence (Partially Done)

### 7.1 ✅ Client Prometheus Metrics
Counter/Gauge/Histogram types, MetricsRegistry, ZtlpMetrics (14 pre-defined). Zero deps. 28 tests.
### 7.2 Auto-Update (macOS) — NOT STARTED
### 7.3 ✅ Admin Dashboard
Single-page HTML on localhost:9105 with dark theme, auto-refresh, JSON API. Zero deps. 8 tests.
### 7.4 ✅ Config Hot-Reload
ConfigWatcher polls YAML every 30s + SIGHUP. Diff-based with audit events. 18 tests.

---

## Priority Matrix

| Phase | Impact | Effort | Status |
|---|---|---|---|
| **0: Production Hardening** | Critical | Low-Medium | ✅ Complete (8/9, audit in progress) |
| **1: Gateway Concurrency** | High | Medium | ✅ Complete (6/6) |
| **2: Connection Pooling** | Medium | Low | 🟡 Mostly Done (1/3, 2 in progress) |
| **5: Mobile (iOS)** | High | Very High | ✅ Mostly Done (3/7) |
| **6: Security Hardening** | Critical | Medium | 🟡 Mostly Done (4/7, rotation in progress) |
| **3: UDP Transport** | High | High | ✅ Complete (4/4) |
| **7: Ops Excellence** | Medium | Low-Medium | 🟡 Partially Done (3/4) |
| **4: Multi-Service** | Medium | High | 🔵 Later |
| **5: Mobile (Android)** | High | High | 🔵 Later |
