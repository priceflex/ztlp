# ZTLP Feature Roadmap

> Last updated: 2026-03-26 | Current release: v0.14.0

## Current State

ZTLP v0.14.0 is a working zero-trust tunnel with a macOS client, Elixir gateway/relay/NS infrastructure, and eBPF packet filter. The macOS app connects to a gateway over encrypted UDP, multiplexes TCP streams, and exposes services on loopback VIPs with pf port redirection.

### Stress Test Baseline (v0.14.0)

| Concurrency | Success Rate | Latency (p50) |
|---|---|---|
| 1 (sequential) | 100% | 141ms |
| 2 | 98% | ~140ms |
| 5 | 90% | ~240ms |
| 10 | 86% | ~330ms |
| 20 | 80% | — |

**Root cause of concurrency drops:** The gateway processes FRAME_OPEN serially in a single GenServer, each opening a synchronous TCP connection to the backend (5s timeout). At 10+ concurrent streams, the GenServer mailbox backs up and some stream opens time out on the client side before the gateway processes them.

---

## Phase 1 — Gateway Stream Concurrency (High Impact, Medium Effort)

**Goal:** 95%+ success rate at concurrency 20.

### 1.1 Async Backend Connection in FRAME_OPEN
The gateway `Session` GenServer currently calls `Backend.start_link()` synchronously inside `handle_tunnel_frame/2`. This blocks the GenServer from processing other frames (including FRAME_DATA for already-open streams) while the TCP connect to Vaultwarden completes.

**Fix:** Spawn the backend connection asynchronously. Send FRAME_OPEN_ACK back to the client when ready, or FRAME_CLOSE on failure.

```elixir
# Before (blocking):
case Backend.start_link({host, port, self(), stream_id}) do
  {:ok, pid} -> ...

# After (async):
Task.start(fn ->
  case Backend.start_link({host, port, owner, stream_id}) do
    {:ok, pid} -> send(owner, {:backend_ready, stream_id, pid})
    {:error, _} -> send(owner, {:backend_failed, stream_id})
  end
end)
```

Buffer incoming FRAME_DATA for a stream until `{:backend_ready, ...}` arrives. Estimated: ~200 lines.

### 1.2 Client-Side Stream Open Queuing
The VIP proxy currently fires FRAME_OPEN and immediately starts forwarding TCP data. If the gateway hasn't opened the backend yet, the data frames hit a closed stream.

**Fix:** Add a per-stream state machine: `opening → open → closing → closed`. Buffer TCP reads during `opening`. Timeout after 10s if no FRAME_DATA arrives from gateway.

### 1.3 Gateway Send Window Tuning
Current: `@send_window_size 64`, `@pacing_interval_ms 1`. The pacing sends 1 packet per ms = 1000 pkt/sec. With 1200-byte payloads, that's ~1.2 MB/s throughput ceiling.

**Fix:** Increase to `@send_window_size 256` and dynamically adjust pacing based on RTT. Target: 10+ MB/s sustained throughput for concurrent streams.

**Expected result:** 95%+ at concurrency 20, latency under 500ms.

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

## Phase 5 — Mobile Clients (High Impact, Very High Effort)

**Goal:** iOS and Android apps with the same VIP proxy architecture.

### 5.1 iOS App (SwiftUI + NetworkExtension)
The macOS FFI layer (`libztlp_proto.a`) is already cross-compiled for arm64. The iOS project skeleton exists.

**Work:** NetworkExtension packet tunnel provider, iOS-appropriate UI (no menu bar), on-demand VPN rules, background keepalive, battery-efficient reconnect.

### 5.2 Android App (Kotlin + VpnService)
JNI bindings to `libztlp_proto.so`. Android VpnService for tun interface.

**Work:** JNI FFI wrapper, VpnService implementation, split tunnel routing, battery optimization (Doze-aware keepalive).

### 5.3 Shared Tunnel Core Refactor
Extract tunnel management (connect/disconnect/reconnect/keepalive/VIP) into a platform-agnostic Rust library. Platform-specific code (NetworkExtension, VpnService, pf redirect) stays in Swift/Kotlin.

**Expected result:** ZTLP accessible from any device.

---

## Phase 6 — Security Hardening for Production (Critical, Medium Effort)

**Goal:** Defense-in-depth beyond the current Noise_XX + ChaCha20 baseline.

### 6.1 Certificate Pinning
Pin the gateway's static public key in the client config. Reject connections to unknown gateways even if Noise handshake succeeds.

### 6.2 Key Rotation
Rotate session keys every 2^32 packets or 24 hours (whichever first). New frame type: `FRAME_REKEY (0x0A)`. Both sides derive new keys from the current ones via HKDF. Zero-downtime — no reconnect needed.

### 6.3 Mutual Device Attestation
Extend the enrollment system to verify device identity on every connection:
- macOS: Secure Enclave attestation
- iOS: DeviceCheck / App Attest
- Android: Play Integrity / Key Attestation

### 6.4 Audit Trail
Structured audit log of all connections, stream opens, policy decisions, and authentication events. Ship to SIEM (Splunk, Elastic, etc.) via syslog or webhook.

### 6.5 Post-Quantum Readiness
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

| Phase | Impact | Effort | Priority |
|---|---|---|---|
| **1: Gateway Concurrency** | High | Medium | 🔴 Do First |
| **2: Connection Pooling** | Medium | Low | 🔴 Do First |
| **6: Security Hardening** | Critical | Medium | 🟡 Do Soon |
| **3: UDP Transport** | High | High | 🟡 Do Soon |
| **7: Ops Excellence** | Medium | Low-Medium | 🟢 Steady |
| **4: Multi-Service** | Medium | High | 🟢 Steady |
| **5: Mobile Clients** | High | Very High | 🔵 Later |

---

## Quick Wins (can ship in a day each)

1. **Async FRAME_OPEN** (Phase 1.1) — biggest bang for buck, fixes the concurrency drop
2. **Backend connection pool** (Phase 2.1) — cuts repeat latency in half
3. **Send window tuning** (Phase 1.3) — pure config change, immediate throughput improvement
4. **Certificate pinning** (Phase 6.1) — ~50 lines, significant security improvement
5. **Client metrics export** (Phase 7.1) — visibility into tunnel health
