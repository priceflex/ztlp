# Session 6: iOS Drift Analysis & Cross-Platform Fix

**Date:** 2026-04-09
**Commits:** 359bf6b → 32110b5 (6 commits)
**Branch:** main

## What We Did

Audited the entire iOS optimization effort (sessions 1–5C, 40+ commits) to
measure cross-platform drift, then fixed desktop/server builds and attempted
to restore gateway CC for all platforms.

## Commits This Session

```
32110b5 doc: client-type detection design spec — mobile vs desktop CC profiles
ffb4698 Revert "fix: restore pre-iOS CC parameters — memory was the real bottleneck"
4834398 fix: restore pre-iOS CC parameters — memory was the real bottleneck
5d3e26a fix: restore desktop-optimized defaults — gate iOS constants behind target_os
359bf6b doc: iOS drift analysis — cross-platform impact assessment
```

## Key Deliverables

### 1. Drift Analysis (docs/IOS-DRIFT-ANALYSIS.md)

Catalogued every shared-code change from iOS work and its cross-platform impact.
Found 7 files with iOS-tuned constants silently applied to ALL platforms.

### 2. Desktop Constants Fixed (commit 5d3e26a)

All iOS-tuned constants gated behind `#[cfg(target_os = "ios")]`:

| File | Constant | iOS | Desktop (restored) |
|------|----------|-----|-------------------|
| Cargo.toml | opt-level | "z" (size) | 3 (speed) |
| ffi.rs | tokio workers | 2 / 256KB | system default |
| vip.rs | TCP_READ_BUF | 4KB | 64KB |
| vip.rs | MAX_CONNECTIONS | 8 | 64 |
| vip.rs | IDLE_TIMEOUT | 35s | 300s |
| vip.rs | channel capacity | 64 | 256 |
| tunnel.rs | MAX_SUB_BATCH | 16 | 64 |
| transport.rs | MAX_PACKET_SIZE | 2048 | 65535 |
| packet_router.rs | OUTBOUND_MAX | 128 | 512 |
| .cargo/config.toml | iOS rustflags | opt-level=z, panic=abort | (new file) |

Also added missing tokio `process` feature to Cargo.toml.

**Verified:** 1,253 tests pass on Linux (debug + release). macOS + iOS lib compile clean.

### 3. Gateway CC Experiment (commits 4834398 + ffb4698)

**Hypothesis:** Conservative mobile CC (initial_cwnd=10, max_cwnd=32) was only
needed because of iOS memory pressure. Now that memory is fixed (sync FFI,
tokio stripped, buffers capped), we can restore pre-iOS CC.

**Test:** Restored initial_cwnd=64, max_cwnd=256, ssthresh=128, pacing=1ms×8.

**Result:** 5/11 iOS benchmarks — FAILED. Reverted.

**Conclusion:** The mobile CC is genuinely needed for the cellular/relay path,
not just a memory workaround. Desktop clients need their own CC profile.

### 4. New Gateway Server

Old gateway (54.149.48.6) died. New server deployed:

| Component | Details |
|-----------|---------|
| Server | 44.246.33.34 (private 172.26.11.164) |
| Gateway | ztlp-gateway:mobile-cc, port 23097, --network host |
| HTTP Backend | python:3.12-slim Flask container, 127.0.0.1:8180 |
| Bootstrap | Machine id=8 updated to new IP, status=ready |
| SSH | ubuntu@44.246.33.34, key in bootstrap DB |

Gateway env vars:
```
ZTLP_GATEWAY_PORT=23097
ZTLP_RELAY_SERVER=172.26.5.220:23095
ZTLP_NS_SERVER=172.26.13.85:23096
ZTLP_GATEWAY_BACKENDS=default:127.0.0.1:8080,http:127.0.0.1:8180,vault:127.0.0.1:8080
ZTLP_GATEWAY_SERVICE_NAMES=default,http,vault
```

HTTP echo endpoints: /ping, /health, /echo?size=N, /upload (POST), /download/<mb>

### 5. Client-Type Detection Design (docs/CLIENT-TYPE-DETECTION.md)

Design spec for per-client CC profiles. Client self-reports its type in the
Noise_XX handshake (15-80 bytes in encrypted message 3).

**CC Profiles:**

| Profile | cwnd_init | cwnd_max | pacing | burst |
|---------|-----------|----------|--------|-------|
| mobile_cellular | 5 | 16 | 6ms | 2 |
| mobile_wifi | 10 | 32 | 4ms | 3 |
| desktop | 64 | 256 | 1ms | 8 |
| server | 64 | 512 | 0.5ms | 16 |

**Implementation phases:**
- Phase 1: ClientProfile in handshake (~1 day) — client reports Mobile/Desktop + Cellular/WiFi
- Phase 2: Mid-session NetworkStatusUpdate (~1 day) — handle WiFi↔cellular transitions
- Phase 3: Passive RTT fallback (~1 day) — heuristic detection for legacy clients

## Current State

- **iOS:** 11/11 benchmarks with mobile CC ✓
- **Linux/macOS builds:** Desktop-optimized constants restored, 1,253 tests pass ✓
- **Gateway CC:** Mobile-tuned for all clients (desktop throttled until Phase 1 implemented)
- **Gateway server:** 44.246.33.34 running ztlp-gateway:mobile-cc ✓

## Next Steps

1. **Implement Phase 1 of client-type detection** — ClientProfile struct in proto,
   populate in CLI + iOS FFI, gateway reads and selects CC profile
2. **Re-run iOS benchmark** after Phase 1 to confirm mobile CC still passes 11/11
3. **Run Linux ztlp-bench** against gateway with desktop CC to verify throughput
4. **Consider Phase 2** mid-session network updates if WiFi↔cellular is common

## Files Changed This Session

```
docs/IOS-DRIFT-ANALYSIS.md      — NEW: full drift catalog
docs/CLIENT-TYPE-DETECTION.md   — NEW: client-type detection design spec
proto/.cargo/config.toml        — NEW: per-target iOS rustflags
proto/Cargo.toml                — [profile.release] + tokio features
proto/src/ffi.rs                — tokio runtime per-platform gate
proto/src/vip.rs                — per-platform constants
proto/src/tunnel.rs             — per-platform MAX_SUB_BATCH
proto/src/transport.rs          — per-platform MAX_PACKET_SIZE
proto/src/packet_router.rs      — per-platform OUTBOUND_MAX_PACKETS
gateway/lib/ztlp_gateway/session.ex — CC restore attempted + reverted
```
