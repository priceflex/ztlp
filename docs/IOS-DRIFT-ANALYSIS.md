# iOS Drift Analysis — v0.23.0 → v0.24.0

**Date:** 2026-04-09
**Scope:** All changes from iOS optimization sessions 1–5C (40+ commits)
**Baseline:** v0.23.0 (commit b886d36)
**Current:** 11/11 iOS benchmarks passing (commit 1d6bf3c)

## Executive Summary

Over 5 iOS debugging sessions, we fixed iOS benchmarks from 0/11 to 11/11.
The fixes touched three layers: iOS-only Swift code, shared Rust proto crate,
and server-side Elixir gateway/relay. While iOS-only code is cleanly isolated
behind feature gates, several shared constants were tuned for iOS's 15MB
Network Extension memory limit and now apply to ALL platforms — crippling
Linux/macOS desktop performance.

This document catalogs every cross-platform impact and the remediation plan.

---

## 1. iOS-Only Changes (Zero Cross-Platform Impact)

These are fully isolated — no action needed:

| Component | What Changed |
|-----------|-------------|
| Swift files | PacketTunnelProvider rewrite, new ZTLPTunnelConnection, ZTLPVIPProxy, ZTLPBridge |
| Rust FFI (ios-sync) | Sync crypto FFI, standalone PacketRouter, sync handshake — all behind `#[cfg(not(feature = "tokio-runtime"))]` |
| Feature gates in lib.rs | 16 modules gated behind `tokio-runtime` (excluded from iOS builds) |
| iOS headers | ztlp.h expansions for new FFI functions |
| Documentation | 6 session status docs, IOS-MEMORY-OPTIMIZATION.md |

---

## 2. Shared Rust Constants — Before vs After

### 2A. Cargo.toml [profile.release] — NEW (did not exist pre-iOS)

```toml
# CURRENT — applies to ALL platforms in release mode
[profile.release]
lto = true
codegen-units = 1
strip = true
opt-level = "z"     # optimize for SIZE not SPEED
panic = "abort"     # no unwinding
```

**Impact:** Linux/macOS release builds are 10-30% slower (size-optimized),
cannot catch panics (abort instead of unwind), and lose debug symbols.

**Fix:** Move to target-specific profile or remove for non-iOS.

### 2B. Cargo.toml [features] — NEW (did not exist pre-iOS)

```toml
[features]
default = ["tokio-runtime"]
tokio-runtime = [dep:tokio, dep:tokio-rustls, dep:clap, ...]
ios-sync = []
```

**Impact:** Low risk. Default features include tokio-runtime, so Linux/macOS
get all dependencies. tokio changed from `features = ["full"]` to explicit
list — verify no missing features.

### 2C. transport.rs

| Constant | Pre-iOS | Current | Change |
|----------|---------|---------|--------|
| MAX_PACKET_SIZE | 65535 | 2048 | 32x smaller |

**Impact:** Any UDP packet >2048 bytes truncated on receive. Safe for ZTLP
(packets are ~1200-1400B) but removes safety margin.

**Fix:** Restore to 65535 or at least 8192 for non-iOS.

### 2D. vip.rs

| Constant | Pre-iOS | Current | Change |
|----------|---------|---------|--------|
| TCP_READ_BUF_SIZE | 65536 | 4096 | 16x smaller |
| MAX_CONCURRENT_CONNECTIONS | 64 | 8 | 8x fewer |
| CONNECTION_IDLE_TIMEOUT_SECS | 300 | 35 | 8.5x shorter |
| MAX_MUX_PAYLOAD | 1195 | 1135 | 60B smaller |
| mpsc channel capacity | 256 | 64 | 4x smaller |

**Impact:** Desktop clients limited to 8 concurrent TCP connections (was 64),
35s idle timeout kills long-lived connections, 4KB read buffer slows bulk
transfers. These are the most impactful changes for desktop performance.

**Fix:** `#[cfg(target_os)]` conditional constants.

### 2E. tunnel.rs

| Constant | Pre-iOS | Current | Change |
|----------|---------|---------|--------|
| MAX_SUB_BATCH | 64 | 16 | 4x smaller |
| MAX_PLAINTEXT_PER_PACKET | 16375 | 1200 | 13.6x smaller |

**Impact:** Massive fragmentation — a 16KB send now requires ~14 packets
instead of 1. Dramatically increases packet overhead on fast networks.

**Fix:** Per-platform gate. iOS: 1200, desktop: 16375.

### 2F. ffi.rs — Tokio Runtime

| Setting | Pre-iOS | Current | Change |
|---------|---------|---------|--------|
| worker_threads | system default (num_cpus) | 2 | Fixed at 2 |
| thread_stack_size | system default (8MB) | 256KB | 32x smaller |

**Impact:** Desktop clients on 8-core machines use only 2 async workers.
256KB stacks may cause stack overflow on deep call chains.

**Fix:** `#[cfg(target_os = "ios")]` gate.

### 2G. packet_router.rs

| Constant | Pre-iOS | Current | Change |
|----------|---------|---------|--------|
| OUTBOUND_MAX_PACKETS | (unlimited) | 128 | New cap |

**Impact:** Low. Drops oldest packets under extreme load. Reasonable for
all platforms.

**Fix:** Consider 512 for desktop, keep 128 for iOS.

### 2H. session.rs

| Field | Pre-iOS | Current | Change |
|-------|---------|---------|--------|
| send_seq type | u64 | Arc\<AtomicU64\> | Thread-safe |

**Impact:** Low. Functionally equivalent. Any code reading .send_seq
directly needs .load(Relaxed).

### 2I. send_controller.rs — Protocol Change

| Behavior | Pre-iOS | Current |
|----------|---------|---------|
| Retransmit seq | Allocate new packet_seq | Reuse original packet_seq |
| Pending queue | Unlimited | Capped at 2048 |
| ACK priority | Through cwnd | Bypass cwnd (priority queue) |

**Impact:** PROTOCOL-LEVEL CHANGE. Gateway and ALL clients must be updated
simultaneously. Old client + new gateway = recv_window pollution from
duplicate seq entries.

---

## 3. Gateway Congestion Control — Before vs After

### 3A. session.ex

| Parameter | Pre-iOS | Current | Change |
|-----------|---------|---------|--------|
| @initial_cwnd | 64 | 10.0 | 6.4x smaller |
| @max_cwnd | 256 | 32 | 8x smaller |
| @initial_ssthresh | 128 | 64 | 2x smaller |
| @loss_beta | (implicit 0.5) | 0.7 | Gentler backoff |
| @min_ssthresh | (none) | 8 | New floor |
| @max_rto_ms | 30000 | 5000 | 6x faster timeout |
| @stall_timeout_ms | (none) | 30000 | New zombie detection |
| @pacing_interval_ms | 1 | 4 | 4x slower pacing |
| @burst_size | 8 | 3 | 2.7x smaller bursts |
| @max_payload_bytes | 1200 | 1140 | 60B smaller |

**Impact:** Desktop clients on fast networks (100Mbps+) will be throttled
to ~mobile speeds. max_cwnd=32 with 1140B payloads = ~36KB window = terrible
on high-BDP links.

**Fix:** Per-client-type CC profiles, or detect link capacity and adjust.

### 3B. bbr.ex

| Parameter | Pre-iOS | Current | Change |
|-----------|---------|---------|--------|
| @max_cwnd | 256 | 512 | 2x larger |

**Impact:** BBR headroom increased (good).

### 3C. New Gateway Features (all beneficial)

- TCP NewReno recovery mode (dup_ack_count, fast_retransmit)
- Backend backpressure (active:true → active:once)
- Recv window gap-skip after 2s stall
- Client FIN handling (half-close)
- Stream FIN/CLOSE as in-band sentinels (reliable delivery)

### 3D. Relay Changes

- Session-ID based routing for NAT rebinding (backwards compatible)
- update_client_addr() for mobile roaming
- Fallback to any dynamic gateway

---

## 4. Remediation Plan

### Priority 1 — Must Fix (breaks desktop performance)

| # | File | Fix | Effort |
|---|------|-----|--------|
| 1 | Cargo.toml | Remove [profile.release] or make iOS-only | 5 min |
| 2 | ffi.rs | Gate worker_threads/stack_size behind target_os=ios | 10 min |
| 3 | vip.rs | Per-platform constants via cfg | 15 min |
| 4 | tunnel.rs | Per-platform MAX_PLAINTEXT_PER_PACKET | 10 min |

### Priority 2 — Should Fix

| # | File | Fix | Effort |
|---|------|-----|--------|
| 5 | transport.rs | Restore MAX_PACKET_SIZE to 65535 | 5 min |
| 6 | session.ex | Per-client CC profiles or dynamic adjustment | 30 min |
| 7 | packet_router.rs | Larger OUTBOUND_MAX_PACKETS for desktop | 5 min |

### Priority 3 — Validate

| # | Item | Action |
|---|------|--------|
| 8 | tokio features | Verify explicit list covers all usage |
| 9 | Retransmit seq change | Ensure all clients updated together |
| 10 | Linux benchmark | Full test suite after fixes |

---

## 5. Testing Plan

After remediation:
1. Build proto with `cargo build --release` on Linux — verify no regressions
2. Run `ztlp-bench` against gateway — compare throughput pre/post
3. Run `ztlp-demo` end-to-end — verify basic connectivity
4. Rebuild iOS with `cargo build --target aarch64-apple-ios --release --features ios-sync --no-default-features` — verify 11/11 still passes
5. Deploy updated gateway — verify both iOS and Linux clients work
