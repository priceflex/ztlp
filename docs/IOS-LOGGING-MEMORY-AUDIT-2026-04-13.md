# iOS Logging Memory Audit — 2026-04-13

## Summary

Verified audit of current iOS Network Extension (NE) logging and packet-path
allocation behavior in the working tree on 2026-04-13.

**Verdict: Yes, a Rust recompile is required for the highest-impact fix.** The
current `diag_log!` macro in `proto/src/ffi.rs` is always compiled and calls
`ios_log()`/NSLog on hot recv-loop paths. The Swift logger append fix is
already present, but Swift still has a periodic full-file rotation read and DNS
still performs per-query debug logging.

## Verification Notes

The findings below were confirmed directly against the current tree:

- `proto/Cargo.toml` has `default = ["tokio-runtime"]` and `ios-sync = []`, but
  no `diag` feature yet.
- `proto/src/ffi.rs` defines an unconditional `diag_log!` macro at lines 67-72.
- `proto/src/ffi.rs` still emits `diag_log!` inside recv-loop hot paths
  (`FRAME_ACK`, `FRAME_DATA`, duplicate re-ACK, periodic diag report, etc.).
- `ios/ZTLP/ZTLP/Services/TunnelLogger.swift` already uses append-only
  `FileHandle.seekToEnd()` + `write()` in `appendLine()`.
- `TunnelLogger.rotateLogIfNeeded()` still reads the entire file into a String
  and trims by line count.
- `ios/ZTLP/ZTLPTunnel/ZTLPDNSResponder.swift` still logs every query and still
  formats `Array(serviceMap.keys)` on NXDOMAIN misses.

---

## What Was Already Fixed

- **TunnelLogger.swift `appendLine()`** — Now uses `FileHandle.seekToEnd()` +
  `write()` (append-only). The old read-modify-write-entire-file pattern that
  caused ~1.2MB transient allocations per log call is gone.

- **Memory soft-limit throttle removed** — `shouldThrottleRouterWork()` no longer
  checks resident memory against a 12MB limit. It only checks
  `tunnelConnection.isOverloaded`. The self-defeating feedback loop (throttle →
  log warning → spike memory → throttle harder) is eliminated.

---

## Issue 1: Rust `diag_log!` — Per-Packet NSLog (REQUIRES RECOMPILE)

**File:** `proto/src/ffi.rs`
**Severity:** High — hot-path heap allocations on every packet

### Problem

The `diag_log!` macro (line 67) calls `ios_log()` which invokes NSLog via raw
CFString FFI on every call. There are multiple call sites in `ffi.rs`, including
these recv-loop hot-path examples confirmed in the current tree:

| Line | Call | Frequency |
|------|------|-----------|
| 1413 | `[ZTLP-RX] {} bytes, first_byte=0x{:02x}` | Every packet received |
| 1469 | `[ZTLP-RX] FRAME_ACK (upload) acked_seq={} len={}` | Every upload ACK |
| 1527 | `[ZTLP-RX] FRAME_DATA stream={} data_seq={} payload={} expected={}` | Every data frame |
| 1595 | `[ZTLP-RX] DUPLICATE data_seq={} (expected={})` | Every duplicate |
| 1605 | `[ZTLP-TX] re-ACK ack_seq={} for dup data_seq={}` | Every duplicate re-ACK |
| 1634 | `[ZTLP-DIAG] reassembly_buf FULL ...` | Every over-cap insertion |
| 1719 | `[ZTLP-TX] ACK ack_seq={} via callback` | Every ACK sent |
| 1736 | periodic `[ZTLP-DIAG] pkts=...` report | Periodic while traffic flows |
| 1855 | `[ZTLP-RX] packet dropped (pipeline/decrypt)` | Every dropped packet |

Each invocation performs:
1. `format!()` — heap-allocated String
2. `CString::new()` — second heap allocation
3. `CFStringCreateWithCString()` — CoreFoundation object allocation
4. `NSLog()` — system log write
5. `CFRelease()` — deallocation

Under heavy traffic (thousands of packets/sec), this is significant memory
churn. There is currently no compile flag, feature gate, or runtime toggle to
disable it — `diag_log!` is unconditionally active on all iOS builds.

### Fix

Add a `diag` feature flag in `Cargo.toml` and gate the macro:

```toml
# proto/Cargo.toml [features]
diag = []
```

```rust
// proto/src/ffi.rs — replace the existing macro

#[cfg(feature = "diag")]
macro_rules! diag_log {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        ios_log(&msg);
    }};
}

#[cfg(not(feature = "diag"))]
macro_rules! diag_log {
    ($($arg:tt)*) => {};
}
```

Production NE builds use `--no-default-features --features ios-sync` today, so
once `diag` exists and is left disabled, the hot-path NSLog calls compile to
zero-cost no-ops. Diagnostic builds can opt in with `--features ios-sync,diag`
when needed.

The existing leveled `log_write()` file logger (recv-loop local helper around
lines 1276-1370) already provides persistent diagnostics with rotation and
level control via `ZTLP_LOG_LEVEL` and `ZTLP_LOG_FILE`, so observability is not
lost by removing unconditional NSLog spam from production builds.

---

## Issue 2: Swift Log Rotation Reads Entire File (Swift-only fix)

**File:** `ios/ZTLP/ZTLP/Services/TunnelLogger.swift`
**Severity:** Medium — periodic spike every 60 seconds

### Problem

`rotateLogIfNeeded()` (line 218) still loads the entire log file into a String
to count lines:

```swift
guard let contents = try? String(contentsOf: url, encoding: .utf8) else {
    return
}
let lines = contents.split(separator: "\n", omittingEmptySubsequences: true)
```

With `maxLines = 5000` and typical log lines around ~100 bytes, this is a
~500KB read/allocation pass every 60 seconds. That is much better than the old
per-append full rewrite, but it still creates avoidable periodic memory pressure
inside a constrained Network Extension process.

### Fix

Replace line-counting with a file-size cap. Approximate: 5000 lines × ~100
bytes = ~500KB. Use `FileManager.attributesOfItem` to check size without
reading the file:

```swift
private static let maxFileSize: UInt64 = 512 * 1024  // 512KB

private func rotateLogIfNeeded(now: Date, url: URL) {
    guard now.timeIntervalSince(lastRotationCheck) >= Self.rotationCheckInterval else {
        return
    }
    lastRotationCheck = now

    guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
          let size = attrs[.size] as? UInt64,
          size > Self.maxFileSize else {
        return
    }

    // Truncate: read last ~256KB, write back
    if let handle = try? FileHandle(forReadingFrom: url) {
        let keepBytes: UInt64 = Self.maxFileSize / 2
        if size > keepBytes {
            handle.seek(toFileOffset: size - keepBytes)
        }
        let tail = handle.readDataToEndOfFile()
        handle.closeFile()
        try? tail.write(to: url, options: .atomic)
    }
}
```

No Rust recompile needed — Swift-only change.

---

## Action Plan

| # | Task | Scope | Recompile? |
|---|------|-------|------------|
| 1 | Add `diag` feature flag, gate `diag_log!` macro | Rust `proto/src/ffi.rs` + `Cargo.toml` | **Yes** |
| 2 | Rebuild NE lib without `diag` feature | `cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync` | **Yes** |
| 3 | Replace rotation line-count with file-size check | Swift `TunnelLogger.swift` | No |
| 4 | Rebuild in Xcode (Clean Build Folder first) | Xcode | N/A |

---

---

## Issue 3: Per-Packet Data Copies in Swift Hot Path (Swift-only)

**Files:** `ZTLPTunnelConnection.swift`, `PacketTunnelProvider.swift`
**Severity:** Medium — allocations on every packet in/out

### Problem

Every received packet creates 2-3 new `Data` objects in the hot path:

1. **Decrypt output copy** (`ZTLPTunnelConnection.swift` line 652-677):
   Mux frame parsing builds new `Data` objects from `decryptBuffer` slices:
   ```swift
   var muxFrame = Data(capacity: 5 + payloadLen)  // alloc
   muxFrame.append(...)                            // copy
   ```
   This happens for every FRAME_DATA received from the gateway.

2. **Encrypt output copy** (`ZTLPTunnelConnection.swift` line 399):
   ```swift
   let wireData = Data(bytes: encryptBuffer, count: encryptWritten)
   ```
   Every outbound packet copies from the reusable buffer into a new Data for
   NWConnection.send(). This is required by NWConnection's async send API
   (the buffer can't be reused until the completion handler fires), but each
   copy is a heap allocation.

3. **Router action extraction** (`PacketTunnelProvider.swift` line 709):
   ```swift
   let actionData: Data? = dataLen > 0 ? Data(actionBuffer[offset..<(offset+dataLen)]) : nil
   ```
   Every router action (OpenStream, SendData, CloseStream) copies data from
   the 256KB `actionBuffer` into a new `Data`.

4. **Outbound packet flush** (`PacketTunnelProvider.swift` line 818):
   ```swift
   packets.append(Data(readPacketBuffer[0..<Int(bytesRead)]))
   ```
   Every outbound packet from the router to utun creates a new `Data`.

### Impact

Under steady traffic (say 500 packets/sec in each direction), this is ~2000+
small heap allocations per second. Each is typically 100-1500 bytes. ARC
overhead and malloc fragmentation accumulate, contributing to the 18-21MB
resident memory baseline.

### Fix (Future)

Most of these are unavoidable with NWConnection's API — it requires owned Data.
Two mitigations:
- **Pool small Data objects** via a reusable buffer pool for common sizes
- **Reduce copies for mux parsing** — use `Data(bytesNoCopy:...)` with careful
  lifetime management where the decrypt buffer is guaranteed stable

This is a **low priority** optimization — the per-packet allocations are small
and short-lived. The diag_log NSLog issue (#1) is far more impactful.

---

## Issue 4: Rust `tracing::*` Calls Still Active in iOS Build (Rust)

**File:** `proto/src/ffi.rs`
**Severity:** Low-Medium

### Problem

There are many `tracing::info!()`, `tracing::debug!()`, and `tracing::warn!()`
calls scattered through `recv_loop`, ACK handling, backpressure handling, and
buffer-limit paths. Confirmed hot/near-hot examples in the current tree include:

- `tracing::debug!("recv_loop: FRAME_ACK...")` at line 1470
- `tracing::info!("recv_loop: re-ACK...")` at line 1606
- `tracing::warn!("recv_loop: reassembly buffer full...")` at line 1630
- `tracing::info!("recv_loop: ACK data_seq=...")` at line 1720
- `tracing::info!("recv_diag: ...")` at line 1742

The tracing subscriber is initialized with `EnvFilter::from_default_env()`, but
on iOS there is usually no `RUST_LOG` configured. Depending on the active level,
these calls still incur per-call filtering, metadata work, and sometimes
formatting overhead. This is much less severe than `diag_log!`, but still worth
eliminating from production NE hot paths when chasing RSS and CPU margin.

### Fix

Gate tracing behind the same `diag` feature flag as `diag_log!`:
```rust
#[cfg(feature = "diag")]
macro_rules! trace_log {
    ($($arg:tt)*) => { tracing::info!($($arg)*); }
}
#[cfg(not(feature = "diag"))]
macro_rules! trace_log {
    ($($arg:tt)*) => {};
}
```

Or more simply, wrap recv_loop tracing calls in `#[cfg(feature = "diag")]`
blocks. The file-based `log_write()` system handles all persistent logging.

---

## Issue 5: Reassembly Buffer Bounded but Holds Vec<u8> Payloads (Rust)

**File:** `proto/src/ffi.rs` line 1109
**Severity:** Low — bounded at 256 entries

### Problem

```rust
let mut reassembly_buf: BTreeMap<u64, (u32, Vec<u8>)> = BTreeMap::new();
const REASSEMBLY_MAX_ENTRIES: usize = 256;
```

Each out-of-order packet is stored as a `(stream_id, Vec<u8>)` in the BTreeMap.
With 256 max entries × ~1400 bytes per packet = ~350KB worst case. The buffer
IS bounded (line 1629 drops new entries when full), but the bound of 256 is
generous for a mobile client.

### Fix (Optional)

Reduce to 64 entries for the ios-sync build:
```rust
#[cfg(feature = "ios-sync")]
const REASSEMBLY_MAX_ENTRIES: usize = 64;
#[cfg(not(feature = "ios-sync"))]
const REASSEMBLY_MAX_ENTRIES: usize = 256;
```

Saves ~270KB worst-case. Low priority — only matters during heavy out-of-order
delivery.

---

## Issue 6: DNS Responder Per-Query Logging (Swift-only)

**File:** `ZTLPDNSResponder.swift`
**Severity:** Low

### Problem

Every DNS query currently logs via `TunnelLogger.shared.debug(...)`:
- Line 137: `DNS: qname=... qtype=... qclass=...`
- Line 141: `DNS: pass-through — not .ztlp suffix`
- Line 148: `DNS: NXDOMAIN for non-A query type=...`
- Line 159: `DNS: NXDOMAIN for ... (not in map: ...)`

iOS generates frequent AAAA, SVCB, and HTTPS queries for `.ztlp` domains.
Each triggers string interpolation and a file-log append. The I/O path is now
append-only, so the logger itself is much cheaper than before, but the message
construction still allocates on every query.

Additionally, the NXDOMAIN log at line 159 formats `Array(serviceMap.keys)` on
every miss, creating an avoidable temporary array/string allocation that has no
steady-state value.

### Fix

Gate DNS debug logging behind a compile flag or remove entirely for production.
The `Array(serviceMap.keys)` dump should definitely be removed — it serves no
purpose in steady state.

---

## Summary of All Issues Found

| # | Issue | Scope | Severity | Recompile? |
|---|-------|-------|----------|------------|
| 1 | `diag_log!` NSLog per packet (no gate) | Rust FFI | **High** | **Yes** |
| 2 | Log rotation reads entire file | Swift TunnelLogger | Medium | No |
| 3 | Per-packet Data copies in hot path | Swift NE | Medium | No |
| 4 | `tracing::*` calls active in iOS build | Rust FFI | Low-Med | Yes (with #1) |
| 5 | Reassembly buffer 256 entries (350KB) | Rust FFI | Low | Optional |
| 6 | DNS responder per-query logging + key dump | Swift DNS | Low | No |

---

## Action Plan

### Phase 1 — High Impact (Rust recompile required)
1. Add `diag` feature flag in `proto/Cargo.toml`
2. Gate `diag_log!` macro behind `#[cfg(feature = "diag")]`
3. Gate recv-loop hot-path `tracing::*` calls behind the same feature (or
   remove/convert them to the existing file logger in production builds)
4. Optionally reduce `REASSEMBLY_MAX_ENTRIES` to 64 for `ios-sync`
5. Rebuild NE lib using a clean ios-sync target dir to avoid stale cargo state:
   `cargo build --release --target aarch64-apple-ios --target-dir target-ios-sync --no-default-features --features ios-sync`

### Phase 2 — Swift-only source changes
6. Replace `rotateLogIfNeeded()` line-count trimming with a file-size check
7. Remove `Array(serviceMap.keys)` from the DNS NXDOMAIN message
8. Gate DNS per-query debug logs behind `#if DEBUG` or a static runtime flag
9. Rebuild in Xcode after Rust lib refresh: Clean Build Folder (⌘⇧K) → Build

### Phase 3 — Future validation / lower priority
10. Investigate whether mux parsing can avoid one copy safely
11. Profile RSS with Instruments on device before/after the Rust diag gating
12. If baseline is still high, revisit buffer pooling and `REASSEMBLY_MAX_ENTRIES`

---

## Related Documents

- `docs/IOS-MEMORY-OPTIMIZATION.md` — Original memory reduction plan
- `docs/SESSION-11-IOS-NS-MEMORY-AUDIT.md` — NE memory audit
- `.hermes/plans/2026-04-12-ne-throttle-analysis-and-fix.md` — Throttle removal plan
