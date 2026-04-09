# Session 7: Client-Type Detection Implementation

**Date:** 2026-04-09
**Status:** Code complete, gateway deployed, iOS build working

## What Was Done

Implemented all 8 tasks from `CLIENT-TYPE-DETECTION-PLAN.md`:

### Rust (proto crate)
1. **ciborium 0.2** added to Cargo.toml (always-on, needed for iOS too)
2. **ClientProfile struct** (`proto/src/client_profile.rs`) with CBOR serialization
   - Enums: ClientClass (Mobile/Desktop/Server), InterfaceType (Cellular/WiFi/Wired), RadioTech (2G-5G)
   - Compact serde rename keys ("c", "i", "r", "l", "s") → 15-80 bytes CBOR
   - 4 unit tests passing
3. **Tokio FFI** (`proto/src/ffi.rs`) sends `ClientProfile::desktop()` in msg3
4. **iOS sync FFI** — `ztlp_set_client_profile(interface_type, radio_tech, is_constrained)` 
   - Stores profile in global Mutex, consumed by `ztlp_connect_sync()`
   - If not set, sends empty payload (backward compat)
5. **CLI binary** (`proto/src/bin/ztlp-cli.rs`) also sends desktop profile

### Swift (iOS)
6. **PacketTunnelProvider.swift** calls `ztlp_set_client_profile()` before connect
   - Uses `NWPathMonitor().currentPath` from Network framework (NOT `self.defaultPath`)
   - CoreTelephony for radio tech detection (2G/3G/LTE/5G)
   - `isConstrained` for Low Data Mode

### Elixir (Gateway)
7. **session.ex** parses ClientProfile from msg3 payload (was discarding `_payload`)
8. **session.ex** selects CC profile per client type:
   - mobile+cellular: cwnd=5/16, pacing=6ms (most conservative)
   - mobile+wifi: cwnd=10/32, pacing=4ms (current behavior)
   - desktop: cwnd=64/256, pacing=1ms (full speed)
   - server: cwnd=64/512, pacing=1ms (max throughput)
   - unknown/legacy: cwnd=10/32, pacing=4ms (safe fallback)

## Gateway Deployment
- New image `ztlp-gateway:client-type` built and deployed to 44.246.33.34:23097
- Verified desktop detection in gateway logs:
  ```
  class=desktop → CC: cwnd=64.0 max=256 pacing=1ms burst=8
  ```
- Legacy clients fall back correctly:
  ```
  class=unknown → CC: cwnd=10.0 max=32 pacing=4ms burst=3
  ```

## iOS Build Notes (IMPORTANT)

### Build command for iOS staticlib
```bash
cd proto
# Build with BOTH default features (tokio-runtime) AND ios-sync
cargo build --release --target aarch64-apple-ios --features ios-sync --lib
# Copy to Xcode Libraries dir
cp target/aarch64-apple-ios/release/libztlp_proto.a \
   ~/ztlp/ios/ZTLP/Libraries/libztlp_proto.a
# Also copy updated header
cp proto/include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h
```

### Critical: ONE lib for both targets
- **Both** the ZTLP app and ZTLPTunnel extension link the **same** `libztlp_proto.a`
- Must build with default features (includes tokio) — the main app needs tokio FFI symbols
- Do NOT use `--no-default-features --features ios-sync` — that strips tokio symbols
  and causes 23 "Undefined symbol" linker errors in the main app
- The NE only calls sync FFI functions; tokio code is linked but never initialized
- Separate `_ne` lib approach was attempted but caused Xcode build config issues

### Interface detection
- Uses `NWPathMonitor().currentPath.usesInterfaceType()` from `import Network`
- Do NOT use `self.defaultPath` — that's `NWPath` from NetworkExtension which
  lacks `usesInterfaceType()` (compile error)

### Header sync
- After adding new FFI functions, MUST copy `proto/include/ztlp.h` to
  `ios/ZTLP/Libraries/ztlp.h` — the bridging header includes from Libraries/

## Commits
```
ef227ba feat: add ciborium CBOR dep + ClientProfile struct for handshake metadata
e85ad15 feat: send ClientProfile in Noise_XX msg3 payload (desktop default)
d6ec1d4 feat: iOS sync FFI sends mobile ClientProfile in handshake
5b8a62a feat: iOS NE reports network type in client profile
880c4a6 feat: gateway parses ClientProfile and selects CC profile per client type
4587756 fix: ztlp CLI connect also sends ClientProfile in msg3
796610a fix: use NWPathMonitor instead of NEPacketTunnelProvider.defaultPath
4ab240f fix: revert to single libztlp_proto.a for both targets
```

## iOS Benchmark Result: 11/11 ✓

Confirmed working at 19:51 UTC. All 11 tests pass with mobile CC profile.

## Key Lessons Learned

1. **NWPathMonitor + CTTelephonyNetworkInfo add ~4MB runtime memory** — pushed NE from ~15MB to 19.6MB, causing jetsam kills. Stripped in favor of lightweight `ztlp_set_client_profile(0,0,0)`.

2. **Tokio FFI path needs `#[cfg(target_os = "ios")]` gating** — in-app benchmark uses tokio FFI which was sending `ClientProfile::desktop`, causing gateway to apply aggressive desktop CC (cwnd=64/256) that overwhelmed mobile connections. Now sends mobile on iOS, desktop on other platforms.

3. **Two-lib approach works but fragile** — `libztlp_proto_ne.a` (26MB, no tokio) for NE, `libztlp_proto.a` (54MB, full tokio) for main app. pbxproj editing must match config IDs to targets via XCConfigurationList, not by line proximity.

4. **Always sync ztlp.h** — `cp proto/include/ztlp.h ios/ZTLP/Libraries/ztlp.h` after any FFI changes. Git stash/pull can revert this.

## Commits (full session)
```
ef227ba feat: add ciborium CBOR dep + ClientProfile struct
e85ad15 feat: send ClientProfile in msg3 (desktop default)
d6ec1d4 feat: iOS sync FFI sends mobile ClientProfile
5b8a62a feat: iOS NE reports network type in client profile
880c4a6 feat: gateway parses ClientProfile and selects CC profile
4587756 fix: ztlp CLI connect also sends ClientProfile in msg3
796610a fix: use NWPathMonitor instead of NEPacketTunnelProvider.defaultPath
c897949 fix: correct two-lib linking — tunnel=_ne, app=_proto
dff5c51 fix: strip NWPathMonitor/CoreTelephony from NE — saves ~4MB
f774f12 fix: tokio FFI sends mobile profile on iOS, desktop elsewhere
```

## Next Steps
- Desktop/Linux testing — verify `class=desktop → cwnd=64/256` gives higher throughput
- macOS testing — same desktop CC profile
- Windows testing — cross-compile and verify
- Phase 2: Mid-session NetworkStatusUpdate (WiFi↔cellular transitions)
- Phase 3: Passive RTT-based fallback for legacy clients
- Phase 2 iOS: Lightweight interface detection without heavy frameworks
