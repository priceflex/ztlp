# ZTLP Safari Fix + NE Memory Fix — Morning Action Plan
# Date: 2026-04-14

## Problem
1. Safari shows "Can't Open Page" when tapping service links (vault.ztlp etc.)
2. NE gets killed by iOS memory pressure (~21MB → limit is ~15MB)
3. Both issues are interconnected: DNS works while NE is alive, but NE dies too fast

## Fix Summary (all code committed)

### Safari Fix
- Replace `SFSafariViewController` (out-of-process, ignores tunnel DNS) with `WKWebView` (in-app browser)
- VIP IP resolution: `vault.ztlp` → `10.122.0.4` before loading in browser — bypasses DNS entirely
- Service cards, benchmark links, and quick actions all use the in-app browser
- File: `ios/ZTLP/ZTLP/Extensions/SafariHelper.swift`

### NE Memory Fix
1. action buffer reduced 256KB → 64KB (saves 192KB)
2. Flow cleanup: `cleanup_stale_flows()` FFI binding added — Swift calls it every 10s
3. Memory diagnostics: logs router stats and NE memory every 10s
4. Files: `proto/src/ffi.rs`, `proto/src/packet_router.rs`, `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`, `ios/ZTLP/Libraries/ztlp.h`

## Commands to Run (on Mac)

```bash
cd ~/ztlp

# Pull latest
git pull origin main

# Rebuild NE static library for iOS
cargo build --target aarch64-apple-ios --no-default-features --features ios-sync --target-dir /tmp/ztlp-ios-ne
cp /tmp/ztlp-ios-ne/aarch64-apple-ios/release/libztlp_proto.a \
   ./ios/ZTLP/Libraries/libztlp_proto_ne.a

# Build in Xcode (or use xcodebuild)
cd ios/ZTLP
xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
  -destination 'generic/platform=iOS' -configuration Release build \
  CODE_SIGN_IDENTITY='' CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO

# Deploy to iPhone from Xcode GUI
# 1. Open ZTLP.xcodeproj in Xcode
# 2. Select your iPhone as destination
# 3. Press Run (⌘R)
```

## Verification After Building

1. Open app, connect to tunnel
2. Tap "Open Vault" or any service card
3. Should open in-app browser (WKWebView) with toolbar at top
4. Check Xcode console for:
   - "Cleaned up N stale TCP flows" messages
   - "Router stats: flows=X outbound=Y" messages
   - Memory should stay under 15MB
5. If Safari says "Can't Open Page" → check console for DNS errors

## Files Changed (5 files)

1. `ios/ZTLP/ZTLP/Extensions/SafariHelper.swift` — VIP URL resolution + WKWebView
2. `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` — cleanup timer, memory diagnostics, 64KB buffer
3. `proto/src/ffi.rs` — FFI bindings for cleanup_stale_flows, router_stats, free_string
4. `proto/src/packet_router.rs` — send_buf cap, flow drain mechanism, outbound queue cap
5. `ios/ZTLP/Libraries/ztlp.h` — New FFI declarations for Swift

## Troubleshooting

If it still doesn't work:
1. Check Xcode console for "ZTLP NE" logs — look for memory warnings
2. Push logs from benchmark page on the iPhone
3. Verify `libztlp_proto_ne.a` was rebuilt (file size should be ~25-26MB)
4. Clean build: Xcode → Product → Clean Build Folder (⌘⇧K) → Build again

## Notes
- WKWebView loads `http://VIP_IP` directly — no DNS needed for `*.ztlp`
- The VIP IPs (10.122.0.x) are routed through the tunnel via includedRoutes
- TLS/HTTPS will show cert warnings with VIP IPs — use HTTP first to validate connectivity
