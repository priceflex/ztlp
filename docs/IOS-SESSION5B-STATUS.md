# ZTLP iOS Session 5B Status: Sync Architecture Running

## Completed (Session 5B — on Mac)

### v5B Sync Architecture Deployed
- PacketTunnelProvider.swift fully rewritten — no ZTLPBridge, no tokio dependency
- Identity: software identity via ztlp_identity_generate() (Secure Enclave skipped — no node ID without enrollment)
- Connect: ztlp_connect_sync() — blocking Noise_XX handshake via std::net::UdpSocket
- Tunnel I/O: ZTLPTunnelConnection (NWConnection UDP) + sync encrypt/decrypt FFI
- VIP Proxy: ZTLPVIPProxy (NWListener TCP on 127.0.0.1:8080/8443)
- Packet Router: standalone ztlp_router_*_sync FFI (no ZtlpClient needed)
- ACK batching: cumulative ACK every 10ms or 32 packets, max 64 in-flight sends
- v5B banner in logs for version identification

### Xcode Project Changes
- ZTLPTunnelConnection.swift + ZTLPVIPProxy.swift added to ZTLPTunnel target
- ZTLPBridge.swift REMOVED from ZTLPTunnel target (kept in main ZTLP app)
- libztlp_proto.a built with BOTH features: tokio-runtime + ios-sync
  - Main app uses tokio-gated functions (ZTLPBridge.swift)
  - NE extension uses ios-sync functions (sync PTP)
  - Single library, dead-code stripping handles the rest

### Build Commands
- iOS staticlib (both features — required for main app + NE extension):
  cd ~/ztlp/proto
  cargo build --target aarch64-apple-ios --release --lib --features ios-sync
  cp target/aarch64-apple-ios/release/libztlp_proto.a ../ios/ZTLP/Libraries/
- iOS staticlib (ios-sync ONLY — smaller TEXT but main app won't link):
  cargo build --target aarch64-apple-ios --release --lib --no-default-features --features ios-sync
  TEXT: 1.65MB vs 4.73MB with both features

### Benchmark Results (v5B — 9/11 pass)
- Device: iPhone16,2 (iPhone 15 Pro Max)
- Date: 2026-04-09T07:05Z
- HTTP Ping:       avg=100ms   min=92ms   max=131ms   (30 iter) PASS
- GET 1KB:         avg=102ms   min=93ms   max=3596ms  (20 iter) PASS
- GET 10KB:        avg=108ms   min=98ms   max=206ms   (20 iter) PASS
- GET 100KB:       avg=307ms   min=285ms  max=410ms   (20 iter) PASS
- GET 1MB:         avg=2249ms  min=2189ms max=3345ms  (20 iter) PASS
- Download 5MB:    avg=10768ms min=10725ms max=10852ms (5 iter)  PASS (was failing before!)
- POST Echo 1KB:   avg=104ms   min=96ms   max=125ms   (20 iter) PASS
- POST Echo 100KB: avg=531ms   min=369ms  max=673ms   (20 iter) PASS
- Upload 1MB:      STALLED                                       FAIL
- Concurrent 5x:   NOT REACHED
- TTFB:            NOT REACHED

### Memory Profile (v5B)
- Resident: 20.2-20.4 MB (STABLE — does not grow during transfers)
- The 20MB baseline comes from linking both tokio + ios-sync features (53MB .a)
- To reduce further: separate libraries (ios-sync only for NE, tokio for app)
- The NE does NOT initialize tokio at runtime — the symbols are just present

## Remaining Issues

### 1. Upload 1MB Stall (Critical)
- Upload starts but never completes — benchmark hangs indefinitely
- Memory stays stable at 20.4MB during stall (not a memory issue)
- Possible causes:
  a. Gateway not ACKing upload data — sender stalls on backpressure
  b. Router action serialization: upload data goes utun->router->actions->sendData
     but the action format may not be correct for upstream data
  c. The VIP proxy send path (NWListener->encrypt->NWConnection) may block
  d. ZTLPTunnelConnection send backpressure (max 64 in-flight) too aggressive
- Need gateway logs to see if upload data is arriving

### 2. Memory 20MB Baseline (Improvement Needed)
- Current: 20.2MB resident with both-features lib
- Target: less than 15MB to stay within iOS NE limit
- Root cause: linking tokio symbols even though NE doesn't use them
- Fix options:
  a. Separate libraries: ios-sync .a for NE target, tokio .a for main app
     Requires different LIBRARY_SEARCH_PATHS per target in Xcode
  b. Move benchmarks out of main app: Use ios-sync for both targets
     Requires rewriting HTTPBenchmark to not use ZTLPBridge
  c. LTO + aggressive dead-code strip: May help but won't eliminate all tokio
- The ios-sync-only build has TEXT=1.65MB — should give ~8-10MB resident

### 3. NS Resolution Unavailable
- ztlp_ns_resolve is tokio-gated — unavailable in sync NE
- Currently uses targetNodeId directly as gateway address (works)
- TODO: Add ztlp_ns_resolve_sync or implement in Swift

## Architecture (v5B)

Main App Process:
- ZTLPBridge.swift (uses tokio FFI)
- HTTPBenchmark (own connection on port 9080)

NE Extension Process (v5B):
- PacketTunnelProvider.swift (uses sync FFI only)
- ztlp_connect_sync() for handshake
- ZTLPTunnelConnection for UDP I/O (NWConnection)
- ZTLPVIPProxy for TCP proxy (NWListener on 127.0.0.1:8080/8443)
- ztlp_router_*_sync for utun packet routing

Both link: libztlp_proto.a (53MB, both features)

## Key Files Changed (Session 5B)
- ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift (rewritten)
- ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift (ACK batching, backpressure)
- ios/ZTLP/ZTLPTunnel/ZTLPVIPProxy.swift (reusable buffers)
- ios/ZTLP/ZTLP.xcodeproj/project.pbxproj (added files, removed ZTLPBridge from NE)

## Git
- Commit: c5c8a78 (pushed to GitHub)
- Working repo on Mac: ~/ztlp (NOT ~/code/ztlp)
- Both repos synced to same commit

## Next Session Priorities
1. Fix Upload 1MB stall — check gateway logs, inspect router action path
2. Reduce memory: separate ios-sync lib for NE target (target less than 15MB)
3. Re-run full 11/11 benchmark suite
4. Tag result: v0.24.2-sync-NofN
