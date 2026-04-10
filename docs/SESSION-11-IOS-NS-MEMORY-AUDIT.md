# Session 11: iOS NS + Memory Audit

Date: 2026-04-10
Status: Investigated, documented, not production-ready yet

## Goal
Audit the iOS ZTLP app/tunnel for:
- name server / DNS issues
- high Network Extension memory usage
- correct iOS build/link configuration
- production readiness

## Environment Used
- Steve's Mac: `stevenprice@10.78.72.234`
- iPhone device ID: `39659E7B-0554-518C-94B1-094391466C12`
- iOS repo on Mac: `~/ztlp`
- Xcode project: `~/ztlp/ios/ZTLP/ZTLP.xcodeproj`
- Shared app-group log path pulled from device: `group.com.ztlp.shared/ztlp.log`

## What Was Done

### 1. Pulled latest iPhone tunnel logs
Used:
```bash
xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log
```

### 2. Audited iOS tunnel code in `~/ztlp`
Reviewed:
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPDNSResponder.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPNSClient.swift`
- `ios/ZTLP/ZTLP/Services/ZTLPBridge.swift`
- `proto/src/ffi.rs`
- `proto/Cargo.toml`
- `ios/ZTLP/ZTLP.xcodeproj/project.pbxproj`

### 3. Rebuilt both iOS Rust static libraries on Steve's Mac
Commands used:
```bash
cd ~/ztlp/proto

# Network Extension lib (no tokio)
cargo build --release --target aarch64-apple-ios \
  --no-default-features --features ios-sync --lib
cp target/aarch64-apple-ios/release/libztlp_proto.a \
  ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a

# Main app lib (full tokio path)
cargo build --release --target aarch64-apple-ios \
  --features ios-sync --lib
cp target/aarch64-apple-ios/release/libztlp_proto.a \
  ~/ztlp/ios/ZTLP/Libraries/libztlp_proto.a

# Header sync
cp include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h
```

### 4. Ran unsigned Xcode Release build check
Used:
```bash
cd ~/ztlp/ios/ZTLP
xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
  -destination 'generic/platform=iOS' -configuration Release build \
  CODE_SIGN_IDENTITY='' CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
```

Result:
- `ZTLPTunnel` compiled and linked
- `ZTLP` app compiled and linked
- `BUILD SUCCEEDED`

## Confirmed Build State

### Two-lib linking is currently correct
`project.pbxproj` shows:
- `ZTLPTunnel` links `-lztlp_proto_ne`
- `ZTLP` app links `-lztlp_proto`

Library sizes after rebuild:
- `libztlp_proto_ne.a`: 26 MB
- `libztlp_proto.a`: 54 MB

This means the app is currently built in the intended split configuration:
- NE uses no-tokio sync library
- Main app uses full tokio-enabled library

## Key Findings

### Finding 1: NE is NOT doing true NS-based gateway resolution yet
In `PacketTunnelProvider.swift`, `resolveGateway(config:svcName:)` explicitly says:
- `ztlp_ns_resolve` is tokio-gated and unavailable in ios-sync builds
- current sync mode uses `targetNodeId` directly
- TODO: add `ztlp_ns_resolve_sync` or implement NS resolution in Swift

Current behavior:
- NE connection path does not rely on real Rust NS resolution
- gateway target is effectively taken from `config.targetNodeId`
- therefore the NE is not yet "production-ready NS-backed"

Important nuance:
- `ZTLPNSClient.swift` exists and is used for service discovery population
- but the actual connect path still bypasses NS resolution and falls back to direct configured target

### Finding 2: Local DNS responder is partially working
Phone logs show for `.ztlp` domains:
- `qtype=65` (HTTPS/SVCB) -> NXDOMAIN
- `qtype=28` (AAAA) -> NXDOMAIN
- `qtype=1` (A) -> handled

Examples seen in logs:
- `vault.techrockstars.ztlp`
- `http.techrockstars.ztlp`
- `vault.ztlp`

This indicates the previous AAAA/SVCB retry problem is mostly fixed.

### Finding 3: DNS interceptor still mishandles non-.ztlp traffic
Phone logs repeatedly show:
```text
DNS: qname=_dns.resolver.arpa qtype=64 qclass=1
DNS: pass-through — not .ztlp suffix
DNS query matched but no response generated
```

Interpretation:
- the DNS hook is still intercepting some non-.ztlp DNS packets
- it then returns nil / pass-through behavior
- call site logs this as "matched but no response generated"

This may not be the primary vault/http failure, but it is still incorrect and could contribute resolver weirdness/noise.

### Finding 4: Tunnel path is still running in legacy mode
Phone logs are full of:
```text
Router: OpenStream (legacy skip)
Router: CloseStream (legacy skip)
```

`PacketTunnelProvider.swift` confirms:
- `OpenStream` is skipped in legacy mode
- `CloseStream` is skipped in legacy mode
- only raw `SendData` payload is forwarded

Interpretation:
- the NE is not operating as a complete mux-mode transport
- it is using a compatibility/legacy path
- service/multiplexing behavior is therefore not fully production-clean

### Finding 5: NE memory is still too high for production safety
Phone log warnings repeatedly show resident memory above Apple-friendly NE limits:
- `18.5MB`
- `18.7MB`
- `20.7MB`
- `20.8MB`
- `20.9MB`
- `21.1MB`
- `21.2MB`

Typical log line:
```text
v5B-SYNC | Memory HIGH — resident=20.8MB virtual=400526.0MB (NE limit ~15MB)
```

Interpretation:
- split lib architecture helped, but did not solve memory pressure
- NE is still materially above the intended ~15MB ceiling
- current state is not production safe on iPhone

### Finding 6: Build works, but Rust static libs were built against newer iOS version than app target
Unsigned Xcode build succeeded, but linker emitted many warnings like:
```text
object file ... was built for newer 'iOS' version (18.5) than being linked (16.0)
```

Interpretation:
- not the main runtime bug
- but should be cleaned up for production build hygiene and compatibility confidence

## Most Likely Root Causes

### Root Cause A: NE sync architecture still lacks real NS resolution
The NE cannot currently use tokio-gated `ztlp_ns_resolve`, and the sync fallback path has not been fully replaced with a true Swift or sync-Rust NS resolution flow for connection targeting.

### Root Cause B: DNS local resolution exists, but service connect path is still partly hard-wired
The local DNS responder can hand out VIPs for `.ztlp` names, but the actual tunnel/gateway connect path still depends on direct config target values.

### Root Cause C: Legacy-mode shortcuts are still masking unfinished mux/service behavior
Skipping `OpenStream` / `CloseStream` means the NE is not yet fully aligned with a production multiplexer model.

### Root Cause D: Memory remains above safe NE threshold
The no-tokio split reduced binary size, but Swift-side runtime/buffers/listeners/state still appear to push resident memory well above the desired threshold.

## Production Readiness Verdict
Not production ready yet.

Reasons:
1. NE resident memory is still consistently too high
2. NE connect path still bypasses true NS resolution
3. Legacy stream handling is still a compatibility shortcut
4. DNS pass-through handling for non-.ztlp traffic is still sloppy
5. Build target/version warnings should be cleaned up

## Recommended Next Steps (ordered)

### Priority 1: Implement real sync NS resolution for the NE connect path
Goal:
- make `resolveGateway()` use a real NS lookup first
- use `targetNodeId` only as emergency fallback

Likely options:
1. Implement `ztlp_ns_resolve_sync` in Rust without tokio
2. Or fully switch `resolveGateway()` to Swift `ZTLPNSClient` for target resolution

### Priority 2: Reduce NE resident memory below ~15MB
Audit likely offenders in:
- `PacketTunnelProvider.swift`
- `ZTLPTunnelConnection.swift`
- `ZTLPVIPProxy.swift`

Specific suspects:
- large packet/action buffers
- repeated `Data` copying in packet loops
- retained pending ACK/data queues
- extra listeners/connections per service/port
- service map duplication / long-lived state
- verbose logging overhead during active traffic

### Priority 3: Tighten DNS pass-through behavior
Fix the non-.ztlp packet path so it is not logged as a matched DNS query with no response.

### Priority 4: Decide whether to fully support mux mode or intentionally simplify legacy mode
Current state is transitional. Pick one:
- complete true mux support in NE
- or deliberately simplify to a supported single-stream legacy architecture

### Priority 5: Align Rust build deployment target with Xcode app target
Remove the 18.5-vs-16.0 object warnings.

## Useful Evidence from This Session

### Phone log patterns confirming DNS behavior
```text
DNS: qname=vault.techrockstars.ztlp qtype=65 qclass=1
DNS: NXDOMAIN for non-A query type=65
DNS: qname=vault.techrockstars.ztlp qtype=28 qclass=1
DNS: NXDOMAIN for non-A query type=28
DNS: qname=vault.techrockstars.ztlp qtype=1 qclass=1
```

### Phone log patterns confirming pass-through bug
```text
DNS: qname=_dns.resolver.arpa qtype=64 qclass=1
DNS: pass-through — not .ztlp suffix
DNS query matched but no response generated
```

### Phone log patterns confirming legacy stream suppression
```text
Router: OpenStream (legacy skip)
Router: CloseStream (legacy skip)
```

### Phone log patterns confirming memory issue
```text
v5B-SYNC | Memory HIGH — resident=20.8MB virtual=400526.0MB (NE limit ~15MB)
v5B-SYNC | Memory HIGH — resident=21.2MB virtual=400525.4MB (NE limit ~15MB)
```

## Files Most Relevant for the Next Session
- `~/ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `~/ztlp/ios/ZTLP/ZTLPTunnel/ZTLPDNSResponder.swift`
- `~/ztlp/ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`
- `~/ztlp/ios/ZTLP/ZTLPTunnel/ZTLPNSClient.swift`
- `~/ztlp/ios/ZTLP/ZTLP/Services/ZTLPBridge.swift`
- `~/ztlp/proto/src/ffi.rs`
- `~/ztlp/proto/Cargo.toml`
- `~/ztlp/ios/ZTLP/ZTLP.xcodeproj/project.pbxproj`

## Quick Restart Context for a Future Session
If resuming later, start with:
1. Pull fresh phone logs from app-group `ztlp.log`
2. Re-check `resolveGateway()` in `PacketTunnelProvider.swift`
3. Verify whether NE still bypasses NS for connection target selection
4. Re-check memory warnings in live phone log after tunnel activity
5. If changing FFI, rebuild both libs and sync `ztlp.h`
6. Re-run unsigned Xcode build before asking Steve to deploy from Xcode GUI
