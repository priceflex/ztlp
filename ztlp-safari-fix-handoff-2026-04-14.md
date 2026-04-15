# ZTLP Safari Fix Handoff
## Context: Safari pages hang then NE disconnects under load

### The Actual Bug (NOT memory)

**Root cause:** `packet_router.rs` silently drops packets when the outbound queue hits 128 packets.

```
process_gateway_data() -> outbound hits 128 packet cap -> pop_front() drops oldest
-> TCP sequence numbers break -> Safari waits for data that never arrives -> stall -> disconnect
```

Safari opens 6+ concurrent TCP streams per page. Gateway pushes back 100+ response packets. Queue fills in ~2 seconds. Packets dropped. Safari stalls.

### What Was FIXED (pushed to main, commit b63d18f + 46c8a55)

1. **No more packet drops** - queue overflow spills into per-flow send_buf (64KB cap), not dropped
2. **Larger queue** - 128 → 256 packets for iOS
3. **PSH only on last chunk** - Safari delivers complete responses
4. **Removed flush throttle** - drain loop not prematurely cut off under load
5. **Added missing FFI headers** - cleanup_stale_flows, router_stats, free_string

### WHAT MUST HAPPEN NEXT

**The NE library on the phone is OLD (pre-fix).** Rebuild required on Mac:

```bash
cd ~/ztlp && git pull origin main

# NE lib
cargo build --manifest-path proto/Cargo.toml --target aarch64-apple-ios --release --lib --no-default-features --features ios-sync --target-dir proto/target-ios-sync
cp proto/target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a ios/ZTLP/Libraries/libztlp_proto_ne.a

# Main app lib  
touch proto/src/ffi.rs
cargo build --manifest-path proto/Cargo.toml --target aarch64-apple-ios --release --lib
cp proto/target/aarch64-apple-ios/release/libztlp_proto.a ios/ZTLP/Libraries/libztlp_proto.a

# Headers
cp proto/include/ztlp.h ios/ZTLP/Libraries/ztlp.h
cp proto/include/ztlp.h ios/ZTLP/ZTLPTunnel/ztlp.h
```

Then: Xcode Clean Build Folder (CMD+Shift+K) → Build → Deploy to phone

### Benchmark Evidence (bootstrap 10.69.95.12:3000)

Latest (19:54Z): NE still dies 5s after page flow starts → confirms OLD lib on phone
Previous (19:07Z): 7/8 pass, all connectivity good, NE stable at 18MB

### Files Changed
- `proto/src/packet_router.rs` - core fix
- `proto/include/ztlp.h` - FFI declarations
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` - throttle removal
- `ios/ZTLP/Libraries/ztlp.h` - synced header (Mac only, not yet committed)

### Secondary Issue to Investigate After Fix

Stream open/close cycling seen in logs:
```
CloseStream 19 -> OpenStream 20 vault -> CloseStream 20 -> OpenStream 21 vault -> CloseStream 21
```
Streams open and immediately close. Could be gateway/relay rejecting concurrent streams, or backend sending RST.

### Server/Device Info
- Device: 39659E7B-0554-518C-94B1-094391466C12 (iOS 26.3.1)
- Mac: stevenprice@10.78.72.234, repo ~/ztlp
- Bootstrap: trs@10.69.95.12:3000
- Gateway: 44.246.33.34:23097
- Relay: 34.219.64.205:23095
- NS: 34.217.62.46:23096
- Git user: Steven Price <steve@techrockstars.com>
- GitHub SSH: /home/trs/openclaw_server_import/ssh/openclaw
