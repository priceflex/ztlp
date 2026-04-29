# ZTLP iOS Rust FD Router Ingress Handoff — 2026-04-29

## Purpose

This handoff captures the iOS Network Extension data-plane migration state after validating that:

1. Nebula-style utun fd discovery works on-device.
2. A Rust lifecycle-only tunnel engine can start/stop with the fd.
3. Swift `packetFlow.readPackets` can be disabled.
4. Rust can own the utun fd read loop without crashing the NE.
5. Rust can feed read packets into the existing `PacketRouter` (`router_ingress` mode) without the old Swift hot-path crash.

Use this file to start the next session and continue with RouterAction -> transport bridging.

## Skills / Context to Load Next Session

Load these skills:

- `ztlp-session-health-recovery`
- `ztlp-ios-build-debugging`
- `ztlp-ffi-layer`

Important machine/context:

- Steve's Mac: `stevenprice@10.78.72.234`
- iOS/Xcode repo on Mac: `~/ztlp`
- Do NOT use `~/code/ztlp` for iOS builds.
- Phone device id: `39659E7B-0554-518C-94B1-094391466C12`
- Pull phone app-group log from Mac:

```bash
ssh stevenprice@10.78.72.234 '
  xcrun devicectl device copy from \
    --device 39659E7B-0554-518C-94B1-094391466C12 \
    --domain-type appGroupDataContainer \
    --domain-identifier group.com.ztlp.shared \
    --source ztlp.log \
    --destination /tmp/ztlp-phone.log &&
  tail -200 /tmp/ztlp-phone.log
'
```

- Pull crash list:

```bash
ssh stevenprice@10.78.72.234 '
  /Users/stevenprice/Library/Python/3.9/bin/pymobiledevice3 crash flush >/dev/null 2>&1 || true
  /Users/stevenprice/Library/Python/3.9/bin/pymobiledevice3 crash ls | grep -iE "ZTLPTunnel|ztlp|com.ztlp" | tail -60
'
```

## Files Changed in This Phase

Local Linux repo and Mac `~/ztlp` were updated.

### Rust

- `proto/src/ios_tunnel_engine.rs`
- `proto/src/ffi.rs`
- `proto/include/ztlp.h`

### iOS / Swift

- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ios/ZTLP/Libraries/ztlp.h`
- If present, also synced: `ios/ZTLP/ZTLP/ztlp.h`
- Rebuilt/copy on Mac: `ios/ZTLP/Libraries/libztlp_proto_ne.a`

## Current Mode on Device

The current test build is Rust fd-owned router ingress mode:

```swift
private static let useRustFdDataPlane = true
```

Swift does NOT call `startPacketLoop()` / `packetFlow.readPackets` when this is true.

Expected app marker:

```text
Rust fd data plane requested; Swift packet I/O loop disabled
Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=not_bridged
```

Important: transport is not bridged yet. App traffic is expected to fail/time out. This mode validates fd reads and PacketRouter ingress only.

## Phase Progression Completed

### Phase 1 — fd discovery only

Swift C helper in `ZTLPTunnel-Bridging-Header.h` finds the utun fd using `getpeername` / `CTLIOCGINFO` because Swift cannot directly see `ctl_info`, `sockaddr_ctl`, or `CTLIOCGINFO` on iOS.

Validated marker:

```text
utun fd acquired fd=5
```

Earlier marker before Phase 2:

```text
utun fd acquired fd=5 (Rust fd engine scaffold not started; Swift packetFlow still owns data plane)
```

### Phase 2 — lifecycle-only Rust engine

Rust `IosTunnelEngine` stored the fd but did not read/write it.

Validated marker:

```text
Rust iOS tunnel engine scaffold started fd=5 mode=lifecycle_only
```

Result: lifecycle-only Rust engine was NOT the crash cause.

### Phase 2B — rwnd=4 cooldown patch

Tried keeping `rwnd=4` more aggressively after a prior crash where rwnd escaped to 5. Patch worked but crash still reproduced at rwnd=4:

```text
Advertised rwnd=4 reason=browser burst flows=2 streamMaps=2
...
VPN status changed: 5
VPN status changed: 1
```

Conclusion: rwnd tuning is not sufficient; Swift packetFlow hot path remains crash boundary.

### Phase 3A — Rust fd read/drop/log mode

Swift packetFlow disabled. Rust owned fd reads and dropped packets.

Expected marker:

```text
Rust iOS tunnel engine scaffold started fd=5 mode=read_drop_log swift_packetFlow=disabled
```

Result: NE stayed up past old failure window; no VPN status 5 -> 1; no fresh crash report.

### Phase 3B — Rust fd read -> PacketRouter ingress

Current code. Swift packetFlow disabled. Rust reads utun fd and feeds packets into `PacketRouter` via `ztlp_router_write_packet_sync`. Router actions are counted/logged inside Rust/syslog, but not yet bridged to transport.

Expected app marker:

```text
Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=not_bridged
```

Observed on-device:

```text
[2026-04-29T07:36:30.029Z] [INFO] [Tunnel] Rust fd data plane requested; Swift packet I/O loop disabled
[2026-04-29T07:36:30.213Z] [INFO] [Tunnel] utun fd acquired fd=5
[2026-04-29T07:36:30.213Z] [INFO] [Tunnel] Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=not_bridged
[2026-04-29T07:36:30.214Z] [INFO] [Tunnel] TUNNEL ACTIVE — v5D RELAY-SIDE VIP (no NWListeners)
```

Observed router ingress after benchmark traffic:

```text
[2026-04-29T07:36:38.218Z] [DEBUG] [Tunnel] Health eval: flows=1 outbound=2 streamMaps=1 sendBuf=0 oldestMs=197 rwnd=4 highSeq=0 stuckTicks=1 usefulRxAge=8.0s outboundRecent=false replayDelta=0 probeOutstanding=false
[2026-04-29T07:36:40.217Z] [DEBUG] [Tunnel] Router stats: flows=1 outbound=2 stream_to_flow=1 next_stream_id=3 send_buf_bytes=0 send_buf_flows=0 oldest_ms=199 stale=0
[2026-04-29T07:36:50.217Z] [DEBUG] [Tunnel] Router stats: flows=2 outbound=4 stream_to_flow=2 next_stream_id=5 send_buf_bytes=0 send_buf_flows=0 oldest_ms=583 stale=0
[2026-04-29T07:36:56.218Z] [DEBUG] [Tunnel] Health eval: flows=2 outbound=2 streamMaps=2 sendBuf=0 oldestMs=1579 rwnd=4 highSeq=0 stuckTicks=1 usefulRxAge=26.0s outboundRecent=false replayDelta=0 probeOutstanding=false
[2026-04-29T07:37:10.217Z] [DEBUG] [Tunnel] Router stats: flows=0 outbound=0 stream_to_flow=0 next_stream_id=1 send_buf_bytes=0 send_buf_flows=0 oldest_ms=0 stale=0
```

Result:

- NE stayed up.
- No `VPN status changed: 5 -> 1` after router_ingress startup.
- No fresh ZTLPTunnel crash report.
- PacketRouter state changed from fd-ingress packets, proving Rust fd read -> Router ingress works.

## Important Interpretation

This is a major validation point.

The old crash/drop happened only when Swift `packetFlow.readPackets` owned the packet hot path. When Swift packetFlow was disabled and Rust owned fd reads, the NE stayed stable.

Therefore the old crash boundary is very likely:

```text
Swift packetFlow/readPackets + Swift router/utun hot-path under browser/benchmark burst
```

Not:

- gateway congestion,
- rwnd value,
- Rust lifecycle scaffold,
- generic NetworkExtension startup,
- relay/session connection,
- health timer queue alone.

## Expected Current Failure

Benchmark/app traffic is expected to fail or time out in current `router_ingress` mode because router actions are not bridged to the transport yet.

The session-health system sees flows/outbound but `highSeq` remains 0 because no gateway response path is bridged. It therefore sends probes and resets router state repeatedly:

```text
Session health candidate: flows=1 outbound=2 ... highSeq=0 noUsefulRxFor=8.0s
Session health suspect: reason=no_useful_rx_8.0s ... sending probe nonce=...
Session health probe response nonce=...
Session health probe ok but flows still suspect; router reset removed=1
```

This is expected for the incomplete data plane and should not be interpreted as a new crash.

## Current Code Shape

### `proto/src/ios_tunnel_engine.rs`

Key behavior:

- `IosUtun::read_packet()` strips the 4-byte iOS utun header.
- `IosUtun::write_packet()` prepends the 4-byte iOS utun header.
- `IosTunnelEngine::start_read_metadata_loop()` starts `read_drop_log` mode.
- `IosTunnelEngine::start_router_ingress_loop(router)` starts `router_ingress` mode.
- In `router_ingress`, Rust calls the existing FFI-safe router function:

```rust
crate::ffi::ztlp_router_write_packet_sync(
    router,
    packet.as_ptr(),
    n,
    action_buf.as_mut_ptr(),
    action_buf.len(),
    &mut action_written as *mut usize,
)
```

### `proto/src/ffi.rs`

Made `ios_log` pub(crate) so `ios_tunnel_engine.rs` can log through NSLog/stderr:

```rust
pub(crate) fn ios_log(msg: &str) { ... }
```

Made `ZtlpPacketRouter.inner` visible inside crate for future native Rust integration:

```rust
pub struct ZtlpPacketRouter {
    pub(crate) inner: std::sync::Mutex<crate::packet_router::PacketRouter>,
}
```

Added FFI:

```c
int32_t ztlp_ios_tunnel_engine_start_read_metadata_loop(ZtlpIosTunnelEngine *engine);

int32_t ztlp_ios_tunnel_engine_start_router_ingress_loop(
    ZtlpIosTunnelEngine *engine,
    ZtlpPacketRouter *router
);
```

Important header pitfall fixed:

`ZtlpPacketRouter` typedef must appear before the `ztlp_ios_tunnel_engine_start_router_ingress_loop` declaration. It was moved near the top, directly after `ZtlpIosTunnelEngine` typedef.

### `PacketTunnelProvider.swift`

Current behavior:

- `useRustFdDataPlane = true`
- `startPacketRouter(...)` does NOT call `startPacketLoop()` when `useRustFdDataPlane` is true.
- After network settings apply and fd is found, Swift starts Rust router ingress:

```swift
let readResult = ztlp_ios_tunnel_engine_start_router_ingress_loop(engine, router)
```

Current marker:

```text
Rust iOS tunnel engine scaffold started fd=\(fd) mode=router_ingress swift_packetFlow=disabled transport=not_bridged
```

## Validation Commands Already Run

Local Linux:

```bash
cargo check --manifest-path /home/trs/ztlp/proto/Cargo.toml --no-default-features --features ios-sync --lib
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml --features ios-sync ios_tunnel_engine --lib
```

Both passed. Tests: 4/4.

Mac build/rebuild:

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/proto &&
  cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib &&
  cp target/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a
'
```

Symbol check:

```bash
strings ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a | grep -E "ztlp_ios_tunnel_engine_start_router_ingress_loop|mode=router_ingress"
```

Unsigned Xcode build:

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/ios/ZTLP &&
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
    -destination "generic/platform=iOS" \
    -configuration Debug build \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO 2>&1 |
  grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" | tail -50
'
```

Result:

```text
** BUILD SUCCEEDED **
```

Server preflight:

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Result:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

## Next Session Starting Point

Start with RouterAction -> transport bridging.

Current Rust ingress creates serialized RouterActions in `action_buf`, but those actions are only counted/logged. They are not sent to `ZTLPTunnelConnection`.

There are two possible next directions:

### Option A — Shortest bridge: Rust -> Swift action callback

Add a Swift callback registered into Rust engine. Rust invokes callback for serialized actions generated by `PacketRouter`.

Swift callback then reuses existing action handling in `PacketTunnelProvider` / `ZTLPTunnelConnection`:

- OpenStream -> existing OpenStream mux send path
- SendData -> existing SendData mux send path
- CloseStream -> existing CloseStream mux send path

Pros:

- Fastest path to working transport while keeping high-volume packet bytes out of Swift.
- Only small action metadata/payload crosses Swift, not utun packet `Data` / `ArraySlice`.
- Reuses existing Swift transport code and relay-side VIP session.

Cons:

- Still has Swift transport and callbacks in the path.
- Action payload data can still be high-volume, but likely much lower risk than packetFlow Data/ArraySlice hot path.

### Option B — Full Rust transport ownership

Move ZTLP transport/session into Rust engine too.

Pros:

- Durable final architecture.
- Swift becomes lifecycle/settings/config only.

Cons:

- Larger change. Need to port/own relay connection, mux, ACK/rwnd, session health, DNS, gateway data path.

Recommended next move: Option A as a staged bridge.

## Suggested Next Implementation Sketch — Option A

### Rust FFI callback type

Add callback type in `ffi.rs` or `ios_tunnel_engine.rs`:

```rust
pub type ZtlpIosRouterActionCallback = extern "C" fn(
    user_data: *mut std::ffi::c_void,
    action_type: u8,
    stream_id: u32,
    data: *const u8,
    data_len: usize,
);
```

Add FFI:

```c
int32_t ztlp_ios_tunnel_engine_set_router_action_callback(
    ZtlpIosTunnelEngine *engine,
    ZtlpIosRouterActionCallback callback,
    void *user_data
);
```

Or combine callback into `start_router_ingress_loop`.

### Rust action dispatch

Instead of only counting actions from `ztlp_router_write_packet_sync`, parse the serialized `action_buf` that function already emits:

Format from `ztlp_router_write_packet_sync`:

```text
[1 byte type][4 bytes stream_id BE][2 bytes data_len BE][data...]
Type: 0=OpenStream, 1=SendData, 2=CloseStream
```

For each action, call callback:

```rust
callback(user_data, action_type, stream_id, payload_ptr, payload_len)
```

Important: callback must either synchronously consume/copy payload or Rust must copy before returning. Swift should copy bytes immediately if needed.

### Swift callback trampoline

In `PacketTunnelProvider.swift`, add file-scope callback function similar to existing C callback patterns.

It should hop onto `tunnelQueue` before touching `tunnelConnection` or shared state.

Pseudo-shape:

```swift
private func handleRustRouterAction(type: UInt8, streamID: UInt32, data: UnsafePointer<UInt8>?, len: Int) {
    tunnelQueue.async { [weak self] in
        guard let self = self else { return }
        switch type {
        case 0: // OpenStream
            let service = data.map { String(bytes: UnsafeBufferPointer(start: $0, count: len), encoding: .utf8) } ?? ""
            self.tunnelConnection?.sendOpenStream(streamID: streamID, serviceName: service)
        case 1: // SendData
            let payload = data.map { Data(bytes: $0, count: len) } ?? Data()
            self.tunnelConnection?.sendData(streamID: streamID, data: payload)
        case 2: // CloseStream
            self.tunnelConnection?.sendCloseStream(streamID: streamID)
        default:
            self.logger.warn("Unknown Rust router action type=\(type)", source: "Tunnel")
        }
    }
}
```

Need to read existing `ZTLPTunnelConnection.swift` APIs before coding exact calls. Do not assume method names.

### Expected validation markers after Option A

App log:

```text
Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback
Rust router action callback registered
Rust router action summary open=N send=N close=N bytes=N
```

Router stats should show flows, and ZTLPTunnelConnection should show mux sends/open streams.

Expected current limitation after Option A:

Gateway response data still needs to be routed back to utun. If Swift existing gateway-data path still calls `ztlp_router_gateway_data_sync` and `flushOutboundPackets()` to `packetFlow.writePackets`, that must be moved/bridged too. The old crash may also involve Swift utun writes. Next after action bridge is Rust-owned router outbound -> utun write loop.

## Important Gotchas for Next Session

1. Do NOT enable Swift `startPacketLoop()` while Rust owns fd reads. Two consumers on utun fd are unsafe.

2. Do NOT forget to rebuild `libztlp_proto_ne.a` after Rust FFI changes.

3. Always sync headers:

```bash
cp ~/ztlp/proto/include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h
if [ -f ~/ztlp/ios/ZTLP/ZTLP/ztlp.h ]; then cp ~/ztlp/proto/include/ztlp.h ~/ztlp/ios/ZTLP/ZTLP/ztlp.h; fi
```

4. Xcode GUI must Clean Build Folder after replacing static libs.

5. The `patch` tool may emit bogus Rust 2015 async lint errors for `ffi.rs`; ignore those and verify with real Cargo commands.

6. On Mac, always build with cargo PATH first:

```bash
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
```

7. If Xcode bridging header says unknown type for a new FFI signature, move the typedef earlier in `ztlp.h` before any function uses it.

8. Current app log can get line-corrupted around startup due concurrent logger writes, e.g. a chopped `Session health manager enabled...` line. Do not overinterpret one malformed line if surrounding markers are present.

## Current High-Level Status

- fd discovery: DONE and validated.
- Rust lifecycle-only engine: DONE and validated.
- Rust fd read/drop/log with Swift packetFlow disabled: DONE and stable.
- Rust fd read -> PacketRouter ingress: DONE and stable.
- RouterAction -> transport bridge: NOT DONE. This is next.
- Router outbound -> utun write ownership: NOT DONE. Needed after transport/gateway data path.
- Full Rust data plane: NOT DONE.

## Suggested First Commands Next Session

Read this handoff:

```bash
read_file /home/trs/ztlp/ZTLP-IOS-RUST-FD-ROUTER-INGRESS-HANDOFF-2026-04-29.md
```

Check repo status locally and on Mac:

```bash
cd /home/trs/ztlp && git status --short
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git status --short'
```

Read exact Swift transport API before coding callbacks:

```bash
read_file /home/trs/ztlp/ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
search_files pattern="func .*Stream|func send|OpenStream|SendData|CloseStream|MUX_FRAME" path="/home/trs/ztlp/ios/ZTLP/ZTLPTunnel" file_glob="*.swift"
```

Then implement RouterAction callback bridge.
