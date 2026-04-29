# ZTLP iOS Rust FD Outbound -> utun Handoff — 2026-04-29

## Purpose

This handoff captures the current iOS Network Extension Rust fd-owned data-plane migration state immediately before implementing Rust-owned router outbound -> utun writes.

The next session should start from here and implement the missing outbound write path.

## Context / Skills to Load

Load these skills:

- `ztlp-session-health-recovery`
- `ztlp-ios-build-debugging`
- `ztlp-ffi-layer`
- `systematic-debugging`

Important machine/context:

- Steve's Mac: `stevenprice@10.78.72.234`
- iOS/Xcode repo on Mac: `~/ztlp`
- Do NOT use `~/code/ztlp` for iOS builds.
- Local Linux repo: `/home/trs/ztlp`
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

## Current Architecture State

Current iOS NE build is Rust fd-owned router ingress with Swift action callback transport bridge:

```swift
private static let useRustFdDataPlane = true
```

Swift `packetFlow.readPackets` is disabled.

Current expected startup markers:

```text
Rust router action callback registered
Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback
TUNNEL ACTIVE — v5D RELAY-SIDE VIP (no NWListeners)
```

Current files changed in this phase:

- `proto/src/ios_tunnel_engine.rs`
- `proto/src/ffi.rs`
- `proto/include/ztlp.h`
- `ios/ZTLP/Libraries/ztlp.h`
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`

## What Was Implemented

### 1. Rust -> Swift RouterAction callback bridge

Added FFI callback type and registration:

```rust
pub type ZtlpIosRouterActionCallback = extern "C" fn(
    user_data: *mut std::ffi::c_void,
    action_type: u8,
    stream_id: u32,
    data: *const u8,
    data_len: usize,
);
```

```c
int32_t ztlp_ios_tunnel_engine_set_router_action_callback(
    ZtlpIosTunnelEngine *engine,
    ZtlpIosRouterActionCallback callback,
    void *user_data
);
```

Rust parses existing serialized RouterActions from `ztlp_router_write_packet_sync`:

```text
[1 byte type][4 bytes stream_id BE][2 bytes data_len BE][data...]
Type: 0=OpenStream, 1=SendData, 2=CloseStream
```

Swift registers callback and reuses existing `processRouterActions(...)` path.

### 2. Swift action callback diagnostics

Swift logs summaries:

```text
Rust action callback summary open=N send=N close=N unknown=N bytes=N lastType=T lastStream=S lastLen=L
RouterAction send OpenStream stream=N serviceBytes=N sent=true/false
RouterAction send SendData stream=N bytes=N sent=true/false
RouterAction send CloseStream stream=N sent=true/false
Mux summary gwData=N/B open=N close=N send=N/B
```

### 3. Rust fd ingress metadata via diagnostic pseudo-action

Because iOS syslog redacts Rust `NSLog` payloads as `<private>`, Rust now routes fd-ingress packet metadata through the existing Swift callback as diagnostic action type `250`.

Swift handles action type 250 separately and writes it to app-group `ztlp.log`:

```text
Rust fd ingress diag count=N proto=6 flags=SYN tcp_payload=0 src=10.122.0.1:PORT dst=10.122.0.4:80 packets=N totals_syn=N payload=N fin=N rst=N non_tcp=N
```

This diagnostic path is temporary and should be removed or rate-limited heavily after the outbound path is fixed.

## Validation Already Run

Local Linux:

```bash
cargo check --manifest-path /home/trs/ztlp/proto/Cargo.toml --no-default-features --features ios-sync --lib
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml --features ios-sync ios_tunnel_engine --lib
```

Result:

- cargo check passed
- ios_tunnel_engine tests passed 4/4

Mac build/rebuild:

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/proto &&
  cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib &&
  cp target/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a
'
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
  grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" | tail -100
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

## Current Live Test Findings

After deploying the diagnostic build and running the tunnel benchmark, the phone app-group log showed:

```text
fd_diag=23
tcp_payload_nonzero=0
send_actions=0
```

Representative fd ingress diagnostics:

```text
Rust fd ingress diag count=1 proto=6 flags=SYN tcp_payload=0 src=10.122.0.1:49258 dst=10.122.0.4:80 packets=1 totals_syn=1 payload=0 fin=0 rst=0 non_tcp=0
Rust fd ingress diag count=2 proto=6 flags=SYN tcp_payload=0 src=10.122.0.1:49259 dst=10.122.0.4:80 packets=2 totals_syn=2 payload=0 fin=0 rst=0 non_tcp=0
...
Rust fd ingress diag count=23 proto=6 flags=SYN tcp_payload=0 src=10.122.0.1:60824 dst=10.122.0.4:80 packets=23 totals_syn=23 payload=0 fin=0 rst=0 non_tcp=0
```

RouterAction summaries repeatedly show OpenStream only, no SendData:

```text
Rust action callback summary open=1 send=0 close=0 unknown=0 bytes=0 lastType=0 lastStream=1 lastLen=5
Mux summary gwData=0/0B open=1 close=0 send=0/0B
RouterAction send OpenStream stream=1 serviceBytes=5 sent=true
```

Gateway confirms it receives only Open/Close mux frames, no HTTP payload:

```text
FRAME_DATA data_seq=0 payload_len=11
FRAME_OPEN stream_id=1 service=vault
Stream 1 connected, buffered_chunks=0 buffered_bytes=0
FRAME_CLOSE stream_id=1 reason=client_close_after_connect service=vault stream_state=connected queue=0
```

The benchmark still times out / fails, and health manager repeatedly reports no useful RX:

```text
Session health candidate: flows=N outbound=N streamMaps=N highSeq=0 noUsefulRxFor=...
Session health probe ok but flows still suspect; router reset removed=N
```

## Root Cause Identified

The Rust fd ingress path is seeing only TCP SYN packets.

It does NOT see TCP payload packets because iOS never receives the router-generated SYN-ACK/ACK packets back through utun, so the local TCP handshake never completes and the app never sends HTTP request payload.

The missing piece is:

```text
PacketRouter outbound -> Rust fd utun write
```

Old Swift path handled this via:

```swift
flushOutboundPackets(...)
  -> ztlp_router_read_packet_sync(...)
  -> packetFlow.writePackets(...)
```

But in Rust fd data-plane mode:

- Swift packetFlow read loop is disabled.
- Rust owns fd reads.
- Rust feeds packets into PacketRouter.
- Rust dispatches RouterActions to Swift transport.
- Rust currently does NOT drain router outbound packets and write them to the utun fd.

Therefore iOS TCP stack never sees SYN-ACK/ACK packets, causing repeated SYN retransmits and no HTTP request payload.

## Next Implementation Target

Implement Rust-owned PacketRouter outbound -> utun write drain inside `router_ingress` mode.

Suggested design:

1. In `proto/src/ios_tunnel_engine.rs`, after each successful `ztlp_router_write_packet_sync(...)`, call a helper to drain outbound packets:

```rust
fn drain_router_outbound_to_utun(
    router: *mut crate::ffi::ZtlpPacketRouter,
    utun: &IosUtun,
    packet_buf: &mut [u8],
) -> (u64, u64, u64) // packets, bytes, errors
```

2. The helper should call existing FFI:

```rust
crate::ffi::ztlp_router_read_packet_sync(router, packet_buf.as_mut_ptr(), packet_buf.len())
```

Loop until return value is 0 or error, with a max drain cap per ingress packet to avoid monopolizing the read thread. Suggested cap: 64 packets.

3. For each returned raw IP packet, call:

```rust
utun.write_packet(&packet_buf[..n])
```

4. Add log/app diagnostic summary. Since Rust NSLog is redacted, consider using diagnostic callback type 250 or a new type 251 to log to app-group via Swift:

```text
Rust fd router outbound wrote packets=N bytes=N errors=N
```

5. Add counters in the read loop:

- `utun_write_packets`
- `utun_write_bytes`
- `utun_write_errors`

6. After this change, expected phone log should progress from only SYNs to:

```text
Rust fd ingress diag ... flags=SYN tcp_payload=0
Rust fd router outbound wrote packets=1 bytes=...
Rust fd ingress diag ... flags=ACK tcp_payload=0
Rust fd ingress diag ... flags=PSHACK+DATA tcp_payload=...  # or ACK+DATA
Rust action callback summary ... send>0 bytes>0
Mux summary ... send=N/B
```

7. Gateway expected after fix:

```text
FRAME_OPEN stream_id=N service=vault/http
FRAME_DATA ... payload_len > 11/10 containing mux DATA
Forwarding ... bytes to backend: "GET /... HTTP/1.1"
CLIENT_ACK data_seq=...
```

## Important Gotchas

1. Do NOT re-enable Swift `startPacketLoop()` while Rust owns fd reads. Two readers on utun are unsafe.

2. Do NOT use Swift `packetFlow.writePackets` for this phase if the goal is Rust fd ownership. Use `IosUtun::write_packet()`.

3. `IosUtun::write_packet()` already prepends the 4-byte iOS utun header and chooses AF_INET/AF_INET6 based on IP version.

4. The Rust read thread currently calls existing FFI functions against `ZtlpPacketRouter`. The router lifetime is still owned by Swift/PacketTunnelProvider. Stop/free order must remain: stop/free engine before freeing router.

5. Keep drain bounded. A runaway drain loop could starve fd reads and health/control work.

6. Header changes are likely not needed for this next step if only calling existing `ztlp_router_read_packet_sync` from Rust, but if new FFI/log callback types are added, sync headers:

```bash
cp ~/ztlp/proto/include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h
if [ -f ~/ztlp/ios/ZTLP/ZTLP/ztlp.h ]; then cp ~/ztlp/proto/include/ztlp.h ~/ztlp/ios/ZTLP/ZTLP/ztlp.h; fi
```

7. Xcode GUI must Clean Build Folder after replacing static libs.

8. On Mac, always build with cargo PATH first:

```bash
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
```

9. The `patch` tool may emit bogus Rust 2015 async lint errors for `ffi.rs`; ignore those and verify with real Cargo commands.

## Suggested First Commands Next Session

Read this handoff:

```bash
read_file /home/trs/ztlp/ZTLP-IOS-RUST-FD-OUTBOUND-UTUN-HANDOFF-2026-04-29.md
```

Check repo status locally and on Mac:

```bash
cd /home/trs/ztlp && git status --short
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git status --short'
```

Read current Rust engine and router FFI:

```bash
read_file /home/trs/ztlp/proto/src/ios_tunnel_engine.rs
read_file /home/trs/ztlp/proto/src/ffi.rs -- around ztlp_router_read_packet_sync
```

Then implement bounded router outbound -> utun write drain in Rust router_ingress mode.

## Current High-Level Status

- fd discovery: DONE and validated.
- Rust lifecycle-only engine: DONE and validated.
- Rust fd read/drop/log with Swift packetFlow disabled: DONE and stable.
- Rust fd read -> PacketRouter ingress: DONE and stable.
- RouterAction -> Swift transport callback: DONE and validated for Open/Close.
- Rust fd ingress diagnostics through app log: DONE and validated.
- Root cause of no SendData: FOUND — no router outbound -> utun write, so TCP handshake never completes.
- Router outbound -> utun write ownership: NOT DONE. This is next.
- Full Rust data plane: NOT DONE.
