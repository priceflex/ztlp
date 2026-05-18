# ZTLP iOS Rust FD Data Plane Validation — 2026-04-29

## Summary

This note documents the successful migration step where the iOS Network Extension Rust fd-owned `router_ingress` loop began draining PacketRouter outbound packets and writing them back to the utun fd.

The original failure mode was:

- Rust fd ingress saw only TCP SYN packets.
- PacketRouter emitted OpenStream/CloseStream actions but no SendData.
- Gateway saw stream lifecycle frames but no HTTP payload.
- Benchmarks timed out because the iOS TCP stack never completed the local TCP handshake.

Root cause:

- Rust owned utun reads and fed PacketRouter ingress.
- Swift `packetFlow.readPackets` was disabled, as intended.
- But Rust did not drain PacketRouter outbound packets and write SYN-ACK/ACK/data packets back to utun.
- Therefore iOS never saw the router-generated TCP handshake responses.

Fix implemented:

- Added a bounded `drain_router_outbound_to_utun(...)` helper in `proto/src/ios_tunnel_engine.rs`.
- After each successful `ztlp_router_write_packet_sync(...)`, Rust now calls `ztlp_router_read_packet_sync(...)` in a bounded loop.
- Each returned raw IP packet is written using `IosUtun::write_packet(...)`, which prepends the iOS utun AF header.
- Drain cap is `MAX_ROUTER_OUTBOUND_DRAIN_PER_INGRESS = 64` packets per ingress packet.
- Added counters and diagnostics for:
  - `utun_write_packets`
  - `utun_write_bytes`
  - `utun_write_errors`
- Added Swift app-log diagnostic callback action type `251` for outbound write summaries.

## Files Changed in This Phase

Primary implementation:

- `proto/src/ios_tunnel_engine.rs`
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`

Related iOS fd-engine/FFI scaffolding from this Rust fd data-plane migration phase:

- `proto/src/ffi.rs`
- `proto/src/lib.rs`
- `proto/include/ztlp.h`
- `ios/ZTLP/Libraries/ztlp.h`
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnel-Bridging-Header.h`

## Key Runtime Markers

Startup markers expected on-device:

```text
Rust router action callback registered
Rust iOS tunnel engine scaffold started fd=N mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback
TUNNEL ACTIVE — v5D RELAY-SIDE VIP (no NWListeners)
```

New outbound drain marker:

```text
Rust fd outbound diag count=N outbound_wrote packets=N bytes=N errors=0 totals_packets=N totals_bytes=N totals_errors=0
```

Success path markers:

```text
Rust fd ingress diag ... flags=ACK tcp_payload=0
Rust fd ingress diag ... flags=PSHACK+DATA tcp_payload=268
Rust action callback summary ... send=1 ... bytes=268
RouterAction send SendData stream=N bytes=268 sent=true
Mux summary gwData=N/B open=N close=N send=N/B
```

## Validation Results

Local Linux validation:

```bash
cargo check --manifest-path /home/trs/ztlp/proto/Cargo.toml --no-default-features --features ios-sync --lib
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml --features ios-sync ios_tunnel_engine --lib
```

Results:

- `cargo check` passed.
- `ios_tunnel_engine` tests passed 4/4.

Mac/iOS build validation on Steve's Mac (`stevenprice@10.78.72.234`, repo `~/ztlp`):

```bash
cd ~/ztlp/proto
cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib
cp target/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a

cd ~/ztlp/ios/ZTLP
xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
  -destination "generic/platform=iOS" \
  -configuration Debug build \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
```

Results:

- NE static library rebuilt successfully.
- Unsigned Xcode build succeeded.

Server preflight:

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Result:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

## Live Phone Validation

Pulled iPhone app-group log from device:

```bash
ssh stevenprice@10.78.72.234 '
  xcrun devicectl device copy from \
    --device 39659E7B-0554-518C-94B1-094391466C12 \
    --domain-type appGroupDataContainer \
    --domain-identifier group.com.ztlp.shared \
    --source ztlp.log \
    --destination /tmp/ztlp-phone.log
'
```

Observed successful outbound writes:

```text
Rust fd outbound diag count=4 outbound_wrote packets=1 bytes=44 errors=0 totals_packets=5 totals_bytes=208 totals_errors=0
Rust fd outbound diag count=15 outbound_wrote packets=1 bytes=40 errors=0 totals_packets=21 totals_bytes=868 totals_errors=0
```

Observed TCP progress beyond SYN:

```text
Rust fd ingress diag count=10 proto=6 flags=ACK tcp_payload=0 src=10.122.0.1:60865 dst=10.122.0.4:80
Rust fd ingress diag count=31 proto=6 flags=PSHACK+DATA tcp_payload=268 src=10.122.0.1:50505 dst=10.122.0.4:80
```

Observed SendData actions:

```text
Rust action callback summary open=5 send=1 close=5 unknown=0 bytes=268 lastType=1 lastStream=7 lastLen=268
RouterAction send SendData stream=7 bytes=268 sent=true
```

Observed gateway response/mux traffic:

```text
Mux summary gwData=38/26343B open=7 close=9 send=2/531B
ZTLP RX summary packets=1710 payload=1250986B acks=1710 replay=1 highSeq=1709 inflight=0
```

Benchmark successes:

```text
Benchmark upload complete: HTTP 201 score=8/8 ... "benchmark_id":236
Benchmark upload complete: HTTP 201 score=8/8 ... "benchmark_id":237
```

## Interpretation

The handoff's root cause is fixed:

- Before: only SYNs reached Rust fd ingress; no SendData; gateway got Open/Close only.
- After: Rust writes router outbound packets back to utun; iOS sends ACK and PSHACK+DATA; PacketRouter emits SendData; benchmark passes 8/8.

A later longer/browser-style traffic sequence still reached the existing session-health recovery path:

```text
Session health dead: probe timeout
Router reset runtime state removed=2 reason=session_health_probe_timeout
Reconnect gen=1 succeeded via relay 34.219.64.205:23095; reset health/rwnd baselines
```

That is a separate remaining browser/long-flow stability/recovery behavior. It does not invalidate this phase: the missing Rust outbound -> utun bridge is confirmed working.

## Operational Notes

- Swift `packetFlow.readPackets` must remain disabled while Rust owns fd reads.
- Do not reintroduce Swift `packetFlow.writePackets` for this Rust fd-ownership phase.
- `IosUtun::write_packet(...)` already prepends the 4-byte iOS utun header and selects AF_INET/AF_INET6 based on IP version.
- Keep the drain bounded to avoid starving the fd read/control loop.
- Diagnostic action type `250` is fd ingress metadata.
- Diagnostic action type `251` is fd outbound write metadata.
- Both diagnostic callbacks are temporary and should be rate-limited further or removed once the Rust fd data plane stabilizes.

## Next Work

Recommended next focus:

1. Preserve this Rust fd outbound drain behavior.
2. Investigate the remaining long-flow/browser recovery path separately.
3. Continue reducing high-volume Swift involvement by moving more transport/session ownership into Rust when ready.
4. Keep using app-group log markers to verify deployed NE code before interpreting benchmark results.
