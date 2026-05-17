# ZTLP iOS Current Handoff — 2026-05-02

## Executive summary

Current repo head is:

- `b1ef1ea` — `docs: add iOS stuck flow cleanup handoff`

The active frontier is no longer the old pure-Swift `packetFlow` tuning path.
The project has moved into the Rust-fd-owned iOS Network Extension migration, with gateway tuning now treated as secondary and evidence-driven.

Big picture state:

1. `utun` fd discovery on iPhone works.
2. Rust lifecycle-only engine worked and was not the crash cause.
3. Swift `packetFlow.readPackets` can be disabled.
4. Rust can own utun ingress without reproducing the old NE crash boundary.
5. Rust router ingress works.
6. Rust -> Swift RouterAction callback bridge exists.
7. Rust router outbound -> utun drain was implemented after that.
8. Duplicate/stale `CloseStream` suppression work happened after outbound drain.
9. Session-health watchdog was moved off `tunnelQueue` and recovery logic exists.
10. Current open question is live-device validation/stabilization of the hybrid Rust-fd path under real WKWebView/browser load, not blind gateway loosening.

## Current repo/worktree state

Local repo:
- `/home/trs/ztlp`

Git status at capture time:
- branch: `main...origin/main`
- untracked:
  - `docs/GATEWAY-REVIEW-POST-RUST-FD-AUDIT-2026-05-01.md`
  - `docs/IOS-GATEWAY-PERFORMANCE-HANDOFF-2026-05-01.md`

Recent commits:
- `b1ef1ea` docs: add iOS stuck flow cleanup handoff
- `0b0367c` ios: bridge close suppression markers to app log
- `459b79c` ios: add Rust fd close suppression markers
- `b3ef9dd` ios: suppress duplicate fd CloseStream callbacks
- `489f1d7` ios: stabilize Rust fd long-flow cleanup
- `fd05b43` docs: add Rust fd long-flow stabilization plan
- `f25dedf` ios: enable Rust fd router outbound utun drain
- `77e17ab` docs: add iOS Nebula-style utun fd architecture
- `d42bf1c` ios: move session health watchdog off tunnel queue
- `05ee776` ios: gate browser bursts at receive window floor
- `625b930` ios: cap adaptive receive window at five
- `c8afd73` ios: reset session health baselines after reconnect
- `172da8d` ios: add conservative adaptive receive window

## Machines / environment / operational facts

- Steve’s Mac: `stevenprice@10.78.72.234`
- Mac iOS/Xcode repo: `~/ztlp`
- Do not use `~/code/ztlp` for iOS builds/deploys.
- Local Linux repo: `/home/trs/ztlp`
- Phone device id: `39659E7B-0554-518C-94B1-094391466C12`

Important standing rules:
- Device deploys/codesign must be done from Xcode GUI on the Mac; SSH unsigned builds are only verification.
- After replacing `libztlp_proto_ne.a`, do Xcode `Product -> Clean Build Folder` before deploying.
- Before asking Steve to test on iPhone, run:
  - `/home/trs/ztlp/scripts/ztlp-server-preflight.sh`
- Do not restart/redeploy gateway while Steve is actively testing.

## Best log / evidence commands

Pull phone app-group log through Steve’s Mac:

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

Live iOS syslog helper:

```bash
/home/trs/ztlp/scripts/ios-syslog-capture.sh 300
```

Crash list from Mac:

```bash
ssh stevenprice@10.78.72.234 '
  /Users/stevenprice/Library/Python/3.9/bin/pymobiledevice3 crash ls | grep -iE "ZTLPTunnel|ztlp|com.ztlp" | tail -60
'
```

Server preflight:

```bash
cd /home/trs/ztlp && ./scripts/ztlp-server-preflight.sh
```

## Architecture progression already completed

### Phase 1 — utun fd discovery

Implemented and validated:
- `PacketTunnelProvider.swift` uses C helper `ztlp_find_utun_fd()` from `ZTLPTunnel-Bridging-Header.h`
- Reason: Swift could not directly see `ctl_info`, `sockaddr_ctl`, `CTLIOCGINFO` on iOS

Expected marker from that phase:
- `utun fd acquired fd=5`

Earlier marker before Rust start:
- `utun fd acquired fd=5 (Rust fd engine scaffold not started; Swift packetFlow still owns data plane)`

Conclusion:
- fd discovery itself is solved and was not the root problem.

### Phase 2 — lifecycle-only Rust engine

Implemented:
- new Rust file `proto/src/ios_tunnel_engine.rs`
- FFI lifecycle exports in `proto/src/ffi.rs` and headers
- `IosUtun` wrapper strips/prepends the 4-byte Darwin utun AF header

FFI symbols introduced:
- `ztlp_ios_tunnel_engine_start`
- `ztlp_ios_tunnel_engine_stop`
- `ztlp_ios_tunnel_engine_reconnect`
- `ztlp_ios_tunnel_engine_free`

Validated marker:
- `Rust iOS tunnel engine scaffold started fd=5 mode=lifecycle_only`

Conclusion:
- lifecycle-only Rust engine was not the crash cause.

### Phase 3A — Rust fd read/drop/log

Implemented:
- Swift packet loop disabled when `useRustFdDataPlane = true`
- Rust owns utun reads and drops/logs packets

Conclusion:
- NE stayed up past the old failure window.
- This strongly implicated the old Swift `packetFlow` hot path rather than generic NE startup, relay, or simple rwnd tuning.

### Phase 3B — Rust fd router ingress

Implemented:
- Rust utun read loop feeds PacketRouter via `ztlp_router_write_packet_sync(...)`
- Swift `packetFlow.readPackets` disabled in this mode

Key observed marker:
- `Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=not_bridged`

Major conclusion from this phase:
- The old crash boundary is very likely the Swift `packetFlow/readPackets + Swift router/utun hot path under browser/benchmark burst`.
- Not primarily gateway congestion, not the Rust scaffold, and not simple rwnd value alone.

### Phase 4 — RouterAction -> Swift transport bridge

Implemented after router_ingress handoff:
- Rust parses serialized router actions from `ztlp_router_write_packet_sync`
- Rust invokes Swift callback
- Swift reuses existing transport send path through `ZTLPTunnelConnection`

Action wire format:
- `[1 byte type][4 bytes stream_id BE][2 bytes data_len BE][data...]`
- `0=OpenStream, 1=SendData, 2=CloseStream`

Transport callback registration symbol:
- `ztlp_ios_tunnel_engine_set_router_action_callback(...)`

Expected startup markers in this phase:
- `Rust router action callback registered`
- `Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback`

Important diagnostic note:
- Rust `NSLog` / `ios_log` payloads were redacted as `<private>` in syslog and absent from app-group `ztlp.log`
- Because of that, Rust fd diagnostics were bridged through Swift callback diagnostics, especially pseudo-action type `250`

### Phase 5 — Router outbound -> utun drain

Root cause discovered before this step:
- Rust fd ingress saw only TCP SYNs
- no `SendData` actions
- gateway saw only Open/Close
- local TCP handshake never completed because PacketRouter-generated SYN-ACK/ACK packets were not being written back to utun

Old Swift path had done:
- `flushOutboundPackets(...) -> ztlp_router_read_packet_sync(...) -> packetFlow.writePackets(...)`

Missing piece in Rust-fd mode was:
- `PacketRouter outbound -> Rust fd utun write`

Implemented in commit line later represented by:
- `f25dedf` — `ios: enable Rust fd router outbound utun drain`

Meaning:
- Rust fd engine now not only feeds ingress into PacketRouter, but also drains router outbound packets back to utun.

### Phase 6 — long-flow / duplicate close cleanup

Later commits show stabilization work after outbound drain:
- `489f1d7` ios: stabilize Rust fd long-flow cleanup
- `b3ef9dd` ios: suppress duplicate fd CloseStream callbacks
- `459b79c` ios: add Rust fd close suppression markers
- `0b0367c` ios: bridge close suppression markers to app log

Key implementation notes from duplicate-close handoff:
- `PacketRouter::has_stream(stream_id)` added
- new FFI `ztlp_router_has_stream_sync(router, stream_id) -> i32`
- Rust fd dispatcher tracks closed streams and suppresses stale/duplicate `CloseStream` callbacks
- expected markers included `suppressed_close=...`

Open validation issue from that handoff:
- some expected Rust-side suppression markers were still missing from phone logs even after the Mac lib/header appeared correct
- possible cause was logging-path visibility, conditional marker emission, or stale deployment confusion

## Session-health / recovery state

Nebula-style session-health recovery exists and is important context.

Core design:
- detect “alive but stuck” sessions without killing the NE blindly
- use encrypted `FRAME_PING` / `FRAME_PONG`
- track useful RX, highSeq progression, router stats, outbound demand
- if suspect:
  - send probe
  - if probe OK: cleanup stale flows or reset router runtime state
  - if probe timeout: reset router runtime state + reconnect transport without manual VPN toggle

Key gateway frame constants:
- `FRAME_PING = 0x07`
- `FRAME_PONG = 0x08`

Important iOS marker:
- `Session health manager enabled interval=2.0s suspectRx=5.0s probeTimeout=5.0s stuckTicks=3 queue=healthQueue`

Important repo milestone:
- `d42bf1c` moved the session-health watchdog off `tunnelQueue`

Important conclusions already established:
- Session-health logic itself was not the original crash cause.
- A major earlier wedge was caused by a cross-queue shared `frameBuffer` race in probe/PONG handling; that was fixed.
- Under pressure, the health ladder can detect and recover, but visible recovery time still matters.

## Current iOS-side facts confirmed in code/docs

Current `PacketTunnelProvider.swift` state at capture time shows:
- `useRustFdDataPlane = true`
- startup log when enabled:
  - `Rust fd data plane requested; Swift packet I/O loop disabled`
- startup log in current callback bridge path:
  - `Rust iOS tunnel engine scaffold started fd=... mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback`
- session health enable marker includes `queue=healthQueue`

Current iOS receive-window posture:
- conservative and intentional
- `rwndFloor = 4`
- adaptive max currently capped at `5`
- browser/WKWebView multi-flow pressure should remain at the floor
- `ZTLPTunnelConnection` clamps advertised receive window to `4...5`

Interpretation:
- The client often advertises only `rwnd=4..5`
- so gateway egress can usually only have ~4–5 packets safely in flight when `peer_rwnd` is honored
- this is why gateway loosening is not the immediate first move

## Current gateway-side posture

From current review docs/code:
- `@queue_high 512`
- `@queue_low 128`
- `@max_mux_streams 32`
- `@max_connecting_buffer_bytes 65_536`
- gateway effective window honors `peer_rwnd`
- mobile/unknown path still uses conservative mobile timing profile

Important interpretation from 2026-05-01 review:
- keep correctness/safety fixes:
  - session replacement cleanup hardening
  - recovery exit when ACK reaches last sent packet
  - recv-window gap recovery
  - ACK fast-path/rwnd support
  - mobile unknown RTO handling
  - session health ping/pong support
- only re-evaluate later, with evidence:
  - queue thresholds
  - max mux streams
  - connecting buffer cap
  - queue-high enqueue halting behavior

Bottom line from that review:
- do not loosen gateway limits first
- validate Rust-fd path under real browser/WKWebView load first
- tune client rwnd before gateway queue/mux caps

## Most important repo files

Swift / iOS:
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnel-Bridging-Header.h`
- `ios/ZTLP/Libraries/ztlp.h`
- possibly duplicate header: `ios/ZTLP/ZTLP/ztlp.h`

Rust:
- `proto/src/ios_tunnel_engine.rs`
- `proto/src/ffi.rs`
- `proto/src/packet_router.rs`
- `proto/include/ztlp.h`
- `proto/src/lib.rs`

Gateway:
- `gateway/lib/ztlp_gateway/session.ex`

Reference / handoff docs worth reading next session:
- `/home/trs/ztlp/ZTLP-IOS-UTUN-FD-PHASE1-HANDOFF-2026-04-29.md`
- `/home/trs/ztlp/ZTLP-IOS-RUST-FD-ROUTER-INGRESS-HANDOFF-2026-04-29.md`
- `/home/trs/ztlp/ZTLP-IOS-RUST-FD-OUTBOUND-UTUN-HANDOFF-2026-04-29.md`
- `/home/trs/ztlp/ZTLP-IOS-DUPLICATE-CLOSESTREAM-HANDOFF-2026-04-29.md`
- `/home/trs/ztlp/ZTLP-IOS-PERFORMANCE-RECOVERY-HANDOFF-2026-04-29.md`
- `/home/trs/ztlp/ZTLP-IOS-SESSION-HEALTH-HANDOFF-2026-04-29.md`
- `/home/trs/ztlp/docs/IOS-GATEWAY-PERFORMANCE-HANDOFF-2026-05-01.md`
- `/home/trs/ztlp/docs/GATEWAY-REVIEW-POST-RUST-FD-AUDIT-2026-05-01.md`

## Proven build / sync commands

Local Rust validation:

```bash
cargo check --manifest-path /home/trs/ztlp/proto/Cargo.toml --no-default-features --features ios-sync --lib
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml --features ios-sync ios_tunnel_engine --lib
```

Mac NE lib rebuild pattern:

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/proto &&
  cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib &&
  cp target/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a &&
  cp include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h &&
  if [ -f ~/ztlp/ios/ZTLP/ZTLP/ztlp.h ]; then cp include/ztlp.h ~/ztlp/ios/ZTLP/ZTLP/ztlp.h; fi
'
```

Known safer variant for avoiding target-dir collisions in ios-sync builds:

```bash
cargo build --manifest-path proto/Cargo.toml --target aarch64-apple-ios --release --lib --no-default-features --features ios-sync --target-dir proto/target-ios-sync
```

Unsigned Xcode verification build:

```bash
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/ios/ZTLP &&
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
    -destination "generic/platform=iOS" \
    -configuration Debug build \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
'
```

## What seems most likely true right now

1. The old catastrophic instability was centered in the Swift `packetFlow` hot path.
2. The Rust-fd migration has crossed several real milestones and is not just a scaffold anymore.
3. The current path is still hybrid:
   - Rust owns utun ingress and router drain work
   - Swift still owns transport send through `ZTLPTunnelConnection` / `NWConnection`
4. Session-health recovery exists and matters, but is not the only story.
5. Current immediate bottleneck is probably still conservative client rwnd / browser-burst behavior and live validation of the Rust-fd hybrid path, not gateway queue depth first.
6. Duplicate/stale close handling and long-flow cleanup were the latest stabilization area after outbound utun drain.

## Best next-session starting point

Recommended next pickup order:

1. Read the newest docs/handoffs listed above, especially the duplicate-close and May 1 gateway review notes.
2. Check local repo status and current HEAD.
3. Verify current source markers in:
   - `PacketTunnelProvider.swift`
   - `proto/src/ios_tunnel_engine.rs`
   - `proto/src/ffi.rs`
   - `gateway/lib/ztlp_gateway/session.ex`
4. If asking Steve to test on phone:
   - run `/home/trs/ztlp/scripts/ztlp-server-preflight.sh`
   - require `PRECHECK GREEN`
5. Pull fresh phone app-group log and verify current deployed markers, especially:
   - `Rust fd data plane requested; Swift packet I/O loop disabled`
   - `Rust router action callback registered`
   - `Rust iOS tunnel engine scaffold started ... transport=swift_action_callback`
   - `Session health manager enabled ... queue=healthQueue`
   - any close-suppression / `suppressed_close` markers
   - any Rust fd dispatch / utun write markers
6. Only after live evidence is clean should gateway queue/mux-limit retesting begin.

## One-line handoff

Where we left off: the project had moved past pure Swift packetFlow debugging into a hybrid Rust-fd iOS data plane with router ingress, action callback bridging, outbound utun drain, session-health recovery, and duplicate-close stabilization; the next practical job is device-log-grounded validation/stabilization of that path under real WKWebView/browser load before loosening gateway limits.