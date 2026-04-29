# ZTLP iOS Restart Handoff — 2026-04-28

## Context

Steve asked to debug the ZTLP iOS app disconnect/crash/stall problem once and for all, using repo history, docs, iPhone logs, gateway history, and mature VPN patterns instead of guessing.

Important current model/tool-session issue: the previous run hit the 60 tool-call iteration limit mid-fix. Steve is considering raising the iteration cap to ~200, which is recommended for this cross-component ZTLP/iOS/Mac/server debugging workflow.

## Current High-Confidence Finding

The latest live iPhone syslog showed a new, very important failure signal:

```text
Apr 28 17:11:46.431555 kernel[0] <Notice>: process ZTLPTunnel[35212] caught waking the CPU 45001 times over ~225 seconds, averaging 199 wakes / second and violating a limit of 45000 wakes over 300 seconds.
```

This is NOT a ZTLPTunnel memory jetsam kill. It is an iOS CPU wakeup-limit violation.

The same live log window also showed:

```text
Apr 28 17:10:32.419702 nesessionmanager[15345] <Notice>: NESMVPNSession[Primary Tunnel:ZTLP:...]: plugin NEVPNTunnelPlugin(com.ztlp.app[packet-tunnel][inactive]) did detach from IPC
```

Interpretation:

- ZTLPTunnel is likely being penalized/detached/unstabilized because it wakes the CPU too frequently.
- This can look like a crash/disconnect.
- This shifts priority above pure congestion tuning.
- Mature iOS VPNs avoid always-on polling and use event-driven timers/callbacks.

## What the Live Watcher Captured

Background process started by Hermes:

```bash
ssh stevenprice@10.78.72.234 '/opt/homebrew/bin/idevicesyslog -m ZTLP -m ZTLPTunnel -m NetworkExtension -m jetsam 2>&1 | tee /tmp/ios-ztlp-live.log'
```

Hermes process id:

```text
proc_f5793aa2231a
```

Mac output file:

```text
/tmp/ios-ztlp-live.log
```

Baseline app-group log pulled before live run:

```text
/tmp/ztlp-phone-before.log
```

It had 3467 lines.

Earlier app-group log pulled in this session:

```text
/tmp/ztlp-phone-current.log
```

It had 3142 lines and showed the older reconnect/socket failure pattern.

## Earlier App-Group Log Finding

The phone app-group log previously showed:

```text
[2026-04-26T14:19:11.861Z] [ERROR] [Tunnel] Tunnel connection failed: The operation couldn’t be completed. (Network.NWError error 57 - Socket is not connected)
[2026-04-26T14:19:11.863Z] [INFO] [Tunnel] Reconnect attempt 1/10 in 1.1s
[2026-04-26T14:19:11.864Z] [ERROR] [Tunnel] Tunnel connection failed: The operation couldn’t be completed. (Network.NWError error 57 - Socket is not connected)
[2026-04-26T14:19:11.864Z] [INFO] [Tunnel] Reconnect attempt 2/10 in 2.3s
[2026-04-26T14:19:12.968Z] [INFO] [Relay] Reported relay failure for 34.219.64.205:23095
[2026-04-26T14:19:12.968Z] [INFO] [Relay] Relay pool stale, re-querying NS for refresh
[2026-04-26T14:19:12.968Z] [INFO] [Relay] Querying NS for RELAY records at 34.217.62.46:23096 (zone=techrockstars)
[2026-04-26T14:19:12.971Z] [WARN] [Relay] NS relay query returned error: NS query send failed: Network is unreachable (os error 51)
[2026-04-26T14:19:12.971Z] [INFO] [Relay] No relay pool available, using configured fallback: 34.219.64.205:23095
[2026-04-26T14:19:12.971Z] [INFO] [Relay] Reconnecting via relay 34.219.64.205:23095...
[2026-04-26T15:40:30.673Z] [INFO] [Tunnel] Stopping tunnel (reason: 9)
```

Interpretation at that point:

- One NWConnection failure likely emitted two callbacks: `.failed` and `receiveMessage` error.
- PacketTunnelProvider scheduled two reconnect attempts for one socket failure.
- Reconnect tried to query NS with plain UDP while the packet tunnel was active.
- That failed with ENETUNREACH.
- After `Reconnecting via relay...`, no success/failure log appeared, suggesting a possible semaphore wait / handshake completion hole.

## Current Primary Root-Cause Hypothesis

There are likely two overlapping failure classes:

### 1. CPU wakeup storm in ZTLPTunnel

Most urgent because iOS explicitly reported it.

Likely contributors in `PacketTunnelProvider.swift` / `ZTLPTunnelConnection.swift`:

- always-on writePacketTimer
- always-on ackFlushTimer
- frequent cleanup timer
- frequent memory diagnostics
- repeated UserDefaults app-group writes
- repeated idle router stats logs
- repeated low-memory warning logs
- per-ACK debug logging
- flush loops running even when `flows=0 outbound=0`

The previous app-group log had many idle lines like:

```text
Router stats: flows=0 outbound=0 stream_to_flow=0 next_stream_id=1
v5D-SYNC | Memory resident=11.5MB virtual=400526.8MB
v5B-SYNC | Low available memory: 46.2MB
v5D-SYNC | Shared NE memory snapshot stored: 11MB
```

The NE should not wake ~199/sec while idle.

### 2. Reconnect state-machine fragility

Still valid and partially patched locally:

- duplicate failure callbacks cause duplicate reconnect attempts
- active-tunnel NS refresh can fail with `Network is unreachable`
- reconnect handshake wait can block forever without timeout/log

## Mature VPN Design Direction

Do NOT solve this primarily with fixed phone-side bandwidth sleeps.

Mature VPN / QUIC-like pattern:

1. iOS NE must be event-driven and quiescent when idle.
2. Gateway owns sender pacing.
3. Phone advertises receive capacity / backpressure.
4. No silent packet drops.
5. ACK/control path should not fight receive path.
6. Reconnect should be idempotent, generation-tracked, and non-blocking.

## Local Changes Made Before Tool Limit Hit

All local changes are in:

```text
/home/trs/ztlp
```

They are NOT committed, NOT pushed, NOT deployed, and NOT on the phone.

### Files changed/added

```text
gateway/lib/ztlp_gateway/session.ex
gateway/test/ztlp_gateway/mobile_pacing_test.exs
proto/src/ffi.rs
proto/include/ztlp.h
ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

### 1. Gateway receiver-window support

File:

```text
gateway/lib/ztlp_gateway/session.ex
```

Added:

```elixir
@default_peer_rwnd 512
```

Added state:

```elixir
peer_rwnd: @default_peer_rwnd
```

Changed effective window calculation from:

```elixir
effective_window = min(trunc(state.cwnd), cc_max_cwnd(state))
```

to:

```elixir
effective_window = min(min(trunc(state.cwnd), cc_max_cwnd(state)), Map.get(state, :peer_rwnd, @default_peer_rwnd))
```

Added 11-byte ACK/rwnd handler:

```elixir
# [FRAME_ACK | ack_seq(8) | rwnd(2)]
defp handle_tunnel_frame(<<@frame_ack, acked_data_seq::big-64, rwnd::big-16>>, state) do
  Logger.info("[Session] CLIENT_ACK data_seq=#{acked_data_seq} rwnd=#{rwnd} last_acked=#{state.last_acked_data_seq} inflight=#{map_size(state.send_buffer)} recovery=#{state.in_recovery}")
  state = %{state | peer_rwnd: max(1, rwnd)}
  ...
end
```

Important: this clause was intentionally inserted before the SACK ACK clause.

### 2. Gateway mobile pacing tests

File added:

```text
gateway/test/ztlp_gateway/mobile_pacing_test.exs
```

Tests passed:

```bash
cd /home/trs/ztlp/gateway
mix test test/ztlp_gateway/mobile_pacing_test.exs
```

Result:

```text
2 tests, 0 failures
```

There were local test startup warnings due to ports already in use:

```text
AuditCollectorServer port 9104 :eaddrinuse
AdminDashboard port 9105 :eaddrinuse
```

These did not fail the test.

Note: token-bucket production wiring was NOT completed. Only the spec/test exists plus rwnd production gating.

### 3. Rust FFI ACK-with-rwnd

Files:

```text
proto/src/ffi.rs
proto/include/ztlp.h
```

Existing `ztlp_build_ack(...)` now delegates to new function with `rwnd=0`.

New function:

```rust
#[no_mangle]
pub extern "C" fn ztlp_build_ack_with_rwnd(
    ack_seq: u64,
    rwnd: u16,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_written: *mut usize,
) -> i32
```

Behavior:

- `rwnd == 0`: writes legacy 9-byte ACK
- `rwnd > 0`: writes 11-byte ACK `[0x01 | ack_seq(8 BE) | rwnd(2 BE)]`

Header declaration added to `proto/include/ztlp.h`.

Validation attempted:

```bash
cd /home/trs/ztlp/proto
cargo test --lib test_sync_build_ack --no-default-features --features ios-sync
```

This failed due to existing ios-sync test cfg hygiene problems in `ffi.rs`, not specifically the new function. Errors referenced default/tokio-only symbols in tests, e.g.:

```text
ZtlpClientInner
tokio
ztlp_client_new
ztlp_send
ztlp_connect
ztlp_dns_start
```

Follow-up needed: run production build commands, not the currently broken ios-sync lib tests, or fix test cfg gating.

### 4. Swift ACK sends rwnd

File:

```text
ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
```

Changed ACK build from:

```swift
ztlp_build_ack(maxSeq, &frameBuffer, frameBuffer.count, &ackWritten)
```

to:

```swift
let availableWindow = max(16, min(512, Self.maxSendsInFlight - sendsInFlight))
let ackResult = ztlp_build_ack_with_rwnd(maxSeq, UInt16(availableWindow), &frameBuffer, frameBuffer.count, &ackWritten)
```

This gives gateway a first receive-window signal based on NE send pressure.

Not perfect yet; future rwnd should combine:

- router outbound queue
- per-flow send_buf pressure
- pending ACK pressure
- packetFlow write pressure if observable
- memory/replay/decrypt health

### 5. Reconnect guardrails

Files:

```text
ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

In `ZTLPTunnelConnection.swift`:

Added:

```swift
private var didReportFailure = false
```

Reset in `start()`.

Added:

```swift
private func reportFailureOnce(_ error: Error, source: String)
```

Both failure paths now call it:

- `.failed` -> `source: "state.failed"`
- `receiveMessage` error -> `source: "receiveMessage"`

This should prevent one NWConnection failure from producing two reconnect attempts.

In `PacketTunnelProvider.swift`:

Added:

```swift
private var reconnectScheduled = false
private var reconnectInProgress = false
private var reconnectGeneration = 0
```

`scheduleReconnect()` now:

- ignores duplicate triggers while scheduled/in-progress
- increments generation
- logs generation
- only runs if generation still matches

`attemptReconnect(generation:)` now:

- guards `reconnectInProgress`
- logs start
- uses `defer { reconnectInProgress = false }`

Reconnect path now skips active-tunnel NS refresh:

```swift
logger.info("Relay pool stale during reconnect; skipping active-tunnel NS refresh and using cached/fallback relay", source: "Relay")
```

Instead of calling `discoverRelays(config:)` while tunnel is active.

Reconnect handshake wait now has timeout:

```swift
let waitResult = handshakeSemaphore.wait(timeout: .now() + 20.0)
if waitResult == .timedOut { ... scheduleReconnect(); return }
```

This targets the earlier “Reconnecting via relay...” then silence problem.

## What Was NOT Completed

Need to do next:

1. Inspect `git diff` carefully.
2. Add tests for:
   - Rust `ztlp_build_ack_with_rwnd` writes 11 bytes.
   - Gateway 11-byte ACK updates `peer_rwnd` and does not parse as SACK.
   - Reconnect duplicate scheduling ideally via a Swift unit-test equivalent if feasible, or at least compile and log validation.
3. Fix or avoid broken ios-sync test cfg issue.
4. Run production builds:

```bash
cd /home/trs/ztlp/gateway && mix compile && mix test
cd /home/trs/ztlp/proto && cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib --target-dir target-ios-sync
cd /home/trs/ztlp/proto && cargo build --release --target aarch64-apple-ios --lib
```

5. Sync headers:

```bash
cp /home/trs/ztlp/proto/include/ztlp.h /home/trs/ztlp/ios/ZTLP/Libraries/ztlp.h
cp /home/trs/ztlp/ios/ZTLP/Libraries/ztlp.h /home/trs/ztlp/ios/ZTLP/ZTLP/ztlp.h
```

Check whether this untracked file should exist or be removed/synced:

```text
ios/ZTLP/ZTLPTunnel/ztlp.h
```

6. Mac repo status before sync/build:

Steve’s Mac repo `~/ztlp` was at:

```text
b63d18f fix: stop dropping gateway packets under Safari load
```

It had local changes:

```text
 M ios/ZTLP/Libraries/ztlp.h
 M ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
 M ztlp-safari-fix-plan.md
?? ios/ZTLP/ZTLPTunnel/ztlp.h
```

Need to preserve or inspect before pulling/overwriting.

7. Build iOS libs on Mac after code is ready:

```bash
ssh stevenprice@10.78.72.234 'export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"; cd ~/ztlp/proto && \
  cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib --target-dir target-ios-sync && \
  cp target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a && \
  cargo build --release --target aarch64-apple-ios --lib && \
  cp target/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto.a && \
  cp include/ztlp.h ~/ztlp/ios/ZTLP/Libraries/ztlp.h && \
  cp ~/ztlp/ios/ZTLP/Libraries/ztlp.h ~/ztlp/ios/ZTLP/ZTLP/ztlp.h'
```

8. Run unsigned Xcode build check:

```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp/ios/ZTLP && xcodebuild -project ZTLP.xcodeproj -scheme ZTLP -destination "generic/platform=iOS" -configuration Release build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO'
```

9. Steve must deploy from Xcode GUI for phone due to codesign/keychain limitations.

10. Before asking Steve to test, run server preflight:

```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

Only proceed if it ends with PRECHECK GREEN.

## New Urgent Work: Reduce CPU Wakeups

This should probably be the next primary patch before deploying the rwnd/congestion work.

Inspect in `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`:

- `startWritePacketTimer`
- `startAckFlushTimer`
- `startCleanupTimer`
- `startKeepaliveTimer`
- `logMemoryDiagnostics`
- `flushOutboundPackets`
- `readPacketLoop`
- any `asyncAfter`/`DispatchSourceTimer` repeating loop
- repeated `sharedDefaults?.set(...)`
- repeated logger lines while idle

Likely fix batch:

1. Convert write packet flushing to demand-driven:
   - Start flush timer only when router/gateway produces outbound packets.
   - Stop after `ztlp_router_read_packet_sync` returns 0 repeatedly.
   - No repeating high-frequency timer while idle.

2. Convert ACK flush timer to one-shot:
   - Schedule only when pending ACKs exist.
   - Cancel/no-op after flush.
   - No repeating timer while idle.

3. Rate-limit memory/UserDefaults writes:
   - 60s minimum.
   - Only write memory snapshot if changed by >= 1MB or state changes.

4. Remove or severely rate-limit repeated warning:

```text
Low available memory: 46.2MB
```

This warning fired constantly while resident memory was only ~11.5MB, so it is misleading/noisy.

5. Add explicit logs:

```text
Idle quiesce: stopped packet/ACK timers
Traffic active: starting packet flush timer
```

6. Verify after rebuild with idevicesyslog:

- no more `199 wakes/sec` warning
- tunnel remains attached
- idle flow shows low/no deltas
- app-group log stops idle spam

## Useful Commands for Next Session

### Pull fresh app-group log

```bash
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone-after.log && \
  wc -l /tmp/ztlp-phone-after.log && tail -n 220 /tmp/ztlp-phone-after.log'
```

### Inspect live syslog on Mac

```bash
ssh stevenprice@10.78.72.234 'grep -E "ZTLPTunnel|ZTLP|waking the CPU|detach from IPC|memorystatus|jetsam|NESMVPNSession" /tmp/ios-ztlp-live.log | tail -200'
```

### Find idle spam in app-group log

```bash
ssh stevenprice@10.78.72.234 'grep -E "Router stats|Memory resident|Low available memory|Shared NE memory snapshot|flush|timer|Reconnect|Stopping tunnel" /tmp/ztlp-phone-after.log | tail -200'
```

### Check local diff

```bash
cd /home/trs/ztlp && git diff --stat && git diff -- ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift gateway/lib/ztlp_gateway/session.ex proto/src/ffi.rs proto/include/ztlp.h
```

## Safety Rules

- Do NOT restart gateway/relay/NS without telling Steve first. Gateway restart crashes his iOS benchmark/session.
- Do NOT ask Steve to test before server preflight is green.
- Steve’s iOS build repo is `~/ztlp` on the Mac, not `~/code/ztlp`.
- For iOS, build two libs:
  - `libztlp_proto_ne.a`: no default features + ios-sync
  - `libztlp_proto.a`: full/default app lib
- Use separate target dir for ios-sync build.
- After replacing static libs, Steve should Clean Build Folder in Xcode before deploying.

## Bottom Line

The clearest new root-cause evidence is the iOS kernel CPU wakeup violation:

```text
ZTLPTunnel woke CPU 45001 times over ~225 seconds, ~199 wakes/sec, violating iOS limit.
```

This likely explains disconnects/crash-like behavior better than memory pressure.

Next best work item: make the Network Extension quiescent/event-driven when idle, then finish validating the partially implemented reconnect/rwnd/pacing changes.
