# Vaultwarden WKWebView Stall — Status / Handoff — 2026-05-03

## TL;DR

Vaultwarden itself is healthy. WKWebView/iOS is loading through ZTLP and receives multiple MB of Vaultwarden JS/assets, but the browser load still stalls on the response tail. We tried several incremental congestion/recovery fixes. They improved the failure shape but did not solve it.

The current evidence suggests the existing approach is the wrong abstraction level: we are trying to make browser-scale HTTP/TCP asset delivery reliable through a hybrid Rust-fd packet router + ZTLP mux stream path with ad-hoc rwnd/backpressure/recovery. The transport now enters repeated tail-replay/RTO/reconnect recovery, and WKWebView gives up before recovery completes.

Recommended next approach: stop continuing micro-tuning rwnd/queue/RTO. Step back and change architecture for browser traffic. Strong candidates:

1. HTTP-aware in-app proxy / URL loading path for service links, bypassing the NE packet-router TCP emulation for WKWebView assets.
2. A real end-to-end reliable stream transport for browser flows, instead of TCP-over-mux-over-UDP with independent gateway queueing and client-side synthetic TCP state.
3. If keeping NE path, implement proper per-stream flow control / explicit gateway-to-client delivery acknowledgements at the mux stream layer, not just session-level packet rwnd.

## Current live deployment state

### Gateway

Live gateway host: `44.246.33.34`

Live image after the last deploy:

```text
ztlp-gateway:vault-shallow128
```

Deployed gateway changes:

- `gateway/lib/ztlp_gateway/backend.ex`
  - `Backend.pause_read/1` now actually sets backend TCP socket `active: false`.
  - Backend `{:tcp, ...}` handler explicitly keeps `active: false` while paused and re-arms `active: :once` only when not paused.

- `gateway/lib/ztlp_gateway/session.ex`
  - RTO retransmit batch for `peer_rwnd <= 8` reduced to 2.
  - `per_packet_rto/2` changed to take full session state and respect `cc_min_rto_ms(state)`.
  - Queue thresholds currently:
    - `@queue_high 128`
    - `@queue_low 32`

Gateway preflight after deploy:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Relevant preflight confirmations:

```text
PASS Gateway container is running
PASS Gateway uses host networking
PASS Gateway runtime NS config is correct: {{172, 26, 13, 85}, 23096}
PASS Gateway can reach backend 127.0.0.1:8080
PASS Gateway can reach backend 127.0.0.1:8180
PASS No backend econnrefused seen in recent gateway logs
PASS No send_queue overload rejections seen in recent gateway logs
```

### iOS / Mac build host

Mac build host: `stevenprice@10.78.72.234`, repo `~/ztlp`.

Local Linux repo and Mac repo have synced Swift changes in:

```text
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Last unsigned Xcode build run from SSH succeeded:

```text
cd ~/ztlp/ios/ZTLP
xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
  -destination "generic/platform=iOS" -configuration Debug build \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO

** BUILD SUCCEEDED **
```

Warnings are the known `withCString` unused-result warnings and existing Rust static lib iOS-version linker warnings.

Important: Xcode GUI deploy to device is still required after Swift changes. Codesign/device deploy from SSH fails by convention.

## Uncommitted working tree changes

At handoff time, these files are modified:

```text
M gateway/lib/ztlp_gateway/backend.ex
M gateway/lib/ztlp_gateway/session.ex
M ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Untracked docs also existed before this handoff:

```text
?? docs/GATEWAY-REVIEW-POST-RUST-FD-AUDIT-2026-05-01.md
?? docs/IOS-GATEWAY-PERFORMANCE-HANDOFF-2026-05-01.md
?? docs/VAULTWARDEN-SPINNER-TAIL-STALL-ANALYSIS-2026-05-02.md
?? docs/ZTLP-IOS-HANDOFF-CURRENT-2026-05-02.md
```

This handoff doc is:

```text
docs/VAULTWARDEN-WKWEBVIEW-STALL-STATUS-HANDOFF-2026-05-03.md
```

## Chronology of this session

### Starting point

We began from:

```text
docs/VAULTWARDEN-RWND8-RTO-COMBINED-FIX-HANDOFF-2026-05-02.md
```

That doc said:

- Vaultwarden backend healthy.
- iOS app already uses WKWebView, not Safari/SFSafariViewController.
- Current failure is in ZTLP iOS Rust-fd browser data path during large Vaultwarden asset delivery.
- Recommended combined fix:
  - Keep browser `rwnd=8` only while clean.
  - Drop to `rwnd=4` on replay.
  - Audit gateway RTO / retransmit behavior.
  - Reduce RTO retransmit batch for mobile/browser.

### Fix 1 — iOS replay-triggered rwnd cooldown

File:

```text
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Implemented:

- `rwndReplayDeltaBad` lowered from 8 to 2.
- Added `rwndPressureCooldown = 15s`.
- Added `rwndPressureUntil`.
- If browser burst and any replay appears:
  - drop advertised rwnd to 4
  - hold 4 through cooldown
  - avoid bouncing immediately back to 8

Expected marker:

```text
browser replay backoff replayDelta=... cooldown=15s
pressure cooldown remaining=...s
```

Result:

- This worked mechanically, but rwnd backoff alone did not rescue WKWebView before the browser transaction stalled.

### Fix 2 — gateway RTO clamp and retransmit batch limiter

File:

```text
gateway/lib/ztlp_gateway/session.ex
```

Implemented:

- `per_packet_rto(state, retransmit_count)` instead of `per_packet_rto(base_rto, retransmit_count)`.
- Per-packet RTO now applies `max(cc_min_rto_ms(state))` before `@max_rto_ms` cap.
- Added `@mobile_rto_retransmit_per_tick 2`.
- `effective_rto_retransmit_limit(state)` uses 2 when `peer_rwnd <= 8`, otherwise default 8.

Validation:

```text
cd gateway && mix compile --warnings-as-errors
mix test test/ztlp_gateway/session_recovery_target_test.exs test/ztlp_gateway/session_dedup_test.exs
9 tests, 0 failures
```

Result:

- Reduced retransmit batch size works. Logs show tail retransmits in pairs rather than blasting full rwnd=8 tail.
- Did not solve the browser stall.

### Fix 3 — gateway backend pause actually disables socket active mode

File:

```text
gateway/lib/ztlp_gateway/backend.ex
```

Implemented:

- `handle_cast(:pause_read, ...)` now calls `:inet.setopts(socket, active: false)`.
- `handle_info({:tcp,...})` now explicitly sets `active: false` if paused, else `active: :once`.

Why:

- Previously `pause_read` only set `paused: true`, but a backend socket could still have an already armed `active: :once` receive. That made backpressure ON/OFF cycles sloppy.

Result:

- Gateway starvation shape improved, but stall persisted.

### Fix 4 — gateway shallow queue 128/32

File:

```text
gateway/lib/ztlp_gateway/session.ex
```

Changed:

```elixir
@queue_high 128
@queue_low 32
```

Deployed as:

```text
ztlp-gateway:vault-shallow128
```

Why:

- `256/64` still allowed too much response tail behind `rwnd=8`.
- Goal was earlier backend TCP backpressure and smaller tail.

Result:

- Queue no longer balloons, but the failure still occurs.
- Later gateway logs show `pacing_tick: 59 queued, 8/8 inflight/cwnd`, not thousands queued.
- Still sees tail RTO attempts around attempt 9.

### Fix 5 — iOS reconnect when session-health probe succeeds but flows remain suspect

File:

```text
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Changed `handleProbeSuccess(nonce:)`:

Before:

- If probe response arrived but router still had suspect flows, it reset router runtime state and kept the same gateway session alive.

Problem:

- Resetting the local router reset `next_stream_id` back to 1 while the gateway still had old streams in the same session.
- This caused gateway logs like:

```text
FRAME_OPEN stream_id=1 service=vault
Duplicate FRAME_OPEN for existing stream 1, ignoring
```

Patch:

- After `Session health probe ok but flows still suspect`, now schedule reconnect and return.
- New intended marker:

```text
scheduling reconnect to avoid stream-id reuse
```

Result:

- Reconnect on actual probe timeout is confirmed working.
- However, stale/older log windows still showed the old message without the new suffix. Make sure Xcode deploy actually picked up the newest NE before relying on this marker.

### Fix 6 — fast reconnect on browser replay burst

File:

```text
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Added:

```swift
private static let rwndReplayDeltaReconnect = 8
```

In `maybeRampAdvertisedRwnd(...)`, for active browser bursts:

- If `replayDelta >= 8` and active flows exist:
  - drop rwnd to 4
  - reset router runtime state
  - set `pendingReconnectReason = "browser_replay_fast_reconnect_\(replayDelta)"`
  - schedule reconnect immediately

Expected markers:

```text
Advertised rwnd=4 reason=browser replay fast reconnect replayDelta=...
Router reset runtime state removed=... reason=browser_replay_fast_reconnect_...
Reconnect attempt ... reason=browser_replay_fast_reconnect_...
Reconnect gen=... succeeded
```

Validation:

- Synced to Mac.
- Unsigned Xcode build succeeded.
- Server preflight green.

Result:

- User still reports not working after deploying/testing.
- Need to pull a clean post-fast-reconnect log window and verify whether these new markers appear. If they do not, the phone is not running the latest NE. If they do, fast reconnect still does not save WKWebView.

## Key log evidence

### A successful large initial transfer before stall

Phone logs repeatedly show large delivery before the tail dies:

```text
ZTLP RX summary packets=3284 payload=2418809B acks=3284 replay=1 highSeq=3283
```

Earlier run:

```text
ZTLP RX summary packets=4083 payload=2999050B acks=4083 replay=1 highSeq=4083
```

Interpretation: data path is not globally broken. It can deliver multiple MB. Failure is tail/recovery/state management.

### Replay burst starts after useful RX stops

Phone:

```text
ZTLP RX summary packets=0 payload=0B acks=0 replay=26 highSeq=3283 inflight=0
ZTLP RX summary packets=0 payload=0B acks=0 replay=14 highSeq=3283 inflight=0
ZTLP RX summary packets=0 payload=0B acks=0 replay=8 highSeq=3283 inflight=0
Advertised rwnd=4 reason=browser replay backoff replayDelta=16 cooldown=15s
```

Interpretation: client is seeing duplicate/replay tail packets, not new useful data.

### Gateway stuck in tail RTO, even with shallow queue and RTO batch=2

Gateway:

```text
pacing_tick: 59 queued, 8/8 inflight/cwnd, ssthresh=22 open=false
RTO retransmit data_seq=3276 seq=3287 elapsed=3430ms rto=3383ms attempt=9
RTO retransmit data_seq=3277 seq=3288 elapsed=3430ms rto=3383ms attempt=9
RTO retransmit data_seq=3278 seq=3289 elapsed=3430ms rto=3383ms attempt=9
...
RTO retransmit data_seq=3283 seq=3294 elapsed=3430ms rto=3383ms attempt=9
```

Interpretation:

- Batch limiter works (pairs), but recovery still reaches attempt 9.
- Queue tuning alone is not enough.
- Gateway still has 59 queued behind the stuck tail.

### Session-health reconnect eventually works, but late

Phone:

```text
Session health dead: probe timeout flows=2 streamMaps=2 noUsefulRxFor=9.7s stuckTicks=3
Router reset runtime state removed=2 reason=session_health_probe_timeout
Reconnect attempt 1/10 gen=1 in 0.8s reason=session_health_probe_timeout
Reconnect gen=1 starting reason=session_health_probe_timeout
Reconnect gen=1 succeeded via relay 34.219.64.205:23095; reset health/rwnd baselines
```

Interpretation:

- Reconnect machinery works.
- It likely happens too late for WKWebView resource loads.

### Stale router reset without reconnect caused duplicate stream IDs

Gateway saw:

```text
FRAME_OPEN stream_id=1 service=vault
Duplicate FRAME_OPEN for existing stream 1, ignoring
```

Cause:

- Client reset local packet router without gateway session reconnect.
- Client reused stream IDs in an existing gateway session.

Patch attempted:

- Schedule reconnect when probe succeeds but flows still suspect.

Need to verify if new marker appears in latest deployed phone logs:

```text
scheduling reconnect to avoid stream-id reuse
```

## Why the current approach is producing so many issues

This is not one isolated bug anymore. The architecture couples several independent reliability layers:

1. Browser/WKWebView TCP stack expects normal TCP semantics.
2. iOS Rust packet router emulates TCP state and maps flows to mux streams.
3. Gateway mux streams queue backend HTTP/TCP bytes into a session-level UDP data stream.
4. Gateway congestion control and `peer_rwnd` pace encrypted UDP packets.
5. Client ACK/replay/health code tries to recover when useful RX stops.
6. Router runtime reset and gateway session state must remain synchronized.

Small mismatches cause cascading symptoms:

- Queue too deep -> browser tail delayed.
- Queue too shallow -> frequent backpressure and RTO tail exposure.
- RTO too aggressive -> replay storm.
- RTO too slow -> browser timeout.
- Client router reset without gateway reconnect -> duplicate stream IDs.
- Reconnect after probe timeout -> transport recovers but WKWebView resource has already failed.

This is why each fix improved one symptom but uncovered the next.

## Recommended change of approach

### Option A — preferred for product reliability: HTTP-aware in-app service proxy for WKWebView

For in-app Vaultwarden links, avoid NE packet-router TCP emulation for the browser data path.

Possible design:

- App presents `WKWebView` pointed at a loopback HTTP proxy URL or custom URL scheme.
- In-app proxy maps `vault.ztlp` / VIP service requests to ZTLP mux/stream requests directly.
- Proxy speaks HTTP to WKWebView and streams response bodies with normal backpressure.
- ZTLP transport handles request/response streams explicitly instead of pretending to be a TCP/IP stack for the browser.

Pros:

- Avoids SFSafari DNS issue because it stays in WKWebView/app process.
- Avoids synthetic TCP FIN/ACK/replay/tail problems in NE packet router.
- Easier to apply HTTP caching, range requests, per-resource timeouts, retry at HTTP layer.
- Easier to debug: each asset URL maps to one app-level stream.

Cons:

- Requires integration work to preserve cookies, origin, relative URLs, mixed content, and maybe WebSocket support.
- Need to ensure Vaultwarden works with rewritten origin or loopback origin. May require Host header preservation.

### Option B — transport correctness: real mux stream flow-control and ACKs

Keep WKWebView through NE, but make the gateway/client mux stream transport reliable at stream level.

Needed:

- Per-stream flow-control windows, not just session-level `peer_rwnd`.
- Explicit per-stream delivered/consumed ACKs from iOS router to gateway.
- Gateway should not queue arbitrary backend chunks beyond stream window.
- Gateway CLOSE/FIN must be tied to per-stream delivery completion.
- Recovery should identify missing stream bytes, not retransmit opaque session packets until replay occurs.

Pros:

- Keeps transparent NE/VIP model.
- More generally correct for all TCP-like services.

Cons:

- Larger protocol change.
- More work than HTTP proxy.

### Option C — emergency band-aid only: force lower throughput and earlier reconnect

If continuing current path temporarily:

- Hard cap browser rwnd at 4 from the start.
- Fast reconnect immediately on any replay >= 2 during browser flow.
- Possibly reduce queue_high below 128, e.g. 64/16.
- This may stabilize but will likely make Vaultwarden slow and still fragile.

Not recommended as final direction.

## Suggested next-session first steps

1. Verify the phone is actually running the latest fast-reconnect NE build.
   - Pull logs after a fresh Xcode deploy.
   - Search for:

```text
browser replay fast reconnect
browser_replay_fast_reconnect
scheduling reconnect to avoid stream-id reuse
```

2. If those markers are absent:
   - Xcode deploy did not include latest `PacketTunnelProvider.swift`.
   - Do Clean Build Folder, rebuild/deploy again.

3. If markers are present but WKWebView still fails:
   - Stop rwnd/queue/RTO tuning.
   - Choose architecture direction: HTTP-aware in-app proxy vs stream-level flow control.

4. If choosing HTTP proxy:
   - Audit current WKWebView URL rewriting in:

```text
ios/ZTLP/ZTLP/Extensions/SafariHelper.swift
```

   - Design a local HTTP server/proxy inside app process for `vault.ztlp` service.
   - Preserve Host header as `vault.ztlp` or `vault.techrockstars.ztlp` while connecting over ZTLP.
   - Start with GET asset streaming; add POST/WebSocket later if Vaultwarden requires it.

5. If choosing stream-level flow control:
   - Start with protocol plan before coding.
   - Avoid more local queue threshold tuning.

## Commands for future debugging

### Pull phone log

```bash
ssh stevenprice@10.78.72.234 'rm -f /tmp/ztlp-phone.log; xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log && \
  grep -E "browser replay fast reconnect|browser_replay_fast_reconnect|scheduling reconnect|Reconnect|Advertised rwnd|Session health|ZTLP RX summary|Router stats|Mux summary|Duplicate FRAME_OPEN" /tmp/ztlp-phone.log | tail -300'
```

### Gateway logs around a test

```bash
ssh ubuntu@44.246.33.34 'docker logs --since 10m ztlp-gateway 2>&1 | \
  grep -E "FRAME_OPEN|Duplicate FRAME_OPEN|CLIENT_ACK|RTO retransmit|pacing_tick|Backpressure|STALL|unknown_session" | tail -500'
```

### Preflight before asking Steve to test

```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

Must end with:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

### Unsigned Xcode build on Mac

```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp/ios/ZTLP && xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
  -destination "generic/platform=iOS" -configuration Debug build \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO'
```

## Current recommendation to Steve

We should stop trying to patch this as pure congestion tuning. The repeated fixes show the same pattern: each low-level tweak makes one symptom better but exposes another mismatch in the hybrid TCP-emulation/mux/recovery architecture.

The cleanest product path is likely an app-level HTTP/WKWebView path for service links, at least for Vaultwarden/browser use. Keep the NE path for general tunnel/VIP connectivity, but do not depend on the NE packet router for heavy WKWebView asset delivery until the stream transport is redesigned.
