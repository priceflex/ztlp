# Vaultwarden WKWebView Stall — rwnd=8 / RTO Combined Fix Handoff — 2026-05-02

## TL;DR

Vaultwarden itself is healthy and the iOS app is already using in-app `WKWebView` with VIP-IP rewriting, not Safari/SFSafariViewController. The current hang is in the ZTLP iOS Rust-fd browser data path during large Vaultwarden asset delivery.

The next session should implement a **combined fix**, not simply increase `rwnd` again:

1. Keep browser-burst `rwnd=8` only while the transfer is clean.
2. Drop immediately to `rwnd=4` on any replay during active browser flows, with a cooldown so it does not bounce back to 8 too quickly.
3. Audit/fix gateway mobile/browser RTO behavior: the failing session retransmitted first tail packets at ~156ms, which is too aggressive for iOS relay browser traffic.
4. Consider reducing mobile/browser RTO retransmit batch size from 8 to 1–2 for tail recovery.

Do **not** jump to `rwnd=16` yet. The rwnd=8 test improved bulk transfer but ended in a bigger replay/RTO storm.

## Current repo state

Latest relevant commits on `main`:

- `0270716 ios: test rwnd eight for Rust fd browser bursts`
- `4841a29 ios: defer router FIN until response tail drains`
- `7303b90 gateway: shallow browser response queue for vaultwarden`

Mac build host `~/ztlp` was pulled to `0270716` and an unsigned Xcode build succeeded.

## What was verified

### Server/backend

Local server-side preflight passed:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Vaultwarden backend on the gateway is healthy:

```text
curl http://127.0.0.1:8080/       -> HTTP 200, Vaultwarden Web HTML
curl http://127.0.0.1:8080/alive  -> HTTP 200
vaultwarden container healthy, 127.0.0.1:8080->80/tcp
```

A browser on the agent machine loaded Vaultwarden through an SSH tunnel:

```text
127.0.0.1:18080 -> gateway 127.0.0.1:8080
Page loaded fully: Vaultwarden Web login form, email field, Continue button, version 2026.1.1.
```

Large assets observed from direct browser load include:

- `app/main...js` around 3.75 MB
- wasm around 5.13 MB
- locale/messages around 394 KB

So Vaultwarden is not the failing component.

### iOS browser implementation

The iOS app already uses `WKWebView`, not Safari:

- `ios/ZTLP/ZTLP/Extensions/SafariHelper.swift`
- `InAppBrowserView`
- `BrowserViewController: UIViewController, WKNavigationDelegate`
- `WKWebView(frame:configuration:)`

Despite the method name `.safariSheet(url:)`, this presents the in-app WKWebView.

The helper rewrites `.ztlp` names to VIP IPs:

```swift
"vault.ztlp" -> "10.122.0.4"
"vault.techrockstars.ztlp" -> "10.122.0.4"
```

and forces HTTP to avoid cert mismatch with IP literals.

## The rwnd=4 baseline failure

With conservative `rwnd=4`, the page starts loading but hangs. The key shape from previous phone logs:

- lots of real Vaultwarden data arrives
- `Mux summary gwData≈100 packets / 70KB` repeatedly
- `ZTLP RX summary packets=1823 payload=1336559B highSeq=1826` in one run
- then flows remain active but useful RX stops
- session health eventually reconnects, too late to save WKWebView

A later run before rwnd=8 showed stall around highSeq ~514 for a new Vaultwarden load.

Interpretation: `rwnd=4` is safe but likely too small. It builds a long gateway-side tail behind big Vaultwarden JS/WASM assets.

## The rwnd=8 experiment

Commit `0270716` changed:

- `PacketTunnelProvider.swift`
  - `rwndAdaptiveMax: 5 -> 8`
  - added `rwndBrowserBurstTarget = 8`
  - browser bursts (`flows >= 2` or `streamMaps >= 2`) now advertise 8 instead of forcing floor 4
- `ZTLPTunnelConnection.swift`
  - `setAdvertisedReceiveWindow` clamp changed from 4..5 to 4..8
  - ACK sendWindow clamp changed from 5 to 8

Expected/observed phone marker:

```text
Advertised rwnd=8 reason=browser burst target flows=2 streamMaps=2
```

Expected/observed gateway marker:

```text
CLIENT_ACK ... rwnd=8
```

### What improved

The rwnd=8 run clearly improved bulk transfer:

Phone log:

```text
[23:50:20.822] Advertised rwnd=8 reason=browser burst target flows=2 streamMaps=2
[23:50:22.497] ZTLP RX summary packets=3738 payload=2736232B acks=3738 replay=1 highSeq=3737
[23:50:24.592] ZTLP RX summary packets=230 payload=169050B acks=230 replay=7 highSeq=3967
[23:50:25.756] ZTLP RX summary packets=26 payload=19110B acks=26 replay=30 highSeq=3993
```

Compared to rwnd=4, this got much farther into the Vaultwarden asset load:

- highSeq reached 3993
- about 2.7 MB delivered in the big summary
- mux summaries increased to around 195–206 packets/sec in the clean part

### What still failed

After the clean bulk phase, replay/RTO pressure exploded:

Phone log:

```text
[23:50:26.822] Advertised rwnd=4 reason=pressure outbound=0 sendBuf=0 oldestMs=1871 replayDelta=31 fullFlushes=0
[23:50:26.823] Health eval: flows=2 outbound=0 streamMaps=2 sendBuf=0 oldestMs=1871 rwnd=4 highSeq=3993 usefulRxAge=1.8s replayDelta=31
[23:50:30.823] Session health candidate: flows=2 ... highSeq=3993 noUsefulRxFor=5.8s replayDelta=8
[23:50:30.823] Session health suspect ... sending probe nonce=1777765830822
[23:50:34.822] Session health dead: probe timeout flows=2 streamMaps=2 noUsefulRxFor=9.8s stuckTicks=3
```

During the failing interval, router pressure was not local buffering:

```text
flows=2 outbound=0 stream_to_flow=2 send_buf_bytes=0 send_buf_flows=0 oldest_ms rising
```

So the previous router send_buf tail fix is not the active issue in this run.

Gateway log showed:

```text
CLIENT_ACK data_seq=3985 rwnd=8 last_acked=3984 inflight=8 recovery=false
RTO retransmit data_seq=3986..3993 attempt=1..8
pacing_tick: 88 queued, 8/8 inflight/cwnd, ssthresh=8 open=false
```

The first retransmits were very aggressive:

```text
RTO retransmit data_seq=3990 seq=4046 elapsed=181ms rto=156ms attempt=1
RTO retransmit data_seq=3986..3992 elapsed=255ms rto=234ms attempt=2
... then 351ms, 527ms, 790ms, 1185ms, 1777ms, 2665ms
```

Interpretation: `rwnd=8` improves the happy path but creates/permits a larger replay/RTO storm at the tail. Raising to 16 is likely to make the tail storm worse.

## Current best root-cause hypothesis

The persistent Vaultwarden spinner is not just `rwnd` size. It is a tail-loss / recovery behavior problem:

1. Gateway sends a large Vaultwarden JS/WASM asset.
2. iPhone receives and ACKs most of it.
3. A small tail gap/loss occurs.
4. Gateway retransmits the tail too aggressively.
5. iPhone sees replay/duplicates; `highSeq` stops advancing.
6. Browser resource never completes.
7. Session health reconnects too late to rescue that WKWebView transaction.

`rwnd=8` helps step 1–2 but worsens step 4 if loss/replay appears.

## Recommended combined fix

### Part A — Swift/iOS adaptive rwnd backoff

Keep `rwnd=8` as the browser burst target, but only while clean.

Implement:

- `rwnd=8` for browser bursts with no pressure.
- Drop to `rwnd=4` immediately on replay during active browser flows.
- Add a cooldown so it stays at 4 for 10–15 seconds after replay pressure.
- Do not ramp/bounce back to 8 while cooldown active.

Suggested state in `PacketTunnelProvider.swift`:

```swift
private static let rwndReplayDeltaBad = 1   // or 2; currently 8
private static let rwndPressureCooldown: TimeInterval = 15.0
private var rwndPressureUntil: Date = .distantPast
```

In health/rwnd evaluation:

```swift
let browserBurst = stats.flows >= Self.rwndBrowserBurstFlowThreshold ||
    stats.streamToFlow >= Self.rwndBrowserBurstFlowThreshold

if browserBurst && replayDelta > 0 {
    rwndPressureUntil = Date().addingTimeInterval(Self.rwndPressureCooldown)
    reduceAdvertisedRwnd(reason: "browser replay backoff replayDelta=\(replayDelta)")
    return
}

if Date() < rwndPressureUntil {
    reduceAdvertisedRwnd(reason: "pressure cooldown until=...")
    return
}

if browserBurst {
    updateAdvertisedRwnd(Self.rwndBrowserBurstTarget, reason: "browser burst target ...")
    return
}
```

Potential alternative: instead of `replayDelta > 0`, use `replayDelta >= 2` to avoid overreacting to one harmless duplicate. But the rwnd=8 failure had replayDelta 31, so either threshold catches it. Start with 1 or 2.

Expected success signal:

- during clean transfer, gateway sees `rwnd=8`
- at first replay, phone logs `browser replay backoff` and ACKs switch to `rwnd=4`
- replay storm does not escalate to attempts 8
- highSeq eventually advances through the tail
- no `session_health_probe_timeout`

### Part B — Gateway mobile/browser RTO audit/fix

The gateway first RTO around 156ms looks too low for iOS relay browser traffic.

Need to inspect `gateway/lib/ztlp_gateway/session.ex`:

- mobile profile selection for iOS client profile
- `mobile + unknown` branch
- `per_packet_rto(...)`
- whether EWMA can lower RTO below a safe mobile/browser floor
- whether current session is actually using mobile-safe min RTO

Search/inspect:

```bash
grep -n "mobile_initial_rto\|mobile_min_rto\|select_cc_profile\|per_packet_rto\|min_rto" gateway/lib/ztlp_gateway/session.ex
```

What to verify in logs:

- ClientProfile / CC profile lines should show mobile/unknown and safe RTO values.
- If actual RTO still goes to ~156ms, the min clamp is not high enough or not applied to per-packet RTO after EWMA/backoff.

Likely fix options:

1. For mobile/unknown/browser sessions, set a higher `min_rto_ms`, e.g. 500ms.
2. Ensure `per_packet_rto(state.rto_ms, rc)` respects `state.min_rto_ms`.
3. Possibly use a separate `tail_min_rto_ms` or mobile floor when `peer_rwnd <= 8`.

Expected success signal:

- first RTO does not fire at ~156ms
- fewer replay rejects on phone
- tail has more time to ACK before retransmit duplicates arrive

### Part C — Gateway mobile/browser retransmit batch reduction

Current `@max_rto_retransmit_per_tick` is 8. With `rwnd=8`, that can retransmit the whole in-flight tail every RTO tick.

For mobile/browser, consider effective retransmit batch of 1–2, especially when:

- `peer_rwnd <= 8`
- client profile is mobile/unknown or mobile/cellular
- in recovery

The strategy should prioritize the first missing cumulative seq (`last_acked + 1`) rather than repeatedly blasting the whole tail.

Expected success signal:

- gateway logs show retransmits focused on first missing data_seq, not 3986..3993 every time
- phone replayDelta stays low
- ACKs recover instead of going replay-only

## Commands and access reminders

### Pull phone app-group log

```bash
ssh stevenprice@10.78.72.234 'rm -f /tmp/ztlp-phone.log; xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log && \
  grep -E "Advertised rwnd|Health eval|Session health|ZTLP RX summary|Mux summary|Router stats|Benchmark run|BenchUpload" /tmp/ztlp-phone.log | tail -180'
```

### Gateway logs for a window

```bash
ssh ubuntu@44.246.33.34 'docker logs --since "2026-05-02T23:50:18Z" --until "2026-05-02T23:50:36Z" ztlp-gateway 2>&1 | \
  grep -E "FRAME_OPEN|CLIENT_ACK|SESSION_PING|SESSION_PONG|RTO retransmit|pacing_tick|STALL|Backpressure|Stream [0-9]+|unknown_session" | tail -260'
```

### Server preflight before asking Steve to test

```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

Must end with `PRECHECK GREEN`.

### Mac build host

```bash
ssh stevenprice@10.78.72.234
cd ~/ztlp
```

For Swift-only changes, Rust lib rebuild is not needed. Still run an unsigned Xcode build check:

```bash
cd ~/ztlp/ios/ZTLP
xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
  -destination "generic/platform=iOS" -configuration Debug build \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
```

Steve must do Xcode GUI deploy because codesign/device deploy from SSH fails.

## Important caution

Do not redeploy/restart gateway without telling Steve first. Gateway restarts kill his active iOS sessions and can crash/hang benchmark/browser tests.

## Suggested first task in next session

Start with Swift-only Part A because it does not require gateway restart:

1. Patch `PacketTunnelProvider.swift` with replay-triggered rwnd cooldown.
2. Build on Mac unsigned.
3. Commit/push.
4. Ask Steve to Xcode clean/build/deploy and test Vaultwarden.
5. Pull logs and check whether the tail still RTO storms.

If it still fails, move to gateway RTO / retransmit batch fix, but warn Steve before restarting gateway.
