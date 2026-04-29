# ZTLP iOS Vaultwarden Watchdog Handoff — 2026-04-29

## Current main top

```text
05ee776 ios: gate browser bursts at receive window floor
e9bf4cf docs: add iOS performance recovery handoff
625b930 ios: cap adaptive receive window at five
c8afd73 ios: reset session health baselines after reconnect
172da8d ios: add conservative adaptive receive window
```

## Executive summary

The last round proved two important things:

1. The conservative receive-window/browser-burst policy works.
2. Nebula-style session-health recovery works when the Network Extension stays alive long enough.

But Vaultwarden/OpenVault still can halt because the iOS Network Extension / `tunnelQueue` can go silent before the health detector gets another tick.

The next best fix is **not** another rwnd increase/decrease. The next target is to make the session-health watchdog independent from the hot packet/router queue.

## Latest committed change

Commit:

```text
05ee776 ios: gate browser bursts at receive window floor
```

Files changed:

```text
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

What it added:

- Browser-burst rwnd gate:
  - if `flows >= 2` or `streamMaps >= 2`, force `rwnd=4`
  - this prevents Vaultwarden/WKWebView multi-stream fan-out from ramping to `rwnd=5`
- Faster stuck-flow health path:
  - if active flow has `oldest_ms >= 3000` and highSeq is stuck for 2 health ticks, classify earlier
  - fast stuck probe timeout uses 3s instead of normal 5s

Validation before phone test:

```text
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml packet_router --lib
36 passed

xcodebuild Debug generic iOS build on Steve's Mac
BUILD SUCCEEDED

/home/trs/ztlp/scripts/ztlp-server-preflight.sh
PRECHECK GREEN
```

## Latest phone log pull

Pulled via:

```bash
ssh stevenprice@10.78.72.234 'rm -f /tmp/ztlp-phone.log; xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log'
```

## What worked

### Fresh benchmark passed

```text
[2026-04-29T06:09:56.635Z] [INFO] [Benchmark] Benchmark run started category=Tunnel
[2026-04-29T06:09:57.608Z] [INFO] [BenchUpload] Benchmark upload complete: HTTP 201 score=8/8 ... benchmark_id=217
```

### Browser-burst gate fired exactly as designed

During Vaultwarden/OpenVault browser traffic:

```text
[2026-04-29T06:10:02.095Z] Mux summary gwData=39/26343B open=7 close=8 send=2/531B
[2026-04-29T06:10:03.130Z] Mux summary gwData=64/45947B open=2 close=0 send=3/997B
[2026-04-29T06:10:05.880Z] Advertised rwnd=4 reason=browser burst flows=3 streamMaps=3 healthyTicks=0
[2026-04-29T06:10:05.880Z] Health eval: flows=3 outbound=0 streamMaps=3 sendBuf=0 oldestMs=3079 rwnd=4 highSeq=381 ...
```

This is the expected new behavior. There was no `rwnd=5` ramp during multi-flow browser load.

### Session-health recovery succeeded once

The first poisoned browser run progressed, then became replay/no-useful-RX stuck:

```text
[2026-04-29T06:10:23.962Z] ZTLP RX summary packets=0 payload=0B acks=0 replay=12 highSeq=1861 inflight=0
[2026-04-29T06:10:25.737Z] ZTLP RX summary packets=0 payload=0B acks=0 replay=8 highSeq=1861 inflight=0
[2026-04-29T06:10:27.880Z] Health eval: flows=3 outbound=0 streamMaps=3 sendBuf=0 oldestMs=25079 rwnd=4 highSeq=1861 stuckTicks=1 usefulRxAge=5.2s ...
[2026-04-29T06:10:27.880Z] Session health candidate: flows=3 outbound=0 streamMaps=3 highSeq=1861 noUsefulRxFor=5.2s replayDelta=4 ...
[2026-04-29T06:10:27.881Z] Session health suspect: reason=no_useful_rx_5.2s ... sending probe nonce=1777443027880
[2026-04-29T06:10:31.880Z] Session health dead: probe timeout flows=3 streamMaps=3 noUsefulRxFor=9.2s stuckTicks=3 ...
[2026-04-29T06:10:31.880Z] Router reset runtime state removed=3 reason=session_health_probe_timeout
[2026-04-29T06:10:33.046Z] Reconnect gen=1 starting reason=session_health_probe_timeout
[2026-04-29T06:10:33.109Z] Reconnect gen=1 succeeded via relay 34.219.64.205:23095; reset health/rwnd baselines
```

Post-reconnect benchmark passed:

```text
[2026-04-29T06:10:35.126Z] Benchmark run started category=Tunnel
[2026-04-29T06:10:35.693Z] Benchmark upload complete: HTTP 201 score=8/8 ... benchmark_id=218
```

Manual log dump also uploaded as 8/8:

```text
[2026-04-29T06:10:48.513Z] Benchmark upload complete: HTTP 201 score=8/8 ... benchmark_id=219
```

Conclusion: the recovery ladder is real and working:

```text
browser burst -> rwnd stays 4 -> flow poisons -> health candidate -> probe -> timeout -> router reset -> reconnect -> benchmark recovers
```

## What still failed

After the successful recovery, another Vaultwarden/OpenVault burst started around 06:11.

Phone log:

```text
[2026-04-29T06:11:00.756Z] Mux summary gwData=39/26343B open=7 close=9 send=2/531B
[2026-04-29T06:11:01.774Z] Mux summary gwData=90/65609B open=1 close=0 send=2/646B
[2026-04-29T06:11:03.880Z] Advertised rwnd=4 reason=browser burst flows=2 streamMaps=2 healthyTicks=0
[2026-04-29T06:11:03.880Z] Health eval: flows=2 outbound=0 streamMaps=2 sendBuf=0 oldestMs=3036 rwnd=4 highSeq=342 stuckTicks=0 usefulRxAge=0.0s ...
[2026-04-29T06:11:05.880Z] Advertised rwnd=4 reason=pressure outbound=0 sendBuf=0 oldestMs=5036 replayDelta=0 fullFlushes=0 healthyTicks=0
[2026-04-29T06:11:07.881Z] Advertised rwnd=4 reason=browser burst flows=2 streamMaps=2 healthyTicks=0
[2026-04-29T06:11:07.881Z] Health eval: flows=2 outbound=0 streamMaps=2 sendBuf=0 oldestMs=898 rwnd=4 highSeq=754 stuckTicks=0 usefulRxAge=0.0s ...
[2026-04-29T06:11:07.896Z] Mux summary gwData=108/78840B open=0 close=0 send=0/0B
[2026-04-29T06:11:13.578Z] VPN status changed: 5
[2026-04-29T06:11:13.925Z] VPN status changed: 1
```

Then Steve/app manually started VPN again:

```text
[2026-04-29T06:11:21.250Z] Starting VPN tunnel...
[2026-04-29T06:11:22.106Z] Session health manager enabled interval=2.0s ...
```

Key observation:

- At 06:11:07, the health detector saw a healthy active flow:
  - `flows=2`
  - `rwnd=4`
  - `highSeq=754`
  - `stuckTicks=0`
  - `usefulRxAge=0.0s`
- The next health tick should have appeared around 06:11:09 or 06:11:11.
- No further health tick appears before VPN status drops at 06:11:13.

That means the watchdog did not get a chance to classify/probe/reconnect. The NE or its hot queue went silent first.

## Gateway observations

Gateway logs during the 06:11 run show the browser gate was honored server-side:

```text
CLIENT_ACK data_seq=N rwnd=4 ...
pacing_tick: ~400 queued, 4/4 inflight/cwnd, open=false
```

Important interpretation:

- Gateway is not exploding to 32/64/512 inflight anymore.
- Gateway is honoring `rwnd=4`.
- ACKs continue advancing during the observed window.
- This does not look like the previous gateway send_queue overload class.

The remaining failure boundary is on iOS/NE lifecycle or `tunnelQueue` starvation, not gateway congestion.

## Current conclusion

The latest architecture is partially successful:

```text
rwnd=4 browser gate: works
rwnd=5 avoided during fan-out: works
health recovery after poisoned flow: works when queue/timer stays alive
post-recovery benchmark: works
Vaultwarden full load: still not stable
```

The remaining bug is likely:

```text
Vaultwarden sustained browser traffic monopolizes or stalls PacketTunnelProvider.tunnelQueue,
so the health DispatchSourceTimer (currently also on tunnelQueue) cannot fire before iOS flips VPN status.
```

This is consistent with:

- health logs stop while browser mux summaries were hot
- no health candidate/probe before status flip in the second failure
- iOS status flips 5 -> 1 without the health manager getting a final tick
- the previous race with shared send buffers is already fixed, so the current silence points more at queue starvation/lifecycle than frame corruption

## Next recommended fix

### 1. Move session-health timer to a dedicated queue

Current code:

```swift
let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
```

Recommended change:

```swift
private let healthQueue = DispatchQueue(label: "com.ztlp.tunnel.health", qos: .utility)
```

Use:

```swift
let timer = DispatchSource.makeTimerSource(queue: healthQueue)
```

Design:

- `healthQueue` owns the timer cadence and late-tick detection.
- The timer should not do heavy router/utun work directly.
- It can dispatch a small evaluation block to `tunnelQueue`, but it must also detect if `tunnelQueue` is late/unresponsive.

### 2. Add health watchdog late-tick instrumentation

Track expected cadence:

```swift
private var lastHealthWatchdogFireAt: Date = .distantPast
private static let healthLateThreshold: TimeInterval = 4.0
```

On healthQueue tick:

```swift
let now = Date()
let delay = now.timeIntervalSince(lastHealthWatchdogFireAt)
if lastHealthWatchdogFireAt != .distantPast && delay > Self.healthLateThreshold {
    logger.warn("Health watchdog late delay=\(String(format: "%.1f", delay))s", source: "Tunnel")
}
lastHealthWatchdogFireAt = now
```

Then dispatch evaluation to `tunnelQueue` with another timing marker:

```swift
let scheduledAt = Date()
tunnelQueue.async { [weak self] in
    let queueDelay = Date().timeIntervalSince(scheduledAt)
    if queueDelay > Self.healthLateThreshold {
        self?.logger.warn("Health eval delayed on tunnelQueue delay=\(String(format: "%.1f", queueDelay))s", source: "Tunnel")
    }
    self?.evaluateSessionHealth()
}
```

This will prove or disprove tunnelQueue starvation.

### 3. If tunnelQueue delay is confirmed, add an emergency watchdog path

If `healthQueue` fires but `tunnelQueue` cannot run for >4-6s while active flows were recently seen, schedule a defensive reconnect/reset from a safe path.

Be careful:

- Do not mutate `packetRouter` directly off `tunnelQueue` unless router access is made thread-safe.
- The emergency path may need to set a flag and call `tunnelConnection.cancel()` / reconnect coordination in a controlled way.
- Avoid adding another data race while fixing queue starvation.

Safer first pass:

- Add instrumentation only.
- Reduce packet flush batch size to lower tunnelQueue monopolization.

### 4. Consider reducing hot-path batch sizes during browser mode

Current:

```swift
private static let maxOutboundPacketsPerFlush: Int = 64
```

If watchdog delay appears, try:

```swift
private static let maxOutboundPacketsPerFlush: Int = 32
```

Or dynamic:

```swift
let browserMode = lastRouterFlows >= 2 || lastRouterStreamMappings >= 2
let flushLimit = browserMode ? 32 : Self.maxOutboundPacketsPerFlush
flushOutboundPackets(maxPackets: flushLimit)
```

Goal: let `tunnelQueue` yield often enough for health/reconnect control-plane work.

## What not to do next

Do NOT raise `rwnd` above 5.

Do NOT remove the browser-burst gate.

Do NOT chase gateway congestion first. Logs show the gateway is respecting `rwnd=4` and ACKs are advancing during the observed window.

Do NOT implement blind HTTP-timeout VPN restart. The health architecture is right; the watchdog just needs to survive hot packet flow.

Do NOT mutate router state from a new health queue without queue-safety. PacketRouter FFI is currently assumed to be used on the provider queue.

## Suggested next-session implementation plan

1. Edit `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`:
   - add `healthQueue`
   - move `DispatchSourceTimer` to `healthQueue`
   - add `Health watchdog late` log
   - add `Health eval delayed on tunnelQueue` log

2. Keep `evaluateSessionHealth()` running on `tunnelQueue` for now.

3. Add dynamic browser-mode flush cap:
   - if `lastRouterFlows >= 2 || lastRouterStreamMappings >= 2`, flush max 32 packets per pass
   - otherwise keep current 64

4. Build/check:

```bash
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml packet_router --lib
ssh stevenprice@10.78.72.234 'cd ~/ztlp/ios/ZTLP && xcodebuild -project ZTLP.xcodeproj \
  -scheme ZTLP -destination "generic/platform=iOS" -configuration Debug build \
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO'
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

5. Phone test:

```text
Fresh benchmark -> Vaultwarden/OpenVault -> wait without manual restart if possible -> post-burst benchmark -> Send Logs
```

6. Expected new diagnostic markers:

```text
Health watchdog late delay=...
Health eval delayed on tunnelQueue delay=...
Advertised rwnd=4 reason=browser burst flows=... streamMaps=...
```

If no watchdog-late markers appear but VPN still flips, then the extension is likely being killed/suspended by iOS lifecycle before any queue can run, and we need syslog/idevicesyslog for NetworkExtension/IPC detach evidence.

## Useful commands for next session

Pull phone app-group log:

```bash
ssh stevenprice@10.78.72.234 'rm -f /tmp/ztlp-phone.log; xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log && tail -n 220 /tmp/ztlp-phone.log'
```

Filter phone markers:

```bash
ssh stevenprice@10.78.72.234 "grep -E 'Benchmark|Advertised rwnd|browser burst|fast_stuck|Session health|Router reset|Reconnect gen|Health eval|Health watchdog|eval delayed|VPN status|HTTP benchmark GET failed|ZTLP RX summary|Mux summary' /tmp/ztlp-phone.log | tail -n 260"
```

Gateway recent logs:

```bash
ssh ubuntu@44.246.33.34 "docker logs --since '10m' ztlp-gateway 2>&1 | grep -E 'SESSION_PING|SESSION_PONG|CLIENT_ACK|STALL|RTO retransmit|pacing_tick|FRAME_OPEN|FRAME_CLOSE|Stream .*backend|send_queue|Backpressure|Rejected packet|Replacing session' | tail -n 260"
```

Preflight before asking Steve to test:

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Must end:

```text
PRECHECK GREEN
```

## Current known stable facts

- `rwnd=4` is the safe browser-burst floor.
- `rwnd=5` is okay only for simple/single-flow traffic.
- `rwnd>=6` is still not justified.
- Browser burst starts around `open=7 close=8/9` and then settles to `flows=2-3`.
- NE memory around 20-21MB is expected and not by itself the failure.
- Gateway `rwnd=4` with `4/4 inflight/cwnd` is expected in browser mode.
- A replay-only/no-useful-RX stuck flow can recover through probe timeout + router reset + reconnect.
- A harder failure remains where the NE/tunnelQueue goes silent before the health timer runs.

## Status at handoff

Code pushed through:

```text
05ee776 ios: gate browser bursts at receive window floor
```

New handoff file:

```text
/home/trs/ztlp/ZTLP-IOS-VAULTWARDEN-WATCHDOG-HANDOFF-2026-04-29.md
```
