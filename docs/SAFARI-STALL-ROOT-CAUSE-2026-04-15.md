# Safari Stall Root Cause — 2026-04-15

## Summary

We finally isolated the current failure mode.

This is no longer primarily:
- NS failure
- host networking / backend econnrefused
- immediate stream open/close race
- missing relay records
- total handshake failure

The current root cause is:

**gateway-side congestion / recovery collapse under Safari page-load fanout**

Safari partially loads HTML/CSS/images, then the gateway enters a saturated recovery state,
ACK progress stops, the send queue never drains, and the gateway tears the session down
after the 30-second stall timeout. The iPhone VPN then drops.

---

## What the phone/bootstrap logs show

Latest relevant records:
- `BenchmarkResult 135` — `score=5/8`, manual benchmark-page log send
- `BenchmarkResult 136` — `score=0/1`, manual benchmark-page log send

Key observations from `device_logs`:
- `OpenStream = 15`
- `CloseStream = 9`
- `SendData = 12`
- `GW->NE mux DATA = 2663`
- `VPN status changed = 14`
- `NS returned no relay records = 3`
- `Using default service map = 3`

Most important tail sequence:
- lots of `ZTLP RX data seq=...`
- lots of `GW->NE mux DATA stream=1 bytes=...`
- lots of `ZTLP ACK sent seq=... inflight=0`
- data reaches at least `seq=1609`
- then:
  - `VPN status changed: 5`
  - `VPN status changed: 1`

Interpretation:
- the phone is definitely receiving a large amount of page data
- this is not a connect-time failure
- the stall happens after substantial successful transfer

---

## What the gateway logs show

Relevant gateway time window: `2026-04-15 07:18:15+`

### Streams really do connect

Observed:
- `FRAME_OPEN stream_id=1 service=vault`
- `Stream 1 connected, buffered_chunks=0 buffered_bytes=0`
- `FRAME_OPEN stream_id=2 service=vault`
- `Stream 2 connected, buffered_chunks=1 buffered_bytes=328`
- `FRAME_OPEN stream_id=3 service=vault`
- `Stream 3 connected, buffered_chunks=1 buffered_bytes=322`

Interpretation:
- this is **not** the earlier `client_close_before_connect` race
- streams 1/2/3 are actually opening and staying connected
- backend connect succeeds

### The actual collapse

Observed repeated for a long period:

```text
pacing_tick: 2528 queued, 32/22 inflight/cwnd, ssthresh=22 open=false
```

Then the final tear-down log:

```text
STALL: no ACK advance for 30s inflight=32 last_acked=1610 recv_base=1363 dup_ack=0 recovery=true queue=2528 backends_paused=true streams=[1:vault:connected:buf=0:chunks=0,2:vault:connected:buf=0:chunks=0,3:vault:connected:buf=0:chunks=0] — tearing down
```

Interpretation:
- `queue=2528` = massive outbound backlog
- `inflight=32`, `cwnd=22` = inflight exceeds available congestion window
- `open=false` = send window closed
- `backends_paused=true` = gateway already applied backpressure to backends
- despite that, queue is still enormous and not draining
- `last_acked=1610` but then no further ACK advance occurs for 30s
- session remains in `recovery=true`
- gateway finally kills the session due to stall timeout

---

## Definitive conclusion

The current Safari failure is:

**gateway congestion collapse during sustained page load**

Specifically:
1. Safari opens multiple streams and starts receiving real payloads
2. Gateway builds a very large outbound send queue
3. Session enters recovery with `cwnd` reduced
4. Inflight stays pinned while queue remains huge
5. Queue does not drain even with backends paused
6. ACK advancement stops
7. After 30s of no ACK advance, gateway tears down the session
8. iPhone VPN disconnects

This exactly matches the user-visible symptom:
- partial page load succeeds
- some assets render
- then everything stalls
- VPN drops

---

## What this is NOT anymore

The current bug is NOT primarily:
- NS resolution
- relay selection fallback
- backend unreachable (`econnrefused`)
- host vs bridge networking
- immediate `FRAME_OPEN -> FRAME_CLOSE` connect race
- missing logs on bootstrap

Those were earlier problems and some were real, but they are not the main blocker now.

---

## Current instrumentation added

Gateway was patched and deployed with deeper diagnostics:

### Added stall diagnostics
- queue length
- `backends_paused`
- all live streams at stall time
- per-stream service/state/buffered bytes/buffered chunks

### Added stream close reason diagnostics
`FRAME_CLOSE` now distinguishes:
- `client_close_before_connect`
- `client_close_after_connect`
- `client_close_stream`
- `client_close_unknown_stream`

### Added async connect race diagnostics
If connect result arrives after the stream is already gone, gateway now logs:
- `reason=client_close_before_connect`
- queue length
- total stream count

### Deployment
- image: `ztlp-gateway:stream-debug`
- commit: `28f7baf gateway: add stream/stall diagnostics for Safari crash isolation`

---

## Best next fix direction

The next patch should target gateway congestion / recovery behavior, not basic connectivity.

Most likely areas to change:

1. **Stricter backpressure before queue reaches thousands**
   - queue is still allowed to balloon to `2528`
   - current backpressure is not enough once the session is saturated

2. **Mobile-specific concurrency reduction**
   - current connected streams at failure: 3 vault streams, but Safari traffic likely fans out quickly
   - may need lower effective mux concurrency for mobile path

3. **Recovery / inflight clamping**
   - session sits at `32/22 inflight/cwnd`
   - inflight remaining above cwnd during recovery appears to prevent drain
   - investigate recovery inflation / retransmit behavior

4. **Earlier queue admission control**
   - queue should probably stop growing well before 2500 packets
   - may need more aggressive stream gating or data gating while in recovery

5. **Potential mobile CC tuning**
   - current profile seen in logs:
     - `class=mobile`
     - `cwnd=10.0`
     - `max=32`
     - `ssthresh=64`
     - `pacing=4ms`
     - `burst=3`
   - despite this, session still saturates under Safari
   - tuning alone may not be sufficient, but recovery logic definitely needs attention

---

## Recommended next session starting point

Start from:
- `gateway/lib/ztlp_gateway/session.ex`

Focus on:
- `pacing_tick`
- retransmit / recovery logic
- stall timeout path
- send queue growth and backpressure
- stream admission while queue is already saturated

Look specifically for why:
- `queue=2528`
- `inflight=32`
- `cwnd=22`
- `backends_paused=true`
- yet queue does not drain and ACK advance stops

---

## Suggested immediate plan for next session

1. Inspect recovery / pacing code paths in `session.ex`
2. Add queue high-water / drain-rate instrumentation if needed
3. Patch to clamp recovery / inflight under mobile load
4. Patch to prevent queue ballooning once `backends_paused=true`
5. Redeploy gateway
6. Re-run iPhone Safari test
7. Re-check bootstrap + gateway logs

---

## Quick evidence snippets

### Bootstrap / phone side
```text
ZTLP RX data seq=1609 payload=1132
GW->NE mux DATA stream=1 bytes=1127
ZTLP ACK sent seq=1609 bytes=71 inflight=0
...
VPN status changed: 5
VPN status changed: 1
```

### Gateway side
```text
pacing_tick: 2528 queued, 32/22 inflight/cwnd, ssthresh=22 open=false
```

```text
STALL: no ACK advance for 30s inflight=32 last_acked=1610 recv_base=1363 dup_ack=0 recovery=true queue=2528 backends_paused=true streams=[1:vault:connected:buf=0:chunks=0,2:vault:connected:buf=0:chunks=0,3:vault:connected:buf=0:chunks=0] — tearing down
```

### Stream state proves this is not connect-race anymore
```text
FRAME_OPEN stream_id=1 service=vault
Stream 1 connected, buffered_chunks=0 buffered_bytes=0
FRAME_OPEN stream_id=2 service=vault
Stream 2 connected, buffered_chunks=1 buffered_bytes=328
FRAME_OPEN stream_id=3 service=vault
Stream 3 connected, buffered_chunks=1 buffered_bytes=322
```

---

## Final one-line diagnosis

Safari is stalling because the gateway enters a mobile-path congestion/recovery deadlock under real page-load fanout, its outbound queue grows into the thousands, ACK progress stops, and the gateway kills the session after the 30-second stall timeout.
