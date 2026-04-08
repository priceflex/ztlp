# ZTLP Gateway Congestion Control Tuning Log

Do NOT change parameters without documenting here first.
Each change records: what, why, the data that motivated it, and results.

---

## Baseline: Pre-tuning state (2026-04-07)

### Current Parameters (session.ex)
```
@initial_cwnd         32.0     # packets
@max_cwnd             512      # packets (512 × 1140 = 583KB)
@min_cwnd             10       # packets
@initial_ssthresh     512      # packets
@min_ssthresh         48       # ~55KB floor
@loss_beta            0.75     # reduce by 25% on loss (gentler than TCP 0.5)
@burst_size           4        # packets per pacing tick
@pacing_interval_ms   2        # ms between bursts
@stall_timeout_ms     15_000   # 15s stall = teardown
@initial_rto_ms       300      
@min_rto_ms           100
@max_rto_ms           30_000
@max_retransmits      20
@max_rto_retransmit_per_tick  8
@queue_high           256
@queue_low            64
```

### ACK parameters (ffi.rs on iOS)
```
ACK_COALESCE_COUNT    = 8      # ACK every 8 packets steady-state
ACK_STARTUP_EVERY     = 2      # ACK every 2 packets during first 64
ACK_STARTUP_THRESHOLD = 64     # first 64 = startup
ACK_FLUSH_TIMEOUT_MS  = 10     # flush unacked data after 10ms
REACK_MIN_INTERVAL_MS = 20     # throttle re-ACKs for duplicates
NACK_GAP_THRESHOLD_MS = 50     # wait before NACKing gaps
NACK_MIN_INTERVAL_MS  = 100    # rate-limit NACKs
```

### Architecture (after speed fix)
- ACKs sent via Swift NWConnection (separate socket, no contention)
- Lock-free encryption (pre-extracted keys, AtomicU64 seq counter)
- Relay routes by session_id (Nebula-style), no peer_a flip-flop
- Gateway receives ACKs correctly — confirmed in logs

### Benchmark Results: 3/11 passing (only 10KB sizes)
- Stalls at ~100KB transfers
- Gateway log pattern:
  - cwnd ramps to 60-80 in slow start
  - Massive dup ACK plateaus (20, 40, 60 dups without progress)
  - Fast retransmit every ~100-300ms
  - cwnd repeatedly slashed by @loss_beta
  - Eventually: "Stall detected: no ACK advance for 15s"
- Phone log pattern:
  - Receives data normally up to a point
  - Then gets flood of DUPLICATE data_seq (retransmits)
  - Re-ACKs duplicates → causes more retransmits → feedback loop
  - Missing seq never arrives → stall

### Root Cause Analysis
The ACK path works. The problem is **real packet loss at high send rates**.
At cwnd=60-80 with burst_size=4 and pacing=2ms, the gateway sends
4 × 1140 = 4560 bytes every 2ms = ~18 Mbps instantaneous rate.
But the relay→phone path can't sustain this — packets get dropped,
triggering retransmits, which create more loss (congestion collapse).

@max_cwnd=512 is way too high. The gateway never gets there but
@initial_ssthresh=512 means it stays in slow start too long,
doubling cwnd per RTT until it blows past the path's capacity.

---

## Change 1: Conservative mobile tuning (2026-04-07 01:35 UTC)

### What changed
```
@max_cwnd:            512  → 64     # cap at 64 × 1140 = 73KB inflight
@initial_ssthresh:    512  → 32     # exit slow start early, enter CA at 32
@initial_cwnd:        32.0 → 10.0   # start conservative (RFC 6928 IW=10)
@burst_size:          4    → 2      # 2 packets per tick = gentler bursts
@pacing_interval_ms:  2    → 5      # 5ms between bursts = more spread
@min_ssthresh:        48   → 16     # lower floor for aggressive paths
@loss_beta:           0.75 → 0.5    # standard TCP halving on loss
```

### Why
- max_cwnd=512 is unreachable but ssthresh=512 keeps slow start going
  until loss. On a lossy relay path, the first loss happens at cwnd~60-80,
  then dup ACK plateaus collapse it. Better to cap earlier.
- burst_size=4 at 2ms pacing = 4 × 1140 = 4.5KB every 2ms. On cellular
  with ~30ms jitter, multiple bursts arrive simultaneously. Reducing to
  2 packets every 5ms = 456 bytes/ms = ~3.6 Mbps pacing rate, which
  is more cellular-friendly.
- loss_beta=0.5 (TCP standard) instead of 0.75: the "gentle" 0.75 means
  cwnd only drops 25% on loss, so it stays near the congestion point and
  hits loss again immediately. Standard halving backs off further and
  recovers more stably.
- initial_cwnd=10 is TCP standard. 32 was too aggressive for first RTT.

### Results: 5/11 passing (up from 3/11)
Improved — 10KB and 100KB sizes now passing. Still stalls at larger sizes.

Gateway log pattern:
- cwnd grows to max_cwnd=64 → immediately hits "dup ACK plateau (20)"
- cwnd slashed to 32, recovers, hits 64 again, crashes again
- Sawtooth pattern: 64→32→64→32→25→... eventually stalls
- "Fast retransmit" happening at buffer=55-64 (near ceiling)
- Still getting "Stall detected: no ACK advance for 15s"

Analysis: max_cwnd=64 is still too high for this relay→cellular path.
The stable operating point appears to be cwnd 25-35 based on where
recovery exits (acked advances when cwnd is around 25-31).
The path can sustain ~25-35 × 1140 = 28-40KB inflight.

Next step: lower max_cwnd to 32, keep everything else the same.

---

## Change 2: Lower max_cwnd to 32 (2026-04-08 01:50 UTC)

### What changed
```
@max_cwnd:  64  → 32     # cap at 32 × 1140 = 36.5KB inflight
```

### Why
- Change 1 showed the stable operating point is cwnd 25-35
- At max_cwnd=64, gateway ramps to ceiling → dup ACK plateaus at 55-64
- Recovery exits healthily around cwnd 25-31
- Sawtooth 64→32→64→32 causes repeated loss events before stalling
- Setting max_cwnd=32 keeps the gateway within the path's observed capacity
- Everything else stays the same — only this one knob

### Expected behavior
- Slow start exits at ssthresh=32, but max_cwnd=32 also caps it
- Congestion avoidance operates in the 16-32 range (after any loss halving)
- Should eliminate the "ramp to 64 → massive loss → crash" pattern
- Throughput target: ~2-4 Mbps sustained (32 × 1140 × 1000/RTT)

### Results: 6/11 passing (up from 5/11)

No stalls (0 "Stall detected" events — first time!). But sawtooth pattern:
- cwnd ramps to 32 → dup ACK plateau (20) or RTO every time
- Slashed to 16, recovers to 32, hits loss again: 32→16→32→16→32→16
- Recovery exits consistently at cwnd 19-27
- Loss consistently at cwnd=32 — that's the congestion threshold, not sustainable rate
- Healthy zone appears to be 16-24

---

## Change 3: Lower max_cwnd to 24 (2026-04-08 01:55 UTC)

### What changed
```
@max_cwnd:  32  → 24     # cap at 24 × 1140 = 27.4KB inflight
```

### Why
- Change 2 showed cwnd=32 is the loss threshold — hits plateau/RTO every time at 32
- Recovery exits at 19-27, meaning the path sustains 16-24 packets
- Capping at 24 keeps gateway below loss point, should reduce sawtooth oscillations
- Should spend more time in steady state, less time in recovery

### Expected behavior
- Slow start exits at ssthresh=32 but capped at max_cwnd=24
- After first loss: ssthresh→12, cwnd halved to 12, climbs back to 24 in CA
- Fewer loss events = fewer retransmits = more consistent throughput

### Results: TBD (deploy and benchmark next)
