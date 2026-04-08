# ZTLP iOS Benchmark: 6/11 → 11/11 Plan

## Goal
Get all 11 HTTP benchmarks passing. Currently 6/11.

## Current State

### What's passing (6):
- HTTP Ping, GET 1KB, GET 10KB, GET 100KB, POST Echo 1KB, + one more

### What's failing (5 probable):
- **GET 1MB** — 20 iterations, all timeout/truncate (need 1 to succeed)
- **Download 5MB** — 5 iterations, VIP proxy connection dies at ~2.5MB
- **Upload 1MB** — 5 iterations, upload CC not tuned at all
- **POST Echo 100KB** — 20 iterations, 200KB round-trip, all fail
- **Concurrent 5x GET** — requires 5/5 success in one round of 3

### Pass/fail criteria:
No throughput thresholds. A test passes if **even 1 iteration completes**.
Failure = zero iterations complete (all timeout at 120s or connection-error).

### Path characteristics (observed):
- Relay → phone over cellular, ~30-50ms RTT
- Sustains cwnd 16-24 before loss at any ceiling
- Loss at max_cwnd=24 still triggers dup ACK plateaus
- Random non-congestion drops common on cellular
- Effective throughput at cwnd=20: ~20 × 1140 / 0.040 = ~570 KB/s = ~4.5 Mbps

### Current CC parameters:
```
@initial_cwnd         10.0
@max_cwnd             24       ← too conservative AND still hits loss at ceiling
@min_cwnd             10       ← too high, recovery can't go deep enough
@initial_ssthresh     32
@min_ssthresh         16
@loss_beta            0.5      ← too aggressive for random cellular drops
@burst_size           2
@pacing_interval_ms   5
@stall_timeout_ms     15_000
@max_rto_retransmit_per_tick  8
```

## Root Cause Analysis

### Why large transfers fail:
1. **Sawtooth exhaustion**: cwnd oscillates 24→12→24→12. At cwnd=12, throughput is ~2 Mbps.
   A 5MB transfer at average ~3 Mbps takes ~13 seconds. But the sawtooth causes periodic
   stalls where NO data flows during retransmit/recovery, pushing total time past 120s timeout.

2. **loss_beta=0.5 is too aggressive**: Standard TCP halving assumes ALL loss is congestion.
   On cellular, random drops are common. Halving on random loss is double-punishment — the
   path has capacity but we cut the window anyway.

3. **min_cwnd=10 is too high as a floor**: After loss, cwnd=24×0.5=12. There's barely any
   room between floor (10) and post-loss cwnd (12). This means recovery is ineffective — we
   immediately climb back to 24 and hit loss again. The "floor" and "operating range" are
   too close together.

4. **Pacing is fixed, not RTT-adaptive**: 2 packets every 5ms = 3.6 Mbps constant rate.
   When cwnd is low (12 after loss), the pacing rate exceeds what the window allows, causing
   bursty sends when the window opens. When cwnd is high (24), pacing is appropriate.

5. **No RTT-based loss discrimination**: Every loss triggers the same beta=0.5 response,
   whether it's random cellular loss (RTT stable) or genuine congestion (RTT inflating).

### Why uploads fail:
The upload path goes: App → TCP → VIP proxy → ZTLP tunnel → relay → gateway.
The gateway's upload receive window (@recv_window_size=256) should be fine, but the
client-side SendController has its OWN congestion control that may be too conservative.

### Why concurrent fails:
5 parallel streams share one ZTLP session. With max_cwnd=24 and 5 streams each
needing ~10KB, they compete for window space. A single loss event halves the shared
cwnd, stalling all 5 streams.

## Proposed Changes

### Phase 1: Gateway CC Tuning (server-side, quick deploy)

**File: `gateway/lib/ztlp_gateway/session.ex`**

| Parameter | Current | New | Rationale |
|-----------|---------|-----|-----------|
| max_cwnd | 24 | 32 | Allow headroom above BDP. Loss at 24 means 24 IS the ceiling. Cap at 32 gives the CC room to oscillate between 20-32 instead of 12-24. |
| min_cwnd | 10 | 4 | Allow deep backoff on genuine congestion. Current floor=10 means recovery from 12→10 is useless. New: 12→4 is meaningful. |
| loss_beta | 0.5 | 0.7 | Cubic-style 30% reduction instead of 50%. On cellular, most loss is random — gentler reduction keeps throughput higher. After loss: cwnd=32×0.7=22 (still in sustainable range) vs 32×0.5=16 (below sustainable). |
| initial_ssthresh | 32 | 64 | Let slow start run longer. Current ssthresh=32=max_cwnd, so we immediately enter CA at the ceiling. Set ssthresh above max_cwnd so slow start naturally hits the cwnd cap first. |
| burst_size | 2 | 3 | Slightly larger bursts align better with cellular radio scheduling (LTE TTI=1ms). 3×1140=3420 bytes per 5ms = 5.4 Mbps pacing rate, closer to path capacity. |
| pacing_interval_ms | 5 | 4 | Slightly faster pacing tick. Combined with burst=3: 3 packets every 4ms. |
| stall_timeout_ms | 15000 | 30000 | 15s is too aggressive for large transfers with recovery. A 5MB transfer at 3 Mbps takes ~13s baseline, and recovery adds delay. 30s gives enough room. |

**Expected effect**: After loss, cwnd goes from 32→22 (instead of 24→12). This keeps us
in the sustainable 16-24 range even during recovery. Throughput stays ~4 Mbps throughout
instead of oscillating between 2-4 Mbps.

**Math check (5MB transfer)**:
- Average cwnd ≈ 27 (oscillates 22-32 with beta=0.7)
- Average throughput ≈ 27 × 1140 / 0.040 = ~770 KB/s = 6.1 Mbps
- 5MB at 6 Mbps ≈ 6.8 seconds (well under 120s timeout)
- Even at worst case cwnd=16: 16 × 1140 / 0.040 = 456 KB/s, 5MB = 11.2 seconds

### Phase 2: Client-side VIP proxy resilience (Rust, needs iOS build)

**File: `proto/src/vip.rs`**

a) **VIP proxy connection error handling**: When a VIP proxy TCP write fails,
   DON'T kill the listener. Just close that specific stream and log it.
   Currently a write error breaks out of the connection handler loop,
   and if the listener task panics, port 9080 dies entirely.

b) **VIP proxy TCP keepalive**: Enable TCP_NODELAY on VIP proxy sockets
   so small responses aren't delayed by Nagle's algorithm.

### Phase 3: Upload CC (client-side SendController)

**File: `proto/src/send_controller.rs`**

Review the client-side SendController parameters. The upload path has its own CC
that we haven't touched. Apply similar tuning (beta=0.7, reasonable max_cwnd).

## Step-by-Step Execution

### Step 1: Gateway CC changes (deploy immediately)
1. Update TUNING-LOG.md with Change 4
2. Edit session.ex: max_cwnd=32, min_cwnd=4, loss_beta=0.7, ssthresh=64, burst=3, pacing=4ms, stall=30s
3. rsync + docker build + deploy (warn Steve first)
4. Benchmark → expect 8-9/11

### Step 2: Quick iOS build for VIP resilience
1. Add TCP_NODELAY to VIP proxy sockets
2. Improve error handling in VIP write task
3. Build on Mac, Xcode deploy
4. Benchmark → expect 9-10/11

### Step 3: Upload CC tuning
1. Review send_controller.rs parameters
2. Apply similar tuning to upload path
3. Build + deploy
4. Benchmark → target 11/11

### Step 4: If still not 11/11
- RTT-based loss discrimination (beta=0.85 when RTT stable, 0.7 when inflating)
- Hybrid slow start (exit slow start early on RTT increase)
- Reduce ACK_COALESCE_COUNT from 8 to 4 for faster gateway CC feedback

## Files to Change

| File | Phase | Changes |
|------|-------|---------|
| gateway/lib/ztlp_gateway/session.ex | 1 | CC parameters |
| TUNING-LOG.md | 1 | Document changes |
| proto/src/vip.rs | 2 | TCP_NODELAY, error handling |
| proto/src/send_controller.rs | 3 | Upload CC tuning |
| proto/src/ffi.rs | 4 | ACK coalescing if needed |

## Risks & Mitigations

1. **loss_beta=0.7 could cause persistent congestion**: If the path really can't handle cwnd=22,
   we'll see continuous loss. Mitigation: we already proved cwnd 16-24 is sustainable, and
   32×0.7=22 lands right in that range.

2. **burst_size=3 might cause micro-drops**: 3 packets at once is more bursty.
   Mitigation: LTE scheduling handles 3-packet bursts well (TTI=1ms). If it causes
   issues, revert to 2.

3. **stall_timeout=30s masks real problems**: Longer timeout means slower failure detection.
   Mitigation: This only affects the stall detection timer, not the CC. URLSession has
   its own 120s timeout as backstop.

4. **Upload CC changes could break passing tests**: Be conservative with send_controller
   changes. Test incrementally.

## Validation

After each phase, run the full HTTP benchmark suite and verify:
- No new regressions in passing tests
- Gateway logs show healthy CC behavior (no long dup ACK plateaus)
- VIP proxy stays alive through all 11 tests
- Upload tests show data actually flowing (check gateway bytes_in)
