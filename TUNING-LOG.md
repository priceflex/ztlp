# ZTLP Gateway Congestion Control Tuning Log

## Change 1 (2026-04-07): Initial conservative mobile tuning
- **From**: cwnd=32, max=512, ssthresh=512, beta=0.75
- **To**: initial_cwnd=10, max_cwnd=32, ssthresh=32, beta=0.75
- **Result**: Dup ACK spirals at cwnd~60 eliminated. But beta=0.75 too gentle.

## Change 2 (2026-04-07): TCP standard halving
- **From**: loss_beta=0.75
- **To**: loss_beta=0.5
- **Rationale**: 0.75 kept cwnd near congestion point, hit loss repeatedly.
- **Result**: Better loss recovery, but sawtooth 32→16→32 too aggressive.

## Change 3 (2026-04-07): Conservative ceiling
- **From**: max_cwnd=32
- **To**: max_cwnd=24, min_cwnd=10, ssthresh=32, burst=2, pacing=5ms, stall=15s
- **Rationale**: Path loses at cwnd=32. Cap below loss threshold.
- **Result**: 6/11 benchmark. No stalls. But sawtooth 24→12 craters throughput.
  Large transfers (1MB, 5MB) can't finish in 120s URLSession timeout.
  Root cause: loss_beta=0.5 halves from 24→12, below sustainable 16-24 range.

## Change 4 (2026-04-08): Phase 1 — Cubic-style beta for cellular
- **Plan**: /home/trs/ztlp/.hermes/plans/2026-04-08_025000-ztlp-11-of-11-benchmark-plan.md
- **From → To**:

| Parameter | Old | New | Rationale |
|-----------|-----|-----|-----------|
| max_cwnd | 24 | 32 | Allow headroom above BDP. Loss at 24 = 24 IS the ceiling. 32 gives oscillation room 22-32 instead of 12-24. |
| min_cwnd | 10 | 4 | Allow deep backoff. Old: 12→10 useless. New: 22→4 meaningful. |
| min_ssthresh | 16 | 8 | Match lower min_cwnd floor. |
| loss_beta | 0.5 | 0.7 | Cubic-style 30% reduction. On cellular, random drops common. After loss: 32×0.7=22 (sustainable) vs 32×0.5=16 (below). |
| initial_ssthresh | 32 | 64 | Let slow start hit cwnd cap naturally. Old ssthresh=max_cwnd meant immediate CA at ceiling. |
| burst_size | 2 | 3 | 3×1140=3420 bytes per tick, better LTE TTI alignment. |
| pacing_interval_ms | 5 | 4 | Combined with burst=3: 6.8 Mbps pacing rate (was 3.6). |
| stall_timeout_ms | 15000 | 30000 | 5MB at 3 Mbps = 13s baseline + recovery delays. 15s too tight. |

- **Expected**: Sawtooth 32→22→32 keeps throughput in sustainable 16-24 range.
  Average cwnd ~27, throughput ~6 Mbps. 5MB in ~7s (well under 120s timeout).
  Target: 8-9/11 benchmark (from 6/11).
- **Result**: **11/11 benchmark pass!** (2026-04-08)
  - GET 1MB: 20/20, avg 2431ms (was timing out)
  - Download 5MB: 5/5, avg 11094ms (was timing out)
  - POST Echo 1KB: 20/20, avg 100ms (was failing — echo server fix needed)
  - POST Echo 100KB: 20/20, avg 690ms (same — echo server fix)
  - Upload 1MB: 5/5, avg 2848ms (was 404 — /upload endpoint added)
  - Concurrent 5x GET: 3/3, avg 345ms
  - TTFB: 1/1, 97ms (squeaked through retransmit hole stall)
  - Note: Retransmit hole bug still present (data_seq gap at 70-85K packets). TTFB passed with 1 iteration after waiting through a 70s stall. Needs fix for reliability.
  - Also fixed: /opt/ztlp/http-echo.py POST /echo now raw-echoes body, added /upload endpoint.
