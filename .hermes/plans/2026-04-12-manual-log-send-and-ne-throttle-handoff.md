# Handoff: Manual Log Send Working, Current iPhone Failure is NE Self-Throttling

Date: 2026-04-12
Commit context: gateway mux/backpressure fix already deployed; iOS app modified on Steve's Mac to support manual bootstrap log POST from Benchmarks page.

## What was confirmed in this session

### 1. Manual "Send Logs" from Benchmarks page now works
Bootstrap received successful manual uploads after the button was fixed.

Confirmed from bootstrap / phone logs:
- `benchmark_id=28`
- `benchmark_id=29`
- phone log shows:
  - `BenchUpload] Submitting manual log dump: benchmark_page_send_logs`
  - `Benchmark upload complete: HTTP 201 ...`
  - `Manual log dump stored on bootstrap server`

This means the Benchmarks page button is now correctly POSTing to bootstrap using the same benchmark endpoint, even when the benchmark is stuck.

### 2. The current iPhone failure is NOT gateway mux collapse
Gateway-side catastrophic fan-out symptoms were not the current blocker during this latest run.
What we saw instead is the phone-side Network Extension continuously self-throttling.

### 3. Current root symptom on phone
The NE repeatedly logs:
- `Router throttle: resident=18-20.6MB exceeds soft limit 12.0MB`
- `readPacketLoop: throttling router work to give inbound UDP/ACK handling room`

Observed resident memory during latest runs:
- ~18.3MB
- ~20.3MB
- ~20.6MB

This means the current soft limit (`12.0MB`) is far below real steady-state runtime memory, so the router loop is almost permanently in throttle mode.

## Important evidence collected

### Bootstrap logs
Recent successful manual uploads:
- benchmark 28: `score=1/1`, `log_lines=370`, `log_bytes=36802`
- benchmark 29: `score=1/1`, `log_lines=400`, `log_bytes=40066`

These are manual dump uploads, not full benchmark completions.

### Phone logs
Key lines:
- `Preparing benchmark-page log export`
- `Submitting manual log dump: benchmark_page_send_logs`
- `Benchmark upload complete: HTTP 201 ...`
- `Manual log dump stored on bootstrap server`

And the main repeating problem:
- `Router throttle: resident=20.xMB exceeds soft limit 12.0MB`

### Bootstrap healthchecker noise
Bootstrap also shows recurring unrelated-ish infrastructure health-check failures:
- NS metrics tunnel timeouts
- relay metrics empty response
- gateway metrics empty response

These are from bootstrap health checks and should not be confused with the iPhone manual log send path, which is working.

## Files changed this session (iOS app side)

Key app-side files touched:
- `ios/ZTLP/ZTLP/Views/BenchmarkView.swift`
- `ios/ZTLP/ZTLP/Services/BenchmarkReporter.swift`
- `ios/ZTLP/ZTLP/Services/HTTPBenchmark.swift`
- `ios/ZTLP/ZTLP/Services/TunnelLogger.swift`
- `ios/ZTLP/ZTLP/Views/LogsView.swift`

Important behavior now present:
- Benchmarks page has persistent `Send Logs` button
- button POSTs to bootstrap manually
- visible status feedback was added on the page
- HTTP benchmark has per-test timeout/checkpoint logging in code on local repo; verify Steve's Mac repo and installed phone build are current before assuming those changes are on-device

## What to do next session

### Priority 1: Fix over-aggressive NE throttle threshold
Current code is protecting too early.

Recommended first change:
- raise `memorySoftLimitMB` in `PacketTunnelProvider.swift`
  - current: `12.0`
  - try: `24.0` first
  - if still over-throttling under normal steady state, try `26.0`

Why:
- actual steady-state resident memory is ~18-21MB
- with a 12MB limit, the NE is effectively always throttled
- that prevents meaningful traffic from flowing and masks deeper issues

### Priority 2: Retest immediately after threshold adjustment
After increasing the soft limit:
1. rebuild/install app from Xcode
2. start VPN
3. reproduce browser/benchmark failure
4. if stuck, tap `Send Logs`
5. immediately inspect:
   - bootstrap logs for new manual upload
   - phone app-group log
   - gateway logs

### Priority 3: Separate "steady-state warning" from "hard throttle"
Follow-up improvement if needed:
- keep warning threshold lower (for logging), e.g. 18MB
- use a higher actual throttle threshold, e.g. 24-26MB

That would avoid permanent throttling while still surfacing memory pressure.

## Suggested concrete next code change

In `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`:
- change:
  - `private static let memorySoftLimitMB: Double = 12.0`
- to:
  - `private static let memorySoftLimitMB: Double = 24.0`

Optionally also split into:
- `memoryWarnLimitMB = 18.0`
- `memoryThrottleLimitMB = 24.0`

## Operational note
The manual Send Logs path is now usable and should be relied on for the next debugging cycle.
This is the main improvement from this session: even if the test wedges, we can now capture current phone logs and push them to bootstrap on demand.

## Short conclusion
Current blocking issue for iPhone use is:
- NE self-throttling due to too-low soft memory threshold

Not currently supported by evidence as the immediate blocker:
- gateway send_queue explosion / mux fan-out collapse during latest test

The next session should start by raising the NE memory throttle threshold, rebuilding, and reproducing with manual log send available.