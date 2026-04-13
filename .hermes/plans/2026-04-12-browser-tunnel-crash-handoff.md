# Plan: Diagnose Browser/Vault Tunnel Crash During Active iPhone Usage
## Date: 2026-04-12

---

## Executive Summary

The original `mobile + unknown` gateway RTO bug is fixed and deployed.

The current problem is different:
- Benchmarks can pass (`8/8` observed)
- But when Steve uses the browser over the tunnel (`vault` HTTPS and/or `http`) the tunnel becomes unstable and disconnects
- Logs strongly suggest concurrent browser traffic causes mux stream fan-out, NE memory pressure, gateway send-queue explosion, then ACK starvation / session stall / teardown

This handoff is for a fresh session focused on the browser/tunnel crash, not the old RTO issue.

---

## What Has Already Been Fixed

### Gateway RTO fix is live
Commit deployed:
- `b93ccbe` — `fix: handle mobile unknown rto and detect NE interface`

Gateway verification log:
```text
08:46:21.269 [info] [Session] ClientProfile: class=mobile iface=unknown radio=nil → CC: cwnd=5.0 max=16 ssthresh=32 pacing=6ms burst=2 beta=0.7 rto=1500/min=500
```

This proves the deployed gateway now correctly maps `mobile + unknown` to the conservative mobile profile.

So the remaining browser crash is NOT caused by the old `300/100ms` mobile-unknown RTO bug.

---

## Current Observed Behavior

### User report
Steve says:
- gateway benchmark path is fine / benchmark passes
- when trying to use browser traffic through the tunnel (`vault` HTTPS or `http`) it does not work
- the tunnel disconnects/crashes

### Benchmark results captured by bootstrap
Latest benchmark row:
```text
2026-04-12 08:56:21 UTC | 8 | 8 | 20 | false | 44.246.33.34:23097 | v5D-SYNC
```
Meaning:
- `benchmarks_passed=8`
- `benchmarks_total=8`
- `ne_memory_mb=20`
- `ne_memory_pass=false`
- gateway `44.246.33.34:23097`
- build tag `v5D-SYNC`

Earlier rows also show similar memory failures even when benchmarks mostly pass.

---

## Key Evidence From Logs

## 1. Browser traffic is mixed into the same tunnel session
From uploaded device logs in bootstrap benchmark records:
```text
[Router] Router: OpenStream stream=5 service=http
[Router] Router: OpenStream stream=16 service=http
[Router] Router: OpenStream stream=1 service=vault
[Router] Router: OpenStream stream=2 service=vault
[Router] Router: OpenStream stream=3 service=vault
...
[Router] Router: OpenStream stream=17 service=vault
```

Interpretation:
- browser/app activity is creating many concurrent mux streams
- both `vault` and `http` are active in the same run/session family
- this is not a single clean benchmark-only tunnel path

## 2. The NE is still under serious memory pressure
From uploaded device logs:
```text
[Tunnel] v5B-SYNC | Memory HIGH — resident=29.6MB virtual=400534.7MB (NE limit ~15MB)
[Tunnel] v5B-SYNC | Low available memory: 43.0MB
[Tunnel] v5B-SYNC | Memory HIGH — resident=31.4MB virtual=400534.1MB (NE limit ~15MB)
[Tunnel] v5B-SYNC | Low available memory: 46.5MB
```

And later:
```text
resident=21.7MB
resident=20.0MB
resident=17.2MB
resident=19.5MB
```

Interpretation:
- even when benchmark completes, NE memory remains above target
- the extension is living in a high-risk range
- concurrent browser traffic likely pushes it over the edge or causes scheduling stalls

## 3. Gateway send queue explodes under mixed traffic
Gateway logs during the bad browser/tunnel run:
```text
[Session] pacing_tick: 8751 queued, 16/11 inflight/cwnd, ssthresh=11 open=false
```
repeated continuously, then:
```text
[Session] STALL: no ACK advance for 30s inflight=16 last_acked=1034 recv_base=1099 dup_ack=0 recovery=true — tearing down
```

Interpretation:
- send queue exploded to `8751`
- effective window stayed blocked (`open=false`)
- ACK advancement stopped
- gateway ultimately tears down the session after 30 seconds

This is consistent with the phone/NE falling behind under concurrent mux load.

## 4. The receive path still progresses before the crash/stall
Bootstrap-uploaded device logs show a long run of received data:
```text
ZTLP RX data seq=309 ...
ZTLP RX data seq=310 ...
...
ZTLP RX data seq=405 ...
```

and another run:
```text
ZTLP RX data seq=0 ...
ZTLP RX data seq=1 ...
...
ZTLP RX data seq=49 ...
```

Interpretation:
- this is not a handshake failure
- data does flow for a while
- the failure happens during sustained multiplexed usage, not at connection setup

---

## Current Hypothesis

Most likely root cause chain:

1. Browser activity opens many concurrent mux streams (`vault`, `http`, maybe background system traffic too)
2. The iOS NE accumulates memory pressure and/or CPU scheduling pressure
3. The client falls behind on drain/ACK progression under concurrent traffic
4. The gateway keeps buffering outbound data until queue depth becomes enormous
5. `pacing_tick` remains `open=false`
6. ACK advance stops
7. Gateway hits stall timeout and tears down the session
8. User perceives this as browser traffic disconnecting/crashing the tunnel

This is NOT primarily a gateway client-profile selection problem anymore.

---

## Important Constraints / Facts

### Gateway host
- public IP: `44.246.33.34`
- private IP from bootstrap inventory: `172.26.11.164`
- SSH path typically via bootstrap container key at `/tmp/gw_key`

### Relay host
- public IP: `34.219.64.205`
- private IP: `172.26.5.220`

### NS host
- public IP: `34.217.62.46`
- private IP: `172.26.13.85`

### Bootstrap host
- `trs@10.69.95.12`
- Rails app root inside container: `/rails`
- container: `bootstrap_web_1`

### Current app/build metadata seen in benchmark uploads
- build tag: `v5D-SYNC`
- iOS version reported: `26.3.1`

### Important note
The device logs still show `v5B-SYNC`/`v5D-SYNC` memory diagnostics. Treat those as the currently deployed phone build context unless Steve confirms a newer Xcode build is on-device.

---

## What Needs Investigation In The Fresh Session

### A. Confirm this is specifically triggered by concurrent browser traffic
Need a clean A/B comparison:
1. benchmark only
2. browser (`vault`/`http`) only
3. browser active + benchmark

Collect for each:
- gateway queue depth
- number of streams opened
- whether ACK progression stops
- NE memory snapshots if available

### B. Determine whether stream fan-out / lack of backpressure is the immediate trigger
The key pattern to validate:
- many `OpenStream` events
- rapidly growing queue depth on gateway
- no proportional client ACK advance

Likely code areas to inspect:
- iOS NE packet/tunnel/router stream opening and buffering behavior
- gateway session send queue handling / backpressure / backend read pausing
- mux stream scheduling fairness

### C. Inspect why browser traffic specifically is worse than benchmark traffic
Browser/Vault traffic may cause:
- more simultaneous streams
- more small control packets + TCP churn
- TLS handshake bursts
- extra DNS/system traffic
- more bidirectional pressure than synthetic benchmark path

### D. Check whether NE memory pressure alone can explain the disconnect
The logs strongly suggest this may be a major factor even when benchmarks pass.
Need to determine:
- is the extension actually being killed/jetsammed?
- or is it alive but too slow to drain and ACK?

---

## Suggested Investigation Steps

### Step 1: Reproduce with live gateway log tail
Watch gateway while Steve reproduces:
```bash
ssh trs@10.69.95.12 "docker exec bootstrap_web_1 bash -lc 'ssh -i /tmp/gw_key ubuntu@44.246.33.34 \"docker logs -f ztlp-gateway 2>&1 | grep -E \\\"ClientProfile|STALL|pacing_tick|ACK data_seq|RTO retransmit|No backend|Policy denied\\\"\"'"
```

Key things to note live:
- queue size
- inflight/cwnd
- whether `open=false` starts immediately after browser activity
- last_acked / recv_base at stall time

### Step 2: Pull latest benchmark/device logs from bootstrap after reproduction
Use Rails runner on bootstrap to inspect latest `BenchmarkResult` and `device_logs`.

### Step 3: Separate browser-only versus benchmark-only traffic patterns
Correlate device logs for:
- `OpenStream ... service=http`
- `OpenStream ... service=vault`
- memory growth timing
- any abrupt stop in RX / ACK logs

### Step 4: Inspect source for mux backpressure gaps
Potential code areas to inspect in fresh session:
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- packet router / mux stream dispatch in iOS path
- gateway session send queue management in `gateway/lib/ztlp_gateway/session.ex`

Specific questions:
- are backend reads paused when queue explodes?
- is per-stream fairness missing?
- can one browser-heavy stream set starve others?
- is there a queue high-water mark?

### Step 5: Determine next fix direction
Likely categories:
1. iOS NE memory / buffering reduction
2. gateway-side send_queue backpressure
3. mux per-stream fairness / stream cap
4. browser/vault-specific stream churn handling

---

## Strong Working Theory

If you need a concise diagnosis to start from:

> The tunnel does not fail because the gateway mobile profile is wrong anymore. It fails when real browser/vault traffic creates many simultaneous mux streams, causing the iOS NE to run hot on memory and/or fall behind on drain/ACK processing. The gateway then accumulates a huge send queue (observed 8751 queued), the congestion window stays closed, ACK advancement stops, and the gateway tears the session down after 30 seconds.

---

## Deliverable For Fresh Session

The next session should produce:
1. a precise root-cause analysis of why browser/vault traffic disconnects the tunnel while benchmarks can still pass
2. identification of the most likely code location(s) to fix
3. a concrete fix plan, preferably in a new markdown plan file under `/home/trs/ztlp/.hermes/plans/`
4. if possible, a minimal change set that reduces browser-triggered queue explosion or NE overload

---

## Session Opening Prompt

Use this in the new session:

"Continue from /home/trs/ztlp/.hermes/plans/2026-04-12-browser-tunnel-crash-handoff.md.
The mobile+unknown gateway RTO bug is already fixed and deployed. Current issue: benchmarks can pass, but when Steve uses browser traffic over vault/http, the tunnel disconnects. Analyze the gateway logs, bootstrap benchmark uploads, and uploaded device logs to determine why concurrent browser traffic causes the tunnel to crash/stall. Focus on mux stream fan-out, NE memory pressure, queue explosion, ACK starvation, and missing backpressure. Produce a new fix plan with the most likely code locations and next implementation steps."