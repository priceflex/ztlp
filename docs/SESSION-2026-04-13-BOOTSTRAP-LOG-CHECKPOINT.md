# Session Checkpoint — Bootstrap Log Review — 2026-04-13

## Context

We verified the newly built iOS NE Rust library was copied to Steve's Mac and the
latest benchmark/log uploads were inspected on the bootstrap server.

Primary question: why recent HTTP benchmark runs are failing after earlier runs
started passing again.

## What Was Done

### 1. Built and copied updated iOS NE library to Steve's Mac

On Steve's Mac (`~/ztlp`):
- synced updated Rust files into `~/ztlp/proto/`
- built NE lib with:

```bash
cargo build --target aarch64-apple-ios --release --lib \
  --target-dir target-ios-sync \
  --no-default-features --features ios-sync
```

- copied outputs to:
  - `~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a`
  - `~/ztlp/ios/ZTLP/Libraries/ztlp.h`

Observed artifact sizes:
- `libztlp_proto_ne.a` = 27,647,904 bytes
- `ztlp.h` = 55,777 bytes

### 2. Queried recent BenchmarkResult records on bootstrap

Latest rows at time of check:
- `53 | 2026-04-13 07:35:08 UTC | 2/6 | ne_memory_mb=21`
- `52 | 2026-04-13 07:33:39 UTC | 1/2 | manual_log_dump`
- `51 | 2026-04-13 07:33:25 UTC | 6/6 | ne_memory_mb=21`
- `50 | 2026-04-13 07:33:23 UTC | 8/8 | ne_memory_mb=21`

## Key Findings

### Benchmark 53 (new failing run)

`BenchmarkResult id=53`
- created: `2026-04-13 07:35:08 UTC`
- score: `2/6`
- `ne_memory_mb = 21`
- `gateway_address = 44.246.33.34:23097`
- `replay_reject_count = 2`

`individual_results`:
- PASS `GET /alive (vault)` — 52ms
- FAIL `GET / (vault web)` — No response
- FAIL `GET /api/config (vault)` — No response
- FAIL `GET / (primary)` — No response
- FAIL `GET / (http proxy)` — No response
- PASS `Throughput (0 reqs)`

### Benchmark 51 (recent successful comparison run)

`BenchmarkResult id=51`
- score: `6/6`
- same `ne_memory_mb = 21`

Passed:
- `GET /alive (vault)`
- `GET / (vault web)`
- `GET /api/config (vault)`
- `GET / (primary)`
- `GET / (http proxy)`
- `Throughput (5 reqs)`

### Bootstrap-side conclusion

Bootstrap server logs did NOT show a Rails-side exception around the failing run.
Only normal health-check traffic was visible in the container logs.

So bootstrap is not the cause.

## Device Log Analysis from Benchmark 53

The attached `device_logs` for benchmark 53 showed:
- no memory throttle loop
- no keepalive timeout
- no duplicate storm
- no DNS NXDOMAIN issue

Counts:
- `THROTTLE_COUNT=0`
- `KEEPALIVE_TIMEOUTS=0`
- `DUPLICATES=0`
- `DNS_NX=0`

The log clearly showed healthy tunnel traffic before failure:
- repeated `GW->NE mux DATA stream=...`
- repeated `ZTLP ACK sent seq=... inflight=0`

This confirms:
- transport path was alive
- ACK path was alive
- mux traffic was arriving successfully

## Most Important Clue

The device log contained:

```text
[2026-04-13T07:33:32.478Z] [DEBUG] [App] VPN status changed: 5
[2026-04-13T07:33:32.863Z] [DEBUG] [App] VPN status changed: 1
```

From `ios/ZTLP/ZTLP/ViewModels/TunnelViewModel.swift`:
- `5 = .reasserting`
- `1 = .disconnected`

So the actual sequence is:
- VPN entered reasserting/reconnecting
- then became disconnected

This lines up with the HTTP failures in benchmark 53.

## Current Diagnosis

The current failure mode is NOT:
- bootstrap ingest
- old memory-throttle behavior
- obvious DNS failure
- obvious ACK starvation / retransmit collapse

The current likely failure mode IS:
- tunnel / NE lifecycle transition after initial success
- specifically `reasserting -> disconnected`, causing later HTTP requests to return `No response`

Why `/alive` passes while later HTTP requests fail:
- `/alive` is early/lightweight and completes before the disconnect
- later requests happen after or during the tunnel state transition

## Relevant Source References

### VPN status mapping
File:
- `ios/ZTLP/ZTLP/ViewModels/TunnelViewModel.swift`

Observed mapping:
- `.invalid`
- `.disconnected`
- `.connecting`
- `.connected`
- `.reasserting`
- `.disconnecting`

### HTTP benchmark endpoints
File:
- `ios/ZTLP/ZTLP/Views/BenchmarkView.swift`

HTTP tests in order:
- `GET /alive (vault)` → `http://10.122.0.4/alive`
- `GET / (vault web)` → `http://10.122.0.4/`
- `GET /api/config (vault)` → `http://10.122.0.4/api/config`
- `GET / (primary)` → `http://10.122.0.2/`
- `GET / (http proxy)` → `http://10.122.0.3/`
- throughput test → `http://10.122.0.4/`

The failing run demonstrates that the tunnel survives long enough for `/alive`,
but not for the rest of the suite.

## Recommended Next Step

Next debugging should focus on on-device tunnel teardown causes, especially:
- `PacketTunnelProvider.stopTunnel(...)`
- any code path that triggers disconnect/reassertion after traffic begins
- shared-defaults error propagation (`ztlp_last_error`)
- provider / NWPath / session lifecycle triggers
- whether a stream/router error cascades into tunnel shutdown

Most useful immediate artifact to collect after reproduction:
- fresh phone app-group log immediately after a failed run, centered on the first
  line before `VPN status changed: 5`

## Summary

Status at checkpoint:
- updated NE lib has been built and copied to Steve's Mac
- benchmark 50/51 prove the path can work at `ne_memory_mb=21`
- benchmark 53 proves the current issue is a tunnel lifecycle disconnect, not the
  previous memory-throttle pathology
- strongest current lead: `reasserting -> disconnected` transition on device
