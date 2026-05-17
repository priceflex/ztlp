# Full-stack Gateway/Relay Bench — 2026-05-17

## Summary

Objective N1 from `bench/HANDOFF-2026-05-17.md` was attempted on a real AWS
three-host testbed:

- NS: `18.236.150.73` (`ztlp-ns:bench-2026-05-17`)
- Relay: `44.243.42.123` (`ztlp-relay:bench-2026-05-17`)
- Gateway: `54.190.82.255` (`ztlp-gateway:bench-2026-05-17`)
- Backend: HTTP byte server on gateway host, `127.0.0.1:7777`

All hosts are 2 vCPU / ~911 MiB RAM AWS instances. Docker 29.5 was installed on
all hosts and UDP sysctls were tuned to the standard 7 MiB values:

```text
net.core.rmem_max = 7340032
net.core.wmem_max = 7340032
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
```

The chain is operational for small transfers:

```text
client (/home/trs/ztlp) → relay 44.243.42.123:23095
  → gateway 54.190.82.255:23097 → backend 127.0.0.1:7777 → back
```

Smoke test proved the end-to-end path by tunneling a TCP echo through relay and
gateway and receiving the echo back.

However, the full-stack throughput bench uncovered a different blocker before a
meaningful MB/s comparison could be made: the Elixir gateway legacy backend path
stalls on response-side bulk transfer and/or concurrent local-forward sessions.
This is **not** the kernel UDP rcvbuf-loss bug fixed in `c6947e0`: UDP `InErrors`
remained zero on client, relay, and gateway during all attempted runs.

## Infrastructure deployed

Commands used by the deploy subagent:

### NS

```bash
sudo docker run -d --name ztlp-ns --restart unless-stopped \
  -p 23096:23096/udp -p 9103:9103/tcp \
  -e ZTLP_NS_PORT=23096 \
  -e ZTLP_NS_STORAGE_MODE=ram_copies \
  -e ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false \
  -e ZTLP_NS_METRICS_PORT=9103 \
  -e ZTLP_LOG_LEVEL=info \
  -e ZTLP_LOG_FORMAT=json \
  ztlp-ns:bench-2026-05-17
```

### Relay

```bash
sudo docker run -d --name ztlp-relay --restart unless-stopped \
  -p 23095:23095/udp -p 9101:9101/tcp \
  -e ZTLP_RELAY_PORT=23095 \
  -e ZTLP_RELAY_LISTEN_PORT=23095 \
  -e ZTLP_RELAY_METRICS_ENABLED=true \
  -e ZTLP_RELAY_METRICS_PORT=9101 \
  -e ZTLP_LOG_LEVEL=info \
  -e ZTLP_LOG_FORMAT=json \
  -e RELEASE_COOKIE=ztlp_relay_docker \
  ztlp-relay:bench-2026-05-17
```

### Gateway

```bash
sudo docker run -d --name ztlp-gateway --restart unless-stopped --network host \
  -e ZTLP_GATEWAY_PORT=23097 \
  -e ZTLP_NS_SERVER=18.236.150.73:23096 \
  -e ZTLP_RELAY_SERVER=44.243.42.123:23095 \
  -e ZTLP_GATEWAY_BACKENDS=echo:127.0.0.1:7777 \
  -e ZTLP_GATEWAY_SERVICE_NAMES=echo \
  -e ZTLP_GATEWAY_POLICIES=*:echo \
  -e ZTLP_LOG_LEVEL=info \
  -e ZTLP_LOG_FORMAT=json \
  ztlp-gateway:bench-2026-05-17
```

Gateway runtime NS parse was verified via RPC and returned:

```text
{{18,236,150,73}, 23096}
```

## Bench harness

New script:

```text
bench/run_fullstack_multistream.py
```

The harness creates N independent `ztlp connect` processes, each with a unique
SessionID and local-forward port, then performs HTTP downloads through those
local forwards:

```text
curl http://127.0.0.1:<local_port>/bytes?size=<SIZE>
```

Important harness corrections made during testing:

1. Readiness must not open a TCP connection to the local forward. `ztlp connect`
   treats the local-forward path as effectively one TCP connection per session;
   a connect/close readiness probe consumes the session. The script now polls
   `ss -ltn` instead.
2. Each stream gets an explicit unique `--session-id` to avoid gateway session
   replacement collisions in repeated/concurrent runs.
3. Handshakes are staggered by 250 ms. Simultaneous HELLO bursts caused some
   gateway sessions to miss `HELLO_ACK`.

## Results

### Small transfer smoke: 64 KiB

```text
Full-stack ZTLP HTTP throughput (size=0 MB per stream)
Path: client → relay 44.243.42.123:23095 → gateway 54.190.82.255:23097 → HTTP backend

  1 streams: aggregate=    0.1 MB/s   wall=   509 ms   per-stream-avg=   0.1 MB/s   stalled=0   ok=1
       udp[client]: dIn=97 dErr=0 dOut=3
       udp[relay]: dIn=1 dErr=0 dOut=1
       udp[gateway]: dIn=11 dErr=0 dOut=330

  4 streams: aggregate=    0.0 MB/s   wall= 90008 ms   per-stream-avg=   0.0 MB/s   stalled=3   ok=1
       udp[client]: dIn=709 dErr=0 dOut=39
       udp[relay]: dIn=8 dErr=0 dOut=8
       udp[gateway]: dIn=73 dErr=0 dOut=748
       errors=s0,s1,s2: curl timed out after 90s with 0 bytes received
```

### 1 MiB single-stream attempt

```text
  1 streams: aggregate=    0.0 MB/s   wall= 90005 ms   per-stream-avg=   0.0 MB/s   stalled=1   ok=0
       udp[client]: dIn=707 dErr=0 dOut=10
       udp[relay]: dIn=7 dErr=0 dOut=7
       udp[gateway]: dIn=40 dErr=0 dOut=740
       errors=s0: curl timed out after 90s with 513737 out of 1048576 bytes received
```

The 1 MiB case received ~502 KiB, then stalled. This is a useful threshold: the
path can move response bytes, but response-side bulk transfer does not complete.

## Interpretation

This real-stack bench did **not** reproduce the old multistream kernel-rxbuf
signature:

- No `UdpRcvbufErrors` appeared (`dErr=0` on all hosts for every run).
- Relay metrics showed valid packets passing after AWS Security Group UDP rules
  were opened.
- Gateway logs showed successful handshakes, `ClientProfile class=desktop`, and
  backend lifecycle messages.

The current blocker is above kernel UDP buffering. The dominant symptoms are:

1. Single-stream HTTP response stalls around ~500 KiB on the gateway legacy
   backend path.
2. Concurrent `ztlp connect` sessions through the Elixir gateway are fragile:
   some complete handshakes, others fail waiting for `HELLO_ACK`; even with
   staggered startup, only 1/4 small transfers completed.
3. Gateway stats show `bytes_out` moving but not enough to complete the HTTP
   response.

This is most likely a gateway/session flow-control or legacy-backend response
flush issue, not a relay or SO_RCVBUF regression.

## Comparison with loopback transport fix

The loopback dumb-pipe transport fix in `c6947e0` is still validated by the
previous table in `bench/RESULTS-2026-05-17.md`:

```text
N=32 loopback: 214 MB/s, stalled=0, UdpRcvbufErrors=0
```

The full-stack gateway path currently fails before reaching a comparable steady
state. The useful takeaway is that the rcvbuf fix holds at the kernel level on
real AWS hosts (`dErr=0`), but Phase B3 now exposes a separate Elixir-gateway
response-path bottleneck/stall.

## Artifacts

- Bench script: `bench/run_fullstack_multistream.py`
- Last result capture: `/tmp/fullstack-bench-result.txt`
- Per-stream logs: `/tmp/ztlp-fullstack/`
- Gateway backend script on gateway host: `/tmp/http_bench.py`

## Next steps

1. Debug the Elixir gateway legacy backend response path before installing a
   browser benchmark site. A browser/librespeed test would hit the same stalled
   response path.
2. Start with a single 1 MiB HTTP response and instrument gateway session send
   buffer / ACK progress. The stall point near 500 KiB is small enough to debug
   quickly.
3. Keep checking `/proc/net/snmp` during each probe. If `dErr` stays zero, avoid
   chasing kernel buffer tuning; the issue is in gateway/session flow control.
4. Once single-stream 1 MiB completes, rerun `bench/run_fullstack_multistream.py`
   at 1/4/8/16/32 streams and then layer on the browser benchmark site.
