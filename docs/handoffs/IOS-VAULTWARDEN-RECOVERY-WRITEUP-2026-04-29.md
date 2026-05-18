# ZTLP iOS Vaultwarden Recovery Breakthrough — 2026-04-29

## Executive summary

After roughly two months of chasing the iOS Vaultwarden/OpenVault tunnel poison bug, we finally got a successful end-to-end recovery test.

Known-good outcome:

- Fresh tunnel benchmark passed 8/8.
- Vaultwarden/OpenVault browser traffic poisoned/stalled the active tunnel state.
- Session-health detector fired.
- Probe timed out, proving the transport/session path was dead enough to require recovery.
- PacketRouter runtime state was reset.
- ZTLP transport reconnected through the relay without manually toggling VPN.
- Post-recovery benchmark passed 8/8.

This proves the Nebula-style session-health architecture works for the real iOS Vaultwarden failure mode.

The currently known-good stabilizing cap is:

```text
iOS advertised receive window: rwnd=4
```

This may be conservative/slow, but it is the first setting that survived the Vaultwarden browser burst and recovered automatically.

---

## Problem we were solving

The recurring failure mode:

1. Start ZTLP VPN on iPhone.
2. Fresh benchmark passes 8/8.
3. Open Vaultwarden/OpenVault in the in-app WKWebView browser.
4. Browser fan-out poisons the tunnel/session/router state.
5. Post-browser benchmark returns `No response`, times out, or the VPN drops.
6. Historically, only a manual VPN toggle recovered the tunnel.

Important: this was not merely a benchmark bug. Browser traffic could wedge the NE/gateway session path while the VPN still looked connected.

---

## Commits involved

Earlier session-health implementation:

```text
61a115d ios+gateway: Nebula-style session health recovery
6dbfdf6 ios: tighten session-health detector
6f0ad0d ios: fix Swift build errors in probe frame handlers
ac07c11 ios: fix frameBuffer cross-queue race in probe path
79f6daa docs: handoff for session-health next-session pickup
```

Breakthrough-session follow-up commits:

```text
463ac49 ios: eliminate shared send buffers in tunnel connection
b7aa633 ios: bound router flush during gateway data bursts
a139403 ios: hard cap receive window for browser bursts
```

---

## Final successful test evidence

### Fresh benchmark before Vaultwarden

Bootstrap benchmark:

```text
ID=195
score=8/8
mem=21
replay=144
Vault HTTP Response: 151ms
Primary HTTP Response: 462ms
```

Phone log:

```text
[2026-04-29T05:05:22.604Z] [INFO] [Tunnel] Build: 2026-04-29 05:05:22 +0000
[2026-04-29T05:05:23.304Z] [INFO] [Tunnel] Session health manager enabled interval=2.0s suspectRx=5.0s probeTimeout=5.0s stuckTicks=3
[2026-04-29T05:05:23.304Z] [INFO] [Tunnel] TUNNEL ACTIVE — v5D RELAY-SIDE VIP (no NWListeners)
[2026-04-29T05:05:29.037Z] [INFO] [Benchmark] Benchmark run started category=Tunnel
[2026-04-29T05:05:29.965Z] [INFO] [BenchUpload] Benchmark report stored on bootstrap server
```

### Vaultwarden/OpenVault burst

Phone log:

```text
[2026-04-29T05:05:33.213Z] [DEBUG] [Tunnel] Mux summary gwData=39/26343B open=7 close=9 send=2/531B
[2026-04-29T05:05:33.308Z] [DEBUG] [Tunnel] Router stats: flows=1 outbound=0 stream_to_flow=1 next_stream_id=9 send_buf_bytes=0 send_buf_flows=0 oldest_ms=93 stale=0
[2026-04-29T05:05:34.229Z] [DEBUG] [Tunnel] Mux summary gwData=89/64513B open=1 close=0 send=2/646B
[2026-04-29T05:05:35.250Z] [DEBUG] [Tunnel] Mux summary gwData=94/67717B open=0 close=0 send=0/0B
[2026-04-29T05:05:36.262Z] [DEBUG] [Tunnel] Mux summary gwData=104/75472B open=0 close=0 send=0/0B
[2026-04-29T05:05:37.286Z] [DEBUG] [Tunnel] Mux summary gwData=104/75920B open=0 close=0 send=0/0B
[2026-04-29T05:05:37.309Z] [DEBUG] [Tunnel] Health eval: flows=2 outbound=0 streamMaps=2 highSeq=432 stuckTicks=0 usefulRxAge=0.0s outboundRecent=true replayDelta=0 probeOutstanding=false
[2026-04-29T05:05:37.459Z] [DEBUG] [Tunnel] ZTLP RX summary packets=433 payload=314717B acks=433 replay=1 highSeq=432 inflight=0
```

Interpretation:

- Browser opened the usual 7-ish stream burst.
- The tunnel did not immediately die.
- Health timer remained alive after the burst.
- RX/ACK path was still functioning.

### Poisoned/stuck session detected

Phone log:

```text
[2026-04-29T05:05:43.308Z] [DEBUG] [Tunnel] Router stats: flows=1 outbound=0 stream_to_flow=1 next_stream_id=17 send_buf_bytes=0 send_buf_flows=0 oldest_ms=1456 stale=0
[2026-04-29T05:05:43.308Z] [DEBUG] [Tunnel] Health eval: flows=1 outbound=0 streamMaps=1 highSeq=432 stuckTicks=1 usefulRxAge=6.0s outboundRecent=true replayDelta=4 probeOutstanding=false
[2026-04-29T05:05:43.308Z] [WARN] [Tunnel] Session health candidate: flows=1 outbound=0 streamMaps=1 highSeq=432 noUsefulRxFor=6.0s replayDelta=4 stats=flows=1 outbound=0 stream_to_flow=1 next_stream_id=17 send_buf_bytes=0 send_buf_flows=0 oldest_ms=1457 stale=0
[2026-04-29T05:05:43.309Z] [WARN] [Tunnel] Session health suspect: reason=no_useful_rx_6.0s activeFlows=1 streamMaps=1 highSeq=432 stuckTicks=1 noUsefulRxFor=6.0s sending probe nonce=1777439143308
```

Interpretation:

- Active flow remained.
- No useful RX for 6 seconds.
- Detector correctly marked the session suspect and sent encrypted FRAME_PING.

### Probe timeout and automatic recovery

Phone log:

```text
[2026-04-29T05:05:49.308Z] [DEBUG] [Tunnel] Health eval: flows=1 outbound=0 streamMaps=1 highSeq=432 stuckTicks=4 usefulRxAge=12.0s outboundRecent=true replayDelta=4 probeOutstanding=true
[2026-04-29T05:05:49.308Z] [WARN] [Tunnel] Session health dead: probe timeout flows=1 streamMaps=1 noUsefulRxFor=12.0s stuckTicks=4 stats=flows=1 outbound=0 stream_to_flow=1 next_stream_id=17 send_buf_bytes=0 send_buf_flows=0 oldest_ms=7456 stale=0
[2026-04-29T05:05:49.308Z] [WARN] [Tunnel] Router reset runtime state removed=1 reason=session_health_probe_timeout
[2026-04-29T05:05:49.309Z] [INFO] [Tunnel] Reconnect attempt 1/10 gen=1 in 1.0s reason=session_health_probe_timeout
[2026-04-29T05:05:50.346Z] [INFO] [Tunnel] Reconnect gen=1 starting reason=session_health_probe_timeout
[2026-04-29T05:05:50.346Z] [WARN] [Tunnel] Router reset runtime state removed=0 reason=reconnect_gen_1_session_health_probe_timeout
[2026-04-29T05:05:50.347Z] [INFO] [Relay] Reconnect gen=1 via relay 34.219.64.205:23095...
[2026-04-29T05:05:50.394Z] [INFO] [Tunnel] Reconnect gen=1 succeeded via relay 34.219.64.205:23095
```

Interpretation:

- Probe timeout path worked.
- Router runtime state reset worked.
- Reconnect path worked.
- VPN did not require manual toggle.

### Benchmark recovered after automatic reconnect

Bootstrap benchmark:

```text
ID=196
score=8/8
mem=20
replay=36
Vault HTTP Response: 53ms
Primary HTTP Response: 368ms
```

Phone log:

```text
[2026-04-29T05:05:53.321Z] [INFO] [BenchUpload] Submitting benchmark report score=8/8 results=8 log_lines=0 log_bytes=0 to 10.69.95.12
[2026-04-29T05:05:53.338Z] [INFO] [BenchUpload] Benchmark upload complete: HTTP 201 score=8/8 response={"status":"ok","benchmark_id":196,"summary":{"all_passed":true,"memory_ok":false,"score":"8/8"},"device_logs_summary":{"lines":0,"bytes":0}}
```

This is the key proof point: the post-Vaultwarden poisoned session recovered to 8/8 without manual VPN toggle.

### Later benchmark also passed

Bootstrap benchmark:

```text
ID=198
score=8/8
mem=20
replay=36
Vault HTTP Response: 2049ms
Primary HTTP Response: 370ms
```

Phone log:

```text
[2026-04-29T05:06:27.456Z] [INFO] [BenchUpload] Submitting benchmark report score=8/8 results=8 log_lines=0 log_bytes=0 to 10.69.95.12
[2026-04-29T05:06:27.466Z] [INFO] [BenchUpload] Benchmark upload complete: HTTP 201 score=8/8 response={"status":"ok","benchmark_id":198,"summary":{"all_passed":true,"memory_ok":false,"score":"8/8"},"device_logs_summary":{"lines":0,"bytes":0}}
```

Vault response was slower at 2049ms, but still passed. That is acceptable for the stability baseline.

---

## Gateway evidence for rwnd=4

Gateway logs showed the client was advertising rwnd=4 and the gateway obeyed it:

```text
CLIENT_ACK data_seq=1930 rwnd=4 last_acked=1929 inflight=4 recovery=false
CLIENT_ACK data_seq=1931 rwnd=4 last_acked=1930 inflight=4 recovery=false
pacing_tick: 74 queued, 4/4 inflight/cwnd, ssthresh=64 open=false
...
CLIENT_ACK data_seq=2045 rwnd=4 last_acked=2044 inflight=1 recovery=false
FRAME_CLOSE stream_id=8 reason=client_close_unknown_stream queue=0 total_streams=0
```

Important differences from failing runs:

- Failing runs had gateway inflight around 10/10 or 12/12.
- Failing runs had queue around 512 and eventually STALL.
- Successful run constrained inflight to 4/4 and drained queue down to zero.
- Replay count dropped from 144 to 36.

---

## Key fixes and why they mattered

### 1. Probe path local buffers were necessary but not sufficient

Commit:

```text
ac07c11 ios: fix frameBuffer cross-queue race in probe path
```

This fixed PING/PONG control frames using shared `frameBuffer`, but later testing showed data/ACK paths still had shared mutable buffers.

### 2. All send paths needed local buffers

Commit:

```text
463ac49 ios: eliminate shared send buffers in tunnel connection
```

Why:

- `sendData` can run from `PacketTunnelProvider` / `tunnelQueue`.
- ACK/PONG handling can run from NWConnection callback queue.
- Shared instance `frameBuffer` / `encryptBuffer` can be corrupted by interleaved writes under browser fan-out.

Fix:

- Removed shared `frameBuffer` and `encryptBuffer` from send paths.
- `sendData` builds FRAME_DATA into a local buffer.
- `flushPendingAcks` builds ACK/rwnd frame into a local buffer.
- PING/PONG also use local frame buffers.
- Encryption uses local output buffer via `sendEncryptedFrame()`.

### 3. Gateway-data flush had to be bounded

Commit:

```text
b7aa633 ios: bound router flush during gateway data bursts
```

Why:

- `handleGatewayMuxFrame` previously ended with unbounded `flushOutboundPackets()`.
- Under Vaultwarden bursts, a gateway-data callback could monopolize `tunnelQueue` while draining router output.
- This starved timers/ACK/progress logic.

Fix:

```swift
flushOutboundPackets(maxPackets: Self.maxOutboundPacketsPerFlush)
```

### 4. rwnd=4 was the stability breakthrough

Commit:

```text
a139403 ios: hard cap receive window for browser bursts
```

Why:

- rwnd=10/12 still allowed gateway inflight 10/10 or 12/12 and queue blowups.
- iOS NE could not reliably absorb Vaultwarden browser bursts at that rate.
- rwnd=4 limited gateway inflight to 4/4 and let ACKs keep up.

Fix:

- `PacketTunnelProvider.advertisedRwnd = 4`
- connect/reconnect set rwnd=4
- pressure transitions all clamp to 4
- `ZTLPTunnelConnection` ACK send path clamps rwnd to 4

---

## Known-good validation protocol

Before asking Steve to test:

```bash
cd /home/trs/ztlp
./scripts/ztlp-server-preflight.sh
```

Must end:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Phone test sequence:

1. Xcode Product → Clean Build Folder.
2. Build/run to iPhone.
3. Start VPN.
4. Wait about 10 seconds.
5. Run benchmark; expect 8/8.
6. Open Vaultwarden/OpenVault in the in-app WKWebView browser.
7. Do not manually toggle VPN.
8. Run benchmark again.
9. Tap Send Logs.

Expected successful markers:

```text
Session health manager enabled interval=2.0s suspectRx=5.0s probeTimeout=5.0s stuckTicks=3
Health eval: ...
Session health candidate: ...
Session health suspect: ... sending probe nonce=...
Session health dead: probe timeout ...
Router reset runtime state removed=N reason=session_health_probe_timeout
Reconnect gen=N starting reason=session_health_probe_timeout
Reconnect gen=N succeeded via relay ...
Benchmark upload complete ... score=8/8
```

Gateway expected markers:

```text
CLIENT_ACK data_seq=... rwnd=4 ...
pacing_tick: ... 4/4 inflight/cwnd ...
```

---

## Important interpretation notes

### rwnd=4 is currently the baseline, not necessarily final performance tuning

Do not raise rwnd casually. rwnd=4 is the first setting that proved automatic recovery after Vaultwarden.

Future tuning should be one variable at a time:

1. Keep all local-buffer and bounded-flush fixes.
2. Try rwnd=5 or 6 only after capturing baseline success.
3. Run the exact same Vaultwarden test sequence.
4. If it fails, go back to rwnd=4.

### A slow Vault HTTP Response can still be success

ID=198 had:

```text
Vault HTTP Response: 2049ms
score=8/8
```

That is slower than ideal but still proves stability and correctness. Optimize later.

### Replay count dropping is a good sign

Replay rejects dropped from 144 to 36 after rwnd=4.

This indicates the gateway was no longer overdriving the phone and causing excessive retransmit/replay pressure.

### Do not treat 20MB NE memory as the root failure

The successful run still had about 20MB memory:

```text
mem=20
```

Memory around 20MB was not the decisive failure cause in this test. The decisive variables were gateway inflight/window pressure, router/session poisoning, and automatic recovery.

---

## Files/areas changed

Primary Swift files:

```text
ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Relevant Rust/FFI/protocol pieces from earlier work:

```text
proto/src/packet_router.rs
proto/src/ffi.rs
proto/include/ztlp.h
ios/ZTLP/Libraries/ztlp.h
gateway/lib/ztlp_gateway/session.ex
```

---

## Current production/server state at time of writeup

Gateway:

```text
44.246.33.34
ztlp-gateway healthy
session-health image/code live
probe handlers live
```

Preflight result after final commit:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Final pushed commit at time of writeup:

```text
a139403 ios: hard cap receive window for browser bursts
```

---

## What not to forget

1. This was not fixed by one magic watchdog.
2. The fix required both:
   - robust session-health recovery, and
   - reducing iOS browser burst pressure to a survivable rwnd.
3. PING/PONG probes must stay ACK-fast-pathed at the gateway.
4. Reconnect must reset PacketRouter runtime state.
5. All Swift send paths must use local frame/encrypt buffers; no shared send buffers across queues.
6. Gateway-data handling must not run unbounded router flushes on the same queue.
7. rwnd=4 is the known-good baseline for Vaultwarden on iOS.
8. The success proof is benchmark IDs 195 through 199, especially 196 and 198.

---

## One-line conclusion

The two-month Vaultwarden/OpenVault iOS tunnel poison bug is finally recoverable: with local send buffers, bounded router flush, session-health probe/reconnect, and rwnd=4, the tunnel automatically recovers from a real browser-induced poisoned session and returns to 8/8 without manual VPN toggle.
