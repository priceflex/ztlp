# ZTLP iOS / OpenVault Stability + Performance Handoff — 2026-04-29

## Context

Steve was testing the ZTLP iOS app with the in-app OpenVault / Vaultwarden path. The initial symptom was that opening Vaultwarden through the ZTLP tunnel would partially load, then the VPN/Network Extension would detach/restart or appear to crash. After stabilizing that, the remaining symptom is slow page load / browser stream churn.

This handoff captures everything learned in this session so a new agent/session can continue without re-discovering it.

## Current repo / deployment state

Local repo:

```text
/home/trs/ztlp
HEAD: d4bc5d9 tune: raise iOS rwnd cap to 16
```

Untracked handoff from prior session still exists:

```text
/home/trs/ztlp/ZTLP-IOS-RESTART-HANDOFF-2026-04-28.md
```

New handoff file:

```text
/home/trs/ztlp/ZTLP-IOS-OPENVAULT-HANDOFF-2026-04-29.md
```

Mac repo:

```text
stevenprice@10.78.72.234:~/ztlp
```

Mac `~/ztlp` was pulled to current main and Xcode unsigned build succeeded at commit `d4bc5d9`.

Gateway currently deployed:

```text
Gateway host: 44.246.33.34
Docker image: ztlp-gateway:shallow-queue-fc6b421
Container: ztlp-gateway
Status: healthy during last check
```

Preflight after deploying gateway image `shallow-queue-fc6b421` was green:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Gateway old container may still exist stopped as `ztlp-gateway-old`.

## Important infrastructure access

- Mac: `ssh stevenprice@10.78.72.234`
- iPhone device identifier: `39659E7B-0554-518C-94B1-094391466C12`
- Bootstrap: `trs@10.69.95.12`, Rails container `bootstrap_web_1`, app root `/rails`
- Gateway: `ubuntu@44.246.33.34`, SSH key extracted to `/tmp/gw_key.pem` in this session
- Relay: `34.219.64.205`, private `172.26.5.220`, port 23095
- NS: `34.217.62.46`, private `172.26.13.85`, port 23096

If `/tmp/gw_key.pem` is missing, extract it from bootstrap:

```bash
ssh trs@10.69.95.12 "docker exec -w /rails bootstrap_web_1 bin/rails runner 'puts Machine.find(8).ssh_private_key_ciphertext'" 2>/dev/null | grep -v WARN > /tmp/gw_key.pem
chmod 600 /tmp/gw_key.pem
```

## Key files changed this session

### iOS

```text
ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

### Gateway

```text
gateway/lib/ztlp_gateway/session.ex
```

## Commits made in this session

### d05132c — quiesce iOS wakeups and add rwnd ACKs

```text
fix: quiesce iOS tunnel wakeups and add rwnd ACKs
```

Main points:

- Disabled the always-on 5ms packet flush timer in `PacketTunnelProvider`.
- Disabled the always-on 10ms ACK flush timer.
- Made flush demand-driven from receive paths.
- Rate-limited memory diagnostics / shared defaults churn.
- Removed/noised-down misleading memory warnings.
- Added reconnect generation/idempotency guardrails.
- Added Rust FFI `ztlp_build_ack_with_rwnd` and gateway 11-byte ACK handling.
- Gateway `session.ex` now supports ACK format:

```text
[FRAME_ACK | ack_seq(8) | rwnd(2)]
```

- Gateway uses `peer_rwnd` in effective send window:

```elixir
effective_window = min(min(trunc(state.cwnd), cc_max_cwnd(state)), Map.get(state, :peer_rwnd, @default_peer_rwnd))
```

### 3309bcb — static iOS rwnd=64 cap

```text
fix: cap iOS advertised receive window
```

- Capped phone-advertised rwnd from 512 to 64.
- Result: deployed and tested. Phone still crashed / VPN restarted under OpenVault.
- Gateway showed `CLIENT_ACK ... rwnd=64`, but queues still grew and NE disconnected.

### 645667e — dynamic rwnd from router pressure

```text
fix: make iOS rwnd respond to router pressure
```

- Added `PacketTunnelProvider` dynamic advertised window based on router flush pressure.
- Rwnd transitions:
  - drained → 64
  - partial drain → 32
  - full flush → 16
  - repeated full flush → 8
- Result: still crashed / VPN restarted. The pressure signal arrived too late; gateway had already enqueued too much.

### 0b31cf9 — hard cap iOS rwnd=8

```text
fix: hard cap iOS rwnd for browser loads
```

- Hard capped iOS rwnd at 8.
- Result: **important improvement** — OpenVault stopped crashing / VPN stopped restarting.
- But it became very slow. Gateway was stable at `8/8 inflight/cwnd`, but page assets took too long and browser kept closing/retrying streams.

### 1f45a37 + fc6b421 — gateway shallow queue

```text
fix: keep gateway send queue shallow for mobile
fix: group gateway handle_info clauses
```

- Gateway queue thresholds changed:

```elixir
@queue_high 512
@queue_low 128
```

- Before: queue could grow to 6000+ packets during Vaultwarden page load.
- After: queue stayed around ~150 in latest logs.
- Removed active mux stream rejection by disabling this branch:

```elixir
false and queue_len >= @queue_high -> reject_mux_stream(...)
```

- Added bounded stream enqueue helper:

```elixir
defp enqueue_stream_chunks(send_queue, stream_id, chunks) do
  Enum.reduce_while(chunks, send_queue, fn chunk, q ->
    if :queue.len(q) >= @queue_high do
      {:halt, q}
    else
      {:cont, :queue.in({:stream, stream_id, chunk}, q)}
    end
  end)
end
```

- Used it in both mux response enqueue paths (`{:tcp, socket, data}` TLS bridge path and plain `{:backend_data, stream_id, data}` path).
- Docker build initially failed because helper was inserted between `handle_info/2` clauses, causing `--warnings-as-errors` failure. Fixed by moving helper near `open_mux_stream`, after the grouped `handle_info` clauses.
- Built and deployed image:

```text
ztlp-gateway:shallow-queue-fc6b421
```

### d4bc5d9 — rwnd cap raised to 16

```text
tune: raise iOS rwnd cap to 16
```

- Raised phone rwnd cap from 8 to 16 after gateway queue was made shallow.
- Phone behavior now:
  - starts at rwnd 16
  - router partial/full pressure can drop to 12 / 8
- Xcode unsigned build succeeded on Mac.
- Latest logs show phone running build at `2026-04-29 01:38:36 +0000` with:

```text
Advertised rwnd=12 reason=router partial drain
Advertised rwnd=16 reason=router drained
```

## Testing timeline and findings

### Initial after d05132c gateway deploy

Gateway image `rwnd-ack-d05132c` deployed. This verified the server understands new 11-byte ACKs.

Before deploy gateway logs showed:

```text
CLIENT_ACK ... sack_count=2
```

After deploy gateway logs showed:

```text
CLIENT_ACK data_seq=N rwnd=512 ...
```

So the 11-byte ACK handler was live.

But with phone advertising `rwnd=512`, OpenVault still crashed / VPN restarted. Gateway queue exploded:

```text
Backpressure ON: pausing backend reads (queue=2049)
pacing_tick: 8870 queued, 23/16 inflight/cwnd, open=false
STALL: no ACK advance for 30s ... queue=8870 ... streams=[1..5 vault connected]
```

### Static rwnd=64

Phone advertised:

```text
CLIENT_ACK ... rwnd=64
```

Still crashed. Gateway still queued thousands of packets and rejected streams.

### Dynamic rwnd

Phone logged:

```text
Advertised rwnd=32 reason=router partial drain
```

Still crashed. Signal arrived too late.

### Static rwnd=8

This was the first stable point.

Phone did not crash; no `VPN status changed: 5 -> 1` during OpenVault. Gateway showed:

```text
CLIENT_ACK ... rwnd=8
pacing_tick: 6195 queued, 8/8 inflight/cwnd, open=false
```

So stability was achieved, but too slow. Browser closed/retried streams and gateway eventually hit a mux-session stall after 30s with queue ~163.

### Gateway shallow queue + rwnd=8

After deploying gateway image `shallow-queue-fc6b421`, queue stayed shallow:

```text
pacing_tick: 163 queued, 8/8 inflight/cwnd, open=false
```

No big queue explosion, no send_queue overload rejections. But page remained slow due to 8-packet window.

### Gateway shallow queue + rwnd=16

Phone log after latest build showed:

```text
Build: 2026-04-29 01:38:36 +0000
Advertised rwnd=12 reason=router partial drain
Advertised rwnd=16 reason=router drained
```

Phone did not show crash/reconnect after this latest build during the log window checked. Memory around 20MB.

Gateway logs for the latest 01:38 test were sparse; likely because it happened near the boundary of queried windows or log volume. No fresh big mux failure or send_queue overload was seen. Later gateway STALLs were tiny legacy/auxiliary sessions only:

```text
STALL ... inflight=1 last_acked=3 queue=0 streams=[]
```

Those are not the main OpenVault mux session.

## Most important conclusions

1. The original crash was caused by gateway flooding the iOS NE/browser path with too much Vaultwarden response data.
2. The new ACK format works; gateway now reads `rwnd` correctly.
3. `rwnd=512` and `rwnd=64` are too aggressive and crash/restart the NE under OpenVault.
4. Dynamic rwnd based on router flush pressure was too late to prevent the first burst.
5. `rwnd=8` is stable but too slow.
6. Gateway queue must stay shallow. `@queue_high=512`, `@queue_low=128`, and bounded stream enqueue prevent 6K+ queue blowups.
7. `rwnd=16` is the current test point after shallow queue. It appears stable in the short log window, but needs deliberate retesting and gateway log verification.
8. Remaining symptoms are now performance/browser retry churn, not NE crash.

## Current expected state for next test

- Phone should be on commit `d4bc5d9` if Steve deployed after the last Xcode build.
- Gateway should be `ztlp-gateway:shallow-queue-fc6b421`.
- During OpenVault, expect gateway ACK lines like:

```text
CLIENT_ACK ... rwnd=16
```

or under pressure:

```text
CLIENT_ACK ... rwnd=12
CLIENT_ACK ... rwnd=8
```

- Queue should remain around hundreds, not thousands.
- No `send_queue already overloaded` should appear.
- No `VPN status changed: 5` / `1` should appear unless Steve manually disconnects/stops the tunnel.

## Commands for next session

### Pull app-group phone log

```bash
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone-latest.log && \
  wc -l /tmp/ztlp-phone-latest.log && \
  grep -E "Build:|Idle quiesce|Advertised rwnd|VPN status|Tunnel connection failure|Reconnect|OpenStream|CloseStream|SendData|ZTLP RX|ACK sent|replay rejected|Memory resident|Router stats|BenchUpload|Manual|error|failed|TIMEOUT|PASS|FAIL" /tmp/ztlp-phone-latest.log | tail -260'
```

### Query recent bootstrap benchmark uploads

```bash
ssh trs@10.69.95.12 "docker exec -w /rails bootstrap_web_1 bin/rails runner '
BenchmarkResult.order(created_at: :desc).limit(8).each do |b|
  logs=b.device_logs.to_s
  puts ["ID=#{b.id}", b.created_at.utc.iso8601, "score=#{b.benchmarks_passed}/#{b.benchmarks_total}", "mem=#{b.ne_memory_mb.inspect}", "err=#{b.error_details.to_s[0,80]}", "logs=#{logs.lines.count}/#{logs.bytesize}", "replay=#{b.replay_reject_count.inspect}"].join(" | ")
end
'"
```

### Check gateway logs for OpenVault run

```bash
ssh -i /tmp/gw_key.pem ubuntu@44.246.33.34 "docker logs --since 5m ztlp-gateway 2>&1 | \
  grep -E 'CLIENT_ACK.*rwnd|FRAME_OPEN|FRAME_CLOSE|Stream [0-9]+|Backpressure|send_queue|STALL|pacing_tick' | tail -250"
```

### Check gateway container

```bash
ssh -i /tmp/gw_key.pem ubuntu@44.246.33.34 "docker ps --filter name=ztlp-gateway --format '{{.Names}} {{.Image}} {{.Status}}'"
```

Expected:

```text
ztlp-gateway ztlp-gateway:shallow-queue-fc6b421 Up ... healthy
```

### Run server preflight

```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

Expected currently:

```text
PRECHECK GREEN
```

Only recurring benign warning:

```text
WARN Did not see relay seeding in recent NS logs
```

## If continuing tuning

Current best next steps depend on Steve’s observed behavior:

### If rwnd=16 is stable but still slow

Consider small throughput tuning:

1. Raise gateway queue slightly:

```elixir
@queue_high 768
@queue_low 192
```

2. Or adjust gateway pacing slightly:

```elixir
@pacing_interval_ms 3
```

Do only one change at a time. Do not restart gateway while Steve is testing unless he explicitly says okay.

### If rwnd=16 crashes

Revert phone-side cap to 8 and focus on gateway stream scheduling rather than increasing throughput.

Likely gateway-side next idea:

- Defer new mux stream backend reads when queue is high instead of letting browser churn open/close.
- Implement per-stream fair queue or per-stream response chunk budget so one asset cannot dominate send_queue.
- Avoid closing/rejecting streams based only on queue high.

### If logs show replay rejects remain high

High replay rejects are likely from RTO/retransmits under slow cwnd/rwnd. Consider mobile RTO tuning:

- Current gateway RTO profile often starts at 300/min 100.
- Slow mobile/browser path may need higher initial/min RTO to avoid duplicate retransmits after original packets arrive late.
- Prior knowledge suggests mobile RTO initial around 1500ms, min 500ms may reduce replay noise.

Be careful: changing RTO can affect benchmark behavior; test deliberately.

## Important safety rules

- Do NOT restart gateway/relay/NS without telling Steve first. Restarting gateway kills active phone sessions.
- Before asking Steve to test after server changes, run:

```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

- For iOS changes, Steve must deploy from Xcode GUI. SSH compile-check works, but signing/device install needs Xcode/keychain.
- For iOS work, edit/build from Mac repo `~/ztlp`, not `~/code/ztlp`.
- No Rust library rebuild is needed for Swift-only changes. Rebuild Rust libs only after changing Rust/FFI.

## Latest subjective state

Steve reported after gateway shallow queue + rwnd=8:

```text
it didn't crash ... very slow though
```

After rwnd=16 patch, Steve asked “can you see if it’s working”; logs showed the new build and no crash in observed window, but further deliberate testing is needed to judge page completeness and speed.
