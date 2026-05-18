# ZTLP iOS / OpenVault Handoff — 2026-04-29 — Next: rwnd=12

## Context

Steve has been testing ZTLP iOS in-app OpenVault / Vaultwarden. The major symptom evolved:

1. Earlier: Vaultwarden/OpenVault partially loaded, then VPN/Network Extension crashed/restarted.
2. After gateway shallow queue + low rwnd: VPN stopped crashing but page/benchmark hung or became very slow.
3. After removing hot-path NE logging: crash pressure improved; rwnd=8 no longer immediately crashed, but gateway still stalled.
4. Steve asked to try rwnd=16 again with logging fixed. It still “kinda crashed”. Next requested step: try rwnd=12 in a fresh session.

This file captures the current state so the next session can continue without rediscovery.

## Current important repo state

Local repo:

```text
/home/trs/ztlp
```

Mac Xcode repo:

```text
stevenprice@10.78.72.234:~/ztlp
```

Important: iOS builds/deploys use Steve’s Mac repo `~/ztlp`, not `~/code/ztlp`.

Current local uncommitted files include at least:

```text
proto/src/packet_router.rs
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
```

Plus handoff markdown files.

## Server-side state

Gateway deployed during this work:

```text
Gateway host: 44.246.33.34
Container: ztlp-gateway
Image: ztlp-gateway:shallow-queue-fc6b421
```

Preflight was green after the latest build check:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Latest preflight notes:

- NS healthy
- Relay healthy
- Gateway healthy
- No backend econnrefused in recent gateway logs
- No send_queue overload rejections in recent gateway logs
- Gateway actively completing handshake step msg2
- recurring benign warning: `WARN Did not see relay seeding in recent NS logs`

Steve gave permission to restart gateway/relay/NS if needed, but no server restart was required for the last changes. Still tell Steve before restarting because restarting gateway kills phone sessions.

## What changed this session

### 1. PacketRouter hidden backlog/starvation fix

File:

```text
proto/src/packet_router.rs
```

Root cause found:

The earlier Safari/Vaultwarden fix stopped silently dropping packets when the PacketRouter outbound queue filled by spilling extra bytes into per-flow `send_buf`. But iOS uses the one-packet FFI path:

```text
Swift flushOutboundPackets()
  -> ztlp_router_read_packet_sync()
  -> PacketRouter.pop_outbound()
```

`pop_outbound()` only popped `self.outbound` and did not re-drain per-flow `send_buf`. So when `outbound` reached zero but a flow still had `send_buf` data, the browser/benchmark could hang forever while VPN stayed connected.

Patch:

```rust
pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
    if self.outbound.is_empty() {
        self.drain_flow_send_buffers();
    }
    self.outbound.pop_front()
}
```

Regression test added:

```rust
test_router_pop_outbound_refills_from_flow_send_buf
```

Test passed on local Linux and Mac:

```text
cargo test packet_router::tests::test_router_pop_outbound_refills_from_flow_send_buf --lib
1 passed
```

### 2. Hot-path Network Extension logging removed / summarized

Files:

```text
ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Removed per-packet logs from hot paths:

- `ZTLP RX data seq=...`
- `ZTLP ACK sent seq=...`
- `GW->NE mux DATA stream=...`
- `Router: SendData stream=...`
- `Router: OpenStream stream=...`
- `Router: CloseStream stream=...`
- replay reject debug every 10 packets
- `readPacketLoop: received N packet(s)`

Added rate-limited summaries:

```text
ZTLP RX summary packets=... payload=...B acks=... replay=... highSeq=... inflight=...
Mux summary gwData=.../...B open=... close=... send=.../...B
```

These emit about once/sec during traffic instead of multiple disk-backed log lines per packet.

Why this matters:

Previous iOS syslog showed a CPU wakeup violation:

```text
process ZTLPTunnel[...] caught waking the CPU 45001 times over ~225 seconds,
averaging 199 wakes / second and violating a limit of 45000 wakes over 300 seconds
```

Per-packet TunnelLogger writes in an NE can recreate that pressure under Vaultwarden bursts.

### 3. rwnd experiments

#### rwnd=8 with logging fixed

Observed after deploying logging fix + rwnd=8:

Phone log shrank dramatically (only ~15 useful lines), proving hot-path logging was removed. It did not immediately crash in the visible phone log.

Phone examples:

```text
Mux summary ...
Router stats: flows=... outbound=0 ...
Memory resident=20.6MB
```

Gateway still stalled:

```text
pacing_tick: 368 queued, 8/8 inflight/cwnd, open=false
STALL: no ACK advance for 30s inflight=8 last_acked=1721 recv_base=1471 queue=368 backends_paused=true streams=[1:vault,2:vault]
```

Interpretation:

- Logging fix gave the NE more breathing room.
- But at rwnd=8, transport can still stall / page does not complete.
- Crash pressure improved, but ACK progress still stops.

#### rwnd=16 with logging fixed

Steve asked to try 16 again after log fix.

On Mac, `PacketTunnelProvider.swift` was changed to:

```swift
private var advertisedRwnd: UInt16 = 16
...
router flush saturated -> 8
router flush full -> 12
router drained -> 16
router partial drain -> 12
clamp max -> 16
```

Unsigned Xcode build succeeded and preflight was green.

Steve then reported:

```text
it kida crash at 16 lets try 12
```

So next step is rwnd=12.

## Next requested action: set rwnd cap to 12

In the next session, patch Steve’s Mac repo `~/ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` and likely local repo too, changing current rwnd=16 experiment to rwnd=12.

Recommended rwnd=12 behavior:

```swift
private var advertisedRwnd: UInt16 = 12

// in flushOutboundPackets pressure logic:
consecutiveFullFlushes >= 2 -> updateAdvertisedRwnd(8, reason: "router flush saturated")
first full flush             -> updateAdvertisedRwnd(10 or 12, reason: "router flush full")
drained                      -> updateAdvertisedRwnd(12, reason: "router drained")
partial drain                -> updateAdvertisedRwnd(10, reason: "router partial drain")

// clamp:
let clamped = max(UInt16(4), min(UInt16(12), rwnd))
```

Safer exact values suggested:

- max/drained: 12
- partial drain: 10
- full flush: 8 or 10
- saturated: 8

If Steve specifically wants simple “cap 12”, use:

```swift
private var advertisedRwnd: UInt16 = 12
...
updateAdvertisedRwnd(8, reason: "router flush saturated")
updateAdvertisedRwnd(10, reason: "router flush full")
updateAdvertisedRwnd(12, reason: "router drained")
updateAdvertisedRwnd(10, reason: "router partial drain")
let clamped = max(UInt16(4), min(UInt16(12), rwnd))
```

## Mac build commands used successfully

After Swift-only rwnd/log changes, Rust library rebuild is NOT needed unless `proto/src/packet_router.rs` changes again. The PacketRouter Rust fix was already built into `libztlp_proto_ne.a` during the prior Mac rebuild.

For Swift-only rwnd=12 change, run unsigned Xcode check:

```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp/ios/ZTLP && xcodebuild -project ZTLP.xcodeproj -scheme ZTLP -destination "generic/platform=iOS" -configuration Release build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO'
```

Expected:

```text
** BUILD SUCCEEDED **
```

Warnings about `withCString` unused result and iOS 18.5 object files linked to iOS 16 target are existing/build-hygiene warnings, not blockers.

Then run preflight before asking Steve to test:

```bash
~/ztlp/scripts/ztlp-server-preflight.sh
```

Expected:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Steve must deploy from Xcode GUI due to signing/keychain limitations:

1. Open `/Users/stevenprice/ztlp/ios/ZTLP/ZTLP.xcodeproj`
2. Product -> Clean Build Folder
3. Build/run to iPhone

## Verification commands after Steve deploys/tests

### Pull phone app-group log

```bash
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone-rwnd12.log >/dev/null && \
  wc -l /tmp/ztlp-phone-rwnd12.log && \
  grep -E "Build:|VPN status|ZTLP RX summary|Mux summary|Advertised rwnd|Router stats|Memory resident|Tunnel connection failed|Reconnect|BenchUpload|Benchmark|TIMEOUT|PASS|FAIL|error|failed" /tmp/ztlp-phone-rwnd12.log | tail -260'
```

Expected after log fix:

- No per-packet spam (`ZTLP RX data seq`, `ACK sent`, `GW->NE mux DATA stream`) should appear.
- Summaries should appear instead.
- New build timestamp should be newer than the prior 02:38 / 02:50 builds.
- `Advertised rwnd=12` or `10` / `8` transitions should appear depending on pressure.

### Gateway logs

```bash
test -f /tmp/gw_key.pem || (ssh trs@10.69.95.12 "docker exec -w /rails bootstrap_web_1 bin/rails runner 'puts Machine.find(8).ssh_private_key_ciphertext'" 2>/dev/null | grep -v WARN > /tmp/gw_key.pem && chmod 600 /tmp/gw_key.pem)
ssh -i /tmp/gw_key.pem ubuntu@44.246.33.34 "docker logs --since 12m ztlp-gateway 2>&1 | grep -E 'CLIENT_ACK.*rwnd|pacing_tick|STALL|Backpressure|send_queue|FRAME_OPEN|FRAME_CLOSE|Stream [0-9]+|ACK_LATENCY|RTO' | tail -260"
```

Look for:

- `CLIENT_ACK ... rwnd=12` / `rwnd=10` / `rwnd=8`
- Queue should ideally remain hundreds, not thousands.
- No `send_queue already overloaded`.
- No major `STALL: no ACK advance` on the main vault mux session.
- Tiny legacy stalls with `last_acked=3 queue=0 streams=[]` are less important.

### Bootstrap benchmark uploads

```bash
ssh trs@10.69.95.12 "docker exec -w /rails bootstrap_web_1 bin/rails runner '
BenchmarkResult.order(created_at: :desc).limit(10).each do |b|
  logs=b.device_logs.to_s
  puts ["ID=#{b.id}", b.created_at.utc.iso8601, "score=#{b.benchmarks_passed}/#{b.benchmarks_total}", "mem=#{b.ne_memory_mb.inspect}", "err=#{b.error_details.to_s[0,100]}", "logs=#{logs.lines.count}/#{logs.bytesize}", "replay=#{b.replay_reject_count.inspect}"].join(" | ")
end
'"
```

## Important observations from latest tests

### After log fix, phone log was tiny

Example after log fix:

```text
15 /tmp/ztlp-phone-postlogfix.log
Mux summary ...
Router stats ...
Memory resident=20.6MB
```

This confirmed per-packet logging was removed and the log-churn/wakeup issue was reduced.

### Gateway still showed stall at rwnd=8

```text
STALL: no ACK advance for 30s inflight=8 last_acked=1721 recv_base=1471 queue=368 backends_paused=true streams=[1:vault,2:vault]
```

### rwnd=16 still too aggressive

Steve reported rwnd=16 “kinda crash” even after logging fix.

## Working hypothesis for next debugging

The system is no longer primarily dying from log spam; log pressure was reduced. The remaining issue is gateway send/ACK progress under browser fan-out:

- Gateway can respect rwnd, but still reaches `inflight=cwnd/rwnd` and waits for ACKs that stop advancing.
- Browser fan-out / multiple streams leaves gateway queue in hundreds.
- iOS receives and ACKs a lot of data, then either the NE disappears or ACK progress stops.

The rwnd=12 test is to find whether there is a middle ground between:

- rwnd=8: stable-ish but stalls/slow
- rwnd=16: faster but crash-prone

If rwnd=12 still stalls/crashes, next likely direction is not just window size; investigate:

1. Gateway stream scheduling / fairness — avoid one/two vault streams dominating queue.
2. ACK progress vs recv_base mismatch — in one stall, `last_acked=1721 recv_base=1471` looked odd and should be inspected.
3. Gateway pacing log spam itself is huge; may need to reduce gateway debug logs but this is server-side only.
4. Phone ACK path under heavy inbound: even with summary logging, confirm ACKs continue leaving via NWConnection when gateway stalls.
5. Consider gateway sending smaller per-stream bursts or fair queue round-robin across mux streams.

## Safety rules/reminders

- Do not restart gateway/relay/NS without telling Steve first, even though he gave permission.
- Before asking Steve to test after any server-side change, run `~/ztlp/scripts/ztlp-server-preflight.sh` and require PRECHECK GREEN.
- For iOS changes, edit/build Mac repo `~/ztlp`.
- For Swift-only rwnd/log tuning, no Rust rebuild needed.
- If changing `proto/src/packet_router.rs` again, rebuild both iOS libs using the dual-lib workflow and separate `target-ios-sync`.
