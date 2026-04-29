# ZTLP iOS Next Focus — Stuck Flow Cleanup After CloseStream Suppression

Date: 2026-04-29
Repo: `/home/trs/ztlp`
Mac Xcode repo: `~/ztlp` on `stevenprice@10.78.72.234`
Current validated commit: `0b0367c ios: bridge close suppression markers to app log`

## Bottom line

Stop chasing duplicate CloseStream as the primary issue. The close suppression path is now proven live on-device and is actively suppressing stale/duplicate CloseStream callbacks before Swift sees them.

The next focused problem is:

> Probe succeeds, but PacketRouter still has suspect active flows, so session-health repeatedly resets router state and benchmark loses one request.

This is now a PacketRouter flow lifecycle / stuck-flow cleanup problem, not a stale build problem and not a dead transport problem.

## What was validated

### Server side

After restarting gateway/relay/NS, `/home/trs/ztlp/scripts/ztlp-server-preflight.sh` returned:

```text
PRECHECK GREEN server-side stack is ready for phone testing
warnings=0 failures=0
```

Restarted components:
- Gateway: `44.246.33.34`, container `ztlp-gateway`, image `ztlp-gateway:session-health`
- Relay: `34.219.64.205`, container `ztlp-relay`, image `ztlp-relay:vip`
- NS: `34.217.62.46`, container `ztlp-ns`, image `ztlp-ns:signed-relay`

NS startup seeder ran successfully after restart:

```text
[ztlp-ns] Seeded relay: techrockstars -> 34.219.64.205:23095 (us-west-2, healthy)
[ztlp-ns] Relay seeder: seeded 1 records, 0 errors
```

### iOS build/deploy state

Commit `0b0367c` was pulled to Mac `~/ztlp` and the NE lib was rebuilt with:

```bash
ZTLP_GIT_COMMIT=0b0367c cargo build --manifest-path proto/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib \
  --no-default-features --features ios-sync \
  --target-dir proto/target-ios-sync
cp proto/target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a ios/ZTLP/Libraries/libztlp_proto_ne.a
cp proto/include/ztlp.h ios/ZTLP/Libraries/ztlp.h
```

Verified strings in `libztlp_proto_ne.a` contained:

```text
0b0367c
Rust fd read loop startup
close_suppression_v3
```

Unsigned Xcode build succeeded:

```text
CLEAN SUCCEEDED
BUILD SUCCEEDED
```

### Phone log evidence

Pulled app-group log:

```text
/tmp/ztlp-phone-v3.log
2131 lines, 352441 bytes
```

Latest app/tunnel processes after rebuild/deploy:

```text
ZTLP pid 36678
ZTLPTunnel pid 36682
```

New app bundle path confirmed rebuild/redeploy happened:

```text
/private/var/containers/Bundle/Application/1F036482-CD69-436C-8193-8F23101DD7AD/ZTLP.app/...
```

Startup marker appeared in app-group log, proving the rebuilt Rust NE lib is running on-device:

```text
[2026-04-29T09:43:15.273Z] [DEBUG] [Tunnel] Rust fd ingress diag count=1 Rust fd read loop startup mode=router_ingress close_suppression_enabled=1 version=0.24.0 git=0b0367c marker=close_suppression_v3
```

Close suppression is actively firing:

```text
[2026-04-29T09:43:24.256Z] [DEBUG] [Tunnel] Rust fd dispatch pre action_count=1 action_written=7 close_suppression_enabled=1 marker=close_suppression_v3
[2026-04-29T09:43:24.256Z] [DEBUG] [Tunnel] Rust fd dispatch post actions=0 open=0 send=0 close=0 suppressed_close=1 unknown=0 payload_bytes=0 action_bytes=7 close_suppression_enabled=1 marker=close_suppression_v3
```

Multiple `suppressed_close=1` events were seen:

```text
09:43:24.256 suppressed_close=1
09:43:24.257 suppressed_close=1
09:43:24.257 suppressed_close=1
09:43:26.894 suppressed_close=1
09:43:27.003 suppressed_close=1
09:43:27.059 suppressed_close=1
09:43:27.060 suppressed_close=1
09:43:35.933 suppressed_close=1
```

## Latest benchmark result

Latest benchmark:

```text
benchmark_id=254
score=7/8
```

Representative failures:

```text
[2026-04-29T09:43:45.923Z] HTTP benchmark GET failed url=http://10.122.0.2/ ms=10011 error=The request timed out.
[2026-04-29T09:43:56.957Z] HTTP benchmark GET failed url=http://10.122.0.2/ ms=10002 error=The request timed out.
[2026-04-29T09:44:07.975Z] HTTP benchmark GET failed url=http://10.122.0.2/ ms=10002 error=The request timed out.
```

## Current failure pattern

Transport liveness is good. Probes respond:

```text
[2026-04-29T09:43:45.277Z] Session health suspect: reason=no_useful_rx_5.2s activeFlows=2 streamMaps=2 highSeq=1383 stuckTicks=1 noUsefulRxFor=5.2s sending probe nonce=1777455825276
[2026-04-29T09:43:45.317Z] Session health probe response nonce=1777455825276
[2026-04-29T09:43:45.317Z] Session health probe ok nonce=1777455825276 cleanup_removed=0 stats=flows=2 outbound=0 stream_to_flow=2 next_stream_id=11 send_buf_bytes=0 send_buf_flows=0 oldest_ms=24259 stale=0
[2026-04-29T09:43:45.317Z] Session health probe ok but flows still suspect; router reset removed=2 stats=flows=2 outbound=0 stream_to_flow=2 next_stream_id=11 send_buf_bytes=0 send_buf_flows=0 oldest_ms=24259 stale=0
```

Repeated later:

```text
[2026-04-29T09:43:47.315Z] probe ok but flows still suspect; router reset removed=1
[2026-04-29T09:43:59.319Z] probe ok but flows still suspect; router reset removed=1
[2026-04-29T09:44:09.316Z] probe ok but flows still suspect; router reset removed=1
```

Important invariant from the stuck state:

```text
flows > 0
outbound == 0
sendBuf == 0
streamMaps > 0
oldestMs high / aging
highSeq stuck
probe response received
```

Interpretation:
- Transport/session is alive.
- Gateway can respond to health probes.
- Router has stale/suspect active flow mappings with no queued output or send buffer.
- Session-health currently has to hard-reset router state to recover.

## What NOT to do next

- Do not spend more time proving whether the close-suppression code is deployed. It is deployed.
- Do not treat missing old ios_log markers as stale build. Rust ios_log was private/redacted in syslog and not mirrored to app-group logs. The callback bridge solved that.
- Do not restart gateway/relay/NS again unless server preflight fails or server code changes are deployed.
- Do not raise rwnd to chase speed. The failure still appears with `rwnd=4`.
- Do not assume transport reconnect is the right fix. The probe succeeds, so transport is alive.

## Recommended next task

### Task: Instrument and fix PacketRouter stale flow lifecycle after CloseStream suppression

Goal:
Make PacketRouter remove stale/drained/half-closed flows deterministically so session-health does not need repeated hard router resets after probes succeed.

### Step 1 — Add richer Rust fd suppression diagnostics

In `proto/src/ios_tunnel_engine.rs`, when suppressing action type 2 (`CloseStream`), include:

- `stream_id`
- reason:
  - `already_closed_stream_set`
  - `router_has_stream_sync=0`
- current dispatch summary counters
- optionally last packet TCP flags / packet meta if available near the action

Desired app-group log shape via Swift callback diag path:

```text
Rust fd suppressed close stream=N reason=router_has_stream_sync_0 marker=close_suppression_v4
Rust fd suppressed close stream=N reason=already_closed_stream_set marker=close_suppression_v4
```

Reason:
We need to know if suppressed closes correspond to the same stream IDs that later remain as suspect/stuck `stream_to_flow` mappings.

### Step 2 — Expose per-flow router state diagnostics

Current stats are too coarse:

```text
flows=1 outbound=0 stream_to_flow=1 next_stream_id=2 send_buf_bytes=0 send_buf_flows=0 oldest_ms=1268 stale=0
```

Add a debug/diagnostic FFI path or extend stats string temporarily to include per-flow summaries:

- stream id
- VIP/service/IP tuple if available
- TCP state (`SynReceived`, `Established`, `FinWait`, `LastAck`, etc.)
- last activity age
- send buffer length
- recv/output queued state
- whether `stream_to_flow` still maps it

Possible log shape:

```text
Router flow diag stream=9 state=LastAck ageMs=24259 sendBuf=0 outbound=0 mapped=true service=vault
```

Reason:
We need to identify why `flows > 0` and `streamMaps > 0` persist when there is no outbound/send buffer and transport is alive.

### Step 3 — Add targeted PacketRouter cleanup rule + tests

Hypothesis:
When `CloseStream` is emitted in the Rust fd-owned iOS path, `stream_to_flow` should be removed immediately, but the flow may remain briefly in `LastAck` or similar close state. Some flows are not getting cleaned up quickly enough, leaving session-health to hard-reset the router.

Add tests for:

1. CloseStream emission removes `stream_to_flow` immediately.
2. Duplicate FIN/RST/replacement packets after close do not re-create stale mapping.
3. A flow with:
   - no outbound
   - no send buffer
   - close-ish state
   - old `last_activity`
   - mapped or unmapped inconsistency
   is removed by cleanup.
4. Cleanup reports removed flows accurately.

Potential cleanup rule:

```text
If flow is close-ish/drained AND send_buf_bytes=0 AND outbound has no packets for it AND age > threshold, remove flow and mapping.
```

Need to inspect actual `PacketRouter` internals before finalizing exact rule.

### Step 4 — Improve session-health recovery behavior

Current behavior after probe OK:

```text
cleanup_removed=0
probe ok but flows still suspect; router reset removed=N
```

Better behavior:

1. Probe OK confirms transport is alive.
2. Call targeted stale-flow cleanup first.
3. Log exactly which stream/flow was removed.
4. Only hard-reset the whole router if targeted cleanup removed nothing.

Desired marker:

```text
Session health probe ok; targeted stale-flow cleanup removed=1 streams=[9] reason=drained_close_state
```

## Useful commands

Pull phone app-group log:

```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 '
  rm -f /tmp/ztlp-phone.log
  xcrun devicectl device copy from \
    --device 39659E7B-0554-518C-94B1-094391466C12 \
    --domain-type appGroupDataContainer \
    --domain-identifier group.com.ztlp.shared \
    --source ztlp.log \
    --destination /tmp/ztlp-phone.log
  grep -nE "close_suppression_v3|suppressed_close|Session health|Router reset|Benchmark upload complete|HTTP benchmark GET failed" /tmp/ztlp-phone.log | tail -250
'
```

Run tests:

```bash
cd /home/trs/ztlp
cargo test --manifest-path proto/Cargo.toml --features ios-sync ios_tunnel_engine::tests --lib
cargo test --manifest-path proto/Cargo.toml --features ios-sync packet_router --lib
cargo test --manifest-path proto/Cargo.toml --features ios-sync --lib
```

Build NE lib on Mac after Rust changes:

```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 '
  set -e
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
  cd ~/ztlp
  git pull --ff-only origin main
  ZTLP_GIT_COMMIT=$(git rev-parse --short HEAD) cargo build --manifest-path proto/Cargo.toml \
    --target aarch64-apple-ios \
    --release --lib \
    --no-default-features --features ios-sync \
    --target-dir proto/target-ios-sync
  cp proto/target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a ios/ZTLP/Libraries/libztlp_proto_ne.a
  cp proto/include/ztlp.h ios/ZTLP/Libraries/ztlp.h
  strings ios/ZTLP/Libraries/libztlp_proto_ne.a | grep -E "NEW_MARKER|ztlp_router_has_stream_sync"
'
```

Unsigned Xcode build:

```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 '
  cd ~/ztlp/ios/ZTLP
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
    -destination "generic/platform=iOS" \
    -configuration Debug clean build \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO 2>&1 |
    grep -E "CLEAN SUCCEEDED|BUILD SUCCEEDED|BUILD FAILED|error:" | tail -80
'
```

Server preflight:

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

## Current status summary for next session

- CloseStream suppression is live and validated.
- `suppressed_close=1` events are visible in app-group logs via marker `close_suppression_v3`.
- Latest run still got `benchmark_id=254 score=7/8`.
- Remaining issue is active-flow/no-useful-RX wedge where health probes succeed but router has stale suspect flows.
- Next work should focus on PacketRouter stale flow diagnostics and targeted cleanup, not transport reconnect or deployment verification.
