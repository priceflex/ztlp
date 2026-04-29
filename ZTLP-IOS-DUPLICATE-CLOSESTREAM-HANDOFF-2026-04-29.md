# ZTLP iOS Duplicate CloseStream / Session Health Handoff — 2026-04-29

## Current baseline

Repo/commit:
- Linux repo: `/home/trs/ztlp`
- Mac Xcode repo: `~/ztlp` on `stevenprice@10.78.72.234`
- Current pushed commit: `b3ef9dd ios: suppress duplicate fd CloseStream callbacks`
- Follow-up in progress: add explicit Rust fd close-suppression startup/dispatch markers so on-device logs prove the NE lib is current.
- Commit `489f1d7` was the previous known-good baseline: Mac clean, iPhone passed 8/8, no session-health death/reconnect, but duplicate CloseStream remained.

Server-side preflight after `b3ef9dd`:
- Ran `/home/trs/ztlp/scripts/ztlp-server-preflight.sh`
- Result: `PRECHECK GREEN server-side stack is ready for phone testing`
- One non-blocking warning: recent NS relay seeding log not seen.

Mac build state after `b3ef9dd`:
- `~/ztlp` clean at `b3ef9dd`
- Built NE ios-sync lib on Mac:
  - `cargo build --manifest-path proto/Cargo.toml --target aarch64-apple-ios --release --lib --no-default-features --features ios-sync --target-dir proto/target-ios-sync`
  - copied to `ios/ZTLP/Libraries/libztlp_proto_ne.a`
  - copied header to `ios/ZTLP/Libraries/ztlp.h`
- Verified `strings ios/ZTLP/Libraries/libztlp_proto_ne.a | grep ztlp_router_has_stream_sync`
- Full unsigned Xcode clean build over SSH succeeded:
  - `xcodebuild -project ZTLP.xcodeproj -scheme ZTLP -destination "generic/platform=iOS" -configuration Debug clean build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO`
  - `CLEAN SUCCEEDED`
  - `BUILD SUCCEEDED`

Important Mac note:
- Do not use `~/code/ztlp` for iOS builds. Xcode uses `~/ztlp`.
- Codesign/device deploy must be done from Xcode GUI, not SSH.
- After replacing `libztlp_proto_ne.a`, Steve should use Xcode `Product -> Clean Build Folder` before deploying.

## What changed in b3ef9dd

Files:
- `proto/src/packet_router.rs`
- `proto/src/ffi.rs`
- `proto/src/ios_tunnel_engine.rs`

Intent:
- Suppress duplicate/stale CloseStream callbacks in the Rust fd-owned iOS data plane.

Implementation summary:
- Added `PacketRouter::has_stream(stream_id)` to check `stream_to_flow` membership.
- Added FFI function:
  - `ztlp_router_has_stream_sync(router, stream_id) -> i32`
  - returns `1` if stream is mapped, `0` if unmapped, `-1` on error.
- In `ios_tunnel_engine.rs`, the Rust fd action dispatcher now tracks `closed_streams: HashSet<u32>` for the read-loop lifetime and suppresses CloseStream action callbacks when:
  - stream already closed by this fd loop, or
  - `ztlp_router_has_stream_sync(...) != 1`
- Added `suppressed_close` to Rust action summary logs.

Expected new markers if b3ef9dd Rust fd dispatcher is running on device:
```text
Rust router action summary open=... send=... close=... suppressed_close=... unknown=... payload_bytes=... action_bytes=...
Rust router action callback dispatched actions=... open=... send=... close=... suppressed_close=... unknown=... payload_bytes=... action_bytes=...
```

These markers have NOT been seen yet in pulled iPhone logs.

## Validation already run

On Linux repo:
```bash
cargo test --manifest-path proto/Cargo.toml --features ios-sync packet_router::tests::test_router_fin_close_removes_stream_mapping_before_last_ack --lib
cargo test --manifest-path proto/Cargo.toml --features ios-sync ios_tunnel_engine::tests --lib
cargo test --manifest-path proto/Cargo.toml --features ios-sync --lib
```
Results:
- targeted PacketRouter test passed
- iOS tunnel engine tests passed
- full ios-sync lib tests: `929 passed; 0 failed`

## Device log pull commands

Pull app-group ZTLP log from iPhone through Steve's Mac:
```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 '
  rm -f /tmp/ztlp-phone.log
  xcrun devicectl device copy from \
    --device 39659E7B-0554-518C-94B1-094391466C12 \
    --domain-type appGroupDataContainer \
    --domain-identifier group.com.ztlp.shared \
    --source ztlp.log \
    --destination /tmp/ztlp-phone.log
  tail -n 200 /tmp/ztlp-phone.log
'
```

Check iPhone process list:
```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 \
  'xcrun devicectl device info processes --device 39659E7B-0554-518C-94B1-094391466C12 2>&1 | grep -iE "ZTLP|tunnel|com.ztlp" || true'
```

Live syslog if app-group log is insufficient:
```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 \
  '/Users/stevenprice/Library/Python/3.9/bin/pymobiledevice3 --no-color syslog live \
   --udid 00008130-000255C11A88001C --label \
   -ei "ztlp|networkextension|packet tunnel|packettunnel|nesession|neagent|nehelper|nesm|vpn|crash|exception|termination|terminated|runningboard|assertion|com\\.ztlp|ZTLPTunnel"'
```

List crash reports:
```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 \
  '/Users/stevenprice/Library/Python/3.9/bin/pymobiledevice3 crash ls 2>/dev/null | grep -iE "ZTLPTunnel|ZTLP|com.ztlp" | tail -20 || true'
```

## Gateway log commands

Recent gateway summary:
```bash
ssh -o StrictHostKeyChecking=no ubuntu@44.246.33.34 \
  'docker logs --since "2026-04-29T09:14:20Z" ztlp-gateway 2>&1 | grep -E "SESSION_PING|SESSION_PONG|STALL|FRAME_OPEN|FRAME_CLOSE|CLIENT_ACK|Backpressure|unknown_session" | tail -200'
```

Python summary pattern:
```bash
ssh -o StrictHostKeyChecking=no ubuntu@44.246.33.34 'python3 - <<"PY"
import subprocess, re
logs=subprocess.check_output(["docker","logs","--since","2026-04-29T09:14:20Z","ztlp-gateway"], stderr=subprocess.STDOUT).decode(errors="ignore").splitlines()
for pat in ["SESSION_PING", "SESSION_PONG", "STALL", "FRAME_OPEN", "Duplicate FRAME_OPEN", "FRAME_CLOSE", "CLIENT_ACK", "Backpressure", "unknown_session"]:
    hits=[l for l in logs if pat in l]
    print(pat, len(hits))
    for l in hits[-8:]: print("  "+l)
acks=[]
for l in logs:
    m=re.search(r"CLIENT_ACK data_seq=(\\d+)(?: rwnd=(\\d+))?", l)
    if m: acks.append((int(m.group(1)), m.group(2), l[:12]))
print("acks", len(acks), "last", acks[-1] if acks else None, "rwnds", sorted(set(r for _,r,_ in acks if r)))
PY'
```

## Latest observed phone behavior after reinstall / start fix

After Steve said tunnel was connecting again, pulled `/tmp/ztlp-phone-connecting.log`.

Startup was good:
```text
[2026-04-29T09:14:26.223Z] Connecting to 44.246.33.34:23097 via relay 34.219.64.205:23095 using NWConnection handshake...
[2026-04-29T09:14:26.267Z] Connected to 44.246.33.34:23097 via relay 34.219.64.205:23095
[2026-04-29T09:14:26.891Z] Tunnel network settings applied
[2026-04-29T09:14:26.891Z] utun fd acquired fd=5
[2026-04-29T09:14:26.891Z] Rust router action callback registered
[2026-04-29T09:14:26.891Z] Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback
[2026-04-29T09:14:26.891Z] Session health manager enabled interval=2.0s suspectRx=5.0s probeTimeout=5.0s stuckTicks=3 queue=healthQueue
[2026-04-29T09:14:26.892Z] TUNNEL ACTIVE — v5D RELAY-SIDE VIP (no NWListeners)
```

So the earlier "tunnel not starting" issue was transient/stale extension state; after reinstall/start it reached `VPN connected` and `TUNNEL ACTIVE`.

Fresh benchmark uploaded:
```text
[2026-04-29T09:14:43.718Z] Benchmark upload complete: HTTP 201 score=8/8 ... benchmark_id=250 ...
```

But there was one HTTP timeout inside the run:
```text
[2026-04-29T09:14:42.065Z] HTTP benchmark GET failed url=http://10.122.0.2/ ms=10005 error=The request timed out.
```

Session-health / recovery sequence observed:
```text
09:14:38 Session health candidate flows=1 highSeq=3 noUsefulRxFor=6.8s
09:14:38 Session health suspect ... sending probe nonce=1777454078895
09:15:00 Session health dead: probe timeout flows=2 streamMaps=2 noUsefulRxFor=10.9s stuckTicks=3
09:15:00 Router reset runtime state removed=2 reason=session_health_probe_timeout
09:15:02 Reconnect gen=1 starting reason=session_health_probe_timeout
09:15:02 Reconnect gen=1 succeeded via relay 34.219.64.205:23095; reset health/rwnd baselines
```

Later probe-success/reset sequence:
```text
09:15:08 Session health suspect ... sending probe nonce=1777454108894
09:15:09 Session health probe response nonce=1777454108894
09:15:09 Session health probe ok nonce=1777454108894 cleanup_removed=0 stats=flows=2 ...
09:15:09 Session health probe ok but flows still suspect; router reset removed=2
```

RX/replay after benchmark/browser-ish traffic:
```text
09:15:15 ZTLP RX summary packets=270 payload=195386B acks=270 replay=1 highSeq=269 inflight=0
09:15:16 ZTLP RX summary packets=0 payload=0B acks=0 replay=12 highSeq=269 inflight=0
09:15:17 ZTLP RX summary packets=0 payload=0B acks=0 replay=8 highSeq=269 inflight=0
09:15:19 ZTLP RX summary packets=0 payload=0B acks=0 replay=4 highSeq=269 inflight=0
```

Interpretation:
- Transport can connect and benchmark can pass 8/8 fresh.
- Under multi-stream/browser pressure it still enters active-flow/no-useful-RX/replay-only wedge.
- Session-health ladder works: detects, probes, resets, reconnects when needed.
- This is not a startup failure anymore.

## Latest gateway observations for same window

From gateway since `2026-04-29T09:14:20Z`:
```text
SESSION_PING 5
SESSION_PONG 0
STALL 3
FRAME_OPEN 20
Duplicate FRAME_OPEN 3
FRAME_CLOSE 0
CLIENT_ACK 540
Backpressure 2
unknown_session 5
acks last data_seq=265 rwnd=4
```

Notable gateway lines:
```text
09:14:38.916 [info] [Session] SESSION_PING nonce=1777454078895
09:15:08.991 [info] [Session] SESSION_PING nonce=1777454108894
09:15:20.914 [info] [Session] SESSION_PING nonce=1777454120894
09:15:26.915 [info] [Session] SESSION_PING nonce=1777454126895
09:15:36.915 [info] [Session] SESSION_PING nonce=1777454136894
```

Gateway did not log `SESSION_PONG`, although phone received at least one probe response at 09:15:09. Gateway log label may only log PING, or PONG send log is missing/suppressed.

Gateway ACKs:
- `CLIENT_ACK` advanced to `data_seq=265` with `rwnd=4`, then stopped.

Gateway backpressure:
```text
09:14:46.714 Backpressure ON: pausing backend reads (queue=512)
09:15:10.605 Backpressure ON: pausing backend reads (queue=512)
```

Gateway duplicate opens:
```text
Duplicate FRAME_OPEN for existing stream 2
Duplicate FRAME_OPEN for existing stream 1
Duplicate FRAME_OPEN for existing stream 1
```

Gateway stalls are mostly tiny/no-stream sessions, but one had `last_acked=-1 recv_base=1 streams=[]`:
```text
09:15:27.104 STALL inflight=1 last_acked=3 recv_base=5 queue=0 streams=[]
09:15:27.716 STALL inflight=1 last_acked=3 recv_base=6 queue=0 streams=[]
09:15:27.744 STALL inflight=5 last_acked=-1 recv_base=1 queue=0 streams=[]
```

## Critical unresolved issue: b3ef9dd markers absent

Despite Mac lib having `ztlp_router_has_stream_sync` and Xcode clean build succeeding, the iPhone logs still do NOT show:
```text
Rust router action summary ... suppressed_close=...
Rust router action callback dispatched ... suppressed_close=...
```

Instead, logs still only show Swift-level callback summaries:
```text
Rust action callback summary open=... send=... close=... unknown=... bytes=... lastType=...
```

Possible explanations:
1. The Rust dispatcher `ios_log` path is compiled but not being called/logged due to condition (`summary.total > 0`) not satisfied or logging path different than expected.
2. Xcode/device is still using a stale NE object/library despite clean build/reinstall.
3. The added logging is only in the Rust fd dispatch path, but the current actions visible in logs are mostly from Swift `handleRustRouterAction`, so the Rust-side log may not flush to app-group log or may be filtered.

Recommended next step for new session:
- Add an unmistakable Rust startup marker in `IosTunnelEngine::start_router_ingress_loop` or `start_read_loop`, e.g.:
```rust
crate::ffi::ios_log("Rust fd close suppression enabled build=b3ef9dd marker=close_suppression_v1");
```
- Also add a log immediately before/after `dispatch_router_actions(...)`, not gated on `summary.total`, e.g.:
```rust
crate::ffi::ios_log(&format!("Rust fd dispatch action_written={} close_suppression_enabled=1", action_written));
```
- Rebuild NE lib, clean build, deploy, and verify marker appears before interpreting CloseStream behavior.

This will remove ambiguity about whether b3ef9dd code is actually running on-device.

## Duplicate CloseStream current status

Earlier logs before b3ef9dd showed duplicate CloseStream clearly:
```text
RouterAction send CloseStream stream=35 sent=true
RouterAction send CloseStream stream=35 sent=true
RouterAction send CloseStream stream=37 sent=true
RouterAction send CloseStream stream=37 sent=true
```

In the latest 248-line log after reconnect/start:
- `RouterAction send CloseStream`: 0
- `suppressed_close`: 0
- no CloseStream validation possible yet.

Do not declare duplicate CloseStream fixed until:
1. on-device logs show the close suppression startup/dispatch marker, and
2. a run that previously produced duplicate closes either shows no duplicates or shows `suppressed_close > 0`.

## Things to avoid

- Do not restart/redeploy gateway while Steve is testing without telling him first.
- Do not assume source pushed or Mac build success means the phone NE is running the new static lib; verify via log markers.
- Do not chase startup failure right now; latest logs prove startup is working.
- Do not raise rwnd above 4/5 to chase speed; current issue still appears under rwnd=4, and backpressure still hits queue=512.

## Useful commands for next session

Check Mac source/lib state:
```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 '
  cd ~/ztlp
  echo GIT=$(git rev-parse --short HEAD)
  git status --short
  echo HAS_LIB_SYMBOL=$(strings ios/ZTLP/Libraries/libztlp_proto_ne.a | grep -c ztlp_router_has_stream_sync || true)
  cd ios/ZTLP
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLPTunnel -destination "generic/platform=iOS" -showBuildSettings 2>/dev/null | grep OTHER_LDFLAGS | head -4
'
```

Build NE lib on Mac:
```bash
ssh -o StrictHostKeyChecking=no stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
  cd ~/ztlp
  cargo build --manifest-path proto/Cargo.toml \
    --target aarch64-apple-ios \
    --release --lib \
    --no-default-features --features ios-sync \
    --target-dir proto/target-ios-sync
  cp proto/target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a ios/ZTLP/Libraries/libztlp_proto_ne.a
  cp proto/include/ztlp.h ios/ZTLP/Libraries/ztlp.h
  strings ios/ZTLP/Libraries/libztlp_proto_ne.a | grep ztlp_router_has_stream_sync >/dev/null && echo NE_BUILD_AND_COPY_OK
'
```

Unsigned clean Xcode build:
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

Run server preflight:
```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

## Suggested first task in new session

Task:
"Add explicit Rust fd close-suppression startup/dispatch markers, rebuild NE lib, clean build on Mac, and ask Steve to redeploy. Then pull iPhone logs and verify the marker appears."

Rationale:
- Current code may already suppress duplicates, but logs cannot prove it.
- Without a marker, every phone run is ambiguous.
- Once marker is present, duplicate CloseStream cleanup can be validated directly.
