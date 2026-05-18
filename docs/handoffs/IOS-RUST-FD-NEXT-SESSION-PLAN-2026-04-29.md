# ZTLP iOS Rust FD Long-Flow Stabilization Plan

> **For Hermes:** Load these skills before executing: `ztlp-session-health-recovery`, `ztlp-ffi-layer`, `ztlp-ios-build-debugging`, `systematic-debugging`, and `ztlp-doc-fact-check` if editing docs. Use tools immediately; do not ask Steve to repeat context.

**Goal:** Diagnose and stabilize the remaining long-flow/browser-style stall after the Rust fd-owned router outbound -> utun drain fix.

**Architecture:** Rust now owns utun fd reads and writes router outbound packets back to utun, while Swift still bridges RouterActions to the existing transport/mux path. The next session should preserve this working dataplane and focus on why longer/browser traffic can still reach session-health probe timeout after useful RX stalls.

**Tech Stack:** Rust `proto` crate, iOS Network Extension Swift, C FFI headers, PacketRouter, app-group `ztlp.log`, Bootstrap benchmark API, AWS gateway/relay/NS logs.

---

## Current Known-Good Baseline

Commit on `main`:

```text
f25dedf ios: enable Rust fd router outbound utun drain
```

Confirmed fixed:

- Rust fd outbound -> utun writes are active.
- iOS TCP progresses from SYN to ACK/PSHACK+DATA.
- PacketRouter emits SendData.
- Benchmark uploads passed 8/8 twice:
  - benchmark_id=236
  - benchmark_id=237

Important validation doc:

```text
/home/trs/ztlp/ZTLP-IOS-RUST-FD-DATAPLANE-VALIDATION-2026-04-29.md
```

Latest root-cause handoff for the fixed phase:

```text
/home/trs/ztlp/ZTLP-IOS-RUST-FD-OUTBOUND-UTUN-HANDOFF-2026-04-29.md
```

Do not regress these markers:

```text
Rust router action callback registered
Rust iOS tunnel engine scaffold started fd=N mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback
Rust fd outbound diag count=N outbound_wrote packets=N bytes=N errors=0
Rust fd ingress diag ... flags=PSHACK+DATA tcp_payload=N
Rust action callback summary ... send=1 ... bytes=N
RouterAction send SendData stream=N bytes=N sent=true
Benchmark upload complete: HTTP 201 score=8/8
```

## Remaining Problem

During longer/browser-style traffic, after real data flows, the tunnel can still hit:

```text
Session health candidate: flows=2 outbound=0 streamMaps=2 highSeq=1718 noUsefulRxFor=6.6s ...
Session health suspect: reason=no_useful_rx_6.6s ... sending probe ...
Session health dead: probe timeout ...
Router reset runtime state removed=2 reason=session_health_probe_timeout
Reconnect gen=1 succeeded ...; reset health/rwnd baselines
```

The recovery ladder works, but the next target is to understand why useful RX stalls with:

```text
flows=2 outbound=0 streamMaps=2 sendBuf=0 oldestMs increasing highSeq stuck
```

This likely points at stale PacketRouter flow/stream mappings, premature close/reset behavior, gateway response/ACK sequencing, or Swift transport bridge limitations. Do not assume before gathering evidence.

---

## Task 1: Re-establish repo and deployment state

**Objective:** Start the next session from a clean, known state and verify the Mac/iPhone build path is using the committed code.

**Files:**
- Inspect only: `/home/trs/ztlp`
- Inspect only on Mac: `stevenprice@10.78.72.234:~/ztlp`

**Steps:**

1. Check local status and latest commit:

```bash
cd /home/trs/ztlp
git status --short
git log --oneline -3
```

Expected:

```text
f25dedf ios: enable Rust fd router outbound utun drain
```

2. Check Mac repo status:

```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git status --short && git log --oneline -3'
```

3. If Mac is behind, pull into `~/ztlp` only:

```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git pull origin main'
```

Do not edit `~/code/ztlp` for iOS builds.

4. Verify server stack before any phone testing:

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Expected final line:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

---

## Task 2: Pull and preserve the latest phone log

**Objective:** Capture app-group logs before changing code so there is a reproducible baseline.

**Files:**
- Create local artifact: `/tmp/ztlp-phone-rust-fd-next-baseline.log`

**Steps:**

1. Pull phone app-group log from Steve's Mac:

```bash
ssh stevenprice@10.78.72.234 '
  xcrun devicectl device copy from \
    --device 39659E7B-0554-518C-94B1-094391466C12 \
    --domain-type appGroupDataContainer \
    --domain-identifier group.com.ztlp.shared \
    --source ztlp.log \
    --destination /tmp/ztlp-phone.log &&
  cp /tmp/ztlp-phone.log /tmp/ztlp-phone-rust-fd-next-baseline.log &&
  tail -250 /tmp/ztlp-phone.log
'
```

2. Copy it locally if needed:

```bash
scp stevenprice@10.78.72.234:/tmp/ztlp-phone-rust-fd-next-baseline.log /tmp/ztlp-phone-rust-fd-next-baseline.log
```

3. Summarize key markers:

```bash
grep -E 'Benchmark upload complete|Rust fd outbound diag|PSHACK\+DATA|Rust action callback summary|Session health candidate|Session health dead|Reconnect gen=.*succeeded|Router reset runtime state' /tmp/ztlp-phone-rust-fd-next-baseline.log | tail -120
```

Expected:

- At least one 8/8 benchmark marker.
- Evidence of outbound writes and SendData.
- If reproducing long-flow behavior, health suspect/dead/reconnect markers.

---

## Task 3: Pull benchmark records 236/237 from Bootstrap

**Objective:** Preserve benchmark server-side records and embedded device logs for analysis.

**Files:**
- Create: `/tmp/ztlp-benchmark-236.json`
- Create: `/tmp/ztlp-benchmark-237.json`

**Steps:**

1. Locate benchmark API token if needed:

```bash
grep -R "Authorization\|Bearer\|benchmark" -n /home/trs/ztlp/ios/ZTLP/ZTLP /home/trs/ztlp/ios/ZTLP/ZTLPTunnel | head -50
```

Known prior token was stored in BenchmarkReporter.swift. Use the current repo value, not memory, if it differs.

2. Fetch the records from Bootstrap at `10.69.95.12:3000`:

```bash
TOKEN='<token-from-repo>'
curl -s "http://10.69.95.12:3000/api/benchmarks/236" -H "Authorization: Bearer $TOKEN" -o /tmp/ztlp-benchmark-236.json
curl -s "http://10.69.95.12:3000/api/benchmarks/237" -H "Authorization: Bearer $TOKEN" -o /tmp/ztlp-benchmark-237.json
```

3. If direct ID endpoint fails, use list endpoint and filter:

```bash
curl -s "http://10.69.95.12:3000/api/benchmarks?limit=20" -H "Authorization: Bearer $TOKEN" > /tmp/ztlp-benchmarks-recent.json
```

4. Extract summaries:

```bash
python3 - <<'PY'
import json
for path in ['/tmp/ztlp-benchmark-236.json','/tmp/ztlp-benchmark-237.json','/tmp/ztlp-benchmarks-recent.json']:
    try:
        data=json.load(open(path))
    except Exception as e:
        print(path, e)
        continue
    print('\n==', path, '==')
    print(json.dumps(data, indent=2)[:4000])
PY
```

Expected:

- Record(s) show score 8/8.
- Embedded logs or metadata include enough timing to align with phone log.

---

## Task 4: Add richer Rust outbound packet diagnostics

**Objective:** Make outbound -> utun writes explain what TCP packets are being written, not just count/bytes.

**Files:**
- Modify: `proto/src/ios_tunnel_engine.rs`
- Test: `proto/src/ios_tunnel_engine.rs` unit tests if helper is refactored/testable

**Design:**

Reuse existing `PacketMeta::parse(...)` and `flags_string()` for packets read from `ztlp_router_read_packet_sync(...)` before calling `utun.write_packet(...)`.

Add a low-rate diagnostic for written outbound packets with:

```text
outbound_wrote packets=N bytes=N errors=N last_proto=6 last_flags=SYNACK/ACK/FINACK/RST last_tcp_payload=N last_src=A:P last_dst=B:P totals_packets=N totals_bytes=N totals_errors=N
```

**Implementation sketch:**

Change `drain_router_outbound_to_utun(...)` to return a struct rather than tuple:

```rust
#[derive(Default, Clone)]
struct OutboundDrainSummary {
    packets: u64,
    bytes: u64,
    errors: u64,
    last_meta: Option<PacketMeta>,
}
```

Inside the drain loop:

```rust
let meta = PacketMeta::parse(&packet_buf[..n]);
match utun.write_packet(&packet_buf[..n]) {
    Ok(written) => {
        summary.packets += 1;
        summary.bytes += written as u64;
        summary.last_meta = meta;
    }
    Err(e) => { ... }
}
```

At the call site, include metadata in the existing action type 251 diagnostic.

**Verification:**

Run:

```bash
cargo fmt --manifest-path /home/trs/ztlp/proto/Cargo.toml
cargo check --manifest-path /home/trs/ztlp/proto/Cargo.toml --no-default-features --features ios-sync --lib
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml --features ios-sync ios_tunnel_engine --lib
```

Expected:

- Check passes.
- `ios_tunnel_engine` tests pass 4/4 or more.

---

## Task 5: Investigate duplicate CloseStream emissions

**Objective:** Determine whether duplicate CloseStream actions are harmless or causing premature long-flow teardown.

**Files:**
- Inspect/modify: `proto/src/packet_router.rs`
- Inspect: `proto/src/ios_tunnel_engine.rs`
- Inspect: `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`

**Evidence to gather first:**

Search logs for duplicate close patterns:

```bash
grep 'RouterAction send CloseStream' /tmp/ztlp-phone-rust-fd-next-baseline.log | tail -100
```

Search code:

```bash
grep -R "CloseStream" -n /home/trs/ztlp/proto/src/packet_router.rs /home/trs/ztlp/proto/src/ios_tunnel_engine.rs /home/trs/ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Questions to answer:

- Does PacketRouter emit CloseStream once for FIN and again for RST/cleanup?
- Does Rust callback dispatch duplicate the same serialized action buffer?
- Does Swift `processRouterActions` get called twice for one action?
- Are duplicate closes only log duplicates or actual mux frames sent twice?

Do not fix until the duplicate source is identified.

**Potential fix only if proven:**

- Deduplicate per stream close at PacketRouter state transition boundary, not in Swift logging.
- Add a unit test in `proto` that feeds FIN/RST sequence and asserts only one CloseStream for an already-closed stream.

Verification command:

```bash
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml packet_router --lib
```

---

## Task 6: Investigate stale flow mappings after useful RX stalls

**Objective:** Explain why health logs show `flows=2 outbound=0 streamMaps=2 sendBuf=0 oldestMs` increasing.

**Files:**
- Inspect/modify: `proto/src/packet_router.rs`
- Inspect: `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` health evaluation and reset paths

**Evidence:**

From phone log, capture windows around health candidate/dead:

```bash
grep -n 'Session health candidate\|Session health dead\|Router stats:\|Health eval:' /tmp/ztlp-phone-rust-fd-next-baseline.log | tail -80
```

Inspect router stats implementation:

```bash
grep -R "router_stats\|oldest_ms\|stream_to_flow\|flows" -n /home/trs/ztlp/proto/src/packet_router.rs /home/trs/ztlp/proto/src/ffi.rs
```

Questions:

- What makes a flow count as active?
- What updates `oldest_ms`?
- Are FIN/RST cleanup paths clearing both `flows` and `stream_to_flow`?
- Is `stream_to_flow` retained after CloseStream because Swift transport still has pending gateway data?
- Is the health detector treating idle browser keepalive flows as active too aggressively?

Possible fixes, only after evidence:

- More aggressive stale flow cleanup when `outbound=0 && sendBuf=0 && no useful RX`.
- Cleanup `stream_to_flow` on final close/reset if missing.
- Adjust health active-flow definition to ignore fully closed/drained flows.

Verification:

- Add PacketRouter unit test reproducing stale mapping.
- Run `cargo test --manifest-path proto/Cargo.toml packet_router --lib`.

---

## Task 7: Correlate gateway logs around the stall window

**Objective:** Determine whether the gateway stopped sending useful data, was waiting for ACK/window, or already closed streams.

**Files:**
- No repo edits unless diagnostics are needed.

**Important safety:** Tell Steve before restarting any ZTLP server components. This task should be log-only and must not restart gateway/relay/NS.

**Steps:**

1. Identify stall timestamp from phone log, e.g. around:

```text
2026-04-29T08:28:25Z to 2026-04-29T08:28:35Z
```

2. Pull gateway logs around that window:

```bash
ssh ubuntu@44.246.33.34 'docker logs --since "2026-04-29T08:28:20Z" --until "2026-04-29T08:28:40Z" ztlp-gateway 2>&1 | tail -300'
```

3. Look for:

```text
CLIENT_ACK
rwnd=4
STALL
FRAME_CLOSE
Forwarding ... bytes to backend
backend close
queue/inflight/cwnd
SESSION_PING / SESSION_PONG
```

Questions:

- Did gateway receive PING and fail to PONG, or did PONG get HOL-blocked/lost?
- Was gateway still sending data while iOS highSeq stopped?
- Was it waiting on client ACKs/rwnd?
- Did backend close streams before router cleanup?

---

## Task 8: Build and deploy validation after any code change

**Objective:** Ensure every fix compiles locally and on Mac before Steve tests.

**Files:**
- Whatever was modified.

**Commands:**

Local:

```bash
cargo fmt --manifest-path /home/trs/ztlp/proto/Cargo.toml
cargo check --manifest-path /home/trs/ztlp/proto/Cargo.toml --no-default-features --features ios-sync --lib
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml --features ios-sync ios_tunnel_engine --lib
cargo test --manifest-path /home/trs/ztlp/proto/Cargo.toml packet_router --lib
```

Mac NE lib and Xcode compile:

```bash
scp /home/trs/ztlp/proto/src/ios_tunnel_engine.rs stevenprice@10.78.72.234:~/ztlp/proto/src/ios_tunnel_engine.rs
scp /home/trs/ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift stevenprice@10.78.72.234:~/ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
ssh stevenprice@10.78.72.234 '
  export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH" &&
  cd ~/ztlp/proto &&
  cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib &&
  cp target/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a &&
  cd ~/ztlp/ios/ZTLP &&
  xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
    -destination "generic/platform=iOS" \
    -configuration Debug build \
    CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO 2>&1 |
  grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" | tail -100
'
```

Before asking Steve to test:

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Expected:

```text
BUILD SUCCEEDED
PRECHECK GREEN server-side stack is ready for phone testing
```

Tell Steve:

```text
Please Clean Build Folder in Xcode, deploy to phone, run benchmark/browser scenario, then I will pull logs.
```

---

## Task 9: Commit and document the next finding

**Objective:** Keep each fix/evidence step recoverable.

**Steps:**

1. Update or create a new validation/handoff doc after the next session:

```text
ZTLP-IOS-RUST-FD-LONG-FLOW-HANDOFF-2026-04-29.md
```

2. Include:

- Hypothesis tested.
- Code changed.
- Commands run.
- Phone/gateway evidence.
- Benchmark IDs.
- What remains.

3. Commit with Steve's identity:

```bash
cd /home/trs/ztlp
git config user.name 'Steven Price'
git config user.email 'steve@techrockstars.com'
git add -A
git commit -m "ios: diagnose Rust fd long-flow stalls"
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push origin main
```

---

## Do Not Do

- Do not restart gateway/relay/NS without warning Steve first.
- Do not re-enable Swift `packetFlow.readPackets` while Rust owns fd reads.
- Do not use Swift `packetFlow.writePackets` for the Rust fd-ownership path.
- Do not treat absence of Rust NSLog markers in app-group log as proof Rust did not run; use Swift diagnostic callbacks for app logs.
- Do not apply random fixes before correlating phone + gateway evidence.
- Do not edit Steve's Mac `~/code/ztlp` for iOS builds; use `~/ztlp`.

## Success Criteria for Next Session

Minimum success:

- Full evidence packet collected: phone log + benchmark record + gateway log around stall.
- Outbound packet diagnostics include TCP flags/ports/payload length.
- No regression of 8/8 benchmark baseline.

Better success:

- Root cause of duplicate CloseStream or stale flow mappings identified.
- PacketRouter unit test added for the identified state transition.
- Long/browser-style traffic avoids unnecessary session-health reconnect, or reconnect cause is narrowed to gateway/transport with proof.

