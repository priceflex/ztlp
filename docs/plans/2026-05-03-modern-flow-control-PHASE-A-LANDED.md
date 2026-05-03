# ZTLP Modern Flow Control — Phase A Landed

Status: **on main, awaiting on-device verification**
Date: 2026-05-03
Predecessor plan: `2026-05-03-modern-flow-control.md`
Rollback tags: `v-before-rtt-instrumentation` → `v-after-rtt-instrumentation`
Commit: `dc6946d` on `main`

## What shipped

Passive RTT / goodput / BDP instrumentation. **No wire change, no
behaviour change** — every byte on the wire today looks identical to
before this commit. All we added is observation.

### Rust (proto/src/mux.rs)
- RFC 6298 smoothed RTT (`srtt`, `rttvar`, `min_rtt`, `latest_rtt`).
- 8-second sliding-window goodput sampler (bytes ACK'd / 8s), peak tracked.
- BDP = `srtt_ms * goodput_bps / 8000` (KB).
- Karn's algorithm: retransmitted packets excluded from RTT samples.
- Two entry points:
  - Native: `on_cumulative_ack_at` — used when the Rust MuxEngine owns
    inflight tracking (post full-mux cutover).
  - Shadow: `observe_sent(now, data_seq, encoded_len)` +
    `observe_ack_cumulative(now, cumulative)` — used today, because
    the Swift data-path still owns inflight tracking. Rust just
    mirrors what Swift sent and measures RTT from the outside.
- Shadow map bounded to `SHADOW_MAX_ENTRIES = 4096`.
- 14 new unit tests on top of 25 baseline → 39/39 passing.

### FFI (proto/include/ztlp.h + proto/src/ffi.rs)
- `ZtlpRttGoodputSnapshot` (repr-C mirror of the Rust struct).
- `ztlp_mux_rtt_goodput_snapshot(engine, *out) -> i32`.
- `ztlp_mux_observe_sent(engine, data_seq, encoded_len) -> i32`.
- `ztlp_mux_observe_ack_cumulative(engine, cumulative) -> i32`.
- `ztlp_mux_shadow_inflight_len(engine) -> i32` (diagnostic).

### iOS Swift
- **ZTLPTunnelConnection**: `onDataFrameSent: ((UInt64, Int) -> Void)?`
  hook fired from `sendData` after framing, before encryption, so
  `encoded_len` matches what the Rust codec would have produced.
- **PacketTunnelProvider**:
  - `useRttInstrumentation = true` gates the feature.
  - `wireRttInstrumentationHook(on:)` installs the observe-sent bridge
    on every fresh tunnel + reconnect.
  - `tunnelConnection(_:didReceiveAck:)` also calls
    `ztlp_mux_observe_ack_cumulative` when the flag is on.
  - `maybeLogRttSnapshot()` runs in the ~2s health tick after the
    rwnd policy runs. Logs `[rtt-bdp]` once values exist.
- Empty startup values are suppressed (no log spam before first ACK).

## Expected log signature

Once the benchmark runs and the Vaultwarden page loads, the NE log
pulled from the phone should contain lines like:

```
[rtt-bdp] srtt=47ms rttvar=12ms min=22ms latest=51ms goodput=824576bps peak=1048000bps bdp=4KB samples=156 shadow_inflight=3
```

Sanity bounds:
- `srtt` should land in the tens of ms (wifi path) to low hundreds
  (cellular).
- `goodput_bps` should be non-zero during active benchmark / browse;
  goes to 0 when idle.
- `shadow_inflight` should stay under ~16 (Swift's
  `maxSendsInFlight`). If it grows unbounded, `observe_sent` is
  firing but `observe_ack_cumulative` isn't matching.
- `bdp` is `0` until both srtt AND goodput are non-zero.

If `samples_total` stays 0 through a full benchmark, something is
wrong — the `onDataFrameSent` closure may not be installed, or
`didReceiveAck` isn't reaching the new call path.

## Device gate

1. `/home/trs/ztlp/scripts/ztlp-server-preflight.sh` → **PRECHECK
   GREEN** (done on Linux side at commit time).
2. On Steve's Mac: rebuild both libs + copy + ztlp.h sync — **done**
   via the standard rebuild recipe. Sizes:
   `libztlp_proto.a` ~56MB, `libztlp_proto_ne.a` ~27MB.
3. On Steve's Mac: `xcodebuild … clean build CODE_SIGN_IDENTITY=""` →
   **CLEAN SUCCEEDED + BUILD SUCCEEDED**.
4. **Device test 2026-05-03 04:25-04:26 UTC**: Benchmark 8/8 (id=275)
   uploaded HTTP 201, no reconnects, no errors. Instrumentation
   verified working.

## Measured numbers (first run)

| time (Z)    | srtt | rttvar | min | latest | goodput | peak  | bdp | samples | shadow |
|-------------|------|--------|-----|--------|---------|-------|-----|---------|--------|
| 04:25:41    | 39   | 0      | 38  | 39     | 796 bps | 796   | 0   | 15      | 0      |
| 04:25:45    | 39   | 0      | 37  | 37     | 3.9k    | 3.9k  | 0   | 20      | 0      |
| 04:25:49    | 39   | 1      | 37  | 37     | 5.5k    | 5.5k  | 0   | 22      | 0      |
| 04:25:53    | 38   | 0      | 37  | 38     | 8.6k    | 8.6k  | 0   | 30      | 0      |
| 04:25:57    | 38   | 0      | 37  | 38     | 13.8k   | 13.8k | 0   | 45      | 0      |
| 04:25:59    | 39   | 2      | 37  | 37     | 17.7k   | 17.7k | 0   | 53      | 0      |
| 04:26:03    | 40   | 2      | 37  | 37     | 18.1k   | 22.4k | 0   | 67      | 0      |
| 04:26:05-19 | 40   | 2      | 37  | 37     | decay→0 | 22.4k | 0   | 67      | 0      |

Findings:
- **RTT healthy**: 37-40 ms srtt, 0-2 ms rttvar. Classic wifi path to
  AWS us-west. RTT samples admitted cleanly by Karn's algo.
- **Peak goodput: 22.4 kbps** (2.8 KB/s). Very low.
- **BDP ≈ 112 bytes** at peak = `0 KB` by our KB rounding. The
  18 KB rwnd=16 ceiling is **nowhere near** a constraint here.
- **Shadow map stays at 0**: observe_sent / observe_ack balanced;
  no leak.
- **rwnd oscillates 4/12/16**: Nebula-collapse fix working, no
  stuck-at-4.
- Idle-tail after 04:26:13 triggers normal probe cadence; no
  reconnect, no regression.

### What this says about Phase B+

The plan's premise — "18 KB window caps throughput" — is **not** the
dominant factor on this path. The 22 kbps ceiling points at a
different bottleneck: gateway send pacing, relay egress, or iOS
utun batching. Phase B (byte-unit windows) is still valuable for the
semantic correctness + parallel-stream story, but it is unlikely to
move the single-stream throughput number measured here.

Suggested Phase B+ shape:
- Keep Phase B (byte-unit FRAME_ACK_V2) for its architectural win.
- **Also** measure where the 22 kbps is coming from. Hypotheses:
  (a) gateway `@recv_window_size 256` packet-semantic interaction
  with the adaptive rwnd=4/12/16 cycle;
  (b) iOS `maxSendsInFlight` static cap pacing sends;
  (c) relay-side TCP termination head-of-line to Vaultwarden.
- Phase D (autotune) will need a wider measurement range to be
  meaningful — the current path doesn't exercise any of the rwnd
  dynamic range.

## Gotchas discovered while implementing

### 1. The plan's gateway path is wrong for Phase B onward.

The plan lists `gateway/src/mux_handler.rs` as a change target for
Phase B. The real path is `gateway/lib/ztlp_gateway/session.ex` —
the gateway is **Elixir**, not Rust. FRAME_ACK decode lives around
lines 1786-1804 (`@frame_ack 0x01`).

### 2. The gateway's default peer_rwnd is 512, not 16.

`@default_peer_rwnd 512` at `session.ex:516`. The gateway treats the
client's advertised rwnd as a packet count and caps inflight
accordingly. The plan's claim that ZTLP caps at "18 KB" is true from
the iOS side but the gateway would happily let the client advertise
much more. Phase B's "reinterpret rwnd as KB" is therefore a
semantics change **for both sides simultaneously** — if iOS ships
V2 first and advertises e.g. 256 KB, the gateway reads it as 256
packets and runs fat.

### 3. The Rust MuxEngine's `inflight` map is empty today.

Even though the Nebula cutover (commit `1520730`) wired the Rust
rwnd policy + SessionHealth, the Swift side still owns the send
buffer + retransmit. That's why Phase A needs the shadow observer
path — otherwise `on_cumulative_ack` would never have anything to
release and all RTT / goodput numbers stay 0.

## Updated Phase B–D considerations

Rewriting the plan wholesale isn't necessary — just these deltas:

- **Phase B target files**: replace `gateway/src/mux_handler.rs` with
  `gateway/lib/ztlp_gateway/session.ex`. Decode both 0x01 and 0x10
  there; reply 0x10 only if peer has sent 0x10.
- **Phase B gateway semantic change**: introduce a new
  `peer_rwnd_bytes` alongside the existing `peer_rwnd` (packets) so
  the effective-window math in `session.ex:977` can pick whichever
  is smaller. Old 0x01 path keeps packet semantics; new 0x10 path
  uses byte semantics.
- **Phase B deploy coordination**: gateway restart crashes Steve's
  benchmark. Tell him before restarting. Consider shipping the
  gateway change first as a passive parser (accepts 0x10 but still
  uses 0x01 for decisions) before flipping iOS to send 0x10.
- **Mac lockstep**: Mac uses the same `libztlp_proto` → picks up the
  new frame codec automatically. No separate work, but the Mac app
  needs a rebuild at each phase boundary.

## Rollback

```
cd /home/trs/ztlp
git reset --hard v-before-rtt-instrumentation
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push --force origin main
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git fetch && git reset --hard origin/main'
# then rebuild libs on Mac (same recipe as above)
```

## Next session

After device verification is green, the right next step is **not**
Phase B yet — the plan's own Phase A acceptance says "read BDP
values". Steve + the Hermes agent should eyeball the first round of
`[rtt-bdp]` log lines to:
- validate the numbers are sane (RTT matches intuition, goodput
  matches benchmark score);
- confirm `shadow_inflight` stays bounded;
- pick a realistic `min_window` and `max_window` for the Phase D
  autotuner using the measured BDP range instead of guessing.

Then Phase B can be scoped with real Elixir gateway + deploy
coordination.
