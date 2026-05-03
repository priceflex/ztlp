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
4. **Pending**: Steve on device — Xcode → Clean Build Folder (⌘⇧K),
   run → benchmark → pull log → Vaultwarden ×3 → pull log.

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
