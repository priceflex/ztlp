# ZTLP Modern Flow Control — Phase D Landed

Status: **code merged on main, awaiting Mac build + on-device verification**
Date: 2026-05-03
Predecessor: `2026-05-03-modern-flow-control-PHASE-B-VERIFIED.md`
Rollback tag: `v-before-autotune`
Scope: **Rust + FFI + Swift only — NO wire change, NO gateway deploy.**
Skipped for now: Phase C (per-stream windows). Will be done in a separate round.

## Why we skipped Phase C (temporarily)

Phase B verified on-device at 05:17–05:19 UTC showed `v2=yes adv_kb=16` sticky
across a full session — the byte-unit wire format works. But `adv_kb` stayed
pinned at 16 because the V1 ladder (RWND_FLOOR=4 → RWND_ADAPTIVE_MAX=16) was
still the source of truth and its max × 1140 ≈ 18 KB capped the byte window.

Phase D (autotune) lifts that cap *without* changing the wire format, so we
get the throughput win immediately. Phase C (per-stream windows) needs a new
wire frame and more coordination; deferred.

## What shipped

**Autotune overlay in `proto/src/mux.rs`.** The V1 packet-count ladder stays
intact for legacy peers. When the peer speaks V2, a BBR-lite autotuner runs
on top of the ladder's pressure reasons and drives the byte window directly:

```
target_bytes = clamp(min_kb*1024, max_kb*1024,
                     srtt_ms × peak_goodput_bps × safety / 8000)
safety = 2.0 on healthy ticks, 0.5 on pressure/replay
```

No wire change: the value just flows out in the existing FRAME_ACK_V2
`window_kb` field, which Phase B already shipped.

### Rust (proto/src/mux.rs) — 485 new lines

New constants:
- `AUTOTUNE_MIN_WINDOW_KB = 8` (roughly the V1 floor × 1140 = 4.6 KB)
- `AUTOTUNE_MAX_WINDOW_KB = 4096` (4 MB — QUIC-ish default)
- `AUTOTUNE_HEALTHY_SAFETY_NUM/DEN = 2/1`
- `AUTOTUNE_PRESSURE_SAFETY_NUM/DEN = 1/2`
- `AUTOTUNE_WIDEN_TICKS_NEEDED = 3`

New MuxEngine state:
- `autotune_min_kb`, `autotune_max_kb` — configurable via `set_autotune_bounds_kb`
- `autotune_healthy_ticks` — gate counter, resets on widen or pressure
- `autotune_target_kb` — diagnostic (post-clamp target)
- `autotune_reason: &'static str` — machine-readable reason tag
- `autotune_last_tick: Option<Instant>`

New methods:
- `set_autotune_bounds_kb(min, max)` — with swap/clamp validation
- `autotune_bounds_kb()` → `(u16, u16)`
- `autotune_target_kb()` → `u16`
- `autotune_reason()` → `&'static str`
- `autotune_compute_target_bytes(pressure)` — pure compute (internal)
- `autotune_tick(pressure, now)` — mutates `advertised_window_bytes` when V2 (internal)

`tick_rwnd` refactor:
- Original ladder extracted into `tick_rwnd_v1_ladder`.
- New `tick_rwnd` calls V1 ladder, then feeds its reason into
  `autotune_tick`. V1-only sessions get `"v1_legacy"` (no-op); V2 sessions
  get one of `{no_sample, widen_healthy, hold_pre_widen, hold_at_target,
  shrink_to_target, pressure_clamp}`.

Tests: **9 new** (autotune_*), **58/58 mux tests passing** (was 49/49), full
lib suite **1006/1006 passing**.

### FFI (proto/src/ffi.rs + proto/include/ztlp.h + ios/Libraries/ztlp.h) — 105 + 40×2 lines

5 new entry points:
- `ztlp_mux_set_autotune_bounds_kb(engine, min_kb, max_kb) -> i32`
- `ztlp_mux_autotune_target_kb(engine) -> u16`
- `ztlp_mux_autotune_min_kb(engine) -> u16`
- `ztlp_mux_autotune_max_kb(engine) -> u16`
- `ztlp_mux_autotune_reason(engine, out_buf, out_buf_len) -> i32`
  (NUL-terminated ASCII reason tag)

Header synced to `ios/ZTLP/Libraries/ztlp.h` per the wire-frame-extension
skill pattern.

### Swift (ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift) — 13 lines

Extended the `[rtt-bdp]` log line to include:
```
auto_target_kb=N auto_reason=widen_healthy
```

No new feature flag — autotune is always on (it's a no-op on V1-only
sessions). The `ztlp_mux_autotune_reason` FFI copies into a 32-byte Swift
buffer and renders as a String via UTF-8 decoding.

## How the overlay composes with the existing V1 ladder

| V1 reason              | Pressure tag | Autotune behaviour (V2 session)              |
|------------------------|--------------|----------------------------------------------|
| `pressure`             | yes          | clamp to `min(target_with_0.5safety, current)` |
| `pressure_cooldown`    | yes          | same as `pressure`                           |
| `browser_replay_backoff` | yes        | same as `pressure`                           |
| `no_progress`          | yes          | same as `pressure`                           |
| `browser_burst_target` | no           | gated widen                                  |
| `post_demand_hold_12`  | no           | gated widen                                  |
| `healthy_hold` / `healthy_ramp` | no  | gated widen                                  |

So the existing Nebula-collapse / Vaultwarden hold=12 logic still drives
the V1-visible packet count, but the byte window can grow past 18 KB on
a healthy fast path.

## Expected log signature

Once on-device and the peer has upgraded to V2 and RTT+goodput have both
landed samples, the `[rtt-bdp]` line should show:

```
... v2=yes adv_kb=N auto_target_kb=M auto_reason=widen_healthy
```

where `M >> 16` on a fast path (Wi-Fi / cellular with decent throughput).
Good signatures to watch for:
- Initial: `v2=yes adv_kb=16 auto_target_kb=0 auto_reason=no_sample`
  (no RTT samples yet, autotune is idle)
- First healthy ticks: `auto_reason=hold_pre_widen` × 2
- Widen: `auto_reason=widen_healthy` with `adv_kb` bumping from 16 → 32+
- Steady-state on fast path: `auto_reason=hold_at_target` with `adv_kb >= 64`
- Pressure event: `auto_reason=pressure_clamp` with `adv_kb` shrinking but
  never below 8 (min bound)

Gateway logs will show `CLIENT_ACK_V2 ... window_kb=N` with `N` now varying
above 18 instead of pinned at 16-18.

## Gotchas that surfaced

1. **Goodput units confusion.** `goodput_bps` is `total_bytes × 8 / GOODPUT_WINDOW_BUCKETS`
   which is literally bits/sec averaged over the 8-sec window. To
   *represent* 10 Mbps in a test you need to push 10 MB of acked bytes
   into the window (not 1.25 MB / sec). Comment in the Phase A code says
   "total_bytes × 8 / 8 = total_bytes" which is technically correct as
   bits/sec when the window is 8 sec, but confusing when you're reading
   the formula cold. Autotune's BDP math uses `goodput_bps × srtt_ms / 8000`
   which gives bytes, consistent with the field's real units.

2. **RFC 6298 RTT smoothing collapses rapid ACK streams.** The first test
   helper had many back-to-back `observe_sent(t)` + `observe_ack_cumulative(t+5ms)`
   pairs to drive goodput, which dragged the smoothed RTT down from the
   intended 50 ms to 5 ms because every ACK generates an RTT sample.
   Fixed by making the test helper use a `rtt_ms` gap per pair, so
   `srtt` stays pinned.

3. **Healthy-tick counter semantics.** `AUTOTUNE_WIDEN_TICKS_NEEDED = 3`
   means "widen on the 3rd healthy tick, resetting the counter after".
   Tests had to count the initial "hold_pre_widen" tick as tick 1, not
   tick 0. Off-by-one caught by the `autotune_healthy_ticks_gate_widening`
   test.

4. **Gateway needs no change.** The gateway already converts `window_kb`
   → packet count via `max(1, div(window_kb*1024, 1140))`. That formula
   handles arbitrary `window_kb` values — no 16-packet ceiling on the
   gateway side. The ceiling was always on the iOS V1 ladder, which
   Phase D bypasses when V2 is active. Verified at
   `gateway/lib/ztlp_gateway/session.ex:1830-1840`.

## Deploy plan

1. ~~Rust changes merged~~ (done)
2. ~~FFI + header synced~~ (done)
3. ~~Swift log extended~~ (done)
4. **Pending**: push to origin main
5. **Pending**: Mac-side dual-lib rebuild + unsigned Xcode build
6. **Pending**: Steve deploys to phone, runs benchmark + Vaultwarden
7. **Pending**: pull log, confirm `auto_target_kb >> 16` on the fast path

No gateway deploy. Gateway already accepts arbitrary `window_kb` (Phase B).

## Rollback

Git-only (fastest):
```bash
cd /home/trs/ztlp
git reset --hard v-before-autotune
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push --force origin main
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git fetch && git reset --hard origin/main'
# Rebuild libs on Mac per ztlp-ios-dual-lib-build skill.
```

No gateway rollback needed — gateway is unchanged since `ztlp-gateway:ack-v2`.

## Phase E (future)

- **Phase C (deferred)**: `FRAME_MAX_STREAM_DATA = 0x11`, `FRAME_MAX_DATA = 0x12`
  — per-stream windows. Should be done once Phase D data-on-device
  confirms the autotuner behaves reasonably under real workloads.
- **Retire FRAME_ACK V1**: only after enough fleet is on V2. Not urgent.
