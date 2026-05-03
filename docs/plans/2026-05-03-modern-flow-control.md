# ZTLP Modern Flow Control — Design & Migration Plan

Status: **draft — handoff for a new session**
Author: Hermes Agent (working with Steve Price)
Date: 2026-05-03
Predecessor: `2026-05-03-ios-nebula-collapse-RUST-PHASE-COMPLETE.md`

## Why we're doing this

The Nebula-collapse cutover (commits through `1520730`) moved ZTLP's rwnd
policy and session-health detector into Rust and fixed the Vaultwarden
stall by holding `rwnd=12` instead of collapsing to `rwnd=4`. On-device
log from 2026-05-03 confirmed it works: rwnd now varies cleanly between
4 / 12 / 16, benchmark 8/8, Vaultwarden-class traffic no longer jams.

But the **shape** of ZTLP's flow control is still unusual and is the
ultimate source of browser/asset-tail stalls we keep chasing. This doc
explains what's weird, why most other tunnels don't have this problem,
and the concrete next step to modernize ZTLP's transport layer.

## The design mismatch

### What most VPNs do
Most VPNs don't implement their own receive window at all. They
encapsulate IP/UDP packets and let the host OS's TCP stack handle
everything:

| Product | Transport | VPN-layer rwnd? | Flow control lives in |
|---|---|---|---|
| WireGuard | UDP | **No** | Inner TCP on both ends |
| OpenVPN | UDP/TCP | **No** | OS TCP + `sndbuf/rcvbuf` tuning |
| IPsec (ESP) | IP | **No** | Inner TCP |
| Tailscale | UDP (WireGuard) | **No** | Inner TCP |
| Nebula | UDP | **No** | Inner TCP |
| ZeroTier | UDP | **No** | Inner TCP |

The VPN is a dumb pipe; the inner TCP session breathes naturally with
the path. No duplicate flow control, no protocol-layer window capping
the real TCP window underneath.

### What ZTLP does
ZTLP **decrypts, demuxes, and reframes** inner streams inside the
tunnel (for NS routing, per-service policy, replay defense). Once you
buffer and reorder, you need backpressure — so ZTLP added a
protocol-layer receive window in `FRAME_ACK`:

```
FRAME_ACK = [0x01 | cumulative_ack(8 BE) | rwnd(2 BE)]   // 11 bytes
```

Current policy (`proto/src/mux.rs`):
- `RWND_FLOOR = 4`
- `RWND_ADAPTIVE_MAX = 16`
- Unit: **frames** (each frame ≤ 1140 bytes of payload)
- Scope: **session-wide** (one window shared across all streams)

Effective byte windows:
```
rwnd=4    ≈  4.6 KB   (floor / pressure / recovery)
rwnd=12   ≈ 13.7 KB   (Vaultwarden hold — just shipped)
rwnd=16   ≈ 18.3 KB   (current ceiling)
```

### Why this is the wrong shape

18 KB of window, session-wide, frame-counted, is roughly **one TCP
initial-cwnd** (RFC 6928 recommends ~14.6 KB). It's a cold-start
quantity. Modern transports use it as the opening bid, then grow by
orders of magnitude:

| Transport | Initial window | Steady-state | Unit | Per-stream? |
|---|---|---|---|---|
| TCP (Linux autotune) | ~14.6 KB cwnd | 32 KB – 6 MB rwnd | **bytes** | one TCP = one stream |
| HTTP/2 default | 65,535 B / stream | 1 – 16 MB / conn | **bytes** | yes + conn-level |
| QUIC default | 256 KB / stream | 1 – 10 MB / conn | **bytes** | yes + conn-level |
| gQUIC (Chrome) | — | 15 MB / conn | **bytes** | yes + conn-level |
| **ZTLP today** | **~4.6 KB** | **~18 KB** | **frames** | **no (session-wide)** |

Three specific consequences of the current shape:

1. **Parallel-stream starvation.** WKWebView opens 6–8 concurrent
   fetches during a page load. With `rwnd=16` shared across all
   streams, each stream sees effectively 2 frames of credit. A
   single blocking stream starves the rest.
2. **Payload-size bias.** Small frames (DNS, ACKs, keepalives) burn
   the same window credit as full-MTU data frames. A chatty control
   stream can shrink the effective data-throughput window.
3. **No BDP awareness.** For a 50 ms / 10 Mbps path the BDP is ~64 KB.
   For 100 ms / 100 Mbps it's ~1.25 MB. ZTLP caps at 18 KB, so any
   path with decent bandwidth-delay product runs permanently
   window-limited regardless of what the gateway could actually accept.

## What "modern" looks like for ZTLP

Five design changes, in priority order:

### 1. Byte-based windows (not frame-count)
Reinterpret the `rwnd` field in `FRAME_ACK` as **bytes** instead of
frames. Small frames stop wasting credit; large frames don't get
artificially throttled. This is the change every modern transport made
in the late 2000s / early 2010s.

Wire impact: the `u16` field maxes at 65,535 B. We either:
- widen to `u32` (breaks wire compat, needs version gate), or
- keep `u16` but make the unit **KB** (4 KB granularity, max 256 MB),
  which is close to what HTTP/2's 4 KB "window update" shift does.

Recommendation: **KB-unit `u16`** on a new `FRAME_ACK_V2 = 0x10`.
Old `FRAME_ACK = 0x01` stays valid for peers that haven't upgraded,
so we can do a staged rollout.

### 2. Per-stream + connection-level two-tier windows
Today there's one session window. Add a per-stream window on top:

```
on OpenStream(sid):     receiver credit sid = initial_stream_window
on data(sid, n bytes):  credit_sid -= n; credit_conn -= n
on WINDOW_UPDATE(sid):  credit_sid += delta (stream-scoped)
on WINDOW_UPDATE(0):    credit_conn += delta (connection-scoped)
```

New frame types needed:
```
FRAME_MAX_STREAM_DATA  = 0x11  [0x11 | stream_id(4 BE) | window(4 BE)]
FRAME_MAX_DATA         = 0x12  [0x12 | window(4 BE)]
```

This directly kills the WKWebView parallel-stream starvation mode.

### 3. Autotuning based on RTT, loss, throughput
Replace the static ladder (4 → 12 → 16) with a policy:
- Sample RTT from probe / ACK round-trip times already recorded in
  `session_health`.
- Sample loss from `consecutive_full_flushes` and retransmit rate.
- Sample goodput from bytes-acked per second.
- Target window = min(configured_max, BDP × safety_factor).
- Back off on loss, replay bursts, `probe_outstanding`.

This is essentially CUBIC / BBR-lite but for the receiver side.
Reuse the existing `RwndPressureSignals` struct; add `smoothed_rtt_ms`
and `goodput_bps` fields.

### 4. Raise the initial window to BDP-sized
Start around **64 KB** session-wide, **16 KB** per-stream. Let
autotuning grow it into the MB range for fat paths. Keep the hard
cap configurable (suggest default 4 MB session, 1 MB per-stream).

### 5. Keep `rwnd=4` as an anti-abuse lever, not the default
Today the floor is the dominant mode because the ceiling is 18 KB.
In the new model, the floor exists only for:
- fresh session slow-start (first 1–2 RTTs)
- replay-detected emergency throttle
- admission control under gateway backpressure (gateway sets
  `send_queue_full` and we collapse)

It's no longer the window 90% of traffic sees.

## Concrete work plan (staged, safe rollback at each phase)

### Phase A — Instrumentation & measurement (no wire change)
Goal: prove we understand what the current tunnel is actually doing
before we change anything.

A.1. Add ACK-clocked RTT sampling to `proto::mux`:
     - timestamp outgoing DATA frames, match against cumulative ACK.
     - export `smoothed_rtt_ms`, `rtt_var_ms`, `min_rtt_ms` via FFI.

A.2. Add goodput sampling:
     - bytes-acked / second sliding window (8s).
     - export `goodput_bps`, `peak_goodput_bps`.

A.3. Log BDP each health tick:
     `bdp_kb = (smoothed_rtt_ms * goodput_bps) / 8000`.
     If `bdp_kb > 18`, we're demonstrably window-limited.

A.4. Ship behind `useRtt Instrumentation = true`. One iOS build,
     benchmark + Vaultwarden ×3, pull log, read BDP values.

Acceptance:
- log shows plausible RTT (tens of ms), non-zero goodput during
  benchmark, BDP numbers match intuition.
- No regression in benchmark 8/8 or Vaultwarden load.

### Phase B — FRAME_ACK_V2 with byte-unit window (wire change, gated)
Goal: land the byte-based window on the wire without breaking existing
clients.

B.1. Add `FRAME_ACK_V2 = 0x10` in `proto/src/mux.rs`:
     `[0x10 | cumulative(8 BE) | window_kb(2 BE)]`
     Max advertised window: 65535 × 1024 = 64 MB. Plenty of room.

B.2. Gateway change:
     - parse both 0x01 and 0x10.
     - when peer has sent any 0x10, reply in 0x10.
     - when peer has only sent 0x01, stay on 0x01 (back-compat).

B.3. iOS change (behind `useByteRwnd = true`):
     - `proto::mux::tick_rwnd` returns a byte window.
     - encode as `FRAME_ACK_V2`.
     - Swift layer stops multiplying frames × 1140.

B.4. Server-side preflight + one-shot device build + Vaultwarden ×3.
     Rollback tag before this phase: `v-before-byte-rwnd`.

Acceptance:
- wireshark / gateway log shows 0x10 frames flowing.
- iOS log shows `rwnd_bytes=65536` range during benchmark.
- benchmark 8/8, Vaultwarden 3/3.

### Phase C — Per-stream windows
Goal: kill parallel-stream starvation.

C.1. Add `FRAME_MAX_STREAM_DATA = 0x11` and
     `FRAME_MAX_DATA = 0x12` to the wire.

C.2. In `proto::mux`:
     - track per-stream receiver credit (`HashMap<StreamId, i64>`).
     - default on OPEN: `initial_stream_window_kb` (config, default 16 KB).
     - emit `FRAME_MAX_STREAM_DATA` when credit is consumed past 50%.

C.3. Gateway side: same ledger, honor the per-stream cap in
     `encrypt_send_frame` so we never fill a stream beyond its credit.

C.4. Remove the session-wide 18 KB ceiling behavior. Session window
     becomes the sum/cap; per-stream is the hot-path throttle.

Acceptance:
- Vaultwarden page with 6 parallel assets loads without any one stream
  blocking the others.
- Gateway log shows per-stream credit moving independently.

### Phase D — Autotuning policy
Goal: replace the static ladder with RTT/loss/goodput-driven sizing.

D.1. Implement `AutotuneState` in `proto::mux`:
     ```
     target_bytes = clamp(
         min_window,
         max_window,
         smoothed_rtt * peak_goodput * safety_factor
     );
     ```
     safety_factor = 2.0 on healthy ticks, 0.5 on loss/replay.

D.2. Integrate into `tick_rwnd`. Replace the `RWND_FLOOR=4 /
     RWND_ADAPTIVE_MAX=16` ladder entirely.

D.3. Tunables in `proto::config`:
     - `min_window_kb` (default 8)
     - `max_window_kb` (default 4096)
     - `stream_min_window_kb` (default 8)
     - `stream_max_window_kb` (default 1024)

D.4. Anti-abuse: if gateway advertises `send_queue_full`, clamp to
     `min_window_kb` for 5s regardless of autotune output.

Acceptance:
- on a fast path (Mac-to-gateway on wifi) the window grows past 128 KB
  during benchmark.
- on a lossy path (phone cellular) it oscillates around BDP without
  pinning at floor.

### Phase E — Retire legacy `FRAME_ACK = 0x01`
Only after enough fleet is on V2. Gated by gateway config flag and a
known rollout window. Not urgent — old format works fine as a fallback.

## Files that will change

Rust:
- `proto/src/mux.rs` — new frame types, autotune state, per-stream windows
- `proto/src/ffi.rs` — FFI signatures for autotune inputs/outputs
- `proto/include/ztlp.h` — regenerate
- `gateway/src/mux_handler.rs` (or wherever gateway decodes FRAME_ACK)

iOS Swift:
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` — swap `ztlp_mux_tick_rwnd`
  for new byte-window call, plumb RTT/goodput into inputs, apply
  `setAdvertisedReceiveWindow` with byte value (rename to
  `setAdvertisedByteWindow`).
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift` — encode/decode new frames.

Docs:
- `docs/WIRE-FORMAT.md` — document FRAME_ACK_V2, FRAME_MAX_STREAM_DATA,
  FRAME_MAX_DATA.

Tests:
- `proto/src/mux.rs` — extend existing 25 mux tests with byte-window,
  per-stream, autotune coverage. Aim for 40+ tests.
- Linux integration harness under `proto/src/ios_tunnel_engine.rs`.

## Open questions for the next session

1. **Gateway team coordination.** Phase B is the first change that
   requires a gateway deploy. Who owns the gateway-side FRAME_ACK_V2
   parser? Is the gateway repo in `/home/trs/ztlp/gateway/` or a
   separate project? Check with Steve before touching anything.

2. **Mac-side mux impl.** Steve's Mac app uses a different build of
   `libztlp_proto.a` than iOS? Need to verify the Mac wire client also
   picks up FRAME_ACK_V2 or it'll degrade to V1.

3. **How far do we go on autotune?** CUBIC-equivalent is overkill for a
   VPN overlay. BBR-lite is the right target — 2 RTT samples + goodput
   is enough. Don't overbuild.

4. **Config surface.** Where do `min_window_kb` etc. live? If in
   `proto::config`, who sets them on iOS? Probably needs a new
   `ztlp_set_flow_control_config` FFI call that the Swift side reads
   from `UserDefaults` / bootstrap config.

5. **Does the gateway have a hard cap?** Current gateway may clamp
   advertised rwnd at some internal max before echoing back. Phase A
   instrumentation should surface this — if gateway clamps at e.g.
   16 frames, we need a gateway change before Phase B is visible.

## Rollback strategy

Each phase gets its own git tag:
- `v-before-rtt-instrumentation`
- `v-before-byte-rwnd`
- `v-before-per-stream-windows`
- `v-before-autotune`
- `v-before-frame-ack-v1-retire`

On any regression:
```
cd /home/trs/ztlp
git reset --hard v-before-<phase>
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push --force origin main
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git fetch && git reset --hard origin/main'
```

## How to start the next session

1. Load this doc first: `docs/plans/2026-05-03-modern-flow-control.md`.
2. Load the Nebula-collapse status skill:
   `skill_view(name='ztlp-nebula-collapse-status')` for the context of
   what just landed.
3. Confirm with Steve: "Phase A (RTT instrumentation, no wire change)
   is the first step. OK to start?"
4. Run `scripts/ztlp-server-preflight.sh` → require PRECHECK GREEN.
5. Begin Phase A.

## Acceptance for "ZTLP has modern flow control"

- Byte-based windows on the wire.
- Per-stream credits visible in benchmarks (6 parallel streams each
  show independent credit evolution).
- Steady-state window on a fast path > 256 KB.
- No more Vaultwarden-class stalls even without the `hold=12` special
  case (the autotuner obviates it).
- iOS log no longer shows any reference to `rwnd=4 / 12 / 16` — it's
  all byte values, all dynamic.

When all five land, ZTLP's flow control looks like HTTP/2 / QUIC
instead of like TCP initial-cwnd. That's the target.
