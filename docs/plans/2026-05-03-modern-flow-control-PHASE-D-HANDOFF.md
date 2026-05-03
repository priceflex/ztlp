# ZTLP Modern Flow Control — Phase D Handoff

Status: **Phase D code merged, hook-ordering fix pending rebuild, Vaultwarden stall traced to gateway BBR (separate issue)**
Date: 2026-05-03 (UTC evening)
Author: Hermes Agent (working with Steve Price)
Current commit on main: `9848f9e` (Phase D autotune)
Local uncommitted change: hook-ordering fix in `PacketTunnelProvider.swift`
Rollback tags: `v-before-byte-rwnd` (Phase B), `v-before-autotune` (Phase D)

---

## TL;DR

1. Phase B (FRAME_ACK_V2 byte-unit window) shipped and **verified on-device
   earlier today** — gateway saw 607 `CLIENT_ACK_V2` lines vs 84 V1, phone
   log showed `v2=yes adv_kb=16` sticky from 05:17:55 UTC onward.
2. Phase D (BBR-lite autotune overlay) code landed, tests green
   (58/58 mux, 1006/1006 lib). No wire change. No gateway deploy.
3. On-device smoke test 18:33–18:34 UTC revealed **two bugs**:
   - **Hook ordering bug** (iOS) — `wireRttInstrumentationHook` runs
     before `rustMux` is created, so `ztlp_mux_note_peer_sent_v2` is
     silently skipped. Autotune stays on the `"v1_legacy"` no-op path.
     **Fix applied, not yet built/tested.**
   - **Gateway BBR cwnd=4 pinning** — gateway congestion control thinks
     `btl_bw=35625 bps ≈ 285 kbps`, so cwnd=4. That's the real
     Vaultwarden stall cause. **Not a Phase D problem.**

Next session should: (1) commit the hook fix, rebuild Mac-side libs, ask
Steve to redeploy + benchmark (should now see `auto_reason=widen_healthy`
and `auto_target_kb` climbing past 16), (2) then tackle gateway BBR.

---

## Where the code is right now

### Committed + pushed (main @ 9848f9e)

```
9848f9e phase-d: BBR-lite autotune overlay for V2 byte window
bbcab4b docs(phase-b): landed handoff (gateway deployed ack-v2, md5 verified, preflight green)
9d77958 phase-b: FRAME_ACK_V2 byte-unit receive window (Rust + Elixir gateway + iOS)
dc6946d phase-a: RTT/goodput/BDP instrumentation
1520730 ios: cutover to Rust MuxEngine rwnd + SessionHealth
```

### Uncommitted local change

`ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` — hook-ordering fix
(see next section for detail). Run `git diff` in `/home/trs/ztlp` to see.

### Server state

- Gateway `44.246.33.34` running `ztlp-gateway:ack-v2` (MD5
  `31237063fdaa2cdf18ff874b9f6cb08e` on `Elixir.ZtlpGateway.Session.beam`).
  Up since Phase B deploy. **No Phase D deploy needed** — gateway is wire-
  compatible unchanged.
- Relay `34.219.64.205`, NS `34.217.62.46` — both healthy, pre-flight GREEN.
- Mac at `stevenprice@10.78.72.234` has `ztlp-gateway:ack-v2` iOS libs +
  ztlp.h synced as of 2026-05-03 05:33 local. Needs a fresh dual-lib
  rebuild **after** we commit the hook fix.

---

## Bug #1 — iOS hook ordering (Phase B latent, Phase D surfaced)

### What we observed

Phone log (2026-05-03 ~18:33 UTC) after Phase D install:

```
[rtt-bdp] srtt=45ms ... v2=no adv_kb=18 auto_target_kb=0 auto_reason=v1_legacy
[rtt-bdp] srtt=45ms ... v2=no adv_kb=5  auto_target_kb=0 auto_reason=v1_legacy
[rtt-bdp] srtt=41ms ... v2=no adv_kb=18 auto_target_kb=0 auto_reason=v1_legacy
```

`v2=no` — the Rust MuxEngine's `peer_speaks_v2` flag never flipped to true,
so autotune's early-exit `"v1_legacy"` path ran instead. Gateway DID see
0x10 frames (`grep CLIENT_ACK_V2 gateway logs` → 6,362 matches), proving
the Swift side emits V2 ACKs via the standalone `ztlp_build_ack_v2` path.
So the problem is **purely local**: engine flag never set.

### Root cause

In `PacketTunnelProvider.swift`:

```swift
// Line 857-858  (startTunnel, after handshake, before MuxEngine init)
self.tunnelConnection = conn
self.wireRttInstrumentationHook(on: conn)   // ← mux doesn't exist yet

// ... 60+ lines later ...

// Line 924-927  (inside `if Self.useRustMux { ... }`)
if let mux = ztlp_mux_new() {
    self.rustMux = mux                      // ← now it exists
    self.logger.info("Rust MuxEngine ready ...")
}
```

Inside `wireRttInstrumentationHook`:

```swift
conn.useByteRwnd = Self.useByteRwnd
if Self.useByteRwnd, let mux = rustMux {    // ← guard fails, branch skipped
    _ = ztlp_mux_note_peer_sent_v2(mux)
    ...
}
```

The `let mux = rustMux` nil-guard silently bails, so `note_peer_sent_v2` is
never called. Only the `conn.useByteRwnd = true` side effect fires — which
is why the Swift ACK path emits 0x10 frames (that's gateway-side visible),
but the Rust engine's `peer_speaks_v2` stays false (phone log visible).

### Why Phase B verified test masked this

The morning Phase B log (`2026-05-03-modern-flow-control-PHASE-B-VERIFIED.md`)
shows:

```
05:17:43  v2=no  adv_kb=14         ← fresh session, hook ran with nil mux
05:17:45  v2=no  adv_kb=18
05:17:47  v2=no  adv_kb=5
05:17:51  v2=no  adv_kb=5
05:17:55  v2=yes adv_kb=16  ← flipped after reconnect around 05:17:54
05:17:59  v2=yes adv_kb=16
```

Gateway log confirms: `05:17:54.192 [info] [Listener] Replacing session
69428E89AD1CDBDDE45C6F98 ... new HELLO received`. Reconnect re-entered
the session-setup path, this time with `rustMux` already non-nil from
the prior session, so the hook's V2 branch fired and flipped the engine.

**In short**: Phase B's "VERIFIED" log was an accident. The hook only works
after a reconnect. Steve's 18:33 test had no reconnect — single clean
session — so the bug was visible the whole time.

### Fix (uncommitted in working tree)

`ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` around line 927:

```swift
if Self.useRustMux {
    if let mux = ztlp_mux_new() {
        self.rustMux = mux
        self.logger.info("Rust MuxEngine ready (useRustMux=true)", source: "Tunnel")
        // Re-run the Rtt/Rwnd instrumentation hook now that
        // `rustMux` exists. The earlier call at step 8
        // (line ~858) runs before the MuxEngine is created
        // so its `ztlp_mux_note_peer_sent_v2(mux)` branch
        // is silently skipped — that's the Phase B "v2=no
        // stuck" bug surfaced by Phase D logs. Second call
        // is idempotent on the connection side and makes
        // the engine's peer_speaks_v2 flag true before the
        // first tick_rwnd, so autotune engages from tick 1.
        self.wireRttInstrumentationHook(on: conn)
    } else {
        self.logger.warn("ztlp_mux_new returned null; falling back to legacy rwnd ramp", source: "Tunnel")
    }
}
```

Hook is already idempotent (it just sets `conn.useByteRwnd` + conditionally
calls `note_peer_sent_v2`, both safe to repeat).

### Verification plan

1. Commit fix + push.
2. Rebuild Mac-side libs (`ztlp-ios-dual-lib-build` skill).
3. Steve Xcode Clean Build, deploy to phone, run benchmark.
4. Pull log. Confirm:
   - Phone: `v2=yes` appears on the **first** `[rtt-bdp]` line after
     "Rust MuxEngine ready" (not waiting for a reconnect).
   - Phone: `auto_reason` cycles through `no_sample` → `hold_pre_widen`
     → `widen_healthy` → `hold_at_target` as RTT/goodput samples land.
   - Phone: `auto_target_kb > 16` on a fast path with real throughput.
   - Gateway: `CLIENT_ACK_V2 window_kb=N` with N > 18 once autotune widens.

---

## Bug #2 — Gateway BBR cwnd pinned at 4 (Vaultwarden stall)

### What we observed

Phone log 18:34:24 onward (Vaultwarden page load kicked off):

```
18:34:24  6 flows open, streams 15/18/19 for Vaultwarden assets
18:34:26  rwnd=16 flows=6 oldestMs=1427 healthy
18:34:32  rwnd=4  oldestMs=7423 stuckTicks=1 usefulRxAge=3.5s  ← session suspect
18:34:32  ztlp_health_tick SEND_PROBE nonce=15               ← probes fire
18:34:32  probe response ok, but flows still suspect          ← preserve session
18:34:34  SEND_PROBE nonce=16  usefulRxAge=5.5s  highSeq=3569 (frozen)
18:34:36  SEND_PROBE nonce=17  usefulRxAge=7.5s  rwnd=4
18:34:38  SEND_PROBE nonce=18  usefulRxAge=9.5s  rwnd=4
```

`highSeq` frozen at 3569 means **gateway isn't sending any new data down**.
Phone is healthy (probes get responses), but no inbound DATA frames.

### Gateway-side evidence

Gateway logs in the same time window:

```
18:34:24.066  pacing_tick: 19 queued, 16/16 inflight/cwnd, ssthresh=64
18:34:24.096  [BBR] state=probe_rtt cwnd=4.0 btl_bw=35625 rt_prop=32 inflight=10561 bdp=1140 pacing=35625
18:34:24.121  pacing_tick: 58 queued, 12/12 inflight/cwnd    ← queue buildup
18:34:24.128  pacing_tick: 128 queued, 12/12 inflight/cwnd   ← Vaultwarden burst arrives
```

Distribution of BBR states in the 15-minute window:

```
395  state=probe_bw  cwnd=4.0
 19  state=drain     cwnd=4.0
 16  state=startup   cwnd=4.0
 12  state=probe_rtt cwnd=4.0
 10  state=probe_bw  cwnd=5.0
```

**452/452 BBR ticks ran with cwnd ≤ 5.** BBR's bandwidth estimate `btl_bw=35625 bytes/sec`
(= 285 kbps). With `rt_prop=32ms`, BDP = 35625 × 0.032 = 1140 bytes = 1
packet. BBR then sets cwnd ≈ 4 × BDP = 4 packets. That cap is what's
choking Vaultwarden.

### Why Phase D can't help this case

Autotune widens the **client's advertised rwnd**. The gateway's effective
send window is:

```
effective_window = min(cwnd, cc_max_cwnd, peer_rwnd)
                 = min(4,    cc_max_cwnd, 16+)        = 4
```

Gateway BBR is the binding constraint, not client rwnd. Phase D lifts the
ceiling but the floor is already below 4.

### Known pre-existing issue

The `ztlp-wire-frame-extension` skill and handoff notes mention "2 pre-existing
BBR fails" in the gateway test suite (`gateway/test/...bbr_test.exs`).
Never chased down because it didn't block Phase A/B/D landings. Now it's
the visible user-facing blocker.

### What the next session should investigate

1. `gateway/lib/ztlp_gateway/bbr.ex` (or wherever the BBR implementation
   lives — path not confirmed) — find `btl_bw` / `rt_prop` update logic.
2. Questions to answer:
   - Why does `btl_bw` saturate at ~35,625 bytes/sec? Hardcoded clamp?
     Broken max-filter?
   - Does BBR ever exit probe_rtt cleanly? (12 ticks in probe_rtt is a
     lot — should be rare brief visits.)
   - Is `cc_max_cwnd` applied correctly?  What's its value?
   - Does the pacing rate (`pacing=35625`) match what the UDP send side
     actually pushes? (Could be the pacing clamp itself is the limit.)
3. Failing BBR tests — run `cd gateway && mix test test/ztlp_gateway/*bbr*`
   and see what they say. Those are probably pointing at the bug already.
4. Consider: is BBR even the right CC for this tunnel, or should it fall
   back to CUBIC / NewReno for mobile paths?

### Cross-check

The Phase B verified session this morning had the same gateway BBR code
and the benchmark got 8/8, Vaultwarden × 3 OK. So BBR isn't *always*
broken — something about today's session (wifi conditions?  reconnect
path?) put it into a stuck state. Check handshake logs / client profile
for this session vs morning's:

```
# Grep gateway log for ClientProfile lines from both sessions
ssh ubuntu@44.246.33.34 'docker logs ztlp-gateway 2>&1 | grep "ClientProfile" | tail -20'
```

---

## File inventory (what changed, what to know)

### Rust (`proto/src/mux.rs`, `proto/src/ffi.rs`, `proto/include/ztlp.h`)

- Phase D is fully landed. 58/58 mux tests + 1006/1006 lib tests pass.
- Key constants: `AUTOTUNE_MIN_WINDOW_KB=8`, `AUTOTUNE_MAX_WINDOW_KB=4096`,
  `AUTOTUNE_HEALTHY_SAFETY_NUM/DEN=2/1`, `AUTOTUNE_PRESSURE_SAFETY_NUM/DEN=1/2`,
  `AUTOTUNE_WIDEN_TICKS_NEEDED=3`.
- New FFI: `ztlp_mux_set_autotune_bounds_kb`, `_autotune_target_kb`,
  `_autotune_min_kb`, `_autotune_max_kb`, `_autotune_reason`.
- `tick_rwnd` refactored into `tick_rwnd_v1_ladder` + `autotune_tick`
  overlay. V1-only sessions get `"v1_legacy"` no-op; V2 sessions get
  one of `{no_sample, widen_healthy, hold_pre_widen, hold_at_target,
  shrink_to_target, pressure_clamp}`.

### iOS Swift (`ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`)

- Committed: `[rtt-bdp]` log extended with `auto_target_kb=N auto_reason=TAG`.
- **Uncommitted working tree**: second `wireRttInstrumentationHook` call
  after `self.rustMux = mux` assignment (the fix for bug #1).

### iOS `ztlp.h` (copy of `proto/include/ztlp.h`)

- Synced to `ios/ZTLP/Libraries/ztlp.h` after Phase D FFI additions.

### Gateway (`gateway/lib/ztlp_gateway/session.ex`)

- **Unchanged since Phase B.** Accepts FRAME_ACK_V2 (0x10) + does byte→packet
  math. `peer_rwnd_bytes` field already set. No Phase D deploy.

### Docs

- `docs/plans/2026-05-03-modern-flow-control.md` — master plan (Phase A/B/C/D/E)
- `docs/plans/2026-05-03-modern-flow-control-PHASE-A-LANDED.md`
- `docs/plans/2026-05-03-modern-flow-control-PHASE-B-VERIFIED.md` ← renamed from *-PHASE-B-LANDED.md after on-device verification
- `docs/plans/2026-05-03-modern-flow-control-PHASE-D-LANDED.md` — written with Phase D details
- `docs/plans/2026-05-03-modern-flow-control-PHASE-D-HANDOFF.md` — **this file**

---

## How to resume in a new session

1. `cd /home/trs/ztlp && git status` — should show modified
   `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` (the hook fix).
2. Load this doc first, then load these skills:
   - `ztlp-ios-dual-lib-build` (for Mac rebuild)
   - `ztlp-wire-frame-extension` (already updated with Phase D learnings)
   - `ztlp-prod-deployment` (only if gateway needs a deploy — it doesn't
     for Phase D, will for BBR work)
3. Confirm with Steve: "Rebuild with hook fix first, then tackle
   gateway BBR?" (Steve previously chose this sequence.)
4. Run pre-flight: `bash /home/trs/ztlp/scripts/ztlp-server-preflight.sh`
   → require PRECHECK GREEN.
5. Commit hook fix, push, Mac rebuild, Steve retest.

---

## Specific commands for next session

```bash
# 1. Commit hook fix (author as Steven Price per his preference)
cd /home/trs/ztlp
git diff ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift   # sanity-check the patch
git add ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
git -c user.name="Steven Price" -c user.email="steve@techrockstars.com" commit -m \
  "ios: fix phase-b/d hook ordering — re-run wireRttInstrumentationHook after rustMux init

Hook calls ztlp_mux_note_peer_sent_v2(mux) inside an \`if let mux = rustMux\`
guard. The original call site at line ~858 runs before self.rustMux is
created at line ~926, so the guard fails silently and the engine never
learns it's speaking V2. Phase B's on-device verification morning ran
only worked because of a reconnect that re-entered the setup path after
rustMux was non-nil; the clean session Steve tested this evening hit
the bug plain.

Fix: second wireRttInstrumentationHook(on: conn) call immediately after
self.rustMux = mux. Idempotent; cheap."
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push origin main

# 2. Rebuild on Mac (per ztlp-ios-dual-lib-build skill)
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git pull origin main --ff-only'
# … then the dual-lib build + header copy + xcodebuild unsigned …

# 3. Preflight + hand off to Steve
bash /home/trs/ztlp/scripts/ztlp-server-preflight.sh 2>&1 | tail -5
```

---

## Log signatures to look for on successful Phase D retest

### Phone (pulled via `xcrun devicectl ... ztlp.log`)

Good signatures (in order):

```
[Tunnel] Rust MuxEngine ready (useRustMux=true)
[Tunnel] [rtt-bdp] ... v2=yes adv_kb=16 auto_target_kb=0 auto_reason=no_sample
[Tunnel] [rtt-bdp] ... v2=yes adv_kb=16 auto_target_kb=0 auto_reason=no_sample
[Tunnel] [rtt-bdp] ... v2=yes adv_kb=16 auto_target_kb=64 auto_reason=hold_pre_widen
[Tunnel] [rtt-bdp] ... v2=yes adv_kb=16 auto_target_kb=64 auto_reason=hold_pre_widen
[Tunnel] [rtt-bdp] ... v2=yes adv_kb=64 auto_target_kb=64 auto_reason=widen_healthy
[Tunnel] [rtt-bdp] ... v2=yes adv_kb=64 auto_target_kb=64 auto_reason=hold_at_target
```

`v2=yes` on the FIRST line (not waiting for a reconnect). `auto_reason`
progresses through the states. `auto_target_kb` climbs past 16.

### Gateway (`docker logs ztlp-gateway | grep CLIENT_ACK_V2`)

```
CLIENT_ACK_V2 data_seq=... window_kb=64 (=57 packets) ...
```

`window_kb=64+` instead of pinned at 18.

### Still expected (because BBR bug is separate)

Gateway BBR still likely stuck at cwnd=4 until we fix it. That means
benchmark throughput won't improve much even with autotune working.
**Phase D itself is correct; BBR is the next phase.**

---

## Open decisions for next session

1. **Rebuild + retest on same day, or batch the BBR fix in too?**
   Steve's call. Small rebuild costs ~10 min, gives us Phase D proof-of-life.
2. **Where does gateway BBR live in the tree?** Not confirmed — worth
   a quick `find gateway -name "*bbr*"` early on.
3. **Is there a safer CC fallback for mobile paths?** Reno/Cubic instead
   of BBR while BBR's estimator is broken? Trade-off between throughput
   ceiling and stability.

---

## Memory / skill updates already applied this session

- `ztlp-wire-frame-extension` skill patched with a "NO-wire-change
  protocol evolution" adjacent pattern (Phase D class) — covering the
  goodput-units bug, RTT smoothing collapse, healthy-tick gate semantics,
  and FFI-string-return pattern.
- Phase B doc renamed `-PHASE-B-LANDED.md` → `-PHASE-B-VERIFIED.md` with
  on-device evidence appended.
- Phase D doc `-PHASE-D-LANDED.md` written (commit-time handoff).
- This doc `-PHASE-D-HANDOFF.md` for the next session.
