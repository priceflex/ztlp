# ZTLP Modern Flow Control — Phase D VERIFIED

Status: **Phase D client-side COMPLETE and VERIFIED on-device.** Two bugs
found and fixed; next blocker is gateway-side AIMD + RTO cascade, which
is a separate investigation.

Date: 2026-05-03 (UTC evening, continuation of the Phase D session)
Author: Hermes Agent (with Steve Price)
Current commit on main: `de64ded` (autotune cold-start fix)
Rollback tags: `v-before-byte-rwnd` (Phase B), `v-before-autotune` (Phase D)

---

## TL;DR

Phase D landed with **two latent bugs** that only surfaced on-device:

1. **Hook ordering bug** (Phase B latent, Phase D amplified).
   `wireRttInstrumentationHook(on: conn)` ran BEFORE `self.rustMux = mux`,
   so the hook's `let mux = rustMux` nil-guard silently skipped
   `ztlp_mux_note_peer_sent_v2(mux)`. Engine's `peer_speaks_v2` stayed
   false, autotune fell into its `v1_legacy` no-op path for the whole
   session. Fixed in `b1648fd`.

2. **Autotune cold-start shrink trap** (Phase D logic bug).
   On tick 1, with a tiny goodput sample, BDP estimate is near zero →
   target clamps to `AUTOTUNE_MIN_WINDOW_KB=8`, which is BELOW
   `DEFAULT_INITIAL_WINDOW_KB=16` → `shrink_to_target` branch fires →
   window collapses from 16 KB to 8 KB and stays there. Fixed in
   `de64ded`: healthy-shrink path now floors at initial window.

Both fixes verified on-device with clean sessions. Phase D autotune
engages correctly: `v2=yes` on tick 1, `shrink_to_target` no longer
drops below 16 KB on cold start.

**New blocker** (separate from Phase D): gateway-side **AIMD + RTO
cascade** — gateway sends data_seq=0..4, client ACKs 0..3 cumulatively,
then STOPS acking. Gateway RTO-retransmits `data_seq=4 seq=6` 13+
times in 23 seconds, halving cwnd each time to 7 packets. Queue grows
to 126+ packets waiting. Phone session_health_probe_timeout → reconnect.
Post-reconnect SRTT gets poisoned by the 7-second gap (jumps from 37 ms
to 2865 ms and never recovers). This is a **different bug** than the
"gateway BBR cwnd=4" story we thought it was this morning.

Next session should: **investigate the data_seq=4 HOL-block** — why
does the client stop ACKing after data_seq=3? Is the frame lost on the
wire (which would require retransmit/recovery), or received but
dropped by the client (decrypt fail, replay window, mux frame parse
error)?

---

## What changed this session

### Commits on main

```
de64ded phase-d: floor healthy-path autotune at DEFAULT_INITIAL_WINDOW_KB (cold-start fix)
b1648fd ios+docs: fix phase-b/d hook ordering bug + handoff for new session
9848f9e phase-d: BBR-lite autotune overlay for V2 byte window
bbcab4b docs(phase-b): landed handoff (gateway deployed ack-v2, md5 verified, preflight green)
9d77958 phase-b: FRAME_ACK_V2 byte-unit receive window (Rust + Elixir gateway + iOS)
```

### Rust tests

`proto/src/mux.rs`: **60/60 mux tests passing** (was 58). Two new
regression tests for the cold-start floor:

- `autotune_does_not_shrink_below_initial_window_on_cold_start` — feeds
  the exact on-device conditions (796 bps / 35 ms RTT) to reproduce
  the shrink-to-8KB cascade; asserts adv stays at/above 16 KB.
- `autotune_pressure_may_shrink_below_initial_window` — asserts the
  pressure path is still allowed to go below initial, so we don't
  overcorrect.

Run: `cd proto && cargo test --lib --features ios-sync mux::`

### iOS libs on Mac

Steve's Mac (`stevenprice@10.78.72.234`) is synced to `de64ded` with
fresh dual libs at `ios/ZTLP/Libraries/libztlp_proto{,_ne,_sim,_ne_sim}.a`
and updated `ztlp.h`. NE lib SHA256 changed between the two rebuilds
confirming new code is in.

### Skills updated

- `ztlp-wire-frame-extension` — patched with the cold-start shrink trap
  as a new pitfall under the "adjacent pattern: NO-wire-change protocol
  evolution (Phase D)" section. Future phases that add BDP-sized policies
  won't repeat the mistake.

---

## On-device evidence

### Test session 1 (18:47:34 UTC, post-hook-fix only)

Commit `b1648fd` on phone.

```
[Tunnel] Rust MuxEngine ready (useRustMux=true)                   ← 18:47:34
[Tunnel] [rtt-bdp] srtt=35ms goodput=796bps v2=yes adv_kb=8       ← 18:48:06
        auto_target_kb=8 auto_reason=shrink_to_target             ← COLD-START BUG
[Tunnel] [rtt-bdp] ... v2=yes adv_kb=8 auto_target_kb=8           ← pinned at 8 KB
        auto_reason=hold_at_target | pressure_clamp
```

Hook fix CONFIRMED: `v2=yes` on first `[rtt-bdp]` line, no reconnect
needed. Cold-start bug surfaced: autotune shrank 16→8 KB on tick 1.

### Test session 2 (19:05:44 UTC, post-hook-fix + cold-start fix)

Commit `de64ded` on phone.

```
[Tunnel] Rust MuxEngine ready (useRustMux=true)                   ← 19:05:44
[Tunnel] [rtt-bdp] srtt=37ms goodput=3427bps v2=yes adv_kb=16     ← 19:05:48
        auto_target_kb=8 auto_reason=shrink_to_target             ← floor HELD (adv=16, not 8!)
[Tunnel] [rtt-bdp] srtt=37ms goodput=3427bps v2=yes adv_kb=16     ← 19:05:52
        auto_target_kb=8 auto_reason=shrink_to_target             ← still holding at 16
[Tunnel] [rtt-bdp] ... v2=yes adv_kb=8  auto_target_kb=8          ← 19:05:56
        auto_reason=pressure_clamp                                ← pressure → 8 KB
                                                                     (correctly allowed)
```

Cold-start fix CONFIRMED: adv_kb stayed at 16 for 2 ticks (4 seconds),
then genuine pressure allowed the shrink below initial — exactly the
design intent.

---

## The REAL current blocker — gateway-side HOL-block

### What the gateway is doing at 19:06:17+ UTC

```
19:06:17.188 RTO retransmit data_seq=4 seq=6 elapsed=1020ms rto=987ms attempt=6
19:06:17.813 RTO retransmit data_seq=4 seq=6 elapsed=1020ms rto=995ms attempt=6
19:06:18.196 RTO retransmit data_seq=4 seq=6 elapsed=1530ms rto=1504ms attempt=7
19:06:18.718 RTO retransmit data_seq=4 seq=6 elapsed=1530ms rto=1481ms attempt=7
19:06:19.343 RTO retransmit data_seq=4 seq=6 elapsed=1530ms rto=1492ms attempt=7
19:06:20.434 RTO retransmit data_seq=4 seq=6 elapsed=3315ms rto=3306ms attempt=9
...
19:06:40.579 RTO retransmit data_seq=4 seq=6 elapsed=5049ms rto=5000ms attempt=13
```

Gateway is retransmitting **the same packet** (data_seq=4 seq=6) 13+
times over 23 seconds. Attempt counter climbs monotonically. RTO
doubles each time (Reno backoff), capped at 5 seconds.

Meanwhile pacing_tick shows:

```
pacing_tick: 41 queued, 7/7 inflight/cwnd, ssthresh=64 open=false
pacing_tick: 126 queued, 7/7 inflight/cwnd, ssthresh=64 open=false  ← Vaultwarden burst
```

126 packets queued, cwnd stuck at 7 because every RTO event halves cwnd.
`max_cwnd=32` for this session's profile (mobile+wifi) — NOT the bind.

### What the phone is doing

```
19:06:05  Mux summary gwData=203/147793B                       ← receiving 148 KB data
19:06:06  Mux summary gwData=205/150047B
19:06:07  Mux summary gwData=203/148587B
```

Phone IS receiving data frames. But gateway CLIENT_ACK logs (later in
the same log file at 19:11) reveal the pattern:

```
CLIENT_ACK data_seq=0 ... inflight=5
CLIENT_ACK data_seq=1 ... inflight=4
CLIENT_ACK data_seq=2 ... inflight=3
CLIENT_ACK data_seq=3 ... inflight=2
<silence>  ← data_seq=4+ never ACKed
```

Client ACKs 0..3 cumulatively, then stops. That's why gateway
retransmits `data_seq=4 seq=6` forever.

### Candidate explanations for the stall

1. **Packet loss on specific flows.** The first few post-reconnect
   packets get through; `data_seq=4` gets dropped somewhere (NAT
   state, mobile path glitch). Retransmit should recover, but if
   the retransmit ALSO loses, we loop. The persistent attempt=13
   suggests something more than occasional loss.
2. **Client-side mux frame parse failure on data_seq=4.** Phone
   receives the UDP packet, decrypts it, but the MuxFrame decoder
   rejects it silently. No ACK generated. Check phone log for
   decode errors around 19:06:10–15.
3. **Client rwnd=4 blocking receiver.** At 19:06:00 the phone's
   own V1 rwnd ladder dropped to `rwnd=4` (pressure). Combined with
   the reconnect, the receive window might be rejecting data_seq=4
   as "out of window" without surfacing the rejection in visible
   logs.
4. **Stream routing failure.** data_seq=4 is on a stream that the
   phone's router hasn't fully re-attached after reconnect. Frame
   received but discarded.
5. **Encryption counter mismatch.** Post-reconnect nonce/counter
   state may be off by one between gateway and phone for a specific
   flow.

### Client-side SRTT poisoning (secondary concern)

At 19:06:04 phone SRTT jumps from 37 ms to **2865 ms** with
`latest=7107 ms`. A single sample with a 7-second gap (post-reconnect
latency) was admitted into the smoother and dominated the estimate.
Autotune is then stuck using `srtt=2865 ms` in its BDP math — even
if goodput recovered, the target would overshoot wildly, and the
log shows we'd never widen because we're in pressure mode.

**Worth a Phase E.1 fix**: reset SRTT/RTTVAR on reconnect, or reject
outlier samples (>10× current srtt) for the first N samples after a
reconnect. Right now, one bad sample locks srtt bad for the rest of
the session.

### AIMD profile issue is secondary

Gateway uses mobile+wifi profile (`max_cwnd=32, initial_cwnd=10,
ssthresh=64`). The cap is NOT binding in this session — cwnd never
got near 32. It got knocked down from 10 → 7 by RTO events.

Earlier in the session (before my investigation), a delegated
subagent theorized that `max_cwnd=16` (mobile+cellular profile) was
the bottleneck and proposed bumping to 48. That analysis was
PARTIALLY WRONG for the current situation: Steve's phone reports
`class=mobile iface=wifi` which selects the `max_cwnd=32` profile,
not 16. Pre-18:54 morning sessions DID use the 16-packet cap
(class=unknown iface=unknown → falls through to `mobile_wifi_profile`
in the current code which is also 32 — so even that wasn't capped
at 16). The subagent was working from MY description of the earlier
log evidence, not the live code.

**Revised recommendation**: bumping `cc_profile.max_cwnd` won't help
this stall because the stall is an RTO loop, not a cwnd ceiling.
Don't waste a deploy on it. Focus on the data_seq=4 ACK gap first.

---

## BBR is still dead telemetry (confirmed)

The subagent investigation was correct on one thing: **BBR has been
disconnected from send gating since commit `4906aef` (Mar 31 2026)**.
Session.ex uses `state.cwnd` (AIMD), NOT `state.bbr.cwnd`, for
effective window:

```elixir
# session.ex:2347-2351
effective_window =
  min(min(trunc(state.cwnd), cc_max_cwnd(state)),
      Map.get(state, :peer_rwnd, @default_peer_rwnd))
```

The `[BBR] cwnd=4.0` lines in the gateway log are pure telemetry from
a shadow BBR struct that nothing reads. Bug #2 from the earlier
handoff doc (morning version of this file) was a red herring caused
by misreading shadow telemetry.

**Cleanup work for a later phase**: either remove BBR entirely from
session.ex (it's dead code maintained in `state.bbr`), or fix its
rate sampler and re-wire it. Either way, it's not on the critical
path for the current stall.

---

## File inventory

### Rust

- `proto/src/mux.rs` — Phase D autotune + cold-start floor fix (lines
  ~918–944) + 2 regression tests at end of test module.
- `proto/src/ffi.rs` — unchanged since Phase D (autotune FFI accessors).
- `proto/include/ztlp.h` — unchanged since Phase D.

### iOS Swift

- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` — hook-ordering fix
  at ~line 927 (second `wireRttInstrumentationHook(on: conn)` call
  right after `self.rustMux = mux`). Idempotent.

### Gateway (Elixir)

- **Unchanged this session.** `session.ex` still has:
  - Line 2347: `effective_window = min(state.cwnd, cc_max_cwnd, peer_rwnd)`
  - Line 3036: mobile+cellular profile `max_cwnd=16`
  - Line 3053: mobile+unknown profile `max_cwnd=16`
  - Line 3102: `mobile_wifi_profile()` → `max_cwnd=32, initial_cwnd=10,
    ssthresh=64` (default fallback for unknown class/iface)

### Docs

- `docs/plans/2026-05-03-modern-flow-control.md` — master plan
- `docs/plans/2026-05-03-modern-flow-control-PHASE-A-LANDED.md`
- `docs/plans/2026-05-03-modern-flow-control-PHASE-B-VERIFIED.md`
- `docs/plans/2026-05-03-modern-flow-control-PHASE-D-LANDED.md`
- `docs/plans/2026-05-03-modern-flow-control-PHASE-D-HANDOFF.md`
  (the morning-before-hook-fix version; keep for history)
- `docs/plans/2026-05-03-modern-flow-control-PHASE-D-VERIFIED.md` ← **this file**

---

## How to resume in a new session

### For the Phase E stall investigation (data_seq=4 HOL-block)

Load this doc first. Then load skills:
- `ztlp-gateway-session-debugging` — for the gateway-side tracing
- `ztlp-ios-performance-debugging` — for correlating phone/gateway
  logs
- `ztlp-session-health-recovery` — if the investigation touches the
  reconnect path
- `ztlp-validation-suite` — to run a reproducer

Reproducer idea: run the benchmark with Vaultwarden × 3 and log on
both sides. The RTO retransmit loop fires ~10 seconds after the
Vaultwarden burst when it's going to trigger.

Key questions to answer:
1. Is data_seq=4 actually arriving at the phone? Grep phone log
   around the timestamp for any mention of seq 4 or 5 or 6 in
   the mux frame decode path.
2. If it's arriving, why isn't an ACK being generated? Check the
   Swift `flushPendingAcks` path or the Rust MuxEngine's `should_ack`
   logic.
3. If it's NOT arriving, is the loss on the UDP wire (check NS/relay
   path via gateway→relay→phone) or is the gateway's retransmit
   itself getting dropped?

Quick diagnostic plan for start of next session:
```bash
# 1. Pre-flight
bash /home/trs/ztlp/scripts/ztlp-server-preflight.sh 2>&1 | tail -5

# 2. Tell Steve we're testing, ask him to run benchmark once
#    (heads up — do NOT restart gateway during his test)

# 3. Pull phone log + gateway log, same time window
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from --device 39659E7B-0554-518C-94B1-094391466C12 --domain-type appGroupDataContainer --domain-identifier group.com.ztlp.shared --source ztlp.log --destination /tmp/ztlp-phone.log'
scp stevenprice@10.78.72.234:/tmp/ztlp-phone.log /tmp/phone.log
ssh ubuntu@44.246.33.34 'docker logs ztlp-gateway --since 10m' > /tmp/gateway.log

# 4. Find the RTO loop in gateway log
grep "RTO retransmit" /tmp/gateway.log | head -5

# 5. Find that data_seq in the phone log's received frames
#    (needs code-reading to know exactly what to grep — start with
#    "data_seq=", any DataFrame log markers, or decode-fail markers)
```

### For Phase E.1 SRTT poisoning fix (lower priority)

In `proto/src/mux.rs::observe_ack_cumulative` (or wherever SRTT is
updated), add a reconnect-reset hook and/or outlier rejection:

- New public method `note_reconnect(&mut self)` that resets
  `srtt=None`, `rttvar=None`, `first_rtt_sample=false`.
- Call from Swift's reconnect success path in `PacketTunnelProvider.swift`.
- Optionally add an outlier check: reject samples where
  `sample_rtt > 10 × srtt` for the first N samples after reconnect.

Can be written + tested purely in Rust with no wire change, no
gateway deploy.

---

## Rollback

If any of this goes sideways:

```bash
cd /home/trs/ztlp
git reset --hard v-before-autotune  # pre-Phase-D state
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push --force origin main
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git fetch && git reset --hard origin/main'
# Then rebuild dual libs per ztlp-ios-dual-lib-build skill.
```

Gateway has been unchanged since Phase B (`ack-v2` tag). No rollback
needed server-side.

---

## Lessons learned (updates to skills / memory already applied)

- **Cold-start shrink trap** → documented in
  `ztlp-wire-frame-extension` skill under "adjacent pattern: NO-wire-
  change protocol evolution (Phase D)" section. Future phases adding
  BDP-sized policies will know to floor healthy-path shrinks at the
  initial window.
- **"Dead telemetry" as a debugging trap** — the `[BBR] cwnd=4` lines
  looked like the smoking gun this morning but were disconnected from
  send gating for 5+ weeks. Lesson: always grep `session.ex` for
  where a log-observed struct field is actually USED before blaming
  it. Also worth adding: when a subagent's analysis is based on log
  text the parent described (rather than live grep), its
  recommendations may be stale relative to current code.
- **SRTT smoother fragility** — one reconnect-gap sample poisons the
  estimate for the rest of the session. Needs outlier rejection or
  explicit reset on reconnect.
