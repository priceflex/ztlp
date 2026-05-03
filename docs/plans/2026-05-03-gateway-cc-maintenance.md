# ZTLP Gateway CC Maintenance — Handoff

Status: **Not urgent. Independent from the Phase E stall investigation.**
Date: 2026-05-03 (evening, written alongside Phase D VERIFIED handoff)
Author: Hermes Agent

---

## Why this doc exists

While investigating the Phase D on-device stall, a delegated subagent
looked at the gateway BBR implementation and found several pieces of
stale/dead code that are worth cleaning up independently. None of it
is on the critical path for current bugs, but it's worth knowing about
before someone stumbles into the BBR rabbit hole again.

The top-level Phase D VERIFIED handoff
(`2026-05-03-modern-flow-control-PHASE-D-VERIFIED.md`) is the
authoritative source for current state. This doc collects the
gateway-side backlog items so they're not lost.

---

## Finding 1: BBR is dead code

Commit `4906aef` (Mar 31 2026, "fix: use session cwnd for send gating
instead of BBR cwnd") disconnected BBR from send gating entirely.
`gateway/lib/ztlp_gateway/session.ex` now uses `state.cwnd` (AIMD) for
the effective window:

```elixir
# session.ex:2347-2351
effective_window =
  min(min(trunc(state.cwnd), cc_max_cwnd(state)),
      Map.get(state, :peer_rwnd, @default_peer_rwnd))
```

No code reads `state.bbr.cwnd` or `state.bbr.pacing_rate` in any
decision path. BBR-related calls remaining:
- `Bbr.on_send(state, bytes)` — updates shadow BBR struct
- `Bbr.on_ack(state, bytes, srtt, time)` — updates shadow BBR struct
- `Bbr.release_bytes(state)` — pacing release, but overridden by AIMD
- `state.bbr = %Bbr{...}` — field stays for telemetry

The `[BBR] state=probe_bw cwnd=4.0 btl_bw=35625 ...` log lines that
this morning's Phase D handoff called out as "the real gateway
bottleneck" were **dead telemetry**. The BBR estimator has a degenerate
rate sampler (dividing each ACK's bytes by SRTT instead of tracking
delivered-at-send snapshots), so it settles on "one packet per RTT"
≈ 35,625 B/s → BDP=1140 B → cwnd≈4. None of which matters for
production because nothing consumes that number.

### Options

**Option A (lazy):** Leave BBR struct in place but **delete all the
log lines** so operators don't get misled. One-line change: remove or
gate the `[BBR]` Logger call on a debug-only flag.

**Option B (proper):** Delete BBR entirely from session.ex. Remove
the struct field, the `on_send`/`on_ack`/`release_bytes` calls, the
`@use_bbr` module attribute. ~40 LOC. `bbr.ex` stays as a library for
a future reintroduction but isn't wired in.

**Option C (aspirational):** Fix the BBR estimator (rate sampler) and
re-enable as an opt-in. Would require:
- `bbr.ex:153-173` — replace `delivery_rate = acked_bytes / srtt`
  with `(state.delivered - sample.delivered_at_send) / (now - sample.send_time)`
- Per-packet `{delivered_at_send, send_time}` snapshot in `send_buffer`
- Max-filter over a 10-RTT window, not per-ACK
- Tested regression that asserts `btl_bw` exceeds one-packet-per-RTT
  when pipe has >=2 packets in flight

Recommend **Option A** first (cheap, kills operator confusion),
Option B on the next gateway deploy, defer Option C.

---

## Finding 2: Stale BBR tests

`gateway/test/ztlp_gateway/bbr_test.exs` has been failing for ~5 weeks.
The subagent traced it to commit `78f491d` (Apr 1 2026) which changed
`defstruct cwnd: 256` → `defstruct cwnd: 16` to match session gentle-
start, but didn't update two test assertions that expected 256.0:

```elixir
# bbr_test.exs:51
assert state.cwnd == 16.0   # was 256.0

# bbr_test.exs:197
assert Bbr.cwnd(state) == 16.0   # was 256.0
```

Two-line fix. Independent of the stall bug and safe to land alone.

---

## Finding 3: Mobile CC profile inconsistency

`session.ex` has three mobile-adjacent CC profiles. Current values:

| Profile | Match clause | initial_cwnd | max_cwnd | ssthresh |
|---|---|---|---|---|
| `mobile+cellular` | `%{client_class: :mobile, interface_type: :cellular}` | 5.0 | 16 | 32 |
| `mobile+wifi` | `%{client_class: :mobile, interface_type: :wifi}` | 10.0 | 32 | 64 |
| `mobile+unknown` | `%{client_class: :mobile, interface_type: :unknown}` | 5.0 | 16 | 32 |
| `mobile+other` | `%{client_class: :mobile}` | (via `mobile_wifi_profile()`) 10.0 | 32 | 64 |
| fallback `_` | catch-all | (via `mobile_wifi_profile()`) 10.0 | 32 | 64 |
| `desktop` | `%{client_class: :desktop}` | 64.0 | 256 | 128 |
| `server` | `%{client_class: :server}` | 64.0 | 512 | 256 |

`max_cwnd=16` on mobile+cellular and mobile+unknown is conservative
compared to TCP initial cwnd (RFC 6928 ≈ 14.6 KB ≈ 10-14 packets for
1140-byte payloads). The `max_cwnd=16` may well be the bottleneck for
cellular sessions once we look at them with the same rigor as today's
wifi session.

### Recommendation

Don't deploy a "Fix A" style bump without on-device evidence that the
cap is actually binding. This morning's analysis assumed it was, but
the subagent was working from a log snippet I described rather than
live code, and today's Steve session actually ran on `mobile+wifi`
(cap=32) which was never hit. `max_cwnd=16` bumps should wait until we
have a real cellular session log showing `inflight==max_cwnd` sustained.

If we do eventually bump: `initial_cwnd: 5→10, max_cwnd: 16→48,
ssthresh: 32→64` was the subagent's proposal, matches mobile+wifi
scaling. Deploy-safe under hot code-reload because `cc_profile` is
snapshotted per session at handshake.

---

## Finding 4: `cc_max_cwnd` logic is correct

Subagent traced the send-gating path end to end. `cc_max_cwnd(state)`
at `session.ex:3117` correctly returns `state.cc_profile.max_cwnd`,
and line 2350 uses it:

```elixir
effective_window = min(min(trunc(state.cwnd), cc_max_cwnd(state)),
                        peer_rwnd)
```

No bug here. The cap is enforced correctly; it's just conservative.

---

## Related skills

- `ztlp-gateway-session-debugging` — for tracing session state +
  pacing_tick behaviour
- `ztlp-gateway-mobile-tuning` — for CC profile tuning once we have
  evidence
- `ztlp-prod-deployment` — when actually deploying any of these

---

## Suggested ordering if someone picks this up

1. **Two-line test fix** (`bbr_test.exs:51` and `:197`). Safe, clears
   the red X in CI, independent of everything.
2. **Option A** (delete `[BBR]` log lines or gate them behind a
   debug flag). One commit. No deploy required if just gated; otherwise
   standard gateway deploy.
3. Optional **Option B** (delete BBR struct/calls from session.ex) as
   a follow-up when you've got a gateway deploy window anyway.
4. Defer Option C and the CC profile bump until there's evidence that
   warrants them.
