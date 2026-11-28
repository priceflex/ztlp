Type: grilling
Status: resolved
Blocked by:
- 02-current-connection-model

## Question

What's the STABILITY acceptance bar — what makes this app "very stable, so we can use it
right away"?

(Define the testable bar: e.g. N hours of continuous connected use with no crash; X
concurrent connections held simultaneously; graceful reconnect (no app crash) when the relay
or a peer drops; a single bad peer/zone doesn't affect other connections; tray + auto-connect
stay up across a network drop. This becomes the exit criterion for the whole effort + the
test suite to build (the headless DOM harness + a real end-to-end stability test).)

## Why this ticket

"Very stable" is the goal but vague — it needs a concrete, testable definition so we know
when the app is "ready to use right away." Depends on #02 (current behavior baseline).

## Answer

(Drafted 2026-08-20. Steven away during Q&A — **PROVISIONAL acceptance bar** (best
judgment, draft) for review. This is the testable definition of "very stable, so we can use
it right away" — the exit criterion for the whole desktop-client effort. Grounded in the
#02 (6 gaps) + #03 (elevated-daemon crash isolation) + #04 (session manager) decisions.)

**"Very stable, ready to use right away" = ALL of the following hold (testable):**

1. **No app crash from any single bad connection.** A dropped relay, a bad/malformed peer,
   a misconfigured zone, or a crashing forward must NOT crash/kill the Tauri app. (This is
   the #1 requirement; verified by the #03 in-app hardening — poison-tolerant mutexes, no
   in-process panic path from a bad connection.)
2. **A bad session doesn't affect other sessions.** With N zone sessions (per #04),
   dropping/breaking session A leaves session B connected + usable. (Per-session isolation.)
3. **Daemon death is contained + recovered.** If the elevated `ztlp` daemon is killed
   (crash / `kill` / power blip), the app detects it (control socket gone / spawn watchdog),
   restarts it **with re-elevation** (UAC/pkexec), rebinds the privileged ports (443/8443),
   and recovers — no manual app restart needed. (Per #03 supervisor.)
4. **Stale-state is impossible.** A real disconnect is reflected in the UI within one poll
   cycle (not held as "Connected" from cache). The UI's state always matches the daemon's
   authoritative state. (Per #04 gap #1.)
5. **Bounded operations — the UI never wedges.** `start_tunnel`/`stop_tunnel` (and any
   daemon spawn) have timeouts; a hung spawn / unreachable relay / DNS stall cannot freeze
   the Connect button or tray indefinitely. (Per #03, fixes #02 gap #3.)
6. **Continuous-use stability.** The app runs **N hours** of connected use (draft: 8h
   continuous + 1h of repeated connect/disconnect cycling) with no crash, no memory leak
   (RSS bounded), tray + auto-connect staying up, and the status ring/log accurate
   throughout. (Draft the exact N + the test harness; this is the "we can live on this" bar.)
7. **Concurrent-session stability.** Hold **X concurrent sessions** (draft: 3 zones)
   simultaneously for the continuous-use window with no cross-session interference. (Draft
   the exact X.)
8. **Graceful network-drop recovery.** A full network drop (Wi-Fi off / cable yanked) for
   M minutes, then restore → the app reconnects (per-session, with backoff) without a
   crash, and the UI reflects the reconnect. (Draft the M + the auto-reconnect behavior.)
9. **Audit trail (CMMC/SOC 2, per #01).** Every connect/drop/reconnect/restart + the
   supervisor's re-elevation is logged to an auditable trail (who/what re-established a
   session, when, on what backoff). The audit log survives the test window and is
   inspectable.

**The test harness to build (the exit-criterion proof):**
- Extend the existing headless DOM harness (`PROGRESS.md`: 48/48 jsdom PASS) to drive the
  connect/disconnect/session flows.
- A **real end-to-end stability test**: run the app (or the daemon) against a test relay
  (the ztlp-test box, per the production map), drive the failure modes (kill the daemon,
  drop the relay, send a malformed peer packet, network drop), and assert no app crash +
  correct recovery + bounded RSS.
- The **stability acceptance bar is met when the harness passes 1–9 above** on a real build
  (`cargo tauri build`) — not just the headless DOM pass.

**Draft values to confirm (the tunables):** N hours (8h), X concurrent sessions (3), M
minutes network-drop (5min), the backoff schedule, and the RSS/leak threshold. These are
best-judgment defaults — confirm at review so the bar is specific + testable.
