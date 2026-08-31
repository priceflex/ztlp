# ZTLP Desktop Client (Mac + PC) — Wayfinder Map

## Destination

**A stable, production-usable ZTLP desktop app (macOS + Windows) with a hardened
connection manager, a session manager, and multi-threaded / crash-isolated tunnel
handling — so a single bad connection can't crash the app — that Steven can use right
away against his existing use cases and our own apps.** (The Tauri `ztlp-desktop` app
already exists in `desktop/` with a UI redesign in progress; this effort shifts the
focus to STABILITY + the connection/session manager + crash isolation, not from-scratch.)

## Notes

- Domain: ZTLP desktop client (Tauri 2, Rust backend + web frontend). The existing app:
  `desktop/src-tauri/src/{main,commands,state,setup,ipc,tunnel,tray}.rs` +
  `desktop/src/components/{home,setup,settings,live-log}.js`.
- Ground truth for current state: `desktop/GOALS.md` (the UI-redesign spec) +
  `desktop/PROGRESS.md` (live ledger; headless DOM tests 35/35 passing). Read these
  before acting — they encode the hard-won setup details + the WebView2 pitfall.
- Working copy convention (from GOALS.md): work in `/home/trs/ztlp-desktop` (isolated
  clone), branch `desktop-simple-ui` (or a new feature branch), commit author
  `steve@techrockstars.com`, update PROGRESS.md every turn.
- This is a SIBLING effort to the ZTLP production-readiness map (`/home/trs/ztlp/wayfinder`)
  — a distinct deliverable (the client app) that the production-readiness effort depends on,
  not the reverse.
- Standing preference: primary evidence over inference; TDD; the app must be STABLE (a
  single failing connection must not take down the app).
- Commit author: steve@techrockstars.com (ZTLP).

## Decisions so far

<!-- index — one line per resolved ticket -->

- [Desktop client scope + destination](issues/01-scope-destination.md) — Focus = STABILITY + connection manager + session manager + multi-threaded crash-isolation on the EXISTING Tauri `ztlp-desktop` app (not from-scratch). Mac + PC (Windows) are the targets; Linux follows. Steven has existing use cases + wants it usable on our own apps right away. (Framing, resolved 2026-08-20.)
- [Current connection model](issues/02-current-connection-model.md) — **The tunnel is ALREADY out-of-process** (the Tauri app is a thin control-plane client that shells out to a spawned `ztlp` daemon + talks over a loopback TCP control socket). A dropped relay/bad peer **cannot crash the Tauri app today** — the daemon absorbs it. No tokio/async in the crate. So the stability work is SIX specific gaps, not "make it not crash": (1) stale UI state after a real disconnect (cache-only `get_status`), (2) no supervisor/self-heal, (3) `start_tunnel`/`stop_tunnel` block with no timeout, (4) single-connection state + one global `Mutex` with `.lock().unwrap()` (poisoned mutex = the only real in-process panic path), (5) no daemon→app event stream, (6) per-connection lifecycle states never set. "Multi-threaded/session manager" = move from 1 zone connection to N sessions, each with its own state + crash/health boundary + lifecycle events. (Full report: `research/current-connection-model.md`.)
- [Crash-isolation design](issues/03-crash-isolation-design.md) — **PROVISIONAL design (2026-08-20, Steven away during Q&A — for review).** Incorporates Steven's confirmed requirement: **crash isolation + the ELEVATED daemon (admin, binds privileged local ports like 443) are handled together.** 3-layer crash boundary: (1) data plane = the `ztlp` daemon (per-connection, already out-of-process), (2) the elevated port-holder (admin/root, UAC/pkexec) = the unit that must be stable + supervised, (3) the non-elevated Tauri control-plane (must survive the daemon dying + restart it). The supervisor: detects daemon death (control socket gone / spawn watchdog), **restarts with re-elevation** (re-invokes via UAC/pkexec), bounded/non-UI-blocking spawn (fixes #02 gap #3 unbounded `.output()`), per-connection backoff. In-app hardening: make the shared `Mutex`es poison-tolerant (fixes #02 gap #4 — the only real in-process panic path). **[OPEN: (a) single elevated daemon = containment unit [draft default for pilot] vs. (b) separate privileged-port-holder from per-connection worker subprocesses [stronger].]** Draft = (a) for pilot, designed so (b) is an incremental upgrade. CMMC/SOC 2: supervisor restart-on-death must be audited (who re-acquires elevation, on what schedule, logging).
- [Session manager / multi-threaded](issues/04-session-manager-multithreaded.md) — **PROVISIONAL design (2026-08-20, for review).** **Session = one ZTLP zone connection** (one identity + relay/NS; the daemon already does N service tunnels within a zone) — generalizes the current single `ConnectionStatus` to N zone sessions, each with its own identity/relay/lifecycle-state/health-boundary. Closes #02 gaps #1,4,5,6: per-session `HashMap<SessionId,Session>` (isolation, poison-tolerant), daemon-backed authoritative status (no stale "Connected"), a **daemon→app event stream** for per-session lifecycle/health (reactive containment, not ~2s poll), a per-session supervisor (pairs with #03), and the backend actually driving Connecting/Reconnecting/Disconnecting. No tokio needed (the daemon is the concurrent unit; isolation = per-session state + bounded non-UI-blocking spawn). **[OPEN: zone-level [default] vs per-forward vs per-profile session granularity.]** CMMC/SOC 2: per-session lifecycle events + supervisor backoff are auditable.
- [Stability acceptance bar](issues/05-stability-acceptance-bar.md) — **PROVISIONAL testable definition of "very stable, ready to use right away" (2026-08-20, for review).** 9 criteria (all must hold): (1) no app crash from any single bad connection, (2) a bad session doesn't affect others, (3) daemon death is contained + recovered (re-elevate + rebind privileged ports), (4) no stale UI state, (5) bounded operations (UI never wedges), (6) continuous-use stability (draft: 8h connected + 1h connect/disconnect cycling, no crash, bounded RSS), (7) concurrent-session stability (draft: 3 zones), (8) graceful network-drop recovery (draft: 5min drop → auto-reconnect, no crash), (9) audit trail (CMMC/SOC 2). The exit-criterion proof = the existing headless DOM harness + a **real end-to-end stability test** (kill the daemon, drop the relay, malformed peer, network drop) on a real `cargo tauri build` against the ztlp-test box. **Draft tunables to confirm:** N hours (8h), X sessions (3), M minutes drop (5min), backoff schedule, RSS threshold.

## Not yet specified

<!-- fog of war: in-scope decisions too vague to ticket yet -->

- **(Resolved by #02 → no longer fog)** the crash-isolation boundary: the tunnel is
  already out-of-process (spawned `ztlp` daemon), so the crash boundary = the daemon
  process + the Tauri control-plane. The concrete stability work is the 6 gaps in #02's
  answer (stale UI state, no supervisor, unbounded spawn, global Mutex + `.lock().unwrap()`,
  no event stream, lifecycle states never set). #03 designs the fix for these.
- **"Session manager" scope:** now clearer post-#02 — it means moving from the current
  single-connection app state (one `ConnectionStatus`) to N sessions, each with its own
  state + crash/health boundary + lifecycle events + a daemon→app event stream. (#04 owns
  the design; the exact session model — per-zone vs. per-target-service — is open.)
- **The stability acceptance bar:** what "very stable, so we can use it" means concretely
  (#05) — e.g. N hours continuous use, X concurrent sessions, no app crash on a dropped
  relay/peer, a bad session doesn't affect others, tray + auto-connect stay up across a
  network drop. The testable definition.
- **Whether to fix stability in the APP or the DAEMON:** #02's UNVERIFIED items (does the
  `ztlp` daemon already have internal QUIC/relay auto-reconnect?) + PROGRESS.md's note that
  self-heal "is a backend change, not a UI one" → the split between app-side (UI state,
  event stream, timeout on spawn, poison-tolerant mutex) vs. daemon-side (auto-reconnect,
  event emission) is a design decision for #03/#04.

## Implementation status (2026-08-20)

Started on branch `desktop-stability-hardening` (isolated clone `/home/trs/ztlp-desktop`,
author steve@techrockstars.com). **Committed `a15b507`** — the four quick wins + the
supervisor (the #02 gaps #1/#2/#3/#4), TDD, 15/15 `cargo test` pass + clean `cargo build`:

- ✅ Gap #3 bounded spawn (`tunnel.rs` `run_daemon_bounded`)
- ✅ Gap #4 poison-tolerant mutex (tray.rs x4, commands.rs x1)
- ✅ Gap #1 authoritative status (`commands.rs::get_status` daemon-backed)
- ✅ Gap #2 daemon supervisor (new `supervisor.rs`, backoff + hard cap, wired in main.rs)
- ✅ **Elevated-daemon restart + two-tier supervision** (commit `e066cf0`): the daemon already ships a
  systemd unit (`Restart=always`, `CAP_NET_BIND_SERVICE`, `WatchdogSec=60`) + macOS launchd `KeepAlive` —
  so the OS supervisor already restarts + re-elevates the daemon on the service path. Two-tier:
  **Tier 1** (OS, primary) — `tunnel::daemon_is_under_service()` detects the service; the app supervisor
  *defers* (no double-restart race), only reflects state + logs. **Tier 2** (app, fallback, non-service /
  Windows path) — `tunnel::restart_daemon_elevated()` restarts the daemon elevated (sudo/UAC) so it
  rebinds 443, bounded. **Audit log (CMMC/SOC 2):** `log_supervisor_event()` appends every restart
  decision to `~/.ztlp/supervisor.log`. 17/17 `cargo test` + clean build.

**Open (per #03/#04/#05):** the elevated-daemon restart re-acquires UAC/pkexec (currently
restarts as current user — the #03 (a)/(b) decision + CMMC/SOC 2 audit log); the
daemon→app event stream (gap #5); the end-to-end stability test against the ztlp-test box
(the #05 acceptance-bar proof); a real `cargo tauri build` + live-app run (not yet exercised
on this box — no display).

## Out of scope

<!-- work consciously ruled beyond the destination -->

- The ZTLP production-readiness / multi-tenant effort itself (separate map,
  `/home/trs/ztlp/wayfinder`); this map is the desktop client only.
- The UI redesign that's already in flight (tracked in `desktop/PROGRESS.md`) — this map
  picks up AFTER / IN PARALLEL with the UI work, focused on stability + the managers.
- Mobile (iOS/Android) — the Tauri app targets desktop (Mac/Win/Linux).
