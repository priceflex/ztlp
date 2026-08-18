# PROGRESS — ZTLP Desktop UI Redesign

Spec: see `GOALS.md`. This file is the live ledger — updated every turn and before
each commit. Always ends with a DONE / PENDING / BLOCKED / UNCERTAIN split.

Working copy: `/home/trs/ztlp-desktop` (isolated clone). Commit author: steve@techrockstars.com.

---

## Baseline (before changes)

Current desktop app is a Tauri 2 app in `desktop/`:
- Frontend: `src/index.html`, `src/app.js`, `src/styles.css`, `src/components/{home,setup,services,identity,enrollment,settings}.js`.
- Backend (Rust): `src-tauri/src/{main,commands,state,setup,ipc,tunnel,tray}.rs`.

Existing UI = sidebar with 6 pages: Home, Setup, Services, Identity, Enrollment, Settings.
Tauri commands already available (reuse, don't reinvent):
- Connection manager: `connect`, `disconnect`, `get_status`, `get_traffic_stats`.
- Identity: `get_identity`.
- Enrollment: `enroll` (token_uri), `record_attestation`.
- Services: `get_services` (mock data in state.rs default — this is why the Services page is noise).
- Config: `get_config`, `save_config` (agent.toml: relay_address, auto_connect, ports...).
- Setup (D6): `setup_status`, `setup_run_ca_init`, `setup_install_ca`, `setup_install_dns`, `setup_test_browse`.
- Elevation already implemented per-platform: Windows `ShellExecuteW("runas")` (UAC);
  macOS/Linux `pkexec`/`sudo` in `setup.rs`. No new elevation backend needed.

Logo: `ztlp-logo.png` at repo root (1000×744 RGBA, the ztlp.org brand mark). Needs copying
into `desktop/src/assets/`.

## Log

### Turn 1 (2026-08-16) — Recon + tracking
- Cloned repo to `ztlp-desktop` (HTTPS remote, main).
- Read all frontend components + backend commands/setup/state. Confirmed full API surface.
- Verified logo is the real ZTLP brand mark (vision check).
- Created `GOALS.md` (spec + DoD) and this `PROGRESS.md`.

### Turn 1 (2026-08-16) — Implementation
- Copied `ztlp-logo.png` → `desktop/src/assets/ztlp-logo.png` (verified the ztlp.org brand mark).
- On branch `desktop-simple-ui`.
- `index.html`: 3 nav items (Home/Setup/Settings), ZTLP logo header; dropped Services/
  Identity/Enrollment pages; wires live-log + home + setup + settings + app.
- `components/live-log.js` (NEW): global scrolling activity feed (capped 400 lines).
  Synthesized from state transitions + setup op events (daemon IPC is request/response
  today — no event stream; clean seam noted to plug a real stream later).
- `components/home.js` (REWRITTEN): logo + status ring + ONE Connect button + live log.
  Removed relay address, connection-detail table, traffic panel. `connect`/`disconnect`
  unchanged (existing connection manager).
- `components/setup.js` (REWRITTEN): enrollment string (paste) — shows when not
  enrolled, green "enrolled" state otherwise — + CA init, CA install (admin), DNS
  (admin), browser smoke test. All ops mirror to LiveLog. addEventListener-only wiring
  (WebView2 inline-handler pitfall).
- `components/settings.js` (REWRITTEN): auto-connect toggle (default ON, honors it live)
  + zone/identity info. Removed relay/STUN/tunnel/DNS/MTU.
- `app.js` (REWIRED): 3-page nav, adaptive poll drives ring + LiveLog.stateChange,
  auto-connect on launch (enrolled + auto_connect default true), exposes components on
  window for testability.
- `styles.css`: added Home hero, big Connect button, live-log, brand header, setup help
  text. Kept existing tokens (cross-platform).
- DELETED: `services.js`, `identity.js`, `enrollment.js` (folded into Setup/Settings).
- Verified: every frontend invoke maps to a registered Tauri command; all JS parses.
- Headless DOM smoke test (jsdom, /tmp/ztlp-ui-test/test.js, stubbed Tauri bridge):
  35/35 checks PASS (structure, nav, connect→Connected, log transitions, enrollment gate
  + success, settings toggles/fields, no stray errors).

### Turn 2 (2026-08-16) — Auto-connect fix + background service-attach in the live log
- Built a second headless harness (autocount.js) for the FIRST-LAUNCH flows
  (not-enrolled / enrolled+auto-on / enrolled+auto-off). Found + fixed TWO real bugs:
    1. Live log never recorded the auto-connect transition at launch (baseline was set
       by the initial poll, so the later flip read as "no change"). Fix: record the true
       initial connection state into the log baseline in init().
    2. Status ring/label did NOT repaint after launch auto-connect (maybeAutoConnect fed
       only the log, not HomeComponent.update). Fix: maybeAutoConnect now refreshes Home
       + log after connecting; and init() now runs auto-connect BEFORE startPolling() to
       avoid a redundant double-connect.
- Added background "attaches to zone services using the device identity" (a spec line the
  first pass under-built): NEW read-only `get_attached` Tauri command (commands.rs) that
  wraps the daemon's `tunnels` control command (same source get_services reads) → returns
  { reachable, active, endpoints }. Registered in main.rs generate_handler!. Frontend
  pollState() now samples it a few seconds after connecting (best-effort; a miss never
  breaks the status poll) and LiveLog.serviceAttach() logs e.g. "Attached to 2 zone
  services via identity: vault.trs.ztlp:443, db.trs.ztlp:5432." (deduped on change).
  HONESTY: this surfaces REAL current tunnel/forward state; the daemon does not (yet)
  push events, so attach is observed via this read-only poll, not a live event stream.
- Re-verified: all JS parses; invoke↔command cross-check OK (incl. get_attached); Rust
  brace balance OK + ipc_request signature match confirmed.
- Headless suites now: main 36/36 (added service-attach check) + first-launch 12/12
  (added service-attach via-identity check). Total 48/48 PASS.

---

## Status

DONE:
- Repo cloned + isolated at /home/trs/ztlp-desktop.
- Full API + elevation model mapped.
- GOALS.md (paragraph goal + DoD) + PROGRESS.md created.
- ZTLP logo verified + copied into desktop/src/assets/.
- Home = logo + ONE Connect button + live log (no relay, no traffic, no table).
- Setup = enrollment (when not enrolled) + CA + DNS + elevation + browser test.
- Settings = auto-connect (default on, honors live) + zone/identity; no relay field.
- Services / Identity / Enrollment standalone pages removed.
- UI standardized on one shared CSS/HTML path (Mac/PC/Linux; only backend elevation differs).
- Verified: invoke↔command cross-check, JS parse, 48/48 headless DOM checks (36 + 12).
- Auto-connect fixed (ring+label repaint after launch connect; log baseline correct).
- Background service-attach surfaced in the live log via new read-only `get_attached`
  command (real daemon tunnel state; deduped).
- Committed on `desktop-simple-ui` branch, author steve@techrockstars.com.

PENDING:
- Live-run the built Tauri app (cargo tauri dev / bundle) on a real machine — needs the
  Tauri toolchain + ztlp sidecar binary, NEITHER of which is on this build box (no rustup,
  no webkit/gtk dev libs). Important: tauri.conf.json uses `frontendDist` (NO devUrl), so
  the frontend is a STATIC BUNDLE compiled in at build time — a fresh `cargo tauri build`
  is REQUIRED to pick up these frontend changes (there is no live-reload dev server). The
  Rust backend change (get_attached) is also only proven by inspection here, not a real
  compile. (Frontend behavior IS proven via the jsdom harnesses; existing Rust is unchanged
  except the additive get_attached command.)
- Build on the canonical host (hermes-ztlp 10.69.95.13 — has `~/.cargo/bin/cargo`) or a
  machine with the toolchain, to get a real compiled app + confirm get_attached compiles.
- When the daemon gains an event/log stream, wire LiveLog to it (seam documented in
  live-log.js) instead of the read-only get_attached poll.
- Optional: real traffic view (deferred per goal — "remove traffic for now").
- Push branch to GitHub for review (Steven to confirm before push/merge to main).

BLOCKED:
- (none)

UNCERTAIN:
- "Stays ready for connections" — the current `connect` just starts the agent daemon;
  it does not itself prove inbound readiness. The UI frames it as "ready"; if you want
  the app to actively keep a tunnel/forwarder open and self-heal on drop, that's a
  backend behavior change (auto-reconnect on the agent), not a UI one — flag before building.
