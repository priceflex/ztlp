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
- Verified: invoke↔command cross-check, JS parse, 35/35 headless DOM checks.
- Committed on `desktop-simple-ui` branch, author steve@techrockstars.com.

PENDING:
- Live-run the built Tauri app (cargo tauri dev / bundle) on a real machine — needs the
  Tauri toolchain + ztlp sidecar binary; not available on this build box. (Frontend
  behavior is proven via the jsdom harness; the Rust backend is unchanged.)
- When the daemon gains an event/log stream, wire LiveLog to it (seam is documented in
  live-log.js).
- Optional: real traffic view (deferred per goal — "remove traffic for now").
- Push branch to GitHub for review (Steven to confirm before push/merge to main).

BLOCKED:
- (none)

UNCERTAIN:
- "Stays ready for connections" — the current `connect` just starts the agent daemon;
  it does not itself prove inbound readiness. The UI frames it as "ready"; if you want
  the app to actively keep a tunnel/forwarder open and self-heal on drop, that's a
  backend behavior change (auto-reconnect on the agent), not a UI one — flag before building.
