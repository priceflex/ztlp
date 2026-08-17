# GOAL — ZTLP Desktop UI Redesign (Standardized, Simple, Cross-Platform)

Reusable goal statement. Paste this into a Hermes session (or `goal` memory) so any
future agent working the `ztlp-desktop` clone keeps to the same spec and keeps
`desktop/PROGRESS.md` current.

## The goal (paragraph)

Build the ZTLP desktop app (the Tauri client in `desktop/`) into a very simple,
standardized interface across all three platforms — Mac, PC, and Linux — using one
shared UI so it looks identical everywhere and only the underlying admin elevation
differs (UAC on Windows, pkexec/sudo on the others). It should show the official ZTLP
logo from ztlp.org prominently, and the home screen should be nearly empty: just the
logo, a status ring, and a single big Connect button that uses the existing connection
manager, with no relay address, no traffic counters, and no service table. Instead of
those removed panels, home should feature a live, scrolling activity log that shows
what's actually happening as it connects to DNS and then automatically attaches to
zone services using the device identity in the background — the user never does that by
hand. The app is not a user-facing VPN, so it should auto-connect and stay ready for
connections, with the auto-connect behavior as a Settings toggle (default on). If the
device isn't enrolled, enrollment surfaces inside the Setup page (paste the
`ztlp://enroll/...` string), alongside the first-time environment initialization —
generating the CA chain, installing it into the system trust store, and configuring DNS
routing — all of which need administrator rights, so there's an elevation prompt, plus
a final browser smoke test to confirm the green lock. In short: strip the UI down to
Home (logo + Connect + live log), Setup (enrollment + CA + DNS + elevation + test), and
Settings (auto-connect + identity info), remove the standalone Services/Identity/
Enrollment pages and the relay address entirely, and keep a `PROGRESS.md` file current
throughout.

## Source of truth
- Working copy: `/home/trs/ztlp-desktop` (cloned from `https://github.com/priceflex/ztlp`).
  Isolated so other agents don't interfere.
- Commit author for ALL repo work: **`steve@techrockstars.com`**.
- Progress ledger: **`desktop/PROGRESS.md`** — update it every turn, and before committing.
- Branch: work on a feature branch (e.g. `desktop-simple-ui`), NOT directly on `main`,
  so it can be reviewed before merge.

## Hard requirements (the spec)
1. **Standardized across 3 platforms.** One UI, one look, on macOS / Windows / Linux.
   No platform-branched layouts. Shared CSS + HTML; only the *backend elevation*
   (UAC vs pkexec/sudo) differs, and the UI treats it identically.
2. **ZTLP logo from ztlp.org.** Use the official brand mark (blue→purple shield +
   padlock + "ZTLP" wordmark). Asset: `desktop/src/assets/ztlp-logo.png` (copied from
   repo-root `ztlp-logo.png`, 1000×744 transparent PNG). Show it prominently.
3. **Very simple home = one Connect button.** Home is nearly empty: the logo, a status
   ring/label, and ONE big Connect button. It uses the existing **connection manager**
   (`connect` / `disconnect` commands + `get_status`). No relay address shown, no
   traffic counters, no connection-detail table on home.
4. **Live log on home (the important part).** A live, scrolling activity log shows
   what is actually happening — connecting, DNS, CA, service identity attach, etc.
   This replaces the removed "Services" page as the primary "what's going on" surface.
5. **Auto-connect, "stay ready".** It is NOT a user-facing VPN — the app just stays
   ready to accept connections. So: connect automatically (auto-connect behavior), and
   on launch keep the tunnel/agent in a ready state. Auto-connect is a **Settings**
   toggle (default ON).
6. **Background identity-driven attach.** Behind the scenes, once connected to the
   NS/DNS, the app automatically connects to zone services **using the device identity**
   (the identity-header flow). The user never does this by hand. Surface it in the log.
7. **Enrollment appears when not enrolled.** If the device isn't enrolled, the UI
   surfaces enrollment (paste the `ztlp://enroll/...` string). Enrollment lives **inside
   Setup**.
8. **Setup page = first-time environment init.** CA chain, CA install into system
   trust, DNS routing — all in Setup. These need **admin** (ports, trust store, DNS) →
   there is an **elevation / API connection** (UAC on Windows, pkexec/sudo on
   macOS+Linux). A browser smoke test is the final "green lock" check.
9. **Remove "Services".** The standalone Services page is dropped (per Steven).
   Rationale kept: service attach is background + identity-driven; the live log is the
   real signal, not a service table.
10. **Remove "Relay address".** From home AND from Settings. Relay/DNS are handled
    through the name server + tunnel, not surfaced to the user.
11. **Remove traffic view for now.** No byte/packet counters on home. (Revisit later.)

## Navigation / IA (final)
- **Home** — logo, Connect, live log.
- **Setup** — enrollment (if not enrolled) + CA + DNS + browser test.
- **Settings** — auto-connect toggle, zone/identity info, (optional) advanced.
- (Dropped: Services, Identity, Enrollment as standalone pages.)

## Definition of done
- [ ] Repo cloned to `/home/trs/ztlp-desktop`, isolated copy; not touching other checkouts.
- [ ] `GOALS.md` + `PROGRESS.md` exist and are being kept current.
- [ ] ZTLP logo copied into `desktop/src/assets/` and used in the UI.
- [ ] Home shows logo + ONE Connect button + live log; no relay address, no traffic,
      no connection-detail table.
- [ ] Setup contains enrollment + CA + DNS + elevation + browser test.
- [ ] Settings has auto-connect (default on) + zone/identity; no relay field.
- [ ] Services / Identity / Enrollment standalone pages removed from the UI.
- [ ] UI is visually standardized (same CSS/HTML path) on Mac, PC, Linux.
- [ ] Frontend builds (and, where possible, the app launches) — verified, not assumed.
- [ ] Committed on a feature branch, author `steve@techrockstars.com`, `PROGRESS.md` updated.
- [ ] `PROGRESS.md` has an honest DONE / PENDING / BLOCKED / UNCERTAIN split.

## Non-goals (out of scope for this pass)
- No changes to the Rust daemon / proto / gateway (frontend + thin command wiring only).
- No new traffic accounting, no per-service control plane.
- No re-architecture of the tunnel; reuse the existing connection manager.
