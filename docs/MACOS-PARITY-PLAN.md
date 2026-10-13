# macOS parity with Windows v0.35.18: plan

Status: DRAFT for review with Steven. Nothing is built, signed or shipped yet.
Branch: `feat/macos-parity-0.35.18` (off `origin/main` 11f8e60c, v0.35.18).
Worktree: `/home/trs/projects/ztlp-main-ro` (the other checkouts are stale/dirty, don't touch them).

## Where things stand

- Last Mac app work was **2026-09-20** (single-page Home, standby enroll, user-domain Trust HTTPS).
  Last Mac build on MACLLM4 came from `b53d0d40` (2026-09-20).
- Since then, 7 releases landed for Windows: v0.35.12 to v0.35.18 (PRs #115 to #122).
- **The Mac app is two layers:**
  1. the Rust `ztlp` helper (root LaunchDaemon, bundled at `Contents/Helpers/ztlp`)
  2. the SwiftUI menu-bar app (`macos/ZTLP`)
- Almost everything Windows got lives in the Rust agent, which is cross-platform, so **layer 1
  catches up just by rebuilding the helper from main.** Layer 2 has a few small gaps.

### Verified today (2026-10-13), on MACLLM4 (macOS 26.5, Xcode 26.3)
- `cargo build --release --bin ztlp` from origin/main: **builds clean**, `ztlp 0.35.18`, 1m45s.
- `cargo test --release --lib agent::` natively on macOS: **567 passed, 0 failed**. These tests
  exercise the `cfg(target_os="macos")` paths that Linux CI never runs.

## What changed on Windows since the last Mac build, and what the Mac needs

| Release | Change | Where it lives | Mac action |
|---|---|---|---|
| 0.35.12 (#115) | Logo icon + Mac-style UI | desktop (Tauri) | **GAP:** the Mac `AppIcon.appiconset` has only `Contents.json`, **no images**. Add the same logo (task 2) |
| 0.35.13 (#116) | Browser splash page while the tunnel connects | Rust agent | Comes with the helper rebuild |
| 0.35.14 (#117/#118) | Direct-first dialing, signed NS registration, per-endpoint QUIC pins | Rust agent + NS | Comes with the helper rebuild |
| 0.35.15 (#119) | `X-Forwarded-Proto: https` on TLS-terminated conns (fixes Rails 422s) | Rust agent | Comes with the helper rebuild |
| 0.35.16 (#120) | `.ztlp` NRPT umbrella so every zone resolves (ZT-02) | `windows_daemon.rs` | **Already parity:** Mac writes `/etc/resolver/ztlp` + per-zone files (`dns_setup.rs:326`). Verify live (task 5) |
| 0.35.17 (#121) | Zero-touch: relay secret inside the token (ZT-01), relay pin per service (ZT-04), splash loop fix (ZT-05), persistent gateway cert (ZT-06) | Rust agent + `enrollment.rs` + NS | Comes with the helper rebuild. The Mac enroll path already passes through `ztlp setup`, which now writes the token's relay secret. Swift change: relay-secret field becomes optional "advanced" (task 3) |
| 0.35.18 (#122) | UI freeze: Tauri commands off the window thread (ZT-10), agent `setup_status` probes cached 5s (ZT-11) | desktop + `control.rs` | Agent cache comes with the rebuild. **Swift is already OK:** `AgentControlClient.send` hops to `DispatchQueue.global` with 2-3s timeouts, and the poll loop is guarded. Audit only (task 4) |

Not applicable on Mac: ThreatLocker (ZT-09), NSIS installer, SCM service, NRPT.

## Tasks (one at a time, each one a commit)

1. **Version bump.** `Info.plist` is still `1.0.0` / build `1`. Set `CFBundleShortVersionString`
   to `1.2.4` (matches desktop) and `CFBundleVersion` to `35018` (proto 0.35.18), so "which
   build is this" can be answered from Finder / `mdls`.
2. **App icon.** Generate the `AppIcon.appiconset` PNGs (16 to 1024, @1x/@2x) from
   `desktop/src-tauri/icons/icon.png` (the same logo Windows shows) and fill in `Contents.json`.
   Check that the menu-bar template icon still renders in light and dark mode.
3. **Enrollment UI for zero-touch.** The token now carries the relay secret, so:
   - make the Relay secret field collapsed under "Advanced" (still there for old tokens)
   - leave the field empty and the agent uses the token's secret (`effective_relay_secret`)
   - XCTest: an empty field sends no `relay_secret` key in the enroll payload
4. **Freeze audit (ZT-10 equivalent).** Confirm no control-socket call happens on the main
   actor. Add an XCTest that `AgentControlClient.send` returns quickly with the daemon down.
   No code change expected.
5. **Native acceptance run** (adapted from `docs/ZERO-TOUCH-ENROLLMENT.md`, see below).
6. **Commit the refreshed helper?** Decision needed: the committed `Libraries/ztlp` (9 MB arm64)
   is from 2026-09-19. The build script regenerates it every run anyway, so the plan is to
   **not** commit binaries and keep regenerating at build time.

## Build on MACLLM4 (`ssh trs@10.99.0.14`)

Same flow as before: **one script, run by Steven in a GUI Terminal on MACLLM4.** Signing,
notarizing and stapling need the unlocked login keychain, which plain SSH can't reach.

Changes to `~/ztlp-mac-build.sh` (I'll write it there, you run it):
- take a branch argument (`~/ztlp-mac-build.sh feat/macos-parity-0.35.18`) instead of hard
  ff-only to `origin/main`, so the build can happen before merge
- step 1 resets the one dirty file it always leaves behind (`macos/ZTLP/Libraries/ztlp`)
- print `ztlp --version` (expect 0.35.18) and the bundle version (expect 1.2.4 / 35018)
- everything else unchanged: `xcodebuild test`, then the Developer-ID hardened Release build
  (team `5527A7TH5P`), notarize with profile `ztlp-notary`, staple, `spctl`, then `~/ZTLP.zip`

I can do the pre-checks over SSH myself (helper build, `cargo test`, unsigned `xcodebuild test`),
so the GUI run should be a single pass.

## Install on Steven's MacBook

- The MacBook IP has moved: memory says `10.78.72.114`, today's Blitz logs show `10.78.72.155`
  and `10.78.72.234`. Confirm before shipping anything.
- **Upgrade order** (avoids the stale-BTM trap): in the ZTLP app, Settings > Uninstall service,
  quit. Replace `/Applications/ZTLP.app` (`xattr -cr`, never run from Downloads, to avoid App
  Translocation). Open it, Install service, confirm the row shows Running/answering.
- **Identity question:** keep the existing enrollment (`/Library/Application Support/ZTLP`),
  or re-enroll with a fresh token minted with `--relay-secret-file`? Re-enrolling = a new
  device name, which means Blitz needs the device approved or the owner subject to match.

## Acceptance check (as the real user, in a real browser; curl does not count)

1. Install the notarized build as above. If re-enrolling, enroll with a token only and edit no files.
2. Open two different zones in Safari **and** Chrome: `https://blitz.trs.ztlp` and
   `https://admin.trs.ztlp`. Both show the real page, not the splash card, within 10s.
3. **Blitz specifically:** the page loads as the console, not the "access not approved" page,
   and the Blitz log shows the request with `subject=steve@trs.ztlp`, not `reason=no signature`.
   This closes today's 403 report.
4. `/Library/Application Support/ZTLP/.ztlp/agent.toml` has the relay secret from the token.
5. Reload each site 5 times: no splash loop, no certificate warning.
6. Reboot the Mac and repeat step 2 (daemon comes back on its own).
7. Record the result in CHANGELOG + this file.

## Out of scope / separate items

- Blitz side: `/metrics.json` is behind the identity gate, so the 30s poller 403-floods the log
  when browsed by raw IP. Separate small Comms Blitz change; your call.
- No GitHub release pipeline for the Mac app. Signing stays manual on MACLLM4 (standing decision).
- Mac DNS interception beyond `/etc/resolver` (the old "no DNS interception" note) is no longer
  a gap for `.ztlp` names. Nothing to do unless a non-`.ztlp` name is needed.

## Cross-zone access: www.chooseforce.ztlp, blitz.trs.ztlp, ... (added 2026-10-13)

Requirement: from one enrolled Mac, any `*.ztlp` name works in the browser with valid TLS,
not just names in the zone the Mac enrolled into.

### Measured today
| Check | Result |
|---|---|
| Prod NS `44.227.148.151:23096` answers `blitz.trs.ztlp`, `admin.trs.ztlp`, `www.chooseforce.ztlp` (SVC) | **yes**: one NS holds both zones |
| Old NS `16.147.41.195:23096` | timeout (dead) |
| Demo NS `44.240.16.59:23096` (defcon) | NXDOMAIN for both |
| MACLLM4 (Sept-20 ZTLP.app daemon, enrolled in `defcon.ztlp`) | `/etc/resolver/ztlp` present, agent DNS returns **NXDOMAIN** for both names |
| Steven's Mac Studio `10.78.72.234` | **not running ZTLP.app**: hand-built dev agent `0.35.4` from `~/ztlp` (Aug 14), NS `34.221.165.244`, zone `fullstack.ztlp`. Names don't resolve, HTTPS fails |
| `10.78.72.155` (the other Blitz poller) | SSH refused, so probably the MacBook. Not checked yet |

### What this means
1. **The Mac plumbing is already right for every zone.** `/etc/resolver/ztlp` sends all of
   `*.ztlp` to the agent, which matches the Windows NRPT umbrella (ZT-02). The agent's DNS
   accepts any `.ztlp` name (`DomainMapper::is_ztlp_name`) and asks the NS.
2. **The NS decides what resolves**, and the agent asks exactly one: `AgentConfig::ns_server()`
   = `ns.servers.first()`. Both failing Macs point at a non-prod NS (demo / fullstack). Today's
   "can't reach blitz" on the Mac is a config/enrollment problem, not missing code.
3. **TLS is already cross-zone:** one device-local root, name-constrained to `.ztlp` (root +
   intermediate), leaves minted per SNI on demand (`cert_mint.rs`). Trust once and every zone
   gets a valid cert. No per-zone prompt.

### Work items
- **X1 (no code): enroll the Mac against prod NS `44.227.148.151:23096`** with a token minted
  with `--relay-secret-file`. Retire the dev `agent start --foreground` process on the Mac
  Studio first, so the bundled daemon owns `/etc/resolver/ztlp` and `:53`-style listeners.
- ~~X2: NS fallback~~ **Dropped.** Enrollment writes exactly one NS (token `ns_addr` ->
  `servers = [<ns>]`), so a fallback would never run on an enrolled device. The fix is X1.
- **X3: acceptance additions.** On the Mac, in Safari and Chrome:
  `https://blitz.trs.ztlp`, `https://admin.trs.ztlp`, `https://www.chooseforce.ztlp`.
  All three show the real page with a green lock (leaf issued by "ZTLP Root CA (this device)").
  `dscacheutil -q host -a name <h>` returns a `127.100.x.x` VIP for each.

## UI freeze fix ("process forking"), DONE in the branch, tests green

Root cause (Swift, not the agent): on the `@MainActor` 2 s poll, `refresh()` called
`rootIsTrustedForThisUser`, which ran `Process` + `waitUntilExit()` (`/usr/bin/security
verify-cert`) synchronously. That's a beachball whenever `security` is slow (endpoint
security makes it seconds). Same on the main thread: `SMAppService.register()/unregister()`
(synchronous XPC into launchd/BTM) from the Install/Uninstall buttons and `installService()`.

Changes (`feat/macos-parity-0.35.18`, uncommitted):
- `BackgroundProcess.run(...)` (in `AgentControlClient.swift`): runs the child on a global
  queue, drains the pipes, kills it after a watchdog timeout, and asserts it's never on main.
- Trust check: async, off-main, cached per PEM (path + mtime) for 30 s, like the agent's ZT-11
  cache. The cache clears after Trust HTTPS.
- Trust write (`security add-trusted-cert`): async via the same helper, 120 s watchdog.
- `AgentServiceInstaller.registerAsync()/unregisterAsync()`: off-main, plus `operationInFlight`.
  Settings buttons disable and show a spinner while it runs. All 5 call sites switched.
- The control socket was already off-main (verified).

Verified on MACLLM4, unsigned Debug, `xcodebuild test`: **37 tests, 0 failures**, including
6 new `FreezeFixTests`: the main actor keeps ticking during a 2 s child, the watchdog kills a
wedged child, missing executable, control-socket fail-fast, cache freshness.

Build note found along the way: the app links `libztlp_proto.a`, which is gitignored and not
built by `~/ztlp-mac-build.sh`. The script must run `cargo build --release --lib` too.
Separately, `macos/ZTLP/Libraries/ztlp.h` has drifted from `proto/include/ztlp.h` (734 diff
lines). It compiles today. Sync only if a new FFI call is needed.

## Open questions for Steven

1. Version scheme: `1.2.4` to match the Windows desktop app, or its own Mac number?
2. Keep the existing MacBook enrollment, or re-enroll fresh (proves zero-touch on Mac)?
3. Commit the helper binary, or keep regenerating it at build time (recommended)?
