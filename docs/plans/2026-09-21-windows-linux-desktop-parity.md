# ZTLP Desktop (Windows + Linux) — Feature Parity with the macOS Single-Page App

> **STATUS as of 2026-09-21 (end of session): Phase A + Phase B are CODE-COMPLETE
> and test-verified, on branch `feat/linux-service-parity-phase-a` in
> `/home/trs/ztlp`. NOT YET DONE: pushing that branch to GitHub (blocked mid-push
> this session — `~/.ssh/github_token` was missing/stale on this box, see the
> `ztlp-desktop-browser-clients` skill's git-push-token pitfall), Task B4, and all
> of Phase C + Phase D. Read the "Session 2026-09-21 progress" section right below
> this box before doing anything else — it has the exact commit list, what's
> verified vs not, and the next 3 concrete steps.

## Session 2026-09-21 progress (READ THIS FIRST)

**Branch:** `feat/linux-service-parity-phase-a`, based on `main` at `39fa329`
(this plan's own commit). 9 commits on top, all TDD, all tests currently green:

1. `46053b7` fix(linux): pin systemd unit HOME to /var/lib/ztlp — **Task A1 done**
2. `085a4ee` fix(agent): unenrolled standby is cross-platform, not macOS-only — **Task A2 done**
3. `937630b` fix(desktop): enrollment goes through the daemon's IPC control socket — **Task A3 done**
4. `f1259a5` docs(agent): confirm Linux needs no loopback alias — **Task A4 done**
   (live-probed on this box: fresh agent binds/answers 127.100.255.1:4433 with
   zero alias setup, unlike macOS)
5. `b17f6b5` refactor(agent): extract run_agent_lifecycle so a Windows Service can
   share it — **prep for Task B1**, verified no behavior change (same live WARN
   line, same 6-test standby suite passing)
6. `b22f990` feat(windows): add windows-service dependency + ztlp-winsvc service
   host skeleton — **Task B1 done**
7. `6b5c107` feat(windows): ztlp agent install/uninstall registers the real SCM
   service — **Task B2 done** (new `agent::windows_service_install` module, pure
   planner unit-tested, real SCM calls `#[cfg(windows)]`-gated)
8. `9d699bb` feat(desktop): Install Service button runs 'ztlp agent install'
   elevated — **Task B3 done** (reused existing `runas_ztlp` helper)

**Verification so far:** proto lib suite 1272/1272 passing, desktop suite 27/27
passing. Crucially, ALL Windows-only code (`ztlp-winsvc.rs`, the new
`windows_service_install` module, `runas_ztlp`, the whole desktop crate) was
proven to actually **compile AND LINK** as real Windows PE32+ binaries via
`cargo build --target x86_64-pc-windows-gnu` on THIS Linux box — mingw-w64
(`x86_64-w64-mingw32-gcc`) is installed here, which the earlier "Windows cross
build is impossible from Linux" note in the `ztlp-desktop-browser-clients` skill
had wrongly generalized from the MSVC target to the GNU target too (corrected in
that skill 2026-09-21). This is real evidence the code is *correct*, not just
type-checked — but it is NOT the same artifact Steven ships: the real NSIS/MSI
installer and code signing specifically require the **MSVC** target, which
genuinely cannot be cross-compiled from this Linux box (`aws-lc-sys` needs
`cl.exe`). So B4 and Phase D still need either `windows-latest` CI or a real
Windows box — that's the actual gap, not "does it compile."

**Immediate next steps for a fresh session:**
1. Push `feat/linux-service-parity-phase-a` to `origin` (GitHub). This was
   attempted and BLOCKED this session because `~/.ssh/github_token` didn't
   exist at the expected path (`cat: /home/trs/.ssh/github_token: No such file
   or directory`) — check where the token actually lives now (may have moved,
   rotated, or need re-creating via `gh auth token` or a fresh PAT), then push
   with the one-shot-URL pattern documented in the `ztlp-desktop-browser-clients`
   skill (do NOT `git remote set-url` to a token URL and leave it there).
2. Open a draft PR (or just push the branch — the `desktop` job in
   `.github/workflows/release.yml` doesn't require a tag) so the `windows-latest`
   runner builds the REAL MSVC artifact.
3. Once that CI run is green, do Task B4 (verify whether `install-ca-cert
   --machine-scope` succeeds unattended as LocalSystem) and Phase D (drive the
   real installer via the AI-computer worker, 10.170.3.207:7777).
4. Phase C (single-page Home checklist UI, Tasks C1-C4) has NOT been started at
   all — it doesn't depend on Windows CI and could be done in parallel/first if
   preferred; it's pure frontend (`desktop/src/`) + a small Rust status-field
   audit, all verifiable on this Linux box via the jsdom harness
   (`scripts/verify_desktop_ui.js`).

---

> **For Hermes:** this is PLAN ONLY — nothing below has been implemented. Read
> `HANDOFF-2026-09-21-live-verified.md` and the `ztlp-desktop-browser-clients` skill
> (macOS section) before starting; almost every fix here is a straight port of a bug
> already found and fixed for macOS. Execute via `subagent-driven-development` /
> `test-driven-development`, task by task, with TDD proof at each step.

**Goal:** Make `desktop/` (the Tauri app, Windows + Linux targets) work the same way
the macOS app now works: a persistent background service that starts automatically
(no terminal, no "keep the app open"), a single-page Home readiness checklist (no
manual multi-button Setup wizard), one enrollment path (token straight to the
daemon), a device-local name-constrained CA, and a GUI "Trust HTTPS" step that needs
the least possible privilege escalation on each OS.

**Architecture:** Mirror the macOS shape exactly:
1. **Background service, not a spawned child of the GUI.** Windows: a real Windows
   Service (LocalSystem) hosting `ztlp agent start` in-process (not `.spawn()`'d by
   Tauri — that dies when the GUI closes, today's actual Windows/Linux bug). Linux:
   fix the existing systemd unit so its `HOME` is a fixed system path, matching the
   already-proven macOS LaunchDaemon pattern (`Environment=HOME=/var/lib/ztlp`)
   instead of root's `/root/.ztlp`.
2. **Unenrolled standby, cross-platform.** The macOS-only gate in
   `daemon::should_enter_unenrolled_standby` becomes cross-platform (Linux/Windows
   too) — a fresh service with no identity serves status/enroll on the control
   socket instead of exiting/crash-looping silently.
3. **One enrollment.** Desktop's `tunnel::process_enrollment` currently runs
   `ztlp setup --token ... --yes` as a **spawned child under the current desktop
   user** — on Windows/Linux there is no separate root-vs-user identity split today,
   so (unlike the macOS bug) there's only ONE identity being created. But it still
   needs to go through the **service's** control socket (`enroll` command), not a
   bare CLI spawn under the app process, once the service exists — otherwise the
   identity lands in the interactively-run app's HOME while the service (running as
   SYSTEM/root) has its own, different HOME, and we've just re-created the mac bug
   in a new shape.
4. **Device-local CA, name-constrained to `.ztlp`.** Already OS-agnostic
   (`generate_real_ca_chain` in `ztlp-cli.rs`) — nothing to change here, it already
   shipped in commit `933c5d2` for every platform.
5. **Trust step needs the least privilege the OS allows** — probe first, don't
   assume (macOS's own "user-domain trust, no password" finding was a surprise; do
   the equivalent probe on Windows/Linux before writing GUI code):
   - **Windows:** Chrome/Edge use the OS cert store. `certutil -addstore Root` into
     **CurrentUser\Root** needs no elevation at all. Likely sufficient for the
     browser-trust use case; `LocalMachine\Root` (today's `--machine-scope` UAC
     path) stays as a fallback/System-service-owned action for curl/system tools.
   - **Linux:** Chrome/Firefox on Linux use **NSS** (`~/.pki/nssdb`), not the OS
     trust store — importing there needs **zero elevation**. `update-ca-certificates`
     (system store, for curl/wget) still needs pkexec/sudo and stays a secondary
     "Install to system trust" action, not the primary flow.
6. **Single-page Home.** Replace the Home/Setup/Settings 3-page shape with a
   3-row readiness checklist (Service / Identity / Network ready), same shape and
   same underlying state machine as macOS's `HomeReadiness`, reimplemented in
   `desktop/src/components/home.js` (JS, not Swift) since the frontend is shared
   HTML/CSS/JS across Windows+Linux (and even macOS's Tauri variant, though that one
   is not the shipped Mac client — see Non-Goals).

**Tech Stack:** Rust (`proto/`, `desktop/src-tauri/`), `windows-service` crate (new
dep, Windows only), Tauri 2 + vanilla JS/HTML/CSS (`desktop/src/`), systemd (Linux),
Windows SCM (Windows), NSIS/deb/AppImage (existing `.github/workflows/release.yml`).

**Non-goals / explicitly out of scope:**
- The **macOS SwiftUI app is untouched** — this plan is Windows+Linux only, targeting
  the separate Tauri `desktop/` codebase (which also technically builds for macOS,
  but Steven designated the SwiftUI app as the real Mac client — see the
  `ztlp-desktop-browser-clients` skill; don't dual-maintain a macOS Tauri UI).
- No changes to NS/relay/gateway (Elixir) — this is purely the client-side agent +
  desktop app.
- No changes to the enrollment token wire format or the NS lookup-before-enroll fix
  — those already landed cross-platform in `ztlp-cli.rs` (commits up to `b53d0d4`).

---

## Current-state findings (read this before writing any code)

Verified by reading the actual source, not assumed:

1. **`desktop/src-tauri/src/tunnel.rs::start_tunnel`** calls
   `get_daemon_cmd().args(["agent","start"]).spawn()` — a bare **child process of the
   Tauri app**. It does not persist after the app quits, does not start at boot/login,
   and (Windows) there is **no Windows Service integration anywhere in this repo** —
   `proto/Cargo.toml` has zero Windows-service-crate dependencies, and
   `cmd_agent_install` (`ztlp-cli.rs:13333`) is `#[cfg(unix)]`-only; the Windows branch
   just returns the error string `"install is only supported on Unix; use the ZTLP
   Windows service installer instead"` — that installer **does not exist in this
   repo**. This is the Windows equivalent of the macOS B4 chicken-and-egg bug, except
   worse: there is no persistent background process AT ALL, just a `spawn()` tied to
   the GUI's lifetime.
2. **Linux systemd unit (`dns_setup.rs::generate_systemd_unit`) has no `User=` line**,
   so it runs as **root** by default (system unit convention) and its `ExecStart`
   uses the *binary's own* `~/.ztlp` resolution, which under systemd's root context
   means **`/root/.ztlp`** — completely different from the invoking user's
   `~/.ztlp` that the desktop app (running as that user) reads and writes via
   `setup_status`/`enroll`. This is the exact shape of the macOS "orphan
   identity"/"wrong HOME" bug class, just not yet hit live because nobody has run
   `ztlp agent install` + the desktop app together and actually tried to reconcile
   the two `.ztlp` directories.
3. **`should_enter_unenrolled_standby` in `daemon.rs` is macOS-only**
   (`cfg!(target_os = "macos") && ...`). On Linux/Windows a service/unit with no
   identity still just exits 1 (systemd's `Restart=always` crash-loops it silently;
   nothing on Windows even runs it persistently per point 1). Neither platform can
   currently receive a GUI `enroll` command against a not-yet-enrolled background
   service, because there is no standby control socket to receive it on.
4. **Desktop's `setup.rs` is a manual, button-per-step wizard** (`setup_run_ca_init`,
   `setup_install_ca`, `setup_install_dns`, `setup_test_browse`) — the opposite of the
   macOS single-page checklist. It also predates the daemon-side
   `build_post_enroll_tls_plan` (macOS commit `34ce9aa`): on Windows/Linux today
   **ca-init and CA-install are two separate manual clicks**, not automatic
   post-enroll steps.
5. **Desktop's enrollment (`tunnel::process_enrollment`) shells out to `ztlp setup`
   directly** under the app's own process/HOME, not through a running daemon's
   control-socket `enroll` command. Once a real background service exists (point 1
   fixed), this must change to go through the *service's* control socket the same
   way macOS's `EnrollmentViewModel.enrollDaemon` does — otherwise the identity lands
   in the wrong HOME the moment the service is a separate OS principal.
6. **The macOS-side fixes that are ALREADY OS-agnostic and need zero porting**
   (verify unchanged, do not re-implement):
   - `generate_real_ca_chain` (device-generic CN + `.ztlp` nameConstraints) —
     `ztlp-cli.rs`, used by every platform's `ca-init`.
   - `enrollment_is_complete` / `remove_orphan_identity` / `standby_may_hand_over` in
     `daemon.rs` — pure functions, no `cfg!` gate on the logic itself (only the
     *decision to enter standby* is macOS-gated — see point 3).
   - `summarize_setup_failure` in `control.rs` — already used by any platform's
     `cmd_enroll` control-socket handler.
   - `ns_name_is_taken_by_other_key` — the pre-enroll NS lookup, already runs before
     every `ztlp setup`, any OS.
   - `build_post_enroll_tls_plan` — already runs `ca-init` after a daemon-side
     enroll on every OS; only the **`install-ca-cert` step is macOS-skipped**
     (`cfg!(target_os = "macos")` inside it) because macOS's root daemon can't write
     trust settings. On Linux/Windows this cfg currently means the daemon **DOES**
     attempt `install-ca-cert` post-enroll today — verify whether that succeeds
     unattended as root/SYSTEM (Linux: `update-ca-certificates` as root — should
     work, no OS refusal like macOS's `SecTrustSettingsSetTrustSettings`; Windows: no
     daemon-as-SYSTEM exists yet to even test). This needs a real check once the
     service exists (Task 6/10) — don't assume parity with macOS's refusal; that was
     a macOS-specific `Security.framework` restriction.

---

## Task list

### Phase A — Linux: fix the background service (the "B4 for Linux")

#### Task A1: Pin the systemd unit's HOME to a fixed system directory

**Objective:** Stop the systemd-run daemon and the desktop-app-run CLI from writing
to two different `~/.ztlp` directories.

**Files:**
- Modify: `proto/src/agent/dns_setup.rs` (`generate_systemd_unit`, ~line 402)
- Test: `proto/src/agent/dns_setup.rs` (existing `#[cfg(test)] mod tests`)

**Step 1: Write failing test**
```rust
#[test]
fn systemd_unit_pins_a_fixed_home_not_the_installing_users() {
    let unit = generate_systemd_unit("/usr/local/bin/ztlp");
    assert!(
        unit.contains("Environment=HOME=/var/lib/ztlp"),
        "must pin HOME so the service and the desktop app don't diverge on ~/.ztlp: {unit}"
    );
    assert!(unit.contains("ReadWritePaths=/var/lib/ztlp"));
}
```
Run: `cd proto && ~/.cargo/bin/cargo test --lib systemd_unit_pins_a_fixed_home -- --nocapture`
Expected: FAIL (no `Environment=HOME=` line exists yet).

**Step 2: Minimal implementation**
Add to the `[Service]` block:
```
Environment=HOME=/var/lib/ztlp
```
and change `ReadWritePaths=/var/lib/ztlp /run/ztlp %h/.ztlp` to
`ReadWritePaths=/var/lib/ztlp /run/ztlp` (drop `%h/.ztlp` — with `Environment=HOME`
pinned, the unit no longer needs the per-invoking-user specifier at all; `%h` under a
system unit with no `User=` resolves to `/root`, which is now irrelevant).

**Step 3: `install_service` must create `/var/lib/ztlp` before the unit starts**
File: `proto/src/agent/dns_setup.rs::install_service` (~line 530). Add, mirroring the
existing macOS branch:
```rust
if !cfg!(target_os = "macos") {
    fs::create_dir_all("/var/lib/ztlp")?;
}
```
(macOS already creates its own equivalent dir a few lines above — this just adds the
Linux one; Windows takes a completely different path, see Phase B.)

**Step 4: Run test, verify pass.** `cargo test --lib systemd_unit_pins`.

**Step 5: Commit.**
```bash
git add proto/src/agent/dns_setup.rs
git commit -m "fix(linux): pin systemd unit HOME to /var/lib/ztlp

Without an explicit HOME, the root-run systemd service resolved ~/.ztlp
to /root/.ztlp while the desktop app (running as the logged-in user)
reads/writes its own ~/.ztlp — two different identities for the same
machine, the Linux shape of the macOS B4/orphan-identity bug class. Pin
HOME the same way the macOS LaunchDaemon already pins
/Library/Application Support/ZTLP."
```

#### Task A2: Cross-platform `should_enter_unenrolled_standby`

**Objective:** Let a fresh Linux systemd service with no identity serve
status/enroll on the control socket instead of crash-looping silently.

**Files:**
- Modify: `proto/src/agent/daemon.rs` (`should_enter_unenrolled_standby`, ~line 254)
- Modify: `proto/src/bin/ztlp-cli.rs` (`cmd_agent_start`, the call site — currently
  unconditionally gated the same way by the function's own internal `cfg!`, so no
  call-site change needed if the function itself changes)
- Test: `proto/src/agent/daemon.rs` (`unenrolled_standby_tests` module)

**Step 1: Write failing test**
```rust
#[test]
fn standby_decision_is_now_cross_platform_not_macos_only() {
    let home = tmp_home("crossplat");
    let missing = home.join(".ztlp").join("identity.json");
    // Previously this only returned true on macOS. It must now return true
    // on Linux and Windows too (still false when identity.json is present
    // and complete — see the existing `missing_identity_is_standby_only_on_macos...`
    // test for that half, which stays correct unchanged).
    assert!(
        should_enter_unenrolled_standby(&missing),
        "a fresh Linux/Windows service with no identity must enter standby too"
    );
    let _ = std::fs::remove_dir_all(&home);
}
```
Run on Linux (this box): `cargo test --lib standby_decision_is_now_cross_platform`.
Expected: PASS already on Linux today if you drop the macOS gate (that's the point —
prove it fails FIRST by temporarily NOT changing the code, i.e. run the test against
the CURRENT function first and confirm it fails, since today's function is
`cfg!(target_os="macos") && !exists`, which — running on this Linux dev box — would
actually ALSO return true only if `cfg!(target_os="macos")` were true, which it isn't
here, so today's test correctly FAILS on Linux. This is the RED proof.)

**Step 2: Minimal implementation** — remove the `cfg!(target_os = "macos")` gate
entirely from `should_enter_unenrolled_standby`; keep the orphan-detection logic
(`enrollment_is_complete`/`remove_orphan_identity`) exactly as-is (already OS-agnostic
pure functions). New body:
```rust
pub fn should_enter_unenrolled_standby(identity_path: &Path) -> bool {
    if !identity_path.exists() {
        return true;
    }
    if !enrollment_is_complete(identity_path) {
        remove_orphan_identity(identity_path);
        return true;
    }
    false
}
```
Update the doc comment above it to say "on every platform" instead of "only on
macOS", and note that Windows/Linux need their OWN standby wiring at the call site
(see A3/B-tasks) since today only `cmd_agent_start`'s macOS-context lo0-alias/token
work is inside `run_unenrolled_standby` guarded separately — check that function too
(next task).

**Step 3: Check `run_unenrolled_standby` for macOS-only side effects that must NOT
run on Linux/Windows** (lo0 alias, `TokenGuiReadable`). Read
`proto/src/agent/daemon.rs` around the `MacosAction::LoopbackAlias` /
`TokenGuiReadable` calls inside `run_unenrolled_standby` (search
`MacosAction::` in that function) — those are already individually
`#[cfg(target_os = "macos")]`-gated at the call site or inside `.execute()`
no-ops on other platforms; CONFIRM this with a read, don't assume. If they are
already no-ops elsewhere, no change needed here beyond A2's gate removal. If not,
wrap them in `if cfg!(target_os = "macos") { ... }` explicitly.

**Step 4: Run existing standby test suite (5 tests) + the new one.**
`cargo test --lib unenrolled_standby`. Expect 6 passed.

**Step 5: Commit.**
```bash
git commit -m "fix(agent): unenrolled standby is cross-platform, not macOS-only

Linux (systemd, no persistent service today per Task A1/B1) and Windows
(no service at all today, per Phase B) both need a background agent to
survive with no identity.json and answer 'enroll' on the control socket
— the exact chicken-and-egg fixed for macOS in 8d068c5/c4decc0, just
never extended past the macOS cfg gate."
```

#### Task A3: Desktop's enrollment goes through the SERVICE's control socket, not a bare spawn

**Objective:** Once the systemd service is the real background daemon (Task A1),
the desktop app's enroll button must talk to IT, not spawn its own `ztlp setup`
under the interactive user — otherwise the identity is created under the
interactive user's HOME while the systemd service (root, HOME=/var/lib/ztlp) never
sees it, recreating the "two identities" bug macOS hit in `e730451`.

**Files:**
- Modify: `desktop/src-tauri/src/tunnel.rs` (`process_enrollment`)
- Modify: `desktop/src-tauri/src/ipc.rs` (check whether `enroll` command shape
  matches `AgentControlClient.send(cmd:"enroll", ...)` from the macOS Swift client —
  read `proto/src/agent/control.rs::cmd_enroll` for the exact JSON field names
  expected: `name`, `enrollment_uri`/similar, `relay_secret`)
- Test: new `desktop/src-tauri/src/tunnel.rs` test using the same
  `spawn_fake_agent()` pattern already in that file (fake TCP listener answering
  `{"ok":true}`)

**Step 1: Read the exact wire shape** `control::cmd_enroll` expects (field names) —
`proto/src/agent/control.rs`, search `"enroll" =>` dispatch and the struct it
deserializes the command into. Write them down before touching `tunnel.rs` so the
JSON keys match exactly (this bit the macOS port once already — don't repeat it).

**Step 2: Write failing test** (mirrors the existing
`start_tunnel_reuses_already_running_agent_without_spawning_another` pattern):
```rust
#[test]
fn process_enrollment_sends_ipc_enroll_not_a_bare_setup_spawn() {
    let addr = spawn_fake_agent(); // answers {"ok":true,"data":{}} to anything
    // process_enrollment must be refactored to accept an IPC address override
    // (same pattern as agent_is_reachable_at) so this is testable without the
    // real fixed 127.100.255.1:4433 daemon address.
    let result = process_enrollment_at(&addr, "ztlp://enroll/?zone=test.ztlp&...", None);
    assert!(result.is_ok());
}
```
(Exact fixture URI: copy a real one from `ns/lib/ztlp_ns` test fixtures or the demo
minting script's wire format — `token=...&expires=...&nonce=...&mac=...`.)

**Step 3: Implementation** — add `process_enrollment_at(addr, uri, relay_secret)`
that calls `crate::ipc::ipc_request_with_addr(addr, "enroll", Some(json!({...})))`
instead of spawning `ztlp setup`; keep `process_enrollment` as a thin wrapper calling
it with the real `127.100.255.1:4433` (Linux/Windows should share this constant with
the macOS control address convention — confirm Linux/Windows already use the SAME
loopback IP `127.100.255.1`, not `127.0.0.1`, by reading `config.rs`'s
`ipc.listen` default — if Linux/Windows default differs, that's Task A4).

**Step 4: Run test, verify pass.**

**Step 5: Commit.**

#### Task A4: Verify (don't assume) the control-socket address/port is the same on Linux as macOS

**Objective:** confirm `127.100.255.1:4433` (or whatever the real default is) is
reachable identically cross-platform before wiring the desktop app to it — the lo0
alias is a macOS-specific step; Linux may need a different loopback-binding story
(e.g. does `127.100.255.1` just bind on Linux with no alias needed, since Linux
loopback covers the whole `127.0.0.0/8` range by default unlike macOS which needs an
explicit `ifconfig lo0 alias`?).

**Step 1:** Read `proto/src/agent/config.rs`'s `ipc.listen` default (already grepped
above: `"127.100.255.1:4433"`).
**Step 2:** On this Linux dev box, `cargo run --bin ztlp -- agent start --foreground`
against a scratch `~/.ztlp`, then `curl` or a raw TCP line to
`127.100.255.1:4433` and confirm it's reachable with ZERO alias setup (Linux's
`127.0.0.0/8` loopback is fully local by default — this is very likely a non-issue,
but PROVE it, don't write it into the plan as fact until checked, per the macOS
lesson about probing OS behavior before shipping).
**Step 3:** Document the finding (comment in `daemon.rs` near the macOS-only
`LoopbackAlias` call) either "Linux needs no alias, confirmed <date>" or add the
missing piece if it turns out Linux also needs one.

### Phase B — Windows: build the background service from scratch

#### Task B1: Add the `windows-service` crate + a service entry point binary

**Objective:** A real Windows Service (SCM), not a Tauri-spawned child process.

**Files:**
- Modify: `proto/Cargo.toml` — add under a `[target.'cfg(windows)'.dependencies]`
  section: `windows-service = "0.7"` (check crates.io for current major; pin exact).
- Create: `proto/src/bin/ztlp-winsvc.rs` — a new binary target, Windows-only
  (`#[cfg(windows)]` guard the whole file, or gate via `Cargo.toml`
  `required-features`/target-cfg so it doesn't even attempt to build on
  Linux/macOS CI legs).
- Modify: `.github/workflows/release.yml` — Windows Desktop build step compiles
  `ztlp-winsvc.exe` alongside `ztlp.exe`, ships it inside the NSIS/MSI bundle.

**Step 1:** Read the `windows-service` crate's own example
(`define_windows_service!` macro + `service_dispatcher::start`) — this is a new
dependency for this repo, budget time to get the skeleton compiling before wiring
real logic in. A minimal skeleton that just calls `ztlp_proto::agent::run_daemon(...)`
in a loop (same fn the CLI's `agent start --foreground` calls) is Step 2.

**Step 2: Write the skeleton** (no test yet — this can't be unit tested without a
real Windows SCM; TDD here means "build it, install it via `sc.exe create` on the AI
computer, verify it starts" rather than `cargo test`). Body:
```rust
#[cfg(windows)]
mod svc {
    use windows_service::{
        define_windows_service, service_dispatcher,
        service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
        service_control_handler::{self, ServiceControlHandlerResult},
    };
    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start("ZtlpAgent", ffi_service_main)
    }

    fn service_main(_args: Vec<std::ffi::OsString>) {
        // Standard SCM status-reporting dance: register a control handler
        // that accepts STOP/SHUTDOWN, report Running, then block on the same
        // async runtime entry point `ztlp agent start --foreground` uses
        // today (ztlp_proto::agent::daemon::run_daemon / the standby wrapper
        // from cmd_agent_start — REUSE that logic via a shared lib fn rather
        // than re-implementing the standby-then-full-daemon sequencing here;
        // extract cmd_agent_start's body into a callable
        // `agent::run_agent_lifecycle(config_path: Option<PathBuf>)` fn in
        // proto/src/agent/mod.rs if it isn't already separable from the CLI
        // binary — check this before writing new sequencing code).
    }
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> { svc::run() }
#[cfg(not(windows))]
fn main() { eprintln!("ztlp-winsvc is Windows-only"); std::process::exit(1); }
```

**Step 3:** Extract the standby→full-daemon sequencing that today lives inline in
`ztlp-cli.rs::cmd_agent_start` (the `should_enter_unenrolled_standby` /
`run_unenrolled_standby` / config-load sequence) into a reusable
`proto/src/agent/mod.rs` function, e.g. `pub async fn run_agent_lifecycle(home: &Path)
-> Result<...>`, called from BOTH `cmd_agent_start` (CLI/foreground path, unchanged
behavior) AND the new `ztlp-winsvc.rs` service entry point. This is a refactor-only
step — no behavior change, verified by the existing `unenrolled_standby` test suite
still passing unchanged after the extraction.

**Step 4:** Pin the service's identity HOME the same way macOS/Linux do — Windows
services running as `LocalSystem` have `%USERPROFILE%` = `C:\Windows\system32\config\
systemprofile`, which is a real, stable, writable path; no extra pinning needed
UNLESS the desktop app (running as the logged-in user) also needs to read/write
there — in which case grant the logged-in user read access to that profile's
`.ztlp` dir, or (cleaner, matches Linux Task A1) explicitly set
`Environment`-equivalent for a Windows service via
`ServiceConfig`/registry `Environment` multi-string value pinning `USERPROFILE` (or
`ZTLP_HOME` if the codebase supports an env override — check `config.rs` for an env
var seam; if none exists, ADD ONE: `ZTLP_HOME` overriding the default `~/.ztlp`
resolution everywhere, which is also the cleanest fix for Task A1's Linux pinning
too — consider doing this FIRST and having both A1 and B1 consume it, rather than
two separate ad-hoc pinning mechanisms).

**Step 5:** Commit the skeleton once it builds (`cargo build --bin ztlp-winsvc` on a
Windows box or via the GitHub Actions windows-latest runner — this CANNOT be
cross-compiled from this Linux dev box, see "Cross-compilation reality" below).

#### Task B2: Service install/uninstall commands

**Objective:** `ztlp.exe agent install` / `uninstall` on Windows creates/removes the
SCM service entry (`sc.exe create`/`windows-service`'s `service_manager` API),
requiring one UAC elevation — the Windows analog of macOS's SMAppService
`register()` and Linux's `pkexec systemctl enable --now`.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs` — flesh out the `#[cfg(not(unix))]
  AgentCommands::Install` arm (currently returns a hardcoded error string, ~line
  14339) to actually call into `windows-service`'s `ServiceManager::open_service`/
  `create_service`, pointing at `ztlp-winsvc.exe`'s installed path
  (`%ProgramFiles%\ZTLP\ztlp-winsvc.exe`, alongside wherever the Tauri bundle installs
  `ztlp.exe` today — check the NSIS installer's install dir convention in
  `tauri.conf.json`/the bundle output).
- Same for `uninstall`.

**Step 1-4:** Standard TDD is limited here (SCM operations aren't easily fakeable);
write a thin pure function `windows_service_definition(binary_path: &Path) ->
ServiceInfo` that's unit-testable (asserts service name, display name, start type
`AutoStart`, dependencies), then a thin non-tested `install`/`uninstall` wrapper that
calls the real API. Mirror the `dns_setup.rs::generate_systemd_unit` /
`install_service` split (pure content-builder function is tested; the actual
filesystem/API write is a thin uncovered wrapper) — same pattern, same reasoning.

**Step 5:** Commit.

#### Task B3: Desktop app's "Install Service" button calls `ztlp.exe agent install` elevated

**Objective:** One UAC prompt, once, exactly like macOS's `AgentServiceInstaller.
register()` / Linux's pkexec systemctl call.

**Files:**
- Modify: `desktop/src-tauri/src/setup.rs` — this already HAS the `runas_ztlp`
  helper (referenced at line ~500, `Windows-only: elevate ztlp.exe <args> via
  ShellExecuteExW("runas")` — read the rest of that function, it's used by
  `setup_install_ca`/`setup_install_dns` today) — REUSE it for a NEW command
  `setup_install_service()` that runs `runas_ztlp(&["agent", "install"])` instead of
  writing a brand new elevation mechanism.
- New Tauri command registered in `main.rs`'s `invoke_handler!` list.

**Step 1-5:** TDD-light (elevation can't be unit tested); write the command, wire it
into `main.rs`, verify via the live AI-computer test in Phase D.

#### Task B4: Post-enroll TLS provisioning as SYSTEM — verify, don't assume, whether install-ca-cert succeeds unattended

**Objective:** Confirm whether a Windows Service running as LocalSystem CAN write
`LocalMachine\Root` unattended (unlike macOS's root LaunchDaemon, which the OS
refuses). This determines whether Windows needs its OWN "Trust HTTPS" GUI button
(Option-B-style) or whether the service can just do it itself, zero GUI action
needed, the way macOS's B4(b) ORIGINALLY assumed before the live probe proved it
wrong.

**Step 1:** Once B1-B3 are live on the AI computer (10.170.3.207), enroll a test
device and read the service's own log / the `tls_provisioned` field the daemon
already returns (`build_post_enroll_tls_plan`'s existing wiring, unchanged) to see
whether `install-ca-cert --machine-scope` succeeded when run BY the LocalSystem
service itself (not by an elevated user session).
**Step 2:** If it succeeds: Windows needs NO manual trust step at all — better than
macOS. Update `HomeReadiness`'s Network row logic (JS) accordingly — no
`.needsAction(..., .trustHTTPS)` state is ever reached on Windows.
**Step 3:** If it's refused (matching macOS): add a Windows "Trust HTTPS" button
that runs the NON-elevated `certutil -addstore Root` (`CurrentUser\Root`, no UAC) —
this is the Windows analog of macOS's login-keychain discovery. Either way, this is
a one-line command difference gated by what Step 1 actually shows — **do not
hard-code a GUI trust step before checking**, since it may not be needed at all.

### Phase C — Single-page Home checklist (shared JS, both platforms)

#### Task C1: Add a `ca_initialized` / `ca_root_pem_path` read to the desktop's `SetupStatusUi`

**Objective:** parity with the macOS `DaemonSnapshot` fields (`caInitialized`,
`caRootPemPath`) needed to drive a 3-row checklist instead of a 5-card wizard.

**Files:**
- Modify: `desktop/src-tauri/src/setup.rs` — `SetupStatusUi` struct already has
  `ca_initialized` and `ca_root_pem_path` (lines 47, 52 — confirmed present already,
  no Rust change needed here, just confirm the JSON field names match what
  `control::SetupStatus` (proto) actually serializes as, same version-skew class of
  bug as the macOS field-name mismatches hit earlier this project).

**Step 1:** `diff` the two struct definitions (`proto/src/agent/control.rs::
SetupStatus` vs `desktop/src-tauri/src/setup.rs::SetupStatusUi`) field-by-field.
Confirm they match (comment at the top of `setup.rs` already says "we re-declare it
here" — verify it hasn't drifted since D6).

#### Task C2: New `home-readiness.js` — pure state-derivation module (port of macOS `HomeReadiness`)

**Objective:** exact same 3-row logic (Service / Identity / Network ready) as
macOS, in JS, so `home.js` and a future `menubar`-equivalent (Tauri tray tooltip) can
both consume it.

**Files:**
- Create: `desktop/src/components/home-readiness.js`
- Test: since this is vanilla JS with no test runner wired into this repo today,
  write it as a small pure module with NO DOM access (mirrors the Swift
  `HomeReadiness.compute` being a static pure function) and verify it via the
  existing `verify_desktop_ui.js` jsdom harness (see
  `ztlp-desktop-browser-clients` skill's `headless-desktop-ui-verification.md`
  reference) — add new assertions there rather than inventing a second test
  mechanism.

**Step 1: Write the pure function**, 1:1 port of the Swift logic:
```js
// home-readiness.js
function computeReadiness({ serviceState, daemonReachable, daemon }) {
  // serviceState: 'running' | 'not_installed' | 'failed:<msg>'
  // daemon: { identityEnrolled, zone, caInitialized, caInstalled, dnsConfigured } | null
  const service = (() => {
    if (serviceState === 'running') {
      return { title: 'Service', state: daemonReachable
        ? { kind: 'ready', detail: 'Running' }
        : { kind: 'waiting', detail: 'Starting…' } };
    }
    if (serviceState.startsWith('failed:')) {
      return { title: 'Service', state: { kind: 'failed', detail: serviceState.slice(7) } };
    }
    return { title: 'Service', state: { kind: 'needsAction', detail: 'Not installed', action: 'installService' } };
  })();
  // ...identity row, network row — same branch structure as HomeReadiness.compute
  // in macos/ZTLP/ZTLP/ViewModels/TunnelViewModel.swift. Port branch-for-branch,
  // including: Identity gated on service.isReady; Network gated on identity.isReady
  // and reading caInitialized-vs-caInstalled the SAME way (needsAction(trustHTTPS)
  // only when caInitialized && !caInstalled).
  return { service, identity, network, rows: [service, identity, network],
    allReady: [service, identity, network].every(r => r.state.kind === 'ready'),
    guidance(zone) { /* same 4-branch text as Swift guidance(zone:) */ } };
}
module.exports = { computeReadiness }; // also attach to window for the browser build
```

**Step 2: Extend `verify_desktop_ui.js`** (or a new sibling test file) with the same
branch coverage as the 9 Swift `HomeReadiness` XCTests — port test names 1:1:
`freshMacServiceNotInstalledGatesEverything` →
`freshInstallServiceNotInstalledGatesEverything`, etc. (rename "Mac" → nothing OS-
specific, since this module is now shared).

**Step 3: Run.** `node desktop/scripts/test_home_readiness.js` (new file) or fold
into the existing jsdom harness — whichever keeps one test entry point, per the
existing skill's guidance not to invent a second mechanism.

**Step 4: Commit.**

#### Task C3: Rewrite `home.js` to render the 3-row checklist; delete the Setup wizard's manual multi-button flow

**Objective:** same visual/interaction shape as macOS `HomeView` — 3 rows, each ≤1
action button, one guidance line, no Connect toggle, no traffic bar/timer.

**Files:**
- Modify: `desktop/src/components/home.js` — replace the hero ring/Connect-button
  markup with a checklist (3 `<div class="readiness-row">`), driven by
  `computeReadiness()` polling `get_status`/`setup_status`/`get_attached` (Tauri
  `invoke`) every ~2s (mirror the macOS `TunnelViewModel`'s poll cadence).
- Modify: `desktop/src/styles.css` — add `.readiness-row`, `.readiness-badge`
  (ready/needsAction/waiting/failed) styles; keep the existing `.card`/`.btn`
  classes, don't invent a parallel design system.
- Modify: `desktop/src/app.js` — remove/trim the "Setup" page nav item; fold what's
  left of Setup (advanced/manual re-run buttons, "1b Create identity" — see Task C4
  for what to keep) behind a gear/Settings sheet, matching macOS's
  `MainWindow`'s gear → Settings pattern.
- Delete or heavily trim: the 5-card manual wizard body of
  `desktop/src/components/setup.js` (cards 2-5 — CA chain / Install CA / DNS / smoke
  test — all become automatic post-enroll actions per Task A2/B4's
  `build_post_enroll_tls_plan`, not user-clicked buttons). **Keep card 1b ("Create
  identity in the NS") as an advanced/Settings-only action** — it has no macOS
  equivalent and serves a real "no token yet" first-run case; don't delete
  functionality that isn't part of the parity gap, just relocate it.
- Modify: `desktop/src-tauri/src/main.rs` — update the `invoke_handler!` list to
  match whichever `setup_*` commands survive the trim (drop
  `setup_run_ca_init`/`setup_install_ca`/`setup_install_dns`/`setup_test_browse` from
  user-facing flow if they become fully automatic; keep them registered if the
  Settings/advanced panel still exposes a manual "re-run" escape hatch — mirror
  macOS's Settings sheet having Factory Reset / Uninstall Service as the only manual
  levers).

**Step 1-5:** No new Rust here — this is a frontend behavior change. Verify via the
jsdom harness (`verify_desktop_ui.js`) updated for the new DOM shape (element IDs
`home.row.service` etc., matching the macOS `accessibilityIdentifier` naming
convention `home.row.<title-lowercase>` for consistency across platforms, useful if
a future cross-platform QA script wants one shared selector convention).

**Step 6: Commit.**

#### Task C4: One enrollment entry point — same token, same shape, straight to the service

**Objective:** the desktop app's paste-token flow calls the (now IPC-based, Task A3)
`process_enrollment` and nothing else — delete/hide the "app also creates its own
identity" concept if any trace of it exists in `commands::enroll` (check
`desktop/src-tauri/src/commands.rs`'s `enroll` command — read it; if it ALREADY only
calls into `tunnel::process_enrollment` with no separate app-level identity step,
this task is just verification, not a code change — the macOS bug (`e730451`) was
specific to the Swift app's own `bridge.generateIdentity()` call, which may not have
a desktop-app equivalent at all).

**Step 1:** Read `desktop/src-tauri/src/commands.rs::enroll` in full.
**Step 2:** If it's already single-path (token → `process_enrollment` → daemon),
mark this task DONE-by-inspection, no diff needed.
**Step 3:** If it has any app-level "generate my own identity, verify via callback"
step (grep for `NodeIdentity::generate` or similar inside `desktop/src-tauri/`), port
the SAME fix as macOS `e730451` — remove that step, forward the token as-is.

### Phase D — Live verification (both platforms, real installs, no CLI cheating)

Per the UI-only verification methodology already documented in the
`ztlp-desktop-browser-clients` skill: drive the REAL installer, REAL desktop
shortcut, REAL Setup/Home screen — never a CLI flag a real user wouldn't type.

#### Task D1: Windows — build via GitHub Actions, install + drive via the AI computer

**Cross-compilation reality (read before attempting this locally):** the Windows
MSVC target cannot be built from this Linux box (`aws-lc-sys`'s C dependency needs
MSVC's `cl.exe`; the `x86_64-pc-windows-gnu` cross target hits the same wall per the
skill's own prior finding). **Use the existing `.github/workflows/release.yml`
`desktop` job's `windows-latest` runner** — push a branch, let CI build
`ztlp.exe` + `ztlp-winsvc.exe` + the NSIS/MSI bundle, download the
`desktop-windows` artifact (see the skill's documented `gh api .../artifacts` +
redirect-stripping recipe for headless artifact download from this box).

**Step 1:** Push the Phase A/B/C branch, open a draft PR (or just push a branch — the
`desktop` job doesn't require a tag) so `windows-latest` builds it.
**Step 2:** Download the NSIS installer artifact.
**Step 3:** Use the AI computer (10.170.3.207:7777, `trs-uiagent`, auth header
`X-Auth: trs-uiagent-2026` — see `/home/trs/7 - How to use ai computer.md`) to:
   a. Transfer the installer to that box (it has no direct file-drop endpoint in the
      documented API — check for an upload/download HTTP verb in the agent; if none
      exists, host the file briefly via a Cloudflare Tunnel or `python -m
      http.server` reachable from 10.170.3.207 and drive Chrome's address bar via
      the documented `key`/`type` sequence to download it).
   b. Double-click-run the installer via `click`/`doubleclick` at its window
      coordinates (screenshot → vision_analyze → click, per the documented Step 3
      loop), accept the UAC prompt (**cannot click a secure-desktop UAC dialog
      programmatically** — per the skill's own documented limitation, this ONE step
      needs a human at the console, or an elevated Scheduled Task launch trick; flag
      this explicitly to Steven rather than silently blocking).
   c. Once installed, open the app, drive: Install Service (UAC #1, same
      human-needed caveat) → Enroll (paste a freshly-minted demo token, same AWS
      minting script already used for macOS) → observe row 3.
   d. Screenshot + `vision_analyze` at each step; confirm the final state reads
      "Ready" and a real browser tab loads a `.ztlp` hostname with a trusted lock —
      the exact same acceptance bar as the macOS live verification.

**Step 4:** Any real bug found gets its own TDD fix + re-build + re-test loop,
exactly like the macOS session — expect this, don't treat a first-try failure as a
plan error (every macOS fix this project shipped was found this way).

#### Task D2: Linux — build + drive locally (this box has the full Tauri toolchain)

**Step 1:** `cd desktop && cargo tauri build` (webkit2gtk/gtk3 already confirmed
present on `10.69.95.13` — build there via the documented git-bundle-transfer
pattern in the skill if this Hermes VM itself lacks the GTK dev headers; check
`pkg-config --exists webkit2gtk-4.1` locally first).
**Step 2:** Install the produced `.deb`/`.AppImage` in a disposable Linux VM/container
(not this Hermes host's live system — installing a systemd service + writing
`/var/lib/ztlp` + `/etc/resolver`-equivalent should not touch the box Hermes itself
runs on; use a throwaway container or a dedicated Linux VM, matching the "disposable
environment" principle from `verify-fixes-with-disposable-environments`).
**Step 3:** Same drive-the-real-GUI sequence as macOS: launch the app, click Install
Service (pkexec prompt — can be answered non-interactively in a test container by
pre-authorizing polkit for the test user, or by running the container as a user with
passwordless sudo for this one binary), Enroll, observe the checklist, curl the zone
hostname, confirm no cert warning.
**Step 4:** Same bug-fix loop as D1/macOS.

---

## Files touched (summary)

- `proto/src/agent/dns_setup.rs` — systemd unit HOME pinning (A1)
- `proto/src/agent/daemon.rs` — cross-platform standby gate (A2)
- `proto/src/agent/mod.rs` (new/extended) — shared `run_agent_lifecycle` (B1)
- `proto/src/agent/config.rs` — possible `ZTLP_HOME` env override (A1/B1, if adopted)
- `proto/Cargo.toml` — `windows-service` dep (B1)
- `proto/src/bin/ztlp-winsvc.rs` (new) — Windows service host (B1)
- `proto/src/bin/ztlp-cli.rs` — `AgentCommands::Install` Windows arm (B2)
- `desktop/src-tauri/src/tunnel.rs` — IPC-based enrollment (A3)
- `desktop/src-tauri/src/setup.rs` — `setup_install_service` (B3), field-shape audit (C1)
- `desktop/src-tauri/src/commands.rs` — audit only (C4)
- `desktop/src-tauri/src/main.rs` — invoke_handler list changes (B3, C3)
- `desktop/src/components/home-readiness.js` (new) — ported pure state machine (C2)
- `desktop/src/components/home.js` — checklist UI (C3)
- `desktop/src/components/setup.js` — trimmed to advanced/Settings-only content (C3)
- `desktop/src/app.js`, `desktop/src/styles.css` — nav + checklist styling (C3)
- `.github/workflows/release.yml` — ship `ztlp-winsvc.exe` in the Windows bundle (B1)

## Open questions to resolve DURING implementation, not before

1. Does Windows `certutil -addstore Root` (CurrentUser, no elevation) actually make
   Chrome/Edge trust the cert with zero prompt, the way macOS's login-keychain
   discovery worked? (Task B4) — very likely yes (standard documented Windows
   behavior), but PROVE it live before writing the "no button needed" GUI branch.
2. Does a Windows Service running as LocalSystem succeed at `LocalMachine\Root`
   install unattended, or does Windows have its own version of macOS's
   `SecTrustSettingsSetTrustSettings` refusal? (Task B4) — needs a live check, no
   existing evidence either way in this codebase.
3. Is `127.100.255.1:4433` reachable on Linux/Windows with zero loopback-alias setup
   (Task A4)? — very likely yes on Linux; Windows loopback behavior needs its own
   check (Windows also generally allows binding anywhere in `127.0.0.0/8` without an
   explicit alias, but this repo already has Windows-specific network code
   elsewhere — check `proto/src/agent/config.rs`/`macos_daemon.rs`'s sibling for a
   `windows_daemon.rs` before assuming no special handling is needed).
4. Should `ZTLP_HOME` become a first-class config env-var override used by BOTH the
   Linux systemd pin and the Windows service pin (cleaner, one mechanism) instead of
   two separate ad-hoc approaches? Recommended yes — decide at Task A1's start, before
   duplicating logic in Task B1.
5. Windows UAC prompts cannot be clicked programmatically by the AI-computer's
   `trs-uiagent` (same documented limitation as any secure-desktop dialog) — Task D1
   will need either a human physically present, or a pre-elevated Scheduled
   Task-based install path (same trick documented for launching GUI apps into
   Session 0 elsewhere in the skill set) for the INSTALL step specifically. Flag
   this to Steven before Task D1, don't discover it mid-task.
