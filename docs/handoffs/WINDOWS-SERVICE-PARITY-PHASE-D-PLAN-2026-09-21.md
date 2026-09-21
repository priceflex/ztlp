# Windows Service Parity — Phase D — Implementation Plan

> **For Hermes:** Use `subagent-driven-development` for D1-D4 (pure Rust, unit
> tested, no live box needed — each slice is a clean subagent task). D5 and D6
> touch the live AI-computer box (`10.170.3.207`) and change persistent
> service/CA/DNS state — do NOT delegate those; run them in-session with
> Steven's go-ahead before the first live install, per his standing rule.

**Goal:** Make the Windows desktop app behave exactly like the Mac app: one
UAC ever (installing the `ZtlpAgent` SCM service), after which the
LocalSystem service owns all privileged work (CA trust, NRPT/DNS) itself at
startup and after `enroll`, and the desktop app is a thin control-API client
with zero further elevation prompts.

**Architecture:** Mirror `macos_daemon.rs` exactly on Windows: a pure
`windows_startup_plan()` planner (unit-testable on Linux, no I/O) producing an
ordered `Vec<WindowsAction>`, plus a `cfg(windows)`-gated `execute()` that
calls the CA/NRPT code that already exists. State moves from
`dirs::home_dir()` (wrong under LocalSystem) to a fixed `C:\ProgramData\ZTLP`
dir, resolved through one new helper so every existing call site keeps
working unchanged — same trick the Mac plist uses by pinning `HOME`.

**Tech Stack:** Rust (`proto/` — daemon, agent, Windows service host),
Tauri/TypeScript (`desktop/src-tauri`), PowerShell (NRPT via
`WindowsNrptApi`), Windows SCM (`ztlp-winsvc.rs`).

**Reference implementation (read first, cite in code comments):**

| Concern | Mac file : lines | Windows equivalent (to build) |
|---|---|---|
| Root-owned config dir, "HOME pin, no code changes elsewhere" | `proto/src/agent/macos_daemon.rs:26-49` (`MACOS_SYSTEM_CONFIG_DIR`, `macos_system_ztlp_dir`, `macos_system_token_path`) | D1: `windows_system_ztlp_dir()`, `windows_system_token_path()` in a new `proto/src/agent/windows_daemon.rs` |
| Pure startup planner | `macos_daemon.rs:107-199` (`MacosStartupInputs`, `MacosAction`, `macos_startup_plan`) | D2: `WindowsStartupInputs`, `WindowsAction`, `windows_startup_plan()` |
| Execution of the plan | `macos_daemon.rs:210+` (`MacosAction::command`/`execute`, cfg-gated) | D3: `WindowsAction::execute()`, cfg(windows) |
| Wiring into the daemon | `proto/src/agent/daemon.rs:632-637` (pre-bind phase) and `:740-746` (post-bind phase, `run_startup_post_bind`) | D3: add a `#[cfg(windows)]` sibling block right after line 746 |
| CA install at machine scope | `proto/src/agent/ca_trust.rs:94` `install_ca_cert_with_scope(path, CertStoreScope::Machine)` — already exists, args differ per-scope at `:282-287` | D3 calls this directly, no new code needed |
| NRPT setup | `proto/src/agent/dns_setup_windows.rs:467-488` `setup_zones(api, namespaces, agent_resolver)`, `:553` `WindowsNrptApi::with_powershell_path` for LocalSystem PATH issues | D3 calls this directly |
| Service registration | `proto/src/agent/windows_service_install.rs:95-101` — `account_name: None` (LocalSystem), `launch_arguments: Vec::new()` (nothing sets env today — this is blocker 1) | D1 will need to either set an env var here or point at a fixed path baked into the binary |
| Token sharing GUI<->daemon | `macos_daemon.rs` `MacosAction::TokenGuiReadable`, read from `AgentControlClient.swift:12-56` | D1/D4: Windows `system_token_path()` + ACL via `icacls`, read from `desktop/src-tauri/src/state.rs` |
| Standby -> enroll -> full takeover | `control.rs:407-441` `"enroll"` command dispatch, `cmd_enroll` at `:589+` | D3: after `cmd_enroll` succeeds, re-run the Windows startup plan (zones/CA don't exist in standby) — mirror however the Mac re-triggers post-enroll (check `daemon.rs` for the standby handover call site before writing this slice) |

---

## D1 — Service state dir (`C:\ProgramData\ZTLP\.ztlp`)

**Objective:** LocalSystem's `dirs::home_dir()` resolves to
`C:\Windows\System32\config\systemprofile`, not `C:\Users\trs`. Every agent
state file (`config.rs:677` token, `ca_trust.rs:69` CA path, `daemon.rs:802`
CA dir, `control.rs:629/689/866/1001`, CLI config load) must resolve into a
service-owned dir instead, without touching those call sites individually.

**Files:**
- Create: `proto/src/agent/windows_daemon.rs` (new module, mirrors
  `macos_daemon.rs`'s "Locations" section only, no planner yet — that's D2)
- Modify: `proto/src/agent/config.rs` — the token/config resolution helpers
  around lines 469-471, 596-598, 663-687 need a Windows branch
- Modify: `proto/src/agent/mod.rs` — register the new module
- Modify: `proto/src/agent/windows_service_install.rs:95-101` — set the
  `launch_arguments` or environment so the service process knows it's
  service-mode (see Step 3)
- Test: inline `#[cfg(test)] mod tests` in `windows_daemon.rs`, run on Linux

**Step 1: Write failing test — path resolution helper**

```rust
// proto/src/agent/windows_daemon.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_system_ztlp_dir_is_programdata_ztlp() {
        assert_eq!(
            windows_system_ztlp_dir(),
            std::path::PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp")
        );
    }

    #[test]
    fn windows_system_token_path_is_under_system_dir() {
        assert_eq!(
            windows_system_token_path(),
            std::path::PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp\agent.token")
        );
    }
}
```

Run: `cd proto && cargo test windows_daemon:: -- --include-ignored`
Expected: FAIL — `windows_system_ztlp_dir` not found (module doesn't exist yet).

**Step 2: Write minimal implementation**

```rust
//! Windows service-tier support for the ZTLP agent — the Windows analogue
//! of macos_daemon.rs. See that file's module doc for the shared design:
//! a fixed, service-owned config dir so every `~/.ztlp/...` lookup in the
//! agent lands in the same place regardless of who's asking, with NO code
//! changes at the call sites.

use std::path::PathBuf;

/// Fixed ProgramData root for everything the ZtlpAgent service owns.
/// Windows analogue of macOS's `/Library/Application Support/ZTLP`.
pub const WINDOWS_SYSTEM_CONFIG_DIR: &str = r"C:\ProgramData\ZTLP";

/// `<ProgramData>\.ztlp` — mirrors the `~/.ztlp` layout exactly so every
/// existing agent.toml / identity.json / ca/ / agent.token / vip_state.json
/// path just works once ZTLP_HOME (or equivalent) points here.
pub fn windows_system_ztlp_dir() -> PathBuf {
    PathBuf::from(WINDOWS_SYSTEM_CONFIG_DIR).join(".ztlp")
}

/// Where the non-elevated GUI reads the control-API bearer token from.
pub fn windows_system_token_path() -> PathBuf {
    windows_system_ztlp_dir().join("agent.token")
}
```

Run: `cd proto && cargo test windows_daemon::`
Expected: PASS (2 tests). This part is platform-independent path math — no
`#[cfg(windows)]` needed on the pure functions, matching the Mac module's
"pure planning runs on every platform" pattern.

**Step 3: Wire the resolution into `config.rs` — RED test first**

Before touching `default_token_path()`/`load_from_default_path`, write the
resolution-order test on Linux (the handoff explicitly calls this out:
"Write the unit test for the resolution order first").

```rust
// proto/src/agent/config.rs, in mod tests
#[test]
fn default_token_path_prefers_ztlp_home_env_over_dirs_home() {
    std::env::set_var("ZTLP_HOME", "/tmp/ztlp-home-test-marker");
    let p = default_token_path();
    std::env::remove_var("ZTLP_HOME");
    assert_eq!(
        p,
        std::path::PathBuf::from("/tmp/ztlp-home-test-marker/.ztlp/agent.token")
    );
}
```

Run: `cd proto && cargo test default_token_path_prefers_ztlp_home`
Expected: FAIL (no `ZTLP_HOME` handling exists yet — existing precedence is
`ZTLP_AGENT_TOKEN_PATH` then `dirs::home_dir()`).

Then implement: add a `ZTLP_HOME` check as a new highest-precedence override
(distinct from the file-specific `ZTLP_AGENT_TOKEN_PATH`, which still wins if
BOTH are set — it's more specific) in `default_token_path()`, and thread the
same check through every other `dirs::home_dir().join(".ztlp")` call site
listed in the handoff (`config.rs:469-471`, `ca_trust.rs:69`, `daemon.rs:802`,
`control.rs:629/689/866/1001`, `ztlp-cli.rs:13460-13465`). Prefer option (b)
from the handoff — one `ztlp_state_dir()` helper — over relying on
`dirs::home_dir()` honoring `USERPROFILE`, since the handoff flags that as
unverified on Windows. Route ALL those call sites through the new helper.

Run: `cd proto && cargo test` (full proto suite)
Expected: all existing + new tests PASS, no regressions on macOS/Linux paths
(they don't set `ZTLP_HOME` so behavior is unchanged).

**Step 4: Make the Windows service set `ZTLP_HOME` at spawn**

`windows_service_install.rs:97` currently has `launch_arguments: Vec::new()`.
The `ServiceInfo`/`ServiceDefinition` struct this feeds — check whether the
underlying Windows service API (likely `windows-service` crate) exposes a way
to set the process environment at SCM-launch time, or whether `ztlp-winsvc.rs`
`main()` should just hardcode `std::env::set_var("ZTLP_HOME",
windows_daemon::WINDOWS_SYSTEM_CONFIG_DIR)` unconditionally at the top of
`main()` before calling `run_agent_lifecycle`. The latter is simpler and
matches "the Mac's no code changes elsewhere trick" — the winsvc binary IS
already Windows-service-specific, so hardcoding there is fine; no test
needed beyond confirming it compiles (`cfg(windows)`, verify build target as
noted in "cross-compile" step below).

**Step 5: Run full test suite + fmt**

```
cd proto && cargo test && cargo fmt --check -- src/agent/windows_daemon.rs src/agent/config.rs
```
Expected: all green.

**Step 6: Commit**

```bash
git add proto/src/agent/windows_daemon.rs proto/src/agent/config.rs proto/src/agent/mod.rs proto/src/bin/ztlp-winsvc.rs
git commit -m "agent: D1 — pin Windows service state to C:\\ProgramData\\ZTLP (blocker 1)"
```
Ask Steven before pushing (standing rule) unless he's said "commit what you have."

---

## D2 — `windows_startup_plan()` pure planner

**Objective:** A pure, unit-tested-on-Linux planner producing the ordered
list of privileged Windows startup actions, structurally identical to
`macos_startup_plan` (`macos_daemon.rs:107-199`).

**Files:**
- Modify: `proto/src/agent/windows_daemon.rs` (append to the D1 module)
- Test: same file, `#[cfg(test)] mod tests`

**Step 1: Write failing tests (mirror `macos_daemon.rs` test names/shapes)**

```rust
#[test]
fn windows_startup_plan_is_empty_when_not_service() {
    let i = WindowsStartupInputs {
        is_service: false,
        dns_listen: "127.0.0.53:5353".into(),
        zones: vec!["defcon.ztlp".into()],
        ca_root_pem: PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp\ca\root.pem"),
        ca_root_pem_exists: true,
        ca_already_trusted: false,
        token_path: PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp\agent.token"),
    };
    assert!(windows_startup_plan(&i).is_empty());
}

#[test]
fn windows_startup_plan_installs_ca_when_present_and_untrusted() {
    let i = WindowsStartupInputs {
        is_service: true,
        dns_listen: "127.0.0.53:5353".into(),
        zones: vec!["defcon.ztlp".into()],
        ca_root_pem: PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp\ca\root.pem"),
        ca_root_pem_exists: true,
        ca_already_trusted: false,
        token_path: PathBuf::from(r"C:\ProgramData\ZTLP\.ztlp\agent.token"),
    };
    let plan = windows_startup_plan(&i);
    assert!(plan.contains(&WindowsAction::InstallCaCertMachine(i.ca_root_pem.clone())));
}

#[test]
fn windows_startup_plan_skips_ca_install_when_already_trusted() {
    let mut i = base_inputs();
    i.ca_already_trusted = true;
    let plan = windows_startup_plan(&i);
    assert!(!plan.iter().any(|a| matches!(a, WindowsAction::InstallCaCertMachine(_))));
}

#[test]
fn windows_startup_plan_always_sets_up_nrpt_when_service() {
    let i = base_inputs();
    let plan = windows_startup_plan(&i);
    assert!(plan.iter().any(|a| matches!(a, WindowsAction::SetupNrpt { .. })));
}

#[test]
fn windows_startup_plan_ends_with_token_gui_readable() {
    let i = base_inputs();
    let plan = windows_startup_plan(&i);
    assert!(matches!(plan.last(), Some(WindowsAction::TokenGuiReadable(_))));
}
```
(`base_inputs()` is a small test helper returning a service=true, CA-exists,
not-yet-trusted `WindowsStartupInputs`.)

Run: `cd proto && cargo test windows_startup_plan`
Expected: FAIL — types don't exist yet.

**Step 2: Implement**

```rust
/// One privileged, idempotent step of the Windows service startup.
/// Windows analogue of `MacosAction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsAction {
    /// `install_ca_cert_with_scope(path, CertStoreScope::Machine)`.
    InstallCaCertMachine(PathBuf),
    /// `dns_setup_windows::setup_zones(api, zones, agent_resolver)`.
    SetupNrpt { listen: String, zones: Vec<String> },
    /// ACL the token file so Administrators + the interactive user can
    /// read it (icacls). Windows analogue of `TokenGuiReadable`.
    TokenGuiReadable(PathBuf),
}

/// Everything the planner needs; gathered by `daemon.rs` at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsStartupInputs {
    pub is_service: bool,
    /// EFFECTIVE DNS listen (post-fallback), bare IP:port — NRPT silently
    /// drops rules given host:port instead of a bare IP (ztlp-cli.rs:13506).
    pub dns_listen: String,
    pub zones: Vec<String>,
    pub ca_root_pem: PathBuf,
    pub ca_root_pem_exists: bool,
    pub ca_already_trusted: bool,
    pub token_path: PathBuf,
}

/// Compute the ordered list of privileged steps. Empty when not running
/// as the service — a foreground `ztlp.exe agent start` on Windows behaves
/// exactly as before. Mirrors `macos_startup_plan`'s `!i.is_root` guard.
pub fn windows_startup_plan(i: &WindowsStartupInputs) -> Vec<WindowsAction> {
    if !i.is_service {
        return Vec::new();
    }
    let mut plan = Vec::new();
    if i.ca_root_pem_exists && !i.ca_already_trusted {
        plan.push(WindowsAction::InstallCaCertMachine(i.ca_root_pem.clone()));
    }
    plan.push(WindowsAction::SetupNrpt {
        listen: i.dns_listen.clone(),
        zones: i.zones.clone(),
    });
    plan.push(WindowsAction::TokenGuiReadable(i.token_path.clone()));
    plan
}
```

Run: `cd proto && cargo test windows_startup_plan`
Expected: PASS (5 tests).

**Step 3: Commit**

```bash
git add proto/src/agent/windows_daemon.rs
git commit -m "agent: D2 — pure windows_startup_plan() planner (blocker 2)"
```

---

## D3 — `execute()` for the plan, wired into `daemon.rs`

**Objective:** Turn the D2 plan into real actions, cfg(windows)-gated, and
invoke it from `daemon.rs` right after the effective DNS bind (mirrors the
macOS call at `daemon.rs:740-746`) and again after `enroll` completes.

**Files:**
- Modify: `proto/src/agent/windows_daemon.rs` — add `impl WindowsAction { pub
  fn execute(&self) -> Result<(), String> }`, `#[cfg(windows)]` body,
  stub/no-op elsewhere (mirror `macos_daemon.rs` pattern of cfg-gating only
  the shell-out, not the enum/planner)
- Modify: `proto/src/agent/daemon.rs` — near lines 740-746, add a
  `#[cfg(windows)]` sibling block computing `WindowsStartupInputs` and
  calling execute() on each action
- Modify: `proto/src/agent/control.rs` — after `cmd_enroll` succeeds (near
  the dispatch at `:407-441`/`:589+`), re-run the Windows plan (zones/CA
  don't exist during standby, per the handoff)

**Step 1: Write failing test — bare-IP NRPT guard (regression from
`ztlp-cli.rs:13506-13526`)**

```rust
#[test]
fn windows_action_setup_nrpt_rejects_host_port_form() {
    // Reuse the existing bare-IP-no-port validation this project already
    // has in ztlp-cli.rs; this test asserts execute() does NOT silently
    // pass a "host:port" listen straight to setup_zones (which would
    // install an empty NameServers list per the known NRPT gotcha).
    let action = WindowsAction::SetupNrpt {
        listen: "127.0.0.53:5353".into(),
        zones: vec!["defcon.ztlp".into()],
    };
    // strip_port() is the function execute() must call before invoking
    // setup_zones — write it as its own pure, testable helper.
    assert_eq!(strip_port("127.0.0.53:5353"), "127.0.0.53");
}
```

Run: `cargo test strip_port` → FAIL (helper doesn't exist).

**Step 2: Implement `strip_port` + `execute()`**

```rust
fn strip_port(listen: &str) -> &str {
    listen.rsplit_once(':').map(|(host, _)| host).unwrap_or(listen)
}

impl WindowsAction {
    #[cfg(windows)]
    pub fn execute(&self) -> Result<(), String> {
        use crate::agent::ca_trust::{install_ca_cert_with_scope, CertStoreScope};
        use crate::agent::dns_setup_windows::{setup_zones, WindowsNrptApi};
        match self {
            WindowsAction::InstallCaCertMachine(path) => {
                install_ca_cert_with_scope(path, CertStoreScope::Machine)
                    .map_err(|e| e.to_string())
            }
            WindowsAction::SetupNrpt { listen, zones } => {
                let api = WindowsNrptApi::with_powershell_path(
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                );
                let bare_ip = strip_port(listen);
                setup_zones(&api, zones, bare_ip).map(|_| ()).map_err(|e| e.to_string())
            }
            WindowsAction::TokenGuiReadable(path) => {
                // icacls <path> /grant Administrators:F /grant <console-user>:R
                // ... (implement via std::process::Command, cfg(windows))
                todo!("implement icacls ACL step")
            }
        }
    }

    #[cfg(not(windows))]
    pub fn execute(&self) -> Result<(), String> {
        Ok(()) // no-op off Windows, mirrors macos_daemon's cfg gating
    }
}

/// Run every step of the plan in order, logging and continuing past
/// individual failures (mirrors `run_startup_post_bind`'s tolerance —
/// one failed action shouldn't crash the daemon).
pub fn run_windows_startup_post_bind(i: &WindowsStartupInputs) {
    for action in windows_startup_plan(i) {
        if let Err(e) = action.execute() {
            tracing::warn!("windows startup action {:?} failed: {}", action, e);
        }
    }
}
```

Resolve the `icacls` TODO before calling this slice done — read
`macos_daemon.rs`'s `TokenGuiReadable` execute arm for the exact
tolerance/fallback pattern (falls back to a broader grant if no console user
determinable) and mirror it with `icacls` + `query user` or
`WTSEnumerateSessions` to find the interactive user's SID.

**Step 3: Wire into `daemon.rs`**

Right after line 746's macOS block:
```rust
#[cfg(windows)]
{
    let i = crate::agent::windows_daemon::WindowsStartupInputs {
        is_service: crate::agent::windows_daemon::is_running_as_service(),
        dns_listen: effective_dns_listen.clone(),
        zones: config.dns.zones.clone(),
        ca_root_pem: crate::agent::ca_trust::default_ca_cert_path(),
        ca_root_pem_exists: crate::agent::ca_trust::default_ca_cert_path().exists(),
        ca_already_trusted: crate::agent::ca_trust::is_ca_installed(),
        token_path: crate::agent::config::default_token_path(),
    };
    crate::agent::windows_daemon::run_windows_startup_post_bind(&i);
}
```
`is_running_as_service()` needs a real implementation — do NOT assume
"running on Windows" == "running as the service"; a foreground `ztlp.exe
agent start` for dev/debug must NOT try to write `LocalMachine\Root` or NRPT
rules without elevation. Simplest correct check: is the process token
elevated/SYSTEM? (`GetTokenInformation` / check `whoami /user` SID
`S-1-5-18`). Write this as its own tested-where-possible function; the
actual Windows API call can't be unit tested off-Windows, but keep it a thin
one-line wrapper so the untested surface is minimal (same shape as macOS's
`is_root()`).

**Step 4: Re-run after enroll**

In `control.rs` near `cmd_enroll`'s success path, add the same
`run_windows_startup_post_bind` call (zones/CA now exist post-enroll where
they didn't in standby) — cfg(windows), mirroring however the Mac equivalent
re-triggers (check daemon.rs standby-handover code for the pattern before
writing this; do not guess the callback shape).

**Step 5: Test, fmt, commit**

```
cd proto && cargo test && cargo fmt --check -- src/agent/windows_daemon.rs src/agent/daemon.rs src/agent/control.rs
git add proto/src/agent/windows_daemon.rs proto/src/agent/daemon.rs proto/src/agent/control.rs
git commit -m "agent: D3 — execute Windows startup plan post-bind and post-enroll (blocker 2/3)"
```

---

## D4 — Desktop app: Home page parity, delete `runas` CA/DNS paths

**Objective:** Windows Home page becomes Mac semantics: "Install Service" is
the one UAC; remove "Trust HTTPS" and "Set up DNS" buttons; checklist reads
from `setup_status`; delete the now-dead `runas_ztlp` CA/DNS call paths
(`setup_install_ca`, `setup_install_dns`'s `runas` branch — keep `runas_ztlp`
itself only for `agent install`).

**Files:**
- Modify: `desktop/src-tauri/src/setup.rs` — remove/deprecate
  `setup_install_ca` and the Windows branch of `setup_install_dns` (the bug
  #4 fix already committed lives in the code being deleted here — expected,
  it was needed as a bridge, not as final state)
- Modify: desktop frontend Home page component (find via `search_files
  "Trust HTTPS" desktop/`) — remove the two buttons on Windows, read
  checklist rows from `setup_status`
- Test: update/remove the now-orphaned `setup_install_dns_rejects_empty_zone`
  and `windows_dns_setup_args_uses_plural_zones_flag` tests (they test code
  being deleted) — do this as its own commit so the diff reads as "delete
  dead code" not "silently drop coverage"

**Step 1: Confirm nothing else calls the doomed functions**

```bash
grep -rn "setup_install_ca\|setup_install_dns" desktop/src-tauri/src desktop/src
```
Read every hit before deleting; the Tauri command registration
(`invoke_handler` list, likely in `main.rs`) must drop these commands too or
the frontend build will still reference a removed IPC command name.

**Step 2: Remove frontend buttons, wire checklist to `setup_status` only**

(Concrete diff depends on the actual component found in step 1 — read it
first, this plan can't hand you exact line numbers sight-unseen. Locate with
`search_files(pattern="Trust HTTPS", path="desktop")`.)

**Step 3: Remove the Rust functions + their tests, run full suite**

```
cd desktop/src-tauri && cargo test
```
Expected: same pass count minus the deleted tests, 0 failures.

**Step 4: Commit**

```bash
git add -A
git commit -m "desktop: D4 — Windows Home page = Mac semantics, delete dead runas CA/DNS paths"
```

---

## D5 — Live deploy on the AI-computer worker (10.170.3.207)

**STOP — ask Steven before this step's first live service install; it
changes the box's persistent state (per his standing rule).**

**Objective:** Prove D1-D4 end to end on the real box.

**Pre-flight (read-only, safe without asking):**
```
ssh trs@10.170.3.207
tasklist | findstr ztlp
Get-DnsClientNrptRule
certutil -store -enterprise Root | findstr -i ztlp
```

**Steps (after go-ahead):**
1. Clean stale state (blocker 4): `ztlp.exe agent dns-teardown` (elevated,
   removes the 4 duplicate `demo.spongebob.ztlp` NRPT rules),
   `ztlp.exe agent remove-ca-cert` for the old spongebob CA.
2. Kill the ad-hoc foreground agent: `taskkill /IM ztlp.exe /F` (was PID
   20756 at last handoff — confirm current PID first, don't assume it's
   still 20756).
3. Cross-compile all three binaries per the handoff's recipe:
   `cargo build --release --target x86_64-pc-windows-gnu --bin ztlp --bin
   ztlp-winsvc` (proto/) and the desktop Tauri build. Confirm
   `ztlp-winsvc.rs` actually compiles under the GNU target — handoff flags
   this as only ever verified on the MSVC CI runner.
4. Transfer via `/tmp/ztlp-serve/` + `python3 -m http.server 8899`,
   `Invoke-WebRequest -OutFile`, verify `sha256sum` == `Get-FileHash`.
5. Migrate or re-enroll (prefer re-enroll — "the honest end-to-end test" per
   handoff): mint a fresh token on the DEF CON NS `44.240.16.59:23096` for
   `defcon.ztlp` / `defcon-ai-computer.defcon.ztlp`.
6. Click "Install Service" in the desktop app — the ONE UAC.
7. Enroll via the GUI with the fresh token — watch for **zero** further
   elevation prompts.
8. Verify via SSH:
   - `sc query ZtlpAgent` → Running
   - `Get-DnsClientNrptRule` → `.defcon.ztlp` → bare IP (no port)
   - `certutil -store -enterprise Root` → shows the defcon CA (exact CN via
     full listing grep, not a targeted query — handoff warns the CN spelling
     was previously recorded two different ways)
   - Token file exists under `C:\ProgramData\ZTLP\.ztlp\agent.token`, ACL'd

---

## D6 — Original ask: demo service in Chrome

**Objective:** Register a demo service (KEY+SVC, mirroring the Kali
`demo-dashboard.defcon.ztlp` pattern — see `ztlp-defcon-demo-recovery` skill)
and open it in Chrome on the AI-computer box. Screenshot it working. This was
the ORIGINAL ask from session 1/2 that was never completed.

Do this only after D5's checklist is fully green.

---

## Merge (do not forget)

Once Phase D work in this session/branch is complete (all slices done, or
the session is wrapping up with whatever landed so far verified green):
merge `feat/linux-service-parity-phase-a` into `main` via PR #112.
Steps: `gh pr checks 112` green -> `gh pr merge 112 --repo priceflex/ztlp`
(squash or merge per repo convention — check existing merged PRs first).
Ask Steven before merging (standing rule: ask before commit/push/merge
except "commit what you have").

## Cross-cutting notes

- Every Rust slice (D1-D3) must stay unit-testable on Linux for the pure
  planning/path logic — only the `execute()` bodies are `#[cfg(windows)]`.
  This is the same split the Mac module documents at the top of
  `macos_daemon.rs`.
- Ask Steven before: commit/push (except "commit what you have"), and before
  D5's first live install.
- After D5, update PR #112's description with what shipped; consider
  splitting Phase D onto its own branch/PR if #112 gets large (per prior
  handoff's closing note).
