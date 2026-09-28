# HANDOFF — Windows: make it work like the Mac (privileged service + API) — 2026-09-21 (session 2, revised)

Continues from `HANDOFF-2026-09-21-live-verified.md` (macOS single-page app +
Option B trust flow — DONE, live-verified on Steven's MacBook). This doc covers
the **Windows** side: PR #112 (`feat/linux-service-parity-phase-a` → `main`),
live-tested on the AI-computer worker (`10.170.3.207`, DESKTOP-CBSQDNE).

This file was reviewed and rewritten at the end of session 2. The original
version framed "service-first vs per-action UAC" as an open question. **It is
no longer open.**

## DECISION (Steven, end of session 2) — this is the brief for the next session

> Make Windows work like the Mac: same UI ease of use. The service runs
> privileged and does the privileged things itself. The desktop app talks to
> it via the control API. The Mac version works well — reference it.

Concretely:

- **One** elevation, ever: installing the `ZtlpAgent` SCM service
  (`setup_install_service` → `ztlp.exe agent install`). That is the Windows
  analogue of the Mac's single "Allow in Background" approval.
- After that, **zero** UAC prompts. CA trust and NRPT/DNS setup are done BY
  the LocalSystem service at its own startup (and whenever zones change), not
  by the GUI shelling out `runas`.
- The desktop app becomes a thin client, exactly like `TunnelViewModel.swift`:
  poll `status` / `setup_status` / `tunnels` over the control API, render the
  Home readiness checklist, and drive `enroll` via the API.
- `runas_ztlp` for `install-ca-cert` / `dns-setup` becomes dead code once this
  lands (keep it only for `agent install`, or delete and use a dedicated
  one-shot elevation for the install step).

## How the Mac does it (the reference implementation — read these first)

| Concern | Mac implementation | File |
|---|---|---|
| Privileged persistent daemon | root LaunchDaemon, `HOME` pinned to `/Library/Application Support/ZTLP` so every `~/.ztlp/...` lookup lands in a root-owned dir **with no code changes elsewhere** | `proto/src/agent/macos_daemon.rs` lines 26-49, `generate_launchdaemon_plist` |
| One-time install | `SMAppService.daemon().register()` — one system approval, no sudo | `macos/ZTLP/ZTLP/Services/AgentServiceInstaller.swift`, `TunnelViewModel.installService()` (line 314) |
| Privileged steps at daemon startup | pure `macos_startup_plan()` -> `Vec<MacosAction>` { `LoopbackAlias`, `WriteResolver`, `InstallCaCert`, `TokenGuiReadable` }, executed by `run_startup_post_bind` inside the root daemon **after** the DNS socket is bound so it knows the effective port | `macos_daemon.rs` lines 144-200, invoked from `daemon.rs` line 740-746 |
| Token sharing GUI <-> root daemon | daemon writes `agent.token` into the system dir, `TokenGuiReadable` chowns it to the console user; GUI reads it from the fixed system path | `macos_daemon.rs` `MacosAction::TokenGuiReadable`, `AgentControlClient.swift` lines 12-56 |
| Standby then enroll | daemon starts in **unenrolled standby**, answers `status` with `standby:true`; GUI sends `enroll` over the API; `standby_may_hand_over` waits for enroll + ca-init to finish, then the full daemon takes over | `daemon.rs` lines 285-403, `EnrollmentViewModel.enrollDaemon()` |
| Trust HTTPS (per-user, no admin) | `security add-trusted-cert -k <login keychain>` as the GUI user — Mac-specific, because the System-keychain path is refused. On Windows this is NOT needed: LocalSystem can write `LocalMachine\Root` directly (`install_ca_cert_with_scope(.., CertStoreScope::Machine)` already exists in `ca_trust.rs`) | `TunnelViewModel.trustHTTPS()` line 429 |
| UI | single Home page = Identity / Service / Network-ready checklist; no Connect button; DNS connects on demand | `HANDOFF-2026-09-21-live-verified.md` |

The Windows pieces that already exist and map onto this:

- `proto/src/bin/ztlp-winsvc.rs` — real SCM service host running
  `run_agent_lifecycle(None, true)`, the same standby->full sequence. Header
  comment explicitly says it is the analogue of the LaunchDaemon.
- `proto/src/agent/windows_service_install.rs` — registers `ztlp-winsvc.exe`
  as `ZtlpAgent`, AutoStart, `account_name: None` = **LocalSystem**.
  `launch_arguments: Vec::new()` — nothing sets HOME/env (see blocker 1).
- `proto/src/agent/dns_setup_windows.rs` — `WindowsNrptApi` is explicitly
  designed to run from "a service-tier process (LocalSystem / elevated)"
  (line 519) and has `with_powershell_path()` for LocalSystem PATH issues.
- `proto/src/agent/ca_trust.rs` — machine-scope install exists; header says
  LocalSystem needs the cert in `LocalMachine\Root`.
- `desktop/src-tauri/src/setup.rs::setup_install_service()` (line 153) —
  `runas_ztlp(&["agent","install"])`. Untested live as of session end.
- Control API (`proto/src/agent/control.rs` lines 438-444) handles: `status`,
  `tunnels`, `dns_cache`, `flush_dns`, `shutdown`, `setup_status`, `enroll`.
  **There is no `install_ca` / `dns_setup` control command** — and per the
  Mac design there shouldn't need to be one: the service does them itself at
  startup / on zone change, the GUI only observes via `setup_status`.

## KNOWN BLOCKERS for the service-first path (found in code review, not yet hit live)

### Blocker 1 — LocalSystem's `home_dir()` is not `C:\Users\trs`  (MUST be slice 1)

Every piece of agent state resolves through `dirs::home_dir()`:
`config.rs:677` (agent.token), `ca_trust.rs:69`, `daemon.rs:802` (CA dir),
`control.rs:629/689/866/1001`, `ztlp-cli.rs:13460-13465` (agent.toml /
config.toml for dns-setup), `state.rs`, `commands.rs`. Under LocalSystem that
is `C:\Windows\System32\config\systemprofile`, not the user's profile.

If you just install the service on the AI computer today, it will come up as
a **fresh unenrolled agent** that can't see the identity/CA/config enrolled
into `C:\Users\trs\.ztlp`, and the GUI (as trs) will read a different
`agent.token` than the service wrote — IPC auth fails. It will look like a
pile of new mysteries. It isn't; it's this.

Fix, mirroring the Mac exactly: pin the service's state dir to
`C:\ProgramData\ZTLP\.ztlp` (the code already names this location in
`config.rs:664` and `macos_daemon.rs:30`). Options, in order of preference:
  a. In `ztlp-winsvc.rs` `main()` (Windows cfg), before anything else, set
     `HOME`/`USERPROFILE` env to `C:\ProgramData\ZTLP` so `dirs::home_dir()`
     resolves there — the Mac's "no code changes elsewhere" trick. Verify
     `dirs::home_dir()` on Windows honours `USERPROFILE` (it uses
     `SHGetKnownFolderPath(FOLDERID_Profile)`, which may NOT read the env
     var — if so, fall through to b).
  b. Introduce one `ztlp_state_dir()` helper in `config.rs` that checks a
     `ZTLP_HOME` env var / fixed ProgramData path when running as a service,
     and replace the `home_dir().join(".ztlp")` call sites with it. More
     edits, but deterministic. Write the unit test for the resolution order
     first.
Then the GUI must read the token from the fixed system path, like
`AgentControlClient.swift` line 56 — a Windows `system_token_path()` in
`desktop/src-tauri/src/state.rs`. ACL the token so only Administrators +
the interactive user can read it (Windows analogue of `TokenGuiReadable`;
`icacls` from the service is fine).

### Blocker 2 — the Windows startup plan doesn't exist yet

`daemon.rs` line 740-746 runs `macos_daemon::run_startup_post_bind` under
`#[cfg(unix)]`. There is no Windows equivalent. Build one the same way:
a pure `windows_startup_plan(&WindowsStartupInputs) -> Vec<WindowsAction>`
with actions `{ InstallCaCertMachine(PathBuf), SetupNrpt { listen, zones },
TokenGuiReadable(PathBuf) }`, returns empty when not running as a service /
not elevated (mirrors `if !i.is_root { return Vec::new() }`), unit-tested
on Linux; and an `execute()` gated `cfg(windows)` that calls the EXISTING
`install_ca_cert_with_scope(.., Machine)` and
`dns_setup_windows::setup_zones(api, zones, bare_ip)`. Reuse the
bare-IP-no-port rule from `ztlp-cli.rs:13506-13526` — NRPT silently stores an
empty NameServers list if you hand it `host:port`. Invoke it from `daemon.rs`
right after the effective DNS bind, `#[cfg(windows)]`, next to the macOS call.
It must also re-run (or be re-triggered) after `enroll` completes, because
zones/CA don't exist in standby.

### Blocker 3 — migrating the AI-computer's existing state

Identity `steven@defcon.ztlp`, device `defcon-ai-computer.defcon.ztlp`, and
CA chain currently live in `C:\Users\trs\.ztlp`. Either copy them into
`C:\ProgramData\ZTLP\.ztlp` before starting the service, or re-enroll through
the new flow (mint a fresh token on the DEF CON NS `44.240.16.59:23096`; the
old one is consumed). Re-enrolling is the honest end-to-end test — prefer it.
Kill the ad-hoc foreground `ztlp.exe` first (`taskkill /IM ztlp.exe /F`); it
holds `127.100.255.1:4433` and the DNS port.

### Blocker 4 — stale state on the box to clean up first

- 4 duplicate `demo.spongebob.ztlp` NRPT rules. Run `ztlp.exe agent
  dns-teardown` (elevated) or `dns_setup_windows::teardown_managed` before
  the service does its first `setup_zones`. `should_use_static_dns_fallback`
  reads the live rule set, so do not assume the stale rules are harmless.
- Old `demo.spongebob.ztlp` root CA in `LocalMachine\Root` — remove via
  `ztlp.exe agent remove-ca-cert` (thumbprint-based `remove_windows` already
  works) so the checklist can't go green on the wrong cert.
- Backup of old profile at `C:\Users\trs\.ztlp.spongebob-bak\` — leave it.

## What shipped this session (PR #112) — 3 real bugs, all found by running it live

Commits `b119166` (Phase C feature), `891c552`, `3eadb41` on top of `d60260f`,
pushed to `feat/linux-service-parity-phase-a`.

**CI state at handoff time:** all jobs green EXCEPT `build (windows-latest)`
still **pending**. Bug #3's tests are `#[cfg(target_os = "windows")]`-gated
and ONLY run there. Re-check with `gh pr checks 112 --repo priceflex/ztlp`
before building on top of this branch.

1. `home-readiness.js` — bare `module.exports` threw `ReferenceError` in
   WebView2, checklist rendered blank. Guarded. Found via F12 console.
2. `runas_ztlp` passed bare `"ztlp.exe"` to `ShellExecuteW`; not on PATH →
   `SE_ERR_FNF` before any UAC prompt, misreported as "user cancelled".
   Fixed with `ztlp_sibling_exe_path` (2 tests, RED→GREEN witnessed).
3. `check_windows_installed` matched cert by CN substring; `ca-init`
   suffixes the CN with the zone so `certutil -store Root "ZTLP Root CA"`
   always returned `NTE_NOT_FOUND`. Fixed with thumbprint matching
   (`check_windows_installed_for`), removed dead CN helpers + 4 orphan tests.

## Bug #4 — `--zone` vs `--zones` (diagnosed, fix on disk, NOT tested/committed)

`setup_install_dns` (Windows) called `runas_ztlp(&["agent","dns-setup","--zone",z])`.
The CLI only accepts `--zones` (`ztlp-cli.rs:870`). `ShellExecuteW` never
captures the child's output, so clap's rejection was completely silent: no
UAC prompt (nothing to elevate), no log line, no NRPT rule, UI sat on
"Setting up DNS routing…" forever. Reproduced via SSH by running the argv
directly.

Uncommitted diff (`git diff desktop/src-tauri/src/setup.rs`, +19/-1):
`windows_dns_setup_args(zone) -> vec!["agent","dns-setup","--zones",zone]`
and `setup_install_dns` now calls it.

**Recommendation: finish and commit this anyway (≈10 min) before starting
the service work.** It is correct, it is a pure unit test, and the same
`dns-setup` argv will still be needed by whatever process invokes it during
the transition. Steps: RED test on `windows_dns_setup_args` → `cargo test`
(desktop crate, 29+ tests) → `cargo fmt --check` → commit in the same style
as `891c552` → push. Do NOT spend time deploying it live to the box; the
service-first work replaces the `runas` call path.

## Current live state of the AI-computer worker (10.170.3.207 / DESKTOP-CBSQDNE)

- Zone `defcon.ztlp`. Identity `steven@defcon.ztlp` (admin) on the DEF CON NS
  `44.240.16.59:23096`. Device `defcon-ai-computer.defcon.ztlp`.
- Enrollment token: single-use, consumed. Mint a fresh one to re-enroll.
  (Token value deliberately not recorded here.)
- Daemon: ad-hoc foreground `ztlp.exe` (PID 20756 at session end) under trs's
  session, listening `127.100.255.1:4433`. **NOT** the SCM service.
- CA generated + trust-installed in `LocalMachine\Root` (certutil showed it,
  2026-09-21 06:07). Exact CN unclear — the doc previously recorded two
  different spellings; read `certutil -store -enterprise Root` and grep,
  don't trust a targeted exact-name query.
- DNS routing for `defcon.ztlp`: NOT configured (bug #4).
- Home checklist never reached fully-green. **Original ask ("open the
  dashboard in Chrome, see if it errors out") NOT completed** — no
  `defcon.ztlp` service was registered/tested either.

## Access + live-test recipe (worked all session)

- SSH: `ssh trs@10.170.3.207` → `cmd.exe`; wrap PS as
  `powershell -NoProfile -Command "..."`. Authoritative for stdout/state.
- Automation agent: `http://10.170.3.207:7777`, header `X-Auth: <trs-uiagent key, see /home/trs/7 - How to use ai computer.md>`.
  `/health /focus /screenshot /click /key /ps`. Build `/ps` JSON with a real
  encoder (`json.dumps`), never hand-escaped shell strings.
- Cross-compile: `cd desktop/src-tauri && cargo build --release --target
  x86_64-pc-windows-gnu` (mingw-w64 installed, proven). For the service work
  you ALSO need `ztlp.exe` and `ztlp-winsvc.exe` rebuilt from `proto/`
  (`cargo build --release --target x86_64-pc-windows-gnu --bin ztlp --bin
  ztlp-winsvc`) — the winsvc body is `#[cfg(windows)]`, confirm it actually
  compiles under the GNU target (it was only ever verified on the MSVC CI
  runner).
- Transfer: `/tmp/ztlp-serve/` + `python3 -m http.server 8899 --bind 0.0.0.0`,
  `Invoke-WebRequest ... -OutFile C:\Users\trs\AppData\Local\ZTLP\<name>.exe`,
  compare `sha256sum` vs `Get-FileHash -Algorithm SHA256`. Note
  `winsvc_sibling_path` expects `ztlp-winsvc.exe` next to `ztlp.exe`.
- Service inspection: `sc query ZtlpAgent`, `sc qc ZtlpAgent`,
  `Get-EventLog -LogName Application -Source ZtlpAgent -Newest 20` (if the
  service logs there; if tracing goes nowhere, that's slice-1 work too —
  the Mac logs to `/Library/Logs/ZTLP`, do the Windows equivalent under
  `C:\ProgramData\ZTLP\logs`).

## Pitfalls hit this session (still apply)

- UI "Service: Not installed / agent not running" flickers for 5-10s under
  load — IPC polling race, self-heals. Cross-check `Get-Process`/`netstat`
  via SSH before believing it. Happened 3 times.
- `autoProvision()` polls `setup_status` 6×1.5s after an elevated step then
  silently stops. "No error in the log" ≠ "nothing went wrong". With the
  service-first design this polling should disappear; the GUI just observes.
- `ShellExecuteW` elevation is a black box; reproduce the exact argv via
  SSH without `runas` to see the real error.
- WebView2 asset cache: `%LOCALAPPDATA%\com.ztlp.desktop\EBWebView` —
  delete as a first step for stale UI, but check F12 console
  (`[System.Windows.Forms.SendKeys]::SendWait("{F12}")` via `/ps`; raw
  `/key` rejects `"F12"`).
- `certutil -store ... "<name>"` needs an EXACT CN; grep the full listing.

## Files with uncommitted work

- `desktop/src-tauri/src/setup.rs` — bug #4 fix, untested, +19/-1.
- `HANDOFF-2026-09-21-live-verified.md`, this file — untracked; commit them.

## Next session — ordered plan

0. `gh pr checks 112` — confirm `build (windows-latest)` went green.
1. Finish bug #4 as a pure unit-tested commit (RED→GREEN, fmt, commit,
   push). ~10 min. Don't deploy it.
2. Write the plan doc / task list for "Windows service parity, Phase D" as
   TDD slices, in this order:
   - D1  Service state dir (`C:\ProgramData\ZTLP\.ztlp`) — blocker 1. Test
         the resolution helper on Linux. Includes token path for the GUI +
         ACL.
   - D2  `windows_startup_plan()` pure planner + `WindowsAction` enum —
         blocker 2. Unit tests on Linux mirror `macos_startup_plan` tests.
   - D3  `execute()` for the plan (cfg windows), wired into `daemon.rs`
         post-bind and post-enroll. Uses existing `install_ca_cert_with_scope`
         + `setup_zones`. Bare-IP NRPT rule.
   - D4  Desktop app: Home page on Windows = Mac semantics. "Install
         Service" = the one UAC. Remove/hide `Trust HTTPS` and `Set up DNS`
         buttons on Windows (service owns them); checklist rows read from
         `setup_status`. Delete the `runas` paths for CA/DNS.
   - D5  Live on the AI computer: clean stale NRPT + old CA (blocker 4), kill
         ad-hoc ztlp.exe, deploy 3 binaries, click Install Service (one UAC),
         re-enroll via the GUI with a fresh token, watch the checklist go
         fully green with **zero further prompts**. Verify with SSH:
         `sc query ZtlpAgent` Running, `Get-DnsClientNrptRule` shows
         `.defcon.ztlp` → bare IP, certutil shows the defcon CA, token file
         under ProgramData.
   - D6  The original ask: register a demo service (KEY+SVC, mirror the Kali
         `demo-dashboard.defcon.ztlp` pattern, see `ztlp-defcon-demo-recovery`
         skill) and open it in Chrome on the box. Screenshot it working.
3. Update PR #112 description with what shipped; leave Phase D on its own
   branch/PR if #112 gets large.

Ask Steven before: commit/push (except "commit what you have"), anything
that touches his Macs, and before D5's first live service install (it
changes the box's persistent state).
