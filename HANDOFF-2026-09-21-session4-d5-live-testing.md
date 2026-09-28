# HANDOFF — Windows Service Parity Phase D — live D5 testing in progress — 2026-09-21 (session 4)

Continues `docs/handoffs/WINDOWS-SERVICE-PARITY-PHASE-D-PLAN-2026-09-21.md`
(read that first for the original D1-D6 design). This doc picks up where
that plan's "Merge (do not forget)" section left off: live testing on the
real Windows box uncovered **three real bugs no amount of code review or
CI would have caught**, one of which is fixed-but-unverified right now.

## Branch / repo state

`feat/linux-service-parity-phase-a`, tip `7ad31b3`, pushed and CI-green
(includes the real `windows-latest` build). **5 files are modified on disk,
UNCOMMITTED, UNTESTED, UNBUILT, UNPUSHED** as of the end of this session:

```
M desktop/src-tauri/src/ipc.rs
M proto/src/agent/config.rs
M proto/src/agent/control.rs
M proto/src/agent/local_tls.rs
M proto/src/agent/mod.rs
```

Do NOT lose this diff. Read every `D5 live-test fix (2026-09-21)` doc
comment in those files before touching them further — each one documents
the exact live symptom that led to the fix.

## Live test box

`10.170.3.207` (DESKTOP-CBSQDNE), `ssh trs@10.170.3.207` (key auth,
already-admin session — `sc create`/`icacls` work without a UAC prompt
over SSH). ZtlpAgent service is currently **STOPPED**. State dir
`C:\ProgramData\ZTLP\.ztlp\` currently has a full identity/config/CA from
the last (crashed) enrollment attempt — safe to wipe before the next test.
Skill: `ztlp-ai-computer-agent-deploy` has the general cross-compile/deploy
recipe; this session's specific throwaway scripts live at
`/tmp/d5-*.ps1` on the Hermes VM (deploy, clean-state, enroll, status,
foreground-repro) — re-usable, re-scp them if a new session starts fresh.

Zone: `defcon.ztlp`, NS `44.240.16.59:23096`, relay `44.240.16.59:23095`.
Zone secret at `/tmp/defcon-zone-secret.hex` on the Hermes VM (64 hex
chars) — needed to mint enrollment tokens via
`ztlp admin enroll --zone defcon.ztlp --secret /tmp/defcon-zone-secret.hex
--ns-server 44.240.16.59:23096 --relay 44.240.16.59:23095 --expires 2h
--max-uses 1`. Tokens are single-use; mint a fresh one each retry. The NS
is demo/RAM-adjacent — don't be surprised if old device registrations
(`defcon-ai-computer`, `steven@defcon.ztlp`) need re-creating; `ztlp admin
create-user`/re-enroll under a fresh device name (`-v2`, `-v3`, ...) avoids
NS name-collision noise.

## What's PROVEN working live (do not re-test unless suspicious)

- **D1** — state dir: identity.json, config.toml, agent.toml, agent.token,
  and the CA all land under `C:\ProgramData\ZTLP\.ztlp\`, not the user
  profile. Confirmed via `Get-ChildItem` after both install and enroll.
- **D3 CA step** — `ZTLP Root CA (this device)` appears in
  `Cert:\LocalMachine\Root` after enroll.
- **D3 NRPT step** — `.defcon.ztlp` namespace routed to a bare IP
  (`127.0.0.55` observed) via `Get-DnsClientNrptRule`. No stray port —
  `strip_port()`'s bare-IP guard works.
- **D5 installer ACL** — `icacls C:\ProgramData\ZTLP` shows
  `Administrators:(OI)(CI)(F)` immediately after `ztlp.exe agent install`.
- **Generalized token fallback** (`config::load_agent_token()`, committed
  in `7ad31b3` this session) — `ztlp.exe agent status` run as a *separate*
  interactive process now correctly authenticates against the running
  service by trying `C:\ProgramData\ZTLP\.ztlp\agent.token` when its own
  default path has nothing. Verified: `agent status` went from
  `hint: agent token not found at C:\Users\trs\.ztlp\agent.token` to
  `● running`.

## Bugs found live this session, fix status

All three were found by actually installing the real `ZtlpAgent` SCM
service and driving it through a real enroll — none were visible from
code review, cross-compilation, or CI, because they all involve runtime
interaction between the service's env (`ZTLP_HOME`) and code paths that
silently didn't honor it.

### Bug A — `cmd_enroll` re-execs the wrong binary under the service (FIXED, in the uncommitted diff)

**Symptom:** sending a real `enroll` control command to a freshly
installed, running `ZtlpAgent` service returned:
```
{"ok":false,"error":"enrollment failed (exit 1): Error: Winapi(Os { code: 1063, ... \"The service process could not connect to the service controller.\" })"}
```
**Root cause:** `control.rs`'s `cmd_enroll` calls `std::env::current_exe()`
and re-execs it with `setup --token ... --yes` args, assuming it's always
the `ztlp` CLI binary. Under the Windows service, `current_exe()` is
`ztlp-winsvc.exe` — a binary whose `main()` is ONLY
`windows_service::service_dispatcher::start(...)`; running it as a plain
subprocess with CLI args crashes immediately with Windows error 1063.

**Fix:** new `control::resolve_enroll_exec_path()` (pure, unit-tested, 6
tests) detects a `ztlp-winsvc` file stem (case-insensitive) and redirects
to the sibling `ztlp` binary in the same directory before re-execing.

**Verification status:** LIVE-VERIFIED. After this fix + rebuild + redeploy,
sending the same `enroll` command returned `{"ok":true,"data":{"output":"","tls_provisioned":true}}` — genuine success, config.toml/identity.json/CA all
appeared correctly under ProgramData.

### Bug B — two duplicate `expand_tilde()` bypass `ZTLP_HOME` (FIXED, in the uncommitted diff)

**Symptom:** After Bug A's fix, enrollment succeeded and wrote everything
to the right place, but `setup_status` kept reporting
`{"standby":true,"enrolled":false}` forever — the standby loop never saw
the identity file arrive and never handed over to the full daemon.

**Root cause:** `config.rs`'s `expand_tilde()` (used by
`AgentConfig::identity_path()`, which `run_agent_lifecycle`'s pre-standby
check and the standby poll loop both use to detect "has the identity
appeared yet?") called `dirs::home_dir()` **directly**, completely
bypassing `ztlp_state_dir()`'s `ZTLP_HOME` check. Under the Windows
service (`ZTLP_HOME=C:\ProgramData\ZTLP`), this meant the standby loop was
polling `C:\Windows\System32\config\systemprofile\.ztlp\identity.json`
(LocalSystem's real home) while `ztlp setup`'s subprocess (which DOES
correctly go through `ztlp_state_dir()` everywhere else) wrote the real
file to `C:\ProgramData\ZTLP\.ztlp\identity.json`. Two processes,
disagreeing about where "home" is.

**Same exact bug existed a second time**, independently, in
`local_tls.rs`'s own duplicate `expand_tilde()` — used for the default TLS
cert directory (`~/.ztlp/certs`). Confirmed live via a foreground repro
(`ZTLP_HOME` set, `ztlp.exe agent start --foreground -v`): log showed
`local TLS: enabled but no certs found in C:\Users\trs\.ztlp/certs` even
though everything else was correctly running under ProgramData.

**Fix:** both `expand_tilde()` implementations now resolve through
`config::ztlp_state_dir()` instead of `dirs::home_dir()` directly. Added
`expand_tilde_honors_ztlp_home_override` tests in both files (pinning the
exact regression). Behavior is unchanged wherever `ZTLP_HOME` isn't set
(`ztlp_state_dir()` falls back to `dirs::home_dir()` identically) — this
should NOT affect macOS/Linux/foreground-Windows behavior at all.

**Verification status:** LIVE-VERIFIED for the standby hand-over path in
combination with Bug C's fix (see below — the crash after handover masked
whether standby genuinely unstuck). The TLS-cert-dir half was confirmed
via the foreground repro log line disappearing is NOT yet re-checked post
the mod.rs fix — do this in the next session.

### Bug C — `run_agent_lifecycle`'s post-standby config load ALSO bypasses `ZTLP_HOME` (FIX WRITTEN, NOT YET BUILT/TESTED/VERIFIED)

**Symptom:** After Bug B's fix, a full clean-state re-test showed: enroll
returns `tls_provisioned: true`, `agent.pid` gets written (proof the
standby → full-daemon handover DID fire this time) — and then, moments
later, the Windows Service Control Manager logs Event ID 7034: "The ZTLP
Agent service terminated unexpectedly." (`sc query` showed `STATE: STOPPED`,
`WIN32_EXIT_CODE: 1067`).

**Root cause, found via a foreground repro** (`$env:ZTLP_HOME =
'C:\ProgramData\ZTLP'; ztlp.exe agent start --foreground -v`, run directly
over SSH so stdout/stderr are visible — the service itself has NO
persistent log file, a real gap, see "Known gaps" below): the repro
actually ran without crashing when I watched it, BUT its log showed the
SAME `local TLS: ... C:\Users\trs\.ztlp/certs` wrong-path symptom as Bug B
(consistent — the repro predates the local_tls.rs fix having been
rebuilt). Reading `agent::mod.rs::run_agent_lifecycle` (the function that
does the pre-standby identity check AND the post-standby full-daemon
config load) revealed a THIRD, separate instance of the exact same
mistake: after standby hands over, the function loads
`agent.toml`/`config.toml` for the full daemon via:

```rust
let agent_path = dirs::home_dir().map(|h| h.join(".ztlp").join("agent.toml"))...
let cli_path = dirs::home_dir().map(|h| h.join(".ztlp").join("config.toml"))...
```

— again `dirs::home_dir()` directly, not `ztlp_state_dir()`. This is
almost certainly why the SERVICE (not the foreground repro, which never
went through this exact code path the same way — needs re-check) crashed
with 1067: it re-loaded config from the wrong (LocalSystem) profile dir,
found neither file, and either panicked or hit a fatal config error deeper
in `daemon::run_daemon`.

**Fix (written, on disk, uncommitted):** replaced both `dirs::home_dir()`
calls with `config::ztlp_state_dir().join(".ztlp").join(...)`.

**NOT YET DONE — pick this up first in the next session, in order:**
1. `cd /home/trs/ztlp/proto && cargo fmt && cargo test --lib` — confirm no
   regressions from all 3 fixes together (last known-good count before
   these changes: 1303 lib + 117 CLI tests, all passing). Consider adding
   a unit test for this specific `run_agent_lifecycle` config-path
   resolution if a clean way to do so exists without spinning a real
   daemon (may not be practically testable in isolation — if not,
   document why in a comment rather than skip silently).
2. `cargo check --target x86_64-pc-windows-gnu` (must stay clean).
3. Cross-compile release binaries:
   ```
   cd /home/trs/ztlp/proto
   CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
   CARGO_TARGET_X86_64_PC_WINDOWS_GNU_AR=x86_64-w64-mingw32-ar \
     cargo build --release --target x86_64-pc-windows-gnu --bin ztlp --bin ztlp-winsvc
   ```
4. Deploy to `10.170.3.207` (stop service first, backup, copy, restart —
   see `/tmp/d5-redeploy.ps1` pattern used this session; SHA256-verify the
   transfer).
5. Clean state: stop service, `Remove-Item C:\ProgramData\ZTLP\.ztlp
   -Recurse -Force`, restart service (regenerates a fresh `agent.token`).
6. Mint a fresh enrollment token (see "Live test box" section above, use a
   new device name suffix to dodge NS collisions from prior attempts —
   `defcon-ai-computer-v3` or similar).
7. Send the enroll control command (reuse `/tmp/d5-enroll.ps1`'s pattern:
   read the CURRENT `agent.token` from `C:\ProgramData\ZTLP\.ztlp\`, POST
   a `{"cmd":"enroll","name":...,"token":...,"enrollment_uri":...}` JSON
   line to `127.100.255.1:4433`).
8. **The actual bar to clear:** `sc query ZtlpAgent` stays `RUNNING` (not
   STOPPED/1067) for at least 60+ seconds after enroll, AND a `setup_status`
   query (send `{"cmd":"setup_status","token":...}` the same way) reports
   `"standby":false,"enrolled":true,"identity_enrolled":true"` — NOT stuck
   on `standby:true` forever, and NOT a connection-refused (service
   crashed) either.
9. Once that's clean: re-check the TLS cert-dir log line is gone (`local
   TLS: enabled but no certs found in ...` should now say
   `C:\ProgramData\ZTLP\.ztlp/certs`, not the user profile) — needs a
   foreground repro or the service's own log if a logging mechanism gets
   added (see gap below).
10. Check `token_shared_with_gui`/ACL: `icacls C:\ProgramData\ZTLP\.ztlp\agent.token`
    should show an explicit grant for the console user `trs`, not just
    `Administrators:(I)(F)` — this was NOT yet seen correctly in ANY test
    this session (every successful enroll so far still only showed the
    Administrators-only ACL). This might be a 4th bug (console-user ACL
    step silently not firing/matching) or might just be an artifact of
    testing via a headless TCP script instead of the real desktop GUI
    (which is what would normally trigger `setup_status` polling that
    reads `token_shared_with_gui`) — investigate before assuming it's
    broken.
11. Commit all fixes together (Bug A + B + C read like one coherent
    "D1's ZTLP_HOME contract wasn't fully honored" story — one commit,
    detailed message, same style as the D1-D6 commits already on this
    branch) — get Steven's go-ahead per the standing rule before pushing.
12. Push, watch CI (must include a fresh `windows-latest` pass).
13. THEN — and only then — is it honest to say D5's "prove it end to end
    on the real box" checklist item is actually done. Update
    `docs/handoffs/WINDOWS-SERVICE-PARITY-PHASE-D-PLAN-2026-09-21.md`'s
    Status note once this is true.

## Known gaps / observations (not bugs to fix necessarily, but don't lose them)

- **The Windows service has no persistent log.** `ztlp-winsvc.rs` uses
  `tracing::info!`/`warn!`/`error!` but nothing routes those to a file
  when running as a real SCM service (stdout goes nowhere). Every crash
  diagnosis this session required either the Windows Event Log (which
  only has "terminated unexpectedly", no stack/reason) or a manual
  foreground repro. Worth a follow-up: wire a rolling file appender
  (`tracing-appender` or similar) so `ztlp-winsvc.exe` writes to e.g.
  `C:\ProgramData\ZTLP\.ztlp\service.log` — would have cut this session's
  Bug C diagnosis time significantly.
- **`ztlp setup --token ...` (the bare CLI subcommand) is NOT the same
  path as the desktop-GUI/D3 `enroll` control command.** The CLI's
  `setup` writes directly to whatever `~/.ztlp` resolves to for the
  *calling* process (no `ZTLP_HOME` awareness needed since it's meant to
  be run by an interactive user) — it does NOT go through the service's
  IPC at all. Do not try to "enroll via `ztlp setup --token`" against a
  service install and expect it to affect the service; you'll just create
  a second, disconnected identity in the wrong place. The only real path
  to enroll the *service's* identity is the `enroll` control command over
  TCP to `127.100.255.1:4433`, which is what the desktop GUI's
  `ipc_enroll_at` does — this session drove that same wire protocol
  directly via PowerShell since no GUI click-through was available.
- **The old `demo.spongebob.ztlp` NRPT rules and CAs were cleaned up**
  this session (backed up ~.ztlp to `.ztlp.bak-<timestamp>`, removed stale
  certs from `LocalMachine\Root`). Should not need re-doing.
- Steven has real interactive access to the AI PC now (per his message
  this session, "i have access to the ai pc") — once the service-side
  bugs above are fixed and verified via the same headless-TCP method,
  the natural final step is to actually click through the **desktop GUI**
  (`ztlp-desktop.exe`, already installed at
  `C:\Users\trs\AppData\Local\ZTLP\ztlp-desktop.exe`) for the true "one
  UAC, zero further prompts" human-verification the original plan asks
  for — that has NOT been done at all yet, only the equivalent wire
  commands have been sent programmatically.

## Merge status — unchanged from before this session

PR #112 is still a **draft**. `gh pr merge 112 --repo priceflex/ztlp`
fails with "Pull Request is still a draft" — this requires Steven's
explicit action to un-draft, on top of the live-box verification above
finally being clean. Do not merge until:
1. Bugs A/B/C above are committed, pushed, and CI-green (A is proven,
   B is proven, C is unverified).
2. A real enroll-through-the-service test shows `enrolled:true` and the
   service survives well past the handover point.
3. Steven has un-drafted the PR himself.
