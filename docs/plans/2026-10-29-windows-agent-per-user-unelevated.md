# Plan: Windows ZTLP agent runs per-user, unelevated (no SYSTEM service)

Status: DESIGN AGREED 2026-10-29 (Steven + Hermes), rev b same day (installer
owns DNS + CA; 4-check UI), rev c (Fix button = UAC repair). IMPLEMENTED on
branch feat/windows-per-user-agent for v0.37.0 / desktop 1.4.0; see
"Implementation + test tracker" at the end. Base: v0.36.0.
Scope: Windows first. macOS follows (see "macOS later"). Linux unchanged.
Supersedes the 2026-10-28 "push identity into the SYSTEM service" draft; that
design is dropped (see Appendix A for why).

## Goal

- Outgoing ZTLP on Windows runs as the logged-in user: a tray app plus an agent
  child process, both unelevated. No ZtlpAgent SYSTEM service for this role.
- Each Windows user enrolls their own identity in their own profile. The
  identity never exists in a SYSTEM process.
- Nobody logged in = no agent = no tunnel, no DNS answers for *.ztlp. Lock =
  freeze (no new connections). That is the "no bots when the human is away"
  property.
- The inbound SSH listener (Chef `ztlp` cookbook, `ztlp listen`, NSSM
  `ztlp_listener`) is OUT OF SCOPE and unchanged.

## Proven on a real box (a Windows test PC, 2026-10-29, details in Appendix B)

The unmodified v0.36.0 agent, started by a standard (non-admin) local user from
a plain cmd window, did everything end to end: bound VIPs :80/:443/:8080 etc.,
DNS stub on 127.0.0.55:53, control socket, QUIC dial to the whoami gateway,
local TLS (TLS 1.3, cert CN=whoami.trs.ztlp), and served the whoami page in a
real browser. Windows has no privileged-port rule.

The ONLY things that need admin: the NRPT rule (HKLM) and, if used, machine-
wide root CA trust. Both are install-time, not runtime.

## Architecture (three pieces; only #1 is ever elevated)

1. Installer (Tauri NSIS, perMachine, ONE UAC prompt at install, runs once)
   Everything that needs admin happens here and only here. After install the
   user never sees another UAC or Windows security prompt.
   - Binaries to `C:\Program Files\ZTLP\` (ztlp.exe, ztlp-desktop.exe).
     `ztlp-winsvc.exe` is no longer bundled on Windows.
   - DNS: NRPT rule, namespace `.ztlp` -> 127.0.0.55. One umbrella rule, zone-
     independent (`nrpt_zones_with_umbrella` already does this). Never touched
     again.
   - CA (machine CA, created by the installer, not per user):
     - Generate the existing `ca-init` chain (ECDSA P-256 root + intermediate,
       both nameConstraints `.ztlp`, so it can never sign a public name) into
       `C:\ProgramData\ZTLP\ca\`.
     - Install the root into `LocalMachine\Root` (`CertStoreScope::Machine`,
       already in ca_trust.rs). No user-facing trust prompt, works for every
       user and for Chrome/Edge.
     - ACLs: root key = Administrators+SYSTEM only (only needed to re-sign the
       intermediate on rotation). Intermediate cert+key + root cert = readable
       by Users, because each user's agent mints the per-site leaf certs.
       Trade-off: any local user can mint `.ztlp` certs trusted on this box.
       Acceptable for v1 (single-console-user desktops); `.ztlp` traffic only
       ever goes to whichever agent owns the VIPs anyway.
     - `C:\ProgramData\ZTLP\ca\` holds ONLY the CA. No identity, no
       agent.toml, no token there (that was the 2026-10-28 competing-configs
       incident).
   - If an old ZtlpAgent service exists: stop + delete it (`ztlp agent
     uninstall`), then remove its old ProgramData identity/agent.toml/token.
   - Register ztlp-desktop.exe to start at logon (HKLM Run, all users).
   - Does NOT install a service. Does NOT enroll.
   - Uninstall (one UAC): remove NRPT rule, root from LocalMachine\Root,
     `C:\ProgramData\ZTLP\ca\`, Run entry, binaries. Per-user identities
     under profiles are left (or offered for removal).

2. Tray app: ztlp-desktop.exe (per user, unelevated, starts at logon)
   - First run -> one step only: paste enrollment link -> Enroll. No CA step,
     no DNS step, no service step (installer did those).
   - Enroll: runs `ztlp setup --token <uri>` IN USER CONTEXT. Identity lands at
     `%USERPROFILE%\.ztlp\identity.json` (+ agent.toml, ns_trust.toml, CA).
     Today the app sends `enroll` over the control socket to the SYSTEM daemon
     to avoid the "two identities" bug (desktop/tunnel.rs comment). With no
     SYSTEM daemon there is one identity, so the control-socket enroll path is
     retired on Windows.
   - CA: none per user. The user's agent.toml points its TLS mint at the
     machine CA in `C:\ProgramData\ZTLP\ca\` (intermediate). `ztlp setup`
     must NOT run ca-init on Windows when the machine CA exists.
   - Then: spawn `ztlp agent start --foreground` as a child; restart it if it
     dies (backoff); kill it on tray exit; it dies with the session at logoff.
   - Session events: the tray app has a window, so it receives
     WM_WTSSESSION_CHANGE. On LOCK / CONSOLE_DISCONNECT / REMOTE_DISCONNECT send
     `freeze` to the agent; on UNLOCK / CONSOLE_CONNECT send `thaw`. Policy
     setting `lock_policy = freeze | drop | keep`, default `freeze`.
   - "In use by another user": if the agent reports it could not bind the DNS
     stub / VIPs (another session's agent owns them), show that state and
     retry every 30 s. Mirrors Tailscale.

3. Agent: `ztlp.exe agent start` (child of tray app, same user)
   - Unchanged engine: DNS stub 127.0.0.55:53 (NRPT sends *.ztlp here), VIP
     listeners on :443 etc. with local TLS, tunnels, control socket on
     127.100.255.1:4433 with agent.token in the user's profile (user-only ACL;
     tray app is the same user, so no change).
   - New control commands: `freeze` (reject new dials, answer DNS NXDOMAIN,
     keep established streams until idle_timeout), `thaw`.
   - Skip the Windows service-only startup plan (InstallCaCertMachine, SetupNrpt,
     TokenGuiReadable) when not running as the service; log at debug, not warn.
   - Bind failure on DNS stub or VIPs is a reportable state (`status` field
     `ports_owned_by_other = true`), not a crash.

## Windows UI (desktop Tauri app; macOS Swift app unchanged)

The UI is: the identity, plus four status lights. Nothing else to set up.

Home = four rows, each a green/amber/red dot with a one-line detail. Each row
is a real end-to-end check, not a "config file exists" flag.

| Row | Green when | Check |
|---|---|---|
| Agent | the user's agent child is up and answering | tray-supervised child alive AND control-socket `status` replies. Amber while (re)starting; red "In use by another user" when `ports_owned_by_other` |
| Identity | enrolled and accepted by the name server | `identity_enrolled` AND last NS check-in succeeded (status gains `ns_checkin_ok` + `ns_checkin_error`). Detail shows `<device>.<zone>`. Amber "Not enrolled" -> Enroll button (the only action button on Windows) |
| DNS | `.ztlp` names actually resolve through Windows to our stub | tray resolves the reserved probe name `ztlp-health.ztlp` via the normal OS resolver (`getaddrinfo`, so it goes Dnscache -> NRPT -> 127.0.0.55); agent answers it with the fixed probe VIP 127.100.255.2. Red detail if NRPT missing ("Reinstall ZTLP to repair DNS") |
| HTTPS | a browser would trust a `.ztlp` site | tray opens TLS to 127.100.255.2:443 SNI `ztlp-health.ztlp` and validates the chain against the Windows store (native schannel verify, same trust as Edge/Chrome). Agent serves a leaf minted from the machine CA there and closes after the handshake. Red detail if root not in LocalMachine\Root ("Reinstall ZTLP to repair HTTPS") |

- A red DNS or HTTPS row has a **Fix** button: it runs `ztlp.exe agent
  machine-setup` elevated (one UAC prompt, same idempotent step the installer
  ran) and the app re-checks every 2 s until green (rev c, Steven: "if DNS and
  HTTPS is red, trigger a UAC that installs the fix").
- Rows are evaluated in order; a red Agent row puts the others in "waiting".
- Checks rerun every 30 s and on unlock/resume; overall tray icon = green
  only when all four are green.
- Probe name/VIP are local-only: never sent to the NS, never a real tunnel.

Removed on Windows (kept on Linux until its own plan; macOS app untouched):
- Home "Service" row and "Install Service" action (home.js, home-readiness.js).
- Setup steps 2-4 (Generate CA, Install CA (admin), Configure DNS (admin)) and
  "1b create identity". Setup = Enroll only (+ the smoke test, optional).
- Gear tooltip "service, identity, reset" -> "identity, reset". Settings keeps
  Auto-connect + Identity & zone.
- Tauri commands `setup_install_service`, `setup_install_ca`, DNS install,
  control-socket `enroll` path on Windows.
- `ztlp-winsvc` from `tauri.windows.conf.json` externalBin.
- hooks.nsh: the service-uninstall preuninstall becomes "remove legacy service
  if present"; install hooks gain NRPT + machine CA; uninstall removes them.

Platform gating: home-readiness.js gets a `platform` input. `windows` ->
rows [agent, identity, dns, https]; anything else -> today's rows unchanged.
The probe responder in daemon.rs is platform-neutral and harmless elsewhere.

## Code changes (proto crate unless noted)

| Area | Change | Size |
|---|---|---|
| desktop/src-tauri (tunnel.rs, setup.rs, state.rs, tray.rs) | spawn/supervise agent; enroll via `ztlp setup` in user context; CurrentUser cert step; WTS session hook -> freeze/thaw; "in use" state | 300-400 |
| agent/control.rs | `freeze`, `thaw`; status gains `frozen`, `ports_owned_by_other` | 80-120 |
| agent/daemon.rs (shared, all platforms) | frozen flag checked in dial path + DNS answer path; bind failures -> state not exit; service-only plan gated on is_windows_service | 150-250 |
| agent/daemon.rs + dns | reserved `ztlp-health.ztlp` -> 127.100.255.2; TLS responder on it (mint from machine CA); status `ns_checkin_ok/_error` | 80-120 |
| agent/config + `ztlp setup` (Windows) | point TLS mint at `C:\ProgramData\ZTLP\ca\`; skip ca-init when machine CA present | 40-80 |
| `ztlp` CLI | `ztlp install-machine` / `uninstall-machine` (NRPT + machine CA + ACLs + legacy service removal) called by the installer hooks | 150-250 |
| desktop frontend (home-readiness.js, home.js, setup.js, index.html) | 4-row Windows Home; Setup = enroll only; service/CA/DNS UI removed on Windows | 150-250 |
| agent/windows_daemon.rs, windows_service_install.rs, bin/ztlp-winsvc.rs | keep for optional "unattended mode" (own identity, later); default install no longer uses them | 0 now |
| installer | NRPT rule + Run entry + binaries; no service | installer-side |
| Win32 for WTS session notify | small separate crate (`ztlp-winsec`), proto stays `#![deny(unsafe_code)]` | 100-150 |

Shared-file rule: anything in daemon.rs must be a platform-neutral hook with
the OS producer behind `cfg(target_os)`, so macOS/Linux compile and behave
exactly as today until their producers exist.

## Multi-user rules (v1)

- One active agent per machine at a time (whoever holds the DNS stub + VIPs).
  Fast user switching: the second user's tray shows "in use by another user"
  until the first logs off. Same as Tailscale. No cross-user routing is
  possible because the second agent never gets the ports.
- RDS / multi-session hosts: OUT OF SCOPE for v1. If needed later, Appendix C
  option B (front-door owner check via GetExtendedTcpTable) gives real
  per-session isolation with the same shared DNS.
- Unattended / nobody-logged-in outgoing ZTLP (server boxes): OUT OF SCOPE.
  Later = opt-in ztlp-winsvc with its own machine identity, Tailscale's
  "unattended mode".

## Security notes

- Identity private key: in the user's profile, ACL'd to the user. Optional
  later: DPAPI (CurrentUser) wrap. A local admin can read any user's profile;
  admin = out of scope, as with every VPN client.
- VIPs are loopback: while a user's agent is up, any process on the box in any
  session can hit the VIPs. Acceptable for one-console-user desktops (v1).
- Machine CA (installer-made, nameConstraints `.ztlp`, root in
  LocalMachine\Root): intermediate key is Users-readable so per-user agents
  can mint leaves; root key admin-only. Worst case a local user mints a
  `.ztlp` cert trusted on this box; it cannot sign any public name. Firefox
  needs `security.enterprise_roots.enabled` (or a policy); Chrome/Edge use the
  Windows store.
- Lock = freeze by default: a bot in the user's session cannot start new
  tunnels while the screen is locked; existing streams idle out (300 s).
  Nothing stops malware running as the user while the user is active; that is
  the same for every VPN and is a per-app-policy problem, not this plan's.

## Test plan

Unit:
- freeze/thaw state machine; dial rejected while frozen; DNS NXDOMAIN while
  frozen; established stream survives freeze until idle timeout.
- bind-conflict -> status `ports_owned_by_other`, no exit.
- service-only startup plan skipped when not a service.

Real box (standing rule: real user, real browser):
- Fresh install on a clean VM: one UAC at install, zero afterwards.
- Standard user: logon -> tray -> enroll (no other prompt) -> all four rows
  green -> https://whoami.trs.ztlp in Edge and Chrome.
- Break each check on purpose and see the right row go red: kill agent
  (Agent, then auto-restart), delete NRPT rule (DNS), remove root from
  LocalMachine\Root (HTTPS), bad/expired identity (Identity).
- Lock screen: new connection fails; existing SSH session stays up ~5 min then
  drops; unlock -> works again.
- Logoff: `netstat` shows no 127.100.x listeners, `.ztlp` lookups fail.
- Second local user (fast switch): sees "in use by another user"; after first
  user logs off, second user's agent takes over with ITS identity (gateway log
  shows the second device name).
- No identity.json anywhere under C:\ProgramData.
- Upgrade path: box with the old ZtlpAgent service installed -> installer stops
  and removes the service, keeps/migrates nothing from ProgramData (user
  re-enrolls), NRPT rule stays.

## Decisions log

- 2026-10-29: drop push-identity-into-SYSTEM. Reason: tests proved no
  elevation needed at runtime; per-user process is less code and keeps the
  key out of SYSTEM.
- 2026-10-29: lock policy default = freeze (Steven's requirement: no bot use
  while the human is away; drop was too disruptive for a 30-second Win+L).
- 2026-10-29: RDS and unattended mode out of scope for v1.
- 2026-10-29: Windows first; macOS after.
- 2026-10-29 (rev c, Steven): a red DNS/HTTPS row may trigger a UAC repair
  (Fix button). Public `.ztlp` sites do not exist, so the Users-readable
  intermediate key trade-off is accepted.
- 2026-10-29 (implementation): default device name `<computer>-<user>` (each
  Windows user has their own identity; the computer name alone may still be
  held by the service-era identity for a year). Lock detection polls
  `WTSQuerySessionInformationW(WTSSessionInfoEx)` every 2 s from the desktop
  crate (no new unsafe crate, no message window). The agent exits with its
  parent (`--parent-pid`) instead of a Job object.
- 2026-10-29 (rev b, Steven): installer does ALL admin work in one UAC: DNS
  (NRPT) AND the CA (machine CA in LocalMachine\Root). Replaces the per-user
  CurrentUser\Root wizard step. App UI = identity + four end-to-end checks
  (Agent, Identity, DNS, HTTPS). All service UI removed on Windows. macOS app
  unchanged for now.

## macOS later (not this plan)

Same end state (agent in the user's session, identity in the user's home).
Differences: macOS 10.14+ needs no root for :443 (documented, untested); but
lo0 aliases for the 127.100.x VIPs need root on every boot, so a small root
helper (the existing SMAppService helper) stays for aliases plus the install-
time steps (/etc/resolver/<zone>, keychain root). The Mac app lives on
feat/macos-parity-0.35.20 (11 commits / 68 files off v0.36.0); land the
Windows daemon.rs hooks on main first, then rebase that branch.

## Out of scope

- `ztlp listen` / Chef `ztlp` cookbook / inbound SSH. Unchanged. The only thing
  that touches its tree is that `C:\ProgramData\ZTLP\` stops holding agent
  state (fixes the 2026-10-28 "competing configs" incident).

---

## Appendix A: why the push-identity design was dropped

Draft of 2026-10-28 proposed keeping the LocalSystem service, having the user's
tray app push identity + config over a named pipe, and holding them in memory.
Research (Tailscale LocalAPI, HITCON 2024 named-pipe CVEs, `interprocess`
crate) showed it was buildable but needed: named pipe with caller-token checks
in a new unsafe crate, an activate/deactivate state machine, a refactor of
run_daemon, zeroization, a desktop re-push loop, and still put every user's
private key inside a SYSTEM process. The only reason for SYSTEM was the belief
that :443 needed it. Tests proved it does not. The named-pipe recipe is kept
below in case a privileged broker is ever needed:
- `\\.\pipe\ztlp-agent`; FILE_FLAG_FIRST_PIPE_INSTANCE; PIPE_REJECT_REMOTE_CLIENTS;
  explicit DACL (SYSTEM+Admins full, INTERACTIVE rw); server:
  ImpersonateNamedPipeClient -> OpenThreadToken -> SID + session id ->
  RevertToSelf; client: SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION and verify
  server PID == service PID; fixed schema, size cap, no paths/exe/args.

## Appendix B: test evidence (a Windows test PC, Win10/11, over breakglass)

B1 2026-10-28 23:55 PDT, restricted token (`runas /trustlevel:0x20000`,
Administrators = deny-only): bound TCP 127.100.9.9:443/:80/:8443,
127.0.0.1:443, 0.0.0.0:443, UDP 127.0.0.56:53.

B2 2026-10-29 00:10, same restricted token, full agent (`ztlp.exe agent start
--foreground`, ZTLP_HOME = copy of service state, ZtlpAgent stopped): bound
127.100.0.{1,2,3}:80/443/3306/3389/5432/8080/8443, 127.100.255.1:4433, UDP
127.0.0.55:53; Resolve-DnsName whoami.trs.ztlp -> 127.100.0.3 via existing
NRPT; QUIC tunnel to the whoami gateway active. Failed as expected: NRPT setup
("Cannot connect to CIM server. Access denied"), token icacls, VIP :22 (sshd
owns 0.0.0.0:22, not a privilege issue), NS check-in 0x09 (same NodeID as the
service's registration; artifact of the copy).

B3 2026-10-29 00:24, REAL standard local user `ztlptest` (Users only), agent
run via scheduled task (SeBatchLogonRight granted for the run, reverted after):
process owner <PC>\ztlptest; same binds; .NET SslStream to
127.100.0.3:443 SNI whoami.trs.ztlp -> TLS 1.3, cert CN=whoami.trs.ztlp. NRPT
-> PermissionDenied (WIN32 5).

B4 2026-10-29 00:40, Steven at the console as `ztlptest`, agent from a plain
cmd, browser https://whoami.trs.ztlp -> page served. Gateway log: "Policy
allowed desktop-fqtgi6c.trs.ztlp for service 'whoami'".

Findings along the way:
- ERR_EMPTY_RESPONSE / curl "Empty reply" was the whoami gateway policy
  (allow = stevens-mac-studio only), also for the SYSTEM service. Opened to
  `allow = ["*"]` on the whoami gateway host (its policy.toml; backup kept next to
  it).
- proto/src/policy.rs is a hand-rolled parser: an inline `# comment` after
  `allow = [...]` silently drops the rule ("loaded 0 policy rules"). Comments
  on their own line only. Candidate for a real TOML parser.
- curl.exe (schannel) fails our CA on revocation checking (no CRL); browsers
  don't check private roots. Use `--ssl-no-revoke` or a browser.
- Launching a process as another user from an SSH (session 0) shell fails with
  0xC0000142; use a scheduled task + batch logon right, or a console login.
- The test box still has the temporary test user and scratch files from these
  runs; remove them (tracked outside this public doc).

## Appendix C: multi-user options considered

- A (chosen): per-user agent process, install-time admin only.
- B (deferred, RDS): single front-door listener on the VIPs; on accept, map the
  client socket to its owner PID (GetExtendedTcpTable TCP_TABLE_OWNER_PID) ->
  session/SID -> route to that session's identity, reject if none. Needed only
  for multi-session hosts; works with shared DNS.
- C (v1 behaviour): one active user; others wait. Tailscale's model.
Why DNS can't separate users: NRPT is machine-wide and queries reach our stub
from the Dnscache service, not from the user's process.

## Appendix D: v0.36.0 facts referenced

- daemon.rs loads identity once at start (no runtime swap); AgentConfig from
  `$ZTLP_HOME/.ztlp/agent.toml`; ns_trust from file; unenrolled standby mode
  exists; control socket commands: status, tunnels, dns_cache, flush_dns,
  shutdown, setup_status, enroll.
- Windows service-only startup plan (windows_daemon.rs): InstallCaCertMachine,
  SetupNrpt, TokenGuiReadable; only runs when `is_windows_service`.
- session_lock.rs: consumer side exists (teardown on lock/logoff/disconnect);
  Windows producer not implemented ("owned by ztlp-service.exe" stub).
- Crate is `#![deny(unsafe_code)]`; Win32 calls go in a separate crate.
- `user_binding.rs` (bound_user_sid) pins an identity to one SID; harmless
  under per-user (each profile's identity is that user's anyway).

## Implementation + test tracker (v0.37.0 / desktop 1.4.0)

| Piece | Where | Proof |
|---|---|---|
| freeze/thaw, health name, check-in record, machine CA dir, parent watch | `proto/src/agent/peruser.rs` | unit tests (peruser) |
| DNS: health name -> 127.100.255.2, NXDOMAIN while frozen | `agent/dns.rs` | 3 tests, RED first |
| control: `freeze`/`thaw` (full + standby), `status.frozen`, `status.ns_checkin`, no post-enroll CA steps with a machine CA | `agent/control.rs` | 4 tests, RED first |
| TLS health responder | `agent/local_tls.rs` `run_health_responder` | test: real TLS + 200, RED first |
| daemon: refuse new VIP conns while frozen, mint from machine CA, TLS on when machine CA present, health listener (Windows) | `agent/daemon.rs` | covered by the above + live box |
| `ports_owned_by_other` refusal | `agent/mod.rs` lifecycle | `control_addr_owned_by_other` test |
| `machine-setup` / `machine-teardown` / `machine-status` | `agent/machine_setup.rs`, CLI | plan + ACL + chain tests; live box |
| desktop: supervisor, lock watch, health report, Fix, device name, Windows-only UI | `desktop/src-tauri/src/peruser.rs`, `desktop/src/**` | 13 Rust tests (incl. rustls accepts the `.ztlp`-constrained chain), `scripts/test_home_peruser.js` |
| installer: one UAC (`machine.ps1`), HKCU Run `--autostart`, teardown skipped on update, no winsvc | `desktop/src-tauri/windows/` | CI NSIS compile; live box |

Live acceptance on the AI computer (real user, real browser): see the release
notes / session log for results of each step below.

1. Back up the service-era identity, uninstall 1.3.0 (service, NRPT, CA gone).
2. Install 1.4.0: one UAC, `machine-status` all true, no `ZtlpAgent`.
3. App at logon (tray), agent process owned by the user, not SYSTEM.
4. Enroll in the app: identity under `%USERPROFILE%\.ztlp`, name `<computer>-<user>`.
5. Home: four green rows. Chrome: https://whoami.trs.ztlp loads, gateway log shows the new device.
6. Break each: kill agent (auto restart), remove NRPT (DNS red -> Fix -> green), remove root (HTTPS red -> Fix -> green).
7. Lock: new connection refused / NXDOMAIN; unlock: works.
8. Quit app: agent gone, no 127.100.x listeners.
