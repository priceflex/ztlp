# HANDOFF: Windows Service Parity Phase D, Bug D FIXED (2026-09-28, session 6)

Continues `HANDOFF-2026-09-21-session5-bugD-service-crash.md`.

## Root cause (proven live, not theorized)
The rustls CryptoProvider was never installed in `ztlp-winsvc.exe`. Both `ring` and
`aws-lc-rs` are in the dep tree, so rustls cannot auto-select a provider.
The first `ServerConfig::builder()` in local TLS (right after the post-enroll handover,
tls.enabled=true) panics:

    PANIC ztlp-winsvc at rustls-0.23.43/src/crypto/mod.rs:249:14:
    Could not automatically determine the process-level CryptoProvider ...

The panic unwinds into the `extern "system"` service_main FFI entry. That aborts the
process, and WER reports it as 0xc0000409 / SCM 1067. The foreground `ztlp.exe agent start`
never crashed because ztlp-cli's `main()` installs ring first. None of the session-5
candidates (stack size, shutdown race, LocalSystem perms) was the cause.
The timing varied because it depends on how long the enroll subprocesses take.

## Fix (uncommitted, on top of session-5's 5 modified files)
- `proto/src/agent/mod.rs`: new `ensure_rustls_crypto_provider()`, called at the top of
  `run_agent_lifecycle` (covers every host binary), plus regression test
  `crypto_provider_tests::ensure_rustls_crypto_provider_installs_and_is_idempotent`.
- `proto/src/bin/ztlp-winsvc.rs`: calls it in `service_main`. Also permanent diagnostics:
  - file log at `C:\ProgramData\ZTLP\.ztlp\ztlp-winsvc.log`. The service previously had
    NO tracing subscriber, so every error was silently dropped.
  - a panic hook that logs location and message.
  - `catch_unwind` around `run_service`, so a future panic reports Stopped cleanly instead
    of aborting across FFI.

## Verified
- cargo test --lib: 1305 passed / 0 failed / 13 ignored (1304 baseline + 1 new).
- cargo check windows-gnu clean. Release builds deployed to 10.170.3.207 and hash-verified:
  - ztlp.exe cd961cb9e60bd2c637b3d126ee5d7caac1068df68fa7fd6d49173cbeedaafb23
  - ztlp-winsvc.exe f9f9c9e4f089ae55e89eee625a1be89cdc80a7b89ac352a14776d8d5d6638b6e
  - rollback: `*.bak-bugD-fix` (session-5 builds), `ztlp-winsvc.exe.bak-bugD-diag`.
- THE BAR: clean state, fresh token, real `enroll` control command, response
  `{"ok":true,"data":{"tls_provisioned":true}}`. Service stayed RUNNING through T+420s
  (session 5 died by T+30..240s). No Application errors. setup_status reported
  identity_enrolled:true, ca_initialized:true, ca_installed_system_trust:true,
  dns_configured:true. Log shows `local TLS: acceptor ready`, the exact point that
  panicked before.
- TLS cert-dir log line is still correct (ProgramData).

## Desktop GUI follow-up (same session): app showed "Service: Not installed"
Three stacked bugs, all fixed with tests and verified on-screen (Ready / Running /
Enrolled / HTTPS trusted + DNS routed):
1. `windows_daemon::console_user_name` gated on `query user` exit status; on this box it
   exits 1 while printing the Active console row, so the service never granted the
   console user read on agent.token -> GUI got "unauthorized". The token-ACL item was a
   REAL bug, not a headless artifact. New pure `parse_query_user_active` + test.
2. `desktop ipc.rs` used a 500ms read timeout for every command; `setup_status` takes
   ~850ms against the service. New `io_timeout_for` (setup_status 5s, enroll 120s) + tests.
3. `config::load_agent_token` tried the stale user-profile token before the service
   token, contradicting its own doc. Now service path first (`load_first_token`) + tests.
Also: `setup_status` now returns `daemon_error` and Home logs it instead of silently
showing "Not installed".
Test counts: proto lib 1308 passed; desktop bins 31 passed.

## Still open
- A stray user-context `ztlp.exe agent start` keeps appearing next to the service
  (likely old auto-connect path in the desktop app); it is what wrote the stale
  %USERPROFILE%\.ztlp\agent.token. Not fixed yet.
- UI polish to match the Mac app (requested, not started).
- Cosmetic: the loopback-alias helper uses `Get-NetIPConfiguration -Loopback`, which does not
  exist on this PS version (WARN, falls back fine). Worth a follow-up ticket.
- The test enroll sent no relay_secret, so it logged a WARN about unsigned CLIENT_ROUTE.
  This is a test artifact.
- Commit A+B+C+D (needs Steven's go-ahead), push, CI incl. windows-latest, then update
  docs/handoffs/WINDOWS-SERVICE-PARITY-PHASE-D-PLAN-2026-09-21.md.

## Test-harness pitfalls (cost most of this session)
- enroll wire format: `token` = the control-plane BEARER (agent.token);
  `enrollment_uri` = the ztlp://enroll/ URI. Swapping them returns a generic
  "unauthorized". Use `C:\temp\bugd-repro.ps1` (hashtable | ConvertTo-Json, StreamWriter
  with "`n" NewLine, ReadLine). It is the proven client.
- Control socket is line-framed: no trailing \n means no response at all.
- `ztlp://enroll/` is 14 chars, not 12. Also, any "mod 4" check on a base64url no-pad token
  is meaningless. Both were red herrings.
