# D2.T5 — Windows-bench smoke runbook

This directory holds the manual smoke we run on a real Windows endpoint
to validate the D2 Windows service host (`ztlp-service.exe`). These
tests are **not** run by CI — they require a real Windows box where the
service can be registered with SCM, started, and observed.

The single check that proves the D2 deliverable works end-to-end is
`d2-bench-smoke.ps1`. It is idempotent and self-cleaning: re-run it as
many times as you want, the bench state is restored when it finishes.

## Prerequisites on the bench

- Windows 10 / Server 2019+ x64
- Administrator account (the script must be elevated)
- Two files staged on disk **next to each other** in the same directory:
  - `ztlp-service.exe` — built via `cargo build --release` in `service/`
    (CI uploads this as an artifact since the D2.T5-followup CI patch)
  - `ztlp.exe` — the agent binary (CI uploads this too; can also be
    copied from any existing v0.30.x ZTLP install)

The smoke script assumes both are on the user's Desktop. Edit
`$ServicePath` at the top if you want to run it from a different layout.

## Running it

From an elevated PowerShell (Admin or SSH session as a user in the
Administrators group):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File d2-bench-smoke.ps1
```

The script reports `[OK]` / `[X]` per check and ends with either
`[PASS] D2.T5 SMOKE PASSED` (exit 0) or `[FAIL]` (exit 1) plus the
list of failed checks.

## What it verifies

| Step | Verification |
|---|---|
| 1 | `ztlp-service.exe install` exits 0 |
| 2 | `C:\ProgramData\ZTLP\agent.token` exists with the right ACL: SYSTEM:FullControl, BUILTIN\Administrators:Read, *current-user*:Read |
| 3 | Service registered with SCM: `LocalSystem` start name, `Auto` start mode, `binPath` is **quoted** (defends against the unquoted-service-path CVE) |
| 4 | `Start-Service ZtlpAgent` transitions the service to `Running` and it stays Running for at least 5 seconds (no immediate crash) |
| 5 | `Stop-Service ZtlpAgent` transitions cleanly to `Stopped` |
| 6 | `ztlp-service.exe uninstall` removes the SCM entry |
| Cleanup | Token file is removed; bench is back to the state we found it in |

## Bugs this smoke caught

- **Workgroup-Windows installer failure** (fixed in D2.T5 follow-up).
  On a non-domain-joined host `$USERDOMAIN` is the literal `WORKGROUP`,
  which `icacls` cannot map to a SID — install would fail with the
  cryptic `1332: No mapping between account names and security IDs
  was done`. Fix: prefer `whoami` (always SID-mappable) over the
  `USERDOMAIN\USERNAME` env-var path. See
  `install::resolve_current_user` + the `tests::workgroup_*` unit tests.
- **Missing `ztlp.exe` next to `ztlp-service.exe`** correctly aborts
  startup (the supervisor logs the error and exits cleanly back to
  STOPPED). The smoke verifies the happy path with both binaries present.

## When to re-run

- Before merging any change in `service/`, `desktop/src-tauri/`, or the
  D1 control-plane code paths
- Whenever Windows itself is upgraded on the bench
- Whenever the bench drifts from workgroup to domain-joined (or back)
