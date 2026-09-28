# HANDOFF — Windows Service Parity Phase D — Bug D found (service-only crash) — 2026-09-21 (session 5)

Continues `HANDOFF-2026-09-21-session4-d5-live-testing.md`. This session
picked up the "NOT YET DONE" checklist from session 4 (test, cross-compile,
redeploy, verify Bug C). Steps 1-7 all passed clean. Step 8 (the actual bar:
service stays RUNNING past handover) **FAILED** — but not for the reason
Bug C's fix was written for. A NEW bug (call it **Bug D**) was found.

## Branch / repo state — unchanged

Still `feat/linux-service-parity-phase-a`, tip `7ad31b3`. The same 5 files
are modified on disk, UNCOMMITTED (do not commit yet — Bug C's fix is
correct but insufficient, see below):
```
M desktop/src-tauri/src/ipc.rs
M proto/src/agent/config.rs
M proto/src/agent/control.rs
M proto/src/agent/local_tls.rs
M proto/src/agent/mod.rs
```

## What was verified clean this session (do not re-do)

1. `cargo fmt && cargo test --lib` — **1304 passed, 0 failed, 13 ignored**
   (was 1303 baseline in session 4 notes; +1 is expected, one of the two
   `expand_tilde_honors_ztlp_home_override` tests). No regressions.
2. `cargo check --target x86_64-pc-windows-gnu` — clean, only pre-existing
   warnings (http_injector.rs, quic_transport.rs, daemon.rs dead-code, cli
   unused import) — none new.
3. Cross-compiled release `ztlp.exe` (11,232,768 bytes,
   sha256 `d704c0835b52030bc7939ea50cd6a9728562267f4b99ecad85bd4ae64b2a8a65`)
   and `ztlp-winsvc.exe` (7,888,384 bytes,
   sha256 `76e6e8461fdacedfb45be44a431289fcd0271e8f04de61664b725cf8d2005e50`)
   with the exact `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER`/`_AR` command
   from the session-4 plan.
4. Deployed both to `10.170.3.207` (`C:\Users\trs\AppData\Local\ZTLP\`),
   SHA256-verified on the remote side (hashes matched exactly), backed up
   the prior binaries as `.bak-bugC-fix`.
5. **Bug B's TLS-cert-dir fix is CONFIRMED working live** — the
   `local TLS: enabled but no certs found in ...` log line now correctly
   reads `C:\ProgramData\ZTLP\.ztlp/certs`, not the user profile. This
   closes session 4's one open item on Bug B.
6. Confirmed the standby → full-daemon handover itself is unaffected by
   Bug C's fix: fresh clean-state enroll consistently produces
   `identity.json`/`config.toml`/`agent.toml`/CA all under
   `C:\ProgramData\ZTLP\.ztlp\` and enroll returns
   `{"ok":true,"data":{"tls_provisioned":true}}` every time, service or
   foreground.

## Bug D — real SCM service process crashes 0xc0000409 (STATUS_STACK_BUFFER_OVERRUN) shortly after handover, NOT reproducible in foreground

**This is a NEW bug, distinct from A/B/C.** Bug C's `dirs::home_dir()` fix
IS correct and IS in effect (see point 6 above and the TLS log line fix in
point 5) but is **not sufficient** — the real `ZtlpAgent` SCM service still
crashes.

### Symptom

Every real-service enroll test this session, after Bug C's fix was
deployed:
1. `sc.exe start ZtlpAgent` → `RUNNING`, standby mode confirmed.
2. Send `enroll` control command over TCP to `127.100.255.1:4433` →
   `{"ok":true,"data":{"output":"","tls_provisioned":true}}` — genuine
   success, full state written to ProgramData.
3. Within roughly 30 seconds to a few minutes (timing varied: one run
   crashed at ~T+180-240s, a later run crashed at ~T+30s — **not a fixed
   delay**, may depend on some later code path being hit, e.g. relay
   connect attempt, NRPT/DNS activity, or a periodic timer), `sc query`
   shows:
   ```
   STATE: STOPPED, WIN32_EXIT_CODE: 1067 (0x42b)
   ```
4. Windows Event Log → Application → Error, every single time, IDENTICAL
   signature:
   ```
   Faulting application name: ztlp-winsvc.exe, version: 0.0.0.0
   Exception code: 0xc0000409
   Fault offset: 0x00000000002c3596   (varies slightly by build timestamp,
                                        but same relative offset pattern
                                        across the two ztlp-winsvc.exe
                                        builds tested: 0x2c3886 pre-fix,
                                        0x2c3596 post Bug-C-fix build)
   ```
   `0xc0000409` = `STATUS_STACK_BUFFER_OVERRUN` — this is the compiler's
   `/GS` stack-cookie check firing (or a Rust panic-into-abort path being
   reported that way by WER), i.e. an actual crash inside `ztlp-winsvc.exe`
   itself, not a graceful `Err` return. Deterministic: same exception code,
   same relative fault offset, every single occurrence across many test
   runs this session.

### What does NOT reproduce it

A **foreground** run — `$env:ZTLP_HOME='C:\ProgramData\ZTLP'; ztlp.exe
agent start --foreground -v` — run directly over an SSH session kept alive
with `terminal(background=true)` (not through a short-lived `ssh ... "cmd"`
invocation, which was a red herring earlier this session: killing that kind
of SSH session does NOT reliably kill the remote child process, it becomes
an orphan that then squats on `127.100.255.1:4433` and causes spurious
"failed to bind" errors on the next attempt — always `Stop-Process` any
stray `ztlp.exe`/`ztlp-winsvc.exe` before a fresh test) — went through the
**exact same code path** (`run_agent_lifecycle`, standby → real enroll via
the same TCP `enroll` command → handover → full daemon), including the
Bug-B-fixed TLS cert-dir log line, and ran clean for **6+ minutes past
handover** with zero crash, zero abnormal log lines, multiple times.

This means Bug D is specific to something about the **real SCM service
process context** that a foreground CLI process run over SSH does not
share. Candidate causes, NOT yet investigated (next session should check
these in order):

1. **Thread stack size under the SCM's `service_dispatcher::start()`
   thread.** `ztlp-winsvc.rs`'s `service_main`/`run_service` run on
   whatever thread `windows_service`'s FFI dispatcher gives it — this is
   NOT necessarily the same 1MB default stack a normal `fn main()` gets.
   Some Windows service hosting APIs hand the service entry point a
   smaller stack. If any code path (async task, TLS/crypto operation,
   something in `run_agent_lifecycle` post-handover) has a large stack
   frame or deep non-tail recursion, this would manifest as EXACTLY a
   `0xc0000409` stack-buffer-overrun/stack-exhaustion crash under the
   service but never under a normal-stack foreground process. This is the
   single most likely candidate given the failure mode.
2. **The `service_control_handler::register` callback thread vs the
   `tokio::task::spawn_blocking(move || shutdown_rx.recv())` interaction**
   in `ztlp-winsvc.rs` — check whether anything in that shutdown-race path
   could double-free, double-drop, or otherwise corrupt the stack when the
   `tokio::select!` resolves via the lifecycle future completing normally
   after a full daemon start (as opposed to via the actual STOP signal).
3. **LocalSystem-specific behavior** in something `run_agent_lifecycle`
   does post-handover that differs by execution context even with
   `ZTLP_HOME` now correctly resolved (Bug C fixed the path resolution,
   but LocalSystem's actual OS-level permissions/quota/token differ from
   an interactive admin SSH session in other ways — e.g. named pipe or
   registry access failing in a way that corrupts state rather than
   erroring cleanly).
4. Get a WER minidump for real analysis instead of just the Application-log
   summary: `reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error
   Reporting\LocalDumps" /v DumpType /t REG_DWORD /d 2 /f` (full dump) plus
   a `DumpFolder` value, THEN reproduce the crash, THEN pull the `.dmp` and
   analyze with `windbg`/`cdb` (not available on this Linux dev box —
   would need to either get windbg onto the Windows box, or copy the dump
   back and analyze with a cross-platform minidump tool). This session
   tried the read-only `Get-ItemProperty` check for existing LocalDumps
   config and found none configured (command syntax needs `-Path`, not
   positional, on Windows PowerShell 5.1 — retry with
   `Get-ItemProperty -Path 'HKLM:\...'`).

### Box state left at end of session

`ZtlpAgent` service is currently **STOPPED** (1067) — this is expected
given Bug D is unresolved, not a new problem to fix blindly. No stray
`ztlp.exe`/`ztlp-winsvc.exe` processes left running (verified clean).
`C:\ProgramData\ZTLP\.ztlp` has the last enrolled identity from the final
test this session (device name `defcon-ai-computer-v7`) — safe to wipe for
the next test, same as always. Prior `.ztlp.bak-<timestamp>` backups
accumulated in `C:\ProgramData\ZTLP\` from each clean-state cycle this
session — harmless, can be cleaned up whenever convenient.

Deployed binaries on `C:\Users\trs\AppData\Local\ZTLP\` right now ARE the
ones built this session (containing Bug C's fix + confirmed Bug B TLS fix)
— do NOT re-deploy session 4's older binaries, this session's build is
strictly newer/better, it just doesn't clear the whole bar yet.

## Updated "NOT YET DONE" list — supersedes session 4's list

1. Root-cause Bug D using the candidate list above (thread-stack-size
   theory first — cheapest to test: try explicitly spawning
   `run_agent_lifecycle`'s work on a `std::thread::Builder::new()
   .stack_size(8*1024*1024)` thread with its own dedicated tokio runtime
   inside `ztlp-winsvc.rs`'s `run_service()`, instead of relying on
   whatever stack the SCM dispatcher thread has, then re-test).
2. Once Bug D has an actual fix: repeat the FULL steps 1-8 from session
   4's checklist (cargo test, cargo check windows target, cross-compile,
   redeploy w/ hash verify, clean state, fresh token+enroll, service stays
   RUNNING 60+s AND setup_status shows enrolled:true).
3. THEN re-check TLS cert-dir log line (already confirmed working, but
   worth a final sanity pass with the Bug D fix baked in — should be
   unaffected).
4. THEN re-check `token_shared_with_gui`/console-user ACL — this remained
   UNCHECKED all of session 5 too (blocked by Bug D crashing before it
   could be verified); still an open question whether it's a 4th bug or a
   headless-test artifact.
5. Commit Bug A + B + C + D together as one coherent story (get Steven's
   go-ahead before pushing, per standing rule).
6. Push, watch CI (must include fresh `windows-latest` pass).
7. Only then is D5 actually done — update
   `docs/handoffs/WINDOWS-SERVICE-PARITY-PHASE-D-PLAN-2026-09-21.md`.

## Merge status — unchanged

PR #112 still a draft. Do not merge until Bug D is fixed and verified live,
on top of everything session 4's merge-status section already required.

## Process-hygiene note for future sessions on this box

Never test with `ssh host "command"` (single-shot, short-lived) for a
process meant to run for minutes — killing that SSH invocation from this
side does NOT kill the remote process tree, it just detaches and orphans
it, which then squats on `127.100.255.1:4433` and produces a misleading
"failed to bind control socket" error on the NEXT test attempt. Use
`terminal(background=true)` so the session handle can be explicitly
`process(action='kill')`'d, or always defensively `Stop-Process -Force` on
any stray `ztlp*` process before starting a new foreground test.
