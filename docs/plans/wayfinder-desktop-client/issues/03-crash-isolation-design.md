Type: grilling
Status: resolved
Blocked by:
- 02-current-connection-model

## Question

What's the crash-isolation design — how do we guarantee a single bad connection (dropped
relay, bad peer, a panic/bug in the tunnel) can NOT crash the whole app?

(Decide: is the tunnel handled by a **spawned `ztlp` child process** (a connection's death
is contained — the child exits, the app supervises + restarts it) vs. **in-process tokio
tasks** (need `catch_unwind`-style isolation + a supervisor that restarts a dead task)? What
is the crash boundary + the supervisor/restart policy? This is the core of "multi-threaded
so a single connection doesn't crash the app.")

## Why this ticket first

It's the direct answer to Steven's #1 requirement. Depends on #02 (the current crash model)
so the design is grounded in the real code, not a guess.

## Requirement from Steven (2026-08-20) — the crash-isolation unit MUST account for the ELEVATED daemon

Steven: "make sure the crash isolation is taken care of at the same time that the daemon
runs as admin to create those local ports (like 443)."

This is a hard design constraint on #03. The `ztlp` daemon binds **privileged local ports
(443, 8443, etc.) as admin/root** (via UAC on Windows / pkexec-sudo on macOS/Linux — see
`setup.rs` elevation path). So the crash-isolation design must handle the elevated daemon as
a FIRST-CLASS containment unit, not just an in-app process:

1. **The elevated daemon is the crash-isolation boundary.** A crash/kill of the elevated
   `ztlp` daemon must NOT take down the (non-elevated) Tauri app — the app detects the
   daemon death (control socket gone / spawn watchdog) and restarts it cleanly.
2. **Elevation + crash isolation are the SAME concern** (Steven's "at the same time"). The
   supervisor that restarts the daemon must re-acquire elevation (UAC/pkexec) on restart —
   so the design must cover "restart the elevated daemon" not just "restart a process."
3. **[OPEN — needs Steven] the exact split:** (a) the elevated daemon IS the single
   containment unit (simplest — make it stable + the app supervises/restarts it), OR (b) the
   privileged-port holder (admin, binds 443) is SEPARATE from the per-connection data path,
   so a bad *connection* can't crash the privileged daemon that holds the admin ports. This
   is the design decision #03 must resolve (see #02's finding that the tunnel is already
   out-of-process — so (b) = making the per-connection workers further isolated from the
   elevated port-holder).

This interacts with #02's gap #3 (unbounded spawn) and gap #4 (poisoned mutex) — the
supervisor + the elevated-daemon lifecycle must be designed together.

## Answer

(Grilling, 2026-08-20. Steven away during Q&A — this is a **PROVISIONAL design** (best
judgment, draft) for review. It incorporates Steven's confirmed requirement that crash
isolation + the elevated daemon are handled together. The (a)-vs-(b) split is the key open
decision, flagged below.)

**Design (draft, default = option (a) for the pilot):** the elevated `ztlp` daemon is the
**single crash-isolation unit**, supervised by the Tauri app.

**Crash boundary (3 layers):**
1. **Data plane (per-connection):** the `ztlp` daemon process. A bad relay/peer/packet is
   contained here (already the case per #02). For option (a), this is the same elevated
   daemon; for option (b), per-connection workers would be a further isolated subprocess.
2. **Elevated port-holder:** the daemon binds privileged local ports (443/8443) as
   admin/root (UAC/pkexec). **This is the unit that must be stable + supervised** (Steven's
   requirement). Its crash is a *process death*, not an app panic.
3. **Control plane (the Tauri app):** non-elevated, thin client. Must survive the daemon
   dying and restart it.

**The supervisor (the core of this ticket — closes #02 gaps #2, #3):**
- **Detect daemon death:** the app watches the daemon's control socket (the existing
  `127.100.255.1:4433` client) +/or a spawn watchdog. When the socket is gone / the spawn
  is unresponsive, the daemon is considered dead.
- **Restart with re-elevation:** on restart, the supervisor re-invokes `ztlp agent start`
  (or the elevated port-holder) **via the same elevation path (UAC/pkexec)** — so it
  re-acquires admin to rebind the privileged ports. This is "restart the *elevated* daemon,"
  not just a process restart.
- **Bounded, non-UI-blocking:** run the spawn on a dedicated thread/`spawn_blocking` with a
  **timeout** (fixes #02 gap #3 — the unbounded `.output()` that can wedge the UI thread).
  Never block the UI-thread command runner on a hung spawn.
- **Per-connection backoff:** on repeated daemon death, exponential backoff (don't spin
  restart-on-crash). A genuinely broken config backs off + surfaces a clear UI error.

**In-app hardening (closes #02 gap #4):**
- Replace `.lock().unwrap()` on the shared `std::sync::Mutex`es (tray.rs:44,56,63,100,
  state.rs) with **poison-tolerant** access (`lock().unwrap_or_else(|e| e.into_inner())` or
  a `parking_lot::Mutex` that recovers from poison) so a poisoned mutex **cannot panic the
  app**. The poisoned-mutex path is the ONLY real in-process crash vector — eliminating it
  means the Tauri app has no in-process panic path from a bad connection.
- (No `tokio`/async needed for this — the app stays blocking + a watchdog thread is fine.)

**[OPEN — the (a)-vs-(b) split, needs Steven + CMMC/SOC 2]:**
- **(a) [draft default for pilot]:** one elevated daemon = the containment unit. Simpler.
  A bad *connection* can't crash the app (it's in the daemon process), and the app
  supervises + restarts the (elevated) daemon. Risk: a bad connection that wedges/crashes
  the elevated daemon also drops the privileged ports (mitigated by the supervisor
  restarting it).
- **(b) [stronger]:** separate the privileged-port holder (admin, binds 443) from the
  per-connection data workers (each in its own subprocess), so a bad *connection* can't
  crash the elevated port-holder. More isolation, more moving parts. This is the "multi-
  threaded, one bad connection can't take down the rest" model taken furthest.
- **Draft decision:** start with **(a)** for the pilot (simple, meets "a single connection
  can't crash the app" since the connection is already out-of-process), and design the
  supervisor so upgrading to **(b)** (per-connection worker subprocesses under the
  elevated port-holder) is an incremental change, not a rewrite. Confirm at review.

**CMMC / SOC 2 interaction (per #01):** the elevated daemon + its restart path must be
audited (who/what re-acquires elevation, on what schedule, with what logging); the
supervisor's restart-on-death must not silently re-bind privileged ports without an audit
log entry. The supervisor's detection + restart + backoff are auditable events.

## Addendum — elevated-daemon restart: RESEARCH + DECISION (2026-08-20, implementation A)

**Key finding (from the `ztlp` daemon source, `proto/src/agent/dns_setup.rs`):** the daemon
**already ships a systemd unit** for Linux with the full OS-level supervision + elevation:
- `ExecStart={ztlp} agent start --foreground`, `Restart=always`, `RestartSec=5` — **systemd
  already restarts a crashed daemon** (and it runs with `AmbientCapabilities=CAP_NET_BIND_SERVICE`,
  so it binds privileged ports like 443 **without** full root).
- `WatchdogSec=60` — systemd kills + restarts a wedged daemon.
- macOS: a LaunchAgent plist with `KeepAlive=true` + `RunAtLoad` (launchd restarts it).

**So the "elevated daemon is the crash-isolation unit, and it must be supervised +
re-elevated on restart" requirement is ALREADY MET by the OS supervisor on the service
path.** The app's `supervisor` (committed `a15b507`) is therefore the **fallback / primary for
the non-service path**: it covers (a) Windows (no CAP_NET_BIND_SERVICE; the daemon binds 443
as an elevated/admin process via the UAC `runas` path — `runas_ztlp` in `setup.rs`), (b) macOS
when not managed by launchd, and (c) the "app-spawned daemon" case where the daemon was
started by the app (`ztlp agent start` as the current user) rather than installed as a
service.

**DECISION (confirm at review): two-tier supervision.**
1. **Tier 1 — OS supervisor (primary, already exists):** `ztlp agent install` installs the
   systemd/LaunchAgent service (with `Restart=always` + `CAP_NET_BIND_SERVICE` / admin). On
   Linux/macOS-service, the OS handles crash-restart + re-elevation natively. **The app's
   supervisor detects (but does not itself re-launch) the daemon death on the service path** —
   it reflects the state and lets systemd/launchd do the restart. This avoids double-restart
   races (app + systemd both restarting).
2. **Tier 2 — app supervisor (fallback, `a15b507`):** when the daemon is NOT under an OS
   service (Windows, or app-spawned non-service), the app supervisor restarts it. On
   Windows this means re-running the elevated `runas` path (UAC) so it rebinds 443 as admin.

**The gap I'm closing (implementation A):** the app supervisor must **know whether the daemon
is under an OS service** so it doesn't double-restart on the service path, and — on the
non-service/Windows path — must **re-acquire elevation (UAC) on restart** so the restarted
daemon can rebind 443. Currently `supervisor.rs` restarts via `tunnel::start_tunnel` (current
user) — it doesn't detect the service or re-elevate. Fix:
- Add `daemon_is_under_service()` (detect `systemctl is-active` / `launchctl` / Windows
  service). If under a service → the app supervisor does NOT re-launch (Tier 1 owns it); it
  only reflects state + logs (CMMC/SOC 2 audit).
- If NOT under a service → the app supervisor restarts via the **elevated** path
  (`runas_ztlp`-equivalent), so it rebinds 443. (On Linux non-service, that's `sudo`/`pkexec`
  + `CAP_NET_BIND_SERVICE`; on Windows, UAC.)
- **Audit log (CMMC/SOC 2):** every restart (who/what, elevation, outcome) is logged.
