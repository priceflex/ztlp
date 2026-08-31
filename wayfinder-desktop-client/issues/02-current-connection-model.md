Type: research
Status: resolved
Blocked by:

## Question

What is the CURRENT state of the `ztlp-desktop` app's connection/tunnel/session handling —
and where specifically does a single bad connection crash (or take down) the app today?

(Surface facts: how `tunnel.rs` + `state.rs` + `ipc.rs` manage connections; is the tunnel
in-process (tokio tasks in the Tauri runtime) or a spawned `ztlp` child process? What
happens on a dropped relay / bad peer / a panic in the tunnel task — does it kill the app,
or just the task? What's the reconnect behavior today? What's the concurrency model — one
connection, or multiple concurrent tunnels/connections, and are they isolated per-connection
(multi-threaded)? Cite `desktop/src-tauri/src/*.rs` file:line + `desktop/PROGRESS.md`.)

## Why this ticket first

Steven's #1 requirement is "a single connection can't crash the app" (multi-threaded). That
only makes sense against the CURRENT crash model — we need to know whether the tunnel is
in-process (a panic/task-failure could take down the Tauri runtime) or out-of-process (a
spawned `ztlp` child whose death is contained). This unblocks the crash-isolation design
(#03) and the multi-threaded model (#04). Resolve by reading the actual Rust code, not by
assuming.

## Answer

(Resolved 2026-08-20. Full report: `research/current-connection-model.md`.)

**Key finding (reframes the whole effort): the tunnel is ALREADY out-of-process.** The
Tauri app is a **thin control-plane client** — it shells out to a spawned `ztlp` daemon
(`ztlp agent start/stop`, `tunnel.rs:2-48`) and talks to it over a loopback TCP control
socket (`127.100.255.1:4433`, `ipc.rs`). The QUIC/relay/data-plane work lives in the
**separate `ztlp` process**, so a dropped relay / bad peer / malformed packet **cannot
crash the Tauri app today** — the daemon absorbs it. No tokio/async/threads in the crate
at all; all commands are blocking `pub fn`s.

**So "make it stable so a single connection can't crash the app" is mostly ALREADY true at
the process boundary.** The remaining stability work is the SIX specific gaps below (this
is what #03/#04 actually must close):

1. **Stale UI state after a real disconnect** — `get_status` (`commands.rs:31-33`) returns
   the *locally cached* `state.status`, written only at `connect`/`disconnect`. If the
   daemon/relay drops, the UI keeps showing "Connected." Need a daemon-backed
   authoritative status (or an event stream) so a dead tunnel shows dead.
2. **No supervisor/self-heal** — nothing restarts a dead tunnel; a relay drop leaves the
   device disconnected with no app-side recovery. `ConnectionState::Reconnecting` exists
   but is never set (decorative). #04 needs a watchdog (Tauri-side or daemon-side) that
   detects the drop + restarts with per-connection backoff.
3. **`start_tunnel`/`stop_tunnel` block with NO timeout** (`tunnel.rs:21,39` `.output()`
   unbounded) — a hung `ztlp agent start` (relay unreachable, DNS stall) can wedge the
   UI-thread command indefinitely (unlike the socket path, which is bounded at 100/500 ms).
   Run the spawn on a bounded, non-UI-blocking path.
4. **Single-connection state + one global `Mutex` with `.lock().unwrap()`**
   (`state.rs:128`, `tray.rs:44,56,63,100`) — the **only real in-process panic path is a
   poisoned mutex** (if any thread ever panics while holding a lock). A multi-connection
   model needs a `HashMap<id, Session>` with per-session error/health boundaries, and
   `.lock().unwrap()` must become poison-tolerant (`unwrap_or_else`/recover) so one bad
   session can't panic the app.
5. **No daemon→app event stream** (request/response only, `PROGRESS.md:44-45`) — a bad
   connection is detected at ~2s poll granularity. #04 needs a daemon→app event stream for
   per-connection lifecycle (connect/drop/reconnect) so containment is reactive, not
   poll-based.
6. **Per-connection lifecycle states never set** (`Connecting`/`Reconnecting`/
   `Disconnecting` exist in the enum + tray but Rust never writes them) — #04 needs the
   backend to actually drive these from the daemon so the UI can show + bound a reconnect.

**Connection model:** single logical connection in app state (one `ConnectionStatus`),
though the *daemon* supports N service tunnels per zone (the UI reads the list). So
"multi-threaded / session manager" (#04) = move from 1 zone connection to N sessions, each
with its own state + crash/health boundary + lifecycle events.

**UNVERIFIED (→ #04):** whether the `ztlp` daemon itself has internal QUIC/relay
auto-reconnect (it lives outside the desktop tree); whether the frontend JS locally sets
the lifecycle states; the exact daemon control-socket lifecycle.
