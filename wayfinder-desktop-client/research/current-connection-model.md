# ZTLP Desktop — Current Connection / Tunnel / Session Model

Wayfinder ticket #02 read-only investigation. All paths relative to
`/home/trs/ztlp/desktop/`. Every claim cites file:line.

## Executive summary (answers to the 5 key questions)

1. **In-process vs. child-process tunnel:** The tunnel is a **spawned `ztlp` child
   process (a daemon/agent)**. The Tauri app never opens the QUIC/relay connection
   itself — it shells out to `ztlp agent start` / `ztlp agent stop` and then talks to
   the already-running agent over a loopback TCP control socket (`127.100.255.1:4433`).
   - Tunnel work itself lives in the **separate `ztlp` binary process**, not the Tauri
     process. Evidence: `src-tauri/src/tunnel.rs:2` (`get_daemon_cmd` builds a
     `std::process::Command` for `ztlp`/`ztlp.exe`), `tunnel.rs:19-35`
     (`start_tunnel` runs `ztlp agent start` via `.output()`), `tunnel.rs:38-48`
     (`stop_tunnel` runs `ztlp agent stop`).
   - Status/traffic reads go to the daemon over its control socket: `tunnel.rs:84`
     (`ipc_request("status", ...)`) and `src-tauri/src/ipc.rs:84-86`
     (`ipc_request` → `ipc_request_with_addr("127.100.255.1:4433", ...)`).
   - It is NOT (a) in-process tokio tasks — there is **no tokio dependency at all**
     and **zero `async`/`tokio::spawn` in the crate** (see "Concurrency model"). It is
     (b) child-process for the tunnel; (c) partially — the *setup/CA/DNS/enroll* flows
     also shell out to `ztlp` (see setup.rs), and the *control/status* path is a plain
     TCP client in-process. So: **tunnel = child process; control-plane = in-process
     TCP client.**

2. **Single vs. multiple concurrent connections:** The **Tauri app state is
   single-connection** — one `ConnectionStatus` value, not a map of sessions.
   - `src-tauri/src/state.rs:127-133`: `AppState { status: Mutex<ConnectionStatus>, ... }`
     — a single `ConnectionStatus` (not `HashMap`/`Vec` of sessions).
   - `state.rs:25-31`: `ConnectionStatus` is one struct (state, relay, zone,
     connected_since). There is no collection of tunnels in app state.
   - Caveat: the *daemon* (the `ztlp` binary) can have **multiple tunnels/forwards**
     per zone-service — the `get_attached`/`get_services` commands read a *list* of
     tunnels from the daemon's `tunnels` control command (`commands.rs:55-84`,
     `commands.rs:172-226`). So "one logical zone connection in UI state, N service
     tunnels inside the daemon." But the UI's connection model is single.

3. **The crash path (dropped relay / bad peer / error):** Because the tunnel runs in a
   **separate process**, a dropped relay or a crashing/misbehaving peer does **NOT
   crash the Tauri app** — the daemon process absorbs it. The Tauri process only ever
   (a) spawns a short-lived child and (b) makes short read-only TCP polls to the
   daemon, all with timeouts. Failure surfaces as a Rust `Err(String)`, never a panic
   in the app:
   - `tunnel.rs:22-34`: `start_tunnel` returns `Err(...)` on nonzero exit or spawn
     failure — no `?`/panic.
   - `ipc.rs:37-38, 41-46, 58-60, 64-66, 72-73`: every socket op is `.map_err(...)?`
     into `Result<Value, String>`; connect timeout 100ms (`ipc.rs:20`), read/write
     timeout 500ms (`ipc.rs:25`), so a hung/half-open daemon can't hang the UI.
   - `commands.rs:16` (`connect` → `tunnel::start_tunnel(&relay,&zone)?`), `commands.rs:24`
     (`disconnect`), `commands.rs:284` (`get_traffic` → `tunnel::get_traffic()`): errors
     become `Err(String)` or a `eprintln!` (`tunnel.rs:110-111`), **never a panic that
     could take down the Tauri runtime**.
   - The ONLY `panic!`-capable spots in the app process are `Mutex::lock().unwrap()`
     and `main.rs:40` `.expect(...)` — see "Concurrency model" / "gaps". A poisoned
     mutex from a dropped thread could `panic` here.

4. **Reconnect / supervisor:** There is **NO supervisor in the Tauri app** that restarts
   a dead tunnel. The reconnect responsibility lives in the **daemon (`ztlp` binary)**,
   not the app:
   - `ConnectionState::Reconnecting` is an enum variant that exists in the UI model
     (`state.rs:21`) and is rendered in the tray (`tray.rs:122-127`), but **nothing in
     the Tauri crate ever sets it** and there is no loop/poller that restarts the agent.
   - The app has no reconnect/backoff loop. `PROGRESS.md:129-133` (UNCERTAIN section)
     states this explicitly: "if you want the app to actively keep a tunnel/forwarder
     open and self-heal on drop, that's a backend behavior change (auto-reconnect on the
     agent), not a UI one."
   - What IS present: the **frontend** auto-connects *once at launch* (JS-side,
     `app.js` — `PROGRESS.md:55-57, 73-75`) and polls `get_status` every ~2s
     (`ipc.rs:10` doc comment). That's a poll, not a supervisor.

5. **Concurrency model:** **All Tauri commands are synchronous (blocking) functions — no
   `async`, no tokio tasks, no threads spawned.** Tunnel ops are blocking `.output()`
   child-process calls run on whatever thread Tauri's IPC command runner uses.
   - `Cargo.toml:8-20`: dependency list has **no `tokio`** (only tauri, shell plugin,
     serde, chrono, ztlp-proto, dirs).
   - Zero `async` in the crate (grep `async|tauri::async|async fn` → 0 matches).
   - Commands are plain `pub fn` returning `Result<_, String>` or values
     (`commands.rs:15, 23, 31, 55, 89, 96, 142, 173, 231, 271, 282`).
   - **Per-connection isolation: NONE.** There is a single global `AppState` with
     `std::sync::Mutex`es (`state.rs:127-133`); every connection command mutates the same
     one `status` field. A "bad connection" today can only damage the *daemon* process or
     wedge the *UI thread* (via a blocked `.output()`), not isolate per-connection.

---

## Tunnel architecture (in-process vs. child-process)

**It is a spawned `ztlp` child process (daemon/agent). The Tauri app is a thin
control-plane client.** The app does not open or hold any QUIC/tunnel connection itself.

`get_daemon_cmd` (tunnel.rs:2-16): builds the `ztlp`/`ztlp.exe` command; on Windows sets
`CREATE_NO_WINDOW` (0x08000000) so the console doesn't flash.

**Actual code path from `connect` command → tunnel established:**

1. Frontend `invoke("connect", {relay, zone})` → Tauri dispatches to
   `commands::connect` (`commands.rs:14-20`).
2. `connect` calls `tunnel::start_tunnel(&relay, &zone)?` (`commands.rs:16`).
3. `start_tunnel` (tunnel.rs:19-35) builds the command and runs it **synchronously and
   to completion**: `get_daemon_cmd().args(["agent", "start"]).output()` (tunnel.rs:21).
   `.output()` blocks the calling thread until the `ztlp agent start` child exits.
4. If exit status is success → returns `ConnectionStatus { state: Connected, relay, zone,
   connected_since: Some(now) }` (tunnel.rs:23-28). The **actual tunnel/QUIC/relay
   work happens inside the `ztlp` process**, which the daemon keeps running after the
   `agent start` child exits (the daemon is the long-lived part; the app's `.output()`
   call returns as soon as the CLI subcommand finishes).
5. Back in `connect`, the returned `ConnectionStatus` is stored into
   `state.status` (commands.rs:17-18). **The app's `ConnectionStatus` is a *reflection*
   of the daemon's state, set once at start — it is not continuously tracked** (see gaps).

**Status/telemetry path (in-process TCP client to the daemon):**

- `get_status` (`commands.rs:31-33`) just reads the locally-cached `state.status`
  `Mutex` — it does NOT re-query the daemon. So after a relay drop the UI can keep
  showing "Connected" until the frontend re-invokes `connect`/`disconnect` or the
  frontend's JS poll drives a change. (UNVERIFIED whether frontend `get_status` poll is
  daemon-backed — from code, `get_status` is cache-only; the *daemon-backed* reads are
  `get_attached`/`get_services`/`get_traffic_stats`.)
- `get_traffic_stats` (`commands.rs:282-294`) → `tunnel::get_traffic()`
  (tunnel.rs:76-115) → `ipc::ipc_request("status", None)` (tunnel.rs:84) →
  `ipc_request_with_addr("127.100.255.1:4433", "status", None)` (ipc.rs:84-86).
- `get_attached` (`commands.rs:55-84`) and `get_services` (`commands.rs:172-226`) →
  `ipc_request("tunnels", None)`.

**Daemon control socket protocol** (ipc.rs): JSON line-delimited request/response.
`ControlCommand { cmd, name, token }` serialized + `\n` written (ipc.rs:48-56),
one `read_line` for a `ControlResponse { ok, error, data }` (ipc.rs:64-73). Auth token
loaded via `ztlp_proto::agent::config::load_agent_token()` (ipc.rs:51).

**Timeouts** (ipc.rs:18-25): connect 100 ms (`IPC_CONNECT_TIMEOUT`), read/write 500 ms
(`IPC_IO_TIMEOUT`) — explicitly to prevent a hung/half-open daemon from freezing the UI.

**Setup / CA / DNS / enroll** also run as `ztlp` child processes (setup.rs):
- `setup_run_ca_init` → `ztlp admin ca-init` non-elevated (setup.rs:99-117).
- `setup_install_ca` → Windows `ShellExecuteW("runas")` UAC (setup.rs:130-133,
  runas_ztlp setup.rs:322-373); Unix `pkexec`/`sudo` (setup.rs:154-170).
- `setup_install_dns` → `ztlp agent dns-setup` (setup.rs:190-236).
- `setup_test_browse` → `curl` child (setup.rs:260-312).
- `setup_status` → daemon `setup_status` over IPC (setup.rs:82-90).
- `enroll` → `ztlp setup --token <uri> --yes` (tunnel.rs:51-73, wired at
  commands.rs:96-97).
So the app is uniformly a "shell out to `ztlp` + poll the daemon" model. The elevation
path (UAC/pkexec) is a fire-and-forget elevated child; the app re-queries `setup_status`
afterwards (setup.rs:314-321 doc) rather than streaming.

---

## Connection model (single vs. multi, state structure)

- **Single logical connection in app state.** `AppState.status: Mutex<ConnectionStatus>`
  (state.rs:128) is a *single* value. `ConnectionStatus` (state.rs:25-31) holds
  exactly one `{state, relay, zone, connected_since}`. There is **no `HashMap`/`Vec`/map
  of sessions** anywhere in state.rs.
- `ConnectionState` enum (state.rs:16-23): `Disconnected, Connecting, Connected,
  Reconnecting, Disconnecting`. Only `Disconnected` (default), `Connected`
  (tunnel.rs:24), and the default-reset (`commands.rs:26`) are ever written by the Tauri
  crate. `Connecting`/`Reconnecting`/`Disconnecting` are defined + rendered in the tray
  (tray.rs:116-139) but **never actually set by the backend** — the backend jumps
  straight to `Connected` or resets to default. (So the "Reconnecting" UI state is
  decorative today — UNVERIFIED that no JS writes it; from Rust, nothing does.)
- **Daemon can have N service tunnels.** The `tunnels` control command returns a
  *list* (`commands.rs:58-70` iterates an array of tunnel objects with `target`/
  `local_port`/`protocol`/`active`). So the model is: **1 UI-facing zone connection →
  N daemon-side service tunnels/forwards.** Multi-*connection* at the zone level is not
  supported in app state; multi-*service-tunnel* is a daemon capability the UI reads.
- Identity is also single: `AppState.identity: Mutex<Option<IdentityInfo>>`
  (state.rs:129) — one device identity, one zone (`IdentityInfo.zone_name: Option<String>`,
  state.rs:52).
- Config is single: `AppState.config: Mutex<AppConfig>` (state.rs:132), one
  `relay_address` (state.rs:94), one `auto_connect` bool (state.rs:100).

---

## The crash path (dropped relay / bad peer / error)

**Bottom line: the tunnel is in a separate process, so a bad relay/peer cannot crash the
Tauri app today. It can only wedge a UI-thread `.output()`/socket call (mitigated by
timeouts) or leave stale UI state.**

Concrete error-handling for each failure mode:

- **`ztlp agent start` child fails** (bad relay, daemon won't start): `start_tunnel`
  returns `Err("Daemon failed to start: <stderr>")` (tunnel.rs:29-32) or
  `Err("Failed to execute command: ...")` (tunnel.rs:33). Propagated via `?` in
  `connect` (commands.rs:16) → returned to frontend as `Result<(), String>`. **No panic.**
- **Relay drops *after* connect (mid-session):** Nothing in the Tauri crate observes
  this. The daemon owns the QUIC connection and would end/drop it internally. The app
  only learns of it if the frontend's ~2s poll hits `get_attached`/`get_traffic_stats`
  and the daemon's control socket is gone → `ipc_request` returns `Err` (ipc.rs:37-38),
  handled gracefully: `get_attached` → `reachable:false, active:0` (commands.rs:78-82);
  `get_traffic` → `eprintln!` + zeroed stats (tunnel.rs:109-112). **No panic, no app
  crash.** The UI's cached `state.status` will still say `Connected` until someone
  calls `disconnect` (state is cache-only, see gap #1).
- **Bad/misbehaving peer data:** The peer's data flows through the **daemon** process,
  not the Tauri process. A malformed peer packet is a daemon problem. The app's in-process
  surface only ever *reads* a single JSON control line (ipc.rs:64-73) with `serde_json`
  `map_err` → `Err` (ipc.rs:72-73); a parse failure is a returned error, not a panic.
- **Hung/half-open daemon socket:** Bounded by the 100ms connect / 500ms read-write
  timeouts (ipc.rs:20, 25, applied at 37, 41-46); a regression test
  `test_ipc_request_unreachable_fails_fast` (ipc.rs:166-179) enforces < 500 ms. So a
  stuck daemon cannot indefinitely block the UI thread.
- **The only `panic!`-capable spots** (would take down the whole Tauri process):
  - `state.status.lock().unwrap()` / `.config.lock().unwrap()` in the **tray** handlers
    (tray.rs:44, 56, 63, 100) — a **poisoned `std::sync::Mutex`** (set if a thread ever
    panics while holding the lock) would `panic` here and kill the app. Today the
    backend holds these locks only briefly on the command/tray thread, so poisoning is
    unlikely, but it's the one real in-process crash vector.
  - `main.rs:40` `.expect("error while running ZTLP desktop application")` — panics if
    the Tauri runtime itself fails to run.
  - `state.rs:139, 151` `dirs::home_dir().unwrap_or_else(...)` — safe (has fallback).
  - `commands.rs:328` `lock().unwrap()` is test-only.
  - No `?`-on-`panic`, no `catch_unwind`, no scoped threads anywhere (grep: 0 matches
    for `catch_unwind|tokio::spawn|std::thread::spawn`).
- **`get_traffic` explicitly avoids panicking for "UI continuity"** (tunnel.rs:109-111:
  `// Log error but don't panic for UI continuity.` + `eprintln!`).

So: **error-returned everywhere; task-end / app-crash only via a mutex poisoning panic or
a Tauri-runtime failure — neither of which is on the tunnel/relay error path.**

---

## Reconnect / supervisor

**No supervisor exists in the Tauri app.** Reconnect is a *daemon* concern today.

- No restart/backoff loop anywhere in the crate (grep `reconnect|supervisor|retry` →
  only the enum variant + config field, no loop).
- `ConnectionState::Reconnecting` (state.rs:21) + tray rendering (tray.rs:122-127) are
  defined but **never set** by Rust code — decorative.
- **Frontend auto-connect is a one-shot launch behavior**, not a supervisor: `app.js`
  auto-connects on launch if enrolled + `auto_connect` (PROGRESS.md:55-57, 73-75), then
  a ~2s adaptive poll drives the status ring/log (PROGRESS.md:55; ipc.rs:10 doc). A
  dropped tunnel is *observed* via poll, not *healed* by the app.
- `PROGRESS.md:129-133` (UNCERTAIN) is the authoritative statement: self-heal/auto-
  reconnect "is a backend behavior change (auto-reconnect on the agent), not a UI one —
  flag before building."
- `Config.auto_connect` (state.rs:100, default `false` in Rust but the UI toggle defaults
  ON per PROGRESS.md:53-54) is read by the **frontend** to decide the one-shot launch
  connect; the Tauri `connect` command does not consult it.

---

## Concurrency model

- **No tokio. No async. No spawned threads.** All commands are plain blocking
  `pub fn`s returning `Result<_, String>` or values (commands.rs:15, 23, 31, 55, 89,
  96, 142, 173, 231, 271, 282). `Cargo.toml:8-20` has no `tokio` dependency.
- Tunnel start/stop are **blocking `.output()` child-process calls** on whatever thread
  Tauri's IPC command runner executes the command on (tunnel.rs:21, 39). A slow/hung
  `ztlp agent start` blocks that command thread until the child exits (no timeout on
  `.output()` in tunnel.rs — **gap**, unlike the IPC socket path which has 100/500 ms
  timeouts).
- State is shared via **global `std::sync::Mutex`es** in `AppState` (state.rs:127-133),
  held briefly by command/tray threads. This is the classic Tauri shared-state pattern.
- **Per-connection isolation: NONE.** One global state, one `status` field, one daemon.
  There is no per-connection task, thread, process, or error boundary. The *only*
  isolation today is process-level: the **tunnel lives in the `ztlp` daemon process**,
  so tunnel data-plane failures are naturally out-of-process. But control-plane (spawn +
  socket) and state are all in the single Tauri process with no further boundary.

---

## Where a single bad connection CAN'T (yet) be contained  (gaps #03/#04 must close)

1. **Stale UI state after a real disconnect (no daemon-backed `get_status`).**
   `get_status` (commands.rs:31-33) returns the *locally cached* `state.status`, which is
   only written at `connect` (commands.rs:17-18) and `disconnect` (commands.rs:25-26).
   If the daemon/relay drops, the UI keeps showing `Connected` (from cache) because
   nothing re-queries the daemon for the authoritative state. A bad/dropped connection
   is invisible to the UI until the next explicit connect/disconnect. #03 needs a
   daemon-backed, authoritative status (or an event stream) so a dead tunnel is shown
   dead.
2. **No self-heal / supervisor.** Nothing restarts a dead tunnel (see Reconnect section).
   A single bad relay drop leaves the device disconnected with no app-side recovery.
   #04 needs a supervisor (either in the daemon or a Tauri-side watchdog) that detects
   the drop and restarts, with per-connection backoff, so one bad connection is contained
   and retried without wedging the app.
3. **`start_tunnel`/`stop_tunnel` block with no timeout.** `tunnel.rs:21/39` use
   `.output()` with no timeout — a hung `ztlp agent start` (e.g. relay unreachable,
   DNS stall) blocks the invoking Tauri command thread indefinitely, unlike the IPC
   socket path which is bounded at 100/500 ms (ipc.rs:20, 25). A wedged spawn can freeze
   the Connect button / tray. #03/#04 should run the daemon spawn on a bounded,
   non-UI-blocking path (spawn child + poll, or `spawn_blocking`/dedicated thread with a
   timeout).
4. **Single-connection state can't express N zones/sessions, and is a single global
   `Mutex`.** `AppState.status` (state.rs:128) is one value; a multi-connection model
   needs a per-session map. More importantly for crash-containment: all connection
   mutations funnel through one shared `Mutex` with `.lock().unwrap()` in the tray
   (tray.rs:44,56,63,100). A **poisoned mutex is the only real in-process panic path**
   that could take down the whole Tauri app (tray.rs). #03/#04 should (a) isolate
   per-connection state (a `HashMap<id, Session>` with its own error/health boundary) and
   (b) avoid `.lock().unwrap()` (use `lock().unwrap_or_else` / recover from poison) so
   one bad session can't panic the app.
5. **No event stream from the daemon.** "daemon IPC is request/response today — no
   event stream" (PROGRESS.md:44-45). The UI can only *poll* (`get_attached`/
   `get_traffic_stats`), so a bad connection is detected at poll granularity with
   latency, and there's no channel to push per-connection health/error events. #04
   needs a daemon→app event stream for per-connection lifecycle (connect/drop/reconnect)
   so containment is reactive, not poll-based.
6. **`Reconnecting`/`Connecting`/`Disconnecting` states are never set.** The backend
   only writes `Connected`/default (tunnel.rs:24; commands.rs:26). Per-connection
   lifecycle is opaque to the UI. #04 needs the backend to actually drive these
   transitions (from the daemon) so the UI can show and bound a reconnect.

---

## Evidence notes (file:line)

| Claim | Evidence |
|---|---|
| Tunnel = `ztlp` child process, not in-process | tunnel.rs:2-16 (`get_daemon_cmd`); tunnel.rs:19-35 (`start_tunnel` runs `ztlp agent start` via `.output()`); tunnel.rs:38-48 (`stop_tunnel`) |
| No tokio/async/tasks/threads in crate | Cargo.toml:8-20 (no tokio dep); grep `catch_unwind\|tokio::spawn\|std::thread::spawn` → 0; grep `async\|async fn` → 0 |
| Control plane = in-process TCP client to daemon | ipc.rs:27-86 (`ipc_request_with_addr`/`ipc_request`); ipc.rs:84-86 (addr `127.100.255.1:4433`); tunnel.rs:84 (`ipc_request("status")`) |
| IPC is JSON line req/resp, request/response (no stream) | ipc.rs:48-73 (write req line, one `read_line` resp); PROGRESS.md:44-45 ("request/response today — no event stream") |
| Timeouts bound the socket path (100ms conn / 500ms io) | ipc.rs:18-25, 37-46; regression test ipc.rs:166-179 |
| Single-connection app state | state.rs:127-133 (`status: Mutex<ConnectionStatus>`); state.rs:25-31 (one struct); state.rs:129 (single `Option<IdentityInfo>`); state.rs:132 (single `AppConfig`) |
| Daemon has N service tunnels (UI reads a list) | commands.rs:55-84 (`get_attached` iterates array); commands.rs:172-226 (`get_services` iterates `tunnels` array) |
| `connect` → start_tunnel → cache state | commands.rs:14-20; commands.rs:16; tunnel.rs:19-35 |
| `get_status` is cache-only (no daemon re-query) | commands.rs:31-33 (reads `state.status` only) |
| Crash path = Err, not panic, for relay/peer/daemon errors | tunnel.rs:22-34 (Err on fail); tunnel.rs:109-111 (`eprintln!`, "don't panic"); ipc.rs:37-38/41-46/58-60/64-66/72-73 (`.map_err(...)?`); commands.rs:16/24/284 |
| Only in-process panic vectors = mutex poison + main expect | tray.rs:44,56,63,100 (`.lock().unwrap()`); main.rs:40 (`.expect`); grep for `catch_unwind`/scoped-thread → 0 |
| No supervisor/restart in app | grep `reconnect\|supervisor\|retry` → enum variant (state.rs:21) + config field only; PROGRESS.md:129-133 (self-heal is a backend change); tray.rs:122-127 (renders `Reconnecting` but nothing sets it) |
| `Reconnecting`/`Connecting`/`Disconnecting` never set by Rust | state.rs:16-23 (enum); tunnel.rs:24 (sets `Connected`); commands.rs:26 (resets to default); tray.rs:116-139 (renders them) |
| Setup/enroll = `ztlp` child processes; elevation via UAC/pkexec | setup.rs:59-72 (`ztlp_cmd`); setup.rs:99-117 (ca-init); setup.rs:130-133 + 322-373 (Windows `runas`); setup.rs:154-170 & 215-223 (pkexec/sudo); tunnel.rs:51-73 (enroll `ztlp setup`) |
| `start_tunnel`/`stop_tunnel` block with no timeout | tunnel.rs:21, 39 (`.output()` with no timeout) |
| Frontend auto-connect is one-shot launch, ~2s poll | PROGRESS.md:55-57, 73-75 (app.js launch connect + poll); ipc.rs:10 (2s poll doc) |
| WebView2 inline-handler pitfall (known stability note) | PROGRESS.md:52 (setup.js addEventListener-only wiring "WebView2 inline-handler pitfall"); Cargo.toml:10-13 (PR #89 WebView2 inline-handler bug, devtools feature) |
| Headless test status | PROGRESS.md:62-64, 85-88 (48/48 jsdom PASS); PROGRESS.md:110-120 (PENDING: real `cargo tauri build` + run not done on this box; no rustup/webkit) |

### Items marked UNVERIFIED (not confirmable from read-only code in this scope)
- Whether the **frontend JS** ever sets `Connecting`/`Reconnecting`/`Disconnecting` in a
  local UI state separate from `get_status` (the Rust backend never sets them; I did not
  re-read `app.js` line-by-line in this bounded pass — the PROGRESS.md summary says
  `get_status`/poll drives the ring, and `get_status` is Rust cache-only).
- Whether `ztlp agent start` (the daemon) itself has an internal auto-reconnect/backoff
  for the QUIC/relay connection — that logic lives in the `ztlp` binary (outside the
  `desktop/` tree and outside this read-only desktop-app scope). The desktop app does not
  implement it; whether the daemon does is UNVERIFIED here and is exactly what #04 must
  confirm/own.
- Exact daemon control-socket lifecycle (does `agent start` daemonize a long-lived
  listener on `127.100.255.1:4433`, or is the listener a separate `ztlp` service?) —
  inferred from the fixed control address in ipc.rs:85 and the "agent not running"
  framing in ipc.rs:10-14, but not confirmed against the daemon source in this scope.
