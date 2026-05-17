# ZTLP Windows Desktop — Production Readiness Plan

> **For Hermes:** Use `subagent-driven-development` skill to implement this plan task-by-task.

**Goal:** Turn the prototype Tauri desktop app into a production-ready client using the `ztlp-proto` daemon CLI for networking.
**Architecture:** The desktop frontend becomes a graphical interface over the ZTLP agent. It will use a new JSON IPC interface (TCP port `127.100.255.1:4433`) for querying agent state, and `Command` spawning (`ztlp.exe agent ...`) for daemon lifecycle controls.

## Phase A: Agent TCP IPC (Cross-Platform Daemon RPC)

The existing `agent.sock` is Unix-only. We will build a platform-agnostic TCP loopback handler that speaks the same protocol.

### Task A1: `agent.toml` config IPC option
**Objective:** Add an IPC address configuration field.
**Files:**
- Modify: `proto/src/agent/config.rs`
- Add `ipc_address: Option<String>` to `TunnelConfig` or root `AgentConfig`.
- Default: `Some("127.100.255.1:4433".to_string())` (or whatever non-conflicting loopback port is sensible).

### Task A2: IPC Server Refactor in `agent/control.rs`
**Objective:** Replace Unix-only constraints with platform-agnostic TCP streaming.
**Files:**
- Modify: `proto/src/agent/control.rs`
- Remove all `#[cfg(unix)]` wrappers around JSON commands.
- Modify `run_control_socket(&Path)` to `run_control_server(ipc_addr: &str)`. 
- Bind a `tokio::net::TcpListener` instead of `UnixListener`.

### Task A3: IPC Client Refactor
**Objective:** Refactor CLI functions connecting to the agent to use TCP instead of UDS.
**Files:**
- Modify: `proto/src/agent/control.rs`
- Modify `send_command(socket_path: &Path, ...)` -> `send_command(ipc_addr: &str, ...)`.
- Update `proto/src/bin/ztlp-cli.rs` (agent subcommands) to pass the new TCP loopback string.


## Phase B: Real Backend Handlers in Tauri

Now the daemon is cross-platform controllable via TCP. Bring the Tauri backend to life.

### Task B1: Remove Backend Mocks
**Objective:** Delete the static mocks from Tauri `state.rs` and `tunnel.rs`.
**Files:**
- Modify `desktop/src-tauri/src/state.rs`: Remove `mock_identity` and `mock_services` generated in `AppState::default()`. Start empty.
- Modify `desktop/src-tauri/src/tunnel.rs`: Delete `TrafficStats` hardcoded increments.

### Task B2: Identity Loader
**Objective:** Parse REAL identity data to feed the UI.
**Files:**
- Modify: `desktop/src-tauri/src/commands.rs` -> function `get_identity()`.
- Implementation: When requested, do `std::fs::read_to_string` on `~/.ztlp/identity.json` or call the `ztlp_proto::identity::Identity` parsing functions. Map to `IdentityInfo`.

### Task B3: Command Runner (`ztlp.exe` Spawning)
**Objective:** Tauri commands should control the daemon by shelling out.
**Files:** 
- Modify: `desktop/src-tauri/src/tunnel.rs`
- Add `start_tunnel`: Executes `ztlp agent start`.
- Add `stop_tunnel`: Executes `ztlp agent stop`.
- Add `process_enrollment`: Executes `ztlp setup --token <URI> --yes`.

### Task B4: IPC State Poller
**Objective:** Fetch real connection/traffic stats.
**Files:**
- Create `desktop/src-tauri/src/ipc.rs`.
- Implement a simple TCP client connecting to `127.100.255.1:4433` and parsing json lines natively.
- Modify: `get_status` and `get_services` in `commands.rs` to call `ipc::request("status")` and `"tunnels"`.


## Phase C: Desktop GUI Wiring

### Task C1: Error Handling & Empty States
**Objective:** Prevent blank screens. Show "No Identity Found" prompt.
**Files:**
- Modify `desktop/src/components/home.js`
- React to connection errors (e.g. Daemon stopped -> Update status text).

### Task C2: Config Persistence (Bonus)
**Objective:** Connect GUI settings to TOML.
**Files:**
- Modify `desktop/src-tauri/src/commands.rs`
- Implement `save_config`: Serialize `AppConfig` fields into `~/.ztlp/agent.toml` format and write to disk.

## Phase D: Final Packaging & QA
- Remove debug assertions from `tauri.conf.json`.
- Provide Windows build commands (`cargo tauri build --target x86_64-pc-windows-msvc`).
