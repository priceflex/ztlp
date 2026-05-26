# ZTLP Desktop — Windows Service + DNS Interception + Single-User Lock Implementation Plan

> **For Hermes:** Use `subagent-driven-development` skill to implement this plan task-by-task.

**Goal:** Ship a production Windows desktop experience where the ZTLP agent runs as a system service, the Tauri UI lives in the tray, a single OS user is bound to each device identity with idle-timeout + lock-screen safeguards, and any browser hit on `*.<zone>.ztlp` (e.g. `https://vault.techrockstars.ztlp`) "just works" with valid TLS — no command line.

**Architecture:** The Rust `proto/src/agent/` module tree already implements the daemon, DNS resolver, VIP pool, domain mapping, on-demand TCP proxy, and SNI-based local TLS termination (`local_tls.rs`). The `desktop/` Tauri app already has a tray, frontend pages (home/services/identity/enrollment/settings), and TCP IPC over `127.100.255.1:4433` to the daemon via `ControlCommand`/`ControlResponse`. This plan **wires the existing pieces together** and adds the missing seams:

1. **D1** — Lock down + harden the existing loopback API: per-install Bearer token, allow GETs from the UI, expand the command surface to cover all current Tauri commands. (We do **not** replace the existing TCP IPC — we add auth + an HTTP-shaped facade alongside it.)
2. **D2** — Windows service host (`ztlp-service.exe`) that runs `ztlp agent start --foreground` as `LocalSystem`, supervises crashes, installs/uninstalls via `sc.exe`. UI talks to it through D1's authenticated API.
3. **D3** — Single-user binding: capture the OS user SID during enrollment, refuse to start a tunnel for any other SID, attestation checkbox in the enrollment UI, configurable idle timeout, session-change handlers (logoff/lock/RDP switch).
4. **D4** — Windows DNS interception via **NRPT** (Name Resolution Policy Table): the service publishes a per-zone NRPT entry pointing `*.<zone>.ztlp` at the agent's DNS resolver at install time and tears it down on stop.
5. **D5** — Final UX wiring: install the ZTLP CA into Windows' machine trust store at first run; verify the browser → agent local-TLS → tunnel flow works end-to-end against the AWS testbed; smoke test `https://vault.techrockstars.ztlp`.

**Tech Stack:** Rust 1.77+ (proto, agent, service host), Tauri 2 (desktop UI shell), Windows Service API (`windows-service` crate), `sc.exe` / `certutil` / `PowerShell Set-DnsClientNrptRule` (admin actions), NSIS installer (existing CI workflow).

**Branch:** `feat/desktop-windows-service-and-dns-interception` (already created).

**Commit author:** `Steven Price <steve@techrockstars.com>`

**Commit shape:** `What/Why/Details/Tests/Validation/Follow-up` per Steve's house style.

---

## Background research already done

Verified state of the repo as of 2026-05-25 on this branch base:

| Area | Status |
|---|---|
| `proto/src/agent/daemon.rs` | ✅ Async tokio daemon, loads `~/.ztlp/agent.toml`, binds DNS + control TCP, runs main loop |
| `proto/src/agent/control.rs` | ✅ TCP loopback control plane at `127.100.255.1:4433`, JSON commands (`status`, `tunnels`, `dns_cache`, `flush_dns`, `shutdown`) |
| `proto/src/agent/dns.rs` | ✅ RFC1035-subset UDP resolver, ZTLP-NS lookup, VIP allocation, upstream forwarding |
| `proto/src/agent/local_tls.rs` | ✅ SNI-routed TLS termination — browser→agent TLS→ZTLP tunnel |
| `proto/src/agent/cert_install.rs` | ✅ Per-platform PKCS#12 client-cert install (Windows uses `certutil`) |
| `proto/src/agent/ca_trust.rs` | ✅ Per-platform CA install/uninstall (Windows uses `certutil -addstore`) |
| `proto/src/agent/dns_setup.rs` | ⚠️ Linux+macOS only (systemd-resolved / /etc/resolver). **Windows path missing — D4 adds NRPT.** |
| `proto/src/bin/ztlp-cli.rs` | ✅ `ztlp agent {start,stop,status,dns,flush-dns,tunnels,dns-setup,dns-teardown,install,pull-certs}` subcommands wired |
| `desktop/src-tauri/src/tray.rs` | ✅ System tray with show/connect/disconnect/open/quit |
| `desktop/src-tauri/src/ipc.rs` | ✅ TCP client for the control plane (unauthenticated) |
| `desktop/src-tauri/src/commands.rs` | ✅ Tauri IPC handlers for connect/disconnect/status/identity/enroll/services/config/traffic |
| Tests over `proto/src/agent/` | ❌ Almost none — D1+D3 must add them |
| Windows service host | ❌ Does not exist — D2 builds it |
| Single-user / idle-timeout / SID lock | ❌ Does not exist — D3 builds it |
| NRPT DNS install/uninstall | ❌ Does not exist — D4 builds it |

---

## Decisions baked into this plan (from 2026-05-25 chat)

- **A.** Windows service runs as `LocalSystem`, owns `ztlp.exe agent start --foreground`. Tauri UI is a separate user-session process that talks to it.
- **B.** UI ↔ service IPC is loopback HTTP with a per-install Bearer token, layered on top of the existing TCP JSON control plane (the token is required; the JSON envelope and port stay the same).
- **C.** DNS interception is NRPT for v1. Full WinTun comes later.
- **Idle timeout.** Default 15 minutes. Tear down tunnels on idle. **Do not** force `LockWorkStation` in v1 — Steve to revisit after watching real-world behavior.
- **Start with D1.** Each PR ships independently.

---

# D1 — Authenticated local agent API

**Goal:** Every request from the UI to the daemon carries a per-install Bearer token. Unauthenticated requests are rejected with `{"ok":false,"error":"unauthorized"}`. The existing JSON-on-TCP envelope stays unchanged; we add a `token` field on `ControlCommand` and verify it server-side.

**Why a token now:** Once D2 lands and the service runs as `LocalSystem`, any user-session process on the machine can connect to `127.100.255.1:4433`. The token scopes API access to the legitimate UI (which reads the token from a `0600`/`ACL`-restricted file written by the service).

**Files:**
- Modify: `proto/src/agent/control.rs` (token field on `ControlCommand`; `AgentState` carries an `Arc<String>` token; handler rejects mismatches)
- Modify: `proto/src/agent/daemon.rs` (generate token on first start, persist to `~/.ztlp/agent.token` with restrictive perms, load on subsequent starts)
- Modify: `proto/src/agent/config.rs` (add `token_path: Option<PathBuf>` config knob)
- Modify: `proto/src/bin/ztlp-cli.rs` (CLI commands that hit the control plane read the token file before sending)
- Modify: `desktop/src-tauri/src/ipc.rs` (read token from a known path, attach to every request)
- Create: `proto/tests/agent_control_auth_test.rs` (TDD)

---

### D1.T1 — RED: failing test for token field on ControlCommand

**Objective:** Prove that `ControlCommand` requires a `token` and that the daemon rejects mismatches.

**Files:**
- Create: `proto/tests/agent_control_auth_test.rs`

**Step 1: Write failing test**

```rust
//! Tests for the Bearer-token auth layer on the agent control plane.

use ztlp_proto::agent::control::{ControlCommand, ControlResponse};

#[test]
fn control_command_serializes_with_token() {
    let cmd = ControlCommand {
        cmd: "status".into(),
        name: None,
        token: Some("abc123".into()),
    };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(json.contains("\"token\":\"abc123\""), "token must be serialized");
}

#[test]
fn control_command_round_trips_with_no_token() {
    let cmd = ControlCommand {
        cmd: "status".into(),
        name: None,
        token: None,
    };
    let json = serde_json::to_string(&cmd).unwrap();
    let back: ControlCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cmd, "status");
    assert!(back.token.is_none());
}
```

**Step 2: Run test to verify failure**

Run: `cargo test -p ztlp-proto --test agent_control_auth_test -- --nocapture`
Expected: FAIL — `ControlCommand` has no field `token`.

**Step 3: Implement minimal field**

Edit `proto/src/agent/control.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlCommand {
    pub cmd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Bearer token; required when the daemon is running with a configured token path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}
```

**Step 4: Run test to verify pass**

Run: `cargo test -p ztlp-proto --test agent_control_auth_test -- --nocapture`
Expected: PASS (2 passed).

**Step 5: Commit**

```bash
git add proto/src/agent/control.rs proto/tests/agent_control_auth_test.rs
git commit -m "test(agent): add ControlCommand.token field + serde round-trip tests

What: Optional token field on the agent's TCP control envelope.
Why: D1 adds Bearer-token auth so the user-session UI can talk to the
     LocalSystem agent (D2) without exposing the loopback to every
     other process on the machine.
Details: Field is Option<String>, serde-skipped when None for
         backward compat with the current ControlResponse wire.
Tests: 2 new round-trip tests in agent_control_auth_test.rs.
Validation: cargo test -p ztlp-proto --test agent_control_auth_test.
Follow-up: D1.T2 wires the token check into AgentState."
```

---

### D1.T2 — Token gate in the handler

**Objective:** When `AgentState.expected_token` is `Some`, the handler rejects commands whose `token` does not match. When `None` (legacy mode), no check is performed.

**Files:**
- Modify: `proto/src/agent/control.rs` — add `expected_token: Option<Arc<String>>` to `AgentState`, branch in the per-line handler

**Step 1: Write failing test (append to `agent_control_auth_test.rs`)**

```rust
use std::sync::Arc;
use ztlp_proto::agent::control::{AgentState, handle_request_line};

#[tokio::test]
async fn rejects_missing_token_when_required() {
    let state = AgentState::test_with_token(Arc::new("secret".into()));
    let req = serde_json::to_string(&ControlCommand {
        cmd: "status".into(), name: None, token: None,
    }).unwrap();
    let resp_line = handle_request_line(&state, &req).await;
    let resp: ControlResponse = serde_json::from_str(&resp_line).unwrap();
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("unauthorized"));
}

#[tokio::test]
async fn rejects_wrong_token() {
    let state = AgentState::test_with_token(Arc::new("secret".into()));
    let req = serde_json::to_string(&ControlCommand {
        cmd: "status".into(), name: None, token: Some("nope".into()),
    }).unwrap();
    let resp_line = handle_request_line(&state, &req).await;
    let resp: ControlResponse = serde_json::from_str(&resp_line).unwrap();
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("unauthorized"));
}

#[tokio::test]
async fn accepts_matching_token() {
    let state = AgentState::test_with_token(Arc::new("secret".into()));
    let req = serde_json::to_string(&ControlCommand {
        cmd: "status".into(), name: None, token: Some("secret".into()),
    }).unwrap();
    let resp_line = handle_request_line(&state, &req).await;
    let resp: ControlResponse = serde_json::from_str(&resp_line).unwrap();
    assert!(resp.ok, "got {:?}", resp.error);
}

#[tokio::test]
async fn no_check_when_state_has_no_token() {
    let state = AgentState::test_without_token();
    let req = serde_json::to_string(&ControlCommand {
        cmd: "status".into(), name: None, token: None,
    }).unwrap();
    let resp_line = handle_request_line(&state, &req).await;
    let resp: ControlResponse = serde_json::from_str(&resp_line).unwrap();
    assert!(resp.ok);
}
```

**Step 2: Run to verify failure**

Run: `cargo test -p ztlp-proto --test agent_control_auth_test`
Expected: FAIL — `AgentState::test_with_token` not found, `handle_request_line` not exported.

**Step 3: Implement minimal code**

In `proto/src/agent/control.rs`:

```rust
pub struct AgentState {
    pub started_at: Instant,
    pub config_path: Option<PathBuf>,
    pub dns_state: Option<Arc<DnsResolverState>>,
    pub expected_token: Option<Arc<String>>,
    // ... existing fields ...
}

impl AgentState {
    #[cfg(test)]
    pub fn test_with_token(t: Arc<String>) -> Self {
        Self { expected_token: Some(t), started_at: Instant::now(), config_path: None, dns_state: None /* ...defaults */ }
    }
    #[cfg(test)]
    pub fn test_without_token() -> Self {
        Self { expected_token: None, started_at: Instant::now(), config_path: None, dns_state: None /* ...defaults */ }
    }
}

pub async fn handle_request_line(state: &AgentState, line: &str) -> String {
    let cmd: ControlCommand = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => return error_json(&format!("parse_error: {e}")),
    };
    if let Some(expected) = state.expected_token.as_deref() {
        let provided = cmd.token.as_deref().unwrap_or("");
        if !constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
            return error_json("unauthorized");
        }
    }
    dispatch(state, &cmd).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
    diff == 0
}
```

Note: refactor the existing accept-loop to call `handle_request_line` instead of inlining the JSON parse + dispatch. This keeps the test surface clean and changes no wire behavior when `expected_token` is `None`.

**Step 4: Run tests**

Run: `cargo test -p ztlp-proto --test agent_control_auth_test`
Expected: PASS (6 passed).

Also run: `cargo test -p ztlp-proto` (full lib+bin suite — must not regress).
Expected: all green.

**Step 5: Commit**

```bash
git add proto/src/agent/control.rs proto/tests/agent_control_auth_test.rs
git commit -m "feat(agent): gate control plane on Bearer token when configured

What: AgentState.expected_token; handle_request_line returns
      {ok:false,error:\"unauthorized\"} on missing/wrong token;
      constant-time comparison avoids timing leaks.
Why: D2's LocalSystem service will share 127.100.255.1:4433 across
     all user-session processes on the machine; Bearer-token gating
     is the boundary that keeps non-UI callers out.
Details: Token check is opt-in (None = legacy unauthenticated mode);
         existing CLI callers keep working until D1.T4 wires them up.
Tests: 4 new async tests covering missing / wrong / matching / no-check.
Validation: cargo test -p ztlp-proto (lib + binaries + 6 auth tests).
Follow-up: D1.T3 persists the token to ~/.ztlp/agent.token at daemon start."
```

---

### D1.T3 — Daemon writes + reads the token file

**Objective:** On `ztlp agent start`, generate a 32-byte random token (hex-encoded), write to `~/.ztlp/agent.token` with `0600` perms (Linux/macOS) or restricted ACL (Windows; permissive in this PR — D2 tightens the ACL when the service installs).

**Files:**
- Modify: `proto/src/agent/config.rs` — add `token_path()` resolver
- Modify: `proto/src/agent/daemon.rs` — generate-or-read token, attach to `AgentState`
- Create: `proto/tests/agent_token_file_test.rs`

**Step 1: Failing test**

```rust
use std::fs;
use tempfile::TempDir;
use ztlp_proto::agent::config::resolve_token_path;
use ztlp_proto::agent::daemon::ensure_token_file;

#[test]
fn ensure_token_creates_64_hex_chars() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    let token = ensure_token_file(&path).unwrap();
    assert_eq!(token.len(), 64, "32 raw bytes → 64 hex chars");
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    let on_disk = fs::read_to_string(&path).unwrap();
    assert_eq!(on_disk.trim(), token);
}

#[test]
fn ensure_token_returns_existing_value_on_second_call() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    let first = ensure_token_file(&path).unwrap();
    let second = ensure_token_file(&path).unwrap();
    assert_eq!(first, second);
}

#[cfg(unix)]
#[test]
fn ensure_token_writes_with_0600_perms() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("agent.token");
    ensure_token_file(&path).unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
```

**Step 2: Run, expect FAIL.**

**Step 3: Implement `ensure_token_file`** — `rand::thread_rng().fill_bytes(&mut [0u8; 32])` → `hex::encode` → write atomically (`tempfile + rename`) with chmod 0o600 on unix. On Windows: write normally; ACL hardening is D2.

**Step 4: Test green.**

**Step 5: Commit** (`feat(agent): persist control-plane token to ~/.ztlp/agent.token`).

---

### D1.T4 — Wire CLI + Tauri callers to read the token

**Objective:** Every call from the CLI (`cmd_agent_status` etc.) and from the Tauri UI (`ipc.rs::ipc_request`) reads `~/.ztlp/agent.token` and attaches it to the `ControlCommand`.

**Files:**
- Modify: `proto/src/bin/ztlp-cli.rs` — helper `load_agent_token() -> Option<String>` used by all `cmd_agent_*` functions
- Modify: `desktop/src-tauri/src/ipc.rs` — same lookup before each request
- Create: `proto/tests/agent_token_load_test.rs` — verifies the helper finds the right file and tolerates missing-file (returns `None`)

**Step 1: Write failing test for `load_agent_token`.**

**Step 2: Implement helper that resolves `~/.ztlp/agent.token` (or `$ZTLP_HOME/agent.token` override for tests) and returns `Option<String>`.**

**Step 3: Add token to every existing `ControlCommand { ... }` constructor in `ztlp-cli.rs`. Modify `ipc.rs::ipc_request_with_addr` to inject the token.**

**Step 4: Manual smoke test on Linux:**

```bash
cd ~/ztlp
cargo build -p ztlp-proto --bin ztlp
target/debug/ztlp agent start --foreground &
target/debug/ztlp agent status   # should succeed
echo "BAD" > ~/.ztlp/agent.token
target/debug/ztlp agent status   # should print "unauthorized"
target/debug/ztlp agent stop
```

**Step 5: Commit + open D1 PR.**

```bash
git push -u origin feat/desktop-windows-service-and-dns-interception
gh pr create --title "feat(D1): Bearer-token auth on agent loopback control plane" \
  --body "$(cat docs/plans/2026-05-25-desktop-windows-service-and-dns-interception.md | head -120)"
```

Wait for CI green. Merge with admin override if Performance/Interop dawdle.

Tag: not yet — we don't ship versions per slice; we'll tag once D2 lands and the service is installable.

---

# D2 — Windows service host

**Goal:** `ztlp-service.exe` installs as a Windows service, runs as `LocalSystem`, spawns `ztlp.exe agent start --foreground` as a child process, restarts it on crash with exponential backoff, and uninstalls cleanly. Tauri UI starts/stops the service via D1's API + admin-only "service install" wizard step at first run.

**Files:**
- Create: `service/Cargo.toml` (new workspace member)
- Create: `service/src/main.rs` (service entry + dispatcher)
- Create: `service/src/supervisor.rs` (child process supervision with backoff)
- Create: `service/src/install.rs` (sc.exe wrappers)
- Modify: `Cargo.toml` (workspace members += `service`)
- Modify: `.github/workflows/desktop-build.yml` (build + bundle service binary into NSIS installer)
- Create: `service/tests/supervisor_test.rs`

**Dependencies:**

```toml
[dependencies]
windows-service = "0.7"
windows = { version = "0.58", features = ["Win32_Foundation", "Win32_Security", "Win32_System_Services", "Win32_System_Threading"] }
tokio = { version = "1", features = ["rt-multi-thread", "process", "signal", "time", "sync"] }
tracing = "1"
tracing-subscriber = "0.3"
anyhow = "1"
```

### D2.T1 — Service install/uninstall CLI

**Objective:** `ztlp-service install` registers the service via `sc.exe create`. `ztlp-service uninstall` removes it. Both work on Linux as no-ops returning "unsupported on this platform" so cross-compile checks stay green.

**Files:**
- Create: `service/src/install.rs`
- Create: `service/tests/install_smoke_test.rs` (Linux: assert "unsupported"; Windows-gated test in `#[cfg(target_os = "windows")]`)

Steps follow standard TDD. Implementation calls `sc.exe create ZtlpAgent binPath= "C:\Program Files\ZTLP\ztlp-service.exe run" start= auto DisplayName= "ZTLP Agent"` then `sc.exe description ZtlpAgent "Zero Trust Layer Protocol background agent"`.

### D2.T2 — Service dispatcher entry point

**Objective:** `ztlp-service run` registers with the Windows SCM via `windows-service::service_dispatcher::start`. On Linux, this command exits with "unsupported."

### D2.T3 — Child-process supervisor

**Objective:** Service main loop spawns `ztlp.exe agent start --foreground --token-path "C:\ProgramData\ZTLP\agent.token"`, captures stdout/stderr to `C:\ProgramData\ZTLP\logs\agent.log`, and restarts the child on exit with exponential backoff (1s → 2s → 4s → … → cap 60s).

**Files:**
- Create: `service/src/supervisor.rs` (state machine: `Idle → Starting → Running → CrashCooldown → Starting → …`)
- Create: `service/tests/supervisor_test.rs` (cross-platform — use `sleep` / `false` as a stand-in for the agent binary)

TDD steps as above. The supervisor accepts a generic `ChildSpec { binary, args, log_path }` so the test can swap in `/bin/sh -c "exit 0"`.

### D2.T4 — Token-file ACL hardening on install

**Objective:** When the service installs, it creates `C:\ProgramData\ZTLP\agent.token` owned by `LocalSystem` with ACL granting read access to `Administrators` + the currently-logged-on user (whichever user ran the installer). This is what lets the Tauri UI (running in the user session) read the token to talk to the LocalSystem-owned daemon.

**Files:** `service/src/install.rs` — uses `windows-acl` crate or shells out to `icacls`.

### D2.T5 — End-to-end manual smoke on a Windows box

**Objective:** From Steve's Windows box (`trs@10.170.3.111`):

1. Build the NSIS installer in CI on a v0.30.13+ tag (the workflow already produces this).
2. Install on the Windows box.
3. Verify `sc.exe query ZtlpAgent` shows `RUNNING`.
4. Verify `ztlp agent status` (run from the user session) succeeds.
5. Kill the agent child PID; verify the supervisor restarts it within 5 seconds.
6. Uninstall and verify clean removal.

**Commit + PR.** Title: `feat(D2): Windows service host with crash-supervision for the ZTLP agent`.

---

# D3 — Single-user lock + idle timeout

**Goal:** A device identity is bound to exactly one OS user (by SID). The service refuses to spawn tunnels for any other session. An idle-timeout (default 15 min, configurable) tears down all active tunnels but does not force-lock the workstation (per Steve's call). Session-change events (RDP switch, fast-user-switch, logoff, lock) tear down immediately.

**Files:**
- Modify: `proto/src/identity.rs` (add `bound_user_sid: Option<String>` field to `NodeIdentity`)
- Modify: `proto/src/agent/config.rs` (`idle_timeout_seconds: u64`, default 900)
- Create: `proto/src/agent/session_lock.rs` (cross-platform: Windows uses `WTSRegisterSessionNotification`, Linux/macOS are no-ops)
- Modify: `proto/src/agent/daemon.rs` (idle tracker + session-change handlers)
- Modify: `desktop/src/components/enrollment.js` (attestation checkbox — "I attest I am the sole user of this device" — must be checked to submit)
- Modify: `desktop/src-tauri/src/commands.rs` (`enroll` captures current user SID via `whoami /user` shell-out)
- Create: `proto/tests/agent_session_lock_test.rs`

### D3.T1 — SID-bind on enrollment

**Objective:** `ztlp setup --token ... --bind-user` writes the current SID into `identity.json` under `bound_user_sid`. On daemon start, if `bound_user_sid` is set and does not match the current process's owning SID (Windows) or `getuid()` translated to a stable string (Linux/macOS), the daemon refuses to operate tunnels and logs `bound_user_mismatch`.

**Steps:** TDD — failing test for `verify_user_binding(identity, current_sid) -> Result<(), BindingError>`, then implementation, then integration into `daemon.rs::run`.

### D3.T2 — Idle timeout tracker

**Objective:** Daemon tracks last-traffic timestamp per tunnel. A periodic task (every 30s) closes any tunnel idle for longer than `idle_timeout_seconds`. On final-tunnel-close due to idle, the daemon logs a structured `idle_teardown` event.

### D3.T3 — Windows session change handler

**Objective:** When `WTS_SESSION_LOCK`, `WTS_SESSION_LOGOFF`, `WTS_CONSOLE_DISCONNECT`, or `WTS_REMOTE_DISCONNECT` fires, the agent closes all tunnels and clears the DNS cache. Cross-platform: Linux/macOS stub returns `Ok(())`.

### D3.T4 — Frontend attestation

**Objective:** The enrollment page's submit button is disabled until the user checks "I attest I am the only user of this device." Text is verbatim, no edits. Visible audit-trail: the attestation timestamp + SID are written to `~/.ztlp/attestation.json`.

**Commit + PR.** Title: `feat(D3): single-user identity binding, idle timeout, and session-change lockdown`.

---

# D4 — NRPT DNS interception (Windows)

**Goal:** When the service installs and is enrolled into a zone, it publishes a Name Resolution Policy Table rule that points `*.<zone>.ztlp` (and any `*.<custom-domain>` per `domain_map`) at the agent's resolver on `127.0.0.53:5353`. When the service uninstalls or unenrolls, the NRPT rule is removed cleanly.

**Files:**
- Create: `proto/src/agent/dns_setup_windows.rs` (analog to `dns_setup.rs` for Linux/macOS)
- Modify: `proto/src/agent/dns_setup.rs` to delegate to the Windows module on `target_os = "windows"`
- Create: `proto/tests/agent_dns_setup_windows_test.rs` (PowerShell-shell-out is mocked via a trait `NrptApi` with a fake impl)

### D4.T1 — NRPT abstraction

**Objective:** Define `trait NrptApi { fn add_rule(...); fn remove_rule(...); fn list_rules() -> Vec<NrptRule>; }`. Production impl shells out to `powershell -Command "Add-DnsClientNrptRule -Namespace .acme.ztlp -NameServers 127.0.0.53:5353"`. Test impl is an in-memory `HashMap<namespace, NrptRule>`.

### D4.T2 — Install + uninstall flow

**Objective:** `ztlp agent dns-setup` on Windows calls `NrptApi::add_rule` for every zone in `~/.ztlp/agent.toml::dns.zones` and every suffix in `dns.domain_map`. `ztlp agent dns-teardown` removes them by inspecting `list_rules()` and matching on a marker comment in the rule's `Comment` field (`"ZTLP-managed"`).

### D4.T3 — Idempotency guarantee

**Objective:** Calling `dns-setup` twice is a no-op the second time. Calling `dns-teardown` twice is harmless.

**Manual smoke test on the Windows box:**

```powershell
ztlp setup --token "ztlp://enroll/?..." --name $env:COMPUTERNAME -y
ztlp agent dns-setup
Get-DnsClientNrptRule | Where-Object Comment -Match "ZTLP-managed"
nslookup vault.techrockstars.ztlp   # should hit 127.0.0.53:5353
ztlp agent dns-teardown
```

**Commit + PR.** Title: `feat(D4): Windows NRPT-based DNS interception for ZTLP zones`.

---

# D5 — End-to-end "vault.techrockstars.ztlp just works"

**Goal:** From a Windows box with the service installed and enrolled, opening `https://vault.techrockstars.ztlp` in Chrome/Edge/Firefox should:

1. Resolve via NRPT → agent resolver (D4 ✓)
2. Agent returns a VIP from the pool (existing ✓)
3. Browser TCP-connects to the VIP → agent's local TLS terminator
4. Agent presents a cert for `vault.techrockstars.ztlp` signed by the ZTLP internal CA (existing — needs CA installed at machine scope by D5)
5. Agent decrypts, opens a Noise_XX tunnel to the gateway, requests TCP forward to the vault service
6. Vault dashboard loads with a valid green-lock TLS (no warnings).

**Files:**
- Modify: `service/src/install.rs` — at install time, call `proto::agent::ca_trust::install_ca_machine()` to plant the ZTLP CA in Windows' machine trust store
- Modify: `proto/src/agent/ca_trust.rs` — confirm Windows machine-scope install (`-enterprise -f -store Root`) works under LocalSystem
- Modify: `proto/src/agent/local_tls.rs` — verify the SNI resolver correctly emits a cert for arbitrary `*.<zone>.ztlp` hostnames (might need on-demand cert minting if `~/.ztlp/certs/<hostname>.pem` doesn't exist)
- Create: `docs/runbooks/desktop-windows-e2e-smoke.md`

### D5.T1 — Machine-scope CA install

**Objective:** Service installer plants the ZTLP CA cert into `Cert:\LocalMachine\Root` so every browser running on the box trusts it without per-user configuration.

### D5.T2 — On-demand cert minting

**Objective:** When the agent's SNI resolver gets a ClientHello for `<host>.<zone>.ztlp` and no pre-provisioned cert exists, mint one on the fly signed by the local intermediate (the intermediate's private key lives in `C:\ProgramData\ZTLP\ca\intermediate.key`, written by the service installer).

### D5.T3 — Full E2E on the Windows box

**Objective:** Run the runbook end-to-end. Capture screenshots of the green-lock + page content + a brief screen recording for the PR. If anything is broken, fix forward.

**Commit + PR + tag.** Title: `feat(D5): end-to-end browser → ZTLP service auto-connect with valid TLS`. After this PR merges, tag `v0.31.0`.

---

## Out of scope (explicitly deferred)

- Full WinTun packet-level capture (covered by a future v0.32 RFC)
- Force `LockWorkStation` on idle (Steve will decide after watching D3 behavior)
- mTLS browser-side client cert auth (handled by D5's on-demand minting if needed; deep configuration deferred)
- macOS or Linux variants of D2/D4 (LocalSystem and NRPT are Windows-specific; macOS launchd + systemd unit are a separate plan)
- Multi-user-on-one-box support (forbidden by the single-user attestation in D3 — out of scope by design)

---

## Execution handoff

After this plan lands on the branch, dispatch a fresh `delegate_task` per D1.Tn task using the `subagent-driven-development` skill — TDD per task, spec-compliance review, code-quality review, only proceed when both green. PR per D-slice (D1, D2, D3, D4, D5), each independently mergeable.
