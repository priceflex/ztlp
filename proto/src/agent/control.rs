//! TCP Loopback IPC control interface for the ZTLP agent daemon.
//!
//! The agent exposes a TCP loopback socket (default: `127.100.255.1:4433`)
//! that the CLI uses to communicate with the running daemon. Commands and
//! responses are JSON-encoded, one per line.
//!
//! ## Protocol
//!
//! Client sends a JSON command, daemon responds with a JSON response:
//!
//! ```json
//! → {"cmd": "status"}
//! ← {"ok": true, "data": {"pid": 4821, "uptime": "3d 14h", ...}}
//!
//! → {"cmd": "tunnels"}
//! ← {"ok": true, "data": {"tunnels": [...]}}
//!
//! → {"cmd": "dns_cache"}
//! ← {"ok": true, "data": {"entries": [...]}}
//!
//! → {"cmd": "flush_dns"}
//! ← {"ok": true}
//!
//! → {"cmd": "shutdown"}
//! ← {"ok": true}
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::dns::DnsResolverState;

// ─── Command/Response types ─────────────────────────────────────────────────

/// A control command from the CLI.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ControlCommand {
    pub cmd: String,
    /// Optional name parameter (for connect/disconnect/enroll's device name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Bearer token authenticating this caller.
    ///
    /// `None` is permitted on the wire for backward compatibility with
    /// pre-D1 CLI binaries. The daemon decides whether to require a
    /// token based on whether `AgentState::expected_token` is set
    /// (configured via `~/.ztlp/agent.token` — D1.T3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Task 6a: `ztlp://enroll/...` URI (or raw base64url token), used only
    /// by the `"enroll"` command. NOT the bearer auth token above — kept as
    /// a separate field to avoid any ambiguity between "who is calling us"
    /// and "what enrollment token should the daemon consume".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_uri: Option<String>,
    /// Task 6a / plan §4a option A-or-B: optional relay CLIENT_ROUTE HMAC
    /// secret to write into the daemon's own `agent.toml [tunnel]
    /// relay_secret`, used only by the `"enroll"` command. Mirrors
    /// `ztlp setup --relay-secret`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_secret: Option<String>,
}

/// A control response to the CLI.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ControlResponse {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }

    pub fn ok_empty() -> Self {
        Self {
            ok: true,
            error: None,
            data: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

/// Status info returned by the status command.
#[derive(Debug, Serialize)]
pub struct StatusInfo {
    pub pid: u32,
    pub uptime_secs: u64,
    pub version: String,
    pub dns_listen: String,
    pub vip_allocated: usize,
    pub vip_capacity: u32,
    pub ns_server: String,
    pub domain_mappings: usize,
}

/// Setup wizard status — what the UI shows on the Setup page.
///
/// Each field is `true` when that step is complete and `false` otherwise.
/// The UI uses this snapshot to render checkmarks and to know which
/// button to enable next. We DO NOT report partial states (e.g. "CA
/// half-installed"); the wizard treats each step as a discrete success
/// the moment its persistence artifact exists on disk / in the trust
/// store.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetupStatus {
    /// `~/.ztlp/identity.json` exists and contains a NodeID.
    pub identity_present: bool,
    /// `~/.ztlp/identity.json` shows a non-empty zone (enrollment succeeded).
    pub identity_enrolled: bool,
    /// `~/.ztlp/ca/root.pem` and `intermediate.pem` are real X.509 certs.
    pub ca_initialized: bool,
    /// On Windows, the root CA thumbprint is in `LocalMachine\Root`.
    /// On macOS/Linux, checks the system trust store (Keychain /
    /// /usr/local/share/ca-certificates). `None` only on unsupported OSes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_installed_system_trust: Option<bool>,
    /// On Windows, NRPT rule is present for the device's zone.
    /// On macOS/Linux, checks the active DNS backend's ZTLP config
    /// (systemd-resolved drop-in / resolv.conf / /etc/resolver).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_configured: Option<bool>,
    /// The agent daemon is running and reachable (we are the daemon, so
    /// this is always `true` when this struct is returned — it lets the UI
    /// distinguish "daemon down" (IPC timeout) from "daemon up but step
    /// incomplete").
    pub daemon_running: bool,
    /// The detected zone the wizard will operate on. Empty until enrolled.
    pub zone: String,
    /// Filesystem paths the UI surfaces in tooltips. Always present so the
    /// JS doesn't have to guess them.
    pub ca_root_pem_path: String,
    pub identity_path: String,
}

/// DNS cache entry for reporting.
#[derive(Debug, Serialize)]
pub struct DnsCacheEntry {
    pub name: String,
    pub ip: String,
    pub peer_addr: Option<String>,
    pub active_connections: u32,
    pub age_secs: u64,
}

// ─── Control socket server ──────────────────────────────────────────────────

/// Agent state shared between the control socket and other components.
pub struct AgentState {
    pub dns_state: Arc<Mutex<DnsResolverState>>,
    pub tunnel_pool: Arc<Mutex<super::tunnel_pool::TunnelPool>>,
    pub start_time: Instant,
    pub dns_listen: String,
    pub shutdown_tx: tokio::sync::broadcast::Sender<()>,
    /// Bearer token the daemon requires on every control command.
    ///
    /// When `Some(_)`, the daemon authenticates every incoming
    /// `ControlCommand` against this value (constant-time compare) and
    /// returns `{"ok":false,"error":"unauthorized"}` on mismatch. When
    /// `None`, no authentication is performed — preserved for backward
    /// compatibility with pre-D1 builds. D1.T3 wires the real value
    /// from `~/.ztlp/agent.token`.
    ///
    /// Held behind `Arc` because `AgentState` is shared across all the
    /// short-lived per-connection tasks the control socket spawns.
    pub expected_token: Option<Arc<String>>,
}

/// Constant-time byte-slice equality.
///
/// We compare both lengths and bytes without short-circuiting so the
/// runtime depends only on `max(a.len(), b.len())`, not on the position
/// of the first differing byte. This prevents a local attacker from
/// recovering the token one byte at a time via response-time timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Lengths are public (a is the configured token, b is the wire input —
    // the wire input length is observable via the JSON we just parsed). We
    // start the accumulator at 1 for any length mismatch so the function
    // returns `false` regardless of byte content; the byte loop still runs
    // up to the longer of the two so timing depends only on the longer
    // input. This avoids the narrow corner where a 256-byte all-zero token
    // would have compared equal to an empty token via a u8-truncated
    // (a.len() ^ b.len()) length term.
    let len = a.len().max(b.len());
    let mut diff: u8 = if a.len() == b.len() { 0 } else { 1 };
    for i in 0..len {
        let ai = *a.get(i).unwrap_or(&0);
        let bi = *b.get(i).unwrap_or(&0);
        diff |= ai ^ bi;
    }
    diff == 0
}

#[cfg(test)]
mod constant_time_eq_tests {
    use super::constant_time_eq;

    #[test]
    fn equal_inputs_return_true() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"a", b"a"));
        assert!(constant_time_eq(&[0u8; 256], &[0u8; 256]));
        assert!(constant_time_eq(b"deadbeefcafef00d", b"deadbeefcafef00d"));
    }

    #[test]
    fn different_inputs_return_false() {
        assert!(!constant_time_eq(b"a", b"b"));
        assert!(!constant_time_eq(b"deadbeef", b"DEADBEEF"));
    }

    #[test]
    fn length_mismatch_returns_false_even_when_bytes_align() {
        // Regression: an earlier version XOR-ed the lengths and truncated
        // to u8, so a 256-byte all-zero token compared equal to an empty
        // token because (0 ^ 256) as u8 == 0. The new length-mismatch
        // seed is 1 whenever the lengths differ, so this case correctly
        // returns false.
        assert!(!constant_time_eq(b"", &[0u8; 256]));
        assert!(!constant_time_eq(&[0u8; 256], b""));
        assert!(!constant_time_eq(b"secret", b"secret-extra"));
        assert!(!constant_time_eq(b"secret-extra", b"secret"));
    }

    #[test]
    fn empty_vs_empty_is_equal() {
        assert!(constant_time_eq(b"", b""));
    }
}

/// Run the control socket server.
///
/// Listens on the TCP loopback socket and handles commands from the CLI.
/// This is a long-running task that should be spawned as a tokio task.
pub async fn run_control_socket(
    ipc_addr: &str,
    state: Arc<AgentState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(ipc_addr)
        .await
        .map_err(|e| format!("failed to bind control socket {}: {}", ipc_addr, e))?;

    info!("control socket listening on {}", ipc_addr);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(result) => result,
            Err(e) => {
                warn!("control socket accept error: {}", e);
                continue;
            }
        };

        let state = state.clone();

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = BufReader::new(reader);
            let mut line = String::new();

            match buf_reader.read_line(&mut line).await {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) => {
                    debug!("control socket read error: {}", e);
                    return;
                }
            }

            let json = handle_request_line(&state, &line).await;
            let _ = writer.write_all(json.as_bytes()).await;
            let _ = writer.write_all(b"\n").await;
        });
    }
}

/// Parse one JSON request line, enforce the optional Bearer-token gate,
/// dispatch the command, and return the serialized response.
///
/// Extracted from the accept loop so it can be unit-tested without
/// standing up a TCP socket. Returns the response body (no trailing
/// newline) — the caller is responsible for framing.
///
/// ## Auth model
///
/// * If `state.expected_token` is `None`, no authentication is performed
///   (legacy/single-user mode — preserved for backward compatibility).
/// * If `state.expected_token` is `Some(expected)`, every command must
///   carry a `token` field whose bytes match `expected` under
///   [`constant_time_eq`]. On mismatch (including missing token), the
///   command is **not** dispatched and we return
///   `{"ok":false,"error":"unauthorized"}` verbatim.
///
/// Parse errors (malformed JSON) short-circuit *before* the auth check
/// and return a distinct `"invalid command: …"` error so that the
/// unauthorized path cannot be distinguished from a parse failure by an
/// attacker probing with garbage.
pub async fn handle_request_line(state: &AgentState, line: &str) -> String {
    let cmd: ControlCommand = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => {
            return serde_json::to_string(&ControlResponse::err(format!("invalid command: {}", e)))
                .unwrap_or_else(|_| r#"{"ok":false,"error":"invalid command"}"#.to_string());
        }
    };

    if let Some(expected) = state.expected_token.as_ref() {
        let provided = cmd.token.as_deref().unwrap_or("");
        if !constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
            return serde_json::to_string(&ControlResponse::err("unauthorized"))
                .unwrap_or_else(|_| r#"{"ok":false,"error":"unauthorized"}"#.to_string());
        }
    }

    let resp = handle_command(cmd, state).await;
    serde_json::to_string(&resp)
        .unwrap_or_else(|_| r#"{"ok":false,"error":"response serialization failed"}"#.to_string())
}

/// B4 (HANDOFF-2026-09-20): request handler for the UNENROLLED STANDBY
/// mode — the daemon has no identity.json yet, so there is no
/// `AgentState` (no VIP pool, no DNS, no tunnels). Only the bearer-token
/// gate and a tiny command surface exist:
///
/// * `status` / `setup_status` → `{ok:true, data:{standby:true,
///   enrolled:false, identity_enrolled:false, ...}}` so the GUI's
///   readiness checklist can show "Service: Running / Identity: Not
///   enrolled" instead of a connect timeout.
/// * `enroll` → the real [`cmd_enroll`] (re-exec `ztlp setup --token …`
///   under the daemon's own HOME). Once identity.json lands, the standby
///   loop in `daemon.rs` notices and hands over to the full daemon.
/// * `shutdown` → honoured (returns `Some(())` to the caller).
/// * anything else → a clear `not enrolled yet` error.
///
/// Returns `(response_json, shutdown_requested)`.
pub async fn handle_standby_request_line(
    expected_token: &str,
    line: &str,
) -> (String, bool) {
    let cmd: ControlCommand = match serde_json::from_str(line) {
        Ok(c) => c,
        Err(e) => {
            return (
                serde_json::to_string(&ControlResponse::err(format!("invalid command: {}", e)))
                    .unwrap_or_else(|_| r#"{"ok":false,"error":"invalid command"}"#.to_string()),
                false,
            );
        }
    };

    let provided = cmd.token.as_deref().unwrap_or("");
    if !constant_time_eq(expected_token.as_bytes(), provided.as_bytes()) {
        return (
            serde_json::to_string(&ControlResponse::err("unauthorized"))
                .unwrap_or_else(|_| r#"{"ok":false,"error":"unauthorized"}"#.to_string()),
            false,
        );
    }

    let (resp, shutdown) = match cmd.cmd.as_str() {
        "status" | "setup_status" => (
            ControlResponse::ok(serde_json::json!({
                "standby": true,
                "enrolled": false,
                "identity_enrolled": false,
                "daemon_running": true,
                "version": env!("CARGO_PKG_VERSION"),
                "pid": std::process::id(),
                "message": "service running, not enrolled yet — send \"enroll\"",
            })),
            false,
        ),
        "enroll" => (cmd_enroll(&cmd).await, false),
        "shutdown" => (ControlResponse::ok_empty(), true),
        other => (
            ControlResponse::err(format!(
                "not enrolled yet: \"{}\" is unavailable until the daemon has an identity (send \"enroll\")",
                other
            )),
            false,
        ),
    };
    (
        serde_json::to_string(&resp)
            .unwrap_or_else(|_| r#"{"ok":false,"error":"response serialization failed"}"#.to_string()),
        shutdown,
    )
}

/// Handle a control command.
async fn handle_command(cmd: ControlCommand, state: &AgentState) -> ControlResponse {
    match cmd.cmd.as_str() {
        "status" => cmd_status(state).await,
        "tunnels" => cmd_tunnels(state).await,
        "dns_cache" => cmd_dns_cache(state).await,
        "flush_dns" => cmd_flush_dns(state).await,
        "shutdown" => cmd_shutdown(state).await,
        "setup_status" => cmd_setup_status(state).await,
        "enroll" => cmd_enroll(&cmd).await,
        other => ControlResponse::err(format!("unknown command: {}", other)),
    }
}

async fn cmd_status(state: &AgentState) -> ControlResponse {
    let dns = state.dns_state.lock().await;
    let status = StatusInfo {
        pid: std::process::id(),
        uptime_secs: state.start_time.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        dns_listen: state.dns_listen.clone(),
        vip_allocated: dns.vip_pool.allocated_count(),
        vip_capacity: dns.vip_pool.capacity(),
        ns_server: dns.ns_server.clone(),
        domain_mappings: dns.domain_mapper.len(),
    };
    drop(dns);

    ControlResponse::ok(serde_json::to_value(status).unwrap_or_default())
}

async fn cmd_tunnels(state: &AgentState) -> ControlResponse {
    let pool = state.tunnel_pool.lock().await;
    let tunnels: Vec<serde_json::Value> = pool
        .tunnel_info()
        .into_iter()
        .map(|t| {
            let state_str = match &t.state {
                super::tunnel_pool::TunnelState::Connecting => "Connecting",
                super::tunnel_pool::TunnelState::Active => "Active",
                super::tunnel_pool::TunnelState::Reconnecting { .. } => "Reconnecting",
                super::tunnel_pool::TunnelState::Closed => "Closed",
            };
            serde_json::json!({
                "name": t.name,
                "peer_addr": t.peer_addr.to_string(),
                "state": state_str,
                "age_secs": t.age_secs,
                "idle_secs": t.idle_secs,
                "bytes_sent": t.bytes_sent,
                "bytes_recv": t.bytes_recv,
            })
        })
        .collect();
    drop(pool);

    ControlResponse::ok(serde_json::json!({
        "tunnels": tunnels,
        "active": tunnels.iter().filter(|t| t.get("state").and_then(|v| v.as_str()) == Some("Active")).count(),
        "total": tunnels.len(),
    }))
}

async fn cmd_dns_cache(state: &AgentState) -> ControlResponse {
    let dns = state.dns_state.lock().await;
    let entries: Vec<DnsCacheEntry> = dns
        .vip_pool
        .entries()
        .map(|e| DnsCacheEntry {
            name: e.ztlp_name.clone(),
            ip: e.ip.to_string(),
            peer_addr: e.peer_addr.map(|a| a.to_string()),
            active_connections: e.active_connections,
            age_secs: e.created_at.elapsed().as_secs(),
        })
        .collect();
    drop(dns);

    ControlResponse::ok(serde_json::json!({ "entries": entries }))
}

async fn cmd_flush_dns(state: &AgentState) -> ControlResponse {
    let mut dns = state.dns_state.lock().await;
    let freed = dns.vip_pool.gc_expired();
    drop(dns);

    ControlResponse::ok(serde_json::json!({ "freed": freed }))
}

async fn cmd_shutdown(state: &AgentState) -> ControlResponse {
    info!("shutdown requested via control socket");
    let _ = state.shutdown_tx.send(());
    ControlResponse::ok_empty()
}

// ─── Task 6a: daemon-owned enrollment ───────────────────────────────────────
//
// "Where the daemon's config dir should be AND how the enrollment written
// by the user-level GUI (`ztlp setup`) lands in the root-owned dir. Likely
// answer: the GUI sends the token to the daemon over the control API and
// the DAEMON runs the enrollment." — ZTLP-MAC-PLAN-2026-09-19.md §3
// UNCERTAIN. This is that answer: the daemon re-execs its OWN binary
// (`std::env::current_exe()`) through the exact same `ztlp setup --token
// ... --yes` path that session 2 already live-proved end-to-end (§5.7) —
// no enrollment logic is duplicated here, we just trigger the proven CLI
// path from inside the process that owns the root-level HOME (`/Library/
// Application Support/ZTLP` on macOS via the LaunchDaemon's
// EnvironmentVariables), so identity.json/config.toml/agent.toml land in
// the daemon's own directory instead of a human's ~/.ztlp.

/// Pure builder: what `cmd_enroll` will exec, given a parsed command.
///
/// Separated from the actual `tokio::process::Command` so the argument
/// construction (including the plan §4a relay-secret plumbing) is
/// unit-testable without spawning a real subprocess.
#[derive(Debug, PartialEq, Eq)]
pub struct EnrollExecPlan {
    pub args: Vec<String>,
}

/// Build the `ztlp setup ...` argv for a daemon-driven enroll request.
///
/// Returns `Err` with a user-facing message if the command is missing its
/// required `enrollment_uri` field — enroll can't proceed without one.
pub fn build_enroll_exec_plan(cmd: &ControlCommand) -> Result<EnrollExecPlan, String> {
    let uri = cmd
        .enrollment_uri
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "enroll requires \"enrollment_uri\"".to_string())?;

    let mut args = vec![
        "setup".to_string(),
        "--token".to_string(),
        uri.to_string(),
        "--yes".to_string(),
    ];

    if let Some(name) = cmd.name.as_deref().filter(|s| !s.trim().is_empty()) {
        args.push("--name".to_string());
        args.push(name.to_string());
    }

    if let Some(secret) = cmd.relay_secret.as_deref().filter(|s| !s.trim().is_empty()) {
        args.push("--relay-secret".to_string());
        args.push(secret.to_string());
    }

    Ok(EnrollExecPlan { args })
}

/// `"enroll"` control command: have the daemon enroll ITSELF (its own
/// identity, under its own HOME) by re-execing `ztlp setup --token ...
/// --yes` via its own already-running binary.
///
/// This intentionally does NOT touch `AgentState` — it shells out to a
/// fresh subprocess rather than reimplementing `setup_join()`'s logic
/// in-process, so the daemon always enrolls through the exact same code
/// path a human running `ztlp setup` from a terminal would use (already
/// live-proven, plan §5.7). The subprocess inherits the daemon's own
/// environment (including `HOME`), so `~/.ztlp` resolves to the daemon's
/// own config dir, not a human user's.
async fn cmd_enroll(cmd: &ControlCommand) -> ControlResponse {
    let plan = match build_enroll_exec_plan(cmd) {
        Ok(p) => p,
        Err(e) => return ControlResponse::err(e),
    };

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return ControlResponse::err(format!("cannot resolve own binary path: {}", e)),
    };

    info!(
        "enroll requested via control socket: {} (name={:?})",
        exe.display(),
        cmd.name
    );

    let output = tokio::process::Command::new(&exe)
        .args(&plan.args)
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            let mut stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            // B4(b): `ztlp setup` never runs ca-init, so a daemon enrolled
            // this way came up with TLS disabled (Safari cert warning).
            // Provision the local CA + system trust right here, in the same
            // root process that owns HOME. Best-effort: enrollment itself
            // already succeeded, so a TLS-provisioning failure is reported
            // in `tls_warning` rather than failing the whole command.
            let mut tls_warning: Option<String> = None;
            match dirs::home_dir() {
                Some(home) => match build_post_enroll_tls_plan(&home) {
                    Ok(steps) => {
                        for args in steps {
                            info!("post-enroll TLS provisioning: {} {}", exe.display(), args.join(" "));
                            match tokio::process::Command::new(&exe).args(&args).output().await {
                                Ok(o) if o.status.success() => {
                                    stdout.push_str(&String::from_utf8_lossy(&o.stdout));
                                }
                                Ok(o) => {
                                    let msg = format!(
                                        "{} failed (exit {}): {}",
                                        args.join(" "),
                                        o.status.code().unwrap_or(-1),
                                        String::from_utf8_lossy(&o.stderr).trim()
                                    );
                                    warn!("post-enroll TLS provisioning: {msg}");
                                    tls_warning = Some(msg);
                                    break;
                                }
                                Err(e) => {
                                    let msg = format!("failed to spawn {}: {e}", args.join(" "));
                                    warn!("post-enroll TLS provisioning: {msg}");
                                    tls_warning = Some(msg);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => tls_warning = Some(e),
                },
                None => tls_warning = Some("cannot resolve home directory".to_string()),
            }
            let mut data = serde_json::json!({ "output": stdout, "tls_provisioned": tls_warning.is_none() });
            if let Some(w) = tls_warning {
                data["tls_warning"] = serde_json::Value::String(w);
            }
            ControlResponse::ok(data)
        }
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            ControlResponse::err(format!(
                "enrollment failed (exit {}): {}",
                out.status.code().unwrap_or(-1),
                if stderr.trim().is_empty() {
                    stdout
                } else {
                    stderr
                }
            ))
        }
        Err(e) => ControlResponse::err(format!("failed to spawn ztlp setup: {}", e)),
    }
}

/// B4(b): the argv list (each a `ztlp` subcommand) the daemon runs right
/// after a successful daemon-side enrollment so HTTPS works without any
/// human `sudo`:
///
/// 1. `admin ca-init --zone <zone>` — only when `~/.ztlp/ca/root.key` does
///    not exist yet (ca-init refuses to overwrite an existing CA, so we skip
///    it rather than fail). ca-init also flips `[tls] enabled = true` in
///    agent.toml (see `enable_tls_in_agent_config` in the CLI).
/// 2. `agent install-ca-cert --cert ~/.ztlp/ca/root.pem` — trusts the root
///    in the System keychain / OS store. `--cert` is HOME-independent.
///
/// Pure (no I/O beyond `exists()` checks) so it is unit-testable; zone is
/// read from the config `ztlp setup` just wrote via [`read_zone_from_config`].
pub fn build_post_enroll_tls_plan(home: &std::path::Path) -> Result<Vec<Vec<String>>, String> {
    let zone = read_zone_from_config(home)
        .ok_or_else(|| "cannot determine zone from ~/.ztlp/config.toml after enrollment".to_string())?;
    let ca_dir = home.join(".ztlp").join("ca");
    let root_pem = ca_dir.join("root.pem");
    let mut steps = Vec::new();
    if !ca_dir.join("root.key").exists() {
        steps.push(vec![
            "admin".to_string(),
            "ca-init".to_string(),
            "--zone".to_string(),
            zone,
        ]);
    }
    steps.push(vec![
        "agent".to_string(),
        "install-ca-cert".to_string(),
        "--cert".to_string(),
        root_pem.to_string_lossy().into_owned(),
    ]);
    Ok(steps)
}

/// Read the enrolled zone name from whichever ZTLP config file exists on
/// disk, checking both known shapes.
///
/// - `~/.ztlp/config.toml` (written by `ztlp setup --token ...`, the exact
///   path the desktop app's own enroll flow uses): flat `zone = "..."` key.
/// - `~/.ztlp/agent.toml` (the older/manual agent-config shape): `zones =
///   [...]` under a `[dns]` section — the first entry is used.
///
/// Returns `None` if neither file exists or neither yields a zone.
fn read_zone_from_config(home: &std::path::Path) -> Option<String> {
    let ztlp_dir = home.join(".ztlp");

    if let Ok(text) = std::fs::read_to_string(ztlp_dir.join("config.toml")) {
        let flat_zone = text
            .lines()
            .find(|l| l.trim_start().starts_with("zone "))
            .or_else(|| text.lines().find(|l| l.trim_start().starts_with("zone=")))
            .and_then(|l| l.split('"').nth(1))
            .map(|s| s.to_string());
        if let Some(z) = flat_zone {
            return Some(z);
        }
    }

    if let Ok(text) = std::fs::read_to_string(ztlp_dir.join("agent.toml")) {
        let dns_zone = text
            .lines()
            .find(|l| l.trim_start().starts_with("zones"))
            .and_then(|l| l.split('"').nth(1))
            .map(|s| s.to_string());
        if let Some(z) = dns_zone {
            return Some(z);
        }
    }

    None
}

/// Compute the wizard's setup status.
///
/// This is a thin observability call: it reads the filesystem and (on
/// Windows) the cert/NRPT stores. It never modifies anything. The UI
/// polls this once per page load and after each button click so the
/// checkmarks update.
///
/// Daemon-running is implicitly `true` (we ARE the daemon answering).
async fn cmd_setup_status(_state: &AgentState) -> ControlResponse {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return ControlResponse::err("cannot resolve home directory"),
    };
    let identity_path = home.join(".ztlp").join("identity.json");
    let ca_root_path = home.join(".ztlp").join("ca").join("root.pem");
    let ca_intermediate_path = home.join(".ztlp").join("ca").join("intermediate.pem");

    // Identity presence: does identity.json exist and parse?
    //
    // Real bug found live on the Windows AI test machine (2026-08-30): this
    // used to ALSO try to read a `"zone"` field directly out of
    // identity.json to decide `identity_enrolled` — but identity.json's
    // real schema (confirmed live, repeatedly) is
    // `{node_id, static_private_key, static_public_key, signing_key_seed}`.
    // There has never been a `zone` field in identity.json; the zone lives
    // in `config.toml` (written by `ztlp setup`, flat `zone = "..."` key)
    // or the older `agent.toml` ([dns] `zones = [...]`). So
    // `identity_enrolled` was ALWAYS false for every real device, which
    // silently blocked the ENTIRE zero-click auto-provisioning chain in
    // app.js's `autoProvision()` (its very first gate is
    // `status.identity_enrolled`) even on a genuinely, successfully
    // enrolled device — confirmed live: Home showed "Active" (a different,
    // correct code path) while CA-init/CA-install/DNS-setup silently never
    // ran, and a real Chrome navigation to the zone hostname failed with
    // ERR_NAME_NOT_RESOLVED because the NRPT rule was never (correctly)
    // installed.
    let identity_present = std::fs::read_to_string(&identity_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .is_some();

    let zone = read_zone_from_config(&home).unwrap_or_default();
    let identity_enrolled = identity_present && !zone.is_empty();

    // CA initialized: both root + intermediate PEMs present AND parseable as X.509.
    let ca_initialized = ca_root_path.exists()
        && ca_intermediate_path.exists()
        && std::fs::read_to_string(&ca_root_path)
            .map(|s| s.contains("-----BEGIN CERTIFICATE-----"))
            .unwrap_or(false);

    // Windows-only: cert in machine root + NRPT rule present.
    #[cfg(target_os = "windows")]
    let (ca_installed_system_trust, dns_configured) = {
        let ca = Some(crate::agent::ca_trust::is_ca_installed());
        let dns = if !zone.is_empty() {
            let api = crate::agent::dns_setup_windows::default_nrpt_api();
            match api.list_rules() {
                Ok(rules) => Some(rules.iter().any(|r| {
                    // The rule must target this zone AND carry a usable
                    // NameServers list: Windows NRPT silently stores an
                    // EMPTY list when handed a host:port string (real bug,
                    // 2026-08-30, DESKTOP-CBSQDNE — Chrome got
                    // DNS_PROBE_FINISHED_NXDOMAIN because the rule
                    // "existed" but pointed nowhere). A rule with no usable
                    // server must count as NOT configured so the wizard
                    // re-runs dns-setup instead of showing a false green
                    // checkmark.
                    r.namespace
                        .trim_start_matches('.')
                        .eq_ignore_ascii_case(&zone)
                        && !r.name_servers.is_empty()
                        && r.name_servers.iter().all(|s| !s.contains(':'))
                })),
                Err(_) => Some(false),
            }
        } else {
            Some(false)
        };
        (ca, dns)
    };
    #[cfg(not(target_os = "windows"))]
    let (ca_installed_system_trust, dns_configured) = {
        let ca = Some(crate::agent::ca_trust::is_ca_installed());
        let dns = if !zone.is_empty() {
            Some(crate::agent::dns_setup::is_dns_configured())
        } else {
            Some(false)
        };
        (ca, dns)
    };

    let status = SetupStatus {
        identity_present,
        identity_enrolled,
        ca_initialized,
        ca_installed_system_trust,
        dns_configured,
        daemon_running: true,
        zone,
        ca_root_pem_path: ca_root_path.display().to_string(),
        identity_path: identity_path.display().to_string(),
    };

    ControlResponse::ok(serde_json::to_value(status).unwrap_or_default())
}

// ─── Client side (for CLI commands) ─────────────────────────────────────────

/// Send a command to the running agent and return the response.
pub async fn send_command(
    ipc_addr: &str,
    command: &ControlCommand,
) -> Result<ControlResponse, Box<dyn std::error::Error + Send + Sync>> {
    let stream = tokio::net::TcpStream::connect(ipc_addr)
        .await
        .map_err(|e| {
            format!(
                "cannot connect to agent ({}): {}\n\
             Is the agent running? Start it with: ztlp agent start",
                ipc_addr, e
            )
        })?;

    let (reader, mut writer) = stream.into_split();

    let json = serde_json::to_string(command)?;
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader.read_line(&mut line).await?;

    let response: ControlResponse = serde_json::from_str(&line)?;
    Ok(response)
}

pub fn default_ipc_address() -> String {
    "127.100.255.1:4433".to_string()
}

/// Get the default PID file path.
pub fn default_pid_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".ztlp").join("agent.pid"))
        .unwrap_or_else(|| PathBuf::from("/tmp/ztlp-agent.pid"))
}

/// Write the PID file.
pub fn write_pid_file(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, std::process::id().to_string())
}

/// Read the PID from a PID file.
pub fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Remove the PID file.
pub fn remove_pid_file(path: &Path) {
    std::fs::remove_file(path).ok();
}

/// Check if a process is running by PID.
#[allow(unsafe_code)]
pub fn is_process_running(pid: u32) -> bool {
    // On Unix, sending signal 0 checks if process exists without affecting it.
    #[cfg(unix)]
    {
        // SAFETY: kill(pid, 0) performs no action on the target process —
        // it only checks for existence and permission. The pid is a valid u32
        // cast to pid_t, and signal 0 is explicitly defined as a no-op probe
        // by POSIX (IEEE Std 1003.1-2017, kill(2)).
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
    #[cfg(windows)]
    {
        // v0.36 fix: this used to be hardcoded `false` on every non-Unix
        // target, which silently disabled `ztlp agent start`'s
        // "already running" duplicate-start guard on Windows — the
        // platform the desktop app actually ships on. Shell out to
        // `tasklist /FI "PID eq N"` (no extra crate/dependency needed) and
        // check whether that PID is actually listed in the output.
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/NH", "/FO", "CSV"])
            .output();
        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                tasklist_output_contains_pid(&stdout, pid)
            }
            _ => false,
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

/// Pure parsing core of the Windows liveness check: does `tasklist`'s
/// stdout actually list `pid`? Separated from the `Command::new("tasklist")`
/// call so this logic is unit-testable without a live Windows process.
///
/// Uses `/FO CSV` output (`"ztlp.exe","12345","Console","1","18,432 K"`) and
/// checks the quoted PID field exactly — a naive substring search on the raw
/// table output would let PID 123 false-positive-match a row for PID 12345.
#[cfg_attr(not(windows), allow(dead_code))]
fn tasklist_output_contains_pid(output: &str, pid: u32) -> bool {
    let pid_str = pid.to_string();
    output.lines().any(|line| {
        line.split(',')
            .nth(1)
            .map(|field| field.trim().trim_matches('"') == pid_str)
            .unwrap_or(false)
    })
}

/// Test-only helpers exposed for integration tests in `tests/`.
///
/// These aren't gated on `#[cfg(test)]` because `cfg(test)` only fires
/// for the crate's own unit-test pass, not for downstream integration
/// tests. `#[doc(hidden)]` keeps them out of the public docs surface,
/// and they construct no resources beyond a tiny in-memory VIP pool +
/// an empty tunnel pool + a broadcast channel — cheap to ship even in
/// release builds and not exercised by production code paths.
#[doc(hidden)]
impl AgentState {
    /// Test-only: build an `AgentState` with auth enabled.
    ///
    /// Uses a minimal in-memory DNS resolver state (a /30 VIP pool with
    /// no domain mappings) and an empty 1-slot tunnel pool. Sufficient
    /// for the `status` command and the auth gate; not suitable for
    /// commands that exercise tunnel-pool or DNS-resolver behavior.
    pub fn test_with_token(token: Arc<String>) -> Self {
        Self::test_state(Some(token))
    }

    /// Test-only: build an `AgentState` with no token configured
    /// (legacy/unauthenticated mode).
    pub fn test_without_token() -> Self {
        Self::test_state(None)
    }

    fn test_state(expected_token: Option<Arc<String>>) -> Self {
        let vip_pool = super::vip_pool::VipPool::new("127.200.0.0/30")
            .expect("test VIP pool /30 must construct");
        let dns_state = Arc::new(Mutex::new(DnsResolverState {
            vip_pool,
            domain_mapper: super::domain_map::DomainMapper::empty(),
            ns_server: "127.0.0.53:53".to_string(),
            upstream_dns: "1.1.1.1:53".to_string(),
            vip_state_path: None,
        }));
        let tunnel_pool = Arc::new(Mutex::new(super::tunnel_pool::TunnelPool::new(1)));
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        Self {
            dns_state,
            tunnel_pool,
            start_time: Instant::now(),
            dns_listen: "127.0.0.53:53".to_string(),
            shutdown_tx,
            expected_token,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── read_zone_from_config (2026-08-30) ─────────────────────────────
    //
    // Real bug found live on the Windows AI test machine: `cmd_setup_status`
    // used to read a `"zone"` field directly out of identity.json to decide
    // `identity_enrolled` -- but identity.json never has a `zone` field
    // (confirmed live, repeatedly: its real schema is
    // {node_id, static_private_key, static_public_key, signing_key_seed}).
    // This silently blocked app.js's ENTIRE auto-provisioning chain
    // (CA-init, CA-install, DNS-setup) on every real device, even ones that
    // had just completed a genuinely successful UI enrollment -- Home
    // showed "Active" (a different, correct code path) while a real Chrome
    // navigation to the zone hostname failed with ERR_NAME_NOT_RESOLVED.

    #[test]
    fn reads_zone_from_config_toml_flat_key() {
        let dir = std::env::temp_dir().join(format!("ztlp-control-test-{}-a", std::process::id()));
        let ztlp_dir = dir.join(".ztlp");
        std::fs::create_dir_all(&ztlp_dir).unwrap();
        std::fs::write(
            ztlp_dir.join("config.toml"),
            "# ZTLP Configuration\nzone = \"demo.spongebob.ztlp\"\nns_server = \"34.221.165.244:24096\"\n",
        )
        .unwrap();

        let zone = read_zone_from_config(&dir);
        assert_eq!(zone.as_deref(), Some("demo.spongebob.ztlp"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reads_zone_from_agent_toml_dns_section() {
        let dir = std::env::temp_dir().join(format!("ztlp-control-test-{}-b", std::process::id()));
        let ztlp_dir = dir.join(".ztlp");
        std::fs::create_dir_all(&ztlp_dir).unwrap();
        std::fs::write(
            ztlp_dir.join("agent.toml"),
            "[dns]\nzones = [\"demo.spongebob.ztlp\"]\n",
        )
        .unwrap();

        let zone = read_zone_from_config(&dir);
        assert_eq!(zone.as_deref(), Some("demo.spongebob.ztlp"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn returns_none_when_no_config_files_exist() {
        let dir = std::env::temp_dir().join(format!("ztlp-control-test-{}-c", std::process::id()));
        // Deliberately do NOT create the directory or any files.
        let zone = read_zone_from_config(&dir);
        assert_eq!(zone, None);
    }

    #[test]
    fn test_control_response_ok() {
        let resp = ControlResponse::ok(serde_json::json!({"test": true}));
        assert!(resp.ok);
        assert!(resp.error.is_none());
        assert!(resp.data.is_some());
    }

    #[test]
    fn test_control_response_err() {
        let resp = ControlResponse::err("something broke");
        assert!(!resp.ok);
        assert_eq!(resp.error, Some("something broke".to_string()));
        assert!(resp.data.is_none());
    }

    #[test]
    fn test_serialize_response() {
        let resp = ControlResponse::ok_empty();
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"ok":true}"#);
    }

    #[test]
    fn test_deserialize_command() {
        let json = r#"{"cmd": "status"}"#;
        let cmd: ControlCommand = serde_json::from_str(json).unwrap();
        assert_eq!(cmd.cmd, "status");
        assert!(cmd.name.is_none());
    }

    #[test]
    fn test_deserialize_command_with_name() {
        let json = r#"{"cmd": "connect", "name": "server.corp.ztlp"}"#;
        let cmd: ControlCommand = serde_json::from_str(json).unwrap();
        assert_eq!(cmd.cmd, "connect");
        assert_eq!(cmd.name, Some("server.corp.ztlp".to_string()));
    }

    #[test]
    fn test_default_ipc_address() {
        let addr = default_ipc_address();
        assert_eq!(addr, "127.100.255.1:4433");
    }

    #[test]
    fn test_default_pid_path() {
        let path = default_pid_path();
        assert!(path.to_string_lossy().contains("agent.pid"));
    }

    // ── Windows liveness check (2026-08-30) ──────────────────────────────
    //
    // `is_process_running` was hardcoded `false` on every non-Unix target
    // (`#[cfg(not(unix))] { let _ = pid; false }`), so `ztlp agent start`'s
    // "already running" duplicate-start guard silently never fired on
    // Windows — the platform every desktop-app user actually runs on. The
    // symptom this produced: the desktop app's "Connect" button spawning a
    // SECOND `ztlp agent start` on top of an already-running agent, which
    // then failed to bind its IPC/DNS ports and surfaced as a spurious
    // error banner even though an agent was already up and working fine.
    //
    // `tasklist_output_contains_pid` is the pure, OS-call-free parsing core
    // of the Windows liveness check — it takes `tasklist /FI "PID eq N"`'s
    // stdout and decides whether that PID is actually listed. Kept
    // separate from the `Command::new("tasklist")` call itself so the
    // matching logic is unit-testable without a live Windows process.

    #[test]
    fn test_tasklist_output_contains_pid_when_present() {
        // Real `tasklist /FI "PID eq N" /NH /FO CSV` output shape.
        let output = "\"ztlp.exe\",\"12345\",\"Console\",\"1\",\"18,432 K\"";
        assert!(tasklist_output_contains_pid(output, 12345));
    }

    #[test]
    fn test_tasklist_output_contains_pid_absent_when_not_found() {
        // tasklist with a /FI filter that matches nothing prints exactly
        // this message instead of a CSV row — must not be misread as a hit.
        let output = "INFO: No tasks are running which match the specified criteria.";
        assert!(!tasklist_output_contains_pid(output, 12345));
    }

    #[test]
    fn test_tasklist_output_contains_pid_does_not_false_positive_on_substring() {
        // PID 123 must not match a row for PID 12345 (naive substring
        // search on the raw output would get this wrong).
        let output = "\"ztlp.exe\",\"12345\",\"Console\",\"1\",\"18,432 K\"";
        assert!(!tasklist_output_contains_pid(output, 123));
    }

    #[test]
    fn test_tasklist_output_contains_pid_empty_output() {
        assert!(!tasklist_output_contains_pid("", 12345));
    }

    // ── Task 6a: daemon-owned enroll (build_enroll_exec_plan) ────────────
    //
    // Pure argv-builder tests — no subprocess spawned. Mirrors `ztlp setup`'s
    // real flag names exactly so a human debugging a failed enroll can copy
    // the logged argv straight into a terminal.

    fn cmd(
        enrollment_uri: Option<&str>,
        name: Option<&str>,
        relay_secret: Option<&str>,
    ) -> ControlCommand {
        ControlCommand {
            cmd: "enroll".to_string(),
            name: name.map(String::from),
            token: None,
            enrollment_uri: enrollment_uri.map(String::from),
            relay_secret: relay_secret.map(String::from),
        }
    }

    #[test]
    fn enroll_plan_requires_enrollment_uri() {
        let err = build_enroll_exec_plan(&cmd(None, None, None)).unwrap_err();
        assert!(err.contains("enrollment_uri"));
    }

    #[test]
    fn enroll_plan_rejects_blank_enrollment_uri() {
        let err = build_enroll_exec_plan(&cmd(Some("   "), None, None)).unwrap_err();
        assert!(err.contains("enrollment_uri"));
    }

    #[test]
    fn enroll_plan_minimal_uri_only() {
        let plan = build_enroll_exec_plan(&cmd(Some("ztlp://enroll/abc123"), None, None)).unwrap();
        assert_eq!(
            plan.args,
            vec!["setup", "--token", "ztlp://enroll/abc123", "--yes"]
        );
    }

    #[test]
    fn enroll_plan_includes_name_when_present() {
        let plan =
            build_enroll_exec_plan(&cmd(Some("ztlp://enroll/abc123"), Some("mac-llm4"), None))
                .unwrap();
        assert_eq!(
            plan.args,
            vec![
                "setup",
                "--token",
                "ztlp://enroll/abc123",
                "--yes",
                "--name",
                "mac-llm4"
            ]
        );
    }

    #[test]
    fn enroll_plan_includes_relay_secret_when_present() {
        let plan =
            build_enroll_exec_plan(&cmd(Some("ztlp://enroll/abc123"), None, Some("deadbeef")))
                .unwrap();
        assert_eq!(
            plan.args,
            vec![
                "setup",
                "--token",
                "ztlp://enroll/abc123",
                "--yes",
                "--relay-secret",
                "deadbeef"
            ]
        );
    }

    #[test]
    fn enroll_plan_includes_name_and_relay_secret_together() {
        let plan = build_enroll_exec_plan(&cmd(
            Some("ztlp://enroll/abc123"),
            Some("mac-llm4"),
            Some("deadbeef"),
        ))
        .unwrap();
        assert_eq!(
            plan.args,
            vec![
                "setup",
                "--token",
                "ztlp://enroll/abc123",
                "--yes",
                "--name",
                "mac-llm4",
                "--relay-secret",
                "deadbeef"
            ]
        );
    }

    #[test]
    fn enroll_plan_ignores_blank_name_and_relay_secret() {
        let plan = build_enroll_exec_plan(&cmd(Some("ztlp://enroll/abc123"), Some("  "), Some("")))
            .unwrap();
        assert_eq!(
            plan.args,
            vec!["setup", "--token", "ztlp://enroll/abc123", "--yes"]
        );
    }

    #[test]
    fn enroll_command_deserializes_full_shape() {
        let json = r#"{"cmd":"enroll","enrollment_uri":"ztlp://enroll/abc","name":"mac-llm4","relay_secret":"deadbeef","token":"bearer-xyz"}"#;
        let cmd: ControlCommand = serde_json::from_str(json).unwrap();
        assert_eq!(cmd.cmd, "enroll");
        assert_eq!(cmd.enrollment_uri.as_deref(), Some("ztlp://enroll/abc"));
        assert_eq!(cmd.name.as_deref(), Some("mac-llm4"));
        assert_eq!(cmd.relay_secret.as_deref(), Some("deadbeef"));
        assert_eq!(cmd.token.as_deref(), Some("bearer-xyz"));
    }

    // ── B4(b): post-enroll TLS provisioning plan ─────────────────────────
    //
    // HANDOFF-2026-09-20 B4 second gap: `ztlp setup` does not run ca-init,
    // so a daemon enrolled via the control command came up with "TLS:
    // disabled" and Safari warned. The daemon must follow a successful
    // enroll with `admin ca-init --zone <zone>` (idempotent: skipped when
    // ca/root.key exists) and `agent install-ca-cert --cert <root.pem>`.

    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ztlp-tlsplan-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".ztlp")).unwrap();
        d
    }

    #[test]
    fn post_enroll_tls_plan_fresh_home_runs_ca_init_then_install() {
        let home = tmp_home("fresh");
        std::fs::write(home.join(".ztlp/config.toml"), "zone = \"defcon.ztlp\"\n").unwrap();
        let plan = build_post_enroll_tls_plan(&home).unwrap();
        let root_pem = home.join(".ztlp/ca/root.pem").to_string_lossy().into_owned();
        assert_eq!(
            plan,
            vec![
                vec!["admin".to_string(), "ca-init".into(), "--zone".into(), "defcon.ztlp".into()],
                vec!["agent".to_string(), "install-ca-cert".into(), "--cert".into(), root_pem],
            ]
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn post_enroll_tls_plan_skips_ca_init_when_ca_exists() {
        let home = tmp_home("existing");
        std::fs::write(home.join(".ztlp/config.toml"), "zone = \"defcon.ztlp\"\n").unwrap();
        std::fs::create_dir_all(home.join(".ztlp/ca")).unwrap();
        std::fs::write(home.join(".ztlp/ca/root.key"), "k").unwrap();
        std::fs::write(home.join(".ztlp/ca/root.pem"), "p").unwrap();
        let plan = build_post_enroll_tls_plan(&home).unwrap();
        assert_eq!(plan.len(), 1, "{plan:?}");
        assert_eq!(plan[0][1], "install-ca-cert");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn post_enroll_tls_plan_errors_without_zone() {
        let home = tmp_home("nozone");
        let err = build_post_enroll_tls_plan(&home).unwrap_err();
        assert!(err.contains("zone"), "{err}");
        let _ = std::fs::remove_dir_all(&home);
    }
}
