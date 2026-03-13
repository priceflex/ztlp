//! Unix socket control interface for the ZTLP agent daemon.
//!
//! The agent exposes a Unix domain socket (default: `~/.ztlp/agent.sock`)
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
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::dns::DnsResolverState;

// ─── Command/Response types ─────────────────────────────────────────────────

/// A control command from the CLI.
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlCommand {
    pub cmd: String,
    /// Optional name parameter (for connect/disconnect).
    #[serde(default)]
    pub name: Option<String>,
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
}

/// Run the control socket server.
///
/// Listens on the Unix socket and handles commands from the CLI.
/// This is a long-running task that should be spawned as a tokio task.
pub async fn run_control_socket(
    socket_path: &Path,
    state: Arc<AgentState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Remove stale socket file
    if socket_path.exists() {
        std::fs::remove_file(socket_path).ok();
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let listener = UnixListener::bind(socket_path).map_err(|e| {
        format!(
            "failed to bind control socket {}: {}",
            socket_path.display(),
            e
        )
    })?;

    info!("control socket listening on {}", socket_path.display());

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

            let response = match serde_json::from_str::<ControlCommand>(&line) {
                Ok(cmd) => handle_command(cmd, &state).await,
                Err(e) => ControlResponse::err(format!("invalid command: {}", e)),
            };

            if let Ok(json) = serde_json::to_string(&response) {
                let _ = writer.write_all(json.as_bytes()).await;
                let _ = writer.write_all(b"\n").await;
            }
        });
    }
}

/// Handle a control command.
async fn handle_command(cmd: ControlCommand, state: &AgentState) -> ControlResponse {
    match cmd.cmd.as_str() {
        "status" => cmd_status(state).await,
        "tunnels" => cmd_tunnels(state).await,
        "dns_cache" => cmd_dns_cache(state).await,
        "flush_dns" => cmd_flush_dns(state).await,
        "shutdown" => cmd_shutdown(state).await,
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

// ─── Client side (for CLI commands) ─────────────────────────────────────────

/// Send a command to the running agent and return the response.
pub async fn send_command(
    socket_path: &Path,
    command: &ControlCommand,
) -> Result<ControlResponse, Box<dyn std::error::Error + Send + Sync>> {
    let stream = tokio::net::UnixStream::connect(socket_path).await.map_err(|e| {
        format!(
            "cannot connect to agent ({}): {}\n\
             Is the agent running? Start it with: ztlp agent start",
            socket_path.display(),
            e
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

/// Get the default control socket path.
pub fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".ztlp").join("agent.sock"))
        .unwrap_or_else(|| PathBuf::from("/tmp/ztlp-agent.sock"))
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
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_default_socket_path() {
        let path = default_socket_path();
        assert!(path.to_string_lossy().contains("agent.sock"));
    }

    #[test]
    fn test_default_pid_path() {
        let path = default_pid_path();
        assert!(path.to_string_lossy().contains("agent.pid"));
    }
}
