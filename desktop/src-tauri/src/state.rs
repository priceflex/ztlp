//! Application state management.
//!
//! Holds the current connection state, identity, configuration, and traffic
//! statistics. All state is behind `Mutex` so Tauri commands can read/write
//! safely from any thread.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

// ── Connection status ───────────────────────────────────────────────────

/// Mirror of the C library's ZTLP_STATE_* values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub state: ConnectionState,
    pub relay: String,
    pub zone: String,
    pub connected_since: Option<i64>, // Unix timestamp (seconds)
}

impl Default for ConnectionStatus {
    fn default() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            relay: String::new(),
            zone: String::new(),
            connected_since: None,
        }
    }
}

// ── Identity ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub node_id: String,
    pub public_key: String,
    pub provider_type: String, // "software" | "hardware"
    pub zone_name: Option<String>,
    pub enrolled: bool,
}

// ── Services ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub protocol_type: String,
    pub host_node_id: String,
    pub is_reachable: bool,
    pub description: Option<String>,
    pub tags: Vec<String>,
}

// ── Traffic stats ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

// ── Enrollment ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResult {
    pub success: bool,
    pub zone_name: Option<String>,
    pub relay_address: Option<String>,
    pub message: String,
}

// ── App configuration ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub relay_address: String,
    pub stun_server: String,
    pub tunnel_address: String,
    pub dns_servers: Vec<String>,
    pub port_mappings: Vec<PortMapping>,
    pub mtu: u32,
    pub auto_connect: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortMapping {
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            relay_address: String::new(),
            stun_server: "stun.l.google.com:19302".into(),
            tunnel_address: "127.100.0.0/16".into(),
            dns_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            port_mappings: vec![],
            mtu: 1400,
            // Zero-click product requirement: the desktop app must
            // auto-connect on every fresh install with no manual "turn this
            // on" step (see app.js's `maybeAutoConnect()`, which was ALREADY
            // written assuming this default — its "default ON" comment
            // documented the intent this field failed to implement).
            // Confirmed live on a real Windows box (2026-08-30): a
            // freshly-enrolled device with valid identity+config never
            // auto-connected because this was `false`.
            auto_connect: true,
        }
    }
}

// ── Global app state ────────────────────────────────────────────────────

/// Central state container managed by Tauri.
pub struct AppState {
    pub status: Mutex<ConnectionStatus>,
    pub identity: Mutex<Option<IdentityInfo>>,
    pub services: Mutex<Vec<ServiceInfo>>,
    pub traffic: Mutex<TrafficStats>,
    pub config: Mutex<AppConfig>,
}

/// Parse zone name + enrollment status out of a ZTLP config file's text.
///
/// Handles BOTH shapes seen in the wild:
/// - `~/.ztlp/config.toml` (written by `ztlp setup --token ...`, the exact
///   path the desktop app's own enroll flow uses): flat top-level keys,
///   `zone = "..."`, `ns_server = "..."`, no `[ns]` section at all.
/// - `~/.ztlp/agent.toml` (the older/manual agent-config shape): an `[ns]`
///   section with `servers = [...]`, and `zones = [...]` under `[dns]`.
///
/// A device is considered enrolled if either an explicit `zone = "..."` key
/// is present (config.toml shape) OR an `[ns]` section exists (agent.toml
/// shape) OR a bare `ns_server = "..."` key is present (config.toml shape,
/// belt-and-suspenders in case `zone` itself is ever omitted).
fn derive_zone_and_enrollment(text: &str) -> (Option<String>, bool) {
    // config.toml shape: `zone = "demo.spongebob.ztlp"`
    let flat_zone = text
        .lines()
        .find(|l| l.trim_start().starts_with("zone "))
        .or_else(|| text.lines().find(|l| l.trim_start().starts_with("zone=")))
        .and_then(|l| l.split('"').nth(1))
        .map(|s| s.to_string());

    // agent.toml shape: first entry of `zones = [...]` under [dns].
    let dns_zones_zone = text
        .lines()
        .find(|l| l.trim_start().starts_with("zones"))
        .and_then(|l| l.split('"').nth(1))
        .map(|s| s.to_string());

    let zone = flat_zone.or(dns_zones_zone);

    let has_ns_section = text.contains("[ns]");
    let has_flat_ns_server = text
        .lines()
        .any(|l| l.trim_start().starts_with("ns_server"));

    let enrolled = has_ns_section || has_flat_ns_server || zone.is_some();

    (zone, enrolled)
}

impl Default for AppState {
    fn default() -> Self {
        // Generate or load identity.
        let default_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".ztlp")
            .join("identity.json");
        let identity_info = match ztlp_proto::identity::NodeIdentity::load(&default_path) {
            Ok(id) => {
                // Derive the zone + enrollment state from whichever config
                // file is actually on disk. Real bug found live on the
                // Windows AI test machine (2026-08-30): `ztlp setup --token
                // ... --yes` (the exact command the desktop app's own
                // `process_enrollment` shells out to) writes
                // `~/.ztlp/config.toml` with FLAT keys (`zone = "..."`,
                // `ns_server = "..."`) — it does NOT write `agent.toml` and
                // never emits an `[ns]` section at all. This code used to
                // hardcode reading `agent.toml` and check for the literal
                // substring `"[ns]"`, so a device that had JUST completed a
                // real, successful enrollment through the app's own Setup
                // screen was STILL reported as `enrolled: false` forever —
                // the Home screen stayed stuck on "Ready" and auto-connect
                // never fired, no matter how many times the user re-enrolled.
                // Confirmed live: `~/.ztlp/config.toml` existed with valid
                // `zone`/`ns_server` keys immediately after a real UI
                // enrollment, while `~/.ztlp/agent.toml` never existed at all.
                let ztlp_dir = dirs::home_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                    .join(".ztlp");
                let (zone_name, enrolled) = std::fs::read_to_string(ztlp_dir.join("config.toml"))
                    .ok()
                    .map(|text| derive_zone_and_enrollment(&text))
                    .filter(|(zone, enrolled)| zone.is_some() || *enrolled)
                    .or_else(|| {
                        // Fall back to the older agent.toml-based check for
                        // any install that still uses that file format.
                        std::fs::read_to_string(ztlp_dir.join("agent.toml"))
                            .ok()
                            .map(|text| derive_zone_and_enrollment(&text))
                    })
                    .unwrap_or((None, false));

                Some(IdentityInfo {
                    node_id: id.node_id.to_string(), // NodeId implements Display via hex encoding
                    public_key: id
                        .static_public_key
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>(),
                    provider_type: "software".into(),
                    zone_name,
                    enrolled,
                })
            }
            Err(_) => Some(Default::default()), // Fallback structure instance
        };

        let mock_services = vec![
            ServiceInfo {
                id: "svc-001".into(),
                name: "Web Server".into(),
                hostname: "web.internal.ztlp".into(),
                port: 443,
                protocol_type: "https".into(),
                host_node_id: "a1b2c3d4e5f60718".into(),
                is_reachable: true,
                description: Some("Main web application".into()),
                tags: vec!["web".into(), "production".into()],
            },
            ServiceInfo {
                id: "svc-002".into(),
                name: "Database".into(),
                hostname: "db.internal.ztlp".into(),
                port: 5432,
                protocol_type: "tcp".into(),
                host_node_id: "f8e7d6c5b4a39201".into(),
                is_reachable: true,
                description: Some("PostgreSQL primary".into()),
                tags: vec!["database".into(), "production".into()],
            },
            ServiceInfo {
                id: "svc-003".into(),
                name: "SSH Gateway".into(),
                hostname: "ssh.internal.ztlp".into(),
                port: 22,
                protocol_type: "tcp".into(),
                host_node_id: "1122334455667788".into(),
                is_reachable: false,
                description: Some("Jump host".into()),
                tags: vec!["ssh".into(), "admin".into()],
            },
        ];

        Self {
            status: Mutex::new(ConnectionStatus::default()),
            identity: Mutex::new(identity_info),
            services: Mutex::new(mock_services),
            traffic: Mutex::new(TrafficStats::default()),
            config: Mutex::new(AppConfig::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── derive_zone_and_enrollment (2026-08-30) ────────────────────────
    //
    // Real bug found live on the Windows AI test machine: a device that
    // had JUST completed a real, successful enrollment through the app's
    // own Setup screen (paste token -> Enroll -> "Identity saved" ->
    // config.toml written with a real zone) was STILL reported as
    // `enrolled: false` by AppState::default() forever, because the old
    // code hardcoded reading `agent.toml` and checking for the literal
    // substring `"[ns]"` -- but `ztlp setup --token ... --yes` (the exact
    // command the app's own `process_enrollment` shells out to) writes
    // `config.toml` with flat `zone = "..."` / `ns_server = "..."` keys
    // and never creates `agent.toml` at all in the desktop-app enrollment
    // path. Confirmed live via SSH: `~/.ztlp/config.toml` existed with a
    // real zone/ns_server immediately after enrollment; `~/.ztlp/agent.toml`
    // never existed.

    #[test]
    fn recognizes_config_toml_shape_as_enrolled() {
        let text = "# ZTLP Configuration\n\
                     # Zone: demo.spongebob.ztlp\n\n\
                     identity = \"C:\\\\Users\\\\trs\\\\.ztlp\\\\identity.json\"\n\
                     ns_server = \"34.221.165.244:24096\"\n\
                     relay = \"34.221.165.244:24095\"\n\
                     zone = \"demo.spongebob.ztlp\"\n";
        let (zone, enrolled) = derive_zone_and_enrollment(text);
        assert_eq!(zone.as_deref(), Some("demo.spongebob.ztlp"));
        assert!(
            enrolled,
            "a device with a real config.toml (flat zone/ns_server keys, \
             the shape `ztlp setup` actually writes) must be recognized as \
             enrolled"
        );
    }

    #[test]
    fn recognizes_agent_toml_shape_as_enrolled() {
        let text = "[ns]\nservers = [\"34.221.165.244:24096\"]\n\n\
                     [dns]\nzones = [\"demo.spongebob.ztlp\"]\n\n\
                     [tunnel]\nrelay = \"34.221.165.244:24095\"\n";
        let (zone, enrolled) = derive_zone_and_enrollment(text);
        assert_eq!(zone.as_deref(), Some("demo.spongebob.ztlp"));
        assert!(
            enrolled,
            "the older agent.toml [ns]-section shape must still work"
        );
    }

    #[test]
    fn empty_config_is_not_enrolled() {
        let (zone, enrolled) = derive_zone_and_enrollment("");
        assert_eq!(zone, None);
        assert!(!enrolled);
    }

    /// Real bug found live on the Windows AI test machine (2026-08-30): a
    /// freshly-enrolled device (valid `~/.ztlp/identity.json` +
    /// `~/.ztlp/agent.toml` on disk, confirmed via a real live UIA/HTTP
    /// desktop-automation session showing the Setup screen already
    /// recognizing the device as enrolled) NEVER auto-connected — the Home
    /// screen stayed stuck on "Ready — standing by" instead of "Active"
    /// indefinitely, and `ztlp.exe` (the agent) was never spawned at all.
    ///
    /// Root cause: `app.js`'s `maybeAutoConnect()` computes
    /// `want = cfg.auto_connect` (defaulting only when `cfg` itself is
    /// absent) with an inline comment claiming "default ON", but
    /// `AppConfig::default()` here set `auto_connect: false` — the exact
    /// opposite of what the JS assumed and what the product's stated
    /// requirement is ("the user shouldn't even have to hit connect").
    /// Every fresh install (no config.json on disk yet, so
    /// `AppConfig::default()` is what `get_config()` actually returns)
    /// silently never auto-connected.
    #[test]
    fn app_config_default_has_auto_connect_enabled() {
        let cfg = AppConfig::default();
        assert!(
            cfg.auto_connect,
            "AppConfig::default() must default auto_connect to true — \
             app.js's maybeAutoConnect() assumes this (see its 'default ON' \
             comment) and the product requirement is zero-click auto-connect \
             on every fresh install, not just after a user manually flips a \
             setting"
        );
    }
}
