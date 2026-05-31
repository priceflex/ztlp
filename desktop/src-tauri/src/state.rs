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
            auto_connect: false,
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

impl Default for AppState {
    fn default() -> Self {
        // Generate or load identity.
        let default_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
            .join(".ztlp")
            .join("identity.json");
        let identity_info = match ztlp_proto::identity::NodeIdentity::load(&default_path) {
            Ok(id) => Some(IdentityInfo {
                node_id: id.node_id.to_string(), // NodeId implements Display via hex encoding
                public_key: id
                    .static_public_key
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>(),
                provider_type: "software".into(),
                zone_name: None,
                enrolled: false,
            }),
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
