//! Agent configuration — parsed from `~/.ztlp/agent.toml`.
//!
//! The agent config extends the existing `~/.ztlp/config.toml` CLI config
//! with agent-specific settings (DNS, tunnels, renewal, health).

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::local_tls::TlsConfig;
use crate::identity::NodeId;

/// IPC configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IpcConfig {
    /// TCP bind address for IPC control.
    pub listen: String,
}

/// Top-level agent configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Identity settings.
    pub identity: IdentityConfig,

    /// DNS resolver settings.
    pub dns: DnsConfig,

    /// Namespace server settings.
    pub ns: NsConfig,

    /// Tunnel settings.
    pub tunnel: TunnelConfig,

    /// Credential renewal settings.
    pub renewal: RenewalConfig,

    /// Logging settings.
    pub log: LogConfig,

    /// Local TLS termination settings.
    pub tls: TlsConfig,

    /// Gateway pinning settings.
    pub gateway: GatewayPinConfig,

    /// IPC settings.
    pub ipc: IpcConfig,

    /// Static proxy targets keyed by SSH hostname.
    ///
    /// These are an operational escape hatch for real-world relay testing,
    /// especially when a host is reachable through ZTLP transport before its
    /// namespace records are fully registered.
    pub proxy_targets: HashMap<String, StaticProxyTargetConfig>,
}

/// Static proxy target override for `ztlp proxy` keyed by hostname.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct StaticProxyTargetConfig {
    /// Optional ZTLP name for logging and future NS fallback semantics.
    pub ztlp_name: Option<String>,
    /// Direct endpoint to connect to for the override path.
    pub addr: String,
    /// Optional peer NodeID as a 32-char hex string.
    #[serde(default, deserialize_with = "deserialize_optional_node_id")]
    pub node_id: Option<NodeId>,
}

fn deserialize_optional_node_id<'de, D>(deserializer: D) -> Result<Option<NodeId>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let hex_value = Option::<String>::deserialize(deserializer)?;
    let Some(hex_value) = hex_value else {
        return Ok(None);
    };

    let bytes = hex::decode(&hex_value)
        .map_err(|e| Error::custom(format!("invalid node_id hex '{}': {}", hex_value, e)))?;

    if bytes.len() != 16 {
        return Err(Error::custom(format!(
            "node_id must decode to 16 bytes, got {} bytes",
            bytes.len()
        )));
    }

    let mut node_id = [0u8; 16];
    node_id.copy_from_slice(&bytes);
    Ok(Some(NodeId::from_bytes(node_id)))
}

/// Identity file location.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Path to identity JSON file.
    pub path: String,
}

/// DNS resolver configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Listen address for DNS resolver (default: "127.0.0.53:5353").
    pub listen: String,

    /// Enable DNS resolver.
    pub enabled: bool,

    /// Upstream DNS for non-ZTLP queries.
    pub upstream: String,

    /// Virtual IP pool CIDR (default: "127.100.0.0/16").
    pub vip_range: String,

    /// Custom domain zones to intercept.
    pub zones: Vec<String>,

    /// Auto-discover ZTLP zones via `_ztlp` TXT records.
    pub auto_discover: bool,

    /// Map custom domains to ZTLP zones.
    pub domain_map: HashMap<String, String>,
}

/// Namespace server configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NsConfig {
    /// NS server addresses (host:port).
    pub servers: Vec<String>,

    /// Query timeout in milliseconds.
    pub timeout_ms: u64,

    /// Cache TTL override (0 = use record TTL).
    pub cache_ttl_override: u64,
}

/// Relay addresses — accepts a single string or a list of strings in TOML.
///
/// ```toml
/// relay = "host:port"           # single relay
/// relays = ["h1:p1", "h2:p2"]  # multiple relays
/// ```
#[derive(Debug, Clone, Default)]
pub struct RelayAddrs(pub Vec<String>);

impl<'de> Deserialize<'de> for RelayAddrs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de;

        struct RelayAddrsVisitor;

        impl<'de> de::Visitor<'de> for RelayAddrsVisitor {
            type Value = RelayAddrs;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a relay address string or list of strings")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<RelayAddrs, E> {
                Ok(RelayAddrs(vec![v.to_string()]))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<RelayAddrs, A::Error> {
                let mut addrs = Vec::new();
                while let Some(s) = seq.next_element::<String>()? {
                    addrs.push(s);
                }
                Ok(RelayAddrs(addrs))
            }
        }

        deserializer.deserialize_any(RelayAddrsVisitor)
    }
}

/// Tunnel configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TunnelConfig {
    /// Local bind address for ZTLP UDP.
    pub bind: String,

    /// Idle tunnel timeout (e.g., "5m").
    pub idle_timeout: String,

    /// Keepalive interval (e.g., "30s").
    pub keepalive_interval: String,

    /// Auto-reconnect on tunnel failure.
    pub auto_reconnect: bool,

    /// Initial reconnect backoff.
    pub reconnect_backoff_initial: String,

    /// Maximum reconnect backoff.
    pub reconnect_backoff_max: String,

    /// Prefer relay routing (even when direct is possible).
    pub prefer_relay: bool,

    /// Static relay addresses.
    /// Accepts either `relays = [...]` (array) or `relay = "addr"` (single string).
    #[serde(alias = "relay")]
    pub relays: RelayAddrs,

    /// Maximum concurrent tunnels.
    pub max_tunnels: usize,
}

/// Credential renewal configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RenewalConfig {
    /// Enable automatic credential renewal.
    pub enabled: bool,

    /// Check interval (e.g., "1h").
    pub check_interval: String,

    /// Certificate renewal threshold (fraction of lifetime).
    pub cert_threshold: f64,

    /// NS record refresh at fraction of TTL.
    pub ns_refresh_threshold: f64,

    /// Jitter ratio for NS refresh (prevents thundering herd).
    pub ns_refresh_jitter: f64,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Log level: error, warn, info, debug, trace.
    pub level: String,

    /// Log file path (empty = stderr).
    pub file: String,

    /// Structured JSON logging.
    pub json: bool,
}

/// Gateway certificate/key pinning configuration.
///
/// When `pinned_keys` is non-empty, connections are only allowed to gateways
/// whose static Noise public key matches one of these pins. This prevents
/// MITM attacks even if the Noise_XX handshake succeeds with an unknown gateway.
///
/// Keys are stored as base64-encoded 32-byte X25519 public keys.
///
/// ```toml
/// [gateway]
/// pinned_keys = [
///   "base64_encoded_key_1",
///   "base64_encoded_key_2"   # for key rotation
/// ]
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GatewayPinConfig {
    /// Pinned gateway static public keys (base64-encoded).
    /// If non-empty, connections are only allowed to gateways whose
    /// static Noise key matches one of these pins.
    #[serde(default, deserialize_with = "deserialize_pinned_keys")]
    pub pinned_keys: Vec<[u8; 32]>,
}

/// Deserialize pinned keys from a list of base64-encoded strings.
fn deserialize_pinned_keys<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    use base64::Engine;
    use serde::de::Error;

    let strings: Vec<String> = Vec::deserialize(deserializer)?;
    let mut keys = Vec::with_capacity(strings.len());

    for s in &strings {
        // Try base64 standard, then URL-safe, then hex
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s))
            .or_else(|_| hex::decode(s).map_err(|_| base64::DecodeError::InvalidLength(0)))
            .map_err(|e| Error::custom(format!("invalid pinned key encoding '{}': {}", s, e)))?;

        if bytes.len() != 32 {
            return Err(Error::custom(format!(
                "pinned key must be 32 bytes, got {} bytes from '{}'",
                bytes.len(),
                s,
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        keys.push(key);
    }

    Ok(keys)
}

// ── Default implementations ─────────────────────────────────────────────────

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            listen: "127.100.255.1:4433".to_string(),
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            path: "~/.ztlp/identity.json".to_string(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.53:5353".to_string(),
            enabled: true,
            upstream: "1.1.1.1:53".to_string(),
            vip_range: "127.100.0.0/16".to_string(),
            zones: Vec::new(),
            auto_discover: true,
            domain_map: HashMap::new(),
        }
    }
}

impl Default for NsConfig {
    fn default() -> Self {
        Self {
            servers: vec!["127.0.0.1:23096".to_string()],
            timeout_ms: 2000,
            cache_ttl_override: 0,
        }
    }
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:0".to_string(),
            idle_timeout: "5m".to_string(),
            keepalive_interval: "30s".to_string(),
            auto_reconnect: true,
            reconnect_backoff_initial: "1s".to_string(),
            reconnect_backoff_max: "60s".to_string(),
            prefer_relay: false,
            relays: RelayAddrs::default(),
            max_tunnels: 256,
        }
    }
}

impl Default for RenewalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval: "1h".to_string(),
            cert_threshold: 0.67,
            ns_refresh_threshold: 0.75,
            ns_refresh_jitter: 0.10,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: String::new(),
            json: false,
        }
    }
}

// ── Loading ─────────────────────────────────────────────────────────────────

impl AgentConfig {
    /// Load agent config from `~/.ztlp/agent.toml`, falling back to defaults.
    pub fn load() -> Self {
        Self::load_from_default_path()
    }

    /// Load from the default path `~/.ztlp/agent.toml`.
    fn load_from_default_path() -> Self {
        let path = dirs::home_dir()
            .map(|h| h.join(".ztlp").join("agent.toml"))
            .unwrap_or_else(|| PathBuf::from(".ztlp/agent.toml"));
        Self::load_from_path(&path)
    }

    /// Load from a specific path, falling back to defaults on any error.
    pub fn load_from_path(path: &Path) -> Self {
        if !path.exists() {
            tracing::debug!("no agent config at {}, using defaults", path.display());
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(cfg) => {
                    tracing::debug!("loaded agent config from {}", path.display());
                    cfg
                }
                Err(e) => {
                    tracing::warn!(
                        "failed to parse agent config {}: {}, using defaults",
                        path.display(),
                        e
                    );
                    Self::default()
                }
            },
            Err(e) => {
                tracing::warn!(
                    "failed to read agent config {}: {}, using defaults",
                    path.display(),
                    e
                );
                Self::default()
            }
        }
    }

    /// Resolve the identity file path, expanding `~` to home dir.
    pub fn identity_path(&self) -> PathBuf {
        expand_tilde(&self.identity.path)
    }

    /// Get the first NS server address, or the default.
    pub fn ns_server(&self) -> &str {
        self.ns
            .servers
            .first()
            .map(|s| s.as_str())
            .unwrap_or("127.0.0.1:23096")
    }
}

/// Expand `~` prefix to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") || path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

/// Default path to the per-install control-plane Bearer token file.
///
/// Resolution order:
/// 1. `ZTLP_AGENT_TOKEN_PATH` env var if set (used by tests and the D2
///    Windows installer to place the file under `C:\ProgramData\ZTLP\`).
/// 2. `~/.ztlp/agent.token` if `home_dir()` is available.
/// 3. `/tmp/ztlp-agent.token` as a last-resort fallback — mirrors the
///    `control::default_pid_path` pattern.
///
/// The file itself is materialized (and chmodded 0o600 on unix) by
/// `daemon::ensure_token_file`.
pub fn default_token_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("ZTLP_AGENT_TOKEN_PATH") {
        if !override_path.is_empty() {
            return PathBuf::from(override_path);
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".ztlp").join("agent.token"))
        .unwrap_or_else(|| PathBuf::from("/tmp/ztlp-agent.token"))
}

/// Best-effort load of the agent control-plane Bearer token.
///
/// Reads the file at [`default_token_path`] and returns
/// `Some(trimmed_content)` on success, or `None` if the file is missing,
/// unreadable, empty, or whitespace-only.
///
/// A `None` result means "no token file" — the resulting `ControlCommand`
/// will have `token: None`, which the daemon will only accept if it is
/// running in legacy mode (`expected_token: None`). Production daemons
/// (post-D1.T3) always materialize a token and require it, so a missing
/// file when a daemon is running will surface as `unauthorized` from
/// the daemon — which is the correct, loud failure mode.
///
/// This function intentionally never errors: callers (CLI / desktop IPC)
/// already get a useful connect-error from `send_command` if the daemon
/// is not running at all.
pub fn load_agent_token() -> Option<String> {
    let path = default_token_path();
    let contents = std::fs::read_to_string(&path).ok()?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = AgentConfig::default();
        assert_eq!(cfg.dns.listen, "127.0.0.53:5353");
        assert_eq!(cfg.dns.vip_range, "127.100.0.0/16");
        assert!(cfg.dns.enabled);
        assert_eq!(cfg.ns.timeout_ms, 2000);
        assert_eq!(cfg.tunnel.max_tunnels, 256);
        assert!(cfg.renewal.enabled);
        assert!(cfg.dns.domain_map.is_empty());
    }

    #[test]
    fn test_expand_tilde() {
        let result = expand_tilde("~/.ztlp/identity.json");
        assert!(!result.starts_with("~"));
        assert!(result
            .to_str()
            .unwrap_or("")
            .contains(".ztlp/identity.json"));
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let result = expand_tilde("/etc/ztlp/identity.json");
        assert_eq!(result, PathBuf::from("/etc/ztlp/identity.json"));
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml_str = r#"
[ns]
servers = ["10.0.0.1:23096"]
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.ns.servers, vec!["10.0.0.1:23096"]);
        // Other fields should be defaults
        assert_eq!(cfg.dns.listen, "127.0.0.53:5353");
        assert!(cfg.dns.enabled);
    }

    #[test]
    fn test_parse_full_toml() {
        let toml_str = r#"
[identity]
path = "~/.ztlp/identity.json"

[dns]
listen = "127.0.0.53:5353"
enabled = true
upstream = "8.8.8.8:53"
vip_range = "127.100.0.0/16"
zones = ["internal.techrockstars.com"]
auto_discover = true

[dns.domain_map]
"internal.techrockstars.com" = "techrockstars.ztlp"
"vpn.acmecorp.com" = "acme.techrockstars.ztlp"

[ns]
servers = ["ns.techrockstars.com:23096"]
timeout_ms = 3000

[tunnel]
bind = "0.0.0.0:0"
idle_timeout = "10m"
max_tunnels = 512

[renewal]
enabled = true
cert_threshold = 0.67

[log]
level = "debug"
json = true
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.dns.upstream, "8.8.8.8:53");
        assert_eq!(cfg.dns.zones, vec!["internal.techrockstars.com"]);
        assert_eq!(
            cfg.dns.domain_map.get("internal.techrockstars.com"),
            Some(&"techrockstars.ztlp".to_string())
        );
        assert_eq!(
            cfg.dns.domain_map.get("vpn.acmecorp.com"),
            Some(&"acme.techrockstars.ztlp".to_string())
        );
        assert_eq!(cfg.ns.timeout_ms, 3000);
        assert_eq!(cfg.tunnel.max_tunnels, 512);
        assert!(cfg.log.json);
    }

    #[test]
    fn test_parse_static_proxy_targets_from_toml() {
        let toml_str = r#"
[proxy_targets.windows-relay]
ztlp_name = "windows.techrockstars.ztlp"
addr = "10.170.3.111:23095"
node_id = "b88397923c2518ca6aa400eb79a18c7b"

[proxy_targets.bootstrap-only]
addr = "127.0.0.1:23095"
"#;

        let cfg: AgentConfig = toml::from_str(toml_str).unwrap();
        let windows = cfg.proxy_targets.get("windows-relay").unwrap();
        assert_eq!(
            windows.ztlp_name.as_deref(),
            Some("windows.techrockstars.ztlp")
        );
        assert_eq!(windows.addr, "10.170.3.111:23095");
        assert_eq!(
            windows.node_id,
            Some(NodeId::from_bytes(
                hex::decode("b88397923c2518ca6aa400eb79a18c7b")
                    .unwrap()
                    .try_into()
                    .unwrap()
            ))
        );

        let bootstrap_only = cfg.proxy_targets.get("bootstrap-only").unwrap();
        assert_eq!(bootstrap_only.ztlp_name, None);
        assert_eq!(bootstrap_only.node_id, None);
    }

    #[test]
    fn test_static_proxy_target_node_id_is_optional() {
        let toml_str = r#"
[proxy_targets.windows-relay]
addr = "10.170.3.111:23095"
"#;

        let cfg: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.proxy_targets["windows-relay"].node_id, None);
    }

    #[test]
    fn test_static_proxy_target_invalid_node_id_fails_decode() {
        let toml_str = r#"
[proxy_targets.windows-relay]
addr = "10.170.3.111:23095"
node_id = "abcd"
"#;

        let err = toml::from_str::<AgentConfig>(toml_str)
            .unwrap_err()
            .to_string();
        assert!(err.contains("node_id must decode to 16 bytes"));
    }

    #[test]
    fn test_ns_server_accessor() {
        let cfg = AgentConfig::default();
        assert_eq!(cfg.ns_server(), "127.0.0.1:23096");

        let mut cfg2 = AgentConfig::default();
        cfg2.ns.servers = vec!["10.0.0.5:23096".to_string()];
        assert_eq!(cfg2.ns_server(), "10.0.0.5:23096");
    }

    #[test]
    fn test_ns_server_empty_fallback() {
        let mut cfg = AgentConfig::default();
        cfg.ns.servers.clear();
        assert_eq!(cfg.ns_server(), "127.0.0.1:23096");
    }

    #[test]
    fn test_load_nonexistent_file() {
        let cfg = AgentConfig::load_from_path(Path::new("/nonexistent/agent.toml"));
        // Should return defaults without error
        assert_eq!(cfg.dns.listen, "127.0.0.53:5353");
    }
}
