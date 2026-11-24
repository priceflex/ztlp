//! Agent configuration — parsed from `~/.ztlp/agent.toml`.
//!
//! The agent config extends the existing `~/.ztlp/config.toml` CLI config
//! with agent-specific settings (DNS, tunnels, renewal, health).

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::local_tls::{self, TlsConfig, TlsMode};
#[allow(unused_imports)]
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

    /// Accept-to-first-response-byte deadline for the VIP TCP proxy
    /// (e.g., "15s").
    ///
    /// When a client connects to a VIP listener, the agent must resolve the
    /// peer, establish the ZTLP tunnel, and (on TLS ports) complete the local
    /// TLS handshake BEFORE the backend can answer. With no deadline, a
    /// black-holed backend leaves the client socket open until the client's
    /// own OS keep-alive gives up (~45s on Windows Chrome) — the
    /// 2026-08-30 Chrome-refresh-hang root cause (see
    /// `docs/2026-08-30-zero-click-nrpt-verify.md`, FOLLOW-UP section).
    ///
    /// This budget covers the whole "accepted → first response byte" journey
    /// as ONE deadline (it is NOT restarted when the tunnel becomes ready).
    /// The steady-state bridge loop is deliberately NOT covered — long-lived
    /// idle flows (websockets, SSE, RDP) must survive arbitrary idle.
    ///
    /// On expiry the agent fails LOUDLY: HTTP-ish ports (80/8080) get a real
    /// `504 Gateway Timeout` with a ZTLP-branded body; other ports get the
    /// connection reset. Never silent.
    pub first_byte_timeout: String,

    /// Shared HMAC secret for signing relay `CLIENT_ROUTE` frames.
    ///
    /// Must equal the relay's `ZTLP_RELAY_REGISTRATION_SECRET` (or the
    /// per-zone `ZTLP_HMAC_SECRET_<ZONE>`). Accepts 64 hex chars, `base64:...`
    /// or a raw string (same rules as the relay). Required when the relay
    /// runs `ZTLP_RELAY_HMAC_MODE=prod`; unset = unsigned frames (dev/staging
    /// relays only).
    pub relay_secret: Option<String>,

    /// Path to a file holding the relay secret (alternative to
    /// `relay_secret`; the file contents are trimmed). `relay_secret` wins
    /// when both are set.
    pub relay_secret_file: Option<String>,

    /// Extra VIP proxy ports to listen on, in addition to the built-in
    /// eight (22, 80, 443, 3306, 5432, 3389, 8080, 8443).
    ///
    /// Every VIP the pool hands out gets a listener on each of these ports
    /// (listeners = VIPs × ports), so the list is capped at
    /// [`VIP_PORTS_MAX`] entries. An entry for a built-in port does NOT add
    /// a second listener — it overrides that port's TLS mode only.
    ///
    /// ```toml
    /// [[tunnel.vip_ports]]
    /// port = 1514
    /// tls  = "passthrough"   # default; bytes are forwarded untouched
    /// ```
    ///
    /// `tls` is one of `passthrough` (default — never terminate TLS),
    /// `terminate` (always terminate locally, like built-in 443/8443) or
    /// `auto` (sniff the first bytes, the built-in default for unknown
    /// ports).
    #[serde(default, deserialize_with = "deserialize_vip_ports")]
    pub vip_ports: Vec<VipPortConfig>,
}

/// Maximum number of `[tunnel] vip_ports` entries. Every VIP the pool hands
/// out gets a listener on every configured port (listeners = VIPs × ports),
/// so an unbounded list would let one config key spawn thousands of sockets.
pub const VIP_PORTS_MAX: usize = 32;

/// The eight ports the VIP proxy has always listened on. `vip_ports` is
/// strictly additive on top of this set (an entry for a built-in port
/// overrides that port's TLS mode; it never removes the listener).
pub const VIP_BUILTIN_PORTS: [u16; 8] = [22, 80, 443, 3306, 5432, 3389, 8080, 8443];

/// TLS handling for one configured VIP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VipTlsMode {
    /// Forward bytes untouched; the agent never terminates TLS on this port.
    /// The default for operator-added ports — required for end-to-end TLS
    /// protocols (e.g. Wazuh enrollment on 1515) that the peer must see
    /// encrypted to its own certificate.
    #[default]
    Passthrough,
    /// Terminate the TLS handshake locally (the built-in 443/8443
    /// behaviour): the client sees a real TLS connection, the tunnel carries
    /// decrypted bytes.
    Terminate,
    /// Sniff the first bytes and terminate only when they look like a TLS
    /// ClientHello (the built-in behaviour for unknown ports).
    Auto,
}

/// One `[[tunnel.vip_ports]]` entry.
///
/// `tls` is optional and defaults to [`VipTlsMode::Passthrough`] when the
/// key is absent (the passthrough contract is the safe default for an
/// operator-added port: bytes cross the tunnel untouched).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VipPortConfig {
    /// Port to listen on, in `1..=65535` (validated at load).
    pub port: u16,
    /// TLS handling for this port.
    #[serde(default, deserialize_with = "deserialize_vip_tls_mode")]
    pub tls: VipTlsMode,
}

/// The `tls` field of a `[[tunnel.vip_ports]]` entry accepts the plain
/// string form (`tls = "auto"`), case-insensitive. An unknown string is a
/// parse error that names the value (fail at load, not at bind).
fn deserialize_vip_tls_mode<'de, D>(deserializer: D) -> Result<VipTlsMode, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    VipTlsMode::parse(&s).ok_or_else(|| {
        serde::de::Error::custom(format!(
            "unknown vip_ports TLS mode '{s}' (want passthrough, terminate or auto)"
        ))
    })
}

impl Default for VipPortConfig {
    fn default() -> Self {
        Self {
            port: 0,
            tls: VipTlsMode::Passthrough,
        }
    }
}

impl VipPortConfig {
    /// Parse a single `ZTLP_AGENT_VIP_PORTS` item (`port` or `port:tls`;
    /// `tls` defaults to `passthrough`).
    pub(crate) fn parse_item(item: &str) -> Result<Self, String> {
        let (port_s, tls_s) = match item.split_once(':') {
            Some((p, t)) => (p, t),
            None => (item, "passthrough"),
        };
        let port: u16 = port_s
            .trim()
            .parse()
            .map_err(|_| format!("invalid VIP port '{port_s}' (want 1..=65535)"))?;
        if port == 0 {
            return Err(format!(
                "invalid VIP port '{port_s}': port 0 is not allowed"
            ));
        }
        Ok(VipPortConfig {
            port,
            tls: VipTlsMode::parse(tls_s.trim())
                .ok_or_else(|| format!("invalid TLS mode '{tls_s}' for port {port} (want passthrough, terminate or auto)"))?,
        })
    }
}

impl VipTlsMode {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "passthrough" => Some(VipTlsMode::Passthrough),
            "terminate" => Some(VipTlsMode::Terminate),
            "auto" => Some(VipTlsMode::Auto),
            _ => None,
        }
    }

    /// Map onto the local TLS engine's mode. `Passthrough` is `Never` —
    /// `Never` returns the stream unwrapped and never peeks, so the bytes
    /// (e.g. an end-to-end TLS ClientHello) cross the tunnel untouched.
    pub fn as_tls_mode(self) -> TlsMode {
        match self {
            VipTlsMode::Passthrough => TlsMode::Never,
            VipTlsMode::Terminate => TlsMode::Always,
            VipTlsMode::Auto => TlsMode::Detect,
        }
    }
}

/// The resolved per-port VIP proxy policy: the effective listener list
/// (built-in eight ∪ configured ports, deduped and sorted) plus the
/// per-port TLS overrides. Built ONCE at daemon startup; the TCP proxy
/// passes it to every handler so there is a single source of truth for
/// both the TLS decision and the stall/504 decision.
///
/// A port is in the 504-class only when it is one of the four
/// built-in-HTTP-ish ports (80, 8080, 443, 8443) AND the agent terminates
/// TLS on it — only then can the deadline-expiry write half speak plain
/// HTTP to the client. A configured port, or a built-in port overridden
/// to `Passthrough`, must get the bare-close strategy: a 504 page through
/// an opaque byte pipe is nonsense (the 504-class decision must never
/// treat an unknown configured port as HTTP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VipPortPolicy {
    effective: Vec<u16>,
    overrides: std::collections::HashMap<u16, TlsMode>,
}

impl Default for VipPortPolicy {
    /// The no-configuration policy: the built-in eight, no overrides.
    fn default() -> Self {
        let mut effective: Vec<u16> = VIP_BUILTIN_PORTS.to_vec();
        effective.sort_unstable();
        Self {
            effective,
            overrides: std::collections::HashMap::new(),
        }
    }
}

impl VipPortPolicy {
    /// The ports the TCP proxy listens on for every VIP.
    pub fn effective_ports(&self) -> &[u16] {
        &self.effective
    }

    /// The resolved TLS mode for `port`: a configured override wins,
    /// otherwise the built-in port table.
    pub fn tls_mode(&self, port: u16) -> TlsMode {
        self.overrides
            .get(&port)
            .copied()
            .unwrap_or_else(|| local_tls::tls_mode_for_port(port))
    }

    /// The VIP accept-loop routing decision (PR #138 review): which
    /// handler a connection on `port` takes when a TLS acceptor is
    /// present.
    ///
    /// `Some(mode)` = route to the TLS-terminating handler
    /// (`handle_tcp_connection_with_tls`), which performs
    /// `maybe_wrap_tls` with `mode` — `Always` terminates
    /// unconditionally, `Detect` peeks the first bytes and terminates
    /// only when they look like a TLS ClientHello. `None` = the plain
    /// `proxy_dial_then_bridge` path (passthrough ports must NEVER peek
    /// or wrap — their bytes go through the tunnel untouched).
    ///
    /// A configured `auto` (`Detect`) override must therefore NOT be
    /// treated as `Never`: before the PR #138 fix, the accept loop's
    /// `tls_mode == Always` predicate sent every Detect port — including
    /// explicitly configured `auto` ports — down the plain path with no
    /// TLS detection at all, defeating the operator's `auto` choice.
    /// Legacy `Detect` ports the operator never configured (DB/RDP,
    /// where the built-in table says Detect) are preserved: they stay
    /// on the plain path with passthrough behavior exactly as before.
    pub fn tls_routing(&self, port: u16) -> Option<TlsMode> {
        if self.overrides.contains_key(&port) {
            match self.tls_mode(port) {
                TlsMode::Never => None,
                m => Some(m),
            }
        } else {
            match local_tls::tls_mode_for_port(port) {
                TlsMode::Always => Some(TlsMode::Always),
                // Built-in `Never` (SSH/HTTP) and `Detect` (DB/RDP):
                // the plain path, exactly as before.
                _ => None,
            }
        }
    }

    /// Deadline-expiry strategy for `port` under this policy.
    pub fn stall_close_strategy(&self, port: u16) -> super::daemon::StallCloseStrategy {
        super::daemon::vip_stall_close_strategy(port, &self.overrides)
    }
}

/// Deserialize `[[tunnel.vip_ports]]` as an array of tables, defaulting to
/// the empty list when the key is absent entirely.
fn deserialize_vip_ports<'de, D>(deserializer: D) -> Result<Vec<VipPortConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    <Vec<VipPortConfig> as serde::Deserialize>::deserialize(deserializer)
}

/// Parse the `ZTLP_AGENT_VIP_PORTS` environment override:
/// `port[:tls]` items, comma-separated, `tls` defaulting to
/// `passthrough` (e.g. `"1514:passthrough,1515"`).
///
/// Returns `Ok(None)` when the variable is unset or empty. Returns `Err`
/// (naming the offending item) when it is set but malformed — the daemon
/// treats that as a fatal config error at startup.
pub fn parse_vip_ports_env(value: &str) -> Result<Option<Vec<VipPortConfig>>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::new();
    for item in trimmed.split(',') {
        if item.trim().is_empty() {
            continue; // tolerate stray separators ("1514,,1515")
        }
        out.push(VipPortConfig::parse_item(item)?);
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

impl TunnelConfig {
    /// Build the resolved per-port policy over the built-in eight plus the
    /// configured `vip_ports`.
    ///
    /// The built-in ports always keep binding exactly as before; a
    /// `vip_ports` entry for a built-in port overrides that port's TLS mode
    /// only (no second listener, no duplicate in the effective list).
    /// Entries for new ports are added to the listener list.
    pub fn vip_ports_policy(&self) -> VipPortPolicy {
        let mut effective: Vec<u16> = VIP_BUILTIN_PORTS.to_vec();
        for entry in &self.vip_ports {
            if !effective.contains(&entry.port) {
                effective.push(entry.port);
            }
        }
        effective.sort_unstable();
        let mut overrides: std::collections::HashMap<u16, local_tls::TlsMode> =
            std::collections::HashMap::new();
        for entry in &self.vip_ports {
            overrides.insert(entry.port, entry.tls.as_tls_mode());
        }
        VipPortPolicy {
            effective,
            overrides,
        }
    }

    /// Resolved relay HMAC secret bytes, or `None` when unconfigured.
    pub fn relay_secret_bytes(&self) -> Option<Vec<u8>> {
        if let Some(s) = self.relay_secret.as_deref() {
            if !s.trim().is_empty() {
                return Some(crate::tunnel::decode_relay_secret(s));
            }
        }
        if let Some(path) = self.relay_secret_file.as_deref() {
            match std::fs::read_to_string(path) {
                Ok(contents) if !contents.trim().is_empty() => {
                    return Some(crate::tunnel::decode_relay_secret(&contents));
                }
                Ok(_) => {
                    tracing::warn!("[tunnel] relay_secret_file {} is empty; CLIENT_ROUTE frames will be unsigned", path);
                }
                Err(e) => {
                    tracing::warn!("[tunnel] cannot read relay_secret_file {}: {}; CLIENT_ROUTE frames will be unsigned", path, e);
                }
            }
        }
        None
    }
}

/// Credential renewal configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RenewalConfig {
    /// Enable automatic credential renewal.
    pub enabled: bool,

    /// How often the agent checks in with the NS (e.g., "1h", the default;
    /// minimum 60 s). Each accepted check-in restarts the enrolled device's
    /// one-year registration (see `agent::ns_checkin`).
    pub check_interval: String,

    /// Certificate renewal threshold (fraction of lifetime).
    pub cert_threshold: f64,

    /// NS record refresh at fraction of TTL. Not used by the check-in loop,
    /// which checks in every `check_interval`; kept so existing agent.toml
    /// files still parse.
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
            first_byte_timeout: "15s".to_string(),
            relay_secret: None,
            relay_secret_file: None,
            vip_ports: Vec::new(),
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
    /// Load agent config from `~/.ztlp/agent.toml`.
    ///
    /// A missing file yields defaults (a fresh box writes no `agent.toml`
    /// until `ztlp setup`); a file that exists but fails to parse is an
    /// error (see [`Self::load_from_path`]).
    pub fn load() -> Result<Self, String> {
        Self::load_from_default_path()
    }

    /// Load from the default path `~/.ztlp/agent.toml` (or
    /// `$ZTLP_HOME/.ztlp/agent.toml` when running as the Windows service —
    /// see [`ztlp_state_dir`]).
    fn load_from_default_path() -> Result<Self, String> {
        let path = ztlp_state_dir().join(".ztlp").join("agent.toml");
        Self::load_from_path(&path)
    }

    /// Load from a specific path.
    ///
    /// An ABSENT file is not an error: the agent runs on defaults (a
    /// freshly-installed box writes no `agent.toml` until `ztlp setup`).
    /// A file that EXISTS but cannot be read or parsed IS an error —
    /// silently substituting `Self::default()` would discard the operator's
    /// whole config (every `[tunnel] vip_ports` entry, the relay list,
    /// everything else in the file) and start a daemon that does not match
    /// what the operator wrote. Malformed `vip_ports` in particular must
    /// stop startup (PR #138 review), not vanish into defaults.
    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        // Read the file DIRECTLY and key the absent-vs-broken decision on
        // the read's error kind, not on `Path::exists()`: `exists()` returns
        // `false` for a file the service account cannot reach (a parent
        // directory the account lacks +x on), which would let a present
        // `agent.toml` read as "absent" and silently fall back to defaults —
        // defeating the fail-closed behaviour. Only a genuine `NotFound`
        // means absent. (PR #138 review #3)
        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!("no agent config at {}, using defaults", path.display());
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(format!(
                    "failed to read agent config {}: {} — startup will not continue \
                     with defaults",
                    path.display(),
                    e
                ))
            }
        };
        let cfg: Self = toml::from_str(&contents).map_err(|e| {
            format!(
                "failed to parse agent config {}: {} — fixing the file is required; \
                 startup will not continue with defaults",
                path.display(),
                e
            )
        })?;
        tracing::debug!("loaded agent config from {}", path.display());
        Ok(cfg)
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

    /// Load agent config, backfilling any field the agent config leaves at
    /// its default from the CLI's `~/.ztlp/config.toml`.
    ///
    /// ## Why this exists
    ///
    /// `ztlp setup --token ... --yes` writes the enrolled zone's
    /// `ns_server`/`relay`/`identity` to `~/.ztlp/config.toml`. `ztlp agent
    /// start` — including the invocation the desktop app's "Connect" button
    /// makes, with no `-c` flag — only ever read `~/.ztlp/agent.toml`, a
    /// file `setup` never writes. A freshly-enrolled device's agent daemon
    /// therefore silently started against `AgentConfig::default()`
    /// (`127.0.0.1:23096`, no relay) instead of the zone the user just
    /// joined, and every tunnel attempt failed or hit the wrong network
    /// entirely. `load_merged` closes that gap without requiring the
    /// operator to hand-author `agent.toml`: real `agent.toml` values are
    /// never overridden, only fields still at their bare struct default are
    /// backfilled from `config.toml`.
    pub fn load_merged(agent_config_path: &Path, cli_config_path: &Path) -> Result<Self, String> {
        let mut cfg = Self::load_from_path(agent_config_path)?;
        let cli = CliConfigForMerge::load(cli_config_path);

        if cfg.ns.servers == NsConfig::default().servers {
            if let Some(ns_server) = cli.ns_server {
                cfg.ns.servers = vec![ns_server];
            }
        }
        if cfg.tunnel.relays.0.is_empty() {
            if let Some(relay) = cli.relay {
                cfg.tunnel.relays = RelayAddrs(vec![relay]);
            }
        }
        if cfg.identity.path == IdentityConfig::default().path {
            if let Some(identity) = cli.identity {
                cfg.identity.path = identity;
            }
        }

        Ok(cfg)
    }

    /// Validate `[tunnel] vip_ports`, returning a readable error that
    /// NAMES the offending entry.
    ///
    /// Checked (in order, first failure wins):
    /// - duplicate `port` entries (an override and a duplicate are the
    ///   same shape — one entry per port, never two);
    /// - `port = 0` (a real socket port is 1..=65535; the `u16` type
    ///   already rules out >65535);
    /// - more than [`VIP_PORTS_MAX`] entries (every VIP binds every port,
    ///   so listeners = VIPs × ports);
    /// - collision with the agent's OWN loopback listeners: a `vip_port`
    ///   equal to the `[dns] listen` or `[ipc] listen` port when that
    ///   listener's IP is inside the configured `[dns] vip_range` (the
    ///   VIP pool would hand out an address the agent itself binds).
    pub fn validate_vip_ports(&self) -> Result<(), String> {
        let ports = &self.tunnel.vip_ports;

        // Cap first: the listener combinator (VIPs × ports) grows with
        // this, and an oversized list is the most operator-visible error.
        if ports.len() > VIP_PORTS_MAX {
            return Err(format!(
                "[tunnel] vip_ports: at most {VIP_PORTS_MAX} entries are allowed (got {}); \
                 every VIP binds every listed port",
                ports.len()
            ));
        }

        // Duplicates and port 0 (named).
        let mut seen = std::collections::HashSet::new();
        for entry in ports {
            if entry.port == 0 {
                return Err("[tunnel] vip_ports: port 0 is not a valid socket port".to_string());
            }
            if !seen.insert(entry.port) {
                return Err(format!(
                    "[tunnel] vip_ports: duplicate port {} (one entry per port)",
                    entry.port
                ));
            }
        }

        // Collisions with the agent's own loopback listeners, but only
        // when that listener's IP actually falls in the VIP range — a
        // DNS listener on 127.0.0.53:5353 never collides with a 127.100.x.x
        // VIP.
        let vip_base: u32 = match parse_vip_range_base(&self.dns.vip_range) {
            Some(b) => b,
            None => {
                // Unparseable vip_range is reported by the daemon when it
                // builds the pool; the collision check can't apply.
                return Ok(());
            }
        };
        let vip_prefix: Option<u8> = self
            .dns
            .vip_range
            .rsplit_once('/')
            .and_then(|(_, p)| p.parse().ok());
        let in_vip_range = |ip: &str| {
            let Ok(ip_num) = ip.parse::<std::net::Ipv4Addr>() else {
                return false;
            };
            let mask = match vip_prefix {
                Some(n) => u32::MAX << (32 - n.min(32)),
                None => u32::MAX,
            };
            (u32::from(ip_num) & mask) == (vip_base & mask)
        };

        for entry in ports {
            let port = entry.port;
            for (label, listen) in [("dns", &self.dns.listen), ("ipc", &self.ipc.listen)] {
                if let Some((ip, p)) = listen.rsplit_once(':') {
                    if let Ok(p) = p.parse::<u16>() {
                        if p == port && in_vip_range(ip) {
                            return Err(format!(
                                "[tunnel] vip_ports: port {port} collides with the agent's own \
                                 [{label}] listener {listen} (its IP {ip} is inside the VIP \
                                 range {})",
                                self.dns.vip_range
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Parse the base address of a CIDR string (e.g. "127.100.0.0/16" → the
/// numeric base), or `None` when it is not a valid `a.b.c.d/len`.
fn parse_vip_range_base(cidr: &str) -> Option<u32> {
    let (ip_s, prefix_s) = cidr.rsplit_once('/')?;
    prefix_s.parse::<u8>().ok()?;
    ip_s.parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

/// Minimal shape of the CLI's `~/.ztlp/config.toml`, used only to backfill
/// [`AgentConfig::load_merged`]. Deliberately narrow — the CLI's `Config`
/// struct (in `bin/ztlp-cli.rs`) is the source of truth for that file's full
/// schema; this is just the handful of fields the agent daemon also cares
/// about.
#[derive(Debug, Default, Deserialize)]
struct CliConfigForMerge {
    #[serde(default)]
    identity: Option<String>,
    #[serde(default)]
    relay: Option<String>,
    #[serde(default)]
    ns_server: Option<String>,
}

impl CliConfigForMerge {
    /// Load from `path`, falling back to all-`None` on any error (missing
    /// file, malformed TOML). This backfill source stays fail-open: the CLI
    /// config only backfills fields the operator never set in `agent.toml`,
    /// so a broken/missing `config.toml` must never block startup — the
    /// operator's own `agent.toml` IS fail-closed (see
    /// [`AgentConfig::load_from_path`]).
    fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }
}

/// Expand `~` prefix to the ZTLP state root, NOT the raw OS home dir.
///
/// D5 live-test fix (2026-09-21): this used to call `dirs::home_dir()`
/// directly, completely bypassing `ztlp_state_dir()`'s `ZTLP_HOME` check
/// (D1). Effect: `AgentConfig::default().identity_path()` — what
/// `run_agent_lifecycle`'s pre-standby check and `run_unenrolled_standby`'s
/// poll loop use to detect "has enrollment finished yet?" — resolved to
/// `C:\Windows\System32\config\systemprofile\.ztlp\identity.json` under
/// the Windows service (LocalSystem's real home dir), while `ztlp setup`'s
/// re-exec subprocess (inheriting `ZTLP_HOME`, correctly routed through
/// `ztlp_state_dir()` everywhere else) wrote the real file to
/// `C:\ProgramData\ZTLP\.ztlp\identity.json`. The standby loop polled a
/// path the file could never appear at and never handed over to the full
/// daemon — reproduced live on 10.170.3.207: `enroll` returned
/// `tls_provisioned: true` (the subprocess genuinely succeeded) but
/// `setup_status` kept reporting `standby: true, enrolled: false` forever.
fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") || path == "~" {
        return ztlp_state_dir().join(&path[2..]);
    }
    PathBuf::from(path)
}

/// Resolve the directory that owns `.ztlp/...` state (agent.toml,
/// identity.json, ca/, agent.token, vip_state.json, agent.pid).
///
/// Resolution order (Phase D plan D1,
/// `docs/handoffs/WINDOWS-SERVICE-PARITY-PHASE-D-PLAN-2026-09-21.md`):
/// 1. [`crate::agent::windows_daemon::ZTLP_HOME_ENV_VAR`] (`ZTLP_HOME`) if
///    set — this is what `ztlp-winsvc.rs`'s `main()` sets unconditionally on
///    Windows so the SCM service process resolves everything under
///    `C:\ProgramData\ZTLP` instead of LocalSystem's profile
///    (`C:\Windows\System32\config\systemprofile`, which is NOT the
///    enrolled user's `C:\Users\<user>\.ztlp`). This is the Windows
///    analogue of the macOS LaunchDaemon plist pinning `HOME` — same goal,
///    different mechanism, because `dirs::home_dir()` on Windows resolves
///    via `SHGetKnownFolderPath(FOLDERID_Profile)`, which does NOT reliably
///    honor a bare `HOME`/`USERPROFILE` env override the way Unix does.
/// 2. `dirs::home_dir()` — unchanged behavior for the CLI, the foreground
///    dev-mode agent, and every macOS/Linux path (they never set
///    `ZTLP_HOME`, so this always falls through to the prior behavior).
/// 3. `.` (current dir) as an absolute last resort, matching the existing
///    per-call-site fallbacks this replaces.
///
/// Callers that used to write `dirs::home_dir().map(|h|
/// h.join(".ztlp").join(...)).unwrap_or_else(...)` should call this once
/// and `.join(...)` onto the result instead — one resolution point instead
/// of N copies that could drift.
pub fn ztlp_state_dir() -> PathBuf {
    if let Ok(override_home) = std::env::var("ZTLP_HOME") {
        if !override_home.is_empty() {
            return PathBuf::from(override_home);
        }
    }
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

/// Parse a short duration string like `"30s"`, `"5m"`, `"2h"`, or `"1d"`.
///
/// Used to interpret `[tunnel].idle_timeout`, `[tunnel].keepalive_interval`,
/// and similar config fields. The format is a sequence of ASCII digits
/// followed by exactly one unit suffix:
///
/// - `s` — seconds
/// - `m` — minutes
/// - `h` — hours
/// - `d` — days (24h)
///
/// Bare numbers (no unit), the empty string, unknown units, and any
/// non-numeric prefix are all rejected — we'd rather force the operator
/// to spell out the unit than silently treat `"30"` as either seconds or
/// milliseconds and surprise them later.
///
/// # Examples
///
/// ```ignore
/// use std::time::Duration;
/// assert_eq!(parse_duration_str("5m").unwrap(), Duration::from_secs(300));
/// assert!(parse_duration_str("30").is_err());
/// ```
pub fn parse_duration_str(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }
    // Split into trailing unit char and leading numeric portion.
    let last = s
        .chars()
        .next_back()
        .ok_or_else(|| "empty duration string".to_string())?;
    let (num_part, unit_secs) = match last {
        's' => (&s[..s.len() - 1], 1u64),
        'm' => (&s[..s.len() - 1], 60u64),
        'h' => (&s[..s.len() - 1], 60 * 60),
        'd' => (&s[..s.len() - 1], 24 * 60 * 60),
        _ => {
            return Err(format!(
                "invalid duration '{}': expected suffix s/m/h/d, got '{}'",
                s, last
            ));
        }
    };
    if num_part.is_empty() {
        return Err(format!("invalid duration '{}': missing numeric value", s));
    }
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("invalid duration '{}': {}", s, e))?;
    let secs = n
        .checked_mul(unit_secs)
        .ok_or_else(|| format!("invalid duration '{}': value is too large", s))?;
    Ok(Duration::from_secs(secs))
}

/// Default path to the per-install control-plane Bearer token file.
///
/// Resolution order:
/// 1. `ZTLP_AGENT_TOKEN_PATH` env var if set — most specific, wins over
///    everything (used by tests and anywhere the exact file path matters
///    independent of the state dir).
/// 2. [`ztlp_state_dir`]`/.ztlp/agent.token` — honors `ZTLP_HOME` when set
///    (Windows service), else `~/.ztlp/agent.token` (unchanged behavior).
/// 3. `/tmp/ztlp-agent.token` as a last-resort fallback — mirrors the
///    `control::default_pid_path` pattern, only reachable if `ztlp_state_dir`
///    itself fell all the way through to `.` AND that's somehow unusable.
///
/// The file itself is materialized (and chmodded 0o600 on unix) by
/// `daemon::ensure_token_file`.
pub fn default_token_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("ZTLP_AGENT_TOKEN_PATH") {
        if !override_path.is_empty() {
            return PathBuf::from(override_path);
        }
    }
    let dir = ztlp_state_dir();
    if dir == PathBuf::from(".") {
        return PathBuf::from("/tmp/ztlp-agent.token");
    }
    dir.join(".ztlp").join("agent.token")
}

/// Where the agent persists name→VIP allocations across restarts.
pub fn vip_state_path() -> PathBuf {
    let dir = ztlp_state_dir();
    if dir == PathBuf::from(".") {
        return PathBuf::from("/tmp/ztlp-vip-state.json");
    }
    dir.join(".ztlp").join("vip_state.json")
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
///
/// D5 live-test fix (2026-09-21): on Windows, a NON-service caller (the
/// `ztlp` CLI run interactively, the desktop GUI) has no `ZTLP_HOME` set,
/// so `default_token_path()` resolves under `%USERPROFILE%\.ztlp\` — a
/// file the ZtlpAgent service (which DOES have `ZTLP_HOME` pinned to
/// `C:\ProgramData\ZTLP`, D1) never writes. Without this fallback, EVERY
/// non-service Windows caller reports `agent token not found` even with
/// the service running and healthy — reproduced live on 10.170.3.207
/// (`ztlp.exe agent status` against a freshly-installed, running
/// ZtlpAgent service). Try the service's fixed path first when it
/// differs from our own, then fall back to the (already-checked) own
/// path — this covers a foreground `ztlp.exe agent start` dev install
/// where there is no service and the CLI's own path is genuinely right.
pub fn load_agent_token() -> Option<String> {
    let path = default_token_path();
    // 2026-09-28 live fix: the own path used to be tried FIRST, which
    // contradicted the doc above. On a box that ever ran a user-context
    // agent, %USERPROFILE%\.ztlp\agent.token exists but is STALE, so the
    // GUI sent the wrong bearer to the service and every call came back
    // `unauthorized` (UI stuck on "Service: Not installed"). Service path
    // first, own path as the fallback.
    #[cfg(target_os = "windows")]
    let candidates = if std::env::var(crate::agent::windows_daemon::ZTLP_HOME_ENV_VAR).is_ok() {
        vec![path]
    } else {
        crate::agent::windows_daemon::gui_token_candidates(path)
    };
    // PR #112 review fix: the Linux systemd service keeps its token at
    // /var/lib/ztlp/.ztlp/agent.token (HOME pinned by the unit); the GUI
    // must try that before its own ~/.ztlp path.
    #[cfg(target_os = "linux")]
    let candidates = crate::agent::linux_daemon::gui_token_candidates(path);
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let candidates = vec![path];
    load_first_token(&candidates)
}

/// First non-empty token among `candidates`, in order. Pure over the
/// filesystem so the precedence rule is unit-testable on every platform.
pub fn load_first_token(candidates: &[PathBuf]) -> Option<String> {
    candidates.iter().find_map(|c| read_token_file(c))
}

fn read_token_file(path: &std::path::Path) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Shared lock guarding `ZTLP_HOME` env mutation across ALL test modules
/// that touch it (`config::tests` and `windows_daemon::tests`) — env vars
/// are process-global, and cargo test runs test fns in parallel threads by
/// default, so two modules each with their own private mutex would still
/// race each other. One shared lock serializes every test that reads or
/// writes `ZTLP_HOME`.
#[cfg(test)]
pub(crate) static ZTLP_HOME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ztlp_state_dir_prefers_ztlp_home_env_when_set() {
        let _guard = ZTLP_HOME_TEST_LOCK.lock().unwrap();
        std::env::set_var("ZTLP_HOME", "/tmp/ztlp-home-test-marker");
        let dir = ztlp_state_dir();
        std::env::remove_var("ZTLP_HOME");
        assert_eq!(dir, PathBuf::from("/tmp/ztlp-home-test-marker"));
    }

    #[test]
    fn ztlp_state_dir_falls_back_to_dirs_home_dir_when_ztlp_home_unset() {
        let _guard = ZTLP_HOME_TEST_LOCK.lock().unwrap();
        std::env::remove_var("ZTLP_HOME");
        let dir = ztlp_state_dir();
        // Unchanged behavior: whatever dirs::home_dir() returns in this
        // environment (never ".", since a real home dir exists in CI/dev).
        assert_ne!(dir, PathBuf::from("."));
        assert_eq!(dir, dirs::home_dir().unwrap());
    }

    #[test]
    fn load_first_token_prefers_earlier_candidate_even_if_later_exists() {
        // Regression (2026-09-28): a stale user-profile token must NOT win
        // over the service token that comes first in the candidate list.
        let dir = std::env::temp_dir().join(format!("ztlp-tok-order-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let service = dir.join("service.token");
        let stale = dir.join("stale.token");
        std::fs::write(&service, "servicetoken\n").unwrap();
        std::fs::write(&stale, "staletoken").unwrap();
        assert_eq!(
            load_first_token(&[service.clone(), stale.clone()]).as_deref(),
            Some("servicetoken")
        );
        // Missing/empty first candidate falls through to the next.
        std::fs::write(&service, "  \n").unwrap();
        assert_eq!(
            load_first_token(&[service, stale]).as_deref(),
            Some("staletoken")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn gui_token_candidates_put_service_path_first() {
        let own = PathBuf::from(r"C:\Users\trs\.ztlp\agent.token");
        let c = crate::agent::windows_daemon::gui_token_candidates(own.clone());
        assert_eq!(
            c[0],
            crate::agent::windows_daemon::windows_system_token_path()
        );
        assert_eq!(c.last(), Some(&own));
    }

    #[test]
    fn default_token_path_honors_ztlp_home_when_ztlp_agent_token_path_unset() {
        let _guard = ZTLP_HOME_TEST_LOCK.lock().unwrap();
        std::env::remove_var("ZTLP_AGENT_TOKEN_PATH");
        std::env::set_var("ZTLP_HOME", "/tmp/ztlp-home-test-marker");
        let p = default_token_path();
        std::env::remove_var("ZTLP_HOME");
        assert_eq!(
            p,
            PathBuf::from("/tmp/ztlp-home-test-marker/.ztlp/agent.token")
        );
    }

    // ── [tunnel] relay_secret (2026-09-13) ─────────────────────────────
    // The relay in prod HMAC mode rejects unsigned CLIENT_ROUTE frames.
    // The agent must be able to carry the relay's shared secret in
    // agent.toml so the automatic VIP dialer can sign them.
    #[test]
    fn tunnel_relay_secret_defaults_to_none() {
        let cfg = AgentConfig::default();
        assert!(cfg.tunnel.relay_secret.is_none());
        assert!(cfg.tunnel.relay_secret_bytes().is_none());
    }

    #[test]
    fn tunnel_relay_secret_parses_and_decodes_hex() {
        let toml_str = r#"
[tunnel]
relays = ["44.240.16.59:23095"]
relay_secret = "06984504bf07f1cd8462fd9909dcd39cd3e04beb96100a3bbe45eb6113025103"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).unwrap();
        let bytes = cfg.tunnel.relay_secret_bytes().expect("secret configured");
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x06);
    }

    #[test]
    fn tunnel_relay_secret_file_is_read_and_trimmed() {
        let tmp = std::env::temp_dir().join(format!("ztlp-relay-secret-{}", std::process::id()));
        std::fs::write(&tmp, "supersecretkey\n").unwrap();
        let toml_str = format!(
            "[tunnel]\nrelay_secret_file = \"{}\"\n",
            tmp.display().to_string().replace('\\', "/")
        );
        let cfg: AgentConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(
            cfg.tunnel.relay_secret_bytes().unwrap(),
            b"supersecretkey".to_vec()
        );
        let _ = std::fs::remove_file(&tmp);
    }

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
    fn expand_tilde_honors_ztlp_home_override() {
        // D5 live-test fix (2026-09-21): expand_tilde must resolve `~`
        // through ztlp_state_dir() (ZTLP_HOME-aware), not dirs::home_dir()
        // directly — otherwise AgentConfig::default().identity_path()
        // disagrees with every OTHER ZTLP_HOME-routed path (config.rs's
        // own token/vip_state paths, ca_trust.rs, control.rs, ztlp-cli.rs)
        // about where the Windows service's state actually lives, and the
        // unenrolled-standby poll loop watches a file that can never
        // appear. Reproduced live: `enroll` succeeded (tls_provisioned:
        // true) but `setup_status` stayed `standby: true` forever because
        // this exact function was watching the wrong directory.
        let _guard = ZTLP_HOME_TEST_LOCK.lock().unwrap();
        std::env::set_var("ZTLP_HOME", "/tmp/ztlp-expand-tilde-test-marker");
        let result = expand_tilde("~/.ztlp/identity.json");
        std::env::remove_var("ZTLP_HOME");
        assert_eq!(
            result,
            PathBuf::from("/tmp/ztlp-expand-tilde-test-marker/.ztlp/identity.json")
        );
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
        let cfg = AgentConfig::load_from_path(Path::new("/nonexistent/agent.toml")).unwrap();
        // Should return defaults without error
        assert_eq!(cfg.dns.listen, "127.0.0.53:5353");
    }

    // ── PR #138 review (CodeRabbit): a malformed vip_ports entry (e.g. an
    // invalid `tls` value) must STOP startup with the parse error named, not
    // be silently discarded in favor of AgentConfig::default() (which drops
    // every other setting from agent.toml too). ────────────────────────────

    #[test]
    fn test_load_from_path_malformed_vip_tls_stops_startup_instead_of_silently_defaulting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        write_file(
            &path,
            r#"
[tunnel]
[[tunnel.vip_ports]]
port = 9000
tls = "nope"
"#,
        );

        // The file EXISTS, so the "absent -> defaults" rule does not apply:
        // a parse failure must surface as a startup error naming the file and
        // the offending value — never as a silent Self::default() that drops
        // the operator's whole config.
        let err = AgentConfig::load_from_path(&path)
            .expect_err("malformed agent.toml must fail startup, not load defaults");
        let msg = err.to_string();
        assert!(
            msg.contains("nope"),
            "error must name the offending tls value, got: {msg}"
        );
        assert!(
            msg.contains("agent.toml"),
            "error must name the config file, got: {msg}"
        );
    }

    #[test]
    fn test_load_from_path_valid_vip_ports_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        write_file(
            &path,
            r#"
[tunnel]
[[tunnel.vip_ports]]
port = 1514
tls = "passthrough"
"#,
        );

        let cfg = AgentConfig::load_from_path(&path).expect("valid vip_ports must load");
        assert_eq!(cfg.tunnel.vip_ports.len(), 1);
        assert_eq!(cfg.tunnel.vip_ports[0].port, 1514);
    }

    // ── PR #138 review #3: a PRESENT-but-unreadable agent.toml must FAIL
    // CLOSED, not read as "absent" (→ defaults). `Path::exists()` is `false`
    // for a file the account cannot reach, so the loader must key on the
    // read's error kind, not `exists()`: only `NotFound` means absent.
    //
    // This verifies the DECISION hermetically (no real permission drop
    // needed): a file whose `read_to_string` returns a NON-`NotFound` error
    // must produce a `load_from_path` error, and `exists()` must still report
    // it as present (the old code's `exists()` guard would have skipped it).
    #[test]
    fn test_load_from_path_present_but_unreadable_fails_closed() {
        // A directory: `read_to_string` fails with IsADirectory (NOT
        // NotFound) and `exists()` is true — the exact shape of an
        // "unreadable but present" file. The loader must fail closed.
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path(); // exists, but reading it as a file errors
        let res = AgentConfig::load_from_path(target);
        assert!(res.is_err(), "a present-but-unreadable config must error");
        assert!(
            target.exists(),
            "the path must still exist (only a genuine NotFound means absent)"
        );
        assert!(
            res.unwrap_err().contains("failed to read"),
            "the error must name the read failure, not fall back to defaults"
        );
    }

    // ── D3.T2: parse_duration_str ───────────────────────────────────────

    #[test]
    fn test_parse_duration_str_seconds() {
        assert_eq!(
            parse_duration_str("30s").unwrap(),
            std::time::Duration::from_secs(30)
        );
    }

    #[test]
    fn test_parse_duration_str_minutes() {
        assert_eq!(
            parse_duration_str("5m").unwrap(),
            std::time::Duration::from_secs(5 * 60)
        );
    }

    #[test]
    fn test_parse_duration_str_hours_and_days() {
        assert_eq!(
            parse_duration_str("2h").unwrap(),
            std::time::Duration::from_secs(2 * 60 * 60)
        );
        assert_eq!(
            parse_duration_str("1d").unwrap(),
            std::time::Duration::from_secs(24 * 60 * 60)
        );
    }

    #[test]
    fn test_parse_duration_str_rejects_bare_number_and_garbage() {
        // Bare number — no unit suffix — must be rejected.
        assert!(parse_duration_str("30").is_err());
        // Empty string.
        assert!(parse_duration_str("").is_err());
        // Unknown unit.
        assert!(parse_duration_str("5y").is_err());
        // Non-numeric leading characters.
        assert!(parse_duration_str("abc").is_err());
    }

    #[test]
    fn test_parse_duration_str_rejects_overflow() {
        // CodeRabbit #1 (config.rs:520): n * unit_secs would wrap on huge inputs
        // and silently produce a smaller-than-requested timeout. The checked_mul
        // path must reject these instead of wrapping.
        let huge = format!("{}m", u64::MAX);
        let err = parse_duration_str(&huge).unwrap_err();
        assert!(
            err.contains("too large"),
            "expected overflow error, got: {}",
            err
        );
    }

    // ── `ztlp setup` / agent config bridge (2026-08-30) ─────────────────────
    //
    // `ztlp setup --token ... --yes` writes ~/.ztlp/config.toml with the
    // enrolled zone's ns_server/relay/identity. `ztlp agent start` (spawned
    // by the desktop app's "Connect" button, with no `-c` flag) only ever
    // read ~/.ztlp/agent.toml — a DIFFERENT file that setup never writes —
    // so a freshly-enrolled device's agent silently fell back to
    // AgentConfig::default() (ns_server 127.0.0.1:23096, no relay), pointing
    // at nothing related to the zone the user just joined. `load_merged`
    // closes that gap: when agent.toml is absent/incomplete, missing fields
    // are backfilled from the CLI's config.toml, without ever overriding an
    // explicit agent.toml value.

    fn write_file(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn test_load_merged_backfills_from_cli_config_when_agent_toml_absent() {
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent.toml"); // does not exist
        let cli_path = dir.path().join("config.toml");
        write_file(
            &cli_path,
            r#"
identity = "/home/user/.ztlp/identity.json"
ns_server = "34.221.165.244:24096"
relay = "34.221.165.244:24095"
zone = "demo.spongebob.ztlp"
"#,
        );

        let cfg = AgentConfig::load_merged(&agent_path, &cli_path).unwrap();

        assert_eq!(cfg.ns_server(), "34.221.165.244:24096");
        assert_eq!(
            cfg.tunnel.relays.0.first().map(String::as_str),
            Some("34.221.165.244:24095")
        );
        assert_eq!(
            cfg.identity_path(),
            PathBuf::from("/home/user/.ztlp/identity.json")
        );
    }

    #[test]
    fn test_load_merged_prefers_explicit_agent_toml_over_cli_config() {
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent.toml");
        let cli_path = dir.path().join("config.toml");
        write_file(
            &agent_path,
            r#"
[ns]
servers = ["10.0.0.1:23096"]
"#,
        );
        write_file(
            &cli_path,
            r#"
ns_server = "34.221.165.244:24096"
relay = "34.221.165.244:24095"
"#,
        );

        let cfg = AgentConfig::load_merged(&agent_path, &cli_path).unwrap();

        // Explicit agent.toml value wins — never silently overridden.
        assert_eq!(cfg.ns_server(), "10.0.0.1:23096");
        // But tunnel.relay, which agent.toml never set, is still backfilled.
        assert_eq!(
            cfg.tunnel.relays.0.first().map(String::as_str),
            Some("34.221.165.244:24095")
        );
    }

    #[test]
    fn test_load_merged_falls_back_to_defaults_when_neither_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent.toml");
        let cli_path = dir.path().join("config.toml");

        let cfg = AgentConfig::load_merged(&agent_path, &cli_path).unwrap();

        assert_eq!(cfg.ns_server(), "127.0.0.1:23096");
        assert!(cfg.tunnel.relays.0.is_empty());
    }

    #[test]
    fn test_load_merged_ignores_malformed_cli_config_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent.toml");
        let cli_path = dir.path().join("config.toml");
        write_file(&cli_path, "not valid toml {{{");

        let cfg = AgentConfig::load_merged(&agent_path, &cli_path).unwrap();

        // Malformed CLI config must not panic and must not poison agent
        // defaults — falls back exactly as if the file were absent.
        assert_eq!(cfg.ns_server(), "127.0.0.1:23096");
    }

    // ── [tunnel] vip_ports: operator-configurable VIP proxy ports ──────
    // The design: `[[tunnel.vip_ports]]` (or `ZTLP_AGENT_VIP_PORTS`) adds
    // listeners beyond the built-in eight, with a per-port TLS mode
    // (passthrough / terminate / auto). Passthrough must NEVER terminate
    // TLS and must NEVER emit a 504 page (bare close only). Bad configs
    // fail at STARTUP with the offending entry named.
    use super::{
        parse_vip_ports_env, VipPortConfig, VipPortPolicy, VipTlsMode, VIP_BUILTIN_PORTS,
        VIP_PORTS_MAX,
    };
    use crate::agent::daemon::{vip_stall_close_strategy, StallCloseStrategy};
    use crate::agent::local_tls::TlsMode;

    fn vpc(port: u16, tls: VipTlsMode) -> VipPortConfig {
        VipPortConfig { port, tls }
    }

    fn cfg_with_ports(ports: Vec<VipPortConfig>) -> AgentConfig {
        let mut cfg = AgentConfig::default();
        cfg.tunnel.vip_ports = ports;
        cfg
    }

    // ── VipTlsMode ─────────────────────────────────────────────────────

    #[test]
    // tls_routing: the VIP accept-loop handler choice (PR #138
    // review, daemon.rs:1684)
    fn tls_routing_configured_auto_port_reaches_the_detecting_path() {
        // The exact PR #138 bug: a configured `auto` override must route
        // to the TLS-detecting handler (Some(Detect)), not the plain
        // passthrough path (None) with no TLS detection at all.
        let policy = cfg_with_ports(vec![vpc(9443, VipTlsMode::Auto)])
            .tunnel
            .vip_ports_policy();
        assert_eq!(policy.tls_routing(9443), Some(TlsMode::Detect));
    }

    #[test]
    fn tls_routing_configured_terminate_routes_to_always_terminating() {
        let policy = cfg_with_ports(vec![vpc(9443, VipTlsMode::Terminate)])
            .tunnel
            .vip_ports_policy();
        assert_eq!(policy.tls_routing(9443), Some(TlsMode::Always));
    }

    #[test]
    fn tls_routing_configured_passthrough_stays_on_the_plain_path() {
        // Passthrough ports (Wazuh 1514/1515 etc.) must NEVER enter the
        // TLS-terminating handler: None, whatever the built-in table says.
        let policy = cfg_with_ports(vec![
            vpc(1514, VipTlsMode::Passthrough),
            // A passthrough override even on a built-in Always port:
            // the operator's explicit choice wins (443 passthrough =
            // opaque byte pipe, no local TLS termination).
            vpc(443, VipTlsMode::Passthrough),
        ])
        .tunnel
        .vip_ports_policy();
        assert_eq!(policy.tls_routing(1514), None);
        assert_eq!(policy.tls_routing(443), None);
    }

    #[test]
    fn tls_routing_legacy_unconfigured_ports_keep_their_existing_behavior() {
        // No vip_ports configured at all: built-in Always ports
        // terminate locally (as before), built-in Never and Detect
        // ports stay on the plain path with passthrough behavior
        // exactly as before (DB/RDP are NOT suddenly TLS-wrapped).
        let policy = VipPortPolicy::default();
        assert_eq!(policy.tls_routing(443), Some(TlsMode::Always));
        assert_eq!(policy.tls_routing(8443), Some(TlsMode::Always));
        assert_eq!(policy.tls_routing(22), None);
        assert_eq!(policy.tls_routing(80), None);
        assert_eq!(policy.tls_routing(8080), None);
        // Legacy Detect (unconfigured DB/RDP): plain path, unchanged.
        assert_eq!(policy.tls_routing(3306), None);
        assert_eq!(policy.tls_routing(5432), None);
        assert_eq!(policy.tls_routing(3389), None);
    }

    #[test]
    fn vip_tls_mode_defaults_to_passthrough() {
        assert_eq!(VipTlsMode::default(), VipTlsMode::Passthrough);
    }

    #[test]
    fn vip_tls_mode_maps_onto_the_local_tls_engine() {
        // Passthrough is `Never`: the engine returns the stream unwrapped
        // and never peeks, so bytes (an end-to-end TLS ClientHello) cross
        // the tunnel untouched.
        assert_eq!(VipTlsMode::Passthrough.as_tls_mode(), TlsMode::Never);
        assert_eq!(VipTlsMode::Terminate.as_tls_mode(), TlsMode::Always);
        assert_eq!(VipTlsMode::Auto.as_tls_mode(), TlsMode::Detect);
    }

    // ── ZTLP_AGENT_VIP_PORTS env parsing ───────────────────────────────

    #[test]
    fn vip_ports_env_parses_port_and_tls_items() {
        let got = parse_vip_ports_env("1514:passthrough,1515")
            .unwrap()
            .unwrap();
        assert_eq!(
            got,
            vec![
                vpc(1514, VipTlsMode::Passthrough),
                vpc(1515, VipTlsMode::Passthrough)
            ]
        );
    }

    #[test]
    fn vip_ports_env_accepts_all_three_modes_case_insensitively() {
        let got = parse_vip_ports_env("100:terminate,101:AUTO,102:Terminate")
            .unwrap()
            .unwrap();
        assert_eq!(got[0].tls, VipTlsMode::Terminate);
        assert_eq!(got[1].tls, VipTlsMode::Auto);
        assert_eq!(got[2].tls, VipTlsMode::Terminate);
    }

    #[test]
    fn vip_ports_env_defaults_to_passthrough_when_mode_omitted() {
        let got = parse_vip_ports_env("1515").unwrap().unwrap();
        assert_eq!(got, vec![vpc(1515, VipTlsMode::Passthrough)]);
    }

    #[test]
    fn vip_ports_env_returns_none_when_unset_or_empty() {
        assert_eq!(parse_vip_ports_env("").unwrap(), None);
        assert_eq!(parse_vip_ports_env("   \t ").unwrap(), None);
        assert_eq!(parse_vip_ports_env(",,").unwrap(), None);
    }

    #[test]
    fn vip_ports_env_tolerates_stray_separators() {
        let got = parse_vip_ports_env("1514,,1515").unwrap().unwrap();
        assert_eq!(
            got,
            vec![
                vpc(1514, VipTlsMode::Passthrough),
                vpc(1515, VipTlsMode::Passthrough)
            ]
        );
    }

    #[test]
    fn vip_ports_env_rejects_port_zero_and_names_it() {
        let err = parse_vip_ports_env("0:passthrough").unwrap_err();
        assert!(
            err.contains("0"),
            "error must name the offending item: {err}"
        );
    }

    #[test]
    fn vip_ports_env_rejects_non_numeric_port_and_names_it() {
        let err = parse_vip_ports_env("abc").unwrap_err();
        assert!(
            err.contains("abc"),
            "error must name the offending item: {err}"
        );
    }

    #[test]
    fn vip_ports_env_rejects_out_of_range_port_and_names_it() {
        // 65536 does not fit a u16, so the parse fails — the error must
        // still name the item, not panic.
        let err = parse_vip_ports_env("65536").unwrap_err();
        assert!(
            err.contains("65536"),
            "error must name the offending item: {err}"
        );
    }

    #[test]
    fn vip_ports_env_rejects_unknown_tls_mode_and_names_it() {
        let err = parse_vip_ports_env("1514:whysoserious").unwrap_err();
        assert!(
            err.contains("whysoserious"),
            "error must name the offending item: {err}"
        );
        assert!(
            err.contains("1514"),
            "error should name the port too: {err}"
        );
    }

    // ── TOML round-trip ────────────────────────────────────────────────

    #[test]
    fn vip_ports_toml_parses_entries_and_defaults_tls_to_passthrough() {
        let toml_str = r#"
[tunnel]
[[tunnel.vip_ports]]
port = 1514
[[tunnel.vip_ports]]
port = 443
tls  = "passthrough"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.tunnel.vip_ports.len(), 2);
        assert_eq!(cfg.tunnel.vip_ports[0], vpc(1514, VipTlsMode::Passthrough));
        assert_eq!(cfg.tunnel.vip_ports[1], vpc(443, VipTlsMode::Passthrough));
    }

    #[test]
    fn vip_ports_toml_parses_terminate_and_auto_modes() {
        let toml_str = r#"
[tunnel]
[[tunnel.vip_ports]]
port = 9000
tls  = "terminate"
[[tunnel.vip_ports]]
port = 9001
tls  = "auto"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.tunnel.vip_ports[0].tls, VipTlsMode::Terminate);
        assert_eq!(cfg.tunnel.vip_ports[1].tls, VipTlsMode::Auto);
    }

    #[test]
    fn vip_ports_toml_empty_when_key_absent() {
        let cfg: AgentConfig = toml::from_str("[tunnel]").unwrap();
        assert!(cfg.tunnel.vip_ports.is_empty());
    }

    #[test]
    fn vip_ports_toml_unknown_mode_fails_at_load_naming_the_value() {
        let toml_str = r#"
[tunnel]
[[tunnel.vip_ports]]
port = 9000
tls  = "nope"
"#;
        let err = toml::from_str::<AgentConfig>(toml_str).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("nope"),
            "load error must name the offending value: {msg}"
        );
    }

    // ── validate_vip_ports ─────────────────────────────────────────────

    #[test]
    fn validate_vip_ports_accepts_empty_and_valid() {
        assert!(cfg_with_ports(vec![]).validate_vip_ports().is_ok());
        assert!(cfg_with_ports(vec![
            vpc(1514, VipTlsMode::Passthrough),
            vpc(1515, VipTlsMode::Auto)
        ])
        .validate_vip_ports()
        .is_ok());
    }

    #[test]
    fn validate_vip_ports_rejects_duplicate_port_naming_it() {
        let err = cfg_with_ports(vec![
            vpc(1514, VipTlsMode::Passthrough),
            vpc(1514, VipTlsMode::Terminate),
        ])
        .validate_vip_ports()
        .unwrap_err();
        assert!(err.contains("1514"), "error must name the duplicate: {err}");
    }

    #[test]
    fn validate_vip_ports_rejects_port_zero() {
        let err = cfg_with_ports(vec![vpc(0, VipTlsMode::Passthrough)])
            .validate_vip_ports()
            .unwrap_err();
        assert!(err.contains("0"), "error must name port 0: {err}");
    }

    #[test]
    fn validate_vip_ports_rejects_over_cap_list() {
        // VIP_PORTS_MAX+1 distinct ports.
        let ports: Vec<VipPortConfig> = (20000..20000 + VIP_PORTS_MAX as u16 + 1)
            .map(|p| vpc(p, VipTlsMode::Passthrough))
            .collect();
        assert_eq!(ports.len(), VIP_PORTS_MAX + 1);
        let err = cfg_with_ports(ports).validate_vip_ports().unwrap_err();
        assert!(
            err.contains(&VIP_PORTS_MAX.to_string()),
            "error must state the cap: {err}"
        );
    }

    #[test]
    fn validate_vip_ports_accepts_exactly_the_cap() {
        let ports: Vec<VipPortConfig> = (20000..20000 + VIP_PORTS_MAX as u16)
            .map(|p| vpc(p, VipTlsMode::Passthrough))
            .collect();
        assert!(cfg_with_ports(ports).validate_vip_ports().is_ok());
    }

    #[test]
    fn validate_vip_ports_flags_listener_collision_inside_vip_range() {
        // The agent's own [dns] listener sits at 127.100.0.53:5353, which
        // is INSIDE the default VIP range 127.100.0.0/16. A vip_port of
        // 5353 would make the pool hand out an address the agent binds.
        let mut cfg = cfg_with_ports(vec![vpc(5353, VipTlsMode::Passthrough)]);
        cfg.dns.listen = "127.100.0.53:5353".to_string();
        let err = cfg.validate_vip_ports().unwrap_err();
        assert!(
            err.contains("5353"),
            "error must name the colliding port: {err}"
        );
    }

    #[test]
    fn validate_vip_ports_allows_same_port_when_listener_outside_vip_range() {
        // Default [dns] listen 127.0.0.53:5353 is OUTSIDE 127.100.0.0/16,
        // so vip_port 5353 is fine (the default config already passes).
        let cfg = cfg_with_ports(vec![vpc(5353, VipTlsMode::Passthrough)]);
        assert_eq!(cfg.dns.listen, "127.0.0.53:5353");
        assert!(cfg.validate_vip_ports().is_ok());
    }

    // ── vip_ports_policy (the resolved policy) ─────────────────────────

    #[test]
    fn vip_ports_policy_is_built_in_eight_when_unconfigured() {
        let cfg = AgentConfig::default();
        let policy = cfg.tunnel.vip_ports_policy();
        let ports: Vec<u16> = policy.effective_ports().to_vec();
        assert_eq!(ports.len(), VIP_BUILTIN_PORTS.len());
        // Same set as the built-in eight (sorted, so compare as sets).
        let mut expected: Vec<u16> = VIP_BUILTIN_PORTS.to_vec();
        expected.sort_unstable();
        assert_eq!(ports, expected);
        // No overrides: every port resolves to the built-in table answer.
        assert_eq!(
            policy.tls_mode(443),
            crate::agent::local_tls::tls_mode_for_port(443)
        );
    }

    #[test]
    fn vip_ports_policy_adds_new_ports_sorted() {
        let cfg = cfg_with_ports(vec![
            vpc(9000, VipTlsMode::Passthrough),
            vpc(3000, VipTlsMode::Auto),
        ]);
        let policy = cfg.tunnel.vip_ports_policy();
        let ports: Vec<u16> = policy.effective_ports().to_vec();
        assert!(ports.contains(&9000));
        assert!(ports.contains(&3000));
        assert_eq!(ports.len(), VIP_BUILTIN_PORTS.len() + 2);
        // Sorted.
        let mut sorted = ports.clone();
        sorted.sort_unstable();
        assert_eq!(ports, sorted);
    }

    #[test]
    fn vip_ports_policy_overrides_builtin_port_mode_without_adding_listener() {
        // 443 is built-in; a passthrough override flips its TLS mode but
        // must NOT add a second listener (no duplicate 443).
        let cfg = cfg_with_ports(vec![vpc(443, VipTlsMode::Passthrough)]);
        let policy = cfg.tunnel.vip_ports_policy();
        let ports: Vec<u16> = policy.effective_ports().to_vec();
        assert_eq!(ports.iter().filter(|&&p| p == 443).count(), 1);
        assert_eq!(policy.tls_mode(443), TlsMode::Never);
    }

    #[test]
    fn vip_ports_policy_override_wins_over_builtin_table() {
        let cfg = cfg_with_ports(vec![vpc(1514, VipTlsMode::Terminate)]);
        let policy = cfg.tunnel.vip_ports_policy();
        assert_eq!(policy.tls_mode(1514), TlsMode::Always);
    }

    #[test]
    fn vip_ports_policy_default_is_built_in_eight_no_overrides() {
        let policy = VipPortPolicy::default();
        let ports: Vec<u16> = policy.effective_ports().to_vec();
        assert_eq!(ports.len(), VIP_BUILTIN_PORTS.len());
        let mut expected: Vec<u16> = VIP_BUILTIN_PORTS.to_vec();
        expected.sort_unstable();
        assert_eq!(ports, expected);
        assert_eq!(
            policy.tls_mode(22),
            crate::agent::local_tls::tls_mode_for_port(22)
        );
    }

    // ── 504-class (stall close strategy) under the policy ──────────────

    #[test]
    fn vip_policy_504_class_kept_for_untouched_builtin_http_ports() {
        let policy = VipPortPolicy::default();
        for port in [80, 8080, 443, 8443u16] {
            assert_eq!(
                policy.stall_close_strategy(port),
                StallCloseStrategy::Deliver504,
                "port {port} must stay 504-class by default"
            );
        }
    }

    #[test]
    fn vip_policy_504_class_dropped_when_builtin_http_port_is_passthrough() {
        // 443 overridden to passthrough → the agent no longer terminates
        // TLS there; a 504 page through the opaque pipe is garbage.
        let cfg = cfg_with_ports(vec![vpc(443, VipTlsMode::Passthrough)]);
        let policy = cfg.tunnel.vip_ports_policy();
        assert_eq!(
            policy.stall_close_strategy(443),
            StallCloseStrategy::BareClose
        );
        // The other built-in HTTP ports are unaffected.
        assert_eq!(
            policy.stall_close_strategy(8080),
            StallCloseStrategy::Deliver504
        );
    }

    #[test]
    fn vip_policy_configured_unknown_port_is_never_504_class() {
        // A Wazuh-style operator-added port: bare close, whatever TLS
        // mode it carries — the agent never speaks HTTP on it.
        let cfg = cfg_with_ports(vec![
            vpc(1514, VipTlsMode::Passthrough),
            vpc(1515, VipTlsMode::Terminate),
            vpc(1516, VipTlsMode::Auto),
        ]);
        let policy = cfg.tunnel.vip_ports_policy();
        for port in [1514, 1515, 1516u16] {
            assert_eq!(
                policy.stall_close_strategy(port),
                StallCloseStrategy::BareClose,
                "configured port {port} must be bare-close"
            );
        }
    }

    #[test]
    fn vip_policy_non_http_builtin_ports_stay_bare_close() {
        let policy = VipPortPolicy::default();
        for port in [22, 3306, 5432, 3389u16] {
            assert_eq!(
                policy.stall_close_strategy(port),
                StallCloseStrategy::BareClose,
                "port {port} must be bare-close by default"
            );
        }
    }

    #[test]
    fn vip_stall_close_strategy_direct_override_never_is_bare_close() {
        // The low-level helper agrees with the policy wrapper: a `Never`
        // override on a built-in HTTP port removes the 504 class.
        let mut overrides = std::collections::HashMap::new();
        overrides.insert(443, TlsMode::Never);
        assert_eq!(
            vip_stall_close_strategy(443, &overrides),
            StallCloseStrategy::BareClose
        );
        // ...and an `Always`/`Detect` override keeps it.
        overrides.insert(443, TlsMode::Always);
        assert_eq!(
            vip_stall_close_strategy(443, &overrides),
            StallCloseStrategy::Deliver504
        );
    }
}
