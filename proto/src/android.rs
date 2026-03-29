//! Android JNI bindings for ZTLP.
//!
//! Provides JNI-compatible function signatures that map to the core ZTLP library.
//! The actual JNI linkage requires the `jni` crate at build time on Android;
//! this module provides:
//! 1. The Kotlin/Java class interface specification
//! 2. Platform-agnostic core logic that JNI functions delegate to
//! 3. Configuration and state management for Android VpnService integration
//!
//! Architecture mirrors iOS FFI but adapted for Android:
//! - iOS: C FFI → Swift bridging header → PacketTunnelProvider
//! - Android: JNI → Kotlin class → VpnService

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Android tunnel configuration (mirrors iOS TunnelConfiguration)
#[derive(Debug, Clone)]
pub struct AndroidTunnelConfig {
    pub relay_server: String,
    pub relay_port: u16,
    pub gateway_server: String,
    pub gateway_port: u16,
    pub ns_server: Option<String>,
    pub ns_port: u16,
    pub service_name: String,
    pub zone_name: String,
    pub tunnel_addr: Ipv4Addr,
    pub tunnel_netmask: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub mtu: u16,
    pub use_relay: bool,
    pub allowed_apps: Vec<String>,
    pub disallowed_apps: Vec<String>,
}

impl Default for AndroidTunnelConfig {
    fn default() -> Self {
        Self {
            relay_server: String::new(),
            relay_port: 23095,
            gateway_server: String::new(),
            gateway_port: 23097,
            ns_server: None,
            ns_port: 23096,
            service_name: "default".into(),
            zone_name: String::new(),
            tunnel_addr: Ipv4Addr::new(10, 122, 0, 1),
            tunnel_netmask: Ipv4Addr::new(255, 255, 0, 0),
            dns_servers: vec![],
            mtu: 1280,
            use_relay: true,
            allowed_apps: vec![],
            disallowed_apps: vec![],
        }
    }
}

impl AndroidTunnelConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.gateway_server.is_empty() {
            return Err(ConfigError::MissingField("gateway_server"));
        }
        if self.zone_name.is_empty() {
            return Err(ConfigError::MissingField("zone_name"));
        }
        if self.service_name.is_empty() {
            return Err(ConfigError::MissingField("service_name"));
        }
        if self.mtu < 576 {
            return Err(ConfigError::InvalidMtu(self.mtu));
        }
        if self.mtu > 9000 {
            return Err(ConfigError::InvalidMtu(self.mtu));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    MissingField(&'static str),
    InvalidMtu(u16),
    InvalidAddress(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field: {}", field),
            Self::InvalidMtu(mtu) => write!(f, "invalid MTU: {} (must be 576-9000)", mtu),
            Self::InvalidAddress(addr) => write!(f, "invalid address: {}", addr),
        }
    }
}

impl std::error::Error for ConfigError {}

/// VPN tunnel state (mirrors Android VpnService states)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

impl TunnelState {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Disconnected => "DISCONNECTED",
            Self::Connecting => "CONNECTING",
            Self::Connected => "CONNECTED",
            Self::Reconnecting => "RECONNECTING",
            Self::Disconnecting => "DISCONNECTING",
            Self::Failed => "FAILED",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "DISCONNECTED" => Some(Self::Disconnected),
            "CONNECTING" => Some(Self::Connecting),
            "CONNECTED" => Some(Self::Connected),
            "RECONNECTING" => Some(Self::Reconnecting),
            "DISCONNECTING" => Some(Self::Disconnecting),
            "FAILED" => Some(Self::Failed),
            _ => None,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Connected | Self::Reconnecting)
    }

    pub fn can_transition_to(&self, next: &Self) -> bool {
        matches!(
            (self, next),
            (Self::Disconnected, Self::Connecting)
                | (Self::Connecting, Self::Connected)
                | (Self::Connecting, Self::Failed)
                | (Self::Connected, Self::Reconnecting)
                | (Self::Connected, Self::Disconnecting)
                | (Self::Reconnecting, Self::Connected)
                | (Self::Reconnecting, Self::Failed)
                | (Self::Disconnecting, Self::Disconnected)
                | (Self::Failed, Self::Connecting)
                | (Self::Failed, Self::Disconnected)
        )
    }
}

/// VPN service statistics
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub handshakes_completed: u64,
    pub reconnects: u64,
    pub uptime_secs: u64,
    pub current_rtt_ms: u64,
    pub active_streams: u32,
}

/// Thread-safe tunnel statistics tracker
pub struct AtomicTunnelStats {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    handshakes: AtomicU64,
    reconnects: AtomicU64,
    start_time: AtomicU64,
    current_rtt: AtomicU64,
    active_streams: AtomicU64,
}

impl AtomicTunnelStats {
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            handshakes: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            start_time: AtomicU64::new(0),
            current_rtt: AtomicU64::new(0),
            active_streams: AtomicU64::new(0),
        }
    }

    pub fn record_send(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_recv(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_handshake(&self) {
        self.handshakes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_rtt(&self, rtt_ms: u64) {
        self.current_rtt.store(rtt_ms, Ordering::Relaxed);
    }

    pub fn set_active_streams(&self, count: u64) {
        self.active_streams.store(count, Ordering::Relaxed);
    }

    pub fn set_start_time(&self, epoch_secs: u64) {
        self.start_time.store(epoch_secs, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TunnelStats {
        let start = self.start_time.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        TunnelStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            handshakes_completed: self.handshakes.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
            uptime_secs: if start > 0 {
                now.saturating_sub(start)
            } else {
                0
            },
            current_rtt_ms: self.current_rtt.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed) as u32,
        }
    }

    pub fn reset(&self) {
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_received.store(0, Ordering::Relaxed);
        self.handshakes.store(0, Ordering::Relaxed);
        self.reconnects.store(0, Ordering::Relaxed);
        self.start_time.store(0, Ordering::Relaxed);
        self.current_rtt.store(0, Ordering::Relaxed);
        self.active_streams.store(0, Ordering::Relaxed);
    }
}

impl Default for AtomicTunnelStats {
    fn default() -> Self {
        Self::new()
    }
}

/// VIP service mapping for Android (mirrors iOS packet router)
#[derive(Debug, Clone)]
pub struct VipMapping {
    pub ip: Ipv4Addr,
    pub service_name: String,
    pub port: Option<u16>,
}

/// VIP routing table
#[derive(Debug, Clone, Default)]
pub struct VipTable {
    mappings: Vec<VipMapping>,
}

impl VipTable {
    pub fn new() -> Self {
        Self { mappings: vec![] }
    }

    pub fn add(&mut self, ip: Ipv4Addr, service_name: &str, port: Option<u16>) {
        self.mappings.push(VipMapping {
            ip,
            service_name: service_name.to_string(),
            port,
        });
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&VipMapping> {
        self.mappings.iter().find(|m| m.ip == ip)
    }

    pub fn remove(&mut self, ip: Ipv4Addr) {
        self.mappings.retain(|m| m.ip != ip);
    }

    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    pub fn all(&self) -> &[VipMapping] {
        &self.mappings
    }
}

/// Per-app VPN routing (Android-specific)
#[derive(Debug, Clone)]
pub struct PerAppConfig {
    /// If non-empty, ONLY these apps go through VPN
    pub allowed_apps: Vec<String>,
    /// If non-empty, these apps are EXCLUDED from VPN
    pub disallowed_apps: Vec<String>,
}

impl PerAppConfig {
    pub fn allow_all() -> Self {
        Self {
            allowed_apps: vec![],
            disallowed_apps: vec![],
        }
    }

    pub fn only_apps(apps: Vec<String>) -> Self {
        Self {
            allowed_apps: apps,
            disallowed_apps: vec![],
        }
    }

    pub fn exclude_apps(apps: Vec<String>) -> Self {
        Self {
            allowed_apps: vec![],
            disallowed_apps: apps,
        }
    }

    pub fn should_route_app(&self, package_name: &str) -> bool {
        if !self.allowed_apps.is_empty() {
            return self.allowed_apps.iter().any(|a| a == package_name);
        }
        if !self.disallowed_apps.is_empty() {
            return !self.disallowed_apps.iter().any(|a| a == package_name);
        }
        true // default: route all
    }

    pub fn is_split_tunnel(&self) -> bool {
        !self.allowed_apps.is_empty() || !self.disallowed_apps.is_empty()
    }
}

/// Kotlin class specification for the Android app.
/// This documents what the Kotlin side looks like.
pub const KOTLIN_CLASS_SPEC: &str = r#"
// ZtlpNative.kt — JNI bridge class
package com.ztlp.vpn.native

class ZtlpNative {
    companion object {
        init { System.loadLibrary("ztlp_proto") }

        // Lifecycle
        external fun initialize(): Long  // returns handle
        external fun shutdown(handle: Long)

        // Configuration
        external fun configure(handle: Long, configJson: String): Boolean

        // Connection
        external fun connect(handle: Long, fd: Int): Boolean  // fd from VpnService.Builder
        external fun disconnect(handle: Long)
        external fun getState(handle: Long): String

        // Packet I/O
        external fun writePacket(handle: Long, packet: ByteArray): Boolean
        external fun readPacket(handle: Long): ByteArray?

        // Stats
        external fun getStats(handle: Long): String  // JSON

        // VIP
        external fun addVipMapping(handle: Long, ip: String, service: String): Boolean
        external fun removeVipMapping(handle: Long, ip: String): Boolean
        external fun lookupVip(handle: Long, ip: String): String?

        // Version
        external fun version(): String
    }
}
"#;

/// JNI function name generator
/// JNI requires: Java\_\<package\>\_\<class\>\_\<method\>
pub fn jni_function_name(package: &str, class: &str, method: &str) -> String {
    let pkg = package.replace('.', "_");
    format!("Java_{pkg}_{class}_{method}")
}
