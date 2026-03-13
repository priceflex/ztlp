//! Tunnel pool — manages persistent ZTLP tunnels with auto-reconnect.
//!
//! Each tunnel is a Noise_XX session to a specific peer. Multiple TCP streams
//! are multiplexed over a single tunnel. Tunnels are established on-demand
//! (first connection to a peer) and kept alive with periodic keepalives.
//!
//! ## Lifecycle
//!
//! ```text
//! TCP connect to VIP → pool.get_or_create(name) → tunnel
//!   ↓
//! tunnel.open_stream(port) → stream_id
//!   ↓
//! bridge TCP ↔ stream (via StreamMux)
//!   ↓
//! idle timeout → pool.remove(name)
//!
//! reconnect on failure:
//!   error → backoff(1s, 2s, 4s, ... 60s) → retry handshake → resume
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::debug;

use super::stream::StreamInfo;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Default idle timeout before tunnel is torn down (5 minutes).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Default keepalive interval (30 seconds).
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Minimum backoff for reconnection.
const MIN_BACKOFF: Duration = Duration::from_secs(1);
/// Maximum backoff for reconnection.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

// ─── Tunnel state ───────────────────────────────────────────────────────────

/// State of a managed tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// Tunnel is being established (handshake in progress).
    Connecting,
    /// Tunnel is active and ready for streams.
    Active,
    /// Tunnel is reconnecting after a failure.
    Reconnecting {
        /// Number of consecutive failures.
        attempts: u32,
        /// Next retry time.
        next_retry: Instant,
    },
    /// Tunnel has been permanently closed.
    Closed,
}

/// A managed tunnel to a specific ZTLP peer.
pub struct ManagedTunnel {
    /// The ZTLP name this tunnel serves (e.g., "server.corp.ztlp").
    pub name: String,
    /// Remote peer address.
    pub peer_addr: SocketAddr,
    /// Current state.
    pub state: TunnelState,
    /// When the tunnel was created.
    pub created_at: Instant,
    /// Last activity (data sent or received).
    pub last_activity: Instant,
    /// Last keepalive sent.
    pub last_keepalive: Instant,
    /// Reconnection attempt counter.
    pub reconnect_attempts: u32,
    /// Total bytes sent through this tunnel.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_recv: u64,
}

/// Summary info about a tunnel (for status reporting).
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub name: String,
    pub peer_addr: SocketAddr,
    pub state: TunnelState,
    pub age_secs: u64,
    pub idle_secs: u64,
    pub streams: Vec<StreamInfo>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

// ─── Tunnel pool ────────────────────────────────────────────────────────────

/// Pool of managed ZTLP tunnels.
///
/// The pool manages tunnel lifecycle, including creation, keepalive,
/// idle timeout, and auto-reconnection.
pub struct TunnelPool {
    /// Active tunnels by ZTLP name.
    tunnels: HashMap<String, ManagedTunnel>,
    /// Maximum number of concurrent tunnels.
    max_tunnels: usize,
    /// Idle timeout before tearing down unused tunnels.
    idle_timeout: Duration,
    /// Keepalive interval.
    keepalive_interval: Duration,
}

impl TunnelPool {
    /// Create a new tunnel pool.
    pub fn new(max_tunnels: usize) -> Self {
        Self {
            tunnels: HashMap::new(),
            max_tunnels,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
        }
    }

    /// Create with custom timeouts.
    pub fn with_timeouts(
        max_tunnels: usize,
        idle_timeout: Duration,
        keepalive_interval: Duration,
    ) -> Self {
        Self {
            tunnels: HashMap::new(),
            max_tunnels,
            idle_timeout,
            keepalive_interval,
        }
    }

    /// Register a new tunnel for the given name.
    ///
    /// Returns an error if max tunnels reached or name already has a tunnel.
    pub fn register(
        &mut self,
        name: &str,
        peer_addr: SocketAddr,
    ) -> Result<(), String> {
        if self.tunnels.contains_key(name) {
            return Err(format!("tunnel already exists for '{}'", name));
        }
        if self.tunnels.len() >= self.max_tunnels {
            return Err(format!(
                "max tunnels reached ({}/{})",
                self.tunnels.len(),
                self.max_tunnels
            ));
        }

        let now = Instant::now();
        let tunnel = ManagedTunnel {
            name: name.to_string(),
            peer_addr,
            state: TunnelState::Connecting,
            created_at: now,
            last_activity: now,
            last_keepalive: now,
            reconnect_attempts: 0,
            bytes_sent: 0,
            bytes_recv: 0,
        };

        self.tunnels.insert(name.to_string(), tunnel);
        debug!("tunnel registered: {} → {}", name, peer_addr);
        Ok(())
    }

    /// Mark a tunnel as active (handshake complete).
    pub fn mark_active(&mut self, name: &str) {
        if let Some(t) = self.tunnels.get_mut(name) {
            t.state = TunnelState::Active;
            t.last_activity = Instant::now();
            t.reconnect_attempts = 0;
            debug!("tunnel active: {}", name);
        }
    }

    /// Mark a tunnel as needing reconnection.
    pub fn mark_reconnecting(&mut self, name: &str) {
        if let Some(t) = self.tunnels.get_mut(name) {
            t.reconnect_attempts += 1;
            let backoff = compute_backoff(t.reconnect_attempts);
            t.state = TunnelState::Reconnecting {
                attempts: t.reconnect_attempts,
                next_retry: Instant::now() + backoff,
            };
            debug!(
                "tunnel reconnecting: {} (attempt {}, backoff {:?})",
                name, t.reconnect_attempts, backoff
            );
        }
    }

    /// Record activity on a tunnel (resets idle timer).
    pub fn touch(&mut self, name: &str, bytes_sent: u64, bytes_recv: u64) {
        if let Some(t) = self.tunnels.get_mut(name) {
            t.last_activity = Instant::now();
            t.bytes_sent += bytes_sent;
            t.bytes_recv += bytes_recv;
        }
    }

    /// Record a keepalive sent.
    pub fn touch_keepalive(&mut self, name: &str) {
        if let Some(t) = self.tunnels.get_mut(name) {
            t.last_keepalive = Instant::now();
        }
    }

    /// Get a tunnel by name.
    pub fn get(&self, name: &str) -> Option<&ManagedTunnel> {
        self.tunnels.get(name)
    }

    /// Check if a tunnel exists and is active.
    pub fn is_active(&self, name: &str) -> bool {
        self.tunnels
            .get(name)
            .map_or(false, |t| t.state == TunnelState::Active)
    }

    /// Remove a tunnel.
    pub fn remove(&mut self, name: &str) -> Option<ManagedTunnel> {
        let t = self.tunnels.remove(name);
        if t.is_some() {
            debug!("tunnel removed: {}", name);
        }
        t
    }

    /// Get all tunnel names that are due for keepalive.
    pub fn needs_keepalive(&self) -> Vec<String> {
        let now = Instant::now();
        self.tunnels
            .iter()
            .filter(|(_, t)| {
                t.state == TunnelState::Active
                    && now.duration_since(t.last_keepalive) >= self.keepalive_interval
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Get all tunnel names that have exceeded idle timeout.
    pub fn idle_tunnels(&self) -> Vec<String> {
        let now = Instant::now();
        self.tunnels
            .iter()
            .filter(|(_, t)| {
                t.state == TunnelState::Active
                    && now.duration_since(t.last_activity) >= self.idle_timeout
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Get all tunnels ready for reconnection.
    pub fn ready_to_reconnect(&self) -> Vec<String> {
        let now = Instant::now();
        self.tunnels
            .iter()
            .filter(|(_, t)| match t.state {
                TunnelState::Reconnecting { next_retry, .. } => now >= next_retry,
                _ => false,
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Get info for all tunnels.
    pub fn tunnel_info(&self) -> Vec<TunnelInfo> {
        let now = Instant::now();
        self.tunnels
            .values()
            .map(|t| TunnelInfo {
                name: t.name.clone(),
                peer_addr: t.peer_addr,
                state: t.state.clone(),
                age_secs: now.duration_since(t.created_at).as_secs(),
                idle_secs: now.duration_since(t.last_activity).as_secs(),
                streams: Vec::new(), // Streams tracked separately
                bytes_sent: t.bytes_sent,
                bytes_recv: t.bytes_recv,
            })
            .collect()
    }

    /// Number of active tunnels.
    pub fn active_count(&self) -> usize {
        self.tunnels
            .values()
            .filter(|t| t.state == TunnelState::Active)
            .count()
    }

    /// Total tunnel count.
    pub fn total_count(&self) -> usize {
        self.tunnels.len()
    }

    /// Maximum concurrent tunnels.
    pub fn max_tunnels(&self) -> usize {
        self.max_tunnels
    }
}

// ─── Backoff ────────────────────────────────────────────────────────────────

/// Compute exponential backoff with cap.
fn compute_backoff(attempt: u32) -> Duration {
    let secs = MIN_BACKOFF.as_secs() * 2u64.saturating_pow(attempt.saturating_sub(1));
    Duration::from_secs(secs.min(MAX_BACKOFF.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), port)
    }

    #[test]
    fn test_register_and_mark_active() {
        let mut pool = TunnelPool::new(256);
        pool.register("server.corp.ztlp", addr(23095)).unwrap();

        assert!(pool.get("server.corp.ztlp").is_some());
        assert!(!pool.is_active("server.corp.ztlp"));

        pool.mark_active("server.corp.ztlp");
        assert!(pool.is_active("server.corp.ztlp"));
    }

    #[test]
    fn test_duplicate_register() {
        let mut pool = TunnelPool::new(256);
        pool.register("a.ztlp", addr(1)).unwrap();
        assert!(pool.register("a.ztlp", addr(2)).is_err());
    }

    #[test]
    fn test_max_tunnels() {
        let mut pool = TunnelPool::new(2);
        pool.register("a.ztlp", addr(1)).unwrap();
        pool.register("b.ztlp", addr(2)).unwrap();
        assert!(pool.register("c.ztlp", addr(3)).is_err());
    }

    #[test]
    fn test_remove() {
        let mut pool = TunnelPool::new(256);
        pool.register("a.ztlp", addr(1)).unwrap();
        assert_eq!(pool.total_count(), 1);
        pool.remove("a.ztlp");
        assert_eq!(pool.total_count(), 0);
    }

    #[test]
    fn test_idle_tunnels() {
        let mut pool = TunnelPool::with_timeouts(
            256,
            Duration::from_millis(1), // Very short idle timeout
            Duration::from_secs(30),
        );
        pool.register("a.ztlp", addr(1)).unwrap();
        pool.mark_active("a.ztlp");

        // Immediately after, should not be idle (depends on timing)
        // After a small sleep, should be idle
        std::thread::sleep(Duration::from_millis(5));
        let idle = pool.idle_tunnels();
        assert!(idle.contains(&"a.ztlp".to_string()));
    }

    #[test]
    fn test_touch_resets_idle() {
        let mut pool = TunnelPool::with_timeouts(
            256,
            Duration::from_secs(60),
            Duration::from_secs(30),
        );
        pool.register("a.ztlp", addr(1)).unwrap();
        pool.mark_active("a.ztlp");
        pool.touch("a.ztlp", 100, 50);

        let t = pool.get("a.ztlp").unwrap();
        assert_eq!(t.bytes_sent, 100);
        assert_eq!(t.bytes_recv, 50);

        let idle = pool.idle_tunnels();
        assert!(idle.is_empty()); // Just touched, not idle
    }

    #[test]
    fn test_reconnect_backoff() {
        let mut pool = TunnelPool::new(256);
        pool.register("a.ztlp", addr(1)).unwrap();
        pool.mark_active("a.ztlp");

        pool.mark_reconnecting("a.ztlp");
        let t = pool.get("a.ztlp").unwrap();
        assert_eq!(t.reconnect_attempts, 1);
        assert!(matches!(t.state, TunnelState::Reconnecting { attempts: 1, .. }));

        pool.mark_reconnecting("a.ztlp");
        let t = pool.get("a.ztlp").unwrap();
        assert_eq!(t.reconnect_attempts, 2);
    }

    #[test]
    fn test_compute_backoff() {
        assert_eq!(compute_backoff(1), Duration::from_secs(1));
        assert_eq!(compute_backoff(2), Duration::from_secs(2));
        assert_eq!(compute_backoff(3), Duration::from_secs(4));
        assert_eq!(compute_backoff(4), Duration::from_secs(8));
        assert_eq!(compute_backoff(5), Duration::from_secs(16));
        assert_eq!(compute_backoff(6), Duration::from_secs(32));
        assert_eq!(compute_backoff(7), Duration::from_secs(60)); // capped
        assert_eq!(compute_backoff(100), Duration::from_secs(60)); // still capped
    }

    #[test]
    fn test_needs_keepalive() {
        let mut pool = TunnelPool::with_timeouts(
            256,
            Duration::from_secs(300),
            Duration::from_millis(1), // Very short keepalive
        );
        pool.register("a.ztlp", addr(1)).unwrap();
        pool.mark_active("a.ztlp");

        std::thread::sleep(Duration::from_millis(5));
        let needs = pool.needs_keepalive();
        assert!(needs.contains(&"a.ztlp".to_string()));
    }

    #[test]
    fn test_tunnel_info() {
        let mut pool = TunnelPool::new(256);
        pool.register("a.ztlp", addr(1)).unwrap();
        pool.mark_active("a.ztlp");
        pool.register("b.ztlp", addr(2)).unwrap();

        let info = pool.tunnel_info();
        assert_eq!(info.len(), 2);
    }

    #[test]
    fn test_active_count() {
        let mut pool = TunnelPool::new(256);
        pool.register("a.ztlp", addr(1)).unwrap();
        pool.register("b.ztlp", addr(2)).unwrap();
        pool.mark_active("a.ztlp");

        assert_eq!(pool.active_count(), 1);
        assert_eq!(pool.total_count(), 2);
    }

    #[test]
    fn test_mark_active_resets_reconnect() {
        let mut pool = TunnelPool::new(256);
        pool.register("a.ztlp", addr(1)).unwrap();

        // Simulate reconnect cycle
        pool.mark_reconnecting("a.ztlp");
        pool.mark_reconnecting("a.ztlp");
        assert_eq!(pool.get("a.ztlp").unwrap().reconnect_attempts, 2);

        // Successful reconnect
        pool.mark_active("a.ztlp");
        assert_eq!(pool.get("a.ztlp").unwrap().reconnect_attempts, 0);
        assert_eq!(pool.get("a.ztlp").unwrap().state, TunnelState::Active);
    }
}
