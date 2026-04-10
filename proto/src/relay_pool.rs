//! Client-side relay pool with automatic failover and health tracking.
//!
//! Manages a ranked list of relay servers queried from ZTLP-NS, provides
//! automatic failover when the primary relay becomes unhealthy, and tracks
//! relay health history with exponential backoff for failed relays.
//!
//! ## Architecture
//!
//! ```text
//!    ┌─────────────────────────────────────────────┐
//!    │              RelayPool                       │
//!    │                                              │
//!    │  ┌──────────┐ ┌──────────┐ ┌──────────┐    │
//!    │  │ Relay A   │ │ Relay B   │ │ Relay C   │  │
//!    │  │ ★ primary │ │ backup    │ │ backup    │  │
//!    │  │ lat: 12ms │ │ lat: 25ms │ │ lat: 40ms │  │
//!    │  │ healthy   │ │ healthy   │ │ degraded  │  │
//!    │  └──────────┘ └──────────┘ └──────────┘    │
//!    │                                              │
//!    │  Health Thread: PING every probe_interval    │
//!    │  Failover: <5s for relay crash               │
//!    └─────────────────────────────────────────────┘
//! ```
//!
//! ## Failover Behavior
//!
//! - `Reestablishing` → mark current degraded, try next best relay
//! - `Dead` → try ALL remaining relays, then re-query NS
//! - Exponential backoff: 5s → 10s → 20s → 40s → 60s max
//! - 3 failures in 10 minutes → deprioritized for 5 minutes

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Default interval between relay health probes.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// Timeout for a single relay probe (PING → PONG).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Base backoff duration for failed relays.
const BACKOFF_BASE: Duration = Duration::from_secs(5);

/// Maximum backoff duration for failed relays.
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Number of failures in the deprioritization window that triggers deprioritization.
const DEPRIORITIZE_FAILURE_COUNT: usize = 3;

/// Window for counting failures toward deprioritization.
const DEPRIORITIZE_WINDOW: Duration = Duration::from_secs(600); // 10 minutes

/// Duration a relay stays deprioritized.
const DEPRIORITIZE_DURATION: Duration = Duration::from_secs(300); // 5 minutes

/// Maximum number of relays to keep in the pool.
const MAX_POOL_SIZE: usize = 32;

/// Grace period before a newly added relay can be primary (allows probe first).
#[allow(dead_code)]
const NEW_RELAY_GRACE: Duration = Duration::from_millis(500);

// ─── Relay Health State ─────────────────────────────────────────────────────

/// Health state of a single relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayHealth {
    /// Relay is responding normally.
    Healthy,
    /// Relay is responding but with degraded performance.
    Degraded,
    /// Relay is not responding.
    Dead,
    /// Relay is temporarily deprioritized after repeated failures.
    Deprioritized,
}

impl std::fmt::Display for RelayHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayHealth::Healthy => write!(f, "healthy"),
            RelayHealth::Degraded => write!(f, "degraded"),
            RelayHealth::Dead => write!(f, "dead"),
            RelayHealth::Deprioritized => write!(f, "deprioritized"),
        }
    }
}

// ─── Relay Entry ────────────────────────────────────────────────────────────

/// Information about a relay from NS discovery (rich format with stats).
#[derive(Debug, Clone)]
pub struct RelayInfo {
    /// Socket address of the relay.
    pub addr: SocketAddr,
    /// Geographic region (e.g., "us-west-2").
    pub region: String,
    /// Last measured latency from NS perspective (milliseconds).
    pub latency_ms: u32,
    /// Current load percentage (0-100).
    pub load_pct: u8,
    /// Number of active tunneled connections.
    pub active_connections: u32,
    /// Health state as reported by NS.
    pub health: RelayHealth,
}

/// Tracks the state and history of a single relay.
#[derive(Debug, Clone)]
pub struct RelayEntry {
    /// Socket address of the relay.
    pub addr: SocketAddr,
    /// Current health state.
    pub health: RelayHealth,
    /// Measured latency (round-trip time of last successful probe).
    pub latency: Option<Duration>,
    /// Geographic region (e.g., "us-west-2"), used for selection tiebreak.
    pub region: String,
    /// Current load percentage (0-100), used for load-adjusted scoring.
    pub load_pct: u8,
    /// Number of active tunneled connections, used for tiebreak.
    pub active_connections: u32,
    /// When this relay was added to the pool.
    pub added_at: Instant,
    /// When we last successfully communicated with this relay.
    pub last_success: Option<Instant>,
    /// When we last attempted to probe this relay.
    pub last_probe: Option<Instant>,
    /// Timestamps of recent failures (for deprioritization window).
    pub failure_times: Vec<Instant>,
    /// Number of consecutive failures (for exponential backoff).
    pub consecutive_failures: u32,
    /// When the current backoff period expires (None = not backing off).
    pub backoff_until: Option<Instant>,
    /// When deprioritization expires (None = not deprioritized).
    pub deprioritized_until: Option<Instant>,
}

impl RelayEntry {
    /// Create a new relay entry.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            health: RelayHealth::Healthy,
            latency: None,
            region: String::new(),
            load_pct: 0,
            active_connections: 0,
            added_at: Instant::now(),
            last_success: None,
            last_probe: None,
            failure_times: Vec::new(),
            consecutive_failures: 0,
            backoff_until: None,
            deprioritized_until: None,
        }
    }

    /// Create a relay entry from NS discovery info (rich format).
    pub fn from_info(info: &RelayInfo) -> Self {
        Self {
            addr: info.addr,
            health: info.health,
            latency: Some(Duration::from_millis(info.latency_ms as u64)),
            region: info.region.clone(),
            load_pct: info.load_pct,
            active_connections: info.active_connections,
            added_at: Instant::now(),
            last_success: None,
            last_probe: None,
            failure_times: Vec::new(),
            consecutive_failures: 0,
            backoff_until: None,
            deprioritized_until: None,
        }
    }

    /// Record a successful probe with the measured latency.
    pub fn record_success(&mut self, latency: Duration) {
        let now = Instant::now();
        self.latency = Some(latency);
        self.last_success = Some(now);
        self.last_probe = Some(now);
        self.consecutive_failures = 0;
        self.backoff_until = None;
        self.deprioritized_until = None;
        self.health = RelayHealth::Healthy;
        debug!("relay {} probe success: {:?}", self.addr, latency);
    }

    /// Record a failed probe attempt.
    pub fn record_failure(&mut self) {
        let now = Instant::now();
        self.last_probe = Some(now);
        self.consecutive_failures += 1;
        self.failure_times.push(now);

        // Trim old failure timestamps outside the deprioritization window
        self.failure_times
            .retain(|t| now.duration_since(*t) < DEPRIORITIZE_WINDOW);

        // Calculate exponential backoff
        let backoff_secs = BACKOFF_BASE.as_secs()
            * 2u64.saturating_pow(self.consecutive_failures.saturating_sub(1));
        let backoff = Duration::from_secs(backoff_secs.min(BACKOFF_MAX.as_secs()));
        self.backoff_until = Some(now + backoff);

        // Check for deprioritization
        if self.failure_times.len() >= DEPRIORITIZE_FAILURE_COUNT {
            self.health = RelayHealth::Deprioritized;
            self.deprioritized_until = Some(now + DEPRIORITIZE_DURATION);
            warn!(
                "relay {} deprioritized for {}s after {} failures in {}s window",
                self.addr,
                DEPRIORITIZE_DURATION.as_secs(),
                self.failure_times.len(),
                DEPRIORITIZE_WINDOW.as_secs(),
            );
        } else {
            self.health = RelayHealth::Dead;
        }

        debug!(
            "relay {} probe failure #{}, backoff {:?}",
            self.addr, self.consecutive_failures, backoff
        );
    }

    /// Mark relay as degraded (still reachable but underperforming).
    pub fn mark_degraded(&mut self) {
        if self.health == RelayHealth::Healthy {
            self.health = RelayHealth::Degraded;
            info!("relay {} marked as degraded", self.addr);
        }
    }

    /// Mark relay as dead.
    pub fn mark_dead(&mut self) {
        self.health = RelayHealth::Dead;
        self.consecutive_failures += 1;
        let now = Instant::now();
        self.failure_times.push(now);
        self.failure_times
            .retain(|t| now.duration_since(*t) < DEPRIORITIZE_WINDOW);

        if self.failure_times.len() >= DEPRIORITIZE_FAILURE_COUNT {
            self.health = RelayHealth::Deprioritized;
            self.deprioritized_until = Some(now + DEPRIORITIZE_DURATION);
        }

        let backoff_secs = BACKOFF_BASE.as_secs()
            * 2u64.saturating_pow(self.consecutive_failures.saturating_sub(1));
        let backoff = Duration::from_secs(backoff_secs.min(BACKOFF_MAX.as_secs()));
        self.backoff_until = Some(now + backoff);

        info!("relay {} marked as dead", self.addr);
    }

    /// Check if this relay is available for selection (not in backoff or deprioritized).
    pub fn is_available(&self) -> bool {
        let now = Instant::now();

        // Check backoff
        if let Some(until) = self.backoff_until {
            if now < until {
                return false;
            }
        }

        // Check deprioritization
        if let Some(until) = self.deprioritized_until {
            if now < until {
                return false;
            }
            // Deprioritization expired — allow retry
        }

        matches!(self.health, RelayHealth::Healthy | RelayHealth::Degraded)
    }

    /// Check if this relay is eligible for probing (backoff expired).
    pub fn is_probe_eligible(&self) -> bool {
        let now = Instant::now();
        if let Some(until) = self.backoff_until {
            now >= until
        } else {
            true
        }
    }

    /// Sorting score: lower is better. Load-adjusted formula with health penalty.
    ///
    /// Formula: `latency_ms * (1 + load_pct / 100) + health_penalty`
    ///
    /// Load-adjusted scoring: a relay at 20ms latency with 10% load scores 22,
    /// while a relay at 15ms latency with 80% load scores 27 — the less-loaded
    /// relay wins despite higher latency.
    pub fn score(&self) -> u64 {
        let latency_ms = self.latency.map(|d| d.as_millis() as u64).unwrap_or(10_000);

        // Load-adjusted: multiply latency by (1 + load/100)
        // load_pct is 0-100, so (1 + load/100) ranges from 1.0 to 2.0
        // We use integer math: (latency_ms * (100 + load_pct)) / 100
        let load_adjusted = (latency_ms * (100 + self.load_pct as u64)) / 100;

        let health_penalty = match self.health {
            RelayHealth::Healthy => 0,
            RelayHealth::Degraded => 500,
            RelayHealth::Dead => 100_000,
            RelayHealth::Deprioritized => 200_000,
        };

        load_adjusted + health_penalty
    }

    /// Compare two relays for selection, considering region preference.
    ///
    /// Returns `Ordering::Less` if `self` is preferred over `other`.
    /// Tiebreak order: score → same-region bonus → fewer active connections.
    pub fn cmp_for_selection(&self, other: &RelayEntry, gateway_region: &str) -> std::cmp::Ordering {
        // Primary: score (lower is better)
        let score_cmp = self.score().cmp(&other.score());
        if score_cmp != std::cmp::Ordering::Equal {
            return score_cmp;
        }

        // Tiebreak 1: same region as gateway wins (prefer local)
        let self_local = self.region == gateway_region;
        let other_local = other.region == gateway_region;
        match (self_local, other_local) {
            (true, false) => return std::cmp::Ordering::Less,
            (false, true) => return std::cmp::Ordering::Greater,
            _ => {}
        }

        // Tiebreak 2: fewer active connections wins
        self.active_connections.cmp(&other.active_connections)
    }

    /// Current backoff duration remaining.
    pub fn backoff_remaining(&self) -> Option<Duration> {
        self.backoff_until
            .and_then(|until| until.checked_duration_since(Instant::now()))
    }
}

// ─── Failover Decision ──────────────────────────────────────────────────────

/// Result of a failover attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverDecision {
    /// Use this relay address.
    UseRelay(SocketAddr),
    /// No relays available — request NS refresh.
    NeedNsRefresh,
    /// No relays available and NS refresh already attempted.
    NoRelaysAvailable,
}

/// Result of a relay handshake attempt during failover.
#[derive(Debug, Clone)]
pub enum HandshakeResult {
    /// Handshake succeeded through this relay.
    Success {
        relay_addr: SocketAddr,
        latency: Duration,
    },
    /// Handshake failed through this relay.
    Failure {
        relay_addr: SocketAddr,
        error: String,
    },
}

// ─── Relay Pool ─────────────────────────────────────────────────────────────

/// Configuration for the relay pool.
#[derive(Debug, Clone)]
pub struct RelayPoolConfig {
    /// Interval between health probes.
    pub probe_interval: Duration,
    /// Whether failover is enabled.
    pub failover_enabled: bool,
    /// Pin to a specific relay (disables failover).
    pub pinned_relay: Option<SocketAddr>,
    /// NS server address for relay discovery.
    pub ns_server: Option<String>,
    /// Zone to query for relays.
    pub zone: Option<String>,
    /// Gateway region for relay selection tiebreak (e.g., "us-west-2").
    pub gateway_region: String,
}

impl Default for RelayPoolConfig {
    fn default() -> Self {
        Self {
            probe_interval: DEFAULT_PROBE_INTERVAL,
            failover_enabled: true,
            pinned_relay: None,
            ns_server: None,
            zone: None,
            gateway_region: String::new(),
        }
    }
}

/// The relay pool manages a ranked set of relay servers with health tracking.
#[derive(Debug)]
pub struct RelayPool {
    /// Relay entries indexed by address.
    relays: HashMap<SocketAddr, RelayEntry>,
    /// Address of the current primary relay.
    primary: Option<SocketAddr>,
    /// Pool configuration.
    config: RelayPoolConfig,
    /// When we last queried NS for relays.
    last_ns_query: Option<Instant>,
    /// Total number of failover events.
    failover_count: u64,
    /// When the pool was created.
    created_at: Instant,
}

impl RelayPool {
    /// Create a new relay pool with the given configuration.
    pub fn new(config: RelayPoolConfig) -> Self {
        Self {
            relays: HashMap::new(),
            primary: config.pinned_relay,
            config,
            last_ns_query: None,
            failover_count: 0,
            created_at: Instant::now(),
        }
    }

    /// Create a relay pool from a list of relay addresses (e.g., from NS query).
    pub fn from_addresses(addrs: Vec<SocketAddr>, config: RelayPoolConfig) -> Self {
        let mut pool = Self::new(config);
        for addr in addrs {
            pool.add_relay(addr);
        }
        pool.last_ns_query = Some(Instant::now());
        pool
    }

    /// Add a relay to the pool.
    pub fn add_relay(&mut self, addr: SocketAddr) {
        if self.relays.len() >= MAX_POOL_SIZE {
            // Evict the worst relay
            if let Some(worst) = self.worst_relay() {
                self.relays.remove(&worst);
            }
        }

        self.relays.entry(addr).or_insert_with(|| {
            debug!("relay pool: added {}", addr);
            RelayEntry::new(addr)
        });

        // Set primary if none exists
        if self.primary.is_none() && self.config.pinned_relay.is_none() {
            self.primary = Some(addr);
        }
    }

    /// Remove a relay from the pool.
    pub fn remove_relay(&mut self, addr: &SocketAddr) {
        self.relays.remove(addr);
        if self.primary.as_ref() == Some(addr) {
            self.primary = self.best_available_relay();
        }
    }

    /// Update the pool with fresh relay addresses from NS.
    ///
    /// Adds new relays, keeps existing ones with their health history.
    pub fn update_from_ns(&mut self, addrs: Vec<SocketAddr>) {
        self.last_ns_query = Some(Instant::now());

        for addr in &addrs {
            self.add_relay(*addr);
        }

        // Prune relays that are both dead AND not in the fresh NS list
        let ns_set: std::collections::HashSet<SocketAddr> = addrs.into_iter().collect();
        let to_remove: Vec<SocketAddr> = self
            .relays
            .iter()
            .filter(|(addr, entry)| {
                !ns_set.contains(addr) && matches!(entry.health, RelayHealth::Dead)
            })
            .map(|(addr, _)| *addr)
            .collect();

        for addr in to_remove {
            self.remove_relay(&addr);
        }

        info!(
            "relay pool: updated from NS, {} relays available",
            self.relays.len()
        );
    }

    /// Update the pool with rich relay info from NS (includes stats).
    ///
    /// Unlike `update_from_ns`, this preserves and updates NS-provided
    /// stats (region, load, active_connections) for existing relays.
    pub fn update_from_ns_rich(&mut self, infos: Vec<RelayInfo>) {
        self.last_ns_query = Some(Instant::now());

        let mut fresh_addrs: std::collections::HashSet<SocketAddr> = Default::default();

        for info in &infos {
            fresh_addrs.insert(info.addr);

            if let Some(existing) = self.relays.get_mut(&info.addr) {
                // Update stats for existing relay (keep health history)
                existing.region = info.region.clone();
                existing.load_pct = info.load_pct;
                existing.active_connections = info.active_connections;
                // If NS reports the relay as Healthy, trust NS over our local health
                // only if our local state is worse (not if we've detected issues locally)
                if info.health == RelayHealth::Healthy
                    && matches!(
                        existing.health,
                        RelayHealth::Healthy | RelayHealth::Degraded
                    )
                {
                    existing.health = RelayHealth::Healthy;
                } else if info.health == RelayHealth::Degraded
                    && existing.health == RelayHealth::Healthy
                {
                    // NS says degraded but we haven't seen issues — trust NS as early signal
                    existing.health = RelayHealth::Degraded;
                }
                // Don't override Dead/Deprioritized from NS — our local probe is more authoritative
            } else {
                // New relay from NS
                self.add_relay_from_info(info);
            }
        }

        // Prune relays that are both dead AND not in the fresh NS list
        let to_remove: Vec<SocketAddr> = self
            .relays
            .iter()
            .filter(|(addr, entry)| {
                !fresh_addrs.contains(addr) && matches!(entry.health, RelayHealth::Dead)
            })
            .map(|(addr, _)| *addr)
            .collect();

        for addr in to_remove {
            self.remove_relay(&addr);
        }

        // Re-evaluate primary after stats update
        if self.config.pinned_relay.is_none() {
            if let Some(best) = self.best_available_relay() {
                if self.primary != Some(best) {
                    let old = self.primary;
                    self.primary = Some(best);
                    if old != Some(best) {
                        info!(
                            "relay pool: primary changed from {:?} to {} after NS stats update",
                            old, best
                        );
                    }
                }
            }
        }

        info!(
            "relay pool: updated from NS (rich), {} relays available",
            self.relays.len()
        );
    }

    /// Add a relay to the pool from NS discovery info.
    pub fn add_relay_from_info(&mut self, info: &RelayInfo) {
        if self.relays.len() >= MAX_POOL_SIZE {
            if let Some(worst) = self.worst_relay() {
                self.relays.remove(&worst);
            }
        }

        self.relays
            .entry(info.addr)
            .or_insert_with(|| RelayEntry::from_info(info));

        // Set primary if none exists
        if self.primary.is_none() && self.config.pinned_relay.is_none() {
            self.primary = Some(info.addr);
        }
    }

    /// Select the best relay considering region preference.
    ///
    /// Unlike `best_available_relay()`, this uses `cmp_for_selection()` which
    /// considers region tiebreak and active connections in addition to score.
    pub fn select_best(&self, gateway_region: &str) -> Option<SocketAddr> {
        let available: Vec<&RelayEntry> = self
            .relays
            .values()
            .filter(|e| e.is_available())
            .collect();

        available
            .into_iter()
            .min_by(|a, b| a.cmp_for_selection(b, gateway_region))
            .map(|e| e.addr)
    }

    /// Get the current primary relay address.
    pub fn primary(&self) -> Option<SocketAddr> {
        if let Some(pinned) = self.config.pinned_relay {
            return Some(pinned);
        }
        self.primary
    }

    /// Get the primary relay entry.
    pub fn primary_entry(&self) -> Option<&RelayEntry> {
        self.primary.and_then(|addr| self.relays.get(&addr))
    }

    /// Get all relay entries, sorted by score (best first).
    pub fn ranked_relays(&self) -> Vec<&RelayEntry> {
        let mut entries: Vec<&RelayEntry> = self.relays.values().collect();
        entries.sort_by_key(|e| e.score());
        entries
    }

    /// Get the best available relay (healthy, not in backoff).
    fn best_available_relay(&self) -> Option<SocketAddr> {
        self.relays
            .values()
            .filter(|e| e.is_available())
            .min_by_key(|e| e.score())
            .map(|e| e.addr)
    }

    /// Get the worst relay (highest score).
    fn worst_relay(&self) -> Option<SocketAddr> {
        self.relays
            .values()
            .max_by_key(|e| e.score())
            .map(|e| e.addr)
    }

    /// Record a successful probe for a relay.
    pub fn record_probe_success(&mut self, addr: SocketAddr, latency: Duration) {
        if let Some(entry) = self.relays.get_mut(&addr) {
            entry.record_success(latency);
        }

        // Re-evaluate primary if the successful relay is better
        if self.config.pinned_relay.is_none() {
            if let Some(best) = self.best_available_relay() {
                if self.primary != Some(best) {
                    let old = self.primary;
                    self.primary = Some(best);
                    if old != Some(best) {
                        info!(
                            "relay pool: primary changed from {:?} to {} (better score)",
                            old, best
                        );
                    }
                }
            }
        }
    }

    /// Record a failed probe for a relay.
    pub fn record_probe_failure(&mut self, addr: SocketAddr) {
        if let Some(entry) = self.relays.get_mut(&addr) {
            entry.record_failure();
        }

        // If the primary failed, find a new one
        if self.primary == Some(addr) && self.config.pinned_relay.is_none() {
            self.primary = self.best_available_relay();
            if let Some(new_primary) = self.primary {
                info!("relay pool: primary failed, switched to {}", new_primary);
            } else {
                warn!("relay pool: primary failed, no available backups");
            }
        }
    }

    /// Mark the current primary relay as degraded and select the next best.
    ///
    /// Called when the TunnelHealthMonitor transitions to `Reestablishing`.
    /// Returns the new relay to try, or NeedNsRefresh if none available.
    pub fn failover_degraded(&mut self) -> FailoverDecision {
        if let Some(pinned) = self.config.pinned_relay {
            return FailoverDecision::UseRelay(pinned);
        }

        // Mark current primary as degraded
        if let Some(primary_addr) = self.primary {
            if let Some(entry) = self.relays.get_mut(&primary_addr) {
                entry.mark_degraded();
            }
        }

        // Select next best
        match self.best_available_relay() {
            Some(addr) => {
                let old_primary = self.primary;
                self.primary = Some(addr);
                self.failover_count += 1;
                info!(
                    "relay pool: failover #{} from {:?} to {} (degraded)",
                    self.failover_count, old_primary, addr
                );
                FailoverDecision::UseRelay(addr)
            }
            None => {
                info!("relay pool: no available relays, requesting NS refresh");
                FailoverDecision::NeedNsRefresh
            }
        }
    }

    /// Mark the current primary relay as dead and try all remaining relays.
    ///
    /// Called when the TunnelHealthMonitor transitions to `Dead`.
    /// Returns an iterator of relay addresses to try in order.
    pub fn failover_dead(&mut self) -> FailoverDecision {
        if let Some(pinned) = self.config.pinned_relay {
            return FailoverDecision::UseRelay(pinned);
        }

        // Mark current primary as dead
        if let Some(primary_addr) = self.primary {
            if let Some(entry) = self.relays.get_mut(&primary_addr) {
                entry.mark_dead();
            }
        }

        // Try all remaining relays in score order
        match self.best_available_relay() {
            Some(addr) => {
                let old_primary = self.primary;
                self.primary = Some(addr);
                self.failover_count += 1;
                info!(
                    "relay pool: failover #{} from {:?} to {} (dead)",
                    self.failover_count, old_primary, addr
                );
                FailoverDecision::UseRelay(addr)
            }
            None => {
                info!("relay pool: all relays exhausted, requesting NS refresh");
                FailoverDecision::NeedNsRefresh
            }
        }
    }

    /// Get all relay addresses to try during a dead-failover, ordered by score.
    ///
    /// Excludes the current (dead) primary. Includes relays in backoff
    /// since we're in emergency mode.
    pub fn failover_candidates(&self) -> Vec<SocketAddr> {
        let current_primary = self.primary;
        let mut candidates: Vec<&RelayEntry> = self
            .relays
            .values()
            .filter(|e| Some(e.addr) != current_primary)
            .filter(|e| !matches!(e.health, RelayHealth::Deprioritized))
            .collect();
        candidates.sort_by_key(|e| e.score());
        candidates.into_iter().map(|e| e.addr).collect()
    }

    /// Get all relay addresses including deprioritized (last resort).
    pub fn all_candidates(&self) -> Vec<SocketAddr> {
        let current_primary = self.primary;
        let mut candidates: Vec<&RelayEntry> = self
            .relays
            .values()
            .filter(|e| Some(e.addr) != current_primary)
            .collect();
        candidates.sort_by_key(|e| e.score());
        candidates.into_iter().map(|e| e.addr).collect()
    }

    /// Report a successful handshake through a relay (after failover).
    pub fn report_handshake_success(&mut self, addr: SocketAddr, latency: Duration) {
        if let Some(entry) = self.relays.get_mut(&addr) {
            entry.record_success(latency);
        }
        self.primary = Some(addr);
        info!(
            "relay pool: failover successful, new primary: {} (latency: {:?})",
            addr, latency
        );
    }

    /// Report a failed handshake through a relay (during failover).
    pub fn report_handshake_failure(&mut self, addr: SocketAddr) {
        if let Some(entry) = self.relays.get_mut(&addr) {
            entry.record_failure();
        }
    }

    /// Get relays that need probing (probe interval elapsed, not in backoff).
    pub fn relays_needing_probe(&self) -> Vec<SocketAddr> {
        let now = Instant::now();
        self.relays
            .values()
            .filter(|e| {
                let since_probe = e
                    .last_probe
                    .map(|t| now.duration_since(t))
                    .unwrap_or(Duration::from_secs(u64::MAX));
                since_probe >= self.config.probe_interval && e.is_probe_eligible()
            })
            .map(|e| e.addr)
            .collect()
    }

    /// Check if an NS refresh is needed (all relays dead or pool empty).
    pub fn needs_ns_refresh(&self) -> bool {
        if self.relays.is_empty() {
            return true;
        }

        // Check if any relay is available
        !self.relays.values().any(|e| e.is_available())
    }

    /// Check if failover is enabled and useful (multiple relays available).
    pub fn failover_available(&self) -> bool {
        self.config.failover_enabled && self.relays.len() > 1
    }

    /// Number of relays in the pool.
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Number of healthy relays.
    pub fn healthy_count(&self) -> usize {
        self.relays
            .values()
            .filter(|e| matches!(e.health, RelayHealth::Healthy))
            .count()
    }

    /// Total number of failover events since pool creation.
    pub fn failover_count(&self) -> u64 {
        self.failover_count
    }

    /// Get a relay entry by address.
    pub fn get_relay(&self, addr: &SocketAddr) -> Option<&RelayEntry> {
        self.relays.get(addr)
    }

    /// Get a mutable relay entry by address.
    pub fn get_relay_mut(&mut self, addr: &SocketAddr) -> Option<&mut RelayEntry> {
        self.relays.get_mut(addr)
    }

    /// Get the pool configuration.
    pub fn config(&self) -> &RelayPoolConfig {
        &self.config
    }

    /// Duration since pool creation.
    pub fn uptime(&self) -> Duration {
        Instant::now().duration_since(self.created_at)
    }

    /// Generate a human-readable status summary.
    pub fn status_summary(&self) -> PoolStatus {
        let ranked = self.ranked_relays();
        let entries: Vec<RelayStatusEntry> = ranked
            .iter()
            .map(|e| RelayStatusEntry {
                addr: e.addr,
                health: e.health,
                latency: e.latency,
                is_primary: self.primary == Some(e.addr),
                consecutive_failures: e.consecutive_failures,
                backoff_remaining: e.backoff_remaining(),
            })
            .collect();

        PoolStatus {
            relays: entries,
            primary: self.primary,
            failover_enabled: self.config.failover_enabled,
            failover_count: self.failover_count,
            uptime: self.uptime(),
        }
    }
}

/// Summary of pool status for display.
#[derive(Debug, Clone)]
pub struct PoolStatus {
    pub relays: Vec<RelayStatusEntry>,
    pub primary: Option<SocketAddr>,
    pub failover_enabled: bool,
    pub failover_count: u64,
    pub uptime: Duration,
}

/// Summary of a single relay's status.
#[derive(Debug, Clone)]
pub struct RelayStatusEntry {
    pub addr: SocketAddr,
    pub health: RelayHealth,
    pub latency: Option<Duration>,
    pub is_primary: bool,
    pub consecutive_failures: u32,
    pub backoff_remaining: Option<Duration>,
}

impl std::fmt::Display for PoolStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Relay Pool Status")?;
        writeln!(
            f,
            "  Failover: {}",
            if self.failover_enabled {
                "enabled"
            } else {
                "disabled"
            }
        )?;
        writeln!(f, "  Failovers: {}", self.failover_count)?;
        writeln!(f, "  Uptime: {:?}", self.uptime)?;
        writeln!(f, "  Relays: {}", self.relays.len())?;
        writeln!(f)?;

        for entry in &self.relays {
            let primary_mark = if entry.is_primary { " ★" } else { "" };
            let latency_str = entry
                .latency
                .map(|d| format!("{:.1}ms", d.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "n/a".to_string());
            let backoff_str = entry
                .backoff_remaining
                .map(|d| format!(" (backoff: {:.0}s)", d.as_secs_f64()))
                .unwrap_or_default();

            writeln!(
                f,
                "  {}{} — {} | latency: {} | failures: {}{}",
                entry.addr,
                primary_mark,
                entry.health,
                latency_str,
                entry.consecutive_failures,
                backoff_str,
            )?;
        }

        Ok(())
    }
}

// ─── Failover Orchestrator ──────────────────────────────────────────────────

/// Manages the failover process, coordinating between the health monitor
/// and the relay pool.
///
/// This is the high-level interface that the client's connection loop uses.
#[derive(Debug)]
pub struct FailoverOrchestrator {
    /// The relay pool.
    pool: RelayPool,
    /// Whether a failover is currently in progress.
    failover_in_progress: bool,
    /// When the current failover started.
    failover_started: Option<Instant>,
    /// Maximum time to spend on failover before giving up.
    failover_timeout: Duration,
    /// Whether we've already tried an NS refresh in this failover cycle.
    ns_refresh_attempted: bool,
}

impl FailoverOrchestrator {
    /// Create a new failover orchestrator.
    pub fn new(pool: RelayPool) -> Self {
        Self {
            pool,
            failover_in_progress: false,
            failover_started: None,
            failover_timeout: Duration::from_secs(30),
            ns_refresh_attempted: false,
        }
    }

    /// Access the underlying pool.
    pub fn pool(&self) -> &RelayPool {
        &self.pool
    }

    /// Access the underlying pool mutably.
    pub fn pool_mut(&mut self) -> &mut RelayPool {
        &mut self.pool
    }

    /// Start a degraded failover (health monitor → Reestablishing).
    ///
    /// Returns the next relay to try.
    pub fn start_degraded_failover(&mut self) -> FailoverDecision {
        if !self.pool.config.failover_enabled {
            if let Some(primary) = self.pool.primary() {
                return FailoverDecision::UseRelay(primary);
            }
            return FailoverDecision::NoRelaysAvailable;
        }

        self.failover_in_progress = true;
        self.failover_started = Some(Instant::now());
        self.ns_refresh_attempted = false;

        info!("relay failover: starting degraded failover");
        self.pool.failover_degraded()
    }

    /// Start a dead failover (health monitor → Dead).
    ///
    /// Returns candidates to try in order.
    pub fn start_dead_failover(&mut self) -> (FailoverDecision, Vec<SocketAddr>) {
        if !self.pool.config.failover_enabled {
            if let Some(primary) = self.pool.primary() {
                return (FailoverDecision::UseRelay(primary), vec![]);
            }
            return (FailoverDecision::NoRelaysAvailable, vec![]);
        }

        self.failover_in_progress = true;
        self.failover_started = Some(Instant::now());
        self.ns_refresh_attempted = false;

        info!("relay failover: starting dead failover (trying all relays)");
        let candidates = self.pool.failover_candidates();
        let decision = self.pool.failover_dead();
        (decision, candidates)
    }

    /// Report the result of a handshake attempt during failover.
    pub fn report_attempt(&mut self, result: HandshakeResult) -> Option<FailoverDecision> {
        match result {
            HandshakeResult::Success {
                relay_addr,
                latency,
            } => {
                self.pool.report_handshake_success(relay_addr, latency);
                self.failover_in_progress = false;
                self.failover_started = None;
                info!(
                    "relay failover: complete — new primary {} (latency: {:?})",
                    relay_addr, latency
                );
                None // Failover complete
            }
            HandshakeResult::Failure { relay_addr, error } => {
                self.pool.report_handshake_failure(relay_addr);
                warn!(
                    "relay failover: handshake to {} failed: {}",
                    relay_addr, error
                );

                // Check timeout
                if let Some(started) = self.failover_started {
                    if Instant::now().duration_since(started) > self.failover_timeout {
                        warn!(
                            "relay failover: timed out after {:?}",
                            self.failover_timeout
                        );
                        self.failover_in_progress = false;
                        return Some(FailoverDecision::NoRelaysAvailable);
                    }
                }

                // Try next relay
                match self.pool.best_available_relay() {
                    Some(addr) => Some(FailoverDecision::UseRelay(addr)),
                    None => {
                        if !self.ns_refresh_attempted {
                            self.ns_refresh_attempted = true;
                            Some(FailoverDecision::NeedNsRefresh)
                        } else {
                            self.failover_in_progress = false;
                            Some(FailoverDecision::NoRelaysAvailable)
                        }
                    }
                }
            }
        }
    }

    /// Provide fresh NS relay addresses after an NS refresh.
    pub fn provide_ns_relays(&mut self, addrs: Vec<SocketAddr>) -> FailoverDecision {
        self.pool.update_from_ns(addrs);

        match self.pool.best_available_relay() {
            Some(addr) => {
                self.pool.primary = Some(addr);
                FailoverDecision::UseRelay(addr)
            }
            None => {
                self.failover_in_progress = false;
                FailoverDecision::NoRelaysAvailable
            }
        }
    }

    /// Check if a failover is currently in progress.
    pub fn is_failover_in_progress(&self) -> bool {
        self.failover_in_progress
    }

    /// Cancel an in-progress failover.
    pub fn cancel_failover(&mut self) {
        self.failover_in_progress = false;
        self.failover_started = None;
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn relay_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
    }

    fn relay_addr2(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port)
    }

    fn relay_addr3(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), port)
    }

    fn default_config() -> RelayPoolConfig {
        RelayPoolConfig::default()
    }

    // ── Relay Entry Tests ───────────────────────────────────────────

    #[test]
    fn test_relay_entry_new() {
        let entry = RelayEntry::new(relay_addr(23095));
        assert_eq!(entry.health, RelayHealth::Healthy);
        assert_eq!(entry.latency, None);
        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.is_available());
    }

    #[test]
    fn test_relay_entry_success_resets_state() {
        let mut entry = RelayEntry::new(relay_addr(23095));
        entry.consecutive_failures = 3;
        entry.health = RelayHealth::Dead;
        entry.backoff_until = Some(Instant::now() + Duration::from_secs(60));

        entry.record_success(Duration::from_millis(15));

        assert_eq!(entry.health, RelayHealth::Healthy);
        assert_eq!(entry.consecutive_failures, 0);
        assert!(entry.backoff_until.is_none());
        assert_eq!(entry.latency, Some(Duration::from_millis(15)));
        assert!(entry.is_available());
    }

    #[test]
    fn test_relay_entry_failure_increments() {
        let mut entry = RelayEntry::new(relay_addr(23095));

        entry.record_failure();
        assert_eq!(entry.consecutive_failures, 1);
        assert_eq!(entry.health, RelayHealth::Dead);
        assert!(entry.backoff_until.is_some());
    }

    #[test]
    fn test_relay_entry_exponential_backoff() {
        let mut entry = RelayEntry::new(relay_addr(23095));
        let now = Instant::now();

        // First failure: 5s backoff
        entry.record_failure();
        let backoff1 = entry.backoff_until.unwrap().duration_since(now);
        assert!(backoff1 >= Duration::from_secs(4)); // ~5s with timing tolerance
        assert!(backoff1 <= Duration::from_secs(6));

        // Immediately record second failure (reset backoff_until)
        entry.record_failure();
        let backoff2 = entry.backoff_until.unwrap().duration_since(Instant::now());
        // 2nd failure: 5 * 2^1 = 10s
        assert!(backoff2 >= Duration::from_secs(9));
        assert!(backoff2 <= Duration::from_secs(11));

        // Third failure: 5 * 2^2 = 20s
        entry.record_failure();
        let backoff3 = entry.backoff_until.unwrap().duration_since(Instant::now());
        assert!(backoff3 >= Duration::from_secs(19));
        assert!(backoff3 <= Duration::from_secs(21));
    }

    #[test]
    fn test_relay_entry_backoff_max_cap() {
        let mut entry = RelayEntry::new(relay_addr(23095));

        // Many failures should cap at 60s
        for _ in 0..10 {
            entry.record_failure();
        }

        let backoff = entry.backoff_until.unwrap().duration_since(Instant::now());
        assert!(backoff <= Duration::from_secs(61));
    }

    #[test]
    fn test_relay_entry_deprioritization() {
        let mut entry = RelayEntry::new(relay_addr(23095));

        // 3 failures in 10 minutes → deprioritized
        for _ in 0..DEPRIORITIZE_FAILURE_COUNT {
            entry.record_failure();
            // Reset backoff to allow next failure immediately in test
            entry.backoff_until = None;
        }

        assert_eq!(entry.health, RelayHealth::Deprioritized);
        assert!(entry.deprioritized_until.is_some());
    }

    #[test]
    fn test_relay_entry_score_ordering() {
        let mut healthy = RelayEntry::new(relay_addr(1));
        healthy.latency = Some(Duration::from_millis(10));

        let mut degraded = RelayEntry::new(relay_addr(2));
        degraded.health = RelayHealth::Degraded;
        degraded.latency = Some(Duration::from_millis(10));

        let mut dead = RelayEntry::new(relay_addr(3));
        dead.health = RelayHealth::Dead;
        dead.latency = Some(Duration::from_millis(10));

        assert!(healthy.score() < degraded.score());
        assert!(degraded.score() < dead.score());
    }

    #[test]
    fn test_relay_entry_score_latency_ordering() {
        let mut fast = RelayEntry::new(relay_addr(1));
        fast.latency = Some(Duration::from_millis(10));

        let mut slow = RelayEntry::new(relay_addr(2));
        slow.latency = Some(Duration::from_millis(100));

        assert!(fast.score() < slow.score());
    }

    #[test]
    fn test_relay_entry_not_available_during_backoff() {
        let mut entry = RelayEntry::new(relay_addr(23095));
        entry.record_failure();
        // During backoff, entry should not be available
        assert!(!entry.is_available());
    }

    #[test]
    fn test_relay_entry_mark_degraded() {
        let mut entry = RelayEntry::new(relay_addr(23095));
        assert_eq!(entry.health, RelayHealth::Healthy);
        entry.mark_degraded();
        assert_eq!(entry.health, RelayHealth::Degraded);
        assert!(entry.is_available()); // Degraded is still available
    }

    #[test]
    fn test_relay_entry_mark_dead() {
        let mut entry = RelayEntry::new(relay_addr(23095));
        entry.mark_dead();
        assert_eq!(entry.health, RelayHealth::Dead);
        assert!(!entry.is_available()); // Dead with backoff not available
    }

    // ── Relay Pool Tests ────────────────────────────────────────────

    #[test]
    fn test_pool_from_addresses() {
        let addrs = vec![relay_addr(1), relay_addr(2), relay_addr(3)];
        let pool = RelayPool::from_addresses(addrs.clone(), default_config());

        assert_eq!(pool.len(), 3);
        assert_eq!(pool.primary(), Some(relay_addr(1)));
        assert!(pool.last_ns_query.is_some());
    }

    #[test]
    fn test_pool_empty() {
        let pool = RelayPool::new(default_config());
        assert!(pool.is_empty());
        assert_eq!(pool.primary(), None);
        assert!(pool.needs_ns_refresh());
    }

    #[test]
    fn test_pool_add_sets_primary() {
        let mut pool = RelayPool::new(default_config());
        pool.add_relay(relay_addr(23095));
        assert_eq!(pool.primary(), Some(relay_addr(23095)));
    }

    #[test]
    fn test_pool_remove_primary_selects_new() {
        let addrs = vec![relay_addr(1), relay_addr(2)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());

        // Make relay 2 have a known latency so it becomes best
        pool.record_probe_success(relay_addr(2), Duration::from_millis(10));
        pool.record_probe_success(relay_addr(1), Duration::from_millis(20));

        // Primary should be the lower-latency one
        assert_eq!(pool.primary(), Some(relay_addr(2)));

        // Remove primary
        pool.remove_relay(&relay_addr(2));
        assert_eq!(pool.primary(), Some(relay_addr(1)));
    }

    #[test]
    fn test_pool_ranking_by_latency() {
        let addrs = vec![relay_addr(1), relay_addr(2), relay_addr(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());

        pool.record_probe_success(relay_addr(1), Duration::from_millis(30));
        pool.record_probe_success(relay_addr(2), Duration::from_millis(10));
        pool.record_probe_success(relay_addr(3), Duration::from_millis(20));

        let ranked = pool.ranked_relays();
        assert_eq!(ranked[0].addr, relay_addr(2)); // 10ms
        assert_eq!(ranked[1].addr, relay_addr(3)); // 20ms
        assert_eq!(ranked[2].addr, relay_addr(1)); // 30ms
    }

    #[test]
    fn test_pool_failover_degraded() {
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());

        // Give relays latencies
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        pool.record_probe_success(relay_addr3(3), Duration::from_millis(30));

        assert_eq!(pool.primary(), Some(relay_addr(1)));

        // Failover from primary
        let decision = pool.failover_degraded();
        match decision {
            FailoverDecision::UseRelay(addr) => {
                assert_eq!(addr, relay_addr2(2)); // Next best
            }
            _ => panic!("Expected UseRelay"),
        }
        assert_eq!(pool.primary(), Some(relay_addr2(2)));
    }

    #[test]
    fn test_pool_failover_dead() {
        let addrs = vec![relay_addr(1), relay_addr2(2)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());

        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));

        let decision = pool.failover_dead();
        match decision {
            FailoverDecision::UseRelay(addr) => {
                assert_eq!(addr, relay_addr2(2));
            }
            _ => panic!("Expected UseRelay"),
        }
    }

    #[test]
    fn test_pool_failover_dead_no_relays() {
        let addrs = vec![relay_addr(1)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());

        let decision = pool.failover_dead();
        assert_eq!(decision, FailoverDecision::NeedNsRefresh);
    }

    #[test]
    fn test_pool_failover_candidates() {
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());

        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        pool.record_probe_success(relay_addr3(3), Duration::from_millis(30));

        let candidates = pool.failover_candidates();
        // Should exclude primary (relay_addr(1))
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0], relay_addr2(2));
        assert_eq!(candidates[1], relay_addr3(3));
    }

    #[test]
    fn test_pool_failover_skip_degraded_dead() {
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());

        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        pool.record_probe_success(relay_addr3(3), Duration::from_millis(30));

        // Mark relay 2 as dead
        pool.record_probe_failure(relay_addr2(2));

        // Failover from primary should skip dead relay 2
        let decision = pool.failover_degraded();
        match decision {
            FailoverDecision::UseRelay(addr) => {
                assert_eq!(addr, relay_addr3(3)); // Skips dead relay 2
            }
            _ => panic!("Expected UseRelay"),
        }
    }

    #[test]
    fn test_pool_update_from_ns() {
        let mut pool =
            RelayPool::from_addresses(vec![relay_addr(1), relay_addr2(2)], default_config());

        // Simulate relay 1 dying
        pool.record_probe_failure(relay_addr(1));
        if let Some(entry) = pool.relays.get_mut(&relay_addr(1)) {
            entry.health = RelayHealth::Dead;
        }

        // NS refresh returns new relay 3, keeps 2, drops dead 1
        pool.update_from_ns(vec![relay_addr2(2), relay_addr3(3)]);

        assert_eq!(pool.len(), 2); // Dead relay 1 pruned, new 3 added
        assert!(pool.get_relay(&relay_addr2(2)).is_some());
        assert!(pool.get_relay(&relay_addr3(3)).is_some());
        assert!(pool.get_relay(&relay_addr(1)).is_none()); // Pruned
    }

    #[test]
    fn test_pool_update_from_ns_keeps_healthy() {
        let mut pool =
            RelayPool::from_addresses(vec![relay_addr(1), relay_addr2(2)], default_config());

        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));

        // NS refresh doesn't include relay 1, but it's healthy → keep it
        pool.update_from_ns(vec![relay_addr2(2), relay_addr3(3)]);

        assert_eq!(pool.len(), 3);
        assert!(pool.get_relay(&relay_addr(1)).is_some()); // Kept (healthy)
    }

    #[test]
    fn test_pool_pinned_relay() {
        let config = RelayPoolConfig {
            pinned_relay: Some(relay_addr(42)),
            ..default_config()
        };
        let mut pool = RelayPool::from_addresses(vec![relay_addr(1), relay_addr(42)], config);

        assert_eq!(pool.primary(), Some(relay_addr(42)));

        // Failover should return pinned relay
        let decision = pool.failover_degraded();
        assert_eq!(decision, FailoverDecision::UseRelay(relay_addr(42)));
    }

    #[test]
    fn test_pool_healthy_count() {
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());

        assert_eq!(pool.healthy_count(), 3);

        pool.record_probe_failure(relay_addr2(2));
        assert_eq!(pool.healthy_count(), 2);
    }

    #[test]
    fn test_pool_needs_ns_refresh() {
        let pool = RelayPool::new(default_config());
        assert!(pool.needs_ns_refresh()); // Empty pool

        let mut pool = RelayPool::from_addresses(vec![relay_addr(1)], default_config());
        assert!(!pool.needs_ns_refresh()); // Has a relay

        // Mark all dead
        pool.record_probe_failure(relay_addr(1));
        assert!(pool.needs_ns_refresh()); // All dead
    }

    #[test]
    fn test_pool_relays_needing_probe() {
        let config = RelayPoolConfig {
            probe_interval: Duration::from_millis(10),
            ..default_config()
        };
        let mut pool = RelayPool::from_addresses(vec![relay_addr(1)], config);

        // Just created, needs probe (last_probe is None)
        let needing = pool.relays_needing_probe();
        assert_eq!(needing.len(), 1);

        // After probing, shouldn't need another immediately
        pool.record_probe_success(relay_addr(1), Duration::from_millis(5));
        let needing = pool.relays_needing_probe();
        assert!(needing.is_empty());
    }

    #[test]
    fn test_pool_max_size_eviction() {
        let mut pool = RelayPool::new(default_config());

        // Add MAX_POOL_SIZE + 1 relays
        for i in 0..MAX_POOL_SIZE + 1 {
            pool.add_relay(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
                23095,
            ));
        }

        assert_eq!(pool.len(), MAX_POOL_SIZE);
    }

    #[test]
    fn test_pool_status_summary() {
        let addrs = vec![relay_addr(1), relay_addr2(2)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(12));

        let status = pool.status_summary();
        assert_eq!(status.relays.len(), 2);
        assert!(status.relays.iter().any(|e| e.is_primary));
    }

    // ── Failover Orchestrator Tests ─────────────────────────────────

    #[test]
    fn test_orchestrator_degraded_failover() {
        let addrs = vec![relay_addr(1), relay_addr2(2)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));

        let mut orch = FailoverOrchestrator::new(pool);
        assert!(!orch.is_failover_in_progress());

        let decision = orch.start_degraded_failover();
        assert!(orch.is_failover_in_progress());

        match decision {
            FailoverDecision::UseRelay(addr) => {
                assert_eq!(addr, relay_addr2(2));

                // Report success
                let next = orch.report_attempt(HandshakeResult::Success {
                    relay_addr: addr,
                    latency: Duration::from_millis(25),
                });
                assert!(next.is_none()); // Failover complete
                assert!(!orch.is_failover_in_progress());
            }
            _ => panic!("Expected UseRelay"),
        }
    }

    #[test]
    fn test_orchestrator_dead_failover_all_candidates() {
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        pool.record_probe_success(relay_addr3(3), Duration::from_millis(30));

        let mut orch = FailoverOrchestrator::new(pool);

        let (decision, candidates) = orch.start_dead_failover();
        assert_eq!(candidates.len(), 2);

        match decision {
            FailoverDecision::UseRelay(_) => {}
            _ => panic!("Expected UseRelay"),
        }
    }

    #[test]
    fn test_orchestrator_ns_refresh_on_exhaustion() {
        let addrs = vec![relay_addr(1)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));

        let mut orch = FailoverOrchestrator::new(pool);

        // Start dead failover — only one relay, it's now dead
        let (decision, _) = orch.start_dead_failover();
        assert_eq!(decision, FailoverDecision::NeedNsRefresh);

        // Provide fresh NS relays
        let decision = orch.provide_ns_relays(vec![relay_addr2(2), relay_addr3(3)]);
        match decision {
            FailoverDecision::UseRelay(addr) => {
                assert!(addr == relay_addr2(2) || addr == relay_addr3(3));
            }
            _ => panic!("Expected UseRelay after NS refresh"),
        }
    }

    #[test]
    fn test_orchestrator_handshake_failure_tries_next() {
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        pool.record_probe_success(relay_addr3(3), Duration::from_millis(30));

        let mut orch = FailoverOrchestrator::new(pool);
        let decision = orch.start_degraded_failover();

        match decision {
            FailoverDecision::UseRelay(addr) => {
                // First attempt fails
                let next = orch.report_attempt(HandshakeResult::Failure {
                    relay_addr: addr,
                    error: "connection refused".to_string(),
                });

                // Should suggest another relay
                match next {
                    Some(FailoverDecision::UseRelay(next_addr)) => {
                        assert_ne!(next_addr, addr);
                    }
                    _ => panic!("Expected another relay suggestion"),
                }
            }
            _ => panic!("Expected UseRelay"),
        }
    }

    #[test]
    fn test_orchestrator_cancel_failover() {
        let addrs = vec![relay_addr(1), relay_addr2(2)];
        let pool = RelayPool::from_addresses(addrs, default_config());
        let mut orch = FailoverOrchestrator::new(pool);

        orch.start_degraded_failover();
        assert!(orch.is_failover_in_progress());

        orch.cancel_failover();
        assert!(!orch.is_failover_in_progress());
    }

    // ── Integration-style Tests ─────────────────────────────────────

    #[test]
    fn test_rapid_relay_cycling() {
        // Simulate: relay 1 dies → failover to 2 → relay 2 dies → failover to 3
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        pool.record_probe_success(relay_addr3(3), Duration::from_millis(30));

        // Relay 1 dies
        let decision = pool.failover_dead();
        assert_eq!(decision, FailoverDecision::UseRelay(relay_addr2(2)));
        assert_eq!(pool.primary(), Some(relay_addr2(2)));

        // Relay 2 dies
        let decision = pool.failover_dead();
        assert_eq!(decision, FailoverDecision::UseRelay(relay_addr3(3)));
        assert_eq!(pool.primary(), Some(relay_addr3(3)));

        // Relay 3 dies — no more relays
        let decision = pool.failover_dead();
        assert_eq!(decision, FailoverDecision::NeedNsRefresh);
    }

    #[test]
    fn test_relay_recovery() {
        let addrs = vec![relay_addr(1), relay_addr2(2)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));

        // Relay 1 fails
        pool.record_probe_failure(relay_addr(1));
        assert_eq!(
            pool.get_relay(&relay_addr(1)).unwrap().health,
            RelayHealth::Dead
        );

        // Relay 1 recovers
        pool.record_probe_success(relay_addr(1), Duration::from_millis(12));
        assert_eq!(
            pool.get_relay(&relay_addr(1)).unwrap().health,
            RelayHealth::Healthy
        );

        // Pool should switch back to relay 1 (lower latency)
        assert_eq!(pool.primary(), Some(relay_addr(1)));
    }

    #[test]
    fn test_concurrent_sessions_failover() {
        // Simulate 50 connections all seeing the same relay failure
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        pool.record_probe_success(relay_addr3(3), Duration::from_millis(30));

        // All 50 connections trigger failover at once
        let decision = pool.failover_dead();
        match decision {
            FailoverDecision::UseRelay(addr) => {
                // All should agree on the same next relay
                assert_eq!(addr, relay_addr2(2));
            }
            _ => panic!("Expected UseRelay"),
        }
    }

    #[test]
    fn test_stale_ns_data() {
        let mut pool = RelayPool::new(default_config());

        // NS returns relay that immediately fails
        pool.update_from_ns(vec![relay_addr(1)]);
        pool.record_probe_failure(relay_addr(1));

        // Pool recognizes it needs NS refresh
        assert!(pool.needs_ns_refresh());

        // NS returns fresh data with a good relay
        pool.update_from_ns(vec![relay_addr2(2)]);
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(15));

        assert!(!pool.needs_ns_refresh());
        assert_eq!(pool.primary(), Some(relay_addr2(2)));
    }

    #[test]
    fn test_failover_count_tracking() {
        let addrs = vec![relay_addr(1), relay_addr2(2), relay_addr3(3)];
        let mut pool = RelayPool::from_addresses(addrs, default_config());
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        pool.record_probe_success(relay_addr3(3), Duration::from_millis(30));

        assert_eq!(pool.failover_count(), 0);
        pool.failover_degraded();
        assert_eq!(pool.failover_count(), 1);
        pool.failover_dead();
        assert_eq!(pool.failover_count(), 2);
    }

    #[test]
    fn test_health_display() {
        assert_eq!(format!("{}", RelayHealth::Healthy), "healthy");
        assert_eq!(format!("{}", RelayHealth::Degraded), "degraded");
        assert_eq!(format!("{}", RelayHealth::Dead), "dead");
        assert_eq!(format!("{}", RelayHealth::Deprioritized), "deprioritized");
    }

    #[test]
    fn test_pool_failover_not_enabled() {
        let config = RelayPoolConfig {
            failover_enabled: false,
            ..default_config()
        };
        let pool = RelayPool::from_addresses(vec![relay_addr(1), relay_addr2(2)], config);
        assert!(!pool.failover_available());
    }

    #[test]
    fn test_pool_single_relay_no_failover() {
        let pool = RelayPool::from_addresses(vec![relay_addr(1)], default_config());
        assert!(!pool.failover_available()); // Need > 1 relay
    }

    #[test]
    fn test_orchestrator_provides_ns_relays_updates_pool() {
        let pool = RelayPool::new(default_config());
        let mut orch = FailoverOrchestrator::new(pool);

        let decision = orch.provide_ns_relays(vec![relay_addr(1), relay_addr2(2)]);
        match decision {
            FailoverDecision::UseRelay(_) => {}
            _ => panic!("Expected UseRelay"),
        }

        assert_eq!(orch.pool().len(), 2);
    }

    // ── Load-Adjusted Scoring Tests ────────────────────────────────

    #[test]
    fn test_score_load_adjusted_low_load_wins() {
        // Relay A: 20ms latency, 10% load → score = 20 * 1.10 = 22
        // Relay B: 15ms latency, 80% load → score = 15 * 1.80 = 27
        // Relay A wins despite higher latency — it's less loaded
        let mut low_load = RelayEntry::new(relay_addr(1));
        low_load.latency = Some(Duration::from_millis(20));
        low_load.load_pct = 10;

        let mut high_load = RelayEntry::new(relay_addr(2));
        high_load.latency = Some(Duration::from_millis(15));
        high_load.load_pct = 80;

        assert!(low_load.score() < high_load.score(),
            "low load relay should score better: {} vs {}", low_load.score(), high_load.score());
    }

    #[test]
    fn test_score_load_adjusted_same_load_latency_wins() {
        // When both relays have same load, lower latency wins
        let mut fast = RelayEntry::new(relay_addr(1));
        fast.latency = Some(Duration::from_millis(10));
        fast.load_pct = 50;

        let mut slow = RelayEntry::new(relay_addr(2));
        slow.latency = Some(Duration::from_millis(30));
        slow.load_pct = 50;

        assert!(fast.score() < slow.score());
    }

    #[test]
    fn test_score_load_adjusted_zero_load() {
        // 0% load: score = latency * 1.0 = latency
        let mut entry = RelayEntry::new(relay_addr(1));
        entry.latency = Some(Duration::from_millis(20));
        entry.load_pct = 0;

        assert_eq!(entry.score(), 20);
    }

    #[test]
    fn test_score_load_adjusted_full_load() {
        // 100% load: score = latency * 2.0
        let mut entry = RelayEntry::new(relay_addr(1));
        entry.latency = Some(Duration::from_millis(20));
        entry.load_pct = 100;

        assert_eq!(entry.score(), 40);
    }

    #[test]
    fn test_score_health_penalty_still_applied() {
        // Load-adjusted scoring + health penalty
        let mut healthy = RelayEntry::new(relay_addr(1));
        healthy.latency = Some(Duration::from_millis(20));
        healthy.load_pct = 50;

        let mut degraded = RelayEntry::new(relay_addr(2));
        degraded.latency = Some(Duration::from_millis(20));
        degraded.load_pct = 50;
        degraded.health = RelayHealth::Degraded;

        assert!(healthy.score() < degraded.score());
    }

    // ── Region Tiebreak Tests ───────────────────────────────────────

    #[test]
    fn test_cmp_for_selection_same_region_wins() {
        let mut local = RelayEntry::new(relay_addr(1));
        local.latency = Some(Duration::from_millis(20));
        local.region = "us-west-2".to_string();

        let mut remote = RelayEntry::new(relay_addr(2));
        remote.latency = Some(Duration::from_millis(20));
        remote.region = "us-east-1".to_string();

        // Same score, but local matches gateway region
        assert_eq!(
            local.cmp_for_selection(&remote, "us-west-2"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn test_cmp_for_selection_score_overrides_region() {
        let mut local_slow = RelayEntry::new(relay_addr(1));
        local_slow.latency = Some(Duration::from_millis(100));
        local_slow.region = "us-west-2".to_string();

        let mut remote_fast = RelayEntry::new(relay_addr(2));
        remote_fast.latency = Some(Duration::from_millis(10));
        remote_fast.region = "us-east-1".to_string();

        // Remote has better score (10 vs 100) — region doesn't override
        assert_eq!(
            local_slow.cmp_for_selection(&remote_fast, "us-west-2"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn test_cmp_for_selection_fewer_connections_tiebreak() {
        let mut low_conn = RelayEntry::new(relay_addr(1));
        low_conn.latency = Some(Duration::from_millis(20));
        low_conn.region = "us-west-2".to_string();
        low_conn.active_connections = 5;

        let mut high_conn = RelayEntry::new(relay_addr(2));
        high_conn.latency = Some(Duration::from_millis(20));
        high_conn.region = "us-west-2".to_string();
        high_conn.active_connections = 50;

        // Same score, same region → fewer connections wins
        assert_eq!(
            low_conn.cmp_for_selection(&high_conn, "us-west-2"),
            std::cmp::Ordering::Less
        );
    }

    // ── RelayInfo / update_from_ns_rich Tests ───────────────────────

    fn make_relay_info(
        port: u16,
        region: &str,
        latency_ms: u32,
        load: u8,
        conns: u32,
        health: RelayHealth,
    ) -> RelayInfo {
        RelayInfo {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port),
            region: region.to_string(),
            latency_ms,
            load_pct: load,
            active_connections: conns,
            health,
        }
    }

    fn make_relay_info2(
        port: u16,
        region: &str,
        latency_ms: u32,
        load: u8,
        conns: u32,
        health: RelayHealth,
    ) -> RelayInfo {
        RelayInfo {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), port),
            region: region.to_string(),
            latency_ms,
            load_pct: load,
            active_connections: conns,
            health,
        }
    }

    #[test]
    fn test_relay_entry_from_info() {
        let info = make_relay_info(23095, "us-west-2", 12, 35, 42, RelayHealth::Healthy);
        let entry = RelayEntry::from_info(&info);

        assert_eq!(entry.addr, info.addr);
        assert_eq!(entry.health, RelayHealth::Healthy);
        assert_eq!(entry.latency, Some(Duration::from_millis(12)));
        assert_eq!(entry.region, "us-west-2");
        assert_eq!(entry.load_pct, 35);
        assert_eq!(entry.active_connections, 42);
    }

    #[test]
    fn test_update_from_ns_rich_adds_new_relays() {
        let mut pool = RelayPool::new(default_config());
        let infos = vec![
            make_relay_info(1, "us-west-2", 12, 35, 42, RelayHealth::Healthy),
            make_relay_info2(2, "us-east-1", 45, 80, 156, RelayHealth::Degraded),
        ];

        pool.update_from_ns_rich(infos);

        assert_eq!(pool.len(), 2);
        assert!(pool.get_relay(&relay_addr(1)).is_some());
        assert!(pool.get_relay(&relay_addr2(2)).is_some());
    }

    #[test]
    fn test_update_from_ns_rich_updates_existing_stats() {
        let mut pool = RelayPool::new(default_config());
        pool.add_relay(relay_addr(1));
        pool.record_probe_success(relay_addr(1), Duration::from_millis(15));

        // NS reports updated load
        let infos = vec![
            make_relay_info(1, "us-west-2", 12, 90, 200, RelayHealth::Healthy),
        ];
        pool.update_from_ns_rich(infos);

        let entry = pool.get_relay(&relay_addr(1)).unwrap();
        assert_eq!(entry.load_pct, 90);
        assert_eq!(entry.active_connections, 200);
        assert_eq!(entry.region, "us-west-2");
        // Local latency measurement preserved (update_from_ns_rich updates stats, not latency)
        assert_eq!(entry.latency, Some(Duration::from_millis(15)));
    }

    #[test]
    fn test_update_from_ns_rich_ns_degraded_overrides_healthy() {
        let mut pool = RelayPool::new(default_config());
        pool.add_relay(relay_addr(1));
        pool.record_probe_success(relay_addr(1), Duration::from_millis(15));

        // NS reports relay as degraded — trust NS as early warning
        let infos = vec![
            make_relay_info(1, "us-west-2", 12, 95, 300, RelayHealth::Degraded),
        ];
        pool.update_from_ns_rich(infos);

        let entry = pool.get_relay(&relay_addr(1)).unwrap();
        assert_eq!(entry.health, RelayHealth::Degraded);
    }

    #[test]
    fn test_update_from_ns_rich_does_not_override_dead() {
        let mut pool = RelayPool::new(default_config());
        pool.add_relay(relay_addr(1));
        pool.record_probe_success(relay_addr(1), Duration::from_millis(15));
        // Locally detected as dead
        pool.record_probe_failure(relay_addr(1));

        // NS still reports as healthy — don't override our local Dead state
        let infos = vec![
            make_relay_info(1, "us-west-2", 12, 35, 42, RelayHealth::Healthy),
        ];
        pool.update_from_ns_rich(infos);

        let entry = pool.get_relay(&relay_addr(1)).unwrap();
        // Dead/Deprioritized from local probes should NOT be overridden by NS
        assert!(matches!(
            entry.health,
            RelayHealth::Dead | RelayHealth::Deprioritized
        ));
    }

    #[test]
    fn test_select_best_with_region() {
        let mut pool = RelayPool::new(default_config());

        // Add relays with same latency but different regions
        let mut entry_west = RelayEntry::new(relay_addr(1));
        entry_west.latency = Some(Duration::from_millis(20));
        entry_west.region = "us-east-1".to_string(); // Different from gateway
        entry_west.load_pct = 0;

        let mut entry_east = RelayEntry::new(relay_addr(2));
        entry_east.latency = Some(Duration::from_millis(20));
        entry_east.region = "us-west-2".to_string(); // Same as gateway
        entry_east.load_pct = 0;

        pool.relays.insert(relay_addr(1), entry_west);
        pool.relays.insert(relay_addr(2), entry_east);

        // select_best with gateway in us-west-2 should prefer relay 2
        let best = pool.select_best("us-west-2");
        assert_eq!(best, Some(relay_addr(2)));
    }

    #[test]
    fn test_select_best_load_beats_region() {
        let mut pool = RelayPool::new(default_config());

        // Local relay but heavily loaded
        let mut local_loaded = RelayEntry::new(relay_addr(1));
        local_loaded.latency = Some(Duration::from_millis(20));
        local_loaded.region = "us-west-2".to_string();
        local_loaded.load_pct = 90; // 20 * 1.90 = 38

        // Remote relay but lightly loaded
        let mut remote_light = RelayEntry::new(relay_addr(2));
        remote_light.latency = Some(Duration::from_millis(15));
        remote_light.region = "us-east-1".to_string();
        remote_light.load_pct = 10; // 15 * 1.10 = 16

        pool.relays.insert(relay_addr(1), local_loaded);
        pool.relays.insert(relay_addr(2), remote_light);

        // Remote relay wins on score despite not matching region
        let best = pool.select_best("us-west-2");
        assert_eq!(best, Some(relay_addr(2)));
    }

    #[test]
    fn test_select_best_empty_pool() {
        let pool = RelayPool::new(default_config());
        assert_eq!(pool.select_best("us-west-2"), None);
    }

    #[test]
    fn test_select_best_all_dead() {
        let mut pool = RelayPool::new(default_config());
        pool.add_relay(relay_addr(1));
        pool.record_probe_failure(relay_addr(1));

        assert_eq!(pool.select_best("us-west-2"), None);
    }

    #[test]
    fn test_update_from_ns_rich_prunes_dead_not_in_list() {
        let mut pool = RelayPool::new(default_config());
        pool.add_relay(relay_addr(1));
        pool.add_relay(relay_addr2(2));
        pool.record_probe_success(relay_addr(1), Duration::from_millis(10));
        pool.record_probe_success(relay_addr2(2), Duration::from_millis(20));
        // Relay 1 dies
        pool.record_probe_failure(relay_addr(1));

        // NS returns only relay 2 (not relay 1)
        let infos = vec![
            make_relay_info2(2, "us-west-2", 20, 30, 10, RelayHealth::Healthy),
        ];
        pool.update_from_ns_rich(infos);

        // Dead relay 1 not in NS list → pruned
        assert!(pool.get_relay(&relay_addr(1)).is_none());
        assert!(pool.get_relay(&relay_addr2(2)).is_some());
    }
}
