//! Roaming detection and NAT timeout auto-detection for ZTLP.
//!
//! Handles three critical production scenarios:
//!
//! 1. **NAT timeout detection** — Automatically discovers the peer's NAT
//!    mapping timeout via binary search probing, then sets the keepalive
//!    interval to 80% of that value for safety margin.
//!
//! 2. **Roaming detection** — Detects when the peer's source address changes
//!    (router reboot, mobile network switch, ISP reassignment) and seamlessly
//!    updates the tunnel's peer address.
//!
//! 3. **Tunnel re-establishment** — When the NAT mapping dies (no response
//!    to keepalives), triggers re-punch or re-handshake to restore the tunnel
//!    without user intervention.
//!
//! ## NAT Timeout Detection Algorithm
//!
//! After tunnel establishment, runs a binary search:
//! 1. Send probe, wait N seconds, send test, check if response arrives
//! 2. If response: mapping alive, try longer interval
//! 3. If no response: mapping died, try shorter interval
//! 4. Converges to ±2s accuracy in ~5 probes (log2 of range)
//!
//! The learned timeout is cached per peer (stored in agent config) so
//! subsequent connections skip the probe phase.
//!
//! ## Roaming Detection
//!
//! On every received packet, compare the source address against the known
//! peer address. If different:
//! - Verify it's a valid authenticated packet (not spoofed)
//! - Update the peer address
//! - Log the roam event
//! - Suppress rapid roam-back for 10s (prevents oscillation)

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

// ─── NAT Timeout Detection ─────────────────────────────────────────────────

/// Default probe range for binary search (seconds).
const MIN_PROBE_INTERVAL_S: u64 = 5;
const MAX_PROBE_INTERVAL_S: u64 = 300; // 5 minutes — most NATs are under this

/// Accuracy target for binary search (seconds).
const PROBE_ACCURACY_S: u64 = 2;

/// Safety margin: set keepalive to this fraction of detected timeout.
const KEEPALIVE_SAFETY_FACTOR: f64 = 0.80;

/// Minimum keepalive interval even if NAT timeout is very short.
const MIN_KEEPALIVE_S: u64 = 5;

/// Maximum keepalive interval even if NAT timeout is very long.
const MAX_KEEPALIVE_S: u64 = 120;

/// Timeout for waiting for a probe response (used by async callers).
#[allow(dead_code)]
const PROBE_RESPONSE_TIMEOUT: Duration = Duration::from_millis(3000);

/// Maximum number of probe rounds to prevent infinite loops.
const MAX_PROBE_ROUNDS: usize = 10;

/// Result of a NAT timeout probe.
#[derive(Debug, Clone, PartialEq)]
pub enum ProbeResult {
    /// NAT mapping was still alive after the given duration.
    Alive(Duration),
    /// NAT mapping died after the given duration.
    Dead(Duration),
    /// Probe failed (network error, etc).
    Error(String),
}

/// Outcome of NAT timeout detection.
#[derive(Debug, Clone)]
pub struct NatTimeoutResult {
    /// Detected NAT mapping timeout (approximate).
    pub timeout: Duration,
    /// Recommended keepalive interval (timeout × safety factor, clamped).
    pub recommended_keepalive: Duration,
    /// Number of probes used.
    pub probes_used: usize,
    /// Probe history for diagnostics.
    pub probe_history: Vec<ProbeResult>,
}

/// Runs the NAT timeout binary search algorithm.
///
/// Returns the detected timeout and recommended keepalive interval.
///
/// The `probe_fn` callback should:
/// 1. Wait the given duration (simulate idle time)
/// 2. Send a test packet through the tunnel
/// 3. Wait up to PROBE_RESPONSE_TIMEOUT for a response
/// 4. Return Alive if response received, Dead if timeout
///
/// This is designed to be called with a closure that uses the actual
/// tunnel's send/recv mechanisms.
pub fn detect_nat_timeout(probe_results: &[ProbeResult]) -> Option<NatTimeoutResult> {
    if probe_results.is_empty() {
        return None;
    }

    // Find the transition point: longest Alive and shortest Dead
    let mut longest_alive: Option<Duration> = None;
    let mut shortest_dead: Option<Duration> = None;

    for result in probe_results {
        match result {
            ProbeResult::Alive(d) => {
                if longest_alive.is_none_or(|prev| *d > prev) {
                    longest_alive = Some(*d);
                }
            }
            ProbeResult::Dead(d) => {
                if shortest_dead.is_none_or(|prev| *d < prev) {
                    shortest_dead = Some(*d);
                }
            }
            ProbeResult::Error(_) => {}
        }
    }

    // Estimate the timeout as the midpoint between longest alive and shortest dead
    let timeout = match (longest_alive, shortest_dead) {
        (Some(alive), Some(dead)) => (alive + dead) / 2,
        (Some(alive), None) => {
            // All probes were alive — timeout is beyond our max probe
            alive + Duration::from_secs(PROBE_ACCURACY_S)
        }
        (None, Some(dead)) => {
            // Even the shortest interval was dead — very aggressive NAT
            dead / 2
        }
        (None, None) => {
            // All errors — use conservative default
            Duration::from_secs(25)
        }
    };

    let keepalive_secs = (timeout.as_secs_f64() * KEEPALIVE_SAFETY_FACTOR) as u64;
    let keepalive_secs = keepalive_secs.clamp(MIN_KEEPALIVE_S, MAX_KEEPALIVE_S);

    Some(NatTimeoutResult {
        timeout,
        recommended_keepalive: Duration::from_secs(keepalive_secs),
        probes_used: probe_results.len(),
        probe_history: probe_results.to_vec(),
    })
}

/// Generate the binary search probe schedule.
///
/// Returns a list of durations to test, converging to ±PROBE_ACCURACY_S.
pub fn generate_probe_schedule() -> Vec<Duration> {
    // Start with the midpoint of the search range.
    // The adaptive scheduler (AdaptiveProbeScheduler) handles the full
    // binary search interactively; this function returns the initial probe.
    let mid = (MIN_PROBE_INTERVAL_S + MAX_PROBE_INTERVAL_S) / 2;
    vec![Duration::from_secs(mid)]
}

/// Adaptive probe scheduler that yields the next probe duration
/// based on previous results.
#[derive(Debug, Clone)]
pub struct AdaptiveProbeScheduler {
    low: u64,
    high: u64,
    probes_done: usize,
    results: Vec<ProbeResult>,
}

impl AdaptiveProbeScheduler {
    pub fn new() -> Self {
        Self {
            low: MIN_PROBE_INTERVAL_S,
            high: MAX_PROBE_INTERVAL_S,
            probes_done: 0,
            results: Vec::new(),
        }
    }

    /// Returns the next probe duration, or None if the search has converged.
    pub fn next_probe(&self) -> Option<Duration> {
        if self.probes_done >= MAX_PROBE_ROUNDS {
            return None;
        }
        if self.high - self.low <= PROBE_ACCURACY_S {
            return None;
        }
        let mid = (self.low + self.high) / 2;
        Some(Duration::from_secs(mid))
    }

    /// Record the result of the latest probe and adjust search range.
    pub fn record_result(&mut self, result: ProbeResult) {
        let duration_secs = match &result {
            ProbeResult::Alive(d) => d.as_secs(),
            ProbeResult::Dead(d) => d.as_secs(),
            ProbeResult::Error(_) => {
                self.results.push(result);
                self.probes_done += 1;
                return;
            }
        };

        match &result {
            ProbeResult::Alive(_) => {
                // Mapping survived — timeout is higher, search upper half
                self.low = duration_secs;
            }
            ProbeResult::Dead(_) => {
                // Mapping died — timeout is lower, search lower half
                self.high = duration_secs;
            }
            _ => {}
        }

        self.results.push(result);
        self.probes_done += 1;
    }

    /// Get the final result after probing is complete.
    pub fn result(&self) -> Option<NatTimeoutResult> {
        detect_nat_timeout(&self.results)
    }

    /// Check if the search has converged.
    pub fn is_converged(&self) -> bool {
        self.high - self.low <= PROBE_ACCURACY_S || self.probes_done >= MAX_PROBE_ROUNDS
    }

    /// Number of probes completed.
    pub fn probes_done(&self) -> usize {
        self.probes_done
    }
}

impl Default for AdaptiveProbeScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Roaming Detection ─────────────────────────────────────────────────────

/// Duration to suppress roam-back to a previous address (prevents oscillation).
const ROAM_SUPPRESSION_SECS: u64 = 10;

/// Maximum number of roam events before triggering a full re-handshake.
const MAX_ROAMS_BEFORE_REHANDSHAKE: usize = 5;

/// Time window for counting rapid roams.
const RAPID_ROAM_WINDOW: Duration = Duration::from_secs(60);

/// A roaming event recorded for diagnostics and anti-oscillation.
#[derive(Debug, Clone)]
pub struct RoamEvent {
    /// Previous peer address.
    pub from: SocketAddr,
    /// New peer address.
    pub to: SocketAddr,
    /// When the roam was detected.
    pub when: Instant,
    /// Whether this roam was suppressed.
    pub suppressed: bool,
}

/// Tracks peer address changes and handles roaming logic.
#[derive(Debug)]
pub struct RoamingDetector {
    /// Current known peer address.
    current_peer: Option<SocketAddr>,
    /// Previous peer address (for suppression).
    last_roam_from: Option<SocketAddr>,
    /// When the last roam was detected.
    last_roam_time: Option<Instant>,
    /// History of roam events.
    roam_history: Vec<RoamEvent>,
    /// Maximum history size.
    max_history: usize,
}

impl RoamingDetector {
    pub fn new(initial_peer: Option<SocketAddr>) -> Self {
        Self {
            current_peer: initial_peer,
            last_roam_from: None,
            last_roam_time: None,
            roam_history: Vec::new(),
            max_history: 100,
        }
    }

    /// Process an incoming packet's source address.
    ///
    /// Returns `Some(new_addr)` if the peer has roamed to a new address,
    /// or `None` if the address is unchanged or the roam was suppressed.
    ///
    /// The caller MUST verify the packet is authenticated before calling this
    /// (i.e., it decrypted successfully with the session key).
    pub fn check_roam(&mut self, packet_source: SocketAddr) -> Option<SocketAddr> {
        let now = Instant::now();

        // First packet — just set the peer address
        let current = match self.current_peer {
            Some(addr) => addr,
            None => {
                self.current_peer = Some(packet_source);
                return None;
            }
        };

        // Same address — no roam
        if current == packet_source {
            return None;
        }

        // Check roam-back suppression
        if let (Some(last_from), Some(last_time)) = (self.last_roam_from, self.last_roam_time) {
            if packet_source == last_from
                && now.duration_since(last_time) < Duration::from_secs(ROAM_SUPPRESSION_SECS)
            {
                debug!(
                    "roaming: suppressing roam-back to {} (within {}s suppression window)",
                    packet_source, ROAM_SUPPRESSION_SECS
                );
                self.record_event(current, packet_source, now, true);
                return None;
            }
        }

        // Roam detected!
        info!("roaming: peer roamed from {} to {}", current, packet_source);

        self.last_roam_from = Some(current);
        self.last_roam_time = Some(now);
        self.current_peer = Some(packet_source);
        self.record_event(current, packet_source, now, false);

        Some(packet_source)
    }

    /// Check if we're experiencing rapid roaming (possible instability).
    pub fn is_rapid_roaming(&self) -> bool {
        let now = Instant::now();
        let recent_roams = self
            .roam_history
            .iter()
            .filter(|e| !e.suppressed && now.duration_since(e.when) < RAPID_ROAM_WINDOW)
            .count();
        recent_roams >= MAX_ROAMS_BEFORE_REHANDSHAKE
    }

    /// Get the current peer address.
    pub fn current_peer(&self) -> Option<SocketAddr> {
        self.current_peer
    }

    /// Get recent roam events.
    pub fn recent_events(&self) -> &[RoamEvent] {
        &self.roam_history
    }

    /// Clear roam history.
    pub fn clear_history(&mut self) {
        self.roam_history.clear();
    }

    fn record_event(&mut self, from: SocketAddr, to: SocketAddr, when: Instant, suppressed: bool) {
        self.roam_history.push(RoamEvent {
            from,
            to,
            when,
            suppressed,
        });
        if self.roam_history.len() > self.max_history {
            self.roam_history.remove(0);
        }
    }
}

// ─── Tunnel Health Monitor ──────────────────────────────────────────────────

/// States for the tunnel health state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelHealth {
    /// Tunnel is operating normally.
    Healthy,
    /// No response received for a while — probing.
    Probing,
    /// NAT mapping appears dead — attempting re-establishment.
    Reestablishing,
    /// Tunnel is dead and needs full re-handshake.
    Dead,
}

/// Monitors tunnel health and triggers re-establishment when needed.
#[derive(Debug)]
pub struct TunnelHealthMonitor {
    /// Current health state.
    state: TunnelHealth,
    /// Last time we received a valid packet from the peer.
    last_recv: Instant,
    /// Last time we sent any packet to the peer.
    last_send: Instant,
    /// Current keepalive interval (may be adjusted by NAT detection).
    keepalive_interval: Duration,
    /// Number of consecutive keepalives sent without response.
    unanswered_keepalives: u32,
    /// Maximum unanswered keepalives before declaring tunnel dead.
    max_unanswered: u32,
    /// Number of re-establishment attempts made.
    reestablish_attempts: u32,
    /// Maximum re-establishment attempts before giving up.
    max_reestablish_attempts: u32,
}

/// Action the tunnel should take based on health monitoring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthAction {
    /// Everything is fine, do nothing.
    None,
    /// Send a keepalive packet.
    SendKeepalive,
    /// NAT mapping may be dead — attempt re-punch.
    RePunch,
    /// Tunnel is dead — do a full re-handshake.
    ReHandshake,
    /// Tunnel is unrecoverable after max attempts.
    GiveUp,
}

impl TunnelHealthMonitor {
    pub fn new(keepalive_interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            state: TunnelHealth::Healthy,
            last_recv: now,
            last_send: now,
            keepalive_interval,
            unanswered_keepalives: 0,
            max_unanswered: 3,
            reestablish_attempts: 0,
            max_reestablish_attempts: 5,
        }
    }

    /// Record that we received a valid packet from the peer.
    pub fn record_recv(&mut self) {
        self.last_recv = Instant::now();
        self.unanswered_keepalives = 0;
        self.reestablish_attempts = 0;

        // If we were in a degraded state, we're healthy again
        if self.state != TunnelHealth::Healthy {
            info!("tunnel health: recovered to Healthy from {:?}", self.state);
            self.state = TunnelHealth::Healthy;
        }
    }

    /// Record that we sent a packet to the peer.
    pub fn record_send(&mut self) {
        self.last_send = Instant::now();
    }

    /// Update the keepalive interval (e.g., from NAT timeout detection).
    pub fn set_keepalive_interval(&mut self, interval: Duration) {
        info!(
            "tunnel health: keepalive interval updated to {:?}",
            interval
        );
        self.keepalive_interval = interval;
    }

    /// Check what action should be taken right now.
    ///
    /// Call this periodically (e.g., every second or on each packet send).
    pub fn check(&mut self) -> HealthAction {
        let now = Instant::now();
        let since_recv = now.duration_since(self.last_recv);
        let since_send = now.duration_since(self.last_send);

        match self.state {
            TunnelHealth::Healthy => {
                // Do we need to send a keepalive?
                if since_send >= self.keepalive_interval {
                    if since_recv >= self.keepalive_interval {
                        // We haven't heard from peer either — start probing
                        self.unanswered_keepalives += 1;
                        if self.unanswered_keepalives >= self.max_unanswered {
                            self.state = TunnelHealth::Probing;
                            info!(
                                "tunnel health: {} unanswered keepalives, transitioning to Probing",
                                self.unanswered_keepalives
                            );
                            return HealthAction::SendKeepalive;
                        }
                    }
                    return HealthAction::SendKeepalive;
                }
                HealthAction::None
            }

            TunnelHealth::Probing => {
                // We're actively probing — send another keepalive
                if since_send >= Duration::from_secs(1) {
                    self.unanswered_keepalives += 1;
                    if self.unanswered_keepalives >= self.max_unanswered + 3 {
                        // Probing failed — NAT mapping is likely dead
                        self.state = TunnelHealth::Reestablishing;
                        info!("tunnel health: probing failed, transitioning to Reestablishing");
                        return HealthAction::RePunch;
                    }
                    return HealthAction::SendKeepalive;
                }
                HealthAction::None
            }

            TunnelHealth::Reestablishing => {
                if self.reestablish_attempts >= self.max_reestablish_attempts {
                    self.state = TunnelHealth::Dead;
                    warn!("tunnel health: max re-establishment attempts reached, transitioning to Dead");
                    return HealthAction::ReHandshake;
                }

                // Try re-punch every 2 seconds
                if since_send >= Duration::from_secs(2) {
                    self.reestablish_attempts += 1;
                    debug!(
                        "tunnel health: re-establishment attempt {}/{}",
                        self.reestablish_attempts, self.max_reestablish_attempts
                    );
                    return HealthAction::RePunch;
                }
                HealthAction::None
            }

            TunnelHealth::Dead => {
                // Full re-handshake needed — check every 5 seconds
                if since_send >= Duration::from_secs(5) {
                    // Reset and try from scratch
                    self.reestablish_attempts += 1;
                    if self.reestablish_attempts > self.max_reestablish_attempts * 2 {
                        return HealthAction::GiveUp;
                    }
                    return HealthAction::ReHandshake;
                }
                HealthAction::None
            }
        }
    }

    /// Get the current health state.
    pub fn state(&self) -> TunnelHealth {
        self.state
    }

    /// Get the current keepalive interval.
    pub fn keepalive_interval(&self) -> Duration {
        self.keepalive_interval
    }

    /// Get the number of unanswered keepalives.
    pub fn unanswered_keepalives(&self) -> u32 {
        self.unanswered_keepalives
    }

    /// Duration since last received packet.
    pub fn since_last_recv(&self) -> Duration {
        Instant::now().duration_since(self.last_recv)
    }
}

// ─── Peer Address Cache ─────────────────────────────────────────────────────

/// Caches learned NAT timeouts and peer addresses for faster reconnection.
#[derive(Debug, Clone)]
pub struct PeerAddressEntry {
    /// Last known public address of the peer.
    pub address: SocketAddr,
    /// Learned NAT timeout for this peer's network path.
    pub nat_timeout: Option<Duration>,
    /// Recommended keepalive interval for this peer.
    pub keepalive_interval: Option<Duration>,
    /// When this entry was last updated.
    pub last_updated: Instant,
}

/// Cache of known peer addresses and NAT characteristics.
#[derive(Debug)]
pub struct PeerAddressCache {
    entries: HashMap<[u8; 16], PeerAddressEntry>, // keyed by NodeID bytes
    max_entries: usize,
}

impl PeerAddressCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Look up a peer's cached address info.
    pub fn get(&self, node_id: &[u8; 16]) -> Option<&PeerAddressEntry> {
        self.entries.get(node_id)
    }

    /// Update a peer's cached address info.
    pub fn put(&mut self, node_id: [u8; 16], entry: PeerAddressEntry) {
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&node_id) {
            // Evict oldest entry
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.last_updated)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&oldest_key);
            }
        }
        self.entries.insert(node_id, entry);
    }

    /// Update just the address for a peer (on roam).
    pub fn update_address(&mut self, node_id: &[u8; 16], new_addr: SocketAddr) {
        if let Some(entry) = self.entries.get_mut(node_id) {
            entry.address = new_addr;
            entry.last_updated = Instant::now();
        }
    }

    /// Update the NAT timeout for a peer.
    pub fn update_nat_timeout(
        &mut self,
        node_id: &[u8; 16],
        timeout: Duration,
        keepalive: Duration,
    ) {
        if let Some(entry) = self.entries.get_mut(node_id) {
            entry.nat_timeout = Some(timeout);
            entry.keepalive_interval = Some(keepalive);
            entry.last_updated = Instant::now();
        }
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for PeerAddressCache {
    fn default() -> Self {
        Self::new(256)
    }
}

// ─── NS Address Change Detection ───────────────────────────────────────────

/// Periodically queries the NS server to check if our public address has changed.
///
/// This detects scenarios where the router reboots and gets a new IP,
/// or the ISP reassigns the public IP, without any packet loss triggering
/// the health monitor.
#[derive(Debug)]
pub struct AddressChangeDetector {
    /// Our last known public address (from NS or STUN).
    last_known_public: Option<SocketAddr>,
    /// When we last checked.
    last_check: Instant,
    /// How often to check (default: 30s).
    check_interval: Duration,
    /// Number of consecutive address changes detected.
    consecutive_changes: u32,
}

impl AddressChangeDetector {
    pub fn new(check_interval: Duration) -> Self {
        Self {
            last_known_public: None,
            last_check: Instant::now(),
            check_interval,
            consecutive_changes: 0,
        }
    }

    /// Check if it's time to poll NS/STUN for our public address.
    pub fn should_check(&self) -> bool {
        Instant::now().duration_since(self.last_check) >= self.check_interval
    }

    /// Record our current public address (from NS or STUN response).
    ///
    /// Returns `Some(new_addr)` if the address changed, None otherwise.
    pub fn update_public_address(&mut self, current: SocketAddr) -> Option<SocketAddr> {
        self.last_check = Instant::now();

        match self.last_known_public {
            None => {
                self.last_known_public = Some(current);
                self.consecutive_changes = 0;
                None
            }
            Some(prev) if prev == current => {
                self.consecutive_changes = 0;
                None
            }
            Some(prev) => {
                info!(
                    "address change detected: {} → {} (change #{})",
                    prev,
                    current,
                    self.consecutive_changes + 1
                );
                self.last_known_public = Some(current);
                self.consecutive_changes += 1;
                Some(current)
            }
        }
    }

    /// Get our last known public address.
    pub fn last_known_public(&self) -> Option<SocketAddr> {
        self.last_known_public
    }

    /// Number of consecutive address changes (possible instability indicator).
    pub fn consecutive_changes(&self) -> u32 {
        self.consecutive_changes
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::thread;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), port))
    }

    fn addr2(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 2), port))
    }

    // ── NAT Timeout Detection Tests ─────────────────────────────────

    #[test]
    fn test_detect_nat_timeout_basic() {
        let results = vec![
            ProbeResult::Alive(Duration::from_secs(30)),
            ProbeResult::Alive(Duration::from_secs(45)),
            ProbeResult::Dead(Duration::from_secs(60)),
        ];
        let result = detect_nat_timeout(&results).unwrap();
        // Midpoint between 45 (longest alive) and 60 (shortest dead) = 52.5
        assert!(result.timeout >= Duration::from_secs(50));
        assert!(result.timeout <= Duration::from_secs(55));
        assert_eq!(result.probes_used, 3);
    }

    #[test]
    fn test_detect_nat_timeout_all_alive() {
        let results = vec![
            ProbeResult::Alive(Duration::from_secs(60)),
            ProbeResult::Alive(Duration::from_secs(120)),
            ProbeResult::Alive(Duration::from_secs(180)),
        ];
        let result = detect_nat_timeout(&results).unwrap();
        // All alive — timeout is beyond our max probe (180 + accuracy)
        assert!(result.timeout > Duration::from_secs(180));
    }

    #[test]
    fn test_detect_nat_timeout_all_dead() {
        let results = vec![
            ProbeResult::Dead(Duration::from_secs(10)),
            ProbeResult::Dead(Duration::from_secs(5)),
        ];
        let result = detect_nat_timeout(&results).unwrap();
        // Shortest dead is 5 — timeout estimated at 5/2 = 2.5
        assert!(result.timeout < Duration::from_secs(5));
    }

    #[test]
    fn test_detect_nat_timeout_empty() {
        let result = detect_nat_timeout(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_detect_nat_timeout_keepalive_clamping() {
        // Very short NAT timeout
        let results = vec![ProbeResult::Dead(Duration::from_secs(6))];
        let result = detect_nat_timeout(&results).unwrap();
        assert!(result.recommended_keepalive >= Duration::from_secs(MIN_KEEPALIVE_S));

        // Very long NAT timeout
        let results = vec![ProbeResult::Alive(Duration::from_secs(300))];
        let result = detect_nat_timeout(&results).unwrap();
        assert!(result.recommended_keepalive <= Duration::from_secs(MAX_KEEPALIVE_S));
    }

    // ── Adaptive Probe Scheduler Tests ──────────────────────────────

    #[test]
    fn test_adaptive_scheduler_convergence() {
        let mut sched = AdaptiveProbeScheduler::new();

        // First probe: midpoint of 5..300 = 152
        let probe1 = sched.next_probe().unwrap();
        assert_eq!(probe1.as_secs(), 152);

        // Alive at 152 — search upper half
        sched.record_result(ProbeResult::Alive(probe1));
        let probe2 = sched.next_probe().unwrap();
        assert_eq!(probe2.as_secs(), 226); // (152+300)/2

        // Dead at 226 — search lower half
        sched.record_result(ProbeResult::Dead(probe2));
        let probe3 = sched.next_probe().unwrap();
        assert_eq!(probe3.as_secs(), 189); // (152+226)/2

        // Continue until convergence
        sched.record_result(ProbeResult::Dead(probe3));
        let probe4 = sched.next_probe().unwrap();
        assert_eq!(probe4.as_secs(), 170); // (152+189)/2

        sched.record_result(ProbeResult::Alive(probe4));
        let probe5 = sched.next_probe().unwrap();
        assert_eq!(probe5.as_secs(), 179); // (170+189)/2

        sched.record_result(ProbeResult::Dead(probe5));
        // Now range is 170..179 = 9s, may need one more
        let probe6 = sched.next_probe().unwrap();
        assert_eq!(probe6.as_secs(), 174); // (170+179)/2

        sched.record_result(ProbeResult::Alive(probe6));
        // Range: 174..179 = 5s, one more
        let probe7 = sched.next_probe().unwrap();
        assert_eq!(probe7.as_secs(), 176); // (174+179)/2

        sched.record_result(ProbeResult::Dead(probe7));
        // Range: 174..176 = 2s — converged!
        assert!(sched.is_converged());
        assert!(sched.next_probe().is_none());

        let result = sched.result().unwrap();
        assert!(result.timeout >= Duration::from_secs(174));
        assert!(result.timeout <= Duration::from_secs(176));
    }

    #[test]
    fn test_adaptive_scheduler_max_rounds() {
        let mut sched = AdaptiveProbeScheduler::new();

        // Feed it errors to prevent convergence
        for _ in 0..MAX_PROBE_ROUNDS {
            if let Some(d) = sched.next_probe() {
                sched.record_result(ProbeResult::Error("test".to_string()));
            }
        }

        // Should stop after max rounds
        assert!(sched.is_converged() || sched.probes_done() >= MAX_PROBE_ROUNDS);
    }

    // ── Roaming Detector Tests ──────────────────────────────────────

    #[test]
    fn test_roaming_no_initial_peer() {
        let mut detector = RoamingDetector::new(None);
        // First packet sets the peer
        assert!(detector.check_roam(addr(5000)).is_none());
        assert_eq!(detector.current_peer(), Some(addr(5000)));
    }

    #[test]
    fn test_roaming_same_address() {
        let mut detector = RoamingDetector::new(Some(addr(5000)));
        assert!(detector.check_roam(addr(5000)).is_none());
        assert!(detector.check_roam(addr(5000)).is_none());
    }

    #[test]
    fn test_roaming_address_change() {
        let mut detector = RoamingDetector::new(Some(addr(5000)));
        let result = detector.check_roam(addr2(6000));
        assert_eq!(result, Some(addr2(6000)));
        assert_eq!(detector.current_peer(), Some(addr2(6000)));
    }

    #[test]
    fn test_roaming_port_change() {
        let mut detector = RoamingDetector::new(Some(addr(5000)));
        // Same IP, different port (NAT rebinding)
        let result = detector.check_roam(addr(5001));
        assert_eq!(result, Some(addr(5001)));
    }

    #[test]
    fn test_roaming_suppression() {
        let mut detector = RoamingDetector::new(Some(addr(5000)));

        // Roam to new address
        let result = detector.check_roam(addr2(6000));
        assert_eq!(result, Some(addr2(6000)));

        // Immediate roam-back should be suppressed
        let result = detector.check_roam(addr(5000));
        assert!(result.is_none()); // Suppressed!
        assert_eq!(detector.current_peer(), Some(addr2(6000))); // Still at new addr
    }

    #[test]
    fn test_roaming_suppression_expires() {
        let mut detector = RoamingDetector::new(Some(addr(5000)));

        // Roam to new address
        detector.check_roam(addr2(6000));

        // Simulate time passing beyond suppression window
        detector.last_roam_time =
            Some(Instant::now() - Duration::from_secs(ROAM_SUPPRESSION_SECS + 1));

        // Roam-back should now be allowed
        let result = detector.check_roam(addr(5000));
        assert_eq!(result, Some(addr(5000)));
    }

    #[test]
    fn test_roaming_rapid_detection() {
        let mut detector = RoamingDetector::new(Some(addr(5000)));

        // Roam rapidly between addresses
        for i in 0..MAX_ROAMS_BEFORE_REHANDSHAKE {
            // Need to bypass suppression for testing
            detector.last_roam_time = None; // Reset suppression
            if i % 2 == 0 {
                detector.check_roam(addr2(6000 + i as u16));
            } else {
                detector.check_roam(addr(5000 + i as u16));
            }
        }

        assert!(detector.is_rapid_roaming());
    }

    #[test]
    fn test_roaming_history() {
        let mut detector = RoamingDetector::new(Some(addr(5000)));
        detector.check_roam(addr2(6000));

        assert_eq!(detector.recent_events().len(), 1);
        let event = &detector.recent_events()[0];
        assert_eq!(event.from, addr(5000));
        assert_eq!(event.to, addr2(6000));
        assert!(!event.suppressed);
    }

    // ── Tunnel Health Monitor Tests ─────────────────────────────────

    #[test]
    fn test_health_initial_state() {
        let monitor = TunnelHealthMonitor::new(Duration::from_secs(25));
        assert_eq!(monitor.state(), TunnelHealth::Healthy);
        assert_eq!(monitor.unanswered_keepalives(), 0);
    }

    #[test]
    fn test_health_keepalive_timing() {
        let mut monitor = TunnelHealthMonitor::new(Duration::from_millis(50));

        // Fresh — should not need keepalive yet
        let action = monitor.check();
        assert_eq!(action, HealthAction::None);

        // Wait for keepalive interval — simulate by backdating last_send
        monitor.last_send = Instant::now() - Duration::from_millis(60);
        monitor.last_recv = Instant::now() - Duration::from_millis(60);
        let action = monitor.check();
        assert_eq!(action, HealthAction::SendKeepalive);
    }

    #[test]
    fn test_health_probing_transition() {
        let mut monitor = TunnelHealthMonitor::new(Duration::from_millis(10));

        // Simulate max_unanswered keepalives without response
        monitor.last_send = Instant::now() - Duration::from_millis(20);
        monitor.last_recv = Instant::now() - Duration::from_millis(20);
        for _ in 0..3 {
            monitor.check();
            monitor.last_send = Instant::now() - Duration::from_millis(20);
        }

        assert_eq!(monitor.state(), TunnelHealth::Probing);
    }

    #[test]
    fn test_health_recovery() {
        let mut monitor = TunnelHealthMonitor::new(Duration::from_millis(10));
        monitor.state = TunnelHealth::Probing;
        monitor.unanswered_keepalives = 5;

        // Receive a packet — should recover
        monitor.record_recv();
        assert_eq!(monitor.state(), TunnelHealth::Healthy);
        assert_eq!(monitor.unanswered_keepalives(), 0);
    }

    #[test]
    fn test_health_reestablishing_transition() {
        let mut monitor = TunnelHealthMonitor::new(Duration::from_millis(10));
        monitor.state = TunnelHealth::Probing;
        monitor.unanswered_keepalives = 5; // max_unanswered(3) + 3 - 1

        monitor.last_send = Instant::now() - Duration::from_secs(2);
        let action = monitor.check();

        assert_eq!(monitor.state(), TunnelHealth::Reestablishing);
        assert_eq!(action, HealthAction::RePunch);
    }

    #[test]
    fn test_health_dead_transition() {
        let mut monitor = TunnelHealthMonitor::new(Duration::from_millis(10));
        monitor.state = TunnelHealth::Reestablishing;
        monitor.reestablish_attempts = 5; // max_reestablish_attempts

        monitor.last_send = Instant::now() - Duration::from_secs(3);
        let action = monitor.check();

        assert_eq!(monitor.state(), TunnelHealth::Dead);
        assert_eq!(action, HealthAction::ReHandshake);
    }

    #[test]
    fn test_health_give_up() {
        let mut monitor = TunnelHealthMonitor::new(Duration::from_millis(10));
        monitor.state = TunnelHealth::Dead;
        monitor.reestablish_attempts = 11; // > max * 2

        monitor.last_send = Instant::now() - Duration::from_secs(6);
        let action = monitor.check();

        assert_eq!(action, HealthAction::GiveUp);
    }

    #[test]
    fn test_health_set_keepalive() {
        let mut monitor = TunnelHealthMonitor::new(Duration::from_secs(25));
        monitor.set_keepalive_interval(Duration::from_secs(40));
        assert_eq!(monitor.keepalive_interval(), Duration::from_secs(40));
    }

    // ── Address Change Detector Tests ───────────────────────────────

    #[test]
    fn test_address_change_first_update() {
        let mut detector = AddressChangeDetector::new(Duration::from_secs(30));
        let result = detector.update_public_address(addr(5000));
        assert!(result.is_none()); // First update — just records, no "change"
        assert_eq!(detector.last_known_public(), Some(addr(5000)));
    }

    #[test]
    fn test_address_change_no_change() {
        let mut detector = AddressChangeDetector::new(Duration::from_secs(30));
        detector.update_public_address(addr(5000));
        let result = detector.update_public_address(addr(5000));
        assert!(result.is_none());
        assert_eq!(detector.consecutive_changes(), 0);
    }

    #[test]
    fn test_address_change_detected() {
        let mut detector = AddressChangeDetector::new(Duration::from_secs(30));
        detector.update_public_address(addr(5000));
        let result = detector.update_public_address(addr2(6000));
        assert_eq!(result, Some(addr2(6000)));
        assert_eq!(detector.consecutive_changes(), 1);
    }

    #[test]
    fn test_address_change_port_only() {
        let mut detector = AddressChangeDetector::new(Duration::from_secs(30));
        detector.update_public_address(addr(5000));
        // Same IP, different port (NAT rebinding after timeout)
        let result = detector.update_public_address(addr(5001));
        assert_eq!(result, Some(addr(5001)));
    }

    #[test]
    fn test_address_change_consecutive_tracking() {
        let mut detector = AddressChangeDetector::new(Duration::from_secs(30));
        detector.update_public_address(addr(5000));
        detector.update_public_address(addr2(6000));
        detector.update_public_address(addr(5001));
        assert_eq!(detector.consecutive_changes(), 2);

        // Same address resets counter
        detector.update_public_address(addr(5001));
        assert_eq!(detector.consecutive_changes(), 0);
    }

    #[test]
    fn test_address_change_should_check_interval() {
        let detector = AddressChangeDetector::new(Duration::from_millis(50));
        assert!(!detector.should_check()); // Just created

        // Wait for interval
        thread::sleep(Duration::from_millis(60));
        assert!(detector.should_check());
    }

    // ── Peer Address Cache Tests ────────────────────────────────────

    #[test]
    fn test_peer_cache_basic() {
        let mut cache = PeerAddressCache::new(10);
        let id = [0xAA; 16];
        cache.put(
            id,
            PeerAddressEntry {
                address: addr(5000),
                nat_timeout: Some(Duration::from_secs(60)),
                keepalive_interval: Some(Duration::from_secs(48)),
                last_updated: Instant::now(),
            },
        );
        let entry = cache.get(&id).unwrap();
        assert_eq!(entry.address, addr(5000));
        assert_eq!(entry.nat_timeout, Some(Duration::from_secs(60)));
    }

    #[test]
    fn test_peer_cache_update_address() {
        let mut cache = PeerAddressCache::new(10);
        let id = [0xBB; 16];
        cache.put(
            id,
            PeerAddressEntry {
                address: addr(5000),
                nat_timeout: None,
                keepalive_interval: None,
                last_updated: Instant::now(),
            },
        );
        cache.update_address(&id, addr2(6000));
        assert_eq!(cache.get(&id).unwrap().address, addr2(6000));
    }

    #[test]
    fn test_peer_cache_eviction() {
        let mut cache = PeerAddressCache::new(2);
        let id1 = [0x01; 16];
        let id2 = [0x02; 16];
        let id3 = [0x03; 16];

        cache.put(
            id1,
            PeerAddressEntry {
                address: addr(1000),
                nat_timeout: None,
                keepalive_interval: None,
                last_updated: Instant::now() - Duration::from_secs(100),
            },
        );
        cache.put(
            id2,
            PeerAddressEntry {
                address: addr(2000),
                nat_timeout: None,
                keepalive_interval: None,
                last_updated: Instant::now(),
            },
        );

        assert_eq!(cache.len(), 2);

        // Adding a 3rd should evict the oldest (id1)
        cache.put(
            id3,
            PeerAddressEntry {
                address: addr(3000),
                nat_timeout: None,
                keepalive_interval: None,
                last_updated: Instant::now(),
            },
        );

        assert_eq!(cache.len(), 2);
        assert!(cache.get(&id1).is_none()); // Evicted
        assert!(cache.get(&id2).is_some());
        assert!(cache.get(&id3).is_some());
    }
}
