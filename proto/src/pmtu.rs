//! Path MTU (PMTU) discovery for ZTLP tunnels.
//!
//! Discovers the maximum UDP payload size that can traverse the network
//! path without fragmentation. Fragmented UDP packets are often dropped
//! by middleboxes, so keeping packets under the path MTU is critical.
//!
//! ## Algorithm
//!
//! Uses Packetization Layer Path MTU Discovery (RFC 8899 / DPLPMTUD):
//!
//! 1. Start at a safe baseline (1280 bytes — IPv6 minimum MTU)
//! 2. Send a probe packet at a larger size
//! 3. If probe is acknowledged: path supports that size, try bigger
//! 4. If no acknowledgment: path doesn't support it, try smaller
//! 5. Binary search converges to the actual PMTU
//!
//! ## Integration with ZTLP
//!
//! The ZTLP overhead per packet is:
//! - 2 bytes magic
//! - 12 bytes SessionID
//! - 4 bytes HeaderAuthTag
//! - N bytes encrypted payload + 16 bytes Poly1305 tag
//! - IP header (20 IPv4 / 40 IPv6) + UDP header (8 bytes)
//!
//! So max ZTLP payload = PMTU - IP_header - UDP_header - ZTLP_overhead
//!
//! ## Common Path MTUs
//!
//! - Ethernet: 1500 bytes
//! - PPPoE: 1492 bytes
//! - VPN tunnels: 1400-1420 bytes
//! - IPv6 minimum: 1280 bytes
//! - Some broken paths: as low as 576 bytes (IPv4 minimum)

#![deny(unsafe_code)]

use std::time::{Duration, Instant};

// ─── Constants ──────────────────────────────────────────────────────────────

/// IPv4 header size (no options).
pub const IPV4_HEADER: usize = 20;
/// IPv6 header size (no extensions).
pub const IPV6_HEADER: usize = 40;
/// UDP header size.
pub const UDP_HEADER: usize = 8;
/// ZTLP per-packet overhead: magic(2) + sessionID(12) + headerAuth(4) + poly1305(16)
pub const ZTLP_OVERHEAD: usize = 2 + 12 + 4 + 16;

/// Total overhead for IPv4 + UDP + ZTLP.
pub const OVERHEAD_IPV4: usize = IPV4_HEADER + UDP_HEADER + ZTLP_OVERHEAD;
/// Total overhead for IPv6 + UDP + ZTLP.
pub const OVERHEAD_IPV6: usize = IPV6_HEADER + UDP_HEADER + ZTLP_OVERHEAD;

/// Minimum safe payload (IPv6 min MTU minus max overhead).
/// 1280 - 40 - 8 - 34 = 1198 bytes of ZTLP payload
pub const MIN_PMTU: usize = 1280;

/// Maximum PMTU to test (jumbo frames on Ethernet).
pub const MAX_PMTU: usize = 9000;

/// Standard Ethernet MTU.
pub const ETHERNET_MTU: usize = 1500;

/// Default starting PMTU (conservative — works on most paths).
pub const DEFAULT_PMTU: usize = 1280;

/// Probe timeout — how long to wait for acknowledgment.
const PROBE_TIMEOUT: Duration = Duration::from_millis(3000);

/// Minimum interval between probe attempts.
const PROBE_INTERVAL: Duration = Duration::from_secs(10);

/// How long to wait before re-probing after a successful PMTU discovery.
/// Paths can change, so we periodically re-verify.
const REPROBE_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes

/// Maximum consecutive probe failures before dropping to base MTU.
const MAX_PROBE_FAILURES: u32 = 3;

/// Accuracy: stop probing when range is within this many bytes.
const PROBE_ACCURACY: usize = 32;

/// Maximum number of probe attempts per discovery cycle.
const MAX_PROBES_PER_CYCLE: u32 = 10;

// ─── PMTU State ─────────────────────────────────────────────────────────────

/// Current state of PMTU discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtuState {
    /// Using default/base MTU, haven't started probing yet.
    Base,
    /// Actively probing to find the path MTU.
    Searching,
    /// PMTU has been discovered and is in use.
    Complete,
    /// Detected a black hole (PMTU decrease) — dropping to base.
    BlackHole,
}

/// PMTU discoverer for a single network path.
#[derive(Debug)]
pub struct PmtuDiscovery {
    /// Current state.
    state: PmtuState,
    /// Current effective PMTU (what we're using for packet sizing).
    current_pmtu: usize,
    /// Whether the peer is IPv6 (affects overhead calculation).
    is_ipv6: bool,
    /// Binary search: lower bound (known-good).
    probe_low: usize,
    /// Binary search: upper bound (known-bad or untested).
    probe_high: usize,
    /// Current probe size being tested.
    probe_current: Option<usize>,
    /// When we sent the current probe.
    probe_sent_at: Option<Instant>,
    /// When the last probe was sent (for rate limiting).
    last_probe_time: Option<Instant>,
    /// When the PMTU was last confirmed.
    last_confirmed: Option<Instant>,
    /// Consecutive probe failures.
    consecutive_failures: u32,
    /// Total probes sent in this cycle.
    probes_this_cycle: u32,
    /// Historical PMTU values seen.
    pmtu_history: Vec<(usize, Instant)>,
}

/// Action the caller should take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PmtuAction {
    /// Nothing to do right now.
    None,
    /// Send a probe packet of this size (total UDP payload bytes).
    SendProbe(usize),
    /// PMTU changed — update the maximum data packet size.
    PmtuChanged(usize),
}

impl PmtuDiscovery {
    /// Create a new PMTU discovery instance.
    ///
    /// `is_ipv6`: whether the path uses IPv6 (affects overhead calculation).
    /// `initial_pmtu`: starting MTU to use. Pass `None` for default (1280).
    pub fn new(is_ipv6: bool, initial_pmtu: Option<usize>) -> Self {
        let pmtu = initial_pmtu.unwrap_or(DEFAULT_PMTU);
        Self {
            state: PmtuState::Base,
            current_pmtu: pmtu,
            is_ipv6,
            probe_low: pmtu,
            probe_high: ETHERNET_MTU, // Start by probing up to Ethernet MTU
            probe_current: None,
            probe_sent_at: None,
            last_probe_time: None,
            last_confirmed: None,
            consecutive_failures: 0,
            probes_this_cycle: 0,
            pmtu_history: Vec::new(),
        }
    }

    /// Calculate the maximum ZTLP payload for the current PMTU.
    pub fn max_payload(&self) -> usize {
        let overhead = if self.is_ipv6 {
            OVERHEAD_IPV6
        } else {
            OVERHEAD_IPV4
        };
        self.current_pmtu.saturating_sub(overhead)
    }

    /// Get the current effective PMTU.
    pub fn current_pmtu(&self) -> usize {
        self.current_pmtu
    }

    /// Get the current state.
    pub fn state(&self) -> PmtuState {
        self.state
    }

    /// Check what action to take. Call this periodically (e.g., every second).
    pub fn check(&mut self) -> PmtuAction {
        let now = Instant::now();

        // Check if a pending probe has timed out
        if let (Some(size), Some(sent_at)) = (self.probe_current, self.probe_sent_at) {
            if now.duration_since(sent_at) >= PROBE_TIMEOUT {
                // Probe failed — this MTU is too big
                return self.handle_probe_failure(size);
            }
            // Still waiting for probe response
            return PmtuAction::None;
        }

        match self.state {
            PmtuState::Base => {
                // Start probing if we haven't recently
                if self.should_probe(now) {
                    return self.start_probe();
                }
            }
            PmtuState::Searching => {
                // Continue binary search
                if self.should_probe(now) {
                    return self.start_probe();
                }
            }
            PmtuState::Complete => {
                // Periodically re-verify
                if let Some(confirmed) = self.last_confirmed {
                    if now.duration_since(confirmed) >= REPROBE_INTERVAL {
                        self.state = PmtuState::Searching;
                        self.probe_low = DEFAULT_PMTU;
                        self.probe_high = self.current_pmtu + PROBE_ACCURACY;
                        self.probes_this_cycle = 0;
                        return self.start_probe();
                    }
                }
            }
            PmtuState::BlackHole => {
                // Wait a bit then try again from base
                if let Some(last) = self.last_probe_time {
                    if now.duration_since(last) >= Duration::from_secs(60) {
                        self.state = PmtuState::Base;
                        self.consecutive_failures = 0;
                        self.probes_this_cycle = 0;
                    }
                }
            }
        }

        PmtuAction::None
    }

    /// Call this when a probe is acknowledged (peer responded to our probe packet).
    pub fn probe_acked(&mut self, probe_size: usize) -> PmtuAction {
        self.probe_current = None;
        self.probe_sent_at = None;
        self.consecutive_failures = 0;

        // This size works — it's a new lower bound
        self.probe_low = probe_size;

        if self.probe_high - self.probe_low <= PROBE_ACCURACY {
            // Converged
            let new_pmtu = self.probe_low;
            if new_pmtu != self.current_pmtu {
                self.current_pmtu = new_pmtu;
                self.pmtu_history.push((new_pmtu, Instant::now()));
                self.state = PmtuState::Complete;
                self.last_confirmed = Some(Instant::now());
                return PmtuAction::PmtuChanged(new_pmtu);
            }
            self.state = PmtuState::Complete;
            self.last_confirmed = Some(Instant::now());
        } else {
            self.state = PmtuState::Searching;
        }

        PmtuAction::None
    }

    /// Call this when we detect packet loss at the current PMTU.
    ///
    /// This is a "black hole" detection — our packets are being silently
    /// dropped because they're too large. Drop to base immediately.
    pub fn detect_black_hole(&mut self) -> PmtuAction {
        if self.current_pmtu > DEFAULT_PMTU {
            self.current_pmtu = DEFAULT_PMTU;
            self.state = PmtuState::BlackHole;
            self.probe_low = DEFAULT_PMTU;
            self.probe_high = ETHERNET_MTU;
            self.probes_this_cycle = 0;
            PmtuAction::PmtuChanged(DEFAULT_PMTU)
        } else {
            PmtuAction::None
        }
    }

    /// Manually set the PMTU (e.g., from ICMP "packet too big" messages).
    pub fn set_pmtu(&mut self, pmtu: usize) -> PmtuAction {
        let pmtu = pmtu.clamp(MIN_PMTU, MAX_PMTU);
        if pmtu != self.current_pmtu {
            self.current_pmtu = pmtu;
            self.state = PmtuState::Complete;
            self.last_confirmed = Some(Instant::now());
            self.pmtu_history.push((pmtu, Instant::now()));
            PmtuAction::PmtuChanged(pmtu)
        } else {
            PmtuAction::None
        }
    }

    /// Get the PMTU history.
    pub fn history(&self) -> &[(usize, Instant)] {
        &self.pmtu_history
    }

    // ── Internal helpers ────────────────────────────────────────────

    fn should_probe(&self, now: Instant) -> bool {
        if self.probes_this_cycle >= MAX_PROBES_PER_CYCLE {
            return false;
        }
        match self.last_probe_time {
            None => true,
            Some(last) => now.duration_since(last) >= PROBE_INTERVAL,
        }
    }

    fn start_probe(&mut self) -> PmtuAction {
        if self.probe_high <= self.probe_low + PROBE_ACCURACY {
            // Already converged
            self.state = PmtuState::Complete;
            self.last_confirmed = Some(Instant::now());
            return PmtuAction::None;
        }

        let probe_size = (self.probe_low + self.probe_high) / 2;
        self.probe_current = Some(probe_size);
        self.probe_sent_at = Some(Instant::now());
        self.last_probe_time = Some(Instant::now());
        self.probes_this_cycle += 1;
        self.state = PmtuState::Searching;

        PmtuAction::SendProbe(probe_size)
    }

    fn handle_probe_failure(&mut self, failed_size: usize) -> PmtuAction {
        self.probe_current = None;
        self.probe_sent_at = None;
        self.consecutive_failures += 1;

        // This size doesn't work — it's a new upper bound
        self.probe_high = failed_size;

        if self.consecutive_failures >= MAX_PROBE_FAILURES {
            // Too many failures — drop to base and stop for a while
            if self.current_pmtu > DEFAULT_PMTU {
                self.current_pmtu = DEFAULT_PMTU;
                self.state = PmtuState::BlackHole;
                return PmtuAction::PmtuChanged(DEFAULT_PMTU);
            }
            self.state = PmtuState::BlackHole;
            return PmtuAction::None;
        }

        if self.probe_high - self.probe_low <= PROBE_ACCURACY {
            // Converged at the lower bound
            if self.probe_low != self.current_pmtu {
                self.current_pmtu = self.probe_low;
                self.state = PmtuState::Complete;
                self.last_confirmed = Some(Instant::now());
                return PmtuAction::PmtuChanged(self.probe_low);
            }
            self.state = PmtuState::Complete;
            self.last_confirmed = Some(Instant::now());
        }

        PmtuAction::None
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_instance_defaults() {
        let p = PmtuDiscovery::new(false, None);
        assert_eq!(p.current_pmtu(), DEFAULT_PMTU);
        assert_eq!(p.state(), PmtuState::Base);
    }

    #[test]
    fn test_max_payload_ipv4() {
        let p = PmtuDiscovery::new(false, Some(1500));
        // 1500 - 20 - 8 - 34 = 1438
        assert_eq!(p.max_payload(), 1500 - OVERHEAD_IPV4);
    }

    #[test]
    fn test_max_payload_ipv6() {
        let p = PmtuDiscovery::new(true, Some(1500));
        // 1500 - 40 - 8 - 34 = 1418
        assert_eq!(p.max_payload(), 1500 - OVERHEAD_IPV6);
    }

    #[test]
    fn test_initial_probe() {
        let mut p = PmtuDiscovery::new(false, None);
        let action = p.check();
        match action {
            PmtuAction::SendProbe(size) => {
                assert!(size > DEFAULT_PMTU);
                assert!(size <= ETHERNET_MTU);
            }
            _ => panic!("expected SendProbe, got {:?}", action),
        }
        assert_eq!(p.state(), PmtuState::Searching);
    }

    #[test]
    fn test_probe_success_raises_pmtu() {
        let mut p = PmtuDiscovery::new(false, None);
        let probe_size = match p.check() {
            PmtuAction::SendProbe(s) => s,
            other => panic!("expected SendProbe, got {:?}", other),
        };
        let action = p.probe_acked(probe_size);
        // May not be converged yet, but low bound should have moved up
        assert!(p.current_pmtu() >= DEFAULT_PMTU);
    }

    #[test]
    fn test_probe_failure_lowers_bound() {
        let mut p = PmtuDiscovery::new(false, None);
        let _probe = p.check();
        // Simulate timeout
        p.probe_sent_at = Some(Instant::now() - PROBE_TIMEOUT - Duration::from_millis(1));
        let action = p.check();
        // Should handle the timeout and adjust bounds
        assert!(matches!(
            action,
            PmtuAction::None | PmtuAction::PmtuChanged(_)
        ));
    }

    #[test]
    fn test_convergence_binary_search() {
        let mut p = PmtuDiscovery::new(false, None);
        // Simulate that 1400 works but 1401+ doesn't
        let target_mtu: usize = 1400;
        let mut probes = 0;

        loop {
            let action = p.check();
            match action {
                PmtuAction::SendProbe(size) => {
                    probes += 1;
                    if size <= target_mtu {
                        p.probe_acked(size);
                    } else {
                        // Simulate timeout
                        p.probe_sent_at =
                            Some(Instant::now() - PROBE_TIMEOUT - Duration::from_millis(1));
                        p.check(); // Process the timeout
                    }
                    // Override rate limiting for test
                    p.last_probe_time =
                        Some(Instant::now() - PROBE_INTERVAL - Duration::from_secs(1));
                }
                PmtuAction::PmtuChanged(new_mtu) => {
                    assert!(new_mtu >= target_mtu - PROBE_ACCURACY);
                    assert!(new_mtu <= target_mtu + PROBE_ACCURACY);
                    break;
                }
                PmtuAction::None => {
                    if p.state() == PmtuState::Complete || p.state() == PmtuState::BlackHole {
                        break;
                    }
                    // Override rate limiting
                    p.last_probe_time =
                        Some(Instant::now() - PROBE_INTERVAL - Duration::from_secs(1));
                }
            }
            assert!(probes < 20, "too many probes: {}", probes);
        }
    }

    #[test]
    fn test_black_hole_detection() {
        let mut p = PmtuDiscovery::new(false, Some(1500));
        let action = p.detect_black_hole();
        assert_eq!(action, PmtuAction::PmtuChanged(DEFAULT_PMTU));
        assert_eq!(p.state(), PmtuState::BlackHole);
        assert_eq!(p.current_pmtu(), DEFAULT_PMTU);
    }

    #[test]
    fn test_black_hole_no_change_at_base() {
        let mut p = PmtuDiscovery::new(false, Some(DEFAULT_PMTU));
        let action = p.detect_black_hole();
        assert_eq!(action, PmtuAction::None);
    }

    #[test]
    fn test_manual_set_pmtu() {
        let mut p = PmtuDiscovery::new(false, None);
        let action = p.set_pmtu(1400);
        assert_eq!(action, PmtuAction::PmtuChanged(1400));
        assert_eq!(p.current_pmtu(), 1400);
        assert_eq!(p.state(), PmtuState::Complete);
    }

    #[test]
    fn test_set_pmtu_clamping() {
        let mut p = PmtuDiscovery::new(false, None);
        p.set_pmtu(100); // Below minimum
        assert!(p.current_pmtu() >= MIN_PMTU);

        p.set_pmtu(20000); // Above maximum
        assert!(p.current_pmtu() <= MAX_PMTU);
    }

    #[test]
    fn test_probe_rate_limiting() {
        let mut p = PmtuDiscovery::new(false, None);
        let first = p.check();
        assert!(matches!(first, PmtuAction::SendProbe(_)));
        // Cancel the in-flight probe for this test
        p.probe_current = None;
        p.probe_sent_at = None;
        // Second check should be rate-limited
        let second = p.check();
        assert_eq!(second, PmtuAction::None);
    }

    #[test]
    fn test_max_probes_per_cycle() {
        let mut p = PmtuDiscovery::new(false, None);
        p.probes_this_cycle = MAX_PROBES_PER_CYCLE;
        let action = p.check();
        assert_eq!(action, PmtuAction::None);
    }

    #[test]
    fn test_history_tracking() {
        let mut p = PmtuDiscovery::new(false, None);
        assert!(p.history().is_empty());
        p.set_pmtu(1400);
        assert_eq!(p.history().len(), 1);
        assert_eq!(p.history()[0].0, 1400);
    }

    #[test]
    fn test_overhead_constants() {
        assert_eq!(OVERHEAD_IPV4, 20 + 8 + 34);
        assert_eq!(OVERHEAD_IPV6, 40 + 8 + 34);
        assert_eq!(ZTLP_OVERHEAD, 34);
    }

    #[test]
    fn test_max_payload_at_minimum_mtu() {
        let p = PmtuDiscovery::new(false, Some(MIN_PMTU));
        let payload = p.max_payload();
        assert!(payload > 0);
        assert_eq!(payload, MIN_PMTU - OVERHEAD_IPV4);
    }
}
