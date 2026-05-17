//! ZTLP session health — Rust state machine for tunnel liveness.
//!
//! Phase 3 of the Nebula-style collapse (plan
//! `docs/plans/2026-05-03-ios-nebula-collapse.md`). Port of the Swift
//! `PacketTunnelProvider` session-health logic (silent-receiver detection,
//! fast-stuck detection, probe send/recv, probe timeout, transition to
//! "needs reconnect"). Runs entirely in Rust; unit-tested on Linux.
//!
//! # States
//!
//! * `Healthy` — useful RX recently, no probe outstanding.
//! * `Suspect(since)` — an above-threshold silent period while flows are
//!   active. We send a FRAME_PING and wait for a FRAME_PONG response.
//! * `Dead` — probe timed out or no progress for too long.
//!   `IosTunnelEngine` treats this as "needs reconnect".
//!
//! # Thresholds (mirror of Swift)
//!
//! * `HEALTH_CHECK_INTERVAL` = 2s — how often the engine tick drives this.
//! * `SUSPECT_THRESHOLD` = 5s — silent RX with active flows.
//! * `PROBE_TIMEOUT` = 5s — no FRAME_PONG within this window → Dead.
//! * `FAST_PROBE_TIMEOUT` = 3s — used when fast-stuck is true.
//! * `FAST_STUCK_OLDEST_MS` = 3000 — outbound queue oldest age that
//!   indicates the gateway hasn't ACKed anything recently.
//! * `NO_PROGRESS_TICKS` = 3 — consecutive ticks of highSeq non-advance
//!   while active.

#![cfg(feature = "ios-sync")]

use std::time::{Duration, Instant};

pub const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(2);
pub const SUSPECT_THRESHOLD: Duration = Duration::from_secs(5);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
pub const FAST_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const FAST_STUCK_OLDEST_MS: u64 = 3_000;
pub const NO_PROGRESS_TICKS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Normal operation.
    Healthy,
    /// Silent/stuck — a probe is outstanding waiting for PONG.
    Suspect,
    /// Probe timed out or repeated no-progress. Caller should reconnect.
    Dead,
}

/// What the caller should do after a `tick`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthAction {
    /// Nothing to do this tick.
    None,
    /// Send a FRAME_PING with this nonce — we just moved into Suspect.
    SendProbe { nonce: u64 },
    /// Transition to Dead — caller should reconnect.
    Reconnect { reason: &'static str },
}

/// Inputs to `SessionHealth::tick`. Caller aggregates from router/mux/
/// useful-rx tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct HealthTickInputs {
    pub has_active_flows: bool,
    /// How long since the most recent useful RX (decrypted inbound frame
    /// that was not a duplicate / pong).
    pub useful_rx_age: Duration,
    /// Router oldest_ms — how long the oldest outbound packet has been
    /// waiting without an ACK.
    pub oldest_outbound_ms: u64,
    /// Number of consecutive ticks where the tunnel's highest data_seq
    /// did not advance.
    pub consecutive_stuck_high_seq_ticks: u32,
}

/// The session health manager. Construct once per tunnel session. Call
/// `tick` every `HEALTH_CHECK_INTERVAL`. Notify incoming probe responses
/// via `on_pong`.
pub struct SessionHealth {
    state: HealthState,
    suspect_since: Option<Instant>,
    probe_outstanding_since: Option<Instant>,
    current_probe_nonce: Option<u64>,
    next_nonce: u64,
}

impl SessionHealth {
    pub fn new() -> Self {
        Self {
            state: HealthState::Healthy,
            suspect_since: None,
            probe_outstanding_since: None,
            current_probe_nonce: None,
            next_nonce: 1,
        }
    }

    pub fn state(&self) -> HealthState {
        self.state
    }

    pub fn suspect_since(&self) -> Option<Instant> {
        self.suspect_since
    }

    pub fn probe_outstanding_since(&self) -> Option<Instant> {
        self.probe_outstanding_since
    }

    /// Called when a FRAME_PONG arrives. If the nonce matches the
    /// outstanding probe, clear Suspect and return to Healthy.
    pub fn on_pong(&mut self, nonce: u64, _now: Instant) {
        if Some(nonce) == self.current_probe_nonce {
            self.state = HealthState::Healthy;
            self.suspect_since = None;
            self.probe_outstanding_since = None;
            self.current_probe_nonce = None;
        }
    }

    /// Call this on every health tick.
    pub fn tick(&mut self, now: Instant, inputs: HealthTickInputs) -> HealthAction {
        // If already Dead, stay Dead until the caller reset()s after
        // reconnect.
        if self.state == HealthState::Dead {
            return HealthAction::None;
        }

        // Evaluate silent / stuck conditions only when flows are active.
        // A quiet tunnel with nothing to send is healthy by definition.
        let silent_too_long =
            inputs.has_active_flows && inputs.useful_rx_age >= SUSPECT_THRESHOLD;
        let stuck_too_long = inputs.has_active_flows
            && inputs.consecutive_stuck_high_seq_ticks >= NO_PROGRESS_TICKS;
        let fast_stuck = inputs.has_active_flows
            && inputs.oldest_outbound_ms >= FAST_STUCK_OLDEST_MS
            && inputs.consecutive_stuck_high_seq_ticks > 0;

        let should_suspect = silent_too_long || stuck_too_long || fast_stuck;

        match self.state {
            HealthState::Healthy => {
                if should_suspect {
                    self.state = HealthState::Suspect;
                    self.suspect_since = Some(now);
                    self.probe_outstanding_since = Some(now);
                    let nonce = self.next_nonce;
                    self.next_nonce = self.next_nonce.wrapping_add(1);
                    self.current_probe_nonce = Some(nonce);
                    HealthAction::SendProbe { nonce }
                } else {
                    HealthAction::None
                }
            }
            HealthState::Suspect => {
                let probe_timeout = if fast_stuck {
                    FAST_PROBE_TIMEOUT
                } else {
                    PROBE_TIMEOUT
                };
                if let Some(since) = self.probe_outstanding_since {
                    if now.duration_since(since) >= probe_timeout {
                        self.state = HealthState::Dead;
                        return HealthAction::Reconnect {
                            reason: "probe_timeout",
                        };
                    }
                }
                // Still within probe window; optionally send a fresh
                // probe each tick while Suspect to cover probe drops.
                let nonce = self.next_nonce;
                self.next_nonce = self.next_nonce.wrapping_add(1);
                self.current_probe_nonce = Some(nonce);
                HealthAction::SendProbe { nonce }
            }
            HealthState::Dead => HealthAction::None,
        }
    }

    /// Call after a successful reconnect to clear Dead and go back to
    /// Healthy.
    pub fn reset_after_reconnect(&mut self) {
        self.state = HealthState::Healthy;
        self.suspect_since = None;
        self.probe_outstanding_since = None;
        self.current_probe_nonce = None;
    }
}

impl Default for SessionHealth {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_healthy() {
        let h = SessionHealth::new();
        assert_eq!(h.state(), HealthState::Healthy);
    }

    #[test]
    fn quiet_tunnel_with_no_flows_stays_healthy() {
        let mut h = SessionHealth::new();
        let action = h.tick(
            Instant::now(),
            HealthTickInputs {
                has_active_flows: false,
                useful_rx_age: Duration::from_secs(60),
                ..Default::default()
            },
        );
        assert_eq!(action, HealthAction::None);
        assert_eq!(h.state(), HealthState::Healthy);
    }

    #[test]
    fn silent_active_moves_to_suspect_and_probes() {
        let mut h = SessionHealth::new();
        let now = Instant::now();
        let action = h.tick(
            now,
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(6),
                ..Default::default()
            },
        );
        assert!(matches!(action, HealthAction::SendProbe { .. }));
        assert_eq!(h.state(), HealthState::Suspect);
        assert!(h.probe_outstanding_since().is_some());
    }

    #[test]
    fn stuck_high_seq_moves_to_suspect() {
        let mut h = SessionHealth::new();
        let action = h.tick(
            Instant::now(),
            HealthTickInputs {
                has_active_flows: true,
                consecutive_stuck_high_seq_ticks: 4,
                ..Default::default()
            },
        );
        assert!(matches!(action, HealthAction::SendProbe { .. }));
        assert_eq!(h.state(), HealthState::Suspect);
    }

    #[test]
    fn pong_restores_health() {
        let mut h = SessionHealth::new();
        let t0 = Instant::now();
        let action = h.tick(
            t0,
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(6),
                ..Default::default()
            },
        );
        let nonce = match action {
            HealthAction::SendProbe { nonce } => nonce,
            other => panic!("expected SendProbe got {other:?}"),
        };

        // Within probe timeout, receive the pong.
        let t1 = t0 + Duration::from_secs(2);
        h.on_pong(nonce, t1);
        assert_eq!(h.state(), HealthState::Healthy);
        assert!(h.probe_outstanding_since().is_none());
    }

    #[test]
    fn probe_timeout_moves_to_dead() {
        let mut h = SessionHealth::new();
        let t0 = Instant::now();
        let _ = h.tick(
            t0,
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(6),
                ..Default::default()
            },
        );
        // Advance past probe timeout (5s).
        let t1 = t0 + Duration::from_secs(6);
        let action = h.tick(
            t1,
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(12),
                ..Default::default()
            },
        );
        assert_eq!(
            action,
            HealthAction::Reconnect {
                reason: "probe_timeout"
            }
        );
        assert_eq!(h.state(), HealthState::Dead);
    }

    #[test]
    fn fast_stuck_uses_shorter_probe_timeout() {
        let mut h = SessionHealth::new();
        let t0 = Instant::now();
        let _ = h.tick(
            t0,
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(6),
                consecutive_stuck_high_seq_ticks: 1,
                oldest_outbound_ms: 4_000,
            },
        );
        // Advance past FAST_PROBE_TIMEOUT (3s) but before normal 5s.
        let t1 = t0 + Duration::from_secs(4);
        let action = h.tick(
            t1,
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(10),
                consecutive_stuck_high_seq_ticks: 2,
                oldest_outbound_ms: 8_000,
            },
        );
        assert_eq!(
            action,
            HealthAction::Reconnect {
                reason: "probe_timeout"
            }
        );
    }

    #[test]
    fn reset_after_reconnect_restores_health() {
        let mut h = SessionHealth::new();
        let t0 = Instant::now();
        let _ = h.tick(
            t0,
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(6),
                ..Default::default()
            },
        );
        let _ = h.tick(
            t0 + Duration::from_secs(6),
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(12),
                ..Default::default()
            },
        );
        assert_eq!(h.state(), HealthState::Dead);
        h.reset_after_reconnect();
        assert_eq!(h.state(), HealthState::Healthy);
    }

    #[test]
    fn dead_tick_returns_none() {
        let mut h = SessionHealth::new();
        // Force Dead by driving suspect + timeout.
        let t0 = Instant::now();
        let _ = h.tick(
            t0,
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(6),
                ..Default::default()
            },
        );
        let _ = h.tick(
            t0 + Duration::from_secs(6),
            HealthTickInputs {
                has_active_flows: true,
                useful_rx_age: Duration::from_secs(12),
                ..Default::default()
            },
        );
        let later = h.tick(
            t0 + Duration::from_secs(30),
            HealthTickInputs::default(),
        );
        assert_eq!(later, HealthAction::None);
    }
}
