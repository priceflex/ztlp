//! Nebula-pivot R1 STUB.
//!
//! The real 394-LOC iOS session-health module (stall detector / probe-timeout
//! / "needs reconnect" state machine) was deleted in Phase R1. Fire-and-forget
//! UDP has nothing to stall on — keepalive alone provides liveness. This
//! file keeps the minimal surface `ffi.rs` uses so the crate compiles under
//! `--features ios-sync`.
//!
//! Every method returns `HealthAction::None`, and every tick reports
//! `HealthState::Healthy`.
//!
//! TODO(nebula-pivot-R4): delete this file + the FFI functions in
//! `ffi.rs` (`ztlp_health_*`) that use these types, and the corresponding
//! `ztlp.h` entries.

#![allow(dead_code, unused_variables)]

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Suspect,
    Dead,
}

#[derive(Debug, Clone)]
pub enum HealthAction {
    None,
    SendProbe { nonce: u64 },
    Reconnect { reason: String },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HealthTickInputs {
    pub now_ms: u64,
    pub last_rx_ms: u64,
    pub oldest_outbound_ms: u64,
    pub probe_inflight_nonce: u64,
    pub probe_sent_at_ms: u64,
    pub has_active_flows: bool,
    pub useful_rx_age: Duration,
    pub consecutive_stuck_high_seq_ticks: u32,
}

#[derive(Default)]
pub struct SessionHealth {
    state: HealthState,
}

impl Default for HealthState {
    fn default() -> Self {
        HealthState::Healthy
    }
}

impl SessionHealth {
    pub fn new() -> Self {
        Self {
            state: HealthState::Healthy,
        }
    }

    /// Stub: accepts both a wall-clock `Instant` and the C-side input snapshot
    /// so the existing `ffi::ztlp_health_tick` keeps compiling. Always returns
    /// `HealthAction::None`.
    pub fn tick(&mut self, _now: Instant, _inputs: HealthTickInputs) -> HealthAction {
        HealthAction::None
    }

    pub fn state(&self) -> HealthState {
        self.state
    }

    pub fn on_probe_ack(&mut self, _nonce: u64, _now_ms: u64) {}

    /// Stub: kept so `ffi::ztlp_health_on_pong` compiles.
    pub fn on_pong(&mut self, _nonce: u64, _now: Instant) {}

    /// Stub: kept so `ffi::ztlp_health_reset_after_reconnect` compiles.
    pub fn reset_after_reconnect(&mut self) {
        self.state = HealthState::Healthy;
    }

    pub fn reset(&mut self) {
        self.state = HealthState::Healthy;
    }
}
