//! Nebula-pivot R1 STUB.
//!
//! The real 401-LOC pacing module (token-bucket + HZ detection + system
//! profile) was deleted in Phase R1. Nebula-style fire-and-forget has no
//! pacer. This file keeps `detect_system` / `pace` / `TARGET_BUFFER_SIZE`
//! as trivial no-ops so `tunnel.rs` and `bin/ztlp-cli.rs` continue to
//! type-check until R3 removes the call sites.
//!
//! TODO(nebula-pivot-R3): delete this file + the `pub mod pacing;` line
//! in `lib.rs` once `tunnel.rs::run_bridge_inner` is rewritten.

#![allow(dead_code, unused_variables)]

use std::net::SocketAddr;
use std::time::Duration;

pub const TARGET_BUFFER_SIZE: usize = 7 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct PacingStrategy;

#[derive(Debug, Clone, Copy)]
pub struct SystemProfile {
    pub pacing: PacingStrategy,
    pub max_sub_batch: usize,
}

impl Default for SystemProfile {
    fn default() -> Self {
        Self {
            pacing: PacingStrategy,
            max_sub_batch: 64,
        }
    }
}

/// Stub: no HZ detection, no buffer sizing, no pacing.
pub fn detect_system(
    _peer_addr: SocketAddr,
    _sock: Option<&std::net::UdpSocket>,
    _probe: Duration,
) -> SystemProfile {
    SystemProfile::default()
}

/// Stub: no-op. Fire-and-forget has no pacing.
pub fn pace<T>(_strategy: &T) {}
