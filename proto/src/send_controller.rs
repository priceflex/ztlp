//! Nebula-pivot R1 STUB.
//!
//! The real 609-LOC `SendController` (cwnd-gated queue, ACK drain, retransmit
//! timer, wraps `AdvancedCongestionController`) was deleted in Phase R1.
//! This stub keeps the same public surface so `vip.rs` compiles until R2
//! collapses all `sc.enqueue(...)` / `sc.flush()` etc. call sites to direct
//! `transport.send_data()`.
//!
//! The stub does NOTHING on the wire — every method is a no-op or returns
//! `Ok(())`. This is intentional: behavior is deliberately broken until R2
//! rewrites vip.rs.
//!
//! TODO(nebula-pivot-R2): delete this file + the `pub mod send_controller;`
//! line in `lib.rs` once `vip.rs` no longer uses `SendController`.

#![allow(dead_code, unused_variables, clippy::unused_async)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::packet::SessionId;
use crate::transport::TransportNode;

pub struct SendController;

impl SendController {
    pub fn new(
        _transport: Arc<TransportNode>,
        _session_id: SessionId,
        _peer_addr: SocketAddr,
        _ack_rx: mpsc::UnboundedReceiver<u64>,
    ) -> Self {
        Self
    }

    /// Stub: drop the frame on the floor. R2 will replace with direct send.
    pub fn enqueue(&mut self, _frame: Vec<u8>) {}

    /// Stub: drop the priority frame. R2 will replace with direct send.
    pub fn enqueue_priority(&mut self, _frame: Vec<u8>) {}

    /// Stub: no ACK tracking exists anymore.
    pub fn process_acks(&mut self) {}

    /// Stub: nothing to flush.
    pub async fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Stub: nothing to retransmit.
    pub async fn check_retransmit(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    /// Stub: no per-stream retransmit buffer to purge.
    pub fn purge_stream(&mut self, _stream_id: u32) {}
}
