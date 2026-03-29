//! Congestion-controlled upload sender for the VIP proxy.
//!
//! The `SendController` wraps `AdvancedCongestionController` to provide
//! cwnd-gated sending, ACK tracking, RTT estimation, and retransmission
//! for the VIP proxy upload path. Previously, uploads sent packets directly
//! via `transport.send_data()` with no flow control, overwhelming cellular
//! networks on large uploads.
//!
//! ## How it works
//!
//! 1. VIP upload loop calls `enqueue()` to add framed payloads to a pending queue
//! 2. `flush()` sends up to `cwnd` packets from the queue via the transport
//! 3. Each sent packet is tracked in `send_buffer` by its transport sequence number
//! 4. The recv_loop in `ffi.rs` feeds gateway ACKs via an unbounded channel
//! 5. `process_acks()` drains the ACK channel, updates RTT, and opens the window
//! 6. `check_retransmit()` retransmits packets that have timed out (RTO)
//!
//! ## Gateway ACK format
//!
//! The gateway sends: `[FRAME_ACK(0x01) | packet_seq(8 BE)]`
//! This is a cumulative ACK — everything ≤ `packet_seq` is acknowledged.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::congestion::AdvancedCongestionController;
use crate::error::TransportError;
use crate::packet::SessionId;
use crate::transport::TransportNode;

/// An in-flight packet tracked for ACK/retransmit.
struct SendEntry {
    /// The framed payload to send/retransmit.
    data: Vec<u8>,
    /// When this packet was first sent (for RTT measurement).
    sent_at: Instant,
    /// The transport-level sequence number assigned by `send_data()`.
    send_seq: u64,
    /// How many times this packet has been retransmitted.
    retransmits: u32,
}

/// Congestion-controlled sender for VIP proxy uploads.
///
/// Wrap in `Arc<tokio::sync::Mutex<>>` for sharing between the VIP upload
/// loop and the background flush/retransmit task.
pub struct SendController {
    /// AIMD congestion controller (cwnd, RTT, loss detection).
    cc: AdvancedCongestionController,
    /// In-flight packets keyed by transport sequence number.
    send_buffer: BTreeMap<u64, SendEntry>,
    /// Framed payloads waiting to be sent (enqueued but not yet transmitted).
    pending_queue: VecDeque<Vec<u8>>,
    /// Receives ACK sequence numbers from the recv_loop.
    ack_rx: mpsc::UnboundedReceiver<u64>,
    /// Transport for sending packets.
    transport: Arc<TransportNode>,
    /// Session ID for this tunnel connection.
    session_id: SessionId,
    /// Gateway address to send packets to.
    peer_addr: SocketAddr,
    /// Highest ACK sequence number we've processed (cumulative).
    highest_ack: Option<u64>,
}

impl SendController {
    /// Create a new SendController.
    ///
    /// # Arguments
    /// - `transport`: The UDP transport node for sending packets
    /// - `session_id`: The active tunnel session ID
    /// - `peer_addr`: The gateway address
    /// - `ack_rx`: Receiver end of the ACK channel (sender is held by recv_loop)
    pub fn new(
        transport: Arc<TransportNode>,
        session_id: SessionId,
        peer_addr: SocketAddr,
        ack_rx: mpsc::UnboundedReceiver<u64>,
    ) -> Self {
        Self {
            cc: AdvancedCongestionController::new(),
            send_buffer: BTreeMap::new(),
            pending_queue: VecDeque::new(),
            ack_rx,
            transport,
            session_id,
            peer_addr,
            highest_ack: None,
        }
    }

    /// Add a framed payload to the pending queue.
    ///
    /// The payload will be sent when `flush()` is called and the congestion
    /// window allows it.
    pub fn enqueue(&mut self, framed_data: Vec<u8>) {
        self.pending_queue.push_back(framed_data);
    }

    /// Number of packets currently in-flight (sent but not yet ACKed).
    pub fn in_flight(&self) -> usize {
        self.send_buffer.len()
    }

    /// Send up to `cwnd - in_flight` packets from the pending queue.
    ///
    /// Returns Ok(number_sent) on success, or the first send error encountered.
    pub async fn flush(&mut self) -> Result<usize, TransportError> {
        let mut sent_count = 0usize;
        let cwnd = self.cc.effective_window() as usize;

        while self.in_flight() < cwnd {
            let framed = match self.pending_queue.pop_front() {
                Some(f) => f,
                None => break,
            };

            let seq = self
                .transport
                .send_data(self.session_id, &framed, self.peer_addr)
                .await?;

            self.send_buffer.insert(
                seq,
                SendEntry {
                    data: framed,
                    sent_at: Instant::now(),
                    send_seq: seq,
                    retransmits: 0,
                },
            );

            sent_count += 1;
        }

        if sent_count > 0 {
            info!(
                "send_controller: flushed {} packets (in_flight={}, cwnd={}, pending={})",
                sent_count,
                self.in_flight(),
                cwnd,
                self.pending_queue.len()
            );
        }

        Ok(sent_count)
    }

    /// Drain the ACK channel and process all pending ACKs.
    ///
    /// For each ACK:
    /// - Removes all send_buffer entries with seq ≤ acked_seq (cumulative ACK)
    /// - Computes RTT from the oldest ACKed entry's `sent_at`
    /// - Calls `cc.on_ack()` to open the congestion window
    pub fn process_acks(&mut self) {
        while let Ok(acked_seq) = self.ack_rx.try_recv() {
            // Skip if we've already processed a higher ACK
            if let Some(highest) = self.highest_ack {
                if acked_seq <= highest {
                    continue;
                }
            }

            // Count newly ACKed packets and measure RTT from the oldest one
            let mut newly_acked = 0u64;
            let mut rtt_sample: Option<Duration> = None;

            // Remove all entries with seq ≤ acked_seq (cumulative ACK)
            let acked_keys: Vec<u64> = self
                .send_buffer
                .range(..=acked_seq)
                .map(|(&k, _)| k)
                .collect();

            for key in acked_keys {
                if let Some(entry) = self.send_buffer.remove(&key) {
                    newly_acked += 1;
                    // Only use RTT from non-retransmitted packets (Karn's algorithm)
                    if entry.retransmits == 0 && rtt_sample.is_none() {
                        rtt_sample = Some(entry.sent_at.elapsed());
                    }
                }
            }

            if newly_acked > 0 {
                // Update RTT estimate
                if let Some(rtt) = rtt_sample {
                    self.cc.update_rtt(rtt.as_secs_f64() * 1000.0);
                }

                // Open the congestion window
                self.cc.on_ack(newly_acked);

                info!(
                    "send_controller: ACK seq={}, newly_acked={}, cwnd={:.1}, in_flight={}, pending={}, rtt={:?}",
                    acked_seq,
                    newly_acked,
                    self.cc.cwnd,
                    self.in_flight(),
                    self.pending_queue.len(),
                    rtt_sample,
                );
            }

            self.highest_ack = Some(acked_seq);
        }
    }

    /// Check for timed-out in-flight packets and retransmit them.
    ///
    /// Uses the congestion controller's RTO estimate. On retransmit:
    /// - Calls `cc.on_rto()` to reduce the window (back to slow start)
    /// - Re-sends the packet via the transport (gets a new seq)
    /// - Updates the send_buffer entry with the new seq
    pub async fn check_retransmit(&mut self) -> Result<usize, TransportError> {
        let rto = Duration::from_millis(self.cc.rto_ms() as u64);
        let now = Instant::now();
        let mut retransmit_count = 0usize;

        // Collect entries that have timed out
        let timed_out: Vec<u64> = self
            .send_buffer
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.sent_at) > rto)
            .map(|(&seq, _)| seq)
            .collect();

        if timed_out.is_empty() {
            return Ok(0);
        }

        // Signal loss to congestion controller (once per retransmit batch)
        let highest_sent = self.send_buffer.keys().next_back().copied();
        self.cc.on_loss(highest_sent);

        for old_seq in timed_out {
            if let Some(mut entry) = self.send_buffer.remove(&old_seq) {
                entry.retransmits += 1;

                // Cap retransmits to avoid infinite loops
                if entry.retransmits > 10 {
                    debug!(
                        "send_controller: dropping packet seq={} after {} retransmits",
                        old_seq, entry.retransmits
                    );
                    continue;
                }

                // Retransmit — gets a new transport seq
                let new_seq = self
                    .transport
                    .send_data(self.session_id, &entry.data, self.peer_addr)
                    .await?;

                debug!(
                    "send_controller: retransmit old_seq={} → new_seq={} (attempt {})",
                    old_seq, new_seq, entry.retransmits
                );

                entry.send_seq = new_seq;
                entry.sent_at = Instant::now();
                self.send_buffer.insert(new_seq, entry);

                retransmit_count += 1;
            }
        }

        Ok(retransmit_count)
    }

    /// Returns true when all data has been sent and acknowledged.
    ///
    /// Both the pending queue and the send buffer must be empty.
    pub fn is_complete(&self) -> bool {
        self.pending_queue.is_empty() && self.send_buffer.is_empty()
    }

    /// Number of packets waiting in the pending queue (not yet sent).
    pub fn pending_count(&self) -> usize {
        self.pending_queue.len()
    }

    /// Current congestion window size.
    pub fn cwnd(&self) -> f64 {
        self.cc.cwnd
    }

    /// Current RTO estimate in milliseconds.
    pub fn rto_ms(&self) -> f64 {
        self.cc.rto_ms()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a SendController with a mock transport for testing.
    ///
    /// Returns (controller, ack_sender) — use ack_sender to simulate gateway ACKs.
    async fn make_test_controller() -> (SendController, mpsc::UnboundedSender<u64>) {
        let transport = TransportNode::bind("127.0.0.1:0")
            .await
            .expect("bind test transport");
        let transport = Arc::new(transport);
        let session_id = SessionId::generate();
        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let (ack_tx, ack_rx) = mpsc::unbounded_channel();

        let controller = SendController::new(transport, session_id, peer_addr, ack_rx);
        (controller, ack_tx)
    }

    #[tokio::test]
    async fn test_new_controller_is_empty() {
        let (ctrl, _tx) = make_test_controller().await;
        assert!(ctrl.is_complete());
        assert_eq!(ctrl.in_flight(), 0);
        assert_eq!(ctrl.pending_count(), 0);
    }

    #[tokio::test]
    async fn test_enqueue_adds_to_pending() {
        let (mut ctrl, _tx) = make_test_controller().await;
        ctrl.enqueue(vec![0x00, 0x01, 0x02]);
        assert_eq!(ctrl.pending_count(), 1);
        assert!(!ctrl.is_complete());

        ctrl.enqueue(vec![0x03, 0x04]);
        assert_eq!(ctrl.pending_count(), 2);
    }

    #[tokio::test]
    async fn test_is_complete_when_drained() {
        let (mut ctrl, _tx) = make_test_controller().await;
        assert!(ctrl.is_complete());
        ctrl.enqueue(vec![0x00]);
        assert!(!ctrl.is_complete());
    }

    #[tokio::test]
    async fn test_process_acks_updates_state() {
        let (mut ctrl, ack_tx) = make_test_controller().await;

        // Manually insert a fake send_buffer entry
        ctrl.send_buffer.insert(
            42,
            SendEntry {
                data: vec![0x00],
                sent_at: Instant::now(),
                send_seq: 42,
                retransmits: 0,
            },
        );
        assert_eq!(ctrl.in_flight(), 1);

        // Simulate gateway ACK for seq 42
        ack_tx.send(42).unwrap();
        ctrl.process_acks();

        assert_eq!(ctrl.in_flight(), 0);
        assert_eq!(ctrl.highest_ack, Some(42));
    }

    #[tokio::test]
    async fn test_process_acks_cumulative() {
        let (mut ctrl, ack_tx) = make_test_controller().await;

        // Insert entries for seqs 10, 11, 12
        for seq in 10..=12 {
            ctrl.send_buffer.insert(
                seq,
                SendEntry {
                    data: vec![0x00],
                    sent_at: Instant::now(),
                    send_seq: seq,
                    retransmits: 0,
                },
            );
        }
        assert_eq!(ctrl.in_flight(), 3);

        // ACK seq 11 — should remove 10 and 11 (cumulative)
        ack_tx.send(11).unwrap();
        ctrl.process_acks();

        assert_eq!(ctrl.in_flight(), 1);
        assert!(ctrl.send_buffer.contains_key(&12));
        assert!(!ctrl.send_buffer.contains_key(&10));
        assert!(!ctrl.send_buffer.contains_key(&11));
    }

    #[tokio::test]
    async fn test_process_acks_ignores_stale() {
        let (mut ctrl, ack_tx) = make_test_controller().await;

        ctrl.highest_ack = Some(50);

        // Send a stale ACK (lower than what we've already processed)
        ack_tx.send(40).unwrap();
        ctrl.process_acks();

        // highest_ack should not change
        assert_eq!(ctrl.highest_ack, Some(50));
    }

    #[tokio::test]
    async fn test_cwnd_initial_value() {
        let (ctrl, _tx) = make_test_controller().await;
        // Initial cwnd from AdvancedCongestionController
        assert!(ctrl.cwnd() >= 2.0);
    }

    #[tokio::test]
    async fn test_rto_initial_value() {
        let (ctrl, _tx) = make_test_controller().await;
        // RTO should be some reasonable initial value
        assert!(ctrl.rto_ms() > 0.0);
        assert!(ctrl.rto_ms() < 60000.0);
    }

    #[tokio::test]
    async fn test_check_retransmit_empty_buffer() {
        let (mut ctrl, _tx) = make_test_controller().await;
        let count = ctrl.check_retransmit().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_check_retransmit_not_timed_out() {
        let (mut ctrl, _tx) = make_test_controller().await;

        // Insert an entry that was just sent (should not be retransmitted)
        ctrl.send_buffer.insert(
            1,
            SendEntry {
                data: vec![0x00],
                sent_at: Instant::now(),
                send_seq: 1,
                retransmits: 0,
            },
        );

        let count = ctrl.check_retransmit().await.unwrap();
        assert_eq!(count, 0);
    }
}
