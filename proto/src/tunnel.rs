//! TCP ↔ ZTLP tunnel bridge with reliable ordered delivery.
//!
//! Provides bidirectional forwarding between a local TCP connection and an
//! encrypted ZTLP session over UDP. This enables tunneling of arbitrary TCP
//! services (SSH, RDP, HTTP, databases, etc.) through ZTLP's identity-first
//! encrypted transport.
//!
//! ## Reliability Layer
//!
//! UDP does not guarantee ordering or delivery. Since TCP is an ordered byte
//! stream, writing decrypted UDP packets to TCP in arrival order corrupts the
//! stream (SSH/SCP will detect this and reset the connection). This module
//! implements a lightweight reliability protocol on top of ZTLP data packets:
//!
//! - **Reassembly buffer:** Out-of-order packets are buffered and delivered
//!   to TCP in sequence-number order. Duplicates and stale packets are dropped.
//!
//! - **ACK mechanism:** The receiver periodically sends ACK frames back
//!   through the ZTLP session, reporting the highest contiguous sequence
//!   number that has been delivered to TCP.
//!
//! - **Sender flow control:** The sender tracks ACKs and limits the number
//!   of in-flight (unacknowledged) packets to a configurable window size.
//!   When the window is exhausted, the sender waits for ACKs.
//!
//! - **Congestion control:** AIMD-style congestion control with slow start
//!   and congestion avoidance phases. RTT is estimated via EWMA from ACK
//!   round-trips, with RTO computed as srtt + 4*rttvar.
//!
//! - **Retransmission:** The sender keeps a bounded retransmit buffer of
//!   sent packets. The receiver detects gaps and sends NACK frames listing
//!   missing sequence numbers. The sender re-encrypts and retransmits them.
//!
//! - **Graceful shutdown:** TCP EOF is signaled via a FIN frame so the
//!   remote side can flush buffered data and close cleanly.
//!
//! ### Frame format
//!
//! Each ZTLP data packet's plaintext is prefixed with a 1-byte frame type.
//! DATA and FIN frames carry an embedded `data_seq` (8-byte BE) that is
//! independent of the ZTLP packet header's `packet_seq`. The `packet_seq`
//! provides nonce uniqueness; `data_seq` provides reassembly ordering.
//! ACK/NACK frames reference `data_seq` values, NOT `packet_seq`.
//!
//! | Type | Byte | Payload |
//! |------|------|---------|
//! | DATA  | 0x00 | 8-byte BE data_seq + raw TCP bytes |
//! | ACK   | 0x01 | 8-byte BE data_seq: highest delivered data_seq |
//! | FIN   | 0x02 | 8-byte BE data_seq |
//! | NACK  | 0x03 | 2-byte BE count + N × 8-byte BE missing data_seqs |
//! | SACK  | 0x05 | 8-byte cumulative_ack + 2-byte count + N × (start, end) ranges |
//! | RESET | 0x04 | (empty) — signals new TCP stream, resets data_seq |
//!
//! Two modes of operation:
//!
//! - **Server-side (`--forward`):** After accepting a ZTLP session, connects
//!   to a local TCP service and bridges traffic bidirectionally.
//!
//! - **Client-side (`--local-forward`):** Opens a local TCP listener, performs
//!   a ZTLP handshake with the remote peer, and bridges incoming TCP
//!   connections through the encrypted ZTLP tunnel.

#![deny(clippy::unwrap_used)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::packet::{DataHeader, SessionId, DATA_HEADER_SIZE};
use crate::pipeline::{compute_header_auth_tag, AdmissionResult, Pipeline};
use crate::stats::{RxBatchStats, TunnelStats, TxBatchStats};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum service name length (must fit in 16-byte DstSvcID field).
pub const MAX_SERVICE_NAME_LEN: usize = 16;

/// The default service name used when no name is specified.
pub const DEFAULT_SERVICE: &str = "_default";

/// Maximum TCP read buffer size per chunk.
/// Larger buffers reduce syscall overhead and improve throughput
/// for bulk transfers (SCP, file copies).
const TCP_READ_BUF: usize = 131072;

/// Default maximum number of packets to send in a single sub-batch.
/// The actual value is determined at runtime based on the detected
/// UDP receive buffer size. This constant serves as the fallback when
/// system detection is unavailable.
///
/// At ~16KB per packet, 64 packets ≈ 1MB per burst.
#[allow(dead_code)]
/// Maximum packets per sendmmsg batch. Relay-friendly default — relays
/// process packets sequentially so large bursts overflow their UDP buffers.
/// 16 packets × 1271 bytes ≈ 20 KB per batch, well within UDP socket buffers.
const MAX_SUB_BATCH: usize = 16;

/// Maximum UDP payload (minus ZTLP header + AEAD overhead).
/// ZTLP data header is 46 bytes, Poly1305 tag is 16 bytes, so
/// max plaintext per packet ≈ 65535 - 46 - 16 = 65473.
/// We use 16KB to stay well within IP fragmentation limits.
/// On 1500-byte MTU networks, ~16KB payloads fragment into ~11 pieces
/// which is manageable. Larger payloads suffer exponentially worse
/// fragment loss rates under any packet loss.
/// Subtract 9 bytes for the frame type prefix (1) + data_seq (8).
/// Maximum plaintext payload per ZTLP packet (TCP data only, before framing).
/// Must fit in a single UDP datagram after adding:
///   - 9 bytes frame overhead (1 type + 8 data_seq)
///   - 16 bytes ChaCha20-Poly1305 tag
///   - 46 bytes ZTLP data header
/// Total overhead = 71 bytes. Target max UDP = 1280 (IPv6 min MTU).
/// 1280 - 71 = 1209, rounded down to 1200 for safety margin.
const MAX_PLAINTEXT_PER_PACKET: usize = 1200;

// ─── Frame types ────────────────────────────────────────────────────────────

/// Frame type byte: DATA frame containing TCP payload bytes.
const FRAME_DATA: u8 = 0x00;

/// Frame type byte: ACK frame containing 8-byte big-endian delivered seq.
const FRAME_ACK: u8 = 0x01;

/// Frame type byte: FIN frame signaling TCP EOF / stream complete.
const FRAME_FIN: u8 = 0x02;

/// Frame type byte: NACK frame listing missing sequence numbers.
/// Payload: [count: u16 BE] [seq1: u64 BE] [seq2: u64 BE] ...
const FRAME_NACK: u8 = 0x03;

/// Stream reset: signals the start of a new TCP connection within the same
/// ZTLP session. The receiver resets its reassembly state (`expected_seq` = 0)
/// and opens a new backend TCP connection. The RESET frame has no payload
/// beyond the frame type byte itself.
const FRAME_RESET: u8 = 0x04;

/// Frame type byte: SACK frame with cumulative ACK + received ranges.
/// Payload: [cumulative_ack: u64 BE] [count: u16 BE] [(start: u64 BE, end: u64 BE) × count]
const FRAME_SACK: u8 = 0x05;

/// Frame type byte: REJECT frame — server denying access after handshake.
/// Payload: [reason_code: 1B] [message: UTF-8 remaining bytes]
const FRAME_REJECT: u8 = 0x08;

/// Frame type byte: RTT_PING frame for dedicated RTT measurement.
/// Payload: [ping_id: u32 BE] [timestamp_us: u64 BE]
/// Sent periodically by the sender to obtain clean RTT samples even during
/// heavy retransmission (when Karn's algorithm filters all data-packet RTTs).
/// Never retransmitted — if lost, the next probe covers it.
const FRAME_RTT_PING: u8 = 0x06;

/// Frame type byte: RTT_PONG frame — response to RTT_PING.
/// Payload: [ping_id: u32 BE] [echo_timestamp_us: u64 BE] [receiver_delay_us: u32 BE]
/// The receiver echoes the ping_id and original timestamp, plus the time it
/// spent processing (receiver_delay_us) so the sender can subtract it.
const FRAME_RTT_PONG: u8 = 0x07;

/// Frame type byte: CORRUPTION_NACK frame — receiver detected AEAD decrypt
/// failure (bit-flip, not congestion). Same wire format as NACK. Sender
/// retransmits but does NOT reduce cwnd.
const FRAME_CORRUPTION_NACK: u8 = 0x09;

/// Frame type byte: STREAM_RESET — VIP mux protocol.
///
/// Sent by the client instead of FRAME_CLOSE + FRAME_OPEN when it wants to
/// reuse the same stream for a new HTTP request. The gateway can then reuse
/// the same backend TCP connection, avoiding a full TCP teardown/setup cycle.
///
/// Wire format: `[0x0B | stream_id(4 BE)]`
///
/// This is a mux-layer frame (like FRAME_OPEN/FRAME_CLOSE in `vip.rs`),
/// not a tunnel reliability frame. It travels inside the encrypted tunnel
/// payload alongside mux DATA/OPEN/CLOSE frames.
///
/// Gateway-side handling is added separately.
pub const FRAME_STREAM_RESET: u8 = 0x0B;

/// PLPMTUD probe request — sent with padding to test larger MTU sizes.
/// Wire format: `[0x0C | probe_size(2 BE) | probe_seq(2 BE) | padding...]`
pub const FRAME_PMTU_PROBE: u8 = 0x0C;

/// PLPMTUD probe acknowledgment.
/// Wire format: `[0x0D | probe_size(2 BE) | probe_seq(2 BE)]`
pub const FRAME_PMTU_PROBE_ACK: u8 = 0x0D;

/// Outcome of a bridge run, distinguishing normal close from a stream reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// The TCP stream closed normally (FIN from both sides).
    Closed,
    /// A RESET frame was received — the remote side is starting a new TCP
    /// stream on the same ZTLP session. The caller should open a new backend
    /// TCP connection and start a fresh bridge.
    ResetReceived,
}

/// Result from `wait_for_reset_buffered`: indicates whether a RESET was
/// received, plus any data packets captured during the wait that must be
/// fed into the next bridge's receiver.
#[derive(Debug)]
pub struct ResetWaitResult {
    /// Whether a RESET frame was received.
    pub reset_received: bool,
    /// Raw encrypted UDP packets received after the RESET (or during the
    /// wait) that belong to the next bridge cycle. These must be processed
    /// by the new bridge to avoid data loss.
    pub buffered_packets: Vec<Vec<u8>>,
}

// ─── Flow control parameters ────────────────────────────────────────────────

/// Maximum number of unacknowledged packets the sender will keep in flight.
/// Large window allows high BDP links to fill the pipe.
pub const SEND_WINDOW: u64 = 65535;

/// The receiver sends an ACK after this many packets have been delivered
/// to TCP, or when the ACK timer fires — whichever comes first.
const ACK_EVERY_PACKETS: u64 = 16;

/// ACK timer interval: send an ACK at least this often while data is flowing.
const ACK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// Maximum number of out-of-order packets the reassembly buffer will hold
/// (matches send window to avoid unnecessary drops).
const REASSEMBLY_MAX_BUFFERED: usize = 65536;

/// If no progress (expected_seq advance) in this duration, abort the tunnel.
/// This prevents the bridge from hanging forever if packets are permanently lost.
const REASSEMBLY_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// If the sender receives no ACK for this long, abort.
const SENDER_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Hard maximum time a bridge can spend waiting for the send window to open.
/// Unlike `SENDER_ACK_TIMEOUT` (which resets on RTO retransmit), this is a
/// monotonic deadline: once the sender enters window-stall, it MUST make
/// progress (receive a new ACK that opens the window) within this duration
/// or the bridge aborts. This prevents infinite retransmit loops where the
/// RTO keeps resetting the ACK timeout.
const SENDER_WINDOW_STALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Maximum number of RTO-driven retransmit cycles for the same stall.
/// If the sender fires RTO this many times without any new ACK advancing
/// the window, the bridge aborts. This is a safety net complementing
/// `SENDER_WINDOW_STALL_LIMIT`.
const MAX_RTO_RETRANSMIT_CYCLES: u32 = 10;

/// After sending FIN, wait this long for remaining buffered packets to drain.
#[allow(dead_code)]
const FIN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

// ─── RTT probe parameters ───────────────────────────────────────────────────

/// How often to send RTT_PING probes during active data transfer.
/// These give clean RTT samples even when all data-packet ACKs are filtered
/// by Karn's algorithm due to retransmission.
const RTT_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

// ─── Congestion control parameters ──────────────────────────────────────────

/// Minimum retransmission timeout in milliseconds.
const MIN_RTO_MS: f64 = 200.0;

/// Maximum number of missing sequence numbers in a single NACK frame.
const MAX_NACK_SEQS: usize = 64;

/// Maximum entries in the retransmit buffer (matches send window).
const RETRANSMIT_BUF_MAX: usize = 65536;

// ─── Reassembly buffer ─────────────────────────────────────────────────────

/// Reassembly buffer that reorders out-of-order UDP packets for TCP delivery.
///
/// UDP does not guarantee packet ordering. When bridging to TCP (an ordered
/// byte stream), we must buffer early-arriving packets and deliver them in
/// sequence-number order. This prevents byte-stream corruption that would
/// cause SSH/SCP to reset the connection.
///
/// The buffer tracks:
/// - `expected_seq`: the next sequence number we need to deliver to TCP
/// - `buffer`: a BTreeMap holding out-of-order packets keyed by seq
/// - `last_progress`: when `expected_seq` last advanced (for stall detection)
///
/// Invariants:
/// - All packets with seq < expected_seq have already been delivered
/// - Packets in `buffer` have seq > expected_seq (gaps exist)
/// - Buffer size is bounded by `max_buffered` to prevent OOM
pub struct ReassemblyBuffer {
    /// Next sequence number that should be delivered to TCP.
    expected_seq: u64,
    /// Out-of-order packets waiting for gaps to fill.
    /// Key = packet sequence number, Value = decrypted data payload.
    buffer: BTreeMap<u64, Vec<u8>>,
    /// Maximum number of packets to buffer before dropping new arrivals.
    max_buffered: usize,
    /// Timestamp of the last time `expected_seq` advanced.
    /// Used to detect stalls (lost packets that never arrive).
    last_progress: Instant,
    /// When a gap was first detected (packets buffered but expected_seq hasn't arrived).
    /// Reset when expected_seq advances. Used for NACK timing.
    gap_detected_at: Option<Instant>,
    /// Timestamp of the last NACK we sent, to rate-limit NACKs.
    last_nack_time: Option<Instant>,
}

impl ReassemblyBuffer {
    /// Create a new reassembly buffer.
    ///
    /// `initial_seq` is the first sequence number we expect to receive.
    /// `max_buffered` limits memory usage for out-of-order packets.
    pub fn new(initial_seq: u64, max_buffered: usize) -> Self {
        Self {
            expected_seq: initial_seq,
            buffer: BTreeMap::new(),
            max_buffered,
            last_progress: Instant::now(),
            gap_detected_at: None,
            last_nack_time: None,
        }
    }

    /// Insert a packet into the reassembly buffer.
    ///
    /// Returns a Vec of `(seq, data)` pairs that are now ready for in-order
    /// delivery to TCP. This may be empty (packet buffered for later),
    /// contain just this packet (it was the next expected), or contain
    /// multiple packets (this packet filled a gap, releasing a run of
    /// consecutive buffered packets).
    ///
    /// Returns `None` if the packet is a duplicate/stale, or if the buffer
    /// is full and this packet can't be accommodated.
    pub fn insert(&mut self, seq: u64, data: Vec<u8>) -> Option<Vec<(u64, Vec<u8>)>> {
        // Duplicate or already-delivered packet — drop silently
        if seq < self.expected_seq {
            debug!(
                "reassembly: dropping duplicate/stale seq {} (expected {})",
                seq, self.expected_seq
            );
            return None;
        }

        // If this isn't the next expected packet, buffer it
        if seq > self.expected_seq {
            // Check if already buffered (duplicate of a future packet)
            if self.buffer.contains_key(&seq) {
                debug!("reassembly: dropping duplicate buffered seq {}", seq);
                return None;
            }
            // Check buffer capacity
            if self.buffer.len() >= self.max_buffered {
                warn!(
                    "reassembly: buffer full ({} packets), dropping seq {}",
                    self.buffer.len(),
                    seq
                );
                return None;
            }
            self.buffer.insert(seq, data);
            // Track gap detection: we have packets beyond expected_seq
            if self.gap_detected_at.is_none() {
                self.gap_detected_at = Some(Instant::now());
            }
            debug!(
                "reassembly: buffered seq {} (expected {}, buffered {})",
                seq,
                self.expected_seq,
                self.buffer.len()
            );
            return Some(vec![]);
        }

        // seq == expected_seq — deliver this packet and any consecutive buffered ones
        let mut deliverable = Vec::new();
        deliverable.push((seq, data));
        self.expected_seq = seq + 1;

        // Drain consecutive packets from the buffer
        while let Some(next_data) = self.buffer.remove(&self.expected_seq) {
            deliverable.push((self.expected_seq, next_data));
            self.expected_seq += 1;
        }

        // Mark progress and clear gap detection if buffer is now empty
        // or all remaining gaps have been filled
        self.last_progress = Instant::now();
        if self.buffer.is_empty() {
            self.gap_detected_at = None;
        } else {
            // Still have buffered packets — there's still a gap, reset timer
            self.gap_detected_at = Some(Instant::now());
        }

        debug!(
            "reassembly: delivered {} packets, expected_seq now {}, buffered {}",
            deliverable.len(),
            self.expected_seq,
            self.buffer.len()
        );

        Some(deliverable)
    }

    /// Check if the buffer has stalled (no progress for too long).
    ///
    /// A stall means `expected_seq` hasn't advanced within the timeout,
    /// which indicates packets were permanently lost. The caller should
    /// abort the tunnel.
    pub fn is_stalled(&self, timeout: std::time::Duration) -> bool {
        self.last_progress.elapsed() > timeout
    }

    /// The highest contiguous sequence number that has been delivered.
    /// This is `expected_seq - 1` (the last seq we handed to TCP).
    /// Returns `None` if no packets have been delivered yet.
    pub fn last_delivered_seq(&self) -> Option<u64> {
        if self.expected_seq == 0 {
            None
        } else {
            Some(self.expected_seq - 1)
        }
    }

    /// Number of packets currently buffered (waiting for gap fill).
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// The next expected sequence number.
    pub fn expected_seq(&self) -> u64 {
        self.expected_seq
    }

    /// Returns true if a gap has persisted beyond the given threshold.
    /// A gap means we have buffered packets beyond expected_seq but
    /// expected_seq hasn't arrived yet.
    pub fn should_nack(&self, threshold: std::time::Duration) -> bool {
        match self.gap_detected_at {
            Some(detected_at) => {
                // Must also have buffered packets (gap is real)
                !self.buffer.is_empty() && detected_at.elapsed() > threshold
            }
            None => false,
        }
    }

    /// Returns up to `max_count` missing sequence numbers between
    /// expected_seq and the lowest buffered seq.
    /// These are the seqs we need the sender to retransmit.
    pub fn missing_seqs(&self, max_count: usize) -> Vec<u64> {
        let mut missing = Vec::new();
        if self.buffer.is_empty() {
            return missing;
        }
        // Find the highest buffered seq to bound the search
        let &max_buffered_seq = match self.buffer.keys().next_back() {
            Some(s) => s,
            None => return missing,
        };
        let mut seq = self.expected_seq;
        while seq <= max_buffered_seq && missing.len() < max_count {
            if !self.buffer.contains_key(&seq) {
                missing.push(seq);
            }
            seq += 1;
        }
        missing
    }

    /// Mark that a NACK was just sent (for rate limiting).
    pub fn mark_nack_sent(&mut self) {
        self.last_nack_time = Some(Instant::now());
    }

    /// Whether a gap has been detected.
    pub fn has_gap(&self) -> bool {
        self.gap_detected_at.is_some()
    }

    /// Check if enough time has passed since the last NACK to send another.
    pub fn can_send_nack(&self, min_interval: std::time::Duration) -> bool {
        match self.last_nack_time {
            Some(last) => last.elapsed() >= min_interval,
            None => true,
        }
    }

    /// Get all buffered (out-of-order) sequence numbers, sorted.
    /// Used by the receiver to build SACK ranges.
    pub fn buffered_seqs(&self) -> Vec<u64> {
        self.buffer.keys().copied().collect()
    }
}

// ─── NACK frame encode/decode ────────────────────────────────────────────────

/// Encode a NACK frame payload: [FRAME_NACK | count: u16 BE | seq1: u64 BE | seq2: u64 BE | ...]
fn encode_nack_frame(missing_seqs: &[u64]) -> Vec<u8> {
    let count = missing_seqs.len().min(MAX_NACK_SEQS) as u16;
    let mut frame = Vec::with_capacity(1 + 2 + (count as usize) * 8);
    frame.push(FRAME_NACK);
    frame.extend_from_slice(&count.to_be_bytes());
    for &seq in missing_seqs.iter().take(MAX_NACK_SEQS) {
        frame.extend_from_slice(&seq.to_be_bytes());
    }
    frame
}

/// Decode a NACK frame payload (without the FRAME_NACK prefix byte).
/// Returns the list of missing sequence numbers, or None if malformed.
pub fn decode_nack_payload(payload: &[u8]) -> Option<Vec<u64>> {
    if payload.len() < 2 {
        return None;
    }
    let count = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if count > MAX_NACK_SEQS {
        return None;
    }
    let expected_len = 2 + count * 8;
    if payload.len() < expected_len {
        return None;
    }
    let mut seqs = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 2 + i * 8;
        // SAFETY: slice is exactly 8 bytes — length verified by `expected_len` check above
        let byte8: [u8; 8] = match payload[offset..offset + 8].try_into() {
            Ok(b) => b,
            Err(_) => return None,
        };
        let seq = u64::from_be_bytes(byte8);
        seqs.push(seq);
    }
    Some(seqs)
}

// ─── Retransmit buffer ──────────────────────────────────────────────────────

/// An entry in the retransmit buffer: the framed plaintext, packet_seq, and send timestamp.
struct RetransmitEntry {
    /// The framed plaintext (FRAME_DATA byte + data_seq + payload) ready for re-encryption.
    framed_plaintext: Vec<u8>,
    /// The original packet_seq used as nonce for encryption (needed for retransmit).
    packet_seq: u64,
    /// When this packet was originally sent (for RTT measurement).
    send_time: Instant,
    /// Whether this packet has been retransmitted (RTO or NACK-driven).
    /// Karn's algorithm: SRTT must NOT be updated from ACKs of retransmitted
    /// packets because we can't disambiguate whether the ACK is for the
    /// original or the retransmit.
    was_retransmitted: bool,
}

/// Buffer of sent packets awaiting ACK, keyed by sequence number.
///
/// Used for two purposes:
/// 1. Retransmission: when a NACK arrives, re-encrypt and resend the packet
/// 2. RTT measurement: compare send_time to ACK arrival for RTT samples
struct RetransmitBuffer {
    entries: HashMap<u64, RetransmitEntry>,
    max_entries: usize,
}

impl RetransmitBuffer {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Store a sent packet for potential retransmission.
    /// `data_seq` is the data-layer sequence number (used as key for NACK lookup).
    /// `packet_seq` is the pipeline sequence number (used as encryption nonce).
    /// If the buffer is full, the insert is silently dropped.
    fn insert(
        &mut self,
        data_seq: u64,
        packet_seq: u64,
        framed_plaintext: Vec<u8>,
        send_time: Instant,
    ) {
        if self.entries.len() >= self.max_entries {
            debug!(
                "retransmit buffer full ({} entries), skipping data_seq {}",
                self.entries.len(),
                data_seq
            );
            return;
        }
        self.entries.insert(
            data_seq,
            RetransmitEntry {
                framed_plaintext,
                packet_seq,
                send_time,
                was_retransmitted: false,
            },
        );
    }

    /// Get the framed plaintext for a data_seq (for retransmission).
    #[cfg(test)]
    fn get(&self, data_seq: u64) -> Option<&[u8]> {
        self.entries
            .get(&data_seq)
            .map(|e| e.framed_plaintext.as_slice())
    }

    /// Get the framed plaintext and original packet_seq for a data_seq.
    /// Returns (plaintext_copy, packet_seq) for retransmission.
    fn get_with_packet_seq(&self, data_seq: u64) -> Option<(Vec<u8>, u64)> {
        self.entries
            .get(&data_seq)
            .map(|e| (e.framed_plaintext.clone(), e.packet_seq))
    }

    /// Get the send timestamp for a data_seq (for RTT measurement).
    /// Returns None if the packet was retransmitted (Karn's algorithm:
    /// ambiguous ACKs must not update SRTT).
    fn send_time(&self, data_seq: u64) -> Option<Instant> {
        self.entries
            .get(&data_seq)
            .filter(|e| !e.was_retransmitted)
            .map(|e| e.send_time)
    }

    /// Mark a data_seq as retransmitted (Karn's algorithm).
    /// After this, `send_time()` will return None for this seq.
    fn mark_retransmitted(&mut self, data_seq: u64) {
        if let Some(entry) = self.entries.get_mut(&data_seq) {
            entry.was_retransmitted = true;
        }
    }

    /// Prune all entries with seq <= acked_seq (they've been ACKed).
    fn prune_up_to(&mut self, acked_seq: u64) {
        self.entries.retain(|&seq, _| seq > acked_seq);
    }

    /// Number of entries currently buffered.
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return the `count` oldest entries (by data_seq) as (data_seq, packet_seq, plaintext).
    /// Used for RTO retransmission of the earliest unacked packets.
    fn oldest_entries(&self, count: usize) -> Vec<(u64, u64, Vec<u8>)> {
        let mut seqs: Vec<u64> = self.entries.keys().copied().collect();
        seqs.sort_unstable();
        seqs.into_iter()
            .take(count)
            .filter_map(|ds| {
                self.entries
                    .get(&ds)
                    .map(|e| (ds, e.packet_seq, e.framed_plaintext.clone()))
            })
            .collect()
    }
}

// ─── Congestion controller ──────────────────────────────────────────────────

// ─── Lazy Connect ───────────────────────────────────────────────────────────

/// Wait for the first ZTLP data packet on a session before connecting to the
/// backend service. This implements "lazy connect" for the listener side.
///
/// Without this, the listener immediately TCP-connects to the backend (e.g.,
/// sshd) after the Noise_XX handshake. The backend sends its protocol banner
/// (SSH version string), which gets bridged over ZTLP. But if the client
/// hasn't accepted a TCP connection on its local port yet (e.g., the user
/// is presenting a demo and hasn't SSH'd yet), nobody reads the UDP socket
/// on the client side, no ACKs are sent, and the listener's sender hits the
/// 30-second `SENDER_ACK_TIMEOUT` — killing the tunnel.
///
/// This function blocks until valid ZTLP data arrives from the peer,
/// buffers the initial packets (with a 50ms grace window for bursts),
/// and returns them for injection into the bridge via
/// [`run_bridge_with_buffered`].
///
/// # Arguments
/// * `udp_socket` — The bound UDP socket for this session
///
/// Send a REJECT frame to a peer over an established ZTLP session.
///
/// This encrypts the reject frame as a DATA packet and sends it to the peer.
/// Used by the server after handshake when policy denies the client.
///
/// # Arguments
/// * `udp_socket` — UDP socket for sending
/// * `pipeline` — Pipeline containing session keys
/// * `session_id` — The established session ID
/// * `peer_addr` — Peer address to send to
/// * `reject_frame` — The encoded REJECT frame payload
pub async fn send_reject(
    udp_socket: &tokio::net::UdpSocket,
    pipeline: &Mutex<Pipeline>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    reject_frame: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    // Extract send key from session
    let send_key = {
        let pl = pipeline.lock().await;
        let session = pl.get_session(&session_id).ok_or("session not found")?;
        session.send_key
    };
    let cipher = ChaCha20Poly1305::new((&send_key).into());

    // Use packet_seq = 0 for the reject packet
    let packet_seq: u64 = 0;

    // Generate nonce from packet_seq (little-endian, matching run_bridge_inner receiver)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&packet_seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the reject payload (no AAD — matches normal sender/receiver flow)
    let ciphertext = cipher
        .encrypt(nonce, reject_frame)
        .map_err(|e| format!("AEAD encrypt failed: {}", e))?;

    // Build the data header
    let mut header = DataHeader::new(session_id, packet_seq);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);
    header.payload_len = ciphertext.len() as u16;

    // Build final packet
    let mut packet = header.serialize();
    packet.extend_from_slice(&ciphertext);

    udp_socket.send_to(&packet, peer_addr).await?;

    Ok(())
}

/// * `pipeline` — Pipeline for admission checks
/// * `session_id` — The established session ID
/// * `peer_addr` — Expected peer address
/// * `timeout_duration` — Maximum time to wait for first data
///
/// # Returns
/// A vector of raw UDP packets (including headers) to inject into the bridge.
pub async fn wait_for_first_data(
    udp_socket: &tokio::net::UdpSocket,
    pipeline: &Mutex<Pipeline>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    timeout_duration: Duration,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    use crate::pipeline::AdmissionResult;

    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut buffered_packets: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; 65535];

    loop {
        let recv_result = tokio::time::timeout_at(deadline, udp_socket.recv_from(&mut buf)).await;
        match recv_result {
            Err(_) => {
                return Err("timeout waiting for first data from client".into());
            }
            Ok(Err(e)) => {
                return Err(format!("recv error while waiting for first data: {}", e).into());
            }
            Ok(Ok((len, addr))) => {
                if addr != peer_addr {
                    continue;
                }

                let data = buf[..len].to_vec();

                // Pipeline admission check
                {
                    let pl = pipeline.lock().await;
                    let result = pl.process(&data);
                    if !matches!(result, AdmissionResult::Pass) {
                        continue;
                    }
                }

                // Must be a data packet for our session
                if data.len() < DATA_HEADER_SIZE {
                    continue;
                }
                let header = match DataHeader::deserialize(&data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if header.session_id != session_id {
                    continue;
                }

                // Got a valid data packet — buffer it
                buffered_packets.push(data);

                // Collect any additional packets that arrive in a short
                // grace window (the client likely sent a burst)
                let grace_deadline = tokio::time::Instant::now() + Duration::from_millis(50);
                loop {
                    let grace_result =
                        tokio::time::timeout_at(grace_deadline, udp_socket.recv_from(&mut buf))
                            .await;
                    match grace_result {
                        Err(_) => break, // Grace period expired
                        Ok(Err(_)) => break,
                        Ok(Ok((glen, gaddr))) => {
                            if gaddr == peer_addr && glen >= DATA_HEADER_SIZE {
                                buffered_packets.push(buf[..glen].to_vec());
                            }
                        }
                    }
                }
                return Ok(buffered_packets);
            }
        }
    }
}

/// Like [`wait_for_first_data`] but reads from an mpsc channel instead of a
/// raw UDP socket. Used in the multi-session listener where the dispatcher
/// routes demuxed packets to per-session channels.
///
/// The received packets are forwarded to the per-session `recv_socket` so the
/// bridge can read from it normally. Returns the forwarded packets for pre-fetch.
pub async fn wait_for_first_data_channeled(
    rx: &mut tokio::sync::mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
    recv_socket: &tokio::net::UdpSocket,
    recv_target: std::net::SocketAddr,
    pipeline: &Mutex<Pipeline>,
    session_id: SessionId,
    timeout_duration: Duration,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    use crate::pipeline::AdmissionResult;

    let deadline = tokio::time::Instant::now() + timeout_duration;
    let mut buffered_packets: Vec<Vec<u8>> = Vec::new();

    loop {
        let recv_result = tokio::time::timeout_at(deadline, rx.recv()).await;
        match recv_result {
            Err(_) => {
                return Err("timeout waiting for first data from client (channeled)".into());
            }
            Ok(None) => {
                return Err("channel closed while waiting for first data".into());
            }
            Ok(Some((data, _addr))) => {
                // Pipeline admission check
                {
                    let pl = pipeline.lock().await;
                    let result = pl.process(&data);
                    if !matches!(result, AdmissionResult::Pass) {
                        continue;
                    }
                }

                // Must be a data packet for our session
                if data.len() < DATA_HEADER_SIZE {
                    continue;
                }
                let header = match DataHeader::deserialize(&data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if header.session_id != session_id {
                    continue;
                }

                // Forward to the recv socket so the bridge can read it
                let _ = recv_socket.send_to(&data, recv_target).await;
                buffered_packets.push(data);

                // Collect any additional packets in a short grace window
                let grace_deadline = tokio::time::Instant::now() + Duration::from_millis(50);
                loop {
                    let grace_result = tokio::time::timeout_at(grace_deadline, rx.recv()).await;
                    match grace_result {
                        Err(_) => break,
                        Ok(None) => break,
                        Ok(Some((gdata, _gaddr))) => {
                            if gdata.len() >= DATA_HEADER_SIZE {
                                let _ = recv_socket.send_to(&gdata, recv_target).await;
                                buffered_packets.push(gdata);
                            }
                        }
                    }
                }
                return Ok(buffered_packets);
            }
        }
    }
}

// ─── Bridge ─────────────────────────────────────────────────────────────────

/// Run the bidirectional TCP ↔ ZTLP bridge with reliable ordered delivery.
///
/// Reads from the TCP stream, encrypts and sends as ZTLP data packets.
/// Receives ZTLP data packets, decrypts, reorders, and writes to TCP.
///
/// The reliability protocol ensures:
/// 1. Packets are delivered to TCP in sequence order (reassembly buffer)
/// 2. The sender knows what's been received (ACK frames)
/// 3. The sender doesn't overwhelm the receiver (flow control window)
/// 4. Both sides know when the stream ends (FIN frames)
///
/// Returns when either side closes or an unrecoverable error occurs.
/// Run a bidirectional TCP ↔ ZTLP bridge.
///
/// If `send_initial_reset` is true, the bridge sends a RESET frame before
/// any data to signal the remote side that a new TCP stream is starting.
/// This allows multiple sequential TCP connections to share a single ZTLP
/// session (e.g., `ztlp connect -L` accepting multiple connections on the
/// local listener).
pub async fn run_bridge(
    tcp_stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    run_bridge_inner(
        tcp_stream,
        udp_socket,
        None,
        pipeline,
        session_id,
        peer_addr,
        false,
        Vec::new(),
    )
    .await
}

/// Like [`run_bridge`] but sends a RESET frame first to signal a new TCP stream.
pub async fn run_bridge_with_reset(
    tcp_stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    run_bridge_inner(
        tcp_stream,
        udp_socket,
        None,
        pipeline,
        session_id,
        peer_addr,
        true,
        Vec::new(),
    )
    .await
}

/// Like [`run_bridge`] but accepts pre-fetched packets from a prior
/// `wait_for_reset_buffered` call. These packets arrived during the
/// inter-bridge gap and must be processed before reading new UDP data.
pub async fn run_bridge_with_buffered(
    tcp_stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    buffered_packets: Vec<Vec<u8>>,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    run_bridge_inner(
        tcp_stream,
        udp_socket,
        None,
        pipeline,
        session_id,
        peer_addr,
        false,
        buffered_packets,
    )
    .await
}

/// Like [`run_bridge_with_buffered`] but uses a dedicated receive socket for
/// demultiplexed packet delivery. Used by the multi-session listener where
/// a dispatcher routes packets to per-session sockets.
pub async fn run_bridge_demuxed(
    tcp_stream: TcpStream,
    udp_send_socket: Arc<UdpSocket>,
    udp_recv_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    buffered_packets: Vec<Vec<u8>>,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>> {
    run_bridge_inner(
        tcp_stream,
        udp_send_socket,
        Some(udp_recv_socket),
        pipeline,
        session_id,
        peer_addr,
        false,
        buffered_packets,
    )
    .await
}

/// Like [`run_bridge`] but accepts any `AsyncRead + AsyncWrite` stream
/// instead of requiring a `TcpStream`. Used by the agent daemon to bridge
/// TLS-terminated streams through ZTLP tunnels.
pub async fn run_bridge_io<S>(
    stream: S,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    run_bridge_inner(
        stream,
        udp_socket,
        None,
        pipeline,
        session_id,
        peer_addr,
        false,
        Vec::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_bridge_inner<S>(
    tcp_stream: S,
    udp_socket: Arc<UdpSocket>,
    udp_recv_override: Option<Arc<UdpSocket>>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    send_initial_reset: bool,
    prefetched_packets: Vec<Vec<u8>>,
) -> Result<BridgeOutcome, Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    info!(
        "run_bridge: starting for session {} peer={} local_udp={:?}",
        session_id,
        peer_addr,
        udp_socket.local_addr()
    );

    // ── Configure socket buffers and detect system capabilities ───────
    // Set SO_RCVBUF and SO_SNDBUF to 7MB (matching WireGuard-Go), then
    // detect the actual buffer sizes to adapt sub-batch sizing.
    // No HZ detection, no pacing — just big buffers + yield.
    let system_profile = {
        #[cfg(unix)]
        #[allow(unsafe_code)]
        let profile = {
            use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
            let fd = udp_socket.as_raw_fd();
            // SAFETY: fd is a valid open socket, and we immediately convert
            // back via into_raw_fd to prevent the std UdpSocket from closing it.
            let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            let p =
                crate::pacing::detect_system(peer_addr, Some(&std_sock), Duration::from_micros(10));
            let _ = std_sock.into_raw_fd();
            p
        };
        #[cfg(not(unix))]
        let profile = crate::pacing::detect_system(peer_addr, None, Duration::from_micros(10));
        profile
    };

    let pacing_strategy = system_profile.pacing;
    let adaptive_sub_batch = system_profile.max_sub_batch;

    // ── Send RESET frame if this is a subsequent TCP connection ──────
    // The RESET frame tells the remote side to reset its reassembly state
    // and open a new backend TCP connection. The first TCP connection on a
    // session doesn't need this (the remote side starts fresh).
    if send_initial_reset {
        info!(
            "sending RESET frame for new TCP stream on session {}",
            session_id
        );
        // Allocate a packet_seq and get the send key from the session.
        let (packet_seq, send_key) = {
            let mut pl = pipeline.lock().await;
            let session = pl
                .get_session_mut(&session_id)
                .ok_or("session not found for RESET")?;
            let seq = session.send_seq;
            session.send_seq += 1;
            (seq, session.send_key)
        };

        // Encrypt the RESET frame (single byte: 0x04)
        let cipher = ChaCha20Poly1305::new((&send_key).into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&packet_seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let reset_frame = vec![FRAME_RESET];
        let encrypted = cipher
            .encrypt(nonce, reset_frame.as_slice())
            .map_err(|e| format!("RESET encryption error: {:?}", e))?;

        // Build the data header
        let mut header = DataHeader::new(session_id, packet_seq);
        let aad = header.aad_bytes();
        header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);

        let mut packet = header.serialize();
        packet.extend_from_slice(&encrypted);
        udp_socket.send_to(&packet, peer_addr).await?;
    }

    let (mut tcp_reader, tcp_writer) = tokio::io::split(tcp_stream);

    let udp_send = udp_socket.clone();
    // For sending ACKs/NACKs back to the peer, always use the shared socket.
    let udp_ack_send = udp_socket.clone();
    let udp_recv = udp_recv_override.unwrap_or(udp_socket);
    let pipeline_send = pipeline.clone();
    let pipeline_recv = pipeline;
    let sid_send = session_id;
    let sid_recv = session_id;

    // ── Pre-extract cryptographic keys before the select! ──────────────
    // Both directions need to lock the pipeline to get their keys.
    // Extracting them here avoids lock contention between the two
    // async blocks inside tokio::select!, which would cause one direction
    // to starve (a pending mutex .await inside select! may never be
    // re-polled if the other branch continuously makes progress).
    let (send_key, recv_key, send_key_for_acks) = {
        let pl = pipeline_send.lock().await;
        let session = pl.get_session(&sid_send).ok_or("session not found")?;
        (session.send_key, session.recv_key, session.send_key)
    };
    debug!(
        "run_bridge: pre-extracted crypto keys for session {}",
        session_id
    );

    // Shared state for ACK-based flow control.
    // The receiver task updates `last_acked_seq` when it sends ACKs.
    // The sender task reads it to determine how many more packets it can send.
    let last_acked_seq: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let last_acked_seq_writer = last_acked_seq.clone();
    let last_acked_seq_reader = last_acked_seq;

    // Notify the sender when an ACK arrives, so it can wake up immediately
    // instead of polling every 100µs. This dramatically improves throughput
    // for transfers that exceed the initial congestion window.
    let ack_notify = Arc::new(tokio::sync::Notify::new());
    let ack_notify_writer = ack_notify.clone();
    let ack_notify_reader = ack_notify;

    // Congestion controller shared between sender and receiver.
    use crate::congestion::AdvancedCongestionController;
    let congestion: Arc<Mutex<AdvancedCongestionController>> =
        Arc::new(Mutex::new(AdvancedCongestionController::new()));
    let congestion_sender = congestion.clone();
    let congestion_receiver = congestion;

    // Debug statistics for performance analysis.
    // Enabled when ZTLP_DEBUG=1 or RUST_LOG=ztlp_proto::stats=debug.
    let tunnel_stats = Arc::new(TunnelStats::new());
    let stats_tx = tunnel_stats.clone();
    let stats_rx = tunnel_stats.clone();

    // Retransmit buffer: sender stores sent packets for retransmission on NACK.
    let retransmit_buf: Arc<Mutex<RetransmitBuffer>> =
        Arc::new(Mutex::new(RetransmitBuffer::new(RETRANSMIT_BUF_MAX)));
    let retransmit_buf_sender = retransmit_buf.clone();
    let retransmit_buf_ack = retransmit_buf;

    // Channel for NACK-triggered retransmit requests (receiver → sender).
    let (retransmit_tx, mut retransmit_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u64>>();

    // Signal from receiver to sender that a FIN was received from the remote.
    let (fin_tx, _fin_rx) = tokio::sync::oneshot::channel::<()>();

    // Flag set by the receiver when a RESET frame arrives. The caller
    // checks this after the bridge exits to decide whether to start a
    // new TCP stream or shut down entirely.
    let reset_received = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reset_received_rx = reset_received.clone();

    // ── RTT probe state (improvement #2: dedicated RTT probes) ─────────
    // The sender sends RTT_PING frames every RTT_PROBE_INTERVAL.
    // The receiver responds immediately with RTT_PONG. These probes are
    // never retransmitted — loss just means the next probe covers it.
    // Outstanding ping timestamps keyed by ping_id.
    let rtt_ping_outstanding: Arc<Mutex<std::collections::HashMap<u32, Instant>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let rtt_ping_outstanding_rx = rtt_ping_outstanding.clone();

    // PTO (Probe Timeout) counter — tracks consecutive PTOs without progress.
    // Improvement #3: PTO replaces RTO for congestion window management.
    let pto_count: Arc<std::sync::atomic::AtomicU32> =
        Arc::new(std::sync::atomic::AtomicU32::new(0));
    let pto_count_rx = pto_count.clone();

    // ── TCP → ZTLP direction (sender) ──────────────────────────────────

    let tcp_to_ztlp = async move {
        info!("tcp_to_ztlp: starting, peer_addr={}", peer_addr);
        let mut buf = vec![0u8; TCP_READ_BUF];

        // Send key is pre-extracted before select! to avoid lock contention.
        let send_key = send_key;

        let cipher = ChaCha20Poly1305::new((&send_key).into());
        let mut last_ack_check = Instant::now();

        // Create BatchSender once — reused for every TCP read flush.
        let batch_sender =
            crate::batch::BatchSender::new(udp_send.clone(), crate::gso::GsoMode::Auto);

        // Record the send strategy for debug stats.
        if stats_tx.enabled {
            let strategy = format!("{:?}", batch_sender.strategy());
            if let Ok(mut s) = stats_tx.send_strategy.lock() {
                *s = strategy;
            }
        }

        let mut tx_batch_num: u64 = 0;

        // Separate data_seq counter for DATA/FIN frames.
        // This is independent of the pipeline's send_seq (which provides
        // nonce uniqueness). The reassembly buffer on the receiver side
        // uses data_seq for ordering, not the packet header's packet_seq.
        let mut data_seq: u64 = 0;

        // ── Window stall tracking ─────────────────────────────────────
        // Monotonic deadline: once the sender enters window-stall (can't
        // send because window is full), it must make progress within
        // SENDER_WINDOW_STALL_LIMIT or the bridge aborts. This prevents
        // infinite retransmit loops where the RTO keeps resetting the
        // softer SENDER_ACK_TIMEOUT.
        let mut window_stall_start: Option<Instant> = None;
        // Count RTO cycles during a single window stall episode.
        let mut rto_cycles_in_stall: u32 = 0;
        // Track the last_acked_seq value when stall started, to detect
        // whether any new ACK arrived (real progress).
        let mut stall_start_acked: Option<u64> = None;

        // RTT probe state (sender side)
        let mut last_rtt_ping = Instant::now();
        let mut next_ping_id: u32 = 0;

        loop {
            // ── Send RTT probe if interval has elapsed ─────────────────
            if last_rtt_ping.elapsed() >= RTT_PROBE_INTERVAL {
                let ping_id = next_ping_id;
                next_ping_id = next_ping_id.wrapping_add(1);

                // Build PING frame: [FRAME_RTT_PING | ping_id: u32 BE | timestamp_us: u64 BE]
                let now_us = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64;
                let mut ping_frame = Vec::with_capacity(13);
                ping_frame.push(FRAME_RTT_PING);
                ping_frame.extend_from_slice(&ping_id.to_be_bytes());
                ping_frame.extend_from_slice(&now_us.to_be_bytes());

                // Encrypt and send
                let seq = {
                    let mut pl = pipeline_send.lock().await;
                    let session = pl
                        .get_session_mut(&sid_send)
                        .ok_or("session not found for RTT ping")?;
                    session.next_send_seq()
                };
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&seq.to_le_bytes());
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(encrypted) = cipher.encrypt(nonce, ping_frame.as_slice()) {
                    let mut header = DataHeader::new(sid_send, seq);
                    let aad = header.aad_bytes();
                    header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);
                    let mut packet = header.serialize();
                    packet.extend_from_slice(&encrypted);
                    let _ = udp_send.send_to(&packet, peer_addr).await;
                    // Record outstanding ping for RTT calculation
                    let mut outstanding = rtt_ping_outstanding.lock().await;
                    outstanding.insert(ping_id, Instant::now());
                    // Prune old pings (keep at most 32)
                    if outstanding.len() > 32 {
                        let oldest_id = ping_id.wrapping_sub(32);
                        outstanding.remove(&oldest_id);
                    }
                    debug!("sent RTT_PING id={} seq={}", ping_id, seq);
                }
                last_rtt_ping = Instant::now();
            }

            // ── Check for retransmit requests before reading new TCP data ──
            // Process any pending NACK-triggered retransmissions.
            while let Ok(nack_seqs) = retransmit_rx.try_recv() {
                // Signal loss to congestion controller (once per NACK batch)
                {
                    let mut cc = congestion_sender.lock().await;
                    cc.on_loss(Some(data_seq));
                }

                for nack_data_seq in &nack_seqs {
                    // Skip if SACK scoreboard says receiver already has it
                    {
                        let cc = congestion_sender.lock().await;
                        if cc.scoreboard.is_acked(*nack_data_seq) {
                            debug!(
                                "skipping retransmit for data_seq {} (SACK'd)",
                                nack_data_seq
                            );
                            continue;
                        }
                    }
                    // Record retransmit for spurious detection
                    {
                        let mut cc = congestion_sender.lock().await;
                        let srtt = cc.srtt_ms();
                        cc.spurious.record_retransmit(*nack_data_seq, srtt);
                    }
                    let entry_info = {
                        let mut rb = retransmit_buf_sender.lock().await;
                        // Karn's algorithm: mark as retransmitted so SRTT
                        // is not updated from the ambiguous ACK.
                        rb.mark_retransmitted(*nack_data_seq);
                        rb.get_with_packet_seq(*nack_data_seq)
                    };
                    if let Some((plaintext, orig_packet_seq)) = entry_info {
                        // Re-encrypt with the ORIGINAL packet_seq as nonce.
                        // ChaCha20-Poly1305 is deterministic: same key+nonce+plaintext
                        // produces identical ciphertext.
                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[4..12].copy_from_slice(&orig_packet_seq.to_le_bytes());
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        let encrypted = match cipher.encrypt(nonce, plaintext.as_slice()) {
                            Ok(enc) => enc,
                            Err(e) => {
                                warn!(
                                    "retransmit encryption error for data_seq {}: {}",
                                    nack_data_seq, e
                                );
                                continue;
                            }
                        };

                        let mut header = DataHeader::new(sid_send, orig_packet_seq);
                        let aad = header.aad_bytes();
                        header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);

                        let mut packet = header.serialize();
                        packet.extend_from_slice(&encrypted);
                        if let Err(e) = udp_send.send_to(&packet, peer_addr).await {
                            warn!(
                                "retransmit send error for data_seq {}: {}",
                                nack_data_seq, e
                            );
                        } else {
                            debug!(
                                "retransmitted data_seq {} (packet_seq {}, {} bytes)",
                                nack_data_seq,
                                orig_packet_seq,
                                packet.len()
                            );
                        }
                    } else {
                        debug!(
                            "retransmit requested for data_seq {} but not in buffer",
                            nack_data_seq
                        );
                    }
                }
            }

            // ── Select between TCP data and retransmit requests ───────
            // The sender must remain responsive to NACK retransmit requests
            // even while waiting for TCP data. Without this select!, a TCP
            // flow-control stall (SCP waiting for the receiver to drain)
            // deadlocks with a missing packet (receiver waiting for retransmit).
            let tcp_read_start = Instant::now();
            let n = 'tcp_read: loop {
                tokio::select! {
                    result = tcp_reader.read(&mut buf) => {
                        match result {
                            Ok(n) => break 'tcp_read n,
                            Err(e) => {
                                warn!("TCP read error: {}", e);
                                return Err(e.into());
                            }
                        }
                    }
                    Some(nack_seqs) = retransmit_rx.recv() => {
                        // Process retransmit while TCP read is stalled.
                        {
                            let mut cc = congestion_sender.lock().await;
                            cc.on_loss(Some(data_seq));
                        }
                        for nack_data_seq in &nack_seqs {
                            // Skip if SACK scoreboard says receiver already has it
                            {
                                let cc = congestion_sender.lock().await;
                                if cc.scoreboard.is_acked(*nack_data_seq) {
                                    debug!("skipping retransmit for data_seq {} (SACK'd)", nack_data_seq);
                                    continue;
                                }
                            }
                            // Record retransmit for spurious detection
                            {
                                let mut cc = congestion_sender.lock().await;
                                let srtt = cc.srtt_ms();
                                cc.spurious.record_retransmit(*nack_data_seq, srtt);
                            }
                            let entry_info = {
                                let mut rb = retransmit_buf_sender.lock().await;
                                // Karn's algorithm
                                rb.mark_retransmitted(*nack_data_seq);
                                rb.get_with_packet_seq(*nack_data_seq)
                            };
                            if let Some((plaintext, orig_packet_seq)) = entry_info {
                                let mut nonce_bytes = [0u8; 12];
                                nonce_bytes[4..12]
                                    .copy_from_slice(&orig_packet_seq.to_le_bytes());
                                let nonce = Nonce::from_slice(&nonce_bytes);
                                if let Ok(encrypted) =
                                    cipher.encrypt(nonce, plaintext.as_slice())
                                {
                                    let mut header =
                                        DataHeader::new(sid_send, orig_packet_seq);
                                    let aad = header.aad_bytes();
                                    header.header_auth_tag =
                                        compute_header_auth_tag(&send_key, &aad);
                                    let mut packet = header.serialize();
                                    packet.extend_from_slice(&encrypted);
                                    let _ =
                                        udp_send.send_to(&packet, peer_addr).await;
                                    debug!(
                                        "retransmitted data_seq {} (async NACK, packet_seq {})",
                                        nack_data_seq, orig_packet_seq
                                    );
                                }
                            }
                        }
                        // Loop back to wait for TCP data again
                        continue;
                    }
                }
            };
            if n == 0 {
                // TCP EOF — send FIN frame to signal stream end to remote.
                // FIN carries the current data_seq so the receiver knows
                // which data_seq marks the end of the stream.
                info!("TCP connection closed (read EOF), sending FIN");
                let fin_data_seq = data_seq;
                let mut fin_frame = Vec::with_capacity(9);
                fin_frame.push(FRAME_FIN);
                fin_frame.extend_from_slice(&fin_data_seq.to_be_bytes());
                let packet_seq = {
                    let mut pl = pipeline_send.lock().await;
                    let session = pl.get_session_mut(&sid_send).ok_or("session not found")?;
                    session.next_send_seq()
                };
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&packet_seq.to_le_bytes());
                let nonce = Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher
                    .encrypt(nonce, fin_frame.as_slice())
                    .map_err(|e| format!("FIN encryption error: {}", e))?;
                let mut header = DataHeader::new(sid_send, packet_seq);
                let aad = header.aad_bytes();
                header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);
                let mut packet = header.serialize();
                packet.extend_from_slice(&encrypted);
                udp_send.send_to(&packet, peer_addr).await?;
                debug!(
                    "sent FIN frame (data_seq {}, packet_seq {})",
                    fin_data_seq, packet_seq
                );
                return Ok::<_, Box<dyn std::error::Error>>(());
            }

            let tcp_read_time = tcp_read_start.elapsed();
            let data = &buf[..n];
            debug!("TCP → ZTLP: {} bytes", n);

            // Split the TCP data into chunks that fit in ZTLP packets
            // (accounting for 1-byte frame type + 8-byte data_seq prefix)
            let chunks: Vec<&[u8]> = data.chunks(MAX_PLAINTEXT_PER_PACKET).collect();
            let num_chunks = chunks.len();

            // ── Per-packet flow control + batch send ──
            // Send chunks in sub-batches that fit within the congestion window.
            // This prevents overwhelming the receiver's UDP buffer.
            let window_wait_start = Instant::now();
            let mut had_window_stall = false;
            let mut chunk_idx = 0;
            let mut total_udp_bytes = 0usize;

            while chunk_idx < num_chunks {
                // Determine how many packets fit in the current window
                let acked = {
                    let guard = last_acked_seq_reader.lock().await;
                    *guard
                };
                let remaining_chunks = num_chunks - chunk_idx;
                let (effective_window, paced) = {
                    let mut cc = congestion_sender.lock().await;
                    let ew = cc.effective_window();
                    let paced = cc.paced_send_count(remaining_chunks);
                    (ew, paced)
                };

                // How many packets can we send right now?
                let window_avail_raw = match acked {
                    Some(acked_data_seq) => {
                        if data_seq < acked_data_seq + effective_window + 1 {
                            (acked_data_seq + effective_window + 1 - data_seq) as usize
                        } else {
                            0
                        }
                    }
                    None => {
                        if data_seq < effective_window {
                            (effective_window - data_seq) as usize
                        } else {
                            0
                        }
                    }
                };

                // Apply pacing: limit actual send count to min(window, paced)
                let window_avail = window_avail_raw.min(paced);

                if window_avail_raw == 0 {
                    had_window_stall = true;

                    // ── Monotonic stall tracking ──────────────────────────
                    // Start tracking when we first enter window stall.
                    // Reset only when a NEW ACK arrives (real progress).
                    let current_acked = {
                        let guard = last_acked_seq_reader.lock().await;
                        *guard
                    };
                    if window_stall_start.is_none() {
                        window_stall_start = Some(Instant::now());
                        rto_cycles_in_stall = 0;
                        stall_start_acked = current_acked;
                        debug!(
                            "sender: entering window stall (data_seq={}, acked={:?})",
                            data_seq, current_acked
                        );
                    } else {
                        // Check if a new ACK arrived since stall started
                        let made_progress = match (stall_start_acked, current_acked) {
                            (Some(start), Some(now)) => now > start,
                            (None, Some(_)) => true,
                            _ => false,
                        };
                        if made_progress {
                            // New ACK arrived — reset stall tracking
                            window_stall_start = Some(Instant::now());
                            rto_cycles_in_stall = 0;
                            stall_start_acked = current_acked;
                            debug!(
                                "sender: window stall progress (acked={:?}), resetting stall timer",
                                current_acked
                            );
                        }
                    }

                    // ── Hard stall limit (monotonic, cannot be reset by RTO) ──
                    if let Some(stall_start) = window_stall_start {
                        if stall_start.elapsed() > SENDER_WINDOW_STALL_LIMIT {
                            warn!(
                                "sender window stall limit reached ({:?} with no new ACK, {} RTO cycles)",
                                SENDER_WINDOW_STALL_LIMIT, rto_cycles_in_stall
                            );
                            return Err("sender window stall limit — no progress".into());
                        }
                    }

                    // ── RTO cycle limit ───────────────────────────────────
                    // If we've fired too many RTOs without any new ACK, abort.
                    if rto_cycles_in_stall >= MAX_RTO_RETRANSMIT_CYCLES {
                        warn!(
                            "sender: {} RTO retransmit cycles with no ACK progress, aborting",
                            rto_cycles_in_stall
                        );
                        return Err("sender max RTO retransmit cycles exceeded".into());
                    }

                    if last_ack_check.elapsed() > SENDER_ACK_TIMEOUT {
                        warn!(
                            "sender ACK timeout ({:?} with no window progress)",
                            SENDER_ACK_TIMEOUT
                        );
                        return Err("sender ACK timeout".into());
                    }

                    // ── PTO (Probe Timeout) — replaces RTO (QUIC-style) ────
                    // Instead of collapsing cwnd on timeout (which causes death
                    // spirals), we send 1-2 probe packets and back off the PTO
                    // timer exponentially. Only collapse cwnd on *persistent*
                    // congestion (multiple consecutive PTOs with zero progress).
                    //
                    // This matches QUIC RFC 9002 §6.2 / §7.5-7.6.
                    {
                        let rto = {
                            let cc = congestion_sender.lock().await;
                            cc.rto_ms()
                        };
                        let current_pto = pto_count.load(std::sync::atomic::Ordering::Relaxed);
                        // Exponential backoff: PTO * 2^pto_count, capped at 4s.
                        // After persistent congestion (PTO >= 3), we retransmit
                        // bulk data, so long backoff would just delay recovery.
                        let backoff_factor = 1u64 << current_pto.min(4);
                        let pto_dur = std::time::Duration::from_millis(
                            (rto.max(MIN_RTO_MS) as u64 * backoff_factor).min(4_000),
                        );

                        if last_ack_check.elapsed() > pto_dur {
                            rto_cycles_in_stall += 1;
                            let new_pto =
                                pto_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;

                            // Persistent congestion: if 3+ consecutive PTOs with
                            // no progress, reduce cwnd to minimum (like QUIC §7.6).
                            if new_pto >= 3 {
                                let old_cwnd = {
                                    let mut cc = congestion_sender.lock().await;
                                    let old = cc.cwnd;
                                    cc.on_rto(); // collapse cwnd on persistent congestion
                                    old
                                };
                                let new_cwnd = {
                                    let cc = congestion_sender.lock().await;
                                    cc.cwnd
                                };
                                warn!(
                                    "persistent congestion: {} PTOs, cwnd {:.0} → {:.0}",
                                    new_pto, old_cwnd, new_cwnd
                                );
                            } else {
                                debug!(
                                    "PTO #{}: sending probe packets (no cwnd reduction)",
                                    new_pto
                                );
                            }

                            // Send probe packets (retransmit earliest unacked).
                            // Probes are exempt from cwnd — they exist to force an
                            // ACK from the receiver.
                            //
                            // On persistent congestion (3+ PTOs), retransmit ALL
                            // unacked data rather than 1-2 probes. When the receiver
                            // has 86 buffered-but-undeliverable packets, sending 1
                            // packet every PTO interval (with exp backoff) means
                            // recovery takes minutes. A bulk retransmit clears the
                            // gap immediately.
                            let probe_count = if new_pto >= 3 {
                                256
                            } else if new_pto == 1 {
                                2
                            } else {
                                1
                            };
                            let entries = {
                                let mut rb = retransmit_buf_sender.lock().await;
                                let entries = rb.oldest_entries(probe_count);
                                // Karn's algorithm: mark probed entries.
                                for (ds, _, _) in &entries {
                                    rb.mark_retransmitted(*ds);
                                }
                                entries
                            };
                            for (ds, ps, plaintext) in &entries {
                                let mut nonce_bytes = [0u8; 12];
                                nonce_bytes[4..12].copy_from_slice(&ps.to_le_bytes());
                                let nonce = Nonce::from_slice(&nonce_bytes);
                                if let Ok(encrypted) = cipher.encrypt(nonce, plaintext.as_slice()) {
                                    let mut header = DataHeader::new(sid_send, *ps);
                                    let aad = header.aad_bytes();
                                    header.header_auth_tag =
                                        compute_header_auth_tag(&send_key, &aad);
                                    let mut packet = header.serialize();
                                    packet.extend_from_slice(&encrypted);
                                    let _ = udp_send.send_to(&packet, peer_addr).await;
                                    debug!("PTO probe: data_seq {} (packet_seq {})", ds, ps);
                                }
                            }

                            // Reset ACK check timer (but NOT window_stall_start)
                            last_ack_check = Instant::now();
                        }
                    }

                    // Wait for an ACK notification (with short timeout fallback).
                    // The ACK receiver calls ack_notify_writer.notify_one() when
                    // it processes an ACK, waking us up immediately.
                    tokio::time::timeout(
                        std::time::Duration::from_millis(5),
                        ack_notify_reader.notified(),
                    )
                    .await
                    .ok();

                    // Process retransmit requests while waiting for window
                    while let Ok(nack_seqs) = retransmit_rx.try_recv() {
                        {
                            let mut cc = congestion_sender.lock().await;
                            cc.on_loss(Some(data_seq));
                        }
                        for nack_data_seq in &nack_seqs {
                            // Skip if SACK scoreboard says receiver already has it
                            {
                                let cc = congestion_sender.lock().await;
                                if cc.scoreboard.is_acked(*nack_data_seq) {
                                    debug!(
                                        "skipping retransmit for data_seq {} (SACK'd)",
                                        nack_data_seq
                                    );
                                    continue;
                                }
                            }
                            // Record retransmit for spurious detection
                            {
                                let mut cc = congestion_sender.lock().await;
                                let srtt = cc.srtt_ms();
                                cc.spurious.record_retransmit(*nack_data_seq, srtt);
                            }
                            let entry_info = {
                                let mut rb = retransmit_buf_sender.lock().await;
                                // Karn's algorithm
                                rb.mark_retransmitted(*nack_data_seq);
                                rb.get_with_packet_seq(*nack_data_seq)
                            };
                            if let Some((plaintext, orig_pkt_seq)) = entry_info {
                                let mut nonce_bytes = [0u8; 12];
                                nonce_bytes[4..12].copy_from_slice(&orig_pkt_seq.to_le_bytes());
                                let nonce = Nonce::from_slice(&nonce_bytes);
                                if let Ok(encrypted) = cipher.encrypt(nonce, plaintext.as_slice()) {
                                    let mut header = DataHeader::new(sid_send, orig_pkt_seq);
                                    let aad = header.aad_bytes();
                                    header.header_auth_tag =
                                        compute_header_auth_tag(&send_key, &aad);
                                    let mut packet = header.serialize();
                                    packet.extend_from_slice(&encrypted);
                                    let _ = udp_send.send_to(&packet, peer_addr).await;
                                    debug!(
                                        "retransmitted data_seq {} (while waiting for window)",
                                        nack_data_seq
                                    );
                                }
                            }
                        }
                    }
                    continue;
                }

                // Send up to window_avail packets from remaining chunks,
                // capped by MAX_SUB_BATCH to avoid overflowing the receiver's
                // UDP socket buffer on systems with small rmem_max.
                let send_count = window_avail
                    .min(num_chunks - chunk_idx)
                    .min(adaptive_sub_batch);

                // Allocate packet_seqs for this sub-batch
                let first_packet_seq = {
                    let mut pl = pipeline_send.lock().await;
                    let session = pl.get_session_mut(&sid_send).ok_or("session not found")?;
                    let first = session.send_seq;
                    session.send_seq += send_count as u64;
                    first
                };

                // Encrypt and build packets
                let now = Instant::now();
                let mut outgoing: Vec<(Vec<u8>, u64, u64)> = Vec::with_capacity(send_count);
                {
                    let mut rb = retransmit_buf_sender.lock().await;
                    for i in 0..send_count {
                        let chunk = &chunks[chunk_idx + i];
                        let current_data_seq = data_seq;
                        data_seq += 1;
                        let packet_seq = first_packet_seq + i as u64;

                        let mut framed = Vec::with_capacity(1 + 8 + chunk.len());
                        framed.push(FRAME_DATA);
                        framed.extend_from_slice(&current_data_seq.to_be_bytes());
                        framed.extend_from_slice(chunk);

                        rb.insert(current_data_seq, packet_seq, framed.clone(), now);

                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[4..12].copy_from_slice(&packet_seq.to_le_bytes());
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        let encrypted = cipher
                            .encrypt(nonce, framed.as_slice())
                            .map_err(|e| format!("encryption error: {}", e))?;

                        let mut header = DataHeader::new(sid_send, packet_seq);
                        let aad = header.aad_bytes();
                        header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);

                        let mut packet = header.serialize();
                        packet.extend_from_slice(&encrypted);
                        outgoing.push((packet, current_data_seq, packet_seq));
                    }
                }

                // Send the sub-batch
                {
                    let batch_packets: Vec<Vec<u8>> =
                        outgoing.iter().map(|(pkt, _, _)| pkt.clone()).collect();
                    batch_sender.send_batch(&batch_packets, peer_addr).await?;
                    for (packet, current_data_seq, packet_seq) in &outgoing {
                        debug!(
                            "ZTLP sent: {} bytes (data_seq {}, packet_seq {})",
                            packet.len(),
                            current_data_seq,
                            packet_seq
                        );
                    }
                }

                total_udp_bytes += outgoing.iter().map(|(p, _, _)| p.len()).sum::<usize>();
                chunk_idx += send_count;

                // Reset ACK timeout on progress
                last_ack_check = Instant::now();
                // Window opened — clear stall tracking
                window_stall_start = None;
                rto_cycles_in_stall = 0;
                // Reset PTO counter on real progress
                pto_count.store(0, std::sync::atomic::Ordering::Relaxed);

                // Yield between sub-batches to let the tokio runtime
                // service the receiver task. With 7MB socket buffers,
                // there's no need for sleep or spin-yield pacing —
                // the buffer absorbs the burst.
                if chunk_idx < num_chunks && send_count > 0 {
                    crate::pacing::pace(&pacing_strategy);
                }
            }

            let window_wait_time = window_wait_start.elapsed();
            let encrypt_time = window_wait_time; // approximation (mixed with send)
            let send_time = window_wait_time; // approximation
            let udp_bytes = total_udp_bytes;

            // Emit per-batch debug stats
            tx_batch_num += 1;
            let (cwnd_snap, ew_snap) = {
                let cc = congestion_sender.lock().await;
                (cc.cwnd, cc.effective_window())
            };
            let tx_stats = TxBatchStats {
                batch_num: tx_batch_num,
                packet_count: num_chunks,
                tcp_bytes: n,
                udp_bytes,
                tcp_read_time,
                encrypt_time,
                send_time,
                window_wait_time,
                send_strategy: stats_tx
                    .send_strategy
                    .lock()
                    .map(|s| s.clone())
                    .unwrap_or_default(),
                data_seq,
                cwnd: cwnd_snap,
                effective_window: ew_snap,
                window_stall: had_window_stall,
            };
            tx_stats.log();
            stats_tx.record_tx(&tx_stats);

            // Reset the ACK timeout tracker (batch sent successfully)
            last_ack_check = Instant::now();
            // Full batch sent — clear any stall tracking
            window_stall_start = None;
            rto_cycles_in_stall = 0;
            pto_count.store(0, std::sync::atomic::Ordering::Relaxed);
        }
    };

    // ── ZTLP → TCP direction (receiver) ────────────────────────────────

    let reset_flag_for_rx = reset_received_rx;
    let prefetched = prefetched_packets; // move into the async block
    let udp_ack_sender = udp_ack_send; // for sending ACKs/NACKs to peer
    let ztlp_to_tcp = async move {
        let reset_received = reset_flag_for_rx;
        info!(
            "ztlp_to_tcp: starting (prefetched_packets={})",
            prefetched.len()
        );
        // Recv key and ACK key are pre-extracted before select! to avoid lock contention.
        let recv_cipher = ChaCha20Poly1305::new((&recv_key).into());
        let ack_cipher = ChaCha20Poly1305::new((&send_key_for_acks).into());

        // Use BufWriter for TCP to batch small writes and reduce syscalls
        let mut tcp_writer = tokio::io::BufWriter::with_capacity(65536, tcp_writer);

        // GRO-aware receiver: transparently uses GRO when available.
        // A single recv() may yield multiple coalesced datagrams.
        let mut gro_receiver =
            crate::gso::GroReceiver::new(udp_recv.clone(), crate::gso::GsoMode::Auto);

        // Reassembly buffer: reorders packets for in-order TCP delivery.
        // Initial expected_seq = 0 (first data packet the sender will send).
        // Note: the sender may have consumed some sequence numbers during the
        // handshake, but the tunnel protocol's data seq tracking starts at
        // whatever the ZTLP session's current send_seq is. The receiver
        // auto-detects the first data seq from the first packet it receives.
        let mut reassembly: Option<ReassemblyBuffer> = None;

        // ── Process pre-fetched packets from the inter-bridge gap ─────
        // These were captured by wait_for_reset_buffered and must be
        // processed before we start reading new UDP packets to avoid
        // data loss during bridge transitions.
        if !prefetched.is_empty() {
            info!(
                "processing {} pre-fetched packets from bridge transition",
                prefetched.len()
            );
            for pkt_data in &prefetched {
                if pkt_data.len() < DATA_HEADER_SIZE {
                    continue;
                }
                let header = match DataHeader::deserialize(pkt_data) {
                    Ok(h) => h,
                    Err(_) => continue,
                };
                if header.session_id != sid_recv {
                    continue;
                }

                // Decrypt
                let encrypted_payload = &pkt_data[DATA_HEADER_SIZE..];
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_le_bytes());
                let nonce = Nonce::from_slice(&nonce_bytes);
                let plaintext = match recv_cipher.decrypt(nonce, encrypted_payload) {
                    Ok(pt) => pt,
                    Err(_) => continue,
                };
                if plaintext.is_empty() {
                    continue;
                }

                let frame_type = plaintext[0];
                let frame_payload = &plaintext[1..];

                match frame_type {
                    FRAME_DATA => {
                        if frame_payload.len() < 8 {
                            continue;
                        }
                        let data_seq = u64::from_be_bytes(match frame_payload[..8].try_into() {
                            Ok(b) => b,
                            Err(_) => continue,
                        });
                        let tcp_payload = &frame_payload[8..];

                        let reasm = reassembly.get_or_insert_with(|| {
                            debug!(
                                "reassembly: initialized at seq 0 from prefetch (first data_seq={})",
                                data_seq
                            );
                            ReassemblyBuffer::new(0, REASSEMBLY_MAX_BUFFERED)
                        });

                        if let Some(deliverable) = reasm.insert(data_seq, tcp_payload.to_vec()) {
                            for (_seq, payload) in &deliverable {
                                if let Err(e) = tcp_writer.write_all(payload).await {
                                    warn!("TCP write error on prefetched data: {}", e);
                                    return Err(format!("prefetched TCP write: {}", e).into());
                                }
                            }
                        }
                    }
                    FRAME_ACK => {
                        if frame_payload.len() >= 8 {
                            let acked_seq = u64::from_be_bytes(
                                frame_payload[..8].try_into().unwrap_or([0u8; 8]),
                            );
                            let mut la = last_acked_seq_writer.lock().await;
                            *la = Some(acked_seq);
                            ack_notify_writer.notify_one();
                        }
                    }
                    FRAME_RESET => {
                        info!("received RESET in prefetched packets — unexpected, ignoring");
                    }
                    FRAME_REJECT => {
                        // REJECT in prefetched — server denied access
                        use crate::reject::RejectFrame;
                        if let Some(reject) = RejectFrame::decode(&plaintext) {
                            warn!(
                                "received REJECT frame in prefetched packets: {} — {}",
                                reject.reason, reject.message
                            );
                            return Err(format!(
                                "server rejected connection: {} ({})",
                                reject.message, reject.reason
                            )
                            .into());
                        }
                    }
                    _ => {}
                }
            }
            // Flush any data we wrote to TCP from prefetched packets
            if let Err(e) = tcp_writer.flush().await {
                warn!("TCP flush error after prefetched processing: {}", e);
                return Err(format!("prefetched TCP flush: {}", e).into());
            }
            info!("prefetched packet processing complete");
        }

        // ACK tracking: send ACKs periodically
        let mut packets_since_ack: u64 = 0;
        let mut last_ack_time = Instant::now();
        let mut last_acked_value: Option<u64> = None;

        // FIN tracking: fin_data_seq records the data_seq carried in the FIN
        // frame, which is one past the last data packet's seq. We must wait
        // for all data_seqs < fin_data_seq to be delivered before closing.
        let mut fin_tx = Some(fin_tx);
        let mut fin_received = false;
        let mut fin_data_seq: Option<u64> = None;

        // Debug stats for receiver
        let mut rx_batch_num: u64 = 0;

        // Record GRO availability
        stats_rx.gro_available.store(
            gro_receiver.is_gro_enabled(),
            std::sync::atomic::Ordering::Relaxed,
        );

        loop {
            // Use a timeout on UDP recv so we can periodically send ACKs
            // and check for stalls even when no packets are arriving.
            // With GRO, a single recv may return multiple coalesced datagrams.
            let recv_start = Instant::now();
            let recv_result = tokio::time::timeout(ACK_INTERVAL, gro_receiver.recv()).await;

            match recv_result {
                Ok(Ok(batch)) => {
                    let recv_time = recv_start.elapsed();
                    // Process each segment in the GRO batch. When GRO coalesces
                    // packets, we get multiple segments from one recv call.
                    let num_segments = batch.segments().len();
                    let total_udp_bytes: usize = batch.segments().iter().map(|s| s.len).sum();
                    let mut batch_packets_ok: usize = 0;
                    let mut batch_packets_drop: usize = 0;
                    let mut batch_tcp_bytes: usize = 0;
                    let mut batch_delivered: usize = 0;
                    let mut batch_buffered: usize = 0;
                    let mut batch_pipeline_time = Duration::ZERO;
                    let mut batch_decrypt_time = Duration::ZERO;
                    let mut batch_reassembly_time = Duration::ZERO;
                    let mut batch_tcp_write_time = Duration::ZERO;

                    for segment in batch.segments() {
                        let data = &batch.buffer()[segment.offset..segment.offset + segment.len];
                        let n = segment.len;

                        // Run through pipeline admission (magic, session, header auth)
                        let pipeline_start = Instant::now();
                        {
                            let pl = pipeline_recv.lock().await;
                            let result = pl.process(data);
                            if !matches!(result, AdmissionResult::Pass) {
                                batch_pipeline_time += pipeline_start.elapsed();
                                batch_packets_drop += 1;
                                debug!("packet dropped by pipeline");
                                continue;
                            }
                        }
                        batch_pipeline_time += pipeline_start.elapsed();

                        // Parse data header
                        if n < DATA_HEADER_SIZE {
                            batch_packets_drop += 1;
                            debug!("packet too short for data header");
                            continue;
                        }
                        let header = match DataHeader::deserialize(data) {
                            Ok(h) => h,
                            Err(_) => {
                                batch_packets_drop += 1;
                                debug!("failed to parse data header");
                                continue;
                            }
                        };

                        // Verify session ID matches
                        if header.session_id != sid_recv {
                            batch_packets_drop += 1;
                            debug!("wrong session ID, ignoring");
                            continue;
                        }

                        // Decrypt the payload
                        let decrypt_start = Instant::now();
                        let encrypted_payload = &data[DATA_HEADER_SIZE..];
                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_le_bytes());
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        let plaintext = match recv_cipher.decrypt(nonce, encrypted_payload) {
                            Ok(pt) => {
                                batch_decrypt_time += decrypt_start.elapsed();
                                pt
                            }
                            Err(e) => {
                                batch_decrypt_time += decrypt_start.elapsed();
                                batch_packets_drop += 1;
                                warn!("decryption failed (seq {}): {}", header.packet_seq, e);
                                continue;
                            }
                        };
                        batch_packets_ok += 1;

                        // Parse the frame type (first byte of plaintext)
                        if plaintext.is_empty() {
                            debug!("empty plaintext, ignoring");
                            continue;
                        }

                        let frame_type = plaintext[0];
                        let frame_payload = &plaintext[1..];

                        match frame_type {
                            FRAME_DATA => {
                                // DATA frame: [0x00] [data_seq: 8B BE] [payload...]
                                if frame_payload.len() < 8 {
                                    debug!("DATA frame too short for data_seq");
                                    continue;
                                }
                                // SAFETY: frame_payload.len() >= 8 verified above
                                let data_seq =
                                    u64::from_be_bytes(match frame_payload[..8].try_into() {
                                        Ok(b) => b,
                                        Err(_) => continue,
                                    });
                                let tcp_payload = &frame_payload[8..];

                                // Initialize reassembly buffer on first data packet.
                                // Always start at seq 0 — the gateway's data_seq starts at 0.
                                // If we initialize from the first received data_seq and seq 0
                                // was lost, we'd never detect the gap or request retransmission.
                                let reassembly_start = Instant::now();
                                let reasm = reassembly.get_or_insert_with(|| {
                                    debug!(
                                        "reassembly: initialized at seq 0 (first received data_seq={})",
                                        data_seq
                                    );
                                    ReassemblyBuffer::new(0, REASSEMBLY_MAX_BUFFERED)
                                });

                                // Insert into reassembly buffer keyed by data_seq
                                if let Some(deliverable) =
                                    reasm.insert(data_seq, tcp_payload.to_vec())
                                {
                                    batch_reassembly_time += reassembly_start.elapsed();
                                    // Write all deliverable packets to TCP in order
                                    let tcp_write_start = Instant::now();
                                    for (_seq, payload) in &deliverable {
                                        batch_tcp_bytes += payload.len();
                                        if let Err(e) = tcp_writer.write_all(payload).await {
                                            warn!("TCP write error: {}", e);
                                            return Err::<(), Box<dyn std::error::Error>>(e.into());
                                        }
                                    }

                                    if !deliverable.is_empty() {
                                        // Flush when we've delivered data
                                        if let Err(e) = tcp_writer.flush().await {
                                            warn!("TCP flush error: {}", e);
                                            return Err(e.into());
                                        }
                                        batch_tcp_write_time += tcp_write_start.elapsed();
                                        batch_delivered += deliverable.len();
                                        packets_since_ack += deliverable.len() as u64;
                                    }
                                } else {
                                    batch_reassembly_time += reassembly_start.elapsed();
                                    batch_buffered += 1;
                                }
                            }

                            FRAME_ACK => {
                                // ACK frame from the remote sender's receiver side.
                                // Contains the highest contiguous seq delivered to TCP.
                                if frame_payload.len() >= 8 {
                                    // SAFETY: frame_payload.len() >= 8 verified by condition
                                    let acked_seq = match frame_payload[..8].try_into() {
                                        Ok(b) => u64::from_be_bytes(b),
                                        Err(_) => continue,
                                    };
                                    debug!("received ACK for data_seq {}", acked_seq);
                                    stats_rx
                                        .acks_received
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                                    // Compute newly acked count for congestion control
                                    let prev_acked = {
                                        let guard = last_acked_seq_writer.lock().await;
                                        *guard
                                    };
                                    let newly_acked = match prev_acked {
                                        Some(prev) if acked_seq > prev => acked_seq - prev,
                                        None => acked_seq + 1,
                                        _ => 0,
                                    };

                                    // Update the shared acked seq
                                    {
                                        let mut guard = last_acked_seq_writer.lock().await;
                                        match *guard {
                                            Some(prev) if acked_seq > prev => {
                                                *guard = Some(acked_seq)
                                            }
                                            None => *guard = Some(acked_seq),
                                            _ => {}
                                        }
                                    }

                                    // Wake the sender if it's waiting for window space
                                    ack_notify_writer.notify_one();

                                    // RTT measurement: find the send time of the acked seq
                                    // in the retransmit buffer and compute the sample
                                    {
                                        let rb = retransmit_buf_ack.lock().await;
                                        if let Some(send_time) = rb.send_time(acked_seq) {
                                            let rtt_sample =
                                                send_time.elapsed().as_secs_f64() * 1000.0;
                                            let mut cc = congestion_receiver.lock().await;
                                            cc.update_rtt(rtt_sample);
                                            if newly_acked > 0 {
                                                cc.on_ack(newly_acked);
                                            }
                                            // Spurious retransmission detection
                                            if cc.spurious.check_ack(acked_seq) {
                                                cc.on_spurious_detected();
                                            }
                                        } else if newly_acked > 0 {
                                            // No RTT sample available, just notify congestion controller
                                            let mut cc = congestion_receiver.lock().await;
                                            cc.on_ack(newly_acked);
                                        }
                                    }

                                    // Prune retransmit buffer up to acked_seq
                                    {
                                        let mut rb = retransmit_buf_ack.lock().await;
                                        rb.prune_up_to(acked_seq);
                                    }
                                }
                            }

                            FRAME_NACK => {
                                // NACK frame from the remote receiver: they're missing packets.
                                // Decode and forward to the sender for retransmission.
                                if let Some(missing_seqs) = decode_nack_payload(frame_payload) {
                                    stats_rx
                                        .nacks_received
                                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    debug!(
                                        "received NACK for {} missing seqs: {:?}",
                                        missing_seqs.len(),
                                        &missing_seqs[..missing_seqs.len().min(5)]
                                    );
                                    // Use advanced CC NACK handling with fast retransmit detection
                                    {
                                        let mut cc = congestion_receiver.lock().await;
                                        let should_fast_retransmit =
                                            cc.on_nack_received(&missing_seqs);
                                        if should_fast_retransmit {
                                            cc.on_loss(None);
                                        }
                                    }
                                    if let Err(e) = retransmit_tx.send(missing_seqs) {
                                        warn!("failed to forward NACK to sender: {}", e);
                                    }
                                } else {
                                    debug!("malformed NACK frame, ignoring");
                                }
                            }

                            FRAME_CORRUPTION_NACK => {
                                // CORRUPTION_NACK: receiver detected AEAD failure (bit-flip,
                                // not congestion). Same wire format as NACK. Retransmit
                                // without reducing cwnd.
                                if let Some(missing_seqs) = decode_nack_payload(frame_payload) {
                                    debug!(
                                        "received CORRUPTION_NACK for {} seqs: {:?}",
                                        missing_seqs.len(),
                                        &missing_seqs[..missing_seqs.len().min(5)]
                                    );
                                    // No CC penalty for corruption — just retransmit
                                    if let Err(e) = retransmit_tx.send(missing_seqs) {
                                        warn!("failed to forward CORRUPTION_NACK to sender: {}", e);
                                    }
                                } else {
                                    debug!("malformed CORRUPTION_NACK frame, ignoring");
                                }
                            }

                            FRAME_SACK => {
                                // SACK frame from the remote receiver: contains cumulative ACK
                                // plus non-contiguous received ranges.
                                if let Some((sack_cum_ack, sack_ranges)) =
                                    crate::congestion::decode_sack_payload(frame_payload)
                                {
                                    debug!(
                                        "received SACK: cumulative_ack={}, {} ranges",
                                        sack_cum_ack,
                                        sack_ranges.len()
                                    );

                                    // Treat cumulative_ack like a regular ACK
                                    let prev_acked = {
                                        let guard = last_acked_seq_writer.lock().await;
                                        *guard
                                    };
                                    let newly_acked = match prev_acked {
                                        Some(prev) if sack_cum_ack > prev => sack_cum_ack - prev,
                                        None => sack_cum_ack + 1,
                                        _ => 0,
                                    };

                                    // Update shared acked seq
                                    {
                                        let mut guard = last_acked_seq_writer.lock().await;
                                        match *guard {
                                            Some(prev) if sack_cum_ack > prev => {
                                                *guard = Some(sack_cum_ack)
                                            }
                                            None => *guard = Some(sack_cum_ack),
                                            _ => {}
                                        }
                                    }

                                    // Wake the sender
                                    ack_notify_writer.notify_one();

                                    // RTT measurement + congestion control
                                    {
                                        let rb = retransmit_buf_ack.lock().await;
                                        if let Some(send_time) = rb.send_time(sack_cum_ack) {
                                            let rtt_sample =
                                                send_time.elapsed().as_secs_f64() * 1000.0;
                                            let mut cc = congestion_receiver.lock().await;
                                            cc.update_rtt(rtt_sample);
                                            // Update SACK scoreboard
                                            cc.scoreboard
                                                .update_from_sack(sack_cum_ack, &sack_ranges);
                                            if newly_acked > 0 {
                                                cc.on_ack(newly_acked);
                                            }
                                            // Spurious retransmission detection
                                            if cc.spurious.check_ack(sack_cum_ack) {
                                                cc.on_spurious_detected();
                                            }
                                        } else if newly_acked > 0 {
                                            let mut cc = congestion_receiver.lock().await;
                                            // Update SACK scoreboard
                                            cc.scoreboard
                                                .update_from_sack(sack_cum_ack, &sack_ranges);
                                            cc.on_ack(newly_acked);
                                        } else {
                                            let mut cc = congestion_receiver.lock().await;
                                            // Update SACK scoreboard even for dup ACKs
                                            cc.scoreboard
                                                .update_from_sack(sack_cum_ack, &sack_ranges);
                                        }
                                    }

                                    // Prune retransmit buffer up to cumulative_ack
                                    {
                                        let mut rb = retransmit_buf_ack.lock().await;
                                        rb.prune_up_to(sack_cum_ack);
                                    }

                                    // SACK ranges tell us which out-of-order seqs the
                                    // receiver has, enabling selective retransmission of
                                    // only the gaps. Forward to sender via retransmit_tx
                                    // with the computed missing sequences.
                                    if !sack_ranges.is_empty() {
                                        // Compute missing seqs from SACK ranges
                                        let mut missing_seqs = Vec::new();
                                        let mut seq = sack_cum_ack + 1;
                                        for range in &sack_ranges {
                                            while seq < range.start
                                                && missing_seqs.len() < MAX_NACK_SEQS
                                            {
                                                missing_seqs.push(seq);
                                                seq += 1;
                                            }
                                            seq = seq.max(range.end + 1);
                                        }
                                        if !missing_seqs.is_empty() {
                                            debug!(
                                                "SACK gap: {} missing seqs: {:?}",
                                                missing_seqs.len(),
                                                &missing_seqs[..missing_seqs.len().min(5)]
                                            );
                                            if let Err(e) = retransmit_tx.send(missing_seqs) {
                                                warn!(
                                                    "failed to forward SACK gaps to sender: {}",
                                                    e
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    debug!("malformed SACK frame, ignoring");
                                }
                            }

                            FRAME_FIN => {
                                // FIN frame: [0x02] [data_seq: 8B BE]
                                // Remote side signaled TCP EOF. The data_seq in
                                // the FIN is one past the last DATA frame's seq.
                                // We must deliver all data_seqs < fin_data_seq
                                // before shutting down TCP.
                                let parsed_fin_seq = if frame_payload.len() >= 8 {
                                    match frame_payload[..8].try_into() {
                                        Ok(b) => {
                                            let fds = u64::from_be_bytes(b);
                                            info!(
                                                "received FIN frame (data_seq {}) — remote TCP stream ended",
                                                fds
                                            );
                                            Some(fds)
                                        }
                                        Err(_) => {
                                            info!("received FIN frame — remote TCP stream ended (malformed seq)");
                                            None
                                        }
                                    }
                                } else {
                                    info!("received FIN frame — remote TCP stream ended");
                                    None
                                };
                                fin_received = true;
                                fin_data_seq = parsed_fin_seq;

                                // Don't return here — continue the recv loop so
                                // remaining in-flight DATA packets are received
                                // and delivered. The FIN drain check below will
                                // close the connection once all data is delivered.
                            }

                            FRAME_RESET => {
                                // RESET frame: the remote side is starting a new
                                // TCP stream on the same ZTLP session. Shut down
                                // the current TCP write half and signal the caller
                                // to open a new backend connection.
                                info!("received RESET frame — remote starting new TCP stream");
                                reset_received.store(true, std::sync::atomic::Ordering::Release);
                                if let Err(e) = tcp_writer.shutdown().await {
                                    debug!("TCP shutdown on RESET: {}", e);
                                }
                                return Ok(());
                            }

                            FRAME_REJECT => {
                                // REJECT frame: server denied access after handshake.
                                // Parse the reason and message, then return an error.
                                use crate::reject::RejectFrame;
                                if let Some(reject) = RejectFrame::decode(&plaintext) {
                                    warn!(
                                        "received REJECT frame: {} — {}",
                                        reject.reason, reject.message
                                    );
                                    if let Err(e) = tcp_writer.shutdown().await {
                                        debug!("TCP shutdown on REJECT: {}", e);
                                    }
                                    return Err(format!(
                                        "server rejected connection: {} ({})",
                                        reject.message, reject.reason
                                    )
                                    .into());
                                }
                                warn!("received malformed REJECT frame");
                            }

                            FRAME_RTT_PING => {
                                // Received a RTT probe from the sender — respond
                                // immediately with RTT_PONG echoing the timestamp.
                                // frame_payload = [ping_id: u32 BE | timestamp_us: u64 BE]
                                if frame_payload.len() >= 12 {
                                    let ping_id = u32::from_be_bytes([
                                        frame_payload[0],
                                        frame_payload[1],
                                        frame_payload[2],
                                        frame_payload[3],
                                    ]);
                                    let echo_ts = &frame_payload[4..12];

                                    // Measure receiver processing delay (time since
                                    // we received this UDP batch until now).
                                    let receiver_delay_us =
                                        recv_start.elapsed().as_micros().min(u32::MAX as u128)
                                            as u32;

                                    // Build PONG: [FRAME_RTT_PONG | ping_id | echo_ts | delay_us]
                                    let mut pong_frame = Vec::with_capacity(17);
                                    pong_frame.push(FRAME_RTT_PONG);
                                    pong_frame.extend_from_slice(&ping_id.to_be_bytes());
                                    pong_frame.extend_from_slice(echo_ts);
                                    pong_frame.extend_from_slice(&receiver_delay_us.to_be_bytes());

                                    // Encrypt and send back
                                    let pong_seq = {
                                        let mut pl = pipeline_recv.lock().await;
                                        let session = pl
                                            .get_session_mut(&sid_recv)
                                            .ok_or("session not found for RTT pong")?;
                                        session.next_send_seq()
                                    };
                                    let mut nonce_bytes = [0u8; 12];
                                    nonce_bytes[4..12].copy_from_slice(&pong_seq.to_le_bytes());
                                    let nonce = Nonce::from_slice(&nonce_bytes);
                                    if let Ok(encrypted) =
                                        ack_cipher.encrypt(nonce, pong_frame.as_slice())
                                    {
                                        let mut header = DataHeader::new(sid_recv, pong_seq);
                                        let aad = header.aad_bytes();
                                        header.header_auth_tag =
                                            compute_header_auth_tag(&send_key_for_acks, &aad);
                                        let mut packet = header.serialize();
                                        packet.extend_from_slice(&encrypted);
                                        let _ = udp_recv.send_to(&packet, peer_addr).await;
                                        debug!(
                                            "sent RTT_PONG id={} delay={}us",
                                            ping_id, receiver_delay_us
                                        );
                                    }
                                }
                            }

                            FRAME_RTT_PONG => {
                                // Received a PONG from the receiver — extract clean
                                // RTT sample and update congestion controller.
                                // frame_payload = [ping_id: u32 BE | echo_ts: u64 BE | delay_us: u32 BE]
                                if frame_payload.len() >= 16 {
                                    let ping_id = u32::from_be_bytes([
                                        frame_payload[0],
                                        frame_payload[1],
                                        frame_payload[2],
                                        frame_payload[3],
                                    ]);
                                    let receiver_delay_us = u32::from_be_bytes([
                                        frame_payload[12],
                                        frame_payload[13],
                                        frame_payload[14],
                                        frame_payload[15],
                                    ]);

                                    // Look up when we sent this ping
                                    let send_time = {
                                        let mut outstanding = rtt_ping_outstanding_rx.lock().await;
                                        outstanding.remove(&ping_id)
                                    };

                                    if let Some(send_time) = send_time {
                                        let total_rtt_ms =
                                            send_time.elapsed().as_secs_f64() * 1000.0;
                                        let delay_ms = receiver_delay_us as f64 / 1000.0;
                                        // Subtract receiver processing delay for
                                        // network-only RTT
                                        let net_rtt_ms = (total_rtt_ms - delay_ms).max(0.01);

                                        let mut cc = congestion_receiver.lock().await;
                                        cc.update_rtt(net_rtt_ms);
                                        // Reset PTO count on successful probe
                                        pto_count_rx.store(0, std::sync::atomic::Ordering::Relaxed);
                                        debug!(
                                            "RTT_PONG id={}: total={:.2}ms net={:.2}ms (delay={:.2}ms)",
                                            ping_id, total_rtt_ms, net_rtt_ms, delay_ms
                                        );
                                    } else {
                                        debug!(
                                            "RTT_PONG id={}: no outstanding ping (late/dup)",
                                            ping_id
                                        );
                                    }
                                }
                            }

                            _ => {
                                debug!("unknown frame type 0x{:02x}, ignoring", frame_type);
                            }
                        }
                    } // end for segment in batch.segments()

                    // Emit per-batch debug stats
                    rx_batch_num += 1;
                    let reasm_depth = reassembly.as_ref().map(|r| r.buffered_count()).unwrap_or(0);
                    let rx_stats = RxBatchStats {
                        batch_num: rx_batch_num,
                        gro_segments: num_segments,
                        packets_processed: batch_packets_ok,
                        packets_dropped: batch_packets_drop,
                        udp_bytes: total_udp_bytes,
                        tcp_bytes: batch_tcp_bytes,
                        recv_time,
                        pipeline_time: batch_pipeline_time,
                        decrypt_time: batch_decrypt_time,
                        reassembly_time: batch_reassembly_time,
                        tcp_write_time: batch_tcp_write_time,
                        delivered_count: batch_delivered,
                        buffered_count: batch_buffered,
                        reasm_buffer_depth: reasm_depth,
                    };
                    rx_stats.log();
                    stats_rx.record_rx(&rx_stats);

                    // Periodic summary (every 1 second)
                    {
                        let (cwnd, ssthresh, srtt, rto) = {
                            let cc = congestion_receiver.lock().await;
                            (cc.cwnd, cc.ssthresh, cc.srtt_ms(), cc.rto_ms())
                        };
                        stats_rx.maybe_report(cwnd, ssthresh, srtt, rto);
                    }

                    // ── Periodic ACK/SACK sending (once per recv call, after all segments) ──
                    // Send an ACK when we've delivered enough packets or enough
                    // time has passed. This lets the sender's flow control advance.
                    // When there are buffered out-of-order packets, send SACK
                    // instead of plain ACK to give the sender selective info.
                    if packets_since_ack >= ACK_EVERY_PACKETS
                        || last_ack_time.elapsed() >= ACK_INTERVAL
                    {
                        if let Some(ref reasm) = reassembly {
                            if let Some(delivered_seq) = reasm.last_delivered_seq() {
                                // Only send if we have new progress to report
                                if last_acked_value.is_none_or(|prev| delivered_seq > prev) {
                                    let buffered = reasm.buffered_seqs();
                                    if buffered.is_empty() {
                                        // No gaps — plain ACK is sufficient
                                        send_ack(
                                            &pipeline_recv,
                                            &ack_cipher,
                                            &send_key_for_acks,
                                            sid_recv,
                                            &udp_ack_sender,
                                            peer_addr,
                                            delivered_seq,
                                        )
                                        .await?;
                                    } else {
                                        // Has gaps — send SACK with received ranges
                                        let mut sack_state =
                                            crate::congestion::ReceiverSackState::new();
                                        sack_state.update_from_reassembly(
                                            reasm.expected_seq(),
                                            &buffered,
                                        );
                                        send_sack(
                                            &pipeline_recv,
                                            &ack_cipher,
                                            &send_key_for_acks,
                                            sid_recv,
                                            &udp_ack_sender,
                                            peer_addr,
                                            delivered_seq,
                                            sack_state.ranges(),
                                        )
                                        .await?;
                                    }
                                    last_acked_value = Some(delivered_seq);
                                    packets_since_ack = 0;
                                    last_ack_time = Instant::now();
                                }
                            }
                        }
                    }
                }

                Ok(Err(e)) => {
                    warn!("UDP recv error: {}", e);
                    return Err(e.into());
                }

                Err(_timeout) => {
                    // Timeout on recv — no packet arrived within ACK_INTERVAL.
                    // This is normal; use the opportunity to send a pending ACK
                    // and check for stalls.
                }
            }

            // ── Periodic maintenance (runs on timeout and after each packet) ──

            // Send ACK/SACK if we have unsent progress
            if packets_since_ack > 0 || last_ack_time.elapsed() >= ACK_INTERVAL {
                if let Some(ref reasm) = reassembly {
                    if let Some(delivered_seq) = reasm.last_delivered_seq() {
                        if last_acked_value.is_none_or(|prev| delivered_seq > prev) {
                            let buffered = reasm.buffered_seqs();
                            if buffered.is_empty() {
                                send_ack(
                                    &pipeline_recv,
                                    &ack_cipher,
                                    &send_key_for_acks,
                                    sid_recv,
                                    &udp_ack_sender,
                                    peer_addr,
                                    delivered_seq,
                                )
                                .await?;
                            } else {
                                let mut sack_state = crate::congestion::ReceiverSackState::new();
                                sack_state.update_from_reassembly(reasm.expected_seq(), &buffered);
                                send_sack(
                                    &pipeline_recv,
                                    &ack_cipher,
                                    &send_key_for_acks,
                                    sid_recv,
                                    &udp_ack_sender,
                                    peer_addr,
                                    delivered_seq,
                                    sack_state.ranges(),
                                )
                                .await?;
                            }
                            last_acked_value = Some(delivered_seq);
                            packets_since_ack = 0;
                            last_ack_time = Instant::now();
                        }
                    }
                }
            }

            // ── Gap detection and NACK sending ──
            // If the reassembly buffer has a persistent gap, send a NACK
            // to request retransmission of the missing packets.
            if let Some(ref mut reasm) = reassembly {
                let nack_threshold = {
                    let cc = congestion_receiver.lock().await;
                    cc.gap_threshold()
                };
                // Debug: log when we have a gap but haven't sent a NACK yet
                if reasm.should_nack(nack_threshold) && reasm.can_send_nack(nack_threshold) {
                    let missing = reasm.missing_seqs(MAX_NACK_SEQS);
                    if !missing.is_empty() {
                        debug!(
                            "sending NACK for {} missing seqs (expected={}): {:?}",
                            missing.len(),
                            reasm.expected_seq(),
                            &missing[..missing.len().min(5)]
                        );

                        let nack_frame = encode_nack_frame(&missing);

                        // Send NACK using the send key (like ACKs)
                        let seq = {
                            let mut pl = pipeline_recv.lock().await;
                            let session = pl
                                .get_session_mut(&sid_recv)
                                .ok_or("session not found for NACK send")?;
                            session.next_send_seq()
                        };
                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[4..12].copy_from_slice(&seq.to_le_bytes());
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        let encrypted = ack_cipher
                            .encrypt(nonce, nack_frame.as_slice())
                            .map_err(|e| format!("NACK encryption error: {}", e))?;

                        let mut header = DataHeader::new(sid_recv, seq);
                        let aad = header.aad_bytes();
                        header.header_auth_tag = compute_header_auth_tag(&send_key_for_acks, &aad);

                        let mut packet = header.serialize();
                        packet.extend_from_slice(&encrypted);
                        udp_ack_sender.send_to(&packet, peer_addr).await?;
                        reasm.mark_nack_sent();
                    }
                }
            }

            // Stall detection: if expected_seq hasn't advanced in too long, abort
            if let Some(ref reasm) = reassembly {
                if reasm.buffered_count() > 0 && reasm.is_stalled(REASSEMBLY_STALL_TIMEOUT) {
                    warn!("reassembly stall detected: expected seq {} not advancing for {:?}, aborting",
                        reasm.expected_seq(), REASSEMBLY_STALL_TIMEOUT);
                    return Err("reassembly stall timeout".into());
                }
            }

            // FIN drain: if we received FIN, check whether all DATA packets
            // up to fin_data_seq have been delivered to TCP before closing.
            if fin_received {
                let all_delivered = match (&reassembly, fin_data_seq) {
                    // All data up to fin_data_seq delivered (seq is exclusive)
                    (Some(reasm), Some(fds)) => {
                        reasm.last_delivered_seq().is_some_and(|lds| lds + 1 >= fds)
                            && reasm.buffered_count() == 0
                    }
                    // FIN had no data_seq or no reassembly — close immediately
                    _ => true,
                };

                if all_delivered {
                    info!("FIN drain complete, shutting down TCP write half");
                    if let Err(e) = tcp_writer.flush().await {
                        warn!("TCP flush error during FIN drain: {}", e);
                    }
                    if let Err(e) = tcp_writer.shutdown().await {
                        warn!("TCP shutdown error during FIN drain: {}", e);
                    }
                    if let Some(tx) = fin_tx.take() {
                        let _ = tx.send(());
                    }
                    return Ok(());
                }
            }
        }
    };

    // Wrap both directions to use Send-compatible error types for tokio::spawn.
    let tcp_to_ztlp_send = async move { tcp_to_ztlp.await.map_err(|e| e.to_string()) };
    let ztlp_to_tcp_send = async move { ztlp_to_tcp.await.map_err(|e| e.to_string()) };

    // Run both directions as independent tokio tasks so they make progress
    // concurrently without starving each other (select! can starve one branch
    // if the other holds resources or is polled first).
    let mut tx_handle = tokio::spawn(tcp_to_ztlp_send);
    let mut rx_handle = tokio::spawn(ztlp_to_tcp_send);

    // AbortOnDrop ensures spawned tasks are cancelled even if run_bridge
    // is aborted from outside (e.g., parent calls .abort()). Without this,
    // the spawned tasks would outlive run_bridge and leak resources forever.
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _tx_guard = AbortOnDrop(tx_handle.abort_handle());
    let _rx_guard = AbortOnDrop(rx_handle.abort_handle());

    // Wait for the first direction to complete, then give the other a grace
    // period. Bidirectional protocols like SCP/SSH need both sides: when
    // the sender sends FIN, the receiver may still need to deliver ACK
    // bytes back. But we can't wait forever — after one side finishes,
    // the other should complete within a reasonable time.
    tokio::select! {
        result = &mut tx_handle => {
            match result {
                Ok(Ok(())) => info!("tunnel: TCP side sent FIN, waiting for ZTLP side..."),
                Ok(Err(e)) => warn!("tunnel error (TCP→ZTLP): {}", e),
                Err(e) => warn!("tunnel task panicked (TCP→ZTLP): {}", e),
            }
            // Give the receiver time to finish delivering remaining data
            match tokio::time::timeout(FIN_DRAIN_TIMEOUT, rx_handle).await {
                Ok(Ok(Ok(()))) => info!("tunnel closed (ZTLP side finished)"),
                Ok(Ok(Err(e))) => warn!("tunnel error (ZTLP→TCP): {}", e),
                Ok(Err(e)) => warn!("tunnel task panicked (ZTLP→TCP): {}", e),
                Err(_) => info!("tunnel: ZTLP side drain timeout, closing"),
            }
        }
        result = &mut rx_handle => {
            match result {
                Ok(Ok(())) => info!("tunnel: ZTLP side received FIN, waiting for TCP side..."),
                Ok(Err(e)) => warn!("tunnel error (ZTLP→TCP): {}", e),
                Err(e) => warn!("tunnel task panicked (ZTLP→TCP): {}", e),
            }
            // Give the sender time to finish
            match tokio::time::timeout(FIN_DRAIN_TIMEOUT, tx_handle).await {
                Ok(Ok(Ok(()))) => info!("tunnel closed (TCP side finished)"),
                Ok(Ok(Err(e))) => warn!("tunnel error (TCP→ZTLP): {}", e),
                Ok(Err(e)) => warn!("tunnel task panicked (TCP→ZTLP): {}", e),
                Err(_) => info!("tunnel: TCP side drain timeout, closing"),
            }
        }
    }

    info!("tunnel bridge terminated for session {}", session_id);
    if reset_received.load(std::sync::atomic::Ordering::Acquire) {
        Ok(BridgeOutcome::ResetReceived)
    } else {
        Ok(BridgeOutcome::Closed)
    }
}

/// Send an ACK frame through the ZTLP session.
///
/// The ACK contains the highest contiguous sequence number that has been
/// delivered to TCP. The remote sender uses this to advance its flow
/// control window.
async fn send_ack(
    pipeline: &Arc<Mutex<Pipeline>>,
    cipher: &ChaCha20Poly1305,
    send_key: &[u8; 32],
    session_id: SessionId,
    udp: &UdpSocket,
    peer_addr: SocketAddr,
    delivered_seq: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Build ACK frame: [FRAME_ACK | 8-byte big-endian delivered_seq]
    let mut ack_frame = Vec::with_capacity(9);
    ack_frame.push(FRAME_ACK);
    ack_frame.extend_from_slice(&delivered_seq.to_be_bytes());

    // Get next send sequence number
    let seq = {
        let mut pl = pipeline.lock().await;
        let session = pl
            .get_session_mut(&session_id)
            .ok_or("session not found for ACK send")?;
        session.next_send_seq()
    };

    // Encrypt
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher
        .encrypt(nonce, ack_frame.as_slice())
        .map_err(|e| format!("ACK encryption error: {}", e))?;

    // Build header
    let mut header = DataHeader::new(session_id, seq);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(send_key, &aad);

    // Send
    let mut packet = header.serialize();
    packet.extend_from_slice(&encrypted);
    udp.send_to(&packet, peer_addr).await?;
    debug!(
        "sent ACK for delivered_seq {} (packet seq {})",
        delivered_seq, seq
    );

    Ok(())
}

/// Send a SACK frame through the ZTLP session.
///
/// The SACK contains the cumulative ACK (highest contiguous seq delivered)
/// plus additional non-contiguous received ranges from the reassembly buffer.
/// This gives the sender precise knowledge of what the receiver has,
/// enabling efficient selective retransmission.
#[allow(clippy::too_many_arguments)]
async fn send_sack(
    pipeline: &Arc<Mutex<Pipeline>>,
    cipher: &ChaCha20Poly1305,
    send_key: &[u8; 32],
    session_id: SessionId,
    udp: &UdpSocket,
    peer_addr: SocketAddr,
    cumulative_ack: u64,
    sack_ranges: &[crate::congestion::SackRange],
) -> Result<(), Box<dyn std::error::Error>> {
    // Build SACK frame
    let sack_frame = crate::congestion::encode_sack_frame(cumulative_ack, sack_ranges);

    // Get next send sequence number
    let seq = {
        let mut pl = pipeline.lock().await;
        let session = pl
            .get_session_mut(&session_id)
            .ok_or("session not found for SACK send")?;
        session.next_send_seq()
    };

    // Encrypt
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&seq.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher
        .encrypt(nonce, sack_frame.as_slice())
        .map_err(|e| format!("SACK encryption error: {}", e))?;

    // Build header
    let mut header = DataHeader::new(session_id, seq);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(send_key, &aad);

    // Send
    let mut packet = header.serialize();
    packet.extend_from_slice(&encrypted);
    udp.send_to(&packet, peer_addr).await?;
    debug!(
        "sent SACK (cumulative_ack={}, {} ranges, packet_seq={})",
        cumulative_ack,
        sack_ranges.len(),
        seq
    );

    Ok(())
}

// ─── Service registry ───────────────────────────────────────────────────────

/// A registry of named services mapped to backend TCP addresses.
///
/// Built from `--forward` flags on the listener:
/// - `--forward ssh:127.0.0.1:22` → named service "ssh"
/// - `--forward 127.0.0.1:22` → unnamed default service
/// - Multiple `--forward` flags → multi-service listener
#[derive(Debug, Clone)]
pub struct ServiceRegistry {
    pub services: HashMap<String, SocketAddr>,
}

impl ServiceRegistry {
    /// Build a service registry from a list of `--forward` arguments.
    ///
    /// Each argument is either:
    /// - `NAME:HOST:PORT` — a named service
    /// - `HOST:PORT` — the default (unnamed) service
    pub fn from_forward_args(args: &[String]) -> Result<Self, String> {
        let mut services = HashMap::new();

        for arg in args {
            let (name, addr) = parse_forward_arg(arg)?;
            if services.contains_key(&name) {
                return Err(format!("duplicate service name '{}'", name));
            }
            services.insert(name, addr);
        }

        Ok(Self { services })
    }

    /// Look up a service by the DstSvcID bytes from the handshake header.
    ///
    /// If the DstSvcID is all zeros, returns the default service.
    /// Otherwise, trims trailing zeros and looks up by name.
    pub fn resolve(&self, dst_svc_id: &[u8; 16]) -> Option<(&str, SocketAddr)> {
        let name = if dst_svc_id == &[0u8; 16] {
            DEFAULT_SERVICE.to_string()
        } else {
            // Trim trailing null bytes to get the service name
            let end = dst_svc_id
                .iter()
                .rposition(|&b| b != 0)
                .map(|i| i + 1)
                .unwrap_or(0);
            String::from_utf8_lossy(&dst_svc_id[..end]).to_string()
        };

        self.services
            .get_key_value(&name)
            .map(|(key, addr)| (key.as_str(), *addr))
    }

    /// Check if this registry has any services.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Number of registered services.
    pub fn len(&self) -> usize {
        self.services.len()
    }
}

/// Encode a service name into a 16-byte DstSvcID field.
///
/// Pads with zeros if shorter than 16 bytes.
/// Returns an error if the name is too long.
pub fn encode_service_name(name: &str) -> Result<[u8; 16], String> {
    let bytes = name.as_bytes();
    if bytes.len() > MAX_SERVICE_NAME_LEN {
        return Err(format!(
            "service name '{}' too long ({} bytes, max {})",
            name,
            bytes.len(),
            MAX_SERVICE_NAME_LEN
        ));
    }
    let mut buf = [0u8; 16];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}

/// Parse a single `--forward` argument.
///
/// Formats:
/// - `NAME:HOST:PORT` → (name, address)
/// - `HOST:PORT` → (DEFAULT_SERVICE, address)
fn parse_forward_arg(s: &str) -> Result<(String, SocketAddr), String> {
    // Try to parse as a plain address first (HOST:PORT)
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok((DEFAULT_SERVICE.to_string(), addr));
    }

    // Try NAME:HOST:PORT — split on first ':'
    let first_colon = s.find(':').ok_or_else(|| {
        format!(
            "invalid --forward argument '{}'. Expected NAME:HOST:PORT or HOST:PORT",
            s
        )
    })?;

    let name = &s[..first_colon];
    let addr_str = &s[first_colon + 1..];

    // Validate the name
    if name.is_empty() {
        return Err(format!("empty service name in '{}'", s));
    }
    if name.len() > MAX_SERVICE_NAME_LEN {
        return Err(format!(
            "service name '{}' too long ({} bytes, max {})",
            name,
            name.len(),
            MAX_SERVICE_NAME_LEN
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "service name '{}' contains invalid characters (use a-z, 0-9, -, _)",
            name
        ));
    }

    let addr: SocketAddr = addr_str
        .parse()
        .map_err(|e| format!("invalid address '{}' in '{}': {}", addr_str, s, e))?;

    Ok((name.to_string(), addr))
}

/// Parse a forward target string like "127.0.0.1:22" into a SocketAddr.
pub fn parse_forward_target(s: &str) -> Result<SocketAddr, String> {
    s.parse::<SocketAddr>()
        .map_err(|e| format!("invalid forward target '{}': {}", s, e))
}

/// Parse a local-forward string like "2222:127.0.0.1:22" into (local_port, remote_addr).
pub fn parse_local_forward(s: &str) -> Result<(u16, String), String> {
    // Format: local_port:remote_host:remote_port
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "invalid local-forward format '{}'. Expected: LOCAL_PORT:REMOTE_HOST:REMOTE_PORT",
            s
        ));
    }

    let local_port: u16 = parts[0]
        .parse()
        .map_err(|_| format!("invalid local port '{}' in '{}'", parts[0], s))?;

    let remote = parts[1].to_string();

    // Validate the remote part looks like host:port
    if !remote.contains(':') {
        return Err(format!(
            "invalid remote address '{}'. Expected HOST:PORT",
            remote
        ));
    }

    Ok((local_port, remote))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── ReassemblyBuffer tests ──────────────────────────────────────────

    #[test]
    fn test_reassembly_in_order_delivery() {
        // Packets arriving in perfect order should be delivered immediately.
        let mut rb = ReassemblyBuffer::new(0, 100);

        let result = rb.insert(0, vec![0x10]);
        assert!(result.is_some());
        let delivered = result.unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], (0, vec![0x10]));
        assert_eq!(rb.expected_seq(), 1);

        let result = rb.insert(1, vec![0x20]);
        let delivered = result.unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], (1, vec![0x20]));
        assert_eq!(rb.expected_seq(), 2);

        let result = rb.insert(2, vec![0x30]);
        let delivered = result.unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], (2, vec![0x30]));
        assert_eq!(rb.expected_seq(), 3);
    }

    #[test]
    fn test_reassembly_out_of_order_reordering() {
        // Packets arrive: 2, 0, 1 → should deliver [0, 1, 2] when gap fills.
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Seq 2 arrives first — buffered, nothing to deliver
        let result = rb.insert(2, vec![0x30]);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty()); // buffered
        assert_eq!(rb.expected_seq(), 0);
        assert_eq!(rb.buffered_count(), 1);

        // Seq 0 arrives — delivers seq 0 only (seq 1 still missing)
        let result = rb.insert(0, vec![0x10]);
        let delivered = result.unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], (0, vec![0x10]));
        assert_eq!(rb.expected_seq(), 1);
        assert_eq!(rb.buffered_count(), 1); // seq 2 still buffered

        // Seq 1 arrives — delivers seq 1 AND seq 2 (consecutive run)
        let result = rb.insert(1, vec![0x20]);
        let delivered = result.unwrap();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0], (1, vec![0x20]));
        assert_eq!(delivered[1], (2, vec![0x30]));
        assert_eq!(rb.expected_seq(), 3);
        assert_eq!(rb.buffered_count(), 0);
    }

    #[test]
    fn test_reassembly_duplicate_rejection() {
        // Duplicate packets should be silently dropped.
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Deliver seq 0
        let result = rb.insert(0, vec![0xAA]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);

        // Duplicate of seq 0 (already delivered) → None
        let result = rb.insert(0, vec![0xAA]);
        assert!(result.is_none());

        // Buffer seq 5
        let result = rb.insert(5, vec![0xBB]);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());

        // Duplicate of seq 5 (already buffered) → None
        let result = rb.insert(5, vec![0xCC]);
        assert!(result.is_none());
    }

    #[test]
    fn test_reassembly_buffer_overflow_protection() {
        // When the buffer is full, new out-of-order packets are dropped.
        let mut rb = ReassemblyBuffer::new(0, 3); // max 3 buffered

        // Skip seq 0, buffer seqs 1, 2, 3
        let _ = rb.insert(1, vec![0x10]);
        let _ = rb.insert(2, vec![0x20]);
        let _ = rb.insert(3, vec![0x30]);
        assert_eq!(rb.buffered_count(), 3);

        // Seq 4 should be dropped — buffer full
        let result = rb.insert(4, vec![0x40]);
        assert!(result.is_none());
        assert_eq!(rb.buffered_count(), 3);

        // Seq 0 fills the gap — delivers all 4
        let result = rb.insert(0, vec![0x00]);
        let delivered = result.unwrap();
        assert_eq!(delivered.len(), 4); // 0, 1, 2, 3
        assert_eq!(rb.expected_seq(), 4);
        assert_eq!(rb.buffered_count(), 0);
    }

    #[test]
    fn test_reassembly_gap_timeout() {
        // The stall detector fires if expected_seq doesn't advance.
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Buffer seq 1 (seq 0 is missing — gap)
        let _ = rb.insert(1, vec![0x10]);
        assert!(!rb.is_stalled(std::time::Duration::from_millis(100)));

        // Not stalled yet with a very long timeout
        assert!(!rb.is_stalled(std::time::Duration::from_secs(300)));

        // With a zero timeout, it should be stalled immediately
        // (since last_progress was set at construction, and time has passed)
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(rb.is_stalled(std::time::Duration::from_millis(5)));
    }

    #[test]
    fn test_reassembly_last_delivered_seq() {
        let mut rb = ReassemblyBuffer::new(0, 100);

        // No deliveries yet
        assert_eq!(rb.last_delivered_seq(), None);

        // Deliver seq 0
        let _ = rb.insert(0, vec![0xAA]);
        assert_eq!(rb.last_delivered_seq(), Some(0));

        // Deliver seq 1, 2
        let _ = rb.insert(1, vec![0xBB]);
        assert_eq!(rb.last_delivered_seq(), Some(1));
        let _ = rb.insert(2, vec![0xCC]);
        assert_eq!(rb.last_delivered_seq(), Some(2));
    }

    #[test]
    fn test_reassembly_non_zero_initial_seq() {
        // The tunnel may start with a non-zero seq if the ZTLP session
        // already consumed some sequence numbers during handshake.
        let mut rb = ReassemblyBuffer::new(100, 100);

        // Seq 99 is stale (< initial expected)
        assert!(rb.insert(99, vec![0xFF]).is_none());

        // Seq 100 is the first expected
        let result = rb.insert(100, vec![0xAA]);
        assert_eq!(result.unwrap().len(), 1);
        assert_eq!(rb.expected_seq(), 101);
    }

    #[test]
    fn test_reassembly_large_gap_then_fill() {
        // Large gap with many buffered packets, then gap fills.
        let mut rb = ReassemblyBuffer::new(0, 1000);

        // Buffer seqs 5..105 (100 packets, gap at 0..4)
        for i in 5..105 {
            let result = rb.insert(i, vec![i as u8]);
            assert!(result.is_some());
            assert!(result.unwrap().is_empty());
        }
        assert_eq!(rb.buffered_count(), 100);

        // Fill gap: deliver 0, 1, 2, 3, 4 → triggers delivery of 0..104
        for i in 0..5 {
            let result = rb.insert(i, vec![i as u8]);
            let delivered = result.unwrap();
            if i < 4 {
                // Each fills one more, but doesn't yet trigger the big run
                assert_eq!(delivered.len(), 1);
            } else {
                // Seq 4 fills the last gap → delivers 4 + all 100 buffered = 101
                assert_eq!(delivered.len(), 101);
            }
        }
        assert_eq!(rb.expected_seq(), 105);
        assert_eq!(rb.buffered_count(), 0);
    }

    // ── Existing tests (preserved) ──────────────────────────────────────

    #[test]
    fn test_parse_forward_target() {
        let addr = parse_forward_target("127.0.0.1:22").unwrap();
        assert_eq!(addr.port(), 22);
        assert_eq!(addr.ip().to_string(), "127.0.0.1");

        let addr = parse_forward_target("0.0.0.0:3389").unwrap();
        assert_eq!(addr.port(), 3389);

        assert!(parse_forward_target("not-an-addr").is_err());
        assert!(parse_forward_target("127.0.0.1").is_err());
    }

    #[test]
    fn test_parse_local_forward() {
        let (port, remote) = parse_local_forward("2222:127.0.0.1:22").unwrap();
        assert_eq!(port, 2222);
        assert_eq!(remote, "127.0.0.1:22");

        let (port, remote) = parse_local_forward("3389:10.0.0.5:3389").unwrap();
        assert_eq!(port, 3389);
        assert_eq!(remote, "10.0.0.5:3389");

        assert!(parse_local_forward("invalid").is_err());
        assert!(parse_local_forward("abc:127.0.0.1:22").is_err());
        assert!(parse_local_forward("2222:noport").is_err());
    }

    #[test]
    fn test_parse_local_forward_ipv6() {
        let (port, remote) = parse_local_forward("8080:[::1]:443").unwrap();
        assert_eq!(port, 8080);
        assert_eq!(remote, "[::1]:443");
    }

    // --- Service registry tests ---

    #[test]
    fn test_parse_forward_arg_unnamed() {
        let (name, addr) = parse_forward_arg("127.0.0.1:22").unwrap();
        assert_eq!(name, DEFAULT_SERVICE);
        assert_eq!(addr.port(), 22);
    }

    #[test]
    fn test_parse_forward_arg_named() {
        let (name, addr) = parse_forward_arg("ssh:127.0.0.1:22").unwrap();
        assert_eq!(name, "ssh");
        assert_eq!(addr.port(), 22);

        let (name, addr) = parse_forward_arg("rdp:10.0.0.1:3389").unwrap();
        assert_eq!(name, "rdp");
        assert_eq!(addr.port(), 3389);
    }

    #[test]
    fn test_parse_forward_arg_invalid() {
        assert!(parse_forward_arg("").is_err());
        assert!(parse_forward_arg("noport").is_err());
        assert!(parse_forward_arg(":127.0.0.1:22").is_err()); // empty name
    }

    #[test]
    fn test_parse_forward_arg_name_too_long() {
        let long_name = "a".repeat(17);
        let arg = format!("{}:127.0.0.1:22", long_name);
        assert!(parse_forward_arg(&arg).is_err());
    }

    #[test]
    fn test_parse_forward_arg_name_invalid_chars() {
        assert!(parse_forward_arg("my service:127.0.0.1:22").is_err()); // space
        assert!(parse_forward_arg("my.svc:127.0.0.1:22").is_err()); // dot
    }

    #[test]
    fn test_service_registry_single_default() {
        let reg = ServiceRegistry::from_forward_args(&["127.0.0.1:22".to_string()]).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.services.contains_key(DEFAULT_SERVICE));
    }

    #[test]
    fn test_service_registry_multi() {
        let reg = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
            "rdp:127.0.0.1:3389".to_string(),
            "db:127.0.0.1:5432".to_string(),
        ])
        .unwrap();
        assert_eq!(reg.len(), 3);
        assert_eq!(reg.services["ssh"].port(), 22);
        assert_eq!(reg.services["rdp"].port(), 3389);
        assert_eq!(reg.services["db"].port(), 5432);
    }

    #[test]
    fn test_service_registry_duplicate_rejected() {
        let result = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
            "ssh:127.0.0.1:2222".to_string(),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_zero_dst_svc_id() {
        let reg = ServiceRegistry::from_forward_args(&[
            "127.0.0.1:22".to_string(), // default
        ])
        .unwrap();
        let zeros = [0u8; 16];
        let (name, addr) = reg.resolve(&zeros).unwrap();
        assert_eq!(name, DEFAULT_SERVICE);
        assert_eq!(addr.port(), 22);
    }

    #[test]
    fn test_resolve_named_service() {
        let reg = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
            "rdp:127.0.0.1:3389".to_string(),
        ])
        .unwrap();

        let mut svc_id = [0u8; 16];
        svc_id[..3].copy_from_slice(b"ssh");
        let (name, addr) = reg.resolve(&svc_id).unwrap();
        assert_eq!(name, "ssh");
        assert_eq!(addr.port(), 22);

        let mut svc_id2 = [0u8; 16];
        svc_id2[..3].copy_from_slice(b"rdp");
        let (name, addr) = reg.resolve(&svc_id2).unwrap();
        assert_eq!(name, "rdp");
        assert_eq!(addr.port(), 3389);
    }

    #[test]
    fn test_resolve_unknown_service() {
        let reg = ServiceRegistry::from_forward_args(&["ssh:127.0.0.1:22".to_string()]).unwrap();

        let mut svc_id = [0u8; 16];
        svc_id[..5].copy_from_slice(b"mysql");
        assert!(reg.resolve(&svc_id).is_none());
    }

    #[test]
    fn test_encode_service_name() {
        let buf = encode_service_name("ssh").unwrap();
        assert_eq!(&buf[..3], b"ssh");
        assert_eq!(&buf[3..], &[0u8; 13]);

        let buf = encode_service_name("rdp").unwrap();
        assert_eq!(&buf[..3], b"rdp");

        // Exactly 16 bytes
        let name16 = "a".repeat(16);
        let buf = encode_service_name(&name16).unwrap();
        assert_eq!(&buf, name16.as_bytes());

        // Too long
        let name17 = "a".repeat(17);
        assert!(encode_service_name(&name17).is_err());
    }

    // ── RetransmitBuffer tests ──────────────────────────────────────────

    #[test]
    fn test_retransmit_buffer_insert_and_get() {
        let mut rb = RetransmitBuffer::new(100);
        let now = Instant::now();
        // insert(data_seq, packet_seq, framed_plaintext, send_time)
        rb.insert(0, 0, vec![FRAME_DATA, 0xAA], now);
        rb.insert(1, 1, vec![FRAME_DATA, 0xBB], now);
        rb.insert(2, 2, vec![FRAME_DATA, 0xCC], now);

        assert_eq!(rb.len(), 3);
        assert_eq!(rb.get(0), Some(&[FRAME_DATA, 0xAA][..]));
        assert_eq!(rb.get(1), Some(&[FRAME_DATA, 0xBB][..]));
        assert_eq!(rb.get(2), Some(&[FRAME_DATA, 0xCC][..]));
        assert_eq!(rb.get(3), None);
    }

    #[test]
    fn test_retransmit_buffer_get_with_packet_seq() {
        let mut rb = RetransmitBuffer::new(100);
        let now = Instant::now();
        // data_seq and packet_seq differ (e.g., ACK/NACK consumed some packet_seqs)
        rb.insert(0, 0, vec![FRAME_DATA, 0xAA], now);
        rb.insert(1, 3, vec![FRAME_DATA, 0xBB], now); // packet_seq=3 (ACK consumed 1,2)
        rb.insert(2, 5, vec![FRAME_DATA, 0xCC], now); // packet_seq=5

        let (data, pkt_seq) = rb.get_with_packet_seq(1).unwrap();
        assert_eq!(data, vec![FRAME_DATA, 0xBB]);
        assert_eq!(pkt_seq, 3);

        let (data, pkt_seq) = rb.get_with_packet_seq(2).unwrap();
        assert_eq!(data, vec![FRAME_DATA, 0xCC]);
        assert_eq!(pkt_seq, 5);

        assert!(rb.get_with_packet_seq(99).is_none());
    }

    #[test]
    fn test_retransmit_buffer_prune() {
        let mut rb = RetransmitBuffer::new(100);
        let now = Instant::now();
        for i in 0..10 {
            rb.insert(i, i, vec![FRAME_DATA, i as u8], now);
        }
        assert_eq!(rb.len(), 10);

        // Prune up to data_seq 4 (0..=4 removed)
        rb.prune_up_to(4);
        assert_eq!(rb.len(), 5);
        assert_eq!(rb.get(4), None); // 4 was pruned (data_seq <= 4)
        assert!(rb.get(5).is_some());
        assert!(rb.get(9).is_some());
    }

    #[test]
    fn test_retransmit_buffer_full() {
        let mut rb = RetransmitBuffer::new(3);
        let now = Instant::now();
        rb.insert(0, 0, vec![0xAA], now);
        rb.insert(1, 1, vec![0xBB], now);
        rb.insert(2, 2, vec![0xCC], now);
        assert_eq!(rb.len(), 3);

        // Buffer full — new insert silently dropped
        rb.insert(3, 3, vec![0xDD], now);
        assert_eq!(rb.len(), 3);
        assert_eq!(rb.get(3), None);
    }

    #[test]
    fn test_retransmit_buffer_send_time() {
        let mut rb = RetransmitBuffer::new(100);
        let t1 = Instant::now();
        rb.insert(42, 42, vec![0xAA], t1);

        let stored_time = rb.send_time(42).unwrap();
        assert_eq!(stored_time, t1);
        assert!(rb.send_time(99).is_none());
    }

    // ── AdvancedCongestionController tests (tunnel integration) ────────

    use crate::congestion::{
        AdvancedCongestionController, CongestionPhase, INITIAL_CWND, INITIAL_SSTHRESH,
        MAX_RTO_MS as CC_MAX_RTO_MS, SEND_WINDOW as CC_SEND_WINDOW,
    };

    #[test]
    fn test_congestion_controller_initial_state() {
        let cc = AdvancedCongestionController::new();
        assert_eq!(cc.cwnd, INITIAL_CWND);
        assert_eq!(cc.ssthresh, INITIAL_SSTHRESH);
        assert_eq!(cc.phase, CongestionPhase::SlowStart);
        assert_eq!(cc.effective_window(), INITIAL_CWND as u64);
    }

    #[test]
    fn test_congestion_slow_start_growth() {
        let mut cc = AdvancedCongestionController::new();
        assert_eq!(cc.phase, CongestionPhase::SlowStart);

        // In slow start, cwnd += newly_acked
        cc.on_ack(1);
        assert_eq!(cc.cwnd, INITIAL_CWND + 1.0);
        assert_eq!(cc.phase, CongestionPhase::SlowStart);

        // ACK covering 5 packets
        cc.on_ack(5);
        assert_eq!(cc.cwnd, INITIAL_CWND + 6.0);
    }

    #[test]
    fn test_congestion_slow_start_to_avoidance_transition() {
        let mut cc = AdvancedCongestionController::new();
        cc.ssthresh = 20.0;

        // Grow cwnd past ssthresh
        cc.on_ack(15); // cwnd = 10 + 15 = 25 >= ssthresh(20)
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);
    }

    #[test]
    fn test_congestion_avoidance_linear_growth() {
        let mut cc = AdvancedCongestionController::new();
        cc.phase = CongestionPhase::CongestionAvoidance;
        cc.cwnd = 100.0;

        // In congestion avoidance: cwnd += 1/cwnd per ACK
        cc.on_ack(1);
        assert!((cc.cwnd - 100.01).abs() < 0.001);

        // After 100 single-packet ACKs, should grow by ~1
        for _ in 1..100u64 {
            cc.on_ack(1);
        }
        assert!((cc.cwnd - 101.0).abs() < 0.1);
    }

    #[test]
    fn test_congestion_on_loss() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;
        cc.ssthresh = 200.0;
        cc.phase = CongestionPhase::SlowStart;

        cc.on_loss(None);
        // ssthresh = cwnd/2, but cwnd stays at pre-loss value (PRR manages it)
        assert_eq!(cc.ssthresh, 50.0);
        assert_eq!(cc.cwnd, 100.0);
        assert_eq!(cc.phase, CongestionPhase::Recovery);
    }

    #[test]
    fn test_congestion_on_loss_min_ssthresh() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 3.0;

        cc.on_loss(None);
        // max(cwnd/2, MIN_CWND) = max(1.5, 2) = 2
        assert_eq!(cc.ssthresh, 2.0);
        // cwnd stays at old value during Recovery
        assert_eq!(cc.cwnd, 3.0);
        assert_eq!(cc.phase, CongestionPhase::Recovery);
    }

    #[test]
    fn test_congestion_on_loss_dedup() {
        // Multiple losses while already in Recovery should only reduce once
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;
        let ssthresh_before = cc.ssthresh;
        cc.on_loss(Some(200));
        let ssthresh_after_first = cc.ssthresh;
        assert_eq!(cc.phase, CongestionPhase::Recovery);
        assert!(ssthresh_after_first < ssthresh_before);

        // Second loss in Recovery — should be a no-op (ssthresh unchanged)
        cc.on_loss(Some(201));
        assert_eq!(cc.ssthresh, ssthresh_after_first);
        assert_eq!(cc.phase, CongestionPhase::Recovery);

        // Simulate recovery complete: update scoreboard cumulative ack
        // past the recovery_seq, then call on_ack to exit recovery
        cc.scoreboard.update_from_sack(200, &[]);
        cc.on_ack(1);
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);

        let ssthresh_before_second = cc.ssthresh;
        cc.on_loss(None);
        // Now it should reduce again (new ssthresh)
        assert!(cc.ssthresh <= ssthresh_before_second);
        assert_eq!(cc.phase, CongestionPhase::Recovery);
    }

    #[test]
    fn test_congestion_nack_fast_retransmit() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = 100.0;
        cc.phase = CongestionPhase::CongestionAvoidance;

        // Single NACK doesn't trigger fast retransmit
        let trigger1 = cc.on_nack_received(&[5]);
        assert!(!trigger1);

        let trigger2 = cc.on_nack_received(&[5, 6]);
        assert!(!trigger2);

        // After enough NACKs, fast retransmit should trigger
        let trigger3 = cc.on_nack_received(&[5, 6, 7]);
        assert!(trigger3);
    }

    #[test]
    fn test_congestion_rtt_estimation() {
        let mut cc = AdvancedCongestionController::new();
        // Initial: srtt=100, rttvar=50, rto=100+4*50=300

        // First real sample: RFC 6298 sets srtt=sample, rttvar=sample/2
        cc.update_rtt(80.0);
        assert!((cc.srtt_ms() - 80.0).abs() < 0.01);
        assert!((cc.rtt.rttvar_ms() - 40.0).abs() < 0.01);
        // rto = 80 + 4*40 = 240
        assert!((cc.rto_ms() - 240.0).abs() < 0.01);

        // Second sample of 90ms uses EWMA:
        // rttvar = 0.75*40 + 0.25*|80-90| = 30 + 2.5 = 32.5
        // srtt = 0.875*80 + 0.125*90 = 70 + 11.25 = 81.25
        // rto = 81.25 + 4*32.5 = 81.25 + 130 = 211.25
        cc.update_rtt(90.0);
        assert!((cc.srtt_ms() - 81.25).abs() < 0.01);
        assert!((cc.rtt.rttvar_ms() - 32.5).abs() < 0.01);
        assert!((cc.rto_ms() - 211.25).abs() < 0.01);
    }

    #[test]
    fn test_congestion_rto_clamping() {
        let mut cc = AdvancedCongestionController::new();

        // Very small RTT sample → RTO should not go below MIN_RTO_MS
        for _ in 0..100 {
            cc.update_rtt(1.0);
        }
        assert!(cc.rto_ms() >= MIN_RTO_MS);

        // Very large RTT sample → RTO should not exceed MAX_RTO_MS
        let mut cc2 = AdvancedCongestionController::new();
        for _ in 0..100 {
            cc2.update_rtt(50000.0);
        }
        assert!(cc2.rto_ms() <= CC_MAX_RTO_MS);
    }

    #[test]
    fn test_congestion_effective_window_capped() {
        let mut cc = AdvancedCongestionController::new();
        cc.cwnd = (CC_SEND_WINDOW + 1000) as f64;
        assert_eq!(cc.effective_window(), CC_SEND_WINDOW);
    }

    #[test]
    fn test_congestion_gap_threshold() {
        let cc = AdvancedCongestionController::new();
        let threshold = cc.gap_threshold();
        // With initial srtt=100ms, threshold = max(2*100, NACK_MIN_THRESHOLD_MS) = 200ms
        assert_eq!(threshold, std::time::Duration::from_millis(200));
    }

    #[test]
    fn test_congestion_gap_threshold_min() {
        let mut cc = AdvancedCongestionController::new();
        // Feed very low RTT samples so srtt converges near 10ms
        for _ in 0..100 {
            cc.update_rtt(10.0);
        }
        let threshold = cc.gap_threshold();
        // max(2*~10, congestion::NACK_MIN_THRESHOLD_MS=50) = 50ms
        // The advanced CC uses its own floor (50ms), not tunnel's old 100ms
        assert!(
            threshold.as_millis() >= crate::congestion::NACK_MIN_THRESHOLD_MS as u128,
            "threshold {:?} should be at least {}ms",
            threshold,
            crate::congestion::NACK_MIN_THRESHOLD_MS
        );
    }

    // ── Gap detection tests ─────────────────────────────────────────────

    #[test]
    fn test_gap_detection_no_gap_in_order() {
        let mut rb = ReassemblyBuffer::new(0, 100);
        rb.insert(0, vec![0xAA]);
        rb.insert(1, vec![0xBB]);
        rb.insert(2, vec![0xCC]);

        assert!(!rb.should_nack(std::time::Duration::from_millis(0)));
        assert!(rb.missing_seqs(10).is_empty());
    }

    #[test]
    fn test_gap_detection_gap_detected() {
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Seq 1 arrives (seq 0 missing → gap)
        rb.insert(1, vec![0xBB]);

        // Gap detected at should be set
        assert!(rb.gap_detected_at.is_some());

        // Not enough time has passed for NACK
        assert!(!rb.should_nack(std::time::Duration::from_secs(10)));

        // With zero threshold, should NACK immediately
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(rb.should_nack(std::time::Duration::from_millis(1)));
    }

    #[test]
    fn test_gap_detection_gap_cleared_on_fill() {
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Create gap
        rb.insert(1, vec![0xBB]);
        assert!(rb.gap_detected_at.is_some());

        // Fill gap
        rb.insert(0, vec![0xAA]);
        // After filling, buffer should be empty → gap cleared
        assert!(rb.gap_detected_at.is_none());
        assert!(!rb.should_nack(std::time::Duration::from_millis(0)));
    }

    #[test]
    fn test_gap_detection_partial_fill() {
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Buffer seqs 2, 3 (gap at 0, 1)
        rb.insert(2, vec![0xCC]);
        rb.insert(3, vec![0xDD]);

        // Fill seq 0 (gap still at 1)
        rb.insert(0, vec![0xAA]);
        assert_eq!(rb.expected_seq(), 1);
        assert_eq!(rb.buffered_count(), 2); // seqs 2, 3 still buffered

        // Gap should be reset (new gap timer)
        assert!(rb.gap_detected_at.is_some());
    }

    #[test]
    fn test_missing_seqs() {
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Buffer seqs 2, 5, 7
        rb.insert(2, vec![0xCC]);
        rb.insert(5, vec![0xFF]);
        rb.insert(7, vec![0x77]);

        let missing = rb.missing_seqs(10);
        assert_eq!(missing, vec![0, 1, 3, 4, 6]);
    }

    #[test]
    fn test_missing_seqs_limited() {
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Buffer seq 10 (seqs 0..9 missing)
        rb.insert(10, vec![0xAA]);

        let missing = rb.missing_seqs(3);
        assert_eq!(missing, vec![0, 1, 2]);
    }

    #[test]
    fn test_missing_seqs_empty_buffer() {
        let rb = ReassemblyBuffer::new(0, 100);
        assert!(rb.missing_seqs(10).is_empty());
    }

    #[test]
    fn test_nack_rate_limiting() {
        let mut rb = ReassemblyBuffer::new(0, 100);
        rb.insert(1, vec![0xBB]); // create gap

        // First NACK should be allowed
        assert!(rb.can_send_nack(std::time::Duration::from_millis(100)));

        rb.mark_nack_sent();

        // Immediately after, should be rate-limited
        assert!(!rb.can_send_nack(std::time::Duration::from_millis(100)));

        // After enough time, should be allowed again
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(rb.can_send_nack(std::time::Duration::from_millis(100)));
    }

    // ── NACK frame encode/decode tests ──────────────────────────────────

    #[test]
    fn test_nack_encode_decode_roundtrip() {
        let seqs = vec![5, 10, 15, 20, 100];
        let frame = encode_nack_frame(&seqs);

        // Check frame structure: [FRAME_NACK, count_hi, count_lo, seq1..., seq2..., ...]
        assert_eq!(frame[0], FRAME_NACK);

        // Decode (skip the FRAME_NACK byte)
        let decoded = decode_nack_payload(&frame[1..]).unwrap();
        assert_eq!(decoded, seqs);
    }

    #[test]
    fn test_nack_encode_empty() {
        let frame = encode_nack_frame(&[]);
        assert_eq!(frame[0], FRAME_NACK);
        let decoded = decode_nack_payload(&frame[1..]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_nack_encode_truncates_at_max() {
        // More than MAX_NACK_SEQS entries → truncated
        let seqs: Vec<u64> = (0..100).collect();
        let frame = encode_nack_frame(&seqs);

        let decoded = decode_nack_payload(&frame[1..]).unwrap();
        assert_eq!(decoded.len(), MAX_NACK_SEQS);
        assert_eq!(decoded[0], 0);
        assert_eq!(decoded[MAX_NACK_SEQS - 1], (MAX_NACK_SEQS - 1) as u64);
    }

    #[test]
    fn test_nack_decode_malformed() {
        // Too short
        assert!(decode_nack_payload(&[]).is_none());
        assert!(decode_nack_payload(&[0]).is_none());

        // Count says 1 but no seq data
        assert!(decode_nack_payload(&[0, 1]).is_none());

        // Count says 1 but only 7 bytes of seq (need 8)
        assert!(decode_nack_payload(&[0, 1, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn test_nack_decode_count_too_large() {
        // Count > MAX_NACK_SEQS is rejected
        let count = (MAX_NACK_SEQS + 1) as u16;
        let mut payload = count.to_be_bytes().to_vec();
        // Even if data exists, reject oversize count
        for _ in 0..=MAX_NACK_SEQS {
            payload.extend_from_slice(&0u64.to_be_bytes());
        }
        assert!(decode_nack_payload(&payload).is_none());
    }

    #[test]
    fn test_nack_single_seq() {
        let frame = encode_nack_frame(&[42]);
        let decoded = decode_nack_payload(&frame[1..]).unwrap();
        assert_eq!(decoded, vec![42]);
    }

    #[test]
    fn test_nack_large_seq_numbers() {
        let seqs = vec![u64::MAX, u64::MAX - 1, u64::MAX / 2];
        let frame = encode_nack_frame(&seqs);
        let decoded = decode_nack_payload(&frame[1..]).unwrap();
        assert_eq!(decoded, seqs);
    }

    // ── Integration scenario tests ──────────────────────────────────────

    #[test]
    fn test_congestion_full_lifecycle() {
        // Simulate: slow start → reach ssthresh → congestion avoidance → loss → recovery → CA
        let mut cc = AdvancedCongestionController::new();
        cc.ssthresh = 20.0; // Low threshold for testing

        // Slow start phase: ACKs grow cwnd exponentially
        for _i in 0..10u64 {
            cc.on_ack(1);
        }
        // cwnd should be 10 + 10 = 20, transitioning to CA
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);

        let cwnd_before_loss = cc.cwnd;

        // Congestion avoidance: linear growth
        for _i in 0..100u64 {
            cc.on_ack(1);
        }
        assert!(cc.cwnd > cwnd_before_loss);
        assert!(cc.cwnd < cwnd_before_loss + 10.0); // Should only grow ~5 packets in 100 ACKs

        let cwnd_before_second_loss = cc.cwnd;

        // Loss event at seq 500 — enters Recovery, cwnd stays (PRR manages)
        cc.on_loss(Some(500));
        assert_eq!(cc.ssthresh, (cwnd_before_second_loss / 2.0).max(2.0));
        assert_eq!(cc.phase, CongestionPhase::Recovery);

        // Simulate recovery complete: update scoreboard past recovery_seq
        cc.scoreboard.update_from_sack(500, &[]);
        cc.on_ack(1);
        assert_eq!(cc.phase, CongestionPhase::CongestionAvoidance);

        // After recovery, cwnd should be at ssthresh
        let cwnd_after_recovery = cc.cwnd;
        assert!(cwnd_after_recovery <= cwnd_before_second_loss);

        // Continue with linear growth
        for _i in 0..100u64 {
            cc.on_ack(1);
        }
        assert!(cc.cwnd > cwnd_after_recovery);
    }

    #[test]
    fn test_retransmit_buffer_lifecycle() {
        let mut rb = RetransmitBuffer::new(100);
        let now = Instant::now();

        // Simulate sending 20 packets (data_seq == packet_seq for simplicity)
        for i in 0..20 {
            rb.insert(i, i, vec![FRAME_DATA, i as u8], now);
        }
        assert_eq!(rb.len(), 20);

        // ACK covers seqs 0..=9
        rb.prune_up_to(9);
        assert_eq!(rb.len(), 10);
        assert!(rb.get(9).is_none());
        assert!(rb.get(10).is_some());

        // NACK requests retransmit of seqs 12, 15
        assert!(rb.get(12).is_some());
        assert!(rb.get(15).is_some());

        // ACK covers all
        rb.prune_up_to(19);
        assert_eq!(rb.len(), 0);
    }

    #[test]
    fn test_gap_detection_with_reassembly() {
        // Full scenario: gap detected, NACK would be sent, then gap fills
        let mut rb = ReassemblyBuffer::new(0, 100);

        // Receive seq 0 normally
        let delivered = rb.insert(0, vec![0xAA]).unwrap();
        assert_eq!(delivered.len(), 1);
        assert!(rb.gap_detected_at.is_none());

        // Seq 1 is "lost", seqs 2, 3, 4 arrive
        rb.insert(2, vec![0xCC]);
        rb.insert(3, vec![0xDD]);
        rb.insert(4, vec![0xEE]);

        // Gap detected
        assert!(rb.gap_detected_at.is_some());
        assert_eq!(rb.expected_seq(), 1);

        // Missing seqs
        let missing = rb.missing_seqs(10);
        assert_eq!(missing, vec![1]);

        // "Retransmitted" seq 1 arrives
        let delivered = rb.insert(1, vec![0xBB]).unwrap();
        assert_eq!(delivered.len(), 4); // 1, 2, 3, 4
        assert_eq!(rb.expected_seq(), 5);
        assert!(rb.gap_detected_at.is_none());
    }

    #[test]
    fn test_reassembly_with_gso_batch_delivery() {
        // Simulate receiving a burst of packets as would happen from GSO
        // on the sending end — all packets arrive in rapid succession in
        // the correct order.
        let mut rb = ReassemblyBuffer::new(0, 1000);

        // Simulate a GSO batch of 64 packets (max GSO segments)
        let batch_size = 64;
        let mut total_delivered = 0;
        for i in 0..batch_size {
            let data = vec![(i & 0xFF) as u8; 1400]; // typical MTU-sized payload
            let result = rb.insert(i as u64, data);
            assert!(result.is_some());
            let delivered = result.unwrap();
            // Each packet should be delivered immediately (in-order)
            assert_eq!(delivered.len(), 1);
            assert_eq!(delivered[0].0, i as u64);
            assert_eq!(delivered[0].1.len(), 1400);
            total_delivered += 1;
        }
        assert_eq!(total_delivered, batch_size);
        assert_eq!(rb.expected_seq(), batch_size as u64);
        assert_eq!(rb.buffered_count(), 0);

        // Simulate a second GSO batch arriving with a gap (one packet lost)
        // Packets 64-127, but packet 65 is lost
        let _ = rb.insert(64, vec![0xAA; 1400]); // delivered
        assert_eq!(rb.expected_seq(), 65);
        // Skip 65
        for i in 66..128 {
            let _ = rb.insert(i, vec![0xBB; 1400]); // all buffered
        }
        assert_eq!(rb.expected_seq(), 65); // stuck waiting for 65
        assert_eq!(rb.buffered_count(), 62); // 66..127

        // Retransmitted packet 65 arrives
        let result = rb.insert(65, vec![0xCC; 1400]).unwrap();
        // Should deliver 65 + all 62 buffered = 63 packets
        assert_eq!(result.len(), 63);
        assert_eq!(rb.expected_seq(), 128);
        assert_eq!(rb.buffered_count(), 0);
    }

    #[test]
    fn test_reassembly_with_gro_coalesced_recv() {
        // Simulate processing a coalesced GRO buffer containing multiple
        // ZTLP packets by verifying that split_gro_segments produces
        // the correct offsets and the reassembly buffer handles the
        // resulting packets correctly.
        use crate::gso::split_gro_segments;

        let addr: std::net::SocketAddr = "127.0.0.1:5000".parse().unwrap();

        // Simulate 5 coalesced ZTLP packets of 1400 bytes each
        let segment_size: u16 = 1400;
        let num_packets = 5;
        let total_len = segment_size as usize * num_packets;

        // Create a fake coalesced buffer
        let mut buffer = vec![0u8; total_len];
        for i in 0..num_packets {
            let start = i * segment_size as usize;
            let end = start + segment_size as usize;
            // Fill each segment with a different byte
            for b in &mut buffer[start..end] {
                *b = i as u8;
            }
        }

        // Split using GRO segment logic
        let segments = split_gro_segments(total_len, Some(segment_size), addr);
        assert_eq!(segments.len(), num_packets);

        // Feed into a reassembly buffer as if they were sequential ZTLP data packets
        let mut rb = ReassemblyBuffer::new(0, 64);
        for (i, seg) in segments.iter().enumerate() {
            let data = &buffer[seg.offset..seg.offset + seg.len];
            assert_eq!(data.len(), segment_size as usize);
            assert!(data.iter().all(|&b| b == i as u8));

            let deliverable = rb.insert(i as u64, data.to_vec());
            assert!(deliverable.is_some());
        }

        // All 5 packets should have been delivered in order
        assert_eq!(rb.expected_seq(), 5);
        assert_eq!(rb.buffered_count(), 0);

        // Test with non-uniform last segment (like real GRO)
        let total_with_short = segment_size as usize * 4 + 800;
        let segments = split_gro_segments(total_with_short, Some(segment_size), addr);
        assert_eq!(segments.len(), 5);
        assert_eq!(segments[4].len, 800); // last segment is shorter
    }

    // ── ResetWaitResult tests ───────────────────────────────────────

    #[test]
    fn test_reset_wait_result_empty() {
        let result = ResetWaitResult {
            reset_received: false,
            buffered_packets: Vec::new(),
        };
        assert!(!result.reset_received);
        assert!(result.buffered_packets.is_empty());
    }

    #[test]
    fn test_reset_wait_result_with_buffered() {
        let result = ResetWaitResult {
            reset_received: true,
            buffered_packets: vec![vec![0x5A, 0x01, 0x02, 0x03], vec![0x5A, 0x04, 0x05, 0x06]],
        };
        assert!(result.reset_received);
        assert_eq!(result.buffered_packets.len(), 2);
    }

    #[test]
    fn test_reset_wait_result_no_reset_with_packets() {
        // Packets arrived but no RESET — could happen on timeout
        let result = ResetWaitResult {
            reset_received: false,
            buffered_packets: vec![vec![0xFF; 100]],
        };
        assert!(!result.reset_received);
        assert_eq!(result.buffered_packets.len(), 1);
    }

    // ── Reassembly across bridge cycles ─────────────────────────────

    #[test]
    fn test_reassembly_fresh_start_after_reset() {
        // Simulate what happens when a new bridge starts after RESET:
        // data_seq restarts from 0, reassembly is fresh.
        let mut reasm = ReassemblyBuffer::new(0, 256);

        // First bridge cycle data
        let r = reasm.insert(0, b"hello".to_vec());
        assert!(r.is_some());
        let delivered = r.unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].1, b"hello");

        let r = reasm.insert(1, b"world".to_vec());
        assert!(r.is_some());

        // Second bridge cycle: create new reassembly (simulates bridge restart)
        let mut reasm2 = ReassemblyBuffer::new(0, 256);
        let r = reasm2.insert(0, b"new session data".to_vec());
        assert!(r.is_some());
        let delivered = r.unwrap();
        assert_eq!(delivered[0].1, b"new session data");
    }

    #[test]
    fn test_reassembly_buffered_out_of_order_from_prefetch() {
        // Simulate prefetched packets arriving out of order:
        // data_seq 1 arrives (buffered by wait_for_reset), data_seq 0
        // arrives in the main recv loop.
        let mut reasm = ReassemblyBuffer::new(0, 256);

        // Prefetched: data_seq=1 arrives first — buffered (returns empty deliverable)
        let r = reasm.insert(1, b"second".to_vec());
        assert!(r.is_some()); // Some(empty vec) — buffered, waiting for seq 0
        assert_eq!(r.unwrap().len(), 0);

        assert_eq!(reasm.buffered_count(), 1);

        // Main loop: data_seq=0 arrives — triggers delivery of both
        let r = reasm.insert(0, b"first".to_vec());
        assert!(r.is_some());
        let delivered = r.unwrap();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].1, b"first");
        assert_eq!(delivered[1].1, b"second");
    }

    #[test]
    fn test_bridge_outcome_variants() {
        assert_eq!(BridgeOutcome::Closed, BridgeOutcome::Closed);
        assert_eq!(BridgeOutcome::ResetReceived, BridgeOutcome::ResetReceived);
        assert_ne!(BridgeOutcome::Closed, BridgeOutcome::ResetReceived);
    }

    // ── wait_for_first_data tests ───────────────────────────────────────

    use crate::identity::NodeIdentity;
    use crate::pipeline::compute_header_auth_tag;
    use crate::session::SessionState;
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

    /// Helper: set up two UDP sockets with an established session pipeline.
    async fn setup_lazy_connect_pair() -> (
        Arc<tokio::net::UdpSocket>,
        Arc<tokio::net::UdpSocket>,
        Arc<Mutex<Pipeline>>,
        SessionId,
        SocketAddr, // client_addr
        SocketAddr, // server_addr
        [u8; 32],   // send_key (client→server)
    ) {
        let _id_server = NodeIdentity::generate().unwrap();
        let id_client = NodeIdentity::generate().unwrap();

        let server_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let session_id = SessionId::generate();
        let send_key = [0x42u8; 32]; // client→server send key
        let recv_key = [0x43u8; 32]; // unused in these tests

        // Register session on the server side (where wait_for_first_data runs)
        let server_session = SessionState::new(
            session_id,
            id_client.node_id,
            recv_key, // server's "send" key (unused here)
            send_key, // server's "recv" key = client's send key
            false,
        );

        let _ = recv_key; // suppress unused warning

        let mut pipeline = Pipeline::new();
        pipeline.register_session(server_session);
        let pipeline = Arc::new(Mutex::new(pipeline));

        (
            server_sock,
            client_sock,
            pipeline,
            session_id,
            client_addr,
            server_addr,
            send_key,
        )
    }

    /// Build a valid encrypted data packet from client to server.
    fn build_data_packet(
        session_id: SessionId,
        send_key: &[u8; 32],
        data_seq: u64,
        packet_seq: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(send_key.into());
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&packet_seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        // DATA frame: 0x00 + 8-byte data_seq + payload
        let mut plaintext = vec![FRAME_DATA];
        plaintext.extend_from_slice(&data_seq.to_be_bytes());
        plaintext.extend_from_slice(payload);

        let encrypted = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();

        let mut header = DataHeader::new(session_id, packet_seq);
        let aad = header.aad_bytes();
        header.header_auth_tag = compute_header_auth_tag(send_key, &aad);

        let mut packet = header.serialize();
        packet.extend_from_slice(&encrypted);
        packet
    }

    #[tokio::test]
    async fn test_wait_for_first_data_receives_valid_packet() {
        let (server_sock, client_sock, pipeline, session_id, client_addr, server_addr, send_key) =
            setup_lazy_connect_pair().await;

        // Client sends a valid data packet after a short delay
        let client_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let pkt = build_data_packet(session_id, &send_key, 0, 0, b"hello");
            client_sock.send_to(&pkt, server_addr).await.unwrap();
        });

        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_secs(5),
        )
        .await;

        client_task.await.unwrap();

        assert!(
            result.is_ok(),
            "should receive first data: {:?}",
            result.err()
        );
        let packets = result.unwrap();
        assert!(!packets.is_empty(), "should have at least one packet");
    }

    #[tokio::test]
    async fn test_wait_for_first_data_timeout() {
        let (server_sock, _client_sock, pipeline, session_id, client_addr, _server_addr, _send_key) =
            setup_lazy_connect_pair().await;

        // Nobody sends anything — should timeout
        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_millis(200),
        )
        .await;

        assert!(result.is_err(), "should timeout when no data arrives");
        let err = result.err().unwrap().to_string();
        assert!(
            err.contains("timeout"),
            "error should mention timeout, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_wait_for_first_data_ignores_wrong_session() {
        let (server_sock, client_sock, pipeline, session_id, client_addr, server_addr, send_key) =
            setup_lazy_connect_pair().await;

        // Client sends a packet with a DIFFERENT session ID, then the correct one
        let wrong_session = SessionId::generate();
        let client_task = tokio::spawn(async move {
            // Wrong session (should be ignored)
            tokio::time::sleep(Duration::from_millis(50)).await;
            let bad_pkt = build_data_packet(wrong_session, &send_key, 0, 0, b"wrong");
            client_sock.send_to(&bad_pkt, server_addr).await.unwrap();

            // Correct session (should be captured)
            tokio::time::sleep(Duration::from_millis(50)).await;
            let good_pkt = build_data_packet(session_id, &send_key, 0, 0, b"right");
            client_sock.send_to(&good_pkt, server_addr).await.unwrap();
        });

        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_secs(5),
        )
        .await;

        client_task.await.unwrap();

        assert!(result.is_ok());
        let packets = result.unwrap();
        assert_eq!(
            packets.len(),
            1,
            "should only capture the correct session packet"
        );
    }

    #[tokio::test]
    async fn test_wait_for_first_data_ignores_wrong_peer() {
        let (server_sock, _client_sock, pipeline, session_id, client_addr, server_addr, send_key) =
            setup_lazy_connect_pair().await;

        // A different "attacker" socket sends from a different address
        let attacker_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let client_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Attacker sends a valid-looking packet from wrong address
            let pkt = build_data_packet(session_id, &send_key, 0, 0, b"evil");
            attacker_sock.send_to(&pkt, server_addr).await.unwrap();
        });

        // Should timeout because attacker's address doesn't match client_addr
        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_millis(300),
        )
        .await;

        client_task.await.unwrap();

        assert!(
            result.is_err(),
            "should timeout — attacker's address doesn't match"
        );
    }

    #[tokio::test]
    async fn test_wait_for_first_data_ignores_garbage() {
        let (server_sock, client_sock, pipeline, session_id, client_addr, server_addr, send_key) =
            setup_lazy_connect_pair().await;

        let client_task = tokio::spawn(async move {
            // Send garbage (too short, wrong magic, etc.)
            tokio::time::sleep(Duration::from_millis(50)).await;
            client_sock
                .send_to(&[0xFFu8; 10], server_addr)
                .await
                .unwrap();

            // Send slightly longer garbage (passes size check but fails pipeline)
            tokio::time::sleep(Duration::from_millis(20)).await;
            client_sock
                .send_to(&[0x00u8; 64], server_addr)
                .await
                .unwrap();

            // Send valid packet
            tokio::time::sleep(Duration::from_millis(50)).await;
            let pkt = build_data_packet(session_id, &send_key, 0, 0, b"finally");
            client_sock.send_to(&pkt, server_addr).await.unwrap();
        });

        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_secs(5),
        )
        .await;

        client_task.await.unwrap();

        assert!(result.is_ok());
        let packets = result.unwrap();
        assert!(
            !packets.is_empty(),
            "should capture the valid packet after garbage"
        );
    }

    #[tokio::test]
    async fn test_wait_for_first_data_captures_burst() {
        let (server_sock, client_sock, pipeline, session_id, client_addr, server_addr, send_key) =
            setup_lazy_connect_pair().await;

        // Client sends a burst of 5 packets with no delay between them
        let client_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            for i in 0..5u64 {
                let pkt = build_data_packet(session_id, &send_key, i, i, &[i as u8; 100]);
                client_sock.send_to(&pkt, server_addr).await.unwrap();
            }
        });

        let result = wait_for_first_data(
            &server_sock,
            &pipeline,
            session_id,
            client_addr,
            Duration::from_secs(5),
        )
        .await;

        client_task.await.unwrap();

        assert!(result.is_ok());
        let packets = result.unwrap();
        // The grace window should capture multiple packets from the burst.
        // On localhost, all 5 should arrive within 50ms.
        assert!(
            packets.len() >= 2,
            "grace window should capture multiple burst packets, got {}",
            packets.len()
        );
    }
}
