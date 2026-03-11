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
//! | DATA | 0x00 | 8-byte BE data_seq + raw TCP bytes |
//! | ACK  | 0x01 | 8-byte BE data_seq: highest delivered data_seq |
//! | FIN  | 0x02 | 8-byte BE data_seq |
//! | NACK | 0x03 | 2-byte BE count + N × 8-byte BE missing data_seqs |
//!
//! Two modes of operation:
//!
//! - **Server-side (`--forward`):** After accepting a ZTLP session, connects
//!   to a local TCP service and bridges traffic bidirectionally.
//!
//! - **Client-side (`--local-forward`):** Opens a local TCP listener, performs
//!   a ZTLP handshake with the remote peer, and bridges incoming TCP
//!   connections through the encrypted ZTLP tunnel.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::packet::{DataHeader, SessionId, DATA_HEADER_SIZE};
use crate::pipeline::{compute_header_auth_tag, AdmissionResult, Pipeline};

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

/// Maximum UDP payload (minus ZTLP header + AEAD overhead).
/// ZTLP data header is 42 bytes, Poly1305 tag is 16 bytes, so
/// max plaintext per packet ≈ 65535 - 42 - 16 = 65477.
/// We use 16KB to stay well within IP fragmentation limits.
/// On 1500-byte MTU networks, ~16KB payloads fragment into ~11 pieces
/// which is manageable. Larger payloads suffer exponentially worse
/// fragment loss rates under any packet loss.
/// Subtract 9 bytes for the frame type prefix (1) + data_seq (8).
const MAX_PLAINTEXT_PER_PACKET: usize = 16384 - 9;

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

// ─── Flow control parameters ────────────────────────────────────────────────

/// Maximum number of unacknowledged packets the sender will keep in flight.
/// At ~16KB per packet, 2048 packets ≈ 32MB of in-flight data.
const SEND_WINDOW: u64 = 2048;

/// The receiver sends an ACK after this many packets have been delivered
/// to TCP, or when the ACK timer fires — whichever comes first.
const ACK_EVERY_PACKETS: u64 = 32;

/// ACK timer interval: send an ACK at least this often while data is flowing.
const ACK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// Maximum number of out-of-order packets the reassembly buffer will hold.
/// At ~16KB per packet, 4096 packets ≈ 64MB of buffered data.
const REASSEMBLY_MAX_BUFFERED: usize = 4096;

/// If no progress (expected_seq advance) in this duration, abort the tunnel.
/// This prevents the bridge from hanging forever if packets are permanently lost.
const REASSEMBLY_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// If the sender receives no ACK for this long, abort.
const SENDER_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// After sending FIN, wait this long for remaining buffered packets to drain.
#[allow(dead_code)]
const FIN_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ─── Congestion control parameters ──────────────────────────────────────────

/// Initial congestion window (in packets). 10 is the standard modern default
/// (RFC 6928). Slow start ramps quickly on low-RTT links.
const INITIAL_CWND: f64 = 10.0;

/// Initial slow-start threshold (in packets).
const INITIAL_SSTHRESH: f64 = 1024.0;

/// Minimum retransmission timeout in milliseconds.
const MIN_RTO_MS: f64 = 200.0;

/// Maximum retransmission timeout in milliseconds.
const MAX_RTO_MS: f64 = 60000.0;

/// Initial smoothed RTT estimate in milliseconds.
const INITIAL_SRTT_MS: f64 = 100.0;

/// Minimum gap detection threshold in milliseconds before sending a NACK.
const NACK_MIN_THRESHOLD_MS: u64 = 100;

/// Maximum number of missing sequence numbers in a single NACK frame.
const MAX_NACK_SEQS: usize = 64;

/// Maximum entries in the retransmit buffer.
const RETRANSMIT_BUF_MAX: usize = 4096;

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

    /// Check if enough time has passed since the last NACK to send another.
    pub fn can_send_nack(&self, min_interval: std::time::Duration) -> bool {
        match self.last_nack_time {
            Some(last) => last.elapsed() >= min_interval,
            None => true,
        }
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
fn decode_nack_payload(payload: &[u8]) -> Option<Vec<u64>> {
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
        let seq = u64::from_be_bytes(payload[offset..offset + 8].try_into().unwrap());
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
            },
        );
    }

    /// Get the framed plaintext for a data_seq (for retransmission).
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
    fn send_time(&self, data_seq: u64) -> Option<Instant> {
        self.entries.get(&data_seq).map(|e| e.send_time)
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
}

// ─── Congestion controller ──────────────────────────────────────────────────

/// Congestion control state: slow start or congestion avoidance.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CongestionState {
    SlowStart,
    CongestionAvoidance,
}

/// AIMD-style congestion controller with RTT estimation.
///
/// Implements TCP-like congestion control:
/// - **Slow Start:** cwnd doubles each RTT (exponential growth) until ssthresh
/// - **Congestion Avoidance:** cwnd grows by ~1 packet per RTT (linear growth)
/// - **On loss (NACK/RTO):** ssthresh = cwnd/2, cwnd = ssthresh (multiplicative decrease)
///
/// RTT is estimated using EWMA (like TCP):
/// - srtt = 0.875 * srtt + 0.125 * sample
/// - rttvar = 0.75 * rttvar + 0.25 * |srtt - sample|
/// - RTO = srtt + 4 * rttvar, clamped to [MIN_RTO_MS, MAX_RTO_MS]
struct CongestionController {
    cwnd: f64,
    ssthresh: f64,
    srtt_ms: f64,
    rttvar_ms: f64,
    rto_ms: f64,
    state: CongestionState,
}

impl CongestionController {
    fn new() -> Self {
        Self {
            cwnd: INITIAL_CWND,
            ssthresh: INITIAL_SSTHRESH,
            srtt_ms: INITIAL_SRTT_MS,
            rttvar_ms: INITIAL_SRTT_MS / 2.0,
            rto_ms: INITIAL_SRTT_MS + 4.0 * (INITIAL_SRTT_MS / 2.0),
            state: CongestionState::SlowStart,
        }
    }

    /// Effective send window: min(cwnd, SEND_WINDOW).
    fn effective_window(&self) -> u64 {
        let cw = self.cwnd as u64;
        cw.min(SEND_WINDOW)
    }

    /// Called when an ACK is received (one ACK = acknowledges one or more packets).
    /// `newly_acked` is the number of new packets this ACK covers.
    fn on_ack(&mut self, newly_acked: u64) {
        match self.state {
            CongestionState::SlowStart => {
                // In slow start, cwnd increases by newly_acked packets
                // (doubles per RTT when every packet is ACKed)
                self.cwnd += newly_acked as f64;
                if self.cwnd >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                    debug!(
                        "congestion: entering congestion avoidance (cwnd={:.1}, ssthresh={:.1})",
                        self.cwnd, self.ssthresh
                    );
                }
            }
            CongestionState::CongestionAvoidance => {
                // Linear increase: cwnd += newly_acked / cwnd per ACK
                // This yields ~1 packet increase per RTT
                self.cwnd += (newly_acked as f64) / self.cwnd;
            }
        }
    }

    /// Called when a loss is detected (NACK or RTO timeout).
    fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(2.0);
        self.cwnd = self.ssthresh;
        self.state = CongestionState::CongestionAvoidance;
        debug!(
            "congestion: loss detected, ssthresh={:.1}, cwnd={:.1}",
            self.ssthresh, self.cwnd
        );
    }

    /// Update RTT estimate from a measured sample.
    fn update_rtt(&mut self, sample_ms: f64) {
        // EWMA: srtt = 0.875 * srtt + 0.125 * sample
        let diff = (self.srtt_ms - sample_ms).abs();
        self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * diff;
        self.srtt_ms = 0.875 * self.srtt_ms + 0.125 * sample_ms;
        self.rto_ms = (self.srtt_ms + 4.0 * self.rttvar_ms).clamp(MIN_RTO_MS, MAX_RTO_MS);
    }

    /// Current RTO in milliseconds.
    #[allow(dead_code)]
    fn rto_ms(&self) -> f64 {
        self.rto_ms
    }

    /// Current smoothed RTT in milliseconds.
    #[allow(dead_code)]
    fn srtt_ms(&self) -> f64 {
        self.srtt_ms
    }

    /// The NACK threshold: how long to wait before sending a NACK.
    /// Uses 3× srtt or NACK_MIN_THRESHOLD_MS, whichever is larger.
    fn nack_threshold(&self) -> std::time::Duration {
        let threshold_ms = (3.0 * self.srtt_ms).max(NACK_MIN_THRESHOLD_MS as f64) as u64;
        std::time::Duration::from_millis(threshold_ms)
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
pub async fn run_bridge(
    tcp_stream: TcpStream,
    udp_socket: Arc<UdpSocket>,
    pipeline: Arc<Mutex<Pipeline>>,
    session_id: SessionId,
    peer_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut tcp_reader, tcp_writer) = tcp_stream.into_split();

    let udp_send = udp_socket.clone();
    let udp_recv = udp_socket;
    let pipeline_send = pipeline.clone();
    let pipeline_recv = pipeline;
    let sid_send = session_id;
    let sid_recv = session_id;

    // Shared state for ACK-based flow control.
    // The receiver task updates `last_acked_seq` when it sends ACKs.
    // The sender task reads it to determine how many more packets it can send.
    let last_acked_seq: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let last_acked_seq_writer = last_acked_seq.clone();
    let last_acked_seq_reader = last_acked_seq;

    // Congestion controller shared between sender and receiver.
    let congestion: Arc<Mutex<CongestionController>> =
        Arc::new(Mutex::new(CongestionController::new()));
    let congestion_sender = congestion.clone();
    let congestion_receiver = congestion;

    // Retransmit buffer: sender stores sent packets for retransmission on NACK.
    let retransmit_buf: Arc<Mutex<RetransmitBuffer>> =
        Arc::new(Mutex::new(RetransmitBuffer::new(RETRANSMIT_BUF_MAX)));
    let retransmit_buf_sender = retransmit_buf.clone();
    let retransmit_buf_ack = retransmit_buf;

    // Channel for NACK-triggered retransmit requests (receiver → sender).
    let (retransmit_tx, mut retransmit_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u64>>();

    // Signal from receiver to sender that a FIN was received from the remote.
    let (fin_tx, _fin_rx) = tokio::sync::oneshot::channel::<()>();

    // ── TCP → ZTLP direction (sender) ──────────────────────────────────

    let tcp_to_ztlp = async move {
        let mut buf = vec![0u8; TCP_READ_BUF];

        // Extract the send key upfront to avoid holding the mutex in the hot loop.
        // The send key is established during the handshake and doesn't change.
        let send_key = {
            let pl = pipeline_send.lock().await;
            let session = pl.get_session(&sid_send).ok_or("session not found")?;
            session.send_key
        };

        let cipher = ChaCha20Poly1305::new((&send_key).into());
        let mut last_ack_check = Instant::now();

        // Create BatchSender once — reused for every TCP read flush.
        let batch_sender = crate::batch::BatchSender::new(
            udp_send.clone(),
            crate::gso::GsoMode::Auto,
        );

        // Separate data_seq counter for DATA/FIN frames.
        // This is independent of the pipeline's send_seq (which provides
        // nonce uniqueness). The reassembly buffer on the receiver side
        // uses data_seq for ordering, not the packet header's packet_seq.
        let mut data_seq: u64 = 0;

        loop {
            // ── Check for retransmit requests before reading new TCP data ──
            // Process any pending NACK-triggered retransmissions.
            while let Ok(nack_seqs) = retransmit_rx.try_recv() {
                // Signal loss to congestion controller (once per NACK batch)
                {
                    let mut cc = congestion_sender.lock().await;
                    cc.on_loss();
                }

                for nack_data_seq in &nack_seqs {
                    let entry_info = {
                        let rb = retransmit_buf_sender.lock().await;
                        rb.get_with_packet_seq(*nack_data_seq)
                    };
                    if let Some((plaintext, orig_packet_seq)) = entry_info {
                        // Re-encrypt with the ORIGINAL packet_seq as nonce.
                        // ChaCha20-Poly1305 is deterministic: same key+nonce+plaintext
                        // produces identical ciphertext.
                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[4..12].copy_from_slice(&orig_packet_seq.to_be_bytes());
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

            let n = match tcp_reader.read(&mut buf).await {
                Ok(0) => {
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
                    nonce_bytes[4..12].copy_from_slice(&packet_seq.to_be_bytes());
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
                Ok(n) => n,
                Err(e) => {
                    warn!("TCP read error: {}", e);
                    return Err(e.into());
                }
            };

            let data = &buf[..n];
            debug!("TCP → ZTLP: {} bytes", n);

            // Split the TCP data into chunks that fit in ZTLP packets
            // (accounting for 1-byte frame type + 8-byte data_seq prefix)
            let chunks: Vec<&[u8]> = data.chunks(MAX_PLAINTEXT_PER_PACKET).collect();
            let num_chunks = chunks.len();

            // ── Flow control: wait for send window before the batch ──
            loop {
                let acked = {
                    let guard = last_acked_seq_reader.lock().await;
                    *guard
                };

                let effective_window = {
                    let cc = congestion_sender.lock().await;
                    cc.effective_window()
                };

                // Window check: ensure we have room for at least one packet.
                let window_ok = match acked {
                    Some(acked_data_seq) => data_seq < acked_data_seq + effective_window + 1,
                    None => data_seq < effective_window,
                };

                if window_ok {
                    break;
                }

                // Window exhausted — check for timeout
                if last_ack_check.elapsed() > SENDER_ACK_TIMEOUT {
                    warn!(
                        "sender ACK timeout ({:?} with no window progress)",
                        SENDER_ACK_TIMEOUT
                    );
                    return Err("sender ACK timeout".into());
                }

                // Brief sleep to let ACKs arrive, also drain retransmits.
                // 100µs avoids busy-spinning while reacting quickly to ACKs.
                tokio::time::sleep(std::time::Duration::from_micros(100)).await;

                // Process retransmit requests while waiting for window
                while let Ok(nack_seqs) = retransmit_rx.try_recv() {
                    {
                        let mut cc = congestion_sender.lock().await;
                        cc.on_loss();
                    }
                    for nack_data_seq in &nack_seqs {
                        let entry_info = {
                            let rb = retransmit_buf_sender.lock().await;
                            rb.get_with_packet_seq(*nack_data_seq)
                        };
                        if let Some((plaintext, orig_pkt_seq)) = entry_info {
                            let mut nonce_bytes = [0u8; 12];
                            nonce_bytes[4..12].copy_from_slice(&orig_pkt_seq.to_be_bytes());
                            let nonce = Nonce::from_slice(&nonce_bytes);
                            if let Ok(encrypted) = cipher.encrypt(nonce, plaintext.as_slice()) {
                                let mut header = DataHeader::new(sid_send, orig_pkt_seq);
                                let aad = header.aad_bytes();
                                header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);
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
            }

            // Batch-allocate packet_seqs for all chunks (one lock acquisition)
            let first_packet_seq = {
                let mut pl = pipeline_send.lock().await;
                let session = pl.get_session_mut(&sid_send).ok_or("session not found")?;
                let first = session.send_seq;
                session.send_seq += num_chunks as u64;
                first
            };

            // Build, encrypt, and buffer all chunks (lock once for retransmit buffer)
            let now = Instant::now();
            let mut outgoing: Vec<(Vec<u8>, u64, u64)> = Vec::with_capacity(num_chunks);
            {
                let mut rb = retransmit_buf_sender.lock().await;
                for (i, chunk) in chunks.iter().enumerate() {
                    let current_data_seq = data_seq;
                    data_seq += 1;
                    let packet_seq = first_packet_seq + i as u64;

                    // Build framed plaintext: [FRAME_DATA | data_seq (8B BE) | chunk_bytes...]
                    let mut framed = Vec::with_capacity(1 + 8 + chunk.len());
                    framed.push(FRAME_DATA);
                    framed.extend_from_slice(&current_data_seq.to_be_bytes());
                    framed.extend_from_slice(chunk);

                    // Store in retransmit buffer
                    rb.insert(current_data_seq, packet_seq, framed.clone(), now);

                    // Encrypt with nonce = 4 zero bytes + 8-byte big-endian packet_seq
                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes[4..12].copy_from_slice(&packet_seq.to_be_bytes());
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    let encrypted = cipher
                        .encrypt(nonce, framed.as_slice())
                        .map_err(|e| format!("encryption error: {}", e))?;

                    // Build data header with packet_seq and auth tag
                    let mut header = DataHeader::new(sid_send, packet_seq);
                    let aad = header.aad_bytes();
                    header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);

                    let mut packet = header.serialize();
                    packet.extend_from_slice(&encrypted);
                    outgoing.push((packet, current_data_seq, packet_seq));
                }
            }
            // Lock released — now send all packets without holding any locks.
            // Use the pre-created BatchSender for efficient GSO/sendmmsg sends.
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

            // Reset the ACK timeout tracker
            last_ack_check = Instant::now();
        }
    };

    // ── ZTLP → TCP direction (receiver) ────────────────────────────────

    let ztlp_to_tcp = async move {
        // Extract recv key upfront — it doesn't change after handshake
        let (recv_key, send_key_for_acks) = {
            let pl = pipeline_recv.lock().await;
            let session = pl
                .get_session(&sid_recv)
                .ok_or("session not found for recv key extraction")?;
            (session.recv_key, session.send_key)
        };
        let recv_cipher = ChaCha20Poly1305::new((&recv_key).into());
        let ack_cipher = ChaCha20Poly1305::new((&send_key_for_acks).into());

        // Use BufWriter for TCP to batch small writes and reduce syscalls
        let mut tcp_writer = tokio::io::BufWriter::with_capacity(65536, tcp_writer);

        // GRO-aware receiver: transparently uses GRO when available.
        // A single recv() may yield multiple coalesced datagrams.
        let mut gro_receiver = crate::gso::GroReceiver::new(
            udp_recv.clone(),
            crate::gso::GsoMode::Auto,
        );

        // Reassembly buffer: reorders packets for in-order TCP delivery.
        // Initial expected_seq = 0 (first data packet the sender will send).
        // Note: the sender may have consumed some sequence numbers during the
        // handshake, but the tunnel protocol's data seq tracking starts at
        // whatever the ZTLP session's current send_seq is. The receiver
        // auto-detects the first data seq from the first packet it receives.
        let mut reassembly: Option<ReassemblyBuffer> = None;

        // ACK tracking: send ACKs periodically
        let mut packets_since_ack: u64 = 0;
        let mut last_ack_time = Instant::now();
        let mut last_acked_value: Option<u64> = None;

        // FIN tracking
        let mut fin_tx = Some(fin_tx);
        let mut fin_received = false;

        loop {
            // Use a timeout on UDP recv so we can periodically send ACKs
            // and check for stalls even when no packets are arriving.
            // With GRO, a single recv may return multiple coalesced datagrams.
            let recv_result =
                tokio::time::timeout(ACK_INTERVAL, gro_receiver.recv()).await;

            match recv_result {
                Ok(Ok(batch)) => {
                  // Process each segment in the GRO batch. When GRO coalesces
                  // packets, we get multiple segments from one recv call.
                  for segment in batch.segments() {
                    let data = &batch.buffer()[segment.offset..segment.offset + segment.len];
                    let n = segment.len;

                    // Run through pipeline admission (magic, session, header auth)
                    {
                        let pl = pipeline_recv.lock().await;
                        let result = pl.process(data);
                        if !matches!(result, AdmissionResult::Pass) {
                            debug!("packet dropped by pipeline");
                            continue;
                        }
                    }

                    // Parse data header
                    if n < DATA_HEADER_SIZE {
                        debug!("packet too short for data header");
                        continue;
                    }
                    let header = match DataHeader::deserialize(data) {
                        Ok(h) => h,
                        Err(_) => {
                            debug!("failed to parse data header");
                            continue;
                        }
                    };

                    // Verify session ID matches
                    if header.session_id != sid_recv {
                        debug!("wrong session ID, ignoring");
                        continue;
                    }

                    // Decrypt the payload
                    let encrypted_payload = &data[DATA_HEADER_SIZE..];
                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_be_bytes());
                    let nonce = Nonce::from_slice(&nonce_bytes);

                    let plaintext = match recv_cipher.decrypt(nonce, encrypted_payload) {
                        Ok(pt) => pt,
                        Err(e) => {
                            warn!("decryption failed (seq {}): {}", header.packet_seq, e);
                            continue;
                        }
                    };

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
                            let data_seq =
                                u64::from_be_bytes(frame_payload[..8].try_into().unwrap());
                            let tcp_payload = &frame_payload[8..];

                            // Initialize reassembly buffer on first data packet.
                            let reasm = reassembly.get_or_insert_with(|| {
                                debug!("reassembly: initialized with first data_seq {}", data_seq);
                                ReassemblyBuffer::new(data_seq, REASSEMBLY_MAX_BUFFERED)
                            });

                            // Insert into reassembly buffer keyed by data_seq
                            if let Some(deliverable) = reasm.insert(data_seq, tcp_payload.to_vec())
                            {
                                // Write all deliverable packets to TCP in order
                                for (_seq, payload) in &deliverable {
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
                                    packets_since_ack += deliverable.len() as u64;
                                }
                            }
                        }

                        FRAME_ACK => {
                            // ACK frame from the remote sender's receiver side.
                            // Contains the highest contiguous seq delivered to TCP.
                            if frame_payload.len() >= 8 {
                                let acked_seq =
                                    u64::from_be_bytes(frame_payload[..8].try_into().unwrap());
                                debug!("received ACK for data_seq {}", acked_seq);

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
                                        Some(prev) if acked_seq > prev => *guard = Some(acked_seq),
                                        None => *guard = Some(acked_seq),
                                        _ => {}
                                    }
                                }

                                // RTT measurement: find the send time of the acked seq
                                // in the retransmit buffer and compute the sample
                                {
                                    let rb = retransmit_buf_ack.lock().await;
                                    if let Some(send_time) = rb.send_time(acked_seq) {
                                        let rtt_sample = send_time.elapsed().as_secs_f64() * 1000.0;
                                        let mut cc = congestion_receiver.lock().await;
                                        cc.update_rtt(rtt_sample);
                                        if newly_acked > 0 {
                                            cc.on_ack(newly_acked);
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
                                debug!(
                                    "received NACK for {} missing seqs: {:?}",
                                    missing_seqs.len(),
                                    &missing_seqs[..missing_seqs.len().min(5)]
                                );
                                if let Err(e) = retransmit_tx.send(missing_seqs) {
                                    warn!("failed to forward NACK to sender: {}", e);
                                }
                            } else {
                                debug!("malformed NACK frame, ignoring");
                            }
                        }

                        FRAME_FIN => {
                            // FIN frame: [0x02] [data_seq: 8B BE]
                            // Remote side signaled TCP EOF.
                            if frame_payload.len() >= 8 {
                                let _fin_data_seq =
                                    u64::from_be_bytes(frame_payload[..8].try_into().unwrap());
                                info!(
                                    "received FIN frame (data_seq {}) — remote TCP stream ended",
                                    _fin_data_seq
                                );
                            } else {
                                info!("received FIN frame — remote TCP stream ended");
                            }
                            fin_received = true;

                            // If there are buffered packets, give them time to arrive
                            if let Some(ref reasm) = reassembly {
                                if reasm.buffered_count() > 0 {
                                    debug!(
                                        "FIN received with {} buffered packets, draining",
                                        reasm.buffered_count()
                                    );
                                    // Continue the loop to drain, but with FIN_DRAIN_TIMEOUT
                                    continue;
                                }
                            }

                            // Flush TCP and signal completion
                            if let Err(e) = tcp_writer.flush().await {
                                warn!("TCP flush error during FIN: {}", e);
                            }
                            if let Some(tx) = fin_tx.take() {
                                let _ = tx.send(());
                            }
                            return Ok(());
                        }

                        _ => {
                            debug!("unknown frame type 0x{:02x}, ignoring", frame_type);
                        }
                    }

                  } // end for segment in batch.segments()

                    // ── Periodic ACK sending (once per recv call, after all segments) ──
                    // Send an ACK when we've delivered enough packets or enough
                    // time has passed. This lets the sender's flow control advance.
                    if packets_since_ack >= ACK_EVERY_PACKETS
                        || last_ack_time.elapsed() >= ACK_INTERVAL
                    {
                        if let Some(ref reasm) = reassembly {
                            if let Some(delivered_seq) = reasm.last_delivered_seq() {
                                // Only send if we have new progress to report
                                if last_acked_value.map_or(true, |prev| delivered_seq > prev) {
                                    send_ack(
                                        &pipeline_recv,
                                        &ack_cipher,
                                        &send_key_for_acks,
                                        sid_recv,
                                        &udp_recv,
                                        peer_addr,
                                        delivered_seq,
                                    )
                                    .await?;
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

            // Send ACK if we have unsent progress
            if packets_since_ack > 0 || last_ack_time.elapsed() >= ACK_INTERVAL {
                if let Some(ref reasm) = reassembly {
                    if let Some(delivered_seq) = reasm.last_delivered_seq() {
                        if last_acked_value.map_or(true, |prev| delivered_seq > prev) {
                            send_ack(
                                &pipeline_recv,
                                &ack_cipher,
                                &send_key_for_acks,
                                sid_recv,
                                &udp_recv,
                                peer_addr,
                                delivered_seq,
                            )
                            .await?;
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
                    cc.nack_threshold()
                };
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
                        nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
                        let nonce = Nonce::from_slice(&nonce_bytes);
                        let encrypted = ack_cipher
                            .encrypt(nonce, nack_frame.as_slice())
                            .map_err(|e| format!("NACK encryption error: {}", e))?;

                        let mut header = DataHeader::new(sid_recv, seq);
                        let aad = header.aad_bytes();
                        header.header_auth_tag = compute_header_auth_tag(&send_key_for_acks, &aad);

                        let mut packet = header.serialize();
                        packet.extend_from_slice(&encrypted);
                        udp_recv.send_to(&packet, peer_addr).await?;
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

            // FIN drain: if we received FIN and buffer is now empty, close
            if fin_received {
                let can_close = match &reassembly {
                    Some(reasm) => reasm.buffered_count() == 0,
                    None => true,
                };
                if can_close {
                    if let Err(e) = tcp_writer.flush().await {
                        warn!("TCP flush error during FIN drain: {}", e);
                    }
                    if let Some(tx) = fin_tx.take() {
                        let _ = tx.send(());
                    }
                    return Ok(());
                }
            }
        }
    };

    // Run both directions concurrently, stop when either ends
    tokio::select! {
        result = tcp_to_ztlp => {
            match result {
                Ok(()) => info!("tunnel closed (TCP side sent FIN)"),
                Err(e) => warn!("tunnel error (TCP→ZTLP): {}", e),
            }
        }
        result = ztlp_to_tcp => {
            match result {
                Ok(()) => info!("tunnel closed (ZTLP side received FIN)"),
                Err(e) => warn!("tunnel error (ZTLP→TCP): {}", e),
            }
        }
    }

    info!("tunnel bridge terminated for session {}", session_id);
    Ok(())
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
    nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
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

        self.services.get(&name).map(|addr| {
            let key = self.services.keys().find(|k| *k == &name).unwrap();
            (key.as_str(), *addr)
        })
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

    // ── CongestionController tests ──────────────────────────────────────

    #[test]
    fn test_congestion_controller_initial_state() {
        let cc = CongestionController::new();
        assert_eq!(cc.cwnd, INITIAL_CWND);
        assert_eq!(cc.ssthresh, INITIAL_SSTHRESH);
        assert_eq!(cc.state, CongestionState::SlowStart);
        assert_eq!(cc.effective_window(), INITIAL_CWND as u64);
    }

    #[test]
    fn test_congestion_slow_start_growth() {
        let mut cc = CongestionController::new();
        assert_eq!(cc.state, CongestionState::SlowStart);

        // In slow start, cwnd += newly_acked
        cc.on_ack(1);
        assert_eq!(cc.cwnd, INITIAL_CWND + 1.0);
        assert_eq!(cc.state, CongestionState::SlowStart);

        // ACK covering 5 packets
        cc.on_ack(5);
        assert_eq!(cc.cwnd, INITIAL_CWND + 6.0);
    }

    #[test]
    fn test_congestion_slow_start_to_avoidance_transition() {
        let mut cc = CongestionController::new();
        cc.ssthresh = 20.0;

        // Grow cwnd past ssthresh
        cc.on_ack(15); // cwnd = 10 + 15 = 25 >= ssthresh(20)
        assert_eq!(cc.state, CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_congestion_avoidance_linear_growth() {
        let mut cc = CongestionController::new();
        cc.state = CongestionState::CongestionAvoidance;
        cc.cwnd = 100.0;

        // In congestion avoidance: cwnd += 1/cwnd per ACK
        cc.on_ack(1);
        assert!((cc.cwnd - 100.01).abs() < 0.001);

        // After 100 single-packet ACKs, should grow by ~1
        for _ in 0..99 {
            cc.on_ack(1);
        }
        assert!((cc.cwnd - 101.0).abs() < 0.1);
    }

    #[test]
    fn test_congestion_on_loss() {
        let mut cc = CongestionController::new();
        cc.cwnd = 100.0;
        cc.ssthresh = 200.0;
        cc.state = CongestionState::SlowStart;

        cc.on_loss();
        assert_eq!(cc.ssthresh, 50.0); // cwnd/2
        assert_eq!(cc.cwnd, 50.0); // set to ssthresh
        assert_eq!(cc.state, CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_congestion_on_loss_min_ssthresh() {
        let mut cc = CongestionController::new();
        cc.cwnd = 3.0;

        cc.on_loss();
        assert_eq!(cc.ssthresh, 2.0); // min(cwnd/2, 2) = max(1.5, 2) = 2
        assert_eq!(cc.cwnd, 2.0);
    }

    #[test]
    fn test_congestion_rtt_estimation() {
        let mut cc = CongestionController::new();
        // Initial: srtt=100, rttvar=50, rto=100+4*50=300

        // Sample of 80ms
        cc.update_rtt(80.0);
        // srtt = 0.875 * 100 + 0.125 * 80 = 87.5 + 10 = 97.5
        assert!((cc.srtt_ms - 97.5).abs() < 0.01);
        // rttvar = 0.75 * 50 + 0.25 * |100 - 80| = 37.5 + 5 = 42.5
        assert!((cc.rttvar_ms - 42.5).abs() < 0.01);
        // rto = 97.5 + 4 * 42.5 = 97.5 + 170 = 267.5
        assert!((cc.rto_ms - 267.5).abs() < 0.01);

        // Another sample of 90ms
        cc.update_rtt(90.0);
        // srtt = 0.875 * 97.5 + 0.125 * 90 = 85.3125 + 11.25 = 96.5625
        assert!((cc.srtt_ms - 96.5625).abs() < 0.01);
    }

    #[test]
    fn test_congestion_rto_clamping() {
        let mut cc = CongestionController::new();

        // Very small RTT sample → RTO should not go below MIN_RTO_MS
        for _ in 0..100 {
            cc.update_rtt(1.0);
        }
        assert!(cc.rto_ms >= MIN_RTO_MS);

        // Very large RTT sample → RTO should not exceed MAX_RTO_MS
        let mut cc2 = CongestionController::new();
        for _ in 0..100 {
            cc2.update_rtt(50000.0);
        }
        assert!(cc2.rto_ms <= MAX_RTO_MS);
    }

    #[test]
    fn test_congestion_effective_window_capped() {
        let mut cc = CongestionController::new();
        cc.cwnd = (SEND_WINDOW + 1000) as f64;
        assert_eq!(cc.effective_window(), SEND_WINDOW);
    }

    #[test]
    fn test_congestion_nack_threshold() {
        let cc = CongestionController::new();
        let threshold = cc.nack_threshold();
        // With initial srtt=100ms, threshold = max(3*100, 100) = 300ms
        assert_eq!(threshold, std::time::Duration::from_millis(300));
    }

    #[test]
    fn test_congestion_nack_threshold_min() {
        let mut cc = CongestionController::new();
        cc.srtt_ms = 10.0; // Very low RTT
        let threshold = cc.nack_threshold();
        // max(3*10, 100) = 100ms (minimum)
        assert_eq!(
            threshold,
            std::time::Duration::from_millis(NACK_MIN_THRESHOLD_MS)
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
        // Simulate: slow start → reach ssthresh → congestion avoidance → loss → recovery
        let mut cc = CongestionController::new();
        cc.ssthresh = 20.0; // Low threshold for testing

        // Slow start phase: ACKs grow cwnd exponentially
        for _ in 0..10 {
            cc.on_ack(1);
        }
        // cwnd should be 10 + 10 = 20, transitioning to CA
        assert_eq!(cc.state, CongestionState::CongestionAvoidance);

        let cwnd_before_loss = cc.cwnd;

        // Congestion avoidance: linear growth
        for _ in 0..100 {
            cc.on_ack(1);
        }
        assert!(cc.cwnd > cwnd_before_loss);
        assert!(cc.cwnd < cwnd_before_loss + 10.0); // Should only grow ~5 packets in 100 ACKs

        let cwnd_before_second_loss = cc.cwnd;

        // Loss event
        cc.on_loss();
        assert_eq!(cc.cwnd, cwnd_before_second_loss / 2.0);
        assert_eq!(cc.state, CongestionState::CongestionAvoidance);

        // Recovery: linear growth from new cwnd
        let cwnd_after_loss = cc.cwnd;
        for _ in 0..100 {
            cc.on_ack(1);
        }
        assert!(cc.cwnd > cwnd_after_loss);
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
}
