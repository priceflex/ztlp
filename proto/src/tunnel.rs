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
//! - **Graceful shutdown:** TCP EOF is signaled via a FIN frame so the
//!   remote side can flush buffered data and close cleanly.
//!
//! ### Frame format
//!
//! Each ZTLP data packet's plaintext is prefixed with a 1-byte frame type:
//!
//! | Type | Byte | Payload |
//! |------|------|---------|
//! | DATA | 0x00 | Raw TCP bytes |
//! | ACK  | 0x01 | 8-byte big-endian u64: highest delivered seq |
//! | FIN  | 0x02 | (empty) |
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
const TCP_READ_BUF: usize = 65536;

/// Maximum UDP payload (minus ZTLP header + AEAD overhead).
/// ZTLP data header is 42 bytes, Poly1305 tag is 16 bytes, so
/// max plaintext per packet ≈ 65535 - 42 - 16 = 65477.
/// We use a conservative 16KB to avoid IP fragmentation on most MTUs.
/// Subtract 1 byte for the frame type prefix.
const MAX_PLAINTEXT_PER_PACKET: usize = 16384 - 1;

// ─── Frame types ────────────────────────────────────────────────────────────

/// Frame type byte: DATA frame containing TCP payload bytes.
const FRAME_DATA: u8 = 0x00;

/// Frame type byte: ACK frame containing 8-byte big-endian delivered seq.
const FRAME_ACK: u8 = 0x01;

/// Frame type byte: FIN frame signaling TCP EOF / stream complete.
const FRAME_FIN: u8 = 0x02;

// ─── Flow control parameters ────────────────────────────────────────────────

/// Maximum number of unacknowledged packets the sender will keep in flight.
/// At ~16KB per packet, 2048 packets ≈ 32MB of in-flight data.
const SEND_WINDOW: u64 = 2048;

/// The receiver sends an ACK after this many packets have been delivered
/// to TCP, or when the ACK timer fires — whichever comes first.
const ACK_EVERY_PACKETS: u64 = 64;

/// ACK timer interval: send an ACK at least this often while data is flowing.
const ACK_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

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
            debug!("reassembly: dropping duplicate/stale seq {} (expected {})", seq, self.expected_seq);
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
                warn!("reassembly: buffer full ({} packets), dropping seq {}", self.buffer.len(), seq);
                return None;
            }
            self.buffer.insert(seq, data);
            debug!("reassembly: buffered seq {} (expected {}, buffered {})",
                seq, self.expected_seq, self.buffer.len());
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

        // Mark progress
        self.last_progress = Instant::now();

        debug!("reassembly: delivered {} packets, expected_seq now {}, buffered {}",
            deliverable.len(), self.expected_seq, self.buffer.len());

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

    // Signal from receiver to sender that a FIN was received from the remote.
    let (fin_tx, _fin_rx) = tokio::sync::oneshot::channel::<()>();

    // ── TCP → ZTLP direction (sender) ──────────────────────────────────

    let tcp_to_ztlp = async move {
        let mut buf = vec![0u8; TCP_READ_BUF];

        // Extract the send key upfront to avoid holding the mutex in the hot loop.
        // The send key is established during the handshake and doesn't change.
        let send_key = {
            let pl = pipeline_send.lock().await;
            let session = pl.get_session(&sid_send)
                .ok_or("session not found")?;
            session.send_key
        };

        let cipher = ChaCha20Poly1305::new((&send_key).into());
        let mut last_ack_check = Instant::now();

        loop {
            let n = match tcp_reader.read(&mut buf).await {
                Ok(0) => {
                    // TCP EOF — send FIN frame to signal stream end to remote
                    info!("TCP connection closed (read EOF), sending FIN");
                    let fin_frame = vec![FRAME_FIN];
                    let seq = {
                        let mut pl = pipeline_send.lock().await;
                        let session = pl.get_session_mut(&sid_send)
                            .ok_or("session not found")?;
                        session.next_send_seq()
                    };
                    let mut nonce_bytes = [0u8; 12];
                    nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
                    let nonce = Nonce::from_slice(&nonce_bytes);
                    let encrypted = cipher.encrypt(nonce, fin_frame.as_slice())
                        .map_err(|e| format!("FIN encryption error: {}", e))?;
                    let mut header = DataHeader::new(sid_send, seq);
                    let aad = header.aad_bytes();
                    header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);
                    let mut packet = header.serialize();
                    packet.extend_from_slice(&encrypted);
                    udp_send.send_to(&packet, peer_addr).await?;
                    debug!("sent FIN frame (seq {})", seq);
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
            // (accounting for the 1-byte frame type prefix)
            for chunk in data.chunks(MAX_PLAINTEXT_PER_PACKET) {
                // ── Flow control: wait for send window ──
                // The sender must not have more than SEND_WINDOW packets in
                // flight (sent but not yet ACKed). If the window is exhausted,
                // we wait for ACKs from the receiver.
                loop {
                    let current_seq = {
                        let pl = pipeline_send.lock().await;
                        let session = pl.get_session(&sid_send)
                            .ok_or("session not found")?;
                        session.send_seq
                    };

                    let acked = {
                        let guard = last_acked_seq_reader.lock().await;
                        *guard
                    };

                    // Calculate available window.
                    // If we haven't received any ACK yet, allow SEND_WINDOW
                    // packets from the start (bootstrapping the connection).
                    let window_ok = match acked {
                        Some(acked_seq) => current_seq < acked_seq + SEND_WINDOW + 1,
                        None => current_seq < SEND_WINDOW,
                    };

                    if window_ok {
                        break;
                    }

                    // Window exhausted — check for timeout
                    if last_ack_check.elapsed() > SENDER_ACK_TIMEOUT {
                        warn!("sender ACK timeout ({:?} with no window progress)", SENDER_ACK_TIMEOUT);
                        return Err("sender ACK timeout".into());
                    }

                    // Yield briefly to let ACKs arrive
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }

                // Reset the ACK timeout tracker whenever we successfully send
                last_ack_check = Instant::now();

                // Get next sequence number from the session
                let seq = {
                    let mut pl = pipeline_send.lock().await;
                    let session = pl.get_session_mut(&sid_send)
                        .ok_or("session not found")?;
                    session.next_send_seq()
                };

                // Build the framed plaintext: [FRAME_DATA | chunk_bytes...]
                let mut framed = Vec::with_capacity(1 + chunk.len());
                framed.push(FRAME_DATA);
                framed.extend_from_slice(chunk);

                // Encrypt with nonce = 4 zero bytes + 8-byte big-endian seq
                let mut nonce_bytes = [0u8; 12];
                nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
                let nonce = Nonce::from_slice(&nonce_bytes);
                let encrypted = cipher.encrypt(nonce, framed.as_slice())
                    .map_err(|e| format!("encryption error: {}", e))?;

                // Build data header with correct seq and auth tag
                let mut header = DataHeader::new(sid_send, seq);
                let aad = header.aad_bytes();
                header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);

                // Serialize and send
                let mut packet = header.serialize();
                packet.extend_from_slice(&encrypted);
                udp_send.send_to(&packet, peer_addr).await?;
                debug!("ZTLP sent: {} bytes (seq {})", packet.len(), seq);
            }
        }
    };

    // ── ZTLP → TCP direction (receiver) ────────────────────────────────

    let ztlp_to_tcp = async move {
        let mut udp_buf = vec![0u8; 65535];

        // Extract recv key upfront — it doesn't change after handshake
        let (recv_key, send_key_for_acks) = {
            let pl = pipeline_recv.lock().await;
            let session = pl.get_session(&sid_recv)
                .ok_or("session not found for recv key extraction")?;
            (session.recv_key, session.send_key)
        };
        let recv_cipher = ChaCha20Poly1305::new((&recv_key).into());
        let ack_cipher = ChaCha20Poly1305::new((&send_key_for_acks).into());

        // Use BufWriter for TCP to batch small writes and reduce syscalls
        let mut tcp_writer = tokio::io::BufWriter::with_capacity(65536, tcp_writer);

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
            let recv_result = tokio::time::timeout(
                ACK_INTERVAL,
                udp_recv.recv_from(&mut udp_buf),
            ).await;

            match recv_result {
                Ok(Ok((n, _addr))) => {
                    let data = &udp_buf[..n];

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
                            // Initialize reassembly buffer on first data packet.
                            // The first data packet's seq becomes our expected_seq.
                            let reasm = reassembly.get_or_insert_with(|| {
                                debug!("reassembly: initialized with first seq {}", header.packet_seq);
                                ReassemblyBuffer::new(header.packet_seq, REASSEMBLY_MAX_BUFFERED)
                            });

                            // Insert into reassembly buffer
                            if let Some(deliverable) = reasm.insert(header.packet_seq, frame_payload.to_vec()) {
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
                                let acked_seq = u64::from_be_bytes(
                                    frame_payload[..8].try_into().unwrap()
                                );
                                debug!("received ACK for seq {}", acked_seq);
                                let mut guard = last_acked_seq_writer.lock().await;
                                // Only advance, never go backward
                                match *guard {
                                    Some(prev) if acked_seq > prev => *guard = Some(acked_seq),
                                    None => *guard = Some(acked_seq),
                                    _ => {}
                                }
                            }
                        }

                        FRAME_FIN => {
                            // Remote side signaled TCP EOF.
                            info!("received FIN frame — remote TCP stream ended");
                            fin_received = true;

                            // If there are buffered packets, give them time to arrive
                            if let Some(ref reasm) = reassembly {
                                if reasm.buffered_count() > 0 {
                                    debug!("FIN received with {} buffered packets, draining",
                                        reasm.buffered_count());
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

                    // ── Periodic ACK sending ──
                    // Send an ACK when we've delivered enough packets or enough
                    // time has passed. This lets the sender's flow control advance.
                    if packets_since_ack >= ACK_EVERY_PACKETS || last_ack_time.elapsed() >= ACK_INTERVAL {
                        if let Some(ref reasm) = reassembly {
                            if let Some(delivered_seq) = reasm.last_delivered_seq() {
                                // Only send if we have new progress to report
                                if last_acked_value.map_or(true, |prev| delivered_seq > prev) {
                                    send_ack(
                                        &pipeline_recv, &ack_cipher, &send_key_for_acks,
                                        sid_recv, &udp_recv, peer_addr, delivered_seq,
                                    ).await?;
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
                                &pipeline_recv, &ack_cipher, &send_key_for_acks,
                                sid_recv, &udp_recv, peer_addr, delivered_seq,
                            ).await?;
                            last_acked_value = Some(delivered_seq);
                            packets_since_ack = 0;
                            last_ack_time = Instant::now();
                        }
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
        let session = pl.get_session_mut(&session_id)
            .ok_or("session not found for ACK send")?;
        session.next_send_seq()
    };

    // Encrypt
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, ack_frame.as_slice())
        .map_err(|e| format!("ACK encryption error: {}", e))?;

    // Build header
    let mut header = DataHeader::new(session_id, seq);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(send_key, &aad);

    // Send
    let mut packet = header.serialize();
    packet.extend_from_slice(&encrypted);
    udp.send_to(&packet, peer_addr).await?;
    debug!("sent ACK for delivered_seq {} (packet seq {})", delivered_seq, seq);

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
            let end = dst_svc_id.iter().rposition(|&b| b != 0)
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
            name, bytes.len(), MAX_SERVICE_NAME_LEN
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
    let first_colon = s.find(':')
        .ok_or_else(|| format!("invalid --forward argument '{}'. Expected NAME:HOST:PORT or HOST:PORT", s))?;

    let name = &s[..first_colon];
    let addr_str = &s[first_colon + 1..];

    // Validate the name
    if name.is_empty() {
        return Err(format!("empty service name in '{}'", s));
    }
    if name.len() > MAX_SERVICE_NAME_LEN {
        return Err(format!(
            "service name '{}' too long ({} bytes, max {})",
            name, name.len(), MAX_SERVICE_NAME_LEN
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(format!(
            "service name '{}' contains invalid characters (use a-z, 0-9, -, _)",
            name
        ));
    }

    let addr: SocketAddr = addr_str.parse()
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

    let local_port: u16 = parts[0].parse()
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
        let reg = ServiceRegistry::from_forward_args(&[
            "127.0.0.1:22".to_string(),
        ]).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.services.contains_key(DEFAULT_SERVICE));
    }

    #[test]
    fn test_service_registry_multi() {
        let reg = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
            "rdp:127.0.0.1:3389".to_string(),
            "db:127.0.0.1:5432".to_string(),
        ]).unwrap();
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
        ]).unwrap();
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
        ]).unwrap();

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
        let reg = ServiceRegistry::from_forward_args(&[
            "ssh:127.0.0.1:22".to_string(),
        ]).unwrap();

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
}
