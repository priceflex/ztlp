//! UDP transport layer for ZTLP.
//!
//! Handles async UDP socket operations using Tokio.
//! The receive path feeds into the three-layer pipeline.
//! The send path looks up sessions, encrypts, serializes, and sends.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use crate::error::TransportError;
use crate::packet::{DataHeader, SessionId, ZtlpPacket};
use crate::pipeline::{compute_header_auth_tag, AdmissionResult, Pipeline};

/// Maximum UDP datagram size we'll handle.
pub const MAX_PACKET_SIZE: usize = 65535;

/// A ZTLP transport node — binds a UDP socket and processes packets.
pub struct TransportNode {
    /// The bound UDP socket.
    pub socket: Arc<UdpSocket>,
    /// Local bind address.
    pub local_addr: SocketAddr,
    /// The admission pipeline (shared, behind a mutex for async safety).
    pub pipeline: Arc<Mutex<Pipeline>>,
    /// PLPMTUD state machine for Path MTU Discovery (RFC 8899).
    pub pmtud: PmtudState,
}

impl TransportNode {
    /// Bind a new transport node to the given address.
    pub async fn bind(addr: &str) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        info!("ZTLP node bound to {}", local_addr);

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            pipeline: Arc::new(Mutex::new(Pipeline::new())),
            pmtud: PmtudState::new(),
        })
    }

    /// Send raw bytes to a destination.
    pub async fn send_raw(&self, data: &[u8], dest: SocketAddr) -> Result<usize, TransportError> {
        let sent = self.socket.send_to(data, dest).await?;
        debug!("sent {} bytes to {}", sent, dest);
        Ok(sent)
    }

    /// Receive a raw packet. Returns (data, sender_address).
    pub async fn recv_raw(&self) -> Result<(Vec<u8>, SocketAddr), TransportError> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        debug!("received {} bytes from {}", len, addr);
        Ok((buf, addr))
    }

    /// Receive a batch of raw packets using GRO when available.
    ///
    /// Returns multiple `(data, sender_address)` pairs from a single receive
    /// call. When GRO is not available, this returns a single-element vector
    /// (same as `recv_raw()`).
    pub async fn recv_batch(
        &self,
        gro_receiver: &mut crate::gso::GroReceiver,
    ) -> Result<Vec<(Vec<u8>, SocketAddr)>, TransportError> {
        let batch = gro_receiver.recv().await?;
        let mut results = Vec::with_capacity(batch.len());
        for segment in batch.segments() {
            let data = batch.buffer()[segment.offset..segment.offset + segment.len].to_vec();
            debug!(
                "received {} bytes from {} (batch)",
                segment.len, segment.addr
            );
            results.push((data, segment.addr));
        }
        Ok(results)
    }

    /// Send an encrypted data packet through an established session.
    ///
    /// Builds a compact data header, computes the HeaderAuthTag,
    /// encrypts the payload, and sends.
    /// Send an encrypted data packet and return the assigned packet sequence number.
    ///
    /// The returned `u64` is the transport-level sequence number assigned to this
    /// packet by the session. Callers that need ACK tracking (e.g., `SendController`)
    /// use this to correlate gateway ACK frames back to in-flight packets.
    pub async fn send_data(
        &self,
        session_id: SessionId,
        plaintext: &[u8],
        dest: SocketAddr,
    ) -> Result<u64, TransportError> {
        let mut pipeline = self.pipeline.lock().await;
        let session = pipeline.get_session_mut(&session_id).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "session not found")
        })?;

        let seq = session.next_send_seq();
        let send_key = session.send_key;

        // Encrypt the payload
        let cipher = ChaCha20Poly1305::new((&send_key).into());
        // Use packet sequence as nonce (padded to 12 bytes)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&seq.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Build the data header
        let mut header = DataHeader::new(session_id, seq);

        // Compute HeaderAuthTag over the header AAD
        let aad = header.aad_bytes();
        header.header_auth_tag = compute_header_auth_tag(&send_key, &aad);

        // Assemble the packet
        let packet = ZtlpPacket::Data {
            header,
            payload: encrypted,
        };
        let data = packet.serialize();

        drop(pipeline);
        self.send_raw(&data, dest).await?;
        Ok(seq)
    }

    /// Send multiple raw packets to a destination using batched I/O.
    ///
    /// Uses GSO/sendmmsg when available for better throughput on bulk sends.
    /// Falls back to individual send_to calls on unsupported platforms.
    pub async fn send_batch(
        &self,
        packets: &[Vec<u8>],
        dest: SocketAddr,
    ) -> Result<usize, TransportError> {
        if packets.is_empty() {
            return Ok(0);
        }
        let batch_sender =
            crate::batch::BatchSender::new(self.socket.clone(), crate::gso::GsoMode::Auto);
        let sent = batch_sender.send_batch(packets, dest).await?;
        debug!("batch sent {} packets to {}", sent, dest);
        Ok(sent)
    }

    /// Send encrypted data through a relay.
    ///
    /// The packet is identical to a direct send — the relay just forwards
    /// by SessionID. The only difference is we send to `relay_addr` instead
    /// of the peer's direct address.
    pub async fn send_data_via_relay(
        &self,
        session_id: SessionId,
        plaintext: &[u8],
        relay_addr: SocketAddr,
    ) -> Result<u64, TransportError> {
        // The relay is transparent — same packet format, different destination.
        self.send_data(session_id, plaintext, relay_addr).await
    }

    /// Receive and process a packet through the pipeline.
    ///
    /// Returns the decrypted payload if the packet passes all checks,
    /// along with the sender's address.
    pub async fn recv_data(&self) -> Result<Option<(Vec<u8>, SocketAddr)>, TransportError> {
        let (data, addr) = self.recv_raw().await?;

        let pipeline = self.pipeline.lock().await;
        let result = pipeline.process(&data);

        match result {
            AdmissionResult::Pass => {
                // Try to decrypt as a data packet
                if let Ok(header) = DataHeader::deserialize(&data) {
                    if let Some(session) = pipeline.get_session(&header.session_id) {
                        let encrypted_payload = &data[crate::packet::DATA_HEADER_SIZE..];
                        let recv_key = session.recv_key;

                        let cipher = ChaCha20Poly1305::new((&recv_key).into());
                        let mut nonce_bytes = [0u8; 12];
                        nonce_bytes[4..12].copy_from_slice(&header.packet_seq.to_le_bytes());
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        match cipher.decrypt(nonce, encrypted_payload) {
                            Ok(plaintext) => {
                                info!(
                                    "decrypted {} bytes from session {}",
                                    plaintext.len(),
                                    header.session_id
                                );
                                return Ok(Some((plaintext, addr)));
                            }
                            Err(e) => {
                                warn!("payload decryption failed: {}", e);
                                return Ok(None);
                            }
                        }
                    }
                }
                // Pass but not a data packet — could be handshake
                Ok(Some((data, addr)))
            }
            AdmissionResult::Drop | AdmissionResult::RateLimit => {
                debug!("packet from {} dropped by pipeline", addr);
                Ok(None)
            }
        }
    }

    /// Get the current effective MTU for sending data.
    ///
    /// Returns the PLPMTUD-discovered MTU, which starts at BASE_PLPMTU (1200)
    /// and may increase as probes succeed.
    pub fn max_payload_size(&self) -> u16 {
        self.pmtud.effective_mtu()
    }
}

// ─── PLPMTUD (RFC 8899) ────────────────────────────────────────────────────

use crate::tunnel::{FRAME_PMTU_PROBE, FRAME_PMTU_PROBE_ACK};

/// Base Path Layer PMTU — the safe minimum that always works.
/// This is the IPv6 minimum MTU (1280) minus headers, matching the current
/// hardcoded MAX_PAYLOAD of 1200.
pub const BASE_PLPMTU: u16 = 1200;

/// Standard PLPMTUD probe ladder (ascending).
///
/// - 1200: IPv6 minimum (current baseline)
/// - 1280: Common with tunneling overhead
/// - 1400: Safe for most paths
/// - 1452: Common PPPoE (1500 - 48)
/// - 1472: Ethernet - IP header (20) - UDP header (8) — max for standard Ethernet
/// - 1500: Full Ethernet MTU
pub const PROBE_SIZES: &[u16] = &[1200, 1280, 1400, 1452, 1472, 1500];

/// Maximum consecutive probe failures before stopping at current MTU.
const PLPMTUD_MAX_FAILURES: u8 = 3;

/// Interval between probes during active search (seconds).
const PLPMTUD_SEARCH_INTERVAL_SECS: u64 = 10;

/// Interval between re-validation probes in SearchComplete state (seconds).
const PLPMTUD_MAINTENANCE_INTERVAL_SECS: u64 = 600;

/// Phase of the PLPMTUD state machine (RFC 8899 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmtudPhase {
    /// Using BASE_PLPMTU, haven't started probing yet.
    Base,
    /// Actively searching for a larger MTU.
    Searching,
    /// Found a working MTU, periodic re-validation.
    SearchComplete,
    /// Probe failed, backing off.
    Error,
}

/// Packetization Layer Path MTU Discovery state machine (RFC 8899).
///
/// Instead of relying on ICMP (unreliable with middleboxes), this probes
/// the path by sending progressively larger packets and tracking what gets
/// acknowledged.
#[derive(Debug)]
pub struct PmtudState {
    /// Current effective MTU (starts at BASE_PLPMTU = 1200).
    effective_mtu: u16,
    /// State machine phase.
    phase: PmtudPhase,
    /// Probe sequence number (for matching ACKs).
    probe_seq: u16,
    /// Number of consecutive probe failures at current size.
    probe_failures: u8,
    /// Maximum consecutive failures before giving up on a size.
    max_failures: u8,
    /// Probe sizes to try (ascending).
    probe_sizes: Vec<u16>,
    /// Index into probe_sizes — the next size to probe.
    probe_index: usize,
    /// Timer: when to send next probe.
    next_probe_time: std::time::Instant,
}

impl PmtudState {
    /// Create a new PLPMTUD state machine.
    ///
    /// Starts at BASE_PLPMTU with the first probe scheduled after the
    /// search interval (10s) to allow the connection to stabilize.
    pub fn new() -> Self {
        Self {
            effective_mtu: BASE_PLPMTU,
            phase: PmtudPhase::Base,
            probe_seq: 0,
            probe_failures: 0,
            max_failures: PLPMTUD_MAX_FAILURES,
            probe_sizes: PROBE_SIZES.to_vec(),
            probe_index: 1, // Start probing at index 1 (1280); index 0 (1200) is the baseline
            next_probe_time: std::time::Instant::now()
                + std::time::Duration::from_secs(PLPMTUD_SEARCH_INTERVAL_SECS),
        }
    }

    /// Get current effective MTU for sending data.
    pub fn effective_mtu(&self) -> u16 {
        self.effective_mtu
    }

    /// Get the current phase.
    pub fn phase(&self) -> PmtudPhase {
        self.phase
    }

    /// Get the current probe sequence number.
    pub fn probe_seq(&self) -> u16 {
        self.probe_seq
    }

    /// Get the number of consecutive probe failures.
    pub fn probe_failures(&self) -> u8 {
        self.probe_failures
    }

    /// Get the current probe index.
    pub fn probe_index(&self) -> usize {
        self.probe_index
    }

    /// Check if it's time to send a probe.
    pub fn should_probe(&self) -> bool {
        std::time::Instant::now() >= self.next_probe_time
    }

    /// Create a probe packet (returns bytes to send).
    ///
    /// Wire format: `[FRAME_PMTU_PROBE | probe_size(2 BE) | probe_seq(2 BE) | 0xAA padding...]`
    /// The total packet is padded to `probe_size` bytes.
    pub fn create_probe(&mut self) -> Vec<u8> {
        self.probe_seq = self.probe_seq.wrapping_add(1);
        let size = self.probe_sizes[self.probe_index];
        let mut probe = Vec::with_capacity(size as usize);
        probe.push(FRAME_PMTU_PROBE);
        probe.extend_from_slice(&size.to_be_bytes());
        probe.extend_from_slice(&self.probe_seq.to_be_bytes());
        // Pad to target size with 0xAA fill pattern
        probe.resize(size as usize, 0xAA);
        probe
    }

    /// Handle a probe ACK — returns true if the effective MTU was updated.
    ///
    /// Validates that the ACK matches the current outstanding probe (by
    /// sequence number and size). On success, updates the effective MTU
    /// and advances to the next probe size or transitions to SearchComplete.
    pub fn handle_probe_ack(&mut self, size: u16, seq: u16) -> bool {
        if seq != self.probe_seq {
            return false;
        }
        if self.probe_index >= self.probe_sizes.len() {
            return false;
        }
        if size != self.probe_sizes[self.probe_index] {
            return false;
        }

        // Probe succeeded — update effective MTU
        self.effective_mtu = size;
        self.probe_failures = 0;

        // Try next size
        if self.probe_index + 1 < self.probe_sizes.len() {
            self.probe_index += 1;
            self.phase = PmtudPhase::Searching;
            self.next_probe_time = std::time::Instant::now()
                + std::time::Duration::from_secs(PLPMTUD_SEARCH_INTERVAL_SECS);
        } else {
            // Reached the top of the ladder
            self.phase = PmtudPhase::SearchComplete;
            self.next_probe_time = std::time::Instant::now()
                + std::time::Duration::from_secs(PLPMTUD_MAINTENANCE_INTERVAL_SECS);
        }
        true
    }

    /// Handle a probe timeout (no ACK received within the expected window).
    ///
    /// Increments the failure counter. After `max_failures` consecutive
    /// failures at the current size, transitions to SearchComplete (the
    /// current effective MTU is the best we can do).
    pub fn handle_probe_timeout(&mut self) {
        self.probe_failures += 1;
        if self.probe_failures >= self.max_failures {
            // This size doesn't work — stop searching
            self.phase = PmtudPhase::SearchComplete;
            self.next_probe_time = std::time::Instant::now()
                + std::time::Duration::from_secs(PLPMTUD_MAINTENANCE_INTERVAL_SECS);
        } else {
            // Retry same size
            self.next_probe_time = std::time::Instant::now()
                + std::time::Duration::from_secs(PLPMTUD_SEARCH_INTERVAL_SECS);
        }
    }

    /// Check if a probe is pending (sent but not yet acknowledged or timed out).
    ///
    /// Returns true when in the Searching phase and we haven't exhausted
    /// the failure limit for the current probe size.
    pub fn is_probe_pending(&self) -> bool {
        matches!(self.phase, PmtudPhase::Searching) && self.probe_failures < self.max_failures
    }

    /// Create a probe ACK packet for a received probe.
    ///
    /// Wire format: `[FRAME_PMTU_PROBE_ACK | probe_size(2 BE) | probe_seq(2 BE)]`
    pub fn create_probe_ack(probe_size: u16, probe_seq: u16) -> Vec<u8> {
        let mut ack = Vec::with_capacity(5);
        ack.push(FRAME_PMTU_PROBE_ACK);
        ack.extend_from_slice(&probe_size.to_be_bytes());
        ack.extend_from_slice(&probe_seq.to_be_bytes());
        ack
    }

    /// Parse a PMTU probe frame payload (after the frame type byte).
    ///
    /// Returns `(probe_size, probe_seq)` or `None` if malformed.
    pub fn parse_probe_payload(payload: &[u8]) -> Option<(u16, u16)> {
        if payload.len() < 4 {
            return None;
        }
        let probe_size = u16::from_be_bytes([payload[0], payload[1]]);
        let probe_seq = u16::from_be_bytes([payload[2], payload[3]]);
        Some((probe_size, probe_seq))
    }
}

impl Default for PmtudState {
    fn default() -> Self {
        Self::new()
    }
}
