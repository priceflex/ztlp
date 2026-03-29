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
}
