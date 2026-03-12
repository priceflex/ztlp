//! Relay support for ZTLP.
//!
//! A ZTLP relay is a simple UDP forwarder that routes packets by SessionID.
//! The relay never has access to session keys — it only inspects the
//! unencrypted SessionID field in packet headers to determine where to
//! forward each packet.
//!
//! This module provides:
//! - [`RelayConnection`] — client-side relay connection state
//! - [`SimulatedRelay`] — a minimal relay implementation for testing/demos

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::admission::RelayAdmissionToken;
use crate::nat::{
    decode_rv_message, encode_rv_peer_info, is_rendezvous_packet, RendezvousEntry,
    RendezvousMessage,
};
use crate::packet::{SessionId, MAGIC};
use crate::transport::MAX_PACKET_SIZE;

/// Relay connection state — tracks how to reach a peer through a relay.
#[derive(Debug, Clone)]
pub struct RelayConnection {
    /// The relay's UDP address.
    pub relay_addr: SocketAddr,
    /// Our session ID (for the relay to route by).
    pub session_id: SessionId,
    /// Admission token received from the ingress relay (if any).
    pub admission_token: Option<RelayAdmissionToken>,
}

impl RelayConnection {
    /// Create a new relay connection (without an admission token).
    pub fn new(relay_addr: SocketAddr, session_id: SessionId) -> Self {
        Self {
            relay_addr,
            session_id,
            admission_token: None,
        }
    }

    /// Set the admission token (received from the ingress relay).
    pub fn set_token(&mut self, token: RelayAdmissionToken) {
        self.admission_token = Some(token);
    }

    /// Get a reference to the current admission token.
    pub fn get_token(&self) -> Option<&RelayAdmissionToken> {
        self.admission_token.as_ref()
    }

    /// Check if we have a valid (non-expired) admission token.
    pub fn has_valid_token(&self) -> bool {
        self.admission_token
            .as_ref()
            .map(|t| !t.is_expired())
            .unwrap_or(false)
    }
}

/// Peer tracking state for one SessionID at the relay.
#[derive(Debug, Clone)]
enum PeerState {
    /// Only one peer has sent a packet so far.
    Pending { first_addr: SocketAddr },
    /// Both peers are known — we can forward in both directions.
    Paired {
        addr_a: SocketAddr,
        addr_b: SocketAddr,
    },
}

/// A simulated ZTLP relay — forwards packets by SessionID.
///
/// This mimics what the Elixir relay server will do in production:
/// inspect the SessionID from the packet header and forward the packet
/// to the other peer in the session. The relay never holds session keys
/// and cannot decrypt any payload.
pub struct SimulatedRelay {
    /// The bound UDP socket.
    pub socket: Arc<UdpSocket>,
    /// Local bind address.
    pub local_addr: SocketAddr,
    /// Session routing table: SessionID → peer addresses.
    peers: Arc<Mutex<HashMap<SessionId, PeerState>>>,
    /// Rendezvous table for NAT traversal coordination.
    rendezvous: Arc<Mutex<HashMap<[u8; 32], RendezvousEntry>>>,
}

impl SimulatedRelay {
    /// Bind a new simulated relay to the given address.
    pub async fn bind(addr: &str) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        info!("Simulated relay bound to {}", local_addr);

        Ok(Self {
            socket: Arc::new(socket),
            local_addr,
            peers: Arc::new(Mutex::new(HashMap::new())),
            rendezvous: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Extract a SessionID from a raw ZTLP packet.
    ///
    /// Uses HdrLen to discriminate handshake (24 words) vs data (12 words)
    /// headers, then reads the SessionID from the appropriate offset.
    fn extract_session_id(data: &[u8]) -> Option<SessionId> {
        // Need at least 4 bytes for Magic + VerHdrLen
        if data.len() < 4 {
            return None;
        }

        let magic = u16::from_be_bytes([data[0], data[1]]);
        if magic != MAGIC {
            return None;
        }

        let ver_hdrlen = u16::from_be_bytes([data[2], data[3]]);
        let hdr_len = ver_hdrlen & 0x0FFF;

        if hdr_len == 24 {
            // Handshake header: SessionID at bytes 11..23
            if data.len() < 23 {
                return None;
            }
            let mut sid = [0u8; 12];
            sid.copy_from_slice(&data[11..23]);
            Some(SessionId(sid))
        } else if hdr_len == 12 {
            // Data header (46 bytes): SessionID at bytes 6..18
            if data.len() < 18 {
                return None;
            }
            let mut sid = [0u8; 12];
            sid.copy_from_slice(&data[6..18]);
            Some(SessionId(sid))
        } else {
            warn!("unknown header length: {}", hdr_len);
            None
        }
    }

    /// Process one incoming packet: learn peers and forward.
    ///
    /// Returns `Ok(true)` if the packet was forwarded, `Ok(false)` if it
    /// was only used to learn a peer address (first packet on a new session).
    pub async fn process_one(&self, data: &[u8], from: SocketAddr) -> Result<bool, std::io::Error> {
        // Check for rendezvous packets first (before ZTLP header parsing)
        if is_rendezvous_packet(data) {
            return self.process_rendezvous(data, from).await;
        }

        let session_id = match Self::extract_session_id(data) {
            Some(sid) => sid,
            None => {
                warn!(
                    "relay: could not extract SessionID from packet from {}",
                    from
                );
                return Ok(false);
            }
        };

        let mut peers = self.peers.lock().await;

        match peers.get(&session_id).cloned() {
            None => {
                // First packet on this SessionID — store sender as pending.
                debug!("relay: new session {} — first peer is {}", session_id, from);
                peers.insert(session_id, PeerState::Pending { first_addr: from });
                Ok(false)
            }
            Some(PeerState::Pending { first_addr }) => {
                if first_addr == from {
                    // Same peer sent again before the other connected — still pending.
                    debug!(
                        "relay: session {} — same peer {} sent again (still pending)",
                        session_id, from
                    );
                    Ok(false)
                } else {
                    // Second peer appeared — pair them and forward.
                    debug!(
                        "relay: session {} — paired {} <-> {}",
                        session_id, first_addr, from
                    );
                    peers.insert(
                        session_id,
                        PeerState::Paired {
                            addr_a: first_addr,
                            addr_b: from,
                        },
                    );

                    // Forward this packet to the first peer.
                    self.socket.send_to(data, first_addr).await?;
                    debug!(
                        "relay: forwarded {} bytes {} -> {}",
                        data.len(),
                        from,
                        first_addr
                    );
                    Ok(true)
                }
            }
            Some(PeerState::Paired { addr_a, addr_b }) => {
                // Forward to the other peer.
                let dest = if from == addr_a { addr_b } else { addr_a };
                self.socket.send_to(data, dest).await?;
                debug!("relay: forwarded {} bytes {} -> {}", data.len(), from, dest);
                Ok(true)
            }
        }
    }

    /// Process a rendezvous packet for NAT traversal coordination.
    ///
    /// When the first peer registers, we store their info. When the second
    /// peer registers with the same rendezvous ID, we send each peer the
    /// other's mapped endpoint information.
    async fn process_rendezvous(
        &self,
        data: &[u8],
        from: SocketAddr,
    ) -> Result<bool, std::io::Error> {
        let msg = match decode_rv_message(data) {
            Ok(m) => m,
            Err(e) => {
                warn!("relay: invalid rendezvous packet from {}: {}", from, e);
                return Ok(false);
            }
        };

        match msg {
            RendezvousMessage::Register {
                rendezvous_id,
                mapped_addr,
            } => {
                let mut table = self.rendezvous.lock().await;

                // Purge expired entries
                table.retain(|_, entry| !entry.is_expired());

                if let Some(existing) = table.remove(&rendezvous_id) {
                    // Second peer arrived — exchange endpoint info
                    if existing.addr == from {
                        // Same peer re-registering — put it back
                        debug!(
                            "relay: rendezvous {} — same peer {} re-registered",
                            hex::encode(&rendezvous_id[..8]),
                            from
                        );
                        table.insert(rendezvous_id, existing);
                        return Ok(false);
                    }

                    debug!(
                        "relay: rendezvous {} — pairing {} <-> {}",
                        hex::encode(&rendezvous_id[..8]),
                        existing.addr,
                        from
                    );

                    // Send first peer the second peer's info
                    let info_for_first = encode_rv_peer_info(&rendezvous_id, mapped_addr);
                    self.socket.send_to(&info_for_first, existing.addr).await?;

                    // Send second peer the first peer's info
                    let info_for_second = encode_rv_peer_info(&rendezvous_id, existing.mapped_addr);
                    self.socket.send_to(&info_for_second, from).await?;

                    info!(
                        "relay: rendezvous {} complete — exchanged endpoints",
                        hex::encode(&rendezvous_id[..8])
                    );
                    Ok(true)
                } else {
                    // First peer — store and wait
                    debug!(
                        "relay: rendezvous {} — first peer {} (mapped: {})",
                        hex::encode(&rendezvous_id[..8]),
                        from,
                        mapped_addr
                    );
                    table.insert(
                        rendezvous_id,
                        RendezvousEntry {
                            addr: from,
                            mapped_addr,
                            registered_at: Instant::now(),
                        },
                    );
                    Ok(false)
                }
            }
            _ => {
                debug!(
                    "relay: ignoring non-register rendezvous message from {}",
                    from
                );
                Ok(false)
            }
        }
    }

    /// Get the number of active rendezvous entries (for testing).
    pub async fn rendezvous_count(&self) -> usize {
        let table = self.rendezvous.lock().await;
        table.len()
    }

    /// Run the relay loop — receive and forward packets indefinitely.
    ///
    /// This blocks forever (or until the task is cancelled).
    pub async fn run(&self) -> Result<(), std::io::Error> {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            let data = &buf[..len];
            if let Err(e) = self.process_one(data, from).await {
                warn!("relay: error processing packet from {}: {}", from, e);
            }
        }
    }
}
