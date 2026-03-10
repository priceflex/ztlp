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
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::packet::{SessionId, MAGIC};
use crate::transport::MAX_PACKET_SIZE;

/// Relay connection state — tracks how to reach a peer through a relay.
#[derive(Debug, Clone)]
pub struct RelayConnection {
    /// The relay's UDP address.
    pub relay_addr: SocketAddr,
    /// Our session ID (for the relay to route by).
    pub session_id: SessionId,
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
        })
    }

    /// Extract a SessionID from a raw ZTLP packet.
    ///
    /// Uses HdrLen to discriminate handshake (24 words) vs data (11 words)
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
        } else if hdr_len == 11 {
            // Data header: SessionID at bytes 6..18
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
        let session_id = match Self::extract_session_id(data) {
            Some(sid) => sid,
            None => {
                warn!("relay: could not extract SessionID from packet from {}", from);
                return Ok(false);
            }
        };

        let mut peers = self.peers.lock().await;

        match peers.get(&session_id).cloned() {
            None => {
                // First packet on this SessionID — store sender as pending.
                debug!(
                    "relay: new session {} — first peer is {}",
                    session_id, from
                );
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
                debug!(
                    "relay: forwarded {} bytes {} -> {}",
                    data.len(),
                    from,
                    dest
                );
                Ok(true)
            }
        }
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
