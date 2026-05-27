//! Gateway-side hole-punch agent — keepalives + responder dispatch.
//!
//! # Overview
//!
//! `PunchAgent` is the missing piece that makes NS-coordinated hole punching
//! actually work end-to-end. It lives next to the gateway's QUIC listener
//! socket and:
//!
//! 1. **Registers** the gateway's real listener endpoint with NS by sending
//!    periodic `PUNCH_REPORT` (`0x0C`) packets — these double as NAT-mapping
//!    keepalives (default 25s, below the 30-60s NAT timeout window).
//! 2. **Responds** to incoming `PUNCH_NOTIFY` (`0x0B`) packets by firing
//!    `PUNCH_BYTE` (`0x00`) at the requester's reported endpoints, opening
//!    the return path through both peers' NATs so the subsequent QUIC
//!    handshake can traverse.
//!
//! Without `PunchAgent`, the wire protocol in [`crate::punch`] cannot work
//! end-to-end — the gateway has no presence at NS from its listener socket
//! (and `ztlp ns register` uses a separate ephemeral socket whose NAT
//! mapping is meaningless for punch packets).
//!
//! # Architecture
//!
//! Gateway shares a single UDP socket between Quinn (QUIC datagrams) and
//! `PunchAgent` (keepalives + punch responses) via `Arc<UdpSocket>`. Inbound
//! packet demultiplexing happens upstream in `PunchSocket` (Task H3 — a
//! [`quinn::AsyncUdpSocket`] wrapper that strips punch-protocol bytes
//! before Quinn sees them).
//!
//! # Design rationale
//!
//! Why a struct instead of a free function:
//! - The agent owns durable state (socket, NS address, node id, task handles)
//!   that needs the same lifetime as the gateway listener.
//! - Tests can construct a `PunchAgent` against a fake-NS socket without
//!   spinning up the full CLI binary.
//! - Future expansion (e.g. exposing `report_endpoints` for STUN-discovered
//!   public addresses to refresh registration) lands cleanly as additional
//!   methods.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::identity::NodeId;

/// Gateway-side hole-punch agent.
///
/// Owns a clone of the gateway's listener socket (`Arc<UdpSocket>`) plus
/// the NS address and the gateway's own NodeId, so the agent can send
/// `PUNCH_REPORT` keepalives from the same NAT mapping that QUIC traffic
/// uses, and respond to `PUNCH_NOTIFY` packets dispatched to it.
///
/// # Field visibility
///
/// `socket` is `pub(crate)` because the dispatcher implementation (H4)
/// inside this module needs direct access to send punch bytes. External
/// callers cannot poke the socket directly — they must go through the
/// agent's public API. `ns_addr` and `node_id` are `pub` for inspection
/// in tests and diagnostics.
pub struct PunchAgent {
    /// Shared clone of the gateway's listener socket. Punch keepalives and
    /// punch responses send from this socket so they share the same
    /// (src_ip, src_port) NAT mapping that QUIC traffic uses.
    ///
    /// `#[allow(dead_code)]` here is temporary: this field becomes the
    /// keepalive sender in H2 and the punch-responder sender in H4. Once
    /// `start_keepalive` lands, this allow comes off.
    #[allow(dead_code)]
    pub(crate) socket: Arc<UdpSocket>,

    /// Address of the ZTLP-NS server used to coordinate punching.
    pub ns_addr: SocketAddr,

    /// This gateway's NodeId — embedded in `PUNCH_REPORT` so NS can index
    /// the endpoint mapping by node.
    pub node_id: NodeId,
}

impl PunchAgent {
    /// Construct a new agent over the given shared socket, NS address,
    /// and node identity.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use tokio::net::UdpSocket;
    /// use ztlp_proto::identity::NodeId;
    /// use ztlp_proto::punch_agent::PunchAgent;
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// let socket = Arc::new(UdpSocket::bind("0.0.0.0:23095").await?);
    /// let ns_addr = "16.147.41.195:23096".parse().unwrap();
    /// let node_id = NodeId([0u8; 16]);
    /// let agent = PunchAgent::new(socket, ns_addr, node_id);
    /// assert_eq!(agent.ns_addr, ns_addr);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(socket: Arc<UdpSocket>, ns_addr: SocketAddr, node_id: NodeId) -> Self {
        Self {
            socket,
            ns_addr,
            node_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H1 — verify the agent constructs and exposes its fields.
    /// Smoke test that the public surface is wired up.
    #[tokio::test]
    async fn punch_agent_constructs_with_socket_and_ns_addr() {
        let sock = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind ephemeral test socket"),
        );
        let ns_addr: SocketAddr = "127.0.0.1:23096".parse().unwrap();
        let node_id = NodeId([0xAA; 16]);

        let agent = PunchAgent::new(sock.clone(), ns_addr, node_id);

        assert_eq!(agent.ns_addr, ns_addr);
        assert_eq!(agent.node_id, node_id);
        // Socket cloned-in is the same kernel socket — Arc strong-count > 1
        assert!(Arc::strong_count(&sock) >= 2);
    }
}
