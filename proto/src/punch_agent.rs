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

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::identity::NodeId;
use crate::punch::encode_punch_report;

/// Default interval for the keepalive task: 25 seconds — chosen to sit
/// comfortably under common NAT idle timeouts (30-60s on consumer
/// routers, 90s+ on enterprise gear). Re-exported from
/// [`crate::punch::DEFAULT_KEEPALIVE_INTERVAL`] but documented separately
/// here because that's the punch-client constant; the gateway keepalive
/// is a different role with the same numerical value.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

/// Gateway-side hole-punch agent.
///
/// Owns a clone of the gateway's listener socket (`Arc<UdpSocket>`) plus
/// the NS address and the gateway's own NodeId, so the agent can send
/// `PUNCH_REPORT` keepalives from the same NAT mapping that QUIC traffic
/// uses, and respond to `PUNCH_NOTIFY` packets dispatched to it.
pub struct PunchAgent {
    /// Shared clone of the gateway's listener socket. Punch keepalives and
    /// punch responses send from this socket so they share the same
    /// (src_ip, src_port) NAT mapping that QUIC traffic uses.
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
    pub fn new(socket: Arc<UdpSocket>, ns_addr: SocketAddr, node_id: NodeId) -> Self {
        Self {
            socket,
            ns_addr,
            node_id,
        }
    }

    /// Spawn a background task that emits a `PUNCH_REPORT` (`0x0C`) packet
    /// to the NS server every `interval`.
    ///
    /// # Why this exists
    ///
    /// NS learns a node's `:learned` endpoint from the source IP:port of
    /// any UDP packet that node sends. Without periodic refresh, the
    /// NAT mapping behind which the gateway lives goes stale within
    /// 30-60s on most consumer routers and NS's `:learned` endpoint
    /// becomes a dead address — incoming `PUNCH_NOTIFY` packets fail
    /// to find a path home.
    ///
    /// The first report fires immediately on `tick().await` (tokio's
    /// `interval` is ready on first poll); subsequent reports fire at
    /// `interval` cadence. Send failures are logged at WARN but do not
    /// terminate the task — transient network issues should not require
    /// gateway restart.
    ///
    /// # Returns
    ///
    /// A `JoinHandle<()>` to the spawned task. Dropping the handle does
    /// not cancel the task; explicit `abort()` on the handle stops it.
    /// In production the handle lives for the gateway's lifetime and is
    /// implicitly cleaned up on process exit; in tests, abort it to
    /// avoid leaking the task between test cases.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use std::time::Duration;
    /// use tokio::net::UdpSocket;
    /// use ztlp_proto::identity::NodeId;
    /// use ztlp_proto::punch_agent::PunchAgent;
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// let socket = Arc::new(UdpSocket::bind("0.0.0.0:23095").await?);
    /// let ns_addr = "16.147.41.195:23096".parse().unwrap();
    /// let agent = PunchAgent::new(socket, ns_addr, NodeId([0u8; 16]));
    /// let _keepalive = agent.start_keepalive(Duration::from_secs(25));
    /// // Keepalive runs in background; agent can still be used for
    /// // dispatcher (H4) or other operations.
    /// # Ok(())
    /// # }
    /// ```
    pub fn start_keepalive(&self, interval: Duration) -> JoinHandle<()> {
        let socket = self.socket.clone();
        let ns_addr = self.ns_addr;
        let node_id = self.node_id;
        // Pre-encode the packet — the keepalive contents are static (no
        // reported endpoints; NS learns the endpoint from the source
        // address of this very packet).
        let pkt = encode_punch_report(&node_id, &[]);

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // `interval`'s first tick is immediate; that's the behavior
            // we want — register with NS as soon as the keepalive starts.
            loop {
                ticker.tick().await;
                if let Err(e) = socket.send_to(&pkt, ns_addr).await {
                    // Don't tear down on send failure — NAT mapping is
                    // refreshed best-effort. Log + carry on.
                    tracing::warn!(
                        target: "ztlp::punch_agent",
                        error = %e,
                        ns_addr = %ns_addr,
                        "punch keepalive send failed"
                    );
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H1 — verify the agent constructs and exposes its fields.
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

    /// H2 — verify the keepalive task sends a well-formed PUNCH_REPORT
    /// on its first tick (within 500ms of start, since tokio::interval
    /// fires immediately on first tick).
    ///
    /// We don't use `start_paused = true` here because tokio::interval's
    /// first tick is documented as immediate-on-first-poll, not "after
    /// interval has elapsed" — so a real-clock test with a short timeout
    /// is the most honest validation of the production behavior.
    #[tokio::test]
    async fn keepalive_sends_punch_report_on_first_tick() {
        // Fake NS receiver — agent will send to this address.
        let ns_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns_addr = ns_sock.local_addr().unwrap();

        // Gateway socket — what the keepalive sends from.
        let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let node_id = NodeId([0x42; 16]);

        let agent = PunchAgent::new(gw_sock, ns_addr, node_id);
        let handle = agent.start_keepalive(Duration::from_secs(25));

        // Receive the first keepalive within 500ms.
        let mut buf = [0u8; 512];
        let recv = tokio::time::timeout(Duration::from_millis(500), ns_sock.recv_from(&mut buf))
            .await
            .expect("keepalive did not arrive within 500ms");
        let (n, _src) = recv.expect("recv_from returned io error");

        // Wire format: 0x0C + 16-byte node_id + 1-byte reported_count (0)
        assert!(n >= 18, "PUNCH_REPORT too short: {} bytes", n);
        assert_eq!(buf[0], 0x0C, "first byte must be NS_PUNCH_REPORT");
        assert_eq!(&buf[1..17], &node_id.0[..], "node_id must match");
        assert_eq!(
            buf[17], 0,
            "reported_count should be 0 (NS learns endpoint)"
        );

        // Clean up the keepalive task — without abort, it would keep
        // ticking in the background and interact with later tests.
        handle.abort();
    }

    /// H2 — verify the keepalive ticks repeatedly at the configured
    /// interval, not just once. Uses a short interval (100ms) so the
    /// test stays under a second.
    #[tokio::test]
    async fn keepalive_ticks_repeatedly() {
        let ns_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns_addr = ns_sock.local_addr().unwrap();
        let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let agent = PunchAgent::new(gw_sock, ns_addr, NodeId([0x99; 16]));
        let handle = agent.start_keepalive(Duration::from_millis(100));

        // Receive at least 3 keepalives within 600ms (first immediate,
        // then 100ms, then 200ms — comfortably under 600ms even with
        // scheduling jitter).
        let mut count = 0usize;
        let mut buf = [0u8; 64];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
        while tokio::time::Instant::now() < deadline && count < 3 {
            if tokio::time::timeout(Duration::from_millis(150), ns_sock.recv_from(&mut buf))
                .await
                .is_ok()
            {
                count += 1;
            }
        }
        handle.abort();
        assert!(count >= 3, "expected >=3 keepalives, got {}", count);
    }
}
