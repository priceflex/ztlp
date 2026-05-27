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
use crate::punch::{decode_punch_notify, encode_punch_report, respond_to_punch, PeerEndpoint};

/// Default keepalive cadence — kept in sync with
/// [`crate::punch::DEFAULT_KEEPALIVE_INTERVAL`] (10 s as of v0.30.12).
/// 10 s comfortably stays under typical SD-WAN / conntrack timeouts
/// (30-120 s); Steve picked this on 2026-05-27 after the Z2LS bench
/// observed stalls at the wider 25 s cadence.
///
/// Re-declared here (rather than re-exported) because the gateway
/// keepalive is a different role from the punch-client keepalive even
/// though they currently share a numerical value.
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

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

    /// Spawn a background task that consumes intercepted `PUNCH_NOTIFY`
    /// packets from `intercept_rx` and invokes the gateway-side
    /// punch responder for each.
    ///
    /// # Why this exists
    ///
    /// [`crate::punch_socket::PunchSocket`] strips `0x0B PUNCH_NOTIFY`
    /// out of the inbound packet stream before Quinn sees it, and forwards
    /// the payload to an unbounded channel. This dispatcher consumes
    /// that channel: for each notification it decodes the requester
    /// NodeId + endpoints and fires [`crate::punch::respond_to_punch`]
    /// against the requester's endpoints, opening the NAT pinhole so
    /// the requester's subsequent QUIC handshake can traverse.
    ///
    /// # Returns
    ///
    /// `JoinHandle<()>` for the dispatcher task. The task runs until
    /// the channel sender is dropped (i.e. the underlying `PunchSocket`
    /// is destroyed) at which point the receiver yields `None` and the
    /// task exits cleanly. The caller can also `abort()` the handle for
    /// graceful shutdown.
    ///
    /// # Concurrency
    ///
    /// Each decoded notification spawns a fresh responder task — multiple
    /// concurrent punch attempts (e.g. from several different clients)
    /// don't serialize through one responder. This matters in production
    /// where a busy gateway may field punch attempts from many clients
    /// simultaneously.
    pub fn start_dispatcher(
        &self,
        mut intercept_rx: tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
        responder_duration: Duration,
    ) -> JoinHandle<()> {
        let socket = self.socket.clone();
        tokio::spawn(async move {
            while let Some((payload, src)) = intercept_rx.recv().await {
                // Decode the notification. Malformed packets are logged
                // and dropped — punch is best-effort.
                let (requester_id, endpoints) = match decode_punch_notify(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!(
                            target: "ztlp::punch_agent",
                            error = %e,
                            src = %src,
                            "PUNCH_NOTIFY decode failed"
                        );
                        continue;
                    }
                };

                let target_addrs: Vec<SocketAddr> =
                    endpoints.iter().map(|e: &PeerEndpoint| e.addr).collect();

                if target_addrs.is_empty() {
                    tracing::debug!(
                        target: "ztlp::punch_agent",
                        requester = %requester_id,
                        "PUNCH_NOTIFY with no endpoints — skipping responder"
                    );
                    continue;
                }

                tracing::info!(
                    target: "ztlp::punch_agent",
                    requester = %requester_id,
                    endpoint_count = target_addrs.len(),
                    "PUNCH_NOTIFY received; responding"
                );

                // Spawn the responder so the dispatcher loop can
                // immediately accept the next notification without
                // blocking for `responder_duration` seconds.
                let sock_clone = socket.clone();
                tokio::spawn(async move {
                    respond_to_punch(&sock_clone, &target_addrs, responder_duration).await;
                });
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

    // ── H4: start_dispatcher consumes PUNCH_NOTIFY + invokes responder ──

    use crate::punch::{encode_punch_notify_for_test, PUNCH_BYTE as PUNCH_BYTE_CONST};

    /// H4 — dispatcher decodes a PUNCH_NOTIFY and fires PUNCH_BYTE
    /// at the requester's reported endpoints.
    #[tokio::test]
    async fn h4_dispatcher_fires_responder_on_punch_notify() {
        // Set up the gateway socket (where responder PUNCH_BYTE will
        // come from) and an "imagined requester" socket (where they
        // should arrive).
        let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let requester = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let requester_addr = requester.local_addr().unwrap();

        let agent = PunchAgent::new(
            gw_sock,
            "127.0.0.1:0".parse().unwrap(), // NS addr unused in this test
            NodeId([0xDE; 16]),
        );

        // Build the PUNCH_NOTIFY payload that PunchSocket would have
        // forwarded — requester NodeId + one endpoint.
        let requester_id = NodeId([0xAB; 16]);
        let notify_payload = encode_punch_notify_for_test(&requester_id, &[requester_addr]);

        // Wire up the channel ourselves (no PunchSocket needed for
        // this isolated test of the dispatcher).
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = agent.start_dispatcher(rx, Duration::from_millis(400));

        // Inject the notification.
        tx.send((notify_payload, "127.0.0.1:1234".parse().unwrap()))
            .unwrap();

        // Expect a PUNCH_BYTE on the requester socket within 1s.
        let mut buf = [0u8; 4];
        let (n, _src) = tokio::time::timeout(Duration::from_secs(1), requester.recv_from(&mut buf))
            .await
            .expect("requester did not receive PUNCH_BYTE")
            .expect("requester recv_from io error");

        assert_eq!(n, 1);
        assert_eq!(buf[0], PUNCH_BYTE_CONST);

        handle.abort();
    }

    /// H4 — dispatcher gracefully exits when the channel sender is dropped.
    #[tokio::test]
    async fn h4_dispatcher_exits_when_channel_closes() {
        let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let agent = PunchAgent::new(gw_sock, "127.0.0.1:0".parse().unwrap(), NodeId([0x11; 16]));

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
        let handle = agent.start_dispatcher(rx, Duration::from_millis(200));

        // Drop the sender; receiver should yield None immediately.
        drop(tx);

        // The dispatcher task should complete (cleanly exit the while-let loop).
        tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("dispatcher did not exit after channel close")
            .expect("dispatcher task panicked");
    }

    /// H4 — malformed PUNCH_NOTIFY payloads are logged and skipped;
    /// the dispatcher keeps running.
    #[tokio::test]
    async fn h4_dispatcher_tolerates_malformed_notifies() {
        let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let requester = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let requester_addr = requester.local_addr().unwrap();

        let agent = PunchAgent::new(gw_sock, "127.0.0.1:0".parse().unwrap(), NodeId([0x22; 16]));

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let handle = agent.start_dispatcher(rx, Duration::from_millis(300));

        // First send a truncated (malformed) notify — dispatcher should
        // skip it.
        tx.send((vec![0x0B, 0xFF], "127.0.0.1:1234".parse().unwrap()))
            .unwrap();

        // Then send a valid one; verify it still fires.
        let req_id = NodeId([0x33; 16]);
        let valid = encode_punch_notify_for_test(&req_id, &[requester_addr]);
        tx.send((valid, "127.0.0.1:1234".parse().unwrap())).unwrap();

        // Should receive PUNCH_BYTE despite the earlier garbage.
        let mut buf = [0u8; 4];
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), requester.recv_from(&mut buf))
            .await
            .expect("requester did not receive PUNCH_BYTE after malformed")
            .expect("requester recv_from io error");
        assert_eq!(n, 1);
        assert_eq!(buf[0], PUNCH_BYTE_CONST);

        handle.abort();
    }
}
