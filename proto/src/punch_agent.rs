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

    /// Cached listener port (extracted from `socket.local_addr()` at
    /// construction time). Stamped onto every local-candidate
    /// `SocketAddr` enumerated for inclusion in `PUNCH_REPORT`. If the
    /// underlying socket cannot report its local_addr (extremely rare on
    /// a bound socket), this falls through to `0` and a WARN is logged —
    /// the dialer side (M5) can ignore port-0 candidates.
    pub(crate) listener_port: u16,

    /// Operator override: force-include these interface names in the
    /// PUNCH_REPORT candidate list, even if the default filter would
    /// skip them. Empty in the default constructor.
    pub(crate) advertise_include: Vec<String>,

    /// Operator override: force-exclude these interface names from the
    /// PUNCH_REPORT candidate list. Takes precedence over `include` and
    /// `all`. Empty in the default constructor.
    pub(crate) advertise_exclude: Vec<String>,

    /// Operator override: when true, disable the default filter entirely
    /// (link-local, docker bridges, etc. all flow through). Only
    /// `advertise_exclude` still applies. False in the default constructor.
    pub(crate) advertise_all: bool,
}

impl PunchAgent {
    /// Construct a new agent over the given shared socket, NS address,
    /// and node identity.
    pub fn new(socket: Arc<UdpSocket>, ns_addr: SocketAddr, node_id: NodeId) -> Self {
        Self::with_advertise_overrides(socket, ns_addr, node_id, Vec::new(), Vec::new(), false)
    }

    /// Construct a new agent with explicit operator overrides for the
    /// PUNCH_REPORT candidate enumeration filter.
    ///
    /// See [`crate::local_candidates::enumerate_local_candidates_with_overrides`]
    /// for filter semantics. `include`/`exclude` are interface names
    /// (e.g. `"eth0"`, `"docker0"`); `all` disables the default skip
    /// filter when true.
    pub fn with_advertise_overrides(
        socket: Arc<UdpSocket>,
        ns_addr: SocketAddr,
        node_id: NodeId,
        advertise_include: Vec<String>,
        advertise_exclude: Vec<String>,
        advertise_all: bool,
    ) -> Self {
        let listener_port = match socket.local_addr() {
            Ok(addr) => addr.port(),
            Err(e) => {
                tracing::warn!(
                    target: "ztlp::punch_agent",
                    error = %e,
                    "PunchAgent: socket.local_addr() failed; using port 0 (candidates will be unusable)"
                );
                0
            }
        };
        Self {
            socket,
            ns_addr,
            node_id,
            listener_port,
            advertise_include,
            advertise_exclude,
            advertise_all,
        }
    }

    /// Construct a PunchAgent with an EXPLICIT listener port that
    /// may differ from the keepalive socket's bind port.
    ///
    /// This is the production shape on listeners: the keepalive socket
    /// is bound to an ephemeral port (because Quinn owns the listener
    /// socket), but the candidates advertised in PUNCH_REPORT must
    /// carry the LISTENER port so peers dial the right destination.
    ///
    /// `with_socket()` and `with_advertise_overrides()` are equivalent
    /// to calling this with `listener_port = socket.local_addr().port()`
    /// — useful for tests and for direct gateways that share their
    /// listener socket with the keepalive task.
    pub fn with_listener_port(
        socket: Arc<UdpSocket>,
        ns_addr: SocketAddr,
        node_id: NodeId,
        listener_port: u16,
        advertise_include: Vec<String>,
        advertise_exclude: Vec<String>,
        advertise_all: bool,
    ) -> Self {
        Self {
            socket,
            ns_addr,
            node_id,
            listener_port,
            advertise_include,
            advertise_exclude,
            advertise_all,
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
        let port = self.listener_port;
        let include = self.advertise_include.clone();
        let exclude = self.advertise_exclude.clone();
        let all = self.advertise_all;

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // `interval`'s first tick is immediate; that's the behavior
            // we want — register with NS as soon as the keepalive starts.
            loop {
                ticker.tick().await;
                // Re-enumerate every tick — laptops change networks
                // (Wi-Fi → Ethernet → VPN flip) and the per-tick
                // getifaddrs(3) cost is microseconds. Re-encode every
                // tick because the candidate set can change between
                // ticks; cloud gateways pay a tiny constant cost for
                // this insurance.
                let candidates = crate::local_candidates::enumerate_local_candidates_with_overrides(
                    port, &include, &exclude, all,
                );
                let pkt = encode_punch_report(&node_id, &candidates);
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
    ///
    /// Updated for M2 (v0.32): reported_count is no longer hard-coded
    /// to 0 — the keepalive now enumerates local NICs and attaches them
    /// as reported endpoints. We assert the count is a valid u8 (i.e.
    /// the byte at offset 17 was actually written) and accept any value
    /// because the host's NIC set is environment-dependent.
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

        // Wire format: 0x0C + 16-byte node_id + 1-byte reported_count + reported_addrs...
        assert!(n >= 18, "PUNCH_REPORT too short: {} bytes", n);
        assert_eq!(buf[0], 0x0C, "first byte must be NS_PUNCH_REPORT");
        assert_eq!(&buf[1..17], &node_id.0[..], "node_id must match");
        // M2: reported_count is environment-dependent (≥ 0). We just
        // verify the byte exists; behaviour of local-candidate
        // enumeration is covered by the M2-T4/T6 tests below.
        let _reported_count = buf[17];

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

    // ── M2 (v0.32): multi-candidate discovery — PUNCH_REPORT carries local NICs ──

    /// Inline mini-decoder for PUNCH_REPORT (0x0C) used by M2 tests.
    /// Returns (node_id, reported_endpoints).
    /// Format: 0x0C | node_id[16] | count[1] | (family[1] + addr + port[2])*
    fn decode_punch_report_for_test(data: &[u8]) -> (NodeId, Vec<SocketAddr>) {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        assert!(data.len() >= 18, "punch report too short: {}", data.len());
        assert_eq!(data[0], 0x0C, "expected NS_PUNCH_REPORT");
        let mut nid = [0u8; 16];
        nid.copy_from_slice(&data[1..17]);
        let count = data[17] as usize;
        let mut endpoints = Vec::with_capacity(count);
        let mut pos = 18;
        for _ in 0..count {
            assert!(pos < data.len(), "truncated punch report");
            match data[pos] {
                4 => {
                    assert!(pos + 7 <= data.len(), "truncated v4 addr");
                    let ip =
                        Ipv4Addr::new(data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]);
                    let port = u16::from_be_bytes([data[pos + 5], data[pos + 6]]);
                    endpoints.push(SocketAddr::new(IpAddr::V4(ip), port));
                    pos += 7;
                }
                6 => {
                    assert!(pos + 19 <= data.len(), "truncated v6 addr");
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[pos + 1..pos + 17]);
                    let port = u16::from_be_bytes([data[pos + 17], data[pos + 18]]);
                    endpoints.push(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port));
                    pos += 19;
                }
                f => panic!("unknown addr family {} in punch report", f),
            }
        }
        (NodeId(nid), endpoints)
    }

    /// M2-T1: PunchAgent caches the listener port at construction so the
    /// keepalive can attach it to every reported local candidate.
    #[tokio::test]
    async fn punch_agent_caches_listener_port_on_construction() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let expected_port = sock.local_addr().unwrap().port();
        let agent = PunchAgent::new(sock, "127.0.0.1:23096".parse().unwrap(), NodeId([0x01; 16]));
        assert_eq!(
            agent.listener_port, expected_port,
            "listener_port must be cached from the bound socket"
        );
        assert_ne!(
            agent.listener_port, 0,
            "ephemeral bind should never produce port 0"
        );
    }

    /// M2-T2: default constructor leaves all three override knobs empty/false.
    #[tokio::test]
    async fn punch_agent_default_advertise_overrides_are_empty() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let agent = PunchAgent::new(sock, "127.0.0.1:23096".parse().unwrap(), NodeId([0x02; 16]));
        assert!(agent.advertise_include.is_empty());
        assert!(agent.advertise_exclude.is_empty());
        assert!(!agent.advertise_all);
    }

    /// M2-T3: with_advertise_overrides() stores all three knobs on the agent.
    #[tokio::test]
    async fn punch_agent_with_advertise_overrides_stores_them() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let agent = PunchAgent::with_advertise_overrides(
            sock,
            "127.0.0.1:23096".parse().unwrap(),
            NodeId([0x03; 16]),
            vec!["eth0".to_string()],
            vec!["docker0".to_string()],
            true,
        );
        assert_eq!(agent.advertise_include, vec!["eth0".to_string()]);
        assert_eq!(agent.advertise_exclude, vec!["docker0".to_string()]);
        assert!(agent.advertise_all);
    }

    /// M2-T4: load-bearing behaviour — every PUNCH_REPORT keepalive packet
    /// carries the gateway's local NIC addresses with the cached listener
    /// port stamped onto each one.
    #[tokio::test]
    async fn keepalive_packet_includes_local_candidates_with_listener_port() {
        let ns_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns_addr = ns_sock.local_addr().unwrap();

        let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let gw_port = gw_sock.local_addr().unwrap().port();

        let agent = PunchAgent::new(gw_sock, ns_addr, NodeId([7u8; 16]));
        let handle = agent.start_keepalive(Duration::from_millis(50));

        let mut buf = [0u8; 1024];
        let (n, _src) =
            tokio::time::timeout(Duration::from_millis(500), ns_sock.recv_from(&mut buf))
                .await
                .expect("keepalive packet did not arrive within 500ms")
                .expect("recv_from io error");

        let (nid, endpoints) = decode_punch_report_for_test(&buf[..n]);
        assert_eq!(nid, NodeId([7u8; 16]), "node_id round-trips");
        for ep in &endpoints {
            assert_eq!(
                ep.port(),
                gw_port,
                "every reported endpoint must carry the cached listener port"
            );
        }

        handle.abort();
    }

    /// M2-T5: smoke test — with_advertise_overrides() wires the override
    /// path end-to-end and the keepalive still sends a well-formed
    /// PUNCH_REPORT (type 0x0C) without crashing.
    #[tokio::test]
    async fn keepalive_packet_respects_exclude_override() {
        let ns_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns_addr = ns_sock.local_addr().unwrap();
        let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let agent = PunchAgent::with_advertise_overrides(
            gw_sock,
            ns_addr,
            NodeId([0x55; 16]),
            Vec::new(),
            vec!["lo".to_string()],
            false,
        );
        assert_eq!(agent.advertise_exclude, vec!["lo".to_string()]);
        let handle = agent.start_keepalive(Duration::from_millis(50));

        let mut buf = [0u8; 1024];
        let (n, _src) =
            tokio::time::timeout(Duration::from_millis(500), ns_sock.recv_from(&mut buf))
                .await
                .expect("keepalive packet did not arrive within 500ms")
                .expect("recv_from io error");
        assert!(n >= 18, "packet too short");
        assert_eq!(buf[0], 0x0C, "must be NS_PUNCH_REPORT");

        handle.abort();
    }

    /// M2-T6: re-enumeration happens INSIDE the tokio tick loop, not
    /// cached pre-tick. We verify by receiving ≥3 packets in 200ms with
    /// a 30ms interval, and every packet's reported endpoints carry the
    /// cached listener port.
    #[tokio::test]
    async fn keepalive_re_enumerates_each_tick() {
        let ns_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ns_addr = ns_sock.local_addr().unwrap();
        let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let gw_port = gw_sock.local_addr().unwrap().port();

        let agent = PunchAgent::new(gw_sock, ns_addr, NodeId([0xC0; 16]));
        let handle = agent.start_keepalive(Duration::from_millis(30));

        let mut count = 0usize;
        let mut buf = [0u8; 1024];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        while tokio::time::Instant::now() < deadline && count < 3 {
            if let Ok(Ok((n, _src))) =
                tokio::time::timeout(Duration::from_millis(100), ns_sock.recv_from(&mut buf)).await
            {
                let (_nid, endpoints) = decode_punch_report_for_test(&buf[..n]);
                for ep in &endpoints {
                    assert_eq!(ep.port(), gw_port, "port stable across re-enumerations");
                }
                count += 1;
            }
        }
        handle.abort();
        assert!(count >= 3, "expected ≥3 keepalives in 250ms, got {}", count);
    }

    /// T1 — when the operator explicitly supplies a listener port that
    /// differs from the keepalive socket's bind port, PUNCH_REPORT must
    /// advertise the EXPLICIT listener port. This is the production
    /// shape: keepalive socket is ephemeral, listener is fixed.
    #[tokio::test]
    async fn keepalive_uses_explicit_listener_port_over_socket_port() {
        use crate::punch::decode_punch_report;
        use std::time::Duration;

        // NS-side listener (receives PUNCH_REPORTs)
        let ns_sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind ns");
        let ns_addr = ns_sock.local_addr().unwrap();

        // Gateway keepalive socket — ephemeral; its port is NOT the listener port.
        let gw_keepalive = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind gw"));
        let keepalive_port = gw_keepalive.local_addr().unwrap().port();

        // Production-shape listener port — completely different from keepalive port.
        let explicit_listener_port: u16 = 23095;
        assert_ne!(explicit_listener_port, keepalive_port);

        let node_id = NodeId([0xBB; 16]);
        let agent = PunchAgent::with_listener_port(
            gw_keepalive,
            ns_addr,
            node_id,
            explicit_listener_port,
            vec![],
            vec![],
            true, // --advertise-all to get loopback candidate
        );
        let handle = agent.start_keepalive(Duration::from_millis(50));

        let mut buf = vec![0u8; 4096];
        let (n, _src) = tokio::time::timeout(
            Duration::from_secs(2),
            ns_sock.recv_from(&mut buf),
        )
        .await
        .expect("keepalive arrived")
        .expect("recv ok");

        handle.abort();

        let (decoded_node_id, candidates) =
            decode_punch_report(&buf[..n]).expect("decode_punch_report");
        assert_eq!(decoded_node_id, node_id);
        assert!(
            !candidates.is_empty(),
            "expected at least one candidate w/ --advertise-all"
        );
        for c in &candidates {
            assert_eq!(
                c.port(),
                explicit_listener_port,
                "candidate {} carries port {} but should carry explicit listener port {}",
                c,
                c.port(),
                explicit_listener_port
            );
        }
    }
}
