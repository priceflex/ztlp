//! v0.32 multi-candidate discovery (M6): the entry point that wires
//! M1–M5 together for a real `ztlp connect` invocation.
//!
//! `try_multi_candidate_connect()` is the helper called from
//! `cmd_connect` (behind `--multi-candidate`). It:
//!
//! 1. Queries NS via `encode_peer_endpoints_request` / awaits a
//!    `decode_peer_endpoints_response`.
//! 2. Wraps the returned host candidates through
//!    [`candidate_priority::prioritize`] together with the (optional)
//!    relay backstop.
//! 3. Races the ranked list via [`dial_orchestrator::dial_candidates`]
//!    using [`QuicDialer`] — Phase 1 of which is a UDP probe rather
//!    than a real QUIC handshake (see [`QuicDialer`] for the
//!    rationale).
//! 4. Returns [`DialOutcome::Established { winning_addr, class }`] on
//!    success, [`MultiCandidateError`] on failure.
//!
//! On any error the caller (cmd_connect) falls through to the
//! existing v0.31 send_addr handshake — failure is non-fatal by
//! design while the feature is gated behind `--multi-candidate`.
//!
//! ## Why a UDP probe instead of a real QUIC handshake (Phase 1)
//!
//! Wiring a full QUIC handshake here would require disturbing the
//! existing handshake state machine in `cmd_connect` (lots of
//! cross-cutting state — RAT tokens, session-id selection,
//! Noise_XX inheritance). For M6 we ship the orchestration scaffold
//! and a connectivity-only probe so the wire path is exercisable;
//! Phase 2 (post-v0.32.0) swaps QuicDialer's body for the real
//! handshake. The probe sends `0xFE + 8 random bytes` (mirroring
//! the existing relay probe pattern) and accepts ANY UDP packet
//! back within `per_candidate_timeout` as proof of liveness.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::candidate_priority::{prioritize, CandidateClass, RankedCandidate};
use crate::dial_orchestrator::{
    dial_candidates, DialError, DialPolicy, DialSuccess, Dialer, OrchestratorError,
};
use crate::identity::NodeId;
use crate::punch::{
    decode_peer_endpoints_response, encode_peer_endpoints_request, NS_PEER_ENDPOINTS,
};

/// One byte we send as the connectivity probe. Mirrors the relay
/// probe's `0xFE` discriminator so a gateway listener that already
/// echoes relay probes will trivially reply to ours too. (Production
/// listeners that don't echo will surface as a timeout — same
/// failure mode as a real unreachable peer.)
const PROBE_BYTE: u8 = 0xFE;

/// Outcome of a successful multi-candidate dial.
///
/// Carries both the winning socket address (so cmd_connect can
/// update `send_addr` and continue the handshake) and the candidate
/// class (for telemetry — "did we win on host, srflx, or relay?").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialOutcome {
    pub winning_addr: SocketAddr,
    pub class: CandidateClass,
}

/// Why a multi-candidate dial failed.
///
/// All variants are non-fatal to cmd_connect — the caller falls
/// back to the existing v0.31 send_addr handshake path.
#[derive(Debug, Clone)]
pub enum MultiCandidateError {
    /// NS returned 0 endpoints AND no relay was supplied.
    NoCandidates,
    /// NS query failed (timeout, parse error, transport error).
    NsQueryFailed(String),
    /// Orchestrator gave up — every candidate failed, or the
    /// total budget expired.
    AllFailed(String),
}

/// Timeout for the NS PEER_ENDPOINTS round-trip. Kept slim so the
/// fallback path can fire quickly if NS is unreachable.
const NS_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Query NS for `peer_node_id`'s endpoints, rank them, and race them
/// in parallel via [`dial_candidates`]. The first dial to succeed
/// wins; losers are cancelled.
///
/// `relay_addr` is appended as a [`CandidateClass::Relay`] backstop
/// when supplied — typically the address cmd_connect would have
/// used as `send_addr` if multi-candidate were disabled.
#[allow(clippy::too_many_arguments)]
pub async fn try_multi_candidate_connect(
    peer_node_id: NodeId,
    ns_server: SocketAddr,
    our_socket: Arc<UdpSocket>,
    our_node_id: NodeId,
    our_local_subnets: &[(std::net::IpAddr, u8)],
    relay_addr: Option<SocketAddr>,
    policy: DialPolicy,
) -> Result<DialOutcome, MultiCandidateError> {
    // Step 1: query NS for peer endpoints. We use our existing socket
    // so any NAT mapping we already have is preserved.
    let req = encode_peer_endpoints_request(&our_node_id, &peer_node_id, &[]);
    our_socket
        .send_to(&req, ns_server)
        .await
        .map_err(|e| MultiCandidateError::NsQueryFailed(format!("send_to NS failed: {e}")))?;

    let peer_endpoints = match tokio::time::timeout(NS_QUERY_TIMEOUT, async {
        let mut buf = [0u8; 2048];
        loop {
            let (len, from) = our_socket.recv_from(&mut buf).await?;
            if from == ns_server && len > 0 && buf[0] == NS_PEER_ENDPOINTS {
                return decode_peer_endpoints_response(&buf[..len]).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}"))
                });
            }
            // Drop unrelated traffic and keep listening within the timeout.
        }
    })
    .await
    {
        Ok(Ok(eps)) => eps,
        Ok(Err(e)) => return Err(MultiCandidateError::NsQueryFailed(e.to_string())),
        Err(_) => {
            return Err(MultiCandidateError::NsQueryFailed(
                "timeout waiting for NS PEER_ENDPOINTS response".to_string(),
            ))
        }
    };

    let host_addrs: Vec<SocketAddr> = peer_endpoints.iter().map(|e| e.addr).collect();

    // Step 2: rank.
    let ranked: Vec<RankedCandidate> = prioritize(&host_addrs, None, relay_addr, our_local_subnets);
    if ranked.is_empty() {
        return Err(MultiCandidateError::NoCandidates);
    }

    // Step 3: race the ranked list. The dialer needs its own socket so
    // probes don't collide with the caller's primary UDP socket; we
    // bind an ephemeral one inside QuicDialer (see its constructor
    // comment for why).
    let dialer: Arc<dyn Dialer> = Arc::new(QuicDialer::new().await.map_err(|e| {
        MultiCandidateError::AllFailed(format!("failed to bind probe socket: {e}"))
    })?);

    // Build a lookup table so we can recover the winning candidate's
    // class for telemetry.
    let class_of: std::collections::HashMap<SocketAddr, CandidateClass> =
        ranked.iter().map(|c| (c.addr, c.class)).collect();

    match dial_candidates(ranked, dialer, policy).await {
        Ok(DialSuccess { addr }) => {
            let class = class_of
                .get(&addr)
                .copied()
                .unwrap_or(CandidateClass::Relay);
            Ok(DialOutcome {
                winning_addr: addr,
                class,
            })
        }
        Err(OrchestratorError::NoCandidates) => Err(MultiCandidateError::NoCandidates),
        Err(e) => Err(MultiCandidateError::AllFailed(format!("{:?}", e))),
    }
}

/// Phase-1 dialer that probes a candidate's UDP reachability.
///
/// Sends `[0xFE, ..random8]` to the candidate and waits up to
/// per-candidate-timeout for ANY UDP packet back from that address.
/// Liveness only — content of the reply is not validated. This lets
/// M6 ship without disturbing the existing QUIC handshake state
/// machine in cmd_connect. Phase 2 (post-v0.32.0) replaces the body
/// with the real handshake.
///
/// ## Per-dial, family-matched bind (v0.32.1)
///
/// As of v0.32.1, the dialer binds a fresh ephemeral UDP socket PER
/// `dial()` call with an address family matched to the candidate's
/// (`0.0.0.0:0` for IPv4, `[::]:0` for IPv6). This costs one extra
/// bind/close per candidate (~50 µs on Linux) and lets us dial IPv6
/// candidates without `EAFNOSUPPORT`.
///
/// Pre-v0.32.1 the dialer held a single `0.0.0.0:0` socket across all
/// candidates, which broke every IPv6 host candidate in PUNCH_REPORT
/// with `send_to: Address family not supported by protocol (os error 97)`.
pub struct QuicDialer {
    // No persistent socket — sockets are per-dial, family-matched.
    _private: (),
}

impl QuicDialer {
    /// Construct a new QuicDialer.
    ///
    /// Infallible in practice — sockets are bound per `dial()` call
    /// against the candidate's address family. Returns `io::Result`
    /// for forward compatibility (Phase 2 may bind shared state).
    pub async fn new() -> std::io::Result<Self> {
        Ok(Self { _private: () })
    }

    /// Build a probe packet: `0xFE` + 8 nonce bytes.
    ///
    /// Nonce is purely so a stale reply from a previous probe (if
    /// the kernel ever re-binds the same ephemeral port) can in
    /// principle be distinguished by future Phase-2 work. Today we
    /// don't validate the reply content, so the nonce is effectively
    /// decorative — kept anyway because it costs nothing and keeps
    /// the wire shape stable for Phase 2.
    fn probe_packet() -> [u8; 9] {
        // Use a deterministic-ish nonce derived from monotonic time —
        // dependency-free, no need for rand here.
        let nanos = std::time::Instant::now().elapsed().as_nanos() as u64;
        let mut pkt = [0u8; 9];
        pkt[0] = PROBE_BYTE;
        pkt[1..9].copy_from_slice(&nanos.to_le_bytes());
        pkt
    }
}

#[async_trait]
impl Dialer for QuicDialer {
    async fn dial(&self, addr: SocketAddr) -> Result<DialSuccess, DialError> {
        // Bind the probe socket with the family that matches `addr`.
        // IPv4 → 0.0.0.0:0, IPv6 → [::]:0. Costs microseconds; avoids
        // EAFNOSUPPORT on IPv6 candidates.
        let bind_addr = match addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => return Err(DialError::Other(format!("bind {bind_addr}: {e}"))),
        };

        let pkt = Self::probe_packet();
        if let Err(e) = socket.send_to(&pkt, addr).await {
            return Err(DialError::Other(format!("send_to {addr}: {e}")));
        }
        // Read loop: accept the first datagram that comes back FROM `addr`.
        // Per-candidate timeout is enforced by the outer orchestrator via
        // `tokio::time::timeout(per_candidate_timeout, ...)` — we don't
        // re-apply it here, but if the timeout layer somehow goes away
        // we fall through to an inner safety timeout slightly longer
        // than the default per_candidate_timeout so we can't deadlock.
        let inner = async {
            let mut buf = [0u8; 1500];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((_len, from)) if from == addr => return Ok(DialSuccess { addr }),
                    Ok(_) => continue, // unrelated reply — keep listening
                    Err(e) => return Err(DialError::Other(format!("recv: {e}"))),
                }
            }
        };
        // Inner safety net: 30 s — well beyond any reasonable per-
        // candidate timeout. Belt-and-braces; orchestrator owns the
        // real timeout.
        match tokio::time::timeout(Duration::from_secs(30), inner).await {
            Ok(res) => res,
            Err(_) => Err(DialError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use std::net::{IpAddr, Ipv4Addr};

    fn fresh_node_id() -> NodeId {
        NodeIdentity::generate().expect("generate node id").node_id
    }

    /// Inline mirror of the (private) `punch::encode_addr` helper so
    /// the test can build PEER_ENDPOINTS responses without bumping
    /// the public surface of `punch.rs`.
    fn encode_addr_inline(buf: &mut Vec<u8>, addr: SocketAddr) {
        match addr.ip() {
            IpAddr::V4(v4) => {
                buf.push(4);
                buf.extend_from_slice(&v4.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(v6) => {
                buf.push(6);
                buf.extend_from_slice(&v6.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
    }

    /// Build a fake PEER_ENDPOINTS response with the given host list.
    fn build_peer_endpoints_response(endpoints: &[SocketAddr]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(2 + endpoints.len() * 7);
        pkt.push(NS_PEER_ENDPOINTS);
        pkt.push(endpoints.len().min(255) as u8);
        for ep in endpoints {
            encode_addr_inline(&mut pkt, *ep);
        }
        pkt
    }

    /// Spawn a fake NS that listens on a random port and replies to
    /// any incoming packet with the given canned PEER_ENDPOINTS
    /// response. Returns `(ns_addr, handle)`.
    async fn spawn_fake_ns(response: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            // Single-shot: reply to the first packet and exit.
            if let Ok((_, from)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&response, from).await;
            }
        });
        (addr, handle)
    }

    /// Spawn a UDP responder that echoes any received packet back to
    /// the sender. Returns `(addr, handle)`. The handle stays alive
    /// for the test's lifetime.
    async fn spawn_echo_responder() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((len, from)) => {
                        let _ = sock.send_to(&buf[..len], from).await;
                    }
                    Err(_) => break,
                }
            }
        });
        (addr, handle)
    }

    /// Spawn a UDP socket that binds but never replies. Returns its
    /// addr + a handle that holds the socket alive.
    async fn spawn_silent_listener() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            // Hold the socket; never reply.
            let mut buf = [0u8; 16];
            loop {
                if sock.recv_from(&mut buf).await.is_err() {
                    break;
                }
            }
        });
        (addr, handle)
    }

    // ── Test 1 ────────────────────────────────────────────────────────
    /// When NS returns 0 endpoints, the relay backstop is the only
    /// candidate. QuicDialer's UDP probe lands on a real echo
    /// responder so the dial succeeds → outcome.class == Relay.
    #[tokio::test]
    async fn try_connect_with_empty_ns_response_uses_only_relay() {
        // NS replies with 0 endpoints.
        let (ns_addr, _ns_h) = spawn_fake_ns(build_peer_endpoints_response(&[])).await;
        // Relay echoes — so the probe succeeds.
        let (relay_addr, _relay_h) = spawn_echo_responder().await;

        let our_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let our_id = fresh_node_id();
        let peer_id = fresh_node_id();

        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(2),
            band_delay: Duration::from_millis(50),
            total_budget: Duration::from_secs(5),
        };
        let out = try_multi_candidate_connect(
            peer_id,
            ns_addr,
            our_socket,
            our_id,
            &[],
            Some(relay_addr),
            policy,
        )
        .await
        .expect("dial should succeed via relay backstop");

        assert_eq!(out.winning_addr, relay_addr);
        assert_eq!(out.class, CandidateClass::Relay);
    }

    // ── Test 2 ────────────────────────────────────────────────────────
    /// When NS returns 1 host candidate AND a relay is supplied,
    /// the host (same-subnet, priority 250) should win because it's
    /// in the higher band and we give it `band_delay` of head start.
    ///
    /// v0.32.1 note: pre-T4, 127.0.0.1 classified as HostPublicV4 (160)
    /// via the catch-all branch — naturally above Relay (50). T4 made
    /// loopback short-circuit to priority 0, which inverted the rank
    /// vs. Relay. To preserve the test's stated intent ("host wins"),
    /// we now pass `127.0.0.0/8` in `our_local_subnets` so the same
    /// loopback address classifies as HostSameSubnet — exercising the
    /// operator-override path that v0.32.1's classify() now respects
    /// over the loopback short-circuit.
    #[tokio::test]
    async fn try_connect_prefers_host_over_relay_when_host_reachable() {
        let (host_addr, _host_h) = spawn_echo_responder().await;
        let (relay_addr, _relay_h) = spawn_echo_responder().await;
        let (ns_addr, _ns_h) = spawn_fake_ns(build_peer_endpoints_response(&[host_addr])).await;

        let our_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let our_id = fresh_node_id();
        let peer_id = fresh_node_id();

        // Operator-override: treat 127.0.0.0/8 as a reachable subnet.
        // Without this override, T4's loopback short-circuit would rank
        // 127.0.0.1 below Relay (priority 0 vs 50) and the relay would
        // win — which is correct production behavior but defeats this
        // test's purpose (host-over-relay precedence).
        let local_subnets = vec![(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8u8)];

        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(2),
            band_delay: Duration::from_millis(250),
            total_budget: Duration::from_secs(5),
        };
        let out = try_multi_candidate_connect(
            peer_id,
            ns_addr,
            our_socket,
            our_id,
            &local_subnets,
            Some(relay_addr),
            policy,
        )
        .await
        .expect("dial should succeed");

        assert_eq!(
            out.winning_addr, host_addr,
            "host candidate should win over relay"
        );
        // Class is HostSameSubnet because we passed 127.0.0.0/8 in subnets.
        assert_ne!(out.class, CandidateClass::Relay);
    }

    // ── Test 3 ────────────────────────────────────────────────────────
    /// 0 host endpoints AND no relay → NoCandidates.
    #[tokio::test]
    async fn try_connect_no_candidates_returns_error() {
        let (ns_addr, _ns_h) = spawn_fake_ns(build_peer_endpoints_response(&[])).await;
        let our_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let our_id = fresh_node_id();
        let peer_id = fresh_node_id();
        let policy = DialPolicy::default();

        let err =
            try_multi_candidate_connect(peer_id, ns_addr, our_socket, our_id, &[], None, policy)
                .await
                .expect_err("expected NoCandidates");
        match err {
            MultiCandidateError::NoCandidates => {}
            other => panic!("expected NoCandidates, got {:?}", other),
        }
    }

    // ── Test 4 ────────────────────────────────────────────────────────
    /// NS returns 2 hosts, both silent (no echo) → orchestrator times
    /// out → AllFailed.
    #[tokio::test]
    async fn try_connect_propagates_dial_error_when_all_fail() {
        let (silent1, _h1) = spawn_silent_listener().await;
        let (silent2, _h2) = spawn_silent_listener().await;
        let (ns_addr, _ns_h) =
            spawn_fake_ns(build_peer_endpoints_response(&[silent1, silent2])).await;

        let our_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let our_id = fresh_node_id();
        let peer_id = fresh_node_id();
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_millis(200),
            band_delay: Duration::from_millis(50),
            total_budget: Duration::from_secs(2),
        };
        let err =
            try_multi_candidate_connect(peer_id, ns_addr, our_socket, our_id, &[], None, policy)
                .await
                .expect_err("expected AllFailed");
        match err {
            MultiCandidateError::AllFailed(_) => {}
            other => panic!("expected AllFailed, got {:?}", other),
        }
    }

    // ── Test 5: QuicDialer behaviour tests ──────────────────────────

    /// Bind a silent target; QuicDialer.dial() should time out.
    /// We wrap dial() in our own timeout because QuicDialer's inner
    /// safety net is 30 s — the orchestrator normally owns the real
    /// per-candidate budget.
    #[tokio::test]
    async fn quic_dialer_returns_timeout_when_target_silent() {
        let (silent, _h) = spawn_silent_listener().await;
        let dialer = QuicDialer::new().await.unwrap();
        let res = tokio::time::timeout(Duration::from_millis(300), dialer.dial(silent)).await;
        // Either: outer timeout fires (and we never see a result), or
        // QuicDialer surfaces DialError::Timeout from its inner net.
        match res {
            Err(_) => {
                // Outer timeout — silent target by definition.
            }
            Ok(Err(DialError::Timeout)) => {
                // Acceptable: inner safety net fired.
            }
            other => panic!("expected timeout, got {:?}", other),
        }
    }

    // ── Test 6 ────────────────────────────────────────────────────────
    /// Echo responder → dial() returns Ok(DialSuccess { addr }).
    #[tokio::test]
    async fn quic_dialer_returns_success_when_target_echoes() {
        let (echo_addr, _h) = spawn_echo_responder().await;
        let dialer = QuicDialer::new().await.unwrap();
        let success = tokio::time::timeout(Duration::from_secs(2), dialer.dial(echo_addr))
            .await
            .expect("inner dial should finish well under 2 s")
            .expect("dial should succeed against echo responder");
        assert_eq!(success.addr, echo_addr);
    }

    // ── Test 7 ────────────────────────────────────────────────────────
    /// Host with same-subnet match should classify as HostSameSubnet
    /// (priority 250). The dialer doesn't *create* the classification,
    /// but the helper feeds `our_local_subnets` into `prioritize` —
    /// this test pins that flow.
    #[tokio::test]
    async fn try_connect_classifies_host_as_same_subnet_when_subnet_matches() {
        let (host_addr, _host_h) = spawn_echo_responder().await;
        let (ns_addr, _ns_h) = spawn_fake_ns(build_peer_endpoints_response(&[host_addr])).await;

        let our_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let our_id = fresh_node_id();
        let peer_id = fresh_node_id();

        // Mark the entire 127.0.0.0/8 as a same-subnet match so the
        // host candidate (127.0.0.1) classifies as HostSameSubnet.
        let local_subnets = vec![(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8u8)];
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_secs(2),
            band_delay: Duration::from_millis(50),
            total_budget: Duration::from_secs(5),
        };
        let out = try_multi_candidate_connect(
            peer_id,
            ns_addr,
            our_socket,
            our_id,
            &local_subnets,
            None,
            policy,
        )
        .await
        .expect("dial should succeed");

        assert_eq!(out.winning_addr, host_addr);
        assert_eq!(out.class, CandidateClass::HostSameSubnet);
    }

    // ── Test 8 ────────────────────────────────────────────────────────
    /// If NS never responds, surface NsQueryFailed (timeout). Bind a
    /// UDP socket but never reply to PEER_ENDPOINTS — analogous to
    /// `spawn_silent_listener` but acting in the NS role.
    #[tokio::test]
    async fn try_connect_returns_ns_query_failed_when_ns_times_out() {
        let (ns_addr, _h) = spawn_silent_listener().await;
        let our_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let our_id = fresh_node_id();
        let peer_id = fresh_node_id();
        // The NS_QUERY_TIMEOUT inside the helper is 3 s; we don't
        // override it. Test wraps the whole call in a 5 s safety
        // timeout so a regression here surfaces as a hang, not a
        // forever-pending test.
        let policy = DialPolicy::default();
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            try_multi_candidate_connect(peer_id, ns_addr, our_socket, our_id, &[], None, policy),
        )
        .await
        .expect("must not hang past NS_QUERY_TIMEOUT + grace");
        match res {
            Err(MultiCandidateError::NsQueryFailed(_)) => {}
            other => panic!("expected NsQueryFailed, got {:?}", other),
        }
    }

    // ── Test 9: T2 — QuicDialer dual-stack ─────────────────────────────

    /// T2 — QuicDialer must succeed against an IPv6 loopback echo
    /// responder. Today's bind of 0.0.0.0:0 fails with
    /// EAFNOSUPPORT on send_to([::1]).
    #[tokio::test]
    async fn quic_dialer_dials_ipv6_loopback() {
        // IPv6 loopback echo: bind ::1, echo any datagram back to its src.
        let echo = Arc::new(UdpSocket::bind("[::1]:0").await.expect("bind v6 echo"));
        let echo_addr = echo.local_addr().unwrap();
        let echo_clone = echo.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            if let Ok((n, src)) = echo_clone.recv_from(&mut buf).await {
                let _ = echo_clone.send_to(&buf[..n], src).await;
            }
        });

        let dialer = QuicDialer::new().await.expect("QuicDialer::new");
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), dialer.dial(echo_addr))
                .await
                .expect("no timeout")
                .expect("dial ok");
        // probe completed — outcome doesn't matter for liveness, only that the
        // dial completed without an EAFNOSUPPORT error.
        let _ = result;
    }

    /// T2 — IPv4 path still works (regression).
    #[tokio::test]
    async fn quic_dialer_dials_ipv4_loopback() {
        let echo = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind v4 echo"));
        let echo_addr = echo.local_addr().unwrap();
        let echo_clone = echo.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64];
            if let Ok((n, src)) = echo_clone.recv_from(&mut buf).await {
                let _ = echo_clone.send_to(&buf[..n], src).await;
            }
        });

        let dialer = QuicDialer::new().await.expect("QuicDialer::new");
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), dialer.dial(echo_addr))
                .await
                .expect("no timeout")
                .expect("dial ok");
        let _ = result;
    }
}
