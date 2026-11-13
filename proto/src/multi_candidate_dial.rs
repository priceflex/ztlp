//! Multi-candidate dialing: which of a peer's published addresses can this
//! client actually reach?
//!
//! Two entry points live here. They share the candidate ranking
//! ([`candidate_priority`](crate::candidate_priority)) and the banded race
//! ([`dial_orchestrator`](crate::dial_orchestrator)) but test reachability
//! differently.
//!
//! ## [`connect_direct_first`] — the QUIC path (`ztlp connect`, default)
//!
//! Races a real QUIC handshake against every DIRECT candidate (the peer's
//! LAN / public addresses) with [`QuicHandshakeDialer`]. The first handshake
//! to complete wins and its connection is handed to the caller, so the
//! reachability test and the connection are the same packets. The relay is
//! not a candidate in this race: it is the backstop the caller dials when no
//! direct candidate completes a handshake, which happens within
//! [`LAN_CANDIDATE_TIMEOUT`] / [`PUBLIC_CANDIDATE_TIMEOUT`].
//!
//! ## [`try_multi_candidate_connect`] — the legacy raw-UDP path
//!
//! v0.32 (M6) helper, still used by `ztlp connect --transport udp --punch`.
//! It:
//!
//! 1. Queries NS via `encode_peer_endpoints_request` / awaits a
//!    `decode_peer_endpoints_response`.
//! 2. Wraps the returned host candidates through
//!    [`candidate_priority::prioritize`] together with the (optional)
//!    relay backstop.
//! 3. Races the ranked list via [`dial_orchestrator::dial_candidates`]
//!    using [`QuicDialer`], which despite its name sends a UDP probe
//!    (see [`QuicDialer`] for the rationale).
//! 4. Returns [`DialOutcome`] on success, [`MultiCandidateError`] on
//!    failure.
//!
//! On any error the caller (cmd_connect) falls through to the existing
//! send_addr handshake; failure is non-fatal by design.
//!
//! ## Why the UDP probe is not used on the QUIC path
//!
//! The probe sends `0xFE + 8 nonce bytes` and accepts ANY UDP packet back
//! within `per_candidate_timeout` as proof of liveness. Nothing on the QUIC
//! path answers it: a quinn listener (`ztlp listen`) drops the datagram as
//! not-QUIC and the relay does not echo it either. Every candidate therefore
//! timed out, a reachable LAN peer was never chosen, and each `ztlp connect
//! <name>` paid the full probe timeout before falling back to the relay.
//! Teaching the listener to echo would add an unauthenticated UDP responder;
//! a QUIC handshake is what the listener already answers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::candidate_priority::{prioritize, CandidateClass, RankedCandidate};
use crate::dial_orchestrator::{
    dial_candidates, DialError, DialPolicy, DialSuccess, Dialer, OrchestratorError,
};
use crate::identity::{NodeId, NodeIdentity};
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
    our_identity: &NodeIdentity,
    our_local_subnets: &[(std::net::IpAddr, u8)],
    relay_addr: Option<SocketAddr>,
    policy: DialPolicy,
) -> Result<DialOutcome, MultiCandidateError> {
    // Step 1: query NS for peer endpoints. We use our existing socket
    // so any NAT mapping we already have is preserved.
    let host_addrs = query_peer_endpoints(
        peer_node_id,
        ns_server,
        &our_socket,
        our_identity,
        NS_QUERY_TIMEOUT,
    )
    .await?;

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

/// Ask the name server for the addresses `peer_node_id` last reported
/// (PEER_ENDPOINTS) and return them in the order received.
///
/// `socket` must be able to reach `ns_server`; unrelated datagrams arriving
/// on it are skipped. Fails with [`MultiCandidateError::NsQueryFailed`] on a
/// send error, a malformed answer, or no answer within `wait`.
pub async fn query_peer_endpoints(
    peer_node_id: NodeId,
    ns_server: SocketAddr,
    socket: &UdpSocket,
    our_identity: &NodeIdentity,
    wait: Duration,
) -> Result<Vec<SocketAddr>, MultiCandidateError> {
    let req = encode_peer_endpoints_request(our_identity, &peer_node_id, &[]);
    socket
        .send_to(&req, ns_server)
        .await
        .map_err(|e| MultiCandidateError::NsQueryFailed(format!("send_to NS failed: {e}")))?;

    let answer = tokio::time::timeout(wait, async {
        let mut buf = [0u8; 2048];
        loop {
            let (len, from) = socket.recv_from(&mut buf).await?;
            if from == ns_server && len > 0 && buf[0] == NS_PEER_ENDPOINTS {
                return decode_peer_endpoints_response(&buf[..len]).map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}"))
                });
            }
            // Drop unrelated traffic and keep listening within the timeout.
        }
    })
    .await;

    match answer {
        Ok(Ok(endpoints)) => Ok(endpoints.iter().map(|e| e.addr).collect()),
        Ok(Err(e)) => Err(MultiCandidateError::NsQueryFailed(e.to_string())),
        Err(_) => Err(MultiCandidateError::NsQueryFailed(
            "timeout waiting for NS PEER_ENDPOINTS response".to_string(),
        )),
    }
}

// ─── Direct-first dialing with real QUIC handshakes ────────────────────────

/// Handshake budget for a direct candidate on a private / LAN address
/// (see [`is_lan_candidate`]).
///
/// Such an address is either on a network this client can reach, in which
/// case the QUIC handshake completes in one round trip (single-digit
/// milliseconds on a LAN, tens over a site-to-site VPN), or it belongs to
/// somebody else's network and nothing answers. Waiting longer only delays
/// the relay fallback for every operator who is not on the peer's LAN.
pub const LAN_CANDIDATE_TIMEOUT: Duration = Duration::from_millis(600);

/// Handshake budget for a direct candidate on a public address (the peer's
/// public host address or its NAT mapping). Internet round trips are longer
/// and the first packet may also have to open a NAT pinhole.
pub const PUBLIC_CANDIDATE_TIMEOUT: Duration = Duration::from_millis(1000);

/// Head start the LAN band gets over the public band in the direct race.
pub const DIRECT_BAND_DELAY: Duration = Duration::from_millis(250);

/// Upper bound on the whole direct race. The slowest schedule is the public
/// band starting [`DIRECT_BAND_DELAY`] in and running its full
/// [`PUBLIC_CANDIDATE_TIMEOUT`] (1.25 s); this adds a little slack on top.
pub const DIRECT_RACE_BUDGET: Duration = Duration::from_millis(1500);

/// How long the QUIC connect path waits for the name server's
/// PEER_ENDPOINTS answer before racing the candidates it already has from
/// the SVC record. The name server answered the SVC query moments earlier,
/// so a late answer here means "no answer", not "slow".
pub const DIRECT_PEER_ENDPOINTS_TIMEOUT: Duration = Duration::from_secs(1);

/// True when `ip` is only reachable from inside some private network:
/// RFC 1918, CGNAT / overlay (100.64.0.0/10), link-local or loopback IPv4,
/// and loopback, unique-local (fc00::/7) or link-local (fe80::/10) IPv6.
pub fn is_lan_candidate(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

/// Handshake budget for one direct candidate: [`LAN_CANDIDATE_TIMEOUT`] for
/// private addresses, [`PUBLIC_CANDIDATE_TIMEOUT`] otherwise.
pub fn direct_candidate_timeout(addr: SocketAddr) -> Duration {
    if is_lan_candidate(addr.ip()) {
        LAN_CANDIDATE_TIMEOUT
    } else {
        PUBLIC_CANDIDATE_TIMEOUT
    }
}

/// [`DialPolicy`] for the direct race. The per-candidate value is the
/// ceiling; [`QuicHandshakeDialer`] shortens it for LAN candidates through
/// [`Dialer::timeout_for`].
pub fn direct_dial_policy() -> DialPolicy {
    DialPolicy {
        per_candidate_timeout: PUBLIC_CANDIDATE_TIMEOUT,
        band_delay: DIRECT_BAND_DELAY,
        total_budget: DIRECT_RACE_BUDGET,
    }
}

/// Build the ranked list of DIRECT candidates for [`connect_direct_first`].
///
/// `svc_candidates` (from the peer's SVC record) and `peer_endpoints` (from
/// the name server's PEER_ENDPOINTS answer) are merged, de-duplicated and
/// ranked with [`prioritize`]. Left out:
///
/// - every address in `relays`. A relay is reached with a CLIENT_ROUTE frame
///   followed by QUIC, not with a bare QUIC handshake, so dialing it here
///   could only time out. It is the caller's fallback instead.
/// - loopback addresses (unless the caller lists the loopback net in
///   `our_local_subnets`, which tests do) and unusable ones (unspecified
///   address or port 0). A peer's loopback address would be answered by
///   whatever listens on THIS machine.
pub fn rank_direct_candidates(
    svc_candidates: &[SocketAddr],
    peer_endpoints: &[SocketAddr],
    relays: &[SocketAddr],
    our_local_subnets: &[(IpAddr, u8)],
) -> Vec<RankedCandidate> {
    let mut seen = std::collections::HashSet::new();
    let hosts: Vec<SocketAddr> = svc_candidates
        .iter()
        .chain(peer_endpoints)
        .copied()
        .filter(|a| !relays.contains(a) && !a.ip().is_unspecified() && a.port() != 0)
        .filter(|a| seen.insert(*a))
        .collect();

    prioritize(&hosts, None, None, our_local_subnets)
        .into_iter()
        .filter(|c| c.class != CandidateClass::Loopback)
        .collect()
}

#[cfg(feature = "quic-transport")]
pub use quic_direct::{connect_direct_first, DialRoute, DirectConnection, QuicHandshakeDialer};

#[cfg(feature = "quic-transport")]
mod quic_direct {
    use super::*;
    use crate::quic_transport::tokio_endpoint::{QuicConnection, QuicEndpoint};
    use crate::quic_transport::{CertExpectation, QuicEndpointConfig};
    use std::collections::HashMap;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// [`Dialer`] that tests a candidate by completing a real QUIC handshake
    /// with it, exactly as `ztlp connect <ip:port>` would
    /// ([`QuicEndpoint::connect_with_socket`]: same ALPN, same transport
    /// tuning, same certificate pin keyed on the candidate's address).
    ///
    /// A candidate "wins" only if the peer completes the TLS 1.3 handshake
    /// and its certificate passes the pin check, so a host that merely
    /// returns some UDP packet, or a different gateway that happens to own
    /// the same private address on another network and whose certificate
    /// does not match the pin, is not selected.
    ///
    /// Each dial uses its own UDP socket (address family matched to the
    /// candidate). The established connection is kept until the caller
    /// collects it with [`Self::take_connection`]; a dial that loses the
    /// race is dropped mid-handshake, which closes it.
    pub struct QuicHandshakeDialer {
        cfg: QuicEndpointConfig,
        server_name: String,
        pin_dir: Option<PathBuf>,
        lan_timeout: Duration,
        public_timeout: Duration,
        established: Mutex<HashMap<SocketAddr, QuicConnection>>,
    }

    impl QuicHandshakeDialer {
        /// Dialer with the production timeouts and the default pin store.
        /// `server_name` is the TLS server name (ZTLP dials use `localhost`).
        pub fn new(cfg: QuicEndpointConfig, server_name: &str) -> Self {
            Self {
                cfg,
                server_name: server_name.to_string(),
                pin_dir: None,
                lan_timeout: LAN_CANDIDATE_TIMEOUT,
                public_timeout: PUBLIC_CANDIDATE_TIMEOUT,
                established: Mutex::new(HashMap::new()),
            }
        }

        /// Keep certificate pins in `dir` instead of `~/.ztlp/quic_pins`.
        pub fn with_pin_dir(mut self, dir: PathBuf) -> Self {
            self.pin_dir = Some(dir);
            self
        }

        /// Override the per-candidate handshake budgets.
        pub fn with_timeouts(mut self, lan: Duration, public: Duration) -> Self {
            self.lan_timeout = lan;
            self.public_timeout = public;
            self
        }

        /// Hand over the connection established to `addr`, if any. Every
        /// other connection this dialer still holds (a candidate that also
        /// completed before the race was called) is closed.
        pub fn take_connection(&self, addr: SocketAddr) -> Option<QuicConnection> {
            let winner = self.lock_established().remove(&addr);
            self.close_all();
            winner
        }

        /// Close every connection this dialer still holds.
        pub fn close_all(&self) {
            for (_, spare) in self.lock_established().drain() {
                spare.close();
            }
        }

        /// The map only ever sees whole inserts and removes, so it is
        /// still consistent if another thread panicked while holding it.
        fn lock_established(
            &self,
        ) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, QuicConnection>> {
            self.established
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }
    }

    #[async_trait]
    impl Dialer for QuicHandshakeDialer {
        async fn dial(&self, addr: SocketAddr) -> Result<DialSuccess, DialError> {
            // Family-matched ephemeral socket, one per candidate.
            let bind_addr = match addr {
                SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            };
            let socket = std::net::UdpSocket::bind(bind_addr)
                .map_err(|e| DialError::Other(format!("bind {bind_addr}: {e}")))?;

            // Bounded by the orchestrator through `timeout_for`.
            let conn = QuicEndpoint::connect_with_socket_in_pin_dir(
                self.cfg.clone(),
                addr,
                &self.server_name,
                socket,
                None,
                CertExpectation::default(),
                self.pin_dir.clone(),
            )
            .await
            .map_err(|e| DialError::Other(e.to_string()))?;

            self.lock_established().insert(addr, conn);
            Ok(DialSuccess { addr })
        }

        fn timeout_for(&self, addr: SocketAddr) -> Option<Duration> {
            Some(if is_lan_candidate(addr.ip()) {
                self.lan_timeout
            } else {
                self.public_timeout
            })
        }
    }

    /// A direct path that completed its QUIC handshake.
    #[derive(Debug, Clone)]
    pub struct DirectConnection {
        /// The established connection, ready for the Noise handshake.
        pub conn: QuicConnection,
        /// The candidate address it was established to.
        pub addr: SocketAddr,
        /// How that candidate was classified (telemetry).
        pub class: CandidateClass,
    }

    /// Where [`connect_direct_first`] says the connect should go.
    #[derive(Debug)]
    pub enum DialRoute {
        /// A direct candidate answered; use this connection as-is.
        Direct(DirectConnection),
        /// No direct candidate answered; route through the relay at `addr`.
        Relay {
            addr: SocketAddr,
            direct_failure: MultiCandidateError,
        },
        /// No direct candidate answered and there is no relay to fall back
        /// to (none known, or the operator passed `--no-relay-fallback`).
        /// The caller keeps its NS-resolved address.
        Unresolved { direct_failure: MultiCandidateError },
    }

    /// Race real QUIC handshakes against the direct `candidates`; fall back
    /// to `relay_fallback` when none completes.
    ///
    /// The relay is deliberately not part of the race. It is a backstop
    /// that is assumed to work, not something to probe, so it must neither
    /// be reported as a failed candidate nor make the caller wait: as soon
    /// as the last direct candidate has failed (immediately when there are
    /// none) the function returns [`DialRoute::Relay`]. With the default
    /// timeouts that is at most [`LAN_CANDIDATE_TIMEOUT`] when all
    /// candidates are LAN addresses and [`DIRECT_RACE_BUDGET`] otherwise.
    pub async fn connect_direct_first(
        candidates: Vec<RankedCandidate>,
        relay_fallback: Option<SocketAddr>,
        dialer: Arc<QuicHandshakeDialer>,
        policy: DialPolicy,
    ) -> DialRoute {
        let class_of: HashMap<SocketAddr, CandidateClass> =
            candidates.iter().map(|c| (c.addr, c.class)).collect();

        let race = dial_candidates(candidates, dialer.clone() as Arc<dyn Dialer>, policy).await;
        let direct_failure = match race {
            Ok(DialSuccess { addr }) => match dialer.take_connection(addr) {
                Some(conn) => {
                    return DialRoute::Direct(DirectConnection {
                        conn,
                        addr,
                        class: class_of
                            .get(&addr)
                            .copied()
                            .unwrap_or(CandidateClass::HostPublicV4),
                    });
                }
                // Unreachable in practice: `dial` stores the connection
                // before it reports success. Treat it as a failed race
                // rather than panic.
                None => MultiCandidateError::AllFailed(format!(
                    "{addr} won the race but its connection was not retained"
                )),
            },
            Err(OrchestratorError::NoCandidates) => MultiCandidateError::NoCandidates,
            Err(e) => MultiCandidateError::AllFailed(format!("{e:?}")),
        };

        // Nothing won; close anything that still completed (a handshake
        // that finished just as the race budget ran out).
        dialer.close_all();

        match relay_fallback {
            Some(addr) => DialRoute::Relay {
                addr,
                direct_failure,
            },
            None => DialRoute::Unresolved { direct_failure },
        }
    }
}

/// Phase-1 dialer that probes a candidate's UDP reachability.
///
/// Sends `[0xFE, ..random8]` to the candidate and waits up to
/// per-candidate-timeout for ANY UDP packet back from that address.
/// Liveness only — content of the reply is not validated.
///
/// Legacy raw-UDP path only. Despite the name it performs no QUIC
/// handshake, and a QUIC listener never answers the probe; the QUIC
/// connect path uses [`QuicHandshakeDialer`] instead.
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

    fn fresh_identity() -> NodeIdentity {
        NodeIdentity::generate().expect("generate identity")
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
        let our_identity = fresh_identity();
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
            &our_identity,
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
        let our_identity = fresh_identity();
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
            &our_identity,
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
        let our_identity = fresh_identity();
        let peer_id = fresh_node_id();
        let policy = DialPolicy::default();

        let err = try_multi_candidate_connect(
            peer_id,
            ns_addr,
            our_socket,
            &our_identity,
            &[],
            None,
            policy,
        )
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
        let our_identity = fresh_identity();
        let peer_id = fresh_node_id();
        let policy = DialPolicy {
            per_candidate_timeout: Duration::from_millis(200),
            band_delay: Duration::from_millis(50),
            total_budget: Duration::from_secs(2),
        };
        let err = try_multi_candidate_connect(
            peer_id,
            ns_addr,
            our_socket,
            &our_identity,
            &[],
            None,
            policy,
        )
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
        let our_identity = fresh_identity();
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
            &our_identity,
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
        let our_identity = fresh_identity();
        let peer_id = fresh_node_id();
        // The NS_QUERY_TIMEOUT inside the helper is 3 s; we don't
        // override it. Test wraps the whole call in a 5 s safety
        // timeout so a regression here surfaces as a hang, not a
        // forever-pending test.
        let policy = DialPolicy::default();
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            try_multi_candidate_connect(
                peer_id,
                ns_addr,
                our_socket,
                &our_identity,
                &[],
                None,
                policy,
            ),
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

    // ── Direct-first: candidate selection (pure) ───────────────────────

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// 127.0.0.0/8 as an operator-declared local subnet, so loopback test
    /// listeners rank as `HostSameSubnet` instead of being dropped.
    fn loopback_subnet() -> Vec<(IpAddr, u8)> {
        vec![(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8u8)]
    }

    #[test]
    fn lan_addresses_get_the_short_handshake_budget() {
        for lan in [
            "10.20.30.40:23095",
            "172.16.5.6:23095",
            "192.168.1.10:23095",
            "100.64.0.9:23095",
            "169.254.3.4:23095",
            "127.0.0.1:23095",
            "[fd12:3456::1]:23095",
            "[fe80::1]:23095",
            "[::1]:23095",
        ] {
            assert!(is_lan_candidate(sa(lan).ip()), "{lan} is a LAN address");
            assert_eq!(direct_candidate_timeout(sa(lan)), LAN_CANDIDATE_TIMEOUT);
        }
        for public in [
            "203.0.113.7:23095",
            "198.51.100.1:23095",
            "172.32.0.1:23095",
            "100.128.0.1:23095",
            "[2001:db8::1]:23095",
        ] {
            assert!(!is_lan_candidate(sa(public).ip()), "{public} is public");
            assert_eq!(
                direct_candidate_timeout(sa(public)),
                PUBLIC_CANDIDATE_TIMEOUT
            );
        }
    }

    /// The fallback penalty this module exists to bound: an operator who
    /// is not on the peer's LAN waits well under a second, and the whole
    /// direct race can never reach the old 2 s probe timeout.
    #[test]
    fn direct_race_budgets_stay_below_the_old_probe_timeout() {
        assert!(LAN_CANDIDATE_TIMEOUT < Duration::from_secs(1));
        assert!(LAN_CANDIDATE_TIMEOUT <= PUBLIC_CANDIDATE_TIMEOUT);
        assert!(DIRECT_BAND_DELAY + PUBLIC_CANDIDATE_TIMEOUT <= DIRECT_RACE_BUDGET);
        assert!(DIRECT_RACE_BUDGET < Duration::from_secs(2));
        let policy = direct_dial_policy();
        assert_eq!(policy.per_candidate_timeout, PUBLIC_CANDIDATE_TIMEOUT);
        assert_eq!(policy.band_delay, DIRECT_BAND_DELAY);
        assert_eq!(policy.total_budget, DIRECT_RACE_BUDGET);
    }

    #[test]
    fn rank_direct_candidates_leaves_the_relay_out_of_the_race() {
        let lan = sa("10.20.30.40:23095");
        let relay = sa("203.0.113.9:23095");
        // The production shape: SVC record = [LAN, relay], and
        // PEER_ENDPOINTS repeats the LAN address.
        let ranked = rank_direct_candidates(&[lan, relay], &[lan], &[relay], &[]);
        assert_eq!(ranked.len(), 1, "relay excluded, LAN de-duplicated");
        assert_eq!(ranked[0].addr, lan);
        assert_eq!(ranked[0].class, CandidateClass::HostOtherRfc1918);
    }

    #[test]
    fn rank_direct_candidates_merges_ranks_and_filters() {
        let lan = sa("10.20.30.40:23095");
        let public = sa("198.51.100.20:40000");
        let same_subnet = sa("192.168.7.20:23095");
        let subnets = vec![(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 0)), 24u8)];
        let ranked = rank_direct_candidates(
            &[public, lan],
            &[
                same_subnet,
                sa("127.0.0.1:23095"), // loopback: this machine, not the peer
                sa("0.0.0.0:23095"),   // unspecified
                sa("10.9.9.9:0"),      // port 0
                public,                // duplicate
            ],
            &[],
            &subnets,
        );
        let addrs: Vec<SocketAddr> = ranked.iter().map(|c| c.addr).collect();
        assert_eq!(addrs, vec![same_subnet, lan, public], "best first");
    }

    #[test]
    fn rank_direct_candidates_with_only_a_relay_is_empty() {
        let relay = sa("203.0.113.9:23095");
        assert!(rank_direct_candidates(&[relay], &[], &[relay], &[]).is_empty());
    }

    // ── Direct-first: real QUIC handshakes on loopback ─────────────────

    #[cfg(feature = "quic-transport")]
    mod direct_first {
        use super::*;
        use crate::quic_transport::tokio_endpoint::QuicEndpoint;
        use crate::quic_transport::QuicEndpointConfig;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;

        /// A real QUIC listener (what `ztlp listen` binds) on a loopback
        /// port. Returns its address and a counter of accepted connections.
        async fn spawn_quic_listener() -> (SocketAddr, Arc<AtomicUsize>) {
            let cfg = QuicEndpointConfig {
                bind: Some(sa("127.0.0.1:0")),
                ..QuicEndpointConfig::default()
            };
            let endpoint = QuicEndpoint::bind(cfg).await.expect("bind QUIC listener");
            let addr = endpoint.inner.local_addr().expect("listener addr");
            let accepted = Arc::new(AtomicUsize::new(0));
            let counter = accepted.clone();
            tokio::spawn(async move {
                let mut live = Vec::new();
                while let Ok(conn) = endpoint.accept().await {
                    counter.fetch_add(1, Ordering::SeqCst);
                    live.push(conn); // keep accepted connections open
                }
            });
            (addr, accepted)
        }

        /// A bound UDP socket that counts datagrams and never answers:
        /// a candidate (or relay) address nothing reachable listens on.
        async fn spawn_counting_silent_socket() -> (SocketAddr, Arc<AtomicUsize>) {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap();
            let received = Arc::new(AtomicUsize::new(0));
            let counter = received.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                while sock.recv_from(&mut buf).await.is_ok() {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            });
            (addr, received)
        }

        /// Production timeouts, pins in a throwaway directory.
        fn dialer(pins: &tempfile::TempDir) -> Arc<QuicHandshakeDialer> {
            Arc::new(
                QuicHandshakeDialer::new(QuicEndpointConfig::default(), "localhost")
                    .with_pin_dir(pins.path().to_path_buf()),
            )
        }

        fn ranked(addrs: &[SocketAddr]) -> Vec<RankedCandidate> {
            let ranked = rank_direct_candidates(addrs, &[], &[], &loopback_subnet());
            assert_eq!(ranked.len(), addrs.len());
            ranked
        }

        /// FIX 1, the headline case: a reachable direct candidate that
        /// speaks QUIC (and does NOT echo UDP probes) is selected, quickly,
        /// and the caller gets a live connection to it.
        #[tokio::test]
        async fn responsive_direct_candidate_wins_with_a_real_handshake() {
            let pins = tempfile::tempdir().unwrap();
            let (listener, accepted) = spawn_quic_listener().await;
            let (relay, relay_datagrams) = spawn_counting_silent_socket().await;

            let started = Instant::now();
            let route = connect_direct_first(
                ranked(&[listener]),
                Some(relay),
                dialer(&pins),
                direct_dial_policy(),
            )
            .await;
            let elapsed = started.elapsed();

            let DialRoute::Direct(direct) = route else {
                panic!("expected the direct path, got {route:?}");
            };
            assert_eq!(direct.addr, listener);
            assert_eq!(direct.class, CandidateClass::HostSameSubnet);
            assert_eq!(direct.conn.inner.remote_address(), listener);
            assert!(
                direct.conn.inner.close_reason().is_none(),
                "the handed-over connection must be open"
            );
            assert!(
                elapsed < Duration::from_secs(1),
                "direct path must be chosen in well under 1 s, took {elapsed:?}"
            );
            // The listener saw exactly the one handshake that became the
            // connection, and the relay was never contacted.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(accepted.load(Ordering::SeqCst), 1);
            assert_eq!(relay_datagrams.load(Ordering::SeqCst), 0);
        }

        /// A reachable candidate wins even when another candidate in the
        /// same band never answers.
        #[tokio::test]
        async fn responsive_candidate_wins_next_to_an_unresponsive_one() {
            let pins = tempfile::tempdir().unwrap();
            let (dead, _) = spawn_counting_silent_socket().await;
            let (listener, _) = spawn_quic_listener().await;

            let started = Instant::now();
            let route = connect_direct_first(
                ranked(&[dead, listener]),
                None,
                dialer(&pins),
                direct_dial_policy(),
            )
            .await;

            let DialRoute::Direct(direct) = route else {
                panic!("expected the direct path, got {route:?}");
            };
            assert_eq!(direct.addr, listener);
            assert!(
                started.elapsed() < LAN_CANDIDATE_TIMEOUT,
                "the winner must not wait for the dead candidate to time out"
            );
        }

        /// FIX 1, the fallback case: when the only direct candidate does
        /// not answer, the relay is chosen within the LAN budget (plus
        /// scheduling slack), and the relay itself is never probed.
        #[tokio::test]
        async fn unresponsive_direct_candidate_falls_back_to_relay_within_bound() {
            let pins = tempfile::tempdir().unwrap();
            let (dead, probes) = spawn_counting_silent_socket().await;
            let (relay, relay_datagrams) = spawn_counting_silent_socket().await;

            let started = Instant::now();
            let route = connect_direct_first(
                ranked(&[dead]),
                Some(relay),
                dialer(&pins),
                direct_dial_policy(),
            )
            .await;
            let elapsed = started.elapsed();

            let DialRoute::Relay {
                addr,
                direct_failure,
            } = route
            else {
                panic!("expected the relay fallback, got {route:?}");
            };
            assert_eq!(addr, relay);
            assert!(
                matches!(&direct_failure, MultiCandidateError::AllFailed(why)
                    if why.contains(&dead.to_string()) && why.contains("Timeout")),
                "the failure must name the dead candidate, got {direct_failure:?}"
            );
            assert!(
                elapsed >= LAN_CANDIDATE_TIMEOUT,
                "the candidate must get its full budget, gave up after {elapsed:?}"
            );
            assert!(
                elapsed < LAN_CANDIDATE_TIMEOUT + Duration::from_millis(400),
                "fallback must come right after the LAN budget, took {elapsed:?}"
            );
            assert!(
                probes.load(Ordering::SeqCst) >= 1,
                "the direct candidate was really dialed"
            );
            assert_eq!(
                relay_datagrams.load(Ordering::SeqCst),
                0,
                "the relay is a backstop, not a candidate: it must not be probed"
            );
        }

        /// The old probe accepted ANY datagram back as proof of liveness.
        /// A UDP echo is not a QUIC handshake, so it no longer wins.
        #[tokio::test]
        async fn udp_echo_is_not_mistaken_for_a_reachable_peer() {
            let pins = tempfile::tempdir().unwrap();
            let (echo, _h) = spawn_echo_responder().await;
            let relay = sa("203.0.113.9:23095");

            let route = connect_direct_first(
                ranked(&[echo]),
                Some(relay),
                dialer(&pins),
                direct_dial_policy(),
            )
            .await;

            assert!(
                matches!(route, DialRoute::Relay { addr, .. } if addr == relay),
                "an echoing non-QUIC host must not be selected, got {route:?}"
            );
        }

        /// No direct candidates at all (the SVC record only lists the
        /// relay): go to the relay immediately, no waiting.
        #[tokio::test]
        async fn no_direct_candidates_goes_straight_to_relay() {
            let pins = tempfile::tempdir().unwrap();
            let relay = sa("203.0.113.9:23095");

            let started = Instant::now();
            let route =
                connect_direct_first(Vec::new(), Some(relay), dialer(&pins), direct_dial_policy())
                    .await;

            assert!(matches!(
                route,
                DialRoute::Relay {
                    addr,
                    direct_failure: MultiCandidateError::NoCandidates,
                } if addr == relay
            ));
            assert!(started.elapsed() < Duration::from_millis(100));
        }

        /// `--no-relay-fallback` (or no known relay): a failed direct race
        /// reports `Unresolved` and never invents a relay.
        #[tokio::test]
        async fn failed_race_without_a_relay_is_unresolved() {
            let pins = tempfile::tempdir().unwrap();
            let (dead, _) = spawn_counting_silent_socket().await;

            let route =
                connect_direct_first(ranked(&[dead]), None, dialer(&pins), direct_dial_policy())
                    .await;

            assert!(
                matches!(
                    route,
                    DialRoute::Unresolved {
                        direct_failure: MultiCandidateError::AllFailed(_)
                    }
                ),
                "got {route:?}"
            );
        }

        /// A candidate whose certificate does not match the pin stored for
        /// its address (a different gateway behind the same private IP) is
        /// rejected, not adopted as the direct path.
        #[tokio::test]
        async fn candidate_with_a_mismatched_pin_is_not_selected() {
            let pins = tempfile::tempdir().unwrap();
            let (listener, _) = spawn_quic_listener().await;
            let relay = sa("203.0.113.9:23095");

            // First dial pins the listener's certificate.
            let first = connect_direct_first(
                ranked(&[listener]),
                Some(relay),
                dialer(&pins),
                direct_dial_policy(),
            )
            .await;
            assert!(matches!(first, DialRoute::Direct(_)), "got {first:?}");

            // Corrupt every stored pin: the next handshake presents a
            // certificate that no longer matches.
            let mut rewritten = 0;
            for entry in std::fs::read_dir(pins.path()).unwrap() {
                std::fs::write(entry.unwrap().path(), "00".repeat(32)).unwrap();
                rewritten += 1;
            }
            assert_eq!(rewritten, 1, "exactly one pin for the one candidate");

            let second = connect_direct_first(
                ranked(&[listener]),
                Some(relay),
                dialer(&pins),
                direct_dial_policy(),
            )
            .await;
            assert!(
                matches!(second, DialRoute::Relay { addr, .. } if addr == relay),
                "a pin mismatch must fail the candidate, got {second:?}"
            );
        }

        /// The fake NS + `query_peer_endpoints` + ranking, end to end.
        #[tokio::test]
        async fn peer_endpoints_feed_the_direct_race() {
            let pins = tempfile::tempdir().unwrap();
            let (listener, _) = spawn_quic_listener().await;
            let (ns_addr, _ns) = spawn_fake_ns(build_peer_endpoints_response(&[listener])).await;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let endpoints = query_peer_endpoints(
                fresh_node_id(),
                ns_addr,
                &socket,
                &fresh_identity(),
                DIRECT_PEER_ENDPOINTS_TIMEOUT,
            )
            .await
            .expect("PEER_ENDPOINTS answer");
            assert_eq!(endpoints, vec![listener]);

            let relay = sa("203.0.113.9:23095");
            let candidates =
                rank_direct_candidates(&[relay], &endpoints, &[relay], &loopback_subnet());
            let route =
                connect_direct_first(candidates, Some(relay), dialer(&pins), direct_dial_policy())
                    .await;
            assert!(
                matches!(&route, DialRoute::Direct(d) if d.addr == listener),
                "got {route:?}"
            );
        }

        /// `query_peer_endpoints` gives up after the wait it is given.
        #[tokio::test]
        async fn peer_endpoints_query_honours_its_timeout() {
            let (ns_addr, _h) = spawn_silent_listener().await;
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

            let started = Instant::now();
            let res = query_peer_endpoints(
                fresh_node_id(),
                ns_addr,
                &socket,
                &fresh_identity(),
                Duration::from_millis(200),
            )
            .await;

            assert!(matches!(res, Err(MultiCandidateError::NsQueryFailed(_))));
            assert!(started.elapsed() < Duration::from_secs(1));
        }
    }
}
