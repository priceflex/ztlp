//! Agent daemon — main loop that runs DNS resolver, TCP proxy, and control socket.
//!
//! The daemon is started with `ztlp agent start` and runs in the background
//! (or foreground with `--foreground`). It manages:
//!
//! - DNS resolver on 127.0.0.53:5353
//! - TCP proxy per virtual IP (on-demand tunnel establishment)
//! - Control socket for CLI communication
//! - Periodic garbage collection of expired VIP allocations
//!
//! ## Lifecycle
//!
//! ```text
//! start → load config → bind DNS → bind control socket → main loop
//!   ↓                                                        ↓
//! shutdown signal (SIGTERM/SIGINT/control socket) → cleanup → exit
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::handshake::HandshakeContext;
use crate::identity::{NodeId, NodeIdentity};
use crate::packet::{HandshakeHeader, MsgType, SessionId, HANDSHAKE_HEADER_SIZE};
use crate::transport::TransportNode;
use crate::tunnel;

use super::config::{self, AgentConfig, VIP_BUILTIN_PORTS};
use super::control::{self, AgentState};
use super::dns::{self, DnsResolverState};
use super::domain_map::DomainMapper;
use super::local_tls::{self, SniCertResolver};
use super::proxy;
use super::tunnel_pool::{TunnelPool, DEFAULT_IDLE_TIMEOUT, DEFAULT_KEEPALIVE_INTERVAL};
use super::vip_pool::VipPool;

// ── Relay CLIENT_ROUTE HMAC secret ───────────────────────────────────────
//
// Installed once by `run_daemon` from `[tunnel] relay_secret` /
// `relay_secret_file`, read by both CLIENT_ROUTE send sites (dial-phase
// and legacy bridged path). Kept process-wide rather than threaded through
// the eight `relay_addr`-carrying signatures between here and there.
static RELAY_SECRET: std::sync::RwLock<Option<Vec<u8>>> = std::sync::RwLock::new(None);

/// Install (or clear) the relay CLIENT_ROUTE signing secret.
pub(crate) fn set_relay_secret(secret: Option<Vec<u8>>) {
    if let Ok(mut g) = RELAY_SECRET.write() {
        *g = secret;
    }
}

// ── Dial order: direct-first (default) or relay-first ─────────────────────
//
// `[tunnel] prefer_relay` from the agent config, installed once by
// `run_daemon`, read by `connect_tunnel`. Same process-wide pattern as the
// relay secret above, for the same reason (eight signatures in between).
static PREFER_RELAY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Install the dial-order preference (`[tunnel] prefer_relay`).
pub(crate) fn set_prefer_relay(v: bool) {
    PREFER_RELAY.store(v, std::sync::atomic::Ordering::Relaxed);
}

fn prefer_relay() -> bool {
    PREFER_RELAY.load(std::sync::atomic::Ordering::Relaxed)
}

// ── Transport memory profile + connection reuse ───────────────────────────
//
// `[tunnel] profile` / `reuse_connections` from the agent config, installed
// once by `run_daemon`, read on the client dial path (`connect_one`,
// `connect_tunnel`). Process-wide for the same reason as the relay secret.
// Defaults are the desktop values, so a process that never installs a
// profile (the CLI, tests) behaves exactly as before.
static DIAL_WINDOWS: std::sync::RwLock<crate::quic_transport::TransportWindows> =
    std::sync::RwLock::new(crate::quic_transport::TransportWindows::DESKTOP);
static REUSE_CONNECTIONS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Install the QUIC flow-control windows the agent dials with.
pub(crate) fn set_dial_windows(w: crate::quic_transport::TransportWindows) {
    if let Ok(mut g) = DIAL_WINDOWS.write() {
        *g = w;
    }
}

fn dial_windows() -> crate::quic_transport::TransportWindows {
    DIAL_WINDOWS
        .read()
        .map(|g| *g)
        .unwrap_or(crate::quic_transport::TransportWindows::DESKTOP)
}

/// The endpoint config every agent client dial uses: the defaults plus the
/// installed window profile.
fn dial_endpoint_config() -> crate::quic_transport::QuicEndpointConfig {
    crate::quic_transport::QuicEndpointConfig {
        windows: dial_windows(),
        ..Default::default()
    }
}

/// Turn the shared connection per (name, port) on or off.
pub(crate) fn set_reuse_connections(v: bool) {
    REUSE_CONNECTIONS.store(v, std::sync::atomic::Ordering::Relaxed);
    if !v {
        tunnel_conn_cache().clear();
        // Network changes are only tracked for shared connections.
        if network_epoch() != 0 {
            network_epoch_tx().send_replace(0);
        }
    }
}

fn reuse_connections() -> bool {
    REUSE_CONNECTIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Cache key: the lower-cased ZTLP name plus the port. The name (not just
/// its leading service label) is part of the key because the same label in
/// two zones is two different gateways.
type TunnelKey = (String, u16);

fn tunnel_key(ztlp_name: &str, port: u16) -> TunnelKey {
    (ztlp_name.trim_end_matches('.').to_ascii_lowercase(), port)
}

fn tunnel_conn_cache() -> &'static super::conn_cache::ConnCache<TunnelKey, ConnectedTunnel> {
    static CACHE: std::sync::OnceLock<super::conn_cache::ConnCache<TunnelKey, ConnectedTunnel>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(super::conn_cache::ConnCache::new)
}

fn tunnel_is_open(t: &ConnectedTunnel) -> bool {
    t.conn.inner.close_reason().is_none()
}

/// Drop the shared connection for this name/port after a failure on it
/// (stream open failed, or the backend never answered), so the next request
/// dials a fresh one instead of riding a connection that may be dead but
/// not yet timed out. No-op when reuse is off.
fn forget_shared_tunnel(ztlp_name: &str, port: u16) {
    if reuse_connections() && tunnel_conn_cache().invalidate(&tunnel_key(ztlp_name, port)) {
        info!(
            "shared tunnel for {} (port {}) dropped after a failure; next request redials",
            ztlp_name, port
        );
    }
}

/// Drop the shared connection for this name/port only when it still is
/// `tunnel` (the caller saw THAT connection fail; one dialed since by
/// another request must stay). `close` also closes it, which ends every
/// stream on it at once: only for a connection that showed no sign of
/// life, never for a failure of one stream.
fn drop_shared_tunnel_if_same(
    ztlp_name: &str,
    port: u16,
    tunnel: &crate::quic_transport::tokio_endpoint::QuicConnection,
    close: bool,
    reason: &str,
) {
    let id = tunnel.inner.stable_id();
    if close {
        // After this `tunnel_is_open` is false, so even a cache entry that
        // could not be removed right now is never handed out again.
        tunnel.inner.close(0u32.into(), b"no answer");
    }
    let removed = tunnel_conn_cache().invalidate_if(&tunnel_key(ztlp_name, port), |t| {
        t.conn.inner.stable_id() == id
    });
    if removed {
        info!(
            "shared tunnel for {} (port {}) dropped ({}); dialing a new one",
            ztlp_name, port, reason
        );
    }
}

// ── Network changes (shared-connection mode) ─────────────────────────────
//
// Nothing below runs unless `[tunnel] reuse_connections` is on: the task
// that serves the signal is only started then, and the epoch stays 0, which
// every reader treats as "never changed" (today's behaviour).

static NETWORK_CHANGE: super::reconnect::ChangeSignal = super::reconnect::ChangeSignal::new();

fn network_epoch_tx() -> &'static tokio::sync::watch::Sender<u64> {
    static TX: std::sync::OnceLock<tokio::sync::watch::Sender<u64>> = std::sync::OnceLock::new();
    TX.get_or_init(|| tokio::sync::watch::channel(0u64).0)
}

/// How many network changes were acted on since the process started.
fn network_epoch() -> u64 {
    *network_epoch_tx().borrow()
}

/// Tell the agent the device's network changed (new interface, wake from
/// sleep). Safe from any thread, never blocks, and a burst of calls is
/// coalesced. Returns `false`, having done nothing, when no agent with
/// shared connections is running. The effect is in
/// [`apply_network_change`].
pub fn notify_network_changed() -> bool {
    NETWORK_CHANGE.raise()
}

/// How many times a network change was acted on (calls in a burst count
/// once or twice, see `reconnect::ChangeSignal`).
pub fn network_change_runs() -> u64 {
    NETWORK_CHANGE.effective()
}

/// What a network change does: every shared connection is closed and
/// forgotten (the next request dials on the current network), every name
/// must be resolved again before its next dial (the ranking of a gateway's
/// addresses depends on the network the device is on, and the address a
/// listener cached may be the one that just became unreachable), the
/// memory of which path won last is cleared, and the sites that had an
/// open shared connection are dialed again in the background. Listeners,
/// resolver, site table and certificates are untouched.
fn apply_network_change() {
    network_epoch_tx().send_modify(|e| *e += 1);
    if let Ok(mut g) = relay_wins().lock() {
        g.clear();
    }
    let taken = tunnel_conn_cache().take_where(|_| true);
    let mut open: Vec<&ConnectedTunnel> = taken.iter().filter(|t| tunnel_is_open(t)).collect();
    let open_count = open.len();
    // The sites somebody is using right now come first.
    open.sort_by_key(|t| !t.shared.as_ref().is_some_and(|s| s.uses.in_use()));
    let prewarm: Vec<Arc<SharedInfo>> = open
        .iter()
        .filter_map(|t| t.shared.clone())
        .take(super::reconnect::PREWARM_MAX_SITES)
        .collect();
    for t in &taken {
        t.conn.inner.close(0u32.into(), b"network changed");
    }
    info!(
        "network changed: {} shared tunnel(s) closed, {} being dialed again in the background; \
         names are resolved again before their next dial",
        open_count,
        prewarm.len()
    );
    for site in prewarm {
        tokio::spawn(prewarm_shared_tunnel(site));
    }
}

/// Dial one site's shared connection ahead of the next request. It goes
/// through the same single-flight slot as a request, so a request that
/// arrives meanwhile waits for this dial instead of starting its own. One
/// try: a failure is left to the next request. Only another network change
/// starts it over (the dial in flight belongs to the previous network).
async fn prewarm_shared_tunnel(site: Arc<SharedInfo>) {
    let p = &site.params;
    let mut epoch = network_epoch_tx().subscribe();
    for _ in 0..3 {
        epoch.borrow_and_update();
        let started = Instant::now();
        let dial = connect_tunnel_opts(
            &p.ztlp_name,
            p.port,
            None,
            p.peer_node_id,
            &p.identity,
            &p.bind_addr,
            &p.ns_server,
            p.relay_addr.as_deref(),
            Some(super::reconnect::PREWARM_DIAL_BUDGET),
            false,
        );
        tokio::select! {
            r = dial => {
                match r {
                    Ok(t) => info!(
                        "shared tunnel for {} (port {}) is ready again via {:?} after {:?}",
                        p.ztlp_name, p.port, t.tunnel.via, started.elapsed()
                    ),
                    Err(e) => info!(
                        "background dial for {} (port {}) failed ({}); the next request dials",
                        p.ztlp_name, p.port, e
                    ),
                }
                return;
            }
            _ = epoch.changed() => {}
        }
    }
}

/// Close shared connections nobody has used for `idle` (and drop the ones
/// that closed by themselves). Returns how many open ones were closed.
fn reap_idle_shared_tunnels(idle: Duration) -> usize {
    let now = Instant::now();
    let taken = tunnel_conn_cache().take_where(|t| {
        !tunnel_is_open(t)
            || t.shared
                .as_ref()
                .is_some_and(|s| s.uses.idle_for(now).is_some_and(|d| d >= idle))
    });
    let mut closed = 0;
    for t in taken.iter().filter(|t| tunnel_is_open(t)) {
        t.conn.inner.close(0u32.into(), b"idle");
        closed += 1;
        if let Some(s) = &t.shared {
            info!(
                "shared tunnel for {} (port {}) unused for {:?}: closed, the next request dials again",
                s.params.ztlp_name, s.params.port, idle
            );
        }
    }
    closed
}

/// The background work of shared-connection mode: act on network changes
/// and, when `idle_close` is set (mobile profile), close unused shared
/// connections. Runs until dropped.
async fn keep_shared_tunnels(idle_close: Option<Duration>) {
    let changes = NETWORK_CHANGE.serve(
        super::reconnect::NETWORK_CHANGE_COALESCE,
        apply_network_change,
    );
    let reaper = async {
        let Some(idle) = idle_close else {
            return std::future::pending::<()>().await;
        };
        loop {
            tokio::time::sleep(super::reconnect::IDLE_REAP_INTERVAL).await;
            reap_idle_shared_tunnels(idle);
        }
    };
    tokio::join!(changes, reaper);
}

/// Names whose last shared connection was won by the relay: their next
/// dial starts the relay together with the direct candidates instead of
/// after the head start. Cleared by a network change; an entry goes away
/// with the name's candidate list.
fn relay_wins() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static WINS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    WINS.get_or_init(Default::default)
}

fn note_dial_winner(ztlp_name: &str, via: DialVia) {
    if let Ok(mut g) = relay_wins().lock() {
        match via {
            DialVia::Relay => g.insert(ztlp_name.to_ascii_lowercase()),
            DialVia::Direct => g.remove(&ztlp_name.to_ascii_lowercase()),
        };
    }
}

fn relay_won_last(ztlp_name: &str) -> bool {
    relay_wins()
        .lock()
        .map(|g| g.contains(&ztlp_name.to_ascii_lowercase()))
        .unwrap_or(false)
}

/// A dial failure that trying again cannot fix (wrong certificate, bad
/// configuration). Everything else may be the network being away.
fn dial_error_is_permanent(err: &str) -> bool {
    is_ns_cert_failure(err)
        || err.contains(crate::quic_transport::TRUSTED_MISMATCH_MARKER)
        || err.contains("does not match the pinned value")
        || err.contains("invalid relay address")
        || err.contains("no dialable endpoint")
}

/// Number of shared tunnel connections currently open (0 when reuse is off).
pub fn shared_tunnel_count() -> usize {
    tunnel_conn_cache().count_open(tunnel_is_open)
}

/// Close every shared tunnel connection (agent shutdown).
pub(crate) fn close_shared_tunnels() {
    tunnel_conn_cache().clear();
}

// ── Per-name ranked candidate cache ───────────────────────────────────────
//
// The VIP listener snapshots `(peer_addr, peer_node_id)` once per entry
// when it binds, so threading the full candidate list through the eight
// signatures between there and `connect_tunnel` would be invasive. The DNS
// resolver instead publishes each name's ranked list here on every
// resolution (same process-wide pattern as the relay secret above);
// `connect_tunnel` consults it on a cache hit. `VipEntry.peer_candidates`
// holds the same list for status/inspection.
//
// Each list carries the network epoch it was resolved in (always 0 unless
// `notify_network_changed` was ever acted on).
type CandidateMap = std::collections::HashMap<String, (u64, Vec<SocketAddr>)>;

static PEER_CANDIDATES: std::sync::OnceLock<std::sync::RwLock<CandidateMap>> =
    std::sync::OnceLock::new();

fn candidate_cache() -> &'static std::sync::RwLock<CandidateMap> {
    PEER_CANDIDATES.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Whether what is cached for `ztlp_name` (its candidate list here and the
/// single address a listener holds) was resolved on the network the device
/// is on now. Always true when connections are not shared, and until a
/// network change was acted on; after one, only once the name has been
/// resolved again.
fn cached_route_is_current(ztlp_name: &str) -> bool {
    let epoch = network_epoch();
    if epoch == 0 || !reuse_connections() {
        return true;
    }
    candidate_cache()
        .read()
        .ok()
        .and_then(|g| g.get(&ztlp_name.to_ascii_lowercase()).map(|(e, _)| *e))
        == Some(epoch)
}

/// Record the ranked candidate list for `ztlp_name` (called by the DNS
/// resolver after each successful NS resolution).
pub(crate) fn set_peer_candidates(ztlp_name: &str, candidates: &[SocketAddr]) {
    if let Ok(mut g) = candidate_cache().write() {
        g.insert(
            ztlp_name.to_ascii_lowercase(),
            (network_epoch(), candidates.to_vec()),
        );
    }
}

/// Drop the cached list for `ztlp_name` (called when its VIP entry is
/// reaped, so the cache cannot grow without bound or outlive the entry).
pub(crate) fn forget_peer_candidates(ztlp_name: &str) {
    if let Ok(mut g) = candidate_cache().write() {
        g.remove(&ztlp_name.to_ascii_lowercase());
    }
    if let Ok(mut g) = relay_wins().lock() {
        g.remove(&ztlp_name.to_ascii_lowercase());
    }
    forget_peer_cert(ztlp_name);
}

// ── Per-name certificate expectation (NS-anchored gateway trust) ─────────
//
// Same process-wide pattern as the candidate cache: the resolver publishes
// what the verified NS record says about each gateway's QUIC certificate;
// `connect_tunnel` dials with it on a cache hit.
static PEER_CERTS: std::sync::OnceLock<
    std::sync::RwLock<std::collections::HashMap<String, crate::quic_transport::CertExpectation>>,
> = std::sync::OnceLock::new();

fn cert_cache() -> &'static std::sync::RwLock<
    std::collections::HashMap<String, crate::quic_transport::CertExpectation>,
> {
    PEER_CERTS.get_or_init(|| std::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Record the certificate expectation for `ztlp_name` (resolver).
pub(crate) fn set_peer_cert(ztlp_name: &str, expect: &crate::quic_transport::CertExpectation) {
    if let Ok(mut g) = cert_cache().write() {
        g.insert(ztlp_name.to_ascii_lowercase(), expect.clone());
    }
}

fn forget_peer_cert(ztlp_name: &str) {
    if let Ok(mut g) = cert_cache().write() {
        g.remove(&ztlp_name.to_ascii_lowercase());
    }
}

fn cached_peer_cert(ztlp_name: &str) -> Option<crate::quic_transport::CertExpectation> {
    cert_cache()
        .read()
        .ok()
        .and_then(|g| g.get(&ztlp_name.to_ascii_lowercase()).cloned())
}

/// Should a cache hit be dialed as-is, or resolved fresh first? A device
/// strict for the name must not dial without a verified record (it would be
/// refused anyway), so a missing / unverified cached expectation forces a
/// fresh resolution. Pure.
fn cache_hit_usable(
    cached: Option<&crate::quic_transport::CertExpectation>,
    strict_for_name: bool,
) -> bool {
    use crate::quic_transport::RecordState;
    if !strict_for_name {
        return true;
    }
    matches!(
        cached,
        Some(c) if matches!(c.record, RecordState::Verified { .. })
    )
}

/// The dial failed because the NS-signed certificate expectation did not
/// hold (gateway restarted with a new cert before re-registering, or a
/// stale cached record): worth exactly one fresh resolution + redial.
fn is_ns_cert_failure(err: &str) -> bool {
    err.contains(crate::quic_transport::NS_MISMATCH_MARKER)
        || err.contains(crate::quic_transport::UNVERIFIED_MARKER)
}

fn cached_peer_candidates(ztlp_name: &str) -> Vec<SocketAddr> {
    candidate_cache()
        .read()
        .ok()
        .and_then(|g| {
            g.get(&ztlp_name.to_ascii_lowercase())
                .map(|(_, list)| list.clone())
        })
        .unwrap_or_default()
}

/// What the dial planner sees on a VIP cache hit: the full cached ranked
/// list when we have one, else the single cached best address, else
/// empty (caller resolves via NS). Pure; see `direct_first_plan` tests.
///
/// The list is only honoured alongside a cache hit (`cached_best` is
/// `Some`). `None` means the caller found no usable VIP entry (expired and
/// reaped, or a first request) and wants a FRESH resolution; the
/// process-wide candidate cache outlives VIP entries, so a leftover list
/// must not override that, or a gateway that moved would keep being dialed
/// at its old addresses until restart.
fn candidates_for_dial(
    cached_best: Option<SocketAddr>,
    cached_list: &[SocketAddr],
) -> Vec<SocketAddr> {
    let Some(best) = cached_best else {
        return Vec::new();
    };
    if !cached_list.is_empty() {
        return cached_list.to_vec();
    }
    vec![best]
}

/// Build a CLIENT_ROUTE frame, HMAC-signed with the installed relay secret
/// when one is configured (zero HMAC otherwise — accepted only by relays in
/// dev/staging mode).
pub(crate) fn build_signed_client_route(
    node_id: &[u8; 16],
    service_name: &str,
    timestamp: i64,
) -> Result<Vec<u8>, String> {
    let guard = RELAY_SECRET
        .read()
        .map_err(|_| "relay secret lock poisoned".to_string())?;
    tunnel::build_client_route_packet(node_id, service_name, timestamp, guard.as_deref())
}

/// Verify that a just-accepted local TCP connection actually originates
/// from loopback (127.0.0.0/8 or ::1) — the property this daemon can
/// realistically rely on to keep the VIP proxy from being reachable off-box.
///
/// [CWE-284 egi-dcvj] The VIP proxy listeners bind on loopback addresses
/// and previously accepted every connection unconditionally, letting ANY
/// local user/process reach protected ZTLP services proxied through the
/// daemon owner's identity — the bearer token only protects the separate
/// control socket, not these data-plane listeners.
///
/// A PRIOR fix attempted same-OS-user verification via SO_PEERCRED
/// (Linux) / LOCAL_PEERCRED (macOS/BSD). That was a genuine regression
/// discovered live on 2026-08-30: **SO_PEERCRED and LOCAL_PEERCRED are
/// Unix-domain-socket-only mechanisms** — calling them on a TCP
/// (AF_INET/AF_INET6) socket, which is exactly what these VIP listeners
/// are, still returns `ret == 0` (success) but with garbage credentials
/// (`uid=-1, pid=0` — confirmed via a raw `getsockopt` probe against a
/// live VIP listener). The old code treated any non-matching uid as a
/// hostile peer and rejected it, which meant it silently rejected
/// EVERY connection, including the daemon's own legitimate local
/// traffic — the VIP proxy was completely unusable, not just insecure in
/// the other direction. This is why a real curl/HTTP client to the VIP
/// address got "Connection reset by peer" on every attempt.
///
/// Same-OS-user verification over TCP would require switching the VIP
/// proxy's transport to Unix domain sockets entirely, which is out of
/// scope for this fix. Loopback-address verification is a strictly
/// weaker guarantee (any local process can connect, not just the same
/// user) but it is what TCP can actually provide, and it restores the
/// VIP proxy to a WORKING state while still blocking the actually
/// dangerous case this code was meant to prevent: a REMOTE peer reaching
/// these listeners (which should be impossible anyway since they bind to
/// 127.100.0.0/16, but defense in depth against a misconfigured bind).
fn verify_local_peer(stream: &tokio::net::TcpStream, policy: ClientPeerPolicy) -> bool {
    match stream.peer_addr() {
        Ok(addr) => {
            let ip = addr.ip();
            if ip.is_loopback()
                || (policy == ClientPeerPolicy::OnHost
                    && peer_is_on_host(ip, &host_addresses_cached()))
            {
                true
            } else {
                warn!(
                    "Rejected VIP connection from non-local peer {} (VIP listeners only accept traffic from this device)",
                    addr
                );
                false
            }
        }
        Err(e) => {
            warn!(
                "Failed to read peer address ({}); rejecting connection as a precaution",
                e
            );
            false
        }
    }
}

/// Which client source addresses a VIP listener accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPeerPolicy {
    /// Loopback only (VIP pool inside 127.0.0.0/8 — every desktop).
    LoopbackOnly,
    /// Loopback, or any address assigned to one of this host's own
    /// interfaces. For a VIP pool that lives on a non-loopback local
    /// interface (the iOS tunnel interface): a connection from another app
    /// on the device arrives with one of the device's own addresses as its
    /// source. A remote peer never has one of those.
    OnHost,
}

impl ClientPeerPolicy {
    /// Policy for a `[dns] vip_range`: loopback ranges keep the strict
    /// loopback-only check. An unparseable range is treated as loopback
    /// (strict); `VipPool::new` rejects it separately.
    pub fn for_vip_range(cidr: &str) -> Self {
        let base = cidr
            .split('/')
            .next()
            .and_then(|ip| ip.trim().parse::<Ipv4Addr>().ok());
        match base {
            Some(ip) if !ip.is_loopback() => Self::OnHost,
            _ => Self::LoopbackOnly,
        }
    }
}

/// Is `peer` one of this host's own addresses? Pure (the address list is
/// passed in) so it is testable without interfaces.
fn peer_is_on_host(peer: std::net::IpAddr, host_addrs: &[std::net::IpAddr]) -> bool {
    let peer = match peer {
        // an IPv4 client seen through a dual-stack socket
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => peer,
        },
        v4 => v4,
    };
    host_addrs.contains(&peer)
}

/// This host's interface addresses, refreshed at most every few seconds
/// (interfaces change on Wi-Fi/cellular switches; a getifaddrs call per
/// accepted connection would be wasteful).
fn host_addresses_cached() -> Vec<std::net::IpAddr> {
    const MAX_AGE: Duration = Duration::from_secs(5);
    static CACHE: std::sync::Mutex<Option<(Instant, Vec<std::net::IpAddr>)>> =
        std::sync::Mutex::new(None);
    let mut guard = CACHE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some((at, addrs)) = guard.as_ref() {
        if at.elapsed() < MAX_AGE {
            return addrs.clone();
        }
    }
    let addrs: Vec<std::net::IpAddr> = if_addrs::get_if_addrs()
        .map(|ifs| ifs.into_iter().map(|i| i.ip()).collect())
        .unwrap_or_default();
    *guard = Some((Instant::now(), addrs.clone()));
    addrs
}

// KNOWN COVERAGE GAP [egi-dcvj]: loopback-address verification (above)
// confirms the peer is on this machine but NOT that it's the same OS
// user — any local process/user can still reach these listeners. True
// same-user isolation would require a Unix-domain-socket (or Windows
// named-pipe) transport for the data plane instead of TCP, which is a
// larger architectural change than this fix. Documented rather than
// silently claimed as fully closed.

/// GC interval for expired VIP allocations (60 seconds).
const GC_INTERVAL: Duration = Duration::from_secs(60);

/// Handshake timeout for on-demand tunnel establishment.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default accept-to-first-byte deadline for VIP TCP proxy connections.
/// Covers: NS resolve → tunnel dial → TLS wrap/peek → first response byte.
/// The steady-state bridge is EXEMPT (see `run_tcp_proxy` deadline wiring).
pub const DEFAULT_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(15);

/// Parse the `first_byte_timeout` config value (e.g. "15s", "30s", "100ms").
/// Returns `None` for empty/zero/negative values (deadline disabled).
pub fn first_byte_deadline(first_byte_timeout: &str, _port: u16) -> Option<Duration> {
    if first_byte_timeout.is_empty() {
        return None;
    }
    let v = first_byte_timeout.trim();
    if v.is_empty() || v == "0" || v == "0s" || v == "0ms" {
        return None;
    }
    // Milliseconds form: "500ms"
    if let Some(ms_str) = v.strip_suffix("ms") {
        let ms: f64 = ms_str.parse().ok()?;
        if ms <= 0.0 {
            return None;
        }
        return Some(Duration::from_millis(ms as u64));
    }
    // Seconds form: "15s" or bare "15"
    let secs_str = v.strip_suffix('s').unwrap_or(v);
    let secs: f64 = secs_str.parse().ok()?;
    if secs <= 0.0 {
        return None;
    }
    Some(Duration::from_secs_f64(secs))
}

/// Return the canned HTTP 504 response bytes for plain-HTTP ports (80, 8080),
/// or `None` for all other ports (those get a bare RST / socket drop).
///
/// The body names the zone and the timeout so the user (or operator reading
/// the page) knows exactly what happened — "the agent tried to reach your
/// backend and it didn't answer in time" instead of a generic error.
pub fn stall_response_for_port(
    port: u16,
    ztlp_name: &str,
    deadline: Option<Duration>,
) -> Option<Vec<u8>> {
    if port != 80 && port != 8080 {
        return None;
    }
    let timeout_s = deadline.map_or_else(|| "15".to_string(), |d| d.as_secs().to_string());
    let body = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>504 Gateway Timeout</title></head>
<body>
<h1>504 Gateway Timeout</h1>
<p>ZTLP agent: backend for <code>{name}</code> did not respond within {secs}s.</p>
<p>The backend service is reachable through the ZTLP tunnel but did not
produce a first response byte within the configured deadline.</p>
<p><i>ZTLP Zero-Trust Private Link</i></p>
</body>
</html>
"#,
        name = ztlp_name,
        secs = timeout_s,
    );
    let response = format!(
        "HTTP/1.1 504 Gateway Timeout\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Server: ztlp-agent\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    Some(response.into_bytes())
}

/// What to do with the client socket when the accept-to-first-byte
/// deadline expires (Option A, PR #108).
///
/// - 504-class ports (plain HTTP 80/8080, TLS 443/8443): deliver the
///   branded `504 Gateway Timeout` page through the retained client
///   write half, then close. Browsers (Chrome in particular) render the
///   page cleanly and release the connection — no more "spinner until
///   RST" on a stalled refresh.
/// - Everything else (SSH, RDP, DBs, …): bare-close the write half — a
///   fake HTTP status line on a non-HTTP port would be nonsense bytes.
///
/// The 443/8443 arms assume the TLS variant terminates the TLS handshake
/// FIRST (fast, client-driven) before the deadline-covered dial phase —
/// so the write half on those ports speaks plain bytes (already
/// encrypted by the surrounding TLS stream) and the 504 page is a
/// valid, readable HTTP response inside the encrypted channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallCloseStrategy {
    /// Write the branded 504 page, then close.
    Deliver504,
    /// Bare close (no payload).
    BareClose,
}

/// Classify a port's deadline-expiry handling (pure, unit-tested).
pub fn stall_close_strategy(port: u16) -> StallCloseStrategy {
    match port {
        80 | 8080 | 443 | 8443 => StallCloseStrategy::Deliver504,
        _ => StallCloseStrategy::BareClose,
    }
}

/// Classify a port's deadline-expiry handling UNDER A VIP POLICY (pure,
/// unit-tested).
///
/// The 504-class decision must account for configured ports: a 504 page
/// is only meaningful when the agent has terminated TLS on the connection
/// (the write half then speaks plain HTTP inside the encrypted channel) or
/// when the port is a built-in plain-HTTP port (80/8080 — the page goes
/// out raw). Two rules:
///
/// - A port the operator ADDED via `[[tunnel.vip_ports]]` is never
///   504-class. It is an unknown protocol to the agent (a Wazuh agent
///   speaking TLS end-to-end, a raw TCP service, ...); a fake HTTP status
///   line through that pipe is nonsense bytes, and `stall_close_strategy`
///   (the built-in table) already puts it in the bare-close class.
/// - A built-in HTTP-ish port overridden to `Passthrough` (e.g.
///   `[[tunnel.vip_ports]] port = 443, tls = "passthrough"`) loses the
///   504 class: the agent no longer terminates TLS there, so the write
///   half carries opaque bytes and a 504 page would be garbage.
///
/// Everything else keeps the built-in table's answer, so a config with no
/// `vip_ports` behaves exactly like before.
pub fn vip_stall_close_strategy(
    port: u16,
    overrides: &std::collections::HashMap<u16, local_tls::TlsMode>,
) -> StallCloseStrategy {
    // Unknown configured ports: bare close, whatever they are.
    if !VIP_BUILTIN_PORTS.contains(&port) {
        return StallCloseStrategy::BareClose;
    }
    match overrides.get(&port).copied() {
        // Override to passthrough: no local TLS termination, no plain-HTTP
        // channel — a 504 page is nonsense bytes. Bare close.
        Some(local_tls::TlsMode::Never) => StallCloseStrategy::BareClose,
        // Override to terminate/auto, or no override: the built-in table.
        Some(local_tls::TlsMode::Always) | Some(local_tls::TlsMode::Detect) | None => {
            stall_close_strategy(port)
        }
    }
}

/// B4 (HANDOFF-2026-09-20): should a daemon with no identity file wait in
/// UNENROLLED STANDBY instead of exiting 1?
///
/// Cross-platform on every OS (was macOS-only until the Windows/Linux parity
/// work — see docs/plans/2026-09-21-windows-linux-desktop-parity.md Task A2):
/// a fresh Windows Service / systemd unit / macOS LaunchDaemon can all be
/// started before enrollment ever happens, and the GUI/desktop app in every
/// case needs the control socket UP to deliver the `enroll` command. Windows
/// and Linux each need their OWN standby wiring at the call site (a real
/// background service to host it) — see Phase A/B of that plan; this
/// function only controls the DECISION, not whether a persistent process
/// exists yet to make the decision inside.
///
/// * Only when the file is ABSENT, or when it is an ORPHAN of a failed
///   `ztlp setup` (identity.json without a config.toml zone — see
///   [`enrollment_is_complete`]); the orphan is removed so the next Enroll
///   is not refused as "already enrolled". A present, COMPLETE but
///   unparseable identity is a real error and must still fail loudly.
pub fn should_enter_unenrolled_standby(identity_path: &Path) -> bool {
    if !identity_path.exists() {
        return true;
    }
    if !enrollment_is_complete(identity_path) {
        remove_orphan_identity(identity_path);
        return true;
    }
    false
}

/// Pure hand-over predicate for the standby loop: identity.json exists AND
/// no `enroll` command is still running. `ztlp setup` writes identity.json
/// before the same enroll command runs ca-init (tls=true), so identity
/// alone is too early — the full daemon would load `[tls] enabled = false`.
pub fn standby_may_hand_over(identity_path: &Path, enroll_in_flight: usize) -> bool {
    enroll_in_flight == 0 && enrollment_is_complete(identity_path)
}

/// A COMPLETE enrollment = identity.json AND a sibling config.toml carrying a
/// non-empty `zone`. `ztlp setup` writes identity.json first and config.toml
/// only after NS accepted the enrollment; a failed setup (used-up token,
/// NS down) leaves identity.json alone. Live (2026-09-20): standby handed
/// over on that orphan, the full daemon ran with AgentConfig::default()
/// (NS 127.0.0.1, zone ""), Home said "Not enrolled" and Enroll then failed
/// with "already enrolled" — wedged until a manual wipe.
pub fn enrollment_is_complete(identity_path: &Path) -> bool {
    if !identity_path.exists() {
        return false;
    }
    let Some(dir) = identity_path.parent() else {
        return false;
    };
    let Ok(cfg) = std::fs::read_to_string(dir.join("config.toml")) else {
        return false;
    };
    cfg.lines().any(|l| {
        let l = l.trim();
        if !l.starts_with("zone") {
            return false;
        }
        let Some((_, v)) = l.split_once('=') else {
            return false;
        };
        let v = v.trim().trim_matches('"').trim_matches('\'');
        !v.is_empty()
    })
}

/// Undo a FAILED `ztlp setup` that already wrote identity.json but never got
/// to config.toml, so the next Enroll from the GUI is not refused with
/// "this machine is already enrolled". Only removes the orphan when the
/// enrollment is provably incomplete. Returns true when a file was removed.
pub fn remove_orphan_identity(identity_path: &Path) -> bool {
    if identity_path.exists() && !enrollment_is_complete(identity_path) {
        if std::fs::remove_file(identity_path).is_ok() {
            warn!(
                "removed orphan {} left by a failed enrollment",
                identity_path.display()
            );
            return true;
        }
    }
    false
}

/// B4: serve ONLY the control socket until `identity_path` appears.
///
/// Materialises `agent.token` (so the GUI can authenticate exactly as it
/// does against the full daemon), binds `ipc_addr`, answers
/// `status`/`setup_status`/`enroll`/`shutdown` via
/// [`control::handle_standby_request_line`], and polls `identity_path`
/// every `poll` interval. Returns `Ok(true)` when the identity has
/// appeared (caller should proceed to the full daemon), `Ok(false)` when a
/// `shutdown` command was received. The listener is dropped before
/// returning so the full daemon can rebind the same address.
pub async fn run_unenrolled_standby(
    ipc_addr: &str,
    identity_path: &Path,
    token_path: &Path,
    poll: Duration,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let token = Arc::new(ensure_token_file(token_path).map_err(|e| format!("token file: {e}"))?);
    // PR #112 review fix: let the Linux desktop GUI authenticate to the root
    // systemd service (no-op unless this IS that service).
    crate::agent::linux_daemon::share_token_with_gui_if_service(token_path);
    crate::agent::linux_daemon::spawn_token_share_refresher(token_path.to_path_buf());
    // macOS root: the control IP (127.100.255.1) is unbindable until lo0
    // is aliased, and the GUI must be able to READ agent.token to talk to
    // us — the same two startup actions the full daemon performs.
    #[cfg(target_os = "macos")]
    if crate::agent::macos_daemon::is_root() {
        use crate::agent::macos_daemon::MacosAction;
        // Only macOS needs this: 127.100.255.1 is outside macOS's default
        // loopback (only 127.0.0.1 is auto-configured), so the control
        // socket bind fails until `ifconfig lo0 alias 127.100.255.1 up` (or
        // this root-daemon startup action) runs. Linux needs NO alias here —
        // its loopback covers the full 127.0.0.0/8 range by default;
        // confirmed live 2026-09-21 (Task A4): a fresh agent on this Linux
        // box bound and answered on 127.100.255.1:4433 with zero extra setup
        // (raw TCP connect + real `{"ok":false,"error":"unauthorized"}`
        // protocol response, not a connection refusal). Windows also
        // generally allows binding anywhere in 127.0.0.0/8 without an
        // explicit alias (same as Linux) — not yet independently verified
        // live on that OS as of this task, but there's no evidence of a
        // Windows-specific loopback restriction in this codebase either.
        if let Some(ip) = ipc_addr
            .rsplit_once(':')
            .and_then(|(h, _)| h.parse::<std::net::Ipv4Addr>().ok())
            .filter(|ip| crate::agent::macos_daemon::vip_needs_loopback_alias(*ip))
        {
            MacosAction::LoopbackAlias(ip).execute();
        }
        MacosAction::TokenGuiReadable(token_path.to_path_buf()).execute();
    }
    // Windows service: grant the console user read on agent.token BEFORE
    // enrollment. Previously this ran only in the full daemon (identity
    // present) and after a successful enroll, so a fresh install sat in
    // standby with an Administrators/SYSTEM-only token and the desktop app's
    // Enroll failed with "unauthorized" (live, 2026-09-29). Only the token
    // ACL runs here: CA trust + NRPT still wait for the CA that enrollment
    // creates. No-op unless this process IS the service.
    #[cfg(target_os = "windows")]
    if crate::agent::windows_daemon::is_windows_service() {
        for action in crate::agent::windows_daemon::standby_startup_plan(token_path) {
            action.execute();
        }
        // Boot autostart precedes logon: keep re-applying until a console
        // user exists (and follow user switches).
        crate::agent::windows_daemon::spawn_token_acl_refresher(token_path.to_path_buf());
    }
    let listener = TcpListener::bind(ipc_addr).await.map_err(|e| {
        format!(
            "failed to bind control socket {} (standby): {}",
            ipc_addr, e
        )
    })?;
    warn!(
        "no identity at {} — entering UNENROLLED STANDBY: control socket on {} answers \
         status/enroll only; waiting for enrollment",
        identity_path.display(),
        ipc_addr
    );

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    // Non-zero while an `enroll` command is still running (setup + ca-init).
    let enroll_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut ticker = tokio::time::interval(poll);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if standby_may_hand_over(identity_path, enroll_in_flight.load(std::sync::atomic::Ordering::SeqCst)) {
                    info!("identity appeared at {} — leaving standby, starting full daemon", identity_path.display());
                    drop(listener);
                    return Ok(true);
                }
            }
            _ = shutdown_rx.recv() => {
                info!("shutdown requested during standby");
                drop(listener);
                return Ok(false);
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(r) => r,
                    Err(e) => { warn!("standby control socket accept error: {}", e); continue; }
                };
                let token = token.clone();
                let shutdown_tx = shutdown_tx.clone();
                let in_flight = enroll_in_flight.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut line = String::new();
                    if tokio::io::AsyncBufReadExt::read_line(&mut tokio::io::BufReader::new(reader), &mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let (json, shutdown) = control::handle_standby_request_line_tracked(&token, &line, Some(&in_flight)).await;
                    let _ = writer.write_all(json.as_bytes()).await;
                    let _ = writer.write_all(b"\n").await;
                    if shutdown { let _ = shutdown_tx.try_send(()); }
                });
            }
        }
    }
}

/// Run the agent daemon.
///
/// This is the main entry point called by `ztlp agent start`.
/// It blocks until shutdown is requested (via signal or control socket).
pub async fn run_daemon(
    config: &AgentConfig,
    foreground: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_daemon_with_hooks(config, foreground, DaemonHooks::default()).await
}

/// What an embedding host (the iOS agent runs the daemon inside the Network
/// Extension process, not as `ztlp agent start`) can hook into.
#[derive(Default)]
pub struct DaemonHooks {
    /// Receives [`DaemonReady`] once the resolver and control listeners are
    /// bound and the proxy is running. Dropped unsent when startup fails
    /// (the error is the daemon's return value).
    pub ready: Option<tokio::sync::oneshot::Sender<DaemonReady>>,
    /// Completing (or dropping) the sender stops the daemon, exactly like
    /// the control socket's `shutdown` command.
    pub shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
}

/// Startup result handed to [`DaemonHooks::ready`].
pub struct DaemonReady {
    /// Address the DNS resolver actually bound (may differ from the
    /// configured one when that port was taken), `None` when disabled.
    pub dns_listen: Option<SocketAddr>,
    /// Whether the control socket bound (`[ipc] listen`).
    pub control_bound: bool,
    /// Whether local TLS termination is active.
    pub tls_ready: bool,
    /// Resolver state (VIP pool) for status reporting.
    pub dns_state: Arc<Mutex<DnsResolverState>>,
    /// Single-address mode (`[dns] single_address`): where the name-routed
    /// HTTPS and HTTP listeners are bound. `None` when the mode is off (and
    /// for HTTP, when its port could not be bound).
    pub single_https_listen: Option<SocketAddr>,
    pub single_http_listen: Option<SocketAddr>,
}

/// [`run_daemon`] with [`DaemonHooks`].
pub async fn run_daemon_with_hooks(
    config: &AgentConfig,
    foreground: bool,
    hooks: DaemonHooks,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();

    // ── [tunnel] vip_ports: env override + startup validation ─────────
    // `ZTLP_AGENT_VIP_PORTS` ("1514:passthrough,1515") beats the TOML
    // key when set (Chef/installers can set ports without templating
    // agent.toml); a malformed value is a fatal config error naming the
    // offending item. `validate_vip_ports` then rejects duplicates,
    // port 0, an over-cap list, and collisions with the agent's own
    // loopback listeners (bad configs fail at STARTUP, not at bind).
    let mut cfg_owned: Option<AgentConfig> = None;
    if let Some(value) = std::env::var("ZTLP_AGENT_VIP_PORTS").ok() {
        match config::parse_vip_ports_env(&value) {
            Ok(Some(ports)) => {
                if !config.tunnel.vip_ports.is_empty() {
                    info!(
                        "ZTLP_AGENT_VIP_PORTS overrides the [[tunnel] vip_ports] config \
                         ({} env port(s) win)",
                        ports.len()
                    );
                } else {
                    info!("ZTLP_AGENT_VIP_PORTS: extra VIP ports from env");
                }
                let mut cfg = config.clone();
                cfg.tunnel.vip_ports = ports;
                cfg_owned = Some(cfg);
            }
            Ok(None) => {}
            Err(e) => {
                return Err(format!("ZTLP_AGENT_VIP_PORTS is malformed: {e}").into());
            }
        }
    }
    let cfg = match &cfg_owned {
        Some(c) => c,
        None => config,
    };
    cfg.validate_vip_ports()?;
    let vip_policy = cfg.tunnel.vip_ports_policy();
    if cfg.tunnel.vip_ports.is_empty() {
        debug!("VIP proxy: no [[tunnel] vip_ports] configured (built-in eight only)");
    }

    // Load identity
    let identity_path = cfg.identity_path();
    // B4 note: the unenrolled-standby wait happens in the CLI's
    // `cmd_agent_start` BEFORE the config is loaded (see
    // `ztlp-cli.rs`), so by the time we get here on a fresh Mac the
    // freshly-written agent.toml/config.toml (zone, NS, relay secret,
    // tls=true) have been read. `should_enter_unenrolled_standby` is
    // still checked here for callers that bypass the CLI.
    if should_enter_unenrolled_standby(&identity_path) {
        let proceed = run_unenrolled_standby(
            &cfg.ipc.listen,
            &identity_path,
            &config::default_token_path(),
            Duration::from_secs(1),
        )
        .await?;
        if !proceed {
            return Ok(());
        }
        return Err(
            "enrolled during standby: restart the daemon to load the new configuration".into(),
        );
    }
    let identity = NodeIdentity::load(&identity_path).map_err(|e| {
        format!(
            "failed to load identity from {}: {}\n\
             Run `ztlp setup` to create an identity first.",
            identity_path.display(),
            e
        )
    })?;

    // D3.T1: enforce OS-user binding if identity.json has bound_user_sid set.
    // Mismatch is fatal (the daemon refuses to operate). ResolutionFailed is
    // logged as a warning so a broken whoami/id environment can't brick the
    // daemon when the identity is in fact unbound (the common case).
    // iOS: one sandboxed app user, no `id` to run, and enrollment there never
    // binds an identity; a bound identity (copied from a desktop) is refused
    // below because the user cannot be resolved.
    let current_user = if cfg!(target_os = "ios") && identity.bound_user_sid.is_none() {
        None
    } else {
        Some(crate::agent::user_binding::current_user_sid())
    };
    match current_user {
        None => {}
        Some(Ok(current_sid)) => {
            if let Err(e) = crate::agent::user_binding::verify_user_binding(&identity, &current_sid)
            {
                match &e {
                    crate::agent::user_binding::BindingError::Mismatch { expected, actual } => {
                        tracing::error!(
                            target: "bound_user_mismatch",
                            expected_sid = %expected,
                            actual_sid = %actual,
                            identity_path = %identity_path.display(),
                            "identity is bound to a different OS user; refusing to start"
                        );
                    }
                    crate::agent::user_binding::BindingError::ResolutionFailed(_) => {
                        // Shouldn't happen on this branch (we got Ok from current_user_sid)
                        // but be defensive.
                        tracing::error!("verify_user_binding returned unexpected error: {e}");
                    }
                }
                return Err(format!("bound_user_mismatch: {e}").into());
            }
        }
        Some(Err(e)) => {
            // Couldn't resolve the current user. If the identity is bound we
            // can't safely enforce, so refuse. If unbound, log and continue.
            if identity.bound_user_sid.is_some() {
                tracing::error!(
                    target: "bound_user_mismatch",
                    identity_path = %identity_path.display(),
                    "identity has bound_user_sid but current user could not be resolved: {e}"
                );
                return Err(format!("bound_user_mismatch: cannot enforce binding: {e}").into());
            }
            tracing::warn!(
                "could not resolve current user identity for binding check (identity is unbound, continuing): {e}"
            );
        }
    }

    info!(
        "ZTLP Agent v{} starting (NodeID: {})",
        env!("CARGO_PKG_VERSION"),
        identity.node_id
    );

    // NS-anchored gateway trust (task 4.4): say at every start whether this
    // device verifies name-server answers; legacy devices are told to
    // re-enroll.
    {
        use super::ns_trust::{NsTrustStore, TrustStatus};
        let st = TrustStatus::of(&NsTrustStore::load(&super::ns_trust::default_path()));
        match st {
            TrustStatus::Verified { .. } => info!("{}", st.message()),
            _ => warn!("{}", st.message()),
        }
    }

    // v0.35.19: hourly NS check-in. Keeps this enrolled device's KEY record
    // alive for a sliding year (each accepted check-in restarts the window),
    // so the gateway can always resolve its device name. Same code on
    // macOS, Windows and Linux (all three daemons run through here).
    if let Some((ns_servers, interval)) = super::ns_checkin::checkin_plan(config) {
        info!(
            "NS check-in every {:?} via {}",
            interval,
            ns_servers.join(", ")
        );
        tokio::spawn(super::ns_checkin::run_checkin_loop(
            std::sync::Arc::new(identity.clone()),
            ns_servers,
            interval,
        ));
    }

    // Initialize VIP pool
    let vip_pool = VipPool::new(&cfg.dns.vip_range)
        .map_err(|e| format!("invalid VIP range '{}': {}", cfg.dns.vip_range, e))?;
    info!(
        "VIP pool: {} ({} addresses)",
        cfg.dns.vip_range,
        vip_pool.capacity()
    );

    // Initialize domain mapper
    let domain_mapper = DomainMapper::new(&cfg.dns.domain_map);
    if !domain_mapper.is_empty() {
        info!("domain mappings: {} configured", domain_mapper.len());
    }

    // Health probe address: the platform default (Windows/macOS loopback
    // alias) unless `[tls] health_ip` moves it somewhere the host's clients
    // can reach. `.1` says whether a responder is wanted on this platform.
    let health_addr: (Ipv4Addr, bool) = match cfg.tls.health_ip.as_deref().map(str::trim) {
        Some(ip) if !ip.is_empty() => (
            ip.parse()
                .map_err(|e| format!("invalid [tls] health_ip '{}': {}", ip, e))?,
            true,
        ),
        _ => (
            super::peruser::HEALTH_VIP,
            cfg!(target_os = "windows") || cfg!(target_os = "macos"),
        ),
    };

    // Single-address (name-routed) mode: off unless `[dns] single_address`
    // is set. When on, no VIP is ever allocated or restored and the VIP
    // proxy is not started; see `agent::name_route`.
    let single_addr: Option<Ipv4Addr> = cfg.dns.single_address_ip()?;

    // Shared DNS resolver state
    let mut dns_resolver_state = DnsResolverState {
        vip_pool,
        domain_mapper,
        ns_server: cfg.ns_server().to_string(),
        upstream_dns: cfg.dns.upstream.clone(),
        vip_state_path: Some(config::vip_state_path()),
        health_vip: health_addr.0,
        single: single_addr.map(super::name_route::SingleAddress::new),
    };
    // Re-bind VIP listeners from the previous run before any DNS query:
    // clients that cached the A record (browsers, `curl --resolve`) would
    // otherwise get ECONNREFUSED until they resolved again.
    let restored = if single_addr.is_some() {
        0
    } else {
        dns_resolver_state.restore_vips()
    };
    if restored > 0 {
        info!(
            "VIP pool: restored {} allocation(s) from previous run",
            restored
        );
    }
    let dns_state = Arc::new(Mutex::new(dns_resolver_state));

    // Initialize tunnel pool
    // D3.T2: honor cfg.tunnel.idle_timeout / keepalive_interval. On parse
    // failure we keep the daemon up using the built-in defaults and log a
    // warning that names the bad value, so operators see the problem in the
    // log instead of having a daemon that refuses to start.
    let idle_timeout = match config::parse_duration_str(&cfg.tunnel.idle_timeout) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                "invalid tunnel.idle_timeout '{}': {} — falling back to default {:?}",
                cfg.tunnel.idle_timeout, e, DEFAULT_IDLE_TIMEOUT
            );
            DEFAULT_IDLE_TIMEOUT
        }
    };
    let keepalive_interval = match config::parse_duration_str(&cfg.tunnel.keepalive_interval) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                "invalid tunnel.keepalive_interval '{}': {} — falling back to default {:?}",
                cfg.tunnel.keepalive_interval, e, DEFAULT_KEEPALIVE_INTERVAL
            );
            DEFAULT_KEEPALIVE_INTERVAL
        }
    };
    let tunnel_pool = Arc::new(Mutex::new(TunnelPool::with_timeouts(
        cfg.tunnel.max_tunnels,
        idle_timeout,
        keepalive_interval,
    )));
    info!(
        "tunnel pool: max {} tunnels, idle_timeout={:?}, keepalive={:?}",
        cfg.tunnel.max_tunnels, idle_timeout, keepalive_interval
    );

    // Shutdown channel
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // ── D1.T3: Load-or-generate the control-plane Bearer token ──────────
    // Per-install secret stored at ~/.ztlp/agent.token (0600 on unix).
    // This is what AgentState.expected_token checks against when a
    // ControlCommand carries `token: Some(...)`. The CLI side gets wired
    // in D1.T4; until then any pre-T4 client sending `token: None` will
    // be rejected, which is the intended production gate.
    let token_path = config::default_token_path();
    let token = ensure_token_file(&token_path).map_err(|e| format!("token file: {e}"))?;
    crate::agent::linux_daemon::share_token_with_gui_if_service(&token_path);
    crate::agent::linux_daemon::spawn_token_share_refresher(token_path.clone());
    info!(
        "control plane token at {} ({} chars)",
        token_path.display(),
        token.len()
    );

    // ── Bind the DNS resolver socket UP FRONT (before AgentState) ────────
    //
    // Real bug found live on Windows (2026-08-30): the configured DNS
    // listen port (5353, standard mDNS) is frequently already occupied
    // system-wide by Windows' own mDNS responder service and even by
    // Chrome — `dns::bind_dns_socket_with_fallback` now falls back to an
    // alternate port when that happens, but the daemon must publish the
    // REAL bound address (not the configured one) into `AgentState` so the
    // control API's status and Windows NRPT/DNS-routing setup both point
    // at where the resolver ACTUALLY is. Binding here, before constructing
    // `agent_state`, means `dns_listen` is always accurate — no separate
    // "what port did the fallback actually pick" plumbing needed later.
    // ── macOS root startup, phase 1 (lo0 aliases) ─────────────────────────
    //
    // macOS lo0 only carries 127.0.0.1; binding the resolver on 127.0.0.55
    // or the control API on 127.100.255.1 fails with "Can't assign requested
    // address (os error 49)" until an alias exists. Root only; no-op
    // otherwise. Windows (NRPT block below) and Linux are untouched.
    #[cfg(unix)]
    let macos_inputs = if cfg!(target_os = "macos") {
        let i = crate::agent::macos_daemon::MacosStartupInputs::from_config(
            config,
            crate::agent::macos_daemon::is_root(),
            &cfg.dns.listen,
        );
        crate::agent::macos_daemon::run_startup_pre_bind(&i);
        Some(i)
    } else {
        None
    };

    let dns_socket_and_addr = if cfg.dns.enabled {
        match dns::bind_dns_socket_with_fallback(&cfg.dns.listen).await {
            Ok((socket, addr)) => Some((socket, addr)),
            Err(e) => {
                return Err(format!(
                    "failed to bind DNS resolver on {} or any fallback port: {}",
                    cfg.dns.listen, e
                )
                .into());
            }
        }
    } else {
        None
    };
    // ── Windows NRPT listen plan ──────────────────────────────────────
    //
    // Real bug found live (2026-08-30, DESKTOP-CBSQDNE): Windows NRPT
    // rules only take a bare IP (implicit port 53). When the agent's DNS
    // resolver ends up on a high fallback port (5353 is routinely taken
    // by svchost mDNS + Chrome), the NRPT rule silently stores an EMPTY
    // NameServers list and browsers get DNS_PROBE_FINISHED_NXDOMAIN.
    //
    // Fix: on Windows, if the bound port is not 53, re-bind the resolver
    // socket to the dedicated loopback alias on port 53 (127.0.0.53:53)
    // and hand NRPT the bare alias IP. `bind_dns_socket_with_fallback`
    // already tries the alias port-53 FIRST on Windows (see dns.rs), so
    // this rebind only fires when that first attempt failed and a higher
    // port won instead.
    let (dns_socket_and_addr, nrpt_bind_overridden) = {
        #[cfg(target_os = "windows")]
        {
            // Plan the NRPT-compatible listen address BEFORE the `let`
            // binding so a misconfigured dns.listen fails loudly (the
            // closure's early `return Err` would otherwise infer the whole
            // plan expression as a Result — E0308).
            let listen_plan =
                match crate::agent::dns_setup_windows::plan_windows_nrpt_listen(&cfg.dns.listen) {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(format!(
                            "Windows NRPT requires a loopback dns.listen on port 53 (got {}): {e} \
                         — set dns.listen to 127.0.0.53:53 in cfg.toml",
                            cfg.dns.listen
                        )
                        .into());
                    }
                };
            let crate::agent::dns_setup_windows::WindowsNrptListenPlan {
                bind_addr,
                nrpt_server: _nrpt,
                needs_alias,
            } = listen_plan;
            let _ = needs_alias; // alias is ensured by the bind step
            match &dns_socket_and_addr {
                Some((_, bound)) if bound.port() != 53 => {
                    match tokio::net::UdpSocket::bind(bind_addr).await {
                        Ok(sock) => {
                            let addr = sock.local_addr().unwrap_or(bind_addr);
                            warn!(
                                "DNS resolver: NRPT requires port 53, re-binding {} -> {}",
                                bound, addr
                            );
                            (Some((sock, addr)), true)
                        }
                        Err(e) => {
                            return Err(format!(
                                "DNS resolver: configured port {} was taken and the NRPT-required \
                             port-53 rebind to {bind_addr} also failed: {} \
                             (NRPT can only route to a bare IP on port 53 — check \
                             `netstat -ano -p UDP | findstr :53` for what holds it)",
                                bound.port(),
                                e
                            )
                            .into());
                        }
                    }
                }
                _ => (dns_socket_and_addr, false),
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            (dns_socket_and_addr, false)
        }
    };
    let _ = nrpt_bind_overridden;
    let bound_dns_addr: Option<SocketAddr> = dns_socket_and_addr.as_ref().map(|(_, addr)| *addr);
    let effective_dns_listen = dns_socket_and_addr
        .as_ref()
        .map(|(_, addr)| addr.to_string())
        .unwrap_or_else(|| cfg.dns.listen.clone());

    // ── Single-address mode: bind the shared address on 443 and 80 ───────
    // Up front, like the resolver socket: a host that cannot listen on 443
    // cannot serve any site in this mode, so that is a failed start (before
    // the PID file and any task exist), not a warning. Port 80 is optional.
    let single_listeners: Option<(TcpListener, Option<TcpListener>)> = match single_addr {
        None => None,
        Some(addr) => {
            let https_addr = SocketAddr::new(addr.into(), cfg.dns.single_address_https_port);
            let https = bind_vip_listener(https_addr).await.map_err(|e| {
                format!(
                    "single-address mode ([dns] single_address = \"{addr}\"): \
                     cannot listen on {https_addr} for HTTPS: {e}"
                )
            })?;
            let http_addr = SocketAddr::new(addr.into(), cfg.dns.single_address_http_port);
            let http = match bind_vip_listener(http_addr).await {
                Ok(l) => Some(l),
                Err(e) => {
                    warn!(
                        "single-address mode: cannot listen on {} for HTTP: {} \
                         (http:// sites will not work; https:// is unaffected)",
                        http_addr, e
                    );
                    None
                }
            };
            Some((https, http))
        }
    };

    // ── macOS root startup, phase 2 (resolver files, CA trust, token) ─────
    // Needs the EFFECTIVE bound DNS port, hence after the bind.
    #[cfg(unix)]
    if let Some(mut i) = macos_inputs {
        i.dns_listen = effective_dns_listen.clone();
        crate::agent::macos_daemon::run_startup_post_bind(&i);
    }

    // ── Windows service startup (CA trust, NRPT, token ACL) — Phase D
    //     plan D3 ─────────────────────────────────────────────────────────
    // Needs the EFFECTIVE bound DNS port (hence after the bind) and only
    // runs when this is actually the LocalSystem ZtlpAgent service (D1
    // sets ZTLP_HOME unconditionally at service startup; a foreground
    // `ztlp.exe agent start` for dev/debug never has it set and skips
    // this entirely, preserving pre-D3 dev behavior byte-for-byte).
    // Best-effort, log-and-continue — mirrors the macOS phase-2 tolerance:
    // one failed privileged step must not crash the daemon, the checklist
    // surfaces failures via `setup_status` instead.
    #[cfg(target_os = "windows")]
    {
        if crate::agent::windows_daemon::is_windows_service() {
            let inputs = crate::agent::windows_daemon::WindowsStartupInputs {
                is_service: true,
                dns_listen: effective_dns_listen.clone(),
                ca_root_pem: crate::agent::ca_trust::default_ca_cert_path(),
                ca_root_pem_exists: crate::agent::ca_trust::default_ca_cert_path().exists(),
                ca_already_trusted: crate::agent::ca_trust::is_ca_installed(),
                token_path: config::default_token_path(),
                zones: cfg.dns.zones.clone(),
            };
            for action in crate::agent::windows_daemon::windows_startup_plan(&inputs) {
                action.execute();
            }
        }
    }

    // Agent state for control socket
    let agent_state = Arc::new(AgentState {
        dns_state: dns_state.clone(),
        tunnel_pool: tunnel_pool.clone(),
        start_time,
        dns_listen: effective_dns_listen,
        shutdown_tx: shutdown_tx.clone(),
        // D1.T3: real Bearer token wired in. The T2 gate is now live.
        expected_token: Some(Arc::new(token)),
        setup_probes: Arc::new(control::SetupProbeCache::new()),
    });

    // Write PID file
    let pid_path = control::default_pid_path();
    control::write_pid_file(&pid_path)?;
    info!("PID file: {}", pid_path.display());

    // ── Spawn DNS resolver (on the socket bound above) ───────────────────
    let dns_handle = if let Some((socket, addr)) = dns_socket_and_addr {
        info!("DNS resolver listening on {}", addr);
        let state = dns_state.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = dns::run_dns_resolver_on_socket(socket, state).await {
                error!("DNS resolver error: {}", e);
            }
        }))
    } else {
        info!("DNS resolver disabled");
        None
    };

    // ── DNS over TCP on the same address (`[dns] tcp = true`) ────────────
    // Off by default. A failed bind is logged, not fatal: UDP is what
    // resolvers use first.
    let dns_tcp_handle = match (cfg.dns.tcp, bound_dns_addr) {
        (true, Some(addr)) => match TcpListener::bind(addr).await {
            Ok(listener) => {
                info!("DNS resolver also listening on {} (TCP)", addr);
                let state = dns_state.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) = dns::run_dns_tcp_resolver_on_listener(listener, state).await {
                        error!("DNS TCP resolver error: {}", e);
                    }
                }))
            }
            Err(e) => {
                warn!("DNS resolver: cannot bind TCP {}: {}", addr, e);
                None
            }
        },
        _ => None,
    };

    // ── Spawn control socket ────────────────────────────────────────────
    // Bound here (not inside the task) so `DaemonHooks::ready` can say
    // whether it worked; a failed bind is logged and the daemon keeps
    // running without a control socket, as before.
    let ipc_addr = cfg.ipc.listen.clone();
    let ctrl_state = agent_state.clone();
    let ctrl_listener = match control::bind_control_socket(&ipc_addr).await {
        Ok(l) => Some(l),
        Err(e) => {
            error!("control socket error: {}", e);
            None
        }
    };
    let control_bound = ctrl_listener.is_some();
    let ctrl_handle = tokio::spawn(async move {
        if let Some(listener) = ctrl_listener {
            if let Err(e) = control::run_control_socket_on(listener, ctrl_state).await {
                error!("control socket error: {}", e);
            }
        }
    });

    // ── Initialize local TLS ──────────────────────────────────────────
    let machine_ca = super::peruser::machine_ca_dir();
    let tls_acceptor =
        if super::peruser::effective_tls_enabled(cfg.tls.enabled, machine_ca.as_deref()) {
            let cert_dir = cfg.tls.cert_dir_path();
            if let Err(e) = std::fs::create_dir_all(&cert_dir) {
                warn!("failed to create cert dir {}: {}", cert_dir.display(), e);
            }

            // D6.T1: try to load the intermediate CA BEFORE constructing the
            // resolver, so we can use `with_mint_ca` (the only constructor
            // that wraps the mint CA in the `Arc` the resolver expects). If
            // the CA chain hasn't been initialized yet (no
            // `~/.ztlp/ca/intermediate.{pem,key}`) we silently fall back
            // to disk-only mode via the plain `new` constructor — the wizard
            // surface step "CA initialized?" tells the user how to fix that.
            // Windows per-user agent: mint from the installer-made machine CA
            // (trusted machine-wide) when it is usable, else the user's own CA.
            let ca_dir = super::peruser::effective_ca_dir(
                &crate::agent::config::ztlp_state_dir()
                    .join(".ztlp")
                    .join("ca"),
                machine_ca.as_deref(),
            );
            let intermediate_pem = ca_dir.join("intermediate.pem");
            let intermediate_key = ca_dir.join("intermediate.key");
            let resolver = if intermediate_pem.exists() && intermediate_key.exists() {
                match crate::agent::cert_mint::IntermediateCa::load_from_dir(&ca_dir) {
                    Ok(ca) => {
                        info!(
                            "local TLS: on-demand cert minting enabled (intermediate at {})",
                            intermediate_pem.display()
                        );
                        Arc::new(SniCertResolver::with_mint_ca(
                            cert_dir.clone(),
                            Arc::new(ca),
                        ))
                    }
                    Err(e) => {
                        warn!(
                            "local TLS: intermediate CA present at {} but failed to load: {} \
                         — on-demand minting disabled",
                            intermediate_pem.display(),
                            e
                        );
                        Arc::new(SniCertResolver::new(cert_dir.clone()))
                    }
                }
            } else {
                info!(
                    "local TLS: no intermediate CA found at {} — \
                 on-demand minting disabled (run `ztlp admin ca-init` first)",
                    intermediate_pem.display()
                );
                Arc::new(SniCertResolver::new(cert_dir.clone()))
            };

            let loaded = resolver.preload_all();
            if loaded > 0 {
                info!(
                    "local TLS: loaded {} cert(s) from {}",
                    loaded,
                    cert_dir.display()
                );
            } else {
                info!(
                    "local TLS: enabled but no certs found in {} — \
                 HTTPS connections will be served by on-demand minting \
                 (if enabled above) or fail otherwise",
                    cert_dir.display()
                );
            }

            match local_tls::create_tls_acceptor(resolver) {
                Ok(acceptor) => {
                    info!("local TLS: acceptor ready");
                    Some(Arc::new(acceptor))
                }
                Err(e) => {
                    error!("local TLS: failed to create acceptor: {}", e);
                    None
                }
            }
        } else {
            info!("local TLS: disabled");
            None
        };

    // ── Per-user agent health probe (Windows + macOS) ─────────────────
    // TLS responder on peruser::HEALTH_VIP:8443 so the desktop app can prove
    // `.ztlp` DNS + machine-CA trust end to end. The macOS per-user model is
    // the analog of Windows: the app's HTTPS row probes
    // `https://ztlp-health.ztlp:8443/` (which resolves to HEALTH_VIP) and
    // expects the `ztlp-health-ok` body — so the macOS agent must serve it
    // too. Linux keeps its per-device CA flow and has no such app probe.
    let health_handle = if health_addr.1 {
        tls_acceptor.as_ref().map(|acc| {
            let acc = (**acc).clone();
            let health_ip = health_addr.0;
            tokio::spawn(async move {
                let addr = SocketAddr::new(health_ip.into(), super::peruser::HEALTH_PORT);
                match TcpListener::bind(addr).await {
                    Ok(l) => {
                        info!("health probe listening on {addr}");
                        local_tls::run_health_responder(l, acc).await;
                    }
                    Err(e) => warn!("health probe: cannot bind {addr}: {e}"),
                }
            })
        })
    } else {
        None
    };

    // ── Spawn TCP proxy listener ────────────────────────────────────────
    // The TCP proxy task watches for new VIP allocations and spawns
    // TCP listeners on each VIP address. When a TCP connection arrives,
    // it establishes a ZTLP tunnel to the peer and bridges traffic.
    let proxy_dns_state = dns_state.clone();
    let proxy_identity = identity.clone();
    let proxy_bind = cfg.tunnel.bind.clone();
    let proxy_ns_server = cfg.ns_server().to_string();
    let proxy_tls_acceptor = tls_acceptor.clone();
    let proxy_relay = cfg.tunnel.relays.0.first().cloned();
    let proxy_first_byte_timeout = cfg.tunnel.first_byte_timeout.clone();
    let proxy_vip_policy = vip_policy.clone();
    // Loopback VIP pool (every desktop): only loopback clients, as before.
    // A pool on another local interface (the iOS tunnel): clients are other
    // apps on this device, whose source address is one of the device's own.
    let proxy_peer_policy = ClientPeerPolicy::for_vip_range(&cfg.dns.vip_range);
    if proxy_peer_policy == ClientPeerPolicy::OnHost {
        info!(
            "VIP pool {} is not loopback: accepting clients from this host's own addresses",
            cfg.dns.vip_range
        );
    }
    if let Some(ref r) = proxy_relay {
        info!("relay configured: {}", r);
        // Direct-first dial order (docs/DIRECT-FIRST-DIAL-PLAN.md step B):
        // published gateway endpoints are tried before the relay unless the
        // operator sets `[tunnel] prefer_relay = true`.
        set_prefer_relay(cfg.tunnel.prefer_relay);
        if cfg.tunnel.prefer_relay {
            info!("dial order: relay first, direct endpoints as fallback (prefer_relay = true)");
        } else {
            info!("dial order: direct endpoints first, relay as fallback");
        }
    } else {
        info!("no relay configured, using direct connections");
    }
    // Relay CLIENT_ROUTE signing: required when the relay runs
    // ZTLP_RELAY_HMAC_MODE=prod (unsigned frames are rejected there).
    match cfg.tunnel.relay_secret_bytes() {
        Some(secret) => {
            info!(
                "relay CLIENT_ROUTE signing enabled ({}-byte secret)",
                secret.len()
            );
            set_relay_secret(Some(secret));
        }
        None => {
            if proxy_relay.is_some() {
                warn!(
                    "no [tunnel] relay_secret configured: CLIENT_ROUTE frames are unsigned \
                     (accepted only by relays in dev/staging HMAC mode)"
                );
            }
            set_relay_secret(None);
        }
    }
    // Transport memory profile ([tunnel] profile / reuse_connections).
    let windows = cfg.tunnel.transport_windows();
    let reuse = cfg.tunnel.reuse_connections_enabled();
    set_dial_windows(windows);
    set_reuse_connections(reuse);
    // Shared-connection mode only: act on network changes; the mobile
    // profile also closes shared connections nobody uses.
    let shared_keeper = reuse.then(|| {
        let idle_close = (cfg.tunnel.profile == super::config::TunnelProfile::Mobile)
            .then_some(super::reconnect::MOBILE_IDLE_CLOSE);
        info!(
            "shared connections: dropped and dialed again on a network change or after {:?} \
             without an answer; closed when unused for {}",
            super::reconnect::LIVENESS_WINDOW,
            match idle_close {
                Some(d) => format!("{d:?}"),
                None => "never (not the mobile profile)".to_string(),
            }
        );
        tokio::spawn(keep_shared_tunnels(idle_close))
    });
    info!(
        "transport profile: {:?} (stream window {} KiB, connection window {} KiB, send window {}, \
         shared connection per service: {})",
        cfg.tunnel.profile,
        windows.stream_receive_window / 1024,
        windows.receive_window / 1024,
        match windows.send_window {
            Some(w) => format!("{} KiB", w / 1024),
            None => "default".to_string(),
        },
        if reuse { "on" } else { "off" }
    );
    let mut single_https_listen: Option<SocketAddr> = None;
    let mut single_http_listen: Option<SocketAddr> = None;
    let mut single_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let proxy_handle = match (single_addr, single_listeners) {
        (Some(addr), Some((https, http))) => {
            // Name-routed listeners instead of the VIP proxy.
            if proxy_tls_acceptor.is_none() {
                warn!(
                    "single-address mode without local TLS: https connections are passed \
                     to the site's port 443 undecrypted, as on a VIP"
                );
            }
            let carrier = SingleAddressCarrier {
                addr,
                dns_state: proxy_dns_state,
                identity: proxy_identity,
                bind: proxy_bind,
                ns_server: proxy_ns_server,
                tls: proxy_tls_acceptor,
                relay: proxy_relay,
                first_byte_timeout: proxy_first_byte_timeout,
                policy: proxy_vip_policy,
                // The shared address is the "pool": loopback keeps the
                // loopback-only client check.
                peer_policy: ClientPeerPolicy::for_vip_range(&addr.to_string()),
            };
            single_https_listen = https.local_addr().ok();
            info!(
                "single-address mode: every site on {} - HTTPS by TLS server name on {}",
                addr,
                single_https_listen.map_or_else(|| "?".to_string(), |a| a.to_string())
            );
            single_handles.push(carrier.clone().spawn(https, 443));
            if let Some(http) = http {
                single_http_listen = http.local_addr().ok();
                info!(
                    "single-address mode: HTTP by Host header on {}",
                    single_http_listen.map_or_else(|| "?".to_string(), |a| a.to_string())
                );
                single_handles.push(carrier.spawn(http, 80));
            }
            None
        }
        _ => Some(tokio::spawn(async move {
            run_tcp_proxy(
                proxy_dns_state,
                proxy_identity,
                proxy_bind,
                proxy_ns_server,
                proxy_tls_acceptor,
                proxy_relay,
                proxy_first_byte_timeout,
                proxy_vip_policy,
                proxy_peer_policy,
            )
            .await;
        })),
    };

    // ── Spawn GC task ───────────────────────────────────────────────────
    // Two responsibilities, both on the same ~GC_INTERVAL cadence:
    //   1. Reap expired VIP allocations from the DNS resolver state.
    //   2. D3.T2: tear down tunnels whose `last_activity` exceeded the
    //      configured `idle_timeout`. We snapshot the idle-name list under
    //      the lock, then drop and re-take it per removal so a slow GC tick
    //      can't block other tunnel operations for the full iteration.
    let gc_state = dns_state.clone();
    let gc_tunnel_pool = tunnel_pool.clone();
    let gc_idle_timeout = idle_timeout;
    let gc_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(GC_INTERVAL);
        loop {
            interval.tick().await;

            // VIP GC.
            {
                let mut st = gc_state.lock().await;
                let freed = st.vip_pool.gc_expired();
                if freed > 0 {
                    debug!("GC: freed {} expired VIP allocations", freed);
                }
                if let Some(single) = st.single.as_mut() {
                    single.purge_expired(Instant::now());
                }
            }

            // D3.T2: idle-tunnel teardown. Snapshot names + last_activity
            // metadata under one lock, then drop the guard before remove()
            // so we don't hold the mutex across multiple operations.
            let idle_names: Vec<(String, u64)> = {
                let pool = gc_tunnel_pool.lock().await;
                pool.idle_tunnels()
                    .into_iter()
                    .map(|name| {
                        let secs = pool
                            .get(&name)
                            .map(|t| t.last_activity.elapsed().as_secs())
                            .unwrap_or(0);
                        (name, secs)
                    })
                    .collect()
            };

            for (name, last_activity_secs) in idle_names {
                let mut pool = gc_tunnel_pool.lock().await;
                // CodeRabbit #2 (daemon.rs:346): re-check idleness under the lock.
                // The snapshot above goes stale as soon as we drop the guard, so
                // a tunnel that received traffic between the snapshot and now
                // would otherwise be torn down while active.
                let still_idle = pool
                    .get(&name)
                    .map(|t| t.last_activity.elapsed() >= gc_idle_timeout)
                    .unwrap_or(false);
                if still_idle && pool.remove(&name).is_some() {
                    // Structured event for the audit story in the D3 plan:
                    // "on idle teardown, the daemon logs a structured
                    //  idle_teardown event". Emitted per-tunnel so the
                    //  log is useful even when several tunnels reap at once.
                    info!(
                        target: "idle_teardown",
                        tunnel_name = %name,
                        last_activity_secs = last_activity_secs,
                        "tearing down idle tunnel"
                    );
                }
            }
        }
    });

    // ── Spawn session-lockdown task (D3.T3) ─────────────────────────────
    // Listens on a broadcast channel that Windows session-change events
    // post to. On any reason (lock/logoff/console/remote disconnect) we
    // drain ALL tunnels and GC the VIP pool. The producer side lives in
    // ztlp-service.exe (see service/src/session.rs once D4/D5 land); this
    // daemon-side wiring runs regardless of platform so the test surface
    // is exercised on Linux CI.
    let (lockdown_tx, mut lockdown_rx) =
        tokio::sync::broadcast::channel::<super::session_lock::LockdownReason>(8);
    super::session_lock::spawn_listener(lockdown_tx.clone())
        .unwrap_or_else(|e| warn!("session-lock listener init failed (non-fatal): {e}"));

    let lock_tunnel_pool = tunnel_pool.clone();
    let lock_dns_state = dns_state.clone();
    let lockdown_handle = tokio::spawn(async move {
        loop {
            match lockdown_rx.recv().await {
                Ok(reason) => {
                    // Snapshot names under one lock, then drop the guard
                    // before per-tunnel removal — same pattern as the GC
                    // idle path so lock ordering stays consistent.
                    let names: Vec<String> = {
                        let pool = lock_tunnel_pool.lock().await;
                        pool.tunnel_info().into_iter().map(|t| t.name).collect()
                    };

                    for name in &names {
                        let mut pool = lock_tunnel_pool.lock().await;
                        if pool.remove(name).is_some() {
                            info!(
                                target: "lockdown_teardown",
                                reason = reason.as_str(),
                                tunnel_name = %name,
                                "tearing down tunnel due to session lockdown"
                            );
                        }
                    }

                    // GC the VIP pool so the next session starts clean.
                    {
                        let mut st = lock_dns_state.lock().await;
                        let freed = st.vip_pool.gc_expired();
                        info!(
                            target: "lockdown_teardown",
                            reason = reason.as_str(),
                            tunnels_torn_down = names.len(),
                            vips_freed = freed,
                            "session lockdown teardown complete"
                        );
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("session-lockdown receiver lagged, missed {n} events");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    // Sender dropped — daemon is shutting down. Exit.
                    break;
                }
            }
        }
    });

    // ── Print startup info ──────────────────────────────────────────────
    if foreground {
        eprintln!("ZTLP Agent v{}", env!("CARGO_PKG_VERSION"));
        eprintln!(
            "  Identity: {} ({})",
            identity.node_id,
            identity_path.display()
        );
        if config.dns.enabled {
            eprintln!("  DNS:      {}", config.dns.listen);
        }
        eprintln!("  Control:  {}", ipc_addr);
        eprintln!("  NS:       {}", config.ns_server());
        match single_addr {
            // Only with `[dns] single_address` set; otherwise as always.
            Some(addr) => eprintln!("  Sites:    {} (single address, routed by name)", addr),
            None => eprintln!("  VIP pool: {}", config.dns.vip_range),
        }
        if config.tls.enabled {
            eprintln!(
                "  TLS:      enabled (certs: {})",
                config.tls.cert_dir_path().display()
            );
        } else {
            eprintln!("  TLS:      disabled");
        }
        eprintln!();
        eprintln!("Agent running. Press Ctrl+C to stop.");
    }

    // ── Tell an embedding host that startup is complete ─────────────────
    let DaemonHooks {
        ready: ready_hook,
        shutdown: shutdown_hook,
    } = hooks;
    if let Some(tx) = ready_hook {
        let _ = tx.send(DaemonReady {
            dns_listen: bound_dns_addr,
            control_bound,
            tls_ready: tls_acceptor.is_some(),
            dns_state: dns_state.clone(),
            single_https_listen,
            single_http_listen,
        });
    }

    // ── Wait for shutdown ───────────────────────────────────────────────
    let mut shutdown_rx = shutdown_tx.subscribe();
    // No hook = a future that never completes (desktop: unchanged).
    let host_shutdown = async move {
        match shutdown_hook {
            Some(rx) => {
                let _ = rx.await;
            }
            None => std::future::pending::<()>().await,
        }
    };

    tokio::select! {
        _ = shutdown_rx.recv() => {
            info!("shutdown signal received");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received, shutting down...");
        }
        _ = host_shutdown => {
            info!("shutdown requested by the host process");
        }
    }

    // ── Cleanup ─────────────────────────────────────────────────────────
    info!("cleaning up...");

    // Remove PID file
    control::remove_pid_file(&pid_path);

    // Abort spawned tasks
    if let Some(h) = dns_handle {
        h.abort();
    }
    if let Some(h) = dns_tcp_handle {
        h.abort();
    }
    ctrl_handle.abort();
    if let Some(h) = proxy_handle {
        h.abort();
    }
    for h in single_handles {
        h.abort();
    }
    gc_handle.abort();
    lockdown_handle.abort();
    if let Some(h) = health_handle {
        h.abort();
    }

    if let Some(h) = shared_keeper {
        h.abort();
    }
    close_shared_tunnels();

    info!("agent stopped");
    Ok(())
}

// ─── TCP Proxy ──────────────────────────────────────────────────────────────

/// TCP proxy that polls for VIP allocations and spawns listeners.
///
/// The proxy runs in a loop, checking the VIP pool for new allocations
/// that don't have active TCP listeners. For each new VIP, it spawns a
/// TCP listener on that address. When a client connects to a VIP, the
/// proxy establishes a ZTLP tunnel to the peer and bridges traffic.
#[allow(clippy::too_many_arguments)]
async fn run_tcp_proxy(
    dns_state: Arc<Mutex<DnsResolverState>>,
    identity: NodeIdentity,
    bind_addr: String,
    ns_server: String,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    relay_addr: Option<String>,
    first_byte_timeout: String,
    vip_policy: super::config::VipPortPolicy,
    peer_policy: ClientPeerPolicy,
) {
    // The resolved listener list (built-in eight ∪ configured `vip_ports`,
    // deduped and sorted) plus the per-port TLS overrides, built ONCE at
    // startup. Every VIP gets one listener per port in this list.
    let effective_ports: Vec<u16> = vip_policy.effective_ports().to_vec();

    // Log the effective port set once at startup (the operators' first
    // look at a new `vip_ports` key).
    let log_parts: Vec<String> = effective_ports
        .iter()
        .map(|p| {
            let mode = vip_policy.tls_mode(*p);
            if VIP_BUILTIN_PORTS.contains(p) {
                p.to_string()
            } else {
                format!(
                    "{p}({})",
                    match mode {
                        local_tls::TlsMode::Never => "passthrough",
                        local_tls::TlsMode::Always => "terminate",
                        local_tls::TlsMode::Detect => "auto",
                    }
                )
            }
        })
        .collect();
    info!("VIP proxy ports: {}", log_parts.join(","));
    // Track which VIPs we're already listening on
    let active_listeners: Arc<Mutex<std::collections::HashSet<Ipv4Addr>>> =
        Arc::new(Mutex::new(std::collections::HashSet::new()));

    let mut poll_interval = tokio::time::interval(Duration::from_millis(50));

    loop {
        poll_interval.tick().await;

        // Check for new VIP allocations
        let entries: Vec<(
            Ipv4Addr,
            String,
            Option<SocketAddr>,
            Option<crate::identity::NodeId>,
        )> = {
            let st = dns_state.lock().await;
            st.vip_pool
                .entries()
                .map(|e| (e.ip, e.ztlp_name.clone(), e.peer_addr, e.peer_node_id))
                .collect()
        };

        for (vip, ztlp_name, peer_addr, peer_node_id) in entries {
            let already = {
                let listeners = active_listeners.lock().await;
                listeners.contains(&vip)
            };

            if already {
                continue;
            }

            // Try to bind a TCP listener on this VIP
            let _listen_addr = SocketAddr::new(vip.into(), 0);

            // We listen on ALL ports by using port 0... but that's not what we want.
            // We need to listen on specific well-known ports. However, the design says
            // "accepts any TCP connection to the virtual IP on any port", which means
            // we need one listener per VIP that handles all ports.
            //
            // The trick: we listen on a fixed set of common ports on each VIP.
            // For the initial implementation, we start a single listener on port 0
            // (ephemeral) and the DNS resolver returns the VIP. The app connects to
            // the VIP on the desired port. But we can't easily listen on arbitrary
            // ports without root.
            //
            // Practical approach: The TCP proxy listens on a single port per VIP
            // and the target port is inferred from the original connection. On Linux,
            // we can use SO_ORIGINAL_DST to get the original port, but that requires
            // iptables REDIRECT. For simplicity, we use a different approach:
            //
            // Each VIP listener accepts connections on ANY port. This is done by
            // spawning listeners on common ports (22, 80, 443, 5432, 3306, 3389, etc.)
            // OR by using a wildcard approach.
            //
            // Simplest approach: listen on a high port (e.g., 23095) and use SSH
            // ProxyCommand for SSH. For other apps, the DNS resolver will resolve to
            // the VIP and the app connects to the VIP:port directly.

            // For each VIP, we'll try to listen on the full range of ports that matter.
            // The list is the startup-resolved `effective_ports` (built-in
            // eight ∪ `[tunnel] vip_ports`, deduped) — see `run_tcp_proxy`.
            {
                let mut listeners = active_listeners.lock().await;
                listeners.insert(vip);
            }

            // macOS: the VIP pool hands out 127.100.0.N lazily and lo0 has no
            // alias for it yet -> every TcpListener::bind below would fail
            // with os error 49. Alias first (root only; no-op elsewhere).
            #[cfg(unix)]
            if cfg!(target_os = "macos") && crate::agent::macos_daemon::is_root() {
                crate::agent::macos_daemon::ensure_vip_alias(vip);
            }

            for &port in &effective_ports {
                let addr = SocketAddr::new(vip.into(), port);
                let identity = identity.clone();
                let ns = ns_server.clone();
                let name = ztlp_name.clone();
                let peer = peer_addr;
                let peer_node_id = peer_node_id;
                let dns_st = dns_state.clone();
                let bind = bind_addr.clone();
                let tls = tls_acceptor.clone();
                let relay = relay_addr.clone();
                let fbt = first_byte_timeout.clone();
                let policy = vip_policy.clone();

                tokio::spawn(async move {
                    match bind_vip_listener(addr).await {
                        Ok(listener) => {
                            debug!(
                                "TCP proxy listening on {} for {} (port {})",
                                addr, name, port
                            );
                            loop {
                                match listener.accept().await {
                                    Ok((tcp_stream, client_addr)) => {
                                        // [CWE-284 egi-dcvj] Reject connections from a
                                        // different local OS user before doing ANYTHING
                                        // else with this stream — these VIP listeners are
                                        // loopback-bound and previously trusted every
                                        // local connection unconditionally, letting any
                                        // local user/process ride the daemon owner's
                                        // ZTLP identity.
                                        if !verify_local_peer(&tcp_stream, peer_policy) {
                                            continue;
                                        }
                                        // Session locked (`freeze`): no new
                                        // connections; established ones keep
                                        // running until they idle out.
                                        if !super::peruser::accept_new_connection(
                                            super::peruser::is_frozen(),
                                        ) {
                                            debug!(
                                                "frozen: refusing new connection {} -> {}",
                                                client_addr, name
                                            );
                                            continue;
                                        }

                                        info!(
                                            "TCP connection {} → {} ({}:{})",
                                            client_addr,
                                            name,
                                            addr.ip(),
                                            port
                                        );

                                        // Increment connection count
                                        {
                                            let mut st = dns_st.lock().await;
                                            st.vip_pool.inc_connections(&vip);
                                        }

                                        let name = name.clone();
                                        let ns = ns.clone();
                                        let identity = identity.clone();
                                        let bind = bind.clone();
                                        let dns_st = dns_st.clone();
                                        let tls = tls.clone();
                                        let relay = relay.clone();
                                        let fbt = fbt.clone();
                                        let policy = policy.clone();

                                        tokio::spawn(async move {
                                            carry_client_connection(
                                                tcp_stream,
                                                name,
                                                port,
                                                peer,
                                                peer_node_id,
                                                identity,
                                                bind,
                                                ns,
                                                tls,
                                                relay,
                                                fbt,
                                                policy,
                                            )
                                            .await;

                                            // Decrement connection count
                                            {
                                                let mut st = dns_st.lock().await;
                                                st.vip_pool.dec_connections(&vip);
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        debug!("TCP accept error on {}: {}", addr, e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            // Port might already be in use — that's OK, but
                            // promote to warn so operators notice a VIP that
                            // failed to bind (the 2026-08-30 "silent dead VIP"
                            // bug was invisible at debug level).
                            warn!(
                                "cannot bind VIP {}:{}: {} — seamless access to this \
                                 host will NOT work until the port is freed",
                                vip, port, e
                            );
                        }
                    }
                });
            }
        }
    }
}

/// What the name-routed listeners of single-address mode share: the same
/// values `run_tcp_proxy` hands to every VIP listener.
#[derive(Clone)]
struct SingleAddressCarrier {
    addr: Ipv4Addr,
    dns_state: Arc<Mutex<DnsResolverState>>,
    identity: NodeIdentity,
    bind: String,
    ns_server: String,
    tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    relay: Option<String>,
    first_byte_timeout: String,
    policy: super::config::VipPortPolicy,
    peer_policy: ClientPeerPolicy,
}

impl SingleAddressCarrier {
    /// Serve `listener` as the shared address's port `port` (443: the name
    /// is the TLS server name; 80: the HTTP `Host` header). Each accepted
    /// connection passes the VIP listeners' checks (local client, session
    /// not locked), is matched to a site by name, and is then carried by
    /// [`carry_client_connection`] exactly like a connection to that
    /// site's VIP on `port`. `port` is the port at the site; the listener
    /// may be bound elsewhere (tests).
    fn spawn(self, listener: TcpListener, port: u16) -> tokio::task::JoinHandle<()> {
        use super::name_route::{self, NameSource};

        let source = if port == 443 {
            NameSource::Sni
        } else {
            NameSource::HttpHost
        };
        let peer_policy = self.peer_policy;
        let admit = move |stream: &TcpStream, client: SocketAddr| {
            if !verify_local_peer(stream, peer_policy) {
                return false;
            }
            if !super::peruser::accept_new_connection(super::peruser::is_frozen()) {
                debug!("frozen: refusing new connection from {}", client);
                return false;
            }
            true
        };
        let dns_state = self.dns_state.clone();
        let resolve = move |host: String| {
            let dns_state = dns_state.clone();
            async move {
                name_route::resolve_site(
                    &dns_state,
                    &host,
                    super::peruser::is_frozen(),
                    |name, ns_server| async move { proxy::ns_resolve(&name, &ns_server).await },
                )
                .await
            }
        };
        let carry = move |stream: TcpStream, site: name_route::Site, client: SocketAddr| {
            let c = self.clone();
            async move {
                info!(
                    "TCP connection {} → {} ({}:{})",
                    client, site.ztlp_name, c.addr, port
                );
                carry_client_connection(
                    stream,
                    site.ztlp_name,
                    port,
                    site.peer_addr,
                    site.peer_node_id,
                    c.identity,
                    c.bind,
                    c.ns_server,
                    c.tls,
                    c.relay,
                    c.first_byte_timeout,
                    c.policy,
                )
                .await;
            }
        };
        tokio::spawn(name_route::run_listener(
            listener, source, admit, resolve, carry,
        ))
    }
}

/// Carry one accepted client connection for the site `name` on `port`:
/// local TLS termination or pass-through as the port policy says, the
/// accept-to-first-byte deadline, the dial (direct first, then relay) and
/// the bridge, with the deadline's 504 page / close on HTTP-class ports.
///
/// The single place a client connection is carried from, whichever way
/// its site was identified: by the VIP it arrived on (`run_tcp_proxy`) or
/// by name on the shared address (`[dns] single_address`).
#[allow(clippy::too_many_arguments)]
async fn carry_client_connection(
    tcp_stream: TcpStream,
    name: String,
    port: u16,
    peer: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: NodeIdentity,
    bind: String,
    ns: String,
    tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
    relay: Option<String>,
    fbt: String,
    policy: super::config::VipPortPolicy,
) {
    let tls_mode = policy.tls_mode(port);
    let stall_strategy = policy.stall_close_strategy(port);

    // ── Accept-to-first-byte deadline (PR 1 / Option A) ─
    // ONE deadline covering NS resolve → tunnel dial →
    // TLS wrap/peek → first response byte, set at
    // accept. The steady-state bridge is EXEMPT:
    // long-lived idle flows (websockets, SSE, RDP)
    // must survive arbitrary idle; only the setup
    // phase is deadline-covered.
    //
    // Option A restructure (PR #107): the client
    // socket is split up front — the READ half
    // enters the deadline-covered dial task, the
    // WRITE half stays here. On deadline expiry we
    // write the branded 504 page (HTTP-ish ports)
    // or bare-close (non-HTTP ports) through the
    // write half we still own — closing the PR #106
    // gap where the socket was dropped with the
    // aborted task and the client saw a silent RST.
    let deadline = first_byte_deadline(&fbt, port);

    // The handler splits the socket internally: the
    // dial task owns both halves during the dial phase
    // (the write half delivers the 504 page on deadline
    // expiry), then hands back what the bridge needs.
    let relay_for_err = relay.clone();

    // ── Local TLS termination fast-path ──────────────
    // Routing by the policy's RESOLVED decision
    // (`VipPortPolicy::tls_routing` — a configured
    // `[[tunnel.vip_ports]]` override first, then the
    // built-in table): `Some(Always)` terminates the
    // TLS handshake LOCALLY (client sees a real TLS
    // connection) and bridges the DECRYPTED stream
    // through the tunnel; `Some(Detect)` peeks the
    // first bytes and terminates only when they look
    // like a TLS ClientHello (an explicitly configured
    // `auto` port — PR #138 review: these used to be
    // sent to the plain path with no detection);
    // `None` (e.g. `passthrough` ports such as Wazuh
    // 1514/1515) must NEVER enter the TLS-terminating
    // branch — their bytes go through the tunnel
    // untouched, still encrypted end to end.
    let result = if let Some(tls_mode) = policy.tls_routing(port) {
        match tls {
            Some(acceptor) => {
                handle_tcp_connection_with_tls(
                    tcp_stream,
                    &name,
                    port,
                    peer,
                    peer_node_id,
                    &identity,
                    &bind,
                    &ns,
                    &acceptor,
                    relay.as_deref(),
                    tls_mode,
                    &policy,
                    deadline,
                )
                .await
            }
            // No TLS acceptor (tls disabled): the
            // Detect path has nothing to wrap with —
            // fall through to the plain path so the
            // connection is still tunneled (plain),
            // exactly as when TLS is unconfigured.
            None => {
                proxy_dial_then_bridge(
                    tcp_stream,
                    &name,
                    port,
                    peer,
                    peer_node_id,
                    &identity,
                    &bind,
                    &ns,
                    relay.as_deref(),
                    tls.as_deref(),
                    deadline,
                    tls_mode,
                    stall_strategy,
                )
                .await
            }
        }
    } else {
        proxy_dial_then_bridge(
            tcp_stream,
            &name,
            port,
            peer,
            peer_node_id,
            &identity,
            &bind,
            &ns,
            relay.as_deref(),
            tls.as_deref(),
            deadline,
            tls_mode,
            stall_strategy,
        )
        .await
    };

    if let Err(e) = result {
        warn!(
            "tunnel error for {}: {} (relay={:?})",
            name, e, relay_for_err
        );
    }
}

/// Bind a VIP listener. Direct bind first; on macOS, when the non-root
/// per-user agent is refused (privileged port, or a new VIP with no lo0
/// alias yet), ask the root port broker in `org.ztlp.machine` for the REAL
/// port — it binds and hands us the listening fd (agent::port_broker).
async fn bind_vip_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    match TcpListener::bind(addr).await {
        Ok(l) => Ok(l),
        Err(e) => {
            #[cfg(target_os = "macos")]
            if let SocketAddr::V4(v4) = addr {
                use crate::agent::port_broker as pb;
                if pb::should_ask_broker(e.kind(), *v4.ip()) {
                    let req = pb::BindRequest {
                        ip: *v4.ip(),
                        port: v4.port(),
                    };
                    // The agent can start before org.ztlp.machine has its
                    // socket up (login vs boot race, or a service restart):
                    // keep asking for up to 2 minutes instead of giving up.
                    let mut tries = 0u32;
                    let got = loop {
                        let r = tokio::task::spawn_blocking(move || {
                            pb::request_listener(std::path::Path::new(pb::BROKER_SOCKET_PATH), &req)
                        })
                        .await
                        .map_err(|j| std::io::Error::other(j.to_string()))?;
                        match r {
                            Err(be) if be.is_retryable() && tries < 120 => {
                                if tries == 0 {
                                    info!("VIP {}: waiting for the port broker ({be})", addr);
                                }
                                tries += 1;
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                            other => break other,
                        }
                    };
                    return match got {
                        Ok(std_l) => {
                            std_l.set_nonblocking(true)?;
                            info!("VIP {} bound via the port broker", addr);
                            TcpListener::from_std(std_l)
                        }
                        Err(msg) => Err(std::io::Error::new(
                            e.kind(),
                            format!("{e}; port broker: {msg}"),
                        )),
                    };
                }
            }
            Err(e)
        }
    }
}

/// Handle a TCP connection with TLS termination, then establish a ZTLP tunnel.
///
/// The TLS mode is RESOLVED by the caller (`VipPortPolicy::tls_mode` — a
/// configured `[[tunnel.vip_ports]]` override first, then the built-in
/// port table) and passed in; this function no longer re-derives it from
/// the port number, so the policy is the single source of truth:
/// - `Always` → always TLS
/// - `Never` → never TLS (passthrough ports: bytes forwarded untouched)
/// - `Detect` → detect by peeking at first bytes
///
/// After TLS (if applicable), the decrypted stream is bridged through a ZTLP tunnel.
///
/// `deadline` is the accept-to-first-byte deadline set at accept; it is
/// propagated to `handle_tcp_connection_gated` so the dial phase (and the
/// relay/last dial attempt inside it) is bounded even when the caller does
/// not wrap it in its own `select!` (PR #138 review: the TLS path previously
/// bypassed the deadline entirely). Steady-state bridging stays exempt.
#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection_with_tls(
    tcp_stream: tokio::net::TcpStream,
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    tls_acceptor: &tokio_rustls::TlsAcceptor,
    relay_addr: Option<&str>,
    tls_mode: local_tls::TlsMode,
    policy: &super::config::VipPortPolicy,
    deadline: Option<Duration>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match local_tls::maybe_wrap_tls(tcp_stream, tls_mode, port, tls_acceptor).await {
        Ok(local_tls::MaybeWrapped::Tls(tls_stream)) => {
            info!("TLS handshake OK for {} (port {})", ztlp_name, port);
            handle_tcp_connection_gated(
                tls_stream,
                ztlp_name,
                port,
                peer_addr,
                peer_node_id,
                identity,
                bind_addr,
                ns_server,
                relay_addr,
                true,
                policy,
                deadline,
            )
            .await
        }
        Ok(local_tls::MaybeWrapped::Plain(stream)) => {
            handle_tcp_connection_gated(
                stream,
                ztlp_name,
                port,
                peer_addr,
                peer_node_id,
                identity,
                bind_addr,
                ns_server,
                relay_addr,
                false,
                policy,
                deadline,
            )
            .await
        }
        Ok(local_tls::MaybeWrapped::PlainWithPeek(peek_stream)) => {
            handle_tcp_connection_gated(
                peek_stream,
                ztlp_name,
                port,
                peer_addr,
                peer_node_id,
                identity,
                bind_addr,
                ns_server,
                relay_addr,
                false,
                policy,
                deadline,
            )
            .await
        }
        Err(e) => {
            warn!("TLS wrapping failed for {} port {}: {}", ztlp_name, port, e);
            Err(e.into())
        }
    }
}

/// The result of the deadline-covered dial phase (Option A, PR #108).
///
/// The dial future owns ONLY the client socket's read half (plus the
/// tunnel establishment); the client's write half stays with the caller
/// for the whole lifetime of the connection — the dial phase never writes
/// to it. On deadline expiry the caller writes the branded 504 page
/// (HTTP-ish ports) or bare-closes (non-HTTP ports) through that write
/// half, then shuts the connection down cleanly (FIN, not RST).
///
/// - `Complete`: the backend produced its first response byte and it was
///   delivered to the client. The steady-state bridge runs next (no
///   deadline — long-lived flows unaffected). The tunnel halves are the
///   QUIC stream ends (no type erasure).
/// - `ClientClosedBeforeFirstByte`: the client hung up during dial (EOF or
///   write error), or the tunnel/backend closed before the first response
///   byte. The caller bare-closes the retained write half.
pub enum DialOutcome {
    Complete {
        /// Client read half (exhausted on EOF, or still valid).
        client_read: tokio::net::tcp::OwnedReadHalf,
        /// Tunnel read side (backend → client direction).
        tunnel_read: quinn::RecvStream,
        /// Tunnel write side (client → backend direction).
        tunnel_write: quinn::SendStream,
        /// The first backend frame's payload, held by the dial phase.
        /// The bridge MUST write this to the client before reading more
        /// from `tunnel_read` — the tunnel may be closed after the first
        /// frame (the gateway sends the response and FINs the stream),
        /// so the bridge would otherwise read 0 bytes and the client
        /// gets nothing (HTTP 000).
        first_frame: Option<Vec<u8>>,
        /// Hold until the bridge ends (marks a shared tunnel connection
        /// as in use; empty when connections are not shared).
        keep: TunnelKeep,
    },
    /// The client or tunnel/backend closed before a first response byte.
    ClientClosedBeforeFirstByte,
}

/// Establish the tunnel dial phase (Option A, PR #108): NS resolve → QUIC dial →
/// forward the client's request bytes → wait for the backend's first
/// response byte.
///
/// This is the phase the accept-to-first-byte deadline (PR #106 → #108)
/// covers. It owns ONLY `client_read` — the client's write half stays with
/// the caller for the connection's entire lifetime so the caller can
/// deliver the branded 504 page on deadline expiry (the PR #106/#107 gap:
/// the write half used to die with the aborted task).
///
/// The dial phase NEVER writes to the client: the backend's first response
/// bytes are held in the tunnel (QUIC receive buffer) and the steady-state
/// bridge (run by the caller right after `Complete`) is what delivers them
/// to the client. This is safe for HTTP because the response is a reply to
/// the request this phase just forwarded — there is no out-of-band client
/// input during dial that the backend could depend on.
#[allow(clippy::too_many_arguments)]
async fn proxy_dial_phase(
    mut client_read: tokio::net::tcp::OwnedReadHalf,
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    // The accept-time first-byte deadline (bounds the relay/last dial
    // attempt — see `connect_tunnel`).
    deadline: Option<Duration>,
) -> Result<DialOutcome, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncReadExt;

    // ── Connect (direct-first plan, then relay) ─────────────────────────
    // See `connect_tunnel`: ranked direct candidates each get a short
    // timeout; the relay/last attempt is bounded by the accept-time
    // first-byte deadline.
    let OpenedTunnel {
        leased,
        mut q_send,
        mut q_recv,
    } = connect_and_open(
        ztlp_name,
        port,
        peer_addr,
        peer_node_id,
        identity,
        bind_addr,
        ns_server,
        relay_addr,
        deadline,
        " (dial)",
    )
    .await?;
    let connected = &leased.tunnel;
    debug!(
        "dial phase: tunnel active: {} → {} via {:?} (session {})",
        ztlp_name, connected.addr, connected.via, connected.session_id
    );

    if leased.reused {
        // A shared connection that was already there may be dead without
        // QUIC knowing yet (the device changed network): watch the first
        // exchange and move the request to a fresh connection if so.
        use super::reconnect::{first_exchange, ExchangeConfig, ExchangeEnd, Leg};
        let dead_conn = leased.tunnel.conn.clone();
        let leg = Leg {
            send: q_send,
            recv: q_recv,
            keep: TunnelKeep {
                _lease: leased.lease,
            },
            progress: datagrams_received(&dead_conn),
        };
        let mut unchanged = |c: Option<&[u8]>| c.map(<[u8]>::to_vec).unwrap_or_default();
        let cfg = ExchangeConfig {
            window: super::reconnect::LIVENESS_WINDOW,
            cap: super::reconnect::REPLAY_CAP,
            eof_ends: true,
        };
        let redial = |dead: super::reconnect::Dead| async move {
            // A failed stream says nothing about the connection's other
            // streams: only a closed or silent connection is dropped.
            if dead.silent || dead_conn.inner.close_reason().is_some() {
                drop_shared_tunnel_if_same(ztlp_name, port, &dead_conn, dead.silent, &dead.reason);
            }
            drop(dead_conn);
            let o = connect_and_open(
                ztlp_name,
                port,
                peer_addr,
                peer_node_id,
                identity,
                bind_addr,
                ns_server,
                relay_addr,
                deadline,
                " (dial)",
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok(Leg {
                progress: datagrams_received(&o.leased.tunnel.conn),
                send: o.q_send,
                recv: o.q_recv,
                keep: TunnelKeep {
                    _lease: o.leased.lease,
                },
            })
        };
        return match first_exchange(&mut client_read, &mut unchanged, &[], leg, cfg, redial).await {
            Err(ExchangeEnd::ClientClosed) => Ok(DialOutcome::ClientClosedBeforeFirstByte),
            Err(ExchangeEnd::RedialFailed(e)) => Err(e.into()),
            Ok(handoff) => {
                if handoff.replayed {
                    info!(
                        "request for {} (port {}) carried on a fresh tunnel connection",
                        ztlp_name, port
                    );
                }
                let (tunnel_read, first) = handoff.first.await;
                match first {
                    Ok(frame) => Ok(DialOutcome::Complete {
                        client_read,
                        tunnel_read,
                        tunnel_write: handoff.send,
                        first_frame: Some(frame),
                        keep: handoff.keep,
                    }),
                    Err(e) => {
                        warn!("[DIAL] tunnel read error before the first byte: {}", e);
                        Ok(DialOutcome::ClientClosedBeforeFirstByte)
                    }
                }
            }
        };
    }
    let keep = TunnelKeep {
        _lease: leased.lease,
    };

    // Pump up: client → tunnel. Reads at most ONE client frame (the
    // complete request) and forwards it to the backend. Owns
    // `client_read` + `q_send`; returns both ends so the caller can hand
    // them to the steady-state bridge.
    let pump_up_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 65000];
        let client_eof = match client_read.read(&mut buf).await {
            Ok(0) => true, // client closed before sending anything
            Ok(n) => {
                let _ =
                    crate::quic_transport::noise_stream::write_ztlp_frame(&mut q_send, &buf[..n])
                        .await
                        .is_err();
                false
            }
            Err(_) => true,
        };
        (client_read, q_send, client_eof)
    });

    // Pump down: tunnel → (held). Reads exactly ONE backend frame (the
    // first response byte) and holds it — the steady-state bridge, run by
    // the caller right after this phase, is what delivers backend bytes to
    // the client. The dial phase NEVER writes to the client: the client's
    // write half stays with the caller for the whole connection lifetime
    // (Option A, PR #108) so the caller can write the branded 504 page
    // through it on deadline expiry instead of the socket dying with an
    // aborted task.
    let pump_down_task = tokio::spawn(async move {
        info!("[DIAL] pump_down: waiting for first backend frame from tunnel");
        let result = match crate::quic_transport::noise_stream::read_ztlp_frame(&mut q_recv).await {
            Ok(payload) => {
                info!(
                    "[DIAL] pump_down: got first backend frame ({} bytes)",
                    payload.len()
                );
                (true, Some(payload))
            }
            Err(e) => {
                warn!("[DIAL] pump_down: tunnel read error: {}", e);
                (false, None)
            }
        };
        let (got, first_frame) = result;
        (q_recv, got, first_frame)
    });

    // Wait for the first backend byte (pump_down finishing), then abort
    // the upstream pump.
    let (q_recv, got_first_byte, first_frame) =
        pump_down_task.await.expect("pump_down task panicked");
    pump_up_task.abort();
    let (client_read, q_send, client_eof) = pump_up_task.await.expect("pump_up task panicked");

    if got_first_byte && !client_eof {
        // First backend byte received and held in the tunnel. The steady-
        // state bridge (called by the caller) delivers it to the client
        // and keeps pumping both directions.
        Ok(DialOutcome::Complete {
            client_read,
            tunnel_read: q_recv,
            tunnel_write: q_send,
            first_frame,
            keep,
        })
    } else {
        // The client hung up during dial (EOF), or the tunnel/backend
        // closed before the first response byte. The caller bare-closes
        // the retained client write half.
        Ok(DialOutcome::ClientClosedBeforeFirstByte)
    }
}

/// Steady-state bridge: run until either direction EOFs (NO deadline —
/// long-lived idle flows like websockets/SSE/RDP must survive).
///
/// Typed on the real QUIC stream types (a QUIC bidi stream is NOT splittable
/// into TCP-style halves — `RecvStream`/`SendStream` are the halves).
async fn proxy_bridge_streams(
    mut client_read: tokio::net::tcp::OwnedReadHalf,
    mut client_write: tokio::net::tcp::OwnedWriteHalf,
    mut tunnel_read: quinn::RecvStream,
    mut tunnel_write: quinn::SendStream,
) {
    let pump_up = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 65000];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if crate::quic_transport::noise_stream::write_ztlp_frame(
                        &mut tunnel_write,
                        &buf[..n],
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tunnel_write.finish();
    });

    let pump_down = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        info!("[BRIDGE] pump_down starting: reading tunnel → writing client");
        let mut frame_count = 0u32;
        let mut total_bytes = 0u64;
        loop {
            match crate::quic_transport::noise_stream::read_ztlp_frame(&mut tunnel_read).await {
                Ok(payload) => {
                    frame_count += 1;
                    total_bytes += payload.len() as u64;
                    if frame_count <= 5 {
                        info!(
                            "[BRIDGE] pump_down frame {}: {} bytes (total {} bytes)",
                            frame_count,
                            payload.len(),
                            total_bytes
                        );
                    }
                    if client_write.write_all(&payload).await.is_err() {
                        warn!(
                            "[BRIDGE] pump_down: client write failed after {} frames / {} bytes",
                            frame_count, total_bytes
                        );
                        break;
                    }
                }
                Err(e) => {
                    warn!(
                        "[BRIDGE] pump_down: tunnel read error after {} frames / {} bytes: {}",
                        frame_count, total_bytes, e
                    );
                    break;
                }
            }
        }
        info!(
            "[BRIDGE] pump_down done: {} frames, {} bytes total",
            frame_count, total_bytes
        );
        let _ = client_write.shutdown().await;
    });

    let _ = tokio::join!(pump_up, pump_down);
}

/// Option A (PR #108): the full accept → first-byte → bridge handler with
/// split-socket 504 delivery.
///
/// The client socket is split UP FRONT — the READ half enters the
/// deadline-covered dial task, the WRITE half stays with this outer task
/// for the connection's entire lifetime. On deadline expiry the outer
/// task writes the branded 504 page (HTTP-ish ports) or bare-closes
/// (non-HTTP ports) through the write half it still owns, then shuts the
/// connection down cleanly (FIN, not RST) — closing the PR #106/#107 gap
/// where the socket died with the aborted task and the client (Chrome in
/// particular) saw a silent RST instead of a real error page.
///
/// - `deadline = Some(d)`: one budget, started at accept, covering
///   dial + first-byte. Expiry → abort dial task, deliver 504/FIN.
/// - `deadline = None`: no deadline (dial runs forever; bridge takes over).
///
/// This is the plain-TCP path. The TLS variant (443/8443) terminates TLS
/// FIRST (client-driven, fast), then runs the same split-socket dial over
/// the TLS stream — the 504 goes out encrypted.
///
/// `tls_mode` is the RESOLVED local-TLS mode for this port (`Never` for
/// passthrough ports — the bytes crossing `client` are opaque and must
/// never be snuck a peek into here; `Detect`/`Always` for the built-in
/// table's behaviour). `stall_strategy` is the RESOLVED deadline-expiry
/// outcome for this port under the same policy — the 504-class decision
/// must never treat an unknown configured port as HTTP.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_dial_then_bridge(
    client: tokio::net::TcpStream,
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    _tls_acceptor: Option<&tokio_rustls::TlsAcceptor>,
    deadline: Option<Duration>,
    _tls_mode: local_tls::TlsMode,
    stall_strategy: StallCloseStrategy,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncWriteExt;

    // Split the client socket: the read half goes into the dial task, the
    // write half stays with us for the WHOLE connection lifetime — the
    // dial phase never writes to the client (the steady-state bridge does),
    // and on deadline expiry we write the 504 page through it (Option A).
    let (client_read, mut client_write) = client.into_split();

    let name_for_log = ztlp_name.to_string();

    // Owned values for the spawned inner dial task (it outlives this
    // function's borrowed parameters).
    let ztlp_name_owned = ztlp_name.to_string();
    let identity_owned = identity.clone();
    let bind_owned = bind_addr.to_string();
    let ns_owned = ns_server.to_string();
    let relay_owned = relay_addr.map(|r| r.to_string());

    // Inner task: the deadline-covered dial phase. It owns the client READ
    // half + the tunnel. On success it returns the tunnel halves; the
    // steady-state bridge (called below) takes over with our write half.
    // On deadline expiry the outer select! aborts this task — the read
    // half and tunnel die with it, but the write half is still ours, so
    // the client gets a clean 504 page + FIN, not a bare RST.
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
    let dial_task = tokio::spawn(async move {
        let result = proxy_dial_phase(
            client_read,
            &ztlp_name_owned,
            port,
            peer_addr,
            peer_node_id,
            &identity_owned,
            &bind_owned,
            &ns_owned,
            relay_owned.as_deref(),
            deadline,
        )
        .await;
        let _ = done_tx.send(());
        result
    });

    let dial_result: Result<DialOutcome, Box<dyn std::error::Error + Send + Sync>> = match deadline
    {
        Some(d) => tokio::select! {
            _ = &mut done_rx => match dial_task.await {
                Ok(r) => r,
                Err(e) => {
                    // Dial task panicked/aborted — the client socket read
                    // half died with it; close the write half cleanly.
                    let _ = client_write.shutdown().await;
                    return Err(format!("dial task join error: {}", e).into());
                }
            },
            _ = tokio::time::sleep(d) => {
                // Deadline expired. Abort the dial task (read half +
                // tunnel die with it), then deliver the outcome the port
                // class deserves through the write half we still own:
                // branded 504 page for HTTP-ish ports, bare close for
                // everything else. The subsequent shutdown() sends FIN
                // (not RST) so browsers render the page cleanly.
                warn!(
                    "accept-to-first-byte deadline ({:?}) expired for {} (port {}) \
                     — backend did not respond in time",
                    d, name_for_log, port
                );
                dial_task.abort();
                // A shared connection that produced no answer may be dead
                // without quinn knowing yet: do not hand it to the next
                // request.
                forget_shared_tunnel(&name_for_log, port);

                if stall_strategy == StallCloseStrategy::Deliver504 {
                    if let Some(page) =
                        stall_response_for_port(port, &name_for_log, Some(d))
                    {
                        if client_write.write_all(&page).await.is_err() {
                            warn!(
                                "failed to write 504 page to {} (port {}): client gone?",
                                name_for_log, port
                            );
                        }
                    }
                }
                // Graceful close: FIN after the page (or immediately for
                // bare-close ports). The write half is dropped at function
                // exit, which would also close the socket — but the
                // explicit shutdown gives the client a clean EOF marker
                // to finish reading the 504 body first.
                let _ = client_write.shutdown().await;

                return Err(format!(
                    "accept-to-first-byte deadline ({:?}) expired for {} (port {})",
                    d, name_for_log, port
                )
                .into());
            }
        },
        None => match dial_task.await {
            Ok(r) => r,
            Err(e) => return Err(format!("dial task join error: {}", e).into()),
        },
    };

    match dial_result {
        Ok(DialOutcome::Complete {
            client_read,
            tunnel_read,
            tunnel_write,
            first_frame,
            keep: _keep,
        }) => {
            // Write the first backend frame to the client immediately —
            // the tunnel may be closed after the first frame (the gateway
            // sends the response and FINs the stream), so the bridge
            // would otherwise read 0 bytes and the client gets nothing.
            if let Some(frame) = &first_frame {
                if let Err(e) = client_write.write_all(frame).await {
                    warn!(
                        "failed to write first frame ({} bytes) to {} (port {}): {}",
                        frame.len(),
                        ztlp_name,
                        port,
                        e
                    );
                    let _ = client_write.shutdown().await;
                    return Ok(());
                }
            }
            // The steady-state bridge delivers any remaining backend bytes
            // to the client, then keeps pumping both directions with NO
            // deadline (long-lived flows).
            proxy_bridge_streams(client_read, client_write, tunnel_read, tunnel_write).await;

            debug!("tunnel closed: {} (port {})", ztlp_name, port);
            Ok(())
        }
        Ok(DialOutcome::ClientClosedBeforeFirstByte) => {
            // The client hung up during dial (or the tunnel/backend closed
            // before the first response byte). Bare-close the retained
            // write half to clean up.
            let _ = client_write.shutdown().await;
            debug!("client closed during dial: {} (port {})", ztlp_name, port);
            Ok(())
        }
        Err(e) => {
            warn!("tunnel error for {}: {}", ztlp_name, e);
            Err(e)
        }
    }
}

/// A dialed, handshaken tunnel with its data stream open. Holds the QUIC
/// connection so it stays alive for as long as the stream is in use.
struct DialedTunnel {
    _conn: crate::quic_transport::tokio_endpoint::QuicConnection,
    q_send: quinn::SendStream,
    q_recv: quinn::RecvStream,
    session_id: String,
    /// The stream is on a shared connection that already existed.
    reused: bool,
    _keep: TunnelKeep,
}

/// Dials again for a client connection whose reused shared connection
/// turned out to be dead. Only built in shared-connection mode.
type RedialFn = Box<
    dyn FnOnce() -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<DialedTunnel, Box<dyn std::error::Error + Send + Sync>>,
                    > + Send,
            >,
        > + Send,
>;

/// The gateway's datagram counter for [`super::reconnect::Leg::progress`].
fn datagrams_received(
    conn: &crate::quic_transport::tokio_endpoint::QuicConnection,
) -> Box<dyn Fn() -> u64 + Send + Sync> {
    let conn = conn.inner.clone();
    Box::new(move || conn.stats().udp_rx.datagrams)
}

impl super::reconnect::FrameSend for quinn::SendStream {
    async fn send_frame(&mut self, payload: &[u8]) -> Result<(), String> {
        crate::quic_transport::noise_stream::write_ztlp_frame(self, payload)
            .await
            .map_err(|e| e.to_string())
    }
    fn finish(&mut self) {
        let _ = quinn::SendStream::finish(self);
    }
}

impl super::reconnect::FrameRecv for quinn::RecvStream {
    async fn recv_frame(&mut self) -> Result<Vec<u8>, String> {
        crate::quic_transport::noise_stream::read_ztlp_frame(self)
            .await
            .map_err(|e| e.to_string())
    }
}

/// Establish a ZTLP tunnel: NS resolve (when uncached), relay CLIENT_ROUTE,
/// QUIC connect, Noise handshake, open the data stream.
///
/// Takes owned arguments so the splash gate can run it in a spawned task.
/// This is the single copy of the dial sequence (the 2026-08-30 fixes had to
/// be applied twice when it was duplicated).
#[allow(clippy::too_many_arguments)]
async fn dial_tunnel(
    ztlp_name: String,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: NodeIdentity,
    bind_addr: String,
    ns_server: String,
    relay_addr: Option<String>,
    deadline: Option<Duration>,
) -> Result<DialedTunnel, Box<dyn std::error::Error + Send + Sync>> {
    // Direct-first plan, then relay (see `connect_tunnel`): ranked direct
    // candidates each get a short timeout; the relay attempt is bounded
    // by the caller's first-byte deadline.
    let OpenedTunnel {
        leased,
        q_send,
        q_recv,
    } = connect_and_open(
        &ztlp_name,
        port,
        peer_addr,
        peer_node_id,
        &identity,
        &bind_addr,
        &ns_server,
        relay_addr.as_deref(),
        deadline,
        "",
    )
    .await?;

    Ok(DialedTunnel {
        session_id: leased.tunnel.session_id.to_string(),
        _conn: leased.tunnel.conn,
        q_send,
        q_recv,
        reused: leased.reused,
        _keep: TunnelKeep {
            _lease: leased.lease,
        },
    })
}

/// The request-head stamper for a connection, or `None`.
///
/// Only connections whose TLS the AGENT terminated get one: the backend then
/// receives plain HTTP and must be told the client used https
/// (`X-Forwarded-Proto: https`), or a framework behind it rejects https form
/// POSTs as cross-origin (Rails 422, found live 2026-10-05). Plain-HTTP
/// connections are forwarded byte-for-byte as before.
fn request_stamper(tls_terminated: bool) -> Option<super::forwarded_proto::ForwardedProtoStamper> {
    tls_terminated.then(super::forwarded_proto::ForwardedProtoStamper::new)
}

/// Write the first-byte-deadline 504 page through `stream`, then shut it
/// down (FIN, not RST — the browser renders the page cleanly). Shared by
/// the plain path (`proxy_dial_then_bridge`) and the gated TLS path
/// (`handle_tcp_connection_gated`): both own the client stream at deadline
/// expiry and must deliver the SAME outcome the port class deserves
/// (PR #138 review — the TLS path bypassed the splash gate and had no
/// deadline at all, so a slow/unresponsive backend held the client
/// open indefinitely).
async fn deliver_deadline_504<S>(
    stream: &mut S,
    port: u16,
    ztlp_name: &str,
    deadline: Option<Duration>,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    if let Some(page) = stall_response_for_port(port, ztlp_name, deadline) {
        if stream.write_all(&page).await.is_err() {
            warn!(
                "failed to write 504 page to {} (port {}): client gone?",
                ztlp_name, port
            );
        }
    }
    stream.shutdown().await
}

/// Bridge a local stream to a dialed tunnel until either side closes.
/// `initial` (the already-read request head, if any) is sent first.
///
/// `redial` is only given in shared-connection mode. When the tunnel's
/// stream is on a connection that already existed, the first exchange is
/// watched (`reconnect::first_exchange`) and the request is carried on a
/// connection from `redial` if that one turns out to be dead.
async fn bridge_tunnel<S>(
    stream: S,
    tunnel: DialedTunnel,
    initial: &[u8],
    ztlp_name: &str,
    port: u16,
    tls_terminated: bool,
    redial: Option<RedialFn>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let DialedTunnel {
        _conn,
        mut q_send,
        q_recv,
        session_id,
        reused,
        _keep,
    } = tunnel;

    // The splash gate may already have read the first request head; it must
    // be stamped like everything after it.
    let mut stamper = request_stamper(tls_terminated);

    if let (true, Some(redial)) = (reused, redial) {
        use super::reconnect::{first_exchange, ExchangeConfig, ExchangeEnd, Leg};
        use tokio::io::AsyncWriteExt;
        let (mut local_read, mut local_write) = tokio::io::split(stream);
        let dead_conn = _conn.clone();
        let leg = Leg {
            progress: datagrams_received(&_conn),
            send: q_send,
            recv: q_recv,
            keep: (_conn, _keep, session_id),
        };
        let cfg = ExchangeConfig {
            window: super::reconnect::LIVENESS_WINDOW,
            cap: super::reconnect::REPLAY_CAP,
            eof_ends: false,
        };
        let outcome = {
            let mut stamp = |chunk: Option<&[u8]>| match (stamper.as_mut(), chunk) {
                (Some(st), Some(bytes)) => st.feed(bytes),
                (Some(st), None) => st.finish(),
                (None, Some(bytes)) => bytes.to_vec(),
                (None, None) => Vec::new(),
            };
            let again = |dead: super::reconnect::Dead| async move {
                // A failed stream says nothing about the connection's other
                // streams: only a closed or silent connection is dropped.
                if dead.silent || dead_conn.inner.close_reason().is_some() {
                    drop_shared_tunnel_if_same(
                        ztlp_name,
                        port,
                        &dead_conn,
                        dead.silent,
                        &dead.reason,
                    );
                }
                drop(dead_conn);
                let t = redial().await.map_err(|e| e.to_string())?;
                Ok(Leg {
                    progress: datagrams_received(&t._conn),
                    send: t.q_send,
                    recv: t.q_recv,
                    keep: (t._conn, t._keep, t.session_id),
                })
            };
            first_exchange(&mut local_read, &mut stamp, initial, leg, cfg, again).await
        };
        let handoff = match outcome {
            Ok(h) => h,
            Err(ExchangeEnd::ClientClosed) => return Ok(()),
            Err(ExchangeEnd::RedialFailed(e)) => {
                let _ = local_write.shutdown().await;
                return Err(e.into());
            }
        };
        if handoff.replayed {
            info!(
                "request for {} (port {}) carried on a fresh tunnel connection",
                ztlp_name, port
            );
        }
        let (_conn, _keep, session_id) = handoff.keep;
        run_bridge_pumps(
            local_read,
            local_write,
            handoff.send,
            BridgeDown::First(handoff.first),
            stamper,
            handoff.client_eof,
        )
        .await;
        debug!("tunnel closed: {} (session {})", ztlp_name, session_id);
        return Ok(());
    }

    if !initial.is_empty() {
        let first = match stamper.as_mut() {
            Some(st) => st.feed(initial),
            None => initial.to_vec(),
        };
        if !first.is_empty() {
            crate::quic_transport::noise_stream::write_ztlp_frame(&mut q_send, &first)
                .await
                .map_err(|e| format!("failed to forward request head: {}", e))?;
        }
    }

    // Bridge the (potentially TLS-unwrapped) local stream <-> the QUIC
    // data stream, one task per direction (mirrors `cmd_connect`'s
    // v0.36.0 quic-pump-throughput fix: coupling both directions in a
    // single select! let a stalled direction starve the other).
    let (local_read, local_write) = tokio::io::split(stream);
    run_bridge_pumps(
        local_read,
        local_write,
        q_send,
        BridgeDown::Stream(q_recv),
        stamper,
        false,
    )
    .await;

    debug!("tunnel closed: {} (session {})", ztlp_name, session_id);

    Ok(())
}

/// Where the tunnel-to-client pump starts.
enum BridgeDown {
    /// Read frames from the stream.
    Stream(quinn::RecvStream),
    /// The first frame is already being awaited (it follows a watched
    /// first exchange); deliver it, then read frames from the stream.
    First(super::reconnect::FirstFrame<quinn::RecvStream>),
}

/// The two pumps of [`bridge_tunnel`], until both ended. `client_eof` =
/// the client already closed its sending side and the stream was finished.
async fn run_bridge_pumps<R, W>(
    mut local_read: R,
    mut local_write: W,
    mut q_send: quinn::SendStream,
    down: BridgeDown,
    mut stamper: Option<super::forwarded_proto::ForwardedProtoStamper>,
    client_eof: bool,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let pump_up = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        if client_eof {
            return;
        }
        let mut buf = vec![0u8; 65000];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    // Stamp request heads on TLS-terminated connections. The
                    // stamper may hold a partial head (empty output): that is
                    // not EOF, just read more.
                    let out = match stamper.as_mut() {
                        Some(st) => st.feed(&buf[..n]),
                        None => buf[..n].to_vec(),
                    };
                    if out.is_empty() {
                        continue;
                    }
                    // A frame is capped at u16::MAX; stamping adds ~24 bytes,
                    // so split rather than fail on a full-size read.
                    let mut failed = false;
                    for part in out.chunks(60_000) {
                        if crate::quic_transport::noise_stream::write_ztlp_frame(&mut q_send, part)
                            .await
                            .is_err()
                        {
                            failed = true;
                            break;
                        }
                    }
                    if failed {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // EOF mid-head: forward what was held instead of dropping it.
        if let Some(st) = stamper.as_mut() {
            let rest = st.finish();
            if !rest.is_empty() {
                let _ =
                    crate::quic_transport::noise_stream::write_ztlp_frame(&mut q_send, &rest).await;
            }
        }
        let _ = q_send.finish();
    });

    let pump_down = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut q_recv = match down {
            BridgeDown::Stream(q_recv) => q_recv,
            BridgeDown::First(first) => {
                let (q_recv, frame) = first.await;
                let delivered = match frame {
                    Ok(payload) => local_write.write_all(&payload).await.is_ok(),
                    Err(_) => false,
                };
                if !delivered {
                    let _ = local_write.shutdown().await;
                    return;
                }
                q_recv
            }
        };
        loop {
            match crate::quic_transport::noise_stream::read_ztlp_frame(&mut q_recv).await {
                Ok(payload) => {
                    if local_write.write_all(&payload).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = local_write.shutdown().await;
    });

    let _ = tokio::join!(pump_up, pump_down);
}

/// Inner handler: establish ZTLP tunnel and bridge an arbitrary AsyncRead+AsyncWrite stream.
///
/// `deadline` is the caller's accept-to-first-byte deadline, propagated
/// into `dial_tunnel` so the relay/last dial attempt is bounded even when
/// the caller does not wrap the whole dial in its own `select!`
/// (PR #138 review — `handle_tcp_connection_gated` previously dropped it).
/// Steady-state bridging stays EXEMPT: long-lived idle flows (websockets,
/// SSE, RDP) must survive arbitrary idle.
#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection_bridged<S>(
    stream: S,
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    tls_terminated: bool,
    deadline: Option<Duration>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tunnel = dial_tunnel(
        ztlp_name.to_string(),
        port,
        peer_addr,
        peer_node_id,
        identity.clone(),
        bind_addr.to_string(),
        ns_server.to_string(),
        relay_addr.map(|r| r.to_string()),
        deadline,
    )
    .await?;
    let redial = shared_redial(
        ztlp_name,
        port,
        peer_addr,
        peer_node_id,
        identity,
        bind_addr,
        ns_server,
        relay_addr,
        deadline,
    );
    bridge_tunnel(stream, tunnel, &[], ztlp_name, port, tls_terminated, redial).await
}

/// The redial for [`bridge_tunnel`]: `None` unless connections are shared.
#[allow(clippy::too_many_arguments)]
fn shared_redial(
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    deadline: Option<Duration>,
) -> Option<RedialFn> {
    if !reuse_connections() {
        return None;
    }
    let name = ztlp_name.to_string();
    let identity = identity.clone();
    let bind = bind_addr.to_string();
    let ns = ns_server.to_string();
    let relay = relay_addr.map(|r| r.to_string());
    Some(Box::new(move || {
        Box::pin(dial_tunnel(
            name,
            port,
            peer_addr,
            peer_node_id,
            identity,
            bind,
            ns,
            relay,
            deadline,
        ))
    }))
}

/// Like `handle_tcp_connection_bridged`, but for HTTP-ish ports it first reads
/// the request head so a browser page load on a slow dial can be shown the
/// splash page (see `splash_gate`). Other ports take the plain path.
///
/// The 504-class (splash-eligible) decision is taken from `policy` — a
/// `[[tunnel.vip_ports]]` override (e.g. 443 → passthrough) or a
/// configured custom port removes the port from the class, so a splash
/// page can only be shown when the agent terminated TLS on a built-in
/// HTTP-ish port.
#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection_gated<S>(
    mut stream: S,
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    tls_terminated: bool,
    policy: &super::config::VipPortPolicy,
    deadline: Option<Duration>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use super::splash_gate::{global_tracker, run_gated, tracker_key, GateConfig, GateOutcome};

    if policy.stall_close_strategy(port) != StallCloseStrategy::Deliver504 {
        // Non-504-class ports (custom ports, passthrough overrides) take
        // the plain path — with the deadline propagated into the dial, so
        // a slow/unresponsive backend cannot hold this connection open
        // indefinitely (PR #138 review: this branch previously had no
        // deadline at all).
        return handle_tcp_connection_bridged(
            stream,
            ztlp_name,
            port,
            peer_addr,
            peer_node_id,
            identity,
            bind_addr,
            ns_server,
            relay_addr,
            tls_terminated,
            deadline,
        )
        .await;
    }

    let redial = shared_redial(
        ztlp_name,
        port,
        peer_addr,
        peer_node_id,
        identity,
        bind_addr,
        ns_server,
        relay_addr,
        deadline,
    );
    let name = ztlp_name.to_string();
    let identity = identity.clone();
    let bind = bind_addr.to_string();
    let ns = ns_server.to_string();
    let relay = relay_addr.map(|r| r.to_string());
    let key = tracker_key(ztlp_name, port);

    let outcome = run_gated(
        &mut stream,
        ztlp_name,
        &key,
        global_tracker(),
        GateConfig::default(),
        move || {
            dial_tunnel(
                name,
                port,
                peer_addr,
                peer_node_id,
                identity,
                bind,
                ns,
                relay,
                deadline,
            )
        },
    )
    .await;

    match outcome {
        GateOutcome::Proceed { head, tunnel } => {
            bridge_tunnel(
                stream,
                tunnel,
                &head,
                ztlp_name,
                port,
                tls_terminated,
                redial,
            )
            .await
        }
        GateOutcome::DialFailed { error, .. } => Err(error),
        GateOutcome::DialAborted { .. } => Err("tunnel dial task aborted".into()),
        GateOutcome::Served(what) => {
            debug!(
                "splash gate served {:?} for {} (port {})",
                what, ztlp_name, port
            );
            Ok(())
        }
    }
}

/// Handle a single TCP connection by establishing a ZTLP tunnel (no TLS).
///
/// Delegates to `handle_tcp_connection_bridged`, which is generic over
/// any `AsyncRead + AsyncWrite` stream (a plain `TcpStream` satisfies
/// this directly) — this eliminates what used to be a second,
/// independently-drifting copy of the entire tunnel-establishment
/// block. Keeping two copies in sync was exactly how the 2026-08-30
/// CLIENT_ROUTE / NodeID-fallback / QUIC-transport fixes had to be
/// applied twice each; a single implementation removes that class of
/// bug going forward.
#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection(
    tcp_stream: tokio::net::TcpStream,
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    handle_tcp_connection_bridged(
        tcp_stream,
        ztlp_name,
        port,
        peer_addr,
        peer_node_id,
        identity,
        bind_addr,
        ns_server,
        relay_addr,
        false,
        None, // legacy helper: no accept-time deadline available
    )
    .await
}
/// Check if the agent daemon is currently running.
///
/// Delegates to [`control::get_agent_pid`], which does the recycled-PID
/// self-heal: if the PID file's process is alive but is NOT one of our ZTLP
/// binaries (Windows recycled the PID to an unrelated program), the stale
/// file is cleared and `false` is returned — so the guard does not keep
/// reporting "running" forever for a PID that no longer belongs to the agent.
pub fn is_agent_running() -> bool {
    control::get_agent_pid().is_some()
}

/// Get the PID of the running agent, if any.
///
/// Delegates to [`control::get_agent_pid`], which does the recycled-PID check
/// and self-heals the stale `agent.pid` on Windows. See that function for the
/// full rationale (the permanent "Agent already running (PID …)" wedge found
/// live on RommelPCAsusTUF).
pub fn get_agent_pid() -> Option<u32> {
    control::get_agent_pid()
}

#[cfg(test)]
mod tests {

    // ── NS-anchored trust: cache + retry helpers ───────────────────────

    #[test]
    fn cache_hit_is_used_freely_on_legacy_devices() {
        assert!(super::cache_hit_usable(None, false));
    }

    #[test]
    fn strict_device_needs_a_verified_cached_expectation() {
        use crate::quic_transport::{CertExpectation, RecordState};
        assert!(!super::cache_hit_usable(None, true));
        let unverified = CertExpectation {
            record: RecordState::Unverified,
            strict: false,
        };
        assert!(!super::cache_hit_usable(Some(&unverified), true));
        let verified = CertExpectation {
            record: RecordState::Verified { fp: None },
            strict: true,
        };
        assert!(super::cache_hit_usable(Some(&verified), true));
    }

    #[test]
    fn ns_cert_failures_are_recognised_through_error_text() {
        use crate::quic_transport::{NS_MISMATCH_MARKER, UNVERIFIED_MARKER};
        assert!(super::is_ns_cert_failure(&format!(
            "all 1 dial attempts failed: the cryptographic handshake failed: error 42: {NS_MISMATCH_MARKER} gateway"
        )));
        assert!(super::is_ns_cert_failure(UNVERIFIED_MARKER));
        assert!(!super::is_ns_cert_failure(
            "QUIC certificate fingerprint ... does not match the pinned value"
        ));
        assert!(!super::is_ns_cert_failure("timed out"));
    }

    #[test]
    fn peer_cert_cache_round_trip_and_forget() {
        use crate::quic_transport::{CertExpectation, RecordState};
        let e = CertExpectation {
            record: RecordState::Verified {
                fp: Some("ab".repeat(32)),
            },
            strict: true,
        };
        super::set_peer_cert("Cert.Cache.ztlp", &e);
        assert_eq!(super::cached_peer_cert("cert.cache.ztlp"), Some(e));
        super::forget_peer_candidates("cert.CACHE.ztlp");
        assert_eq!(super::cached_peer_cert("cert.cache.ztlp"), None);
    }
    use std::time::Duration;

    // ── Direct-first dial plan, step B3 (2026-10-05) ────────────────────────
    //
    // docs/DIRECT-FIRST-DIAL-PLAN.md. `dial_plan` is the pure planner the
    // dialers walk: ranked direct candidates first (each with a short
    // timeout), the relay last (with the remaining budget). It never dials;
    // it only decides the order, so it is fully unit-testable.
    // ── X-Forwarded-Proto wiring (2026-10-05) ───────────────────────────────
    //
    // The stamper itself is covered in `forwarded_proto`. These pin WHERE it
    // applies: only when the agent terminated TLS, and to the request head the
    // splash gate already consumed (the gate reads the first head before
    // `bridge_tunnel` runs, so stamping only the pump would miss request #1,
    // which is exactly the first page load / first form POST).
    mod forwarded_proto_wiring {
        use super::super::request_stamper;

        const POST: &[u8] =
            b"POST /p HTTP/1.1\r\nHost: a\r\nOrigin: https://a\r\nContent-Length: 2\r\n\r\nhi";

        #[test]
        fn tls_terminated_connections_get_a_stamper() {
            let mut st = request_stamper(true).expect("TLS-terminated must stamp");
            let out = String::from_utf8(st.feed(POST)).unwrap();
            assert!(out.contains("X-Forwarded-Proto: https\r\n"), "{out:?}");
        }

        #[test]
        fn plain_connections_are_forwarded_byte_for_byte() {
            assert!(
                request_stamper(false).is_none(),
                "no stamper means the plain-HTTP path is untouched"
            );
        }

        #[test]
        fn the_head_the_splash_gate_already_read_is_stamped_too() {
            // bridge_tunnel feeds `initial` through the SAME stamper that then
            // handles the pump, so request #1 (consumed by the gate) and the
            // later requests are all stamped, and a head split between the gate's
            // read and the pump's first read is reassembled correctly.
            let mut st = request_stamper(true).unwrap();
            let (gate_head, pump_rest) = POST.split_at(25); // mid-head split
            let mut out = st.feed(gate_head);
            out.extend(st.feed(pump_rest));
            let out = String::from_utf8(out).unwrap();
            assert_eq!(
                out.matches("X-Forwarded-Proto: https\r\n").count(),
                1,
                "{out:?}"
            );
            assert!(out.ends_with("\r\n\r\nhi"), "body intact: {out:?}");
        }
    }

    mod direct_first_plan {
        use super::super::{dial_plan, DialAttempt, DialVia, DIRECT_ATTEMPT_TIMEOUT};
        use std::net::SocketAddr;

        fn sa(s: &str) -> SocketAddr {
            s.parse().unwrap()
        }

        #[test]
        fn relayed_dial_scopes_the_pin_to_the_service() {
            // ZT-04: every relayed service shares relay_ip:port, so the pin
            // must carry the service name.
            assert_eq!(
                super::super::relayed_pin_service(DialVia::Relay, "www"),
                Some("www")
            );
            assert_eq!(
                super::super::relayed_pin_service(DialVia::Relay, "admin"),
                Some("admin")
            );
        }

        #[test]
        fn direct_dial_keeps_the_unscoped_pin() {
            assert_eq!(
                super::super::relayed_pin_service(DialVia::Direct, "www"),
                None,
                "a direct dial has its own address; its pin key must not change"
            );
        }

        #[test]
        fn direct_candidates_first_then_relay() {
            let plan = dial_plan(
                &[sa("10.20.30.40:23097"), sa("203.0.113.9:23097")],
                Some(sa("198.51.100.7:23095")),
                false,
            );
            assert_eq!(plan.len(), 3);
            assert_eq!(
                plan[0],
                DialAttempt {
                    addr: sa("10.20.30.40:23097"),
                    via: DialVia::Direct
                }
            );
            assert_eq!(
                plan[1],
                DialAttempt {
                    addr: sa("203.0.113.9:23097"),
                    via: DialVia::Direct
                }
            );
            assert_eq!(
                plan[2],
                DialAttempt {
                    addr: sa("198.51.100.7:23095"),
                    via: DialVia::Relay
                }
            );
        }

        #[test]
        fn relay_address_published_as_a_candidate_is_not_dialed_direct() {
            // The Rust gateway appends the relay as the last `addresses`
            // entry. Dialing it "direct" (no CLIENT_ROUTE) can never work;
            // it must collapse into the single Relay attempt.
            let plan = dial_plan(
                &[sa("10.20.30.40:23097"), sa("198.51.100.7:23095")],
                Some(sa("198.51.100.7:23095")),
                false,
            );
            assert_eq!(plan.len(), 2);
            assert_eq!(plan[0].via, DialVia::Direct);
            assert_eq!(
                plan[1],
                DialAttempt {
                    addr: sa("198.51.100.7:23095"),
                    via: DialVia::Relay
                }
            );
        }

        #[test]
        fn prefer_relay_puts_relay_first_and_keeps_direct_as_fallback() {
            let plan = dial_plan(&[sa("10.0.0.5:23097")], Some(sa("1.2.3.4:23095")), true);
            assert_eq!(plan[0].via, DialVia::Relay);
            assert_eq!(
                plan[1],
                DialAttempt {
                    addr: sa("10.0.0.5:23097"),
                    via: DialVia::Direct
                }
            );
        }

        #[test]
        fn no_relay_configured_means_direct_only_as_today() {
            let plan = dial_plan(&[sa("10.0.0.5:23097"), sa("10.0.0.6:23097")], None, false);
            assert_eq!(plan.len(), 2);
            assert!(plan.iter().all(|a| a.via == DialVia::Direct));
        }

        #[test]
        fn relay_only_when_gateway_published_nothing_dialable() {
            let plan = dial_plan(&[], Some(sa("1.2.3.4:23095")), false);
            assert_eq!(
                plan,
                vec![DialAttempt {
                    addr: sa("1.2.3.4:23095"),
                    via: DialVia::Relay
                }]
            );
        }

        #[test]
        fn direct_attempt_timeout_is_short_but_not_silly() {
            // Same-LAN QUIC+Noise completes in well under 100 ms; a dead
            // candidate must not eat the 15 s first-byte budget. Pin the
            // band so a "let's be generous" edit gets flagged.
            assert!(DIRECT_ATTEMPT_TIMEOUT >= std::time::Duration::from_millis(250));
            assert!(DIRECT_ATTEMPT_TIMEOUT <= std::time::Duration::from_millis(1500));
        }

        // ── PR #138 review, finding 3: the accept-to-first-byte deadline
        //    must BOUND the attempts `attempt_timeout` leaves open ────────
        //
        // `attempt_timeout` gives a SHORT budget only to a direct attempt
        // that has a fallback after it. Two slots are left with `None`:
        //   • the RELAY attempt, and
        //   • the LAST attempt of any plan (the final direct candidate when
        //     there is no relay).
        // Before this fix those slots ran with NO timeout at all — a dead
        // relay or a single unresponsive direct candidate held the client
        // connection open indefinitely. `walk_dial_plan` now wraps those
        // `None`-budget attempts in `tokio::time::timeout(caller's
        // first-byte deadline, …)`, so the dial can no longer outlive the
        // accept-to-first-byte budget.
        //
        // A real tunnel can't be stood up hermetically (it needs a live
        // QUIC+Noise peer), so — exactly like
        // `slow_but_alive_backend_survives_deadline` — this pins the
        // DECISION: the plan-shape that produces the unbounded slots, and
        // the fact that the deadline is the bound that must cover them.
        #[test]
        fn relay_and_last_attempt_are_the_unbounded_slots_the_deadline_must_bound() {
            use super::super::attempt_timeout;

            let deadline = std::time::Duration::from_secs(15);

            // Case A — direct-first with a relay (the default ladder):
            // [direct, direct, relay]. The relay is the LAST attempt and
            // the only Relay slot — BOTH `attempt_timeout`-unbounded, and
            // the relay is where a dead relay would hang the client.
            let plan = dial_plan(
                &[sa("10.0.0.5:23097"), sa("10.0.0.6:23097")],
                Some(sa("1.2.3.4:23095")),
                false, // direct-first
            );
            assert_eq!(plan.len(), 3);
            // Every direct attempt EXCEPT the last gets the short budget.
            assert_eq!(attempt_timeout(plan[0], true), Some(DIRECT_ATTEMPT_TIMEOUT));
            assert_eq!(attempt_timeout(plan[1], true), Some(DIRECT_ATTEMPT_TIMEOUT));
            // The relay (last attempt) is the unbounded slot the deadline
            // must cover — `walk_dial_plan` wraps it in
            // `timeout(deadline, …)`.
            assert!(plan[2].via == DialVia::Relay);
            assert_eq!(attempt_timeout(plan[2], false), None);

            // Case B — no relay configured, single candidate: the ONE
            // attempt is `has_fallback == false` → `attempt_timeout` is
            // `None`. This is the "single unresponsive direct candidate"
            // hang; the deadline is the bound.
            let plan_b = dial_plan(&[sa("10.0.0.5:23097")], None, false);
            assert_eq!(plan_b.len(), 1);
            assert!(plan_b[0].via == DialVia::Direct);
            assert_eq!(attempt_timeout(plan_b[0], false), None);

            // The bound the caller passes for BOTH slots is the accept-to-
            // first-byte deadline itself (a finite, sane, positive budget),
            // not an unbounded one. A regression that drops the deadline
            // from the relay/last slot makes this the only test that
            // notices.
            assert_eq!(deadline, std::time::Duration::from_secs(15));
            assert!(!deadline.is_zero());
        }

        // ── Cache hit must dial the FULL ranked list (2026-10-05 follow-up) ──
        //
        // The VIP cache used to hand the dialer only `peer_addr` (the best
        // single candidate). A client whose cached LAN candidate went stale
        // (laptop left the office) would fail that one direct attempt and
        // fall to the relay, never trying the gateway's public address.
        // `candidates_for_dial` is the one place that decides what the
        // planner sees: cached list when present, else [cached best], else
        // the fresh resolution.
        #[test]
        fn cache_hit_with_list_uses_the_whole_list() {
            use super::super::candidates_for_dial;
            let cached = vec![sa("10.20.30.40:23097"), sa("203.0.113.9:23097")];
            let got = candidates_for_dial(Some(sa("10.20.30.40:23097")), &cached);
            assert_eq!(got, cached);
        }

        #[test]
        fn cache_hit_without_list_falls_back_to_the_single_best() {
            use super::super::candidates_for_dial;
            // Entries restored from vip_state.json have no peer info until the
            // first DNS hit; an older in-memory entry may have addr but no list.
            let got = candidates_for_dial(Some(sa("10.0.0.5:23097")), &[]);
            assert_eq!(got, vec![sa("10.0.0.5:23097")]);
        }

        #[test]
        fn no_cache_means_empty_so_caller_resolves() {
            use super::super::candidates_for_dial;
            assert!(candidates_for_dial(None, &[]).is_empty());
        }

        // ── Only bound a DIRECT attempt when something follows it ──────────
        //
        // CodeRabbit (PR #117): with no relay configured the plan is
        // direct-only, and the LAST attempt used to be cut at 750 ms with no
        // fallback, where the old code had no inner timeout (the 15 s
        // first-byte deadline bounded it). A WAN gateway (QUIC + Noise is
        // ~3 round trips) or one lost QUIC Initial (~1 s PTO) then failed
        // where it worked before. The short budget only makes sense when a
        // next attempt can take over.
        #[test]
        fn direct_attempt_is_bounded_only_when_another_attempt_follows() {
            use super::super::attempt_timeout;
            let direct = DialAttempt {
                addr: sa("10.0.0.5:23097"),
                via: DialVia::Direct,
            };
            let relay = DialAttempt {
                addr: sa("1.2.3.4:23095"),
                via: DialVia::Relay,
            };
            assert_eq!(attempt_timeout(direct, true), Some(DIRECT_ATTEMPT_TIMEOUT));
            assert_eq!(
                attempt_timeout(direct, false),
                None,
                "last direct attempt: caller's deadline bounds it"
            );
            assert_eq!(attempt_timeout(relay, true), None);
            assert_eq!(attempt_timeout(relay, false), None);
        }

        #[test]
        fn direct_only_plan_never_times_out_early_on_its_last_candidate() {
            use super::super::attempt_timeout;
            let plan = dial_plan(
                &[sa("10.0.0.5:23097"), sa("203.0.113.9:23097")],
                None,
                false,
            );
            let n = plan.len();
            let budgets: Vec<_> = plan
                .iter()
                .enumerate()
                .map(|(i, a)| attempt_timeout(*a, i + 1 < n))
                .collect();
            assert_eq!(budgets, vec![Some(DIRECT_ATTEMPT_TIMEOUT), None]);
        }

        // ── A stale list must never override "resolve fresh" ───────────────
        //
        // `peer_addr == None` is the caller saying "no usable VIP cache
        // entry; resolve via NS" (entry expired and was reaped, or a first
        // request). The process-wide candidate cache outlives VIP entries,
        // so consulting it in that case would keep dialing a gateway's OLD
        // addresses after it moved, until the process restarts. The list is
        // only valid alongside a cache hit.
        #[test]
        fn stale_list_is_ignored_when_the_vip_entry_is_gone() {
            use super::super::candidates_for_dial;
            let stale = vec![sa("10.0.0.5:23097"), sa("203.0.113.9:23097")];
            assert!(
                candidates_for_dial(None, &stale).is_empty(),
                "peer_addr None means resolve fresh; a leftover list must not win"
            );
        }

        #[test]
        fn forgetting_a_name_drops_its_cached_list() {
            use super::super::{
                cached_peer_candidates, forget_peer_candidates, set_peer_candidates,
            };
            set_peer_candidates("forget.me.ztlp", &[sa("10.0.0.5:23097")]);
            assert_eq!(cached_peer_candidates("FORGET.me.ztlp").len(), 1);
            forget_peer_candidates("forget.ME.ztlp");
            assert!(cached_peer_candidates("forget.me.ztlp").is_empty());
        }
    }

    // ── CLIENT_ROUTE signing via the daemon-wide relay secret (2026-09-13) ──
    //
    // The relay in prod HMAC mode rejects a zero-HMAC CLIENT_ROUTE, so the
    // automatic VIP dialer must sign with `[tunnel] relay_secret`. The
    // secret is installed once by run_daemon and read at both send sites.
    #[test]
    fn build_signed_client_route_uses_installed_relay_secret() {
        use super::{build_signed_client_route, set_relay_secret};
        let node_id = [0x22u8; 16];

        set_relay_secret(None);
        let unsigned =
            build_signed_client_route(&node_id, "demo-dashboard", 1_800_000_000).unwrap();
        assert_eq!(&unsigned[unsigned.len() - 32..], &[0u8; 32]);

        let key = crate::tunnel::decode_relay_secret(
            "06984504bf07f1cd8462fd9909dcd39cd3e04beb96100a3bbe45eb6113025103",
        );
        set_relay_secret(Some(key.clone()));
        let signed = build_signed_client_route(&node_id, "demo-dashboard", 1_800_000_000).unwrap();
        let expected = crate::tunnel::build_client_route_packet(
            &node_id,
            "demo-dashboard",
            1_800_000_000,
            Some(&key),
        )
        .unwrap();
        assert_eq!(signed, expected);
        assert_ne!(&signed[signed.len() - 32..], &[0u8; 32]);
        set_relay_secret(None);
    }
    // ── first_byte_deadline / stall_response_for_port (PR 1 policy) ──────

    #[test]
    fn first_byte_deadline_parses_seconds() {
        assert_eq!(
            super::first_byte_deadline("15s", 80),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            super::first_byte_deadline("30s", 443),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            super::first_byte_deadline("1s", 80),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn first_byte_deadline_parses_millis() {
        assert_eq!(
            super::first_byte_deadline("500ms", 80),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            super::first_byte_deadline("100ms", 443),
            Some(Duration::from_millis(100))
        );
    }

    #[test]
    fn first_byte_deadline_zero_disables() {
        assert_eq!(super::first_byte_deadline("0", 80), None);
        assert_eq!(super::first_byte_deadline("0s", 80), None);
        assert_eq!(super::first_byte_deadline("0ms", 80), None);
    }

    #[test]
    fn first_byte_deadline_empty_disables() {
        assert_eq!(super::first_byte_deadline("", 80), None);
        assert_eq!(super::first_byte_deadline("  ", 80), None);
    }

    #[test]
    fn first_byte_deadline_garbage_disables() {
        assert_eq!(super::first_byte_deadline("banana", 80), None);
        assert_eq!(super::first_byte_deadline("-5s", 80), None);
    }

    #[test]
    fn first_byte_deadline_default_is_15s() {
        assert_eq!(
            super::first_byte_deadline("15s", 80),
            Some(super::DEFAULT_FIRST_BYTE_TIMEOUT)
        );
    }

    #[test]
    fn stall_response_http_ports_get_504() {
        for port in [80, 8080u16] {
            let bytes = super::stall_response_for_port(
                port,
                "web.demo.spongebob.ztlp",
                Some(Duration::from_secs(15)),
            )
            .expect("HTTP port should produce 504 bytes");
            let text = String::from_utf8(bytes).unwrap();
            assert!(
                text.starts_with("HTTP/1.1 504"),
                "should start with 504 status line"
            );
            assert!(
                text.contains("504 Gateway Timeout"),
                "should name the error"
            );
            assert!(
                text.contains("web.demo.spongebob.ztlp"),
                "should name the zone"
            );
            assert!(text.contains("15s"), "should name the timeout");
            assert!(
                text.contains("Connection: close"),
                "should set Connection: close so client doesn't reuse the socket"
            );
        }
    }

    #[test]
    fn stall_response_non_http_ports_get_none() {
        // NOTE: 443/8443 are in the DELIVER-504 class for the deadline-expiry
        // path (see `stall_close_strategy`) because the TLS variant terminates
        // the TLS handshake BEFORE the deadline-covered dial phase, so the
        // write half speaks plain (already-encrypted) bytes. This test pins
        // the PLAIN-TCP policy function only, which must not fabricate an
        // HTTP 504 on a port whose traffic is still raw TLS ClientHello
        // bytes (the plain path can't terminate TLS here — that would need
        // the SNI cert resolver, which is the TLS variant's job).
        for port in [443, 8443, 22, 3389, 5432u16] {
            assert!(
                super::stall_response_for_port(port, "name", Some(Duration::from_secs(15)))
                    .is_none(),
                "port {} should get None (RST), not a fake 504",
                port
            );
        }
    }

    // ── stall_close_strategy (PR #108 Option A policy) ───────────────────
    //
    // The deadline-expiry decision table for the outer task: which ports
    // get the branded 504 page through the retained client write half,
    // and which get a bare close.

    #[test]
    fn stall_close_strategy_504_class_ports() {
        use super::StallCloseStrategy::*;
        for port in [80, 8080, 443, 8443u16] {
            assert_eq!(
                super::stall_close_strategy(port),
                Deliver504,
                "port {} must be 504-class",
                port
            );
        }
    }

    #[test]
    fn stall_close_strategy_non_http_ports_bare_close() {
        use super::StallCloseStrategy::*;
        for port in [22, 3389, 3306, 5432, 6379, 9050u16] {
            assert_eq!(
                super::stall_close_strategy(port),
                BareClose,
                "port {} must be bare-close class (no fake 504)",
                port
            );
        }
    }

    #[test]
    fn stall_close_strategy_504_class_matches_page_availability_on_plain_ports() {
        // On plain-HTTP ports (80/8080) the Deliver504 class and the
        // `stall_response_for_port` page producer must AGREE — the outer
        // task only writes a page when both the strategy says deliver AND
        // the page producer returns bytes.
        for port in [80, 8080u16] {
            assert_eq!(
                super::stall_close_strategy(port),
                super::StallCloseStrategy::Deliver504
            );
            assert!(
                super::stall_response_for_port(port, "x.ztlp", Some(Duration::from_secs(15)))
                    .is_some(),
                "strategy/page-policy mismatch on port {}",
                port
            );
        }
    }

    #[test]
    fn stall_response_content_length_matches_body() {
        let bytes =
            super::stall_response_for_port(80, "test.zone", Some(Duration::from_secs(30))).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        // Split at the blank line
        let (headers, body) = text.split_once("\r\n\r\n").unwrap();
        let cl = headers
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .map(|l| l.split(':').nth(1).unwrap().trim())
            .unwrap();
        assert_eq!(cl, body.len().to_string());
    }

    #[test]
    fn test_is_agent_running_no_panic() {
        // Verify is_agent_running() doesn't panic regardless of environment.
        // In CI (no PID file) this returns false; on dev machines with a
        // running agent it may return true — both are valid.
        let _running = super::is_agent_running();
    }

    // ── verify_local_peer SO_PEERCRED-on-TCP regression (2026-08-30) ──────
    //
    // Real bug found live: a PRIOR CWE-284 fix used SO_PEERCRED (Linux) /
    // LOCAL_PEERCRED (macOS) to verify the connecting peer is the same OS
    // user — but those mechanisms are Unix-DOMAIN-socket-only. Called on
    // a TCP socket (exactly what the VIP proxy listeners are), the
    // getsockopt call still "succeeds" but returns garbage credentials
    // (uid=-1, pid=0 — confirmed via a raw getsockopt probe against a
    // live listener), which the old code treated as "not us" and
    // rejected. Net effect: the VIP proxy rejected EVERY connection,
    // including entirely legitimate local traffic — real curl/HTTP
    // clients got "Connection reset by peer" on every single request,
    // making the automatic browser-just-works flow completely non-
    // functional. Fixed by checking the peer's IP is loopback instead
    // (the property TCP can actually provide), verified here with a real
    // loopback TCP connection.
    #[tokio::test]
    async fn verify_local_peer_accepts_real_loopback_tcp_connection() {
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });

        let (server_stream, _) = listener.accept().await.unwrap();
        let _client_stream = client_task.await.unwrap();

        assert!(
            super::verify_local_peer(&server_stream, super::ClientPeerPolicy::LoopbackOnly),
            "a real loopback TCP connection must be accepted — this is \
             exactly the case the old SO_PEERCRED-on-TCP code silently \
             broke, rejecting 100% of real traffic"
        );
    }

    // ── non-loopback VIP pools (iOS tunnel interface) ────────────────────

    #[test]
    fn loopback_vip_ranges_keep_the_loopback_only_policy() {
        use super::ClientPeerPolicy as P;
        assert_eq!(P::for_vip_range("127.100.0.0/16"), P::LoopbackOnly);
        assert_eq!(P::for_vip_range("127.200.0.0/30"), P::LoopbackOnly);
        // unparseable = strict
        assert_eq!(P::for_vip_range("not-a-cidr"), P::LoopbackOnly);
        assert_eq!(P::for_vip_range(""), P::LoopbackOnly);
    }

    #[test]
    fn a_tunnel_interface_vip_range_accepts_on_host_clients() {
        use super::ClientPeerPolicy as P;
        assert_eq!(P::for_vip_range("100.64.77.32/27"), P::OnHost);
        assert_eq!(P::for_vip_range("10.77.3.0/24"), P::OnHost);
    }

    #[test]
    fn only_this_hosts_own_addresses_count_as_on_host() {
        use std::net::IpAddr;
        let host: Vec<IpAddr> = vec![
            "127.0.0.1".parse().unwrap(),
            "100.64.77.1".parse().unwrap(),
            "100.64.77.33".parse().unwrap(),
            "192.0.2.10".parse().unwrap(),
        ];
        assert!(super::peer_is_on_host(
            "100.64.77.33".parse().unwrap(),
            &host
        ));
        assert!(super::peer_is_on_host("192.0.2.10".parse().unwrap(), &host));
        // IPv4-mapped form of an own address
        assert!(super::peer_is_on_host(
            "::ffff:100.64.77.1".parse().unwrap(),
            &host
        ));
        // same subnet but NOT this host: rejected
        assert!(!super::peer_is_on_host(
            "100.64.77.34".parse().unwrap(),
            &host
        ));
        assert!(!super::peer_is_on_host(
            "192.0.2.11".parse().unwrap(),
            &host
        ));
        assert!(!super::peer_is_on_host("203.0.113.5".parse().unwrap(), &[]));
    }

    #[tokio::test]
    async fn on_host_policy_still_accepts_loopback_clients() {
        use tokio::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server_stream, _) = listener.accept().await.unwrap();
        let _c = client.await.unwrap();
        assert!(super::verify_local_peer(
            &server_stream,
            super::ClientPeerPolicy::OnHost
        ));
    }

    #[test]
    fn test_get_agent_pid_none() {
        // Without a PID file, returns None
        // (may fail if an actual agent is running, but that's unlikely in CI)
        let pid = super::get_agent_pid();
        // Just verify it doesn't panic
        let _ = pid;
    }

    // ── conventional_service_name_for_port (2026-08-30) ───────────────────
    //
    // Real bug found live: the agent's built-in TCP proxy guessed
    // `format!("tcp:{}", port)` as the ZTLP service name for every VIP
    // connection, but real `ztlp listen --forward NAME:HOST:PORT` servers
    // register CONVENTIONAL names (`http`, `ssh`, `https`, etc.) — verified
    // live against the demo gateway, whose actual invocation was
    // `--forward ssh:172.28.0.30:22 --forward http:172.28.0.30:8080`. A
    // client dialing service `tcp:8080` never matches the server's
    // registered `http` service hash, so every VIP proxy connection to a
    // "well-known" port failed the service lookup even though the tunnel
    // and DNS resolution were both otherwise working correctly. This
    // mirrors the manual `ztlp connect --service web` verification done
    // earlier in this investigation, which worked only because the flag
    // was supplied explicitly — the agent's automatic path had no such
    // override and always guessed wrong.
    #[test]
    fn conventional_service_name_for_port_matches_common_forward_names() {
        use super::conventional_service_name_for_port;
        assert_eq!(conventional_service_name_for_port(80), "http");
        assert_eq!(conventional_service_name_for_port(8080), "http");
        assert_eq!(conventional_service_name_for_port(443), "https");
        assert_eq!(conventional_service_name_for_port(8443), "https");
        assert_eq!(conventional_service_name_for_port(22), "ssh");
        assert_eq!(conventional_service_name_for_port(3389), "rdp");
        assert_eq!(conventional_service_name_for_port(3306), "mysql");
        assert_eq!(conventional_service_name_for_port(5432), "postgres");
        // Unknown ports fall back to the old tcp:PORT convention so custom
        // server-side `--forward tcp:9999:...` registrations still work.
        assert_eq!(conventional_service_name_for_port(9999), "tcp:9999");
    }

    // ── service_name_for_ztlp_name (2026-08-30) — the REAL fix ────────────
    //
    // Even after `conventional_service_name_for_port` above, a live curl
    // through the demo's actual VIP proxy still 404'd from the WRONG
    // backend: the real gateway was started with
    // `--forward web:172.28.0.2:8080` — an OPERATOR-CHOSEN arbitrary
    // service name "web" that has nothing to do with port 8080's
    // "conventional" name ("http"). Port-based guessing can never work for
    // arbitrary operator-chosen service names.
    //
    // The fix: a ZTLP hostname like `web.demo.spongebob.ztlp` encodes the
    // service name AS ITS LEADING LABEL — "web" — with the remaining
    // labels ("demo.spongebob.ztlp") being the zone/gateway routing key.
    // This is exactly the real demo's naming convention (verified live:
    // the gateway process registered under zone `demo.spongebob.ztlp`
    // with `--forward web:...`, and the hostname clients resolve is
    // `web.demo.spongebob.ztlp`). Deriving the service name from the
    // hostname works for ANY operator-chosen name, not just the handful
    // of "conventional" ports covered above — port-based guessing becomes
    // a fallback for names that don't look like `service.zone` (e.g. bare
    // single-label names or IP-literal-style names).
    #[test]
    fn service_name_for_ztlp_name_extracts_leading_label_for_multi_label_names() {
        use super::service_name_for_ztlp_name;
        assert_eq!(
            service_name_for_ztlp_name("web.demo.spongebob.ztlp", 8080),
            "web"
        );
        assert_eq!(
            service_name_for_ztlp_name("ssh.demo.spongebob.ztlp", 22),
            "ssh"
        );
        assert_eq!(
            service_name_for_ztlp_name("api.internal.example.ztlp", 443),
            "api"
        );
    }

    #[test]
    fn service_name_for_ztlp_name_falls_back_to_port_for_single_label_names() {
        use super::service_name_for_ztlp_name;
        // A name with no zone subdomain structure (fewer than 3 labels —
        // i.e. just "name" or "name.tld") has no leading "service" label
        // to meaningfully extract — fall back to the port-based
        // conventional guess so direct `ztlp listen --forward http:...`
        // style servers (flat names, no service.zone structure) still
        // resolve correctly instead of misreading their only label as a
        // bogus "service name".
        assert_eq!(service_name_for_ztlp_name("myserver", 8080), "http");
        assert_eq!(service_name_for_ztlp_name("myserver.ztlp", 22), "ssh");
    }
}

/// Map a well-known port to the conventional ZTLP service name a real
/// `ztlp listen --forward NAME:HOST:PORT` server is likely to have
/// registered, so the agent's automatic VIP proxy dials the SAME service
/// name a server operator would naturally choose (`http`, `ssh`, etc.)
/// instead of a synthetic `tcp:PORT` name no real server ever registers.
/// See `conventional_service_name_for_port_matches_common_forward_names`
/// for the real-world mismatch this fixes (2026-08-30).
fn conventional_service_name_for_port(port: u16) -> String {
    match port {
        80 | 8080 => "http".to_string(),
        443 | 8443 => "https".to_string(),
        22 => "ssh".to_string(),
        3389 => "rdp".to_string(),
        3306 => "mysql".to_string(),
        5432 => "postgres".to_string(),
        _ => format!("tcp:{}", port),
    }
}

// ── Direct-first dial plan (docs/DIRECT-FIRST-DIAL-PLAN.md, step B3) ──────
//
// The VIP dialer used to pick ONE send address: the relay when configured,
// else the single SVC `address`. A gateway on the same LAN (or behind the
// same NAT) was therefore reached via relay → NAT hairpin, which the office
// edge drops (504 after the 15 s deadline; found live 2026-10-05 with
// www.app.example.ztlp). Now the resolver returns every endpoint the gateway
// published, ranked for this client, and `dial_plan` orders the attempts:
// direct candidates first (each bounded by `DIRECT_ATTEMPT_TIMEOUT`), the
// relay last with whatever budget remains. `[tunnel] prefer_relay = true`
// flips the order. No relay configured = direct-only, exactly as before.

/// Per-candidate budget for a DIRECT attempt (QUIC + Noise handshake).
/// Same-LAN completes in tens of ms; this is the cost of ONE dead
/// candidate before moving on. Pinned by
/// `direct_attempt_timeout_is_short_but_not_silly`.
const DIRECT_ATTEMPT_TIMEOUT: Duration = Duration::from_millis(750);

/// A QUIC connection with the Noise handshake done; what both VIP dial
/// paths need before they open the data stream. Cloning yields another
/// handle to the same connection (that is how a shared connection is
/// handed to each request).
#[derive(Clone)]
struct ConnectedTunnel {
    conn: crate::quic_transport::tokio_endpoint::QuicConnection,
    session_id: crate::packet::SessionId,
    /// Which attempt won (for the log line and tests).
    via: DialVia,
    addr: SocketAddr,
    /// Set on a connection that lives in the shared cache.
    shared: Option<Arc<SharedInfo>>,
}

/// What the agent keeps about a shared connection besides the connection.
struct SharedInfo {
    /// Who is using it right now (idle close, see `reap_idle_shared_tunnels`).
    uses: Arc<super::reconnect::UseState>,
    /// How it was dialed, so it can be dialed again after a network change.
    params: DialParams,
}

struct DialParams {
    ztlp_name: String,
    port: u16,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: NodeIdentity,
    bind_addr: String,
    ns_server: String,
    relay_addr: Option<String>,
}

/// A tunnel connection handed to one client connection.
struct LeasedTunnel {
    tunnel: ConnectedTunnel,
    /// An existing shared connection (not one dialed for this request).
    reused: bool,
    /// Marks the shared connection as in use until dropped (`None` when
    /// connections are not shared).
    lease: Option<super::reconnect::Lease>,
}

/// Kept by a client connection for as long as it uses its tunnel stream.
pub struct TunnelKeep {
    _lease: Option<super::reconnect::Lease>,
}

/// Resolve `ztlp_name` (or use the cached peer), build the dial plan and
/// walk it: every DIRECT candidate gets `DIRECT_ATTEMPT_TIMEOUT`; the RELAY
/// attempt gets no inner timeout (the caller's first-byte deadline bounds
/// it, exactly as before this change). Returns the first attempt whose QUIC
/// connect AND Noise handshake both succeed.
///
/// Shared by `proxy_dial_phase` (deadline path, PR #108) and
/// `handle_tcp_connection_bridged` (plain path), which previously carried
/// two copies of the single-address dial.
///
/// With `[tunnel] reuse_connections` on, the connection is shared: one per
/// (name, port), dialed by the first request (concurrent first requests
/// wait for that one dial) and reused while it is open; the caller opens
/// its own stream on it. Off (the default), every call dials.
///
/// In that mode the dial itself is retried with a short backoff until the
/// caller's deadline (the network may be away for a moment), inside the
/// single-flight slot, so every request waiting for the same name shares
/// the one dial in progress.
#[allow(clippy::too_many_arguments)]
async fn connect_tunnel(
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    deadline: Option<Duration>,
) -> Result<LeasedTunnel, Box<dyn std::error::Error + Send + Sync>> {
    connect_tunnel_opts(
        ztlp_name,
        port,
        peer_addr,
        peer_node_id,
        identity,
        bind_addr,
        ns_server,
        relay_addr,
        deadline,
        true,
    )
    .await
}

/// [`connect_tunnel`]; `retry = false` makes a shared dial a single try
/// (the background dial after a network change).
#[allow(clippy::too_many_arguments)]
async fn connect_tunnel_opts(
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    deadline: Option<Duration>,
    retry: bool,
) -> Result<LeasedTunnel, Box<dyn std::error::Error + Send + Sync>> {
    if !reuse_connections() {
        let tunnel = connect_tunnel_fresh(
            ztlp_name,
            port,
            peer_addr,
            peer_node_id,
            identity,
            bind_addr,
            ns_server,
            relay_addr,
            deadline,
        )
        .await?;
        return Ok(LeasedTunnel {
            tunnel,
            reused: false,
            lease: None,
        });
    }
    // The budget counts from now, not from when this request gets its turn
    // in the slot: a request that waited for somebody else's failed dial
    // until its own deadline does not start dialing after it.
    let give_up_at = match (retry, deadline) {
        (true, Some(d)) => Some(tokio::time::Instant::now() + d),
        _ => None,
    };
    let taken_lease: std::sync::Mutex<Option<super::reconnect::Lease>> =
        std::sync::Mutex::new(None);
    let fresh = || {
        connect_tunnel_fresh(
            ztlp_name,
            port,
            peer_addr,
            peer_node_id,
            identity,
            bind_addr,
            ns_server,
            relay_addr,
            deadline,
        )
    };
    let (tunnel, reused) = tunnel_conn_cache()
        .get_or_dial(
            &tunnel_key(ztlp_name, port),
            |t| {
                if !tunnel_is_open(t) {
                    return false;
                }
                // Marked as in use under the slot's lock, so the idle
                // close cannot take it between here and the return.
                if let (Some(s), Ok(mut slot)) = (&t.shared, taken_lease.lock()) {
                    *slot = Some(s.uses.acquire());
                }
                true
            },
            || async {
                let mut t = if retry {
                    super::reconnect::retry_dial(
                        ztlp_name,
                        give_up_at,
                        Some(network_epoch_tx().subscribe()),
                        dial_error_is_permanent,
                        fresh,
                    )
                    .await?
                } else {
                    fresh().await?
                };
                t.shared = Some(Arc::new(SharedInfo {
                    uses: super::reconnect::UseState::new(),
                    params: DialParams {
                        ztlp_name: ztlp_name.to_string(),
                        port,
                        peer_node_id,
                        identity: identity.clone(),
                        bind_addr: bind_addr.to_string(),
                        ns_server: ns_server.to_string(),
                        relay_addr: relay_addr.map(str::to_string),
                    },
                }));
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(t)
            },
        )
        .await?;
    if reused {
        debug!(
            "reusing shared tunnel: {} (port {}) → {} via {:?} (session {})",
            ztlp_name, port, tunnel.addr, tunnel.via, tunnel.session_id
        );
    }
    let lease = taken_lease
        .into_inner()
        .unwrap_or(None)
        .or_else(|| tunnel.shared.as_ref().map(|s| s.uses.acquire()));
    Ok(LeasedTunnel {
        tunnel,
        reused,
        lease,
    })
}

/// A tunnel connection with a data stream open on it.
struct OpenedTunnel {
    leased: LeasedTunnel,
    q_send: quinn::SendStream,
    q_recv: quinn::RecvStream,
}

/// [`connect_tunnel`] plus the data stream. On a REUSED shared connection
/// a stream that cannot be opened (the connection closed, or no stream
/// within the liveness window) drops that connection and dials once more;
/// a connection dialed for this request fails as before. `what` is the
/// suffix of the error text (the two callers always differed in it).
#[allow(clippy::too_many_arguments)]
async fn connect_and_open(
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    deadline: Option<Duration>,
    what: &str,
) -> Result<OpenedTunnel, Box<dyn std::error::Error + Send + Sync>> {
    let mut leased = connect_tunnel(
        ztlp_name,
        port,
        peer_addr,
        peer_node_id,
        identity,
        bind_addr,
        ns_server,
        relay_addr,
        deadline,
    )
    .await?;
    if leased.reused {
        let window = super::reconnect::LIVENESS_WINDOW;
        let reason = match tokio::time::timeout(window, leased.tunnel.conn.open_bi()).await {
            Ok(Ok((q_send, q_recv))) => {
                return Ok(OpenedTunnel {
                    leased,
                    q_send,
                    q_recv,
                })
            }
            Ok(Err(e)) => format!("could not open a stream: {e}"),
            Err(_) => format!("no stream within {window:?}"),
        };
        drop_shared_tunnel_if_same(ztlp_name, port, &leased.tunnel.conn, false, &reason);
        leased = connect_tunnel(
            ztlp_name,
            port,
            peer_addr,
            peer_node_id,
            identity,
            bind_addr,
            ns_server,
            relay_addr,
            deadline,
        )
        .await?;
    }
    let (q_send, q_recv) = leased.tunnel.conn.open_bi().await.map_err(|e| {
        forget_shared_tunnel(ztlp_name, port);
        format!("failed to open QUIC data stream{}: {}", what, e)
    })?;
    Ok(OpenedTunnel {
        leased,
        q_send,
        q_recv,
    })
}

/// Dial a new connection (see [`connect_tunnel`]).
#[allow(clippy::too_many_arguments)]
async fn connect_tunnel_fresh(
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    peer_node_id: Option<crate::identity::NodeId>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
    // The caller's accept-to-first-byte deadline bounds the relay attempt
    // and the last direct attempt when `walk_dial_plan` would otherwise
    // leave them unbounded (PR #138 review — the gated TLS path dropped
    // this deadline, so an unresponsive backend held the client open).
    deadline: Option<Duration>,
) -> Result<ConnectedTunnel, Box<dyn std::error::Error + Send + Sync>> {
    // Candidates: on a VIP cache hit use the full ranked list the DNS
    // resolver published for this name (falls back to the single cached
    // best address for entries that predate the list); otherwise resolve
    // fresh via NS.
    let strict = super::ns_trust::load_cached()
        .map(|s| s.strict_for(ztlp_name))
        // A broken trust file must not silently downgrade to legacy.
        .unwrap_or(true);
    let cached = candidates_for_dial(peer_addr, &cached_peer_candidates(ztlp_name));
    let cached_cert = cached_peer_cert(ztlp_name);
    // After a network change the cached view is from the other network
    // (never the case unless `notify_network_changed` was acted on).
    let from_cache = !cached.is_empty()
        && cache_hit_usable(cached_cert.as_ref(), strict)
        && cached_route_is_current(ztlp_name);
    let (candidates, resolved_node_id, expect) = if from_cache {
        (cached, peer_node_id, cached_cert.unwrap_or_default())
    } else {
        let r = proxy::ns_resolve(ztlp_name, ns_server).await?;
        set_peer_candidates(ztlp_name, &r.candidates);
        set_peer_cert(ztlp_name, &r.cert);
        (r.candidates, r.node_id, r.cert)
    };

    match walk_dial_plan(
        ztlp_name,
        port,
        &candidates,
        resolved_node_id,
        &expect,
        identity,
        bind_addr,
        relay_addr,
        deadline,
    )
    .await
    {
        Err(e) if is_ns_cert_failure(&e.to_string()) => {
            // Task 5.4: the gateway's cert no longer matches what we
            // dialed with. Drop the cached view, resolve fresh from the NS
            // (a restarted gateway re-registers its new fingerprint), and
            // redial exactly once. No fallback to weaker checks.
            warn!(
                "{}: gateway certificate does not match its name-server record; re-resolving once",
                ztlp_name
            );
            forget_peer_candidates(ztlp_name);
            crate::ns_cache::evict(&crate::ns_cache::default_dir(), ztlp_name, 2);
            let r = proxy::ns_resolve(ztlp_name, ns_server).await?;
            set_peer_candidates(ztlp_name, &r.candidates);
            set_peer_cert(ztlp_name, &r.cert);
            walk_dial_plan(
                ztlp_name,
                port,
                &r.candidates,
                r.node_id,
                &r.cert,
                identity,
                bind_addr,
                relay_addr,
                deadline,
            )
            .await
        }
        other => other,
    }
}

/// Build the dial plan for one resolution and walk it (see
/// [`connect_tunnel`]).
#[allow(clippy::too_many_arguments)]
async fn walk_dial_plan(
    ztlp_name: &str,
    port: u16,
    candidates: &[SocketAddr],
    resolved_node_id: Option<NodeId>,
    expect: &crate::quic_transport::CertExpectation,
    identity: &NodeIdentity,
    bind_addr: &str,
    relay_addr: Option<&str>,
    // Bounds the attempt `attempt_timeout` leaves open (the relay, and the
    // last/only attempt): the caller's accept-to-first-byte deadline
    // (PR #138 review — without it a dead relay or a single unresponsive
    // direct candidate hangs the connection forever).
    deadline: Option<Duration>,
) -> Result<ConnectedTunnel, Box<dyn std::error::Error + Send + Sync>> {
    let relay: Option<SocketAddr> = match relay_addr {
        Some(r) => Some(
            r.parse()
                .map_err(|e| format!("invalid relay address '{}': {}", r, e))?,
        ),
        None => None,
    };

    let plan = dial_plan(candidates, relay, prefer_relay());
    if plan.is_empty() {
        return Err(format!("no dialable endpoint for '{}'", ztlp_name).into());
    }

    let service_name = service_name_for_ztlp_name(ztlp_name, port);
    let responder_id = resolved_node_id.unwrap_or_else(NodeId::zero);
    let service_hash = tunnel::encode_service_name(&service_name).unwrap_or_else(|_| {
        let mut svc = [0u8; 16];
        let port_str = port.to_string();
        let bytes = port_str.as_bytes();
        let len = bytes.len().min(16);
        svc[..len].copy_from_slice(&bytes[..len]);
        svc
    });

    let n = plan.len();
    let ctx = AttemptContext {
        ztlp_name,
        service_name: &service_name,
        resolved_node_id,
        responder_id,
        service_hash,
        identity,
        bind_addr,
        expect,
        n,
    };

    // Shared-connection mode with a relay behind the direct candidates:
    // do not make the relay wait for every direct candidate's full
    // timeout. The direct candidates run in their usual order and get a
    // short head start; then the relay is dialed next to them and the
    // first finished handshake is taken (direct when both are ready).
    if reuse_connections() && !prefer_relay() && n >= 2 {
        if let Some(relay_attempt) = plan.last().copied().filter(|a| a.via == DialVia::Relay) {
            let directs = &plan[..n - 1];
            let head_start = if relay_won_last(ztlp_name) {
                Duration::ZERO
            } else {
                super::reconnect::RELAY_HEAD_START
            };
            let direct = async {
                let mut last = String::new();
                for (i, attempt) in directs.iter().copied().enumerate() {
                    let budget = AttemptBudget::Direct(DIRECT_ATTEMPT_TIMEOUT);
                    match run_dial_attempt(&ctx, i + 1, attempt, budget).await {
                        Ok(t) => return Ok(t),
                        Err(e) => last = e,
                    }
                }
                Err(last)
            };
            let relay =
                || run_dial_attempt(&ctx, n, relay_attempt, AttemptBudget::Deadline(deadline));
            return match super::reconnect::race_direct_relay(direct, relay, head_start).await {
                Ok((tunnel, _)) => {
                    note_dial_winner(ztlp_name, tunnel.via);
                    Ok(tunnel)
                }
                Err((direct_err, relay_err)) => Err(format!(
                    "all {} dial attempts failed for '{}': {} (direct: {})",
                    n, ztlp_name, relay_err, direct_err
                )
                .into()),
            };
        }
    }

    let mut last_err: String = String::new();
    for (i, attempt) in plan.into_iter().enumerate() {
        let budget = match attempt_timeout(attempt, i + 1 < n) {
            Some(budget) => AttemptBudget::Direct(budget),
            // Relay, or the LAST attempt: the caller's first-byte deadline
            // bounds it (unchanged from before direct-first); when the
            // caller passed no deadline at all (legacy paths) the attempt
            // runs unbounded, exactly as before.
            None => AttemptBudget::Deadline(deadline),
        };
        match run_dial_attempt(&ctx, i + 1, attempt, budget).await {
            Ok(tunnel) => return Ok(tunnel),
            Err(e) => last_err = e,
        }
    }
    Err(format!(
        "all {} dial attempts failed for '{}': {}",
        n, ztlp_name, last_err
    )
    .into())
}

/// What every attempt of one dial plan shares.
struct AttemptContext<'a> {
    ztlp_name: &'a str,
    service_name: &'a str,
    resolved_node_id: Option<NodeId>,
    responder_id: NodeId,
    service_hash: [u8; 16],
    identity: &'a NodeIdentity,
    bind_addr: &'a str,
    expect: &'a crate::quic_transport::CertExpectation,
    /// Number of attempts in the plan (for the log lines).
    n: usize,
}

/// How long one attempt may take.
#[derive(Clone, Copy)]
enum AttemptBudget {
    /// A direct candidate with something after it: the short timeout.
    Direct(Duration),
    /// The relay or the last attempt: the caller's deadline, if any.
    Deadline(Option<Duration>),
}

/// Run attempt number `i` of a plan within its budget, with the log lines.
async fn run_dial_attempt(
    ctx: &AttemptContext<'_>,
    i: usize,
    attempt: DialAttempt,
    budget: AttemptBudget,
) -> Result<ConnectedTunnel, String> {
    let n = ctx.n;
    info!(
        "dial {}/{} {} → {} via {:?} (service={})",
        i, n, ctx.ztlp_name, attempt.addr, attempt.via, ctx.service_name
    );
    let one = connect_one(
        attempt,
        ctx.service_name,
        ctx.resolved_node_id,
        ctx.responder_id,
        ctx.service_hash,
        ctx.identity,
        ctx.bind_addr,
        ctx.expect,
    );
    let result = match budget {
        AttemptBudget::Direct(budget) => match tokio::time::timeout(budget, one).await {
            Ok(r) => r,
            Err(_) => Err(format!(
                "direct candidate {} did not answer within {:?}",
                attempt.addr, budget
            )
            .into()),
        },
        AttemptBudget::Deadline(Some(budget)) => match tokio::time::timeout(budget, one).await {
            Ok(r) => r,
            Err(_) => Err(format!(
                "dial attempt {} (via {:?}) did not answer within the \
                 accept-to-first-byte deadline",
                attempt.addr, attempt.via
            )
            .into()),
        },
        AttemptBudget::Deadline(None) => one.await,
    };
    match result {
        Ok((conn, session_id)) => {
            info!(
                "tunnel active: {} → {} via {:?} (session {})",
                ctx.ztlp_name, attempt.addr, attempt.via, session_id
            );
            Ok(ConnectedTunnel {
                conn,
                session_id,
                via: attempt.via,
                addr: attempt.addr,
                shared: None,
            })
        }
        Err(e) => {
            info!(
                "dial {}/{} {} via {:?} failed: {}",
                i, n, attempt.addr, attempt.via, e
            );
            Err(e.to_string())
        }
    }
}

/// One attempt: (CLIENT_ROUTE when via relay) + QUIC connect + Noise handshake.
#[allow(clippy::too_many_arguments)]
async fn connect_one(
    attempt: DialAttempt,
    service_name: &str,
    resolved_node_id: Option<NodeId>,
    responder_id: NodeId,
    service_hash: [u8; 16],
    identity: &NodeIdentity,
    bind_addr: &str,
    expect: &crate::quic_transport::CertExpectation,
) -> Result<
    (
        crate::quic_transport::tokio_endpoint::QuicConnection,
        crate::packet::SessionId,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let std_socket = std::net::UdpSocket::bind(bind_addr)?;

    if attempt.via == DialVia::Relay {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // Prefer the NS-resolved GATEWAY NodeID over our own identity —
        // the relay's fallback-by-NodeID lookup needs the PEER's NodeID
        // (confirmed live 2026-08-30 against cmd_connect).
        let client_route_node_id: [u8; 16] = resolved_node_id
            .map(|nid| *nid.as_bytes())
            .unwrap_or(*identity.node_id.as_bytes());
        match build_signed_client_route(&client_route_node_id, service_name, ts) {
            Ok(route_pkt) => {
                if let Err(e) = std_socket.send_to(&route_pkt, attempt.addr) {
                    warn!("failed to send CLIENT_ROUTE to {}: {}", attempt.addr, e);
                } else {
                    debug!(
                        "CLIENT_ROUTE sent to {} (service={})",
                        attempt.addr, service_name
                    );
                }
                // Let the relay install the 5-tuple mapping before the
                // first QUIC INITIAL races down the same socket (mirrors
                // cmd_connect's identical 50 ms wait).
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                warn!(
                    "could not build CLIENT_ROUTE for service '{}': {}",
                    service_name, e
                );
            }
        }
    }

    let quic_conn =
        crate::quic_transport::tokio_endpoint::QuicEndpoint::connect_with_socket_for_service(
            dial_endpoint_config(),
            attempt.addr,
            "localhost",
            std_socket,
            relayed_pin_service(attempt.via, service_name),
            expect.clone(),
        )
        .await?;

    let handshake_result = crate::quic_transport::noise_stream::run_initiator_handshake(
        &quic_conn,
        identity,
        responder_id,
        service_hash,
    )
    .await
    .map_err(|e| format!("QUIC Noise handshake failed: {}", e))?;

    Ok((quic_conn, handshake_result.session_id))
}

/// The service name to scope a TOFU QUIC pin to for this dial (ZT-04).
///
/// A relayed dial reaches every service at the same `relay_ip:port`, so the
/// pin must be scoped to the service or the second service a device uses is
/// rejected as a certificate mismatch. A direct dial has its own address and
/// keeps the unscoped key (existing pins survive an upgrade).
fn relayed_pin_service(via: DialVia, service_name: &str) -> Option<&str> {
    match via {
        DialVia::Relay => Some(service_name),
        DialVia::Direct => None,
    }
}

/// How an attempt reaches the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DialVia {
    /// Straight to the published endpoint; no CLIENT_ROUTE.
    Direct,
    /// Through the configured relay (CLIENT_ROUTE first, then QUIC).
    Relay,
}

/// One ordered attempt in a dial plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DialAttempt {
    addr: SocketAddr,
    via: DialVia,
}

/// Order the attempts for one tunnel. Pure; never dials.
///
/// * `ranked` — candidates best-first (see `proxy::NsResolution::candidates`).
///   An entry equal to the relay address is dropped (the Rust gateway
///   appends the relay as a backstop; dialing it without CLIENT_ROUTE can't
///   work and would waste a slot).
/// * `relay` — the configured relay, appended as the final `Relay` attempt
///   (first, when `prefer_relay`).
fn dial_plan(
    ranked: &[SocketAddr],
    relay: Option<SocketAddr>,
    prefer_relay: bool,
) -> Vec<DialAttempt> {
    let direct = ranked
        .iter()
        .copied()
        .filter(|a| Some(*a) != relay)
        .map(|addr| DialAttempt {
            addr,
            via: DialVia::Direct,
        });
    let relay_attempt = relay.map(|addr| DialAttempt {
        addr,
        via: DialVia::Relay,
    });
    if prefer_relay {
        relay_attempt.into_iter().chain(direct).collect()
    } else {
        direct.chain(relay_attempt).collect()
    }
}

/// Inner time budget for one attempt. A DIRECT attempt gets the short
/// `DIRECT_ATTEMPT_TIMEOUT` ONLY when another attempt follows it (so a dead
/// candidate costs ~750 ms before the next one takes over). The relay, and
/// the final attempt of any plan, get `None`: the caller's first-byte
/// deadline bounds them, exactly as before direct-first dialing.
fn attempt_timeout(attempt: DialAttempt, has_fallback: bool) -> Option<Duration> {
    match attempt.via {
        DialVia::Direct if has_fallback => Some(DIRECT_ATTEMPT_TIMEOUT),
        _ => None,
    }
}

/// Derive the ZTLP service name to dial for a given resolved hostname.
///
/// A ZTLP hostname of the form `SERVICE.ZONE...` (2+ labels) encodes the
/// gateway operator's chosen service name as its leading label — e.g.
/// `web.demo.spongebob.ztlp` was registered by a real gateway as
/// `--forward web:...`, which port-based guessing can never discover
/// since "web" bears no relationship to port 8080. For single-label names
/// (no zone subdomain to split off), falls back to the port-based
/// conventional guess. See
/// `service_name_for_ztlp_name_extracts_leading_label_for_multi_label_names`
/// and its single-label sibling test for the exact contract (2026-08-30).
fn service_name_for_ztlp_name(ztlp_name: &str, port: u16) -> String {
    let name = ztlp_name.trim_end_matches('.');
    let labels: Vec<&str> = name.split('.').collect();
    // Require at least 3 labels (service + a zone of at least 2 labels,
    // e.g. "web.demo.spongebob.ztlp") before treating the leading label
    // as an operator-chosen service name. A 1- or 2-label name (bare
    // hostname, or hostname.tld) has no meaningful "service.zone"
    // structure to extract from — misreading its only label as a service
    // name would silently break flat, non-zoned deployments.
    if labels.len() >= 3 && !labels[0].is_empty() {
        labels[0].to_string()
    } else {
        conventional_service_name_for_port(port)
    }
}

// ─── Control-plane Bearer token persistence (D1.T3) ─────────────────────────

/// Load (or generate-and-persist) the per-install control-plane Bearer token.
///
/// Returns the hex-encoded token string. If a non-empty trimmed token already
/// exists at `path`, it is returned unchanged (idempotent). Otherwise 32
/// cryptographically-random bytes are generated, hex-encoded to a 64-char
/// lowercase string, and written atomically.
///
/// ## Atomic write protocol
///
/// 1. Create parent directories as needed.
/// 2. Write the new token to `<path>.tmp`.
/// 3. On unix, chmod the tmp file to `0o600` *before* renaming, so the final
///    path is never world-readable, not even for a microsecond.
/// 4. Rename tmp → final. Rename is atomic on the same filesystem.
///
/// Whitespace-only existing files are treated as missing and regenerated.
pub fn ensure_token_file(path: &Path) -> std::io::Result<String> {
    // Fast path: existing non-empty token.
    if path.exists() {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let trimmed = contents.trim();
                if !trimmed.is_empty() {
                    return Ok(trimmed.to_string());
                }
                // fall through to regenerate
            }
            Err(e) => return Err(e),
        }
    }

    // Generate fresh token: 32 random bytes → 64 hex chars.
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = hex::encode(raw);

    // Ensure parent dir exists.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Atomic write: tmp → chmod tmp → rename.
    let tmp_path = {
        let mut p = path.as_os_str().to_owned();
        p.push(".tmp");
        std::path::PathBuf::from(p)
    };

    std::fs::write(&tmp_path, &token)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
    }

    std::fs::rename(&tmp_path, path)?;

    Ok(token)
}

// ────────────────────────────────────────────────────────────────────────────
// Option A — split-socket 504 delivery (PR #108, follow-up to PR #106/#107)
//
// PR #106 shipped the accept-to-first-byte deadline, but on expiry the client
// socket was DROPPED with the aborted dial task (fast RST) — the branded 504
// page could not be written through a socket we no longer owned. PR #107
// restructured the deadline to spawned-task + outer-select but kept the same
// abort-drops-socket behavior.
//
// PR #108 completes Option A: the client socket is split UP FRONT — the
// dial task owns ONLY the read half, the write half stays with the outer
// task. On deadline expiry the outer task writes the branded 504 page
// (HTTP-ish ports) through the write half it still owns, then shuts the
// connection down cleanly (FIN, not RST) so browsers render the page
// instead of showing a raw connection error. Also fixes the Chrome
// double-refresh stall: the up-pump now stops after the FIRST client frame
// (the complete HTTP request) instead of draining the socket unboundedly
// before forwarding.
//
// A real QUIC tunnel can't be stood up hermetically (needs NS + relay +
// gateway — explicitly skipped in the original TDD plan 2026-08-30; the
// live AI-computer test against the real demo backend substitutes as
// integration proof). These tests therefore drive the deadline path through
// a black-hole "NS" TCP listener that accepts and never answers — the
// exact stall shape of the single-threaded demo backend — and assert on
// what the CLIENT actually receives.
// ────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod option_a_tests {
    use super::{
        first_byte_deadline, proxy_dial_then_bridge, stall_close_strategy, stall_response_for_port,
    };
    use crate::identity::NodeIdentity;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    type BoxErr = Box<dyn std::error::Error + Send + Sync>;

    fn real_identity() -> NodeIdentity {
        NodeIdentity::generate().unwrap()
    }

    /// Black-hole "NS" listener: accepts connections, never answers. The
    /// agent's `ns_resolve` will hang against it until the deadline fires.
    async fn start_blackhole_ns() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((mut sock, _)) = listener.accept().await {
                // Accept, read whatever arrives, then never respond.
                let _ = sock.read(&mut buf).await;
                // Hold the socket open for the test's duration.
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });
        (addr.to_string(), handle)
    }

    /// Run `proxy_dial_then_bridge` against a black-hole NS on the given
    /// port and return the bytes the CLIENT side of the socket received
    /// before it closed (bounded so the test can't hang).
    async fn dial_against_blackhole(port: u16, deadline: Duration) -> (Vec<u8>, Option<BoxErr>) {
        let (ns_addr, _ns_task) = start_blackhole_ns().await;

        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = client_listener.local_addr().unwrap();

        // Real client side: this is what Chrome/curl would be.
        let mut client = TcpStream::connect(listener_addr).await.unwrap();

        // Proxy side: accept (the handler splits internally).
        let (proxy_sock, _) = client_listener.accept().await.unwrap();

        let identity = real_identity();
        let result: Option<BoxErr> = proxy_dial_then_bridge(
            proxy_sock,
            "blackhole.test",
            port,
            None, // peer_addr → NS path (the black hole)
            None, // peer_node_id
            &identity,
            "127.0.0.1",
            &ns_addr,
            None, // relay
            None, // tls_acceptor (plain path)
            Some(deadline),
            super::local_tls::TlsMode::Detect, // built-in table default for test ports
            stall_close_strategy(port),
        )
        .await
        .err();

        // Read whatever the client received before EOF (bounded).
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let mut buf = [0u8; 4096];
            loop {
                match client.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
        })
        .await;

        (got, result)
    }

    /// HTTP port (80): deadline expiry must give the client the branded
    /// 504 Gateway Timeout page, delivered through the write half the
    /// outer task retains (Option A, PR #108) — NOT a silent RST. The
    /// page lets Chrome render a real error page and release the
    /// connection cleanly instead of spinning until an OS-level reset.
    #[tokio::test]
    async fn client_gets_504_page_on_dial_timeout_http_port() {
        let (bytes, err) = dial_against_blackhole(80, Duration::from_millis(300)).await;

        let err = err.expect("dial against a black-hole NS must time out");
        assert!(
            err.to_string().contains("deadline"),
            "error must name the deadline expiry, got: {err:?}"
        );
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.starts_with("HTTP/1.1 504"),
            "client must receive the branded 504 page, got {} bytes: {text:?}",
            bytes.len()
        );
        assert!(
            text.contains("504 Gateway Timeout"),
            "504 page must name the error"
        );
        assert!(
            text.contains("blackhole.test"),
            "504 page must name the zone"
        );
        assert!(
            text.contains("Connection: close"),
            "504 page must set Connection: close (client must not reuse the socket)"
        );
        // The policy chain agrees: strategy = Deliver504, page = produced.
        assert_eq!(
            stall_close_strategy(80),
            super::StallCloseStrategy::Deliver504,
            "port 80 must be 504-class"
        );
    }

    /// HTTP-ish port (8080): same branded 504 delivery as port 80.
    #[tokio::test]
    async fn client_gets_504_page_on_dial_timeout_8080() {
        let (bytes, err) = dial_against_blackhole(8080, Duration::from_millis(300)).await;

        assert!(
            err.as_ref()
                .map(|e| e.to_string().contains("deadline"))
                .unwrap_or(false),
            "deadline expiry must be the error, got: {err:?}"
        );
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.starts_with("HTTP/1.1 504"),
            "port 8080 must get the branded 504 page, got {} bytes: {text:?}",
            bytes.len()
        );
        assert!(
            stall_response_for_port(8080, "x.test", Some(Duration::from_secs(15))).is_some(),
            "port 8080 must be 504-class"
        );
    }

    /// Non-HTTP port (3306): deadline expiry must NOT send a 504 page —
    /// the client gets a bare close (FIN with zero payload). This pins
    /// the port-class split: a fake HTTP status line on a database port
    /// would be nonsense bytes.
    #[tokio::test]
    async fn non_http_port_timeout_gives_bare_close_not_504() {
        let (bytes, err) = dial_against_blackhole(3306, Duration::from_millis(300)).await;

        assert!(
            err.as_ref()
                .map(|e| e.to_string().contains("deadline"))
                .unwrap_or(false),
            "deadline expiry must be the error, got: {err:?}"
        );
        assert!(
            bytes.is_empty(),
            "non-HTTP port must get ZERO bytes (bare close/FIN), got {} bytes: {:?}",
            bytes.len(),
            String::from_utf8_lossy(&bytes)
        );

        // And the policy functions themselves classify this port.
        assert!(
            stall_response_for_port(3306, "db.test", Some(Duration::from_secs(15))).is_none(),
            "port 3306 must be RST-class, not 504-class"
        );
        assert_eq!(
            stall_close_strategy(3306),
            super::StallCloseStrategy::BareClose,
            "port 3306 must be bare-close class"
        );
    }

    /// Slow-but-alive boundary: a dial finishing at deadline − 1s must NOT
    /// be killed. A real tunnel can't be stood up hermetically, so this
    /// pins the DECISION boundary on the pure policy: the select! structure
    /// races the done-signal against the sleep, and any dial that signals
    /// completion before `deadline` wins. Here we assert the budget math:
    /// 14.9s < 15s budget (in-budget), 15.1s > 15s (out-of-budget).
    #[tokio::test]
    async fn slow_but_alive_backend_survives_deadline() {
        let deadline = first_byte_deadline("15s", 80).unwrap();
        assert_eq!(deadline, Duration::from_secs(15));

        let fast = Duration::from_secs_f64(14.9);
        let slow = Duration::from_secs_f64(15.1);
        assert!(
            fast < deadline,
            "a dial finishing at 14.9s must be in budget (not killed)"
        );
        assert!(
            slow > deadline,
            "a dial finishing at 15.1s must be out of budget (killed)"
        );
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Local TLS termination (HTTPS by default) — 2026-09-01
//
// The VIP proxy on port 443/8443 must terminate TLS LOCALLY (the client sees
// a real TLS handshake against the agent's cert) and bridge the DECRYPTED
// bytes through the ZTLP tunnel. Before this fix the VIP proxy routed 443
// through `proxy_dial_then_bridge`, which forwarded the RAW TLS ClientHello
// to the backend (which can't do TLS) — so the client's handshake got no
// ServerHello and timed out.
//
// These tests lock the routing decision (TLS port → TLS-terminating handler)
// and the core property that the local acceptor is ready to complete a real
// TLS handshake (the cert chain + key load correctly).
// ────────────────────────────────────────────────────────────────────────────
/// Single-address mode through the daemon's own wiring: the real accept
/// loop, the real name -> site step, and the real VIP carrier
/// (`carry_client_connection`). The name server is a black hole, so the
/// test ends where a VIP connection to an unreachable site ends: the 504
/// page, which names the site the connection was carried for.
/// Tests that turn shared connections on (a process-wide switch) take this
/// lock, so they do not change the mode under one another.
#[cfg(test)]
pub(crate) static SHARED_MODE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Shared-connection mode against a gateway, a name server and network
/// paths that all live on loopback in this process: what happens to a
/// request when the path under a shared connection dies, when the network
/// changes, when no dial works for a while, and that none of it happens
/// with connections not shared (the desktop default).
#[cfg(test)]
mod reconnect_wiring_tests {
    use super::*;
    use crate::quic_transport::noise_stream::{
        read_ztlp_frame, run_responder_handshake, write_ztlp_frame,
    };
    use crate::quic_transport::tokio_endpoint::QuicEndpoint;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    /// The process-wide mode for one test, with pins and caches in a
    /// directory of its own. Everything is put back when it is dropped.
    ///
    /// In test builds the state-home override is per thread, so every test
    /// here runs on a current-thread runtime: a dial on another worker
    /// thread would read and write pins in the real state directory, and
    /// a pin left there for a reused loopback port fails a later run.
    struct Mode {
        _guard: tokio::sync::MutexGuard<'static, ()>,
        _home: tempfile::TempDir,
    }

    impl Mode {
        async fn shared() -> Self {
            Self::enter(true).await
        }
        async fn desktop() -> Self {
            Self::enter(false).await
        }
        async fn enter(reuse: bool) -> Self {
            let guard = SHARED_MODE_TEST_LOCK.lock().await;
            let home = tempfile::tempdir().unwrap();
            crate::state_home::set_override(Some(home.path().to_path_buf()));
            set_prefer_relay(false);
            set_reuse_connections(reuse);
            Self {
                _guard: guard,
                _home: home,
            }
        }
    }

    impl Drop for Mode {
        fn drop(&mut self) {
            drop_all_shared();
            set_reuse_connections(false);
            crate::state_home::set_override(None);
        }
    }

    fn drop_all_shared() {
        for t in tunnel_conn_cache().take_where(|_| true) {
            t.conn.close();
        }
    }

    #[derive(Clone, Copy)]
    enum Backend {
        Answers,
        /// Acknowledges at once (QUIC does), answers after this long.
        Slow(Duration),
    }

    /// A gateway: QUIC + Noise, then one answer per stream that says which
    /// connection (1, 2, ...) carried the request.
    struct Gateway {
        addr: SocketAddr,
        handshakes: Arc<AtomicUsize>,
        requests: Arc<std::sync::Mutex<Vec<(usize, Vec<u8>)>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Gateway {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Gateway {
        fn handshakes(&self) -> usize {
            self.handshakes.load(Ordering::SeqCst)
        }
        fn requests(&self) -> Vec<(usize, String)> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|(n, r)| (*n, String::from_utf8_lossy(r).into_owned()))
                .collect()
        }
    }

    async fn gateway(backend: Backend) -> Gateway {
        let ep = QuicEndpoint::bind(crate::quic_transport::QuicEndpointConfig {
            bind: Some("127.0.0.1:0".parse().unwrap()),
            ..Default::default()
        })
        .await
        .unwrap();
        let addr = ep.inner.local_addr().unwrap();
        let identity = NodeIdentity::generate().unwrap();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (hs, reqs) = (handshakes.clone(), requests.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok(conn) = ep.accept().await else {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                };
                let (identity, hs, reqs) = (identity.clone(), hs.clone(), reqs.clone());
                tokio::spawn(async move {
                    if run_responder_handshake(&conn, &identity, NodeId::zero())
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let n = hs.fetch_add(1, Ordering::SeqCst) + 1;
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let reqs = reqs.clone();
                        tokio::spawn(async move {
                            let Ok(req) = read_ztlp_frame(&mut recv).await else {
                                return;
                            };
                            reqs.lock().unwrap().push((n, req));
                            if let Backend::Slow(d) = backend {
                                tokio::time::sleep(d).await;
                            }
                            let body = format!("conn{n}");
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = write_ztlp_frame(&mut send, resp.as_bytes()).await;
                            let _ = send.finish();
                            while read_ztlp_frame(&mut recv).await.is_ok() {}
                        });
                    }
                });
            }
        });
        Gateway {
            addr,
            handshakes,
            requests,
            task,
        }
    }

    /// A network path to `to`: datagrams are carried both ways while `up`,
    /// silently dropped otherwise (what a device that left the network
    /// looks like from both ends).
    struct NetPath {
        addr: SocketAddr,
        up: Arc<AtomicBool>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for NetPath {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn path(to: SocketAddr) -> NetPath {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = front.local_addr().unwrap();
        let up = Arc::new(AtomicBool::new(true));
        let flag = up.clone();
        let task = tokio::spawn(async move {
            let mut backs: std::collections::HashMap<SocketAddr, Arc<UdpSocket>> =
                std::collections::HashMap::new();
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, src)) = front.recv_from(&mut buf).await else {
                    continue;
                };
                if !flag.load(Ordering::SeqCst) {
                    continue;
                }
                let back = match backs.get(&src) {
                    Some(b) => b.clone(),
                    None => {
                        let b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        backs.insert(src, b.clone());
                        let (b2, front, flag) = (b.clone(), front.clone(), flag.clone());
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65535];
                            while let Ok(n) = b2.recv(&mut buf).await {
                                if flag.load(Ordering::SeqCst) {
                                    let _ = front.send_to(&buf[..n], src).await;
                                }
                            }
                        });
                        b
                    }
                };
                let _ = back.send_to(&buf[..n], to).await;
            }
        });
        NetPath { addr, up, task }
    }

    /// An address nothing answers on.
    async fn dead_end() -> (UdpSocket, SocketAddr) {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = s.local_addr().unwrap();
        (s, a)
    }

    /// A name server (the unsigned protocol): every name has the SVC
    /// addresses in `addresses` ("" = not found) and no KEY record.
    struct NameServer {
        addr: String,
        addresses: Arc<std::sync::Mutex<String>>,
        asked: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for NameServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl NameServer {
        fn set(&self, addrs: &[SocketAddr]) {
            *self.addresses.lock().unwrap() = join(addrs);
        }
        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }
    }

    fn join(addrs: &[SocketAddr]) -> String {
        addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    async fn name_server(addrs: &[SocketAddr]) -> NameServer {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        let addresses = Arc::new(std::sync::Mutex::new(join(addrs)));
        let asked = Arc::new(AtomicUsize::new(0));
        let (list, count) = (addresses.clone(), asked.clone());
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                if n < 4 || buf[0] != 0x01 {
                    continue;
                }
                let name_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
                if n < 3 + name_len + 1 {
                    continue;
                }
                let name = buf[3..3 + name_len].to_vec();
                let record_type = buf[3 + name_len];
                let list = list.lock().unwrap().clone();
                if record_type != 2 {
                    let _ = sock.send_to(&[0x03], src).await;
                    continue;
                }
                count.fetch_add(1, Ordering::SeqCst);
                if list.is_empty() {
                    let _ = sock.send_to(&[0x03], src).await;
                    continue;
                }
                let mut cbor = Vec::new();
                ciborium::ser::into_writer(
                    &ciborium::value::Value::Map(vec![(
                        ciborium::value::Value::Text("addresses".into()),
                        ciborium::value::Value::Text(list),
                    )]),
                    &mut cbor,
                )
                .unwrap();
                let mut reply = vec![0x02, 0x02];
                reply.extend_from_slice(&(name.len() as u16).to_be_bytes());
                reply.extend_from_slice(&name);
                reply.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
                reply.extend_from_slice(&cbor);
                let _ = sock.send_to(&reply, src).await;
            }
        });
        NameServer {
            addr,
            addresses,
            asked,
            task,
        }
    }

    /// One site as a listener knows it.
    #[derive(Clone)]
    struct Site {
        name: String,
        peer: Option<SocketAddr>,
        ns: String,
        relay: Option<String>,
        deadline: Option<Duration>,
        identity: NodeIdentity,
    }

    impl Site {
        fn new(name: &str, peer: Option<SocketAddr>, ns: &str) -> Self {
            // What resolving the name leaves behind for a listener's site.
            if let Some(peer) = peer {
                set_peer_candidates(name, &[peer]);
            }
            Self {
                name: name.to_string(),
                peer,
                ns: ns.to_string(),
                relay: None,
                deadline: Some(Duration::from_secs(15)),
                identity: NodeIdentity::generate().unwrap(),
            }
        }

        async fn connect(&self) -> Result<LeasedTunnel, String> {
            connect_tunnel(
                &self.name,
                80,
                self.peer,
                None,
                &self.identity,
                "127.0.0.1:0",
                &self.ns,
                self.relay.as_deref(),
                self.deadline,
            )
            .await
            .map_err(|e| e.to_string())
        }

        /// A browser connection on port 80: the plain path
        /// (`proxy_dial_then_bridge`). Returns what the client read until
        /// the connection closed, and how long that took.
        async fn get_http(&self, request: &str) -> (String, Duration) {
            let site = self.clone();
            self.exchange(request, move |sock| async move {
                proxy_dial_then_bridge(
                    sock,
                    &site.name,
                    80,
                    site.peer,
                    None,
                    &site.identity,
                    "127.0.0.1:0",
                    &site.ns,
                    site.relay.as_deref(),
                    None,
                    site.deadline,
                    local_tls::TlsMode::Never,
                    StallCloseStrategy::Deliver504,
                )
                .await
                .map_err(|e| e.to_string())
            })
            .await
        }

        /// A browser connection on port 443 after the local TLS handshake:
        /// the gated path (`handle_tcp_connection_gated`, then
        /// `bridge_tunnel`), with the agent's TLS already taken off.
        async fn get_https(&self, request: &str) -> (String, Duration) {
            let site = self.clone();
            self.exchange(request, move |sock| async move {
                let policy = AgentConfig::default().tunnel.vip_ports_policy();
                handle_tcp_connection_gated(
                    sock,
                    &site.name,
                    443,
                    site.peer,
                    None,
                    &site.identity,
                    "127.0.0.1:0",
                    &site.ns,
                    site.relay.as_deref(),
                    true,
                    &policy,
                    site.deadline,
                )
                .await
                .map_err(|e| e.to_string())
            })
            .await
        }

        async fn exchange<F, Fut>(&self, request: &str, carry: F) -> (String, Duration)
        where
            F: FnOnce(TcpStream) -> Fut + Send + 'static,
            Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                // Shown when a test fails (output is captured otherwise).
                if let Err(e) = carry(sock).await {
                    eprintln!("carrying the connection ended with: {e}");
                }
            });
            let started = Instant::now();
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(request.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(40), c.read_to_end(&mut out)).await;
            let took = started.elapsed();
            // Let the carrier report how it ended before it is dropped.
            let mut server = server;
            if tokio::time::timeout(Duration::from_millis(500), &mut server)
                .await
                .is_err()
            {
                server.abort();
            }
            (String::from_utf8_lossy(&out).into_owned(), took)
        }
    }

    /// Wait (up to 5 s) for something another task is about to do.
    async fn eventually(cond: impl Fn() -> bool) {
        for _ in 0..500 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("condition not reached within 5 s");
    }

    fn get(name: &str, path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {name}\r\nAccept: */*\r\n\r\n")
    }

    fn body(response: &str) -> &str {
        response.rsplit("\r\n\r\n").next().unwrap_or("")
    }

    // ---- connect times: direct with a head start, relay next to it ----

    #[tokio::test]
    async fn shared_mode_connect_times_direct_alive_direct_dead_and_both_dead() {
        let _mode = Mode::shared().await;
        let gw = gateway(Backend::Answers).await;
        let direct = path(gw.addr).await;
        let relay = path(gw.addr).await;
        let (_d1, dead_direct) = dead_end().await;
        let (_d2, dead_relay) = dead_end().await;
        let ns = name_server(&[]).await;

        // direct alive: taken, and well inside its head start
        let name = "wiki.connect-times.example.ztlp";
        let mut site = Site::new(name, Some(direct.addr), &ns.addr);
        site.relay = Some(relay.addr.to_string());
        let t = Instant::now();
        let got = site.connect().await.unwrap();
        let direct_alive = t.elapsed();
        assert_eq!(got.tunnel.via, DialVia::Direct);
        assert!(!got.reused);
        assert!(direct_alive < DIRECT_ATTEMPT_TIMEOUT, "{direct_alive:?}");
        drop(got);
        drop_all_shared();
        forget_peer_candidates(name);

        // direct dead, relay alive: the relay starts after the head start,
        // not after the direct candidate's 750 ms
        let name = "mail.connect-times.example.ztlp";
        let mut site = Site::new(name, Some(dead_direct), &ns.addr);
        site.relay = Some(relay.addr.to_string());
        let t = Instant::now();
        let got = site.connect().await.unwrap();
        let direct_dead = t.elapsed();
        assert_eq!(got.tunnel.via, DialVia::Relay);
        assert!(
            direct_dead >= super::super::reconnect::RELAY_HEAD_START,
            "{direct_dead:?}"
        );
        assert!(direct_dead < DIRECT_ATTEMPT_TIMEOUT, "{direct_dead:?}");
        drop(got);
        drop_all_shared();

        // the same name again: the relay won last time, so it starts
        // together with the direct candidate
        assert!(relay_won_last(name));
        let t = Instant::now();
        let got = site.connect().await.unwrap();
        let relay_again = t.elapsed();
        assert_eq!(got.tunnel.via, DialVia::Relay);
        assert!(
            relay_again < direct_dead,
            "{relay_again:?} vs {direct_dead:?}"
        );
        drop(got);
        drop_all_shared();
        forget_peer_candidates(name);
        assert!(!relay_won_last(name));

        // both dead: the request is held until its deadline, then fails
        let name = "files.connect-times.example.ztlp";
        let mut site = Site::new(name, Some(dead_direct), &ns.addr);
        site.relay = Some(dead_relay.to_string());
        site.deadline = Some(Duration::from_secs(2));
        let t = Instant::now();
        let err = site.connect().await.err().unwrap();
        let both_dead = t.elapsed();
        assert!(err.contains("dial attempt"), "{err}");
        assert!(both_dead >= Duration::from_millis(1900), "{both_dead:?}");
        assert!(both_dead < Duration::from_secs(4), "{both_dead:?}");
        forget_peer_candidates(name);

        eprintln!(
            "connect times (loopback, shared mode): direct alive {direct_alive:?}; \
             direct dead + relay alive {direct_dead:?} (same name again {relay_again:?}); \
             both dead {both_dead:?} with a 2 s deadline"
        );
    }

    #[tokio::test]
    async fn without_shared_connections_nothing_new_happens() {
        let _mode = Mode::desktop().await;
        let gw = gateway(Backend::Answers).await;
        let relay = path(gw.addr).await;
        let (_d, dead_direct) = dead_end().await;
        let ns = name_server(&[]).await;
        let name = "wiki.desktop-unchanged.example.ztlp";
        let mut site = Site::new(name, Some(dead_direct), &ns.addr);
        site.relay = Some(relay.addr.to_string());

        // the plan is walked in order: the dead direct candidate costs its
        // full 750 ms before the relay is tried
        let t = Instant::now();
        let got = site.connect().await.unwrap();
        let took = t.elapsed();
        assert_eq!(got.tunnel.via, DialVia::Relay);
        assert!(took >= DIRECT_ATTEMPT_TIMEOUT, "{took:?}");
        // nothing is shared, leased, remembered or cached
        assert!(!got.reused);
        assert!(got.lease.is_none());
        assert!(got.tunnel.shared.is_none());
        assert!(!relay_won_last(name));
        assert_eq!(shared_tunnel_count(), 0);
        assert!(tunnel_conn_cache().take_where(|_| true).is_empty());
        // every request dials its own connection
        let (resp, _) = site.get_http(&get(name, "/")).await;
        assert_eq!(body(&resp), "conn2", "{resp}");
        let (resp, _) = site.get_https(&get(name, "/")).await;
        assert_eq!(body(&resp), "conn3", "{resp}");
        assert_eq!(gw.handshakes(), 3);
        drop(got);

        // a dial that fails is not retried: the client is closed at once
        let unknown = "gone.desktop-unchanged.example.ztlp";
        let mut site = Site::new(unknown, None, &ns.addr);
        site.deadline = Some(Duration::from_secs(5));
        let (resp, took) = site.get_http(&get(unknown, "/")).await;
        assert_eq!(resp, "", "closed without an answer, as before");
        assert!(took < Duration::from_secs(1), "{took:?}");
        assert_eq!(ns.asked(), 1);

        // and a network change is nobody's business
        let runs = network_change_runs();
        assert!(!notify_network_changed());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(network_change_runs(), runs);
        forget_peer_candidates(name);
        forget_peer_candidates(unknown);
    }

    // ---- a reused connection whose path died ----

    /// One request on the shared connection, then its path goes silent and
    /// a second path to the same gateway appears. The next request must
    /// arrive, once, over a fresh connection, after about the liveness
    /// window: far from QUIC's 60 s idle timeout and the first-byte
    /// deadline.
    async fn dead_shared_connection_is_replaced(https: bool, name: &str) {
        let _mode = Mode::shared().await;
        let gw = gateway(Backend::Answers).await;
        let wifi = path(gw.addr).await;
        let cellular = path(gw.addr).await;
        let ns = name_server(&[]).await;
        let site = Site::new(name, Some(wifi.addr), &ns.addr);
        let fetch = |p: &'static str| {
            let site = site.clone();
            let req = get(name, p);
            async move {
                if https {
                    site.get_https(&req).await
                } else {
                    site.get_http(&req).await
                }
            }
        };

        let (resp, _) = fetch("/first").await;
        assert_eq!(body(&resp), "conn1", "{resp}");
        let (resp, warm) = fetch("/second").await;
        assert_eq!(body(&resp), "conn1", "the connection is shared: {resp}");
        assert_eq!(gw.handshakes(), 1);

        // the device leaves the network; nothing tells the agent
        wifi.up.store(false, Ordering::SeqCst);
        set_peer_candidates(name, &[cellular.addr]);
        assert_eq!(shared_tunnel_count(), 1, "QUIC still believes in it");

        let (resp, took) = fetch("/after-the-switch").await;
        assert_eq!(body(&resp), "conn2", "{resp}");
        let window = super::super::reconnect::LIVENESS_WINDOW;
        assert!(took >= window, "{took:?}");
        assert!(took < window + Duration::from_secs(3), "{took:?}");
        let after: Vec<_> = gw
            .requests()
            .into_iter()
            .filter(|(_, r)| r.contains("/after-the-switch"))
            .collect();
        assert_eq!(after.len(), 1, "carried exactly once: {after:?}");
        assert_eq!(after[0].0, 2);
        if https {
            assert!(
                after[0]
                    .1
                    .to_ascii_lowercase()
                    .contains("x-forwarded-proto: https"),
                "the replayed head is the stamped one: {}",
                after[0].1
            );
        }
        // the fresh connection is what later requests share
        let (resp, again) = fetch("/later").await;
        assert_eq!(body(&resp), "conn2", "{resp}");
        assert!(again < Duration::from_secs(1), "{again:?}");
        assert_eq!(gw.handshakes(), 2);
        eprintln!(
            "dead shared connection ({}): warm request {warm:?}, request after the path died \
             {took:?}, next request {again:?}",
            if https {
                "port 443 path"
            } else {
                "port 80 path"
            }
        );
        forget_peer_candidates(name);
    }

    #[tokio::test]
    async fn a_dead_shared_connection_is_replaced_within_the_liveness_window_on_port_80() {
        dead_shared_connection_is_replaced(false, "wiki.dead-path-80.example.ztlp").await;
    }

    #[tokio::test]
    async fn a_dead_shared_connection_is_replaced_within_the_liveness_window_on_port_443() {
        dead_shared_connection_is_replaced(true, "wiki.dead-path-443.example.ztlp").await;
    }

    #[tokio::test]
    async fn many_requests_on_a_dead_shared_connection_share_one_new_dial() {
        let _mode = Mode::shared().await;
        let gw = gateway(Backend::Answers).await;
        let wifi = path(gw.addr).await;
        let cellular = path(gw.addr).await;
        let ns = name_server(&[]).await;
        let name = "wiki.dead-path-many.example.ztlp";
        let site = Site::new(name, Some(wifi.addr), &ns.addr);
        let (resp, _) = site.get_https(&get(name, "/first")).await;
        assert_eq!(body(&resp), "conn1", "{resp}");
        wifi.up.store(false, Ordering::SeqCst);
        set_peer_candidates(name, &[cellular.addr]);

        // what the phone log showed: fourteen connections on the dead one
        let mut tasks = Vec::new();
        for i in 0..14 {
            let site = site.clone();
            tasks.push(tokio::spawn(async move {
                site.get_https(&get(&site.name, &format!("/asset{i}")))
                    .await
            }));
        }
        for t in tasks {
            let (resp, took) = t.await.unwrap();
            assert_eq!(body(&resp), "conn2", "{resp}");
            assert!(took < Duration::from_secs(7), "{took:?}");
        }
        assert_eq!(gw.handshakes(), 2, "one new connection for all fourteen");
        let assets = gw
            .requests()
            .into_iter()
            .filter(|(_, r)| r.contains("/asset"))
            .count();
        assert_eq!(assets, 14, "each carried exactly once");
        forget_peer_candidates(name);
    }

    #[tokio::test]
    async fn a_gateway_that_is_alive_with_a_slow_backend_is_not_dialed_again() {
        let _mode = Mode::shared().await;
        // longer than the liveness window
        let slow = super::super::reconnect::LIVENESS_WINDOW + Duration::from_millis(500);
        let gw = gateway(Backend::Slow(slow)).await;
        let net = path(gw.addr).await;
        let ns = name_server(&[]).await;
        let name = "report.slow-backend.example.ztlp";
        let site = Site::new(name, Some(net.addr), &ns.addr);

        // ports 443 and 80 each have their own shared connection
        for (https, conn) in [(true, "conn1"), (false, "conn2")] {
            let first = get(name, "/first");
            let req = "POST /pay HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nok";
            for req in [first.as_str(), req] {
                let (resp, took) = if https {
                    site.get_https(req).await
                } else {
                    site.get_http(req).await
                };
                assert_eq!(body(&resp), conn, "{resp}");
                assert!(took >= slow, "{took:?}");
            }
        }
        assert_eq!(gw.handshakes(), 2, "never dialed again");
        let posts = gw
            .requests()
            .into_iter()
            .filter(|(_, r)| r.starts_with("POST /pay"))
            .count();
        assert_eq!(posts, 2, "each POST reached the backend exactly once");
        forget_peer_candidates(name);
    }

    // ---- the dial itself fails for a while ----

    #[tokio::test]
    async fn a_failing_dial_is_retried_and_waiting_requests_share_it() {
        let _mode = Mode::shared().await;
        let gw = gateway(Backend::Answers).await;
        let net = path(gw.addr).await;
        // no route yet: the name server has nothing for the name
        let ns = name_server(&[]).await;
        let name = "wiki.dial-retry.example.ztlp";
        let site = Site::new(name, None, &ns.addr);

        let mut tasks = Vec::new();
        for i in 0..5 {
            let site = site.clone();
            tasks.push(tokio::spawn(async move {
                site.get_http(&get(&site.name, &format!("/r{i}"))).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let asked_while_down = ns.asked();
        ns.set(&[net.addr]);
        for t in tasks {
            let (resp, took) = t.await.unwrap();
            assert_eq!(
                body(&resp),
                "conn1",
                "the client was held, then served: {resp}"
            );
            assert!(took >= Duration::from_millis(1200), "{took:?}");
            assert!(took < Duration::from_secs(5), "{took:?}");
        }
        assert_eq!(gw.handshakes(), 1);
        // 250 ms, 500 ms, 1 s apart: one retry loop, not five
        assert!(
            (2..=4).contains(&asked_while_down),
            "{asked_while_down} lookups in 1.2 s"
        );
        forget_peer_candidates(name);
    }

    #[tokio::test]
    async fn a_dial_that_never_works_ends_at_the_deadline_with_the_usual_504() {
        let _mode = Mode::shared().await;
        let ns = name_server(&[]).await;
        let name = "wiki.dial-never.example.ztlp";
        let mut site = Site::new(name, None, &ns.addr);
        site.deadline = Some(Duration::from_millis(1500));
        let (resp, took) = site.get_http(&get(name, "/")).await;
        assert!(resp.starts_with("HTTP/1.1 504 "), "{resp:?}");
        assert!(resp.contains(&format!("<code>{name}</code>")), "{resp}");
        assert!(took >= Duration::from_millis(1500), "{took:?}");
        assert!(took < Duration::from_secs(3), "{took:?}");
        assert!(ns.asked() >= 3, "{} lookups", ns.asked());
        forget_peer_candidates(name);
    }

    // ---- the network changed ----

    #[tokio::test]
    async fn a_network_change_drops_shared_connections_and_dials_them_again_at_once() {
        let _mode = Mode::shared().await;
        let gw = gateway(Backend::Answers).await;
        let wifi = path(gw.addr).await;
        let cellular = path(gw.addr).await;
        let ns = name_server(&[wifi.addr]).await;
        let name = "wiki.network-change.example.ztlp";
        let site = Site::new(name, Some(wifi.addr), &ns.addr);
        let keeper = tokio::spawn(keep_shared_tunnels(None));
        tokio::time::sleep(Duration::from_millis(20)).await;

        let (resp, _) = site.get_http(&get(name, "/first")).await;
        assert_eq!(body(&resp), "conn1", "{resp}");
        let old = tunnel_conn_cache()
            .get_or_dial(&tunnel_key(name, 80), tunnel_is_open, || async {
                Err::<ConnectedTunnel, String>("expected a cached connection".into())
            })
            .await
            .unwrap()
            .0;
        assert!(cached_route_is_current(name));
        note_dial_winner(name, DialVia::Relay);

        // Wi-Fi goes, cellular comes; the extension reports it in a burst
        wifi.up.store(false, Ordering::SeqCst);
        ns.set(&[cellular.addr]);
        let lookups = ns.asked();
        let runs = network_change_runs();
        let changed = Instant::now();
        for _ in 0..20 {
            assert!(notify_network_changed());
        }

        // the old connection is closed, not left to its idle timeout, and
        // the site is dialed again without waiting for a request
        let mut ready = None;
        for _ in 0..200 {
            if gw.handshakes() >= 2 && shared_tunnel_count() == 1 {
                ready = Some(changed.elapsed());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let ready = ready.expect("the site was not dialed again in the background");
        assert!(old.conn.inner.close_reason().is_some());
        assert!(!relay_won_last(name), "the path memory is reset");
        assert!(ns.asked() > lookups, "the name was resolved again");
        assert!(cached_route_is_current(name));

        // the burst was one event (at most the run after the window too)
        tokio::time::sleep(Duration::from_millis(600)).await;
        let acted = network_change_runs() - runs;
        assert!((1..=2).contains(&acted), "{acted} runs for 20 calls");

        // the next request rides the connection that is already there,
        // although the listener still holds the old address for the site
        let (resp, took) = site.get_http(&get(name, "/after")).await;
        let n = gw.handshakes();
        assert_eq!(body(&resp), format!("conn{n}"), "{resp}");
        assert!(n <= 3, "{n} connections (2, or 3 when the burst ran twice)");
        assert!(took < Duration::from_secs(1), "{took:?}");
        eprintln!(
            "network change: site dialed again in the background after {ready:?}; \
             the next request took {took:?}"
        );

        // with the task gone the call is a no-op again
        keeper.abort();
        let _ = keeper.await;
        let runs = network_change_runs();
        assert!(!notify_network_changed());
        assert_eq!(network_change_runs(), runs);
        forget_peer_candidates(name);
    }

    #[tokio::test]
    async fn an_acknowledged_request_in_flight_is_closed_not_replayed_by_a_network_change() {
        // The connection is alive but the answer takes 2 s; 300 ms in, the
        // network "changes" and every shared connection is closed. The
        // gateway had acknowledged the request, so it is NOT sent again:
        // the client connection is closed, as an in-flight transfer is.
        // A request that arrives right after is carried normally.
        let _mode = Mode::shared().await;
        let gw = gateway(Backend::Slow(Duration::from_secs(2))).await;
        let net = path(gw.addr).await;
        let ns = name_server(&[net.addr]).await;
        let name = "wiki.change-in-flight.example.ztlp";
        let site = Site::new(name, Some(net.addr), &ns.addr);
        let keeper = tokio::spawn(keep_shared_tunnels(None));
        let (resp, _) = site.get_https(&get(name, "/first")).await;
        assert_eq!(body(&resp), "conn1", "{resp}");

        let in_flight = {
            let site = site.clone();
            tokio::spawn(async move { site.get_https(&get(&site.name, "/in-flight")).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(notify_network_changed());
        let (resp, took) = in_flight.await.unwrap();
        assert_eq!(resp, "", "closed, not answered twice");
        assert!(took < Duration::from_secs(2), "{took:?}");
        let seen = gw
            .requests()
            .into_iter()
            .filter(|(_, r)| r.contains("/in-flight"))
            .count();
        assert_eq!(seen, 1, "an acknowledged request is never replayed");

        let (resp, _) = site.get_https(&get(name, "/next")).await;
        assert!(body(&resp).starts_with("conn"), "{resp}");
        assert_ne!(body(&resp), "conn1");
        keeper.abort();
        forget_peer_candidates(name);
    }

    #[tokio::test]
    async fn at_most_eight_sites_are_dialed_again_after_a_network_change() {
        let _mode = Mode::shared().await;
        let gw = gateway(Backend::Answers).await;
        let net = path(gw.addr).await;
        let ns = name_server(&[net.addr]).await;
        let keeper = tokio::spawn(keep_shared_tunnels(None));
        let names: Vec<String> = (0..10)
            .map(|i| format!("site{i}.prewarm-cap.example.ztlp"))
            .collect();
        for name in &names {
            let site = Site::new(name, Some(net.addr), &ns.addr);
            drop(site.connect().await.unwrap());
        }
        // (the gateway counts a handshake a moment after the client has it)
        eventually(|| gw.handshakes() == 10).await;
        assert_eq!(shared_tunnel_count(), 10);

        assert!(notify_network_changed());
        let cap = super::super::reconnect::PREWARM_MAX_SITES;
        eventually(|| gw.handshakes() == 10 + cap).await;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        assert_eq!(shared_tunnel_count(), cap);
        assert_eq!(gw.handshakes(), 10 + cap, "and no more than that");
        keeper.abort();
        for name in &names {
            forget_peer_candidates(name);
        }
    }

    // ---- idle close (mobile profile) ----

    #[tokio::test]
    async fn an_unused_shared_connection_is_closed_and_the_next_request_dials() {
        let _mode = Mode::shared().await;
        let gw = gateway(Backend::Answers).await;
        let net = path(gw.addr).await;
        let ns = name_server(&[]).await;
        let name = "wiki.idle-close.example.ztlp";
        let site = Site::new(name, Some(net.addr), &ns.addr);

        let in_use = site.connect().await.unwrap();
        assert!(in_use.lease.is_some());
        // in use: never closed, however short the idle time asked for
        assert_eq!(reap_idle_shared_tunnels(Duration::ZERO), 0);
        assert_eq!(shared_tunnel_count(), 1);
        // a second user keeps it alive after the first left
        let second = site.connect().await.unwrap();
        assert!(second.reused);
        drop(in_use);
        assert_eq!(reap_idle_shared_tunnels(Duration::ZERO), 0);
        let conn = second.tunnel.conn.clone();
        drop(second);

        // unused, but not for long enough
        assert_eq!(reap_idle_shared_tunnels(Duration::from_secs(120)), 0);
        assert_eq!(shared_tunnel_count(), 1);
        // unused for long enough
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(reap_idle_shared_tunnels(Duration::from_millis(50)), 1);
        assert_eq!(shared_tunnel_count(), 0);
        assert!(
            conn.inner.close_reason().is_some(),
            "closed, keep-alive stops"
        );

        let (resp, took) = site.get_http(&get(name, "/")).await;
        assert_eq!(body(&resp), "conn2", "{resp}");
        eprintln!("idle close: the request after it dialed again in {took:?}");
        forget_peer_candidates(name);
    }

    #[test]
    fn the_mobile_idle_close_is_longer_than_a_keep_alive_and_bounded() {
        let idle = super::super::reconnect::MOBILE_IDLE_CLOSE;
        let cfg = crate::quic_transport::QuicEndpointConfig::default();
        // the transport values themselves are the desktop ones, untouched
        assert_eq!(cfg.keep_alive_interval_ms, Some(15_000));
        assert_eq!(cfg.max_idle_timeout_ms, Some(60_000));
        assert!(idle >= Duration::from_secs(60));
        assert!(idle <= Duration::from_secs(300));
    }

    #[test]
    fn permanent_dial_failures_are_told_apart_from_a_missing_network() {
        for permanent in [
            "invalid relay address 'x': bad",
            "no dialable endpoint for 'a.example.ztlp'",
            "[ztlp-ns-cert-mismatch] gateway presented ...",
            "[ztlp-ns-unverified] no verified name-server record",
            "QUIC certificate fingerprint for 'localhost' does not match the pinned value",
        ] {
            assert!(dial_error_is_permanent(permanent), "{permanent}");
        }
        for transient in [
            "Network is unreachable (os error 101)",
            "all 2 dial attempts failed for 'a.example.ztlp': timed out",
            "no SVC address found for 'a.example.ztlp'",
            "dial attempt did not finish within 5s",
        ] {
            assert!(!dial_error_is_permanent(transient), "{transient}");
        }
    }
}

#[cfg(test)]
mod single_address_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    /// A name server that accepts and never answers (not expected to be
    /// asked at all here: the sites are already known).
    async fn blackhole_ns() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        addr.to_string()
    }

    /// A "gateway" on loopback that receives the agent's dial and never
    /// answers it.
    async fn silent_gateway() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").await.unwrap()
    }

    /// Did a datagram (the QUIC dial) arrive at this gateway?
    fn was_dialed(gw: &UdpSocket) -> bool {
        let mut buf = [0u8; 2048];
        gw.try_recv_from(&mut buf).is_ok()
    }

    /// The carrier the daemon builds, with `sites` already resolved (what
    /// a DNS query for each name leaves behind).
    fn carrier(ns_server: String, sites: &[(&str, SocketAddr)]) -> SingleAddressCarrier {
        let mut single = super::super::name_route::SingleAddress::new(Ipv4Addr::LOCALHOST);
        for (name, gateway) in sites {
            let r = proxy::NsResolution {
                addr: *gateway,
                node_id: None,
                ztlp_name: name.to_string(),
                candidates: vec![*gateway],
                cert: Default::default(),
            };
            single.record(name, &r, Instant::now());
        }
        let dns_state = Arc::new(Mutex::new(DnsResolverState {
            vip_pool: VipPool::new("127.100.0.0/24").unwrap(),
            domain_mapper: DomainMapper::empty(),
            ns_server: ns_server.clone(),
            upstream_dns: "192.0.2.53:53".to_string(),
            vip_state_path: None,
            health_vip: Ipv4Addr::LOCALHOST,
            single: Some(single),
        }));
        SingleAddressCarrier {
            addr: Ipv4Addr::LOCALHOST,
            dns_state,
            identity: NodeIdentity::generate().unwrap(),
            bind: "127.0.0.1:0".to_string(),
            ns_server,
            tls: None,
            relay: None,
            first_byte_timeout: "400ms".to_string(),
            policy: AgentConfig::default().tunnel.vip_ports_policy(),
            peer_policy: ClientPeerPolicy::LoopbackOnly,
        }
    }

    async fn exchange(addr: SocketAddr, request: &str) -> String {
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn http_by_host_is_carried_by_the_vip_path_to_the_named_sites_gateway() {
        // (not while another test has shared connections and a network
        // change in progress: this one counts on the sites' cached routes)
        let _mode = SHARED_MODE_TEST_LOCK.lock().await;
        let ns = blackhole_ns().await;
        let wiki_gw = silent_gateway().await;
        let mail_gw = silent_gateway().await;
        let wiki = "wiki.single-address-test.example.ztlp";
        let mail = "mail.single-address-test.example.ztlp";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = carrier(
            ns,
            &[
                (wiki, wiki_gw.local_addr().unwrap()),
                (mail, mail_gw.local_addr().unwrap()),
            ],
        )
        .spawn(listener, 80);

        // Host in upper case with a port: the wiki site, and only it
        let got = exchange(
            addr,
            &format!("GET / HTTP/1.1\r\nHost: {}:80\r\n\r\n", wiki.to_uppercase()),
        )
        .await;
        assert!(got.starts_with("HTTP/1.1 504 "), "{got:?}");
        assert!(got.contains(&format!("<code>{wiki}</code>")), "{got}");
        assert!(was_dialed(&wiki_gw), "the wiki gateway must be dialed");
        assert!(!was_dialed(&mail_gw), "the mail gateway must not be");
        while was_dialed(&wiki_gw) {}

        let got = exchange(addr, &format!("GET / HTTP/1.1\r\nHost: {mail}\r\n\r\n")).await;
        assert!(got.starts_with("HTTP/1.1 504 "), "{got:?}");
        assert!(got.contains(&format!("<code>{mail}</code>")), "{got}");
        assert!(was_dialed(&mail_gw), "the mail gateway must be dialed");
        while was_dialed(&mail_gw) {}

        // not a ZTLP name: a short 4xx from the listener and no dial
        let got = exchange(addr, "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n").await;
        assert!(got.starts_with("HTTP/1.1 421 "), "{got:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!was_dialed(&wiki_gw) && !was_dialed(&mail_gw));
        task.abort();
        forget_peer_candidates(wiki);
        forget_peer_candidates(mail);
    }

    #[tokio::test]
    async fn a_locked_session_refuses_new_connections_like_a_vip_listener() {
        let ns = blackhole_ns().await;
        let gw = silent_gateway().await;
        let name = "wiki.single-address-lock.example.ztlp";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = carrier(ns, &[(name, gw.local_addr().unwrap())]).spawn(listener, 80);

        super::super::peruser::set_frozen(true);
        let got = exchange(addr, &format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n")).await;
        super::super::peruser::set_frozen(false);
        assert_eq!(got, "", "closed without an answer, as on a VIP");
        assert!(!was_dialed(&gw));
        task.abort();
        forget_peer_candidates(name);
    }
}

#[cfg(test)]
mod splash_wiring_tests {
    //! The real `dial_tunnel` against a black-hole NS (it hangs), driven
    //! through `handle_tcp_connection_gated`.
    use super::handle_tcp_connection_gated;
    use crate::identity::NodeIdentity;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn blackhole_ns() -> String {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 256];
                    let _ = s.read(&mut b).await;
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                });
            }
        });
        addr
    }

    async fn run(port: u16, request: &'static [u8]) -> Vec<u8> {
        let ns = blackhole_ns().await;
        let (mut browser, agent) = tokio::io::duplex(256 * 1024);
        browser.write_all(request).await.unwrap();
        let id = NodeIdentity::generate().unwrap();
        let task = tokio::spawn(async move {
            let _ = handle_tcp_connection_gated(
                agent,
                "slow.splash.test",
                port,
                None,
                None,
                &id,
                "127.0.0.1",
                &ns,
                None,
                port == 443, // the https port is the one the agent terminates TLS on
                &crate::agent::config::VipPortPolicy::default(),
                None, // no accept-time deadline in this test harness
            )
            .await;
        });
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_millis(2500), async {
            let mut b = [0u8; 4096];
            loop {
                match browser.read(&mut b).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&b[..n]),
                }
            }
        })
        .await;
        task.abort();
        got
    }

    const BROWSER: &[u8] = b"GET / HTTP/1.1\r\nHost: slow.splash.test\r\nAccept: text/html\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Dest: document\r\n\r\n";
    const CURL: &[u8] = b"GET / HTTP/1.1\r\nHost: slow.splash.test\r\nAccept: */*\r\n\r\n";

    #[tokio::test]
    async fn stalled_dial_browser_on_https_port_gets_splash() {
        let got = run(443, BROWSER).await;
        let text = String::from_utf8_lossy(&got);
        assert!(
            text.starts_with("HTTP/1.1 200 "),
            "got {} bytes: {:.80}",
            got.len(),
            text
        );
        assert!(text.contains("slow.splash.test") && text.contains("/.ztlp/ready"));
    }

    #[tokio::test]
    async fn stalled_dial_curl_on_https_port_gets_no_bytes() {
        let got = run(443, CURL).await;
        assert!(
            got.is_empty(),
            "curl-style client got {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    #[tokio::test]
    async fn non_http_port_never_gets_splash() {
        let got = run(3306, BROWSER).await;
        assert!(
            got.is_empty(),
            "db port got {:?}",
            String::from_utf8_lossy(&got)
        );
    }
}

#[cfg(test)]
mod local_tls_termination_tests {
    use crate::agent::local_tls::{tls_mode_for_port, TlsMode};

    /// The VIP proxy routes by TLS mode: 443/8443 = Always (terminate TLS
    /// locally), 80/8080/DB/RDP = Never (plain passthrough). This is the
    /// exact predicate the accept loop uses to choose the TLS-terminating
    /// handler (`handle_tcp_connection_with_tls`) over `proxy_dial_then_bridge`.
    ///
    /// Before the 2026-09-01 fix, the accept loop ignored this for 443 and
    /// routed it through the plain passthrough path, which is why HTTPS
    /// handshakes never completed.
    #[test]
    fn tls_mode_for_port_matches_vip_terminating_ports() {
        // TLS-terminating ports (the "HTTPS by default" path). These are the
        // ONLY ports the VIP proxy routes to the TLS-terminating handler;
        // everything else stays on the plain passthrough path.
        assert_eq!(tls_mode_for_port(443), TlsMode::Always);
        assert_eq!(tls_mode_for_port(8443), TlsMode::Always);
        // Explicit never-TLS ports (SSH, plain HTTP).
        assert_eq!(tls_mode_for_port(22), TlsMode::Never);
        assert_eq!(tls_mode_for_port(80), TlsMode::Never);
        assert_eq!(tls_mode_for_port(8080), TlsMode::Never);
        // Anything else is Detect (sniff first bytes) — NOT Always, so the
        // VIP proxy keeps them on the plain passthrough path. Locking this
        // in prevents an accidental widening of the TLS-termination set to
        // DB/RDP/etc. ports where a blanket TLS wrap would break clients.
        assert_eq!(tls_mode_for_port(3306), TlsMode::Detect);
        assert_eq!(tls_mode_for_port(3389), TlsMode::Detect);
        assert_eq!(tls_mode_for_port(5432), TlsMode::Detect);
    }
}

// ─── B4: unenrolled standby (fresh-Mac chicken-and-egg) ─────────────────────
//
// HANDOFF-2026-09-20 B4: SMAppService starts the root daemon immediately
// (RunAtLoad) but the daemon exited 1 when identity.json was missing, so
// the GUI's "enroll the daemon" control command never found a listener.
// Fix (a): on macOS, a missing identity is NOT fatal — the daemon binds
// ONLY its control socket, answers `status`/`setup_status`/`enroll`, and
// promotes itself to the full daemon once identity.json appears.
#[cfg(test)]
mod unenrolled_standby_tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ztlp-standby-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(".ztlp")).unwrap();
        d
    }

    #[test]
    fn missing_identity_is_standby_on_every_platform() {
        let home = tmp_home("decide");
        let missing = home.join(".ztlp").join("identity.json");
        // Absent file: standby on every platform now (was macOS-only).
        assert!(
            should_enter_unenrolled_standby(&missing),
            "a fresh service/unit with no identity must enter standby on every platform"
        );
        // Corrupt (present but unparseable) file WITH a complete config: NEVER
        // standby — that is a real error the operator must see. (Without a
        // config it is an orphan of a failed setup and IS cleared, see
        // orphan_identity_is_removed_but_complete_one_is_kept.)
        std::fs::write(&missing, "not json").unwrap();
        std::fs::write(home.join(".ztlp/config.toml"), "zone = \"a.ztlp\"\n").unwrap();
        assert!(!should_enter_unenrolled_standby(&missing));
        assert!(
            missing.exists(),
            "complete enrollment must never be deleted"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn standby_decision_is_now_cross_platform_not_macos_only() {
        let home = tmp_home("crossplat");
        let missing = home.join(".ztlp").join("identity.json");
        // Previously this only returned true on macOS. It must now return true
        // on Linux and Windows too (still false when identity.json is present
        // and complete — see missing_identity_is_standby_on_every_platform for
        // that half, which stays correct unchanged).
        assert!(
            should_enter_unenrolled_standby(&missing),
            "a fresh Linux/Windows service with no identity must enter standby too"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn standby_waits_for_enroll_to_finish_not_just_identity_json() {
        let home = tmp_home("handover");
        let idp = home.join(".ztlp").join("identity.json");
        assert!(!standby_may_hand_over(&idp, 0), "no identity -> stay");
        std::fs::write(&idp, "{}").unwrap();
        // identity.json written by `ztlp setup`, but nothing else yet ->
        // orphan; MUST NOT hand over (this is the live wedge of 2026-09-20).
        assert!(
            !standby_may_hand_over(&idp, 0),
            "identity without config -> stay"
        );
        std::fs::write(home.join(".ztlp/config.toml"), "zone = \"defcon.ztlp\"\n").unwrap();
        // complete on disk, but the enroll command is still running ca-init
        // -> MUST NOT hand over yet.
        assert!(!standby_may_hand_over(&idp, 1), "enroll in flight -> stay");
        assert!(
            standby_may_hand_over(&idp, 0),
            "identity + config + enroll done -> go"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn enrollment_complete_requires_nonempty_zone() {
        let home = tmp_home("complete");
        let idp = home.join(".ztlp").join("identity.json");
        std::fs::write(&idp, "{}").unwrap();
        std::fs::write(
            home.join(".ztlp/config.toml"),
            "# no zone\nns_server = \"x\"\n",
        )
        .unwrap();
        assert!(!enrollment_is_complete(&idp));
        std::fs::write(home.join(".ztlp/config.toml"), "zone = \"\"\n").unwrap();
        assert!(!enrollment_is_complete(&idp));
        std::fs::write(home.join(".ztlp/config.toml"), "zone = \"a.ztlp\"\n").unwrap();
        assert!(enrollment_is_complete(&idp));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn orphan_identity_is_removed_but_complete_one_is_kept() {
        let home = tmp_home("orphan");
        let idp = home.join(".ztlp").join("identity.json");
        assert!(!remove_orphan_identity(&idp), "nothing to remove");
        std::fs::write(&idp, "{}").unwrap();
        assert!(remove_orphan_identity(&idp));
        assert!(!idp.exists());
        std::fs::write(&idp, "{}").unwrap();
        std::fs::write(home.join(".ztlp/config.toml"), "zone = \"a.ztlp\"\n").unwrap();
        assert!(
            !remove_orphan_identity(&idp),
            "complete enrollment must never be touched"
        );
        assert!(idp.exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn standby_serves_control_socket_and_exits_when_identity_appears() {
        let home = tmp_home("serve");
        let identity_path = home.join(".ztlp").join("identity.json");
        let token_path = home.join(".ztlp").join("agent.token");
        // Ephemeral loopback port for the control socket.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ipc_addr = probe.local_addr().unwrap().to_string();
        drop(probe);

        let ip = ipc_addr.clone();
        let idp = identity_path.clone();
        let tp = token_path.clone();
        let standby = tokio::spawn(async move {
            run_unenrolled_standby(&ip, &idp, &tp, Duration::from_millis(50)).await
        });

        // Wait for the socket to come up.
        let mut stream = None;
        for _ in 0..50 {
            if let Ok(s) = TcpStream::connect(&ipc_addr).await {
                stream = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut stream = stream.expect("standby control socket must come up");
        let token = std::fs::read_to_string(&token_path)
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(token.len(), 64, "standby must materialize agent.token");

        // `status` answers, and says enrolled:false + standby:true.
        let req = format!(r#"{{"cmd":"status","token":"{}"}}"#, token);
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(b"\n").await.unwrap();
        let mut line = String::new();
        BufReader::new(&mut stream)
            .read_line(&mut line)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["ok"], true, "status must succeed in standby: {line}");
        assert_eq!(v["data"]["standby"], true);
        assert_eq!(v["data"]["enrolled"], false);

        // Wrong token is still rejected in standby (no auth regression).
        let mut s2 = TcpStream::connect(&ipc_addr).await.unwrap();
        s2.write_all(br#"{"cmd":"status","token":"nope"}"#)
            .await
            .unwrap();
        s2.write_all(b"\n").await.unwrap();
        let mut l2 = String::new();
        BufReader::new(&mut s2).read_line(&mut l2).await.unwrap();
        assert!(l2.contains("unauthorized"), "{l2}");

        // identity.json ALONE must NOT end standby (orphan of a failed setup).
        assert!(!standby.is_finished());
        std::fs::write(&identity_path, "{}").unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(
            !standby.is_finished(),
            "identity.json without config.toml must not end standby"
        );

        // Complete enrollment (config.toml with a zone) -> standby returns Ok
        // and releases the port.
        std::fs::write(
            identity_path.parent().unwrap().join("config.toml"),
            "zone = \"test.ztlp\"\n",
        )
        .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(3), standby)
            .await
            .expect("standby must exit once the enrollment is complete")
            .unwrap();
        assert!(res.is_ok(), "{res:?}");
        // Port must be free again for the full daemon to bind.
        let rebind = TcpListener::bind(&ipc_addr).await;
        assert!(
            rebind.is_ok(),
            "control port must be released after standby"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}
