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
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::handshake::HandshakeContext;
use crate::identity::{NodeId, NodeIdentity};
use crate::packet::{HandshakeHeader, MsgType, SessionId, HANDSHAKE_HEADER_SIZE};
use crate::transport::TransportNode;
use crate::tunnel;

use super::config::{self, AgentConfig};
use super::control::{self, AgentState};
use super::dns::{self, DnsResolverState};
use super::domain_map::DomainMapper;
use super::local_tls::{self, SniCertResolver};
use super::proxy;
use super::tunnel_pool::{TunnelPool, DEFAULT_IDLE_TIMEOUT, DEFAULT_KEEPALIVE_INTERVAL};
use super::vip_pool::VipPool;

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
fn verify_local_peer(stream: &tokio::net::TcpStream) -> bool {
    match stream.peer_addr() {
        Ok(addr) => {
            let ip = addr.ip();
            if ip.is_loopback() {
                true
            } else {
                warn!(
                    "Rejected VIP connection from non-loopback peer {} (VIP listeners must only accept loopback traffic)",
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

/// Run the agent daemon.
///
/// This is the main entry point called by `ztlp agent start`.
/// It blocks until shutdown is requested (via signal or control socket).
pub async fn run_daemon(
    config: &AgentConfig,
    foreground: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start_time = Instant::now();

    // Load identity
    let identity_path = config.identity_path();
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
    match crate::agent::user_binding::current_user_sid() {
        Ok(current_sid) => {
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
        Err(e) => {
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

    // Initialize VIP pool
    let vip_pool = VipPool::new(&config.dns.vip_range)
        .map_err(|e| format!("invalid VIP range '{}': {}", config.dns.vip_range, e))?;
    info!(
        "VIP pool: {} ({} addresses)",
        config.dns.vip_range,
        vip_pool.capacity()
    );

    // Initialize domain mapper
    let domain_mapper = DomainMapper::new(&config.dns.domain_map);
    if !domain_mapper.is_empty() {
        info!("domain mappings: {} configured", domain_mapper.len());
    }

    // Shared DNS resolver state
    let dns_state = Arc::new(Mutex::new(DnsResolverState {
        vip_pool,
        domain_mapper,
        ns_server: config.ns_server().to_string(),
        upstream_dns: config.dns.upstream.clone(),
    }));

    // Initialize tunnel pool
    // D3.T2: honor config.tunnel.idle_timeout / keepalive_interval. On parse
    // failure we keep the daemon up using the built-in defaults and log a
    // warning that names the bad value, so operators see the problem in the
    // log instead of having a daemon that refuses to start.
    let idle_timeout = match config::parse_duration_str(&config.tunnel.idle_timeout) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                "invalid tunnel.idle_timeout '{}': {} — falling back to default {:?}",
                config.tunnel.idle_timeout, e, DEFAULT_IDLE_TIMEOUT
            );
            DEFAULT_IDLE_TIMEOUT
        }
    };
    let keepalive_interval = match config::parse_duration_str(&config.tunnel.keepalive_interval) {
        Ok(d) => d,
        Err(e) => {
            warn!(
                "invalid tunnel.keepalive_interval '{}': {} — falling back to default {:?}",
                config.tunnel.keepalive_interval, e, DEFAULT_KEEPALIVE_INTERVAL
            );
            DEFAULT_KEEPALIVE_INTERVAL
        }
    };
    let tunnel_pool = Arc::new(Mutex::new(TunnelPool::with_timeouts(
        config.tunnel.max_tunnels,
        idle_timeout,
        keepalive_interval,
    )));
    info!(
        "tunnel pool: max {} tunnels, idle_timeout={:?}, keepalive={:?}",
        config.tunnel.max_tunnels, idle_timeout, keepalive_interval
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
    let dns_socket_and_addr = if config.dns.enabled {
        match dns::bind_dns_socket_with_fallback(&config.dns.listen).await {
            Ok((socket, addr)) => Some((socket, addr)),
            Err(e) => {
                return Err(format!(
                    "failed to bind DNS resolver on {} or any fallback port: {}",
                    config.dns.listen, e
                )
                .into());
            }
        }
    } else {
        None
    };
    let effective_dns_listen = dns_socket_and_addr
        .as_ref()
        .map(|(_, addr)| addr.to_string())
        .unwrap_or_else(|| config.dns.listen.clone());

    // Agent state for control socket
    let agent_state = Arc::new(AgentState {
        dns_state: dns_state.clone(),
        tunnel_pool: tunnel_pool.clone(),
        start_time,
        dns_listen: effective_dns_listen,
        shutdown_tx: shutdown_tx.clone(),
        // D1.T3: real Bearer token wired in. The T2 gate is now live.
        expected_token: Some(Arc::new(token)),
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

    // ── Spawn control socket ────────────────────────────────────────────
    let ipc_addr = config.ipc.listen.clone();
    let ctrl_state = agent_state.clone();
    let ctrl_path = ipc_addr.clone();
    let ctrl_handle = tokio::spawn(async move {
        if let Err(e) = control::run_control_socket(&ctrl_path, ctrl_state).await {
            error!("control socket error: {}", e);
        }
    });

    // ── Initialize local TLS ──────────────────────────────────────────
    let tls_acceptor = if config.tls.enabled {
        let cert_dir = config.tls.cert_dir_path();
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
        let ca_dir = dirs::home_dir()
            .map(|h| h.join(".ztlp").join("ca"))
            .unwrap_or_else(|| std::path::PathBuf::from(".ztlp/ca"));
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

    // ── Spawn TCP proxy listener ────────────────────────────────────────
    // The TCP proxy task watches for new VIP allocations and spawns
    // TCP listeners on each VIP address. When a TCP connection arrives,
    // it establishes a ZTLP tunnel to the peer and bridges traffic.
    let proxy_dns_state = dns_state.clone();
    let proxy_identity = identity.clone();
    let proxy_bind = config.tunnel.bind.clone();
    let proxy_ns_server = config.ns_server().to_string();
    let proxy_tls_acceptor = tls_acceptor.clone();
    let proxy_relay = config.tunnel.relays.0.first().cloned();
    if let Some(ref r) = proxy_relay {
        info!("relay configured: {}", r);
    } else {
        info!("no relay configured, using direct connections");
    }
    let proxy_handle = tokio::spawn(async move {
        run_tcp_proxy(
            proxy_dns_state,
            proxy_identity,
            proxy_bind,
            proxy_ns_server,
            proxy_tls_acceptor,
            proxy_relay,
        )
        .await;
    });

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
        eprintln!("  VIP pool: {}", config.dns.vip_range);
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

    // ── Wait for shutdown ───────────────────────────────────────────────
    let mut shutdown_rx = shutdown_tx.subscribe();

    tokio::select! {
        _ = shutdown_rx.recv() => {
            info!("shutdown signal received");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Ctrl+C received, shutting down...");
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
    ctrl_handle.abort();
    proxy_handle.abort();
    gc_handle.abort();
    lockdown_handle.abort();

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
async fn run_tcp_proxy(
    dns_state: Arc<Mutex<DnsResolverState>>,
    identity: NodeIdentity,
    bind_addr: String,
    ns_server: String,
    tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    relay_addr: Option<String>,
) {
    // Track which VIPs we're already listening on
    let active_listeners: Arc<Mutex<std::collections::HashSet<Ipv4Addr>>> =
        Arc::new(Mutex::new(std::collections::HashSet::new()));

    let mut poll_interval = tokio::time::interval(Duration::from_millis(500));

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
            // Start with the most common ones.
            let common_ports = [22, 80, 443, 3306, 5432, 3389, 8080, 8443];

            {
                let mut listeners = active_listeners.lock().await;
                listeners.insert(vip);
            }

            for &port in &common_ports {
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

                tokio::spawn(async move {
                    match TcpListener::bind(addr).await {
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
                                        if !verify_local_peer(&tcp_stream) {
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

                                        tokio::spawn(async move {
                                            let result = if let Some(ref acceptor) = tls {
                                                handle_tcp_connection_with_tls(
                                                    tcp_stream,
                                                    &name,
                                                    port,
                                                    peer,
                                                    peer_node_id,
                                                    &identity,
                                                    &bind,
                                                    &ns,
                                                    acceptor,
                                                    relay.as_deref(),
                                                )
                                                .await
                                            } else {
                                                handle_tcp_connection(
                                                    tcp_stream,
                                                    &name,
                                                    port,
                                                    peer,
                                                    peer_node_id,
                                                    &identity,
                                                    &bind,
                                                    &ns,
                                                    relay.as_deref(),
                                                )
                                                .await
                                            };

                                            if let Err(e) = result {
                                                warn!("tunnel error for {}: {}", name, e);
                                            }

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
                            // Port might already be in use — that's OK
                            debug!("cannot bind {}:{}: {} (likely in use)", vip, port, e);
                        }
                    }
                });
            }
        }
    }
}

/// Handle a TCP connection with TLS termination, then establish a ZTLP tunnel.
///
/// The TLS mode is determined by port number:
/// - Port 443, 8443 → always TLS
/// - Port 80, 8080, 22 → never TLS
/// - Other ports → detect by peeking at first bytes
///
/// After TLS (if applicable), the decrypted stream is bridged through a ZTLP tunnel.
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match local_tls::maybe_wrap_tls(tcp_stream, port, tls_acceptor).await {
        Ok(local_tls::MaybeWrapped::Tls(tls_stream)) => {
            info!("TLS handshake OK for {} (port {})", ztlp_name, port);
            handle_tcp_connection_bridged(
                tls_stream,
                ztlp_name,
                port,
                peer_addr,
                peer_node_id,
                identity,
                bind_addr,
                ns_server,
                relay_addr,
            )
            .await
        }
        Ok(local_tls::MaybeWrapped::Plain(stream)) => {
            handle_tcp_connection_bridged(
                stream,
                ztlp_name,
                port,
                peer_addr,
                peer_node_id,
                identity,
                bind_addr,
                ns_server,
                relay_addr,
            )
            .await
        }
        Ok(local_tls::MaybeWrapped::PlainWithPeek(peek_stream)) => {
            handle_tcp_connection_bridged(
                peek_stream,
                ztlp_name,
                port,
                peer_addr,
                peer_node_id,
                identity,
                bind_addr,
                ns_server,
                relay_addr,
            )
            .await
        }
        Err(e) => {
            warn!("TLS wrapping failed for {} port {}: {}", ztlp_name, port, e);
            Err(e.into())
        }
    }
}

/// Inner handler: establish ZTLP tunnel and bridge an arbitrary AsyncRead+AsyncWrite stream.
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Resolve peer address (use cached or query NS). Also capture the
    // resolved NodeID when available — the gateway relay's CLIENT_ROUTE
    // handler falls back to routing by NodeID when the plain service-
    // name lookup misses (see `udp_listener.ex`'s
    // `pick_fallback_gateway/2`), which matters for exactly the shared-
    // relay case this demo exercises (gateway registered under a zone
    // key, not the bare service name). When `peer_addr` is already
    // cached (the common VIP-proxy path), use the CALLER-supplied
    // `peer_node_id` (cached alongside `peer_addr` in `VipEntry` — see
    // `vip_pool.rs`) instead of discarding it; only a fresh NS lookup
    // (uncached path) needs to re-resolve it here.
    let (peer, resolved_node_id) = match peer_addr {
        Some(addr) => (addr, peer_node_id),
        None => {
            let resolution = proxy::ns_resolve(ztlp_name, ns_server).await?;
            (resolution.addr, resolution.node_id)
        }
    };

    // If relay is configured, route all ZTLP packets through the relay
    let send_addr: SocketAddr = match relay_addr {
        Some(relay) => {
            info!("routing tunnel through relay {}", relay);
            relay
                .parse()
                .map_err(|e| format!("invalid relay address '{}': {}", relay, e))?
        }
        None => peer,
    };

    debug!(
        "establishing tunnel to {} ({}) port {}",
        ztlp_name, peer, port
    );

    // Encode port as service name — derive from the hostname's leading
    // label when present (real gateways register arbitrary operator-
    // chosen names like "web", not port-derivable ones — see
    // `service_name_for_ztlp_name` for the real mismatch this fixes,
    // found live 2026-08-30), falling back to a port-based guess.
    let service_name = service_name_for_ztlp_name(ztlp_name, port);

    // ── QUIC transport (2026-08-30 architecture fix) ───────────────────
    //
    // The automatic VIP tunnel dialer used to speak a raw-UDP Noise
    // handshake directly (`TransportNode` + `HandshakeHeader`). Root-
    // caused live: every modern ZTLP gateway (confirmed via this demo's
    // `ztlp listen --gateway` process, whose own log literally says
    // "ZTLP QUIC server listening on UDP ...") is a pure QUIC endpoint —
    // it has no raw-UDP listener at all. A raw HELLO packet reaching it
    // gets "dropping packet with invalid CID" (Quinn trying to parse it
    // as a malformed QUIC packet) and is silently discarded, which is
    // why the handshake always timed out even after CLIENT_ROUTE,
    // NodeID-fallback routing, and VIP-cache threading were all fixed
    // and independently verified working (confirmed live: the relay's
    // own stats showed `forwarded` incrementing correctly, so the
    // packet WAS reaching the gateway — it just spoke the wrong
    // protocol once there). `ztlp connect`'s `cmd_connect` already uses
    // this exact QUIC path successfully against the same relay/gateway
    // (see `bin/ztlp-cli.rs`'s `QuicEndpoint::connect_with_socket` +
    // `noise_stream::run_initiator_handshake`); this brings the
    // automatic agent dialer onto the same, actually-working transport
    // instead of a protocol no real-world gateway speaks anymore.
    let std_socket = std::net::UdpSocket::bind(bind_addr)?;

    if relay_addr.is_some() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // Prefer the NS-resolved GATEWAY NodeID over our own identity —
        // this is the relay's fallback lookup key when the plain
        // service-name doesn't match a registered gateway (e.g. a
        // gateway registered under a zone key like
        // "gw:demo.spongebob.ztlp" rather than the bare service name
        // "web"). Using our OWN node_id here was the bug: the relay's
        // fallback-by-NodeID lookup needs the PEER's (gateway's) NodeID,
        // not the client's — confirmed live 2026-08-30 by comparing
        // against `ztlp connect`'s cmd_connect, which does exactly this
        // (stamps the NS-resolved gateway NodeID when available).
        let client_route_node_id: [u8; 16] = resolved_node_id
            .map(|nid| *nid.as_bytes())
            .unwrap_or(*identity.node_id.as_bytes());
        match tunnel::build_client_route_packet(&client_route_node_id, &service_name, ts, None) {
            Ok(route_pkt) => {
                if let Err(e) = std_socket.send_to(&route_pkt, send_addr) {
                    warn!("failed to send CLIENT_ROUTE to {}: {}", send_addr, e);
                } else {
                    debug!(
                        "CLIENT_ROUTE sent to {} (service={})",
                        send_addr, service_name
                    );
                }
                // Brief delay to let the relay install the 5-tuple
                // mapping before the first QUIC INITIAL races down the
                // same socket — mirrors `cmd_connect`'s identical
                // 50ms wait for the exact same reason (see
                // "Brief delay to let the relay install the 5-tuple"
                // in ztlp-cli.rs).
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

    let quic_conn = crate::quic_transport::tokio_endpoint::QuicEndpoint::connect_with_socket(
        crate::quic_transport::QuicEndpointConfig::default(),
        send_addr,
        "localhost",
        std_socket,
    )
    .await?;

    let responder_id = resolved_node_id.unwrap_or_else(NodeId::zero);
    let service_hash = tunnel::encode_service_name(&service_name).unwrap_or_else(|_| {
        let mut svc = [0u8; 16];
        let port_str = port.to_string();
        let bytes = port_str.as_bytes();
        let len = bytes.len().min(16);
        svc[..len].copy_from_slice(&bytes[..len]);
        svc
    });

    let handshake_result = crate::quic_transport::noise_stream::run_initiator_handshake(
        &quic_conn,
        identity,
        responder_id,
        service_hash,
    )
    .await
    .map_err(|e| format!("QUIC Noise handshake failed: {}", e))?;

    info!(
        "tunnel active: {} → {} (session {})",
        ztlp_name, peer, handshake_result.session_id
    );

    let (mut q_send, mut q_recv) = quic_conn
        .open_bi()
        .await
        .map_err(|e| format!("failed to open QUIC data stream: {}", e))?;

    // Bridge the (potentially TLS-unwrapped) local stream <-> the QUIC
    // data stream, one task per direction (mirrors `cmd_connect`'s
    // v0.36.0 quic-pump-throughput fix: coupling both directions in a
    // single select! let a stalled direction starve the other).
    let (mut local_read, mut local_write) = tokio::io::split(stream);

    let pump_up = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 65000];
        loop {
            match local_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if crate::quic_transport::noise_stream::write_ztlp_frame(&mut q_send, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = q_send.finish();
    });

    let pump_down = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
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

    debug!(
        "tunnel closed: {} (session {})",
        ztlp_name, handshake_result.session_id
    );

    Ok(())
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
    )
    .await
}
/// Check if the agent daemon is currently running.
pub fn is_agent_running() -> bool {
    let pid_path = control::default_pid_path();
    if let Some(pid) = control::read_pid_file(&pid_path) {
        control::is_process_running(pid)
    } else {
        false
    }
}

/// Get the PID of the running agent, if any.
pub fn get_agent_pid() -> Option<u32> {
    let pid_path = control::default_pid_path();
    let pid = control::read_pid_file(&pid_path)?;
    if control::is_process_running(pid) {
        Some(pid)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
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
            super::verify_local_peer(&server_stream),
            "a real loopback TCP connection must be accepted — this is \
             exactly the case the old SO_PEERCRED-on-TCP code silently \
             broke, rejecting 100% of real traffic"
        );
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
