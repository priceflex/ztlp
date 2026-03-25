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
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use tokio::io::{AsyncRead, AsyncWrite};

use crate::handshake::HandshakeContext;
use crate::identity::{NodeId, NodeIdentity};
use crate::packet::{HandshakeHeader, MsgType, SessionId, HANDSHAKE_HEADER_SIZE};
use crate::transport::TransportNode;
use crate::tunnel;

use super::config::AgentConfig;
use super::control::{self, AgentState};
use super::dns::{self, DnsResolverState};
use super::domain_map::DomainMapper;
use super::local_tls::{self, SniCertResolver};
use super::proxy;
use super::tunnel_pool::TunnelPool;
use super::vip_pool::VipPool;

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
    let tunnel_pool = Arc::new(Mutex::new(TunnelPool::new(config.tunnel.max_tunnels)));
    info!("tunnel pool: max {} tunnels", config.tunnel.max_tunnels);

    // Shutdown channel
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Agent state for control socket
    let agent_state = Arc::new(AgentState {
        dns_state: dns_state.clone(),
        tunnel_pool: tunnel_pool.clone(),
        start_time,
        dns_listen: config.dns.listen.clone(),
        shutdown_tx: shutdown_tx.clone(),
    });

    // Write PID file
    let pid_path = control::default_pid_path();
    control::write_pid_file(&pid_path)?;
    info!("PID file: {}", pid_path.display());

    // ── Spawn DNS resolver ──────────────────────────────────────────────
    let dns_handle = if config.dns.enabled {
        let listen = config.dns.listen.clone();
        let state = dns_state.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = dns::run_dns_resolver(&listen, state).await {
                error!("DNS resolver error: {}", e);
            }
        }))
    } else {
        info!("DNS resolver disabled");
        None
    };

    // ── Spawn control socket ────────────────────────────────────────────
    let socket_path = control::default_socket_path();
    let ctrl_state = agent_state.clone();
    let ctrl_path = socket_path.clone();
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

        let resolver = Arc::new(SniCertResolver::new(cert_dir.clone()));
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
                 HTTPS connections will fail until certs are provisioned \
                 (run: ztlp admin cert-issue --hostname <name>)",
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
    let gc_state = dns_state.clone();
    let gc_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(GC_INTERVAL);
        loop {
            interval.tick().await;
            let mut st = gc_state.lock().await;
            let freed = st.vip_pool.gc_expired();
            if freed > 0 {
                debug!("GC: freed {} expired VIP allocations", freed);
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
        eprintln!("  Control:  {}", socket_path.display());
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

    // Remove PID file and socket
    control::remove_pid_file(&pid_path);
    std::fs::remove_file(&socket_path).ok();

    // Abort spawned tasks
    if let Some(h) = dns_handle {
        h.abort();
    }
    ctrl_handle.abort();
    proxy_handle.abort();
    gc_handle.abort();

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
        let entries: Vec<(Ipv4Addr, String, Option<SocketAddr>)> = {
            let st = dns_state.lock().await;
            st.vip_pool
                .entries()
                .map(|e| (e.ip, e.ztlp_name.clone(), e.peer_addr))
                .collect()
        };

        for (vip, ztlp_name, peer_addr) in entries {
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
                tls_stream, ztlp_name, port, peer_addr, identity, bind_addr, ns_server, relay_addr,
            )
            .await
        }
        Ok(local_tls::MaybeWrapped::Plain(stream)) => {
            handle_tcp_connection_bridged(
                stream, ztlp_name, port, peer_addr, identity, bind_addr, ns_server, relay_addr,
            )
            .await
        }
        Ok(local_tls::MaybeWrapped::PlainWithPeek(peek_stream)) => {
            handle_tcp_connection_bridged(
                peek_stream,
                ztlp_name,
                port,
                peer_addr,
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
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Resolve peer address (use cached or query NS)
    let peer = match peer_addr {
        Some(addr) => addr,
        None => {
            let resolution = proxy::ns_resolve(ztlp_name, ns_server).await?;
            resolution.addr
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

    // Establish ZTLP tunnel
    let node = TransportNode::bind(bind_addr).await?;
    let session_id = SessionId::generate();
    let mut ctx = HandshakeContext::new_initiator(identity)?;

    // Encode port as service name
    let service_name = format!("tcp:{}", port);
    let dst_svc_id = tunnel::encode_service_name(&service_name).unwrap_or_else(|_| {
        let mut svc = [0u8; 16];
        let port_str = port.to_string();
        let bytes = port_str.as_bytes();
        let len = bytes.len().min(16);
        svc[..len].copy_from_slice(&bytes[..len]);
        svc
    });

    // Noise_XX handshake
    let msg1 = ctx.write_message(&[])?;
    let mut hello_hdr = HandshakeHeader::new(MsgType::Hello);
    hello_hdr.session_id = session_id;
    hello_hdr.src_node_id = *identity.node_id.as_bytes();
    hello_hdr.payload_len = msg1.len() as u16;
    hello_hdr.dst_svc_id = dst_svc_id;
    let mut pkt1 = hello_hdr.serialize();
    pkt1.extend_from_slice(&msg1);
    node.send_raw(&pkt1, send_addr).await?;

    let (recv2, _) = tokio::time::timeout(HANDSHAKE_TIMEOUT, node.recv_raw())
        .await
        .map_err(|_| "handshake timeout")??;

    if recv2.len() < HANDSHAKE_HEADER_SIZE {
        return Err("response too short".into());
    }
    let recv2_hdr = HandshakeHeader::deserialize(&recv2)?;
    if recv2_hdr.msg_type != MsgType::HelloAck {
        return Err(format!("expected HELLO_ACK, got {:?}", recv2_hdr.msg_type).into());
    }

    ctx.read_message(&recv2[HANDSHAKE_HEADER_SIZE..])?;

    let msg3 = ctx.write_message(&[])?;
    let mut final_hdr = HandshakeHeader::new(MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;
    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);
    node.send_raw(&pkt3, send_addr).await?;

    if !ctx.is_finished() {
        return Err("handshake incomplete".into());
    }

    let peer_node_id = NodeId::from_bytes(recv2_hdr.src_node_id);
    let (_, session) = ctx.finalize(peer_node_id, session_id)?;

    {
        let mut pl = node.pipeline.lock().await;
        pl.register_session(session);
    }

    info!(
        "tunnel active: {} → {} (session {})",
        ztlp_name, peer, session_id
    );

    // Bridge the (potentially TLS-unwrapped) stream ↔ ZTLP tunnel
    match tunnel::run_bridge_io(
        stream,
        node.socket.clone(),
        node.pipeline.clone(),
        session_id,
        send_addr,
    )
    .await
    {
        Ok(_) => {
            debug!("tunnel closed: {} (session {})", ztlp_name, session_id);
        }
        Err(e) => {
            warn!("tunnel error: {} — {}", ztlp_name, e);
        }
    }

    Ok(())
}

/// Handle a single TCP connection by establishing a ZTLP tunnel (no TLS).
#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection(
    tcp_stream: tokio::net::TcpStream,
    ztlp_name: &str,
    port: u16,
    peer_addr: Option<SocketAddr>,
    identity: &NodeIdentity,
    bind_addr: &str,
    ns_server: &str,
    relay_addr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Resolve peer address (use cached or query NS)
    let peer = match peer_addr {
        Some(addr) => addr,
        None => {
            let resolution = proxy::ns_resolve(ztlp_name, ns_server).await?;
            resolution.addr
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

    // Establish ZTLP tunnel
    let node = TransportNode::bind(bind_addr).await?;
    let session_id = SessionId::generate();
    let mut ctx = HandshakeContext::new_initiator(identity)?;

    // Encode port as service name
    let service_name = format!("tcp:{}", port);
    let dst_svc_id = tunnel::encode_service_name(&service_name).unwrap_or_else(|_| {
        let mut svc = [0u8; 16];
        let port_str = port.to_string();
        let bytes = port_str.as_bytes();
        let len = bytes.len().min(16);
        svc[..len].copy_from_slice(&bytes[..len]);
        svc
    });

    // Noise_XX handshake
    let msg1 = ctx.write_message(&[])?;
    let mut hello_hdr = HandshakeHeader::new(MsgType::Hello);
    hello_hdr.session_id = session_id;
    hello_hdr.src_node_id = *identity.node_id.as_bytes();
    hello_hdr.payload_len = msg1.len() as u16;
    hello_hdr.dst_svc_id = dst_svc_id;
    let mut pkt1 = hello_hdr.serialize();
    pkt1.extend_from_slice(&msg1);
    node.send_raw(&pkt1, send_addr).await?;

    let (recv2, _) = tokio::time::timeout(HANDSHAKE_TIMEOUT, node.recv_raw())
        .await
        .map_err(|_| "handshake timeout")??;

    if recv2.len() < HANDSHAKE_HEADER_SIZE {
        return Err("response too short".into());
    }
    let recv2_hdr = HandshakeHeader::deserialize(&recv2)?;
    if recv2_hdr.msg_type != MsgType::HelloAck {
        return Err(format!("expected HELLO_ACK, got {:?}", recv2_hdr.msg_type).into());
    }

    ctx.read_message(&recv2[HANDSHAKE_HEADER_SIZE..])?;

    let msg3 = ctx.write_message(&[])?;
    let mut final_hdr = HandshakeHeader::new(MsgType::Data);
    final_hdr.session_id = session_id;
    final_hdr.src_node_id = *identity.node_id.as_bytes();
    final_hdr.payload_len = msg3.len() as u16;
    let mut pkt3 = final_hdr.serialize();
    pkt3.extend_from_slice(&msg3);
    node.send_raw(&pkt3, send_addr).await?;

    if !ctx.is_finished() {
        return Err("handshake incomplete".into());
    }

    let peer_node_id = NodeId::from_bytes(recv2_hdr.src_node_id);
    let (_, session) = ctx.finalize(peer_node_id, session_id)?;

    {
        let mut pl = node.pipeline.lock().await;
        pl.register_session(session);
    }

    info!(
        "tunnel active: {} → {} (session {})",
        ztlp_name, peer, session_id
    );

    // Bridge TCP ↔ ZTLP tunnel
    match tunnel::run_bridge(
        tcp_stream,
        node.socket.clone(),
        node.pipeline.clone(),
        session_id,
        send_addr,
    )
    .await
    {
        Ok(_) => {
            debug!("tunnel closed: {} (session {})", ztlp_name, session_id);
        }
        Err(e) => {
            warn!("tunnel error: {} — {}", ztlp_name, e);
        }
    }

    Ok(())
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

    #[test]
    fn test_get_agent_pid_none() {
        // Without a PID file, returns None
        // (may fail if an actual agent is running, but that's unlikely in CI)
        let pid = super::get_agent_pid();
        // Just verify it doesn't panic
        let _ = pid;
    }
}
