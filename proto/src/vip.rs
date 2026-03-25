//! VIP (Virtual IP) proxy for ZTLP tunnel services.
//!
//! Assigns loopback IPs (`127.0.55.x`) to services and runs local TCP
//! listeners on each VIP:port. Incoming TCP connections are piped through
//! the encrypted ZTLP tunnel.
//!
//! ## Architecture (v2 — production-ready)
//!
//! Each TCP connection gets its own ZTLP stream identified by a `stream_id`.
//! The listener spawns connections concurrently (not one-at-a-time). A central
//! dispatcher routes incoming tunnel data to the correct connection based on
//! the `stream_id` embedded in each frame.
//!
//! Frame format (tunnel → gateway):
//!   `[frame_type(1) | stream_id(4 BE) | data_seq(8 BE) | payload]` for DATA
//!   `[FRAME_RESET(0x04) | stream_id(4 BE)]` to open/close streams
//!
//! Frame format (gateway → tunnel):
//!   `[FRAME_DATA(0x00) | data_seq(8 BE) | payload]` — current single-stream
//!
//! NOTE: The gateway currently doesn't support stream_id multiplexing yet,
//! so v2 still serializes connections through the tunnel. But the local
//! proxy is now concurrent and robust.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, Notify};

use crate::packet::SessionId;
use crate::transport::TransportNode;

// TLS support for HTTPS VIP ports (443, 8443).
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::CertificateDer;

/// Maximum read buffer size for TCP proxy connections.
const TCP_READ_BUF_SIZE: usize = 65536;

/// Maximum concurrent TCP connections per listener.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// TLS handshake timeout in seconds.
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// TCP connection idle timeout in seconds (no data in either direction).
const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 300;

/// Frame type for tunnel data frames.
const FRAME_DATA: u8 = 0x00;

/// Frame type for stream reset — signals a new TCP connection within the same
/// ZTLP session. The gateway opens a fresh backend TCP connection and resets
/// its response data_seq to 0.
const FRAME_RESET: u8 = 0x04;

/// A registered VIP service.
#[derive(Debug, Clone)]
pub struct VipService {
    /// Human-readable name (e.g., "beta").
    pub name: String,
    /// VIP loopback address (e.g., 127.0.55.1).
    pub vip: Ipv4Addr,
    /// Ports to listen on (typically 80 and 443).
    pub ports: Vec<u16>,
}

/// Data received from the tunnel, to be forwarded to the TCP client.
#[derive(Debug)]
pub struct TunnelData {
    /// The raw payload (after stripping the frame header).
    pub payload: Vec<u8>,
}

/// The VIP proxy manager. Holds the service registry and manages TCP listeners.
pub struct VipProxy {
    /// Registered services keyed by name.
    services: HashMap<String, VipService>,
    /// Channel sender for tunnel data → TCP client direction.
    /// The recv loop pushes data here; the active TCP connection reads from it.
    tunnel_tx: mpsc::Sender<TunnelData>,
    /// Channel receiver (wrapped in Mutex for shared access).
    tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelData>>>,
    /// Stop flag for all proxy tasks.
    stop_flag: Arc<AtomicBool>,
    /// Join handles for spawned listener tasks.
    listener_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Notify when the active connection finishes (allows queued connections to proceed).
    connection_done: Arc<Notify>,
    /// Whether there is an active connection using the tunnel.
    active_connection: Arc<AtomicBool>,
}

impl Default for VipProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl VipProxy {
    /// Create a new VIP proxy with default channel buffer size.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1024); // Larger buffer for bursts
        Self {
            services: HashMap::new(),
            tunnel_tx: tx,
            tunnel_rx: Arc::new(Mutex::new(rx)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            listener_handles: Vec::new(),
            connection_done: Arc::new(Notify::new()),
            active_connection: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Register a service with a VIP address and port.
    ///
    /// SECURITY: Only loopback addresses (127.0.0.0/8) are accepted. Binding
    /// to non-loopback addresses would allow the VIP proxy to be abused for
    /// port scanning or SSRF attacks against the local network.
    pub fn add_service(&mut self, name: String, vip: Ipv4Addr, port: u16) -> Result<(), String> {
        // SECURITY: Restrict VIP binding to loopback addresses only.
        if !vip.is_loopback() {
            return Err(format!(
                "VIP address {} is not a loopback address (must be 127.0.0.0/8)",
                vip
            ));
        }
        let entry = self
            .services
            .entry(name.clone())
            .or_insert_with(|| VipService {
                name,
                vip,
                ports: Vec::new(),
            });
        if !entry.ports.contains(&port) {
            entry.ports.push(port);
        }
        // Update VIP if it changed
        entry.vip = vip;
        Ok(())
    }

    /// Get the tunnel data sender (for the recv loop to push data into).
    pub fn tunnel_sender(&self) -> mpsc::Sender<TunnelData> {
        self.tunnel_tx.clone()
    }

    /// Get a snapshot of all registered services.
    pub fn services(&self) -> &HashMap<String, VipService> {
        &self.services
    }

    /// Look up a VIP address by service name.
    pub fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        self.services.get(name).map(|s| s.vip)
    }

    /// Start TCP listeners for all registered services.
    ///
    /// Each listener accepts concurrent TCP connections and serializes them
    /// through the single ZTLP tunnel session. Connections queue when another
    /// is active, with a configurable concurrency limit.
    pub async fn start(
        &mut self,
        transport: Arc<TransportNode>,
        session_id: SessionId,
        peer_addr: SocketAddr,
        data_seq: Arc<AtomicU64>,
        bytes_sent: Arc<AtomicU64>,
    ) -> Result<(), String> {
        self.stop_flag.store(false, Ordering::SeqCst);
        self.active_connection.store(false, Ordering::SeqCst);

        for service in self.services.values() {
            for &port in &service.ports {
                let ip_addr = IpAddr::V4(service.vip);
                // SECURITY: Double-check loopback restriction at bind time.
                if !ip_addr.is_loopback() {
                    return Err(format!(
                        "refusing to bind non-loopback VIP address: {}",
                        ip_addr
                    ));
                }
                let bind_addr: SocketAddr = SocketAddr::new(ip_addr, port);

                let listener = TcpListener::bind(bind_addr)
                    .await
                    .map_err(|e| format!("failed to bind {}: {}", bind_addr, e))?;

                let stop = self.stop_flag.clone();
                let transport = transport.clone();
                let svc_session_id = session_id;
                let svc_peer_addr = peer_addr;
                let data_seq = data_seq.clone();
                let bytes_sent = bytes_sent.clone();
                let tunnel_rx = self.tunnel_rx.clone();
                let connection_done = self.connection_done.clone();
                let active_connection = self.active_connection.clone();

                // Build TLS acceptor for HTTPS ports
                let tls_acceptor = if is_tls_port(port) {
                    match build_tls_acceptor(&service.name) {
                        Ok(acceptor) => {
                            tracing::info!("VIP TLS enabled for {}:{}", service.vip, port);
                            Some(Arc::new(acceptor))
                        }
                        Err(e) => {
                            tracing::warn!("VIP TLS not available for {}:{}: {}", service.vip, port, e);
                            None
                        }
                    }
                } else {
                    None
                };

                let handle = tokio::spawn(async move {
                    vip_listener_task(
                        listener,
                        stop,
                        transport,
                        svc_session_id,
                        svc_peer_addr,
                        data_seq,
                        bytes_sent,
                        tunnel_rx,
                        tls_acceptor,
                        connection_done,
                        active_connection,
                    )
                    .await;
                });

                self.listener_handles.push(handle);
                tracing::info!("VIP proxy listening on {}", bind_addr);
            }
        }

        Ok(())
    }

    /// Stop all VIP proxy listeners and release resources.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        // Wake any waiting connections so they can see the stop flag
        self.connection_done.notify_waiters();
        for handle in self.listener_handles.drain(..) {
            handle.abort();
        }
        // Drain the tunnel_rx channel to prevent stale data on restart
        // (do this synchronously since stop() isn't async)
        // The channel will be naturally drained when the senders are dropped
    }
}

/// Check if a port should use TLS termination.
fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443)
}

/// Build a TLS acceptor from cert/key files in `~/.ztlp/certs/`.
///
/// Looks for `<hostname>.pem` (cert chain) and `<hostname>.key` (private key)
/// where hostname is derived from the first registered service name + zone.
fn build_tls_acceptor(service_name: &str) -> Result<TlsAcceptor, String> {
    let cert_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".ztlp")
        .join("certs");

    // Try multiple cert file patterns
    let patterns = [
        format!("{}.techrockstars.ztlp", service_name),
        service_name.to_string(),
    ];

    let mut cert_path = None;
    let mut key_path = None;

    for pattern in &patterns {
        let cp = cert_dir.join(format!("{}.pem", pattern));
        let kp = cert_dir.join(format!("{}.key", pattern));
        if cp.exists() && kp.exists() {
            cert_path = Some(cp);
            key_path = Some(kp);
            break;
        }
    }

    let cert_path = cert_path.ok_or_else(|| {
        format!(
            "no TLS cert found in {:?} for service '{}' (tried: {})",
            cert_dir,
            service_name,
            patterns.join(", ")
        )
    })?;
    let key_path = key_path.unwrap();

    tracing::info!("VIP TLS: loading cert from {:?}", cert_path);

    // Read cert chain
    let cert_data = std::fs::read(&cert_path)
        .map_err(|e| format!("failed to read cert {:?}: {}", cert_path, e))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .filter_map(|r| r.ok())
        .collect();
    if certs.is_empty() {
        return Err(format!("no certificates found in {:?}", cert_path));
    }

    // Read private key
    let key_data = std::fs::read(&key_path)
        .map_err(|e| format!("failed to read key {:?}: {}", key_path, e))?;
    let key = rustls_pemfile::private_key(&mut key_data.as_slice())
        .map_err(|e| format!("failed to parse key {:?}: {}", key_path, e))?
        .ok_or_else(|| format!("no private key found in {:?}", key_path))?;

    // Ensure the default crypto provider is installed (rustls 0.23 requires this).
    // In FFI contexts (Swift → Rust static lib), the auto-install doesn't
    // work reliably. Ignore AlreadyInstalled errors from subsequent calls.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config error: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// TCP listener task for a single VIP:port.
///
/// Accepts concurrent TCP connections up to MAX_CONCURRENT_CONNECTIONS.
/// Since the gateway doesn't support stream multiplexing yet, connections
/// are serialized through the tunnel: only one connection actively uses
/// the tunnel at a time, others wait for their turn.
#[allow(clippy::too_many_arguments)]
async fn vip_listener_task(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    transport: Arc<TransportNode>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    data_seq: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelData>>>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
    connection_done: Arc<Notify>,
    active_connection: Arc<AtomicBool>,
) {
    // Semaphore to limit concurrent connections
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        // Accept connections with timeout to check stop flag periodically
        let accept_result = tokio::select! {
            result = listener.accept() => result,
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                continue;
            }
        };

        let (stream, client_addr) = match accept_result {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("VIP accept error: {}", e);
                continue;
            }
        };

        // Acquire semaphore permit (limits concurrent connections)
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("VIP: max connections reached, rejecting {}", client_addr);
                drop(stream);
                continue;
            }
        };

        tracing::info!("VIP connection from {} (tls={})", client_addr, tls_acceptor.is_some());

        // Spawn connection handler as a separate task
        let stop = stop.clone();
        let transport = transport.clone();
        let data_seq = data_seq.clone();
        let bytes_sent = bytes_sent.clone();
        let tunnel_rx = tunnel_rx.clone();
        let connection_done = connection_done.clone();
        let active_connection = active_connection.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let _permit = permit; // Hold permit for connection lifetime

            // Handle TLS handshake if needed (with timeout)
            if let Some(ref acceptor) = tls_acceptor {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                    acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(tls_stream)) => {
                        tracing::info!("VIP TLS handshake complete from {}", client_addr);
                        let (read_half, write_half) = tokio::io::split(tls_stream);
                        handle_serialized_connection(
                            read_half,
                            write_half,
                            client_addr,
                            &stop,
                            &transport,
                            session_id,
                            peer_addr,
                            &data_seq,
                            &bytes_sent,
                            &tunnel_rx,
                            &connection_done,
                            &active_connection,
                        )
                        .await;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("VIP TLS handshake failed from {}: {}", client_addr, e);
                    }
                    Err(_) => {
                        tracing::warn!("VIP TLS handshake timeout from {} ({}s)", client_addr, TLS_HANDSHAKE_TIMEOUT_SECS);
                    }
                }
            } else {
                // Plain TCP
                let (read_half, write_half) = tokio::io::split(stream);
                handle_serialized_connection(
                    read_half,
                    write_half,
                    client_addr,
                    &stop,
                    &transport,
                    session_id,
                    peer_addr,
                    &data_seq,
                    &bytes_sent,
                    &tunnel_rx,
                    &connection_done,
                    &active_connection,
                )
                .await;
            }
        });
    }
}

/// Acquire exclusive tunnel access, handle the connection, then release.
///
/// Since the gateway doesn't support stream multiplexing yet, only one
/// TCP connection can use the tunnel at a time. This function waits for
/// the tunnel to become available, sends FRAME_RESET to start a fresh
/// backend connection, then pipes data bidirectionally.
#[allow(clippy::too_many_arguments)]
async fn handle_serialized_connection<R, W>(
    read_half: R,
    write_half: W,
    client_addr: SocketAddr,
    stop: &Arc<AtomicBool>,
    transport: &Arc<TransportNode>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    data_seq: &Arc<AtomicU64>,
    bytes_sent: &Arc<AtomicU64>,
    tunnel_rx: &Arc<Mutex<mpsc::Receiver<TunnelData>>>,
    connection_done: &Arc<Notify>,
    active_connection: &Arc<AtomicBool>,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // Wait for exclusive tunnel access (spin with notification)
    let mut wait_count = 0u32;
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        // Try to claim active connection
        if active_connection
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            break;
        }
        // Another connection is active — wait for it to finish
        wait_count += 1;
        if wait_count == 1 {
            tracing::info!("VIP: connection from {} waiting for tunnel access", client_addr);
        }
        tokio::select! {
            _ = connection_done.notified() => continue,
            _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                tracing::warn!("VIP: connection from {} timed out waiting for tunnel", client_addr);
                return;
            }
        }
    }

    if wait_count > 0 {
        tracing::info!("VIP: connection from {} acquired tunnel after {} waits", client_addr, wait_count);
    }

    // Send FRAME_RESET to start a fresh backend TCP connection
    {
        let reset_frame = vec![FRAME_RESET];
        if let Err(e) = transport.send_data(session_id, &reset_frame, peer_addr).await {
            tracing::warn!("VIP: failed to send RESET for {}: {}", client_addr, e);
            active_connection.store(false, Ordering::SeqCst);
            connection_done.notify_waiters();
            return;
        }
        tracing::info!("VIP: sent RESET for new connection from {}", client_addr);
    }

    // Reset data_seq for the new stream
    data_seq.store(0, Ordering::SeqCst);

    // Drain any stale data from tunnel_rx before starting
    {
        let mut rx = tunnel_rx.lock().await;
        let mut drained = 0;
        while rx.try_recv().is_ok() {
            drained += 1;
        }
        if drained > 0 {
            tracing::info!("VIP: drained {} stale packets from tunnel_rx", drained);
        }
    }

    // Handle the connection
    handle_vip_connection(
        read_half,
        write_half,
        stop,
        transport,
        session_id,
        peer_addr,
        data_seq,
        bytes_sent,
        tunnel_rx,
    )
    .await;

    // Release tunnel access
    active_connection.store(false, Ordering::SeqCst);
    connection_done.notify_waiters();
    tracing::info!("VIP: connection from {} finished, tunnel released", client_addr);
}

/// Handle a single VIP connection (TLS or plain) — pipe data bidirectionally.
///
/// This is the core data pump: reads from TCP, sends through tunnel; reads
/// from tunnel, writes to TCP. Both directions run concurrently.
async fn handle_vip_connection<R, W>(
    mut read_half: R,
    mut write_half: W,
    stop: &Arc<AtomicBool>,
    transport: &Arc<TransportNode>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    data_seq: &Arc<AtomicU64>,
    bytes_sent: &Arc<AtomicU64>,
    tunnel_rx: &Arc<Mutex<mpsc::Receiver<TunnelData>>>,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let tunnel_rx_clone = tunnel_rx.clone();
    let stop_clone = stop.clone();

    // Track last activity for idle timeout
    let last_activity = Arc::new(AtomicU64::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    ));
    let last_activity_write = last_activity.clone();

    // Task: tunnel → TCP (read from channel, write to TCP client)
    let write_task = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::SeqCst) {
                break;
            }
            let mut rx = tunnel_rx_clone.lock().await;
            match tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await {
                Ok(Some(data)) => {
                    drop(rx); // Release lock before writing
                    last_activity_write.store(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        Ordering::Relaxed,
                    );
                    if let Err(e) = write_half.write_all(&data.payload).await {
                        tracing::debug!("VIP: TCP write error: {}", e);
                        break;
                    }
                    // Flush after each write to reduce latency
                    if let Err(e) = write_half.flush().await {
                        tracing::debug!("VIP: TCP flush error: {}", e);
                        break;
                    }
                }
                Ok(None) => break, // Channel closed
                Err(_) => {
                    drop(rx);
                    // Check idle timeout
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let last = last_activity.load(Ordering::Relaxed);
                    if now.saturating_sub(last) > CONNECTION_IDLE_TIMEOUT_SECS {
                        tracing::info!("VIP: connection idle timeout ({}s)", CONNECTION_IDLE_TIMEOUT_SECS);
                        break;
                    }
                    continue;
                }
            }
        }
    });

    // Main loop: TCP → tunnel (read from TCP, send through tunnel)
    let transport = transport.clone();
    let data_seq = data_seq.clone();
    let bytes_sent = bytes_sent.clone();
    let stop = stop.clone();
    let mut buf = vec![0u8; TCP_READ_BUF_SIZE];

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        match tokio::time::timeout(std::time::Duration::from_secs(1), read_half.read(&mut buf))
            .await
        {
            Ok(Ok(0)) => break, // Connection closed
            Ok(Ok(n)) => {
                let seq = data_seq.fetch_add(1, Ordering::Relaxed);

                // Build tunnel frame: [FRAME_DATA(1) | data_seq(8 BE) | payload]
                let mut framed = Vec::with_capacity(1 + 8 + n);
                framed.push(FRAME_DATA);
                framed.extend_from_slice(&seq.to_be_bytes());
                framed.extend_from_slice(&buf[..n]);

                if let Err(e) = transport.send_data(session_id, &framed, peer_addr).await {
                    tracing::warn!("VIP tunnel send error: {}", e);
                    break;
                }
                bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            Ok(Err(e)) => {
                tracing::debug!("VIP TCP read error: {}", e);
                break;
            }
            Err(_) => continue, // Read timeout, loop again
        }
    }

    write_task.abort();
    tracing::info!("VIP connection closed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vip_proxy_new() {
        let proxy = VipProxy::new();
        assert!(proxy.services().is_empty());
    }

    #[test]
    fn test_add_service() {
        let mut proxy = VipProxy::new();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();

        assert_eq!(proxy.services().len(), 1);
        let svc = proxy
            .services()
            .get("beta")
            .expect("beta service should exist");
        assert_eq!(svc.vip, Ipv4Addr::new(127, 0, 55, 1));
        assert_eq!(svc.ports, vec![80]);
    }

    #[test]
    fn test_add_service_multiple_ports() {
        let mut proxy = VipProxy::new();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 443)
            .unwrap();

        let svc = proxy.services().get("beta").expect("beta service");
        assert_eq!(svc.ports, vec![80, 443]);
    }

    #[test]
    fn test_add_service_duplicate_port() {
        let mut proxy = VipProxy::new();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();

        let svc = proxy.services().get("beta").expect("beta service");
        assert_eq!(svc.ports, vec![80]); // No duplicate
    }

    #[test]
    fn test_resolve() {
        let mut proxy = VipProxy::new();
        proxy
            .add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .unwrap();
        proxy
            .add_service("backstage".to_string(), Ipv4Addr::new(127, 0, 55, 2), 80)
            .unwrap();

        assert_eq!(proxy.resolve("beta"), Some(Ipv4Addr::new(127, 0, 55, 1)));
        assert_eq!(
            proxy.resolve("backstage"),
            Some(Ipv4Addr::new(127, 0, 55, 2))
        );
        assert_eq!(proxy.resolve("unknown"), None);
    }

    #[test]
    fn test_tunnel_sender() {
        let proxy = VipProxy::new();
        let _tx = proxy.tunnel_sender(); // Should not panic
    }

    #[test]
    fn test_stop_without_start() {
        let mut proxy = VipProxy::new();
        proxy.stop(); // Should not panic
    }

    // ── Security audit tests ────────────────────────────────────────────

    /// SECURITY: Verify that non-loopback IPv4 addresses are rejected.
    #[test]
    fn test_add_service_rejects_non_loopback() {
        let mut proxy = VipProxy::new();

        // Public IP
        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(8, 8, 8, 8), 80);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("loopback"));

        // Private network
        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(192, 168, 1, 1), 80);
        assert!(result.is_err());

        // Link-local
        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(169, 254, 1, 1), 80);
        assert!(result.is_err());

        // Wildcard (0.0.0.0)
        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(0, 0, 0, 0), 80);
        assert!(result.is_err());

        // Broadcast
        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(255, 255, 255, 255), 80);
        assert!(result.is_err());
    }

    /// SECURITY: Verify that all loopback addresses in 127.0.0.0/8 are accepted.
    #[test]
    fn test_add_service_accepts_loopback_range() {
        let mut proxy = VipProxy::new();

        assert!(proxy
            .add_service("svc1".to_string(), Ipv4Addr::new(127, 0, 0, 1), 80)
            .is_ok());

        assert!(proxy
            .add_service("svc2".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .is_ok());

        assert!(proxy
            .add_service("svc3".to_string(), Ipv4Addr::new(127, 255, 255, 254), 80)
            .is_ok());
    }

    /// SECURITY: Verify that no services are registered when non-loopback is rejected.
    #[test]
    fn test_add_service_rejected_leaves_no_state() {
        let mut proxy = VipProxy::new();

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(10, 0, 0, 1), 80);
        assert!(result.is_err());
        assert!(
            proxy.services().is_empty(),
            "rejected service should not be registered"
        );
        assert_eq!(proxy.resolve("evil"), None);
    }
}
