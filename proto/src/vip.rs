//! VIP (Virtual IP) proxy for ZTLP tunnel services.
//!
//! Assigns loopback IPs (`127.0.55.x`) to services and runs local TCP
//! listeners on each VIP:port. Incoming TCP connections are piped through
//! the encrypted ZTLP tunnel.
//!
//! ## Architecture (v3 — stream multiplexing)
//!
//! Each TCP connection gets its own stream_id. The client sends FRAME_OPEN
//! to create a backend connection on the gateway, FRAME_DATA with stream_id
//! to forward data, and FRAME_CLOSE to tear down. The gateway responds with
//! FRAME_DATA tagged by stream_id, and FRAME_FIN/FRAME_CLOSE per stream.
//!
//! A `StreamDispatcher` routes incoming tunnel data to per-connection channels
//! based on stream_id. No serialization — all connections run concurrently.
//!
//! Frame format (client → gateway):
//!   `[FRAME_OPEN(0x06) | stream_id(4 BE)]` — open stream
//!   `[FRAME_DATA(0x00) | stream_id(4 BE) | payload]` — data
//!   `[FRAME_CLOSE(0x05) | stream_id(4 BE)]` — close stream
//!
//! Frame format (gateway → client):
//!   `[FRAME_DATA(0x00) | stream_id(4 BE) | data_seq(8 BE) | payload]` — data
//!   `[FRAME_FIN(0x02) | stream_id(4 BE)]` — stream finished (backend closed)
//!   `[FRAME_CLOSE(0x05) | stream_id(4 BE)]` — stream error/closed

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::packet::SessionId;
use crate::transport::TransportNode;

// TLS support for HTTPS VIP ports (443, 8443).
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

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

/// Frame type for closing a multiplexed stream.
const FRAME_CLOSE: u8 = 0x05;

/// Frame type for opening a new multiplexed stream.
const FRAME_OPEN: u8 = 0x06;

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
    /// Stream ID this data belongs to (0 = legacy single-stream).
    pub stream_id: u32,
    /// The raw payload (after stripping the frame header).
    pub payload: Vec<u8>,
}

/// Stream dispatcher: routes incoming tunnel data to per-connection channels.
///
/// Each TCP connection registers with a stream_id and gets a dedicated
/// mpsc::Sender. The recv_loop dispatches tunnel data by stream_id.
pub struct StreamDispatcher {
    streams: std::sync::Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
}

impl Default for StreamDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamDispatcher {
    pub fn new() -> Self {
        Self {
            streams: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Register a new stream and return the receiver for it.
    pub fn register(&self, stream_id: u32) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(256);
        if let Ok(mut streams) = self.streams.lock() {
            streams.insert(stream_id, tx);
        }
        rx
    }

    /// Unregister a stream (called when connection closes).
    pub fn unregister(&self, stream_id: u32) {
        if let Ok(mut streams) = self.streams.lock() {
            streams.remove(&stream_id);
        }
    }

    /// Dispatch data to the appropriate stream. Returns false if stream not found.
    pub fn dispatch(&self, stream_id: u32, data: Vec<u8>) -> bool {
        if let Ok(streams) = self.streams.lock() {
            if let Some(tx) = streams.get(&stream_id) {
                return tx.try_send(data).is_ok();
            }
        }
        false
    }

    /// Signal that a stream has been closed by the remote side (drop the sender).
    pub fn close_stream(&self, stream_id: u32) {
        self.unregister(stream_id);
    }

    /// Number of active streams.
    pub fn stream_count(&self) -> usize {
        self.streams.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// The VIP proxy manager. Holds the service registry and manages TCP listeners.
pub struct VipProxy {
    /// Registered services keyed by name.
    services: HashMap<String, VipService>,
    /// Stream dispatcher for routing tunnel data to per-connection channels.
    dispatcher: Arc<StreamDispatcher>,
    /// Atomic counter for assigning stream IDs to new connections.
    next_stream_id: Arc<AtomicU32>,
    /// Stop flag for all proxy tasks.
    stop_flag: Arc<AtomicBool>,
    /// Join handles for spawned listener tasks.
    listener_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Default for VipProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl VipProxy {
    /// Create a new VIP proxy with stream multiplexing support.
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            dispatcher: Arc::new(StreamDispatcher::new()),
            next_stream_id: Arc::new(AtomicU32::new(1)), // Start at 1 (0 = legacy)
            stop_flag: Arc::new(AtomicBool::new(false)),
            listener_handles: Vec::new(),
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

    /// Get the stream dispatcher (for the recv loop to dispatch data by stream_id).
    pub fn dispatcher(&self) -> Arc<StreamDispatcher> {
        self.dispatcher.clone()
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
    /// Each listener accepts concurrent TCP connections. Each connection
    /// gets its own stream_id and communicates through the multiplexed tunnel.
    pub async fn start(
        &mut self,
        transport: Arc<TransportNode>,
        session_id: SessionId,
        peer_addr: SocketAddr,
        data_seq: Arc<AtomicU64>,
        bytes_sent: Arc<AtomicU64>,
    ) -> Result<(), String> {
        // Stop any existing listeners first (idempotent for reconnect)
        if !self.listener_handles.is_empty() {
            self.stop();
            // Give OS time to release sockets
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // Fresh dispatcher for this session
        self.dispatcher = Arc::new(StreamDispatcher::new());
        self.next_stream_id.store(1, Ordering::SeqCst);
        self.stop_flag.store(false, Ordering::SeqCst);

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
                let dispatcher = self.dispatcher.clone();
                let next_stream_id = self.next_stream_id.clone();

                // Build TLS acceptor for HTTPS ports
                let tls_acceptor = if is_tls_port(port) {
                    match build_tls_acceptor(&service.name) {
                        Ok(acceptor) => {
                            tracing::info!("VIP TLS enabled for {}:{}", service.vip, port);
                            Some(Arc::new(acceptor))
                        }
                        Err(e) => {
                            tracing::warn!(
                                "VIP TLS not available for {}:{}: {}",
                                service.vip,
                                port,
                                e
                            );
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
                        dispatcher,
                        next_stream_id,
                        tls_acceptor,
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
        for handle in self.listener_handles.drain(..) {
            handle.abort();
        }
        // Note: Don't clear services — they're configuration, not runtime state.
        // They need to persist across reconnect cycles.
        tracing::info!("VIP proxy stopped");
    }
}

/// Check if a port should use TLS termination.
fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443)
}

/// Build a TLS acceptor from cert/key files in `~/.ztlp/certs/`.
fn build_tls_acceptor(service_name: &str) -> Result<TlsAcceptor, String> {
    let cert_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".ztlp")
        .join("certs");

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

    let cert_data = std::fs::read(&cert_path)
        .map_err(|e| format!("failed to read cert {:?}: {}", cert_path, e))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .filter_map(|r| r.ok())
        .collect();
    if certs.is_empty() {
        return Err(format!("no certificates found in {:?}", cert_path));
    }

    let key_data = std::fs::read(&key_path)
        .map_err(|e| format!("failed to read key {:?}: {}", key_path, e))?;
    let key = rustls_pemfile::private_key(&mut key_data.as_slice())
        .map_err(|e| format!("failed to parse key {:?}: {}", key_path, e))?
        .ok_or_else(|| format!("no private key found in {:?}", key_path))?;

    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config error: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

// ─── Listener + Connection Handling ─────────────────────────────────────────

/// TCP listener task for a single VIP:port.
///
/// Accepts concurrent TCP connections. Each gets a unique stream_id and
/// runs independently through the multiplexed tunnel.
#[allow(clippy::too_many_arguments)]
async fn vip_listener_task(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    transport: Arc<TransportNode>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    data_seq: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    dispatcher: Arc<StreamDispatcher>,
    next_stream_id: Arc<AtomicU32>,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

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

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("VIP: max connections reached, rejecting {}", client_addr);
                drop(stream);
                continue;
            }
        };

        // Assign a unique stream_id for this connection
        let stream_id = next_stream_id.fetch_add(1, Ordering::SeqCst);

        tracing::info!(
            "VIP connection from {} stream_id={} (tls={})",
            client_addr,
            stream_id,
            tls_acceptor.is_some()
        );

        let stop = stop.clone();
        let transport = transport.clone();
        let data_seq = data_seq.clone();
        let bytes_sent = bytes_sent.clone();
        let dispatcher = dispatcher.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let _permit = permit;

            if let Some(ref acceptor) = tls_acceptor {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                    acceptor.accept(stream),
                )
                .await
                {
                    Ok(Ok(tls_stream)) => {
                        tracing::info!(
                            "VIP TLS handshake complete from {} stream_id={}",
                            client_addr,
                            stream_id
                        );
                        let (read_half, write_half) = tokio::io::split(tls_stream);
                        handle_mux_connection(
                            read_half,
                            write_half,
                            stream_id,
                            client_addr,
                            &stop,
                            &transport,
                            session_id,
                            peer_addr,
                            &data_seq,
                            &bytes_sent,
                            &dispatcher,
                        )
                        .await;
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("VIP TLS handshake failed from {}: {}", client_addr, e);
                    }
                    Err(_) => {
                        tracing::warn!(
                            "VIP TLS handshake timeout from {} ({}s)",
                            client_addr,
                            TLS_HANDSHAKE_TIMEOUT_SECS
                        );
                    }
                }
            } else {
                let (read_half, write_half) = tokio::io::split(stream);
                handle_mux_connection(
                    read_half,
                    write_half,
                    stream_id,
                    client_addr,
                    &stop,
                    &transport,
                    session_id,
                    peer_addr,
                    &data_seq,
                    &bytes_sent,
                    &dispatcher,
                )
                .await;
            }
        });
    }
}

/// Handle a multiplexed VIP connection.
///
/// 1. Register stream with dispatcher
/// 2. Send FRAME_OPEN to gateway
/// 3. Pipe data bidirectionally with stream_id tagging
/// 4. Send FRAME_CLOSE on teardown
/// 5. Unregister stream
#[allow(clippy::too_many_arguments)]
async fn handle_mux_connection<R, W>(
    mut read_half: R,
    mut write_half: W,
    stream_id: u32,
    client_addr: SocketAddr,
    stop: &Arc<AtomicBool>,
    transport: &Arc<TransportNode>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    data_seq: &Arc<AtomicU64>,
    bytes_sent: &Arc<AtomicU64>,
    dispatcher: &Arc<StreamDispatcher>,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // 1. Register stream with dispatcher to receive tunnel data
    let mut stream_rx = dispatcher.register(stream_id);

    // 2. Send FRAME_OPEN to gateway to create backend connection
    {
        let open_frame = vec![
            FRAME_OPEN,
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
        ];
        if let Err(e) = transport
            .send_data(session_id, &open_frame, peer_addr)
            .await
        {
            tracing::warn!("VIP: failed to send OPEN for stream {}: {}", stream_id, e);
            dispatcher.unregister(stream_id);
            return;
        }
        tracing::info!(
            "VIP: sent OPEN for stream {} from {}",
            stream_id,
            client_addr
        );
    }

    // Small delay for gateway to set up backend
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. Bidirectional data pump
    let stop_clone = stop.clone();
    let last_activity = Arc::new(AtomicU64::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    ));
    let last_activity_write = last_activity.clone();

    // Task: tunnel → TCP (receive from dispatcher channel, write to TCP)
    let write_task = tokio::spawn(async move {
        loop {
            if stop_clone.load(Ordering::SeqCst) {
                break;
            }
            match tokio::time::timeout(std::time::Duration::from_millis(200), stream_rx.recv())
                .await
            {
                Ok(Some(data)) => {
                    last_activity_write.store(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        Ordering::Relaxed,
                    );
                    if let Err(e) = write_half.write_all(&data).await {
                        tracing::debug!("VIP: TCP write error stream {}: {}", stream_id, e);
                        break;
                    }
                    if let Err(e) = write_half.flush().await {
                        tracing::debug!("VIP: TCP flush error stream {}: {}", stream_id, e);
                        break;
                    }
                }
                Ok(None) => {
                    // Channel closed — stream ended by remote
                    tracing::info!(
                        "VIP: stream {} channel closed (remote FIN/CLOSE)",
                        stream_id
                    );
                    break;
                }
                Err(_) => {
                    // Timeout — check idle
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let last = last_activity.load(Ordering::Relaxed);
                    if now.saturating_sub(last) > CONNECTION_IDLE_TIMEOUT_SECS {
                        tracing::info!(
                            "VIP: stream {} idle timeout ({}s)",
                            stream_id,
                            CONNECTION_IDLE_TIMEOUT_SECS
                        );
                        break;
                    }
                    continue;
                }
            }
        }
    });

    // Main loop: TCP → tunnel (read from TCP, send through tunnel with stream_id)
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
                // Build multiplexed tunnel frame: [FRAME_DATA | stream_id(4 BE) | payload]
                let mut framed = Vec::with_capacity(1 + 4 + n);
                framed.push(FRAME_DATA);
                framed.extend_from_slice(&stream_id.to_be_bytes());
                framed.extend_from_slice(&buf[..n]);

                if let Err(e) = transport.send_data(session_id, &framed, peer_addr).await {
                    tracing::warn!("VIP tunnel send error stream {}: {}", stream_id, e);
                    break;
                }
                bytes_sent.fetch_add(n as u64, Ordering::Relaxed);

                // Legacy: also bump data_seq for global ACK tracking
                data_seq.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Err(e)) => {
                tracing::debug!("VIP TCP read error stream {}: {}", stream_id, e);
                break;
            }
            Err(_) => continue,
        }
    }

    write_task.abort();

    // 4. Send FRAME_CLOSE to gateway
    {
        let close_frame = vec![
            FRAME_CLOSE,
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
        ];
        let _ = transport
            .send_data(session_id, &close_frame, peer_addr)
            .await;
        tracing::info!("VIP: stream {} closed from {}", stream_id, client_addr);
    }

    // 5. Unregister from dispatcher
    dispatcher.unregister(stream_id);
}

// ─── Tests ──────────────────────────────────────────────────────────────────

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
    fn test_dispatcher() {
        let proxy = VipProxy::new();
        let _disp = proxy.dispatcher(); // Should not panic
    }

    #[test]
    fn test_stop_without_start() {
        let mut proxy = VipProxy::new();
        proxy.stop(); // Should not panic
    }

    #[test]
    fn test_stream_dispatcher_register_dispatch() {
        let disp = StreamDispatcher::new();
        let mut rx = disp.register(1);
        assert!(disp.dispatch(1, vec![1, 2, 3]));
        assert_eq!(rx.try_recv().unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_stream_dispatcher_unknown_stream() {
        let disp = StreamDispatcher::new();
        assert!(!disp.dispatch(99, vec![1, 2, 3]));
    }

    #[test]
    fn test_stream_dispatcher_unregister() {
        let disp = StreamDispatcher::new();
        let _rx = disp.register(1);
        assert_eq!(disp.stream_count(), 1);
        disp.unregister(1);
        assert_eq!(disp.stream_count(), 0);
        assert!(!disp.dispatch(1, vec![1, 2, 3]));
    }

    #[test]
    fn test_stream_dispatcher_close_stream() {
        let disp = StreamDispatcher::new();
        let _rx = disp.register(1);
        disp.close_stream(1);
        assert_eq!(disp.stream_count(), 0);
    }

    #[test]
    fn test_stream_dispatcher_multiple_streams() {
        let disp = StreamDispatcher::new();
        let mut rx1 = disp.register(1);
        let mut rx2 = disp.register(2);
        assert_eq!(disp.stream_count(), 2);

        assert!(disp.dispatch(1, vec![10]));
        assert!(disp.dispatch(2, vec![20]));

        assert_eq!(rx1.try_recv().unwrap(), vec![10]);
        assert_eq!(rx2.try_recv().unwrap(), vec![20]);
    }

    // ── Security audit tests ────────────────────────────────────────────

    #[test]
    fn test_add_service_rejects_non_loopback() {
        let mut proxy = VipProxy::new();

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(8, 8, 8, 8), 80);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("loopback"));

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(192, 168, 1, 1), 80);
        assert!(result.is_err());

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(169, 254, 1, 1), 80);
        assert!(result.is_err());

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(0, 0, 0, 0), 80);
        assert!(result.is_err());

        let result = proxy.add_service("evil".to_string(), Ipv4Addr::new(255, 255, 255, 255), 80);
        assert!(result.is_err());
    }

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
