//! VIP (Virtual IP) proxy for ZTLP tunnel services.
//!
//! Assigns loopback IPs (`127.0.55.x`) to services and runs local TCP
//! listeners on each VIP:port. Incoming TCP connections are piped through
//! the encrypted ZTLP tunnel.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::packet::SessionId;
use crate::transport::TransportNode;

// TLS support for HTTPS VIP ports (443, 8443).
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::CertificateDer;

/// Maximum read buffer size for TCP proxy connections.
const TCP_READ_BUF_SIZE: usize = 65536;

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
    /// The recv loop pushes data here; the TCP proxy task reads from it.
    tunnel_tx: mpsc::Sender<TunnelData>,
    /// Channel receiver (wrapped in Mutex for shared access).
    tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelData>>>,
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
    /// Create a new VIP proxy with default channel buffer size.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(256);
        Self {
            services: HashMap::new(),
            tunnel_tx: tx,
            tunnel_rx: Arc::new(Mutex::new(rx)),
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
        // 127.0.0.0/8 is the IPv4 loopback range.
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
    /// Each listener accepts one TCP connection at a time (v1 simplification)
    /// and pipes data bidirectionally through the ZTLP tunnel.
    pub async fn start(
        &mut self,
        transport: Arc<TransportNode>,
        session_id: SessionId,
        peer_addr: SocketAddr,
        data_seq: Arc<AtomicU64>,
        bytes_sent: Arc<AtomicU64>,
    ) -> Result<(), String> {
        self.stop_flag.store(false, Ordering::SeqCst);

        for service in self.services.values() {
            for &port in &service.ports {
                let ip_addr = IpAddr::V4(service.vip);
                // SECURITY: Double-check loopback restriction at bind time.
                // This is defense-in-depth — add_service already validates,
                // but we check again in case the service struct is mutated directly.
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

                // Build TLS acceptor for HTTPS ports
                let tls_acceptor = if is_tls_port(port) {
                    match build_tls_acceptor(&service.name) {
                        Ok(acceptor) => {
                            tracing::info!("VIP TLS enabled for {}:{}", service.vip, port);
                            Some(acceptor)
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
                    )
                    .await;
                });

                self.listener_handles.push(handle);
                tracing::info!("VIP proxy listening on {}", bind_addr);
            }
        }

        Ok(())
    }

    /// Stop all VIP proxy listeners.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        for handle in self.listener_handles.drain(..) {
            handle.abort();
        }
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
    // Debug logging to file (temporary — remove after TLS works)
    fn tls_log(msg: &str) {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/ztlp-tls-debug.log")
        {
            let _ = writeln!(f, "{}", msg);
        }
    }
    tls_log(&format!("build_tls_acceptor called for service '{}'", service_name));

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

    tls_log(&format!("cert_dir={:?}, cert_path={:?}, key_path={:?}", cert_dir, cert_path, key_path));

    let cert_path = cert_path.ok_or_else(|| {
        let msg = format!(
            "no TLS cert found in {:?} for service '{}' (tried: {})",
            cert_dir,
            service_name,
            patterns.join(", ")
        );
        tls_log(&format!("ERROR: {}", msg));
        msg
    })?;
    let key_path = key_path.unwrap();

    tls_log(&format!("loading cert from {:?}", cert_path));
    tracing::info!("VIP TLS: loading cert from {:?}", cert_path);

    // Read cert chain
    let cert_data = std::fs::read(&cert_path)
        .map_err(|e| format!("failed to read cert {:?}: {}", cert_path, e))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_data.as_slice())
        .filter_map(|r| r.ok())
        .collect();
    tls_log(&format!("parsed {} certs from {:?}", certs.len(), cert_path));
    if certs.is_empty() {
        tls_log("ERROR: no certs found");
        return Err(format!("no certificates found in {:?}", cert_path));
    }

    // Read private key
    let key_data = std::fs::read(&key_path)
        .map_err(|e| format!("failed to read key {:?}: {}", key_path, e))?;
    let key = rustls_pemfile::private_key(&mut key_data.as_slice())
        .map_err(|e| {
            tls_log(&format!("ERROR parsing key: {}", e));
            format!("failed to parse key {:?}: {}", key_path, e)
        })?
        .ok_or_else(|| {
            tls_log("ERROR: no key found in file");
            format!("no private key found in {:?}", key_path)
        })?;
    tls_log("key parsed OK");

    // Ensure the default crypto provider is installed (rustls 0.23 requires this).
    // Ignore the error if it's already installed from a previous call.
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    tls_log("building ServerConfig...");
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            tls_log(&format!("ERROR ServerConfig: {}", e));
            format!("TLS config error: {}", e)
        })?;

    tls_log(&format!("ServerConfig OK, versions={:?}", config.protocol_versions));
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// TCP listener task for a single VIP:port.
///
/// Accepts one connection at a time. For each connection:
/// 1. Reads TCP data from the client
/// 2. Wraps in FRAME_DATA tunnel frame
/// 3. Sends through the ZTLP transport
/// 4. Receives tunnel responses via the mpsc channel
/// 5. Forwards responses back to the TCP client
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
    tls_acceptor: Option<TlsAcceptor>,
) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        // Accept one connection at a time (v1 simplification)
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

        tracing::info!("VIP connection from {} (tls={})", client_addr, tls_acceptor.is_some());

        // Send FRAME_RESET to tell the gateway to open a new backend TCP
        // connection. Without this, subsequent TCP connections through the
        // VIP proxy would try to reuse the gateway's existing (possibly
        // closed) backend connection.
        {
            let reset_frame = vec![FRAME_RESET];
            if let Err(e) = transport.send_data(session_id, &reset_frame, peer_addr).await {
                tracing::warn!("VIP: failed to send RESET for new connection: {}", e);
            } else {
                tracing::info!("VIP: sent RESET for new connection from {}", client_addr);
            }
        }

        // Handle TLS or plain TCP
        if let Some(ref acceptor) = tls_acceptor {
            // TLS handshake
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("VIP TLS handshake failed from {}: {}", client_addr, e);
                    continue;
                }
            };
            tracing::info!("VIP TLS handshake complete from {}", client_addr);

            let (read_half, write_half) = tokio::io::split(tls_stream);
            handle_vip_connection(
                read_half,
                write_half,
                &stop,
                &transport,
                session_id,
                peer_addr,
                &data_seq,
                &bytes_sent,
                &tunnel_rx,
            )
            .await;
        } else {
            // Plain TCP
            let (read_half, write_half) = tokio::io::split(stream);
            handle_vip_connection(
                read_half,
                write_half,
                &stop,
                &transport,
                session_id,
                peer_addr,
                &data_seq,
                &bytes_sent,
                &tunnel_rx,
            )
            .await;
        }
    }
}

/// Handle a single VIP connection (TLS or plain) — pipe data bidirectionally.
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
        // Spawn a task to read from tunnel_rx and write to TCP client
        let tunnel_rx_clone = tunnel_rx.clone();
        let stop_clone = stop.clone();
        let write_task = tokio::spawn(async move {
            loop {
                if stop_clone.load(Ordering::SeqCst) {
                    break;
                }
                let mut rx = tunnel_rx_clone.lock().await;
                match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                    Ok(Some(data)) => {
                        drop(rx); // Release lock before writing
                        if write_half.write_all(&data.payload).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break, // Channel closed
                    Err(_) => {
                        drop(rx);
                        continue;
                    } // Timeout, loop again
                }
            }
        });

        // Read from TCP client and send through tunnel
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
                    tracing::warn!("VIP TCP read error: {}", e);
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
    /// The VIP proxy must only bind to loopback addresses to prevent
    /// SSRF and port scanning attacks.
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

        // 127.0.0.1 — standard loopback
        assert!(proxy
            .add_service("svc1".to_string(), Ipv4Addr::new(127, 0, 0, 1), 80)
            .is_ok());

        // 127.0.55.1 — VIP range used by ZTLP
        assert!(proxy
            .add_service("svc2".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80)
            .is_ok());

        // 127.255.255.254 — end of loopback range
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
