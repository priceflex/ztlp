//! VIP (Virtual IP) proxy for ZTLP tunnel services.
//!
//! Assigns loopback IPs (`127.0.55.x`) to services and runs local TCP
//! listeners on each VIP:port. Incoming TCP connections are piped through
//! the encrypted ZTLP tunnel.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use crate::packet::SessionId;
use crate::transport::TransportNode;

/// Maximum read buffer size for TCP proxy connections.
const TCP_READ_BUF_SIZE: usize = 65536;

/// Frame type for tunnel data frames.
const FRAME_DATA: u8 = 0x00;

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
    pub fn add_service(&mut self, name: String, vip: Ipv4Addr, port: u16) {
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
                let bind_addr: SocketAddr =
                    SocketAddr::new(std::net::IpAddr::V4(service.vip), port);

                let listener = TcpListener::bind(bind_addr)
                    .await
                    .map_err(|e| format!("failed to bind {}: {}", bind_addr, e))?;

                let stop = self.stop_flag.clone();
                let transport = transport.clone();
                let session_id = session_id;
                let peer_addr = peer_addr;
                let data_seq = data_seq.clone();
                let bytes_sent = bytes_sent.clone();
                let tunnel_rx = self.tunnel_rx.clone();

                let handle = tokio::spawn(async move {
                    vip_listener_task(
                        listener, stop, transport, session_id, peer_addr, data_seq, bytes_sent,
                        tunnel_rx,
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

/// TCP listener task for a single VIP:port.
///
/// Accepts one connection at a time. For each connection:
/// 1. Reads TCP data from the client
/// 2. Wraps in FRAME_DATA tunnel frame
/// 3. Sends through the ZTLP transport
/// 4. Receives tunnel responses via the mpsc channel
/// 5. Forwards responses back to the TCP client
async fn vip_listener_task(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    transport: Arc<TransportNode>,
    session_id: SessionId,
    peer_addr: SocketAddr,
    data_seq: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    tunnel_rx: Arc<Mutex<mpsc::Receiver<TunnelData>>>,
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

        tracing::info!("VIP connection from {}", client_addr);

        // Handle the connection — pipe TCP ↔ tunnel
        let (mut read_half, mut write_half) = stream.into_split();

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
        tracing::info!("VIP connection from {} closed", client_addr);
    }
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
        proxy.add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80);

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
        proxy.add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80);
        proxy.add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 443);

        let svc = proxy.services().get("beta").expect("beta service");
        assert_eq!(svc.ports, vec![80, 443]);
    }

    #[test]
    fn test_add_service_duplicate_port() {
        let mut proxy = VipProxy::new();
        proxy.add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80);
        proxy.add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80);

        let svc = proxy.services().get("beta").expect("beta service");
        assert_eq!(svc.ports, vec![80]); // No duplicate
    }

    #[test]
    fn test_resolve() {
        let mut proxy = VipProxy::new();
        proxy.add_service("beta".to_string(), Ipv4Addr::new(127, 0, 55, 1), 80);
        proxy.add_service("backstage".to_string(), Ipv4Addr::new(127, 0, 55, 2), 80);

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
}
