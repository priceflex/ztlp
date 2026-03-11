//! Batch packet construction and sending for the ZTLP tunnel bridge.
//!
//! Collects encrypted ZTLP packets (with headers already prepended) and
//! sends them in batches via GSO or sendmmsg() when available.
//!
//! The batch sender integrates with the tunnel's TCP→ZTLP sender loop,
//! which currently builds packets one-at-a-time and sends individually.
//! Instead, the BatchSender collects all packets from one TCP read and
//! flushes them as a single GSO/sendmmsg/individual batch.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::debug;

use crate::gso::{GsoCapability, GsoMode, SendStrategy, UdpSender};

// ─── BatchSender ────────────────────────────────────────────────────────────

/// Collects ZTLP packets and sends them in efficient batches.
///
/// Transparently picks the best send method based on system capability:
/// 1. **GSO** — single `sendmsg()` with `UDP_SEGMENT` cmsg (best, Linux only)
/// 2. **sendmmsg** — single syscall with multiple messages (good, Linux only)
/// 3. **Individual** — one `send_to()` per packet (always works)
///
/// Usage:
/// ```ignore
/// let sender = BatchSender::new(socket, GsoMode::Auto);
/// // ... build packets ...
/// sender.send_batch(&packets, peer_addr).await?;
/// ```
pub struct BatchSender {
    inner: UdpSender,
}

impl BatchSender {
    /// Create a new BatchSender wrapping the given socket.
    ///
    /// Probes GSO capability unless `mode` is `Disabled`.
    pub fn new(socket: Arc<UdpSocket>, mode: GsoMode) -> Self {
        Self {
            inner: UdpSender::new(socket, mode),
        }
    }

    /// Create with explicit capability (for testing).
    pub fn with_capability(
        socket: Arc<UdpSocket>,
        mode: GsoMode,
        capability: GsoCapability,
    ) -> Self {
        Self {
            inner: UdpSender::with_capability(socket, mode, capability),
        }
    }

    /// The send strategy in use.
    pub fn strategy(&self) -> SendStrategy {
        self.inner.strategy()
    }

    /// The GSO capability.
    pub fn capability(&self) -> GsoCapability {
        self.inner.capability()
    }

    /// Get a reference to the underlying socket.
    pub fn socket(&self) -> &UdpSocket {
        self.inner.socket()
    }

    /// Get a clone of the underlying socket Arc.
    pub fn socket_arc(&self) -> Arc<UdpSocket> {
        self.inner.socket_arc()
    }

    /// Send a batch of pre-built ZTLP packets to the given destination.
    ///
    /// Each packet in `packets` should be a complete serialized ZTLP data packet
    /// (header + encrypted payload). The BatchSender handles the transport
    /// optimization transparently.
    ///
    /// Returns the number of packets successfully sent.
    pub async fn send_batch(
        &self,
        packets: &[Vec<u8>],
        dest: SocketAddr,
    ) -> std::io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        if packets.len() == 1 {
            self.inner.send_one(&packets[0], dest).await?;
            return Ok(1);
        }

        debug!(
            "batch sending {} packets via {} to {}",
            packets.len(),
            self.strategy(),
            dest
        );

        self.inner.send_batch(packets, dest).await
    }

    /// Send a batch of packet slices (avoids cloning when the caller already has slices).
    pub async fn send_batch_slices(
        &self,
        packets: &[&[u8]],
        dest: SocketAddr,
    ) -> std::io::Result<usize> {
        if packets.is_empty() {
            return Ok(0);
        }

        if packets.len() == 1 {
            self.inner.send_one(packets[0], dest).await?;
            return Ok(1);
        }

        // Convert to Vec for the inner API
        let owned: Vec<Vec<u8>> = packets.iter().map(|p| p.to_vec()).collect();
        self.inner.send_batch(&owned, dest).await
    }

    /// Send a single packet.
    pub async fn send_one(&self, packet: &[u8], dest: SocketAddr) -> std::io::Result<usize> {
        self.inner.send_one(packet, dest).await
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gso::GsoCapability;

    #[tokio::test]
    async fn test_batch_sender_gso_mode() {
        // Create sender and receiver
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let batch = BatchSender::new(sender_sock, GsoMode::Auto);

        // Send 10 identical-size packets
        let packets: Vec<Vec<u8>> = (0..10).map(|i| vec![i; 200]).collect();
        let sent = batch.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, 10);

        // Verify all received
        let mut buf = [0u8; 300];
        for i in 0..10u8 {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 200);
            assert!(buf[..n].iter().all(|&b| b == i));
        }
    }

    #[tokio::test]
    async fn test_batch_sender_fallback() {
        // Force fallback by disabling GSO and using Unavailable capability
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        // Non-Linux or forced unavailable
        let batch = BatchSender::with_capability(
            sender_sock,
            GsoMode::Disabled,
            GsoCapability::Unavailable,
        );

        let packets: Vec<Vec<u8>> = (0..5).map(|i| vec![i; 150]).collect();
        let sent = batch.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, 5);

        let mut buf = [0u8; 300];
        for i in 0..5u8 {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 150);
            assert!(buf[..n].iter().all(|&b| b == i));
        }
    }

    #[tokio::test]
    async fn test_batch_sender_sendmmsg() {
        // Use auto mode — on Linux this will use sendmmsg if GSO is unavailable
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        // Force sendmmsg by disabling GSO but staying on Linux
        let batch = BatchSender::new(sender_sock, GsoMode::Disabled);

        let packets: Vec<Vec<u8>> = (0..8).map(|i| vec![i; 120]).collect();
        let sent = batch.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, 8);

        let mut buf = [0u8; 200];
        for i in 0..8u8 {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 120);
            assert!(buf[..n].iter().all(|&b| b == i));
        }
    }

    #[tokio::test]
    async fn test_batch_sender_mixed_sizes() {
        // Packets of varying sizes — can't use GSO, should fall back
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let batch = BatchSender::new(sender_sock, GsoMode::Auto);

        let packets = vec![
            vec![0xAA; 100],
            vec![0xBB; 200],
            vec![0xCC; 50],
            vec![0xDD; 300],
            vec![0xEE; 150],
        ];
        let sent = batch.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, 5);

        let mut buf = [0u8; 400];
        let mut received = Vec::new();
        for _ in 0..5 {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            received.push((n, buf[0]));
        }
        // Sort by first byte to handle any reordering
        received.sort_by_key(|&(_, b)| b);
        assert_eq!(received[0], (100, 0xAA));
        assert_eq!(received[1], (200, 0xBB));
        assert_eq!(received[2], (50, 0xCC));
        assert_eq!(received[3], (300, 0xDD));
        assert_eq!(received[4], (150, 0xEE));
    }

    #[tokio::test]
    async fn test_batch_sender_empty_batch() {
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let batch = BatchSender::new(sender_sock, GsoMode::Auto);

        let dest: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let sent = batch.send_batch(&[], dest).await.unwrap();
        assert_eq!(sent, 0);
    }

    #[tokio::test]
    async fn test_batch_sender_single_packet() {
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let batch = BatchSender::new(sender_sock, GsoMode::Auto);

        let packets = vec![vec![0x42; 75]];
        let sent = batch.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, 1);

        let mut buf = [0u8; 200];
        let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, 75);
        assert!(buf[..n].iter().all(|&b| b == 0x42));
    }

    #[tokio::test]
    async fn test_batch_sender_large_batch() {
        // 100+ packets — should be split into GSO-sized groups
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let batch = BatchSender::new(sender_sock, GsoMode::Auto);

        let num_packets = 128;
        let packets: Vec<Vec<u8>> = (0..num_packets)
            .map(|i| {
                let mut pkt = vec![0u8; 100];
                pkt[0] = (i & 0xFF) as u8;
                pkt[1] = ((i >> 8) & 0xFF) as u8;
                pkt
            })
            .collect();

        let sent = batch.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, num_packets);

        // Receive all packets
        let mut buf = [0u8; 200];
        let mut received_ids = std::collections::HashSet::new();
        for _ in 0..num_packets {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 100);
            let id = buf[0] as u16 | ((buf[1] as u16) << 8);
            received_ids.insert(id);
        }
        assert_eq!(received_ids.len(), num_packets);
    }

    #[tokio::test]
    async fn test_batch_sender_send_slices() {
        let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = receiver.local_addr().unwrap();

        let batch = BatchSender::new(sender_sock, GsoMode::Auto);

        let data: Vec<Vec<u8>> = (0..5).map(|i| vec![i; 60]).collect();
        let slices: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let sent = batch.send_batch_slices(&slices, dest).await.unwrap();
        assert_eq!(sent, 5);

        let mut buf = [0u8; 100];
        for i in 0..5u8 {
            let (n, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(n, 60);
            assert!(buf[..n].iter().all(|&b| b == i));
        }
    }
}
