//! GRO-aware batch receive processing for the ZTLP tunnel bridge.
//!
//! When GRO is enabled, a single recvmsg() may deliver multiple coalesced
//! UDP datagrams. This module splits them and processes each as an
//! independent ZTLP packet.
//!
//! The [`BatchReceiver`] wraps [`GroReceiver`] and provides ergonomic access
//! to individual received packets, whether the kernel coalesced them or not.

#![deny(unsafe_code)]

use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::debug;

use crate::gso::{GroReceiver, GsoMode, RecvBatch};

// ─── BatchReceiver ──────────────────────────────────────────────────────────

/// A receive-side batch processor that integrates with the tunnel bridge.
///
/// Wraps `GroReceiver` and provides a vec of individual ZTLP packet slices
/// from a single receive call. When GRO is enabled, a single call to
/// [`recv()`](Self::recv) may yield multiple packets.
///
/// Usage:
/// ```ignore
/// let mut batch_recv = BatchReceiver::new(socket, GsoMode::Auto);
/// let batch = batch_recv.recv().await?;
/// for segment in batch.segments() {
///     let data = &batch.buffer()[segment.offset..segment.offset + segment.len];
///     // process individual ZTLP packet
/// }
/// ```
pub struct BatchReceiver {
    inner: GroReceiver,
}

impl BatchReceiver {
    /// Create a new `BatchReceiver` wrapping the given socket.
    ///
    /// Probes GRO capability and enables it unless `mode` is `Disabled`.
    pub fn new(socket: Arc<UdpSocket>, mode: GsoMode) -> Self {
        let inner = GroReceiver::new(socket, mode);
        debug!(
            "BatchReceiver created (gro_enabled={})",
            inner.is_gro_enabled()
        );
        Self { inner }
    }

    /// Whether GRO is enabled on the underlying receiver.
    pub fn is_gro_enabled(&self) -> bool {
        self.inner.is_gro_enabled()
    }

    /// Receive one batch of (possibly coalesced) ZTLP packets.
    ///
    /// Returns a `RecvBatch` that can be iterated over. Each segment
    /// represents one individual ZTLP packet.
    pub async fn recv(&mut self) -> std::io::Result<RecvBatch> {
        self.inner.recv().await
    }

    /// Get a reference to the underlying socket.
    pub fn socket(&self) -> &UdpSocket {
        self.inner.socket()
    }

    /// Get a clone of the underlying socket Arc.
    pub fn socket_arc(&self) -> Arc<UdpSocket> {
        self.inner.socket_arc()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_batch_receiver_single() {
        // Receives one packet via BatchReceiver.
        let recv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest = recv_sock.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut batch_recv = BatchReceiver::new(recv_sock, GsoMode::Auto);

        // Send one packet
        sender.send_to(b"single-packet", dest).await.unwrap();

        // Receive
        let batch = batch_recv.recv().await.unwrap();
        assert_eq!(batch.len(), 1);
        let seg = &batch.segments()[0];
        assert_eq!(
            &batch.buffer()[seg.offset..seg.offset + seg.len],
            b"single-packet"
        );
    }

    #[tokio::test]
    async fn test_batch_receiver_burst() {
        // Rapid-fire sends, receives batch(es).
        let recv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest = recv_sock.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut batch_recv = BatchReceiver::new(recv_sock, GsoMode::Auto);

        // Send 20 packets quickly
        for i in 0u8..20 {
            let data = vec![i; 200];
            sender.send_to(&data, dest).await.unwrap();
        }

        // Receive all 20 packets (may come in one or multiple batches)
        let mut total_segments = 0;
        let mut total_bytes = 0;

        while total_segments < 20 {
            let batch = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                batch_recv.recv(),
            )
            .await
            .expect("receive timed out")
            .expect("receive failed");

            for seg in batch.segments() {
                assert_eq!(seg.len, 200);
                let data = &batch.buffer()[seg.offset..seg.offset + seg.len];
                // Verify all bytes are the same value
                assert!(data.iter().all(|&b| b == data[0]));
            }

            total_segments += batch.len();
            total_bytes += batch.total_bytes();
        }

        assert_eq!(total_segments, 20);
        assert_eq!(total_bytes, 4000);
    }

    #[tokio::test]
    async fn test_batch_receiver_mixed_with_gso_sender() {
        // Use BatchSender on send + BatchReceiver on recv.
        use crate::batch::BatchSender;

        let recv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dest = recv_sock.local_addr().unwrap();
        let send_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

        let batch_sender = BatchSender::new(send_sock, GsoMode::Auto);
        let mut batch_recv = BatchReceiver::new(recv_sock, GsoMode::Auto);

        // Build and send 15 packets via GSO batch sender
        let packets: Vec<Vec<u8>> = (0..15).map(|i| vec![i as u8; 300]).collect();
        let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
        assert_eq!(sent, 15);

        // Receive all via batch receiver
        let mut total_segments = 0;
        let mut total_bytes = 0;

        while total_segments < 15 {
            let batch = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                batch_recv.recv(),
            )
            .await
            .expect("receive timed out")
            .expect("receive failed");

            for seg in batch.segments() {
                assert_eq!(seg.len, 300);
            }

            total_segments += batch.len();
            total_bytes += batch.total_bytes();
        }

        assert_eq!(total_segments, 15);
        assert_eq!(total_bytes, 4500);
    }
}
