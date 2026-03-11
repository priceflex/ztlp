// Test code uses index loops for constructing/verifying packet byte patterns.
#![allow(clippy::needless_range_loop)]

//! Throughput and transport optimization integration tests.
//!
//! These tests exercise GSO, GRO, BatchSender, GroReceiver, and their
//! integration with the ZTLP transport and tunnel layers over real sockets.
//!
//! Every test uses real tokio UDP sockets on localhost, asserts exact byte
//! equality, and sets timeouts to avoid hanging on failure.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use ztlp_proto::batch::BatchSender;
use ztlp_proto::gro_batch::BatchReceiver;
use ztlp_proto::gso::{GroReceiver, GsoCapability, GsoMode, MAX_GSO_SEGMENTS};
use ztlp_proto::transport::TransportNode;

/// Default timeout for receive operations.
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

// ─── Helper: receive exactly N packets via individual recv_from ─────────────

async fn recv_n_packets(socket: &UdpSocket, n: usize, timeout_dur: Duration) -> Vec<Vec<u8>> {
    let mut received = Vec::with_capacity(n);
    let mut buf = vec![0u8; 65535];
    for i in 0..n {
        let result = timeout(timeout_dur, socket.recv_from(&mut buf)).await;
        match result {
            Ok(Ok((len, _addr))) => {
                received.push(buf[..len].to_vec());
            }
            Ok(Err(e)) => {
                panic!("recv_from error on packet {}/{}: {}", i + 1, n, e);
            }
            Err(_) => {
                panic!(
                    "Timeout waiting for packet {}/{}. Received {} so far.",
                    i + 1,
                    n,
                    received.len()
                );
            }
        }
    }
    received
}

/// Receive all packets via BatchReceiver until we have at least `n` segments.
async fn recv_n_via_batch(
    batch_recv: &mut BatchReceiver,
    n: usize,
    timeout_dur: Duration,
) -> Vec<Vec<u8>> {
    let mut received = Vec::with_capacity(n);
    let deadline = tokio::time::Instant::now() + timeout_dur;

    while received.len() < n {
        let remaining = deadline - tokio::time::Instant::now();
        let batch = timeout(remaining, batch_recv.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "Timeout: received {}/{} segments via BatchReceiver",
                    received.len(),
                    n
                )
            })
            .expect("BatchReceiver recv failed");

        for seg in batch.segments() {
            let data = batch.buffer()[seg.offset..seg.offset + seg.len].to_vec();
            received.push(data);
        }
    }
    received
}

// ─── Test 1: GSO roundtrip — 10 packets ────────────────────────────────────

#[tokio::test]
async fn test_gso_roundtrip_10_packets() {
    let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let receiver_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver_sock.local_addr().unwrap();

    let batch_sender = BatchSender::new(sender_sock, GsoMode::Auto);

    // Build 10 packets, each 200 bytes, with distinct content
    let packets: Vec<Vec<u8>> = (0..10u8)
        .map(|i| {
            let mut pkt = vec![i; 200];
            // Embed index at byte 0 for identification
            pkt[0] = i;
            pkt
        })
        .collect();

    let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, 10, "should send all 10 packets");

    // Receive all 10 individually
    let received = recv_n_packets(&receiver_sock, 10, RECV_TIMEOUT).await;
    assert_eq!(received.len(), 10);

    // Verify content — packets may arrive reordered, so collect by ID
    let mut seen: HashSet<u8> = HashSet::new();
    for pkt in &received {
        assert_eq!(pkt.len(), 200, "packet length mismatch");
        let id = pkt[0];
        assert!(
            pkt.iter().all(|&b| b == id),
            "packet content mismatch for id={}",
            id
        );
        seen.insert(id);
    }
    assert_eq!(seen.len(), 10, "should receive all 10 distinct packets");
}

// ─── Test 2: GSO roundtrip — 100 packets ───────────────────────────────────

#[tokio::test]
async fn test_gso_roundtrip_100_packets() {
    let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let receiver_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver_sock.local_addr().unwrap();

    let batch_sender = BatchSender::new(sender_sock, GsoMode::Auto);

    let packets: Vec<Vec<u8>> = (0..100u16)
        .map(|i| {
            let mut pkt = vec![0u8; 150];
            // Encode 16-bit ID in first two bytes
            pkt[0] = (i & 0xFF) as u8;
            pkt[1] = ((i >> 8) & 0xFF) as u8;
            // Fill rest with pattern
            for j in 2..150 {
                pkt[j] = ((i as usize + j) & 0xFF) as u8;
            }
            pkt
        })
        .collect();

    let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, 100);

    let received = recv_n_packets(&receiver_sock, 100, RECV_TIMEOUT).await;
    assert_eq!(received.len(), 100);

    let mut seen_ids: HashSet<u16> = HashSet::new();
    for pkt in &received {
        assert_eq!(pkt.len(), 150);
        let id = pkt[0] as u16 | ((pkt[1] as u16) << 8);
        // Verify payload pattern
        for j in 2..150 {
            assert_eq!(
                pkt[j],
                ((id as usize + j) & 0xFF) as u8,
                "content mismatch at byte {} for packet id={}",
                j,
                id
            );
        }
        seen_ids.insert(id);
    }
    assert_eq!(seen_ids.len(), 100, "all 100 packets should be unique");
}

// ─── Test 3: GSO roundtrip — MAX_GSO_SEGMENTS (64) ─────────────────────────

#[tokio::test]
async fn test_gso_roundtrip_max_segments() {
    let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let receiver_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver_sock.local_addr().unwrap();

    let batch_sender = BatchSender::new(sender_sock, GsoMode::Auto);

    // Exactly MAX_GSO_SEGMENTS packets of uniform size
    let packets: Vec<Vec<u8>> = (0..MAX_GSO_SEGMENTS)
        .map(|i| vec![(i & 0xFF) as u8; 100])
        .collect();

    let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, MAX_GSO_SEGMENTS);

    let received = recv_n_packets(&receiver_sock, MAX_GSO_SEGMENTS, RECV_TIMEOUT).await;
    assert_eq!(received.len(), MAX_GSO_SEGMENTS);

    let mut seen: HashSet<u8> = HashSet::new();
    for pkt in &received {
        assert_eq!(pkt.len(), 100);
        let id = pkt[0];
        assert!(pkt.iter().all(|&b| b == id));
        seen.insert(id);
    }
    assert_eq!(seen.len(), MAX_GSO_SEGMENTS);
}

// ─── Test 4: GSO exceeds max segments (200 packets → multiple batches) ─────

#[tokio::test]
async fn test_gso_roundtrip_exceeds_max() {
    let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let receiver_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver_sock.local_addr().unwrap();

    let batch_sender = BatchSender::new(sender_sock, GsoMode::Auto);

    let num_packets = 200;
    let packets: Vec<Vec<u8>> = (0..num_packets)
        .map(|i| {
            let mut pkt = vec![0u8; 100];
            pkt[0] = (i & 0xFF) as u8;
            pkt[1] = ((i >> 8) & 0xFF) as u8;
            pkt
        })
        .collect();

    let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, num_packets, "all 200 packets should be sent");

    let received = recv_n_packets(&receiver_sock, num_packets, RECV_TIMEOUT).await;
    assert_eq!(received.len(), num_packets);

    let mut seen_ids: HashSet<u16> = HashSet::new();
    for pkt in &received {
        assert_eq!(pkt.len(), 100);
        let id = pkt[0] as u16 | ((pkt[1] as u16) << 8);
        seen_ids.insert(id);
    }
    assert_eq!(
        seen_ids.len(),
        num_packets,
        "all 200 packet IDs should be unique"
    );
}

// ─── Test 5: GRO coalesced receive ─────────────────────────────────────────

#[tokio::test]
async fn test_gro_coalesced_receive() {
    let recv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let dest = recv_sock.local_addr().unwrap();
    let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let mut batch_recv = BatchReceiver::new(recv_sock, GsoMode::Auto);

    // Rapid-fire send 30 packets
    let num_packets = 30usize;
    for i in 0..num_packets {
        let data = vec![(i & 0xFF) as u8; 200];
        send_sock.send_to(&data, dest).await.unwrap();
    }

    // Receive via GRO-enabled BatchReceiver
    let received = recv_n_via_batch(&mut batch_recv, num_packets, RECV_TIMEOUT).await;
    assert!(
        received.len() >= num_packets,
        "expected at least {} segments, got {}",
        num_packets,
        received.len()
    );

    // Verify all data intact (content, not ordering — UDP can reorder)
    let mut seen_ids: HashSet<u8> = HashSet::new();
    for pkt in &received[..num_packets] {
        assert_eq!(pkt.len(), 200, "segment length mismatch");
        let id = pkt[0];
        assert!(
            pkt.iter().all(|&b| b == id),
            "segment content mismatch for id={}",
            id
        );
        seen_ids.insert(id);
    }
    assert_eq!(seen_ids.len(), num_packets);
}

// ─── Test 6: GSO + GRO bidirectional ───────────────────────────────────────

#[tokio::test]
async fn test_gso_gro_bidirectional() {
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    let sender_a = BatchSender::new(sock_a.clone(), GsoMode::Auto);
    let sender_b = BatchSender::new(sock_b.clone(), GsoMode::Auto);

    let mut recv_a = BatchReceiver::new(sock_a.clone(), GsoMode::Auto);
    let mut recv_b = BatchReceiver::new(sock_b.clone(), GsoMode::Auto);

    let num_each = 50usize;

    // A → B: 50 packets with pattern 0xA0+i
    let packets_a: Vec<Vec<u8>> = (0..num_each)
        .map(|i| {
            let mut pkt = vec![0u8; 120];
            pkt[0] = 0xA0;
            pkt[1] = i as u8;
            for j in 2..120 {
                pkt[j] = (i + j) as u8;
            }
            pkt
        })
        .collect();

    // B → A: 50 packets with pattern 0xB0+i
    let packets_b: Vec<Vec<u8>> = (0..num_each)
        .map(|i| {
            let mut pkt = vec![0u8; 120];
            pkt[0] = 0xB0;
            pkt[1] = i as u8;
            for j in 2..120 {
                pkt[j] = (i + j + 128) as u8;
            }
            pkt
        })
        .collect();

    // Send both directions concurrently
    let (sent_a, sent_b) = tokio::join!(
        sender_a.send_batch(&packets_a, addr_b),
        sender_b.send_batch(&packets_b, addr_a),
    );
    assert_eq!(sent_a.unwrap(), num_each);
    assert_eq!(sent_b.unwrap(), num_each);

    // Receive both directions
    let (recvd_b, recvd_a) = tokio::join!(
        recv_n_via_batch(&mut recv_b, num_each, RECV_TIMEOUT),
        recv_n_via_batch(&mut recv_a, num_each, RECV_TIMEOUT),
    );

    // Verify A→B packets
    let mut a_to_b_ids: HashSet<u8> = HashSet::new();
    for pkt in &recvd_b[..num_each] {
        assert_eq!(pkt.len(), 120);
        assert_eq!(pkt[0], 0xA0, "direction marker mismatch");
        a_to_b_ids.insert(pkt[1]);
    }
    assert_eq!(a_to_b_ids.len(), num_each);

    // Verify B→A packets
    let mut b_to_a_ids: HashSet<u8> = HashSet::new();
    for pkt in &recvd_a[..num_each] {
        assert_eq!(pkt.len(), 120);
        assert_eq!(pkt[0], 0xB0, "direction marker mismatch");
        b_to_a_ids.insert(pkt[1]);
    }
    assert_eq!(b_to_a_ids.len(), num_each);
}

// ─── Test 7: Full pipeline — batch send (GSO) → batch receive (GRO) ────────

#[tokio::test]
async fn test_batch_sender_receiver_pipeline() {
    let send_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let recv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let dest = recv_sock.local_addr().unwrap();

    let batch_sender = BatchSender::new(send_sock, GsoMode::Auto);
    let mut batch_recv = BatchReceiver::new(recv_sock, GsoMode::Auto);

    // Generate packets with unique checksums (simulating encrypt/decrypt by
    // using plain data with embedded CRC-like fingerprint)
    let num_packets = 25usize;
    let packets: Vec<Vec<u8>> = (0..num_packets)
        .map(|i| {
            let mut pkt = vec![0u8; 300];
            // Header: 2-byte ID
            pkt[0] = (i & 0xFF) as u8;
            pkt[1] = ((i >> 8) & 0xFF) as u8;
            // Payload: deterministic pattern
            for j in 2..300 {
                pkt[j] = ((i * 7 + j * 13) & 0xFF) as u8;
            }
            // Last 4 bytes: simple checksum
            let sum: u32 = pkt[..296].iter().map(|&b| b as u32).sum();
            pkt[296..300].copy_from_slice(&sum.to_be_bytes());
            pkt
        })
        .collect();

    let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, num_packets);

    // Receive all via batch
    let received = recv_n_via_batch(&mut batch_recv, num_packets, RECV_TIMEOUT).await;
    assert!(received.len() >= num_packets);

    // Verify checksums and content
    let mut seen_ids: HashSet<u16> = HashSet::new();
    for pkt in &received[..num_packets] {
        assert_eq!(pkt.len(), 300, "packet length mismatch");
        let id = pkt[0] as u16 | ((pkt[1] as u16) << 8);

        // Verify checksum
        let sum: u32 = pkt[..296].iter().map(|&b| b as u32).sum();
        let stored = u32::from_be_bytes([pkt[296], pkt[297], pkt[298], pkt[299]]);
        assert_eq!(sum, stored, "checksum mismatch for packet id={}", id);

        // Verify payload pattern
        for j in 2..296 {
            assert_eq!(
                pkt[j],
                ((id as usize * 7 + j * 13) & 0xFF) as u8,
                "content mismatch at byte {} for id={}",
                j,
                id
            );
        }
        seen_ids.insert(id);
    }
    assert_eq!(seen_ids.len(), num_packets);
}

// ─── Test 8: TransportNode::send_batch ──────────────────────────────────────

#[tokio::test]
async fn test_transport_send_batch() {
    let node_a = TransportNode::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver.local_addr().unwrap();

    let num_packets = 20;
    let packets: Vec<Vec<u8>> = (0..num_packets)
        .map(|i| {
            let mut pkt = vec![0u8; 80];
            pkt[0] = i as u8;
            for j in 1..80 {
                pkt[j] = (i + j) as u8;
            }
            pkt
        })
        .collect();

    let sent = node_a.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, num_packets);

    // Receive all via plain socket
    let received = recv_n_packets(&receiver, num_packets, RECV_TIMEOUT).await;
    assert_eq!(received.len(), num_packets);

    let mut seen: HashSet<u8> = HashSet::new();
    for pkt in &received {
        assert_eq!(pkt.len(), 80);
        let id = pkt[0];
        // Verify content
        for j in 1..80 {
            assert_eq!(pkt[j], (id as usize + j) as u8);
        }
        seen.insert(id);
    }
    assert_eq!(seen.len(), num_packets);
}

// ─── Test 9: TransportNode::recv_batch with GRO ────────────────────────────

#[tokio::test]
async fn test_transport_recv_batch() {
    let node = TransportNode::bind("127.0.0.1:0").await.unwrap();
    let sender_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = node.local_addr;

    let mut gro_recv = GroReceiver::new(node.socket.clone(), GsoMode::Auto);

    // Send 15 packets
    let num_packets = 15;
    for i in 0..num_packets {
        let data = vec![i as u8; 250];
        sender_sock.send_to(&data, dest).await.unwrap();
    }

    // Receive via batch
    let mut total_received = Vec::new();
    let deadline = tokio::time::Instant::now() + RECV_TIMEOUT;

    while total_received.len() < num_packets {
        let remaining = deadline - tokio::time::Instant::now();
        let results = timeout(remaining, node.recv_batch(&mut gro_recv))
            .await
            .expect("timeout")
            .expect("recv_batch failed");

        for (data, _addr) in results {
            total_received.push(data);
        }
    }

    assert!(total_received.len() >= num_packets);

    let mut seen: HashSet<u8> = HashSet::new();
    for pkt in &total_received[..num_packets] {
        assert_eq!(pkt.len(), 250);
        let id = pkt[0];
        assert!(pkt.iter().all(|&b| b == id));
        seen.insert(id);
    }
    assert_eq!(seen.len(), num_packets);
}

// ─── Test 10: Mixed GSO modes ──────────────────────────────────────────────

#[tokio::test]
async fn test_mixed_gso_modes() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver.local_addr().unwrap();

    // Create three senders with different modes
    let auto_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let enabled_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let disabled_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let auto_sender = BatchSender::new(auto_sock, GsoMode::Auto);
    let enabled_sender = BatchSender::new(enabled_sock, GsoMode::Enabled);
    let disabled_sender = BatchSender::new(disabled_sock, GsoMode::Disabled);

    let packets_per_sender = 5;

    // Auto mode: packets with marker 0xAA
    let auto_pkts: Vec<Vec<u8>> = (0..packets_per_sender)
        .map(|i| {
            let mut p = vec![0xAA; 100];
            p[1] = i as u8;
            p
        })
        .collect();

    // Enabled mode: packets with marker 0xBB
    let enabled_pkts: Vec<Vec<u8>> = (0..packets_per_sender)
        .map(|i| {
            let mut p = vec![0xBB; 100];
            p[1] = i as u8;
            p
        })
        .collect();

    // Disabled mode: packets with marker 0xCC
    let disabled_pkts: Vec<Vec<u8>> = (0..packets_per_sender)
        .map(|i| {
            let mut p = vec![0xCC; 100];
            p[1] = i as u8;
            p
        })
        .collect();

    // Send from all three
    let (r1, r2, r3) = tokio::join!(
        auto_sender.send_batch(&auto_pkts, dest),
        enabled_sender.send_batch(&enabled_pkts, dest),
        disabled_sender.send_batch(&disabled_pkts, dest),
    );
    assert_eq!(r1.unwrap(), packets_per_sender);
    assert_eq!(r2.unwrap(), packets_per_sender);
    assert_eq!(r3.unwrap(), packets_per_sender);

    // Receive all 15 packets
    let total = packets_per_sender * 3;
    let received = recv_n_packets(&receiver, total, RECV_TIMEOUT).await;
    assert_eq!(received.len(), total);

    let mut aa_count = 0;
    let mut bb_count = 0;
    let mut cc_count = 0;
    for pkt in &received {
        assert_eq!(pkt.len(), 100);
        match pkt[0] {
            0xAA => aa_count += 1,
            0xBB => bb_count += 1,
            0xCC => cc_count += 1,
            other => panic!("unexpected marker byte: 0x{:02X}", other),
        }
    }
    assert_eq!(aa_count, packets_per_sender, "auto mode count");
    assert_eq!(bb_count, packets_per_sender, "enabled mode count");
    assert_eq!(cc_count, packets_per_sender, "disabled mode count");
}

// ─── Test 11: GSO with ZTLP-like headers ───────────────────────────────────

#[tokio::test]
async fn test_gso_with_ztlp_headers() {
    let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let receiver_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver_sock.local_addr().unwrap();

    let batch_sender = BatchSender::new(sender_sock, GsoMode::Auto);

    // Build packets that look like ZTLP data packets:
    // [0x5A, 0x37] magic + session_id(16) + seq(8) + auth_tag(16) + payload
    let num_packets = 10;
    let header_size = 2 + 16 + 8 + 16; // 42 bytes header
    let payload_size = 200;
    let total_size = header_size + payload_size;

    let packets: Vec<Vec<u8>> = (0..num_packets)
        .map(|i| {
            let mut pkt = vec![0u8; total_size];
            // Magic bytes
            pkt[0] = 0x5A;
            pkt[1] = 0x37;
            // Fake session_id (16 bytes)
            pkt[2..18].fill(0x42);
            // Sequence number (8 bytes, big-endian)
            pkt[18..26].copy_from_slice(&(i as u64).to_be_bytes());
            // Fake auth tag (16 bytes)
            pkt[26..42].fill(0xAA);
            // Payload
            for j in 0..payload_size {
                pkt[header_size + j] = ((i + j) & 0xFF) as u8;
            }
            pkt
        })
        .collect();

    let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, num_packets);

    let received = recv_n_packets(&receiver_sock, num_packets, RECV_TIMEOUT).await;
    assert_eq!(received.len(), num_packets);

    for pkt in &received {
        assert_eq!(pkt.len(), total_size);
        // Verify magic
        assert_eq!(pkt[0], 0x5A, "magic byte 0 mismatch");
        assert_eq!(pkt[1], 0x37, "magic byte 1 mismatch");
        // Verify session_id preserved
        assert!(pkt[2..18].iter().all(|&b| b == 0x42));
        // Verify auth tag preserved
        assert!(pkt[26..42].iter().all(|&b| b == 0xAA));
        // Parse sequence number
        let seq = u64::from_be_bytes(pkt[18..26].try_into().unwrap());
        assert!(seq < num_packets as u64, "seq {} out of range", seq);
        // Verify payload
        for j in 0..payload_size {
            assert_eq!(
                pkt[header_size + j],
                ((seq as usize + j) & 0xFF) as u8,
                "payload mismatch at byte {} for seq={}",
                j,
                seq
            );
        }
    }
}

// ─── Test 12: GSO fallback sends correctly ─────────────────────────────────

#[tokio::test]
async fn test_gso_fallback_sends_correctly() {
    let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let receiver_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver_sock.local_addr().unwrap();

    // Force GSO disabled — must use sendmmsg or individual fallback
    let batch_sender =
        BatchSender::with_capability(sender_sock, GsoMode::Disabled, GsoCapability::Unavailable);

    let num_packets = 20;
    let packets: Vec<Vec<u8>> = (0..num_packets)
        .map(|i| {
            let mut pkt = vec![0u8; 175];
            pkt[0] = (i & 0xFF) as u8;
            pkt[1] = ((i >> 8) & 0xFF) as u8;
            for j in 2..175 {
                pkt[j] = ((i * 3 + j) & 0xFF) as u8;
            }
            pkt
        })
        .collect();

    let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, num_packets);

    let received = recv_n_packets(&receiver_sock, num_packets, RECV_TIMEOUT).await;
    assert_eq!(received.len(), num_packets);

    let mut seen: HashSet<u16> = HashSet::new();
    for pkt in &received {
        assert_eq!(pkt.len(), 175);
        let id = pkt[0] as u16 | ((pkt[1] as u16) << 8);
        // Verify payload pattern
        for j in 2..175 {
            assert_eq!(
                pkt[j],
                ((id as usize * 3 + j) & 0xFF) as u8,
                "fallback: content mismatch at byte {} for id={}",
                j,
                id
            );
        }
        seen.insert(id);
    }
    assert_eq!(
        seen.len(),
        num_packets,
        "all fallback packets should arrive"
    );
}

// ─── Test 13: Large payload batch (max-MTU packets) ─────────────────────────

#[tokio::test]
async fn test_large_payload_batch() {
    let sender_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let receiver_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dest = receiver_sock.local_addr().unwrap();

    let batch_sender = BatchSender::new(sender_sock, GsoMode::Auto);

    let num_packets = 20;
    let pkt_size = 1400; // max-MTU typical for ZTLP

    let packets: Vec<Vec<u8>> = (0..num_packets)
        .map(|i| {
            let mut pkt = vec![0u8; pkt_size];
            // ID in first 2 bytes
            pkt[0] = (i & 0xFF) as u8;
            pkt[1] = ((i >> 8) & 0xFF) as u8;
            // Fill with deterministic content for checksum verification
            for j in 2..pkt_size - 4 {
                pkt[j] = ((i * 11 + j * 7) & 0xFF) as u8;
            }
            // Embed checksum in last 4 bytes
            let sum: u32 = pkt[..pkt_size - 4].iter().map(|&b| b as u32).sum();
            pkt[pkt_size - 4..].copy_from_slice(&sum.to_be_bytes());
            pkt
        })
        .collect();

    let sent = batch_sender.send_batch(&packets, dest).await.unwrap();
    assert_eq!(sent, num_packets);

    let received = recv_n_packets(&receiver_sock, num_packets, RECV_TIMEOUT).await;
    assert_eq!(received.len(), num_packets);

    let mut seen: HashSet<u16> = HashSet::new();
    for pkt in &received {
        assert_eq!(pkt.len(), pkt_size, "large packet size mismatch");
        let id = pkt[0] as u16 | ((pkt[1] as u16) << 8);

        // Verify checksum
        let computed: u32 = pkt[..pkt_size - 4].iter().map(|&b| b as u32).sum();
        let stored = u32::from_be_bytes(pkt[pkt_size - 4..pkt_size].try_into().unwrap());
        assert_eq!(
            computed, stored,
            "checksum mismatch for large packet id={}",
            id
        );
        seen.insert(id);
    }
    assert_eq!(seen.len(), num_packets, "all large packets should arrive");
}

// ─── Test 14: GRO timeout handling ─────────────────────────────────────────

#[tokio::test]
async fn test_gro_timeout_handling() {
    let recv_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let mut batch_recv = BatchReceiver::new(recv_sock, GsoMode::Auto);

    // Attempt to receive with a short timeout — no data is sent
    let result = timeout(Duration::from_millis(200), batch_recv.recv()).await;

    // Should timeout (Err from timeout), not hang forever
    assert!(
        result.is_err(),
        "BatchReceiver.recv() should time out when no data arrives"
    );
}

// ─── Test 15: Concurrent batch senders ─────────────────────────────────────

#[tokio::test]
async fn test_concurrent_batch_senders() {
    let receiver = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let dest = receiver.local_addr().unwrap();

    // Two independent senders targeting the same receiver
    let sock_1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let sender_1 = BatchSender::new(sock_1, GsoMode::Auto);
    let sender_2 = BatchSender::new(sock_2, GsoMode::Auto);

    let pkts_per_sender = 30;

    // Sender 1: marker 0x11
    let pkts_1: Vec<Vec<u8>> = (0..pkts_per_sender)
        .map(|i| {
            let mut p = vec![0x11; 100];
            p[1] = i as u8;
            p
        })
        .collect();

    // Sender 2: marker 0x22
    let pkts_2: Vec<Vec<u8>> = (0..pkts_per_sender)
        .map(|i| {
            let mut p = vec![0x22; 100];
            p[1] = i as u8;
            p
        })
        .collect();

    // Send concurrently
    let (r1, r2) = tokio::join!(
        sender_1.send_batch(&pkts_1, dest),
        sender_2.send_batch(&pkts_2, dest),
    );
    assert_eq!(r1.unwrap(), pkts_per_sender);
    assert_eq!(r2.unwrap(), pkts_per_sender);

    // Receive all 60 packets
    let total = pkts_per_sender * 2;
    let received = recv_n_packets(&receiver, total, RECV_TIMEOUT).await;
    assert_eq!(received.len(), total);

    let mut from_1: HashSet<u8> = HashSet::new();
    let mut from_2: HashSet<u8> = HashSet::new();

    for pkt in &received {
        assert_eq!(pkt.len(), 100);
        match pkt[0] {
            0x11 => {
                assert!(pkt[2..].iter().all(|&b| b == 0x11));
                from_1.insert(pkt[1]);
            }
            0x22 => {
                assert!(pkt[2..].iter().all(|&b| b == 0x22));
                from_2.insert(pkt[1]);
            }
            other => panic!("unexpected marker: 0x{:02X}", other),
        }
    }
    assert_eq!(
        from_1.len(),
        pkts_per_sender,
        "all sender 1 packets received"
    );
    assert_eq!(
        from_2.len(),
        pkts_per_sender,
        "all sender 2 packets received"
    );
}
