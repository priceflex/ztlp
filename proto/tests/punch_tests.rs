//! Integration tests for NAT hole punching.
//!
//! Tests the punch module's wire protocol encoding/decoding, timing behavior,
//! and simulated NAT punch coordination.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use ztlp_proto::identity::NodeId;
use ztlp_proto::punch::{
    self, decode_peer_endpoints_response, decode_punch_notify, encode_peer_endpoints_request,
    encode_punch_report, is_punch_notify, is_punch_packet, KeepaliveTracker,
    PunchConfig, PunchResult, PUNCH_BYTE, NS_PEER_ENDPOINTS, NS_PUNCH_NOTIFY,
};

// ─── Wire Protocol Roundtrip Tests ──────────────────────────────────

#[test]
fn test_peer_endpoints_request_roundtrip() {
    let our_id = NodeId::from_bytes([0x11; 16]);
    let peer_id = NodeId::from_bytes([0x22; 16]);
    let endpoints = vec![
        "192.168.1.100:12345".parse::<SocketAddr>().unwrap(),
        "10.0.0.1:54321".parse::<SocketAddr>().unwrap(),
    ];

    let pkt = encode_peer_endpoints_request(&our_id, &peer_id, &endpoints);

    // Verify structure
    assert_eq!(pkt[0], NS_PEER_ENDPOINTS);
    assert_eq!(&pkt[1..17], our_id.as_bytes());
    assert_eq!(&pkt[17..33], peer_id.as_bytes());
    assert_eq!(pkt[33], 2); // 2 reported endpoints
}

#[test]
fn test_peer_endpoints_response_roundtrip_ipv4() {
    // Build a response manually
    let mut resp = vec![0x0A, 0x02]; // 2 endpoints

    // Endpoint 1: 203.0.113.42:3478
    resp.push(4);
    resp.extend_from_slice(&[203, 0, 113, 42]);
    resp.extend_from_slice(&3478u16.to_be_bytes());

    // Endpoint 2: 198.51.100.25:19302
    resp.push(4);
    resp.extend_from_slice(&[198, 51, 100, 25]);
    resp.extend_from_slice(&19302u16.to_be_bytes());

    let endpoints = decode_peer_endpoints_response(&resp).unwrap();
    assert_eq!(endpoints.len(), 2);
    assert_eq!(
        endpoints[0].addr,
        "203.0.113.42:3478".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        endpoints[1].addr,
        "198.51.100.25:19302".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn test_peer_endpoints_response_roundtrip_ipv6() {
    let addr: SocketAddr = "[2001:db8::1]:19302".parse().unwrap();
    let mut resp = vec![0x0A, 0x01]; // 1 endpoint
    resp.push(6);
    if let IpAddr::V6(v6) = addr.ip() {
        resp.extend_from_slice(&v6.octets());
    }
    resp.extend_from_slice(&addr.port().to_be_bytes());

    let endpoints = decode_peer_endpoints_response(&resp).unwrap();
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0].addr, addr);
}

#[test]
fn test_punch_notify_roundtrip() {
    let node_id = [0xAA; 16];
    let mut data = vec![NS_PUNCH_NOTIFY];
    data.extend_from_slice(&node_id);
    data.push(2); // 2 endpoints

    // IPv4: 10.0.0.1:5000
    data.push(4);
    data.extend_from_slice(&[10, 0, 0, 1]);
    data.extend_from_slice(&5000u16.to_be_bytes());

    // IPv4: 192.168.1.1:6000
    data.push(4);
    data.extend_from_slice(&[192, 168, 1, 1]);
    data.extend_from_slice(&6000u16.to_be_bytes());

    let (decoded_id, endpoints) = decode_punch_notify(&data).unwrap();
    assert_eq!(decoded_id.0, node_id);
    assert_eq!(endpoints.len(), 2);
    assert_eq!(
        endpoints[0].addr,
        "10.0.0.1:5000".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        endpoints[1].addr,
        "192.168.1.1:6000".parse::<SocketAddr>().unwrap()
    );
}

#[test]
fn test_punch_report_encoding() {
    let node_id = NodeId::from_bytes([0xBB; 16]);
    let addrs = vec![
        "1.2.3.4:5000".parse::<SocketAddr>().unwrap(),
        "5.6.7.8:9000".parse::<SocketAddr>().unwrap(),
    ];

    let pkt = encode_punch_report(&node_id, &addrs);

    assert_eq!(pkt[0], 0x0C); // PUNCH_REPORT
    assert_eq!(&pkt[1..17], &[0xBB; 16]);
    assert_eq!(pkt[17], 2); // 2 endpoints
    // Total: 1 + 16 + 1 + 14 = 32
    assert_eq!(pkt.len(), 32);
}

// ─── Packet Classification Tests ────────────────────────────────────

#[test]
fn test_punch_packet_not_confused_with_ztlp() {
    // Punch packet (1 byte 0x00) must NOT be confused with any ZTLP packet
    let punch = [PUNCH_BYTE];
    assert!(is_punch_packet(&punch));

    // ZTLP magic starts with 0x5A37
    let ztlp_start = [0x5A, 0x37];
    assert!(!is_punch_packet(&ztlp_start));

    // PUNCH_NOTIFY starts with 0x0B
    let notify = [0x0B, 0x00];
    assert!(!is_punch_packet(&notify));
    assert!(is_punch_notify(&notify));
}

// ─── Timing Tests ───────────────────────────────────────────────────

#[test]
fn test_punch_config_delay_variants() {
    let delays = [0, 100, 500, 1000, 5000, 10000];

    for delay_ms in &delays {
        let config = PunchConfig {
            punch_delay: Duration::from_millis(*delay_ms),
            punch_timeout: Duration::from_secs(30),
            ..PunchConfig::default()
        };

        assert!(
            config.punch_timeout >= config.punch_delay,
            "timeout must be >= delay for {} ms",
            delay_ms
        );
    }
}

#[test]
fn test_keepalive_tracker_idle_detection() {
    let tracker = KeepaliveTracker::new(Duration::from_millis(0));
    assert!(tracker.should_send());

    let tracker = KeepaliveTracker::new(Duration::from_secs(3600));
    assert!(!tracker.should_send());
    assert!(tracker.time_until_next() > Duration::from_secs(3599));
}

#[test]
fn test_keepalive_tracker_activity_resets_timer() {
    let mut tracker = KeepaliveTracker::new(Duration::from_secs(25));
    let before = tracker.time_until_next();
    std::thread::sleep(Duration::from_millis(10));
    tracker.note_activity();
    let after = tracker.time_until_next();

    // After noting activity, time_until_next should be reset (close to 25s again)
    assert!(after >= before.saturating_sub(Duration::from_millis(5)));
}

// ─── Full Integration: Simulated Punch with Fake NS ─────────────────

#[tokio::test]
async fn test_full_punch_flow_with_fake_ns() {
    // Create a fake NS server, two clients, and simulate the full punch flow
    let ns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns_addr = ns_socket.local_addr().unwrap();

    let client_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let _addr_a_local = client_a.local_addr().unwrap();
    let addr_b = client_b.local_addr().unwrap();

    let node_a = NodeId::from_bytes([0x01; 16]);
    let node_b = NodeId::from_bytes([0x02; 16]);

    // Fake NS: receive PEER_ENDPOINTS request, respond with B's address,
    // and send PUNCH_NOTIFY to B
    let node_a_copy = node_a;
    let ns_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (_len, from) = ns_socket.recv_from(&mut buf).await.unwrap();
        assert_eq!(buf[0], NS_PEER_ENDPOINTS);

        // Respond with B's address
        let mut resp = vec![0x0A, 0x01]; // 1 endpoint
        resp.push(4);
        if let IpAddr::V4(v4) = addr_b.ip() {
            resp.extend_from_slice(&v4.octets());
        }
        resp.extend_from_slice(&addr_b.port().to_be_bytes());
        ns_socket.send_to(&resp, from).await.unwrap();

        // Send PUNCH_NOTIFY to B with A's address
        let mut notify = vec![NS_PUNCH_NOTIFY];
        notify.extend_from_slice(node_a_copy.as_bytes());
        notify.push(1);
        notify.push(4);
        if let IpAddr::V4(v4) = from.ip() {
            notify.extend_from_slice(&v4.octets());
        }
        notify.extend_from_slice(&from.port().to_be_bytes());
        ns_socket.send_to(&notify, addr_b).await.unwrap();
    });

    // Client B: listen for PUNCH_NOTIFY and punch back
    let b_clone = client_b.clone();
    let b_handle = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            let (len, from) = b_clone.recv_from(&mut buf).await.unwrap();
            let data = &buf[..len];

            if is_punch_notify(data) {
                if let Ok((_node_id, endpoints)) = decode_punch_notify(data) {
                    for ep in &endpoints {
                        let _ = b_clone.send_to(&[PUNCH_BYTE], ep.addr).await;
                    }
                }
            } else if is_punch_packet(data) {
                let _ = b_clone.send_to(&[PUNCH_BYTE], from).await;
                return;
            }
        }
    });

    // Client A: execute punch
    let config = PunchConfig {
        punch_delay: Duration::from_millis(10),
        punch_interval: Duration::from_millis(50),
        punch_timeout: Duration::from_secs(5),
        punch_all_addresses: true,
        keepalive_interval: Duration::from_secs(25),
    };

    let result =
        punch::execute_punch(&client_a, ns_addr, &node_a, &node_b, &[], &config).await;

    match result {
        Ok(PunchResult::Success { peer_addr }) => {
            assert_eq!(peer_addr.ip(), addr_b.ip());
        }
        Ok(PunchResult::TimedOut) => panic!("Expected success, got timeout"),
        Err(e) => panic!("Expected success, got error: {}", e),
    }

    ns_handle.await.unwrap();
    // b_handle may or may not finish (it's in a loop)
    b_handle.abort();
}

#[tokio::test]
async fn test_punch_timeout_with_unreachable_peer() {
    let ns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns_addr = ns_socket.local_addr().unwrap();

    let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let node_a = NodeId::from_bytes([0xAA; 16]);
    let node_b = NodeId::from_bytes([0xBB; 16]);

    // Fake NS: return a non-responsive endpoint
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (_len, from) = ns_socket.recv_from(&mut buf).await.unwrap();
        // Respond with an endpoint that won't respond
        let resp = vec![0x0A, 0x01, 4, 192, 0, 2, 1, 0x27, 0x10]; // 192.0.2.1:10000
        ns_socket.send_to(&resp, from).await.unwrap();
    });

    let config = PunchConfig {
        punch_delay: Duration::from_millis(0),
        punch_interval: Duration::from_millis(50),
        punch_timeout: Duration::from_millis(500),
        punch_all_addresses: true,
        keepalive_interval: Duration::from_secs(25),
    };

    let start = Instant::now();
    let result =
        punch::execute_punch(&client, ns_addr, &node_a, &node_b, &[], &config).await;
    let elapsed = start.elapsed();

    match result {
        Ok(PunchResult::TimedOut) => {
            assert!(elapsed >= Duration::from_millis(400));
            assert!(elapsed < Duration::from_secs(3));
        }
        other => panic!("Expected TimedOut, got {:?}", other),
    }
}

#[tokio::test]
async fn test_keepalive_prevents_nat_timeout() {
    // Test that keepalive packets are sent at the right interval
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = receiver.local_addr().unwrap();

    let mut tracker = KeepaliveTracker::new(Duration::from_millis(50));

    // Initially, should not send (just created)
    let sent = tracker.maybe_send(&sender, peer_addr).await.unwrap();
    assert!(!sent);

    // Wait for the interval to elapse
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Now it should send
    let sent = tracker.maybe_send(&sender, peer_addr).await.unwrap();
    assert!(sent);

    // Verify receiver got it
    let mut buf = [0u8; 10];
    let (len, _) = tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, 1);
    assert!(is_punch_packet(&buf[..len]));
}

#[tokio::test]
async fn test_graceful_fallback_when_punch_fails() {
    // When punch times out, the result should indicate timeout (not error),
    // allowing the caller to fall back to relay
    let ns_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ns_addr = ns_socket.local_addr().unwrap();

    let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    // Fake NS returns empty endpoints
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (_len, from) = ns_socket.recv_from(&mut buf).await.unwrap();
        let resp = vec![0x0A, 0x00]; // 0 endpoints
        ns_socket.send_to(&resp, from).await.unwrap();
    });

    let config = PunchConfig {
        punch_delay: Duration::from_millis(0),
        punch_interval: Duration::from_millis(50),
        punch_timeout: Duration::from_millis(200),
        punch_all_addresses: true,
        keepalive_interval: Duration::from_secs(25),
    };

    let result = punch::execute_punch(
        &client,
        ns_addr,
        &NodeId::from_bytes([0x11; 16]),
        &NodeId::from_bytes([0x22; 16]),
        &[],
        &config,
    )
    .await;

    // Should timeout (not error), allowing graceful fallback
    assert!(matches!(result, Ok(PunchResult::TimedOut)));
}

// ─── Two Peers Punch Each Other Simultaneously ──────────────────────

#[tokio::test]
async fn test_simultaneous_punch_both_sides() {
    let socket_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let socket_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());

    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    // Both sides send punch packets simultaneously
    let a_clone = socket_a.clone();
    let punch_a = tokio::spawn(async move {
        for _ in 0..10 {
            a_clone.send_to(&[PUNCH_BYTE], addr_b).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let b_clone = socket_b.clone();
    let punch_b = tokio::spawn(async move {
        for _ in 0..10 {
            b_clone.send_to(&[PUNCH_BYTE], addr_a).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    // Both should receive at least one punch
    let mut buf = [0u8; 10];

    let (len, from) = tokio::time::timeout(
        Duration::from_secs(2),
        socket_a.recv_from(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(len, 1);
    assert!(is_punch_packet(&buf[..len]));
    assert_eq!(from, addr_b);

    let (len, from) = tokio::time::timeout(
        Duration::from_secs(2),
        socket_b.recv_from(&mut buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(len, 1);
    assert!(is_punch_packet(&buf[..len]));
    assert_eq!(from, addr_a);

    punch_a.await.unwrap();
    punch_b.await.unwrap();
}
