//! ZTLP Edge Case / Error Handling Interop Test
//!
//! Tests boundary conditions and error handling across Rust↔Elixir:
//! - Packet truncation (partial headers)
//! - Wrong magic bytes
//! - MTU boundary packets (exactly 1500 bytes)
//! - Rapid reconnection
//! - Concurrent operations

use ztlp_proto::packet::{DataHeader, SessionId};
use ztlp_proto::pipeline::compute_header_auth_tag;

use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ztlp-edge-cases <elixir_server_addr>");
        std::process::exit(1);
    }
    let server_addr = &args[1];

    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind failed");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut buf = [0u8; 65535];
    let mut passed = 0u32;
    let mut failed = 0u32;

    // Setup: get session credentials
    socket
        .send_to(b"EDGE_SETUP", server_addr)
        .expect("send setup failed");
    let (len, _) = socket.recv_from(&mut buf).expect("recv setup failed");
    let setup = &buf[..len];

    if setup.len() != 44 {
        eprintln!("Bad setup response: {} bytes (expected 44)", setup.len());
        std::process::exit(1);
    }

    let mut session_id_bytes = [0u8; 12];
    session_id_bytes.copy_from_slice(&setup[..12]);
    let session_id = SessionId(session_id_bytes);

    let mut auth_key = [0u8; 32];
    auth_key.copy_from_slice(&setup[12..44]);

    // ── Test 1: Zero-length payload ─────────────────────────────
    print!("  Test 1: Zero-length payload data packet... ");

    let mut header = DataHeader::new(session_id, 100);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&auth_key, &aad);

    let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
    packet.extend_from_slice(&header.serialize());
    // No payload — just the header

    socket.send_to(&packet, server_addr).expect("send failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];
    if resp.starts_with(b"VALID") {
        println!("✓ Zero-length payload accepted (header-only packet)");
        passed += 1;
    } else {
        println!("✗ Response: {}", String::from_utf8_lossy(resp));
        failed += 1;
    }

    // ── Test 2: MTU boundary packet (exactly 1500 bytes) ────────
    print!("  Test 2: MTU boundary packet (1500 bytes total)... ");

    let mut header = DataHeader::new(session_id, 101);
    let header_bytes = header.serialize();
    let payload_len = 1500 - header_bytes.len(); // Fill to exactly 1500

    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&auth_key, &aad);

    let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
    packet.extend_from_slice(&header.serialize());
    packet.extend_from_slice(&vec![0xAB; payload_len]);

    socket
        .send_to(&packet, server_addr)
        .expect("send MTU packet failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];
    if resp.starts_with(b"VALID") {
        println!("✓ MTU boundary packet (1500 bytes) accepted");
        passed += 1;
    } else {
        println!("✗ Response: {}", String::from_utf8_lossy(resp));
        failed += 1;
    }

    // ── Test 3: Oversized packet (near UDP limit) ───────────────
    print!("  Test 3: Large packet (8000 bytes)... ");

    let mut header = DataHeader::new(session_id, 102);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&auth_key, &aad);

    let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
    packet.extend_from_slice(&header.serialize());
    packet.extend_from_slice(&vec![0xCD; 8000 - 42]); // Large payload

    socket
        .send_to(&packet, server_addr)
        .expect("send large packet failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];
    if resp.starts_with(b"VALID") {
        println!("✓ Large packet (8000 bytes) accepted");
        passed += 1;
    } else {
        println!("✗ Response: {}", String::from_utf8_lossy(resp));
        failed += 1;
    }

    // ── Test 4: Minimum valid packet (just the header) ──────────
    print!("  Test 4: Minimum valid data packet (46-byte header only)... ");

    let mut header = DataHeader::new(session_id, 103);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&auth_key, &aad);

    let serialized = header.serialize();
    assert_eq!(
        serialized.len(),
        46,
        "data header should be exactly 46 bytes (v0.5.1 format)"
    );

    let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
    packet.extend_from_slice(&serialized);

    socket
        .send_to(&packet, server_addr)
        .expect("send min packet failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];
    if resp.starts_with(b"VALID") {
        println!("✓ Minimum 46-byte data header accepted");
        passed += 1;
    } else {
        println!("✗ Response: {}", String::from_utf8_lossy(resp));
        failed += 1;
    }

    // ── Test 5: Rapid sequential packets (10 in burst) ──────────
    print!("  Test 5: Rapid burst of 10 sequential packets... ");

    let start = Instant::now();
    let mut all_ok = true;

    for i in 0..10u64 {
        let seq = 200 + i;
        let mut header = DataHeader::new(session_id, seq);
        let aad = header.aad_bytes();
        header.header_auth_tag = compute_header_auth_tag(&auth_key, &aad);

        let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
        packet.extend_from_slice(&header.serialize());
        packet.extend_from_slice(&[i as u8; 10]);

        socket
            .send_to(&packet, server_addr)
            .expect("send burst failed");
        let (rlen, _) = socket.recv_from(&mut buf).expect("recv burst failed");
        if !buf[..rlen].starts_with(b"VALID") {
            all_ok = false;
            break;
        }
    }

    let elapsed = start.elapsed();
    if all_ok {
        println!("✓ All 10 burst packets validated in {:?}", elapsed);
        passed += 1;
    } else {
        println!("✗ Some burst packets failed");
        failed += 1;
    }

    // ── Test 6: Packet with all-zero SessionID ──────────────────
    print!("  Test 6: All-zero SessionID (should be rejected)... ");

    let zero_sid = SessionId([0u8; 12]);
    let mut zero_header = DataHeader::new(zero_sid, 300);
    let aad = zero_header.aad_bytes();
    zero_header.header_auth_tag = compute_header_auth_tag(&auth_key, &aad);

    let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
    packet.extend_from_slice(&zero_header.serialize());
    packet.extend_from_slice(b"test");

    socket
        .send_to(&packet, server_addr)
        .expect("send zero sid failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];
    if resp.starts_with(b"REJECTED") {
        println!("✓ Zero SessionID correctly rejected");
        passed += 1;
    } else {
        println!(
            "✗ Expected rejection, got: {}",
            String::from_utf8_lossy(resp)
        );
        failed += 1;
    }

    // ── Test 7: Partial header (various truncation lengths) ─────
    print!("  Test 7: Truncated packets at various lengths... ");

    let truncation_lengths = [0, 1, 2, 3, 5, 10, 20, 41, 45]; // All less than 46-byte data header
    let mut all_rejected = true;

    for &tlen in &truncation_lengths {
        let full_header = header.serialize();
        let truncated = &full_header[..tlen.min(full_header.len())];

        let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
        packet.extend_from_slice(truncated);

        socket
            .send_to(&packet, server_addr)
            .expect("send truncated failed");
        let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
        if !buf[..rlen].starts_with(b"REJECTED") {
            all_rejected = false;
            eprintln!(
                "    Truncation at {} bytes NOT rejected: {}",
                tlen,
                String::from_utf8_lossy(&buf[..rlen])
            );
        }
    }

    if all_rejected {
        println!(
            "✓ All {} truncation lengths correctly rejected",
            truncation_lengths.len()
        );
        passed += 1;
    } else {
        println!("✗ Some truncated packets not rejected");
        failed += 1;
    }

    // ── Test 8: Max sequence number ─────────────────────────────
    print!("  Test 8: Maximum sequence number (u64::MAX)... ");

    let mut header = DataHeader::new(session_id, u64::MAX);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&auth_key, &aad);

    let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
    packet.extend_from_slice(&header.serialize());
    packet.extend_from_slice(b"max_seq");

    socket
        .send_to(&packet, server_addr)
        .expect("send max seq failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];
    if resp.starts_with(b"VALID") {
        println!("✓ Max sequence number u64::MAX accepted");
        passed += 1;
    } else {
        println!("✗ Response: {}", String::from_utf8_lossy(resp));
        failed += 1;
    }

    // ── Print summary ────────────────────────────────────────────
    println!();
    println!("  Results: {} passed, {} failed", passed, failed);

    if failed > 0 {
        std::process::exit(1);
    }
}
