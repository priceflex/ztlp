//! ZTLP Pipeline Interop Test
//!
//! Tests that Rust-generated ZTLP headers (magic, SessionID, HeaderAuthTag)
//! are correctly validated by Elixir, and vice versa.
//!
//! Protocol with Elixir test server:
//! - Send packets with correct/incorrect magic, SessionIDs, auth tags
//! - Elixir validates and reports results
//! - Test both data and handshake header formats

use ztlp_proto::packet::{DataHeader, HandshakeHeader, MsgType, SessionId, MAGIC};
use ztlp_proto::pipeline::compute_header_auth_tag;

use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ztlp-pipeline-interop <elixir_server_addr>");
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

    // ── Setup: Get shared session key from Elixir ─────────────────
    socket
        .send_to(b"PIPELINE_SETUP", server_addr)
        .expect("send setup failed");
    let (len, _) = socket.recv_from(&mut buf).expect("recv setup failed");
    let setup = &buf[..len];

    // Response: session_id(12) + auth_key(32)
    if setup.len() != 44 {
        eprintln!("Bad setup response: {} bytes (expected 44)", setup.len());
        std::process::exit(1);
    }

    let mut session_id_bytes = [0u8; 12];
    session_id_bytes.copy_from_slice(&setup[..12]);
    let session_id = SessionId(session_id_bytes);

    let mut auth_key = [0u8; 32];
    auth_key.copy_from_slice(&setup[12..44]);

    println!(
        "  Setup: session_id={}, auth_key={}...",
        hex::encode(session_id_bytes),
        hex::encode(&auth_key[..4])
    );

    // ── Test 1: Valid data packet header with auth tag ────────────
    print!("  Test 1: Rust data header validated by Elixir... ");

    let mut header = DataHeader::new(session_id, 1);
    let aad = header.aad_bytes();
    header.header_auth_tag = compute_header_auth_tag(&auth_key, &aad);

    let serialized = header.serialize();
    let payload = b"test_payload_data";
    let mut packet = b"VALIDATE_DATA_PACKET".to_vec();
    packet.extend_from_slice(&serialized);
    packet.extend_from_slice(payload);

    socket
        .send_to(&packet, server_addr)
        .expect("send data packet failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv validation failed");
    let resp = &buf[..rlen];
    if resp.starts_with(b"VALID") {
        println!("✓ Elixir validated Rust-generated data header + auth tag");
        passed += 1;
    } else {
        println!("✗ Validation failed: {}", String::from_utf8_lossy(resp));
        failed += 1;
    }

    // ── Test 2: Valid handshake header with auth tag ─────────────
    print!("  Test 2: Rust handshake header validated by Elixir... ");

    let mut hs_header = HandshakeHeader::new(MsgType::Data);
    hs_header.session_id = session_id;
    hs_header.packet_seq = 1;
    hs_header.payload_len = 32;

    let hs_aad = hs_header.aad_bytes();
    hs_header.header_auth_tag = compute_header_auth_tag(&auth_key, &hs_aad);

    let hs_serialized = hs_header.serialize();
    let mut hs_packet = b"VALIDATE_HS_PACKET".to_vec();
    hs_packet.extend_from_slice(&hs_serialized);
    // Add a dummy payload
    hs_packet.extend_from_slice(&[0u8; 32]);

    socket
        .send_to(&hs_packet, server_addr)
        .expect("send hs packet failed");
    let (rlen, _) = socket
        .recv_from(&mut buf)
        .expect("recv hs validation failed");
    let resp = &buf[..rlen];
    if resp.starts_with(b"VALID") {
        println!("✓ Elixir validated Rust-generated handshake header + auth tag");
        passed += 1;
    } else {
        println!("✗ Validation failed: {}", String::from_utf8_lossy(resp));
        failed += 1;
    }

    // ── Test 3: Wrong magic bytes rejected ──────────────────────
    print!("  Test 3: Wrong magic bytes rejected by Elixir... ");

    let mut bad_magic_packet = header.serialize();
    // Corrupt magic bytes
    bad_magic_packet[0] = 0xDE;
    bad_magic_packet[1] = 0xAD;

    let mut cmd = b"VALIDATE_DATA_PACKET".to_vec();
    cmd.extend_from_slice(&bad_magic_packet);
    cmd.extend_from_slice(payload);

    socket
        .send_to(&cmd, server_addr)
        .expect("send bad magic failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv bad magic response");
    let resp = &buf[..rlen];
    if resp.starts_with(b"REJECTED_MAGIC") || resp.starts_with(b"REJECTED") {
        println!("✓ Bad magic bytes correctly rejected");
        passed += 1;
    } else {
        println!(
            "✗ Expected rejection, got: {}",
            String::from_utf8_lossy(resp)
        );
        failed += 1;
    }

    // ── Test 4: Wrong SessionID rejected ────────────────────────
    print!("  Test 4: Wrong SessionID rejected by Elixir... ");

    let wrong_sid = SessionId::generate();
    let mut wrong_sid_header = DataHeader::new(wrong_sid, 2);
    let wrong_aad = wrong_sid_header.aad_bytes();
    wrong_sid_header.header_auth_tag = compute_header_auth_tag(&auth_key, &wrong_aad);

    let mut cmd = b"VALIDATE_DATA_PACKET".to_vec();
    cmd.extend_from_slice(&wrong_sid_header.serialize());
    cmd.extend_from_slice(payload);

    socket
        .send_to(&cmd, server_addr)
        .expect("send wrong sid failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv wrong sid response");
    let resp = &buf[..rlen];
    if resp.starts_with(b"REJECTED_SESSION") || resp.starts_with(b"REJECTED") {
        println!("✓ Unknown SessionID correctly rejected");
        passed += 1;
    } else {
        println!(
            "✗ Expected rejection, got: {}",
            String::from_utf8_lossy(resp)
        );
        failed += 1;
    }

    // ── Test 5: Wrong auth tag rejected ─────────────────────────
    print!("  Test 5: Wrong HeaderAuthTag rejected by Elixir... ");

    let mut bad_auth_header = DataHeader::new(session_id, 3);
    bad_auth_header.header_auth_tag = [0xFFu8; 16]; // garbage auth tag

    let mut cmd = b"VALIDATE_DATA_PACKET".to_vec();
    cmd.extend_from_slice(&bad_auth_header.serialize());
    cmd.extend_from_slice(payload);

    socket
        .send_to(&cmd, server_addr)
        .expect("send bad auth failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv bad auth response");
    let resp = &buf[..rlen];
    if resp.starts_with(b"REJECTED_AUTH") || resp.starts_with(b"REJECTED") {
        println!("✓ Invalid HeaderAuthTag correctly rejected");
        passed += 1;
    } else {
        println!(
            "✗ Expected rejection, got: {}",
            String::from_utf8_lossy(resp)
        );
        failed += 1;
    }

    // ── Test 6: Elixir-generated auth tag validated by Rust ─────
    print!("  Test 6: Elixir-generated data header validated by Rust... ");

    socket
        .send_to(b"GENERATE_DATA_PACKET", server_addr)
        .expect("send generate request");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv generated packet");
    let elixir_packet = &buf[..rlen];

    // Parse the data header (46 bytes: 26B pre-tag + 16B tag + 4B ext/payload)
    if elixir_packet.len() >= 46 {
        // Verify magic
        let magic = u16::from_be_bytes([elixir_packet[0], elixir_packet[1]]);
        if magic != MAGIC {
            println!("✗ Bad magic from Elixir: 0x{:04X}", magic);
            failed += 1;
        } else {
            // Extract SessionID (bytes 6..18 in data header)
            let mut sid = [0u8; 12];
            sid.copy_from_slice(&elixir_packet[6..18]);
            if sid == session_id_bytes {
                // Verify auth tag
                // AAD = bytes 0..26 (pre-tag) + bytes 42..46 (ext_len + payload_len)
                let mut aad = Vec::with_capacity(30);
                aad.extend_from_slice(&elixir_packet[..26]);
                aad.extend_from_slice(&elixir_packet[42..46]);
                let auth_tag = &elixir_packet[26..42];

                let expected_tag = compute_header_auth_tag(&auth_key, &aad);
                if auth_tag == expected_tag {
                    println!("✓ Rust validated Elixir-generated data header + auth tag");
                    passed += 1;
                } else {
                    println!("✗ Auth tag mismatch (Rust computed != Elixir generated)");
                    failed += 1;
                }
            } else {
                println!("✗ SessionID mismatch in Elixir packet");
                failed += 1;
            }
        }
    } else {
        println!(
            "✗ Elixir packet too short: {} bytes (need 46)",
            elixir_packet.len()
        );
        failed += 1;
    }

    // ── Test 7: Elixir-generated handshake header validated by Rust ──
    print!("  Test 7: Elixir-generated handshake header validated by Rust... ");

    socket
        .send_to(b"GENERATE_HS_PACKET", server_addr)
        .expect("send generate hs request");
    let (rlen, _) = socket
        .recv_from(&mut buf)
        .expect("recv generated hs packet");
    let elixir_hs_packet = &buf[..rlen];

    if elixir_hs_packet.len() >= 96 {
        let magic = u16::from_be_bytes([elixir_hs_packet[0], elixir_hs_packet[1]]);
        if magic != MAGIC {
            println!("✗ Bad magic from Elixir: 0x{:04X}", magic);
            failed += 1;
        } else {
            // Handshake header (96 bytes): auth tag at bytes 80..96
            // AAD = everything except the 16-byte auth tag = bytes 0..80
            let aad = &elixir_hs_packet[..80];
            let auth_tag = &elixir_hs_packet[80..96];

            let expected_tag = compute_header_auth_tag(&auth_key, aad);
            if auth_tag == expected_tag {
                println!("✓ Rust validated Elixir-generated handshake header + auth tag");
                passed += 1;
            } else {
                println!("✗ Handshake auth tag mismatch");
                failed += 1;
            }
        }
    } else {
        println!(
            "✗ Elixir handshake packet too short: {} bytes (need 96)",
            elixir_hs_packet.len()
        );
        failed += 1;
    }

    // ── Test 8: Truncated packet handled gracefully ─────────────
    print!("  Test 8: Truncated packet handled gracefully... ");

    let mut cmd = b"VALIDATE_DATA_PACKET".to_vec();
    cmd.extend_from_slice(&[0x5A, 0x37, 0x10]); // magic + partial header (3 bytes only)

    socket
        .send_to(&cmd, server_addr)
        .expect("send truncated failed");
    let (rlen, _) = socket.recv_from(&mut buf).expect("recv truncated response");
    let resp = &buf[..rlen];
    if resp.starts_with(b"REJECTED") {
        println!("✓ Truncated packet correctly rejected");
        passed += 1;
    } else {
        println!(
            "✗ Expected rejection, got: {}",
            String::from_utf8_lossy(resp)
        );
        failed += 1;
    }

    // ── Print summary ────────────────────────────────────────────
    println!();
    println!("  Results: {} passed, {} failed", passed, failed);

    if failed > 0 {
        std::process::exit(1);
    }
}
