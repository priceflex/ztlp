//! ZTLP Cross-Language Interop Test
//!
//! Tests that Rust ZTLP clients can communicate through an Elixir relay.
//!
//! Protocol with the test harness (shell script):
//! 1. Binds two UDP sockets on random ports
//! 2. Prints "PORTS <port_a> <port_b> <session_id_hex>" to stdout
//! 3. Waits for "SESSION_REGISTERED" on stdin
//! 4. Sends ZTLP packets from A→relay and B→relay
//! 5. Verifies forwarding in both directions
//! 6. Exits 0 on success, non-zero on failure

#![deny(unsafe_code)]

use std::io::{self, BufRead};
use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use ztlp_proto::packet::{DataHeader, HandshakeHeader, MsgType, SessionId};

#[derive(Parser)]
struct Args {
    /// Relay port on localhost
    #[clap(long)]
    relay_port: u16,

    /// Relay host (default: 127.0.0.1)
    #[clap(long, default_value = "127.0.0.1")]
    relay_host: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let relay_addr: SocketAddr = format!("{}:{}", args.relay_host, args.relay_port).parse()?;

    // Bind two nodes on random ports
    let sock_a = UdpSocket::bind("127.0.0.1:0").await?;
    let sock_b = UdpSocket::bind("127.0.0.1:0").await?;

    let addr_a = sock_a.local_addr()?;
    let addr_b = sock_b.local_addr()?;

    // Generate a SessionID
    let session_id = SessionId::generate();

    // Tell the harness our ports and session ID
    println!("PORTS {} {} {}", addr_a.port(), addr_b.port(), session_id);

    // Wait for the harness to register the session with the relay
    eprintln!("[interop] Waiting for SESSION_REGISTERED...");
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim() == "SESSION_REGISTERED" {
            break;
        }
    }
    eprintln!("[interop] Session registered, starting tests");

    let mut passed = 0;
    let mut failed = 0;

    // ── Test 1: Data packet A → Relay → B ────────────────────────
    eprintln!("[interop] Test 1: Data packet A → Relay → B");
    {
        let hdr = DataHeader::new(session_id, 1);
        let payload = b"interop-test-a-to-b";
        let mut pkt = hdr.serialize();
        pkt.extend_from_slice(payload);

        sock_a.send_to(&pkt, relay_addr).await?;

        let mut buf = vec![0u8; 2048];
        match timeout(Duration::from_secs(2), sock_b.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                if buf[..len] == pkt[..] {
                    eprintln!("[interop]   ✓ B received exact packet from {} ({} bytes)", from, len);
                    passed += 1;
                } else {
                    eprintln!("[interop]   ✗ B received different data ({} bytes, expected {})", len, pkt.len());
                    failed += 1;
                }
            }
            Ok(Err(e)) => {
                eprintln!("[interop]   ✗ B recv error: {}", e);
                failed += 1;
            }
            Err(_) => {
                eprintln!("[interop]   ✗ B timed out waiting for packet");
                failed += 1;
            }
        }
    }

    // ── Test 2: Data packet B → Relay → A ────────────────────────
    eprintln!("[interop] Test 2: Data packet B → Relay → A");
    {
        let hdr = DataHeader::new(session_id, 2);
        let payload = b"interop-test-b-to-a";
        let mut pkt = hdr.serialize();
        pkt.extend_from_slice(payload);

        sock_b.send_to(&pkt, relay_addr).await?;

        let mut buf = vec![0u8; 2048];
        match timeout(Duration::from_secs(2), sock_a.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                if buf[..len] == pkt[..] {
                    eprintln!("[interop]   ✓ A received exact packet from {} ({} bytes)", from, len);
                    passed += 1;
                } else {
                    eprintln!("[interop]   ✗ A received different data ({} bytes, expected {})", len, pkt.len());
                    failed += 1;
                }
            }
            Ok(Err(e)) => {
                eprintln!("[interop]   ✗ A recv error: {}", e);
                failed += 1;
            }
            Err(_) => {
                eprintln!("[interop]   ✗ A timed out waiting for packet");
                failed += 1;
            }
        }
    }

    // ── Test 3: Handshake packet (non-HELLO) A → Relay → B ─────
    // Note: The Elixir relay intercepts HELLO/HELLO_ACK for session creation
    // but forwards other handshake msg types (e.g. Data type in a handshake header).
    eprintln!("[interop] Test 3: Handshake-format packet (MsgType::Data) A → Relay → B");
    {
        let mut hdr = HandshakeHeader::new(MsgType::Data);
        hdr.session_id = session_id;
        hdr.src_node_id = [0xAA; 16];
        hdr.packet_seq = 0;
        hdr.payload_len = 5;
        let mut pkt = hdr.serialize();
        pkt.extend_from_slice(b"hello");

        sock_a.send_to(&pkt, relay_addr).await?;

        let mut buf = vec![0u8; 2048];
        match timeout(Duration::from_secs(2), sock_b.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                if buf[..len] == pkt[..] {
                    eprintln!("[interop]   ✓ B received handshake-format packet from {} ({} bytes)", from, len);
                    passed += 1;
                } else {
                    eprintln!("[interop]   ✗ B received different data ({} bytes, expected {})", len, pkt.len());
                    failed += 1;
                }
            }
            Ok(Err(e)) => {
                eprintln!("[interop]   ✗ B recv error: {}", e);
                failed += 1;
            }
            Err(_) => {
                eprintln!("[interop]   ✗ B timed out waiting for handshake-format packet");
                failed += 1;
            }
        }
    }

    // ── Test 4: Multiple packets in sequence ─────────────────────
    eprintln!("[interop] Test 4: 10 sequential packets A → B through relay");
    {
        let mut seq_passed = 0;
        for seq in 10..20u64 {
            let hdr = DataHeader::new(session_id, seq);
            let payload = format!("seq-{}", seq);
            let mut pkt = hdr.serialize();
            pkt.extend_from_slice(payload.as_bytes());

            sock_a.send_to(&pkt, relay_addr).await?;

            let mut buf = vec![0u8; 2048];
            match timeout(Duration::from_millis(500), sock_b.recv_from(&mut buf)).await {
                Ok(Ok((len, _))) if buf[..len] == pkt[..] => {
                    seq_passed += 1;
                }
                _ => {}
            }
        }
        if seq_passed == 10 {
            eprintln!("[interop]   ✓ All 10 packets forwarded correctly");
            passed += 1;
        } else {
            eprintln!("[interop]   ✗ Only {}/10 packets forwarded", seq_passed);
            failed += 1;
        }
    }

    // ── Test 5: Verify relay doesn't forward wrong SessionID ─────
    eprintln!("[interop] Test 5: Packet with wrong SessionID not forwarded");
    {
        let wrong_session = SessionId::generate();
        let hdr = DataHeader::new(wrong_session, 99);
        let pkt = hdr.serialize();

        sock_a.send_to(&pkt, relay_addr).await?;

        let mut buf = vec![0u8; 2048];
        match timeout(Duration::from_millis(300), sock_b.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                eprintln!("[interop]   ✗ B received packet with wrong SessionID ({} bytes)", len);
                failed += 1;
            }
            _ => {
                eprintln!("[interop]   ✓ B correctly received nothing (wrong SessionID dropped)");
                passed += 1;
            }
        }
    }

    // ── Results ──────────────────────────────────────────────────
    eprintln!();
    eprintln!("[interop] Results: {} passed, {} failed", passed, failed);

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}
