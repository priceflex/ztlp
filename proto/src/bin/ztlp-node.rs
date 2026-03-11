//! ZTLP Node — persistent daemon that acts as initiator or responder.
//!
//! This is the main binary for running a ZTLP node. It performs the full
//! Noise_XX handshake over the network, establishes an encrypted session,
//! and then enters a bidirectional data exchange loop.
//!
//! ## Responder mode (default)
//!
//! ```bash
//! ztlp-node --listen 0.0.0.0:23095
//! ```
//!
//! Waits for an inbound HELLO, completes the three-message Noise_XX handshake,
//! registers the session in the pipeline, and enters the data loop.
//!
//! ## Initiator mode
//!
//! ```bash
//! ztlp-node --connect 192.168.1.10:23095
//! ```
//!
//! Sends HELLO to the peer, completes the handshake, and enters the data loop.
//!
//! ## Identity persistence
//!
//! ```bash
//! ztlp-node --identity node.json --listen 0.0.0.0:23095
//! ```
//!
//! Loads identity from `node.json` if it exists; otherwise generates a new one
//! and saves it so the NodeID persists across restarts.

#![deny(unsafe_code)]

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::packet::{HandshakeHeader, MsgType, SessionId, HANDSHAKE_HEADER_SIZE};
use ztlp_proto::session::SessionState;
use ztlp_proto::transport::TransportNode;

/// ZTLP Node — Zero Trust Layer Protocol node daemon.
///
/// Runs as either an initiator (--connect) or responder (default).
/// Performs Noise_XX mutual authentication and establishes an encrypted session.
#[derive(Parser, Debug)]
#[command(name = "ztlp-node", about = "ZTLP protocol node")]
struct Args {
    /// Address to listen on (e.g., 0.0.0.0:23095).
    #[arg(short, long, default_value = "0.0.0.0:23095")]
    listen: String,

    /// Path to identity JSON file.
    /// If the file exists, loads identity from it.
    /// If not, generates a new identity and saves it here.
    /// If omitted, generates an ephemeral identity (lost on exit).
    #[arg(short, long)]
    identity: Option<PathBuf>,

    /// Peer address to connect to (initiator mode).
    /// If omitted, runs in responder mode.
    #[arg(short, long)]
    connect: Option<String>,

    /// Optional relay address to send through instead of direct peer.
    #[arg(short, long)]
    relay: Option<String>,

    /// Handshake timeout in seconds. Default: 10.
    #[arg(long, default_value = "10")]
    handshake_timeout: u64,
}

/// Timeout for receiving individual handshake messages.
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

/// Load or generate a node identity.
/// If `path` is Some and the file exists, loads from it.
/// If `path` is Some and the file doesn't exist, generates and saves.
/// If `path` is None, generates an ephemeral identity.
fn load_or_generate_identity(
    path: &Option<PathBuf>,
) -> Result<NodeIdentity, Box<dyn std::error::Error>> {
    match path {
        Some(p) if p.exists() => {
            info!("loading identity from {}", p.display());
            let ident = NodeIdentity::load(p)?;
            info!("loaded node ID: {}", ident.node_id);
            Ok(ident)
        }
        Some(p) => {
            info!(
                "no identity file at {} — generating new identity",
                p.display()
            );
            let ident = NodeIdentity::generate()?;
            ident.save(p)?;
            info!(
                "saved new identity to {} — node ID: {}",
                p.display(),
                ident.node_id
            );
            Ok(ident)
        }
        None => {
            info!("no identity file specified — generating ephemeral identity");
            let ident = NodeIdentity::generate()?;
            info!(
                "ephemeral node ID: {} (will be lost on exit)",
                ident.node_id
            );
            Ok(ident)
        }
    }
}

/// Run the initiator flow: send HELLO, receive HELLO_ACK, send final message.
///
/// Returns the established SessionState and the peer's address.
async fn run_initiator(
    node: &TransportNode,
    identity: &NodeIdentity,
    peer_addr: SocketAddr,
    send_addr: SocketAddr, // May differ from peer_addr if using relay
    handshake_timeout: Duration,
) -> Result<(SessionState, SocketAddr), Box<dyn std::error::Error>> {
    info!("initiator mode — connecting to {}", peer_addr);
    if send_addr != peer_addr {
        info!("routing through relay at {}", send_addr);
    }

    let mut ctx = HandshakeContext::new_initiator(identity)?;
    let session_id = SessionId::generate();
    info!("proposed session ID: {}", session_id);

    // ── Message 1: HELLO (ephemeral key) ─────────────────────────
    // The initiator sends its ephemeral public key. No static key yet —
    // this is the "XX" pattern where identities are exchanged encrypted.
    info!("sending HELLO (message 1 of 3)");
    let msg1 = ctx.write_message(&[])?;
    let mut hello_header = HandshakeHeader::new(MsgType::Hello);
    hello_header.session_id = session_id;
    hello_header.src_node_id = *identity.node_id.as_bytes();
    hello_header.payload_len = msg1.len() as u16;
    let mut pkt1 = hello_header.serialize();
    pkt1.extend_from_slice(&msg1);
    node.send_raw(&pkt1, send_addr).await?;

    // ── Receive Message 2: HELLO_ACK ─────────────────────────────
    // The responder sends back: its ephemeral key + encrypted static key + identity.
    info!("waiting for HELLO_ACK (message 2 of 3)...");
    let (recv2, from2) = timeout(handshake_timeout, node.recv_raw())
        .await
        .map_err(|_| "handshake timeout waiting for HELLO_ACK")??;

    // Verify it's a handshake packet for our session
    if recv2.len() < HANDSHAKE_HEADER_SIZE {
        return Err("received packet too short for handshake header".into());
    }
    let recv2_header = HandshakeHeader::deserialize(&recv2)?;
    if recv2_header.msg_type != MsgType::HelloAck {
        return Err(format!("expected HELLO_ACK, got {:?}", recv2_header.msg_type).into());
    }
    if recv2_header.session_id != session_id {
        return Err("HELLO_ACK has wrong SessionID".into());
    }

    let noise_payload2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload2)?;
    info!("received HELLO_ACK from {} ({} bytes)", from2, recv2.len());

    // ── Message 3: Final confirmation ────────────────────────────
    // Initiator sends its encrypted static key + identity.
    // After this, both sides have mutually authenticated.
    info!("sending final confirmation (message 3 of 3)");
    let msg3 = ctx.write_message(&[])?;
    let mut final_header = HandshakeHeader::new(MsgType::Data);
    final_header.session_id = session_id;
    final_header.src_node_id = *identity.node_id.as_bytes();
    final_header.payload_len = msg3.len() as u16;
    let mut pkt3 = final_header.serialize();
    pkt3.extend_from_slice(&msg3);
    node.send_raw(&pkt3, send_addr).await?;

    // ── Finalize ─────────────────────────────────────────────────
    if !ctx.is_finished() {
        return Err("handshake did not complete after 3 messages".into());
    }

    // Extract the peer's NodeID from the HELLO_ACK header
    let peer_node_id = ztlp_proto::identity::NodeId::from_bytes(recv2_header.src_node_id);
    let (_transport, session) = ctx.finalize(peer_node_id, session_id)?;

    info!("handshake complete — peer node ID: {}", peer_node_id);
    info!("session established: {}", session_id);

    Ok((session, from2))
}

/// Run the responder flow: wait for HELLO, send HELLO_ACK, receive final message.
///
/// Returns the established SessionState and the initiator's address.
async fn run_responder(
    node: &TransportNode,
    identity: &NodeIdentity,
    handshake_timeout: Duration,
) -> Result<(SessionState, SocketAddr, SocketAddr), Box<dyn std::error::Error>> {
    info!("responder mode — waiting for HELLO...");

    let mut ctx = HandshakeContext::new_responder(identity)?;

    // ── Receive Message 1: HELLO ─────────────────────────────────
    // Wait for an initiator to send its ephemeral public key.
    let (recv1, from1) = timeout(handshake_timeout, async {
        loop {
            let (data, addr) = node.recv_raw().await?;
            // Filter for handshake packets with HELLO msg type
            if data.len() >= HANDSHAKE_HEADER_SIZE {
                if let Ok(hdr) = HandshakeHeader::deserialize(&data) {
                    if hdr.msg_type == MsgType::Hello {
                        return Ok::<_, Box<dyn std::error::Error>>((data, addr));
                    }
                }
            }
            // Not a HELLO — discard and keep waiting
            warn!("received non-HELLO packet from {} — ignoring", addr);
        }
    })
    .await
    .map_err(|_| "handshake timeout waiting for HELLO")??;

    let recv1_header = HandshakeHeader::deserialize(&recv1)?;
    let session_id = recv1_header.session_id;
    let noise_payload1 = &recv1[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload1)?;
    info!("received HELLO from {} — session ID: {}", from1, session_id);

    // ── Message 2: HELLO_ACK ─────────────────────────────────────
    // Responder sends: ephemeral key + encrypted(static key + identity).
    info!("sending HELLO_ACK (message 2 of 3)");
    let msg2 = ctx.write_message(&[])?;
    let mut ack_header = HandshakeHeader::new(MsgType::HelloAck);
    ack_header.session_id = session_id;
    ack_header.src_node_id = *identity.node_id.as_bytes();
    ack_header.payload_len = msg2.len() as u16;
    let mut pkt2 = ack_header.serialize();
    pkt2.extend_from_slice(&msg2);
    node.send_raw(&pkt2, from1).await?;

    // ── Receive Message 3: Final confirmation ────────────────────
    info!("waiting for final confirmation (message 3 of 3)...");
    let (recv3, from3) = timeout(RECV_TIMEOUT, node.recv_raw())
        .await
        .map_err(|_| "handshake timeout waiting for message 3")??;

    if recv3.len() < HANDSHAKE_HEADER_SIZE {
        return Err("message 3 too short for handshake header".into());
    }
    let recv3_header = HandshakeHeader::deserialize(&recv3)?;
    if recv3_header.session_id != session_id {
        return Err("message 3 has wrong SessionID".into());
    }

    let noise_payload3 = &recv3[HANDSHAKE_HEADER_SIZE..];
    ctx.read_message(noise_payload3)?;

    // ── Finalize ─────────────────────────────────────────────────
    if !ctx.is_finished() {
        return Err("handshake did not complete after 3 messages".into());
    }

    let peer_node_id = ztlp_proto::identity::NodeId::from_bytes(recv1_header.src_node_id);
    let (_transport, session) = ctx.finalize(peer_node_id, session_id)?;

    info!("handshake complete — peer node ID: {}", peer_node_id);
    info!("session established: {}", session_id);

    // from1 = where the HELLO came from (could be relay or direct peer)
    // from3 = where msg3 came from (should match from1)
    Ok((session, from1, from3))
}

/// Interactive data exchange loop.
///
/// Reads lines from stdin and sends them encrypted.
/// Receives encrypted packets and prints the plaintext.
/// Ctrl+C or EOF exits.
async fn data_loop(
    node: &TransportNode,
    session_id: SessionId,
    send_dest: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("entering data loop — type a message and press Enter to send");
    info!(
        "encrypted traffic flows to {} (session {})",
        send_dest, session_id
    );
    println!();
    println!("--- ZTLP encrypted session active ---");
    println!("Type a message and press Enter to send. Ctrl+C to exit.");
    println!();

    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    loop {
        tokio::select! {
            // Read a line from stdin → send encrypted
            line = lines.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        if text.is_empty() {
                            continue;
                        }
                        match node.send_data(session_id, text.as_bytes(), send_dest).await {
                            Ok(()) => {
                                info!("sent: \"{}\" ({} bytes)", text, text.len());
                            }
                            Err(e) => {
                                error!("send error: {}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        // EOF on stdin
                        info!("stdin closed — exiting");
                        break;
                    }
                    Err(e) => {
                        error!("stdin read error: {}", e);
                        break;
                    }
                }
            }

            // Receive a packet → decrypt and print
            result = node.recv_data() => {
                match result {
                    Ok(Some((plaintext, from))) => {
                        let text = String::from_utf8_lossy(&plaintext);
                        println!("[{}] {}", from, text);
                    }
                    Ok(None) => {
                        // Packet dropped by pipeline — silently continue
                    }
                    Err(e) => {
                        error!("receive error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ztlp_proto=info".parse()?),
        )
        .init();

    let args = Args::parse();

    // Load or generate identity
    let identity = load_or_generate_identity(&args.identity)?;

    // Bind transport
    let node = TransportNode::bind(&args.listen).await?;
    info!("bound to {}", node.local_addr);

    let handshake_timeout = Duration::from_secs(args.handshake_timeout);

    if let Some(peer_addr_str) = &args.connect {
        // ── Initiator mode ──────────────────────────────────────
        let peer_addr: SocketAddr = peer_addr_str
            .parse()
            .map_err(|e| format!("invalid peer address '{}': {}", peer_addr_str, e))?;

        // If --relay is specified, route through the relay
        let send_addr = if let Some(relay_str) = &args.relay {
            relay_str
                .parse()
                .map_err(|e| format!("invalid relay address '{}': {}", relay_str, e))?
        } else {
            peer_addr
        };

        let (session, _peer_from) =
            run_initiator(&node, &identity, peer_addr, send_addr, handshake_timeout).await?;

        // Register session in the pipeline
        let session_id = session.session_id;
        {
            let mut pipeline = node.pipeline.lock().await;
            pipeline.register_session(session);
        }

        // Enter data loop — send to relay or peer directly
        data_loop(&node, session_id, send_addr).await?;
    } else {
        // ── Responder mode ──────────────────────────────────────
        let (session, peer_addr, _) = run_responder(&node, &identity, handshake_timeout).await?;

        // Register session in the pipeline
        let session_id = session.session_id;
        {
            let mut pipeline = node.pipeline.lock().await;
            pipeline.register_session(session);
        }

        // Enter data loop — reply to whoever sent us the handshake
        data_loop(&node, session_id, peer_addr).await?;
    }

    Ok(())
}
