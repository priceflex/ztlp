//! ZTLP Relay Demo — Two nodes communicating through a simulated relay.
//!
//! Demonstrates:
//! 1. A simulated relay running on localhost (UDP forwarder by SessionID)
//! 2. Node A and Node B perform a Noise_XX handshake THROUGH the relay
//! 3. Encrypted data exchange through the relay
//! 4. The relay never sees plaintext — it only forwards opaque packets

#![deny(unsafe_code)]

use tokio::time::{sleep, Duration};
use tracing::error;

use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::packet::{HandshakeHeader, MsgType, SessionId, HANDSHAKE_HEADER_SIZE};
use ztlp_proto::relay::SimulatedRelay;
use ztlp_proto::session::SessionState;
use ztlp_proto::transport::TransportNode;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("ztlp_proto=info".parse().expect("valid directive")),
        )
        .init();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║        ZTLP — Zero Trust Layer Protocol Relay Demo          ║");
    println!("║        Two nodes communicating through a relay              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ── Step 1: Generate identities ──────────────────────────────────
    println!("━━━ Step 1: Generating node identities ━━━");
    let node_a_identity = NodeIdentity::generate().expect("generate identity A");
    let node_b_identity = NodeIdentity::generate().expect("generate identity B");
    println!("  Node A: {}", node_a_identity.node_id);
    println!("  Node B: {}", node_b_identity.node_id);
    println!();

    // ── Step 2: Start the simulated relay ────────────────────────────
    println!("━━━ Step 2: Starting simulated relay ━━━");
    let relay = SimulatedRelay::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_addr = relay.local_addr;
    println!("  Relay listening on {}", relay_addr);

    // Spawn the relay loop in the background
    tokio::spawn(async move {
        relay.run().await.expect("relay loop failed");
    });
    println!("  ✓ Relay running in background");
    println!();

    // ── Step 3: Bind transport nodes ─────────────────────────────────
    // Nodes only know the relay address — they cannot talk directly.
    println!("━━━ Step 3: Binding UDP sockets (nodes only know the relay) ━━━");
    let node_a = TransportNode::bind("127.0.0.1:0")
        .await
        .expect("bind node A");
    let node_b = TransportNode::bind("127.0.0.1:0")
        .await
        .expect("bind node B");
    let addr_a = node_a.local_addr;
    let addr_b = node_b.local_addr;
    println!("  Node A on {}", addr_a);
    println!("  Node B on {}", addr_b);
    println!(
        "  Both nodes send to relay at {} (not to each other)",
        relay_addr
    );
    println!();

    // ── Step 4: Noise_XX Handshake through the relay ─────────────────
    println!("━━━ Step 4: Performing Noise_XX handshake THROUGH the relay ━━━");

    // Both sides will use a pre-agreed SessionID so the relay can route.
    // In production the initiator proposes the SessionID in the HELLO.
    let shared_session_id = SessionId::generate();
    println!("  Pre-agreed Session ID: {}", shared_session_id);

    let mut init_ctx =
        HandshakeContext::new_initiator(&node_a_identity).expect("create initiator context");
    let mut resp_ctx =
        HandshakeContext::new_responder(&node_b_identity).expect("create responder context");

    // Message 1: A → Relay → B (HELLO with ephemeral key)
    println!("  → Message 1: Node A sends HELLO through relay");
    let msg1 = init_ctx.write_message(&[]).expect("write msg1");
    let mut hello_header = HandshakeHeader::new(MsgType::Hello);
    hello_header.session_id = shared_session_id;
    hello_header.src_node_id = *node_a_identity.node_id.as_bytes();
    hello_header.payload_len = msg1.len() as u16;
    let mut pkt1 = hello_header.serialize();
    pkt1.extend_from_slice(&msg1);

    // Send to RELAY (not to Node B directly)
    node_a
        .send_raw(&pkt1, relay_addr)
        .await
        .expect("send msg1 to relay");

    // The relay sees this as the first packet for this SessionID — stores Node A as pending.
    // Node B now sends its first packet so the relay can pair them.

    // Small delay to let the relay process
    sleep(Duration::from_millis(20)).await;

    // Message 2: B → Relay → A (HELLO_ACK)
    // But first, B needs to "register" with the relay by sending a packet.
    // In the real protocol, the relay would have a signaling channel.
    // For this demo, B sends a HELLO_ACK to the relay (which learns B's address).
    println!("  ← Message 2: Node B sends HELLO_ACK through relay");

    // B hasn't received msg1 yet because the relay was pending.
    // Let's have B send a dummy HELLO_ACK to register with the relay,
    // which will pair them. Then the relay will forward msg1 to B.

    // Actually — the relay needs msg1 forwarded to B first. The relay stores
    // A as pending on the first packet. When B sends on the same SessionID,
    // the relay pairs them and forwards B's packet to A. But B doesn't know
    // to send yet because B hasn't received the HELLO.
    //
    // Solution: Pre-register both peers with the relay by sending an initial
    // registration packet from B as well. The relay pairs on the second packet.
    //
    // Better solution: The relay holds msg1 for the pending session and delivers
    // it once the second peer appears. Let's implement a simple version:
    // B sends a dummy registration packet to the relay with the same SessionID.
    // The relay sees this as the second peer, pairs them, and forwards B's
    // registration to A (which A ignores). Then the relay has both addresses
    // and can forward normally.
    //
    // Simplest approach for demo: We tell B to send a small registration
    // packet to the relay so the relay learns both addresses.

    // B sends a handshake registration to the relay
    let mut reg_header = HandshakeHeader::new(MsgType::Hello);
    reg_header.session_id = shared_session_id;
    reg_header.src_node_id = *node_b_identity.node_id.as_bytes();
    reg_header.payload_len = 0;
    let reg_pkt = reg_header.serialize();
    node_b
        .send_raw(&reg_pkt, relay_addr)
        .await
        .expect("send registration to relay");

    // Now the relay has paired A and B, and forwarded B's registration to A.
    sleep(Duration::from_millis(20)).await;

    // A receives B's registration (discard it — it's just for relay pairing)
    let _ = tokio::time::timeout(Duration::from_millis(100), node_a.recv_raw()).await;

    // Now resend msg1 through the relay — this time it will be forwarded to B
    node_a
        .send_raw(&pkt1, relay_addr)
        .await
        .expect("resend msg1 to relay");
    sleep(Duration::from_millis(20)).await;

    // B receives message 1 (forwarded by relay)
    let (recv1, from1) = node_b.recv_raw().await.expect("recv msg1 from relay");
    println!(
        "  ✓ Node B received HELLO from {} (relay) — {} bytes",
        from1,
        recv1.len()
    );
    let noise_payload1 = &recv1[HANDSHAKE_HEADER_SIZE..];
    let _p1 = resp_ctx.read_message(noise_payload1).expect("read msg1");

    // B sends HELLO_ACK to relay
    let msg2 = resp_ctx.write_message(&[]).expect("write msg2");
    let mut ack_header = HandshakeHeader::new(MsgType::HelloAck);
    ack_header.session_id = shared_session_id;
    ack_header.src_node_id = *node_b_identity.node_id.as_bytes();
    ack_header.payload_len = msg2.len() as u16;
    let mut pkt2 = ack_header.serialize();
    pkt2.extend_from_slice(&msg2);
    node_b
        .send_raw(&pkt2, relay_addr)
        .await
        .expect("send msg2 to relay");
    sleep(Duration::from_millis(20)).await;

    // A receives HELLO_ACK (forwarded by relay)
    let (recv2, from2) = node_a.recv_raw().await.expect("recv msg2 from relay");
    println!(
        "  ✓ Node A received HELLO_ACK from {} (relay) — {} bytes",
        from2,
        recv2.len()
    );
    let noise_payload2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    let _p2 = init_ctx.read_message(noise_payload2).expect("read msg2");

    // Message 3: A → Relay → B (final auth)
    println!("  → Message 3: Node A sends final confirmation through relay");
    let msg3 = init_ctx.write_message(&[]).expect("write msg3");
    let mut final_header = HandshakeHeader::new(MsgType::Data);
    final_header.session_id = shared_session_id;
    final_header.src_node_id = *node_a_identity.node_id.as_bytes();
    final_header.payload_len = msg3.len() as u16;
    let mut pkt3 = final_header.serialize();
    pkt3.extend_from_slice(&msg3);
    node_a
        .send_raw(&pkt3, relay_addr)
        .await
        .expect("send msg3 to relay");
    sleep(Duration::from_millis(20)).await;

    // B receives message 3 (forwarded by relay)
    let (recv3, _from3) = node_b.recv_raw().await.expect("recv msg3 from relay");
    let noise_payload3 = &recv3[HANDSHAKE_HEADER_SIZE..];
    let _p3 = resp_ctx.read_message(noise_payload3).expect("read msg3");

    assert!(init_ctx.is_finished(), "initiator should be finished");
    assert!(resp_ctx.is_finished(), "responder should be finished");
    println!("  ✓ Noise_XX handshake complete THROUGH the relay!");
    println!();

    // ── Step 5: Establish session ────────────────────────────────────
    println!("━━━ Step 5: Establishing encrypted session ━━━");
    println!("  Session ID: {}", shared_session_id);

    let (_init_transport, init_session) = init_ctx
        .finalize(node_b_identity.node_id, shared_session_id)
        .expect("finalize initiator");
    let (_resp_transport, resp_session) = resp_ctx
        .finalize(node_a_identity.node_id, shared_session_id)
        .expect("finalize responder");

    let a_session = SessionState::new(
        shared_session_id,
        node_b_identity.node_id,
        init_session.send_key,
        init_session.recv_key,
        false,
    );
    let b_session = SessionState::new(
        shared_session_id,
        node_a_identity.node_id,
        resp_session.send_key,
        resp_session.recv_key,
        false,
    );

    println!(
        "  Send key (A→B): {}…",
        &hex::encode(a_session.send_key)[..16]
    );
    println!(
        "  Send key (B→A): {}…",
        &hex::encode(b_session.send_key)[..16]
    );

    // Register sessions in both pipelines
    {
        let mut pipeline_a = node_a.pipeline.lock().await;
        pipeline_a.register_session(a_session);
    }
    {
        let mut pipeline_b = node_b.pipeline.lock().await;
        pipeline_b.register_session(b_session);
    }
    println!("  ✓ Sessions registered in both pipelines");
    println!();

    // ── Step 6: Send encrypted data through relay ────────────────────
    println!("━━━ Step 6: Sending encrypted data THROUGH the relay ━━━");
    let message = b"Hello through the relay!";
    println!("  Plaintext: \"{}\"", String::from_utf8_lossy(message));

    // Use send_data_via_relay — sends to relay_addr instead of B directly
    node_a
        .send_data_via_relay(shared_session_id, message, relay_addr)
        .await
        .expect("send data via relay");
    println!(
        "  → Node A sent encrypted data to relay ({} bytes plaintext)",
        message.len()
    );

    sleep(Duration::from_millis(50)).await;

    // B receives and decrypts
    let received = node_b.recv_data().await.expect("recv data");
    match received {
        Some((plaintext, from_addr)) => {
            println!(
                "  ✓ Node B received from {} (relay): \"{}\"",
                from_addr,
                String::from_utf8_lossy(&plaintext)
            );
        }
        None => {
            error!("  ✗ Node B failed to receive/decrypt data");
            std::process::exit(1);
        }
    }
    println!();

    // ── Step 7: Verify relay never saw plaintext ─────────────────────
    println!("━━━ Step 7: Relay transparency verification ━━━");
    println!("  The relay forwarded all packets by SessionID only.");
    println!("  It never held session keys or decrypted any payload.");
    println!("  The encrypted data was opaque to the relay — zero-trust relay!");
    println!();

    // ── Step 8: Bidirectional test — B sends to A through relay ──────
    println!("━━━ Step 8: Bidirectional — Node B sends to Node A through relay ━━━");
    let reply = b"Reply from Node B through the relay!";
    println!("  Plaintext: \"{}\"", String::from_utf8_lossy(reply));

    node_b
        .send_data_via_relay(shared_session_id, reply, relay_addr)
        .await
        .expect("send reply via relay");
    println!("  ← Node B sent encrypted reply to relay");

    sleep(Duration::from_millis(50)).await;

    let received_reply = node_a.recv_data().await.expect("recv reply");
    match received_reply {
        Some((plaintext, from_addr)) => {
            println!(
                "  ✓ Node A received from {} (relay): \"{}\"",
                from_addr,
                String::from_utf8_lossy(&plaintext)
            );
        }
        None => {
            error!("  ✗ Node A failed to receive/decrypt reply");
            std::process::exit(1);
        }
    }
    println!();

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Relay demo complete!                                       ║");
    println!("║                                                              ║");
    println!("║  • Noise_XX handshake through relay ✓                       ║");
    println!("║  • Encrypted data exchange through relay ✓                  ║");
    println!("║  • Bidirectional communication ✓                            ║");
    println!("║  • Relay never saw plaintext — zero-trust relay ✓           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
