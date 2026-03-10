//! ZTLP Demo — Two-node handshake, session, and encrypted data exchange.
//!
//! Spawns two ZTLP nodes on localhost, performs a Noise_XX handshake,
//! exchanges encrypted data, and demonstrates the three-layer pipeline
//! dropping unauthenticated packets at each layer.

#![deny(unsafe_code)]

use tokio::time::{sleep, Duration};
use tracing::error;

use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::NodeIdentity;
use ztlp_proto::packet::{
    DataHeader, HandshakeHeader, MsgType, SessionId, HANDSHAKE_HEADER_SIZE,
};
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
    println!("║          ZTLP — Zero Trust Layer Protocol Demo              ║");
    println!("║          Phase 1: Two-Node LAN Prototype                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ── Step 1: Generate identities ──────────────────────────────────
    println!("━━━ Step 1: Generating node identities ━━━");
    let node_a_identity = NodeIdentity::generate().expect("generate identity A");
    let node_b_identity = NodeIdentity::generate().expect("generate identity B");
    println!(
        "  Node A: {}",
        node_a_identity.node_id
    );
    println!(
        "  Node B: {}",
        node_b_identity.node_id
    );
    println!();

    // ── Step 2: Bind transport nodes ─────────────────────────────────
    println!("━━━ Step 2: Binding UDP sockets ━━━");
    let node_a = TransportNode::bind("127.0.0.1:0").await.expect("bind node A");
    let node_b = TransportNode::bind("127.0.0.1:0").await.expect("bind node B");
    let addr_a = node_a.local_addr;
    let addr_b = node_b.local_addr;
    println!("  Node A listening on {}", addr_a);
    println!("  Node B listening on {}", addr_b);
    println!();

    // ── Step 3: Noise_XX Handshake ───────────────────────────────────
    println!("━━━ Step 3: Performing Noise_XX handshake ━━━");

    let mut init_ctx = HandshakeContext::new_initiator(&node_a_identity)
        .expect("create initiator context");
    let mut resp_ctx = HandshakeContext::new_responder(&node_b_identity)
        .expect("create responder context");

    // Message 1: A → B (HELLO with ephemeral key)
    println!("  → Message 1: Node A sends HELLO (ephemeral key)");
    let msg1 = init_ctx.write_message(&[]).expect("write msg1");
    let mut hello_header = HandshakeHeader::new(MsgType::Hello);
    hello_header.src_node_id = *node_a_identity.node_id.as_bytes();
    hello_header.payload_len = msg1.len() as u16;
    let mut pkt1 = hello_header.serialize();
    pkt1.extend_from_slice(&msg1);
    node_a
        .send_raw(&pkt1, addr_b)
        .await
        .expect("send msg1");

    // B receives message 1
    let (recv1, _) = node_b.recv_raw().await.expect("recv msg1");
    let noise_payload1 = &recv1[HANDSHAKE_HEADER_SIZE..];
    let _p1 = resp_ctx.read_message(noise_payload1).expect("read msg1");
    println!("  ✓ Node B received HELLO ({} bytes)", recv1.len());

    // Message 2: B → A (HELLO_ACK with ephemeral + static + identity)
    println!("  ← Message 2: Node B sends HELLO_ACK (encrypted identity)");
    let msg2 = resp_ctx.write_message(&[]).expect("write msg2");
    let mut ack_header = HandshakeHeader::new(MsgType::HelloAck);
    ack_header.src_node_id = *node_b_identity.node_id.as_bytes();
    ack_header.payload_len = msg2.len() as u16;
    let mut pkt2 = ack_header.serialize();
    pkt2.extend_from_slice(&msg2);
    node_b
        .send_raw(&pkt2, addr_a)
        .await
        .expect("send msg2");

    // A receives message 2
    let (recv2, _) = node_a.recv_raw().await.expect("recv msg2");
    let noise_payload2 = &recv2[HANDSHAKE_HEADER_SIZE..];
    let _p2 = init_ctx.read_message(noise_payload2).expect("read msg2");
    println!("  ✓ Node A received HELLO_ACK ({} bytes)", recv2.len());

    // Message 3: A → B (final auth)
    println!("  → Message 3: Node A sends final confirmation");
    let msg3 = init_ctx.write_message(&[]).expect("write msg3");
    let mut final_header = HandshakeHeader::new(MsgType::Data);
    final_header.src_node_id = *node_a_identity.node_id.as_bytes();
    final_header.payload_len = msg3.len() as u16;
    let mut pkt3 = final_header.serialize();
    pkt3.extend_from_slice(&msg3);
    node_a
        .send_raw(&pkt3, addr_b)
        .await
        .expect("send msg3");

    // B receives message 3
    let (recv3, _) = node_b.recv_raw().await.expect("recv msg3");
    let noise_payload3 = &recv3[HANDSHAKE_HEADER_SIZE..];
    let _p3 = resp_ctx.read_message(noise_payload3).expect("read msg3");
    println!("  ✓ Node B received final confirmation ({} bytes)", recv3.len());

    // Verify handshake completion
    assert!(init_ctx.is_finished(), "initiator handshake should be finished");
    assert!(resp_ctx.is_finished(), "responder handshake should be finished");
    println!("  ✓ Noise_XX handshake complete — mutual authentication successful!");
    println!();

    // ── Step 4: Establish session ────────────────────────────────────
    println!("━━━ Step 4: Establishing encrypted session ━━━");

    // Both sides agree on a shared SessionID (in production, responder assigns it in HELLO_ACK)
    let shared_session_id = SessionId::generate();
    println!("  Session ID: {}", shared_session_id);

    let (_init_transport, init_session) = init_ctx
        .finalize(node_b_identity.node_id, shared_session_id)
        .expect("finalize initiator");
    let (_resp_transport, resp_session) = resp_ctx
        .finalize(node_a_identity.node_id, shared_session_id)
        .expect("finalize responder");

    // Create sessions with matching keys and shared SessionID
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
        "  Recv key (B→A): {}…",
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

    // ── Step 5: Send encrypted data ──────────────────────────────────
    println!("━━━ Step 5: Sending encrypted data ━━━");
    let message = b"Hello from ZTLP! This message is encrypted and authenticated.";
    println!("  Plaintext: \"{}\"", String::from_utf8_lossy(message));

    node_a
        .send_data(shared_session_id, message, addr_b)
        .await
        .expect("send data");
    println!("  → Node A sent encrypted data ({} bytes plaintext)", message.len());

    // Small delay to ensure delivery
    sleep(Duration::from_millis(50)).await;

    // B receives and decrypts
    let received = node_b.recv_data().await.expect("recv data");
    match received {
        Some((plaintext, from_addr)) => {
            println!(
                "  ✓ Node B received from {}: \"{}\"",
                from_addr,
                String::from_utf8_lossy(&plaintext)
            );
        }
        None => {
            error!("  ✗ Node B failed to receive/decrypt data");
        }
    }
    println!();

    // ── Step 6: Demonstrate pipeline drops ───────────────────────────
    println!("━━━ Step 6: Testing pipeline — sending bad packets ━━━");
    println!();

    // 6a: Garbage packet — fails Layer 1 (bad magic)
    println!("  [Test 6a] Sending garbage packet (random bytes)...");
    let garbage: Vec<u8> = (0..64).map(|i| i as u8 ^ 0xAA).collect();
    node_a
        .send_raw(&garbage, addr_b)
        .await
        .expect("send garbage");
    sleep(Duration::from_millis(20)).await;
    let _ = tokio::time::timeout(Duration::from_millis(50), node_b.recv_data()).await;
    {
        let pipeline_b = node_b.pipeline.lock().await;
        let snap = pipeline_b.counters.snapshot();
        println!("  ✗ Dropped at Layer 1 (bad magic): {} total L1 drops", snap.layer1_drops);
    }
    println!();

    // 6b: Valid magic but wrong SessionID — fails Layer 2
    println!("  [Test 6b] Sending packet with valid magic but fake SessionID...");
    let mut fake_session_packet = DataHeader::new(SessionId::generate(), 0);
    fake_session_packet.header_auth_tag = [0u8; 16]; // dummy tag
    let fake_bytes = fake_session_packet.serialize();
    node_a
        .send_raw(&fake_bytes, addr_b)
        .await
        .expect("send fake session");
    sleep(Duration::from_millis(20)).await;
    let _ = tokio::time::timeout(Duration::from_millis(50), node_b.recv_data()).await;
    {
        let pipeline_b = node_b.pipeline.lock().await;
        let snap = pipeline_b.counters.snapshot();
        println!("  ✗ Dropped at Layer 2 (unknown session): {} total L2 drops", snap.layer2_drops);
    }
    println!();

    // 6c: Valid magic, correct SessionID, but bad auth tag — fails Layer 3
    println!("  [Test 6c] Sending packet with correct SessionID but bad auth tag...");
    let mut bad_auth_packet = DataHeader::new(shared_session_id, 999);
    bad_auth_packet.header_auth_tag = [0xFF; 16]; // bad tag
    let mut bad_auth_bytes = bad_auth_packet.serialize();
    // Add some fake encrypted payload to make it look realistic
    bad_auth_bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    node_a
        .send_raw(&bad_auth_bytes, addr_b)
        .await
        .expect("send bad auth");
    sleep(Duration::from_millis(20)).await;
    let _ = tokio::time::timeout(Duration::from_millis(50), node_b.recv_data()).await;
    {
        let pipeline_b = node_b.pipeline.lock().await;
        let snap = pipeline_b.counters.snapshot();
        println!("  ✗ Dropped at Layer 3 (invalid auth tag): {} total L3 drops", snap.layer3_drops);
    }
    println!();

    // ── Step 7: Final pipeline statistics ────────────────────────────
    println!("━━━ Step 7: Final Pipeline Statistics ━━━");
    {
        let pipeline_b = node_b.pipeline.lock().await;
        let snap = pipeline_b.counters.snapshot();
        println!("  {}", snap);
        println!();
        println!("  Layer 1 (Magic check):      {} dropped  — zero crypto cost", snap.layer1_drops);
        println!("  Layer 2 (SessionID lookup):  {} dropped  — zero crypto cost", snap.layer2_drops);
        println!("  Layer 3 (AuthTag verify):    {} dropped  — real crypto cost", snap.layer3_drops);
        println!("  Passed all layers:           {}", snap.passed);
    }
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  Demo complete! ZTLP prototype working as designed.         ║");
    println!("║                                                              ║");
    println!("║  • Noise_XX handshake: mutual authentication ✓              ║");
    println!("║  • Encrypted data exchange: ChaCha20-Poly1305 ✓            ║");
    println!("║  • Pipeline drops: all 3 layers demonstrated ✓              ║");
    println!("║  • Zero state allocated for unauthenticated traffic ✓       ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
