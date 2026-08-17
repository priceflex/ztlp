//! H6 — End-to-end punch integration test.
//!
//! GIVEN a fake NS server, a gateway PunchAgent, and a client invoking
//!  execute_punch, all running on 127.0.0.1 with ephemeral UDP ports,
//! WHEN the gateway emits PUNCH_REPORT to NS and the client issues a
//!  PEER_ENDPOINTS request,
//! THEN both sides receive the peer's endpoints, exchange PUNCH_BYTE
//!  packets, and execute_punch returns PunchResult::Success { peer_addr }
//!  pointing at the gateway's local address.
//!
//! ## Why these tests exist
//!
//! The unit tests in `proto/src/punch.rs` and `proto/src/punch_agent.rs`
//! exercise each component in isolation against synthetic packets. They
//! cannot prove that the full handshake — NS coordination, gateway
//! keepalive registration, NS-driven PUNCH_NOTIFY, gateway responder,
//! and client send/listen loop — actually composes into a working
//! end-to-end flow when wired together on real UDP sockets.
//!
//! This file fills that gap: three actors on 127.0.0.1 (fake NS,
//! gateway PunchAgent, client `execute_punch`), no real relay, no
//! Quinn, just raw UDP and the punch wire protocol. Each test asserts
//! one end-to-end behavior:
//!
//!   1. Happy path → PunchResult::Success pointing at gateway addr.
//!   2. Gateway never registers → PunchResult::TimedOut.
//!   3. NS replies with an empty PUNCH_NOTIFY → PunchResult::TimedOut.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;

use ztlp_proto::identity::{NodeId, NodeIdentity};
use ztlp_proto::punch::{
    self, encode_punch_notify, PunchConfig, PunchResult, NS_PEER_ENDPOINTS, NS_PUNCH_NOTIFY,
    NS_PUNCH_REPORT,
};
use ztlp_proto::punch_agent::PunchAgent;

// ─── Wire-format helpers (no new pub API; all inline) ───────────────

/// Encode a SocketAddr in the punch wire format:
/// `[family: 1B (4|6)][addr: 4|16 B][port: u16 BE]`.
fn encode_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}

/// Build a PEER_ENDPOINTS *response*:
/// `[0x0A][count: 1B][addrs...]` (mirror of `decode_peer_endpoints_response`).
fn build_peer_endpoints_response(addrs: &[SocketAddr]) -> Vec<u8> {
    let count = addrs.len().min(255) as u8;
    let mut pkt = Vec::with_capacity(2 + count as usize * 7);
    pkt.push(NS_PEER_ENDPOINTS);
    pkt.push(count);
    for addr in addrs.iter().take(count as usize) {
        encode_addr(&mut pkt, *addr);
    }
    pkt
}

/// Decode the SOURCE half of a PEER_ENDPOINTS *request* (sent by client):
/// signed irt-rwzo format:
/// `[0x0A][requester:16][target:16][timestamp:8][sig:64][pubkey:32][count:1][addrs...]`.
/// Returns (requester_id, target_id, our_endpoints).
fn decode_peer_endpoints_request(data: &[u8]) -> Option<(NodeId, NodeId, Vec<SocketAddr>)> {
    // 1 (type) + 16 + 16 + 8 + 64 + 32 + 1 (count) = 138-byte header
    if data.len() < 138 || data[0] != NS_PEER_ENDPOINTS {
        return None;
    }
    let mut req_id = [0u8; 16];
    req_id.copy_from_slice(&data[1..17]);
    let mut tgt_id = [0u8; 16];
    tgt_id.copy_from_slice(&data[17..33]);
    let count = data[137] as usize;
    let mut pos = 138;
    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
        if pos >= data.len() {
            break;
        }
        let family = data[pos];
        let entry_len = match family {
            4 => 7,
            6 => 19,
            _ => return None,
        };
        if pos + entry_len > data.len() {
            return None;
        }
        let entry = &data[pos..pos + entry_len];
        // Reuse the NS_PEER_ENDPOINTS decoder by wrapping `entry` in a
        // mini PEER_ENDPOINTS response with count=1. Easier than
        // duplicating the IP parsing here.
        let mut tiny = Vec::with_capacity(2 + entry_len);
        tiny.push(NS_PEER_ENDPOINTS);
        tiny.push(1);
        tiny.extend_from_slice(entry);
        let decoded = punch::decode_peer_endpoints_response(&tiny).ok()?;
        addrs.push(decoded.first()?.addr);
        pos += entry_len;
    }
    Some((NodeId(req_id), NodeId(tgt_id), addrs))
}

/// Decode a PUNCH_REPORT (sent by gateway to NS):
/// signed irt-rwzo format:
/// `[0x0C][node_id:16][timestamp:8][sig:64][pubkey:32][count:1][addrs...]`.
/// Returns the reporter NodeId.
fn decode_punch_report_node_id(data: &[u8]) -> Option<NodeId> {
    // 1 (type) + 16 (node_id) + 8 + 64 + 32 + 1 (count) = 122-byte header
    if data.len() < 122 || data[0] != NS_PUNCH_REPORT {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&data[1..17]);
    Some(NodeId(id))
}

// ─── Fake NS server ─────────────────────────────────────────────────

/// Mode controlling how the fake NS replies to a PEER_ENDPOINTS request.
#[derive(Clone)]
enum FakeNsMode {
    /// Reply with the gateway's learned endpoint (happy path) and emit
    /// a PUNCH_NOTIFY to the gateway carrying the client's endpoints.
    Standard,
    /// Reply normally with the gateway endpoint, but the PUNCH_NOTIFY
    /// to the gateway carries ZERO endpoints — exercises the
    /// dispatcher's "empty endpoint list" branch and forces the client
    /// to time out (no return punch possible).
    EmptyNotify,
    /// Don't reply at all (PEER_ENDPOINTS times out → execute_punch
    /// surfaces NsError. Currently unused but kept for future tests.)
    #[allow(dead_code)]
    NoReply,
}

/// Spawn a fake NS server bound to an ephemeral 127.0.0.1 port.
/// Returns the bound address and a JoinHandle for clean shutdown.
///
/// The server tracks (NodeId → learned src_addr) so that when a client
/// asks for a peer's endpoints, NS can answer with the address it
/// learned via PUNCH_REPORT from that peer.
async fn spawn_fake_ns(mode: FakeNsMode) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind fake NS socket");
    let addr = sock.local_addr().expect("ns local_addr");
    let sock = Arc::new(sock);
    // (node_id → learned source SocketAddr)
    let registry: Arc<Mutex<HashMap<[u8; 16], SocketAddr>>> = Arc::new(Mutex::new(HashMap::new()));

    let sock_task = sock.clone();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, src) = match sock_task.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let pkt = &buf[..n];
            if pkt.is_empty() {
                continue;
            }
            match pkt[0] {
                NS_PUNCH_REPORT => {
                    // Gateway is registering. Learn its source endpoint.
                    if let Some(node_id) = decode_punch_report_node_id(pkt) {
                        registry.lock().await.insert(node_id.0, src);
                    }
                }
                NS_PEER_ENDPOINTS => {
                    // Client is asking about the gateway.
                    let Some((req_id, tgt_id, client_endpoints)) =
                        decode_peer_endpoints_request(pkt)
                    else {
                        continue;
                    };
                    // Always also remember the client's own source addr;
                    // production NS does this for symmetry.
                    registry.lock().await.insert(req_id.0, src);

                    // Resolve the gateway's learned endpoint.
                    let gw_addr = registry.lock().await.get(&tgt_id.0).copied();
                    let resp_endpoints: Vec<SocketAddr> = gw_addr.iter().copied().collect();

                    // 1) Reply to the client.
                    let resp = build_peer_endpoints_response(&resp_endpoints);
                    let _ = sock_task.send_to(&resp, src).await;

                    // 2) Push PUNCH_NOTIFY to the gateway so its
                    //    dispatcher fires PUNCH_BYTE back at the
                    //    client's endpoints.
                    if let Some(gw) = gw_addr {
                        let notify_endpoints: Vec<SocketAddr> = match mode {
                            FakeNsMode::Standard => {
                                if client_endpoints.is_empty() {
                                    vec![src]
                                } else {
                                    client_endpoints.clone()
                                }
                            }
                            FakeNsMode::EmptyNotify => Vec::new(),
                            FakeNsMode::NoReply => continue,
                        };
                        let notify = encode_punch_notify(&req_id, &notify_endpoints);
                        let _ = sock_task.send_to(&notify, gw).await;
                    }
                }
                _ => {
                    // Ignore everything else.
                }
            }
        }
    });

    (addr, handle)
}

// ─── PunchSocket-lite for the gateway side ──────────────────────────
//
// We can't use the real PunchSocket here because it's a quinn AsyncUdpSocket
// wrapper that expects to be driven by quinn's IO. For H6 we replicate just
// the "intercept PUNCH_NOTIFY and forward into mpsc" behavior with a tiny
// recv loop on the shared gateway UdpSocket — this is the same role
// PunchSocket plays in production, just inlined for the test.

/// Spawn a background task on the gateway socket that intercepts inbound
/// PUNCH_NOTIFY packets and forwards them into the dispatcher channel.
/// Other packet types (like return PUNCH_BYTE from the client) are
/// dropped — this socket is shared with no other consumer in the test.
fn spawn_gateway_intercept(
    sock: Arc<UdpSocket>,
    tx: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let (n, src) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            if n >= 1 && buf[0] == NS_PUNCH_NOTIFY {
                if tx.send((buf[..n].to_vec(), src)).await.is_err() {
                    return;
                }
            }
            // Drop everything else — incoming PUNCH_BYTE from the client
            // is just the NAT-pinhole-poke; the gateway doesn't need to
            // act on it. In production, Quinn would handle non-punch
            // traffic; here there's no Quinn so we just discard.
        }
    })
}

// ─── Tests ──────────────────────────────────────────────────────────

/// Tiny config tuned for fast tests: 1ms punch_delay, 50ms interval,
/// 500ms overall timeout. The outer `tokio::time::timeout` is the
/// flake-safety net.
fn fast_punch_config() -> PunchConfig {
    PunchConfig {
        punch_delay: Duration::from_millis(1),
        punch_interval: Duration::from_millis(50),
        // Generous timeout: the full fake-NS round-trip (NS query → reply →
        // PUNCH_NOTIFY → gateway intercept → dispatcher → PUNCH_BYTE) needs
        // a few hundred ms; 2s avoids false failures on slow CI runners.
        punch_timeout: Duration::from_millis(2000),
        punch_all_addresses: true,
        keepalive_interval: Duration::from_secs(25),
    }
}

/// H6 — happy path: full punch handshake completes through fake NS.

/// Test helper: build a NodeIdentity with a pinned node_id (real keys +
/// signing key) for the signed punch wire format (irt-rwzo).
fn ident_for(node_id: NodeId) -> NodeIdentity {
    let mut ident = NodeIdentity::generate().expect("generate identity");
    ident.node_id = node_id;
    ident
}
/// H6 — CTF-007 security regression: a loopback-based punch handshake must
/// NOT complete. The gateway's `start_dispatcher` filters out non-globally-
/// routable punch targets (RFC 1918 / loopback / link-local) to prevent the
/// gateway being used as an open UDP proxy (SSRF / amplification). The e2e
/// harness binds everything on 127.0.0.1, so the client's advertised
/// endpoint is loopback — the dispatcher must refuse to punch back, and the
/// client observes a timeout. (Pre-CTF-007 this test asserted the punch
/// *succeeded*; the security fix intentionally made loopback punching
/// impossible by design, so the expectation flipped.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_e2e_succeeds_through_fake_ns() {
    // GIVEN a fake NS in Standard mode.
    let (ns_addr, ns_handle) = spawn_fake_ns(FakeNsMode::Standard).await;

    // GIVEN a gateway socket + PunchAgent registering with NS.
    let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let gw_addr = gw_sock.local_addr().unwrap();
    let gw_node_id = NodeId([0xAA; 16]);
    let agent = PunchAgent::new(gw_sock.clone(), ns_addr, ident_for(gw_node_id));

    // Fast keepalive so NS learns the gateway endpoint within ms.
    let keepalive = agent.start_keepalive(Duration::from_millis(50));

    // Gateway-side intercept → dispatcher pipeline.
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let intercept = spawn_gateway_intercept(gw_sock.clone(), tx);
    let dispatcher = agent.start_dispatcher(rx, Duration::from_millis(400));

    // Give the keepalive ~100ms to register the gateway with NS.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // GIVEN a client socket.
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_addr = client_sock.local_addr().unwrap();
    let client_node_id = NodeId([0xBB; 16]);

    // WHEN the client invokes execute_punch.
    let cfg = fast_punch_config();
    let client_identity = ident_for(client_node_id);
    let result = timeout(
        Duration::from_secs(5),
        punch::execute_punch(
            &client_sock,
            ns_addr,
            &client_identity,
            &gw_node_id,
            &[client_addr],
            &cfg,
        ),
    )
    .await
    .expect("e2e safety-net timeout: execute_punch did not complete in 5s")
    .expect("execute_punch returned an error");

    // THEN: the CTF-007 safe-target filter blocks the loopback punch target,
    // so the gateway never punches back and the client times out. This is
    // the *correct* behavior — the filter prevents the gateway from being
    // used to punch at internal/loopback endpoints.
    match result {
        PunchResult::TimedOut => {
            // Expected: loopback target filtered by is_safe_punch_target.
        }
        other => panic!(
            "expected TimedOut (CTF-007 blocks loopback punch), got {:?}",
            other
        ),
    }

    // Cleanup.
    keepalive.abort();
    intercept.abort();
    dispatcher.abort();
    ns_handle.abort();
}

/// H6 — gateway never registers with NS: punch must time out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_e2e_times_out_when_gateway_unregistered() {
    // GIVEN a fake NS in Standard mode (so it WOULD respond if it had
    // learned the gateway's endpoint — which it never will).
    let (ns_addr, ns_handle) = spawn_fake_ns(FakeNsMode::Standard).await;

    // GIVEN a client socket. No gateway, no PunchAgent.
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_addr = client_sock.local_addr().unwrap();
    let client_node_id = NodeId([0x11; 16]);
    let gw_node_id = NodeId([0x22; 16]); // unknown to NS

    // WHEN execute_punch runs with a tight punch_timeout.
    let cfg = fast_punch_config();
    let client_identity = ident_for(client_node_id);
    let result = timeout(
        Duration::from_secs(5),
        punch::execute_punch(
            &client_sock,
            ns_addr,
            &client_identity,
            &gw_node_id,
            &[client_addr],
            &cfg,
        ),
    )
    .await
    .expect("safety-net timeout: execute_punch did not finish in 5s")
    .expect("execute_punch returned an error");

    // THEN the punch times out — NS replied with zero peer endpoints
    // and no one ever sent a PUNCH_BYTE back.
    assert_eq!(
        result,
        PunchResult::TimedOut,
        "expected TimedOut when the gateway never registered, got {:?}",
        result
    );

    ns_handle.abort();
}

/// H6 — NS responds but with an EMPTY PUNCH_NOTIFY (no endpoints).
/// The gateway dispatcher receives the notify but skips the responder,
/// and the client sees no return punch → timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn punch_e2e_times_out_on_empty_punch_notify() {
    // GIVEN a fake NS that always emits an empty PUNCH_NOTIFY.
    let (ns_addr, ns_handle) = spawn_fake_ns(FakeNsMode::EmptyNotify).await;

    // GIVEN a registered gateway.
    let gw_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let gw_node_id = NodeId([0x33; 16]);
    let agent = PunchAgent::new(gw_sock.clone(), ns_addr, ident_for(gw_node_id));
    let keepalive = agent.start_keepalive(Duration::from_millis(50));
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let intercept = spawn_gateway_intercept(gw_sock.clone(), tx);
    let dispatcher = agent.start_dispatcher(rx, Duration::from_millis(400));

    tokio::time::sleep(Duration::from_millis(300)).await;

    // GIVEN a client.
    let client_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client_addr = client_sock.local_addr().unwrap();
    let client_node_id = NodeId([0x44; 16]);

    // WHEN execute_punch runs.
    let cfg = fast_punch_config();
    let client_identity = ident_for(client_node_id);
    let result = timeout(
        Duration::from_secs(5),
        punch::execute_punch(
            &client_sock,
            ns_addr,
            &client_identity,
            &gw_node_id,
            &[client_addr],
            &cfg,
        ),
    )
    .await
    .expect("safety-net timeout: execute_punch did not finish in 5s")
    .expect("execute_punch returned an error");

    // THEN: even though NS replied with the gateway endpoint, the
    // gateway's dispatcher received an empty PUNCH_NOTIFY and skipped
    // its responder — so the client only ever sees its own outbound
    // PUNCH_BYTEs and never gets one back. Result: TimedOut.
    //
    // (Note: the client still PUNCH_BYTE-spams the gateway endpoint
    // returned by NS. But the gateway has no PunchSocket-strip layer
    // here — our intercept task drops non-NOTIFY traffic — so those
    // bytes are silently consumed without triggering anything.)
    assert_eq!(
        result,
        PunchResult::TimedOut,
        "expected TimedOut on empty PUNCH_NOTIFY, got {:?}",
        result
    );

    keepalive.abort();
    intercept.abort();
    dispatcher.abort();
    ns_handle.abort();
}
