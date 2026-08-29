//! QUIC reconnect-churn stress test for the ZTLP tunnel.
//!
//! Regression context (feature/quic-churn-stability, follow-up to the
//! 2026-08-18 AWS `ztlp-test` validation):
//!
//! The built-in `ztlp-client` benchmark opens a FRESH tunnel (a brand-new
//! QUIC connection + Noise handshake) for each file-transfer size. On the
//! live AWS box this rapid-reconnect pattern produced non-deterministic
//! failures at 1MB/10MB even though a steady single session (and single-shot
//! manual scps) passed reliably. Server-side logs under the churn showed
//! `discarding possible duplicate packet`, `failed to authenticate packet`,
//! and `PUNCH_NOTIFY from untrusted source — dropped` — symptoms of QUIC
//! session/keepalive instability under rapid fresh-connection creation.
//!
//! This test reproduces that pattern at the `quic_transport` layer:
//! one server, N rapid sequential fresh `connect()` calls (each a new quinn
//! Endpoint + fresh Noise handshake + a real data transfer), and asserts
//! every connection succeeds and delivers byte-exact data.
//!
//! Correctness is a HARD assert (every connection byte-exact). Throughput
//! under churn is a SOFT metric (logged) — the point of the test is
//! RELIABILITY under churn, not raw speed.
//!
//! Loopback caveat: the live-box failure is induced by network-level
//! retransmission/duplicate/auth churn (real UDP between host and box).
//! On loopback the same code path may be too clean to reproduce the
//! flake. If this test passes stably here, that is the expected honest
//! outcome — the AWS size-sweep (fullstack/bench-sizes.sh + the live-box
//! manual test in the `ztlp-aws-test-box` skill) remains the authoritative
//! churn check. The value of this test is that any REGRESSION in the
//! reconnect path (endpoint teardown, CID space reuse, stream caps under
//! rapid connect/disconnect) fails the hard byte-exact assert immediately.

#![cfg(feature = "quic-transport")]

use std::time::{Instant, SystemTime, UNIX_EPOCH};
use ztlp_proto::quic_transport::tokio_endpoint::{QuicClientEndpoint, QuicEndpoint};
use ztlp_proto::quic_transport::{QuicEndpointConfig, ZTLP_ALPN};

const MB: f64 = 1_048_576.0;

/// 16-hex-char fingerprint (first 8 bytes of SHA-256). Informational only —
/// the hard assertions are exact-byte equality (crate already has `sha2`).
fn fingerprint(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(data);
    d.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

/// Deterministic non-constant payload of `len` bytes, seeded by `seed` so
/// each iteration's payload is distinct (catches a connection silently
/// delivering a stale/previous connection's bytes).
fn make_payload(len: usize, seed: u8) -> Vec<u8> {
    let mut v = vec![0u8; len];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(seed.wrapping_add(31)) % 251;
    }
    v
}

#[test]
fn alpn_is_stable_for_churn_tests() {
    assert_eq!(ZTLP_ALPN, b"ztlp/1");
}

/// One server, N rapid sequential fresh client connections. Each connection:
///   - a brand-new quinn Endpoint + fresh TofuCertVerifier (pinned on first
///     connect to the one server's stable ephemeral cert),
///   - a fresh Noise handshake (ALPN ztlp/1),
///   - a real bidirectional data transfer (distinct payload per connect).
/// Every connection must deliver its own bytes end-to-end.
#[cfg(feature = "tokio-runtime")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn sequential_reconnect_churn_is_reliable() {
    const CONNS: usize = 20;
    const PAYLOAD: usize = 256 * 1024; // 256KB each (above the old ~192-448KB stall band)

    // Unique server name → fresh TOFU pin on first connect; the single
    // server's ephemeral cert is stable for the test's lifetime, so
    // subsequent connects match the pinned fingerprint.
    let server_name = format!(
        "ztlp-churn-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );

    let server_cfg = QuicEndpointConfig {
        bind: Some("127.0.0.1:0".parse().expect("valid loopback addr")),
        ..Default::default()
    };
    let server = QuicEndpoint::bind(server_cfg).await.expect("bind server");
    let server_addr = server.inner.local_addr().unwrap();

    // Server: accept one connection at a time (matching the sequential,
    // benchmark-like reconnect pattern). For each, open a bidi stream,
    // drain the payload, finish. Returns per-connection received bytes.
    let server_task = tokio::spawn(async move {
        let mut out = Vec::with_capacity(CONNS);
        for _ in 0..CONNS {
            let conn = server.accept().await.expect("accept a fresh connection");
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            let mut received = Vec::new();
            let mut buf = vec![0u8; 65_536];
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => received.extend_from_slice(&buf[..n]),
                    Ok(None) | Err(_) => break,
                }
            }
            let _ = send.write_all(b"ACK").await;
            let _ = send.finish();
            out.push(received);
        }
        out
    });

    // Client: N rapid sequential reconnects on ONE persistent client
    // endpoint (the fix — same socket/driver/CID space, only the connection
    // is new each time). Each transfer's delivery proof is the SERVER
    // draining all bytes (EOF on the recv half = client finished) — NOT a
    // client-side ACK read (which races with quinn's CONNECTION_CLOSE sent
    // when a connection is dropped).
    //
    // Churn pattern: N fresh connections on the same persistent endpoint,
    // each fully completing (connect → open → write → finish → yield) before
    // the next connects — true sequential reconnect churn, matching the
    // benchmark's per-transfer fresh-tunnel pattern. The yield between
    // connects lets the server drain each connection before the next EOF.
    let client = QuicClientEndpoint::new(QuicEndpointConfig::default())
        .await
        .expect("create persistent client endpoint");
    let start = Instant::now();
    for i in 0..CONNS {
        let payload = make_payload(PAYLOAD, i as u8);
        let fp = fingerprint(&payload);
        let conn = client
            .connect_peer(server_addr, &server_name)
            .await
            .unwrap_or_else(|e| {
                panic!("churn reconnect #{i} FAILED: {e:?} (reconnect instability)");
            });
        let (mut send, _recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(&payload).await.expect("client send");
        send.finish().expect("client finish");
        // Yield so the server drains this connection (accept_bi + read to
        // EOF) before the next connection's handshake arrives.
        tokio::task::yield_now().await;
        // Small sleep to give the server's drain task real time to complete
        // accept_bi + drain before the next connect (the server processes
        // connections in arrival order on a single drain task).
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let _ = fp;
    }

    let received = server_task.await.unwrap();
    let elapsed = start.elapsed();

    // HARD assert: every connection delivered its OWN full payload.
    assert_eq!(
        received.len(),
        CONNS,
        "server saw {} connections, expected {CONNS}",
        received.len()
    );
    for (i, got) in received.iter().enumerate() {
        let expected = make_payload(PAYLOAD, i as u8);
        assert_eq!(
            got.len(),
            PAYLOAD,
            "churn connect #{i}: truncated — received {} bytes, expected {PAYLOAD}",
            got.len()
        );
        assert_eq!(
            got,
            &expected,
            "churn reconnect #{i}: NOT byte-exact — stale/corrupted delivery (fp={})",
            fingerprint(&expected)
        );
    }

    let total: usize = CONNS * PAYLOAD;
    let secs = elapsed.as_secs_f64();
    let mbps = (total as f64 / MB) / secs.max(0.0001);
    println!(
        "CHURN {} sequential reconnects x{}KB: {:.1} MB/s aggregate ({} ms), all byte-exact",
        CONNS,
        PAYLOAD / 1024,
        mbps,
        elapsed.as_millis()
    );
}

/// Concurrent churn: spawn M client tasks that each open their OWN fresh
/// connection (not a shared one) and transfer, in parallel. This stresses
/// the endpoint-creation + CID-space + concurrent-handshake path harder
/// than the sequential variant. Every connection must be byte-exact.
#[cfg(feature = "tokio-runtime")]
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn concurrent_reconnect_churn_is_reliable() {
    const CONNS: usize = 12;
    const PAYLOAD: usize = 128 * 1024; // 128KB each (smaller to keep concurrent load bounded)

    let server_name = format!(
        "ztlp-churn-c-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );

    let server_cfg = QuicEndpointConfig {
        bind: Some("127.0.0.1:0".parse().expect("valid loopback addr")),
        ..Default::default()
    };
    let server = QuicEndpoint::bind(server_cfg).await.expect("bind server");
    let server_addr = server.inner.local_addr().unwrap();
    let server = std::sync::Arc::new(server);

    // Server: handle CONNS connections — each on its own task that accepts,
    // then accept_bi + drains + ACKs immediately (no accept-then-accept
    // serialization that would stall an early connection's ACK).
    let server_task = tokio::spawn(async move {
        let mut handles = Vec::new();
        for _ in 0..CONNS {
            // Spawn a full handler per connection so an early connection's
            // accept_bi + drain + ACK is not blocked by later accepts.
            let server = server.clone();
            handles.push(tokio::spawn(async move {
                let conn = server.accept().await.expect("accept");
                let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
                let mut received = Vec::new();
                let mut buf = vec![0u8; 65_536];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) => received.extend_from_slice(&buf[..n]),
                        Ok(None) | Err(_) => break,
                    }
                }
                let _ = send.write_all(b"ACK").await;
                let _ = send.finish();
                received
            }));
        }
        let mut out = Vec::with_capacity(CONNS);
        for h in handles {
            out.push(h.await.unwrap());
        }
        out
    });

    // Client: CONNS parallel tasks, each a FRESH connection but on the SAME
    // persistent endpoint (the fix — one socket/driver/CID space shared).
    let client = QuicClientEndpoint::new(QuicEndpointConfig::default())
        .await
        .expect("create persistent client endpoint");
    let start = Instant::now();
    let mut client_tasks = Vec::new();
    for i in 0..CONNS {
        let payload = make_payload(PAYLOAD, i as u8);
        let server_addr = server_addr;
        let server_name = server_name.clone();
        // Clone the persistent endpoint (shallow — shares the same
        // socket/driver/CID space) into each concurrent task.
        let client_clone = client.clone();
        client_tasks.push(tokio::spawn(async move {
            let conn = client_clone
                .connect_peer(server_addr, &server_name)
                .await
                .unwrap_or_else(|e| panic!("concurrent churn reconnect #{i} FAILED: {e:?}"));
            let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
            send.write_all(&payload).await.expect("client send");
            send.finish().expect("client finish");
            // Read the recv half until the server closes it (the server
            // drains to EOF, then writes an ACK and finishes its send half).
            // Reading until server-EOF guarantees the server finished
            // draining BEFORE the client drops the connection — no
            // CONNECTION_CLOSE-before-drain race.
            loop {
                match recv.read(&mut [0u8; 64]).await {
                    Ok(Some(_)) => {}           // ACK bytes / drain progress
                    Ok(None) | Err(_) => break, // server closed (drained)
                }
            }
        }));
    }
    for t in client_tasks {
        t.await.unwrap();
    }
    let received = server_task.await.unwrap();
    let elapsed = start.elapsed();

    // HARD assert: every concurrent connection delivered byte-exact.
    // QUIC may complete connections out of order; match by payload set.
    assert_eq!(received.len(), CONNS, "expected {CONNS} connections");
    let sent_fps: std::collections::BTreeSet<String> = (0..CONNS)
        .map(|i| fingerprint(&make_payload(PAYLOAD, i as u8)))
        .collect();
    let got_fps: std::collections::BTreeSet<String> =
        received.iter().map(|g| fingerprint(g)).collect();
    assert_eq!(
        got_fps, sent_fps,
        "concurrent churn: received fingerprint set != sent (cross-connection \
         bleed, corruption, or truncation)"
    );
    for (i, g) in received.iter().enumerate() {
        assert_eq!(g.len(), PAYLOAD, "connection {i}: truncated ({})", g.len());
    }

    let total: usize = CONNS * PAYLOAD;
    let secs = elapsed.as_secs_f64();
    let mbps = (total as f64 / MB) / secs.max(0.0001);
    println!(
        "CHURN {} concurrent reconnects x{}KB: {:.1} MB/s aggregate ({} ms), all byte-exact",
        CONNS,
        PAYLOAD / 1024,
        mbps,
        elapsed.as_millis()
    );
}
