//! QUIC throughput integration tests for the ZTLP tunnel data path.
//!
//! Regression context (feature/quic-pump-throughput):
//! The default `ztlp connect` QUIC data pump truncated transfers above
//! ~192-448 KB live on AWS (512/768/1024 KB all failed byte-exact).
//! These tests pin two properties on the QUIC transport itself:
//!
//!   1. A >=1MB transfer over a single bidi stream is byte-exact
//!      (exact-bytes assertion; a sha256-based fingerprint is also
//!      computed + logged for parity with the md5sum-based shell
//!      scripts — no new cargo deps allowed).
//!   2. 8 parallel streams, each carrying a DISTINCT 105KB payload,
//!      all deliver their own bytes end-to-end (no head-of-line
//!      blocking, no cross-stream bleed).
//!
//! The throughput floor is a *soft* assertion: loopback on a healthy
//! dev box should easily exceed 50 MB/s, but slow CI runners can dip
//! below that without indicating a correctness bug — we log the number
//! and warn instead of failing. Byte-exactness is a hard assert.
//!
//! NOTE: these tests exercise the `quic_transport` API directly
//! (open_bi / write / finish + read). The pump code in `ztlp-cli.rs`
//! (Agent 1's scope) is NOT exercised here; the AWS size-sweep in
//! `fullstack/bench-sizes.sh` is the end-to-end check for the pump fix.

#![cfg(feature = "quic-transport")]

use std::time::{SystemTime, UNIX_EPOCH};
use ztlp_proto::quic_transport::tokio_endpoint::QuicEndpoint;
use ztlp_proto::quic_transport::{QuicEndpointConfig, ZTLP_ALPN};

const MB: f64 = 1_048_576.0;
/// Soft floor for loopback throughput. Lenient on purpose — see module docs.
const THROUGHPUT_FLOOR_MB_S: f64 = 50.0;

/// 16-hex-char fingerprint of `data` (first 8 bytes of its SHA-256).
///
/// The crate already depends on `sha2`; real md5 is not available
/// without a new dependency, so this is a stand-in for logging parity
/// with the shell scripts' `md5sum`. The HARD correctness assertions
/// are exact-byte equality — the fingerprint is informational only.
fn fingerprint(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(data);
    d.iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn alpn_is_stable_for_throughput_tests() {
    assert_eq!(ZTLP_ALPN, b"ztlp/1");
}

#[cfg(feature = "tokio-runtime")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_mib_single_stream_is_byte_exact() {
    use std::time::Instant;

    // Unique server name per run so the TOFU cert pin is first-use each
    // time (a stale ~/.ztlp/quic_pins/<name>.pin from a prior run would
    // mismatch the fresh ephemeral self-signed cert and abort the handshake).
    let server_name = format!(
        "ztlp-throughput-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );

    let payload: Vec<u8> = {
        let mut v = vec![0u8; 1_048_576];
        // Deterministic non-constant payload (catches truncation AND
        // corruption — a constant buffer is weaker evidence of
        // byte-exact delivery).
        for i in 0..v.len() {
            v[i] = (i.wrapping_mul(31) % 251) as u8;
        }
        v
    };

    let server_cfg = QuicEndpointConfig {
        bind: Some("127.0.0.1:0".parse().expect("valid loopback addr")),
        ..Default::default()
    };
    let server = QuicEndpoint::bind(server_cfg).await.expect("bind server");
    let server_addr = server.inner.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("accept");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
        // Drain the full payload then finish — mirrors the sink side
        // of the pump (read frames until EOF, no echo).
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
    });

    let client = QuicEndpoint::connect(QuicEndpointConfig::default(), server_addr, &server_name)
        .await
        .expect("client connect");

    let (mut send, _recv) = client.open_bi().await.expect("open_bi");
    let start = Instant::now();
    send.write_all(&payload).await.expect("client send 1MiB");
    send.finish().expect("client finish");

    // The server's `received` bytes ARE the proof of delivery (it drains the
    // stream until EOF). We do NOT read a client-side ACK here: the server
    // `finish()`es its send side after draining, which closes the connection,
    // and a client `read_exact(ACK)` on the same stream would race that close.
    // Verifying the server's received bytes is the authoritative check.
    let received = server_task.await.unwrap();
    let elapsed = start.elapsed();

    // HARD assert: byte-exact, full length.
    assert_eq!(
        received.len(),
        payload.len(),
        "1MiB single-stream transfer truncated: received {} bytes, expected {}",
        received.len(),
        payload.len()
    );
    assert_eq!(
        received, payload,
        "1MiB single-stream transfer is NOT byte-exact"
    );

    let secs = elapsed.as_secs_f64();
    let mbps = (payload.len() as f64 / MB) / secs;
    println!(
        "THROUGHPUT single-stream 1MiB: {:.2} MB/s ({} ms) fp={} bytes={}",
        mbps,
        elapsed.as_millis(),
        fingerprint(&payload),
        payload.len()
    );
    if mbps < THROUGHPUT_FLOOR_MB_S {
        // Soft assertion — log loudly but don't fail (slow CI).
        eprintln!(
            "WARN: loopback throughput {:.2} MB/s is below the soft floor \
             ({:.0} MB/s). Not failing — verify on a fast box.",
            mbps, THROUGHPUT_FLOOR_MB_S
        );
    }
}

#[cfg(feature = "tokio-runtime")]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn eight_parallel_streams_distinct_payloads_no_hol() {
    use std::time::Instant;

    const STREAMS: usize = 8;
    const PAYLOAD: usize = 105 * 1024; // 105KB, matches quic-client.rs bench

    // Unique server name per run → fresh TOFU pin (avoids a stale pin from
    // a prior run aborting the handshake with a fingerprint mismatch).
    let server_name = format!(
        "ztlp-hol-{}-{}",
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

    // Server: per-stream sink. Each handler returns its own received
    // bytes; the test verifies each stream received ITS OWN payload.
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("accept");
        let mut handles = Vec::new();
        for _ in 0..STREAMS {
            let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
            handles.push(tokio::spawn(async move {
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
        let mut out = Vec::with_capacity(STREAMS);
        for h in handles {
            out.push(h.await.unwrap());
        }
        out
    });

    let client = QuicEndpoint::connect(QuicEndpointConfig::default(), server_addr, &server_name)
        .await
        .expect("client connect");

    let payloads: Vec<Vec<u8>> = (0..STREAMS)
        .map(|i| {
            // Distinct, deterministic payload per stream: the stream
            // id is repeated at offsets 0 and 16 so a cross-stream
            // bleed is detectable even if the rest happened to match.
            let mut v = vec![0u8; PAYLOAD];
            for (j, b) in v.iter_mut().enumerate() {
                *b = (j.wrapping_mul(17 + i * 7) + i * 13) as u8;
            }
            // Stream id stamped (as a u64 → 8 bytes) at offsets 0 and 16 so
            // a cross-stream bleed is detectable even if the rest happened
            // to match. The 16-byte window holds the 8-byte id + 8 zero bytes.
            let id = (i as u64).to_be_bytes();
            v[..8].copy_from_slice(&id);
            v[16..24].copy_from_slice(&id);
            v
        })
        .collect();

    let start = Instant::now();
    let mut client_tasks = Vec::new();
    for p in &payloads {
        let conn_clone = client.clone();
        let payload = p.clone();
        client_tasks.push(tokio::spawn(async move {
            let (mut send, _recv) = conn_clone.open_bi().await.expect("open_bi");
            send.write_all(&payload).await.expect("client send");
            send.finish().expect("client finish");
            // No client-side ACK read: the server's per-stream `received`
            // bytes (awaited below) are the authoritative delivery proof, and
            // reading an ACK on the same stream races the server's finish()/
            // connection-close.
        }));
    }
    for t in client_tasks {
        t.await.unwrap();
    }
    let received = server_task.await.unwrap();
    let elapsed = start.elapsed();

    assert_eq!(received.len(), STREAMS, "expected {} streams", STREAMS);
    // QUIC assigns stream ids independently of the client's spawn order, so
    // the received payloads may arrive in a different order than `payloads`.
    // The correct check is set equality: every received payload must match
    // exactly one sent payload (and vice-versa). This still catches cross-
    // stream bleed / corruption — a blended or corrupted payload would match
    // neither the sent set nor the received set.
    let mut sent: Vec<Vec<u8>> = payloads.iter().map(|p| p.clone()).collect();
    let mut got: Vec<Vec<u8>> = received;
    sent.sort();
    got.sort();
    assert_eq!(
        got, sent,
        "8-stream concurrency: received payload set != sent payload set \
         (cross-stream bleed, corruption, or truncation)"
    );
    // Also assert every stream delivered the full length (no truncation).
    for (i, g) in got.iter().enumerate() {
        assert_eq!(
            g.len(),
            PAYLOAD,
            "stream {i}: truncated — received {} bytes, expected {}",
            g.len(),
            PAYLOAD
        );
    }

    let total: usize = payloads.iter().map(|p| p.len()).sum();
    let secs = elapsed.as_secs_f64();
    let mbps = (total as f64 / MB) / secs;
    println!(
        "THROUGHPUT 8x{}KB parallel: {:.2} MB/s ({} ms) total={} bytes",
        PAYLOAD / 1024,
        mbps,
        elapsed.as_millis(),
        total
    );
    if mbps < THROUGHPUT_FLOOR_MB_S {
        eprintln!(
            "WARN: loopback 8-stream throughput {:.2} MB/s is below the soft floor \
             ({:.0} MB/s). Not failing — verify on a fast box.",
            mbps, THROUGHPUT_FLOOR_MB_S
        );
    }
}
