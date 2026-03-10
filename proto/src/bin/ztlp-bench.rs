//! ZTLP Proto Benchmarks
//!
//! Standalone benchmark binary measuring:
//!   - Pipeline Layer 1: magic check throughput
//!   - Pipeline Layer 2: session lookup (100, 1K, 10K entries)
//!   - Pipeline full admission
//!   - Noise_XX handshake: full 3-message exchange
//!   - Encrypt/decrypt: ChaCha20-Poly1305 with varying payloads
//!   - Identity generation: NodeID + keypair
//!   - Packet serialize/deserialize round-trip
//!
//! Run: cargo run --release --bin ztlp-bench

use std::time::{Duration, Instant};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};

use ztlp_proto::handshake;
use ztlp_proto::identity::{NodeId, NodeIdentity};
use ztlp_proto::packet::{
    DataHeader, HandshakeHeader, MsgType, SessionId, ZtlpPacket,
};
use ztlp_proto::pipeline::{Pipeline, compute_header_auth_tag};
use ztlp_proto::session::SessionState;

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark harness
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct BenchResult {
    name: String,
    iterations: u64,
    total: Duration,
    mean_ns: f64,
    median_ns: f64,
    p99_ns: f64,
    min_ns: f64,
    max_ns: f64,
    ops_sec: f64,
}

fn bench<F: FnMut()>(name: &str, iterations: u64, warmup: u64, mut f: F) -> BenchResult {
    // Warmup
    for _ in 0..warmup {
        f();
    }

    // Measure
    let mut times: Vec<u64> = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        let elapsed = start.elapsed().as_nanos() as u64;
        times.push(elapsed);
    }

    times.sort_unstable();
    let total_ns: u64 = times.iter().sum();
    let mean_ns = total_ns as f64 / iterations as f64;
    let median_ns = times[iterations as usize / 2] as f64;
    let p99_ns = times[(iterations as f64 * 0.99) as usize] as f64;
    let min_ns = times[0] as f64;
    let max_ns = times[iterations as usize - 1] as f64;
    let ops_sec = if mean_ns > 0.0 {
        1_000_000_000.0 / mean_ns
    } else {
        0.0
    };

    let result = BenchResult {
        name: name.to_string(),
        iterations,
        total: Duration::from_nanos(total_ns),
        mean_ns,
        median_ns,
        p99_ns,
        min_ns,
        max_ns,
        ops_sec,
    };

    println!("\n  {}", name);
    println!("  {}", "-".repeat(name.len()));
    println!("  iterations:  {}", iterations);
    println!("  total:       {:.1} µs", total_ns as f64 / 1_000.0);
    println!("  mean:        {:.1} ns", mean_ns);
    println!("  median:      {:.0} ns", median_ns);
    println!("  p99:         {:.0} ns", p99_ns);
    println!("  min:         {:.0} ns", min_ns);
    println!("  max:         {:.0} ns", max_ns);
    println!("  throughput:  {:.0} ops/sec", ops_sec);

    result
}

fn main() {
    println!("{}", "=".repeat(61));
    println!("  ZTLP Proto (Rust) Benchmarks");
    println!("{}", "=".repeat(61));

    // ─────────────────────────────────────────────────────────────────────
    // Setup: build test packets
    // ─────────────────────────────────────────────────────────────────────

    let session_id = SessionId::generate();
    let send_key: [u8; 32] = rand::random();
    let recv_key: [u8; 32] = rand::random();
    let peer_node_id = NodeId::generate();

    // Build a valid data packet
    let mut data_header = DataHeader::new(session_id, 42);
    let aad = data_header.aad_bytes();
    data_header.header_auth_tag = compute_header_auth_tag(&recv_key, &aad);
    let data_payload = vec![0xABu8; 64];
    let data_packet = ZtlpPacket::Data {
        header: data_header.clone(),
        payload: data_payload.clone(),
    };
    let data_raw = data_packet.serialize();

    // Build a HELLO packet
    let hello_header = HandshakeHeader::new(MsgType::Hello);
    let hello_packet = ZtlpPacket::Handshake {
        header: hello_header,
        payload: vec![],
    };
    let hello_raw = hello_packet.serialize();

    // Build bad magic packet
    let mut bad_magic = vec![0xDE, 0xAD];
    bad_magic.extend_from_slice(&[0u8; 40]);

    // Build garbage
    let garbage: Vec<u8> = (0..100).map(|_| rand::random()).collect();

    // ─────────────────────────────────────────────────────────────────────
    // Layer 1: Magic Check
    // ─────────────────────────────────────────────────────────────────────

    println!("\n--- Layer 1: Magic Check ---");

    let pipeline = Pipeline::new();
    let dr = data_raw.clone();
    bench("layer1_magic_check — valid ZTLP", 100_000, 1_000, || {
        std::hint::black_box(pipeline.layer1_magic_check(&dr));
    });

    let bm = bad_magic.clone();
    bench("layer1_magic_check — bad magic", 100_000, 1_000, || {
        std::hint::black_box(pipeline.layer1_magic_check(&bm));
    });

    let gb = garbage.clone();
    bench("layer1_magic_check — garbage", 100_000, 1_000, || {
        std::hint::black_box(pipeline.layer1_magic_check(&gb));
    });

    // ─────────────────────────────────────────────────────────────────────
    // Layer 2: Session Lookup (varying counts)
    // ─────────────────────────────────────────────────────────────────────

    println!("\n--- Layer 2: Session Lookup ---");

    for count in &[100u32, 1_000, 10_000] {
        let mut pipe = Pipeline::new();
        // Register our known session
        let session = SessionState::new(session_id, peer_node_id, send_key, recv_key, false);
        pipe.register_session(session);

        // Add extra sessions
        for _ in 0..*count {
            let sid = SessionId::generate();
            let nid = NodeId::generate();
            let sk: [u8; 32] = rand::random();
            let rk: [u8; 32] = rand::random();
            let s = SessionState::new(sid, nid, sk, rk, false);
            pipe.register_session(s);
        }

        let dr2 = data_raw.clone();
        bench(
            &format!("layer2_session_check — known ({} sessions)", count),
            50_000, 500,
            || { std::hint::black_box(pipe.layer2_session_check(&dr2)); },
        );

        // Unknown session packet
        let unknown_sid = SessionId::generate();
        let mut unk_header = DataHeader::new(unknown_sid, 1);
        unk_header.header_auth_tag = [0u8; 16];
        let unk_pkt = ZtlpPacket::Data {
            header: unk_header,
            payload: vec![],
        };
        let unk_raw = unk_pkt.serialize();

        bench(
            &format!("layer2_session_check — unknown ({} sessions)", count),
            50_000, 500,
            || { std::hint::black_box(pipe.layer2_session_check(&unk_raw)); },
        );
    }

    let hr = hello_raw.clone();
    bench("layer2_session_check — HELLO (pass-through)", 50_000, 500, || {
        std::hint::black_box(pipeline.layer2_session_check(&hr));
    });

    // ─────────────────────────────────────────────────────────────────────
    // Layer 3: HeaderAuthTag Verification
    // ─────────────────────────────────────────────────────────────────────

    println!("\n--- Layer 3: HeaderAuthTag Verification ---");

    let test_aad: Vec<u8> = (0..26).collect(); // 26 bytes data header AAD
    bench("compute_header_auth_tag", 50_000, 500, || {
        std::hint::black_box(compute_header_auth_tag(&recv_key, &test_aad));
    });

    // Full pipeline with auth check
    let mut auth_pipe = Pipeline::new();
    let auth_session = SessionState::new(session_id, peer_node_id, send_key, recv_key, false);
    auth_pipe.register_session(auth_session);

    let dr3 = data_raw.clone();
    bench("layer3_auth_check — valid tag", 20_000, 500, || {
        std::hint::black_box(auth_pipe.layer3_auth_check(&dr3));
    });

    // ─────────────────────────────────────────────────────────────────────
    // Full Pipeline
    // ─────────────────────────────────────────────────────────────────────

    println!("\n--- Full Pipeline ---");

    let dr4 = data_raw.clone();
    bench("pipeline.process — valid data packet (full 3 layers)", 20_000, 500, || {
        std::hint::black_box(auth_pipe.process(&dr4));
    });

    let hr2 = hello_raw.clone();
    bench("pipeline.process — HELLO", 50_000, 500, || {
        std::hint::black_box(auth_pipe.process(&hr2));
    });

    let bm2 = bad_magic.clone();
    bench("pipeline.process — bad magic (L1 reject)", 100_000, 1_000, || {
        std::hint::black_box(auth_pipe.process(&bm2));
    });

    // ─────────────────────────────────────────────────────────────────────
    // Noise_XX Handshake
    // ─────────────────────────────────────────────────────────────────────

    println!("\n--- Noise_XX Handshake ---");

    let init_id = NodeIdentity::generate().expect("gen identity");
    let resp_id = NodeIdentity::generate().expect("gen identity");

    bench("Full Noise_XX handshake (3 messages + finalize)", 1_000, 100, || {
        let result = handshake::perform_handshake(&init_id, &resp_id)
            .expect("handshake should succeed");
        std::hint::black_box(result);
    });

    // ─────────────────────────────────────────────────────────────────────
    // ChaCha20-Poly1305 Encrypt/Decrypt
    // ─────────────────────────────────────────────────────────────────────

    println!("\n--- ChaCha20-Poly1305 Encrypt/Decrypt ---");

    let aead_key = Key::from_slice(&send_key);
    let cipher = ChaCha20Poly1305::new(aead_key);
    let nonce = Nonce::default();
    let aead_aad = b"ztlp-bench-aad";

    for (label, size) in &[("64B", 64usize), ("1KB", 1024), ("8KB", 8192), ("64KB", 65536)] {
        let plaintext: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();

        let pt = plaintext.clone();
        bench(&format!("encrypt {} payload", label), 10_000, 500, || {
            let ct = cipher
                .encrypt(
                    &nonce,
                    chacha20poly1305::aead::Payload {
                        msg: &pt,
                        aad: aead_aad,
                    },
                )
                .unwrap();
            std::hint::black_box(ct);
        });

        let ciphertext = cipher
            .encrypt(
                &nonce,
                chacha20poly1305::aead::Payload {
                    msg: &plaintext,
                    aad: aead_aad,
                },
            )
            .unwrap();

        let ct2 = ciphertext.clone();
        bench(&format!("decrypt {} payload", label), 10_000, 500, || {
            let pt = cipher
                .decrypt(
                    &nonce,
                    chacha20poly1305::aead::Payload {
                        msg: &ct2,
                        aad: aead_aad,
                    },
                )
                .unwrap();
            std::hint::black_box(pt);
        });
    }

    // ─────────────────────────────────────────────────────────────────────
    // Identity Generation
    // ─────────────────────────────────────────────────────────────────────

    println!("\n--- Identity Generation ---");

    bench("NodeId::generate()", 50_000, 1_000, || {
        std::hint::black_box(NodeId::generate());
    });

    bench("NodeIdentity::generate() (NodeID + X25519 keypair)", 5_000, 100, || {
        std::hint::black_box(NodeIdentity::generate().unwrap());
    });

    bench("SessionId::generate()", 50_000, 1_000, || {
        std::hint::black_box(SessionId::generate());
    });

    // ─────────────────────────────────────────────────────────────────────
    // Packet Serialize / Deserialize
    // ─────────────────────────────────────────────────────────────────────

    println!("\n--- Packet Serialize / Deserialize ---");

    let hdr = HandshakeHeader::new(MsgType::Hello);
    bench("HandshakeHeader::serialize()", 50_000, 1_000, || {
        std::hint::black_box(hdr.serialize());
    });

    bench("HandshakeHeader::deserialize()", 50_000, 1_000, || {
        std::hint::black_box(HandshakeHeader::deserialize(&hello_raw).unwrap());
    });

    let dhdr = DataHeader::new(session_id, 1);
    bench("DataHeader::serialize()", 50_000, 1_000, || {
        std::hint::black_box(dhdr.serialize());
    });

    let data_hdr_raw = dhdr.serialize();
    bench("DataHeader::deserialize()", 50_000, 1_000, || {
        std::hint::black_box(DataHeader::deserialize(&data_hdr_raw).unwrap());
    });

    // Round-trip
    bench("Data packet serialize + deserialize round-trip", 50_000, 1_000, || {
        let hdr = DataHeader::new(session_id, 99);
        let serialized = hdr.serialize();
        let parsed = DataHeader::deserialize(&serialized).unwrap();
        std::hint::black_box(parsed);
    });

    println!("\n{}", "=".repeat(61));
    println!("  Rust benchmarks complete.");
    println!("{}", "=".repeat(61));
}
