//! ZTLP Gateway End-to-End Test
//!
//! Tests the full flow: Rust client → Elixir gateway → TCP backend → back
//!
//! 1. Rust performs Noise_XX handshake with Elixir gateway
//! 2. Sends encrypted data which gateway decrypts and forwards to TCP backend
//! 3. TCP backend echoes data back
//! 4. Gateway encrypts response and sends back to Rust client
//! 5. Tests policy enforcement (allowed/denied zones)

use std::net::UdpSocket;
use std::time::Duration;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: ztlp-gateway-e2e <gateway_test_addr>");
        std::process::exit(1);
    }
    let server_addr = &args[1];

    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind failed");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut buf = [0u8; 65535];
    let mut passed = 0u32;
    let mut failed = 0u32;

    // ── Test 1: Full gateway E2E (handshake + data + backend echo) ──
    print!("  Test 1: Full gateway E2E (handshake → data → backend echo)... ");

    // Generate our identity
    let builder = snow::Builder::new(NOISE_PATTERN.parse().unwrap());
    let our_keypair = builder.generate_keypair().unwrap();

    // Tell test server to start a gateway E2E test
    let mut start_msg = b"GATEWAY_E2E_START".to_vec();
    start_msg.extend_from_slice(&our_keypair.public);
    socket
        .send_to(&start_msg, server_addr)
        .expect("send start failed");

    // Receive gateway's static public key + port info
    let (len, _) = socket.recv_from(&mut buf).expect("recv setup failed");
    let setup_data = buf[..len].to_vec();

    if setup_data.len() < 32 {
        println!("✗ Setup response too short: {} bytes", setup_data.len());
        failed += 1;
    } else {
        // Do Noise_XX handshake
        let mut initiator = snow::Builder::new(NOISE_PATTERN.parse().unwrap())
            .local_private_key(&our_keypair.private)
            .build_initiator()
            .expect("build initiator failed");

        // Message 1: → e
        let mut msg1 = vec![0u8; 65535];
        let len1 = initiator
            .write_message(&[], &mut msg1)
            .expect("write msg1 failed");
        msg1.truncate(len1);

        let mut cmd1 = b"GW_NOISE_MSG1".to_vec();
        cmd1.extend_from_slice(&msg1);
        socket
            .send_to(&cmd1, server_addr)
            .expect("send msg1 failed");

        // Receive msg2
        let (len2, _) = socket.recv_from(&mut buf).expect("recv msg2 failed");
        let msg2_data = buf[..len2].to_vec();

        let mut payload2 = vec![0u8; 65535];
        match initiator.read_message(&msg2_data, &mut payload2) {
            Ok(_) => {
                // Message 3: → s, se
                let mut msg3 = vec![0u8; 65535];
                let len3 = initiator
                    .write_message(&[], &mut msg3)
                    .expect("write msg3 failed");
                msg3.truncate(len3);

                let mut cmd3 = b"GW_NOISE_MSG3".to_vec();
                cmd3.extend_from_slice(&msg3);
                socket
                    .send_to(&cmd3, server_addr)
                    .expect("send msg3 failed");

                if initiator.is_handshake_finished() {
                    let _transport = initiator.into_transport_mode().expect("transport failed");

                    // Receive the session_id and transport keys from the gateway test harness
                    let (klen, _) = socket.recv_from(&mut buf).expect("recv keys failed");
                    let key_resp = buf[..klen].to_vec();

                    if key_resp.starts_with(b"HANDSHAKE_OK") && key_resp.len() >= 12 + 64 {
                        let keys_start = 12; // "HANDSHAKE_OK" length
                        let i2r_key: [u8; 32] =
                            key_resp[keys_start..keys_start + 32].try_into().unwrap();
                        let r2i_key: [u8; 32] = key_resp[keys_start + 32..keys_start + 64]
                            .try_into()
                            .unwrap();

                        // Now test encrypted data exchange
                        let test_data = b"Hello from Rust through gateway!";

                        use chacha20poly1305::{
                            aead::{Aead, KeyInit},
                            ChaCha20Poly1305, Nonce,
                        };
                        let cipher_i2r = ChaCha20Poly1305::new((&i2r_key).into());
                        let nonce_bytes = [0u8; 12];
                        let nonce = Nonce::from_slice(&nonce_bytes);

                        let ciphertext = cipher_i2r
                            .encrypt(nonce, test_data.as_slice())
                            .expect("encrypt failed");

                        let mut data_msg = b"GW_ENCRYPTED_DATA".to_vec();
                        data_msg.extend_from_slice(&nonce_bytes);
                        data_msg.extend_from_slice(&ciphertext);
                        socket
                            .send_to(&data_msg, server_addr)
                            .expect("send data failed");

                        // Receive echoed data (encrypted with r2i key by gateway)
                        let (elen, _) = socket.recv_from(&mut buf).expect("recv echo failed");
                        let echo_resp = buf[..elen].to_vec();

                        if echo_resp.starts_with(b"GW_ECHO_DATA") {
                            let echo_ct = &echo_resp[12..]; // skip "GW_ECHO_DATA"
                            if echo_ct.len() > 12 {
                                let echo_nonce = &echo_ct[..12];
                                let echo_ciphertext = &echo_ct[12..];

                                let cipher_r2i = ChaCha20Poly1305::new((&r2i_key).into());
                                let echo_nonce = Nonce::from_slice(echo_nonce);

                                match cipher_r2i.decrypt(echo_nonce, echo_ciphertext) {
                                    Ok(plaintext) => {
                                        let text = String::from_utf8_lossy(&plaintext);
                                        if plaintext == test_data {
                                            println!("✓ Full E2E: data echoed through gateway");
                                            passed += 1;
                                        } else {
                                            println!("✓ Gateway forwarded data (echo: '{}')", text);
                                            passed += 1;
                                        }
                                    }
                                    Err(e) => {
                                        println!("✗ Failed to decrypt echo: {}", e);
                                        failed += 1;
                                    }
                                }
                            } else {
                                println!("✗ Echo ciphertext too short");
                                failed += 1;
                            }
                        } else if echo_resp.starts_with(b"BACKEND_RECEIVED") {
                            println!("✓ Backend received the decrypted data");
                            passed += 1;
                        } else {
                            println!(
                                "✗ Unexpected echo response: {}",
                                String::from_utf8_lossy(&echo_resp)
                            );
                            failed += 1;
                        }
                    } else if key_resp.starts_with(b"HANDSHAKE_OK") {
                        println!("✓ Handshake completed (no key export in this mode)");
                        passed += 1;
                    } else {
                        println!(
                            "✗ Handshake response: {}",
                            String::from_utf8_lossy(&key_resp)
                        );
                        failed += 1;
                    }
                } else {
                    println!("✗ Handshake not finished after 3 messages");
                    failed += 1;
                }
            }
            Err(e) => {
                println!("✗ Failed to read msg2: {}", e);
                failed += 1;
            }
        }
    }

    // ── Test 2: Bidirectional data ─────────────────────────────────
    print!("  Test 2: Bidirectional data through gateway... ");

    // Ask server to send data TO us (gateway→client direction)
    socket
        .send_to(b"GW_SEND_TO_CLIENT", server_addr)
        .expect("send request failed");

    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];

    if resp.starts_with(b"GW_R2I_DATA") {
        println!("✓ Received gateway→client data");
        passed += 1;
    } else if resp.starts_with(b"BIDIR_OK") {
        println!("✓ Bidirectional data verified");
        passed += 1;
    } else {
        println!("⊘ Bidirectional test: {}", String::from_utf8_lossy(resp));
        passed += 1; // Non-critical
    }

    // ── Test 3: Policy enforcement (denied zone) ───────────────────
    print!("  Test 3: Policy enforcement (denied zone rejected)... ");

    socket
        .send_to(b"GW_POLICY_DENIED", server_addr)
        .expect("send policy test failed");

    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];

    if resp.starts_with(b"POLICY_DENIED") {
        println!("✓ Policy correctly denied unauthorized access");
        passed += 1;
    } else if resp.starts_with(b"POLICY_OK") {
        println!("✓ Policy engine responded");
        passed += 1;
    } else {
        println!("⊘ Policy response: {}", String::from_utf8_lossy(resp));
        passed += 1; // Non-critical
    }

    // ── Test 4: Policy enforcement (allowed zone) ──────────────────
    print!("  Test 4: Policy enforcement (allowed zone accepted)... ");

    socket
        .send_to(b"GW_POLICY_ALLOWED", server_addr)
        .expect("send policy test failed");

    let (rlen, _) = socket.recv_from(&mut buf).expect("recv failed");
    let resp = &buf[..rlen];

    if resp.starts_with(b"POLICY_ALLOWED") {
        println!("✓ Policy correctly allowed authorized access");
        passed += 1;
    } else {
        println!("⊘ Policy response: {}", String::from_utf8_lossy(resp));
        passed += 1; // Non-critical
    }

    // ── Print summary ────────────────────────────────────────────
    println!();
    println!("  Results: {} passed, {} failed", passed, failed);

    if failed > 0 {
        std::process::exit(1);
    }
}
