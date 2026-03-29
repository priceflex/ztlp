//! Tests for gateway certificate/key pinning.
//!
//! Validates that the ZTLP client correctly pins and verifies gateway
//! static Noise public keys after enrollment.

use ztlp_proto::error::TransportError;
use ztlp_proto::handshake::HandshakeContext;
use ztlp_proto::identity::NodeIdentity;

fn test_identity() -> NodeIdentity {
    NodeIdentity::generate().expect("failed to generate identity")
}

// ── Test 1: Pinned key matches → verification succeeds ──────────────────

#[test]
fn test_pin_match_succeeds() {
    let init_id = test_identity();
    let resp_id = test_identity();

    let mut initiator = HandshakeContext::new_initiator(&init_id).expect("initiator");
    let mut responder = HandshakeContext::new_responder(&resp_id).expect("responder");

    // Perform full Noise_XX handshake
    let msg1 = initiator.write_message(&[]).expect("msg1");
    responder.read_message(&msg1).expect("read msg1");
    let msg2 = responder.write_message(&[]).expect("msg2");
    initiator.read_message(&msg2).expect("read msg2");
    let msg3 = initiator.write_message(&[]).expect("msg3");
    responder.read_message(&msg3).expect("read msg3");

    assert!(initiator.is_finished());

    // Get the responder's static key (the gateway's key)
    let remote_static = initiator
        .remote_static_bytes()
        .expect("remote static should be available");
    let mut pinned_key = [0u8; 32];
    pinned_key.copy_from_slice(remote_static);

    // Verify with matching pin
    let result = initiator.verify_gateway_pin(&[pinned_key]);
    assert!(result.is_ok(), "matching pin should succeed");
}

// ── Test 2: Pinned key doesn't match → PinMismatch error ───────────────

#[test]
fn test_pin_mismatch_rejected() {
    let init_id = test_identity();
    let resp_id = test_identity();

    let mut initiator = HandshakeContext::new_initiator(&init_id).expect("initiator");
    let mut responder = HandshakeContext::new_responder(&resp_id).expect("responder");

    // Full handshake
    let msg1 = initiator.write_message(&[]).expect("msg1");
    responder.read_message(&msg1).expect("read msg1");
    let msg2 = responder.write_message(&[]).expect("msg2");
    initiator.read_message(&msg2).expect("read msg2");
    let msg3 = initiator.write_message(&[]).expect("msg3");
    responder.read_message(&msg3).expect("read msg3");

    assert!(initiator.is_finished());

    // Get the actual remote key for later comparison
    let remote_static = initiator
        .remote_static_bytes()
        .expect("remote static available");

    // Use a bogus pinned key that doesn't match the responder
    let bogus_key = [0xAA; 32];
    let result = initiator.verify_gateway_pin(&[bogus_key]);
    assert!(result.is_err(), "mismatched pin should fail");

    match result.unwrap_err() {
        TransportError::PinMismatch { expected, got } => {
            assert_eq!(expected.len(), 1);
            assert_eq!(expected[0], bogus_key);
            assert_eq!(got.len(), 32);
            assert_eq!(got, remote_static);
        }
        other => panic!("expected PinMismatch, got {:?}", other),
    }
}

// ── Test 3: Empty pinned_keys → all connections accepted ────────────────

#[test]
fn test_empty_pins_accepts_all() {
    let init_id = test_identity();
    let resp_id = test_identity();

    let mut initiator = HandshakeContext::new_initiator(&init_id).expect("initiator");
    let mut responder = HandshakeContext::new_responder(&resp_id).expect("responder");

    // Full handshake
    let msg1 = initiator.write_message(&[]).expect("msg1");
    responder.read_message(&msg1).expect("read msg1");
    let msg2 = responder.write_message(&[]).expect("msg2");
    initiator.read_message(&msg2).expect("read msg2");
    let msg3 = initiator.write_message(&[]).expect("msg3");
    responder.read_message(&msg3).expect("read msg3");

    assert!(initiator.is_finished());

    // Empty pinned_keys should accept any gateway
    let result = initiator.verify_gateway_pin(&[]);
    assert!(
        result.is_ok(),
        "empty pins should accept all connections (backward compat)"
    );
}

// ── Test 4: Multiple pinned keys → any match succeeds ───────────────────

#[test]
fn test_multi_key_rotation_support() {
    let init_id = test_identity();
    let resp_id = test_identity();

    let mut initiator = HandshakeContext::new_initiator(&init_id).expect("initiator");
    let mut responder = HandshakeContext::new_responder(&resp_id).expect("responder");

    // Full handshake
    let msg1 = initiator.write_message(&[]).expect("msg1");
    responder.read_message(&msg1).expect("read msg1");
    let msg2 = responder.write_message(&[]).expect("msg2");
    initiator.read_message(&msg2).expect("read msg2");
    let msg3 = initiator.write_message(&[]).expect("msg3");
    responder.read_message(&msg3).expect("read msg3");

    assert!(initiator.is_finished());

    // Get the actual remote key
    let remote_static = initiator
        .remote_static_bytes()
        .expect("remote static available");
    let mut real_key = [0u8; 32];
    real_key.copy_from_slice(remote_static);

    // Pin multiple keys — the real one plus some old/rotated keys
    let old_key1 = [0x11; 32];
    let old_key2 = [0x22; 32];
    let pinned = [old_key1, old_key2, real_key];

    let result = initiator.verify_gateway_pin(&pinned);
    assert!(
        result.is_ok(),
        "should succeed when any pinned key matches (key rotation)"
    );
}

// ── Test 5: Multiple pinned keys, none match → rejected ─────────────────

#[test]
fn test_multi_key_none_match() {
    let init_id = test_identity();
    let resp_id = test_identity();

    let mut initiator = HandshakeContext::new_initiator(&init_id).expect("initiator");
    let mut responder = HandshakeContext::new_responder(&resp_id).expect("responder");

    // Full handshake
    let msg1 = initiator.write_message(&[]).expect("msg1");
    responder.read_message(&msg1).expect("read msg1");
    let msg2 = responder.write_message(&[]).expect("msg2");
    initiator.read_message(&msg2).expect("read msg2");
    let msg3 = initiator.write_message(&[]).expect("msg3");
    responder.read_message(&msg3).expect("read msg3");

    // None of these are the real gateway key
    let fake1 = [0x11; 32];
    let fake2 = [0x22; 32];
    let fake3 = [0x33; 32];

    let result = initiator.verify_gateway_pin(&[fake1, fake2, fake3]);
    assert!(result.is_err(), "should reject when no pinned key matches");
}

// ── Test 6: Pin saved during enrollment → config file updated ───────────

#[test]
fn test_pin_saved_during_enrollment() {
    use std::io::Write;

    let dir = std::env::temp_dir().join(format!("ztlp_pin_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");

    // Write an initial config
    {
        let mut f = std::fs::File::create(&config_path).expect("create config");
        writeln!(f, "# Test config").expect("write");
        writeln!(f, "zone = \"test.ztlp\"").expect("write");
    }

    // Pin a gateway key
    let key = [0x42u8; 32];
    ztlp_proto::enrollment::pin_gateway_key(&config_path, &key).expect("pin should succeed");

    // Read back and verify
    let contents = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        contents.contains("pinned_gateway_keys"),
        "config should contain pinned_gateway_keys"
    );

    // The key should be base64-encoded in the file
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    assert!(
        contents.contains(&encoded),
        "config should contain the base64-encoded key"
    );

    // Pinning the same key again should be idempotent
    ztlp_proto::enrollment::pin_gateway_key(&config_path, &key)
        .expect("duplicate pin should succeed");
    let contents2 = std::fs::read_to_string(&config_path).expect("read config");
    // Count occurrences — should appear only once
    let count = contents2.matches(&encoded).count();
    assert_eq!(count, 1, "duplicate pin should not add key again");

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

// ── Test 7: Pin multiple keys to config file ────────────────────────────

#[test]
fn test_pin_multiple_keys_to_config() {
    use std::io::Write;

    let dir = std::env::temp_dir().join(format!("ztlp_pin_multi_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let config_path = dir.join("config.toml");

    {
        let mut f = std::fs::File::create(&config_path).expect("create config");
        writeln!(f, "zone = \"test.ztlp\"").expect("write");
    }

    // Pin first key
    let key1 = [0x11u8; 32];
    ztlp_proto::enrollment::pin_gateway_key(&config_path, &key1).expect("pin key1");

    // Pin second key (simulating key rotation)
    let key2 = [0x22u8; 32];
    ztlp_proto::enrollment::pin_gateway_key(&config_path, &key2).expect("pin key2");

    // Both keys should be in the config
    use base64::Engine;
    let contents = std::fs::read_to_string(&config_path).expect("read config");
    let enc1 = base64::engine::general_purpose::STANDARD.encode(key1);
    let enc2 = base64::engine::general_purpose::STANDARD.encode(key2);
    assert!(contents.contains(&enc1), "should contain key1");
    assert!(contents.contains(&enc2), "should contain key2");

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

// ── Test 8: PinMismatch error display is readable ───────────────────────

#[test]
fn test_pin_mismatch_error_display() {
    let expected = vec![[0xAA; 32], [0xBB; 32]];
    let got = vec![0xCC; 32];
    let err = TransportError::PinMismatch {
        expected: expected.clone(),
        got: got.clone(),
    };

    let msg = err.to_string();
    assert!(msg.contains("pin mismatch"), "should mention pin mismatch");
    assert!(
        msg.contains(&hex::encode([0xAA; 32])),
        "should show expected key"
    );
    assert!(
        msg.contains(&hex::encode([0xCC; 32])),
        "should show got key"
    );
}

// ── Test 9: Config deserialization with pinned keys ─────────────────────

#[test]
fn test_agent_config_with_pinned_keys() {
    use base64::Engine;

    let key1 = [0x42u8; 32];
    let key2 = [0x43u8; 32];
    let enc1 = base64::engine::general_purpose::STANDARD.encode(key1);
    let enc2 = base64::engine::general_purpose::STANDARD.encode(key2);

    let toml_str = format!(
        r#"
[gateway]
pinned_keys = ["{}", "{}"]
"#,
        enc1, enc2,
    );

    let cfg: ztlp_proto::agent::config::AgentConfig =
        toml::from_str(&toml_str).expect("should parse TOML");
    assert_eq!(cfg.gateway.pinned_keys.len(), 2);
    assert_eq!(cfg.gateway.pinned_keys[0], key1);
    assert_eq!(cfg.gateway.pinned_keys[1], key2);
}

// ── Test 10: Config deserialization with empty pinned keys ──────────────

#[test]
fn test_agent_config_empty_pinned_keys() {
    let toml_str = r#"
[dns]
listen = "127.0.0.53:5353"
"#;

    let cfg: ztlp_proto::agent::config::AgentConfig =
        toml::from_str(toml_str).expect("should parse TOML");
    assert!(
        cfg.gateway.pinned_keys.is_empty(),
        "default should have no pinned keys"
    );
}
