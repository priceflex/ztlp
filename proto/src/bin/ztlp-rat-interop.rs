//! # `ztlp-rat-interop` — Cross-language RAT verification tool
//!
//! Generates a deterministic RAT with known parameters, prints it for
//! Elixir to verify, then reads an Elixir-generated RAT from stdin
//! and verifies it.
//!
//! ## Usage
//!
//! ```bash
//! # Generate a Rust RAT, pipe to Elixir for verification:
//! ztlp-rat-interop generate | elixir_verify_script
//!
//! # Verify an Elixir RAT:
//! echo "<hex>" | ztlp-rat-interop verify
//!
//! # Full interop test (self-contained):
//! ztlp-rat-interop selftest
//! ```

#![deny(unsafe_code)]

use std::io::{self, BufRead};

use ztlp_proto::admission::{self, RelayAdmissionToken, RAT_SIZE, RAT_VERSION};

/// Known test parameters for cross-language verification.
const TEST_SECRET: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

const TEST_NODE_ID: [u8; 16] = [0xAA; 16];
const TEST_ISSUER_ID: [u8; 16] = [0xBB; 16];
const TEST_ISSUED_AT: u64 = 1700000000;
const TEST_EXPIRES_AT: u64 = 1700000300;
const TEST_SESSION_SCOPE: [u8; 12] = [0u8; 12];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("selftest");

    match cmd {
        "generate" => cmd_generate(),
        "verify" => cmd_verify(),
        "selftest" => cmd_selftest(),
        "hmac-test" => cmd_hmac_test(),
        _ => {
            eprintln!("Usage: ztlp-rat-interop [generate|verify|selftest|hmac-test]");
            eprintln!();
            eprintln!("Commands:");
            eprintln!("  generate   — Generate a deterministic RAT and print hex to stdout");
            eprintln!("  verify     — Read a hex RAT from stdin and verify with known secret");
            eprintln!("  selftest   — Round-trip self-test (no external tools needed)");
            eprintln!(
                "  hmac-test  — Print HMAC-BLAKE2s test vectors for cross-language comparison"
            );
            std::process::exit(1);
        }
    }
}

/// Generate a deterministic RAT with known parameters and print hex to stdout.
fn cmd_generate() {
    let token = RelayAdmissionToken::issue_at(
        TEST_NODE_ID,
        TEST_ISSUER_ID,
        TEST_SESSION_SCOPE,
        TEST_ISSUED_AT,
        TEST_EXPIRES_AT,
        &TEST_SECRET,
    );

    let bytes = token.serialize();
    println!("{}", hex::encode(&bytes));

    // Print details to stderr for human inspection
    eprintln!("Generated RAT with known test parameters:");
    eprintln!("  Secret:     {}", hex::encode(TEST_SECRET));
    eprintln!("  NodeID:     {}", hex::encode(TEST_NODE_ID));
    eprintln!("  IssuerID:   {}", hex::encode(TEST_ISSUER_ID));
    eprintln!("  IssuedAt:   {}", TEST_ISSUED_AT);
    eprintln!("  ExpiresAt:  {}", TEST_EXPIRES_AT);
    eprintln!("  Scope:      {}", hex::encode(TEST_SESSION_SCOPE));
    eprintln!("  MAC:        {}", hex::encode(token.mac));
    eprintln!("  Token:      {} bytes", bytes.len());
}

/// Read a hex RAT from stdin and verify with known secret.
fn cmd_verify() {
    let stdin = io::stdin();
    let line = stdin.lock().lines().next();

    let hex_str = match line {
        Some(Ok(s)) => s.trim().to_string(),
        _ => {
            eprintln!("FAIL: could not read hex from stdin");
            std::process::exit(1);
        }
    };

    let bytes = match hex::decode(&hex_str) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FAIL: invalid hex: {}", e);
            std::process::exit(1);
        }
    };

    if bytes.len() != RAT_SIZE {
        eprintln!("FAIL: expected {} bytes, got {}", RAT_SIZE, bytes.len());
        std::process::exit(1);
    }

    let token = match RelayAdmissionToken::parse(&bytes) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("FAIL: parse error: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("Parsed RAT:");
    eprintln!("  Version:    {}", token.version);
    eprintln!("  NodeID:     {}", hex::encode(token.node_id));
    eprintln!("  IssuerID:   {}", hex::encode(token.issuer_id));
    eprintln!("  IssuedAt:   {}", token.issued_at);
    eprintln!("  ExpiresAt:  {}", token.expires_at);
    eprintln!("  Scope:      {}", hex::encode(token.session_scope));
    eprintln!("  MAC:        {}", hex::encode(token.mac));

    // Verify MAC
    if token.verify(&TEST_SECRET) {
        eprintln!("\nPASS: MAC verification succeeded");
        println!("PASS");
    } else {
        // Also show what we expected
        let data = &bytes[..61];
        let expected_mac = admission::hmac_blake2s(&TEST_SECRET, data);
        eprintln!("\nFAIL: MAC verification failed");
        eprintln!("  Expected MAC: {}", hex::encode(expected_mac));
        eprintln!("  Actual MAC:   {}", hex::encode(token.mac));
        println!("FAIL");
        std::process::exit(1);
    }

    // Verify expected field values
    let mut all_ok = true;
    if token.node_id != TEST_NODE_ID {
        eprintln!("FAIL: NodeID mismatch");
        all_ok = false;
    }
    if token.issuer_id != TEST_ISSUER_ID {
        eprintln!("FAIL: IssuerID mismatch");
        all_ok = false;
    }
    if token.issued_at != TEST_ISSUED_AT {
        eprintln!(
            "FAIL: IssuedAt mismatch (got {}, expected {})",
            token.issued_at, TEST_ISSUED_AT
        );
        all_ok = false;
    }
    if token.expires_at != TEST_EXPIRES_AT {
        eprintln!(
            "FAIL: ExpiresAt mismatch (got {}, expected {})",
            token.expires_at, TEST_EXPIRES_AT
        );
        all_ok = false;
    }

    if all_ok {
        eprintln!("All field checks PASS");
    } else {
        std::process::exit(1);
    }
}

/// Self-contained round-trip test.
fn cmd_selftest() {
    eprintln!("=== RAT Interop Self-Test ===\n");

    // 1. Generate
    let token = RelayAdmissionToken::issue_at(
        TEST_NODE_ID,
        TEST_ISSUER_ID,
        TEST_SESSION_SCOPE,
        TEST_ISSUED_AT,
        TEST_EXPIRES_AT,
        &TEST_SECRET,
    );

    let bytes = token.serialize();
    eprintln!(
        "1. Generated RAT: {} ({} bytes)",
        hex::encode(&bytes),
        bytes.len()
    );

    // 2. Parse
    let parsed = RelayAdmissionToken::parse(&bytes).expect("parse should succeed");
    eprintln!(
        "2. Parsed: version={}, node_id={}",
        parsed.version,
        hex::encode(parsed.node_id)
    );

    // 3. Verify MAC
    assert!(parsed.verify(&TEST_SECRET), "MAC verification failed");
    eprintln!("3. MAC verification: PASS");

    // 4. Field checks
    assert_eq!(parsed.version, RAT_VERSION);
    assert_eq!(parsed.node_id, TEST_NODE_ID);
    assert_eq!(parsed.issuer_id, TEST_ISSUER_ID);
    assert_eq!(parsed.issued_at, TEST_ISSUED_AT);
    assert_eq!(parsed.expires_at, TEST_EXPIRES_AT);
    assert_eq!(parsed.session_scope, TEST_SESSION_SCOPE);
    eprintln!("4. Field checks: PASS");

    // 5. Tamper detection
    let mut tampered = bytes;
    tampered[5] ^= 0xFF;
    let tampered_token = RelayAdmissionToken::parse(&tampered).expect("parse should succeed");
    assert!(
        !tampered_token.verify(&TEST_SECRET),
        "tampered token should fail verification"
    );
    eprintln!("5. Tamper detection: PASS");

    // 6. Wrong key detection
    let wrong_key = [0xFFu8; 32];
    assert!(
        !parsed.verify(&wrong_key),
        "wrong key should fail verification"
    );
    eprintln!("6. Wrong key rejection: PASS");

    // 7. Session scope
    assert!(
        parsed.valid_for_session(&[0xFF; 12]),
        "any-scope token should match any session"
    );
    let scoped = RelayAdmissionToken::issue_at(
        TEST_NODE_ID,
        TEST_ISSUER_ID,
        [0xCC; 12],
        TEST_ISSUED_AT,
        TEST_EXPIRES_AT,
        &TEST_SECRET,
    );
    assert!(
        scoped.valid_for_session(&[0xCC; 12]),
        "scoped token should match its session"
    );
    assert!(
        !scoped.valid_for_session(&[0xDD; 12]),
        "scoped token should not match other sessions"
    );
    eprintln!("7. Session scope: PASS");

    eprintln!("\n=== ALL TESTS PASSED ===");
    println!("PASS");
}

/// Print HMAC-BLAKE2s test vectors for cross-language comparison.
fn cmd_hmac_test() {
    eprintln!("=== HMAC-BLAKE2s Test Vectors ===\n");
    eprintln!("These can be verified against the Elixir implementation.");
    eprintln!();

    // Vector 1: Simple
    let key1 = [0xAA; 32];
    let msg1 = b"hello world";
    let mac1 = admission::hmac_blake2s(&key1, msg1);
    println!("vector1_key={}", hex::encode(key1));
    println!("vector1_msg={}", hex::encode(msg1));
    println!("vector1_mac={}", hex::encode(mac1));
    eprintln!("Vector 1: key=AA*32, msg=\"hello world\"");
    eprintln!("  MAC: {}", hex::encode(mac1));

    // Vector 2: Empty message
    let key2 = [0x42; 32];
    let msg2 = b"";
    let mac2 = admission::hmac_blake2s(&key2, msg2);
    println!("vector2_key={}", hex::encode(key2));
    println!("vector2_msg=");
    println!("vector2_mac={}", hex::encode(mac2));
    eprintln!("\nVector 2: key=42*32, msg=\"\"");
    eprintln!("  MAC: {}", hex::encode(mac2));

    // Vector 3: The known RAT data
    let data = {
        let mut buf = Vec::with_capacity(61);
        buf.push(0x01); // version
        buf.extend_from_slice(&[0xAA; 16]); // node_id
        buf.extend_from_slice(&[0xBB; 16]); // issuer_id
        buf.extend_from_slice(&TEST_ISSUED_AT.to_be_bytes());
        buf.extend_from_slice(&TEST_EXPIRES_AT.to_be_bytes());
        buf.extend_from_slice(&[0u8; 12]); // session_scope
        buf
    };
    let mac3 = admission::hmac_blake2s(&TEST_SECRET, &data);
    println!("vector3_key={}", hex::encode(TEST_SECRET));
    println!("vector3_msg={}", hex::encode(&data));
    println!("vector3_mac={}", hex::encode(mac3));
    eprintln!("\nVector 3: known RAT data");
    eprintln!("  Key:  {}", hex::encode(TEST_SECRET));
    eprintln!("  Data: {} ({} bytes)", hex::encode(&data), data.len());
    eprintln!("  MAC:  {}", hex::encode(mac3));
}
