//! Fuzz target: Noise_XX handshake state machine.
//!
//! Feeds random message sequences into HandshakeContext to test
//! that invalid messages are rejected gracefully (no panics).

#![no_main]

use libfuzzer_sys::fuzz_target;
use ztlp_proto::handshake::{HandshakeContext, Role};
use ztlp_proto::identity::NodeIdentity;

fuzz_target!(|data: &[u8]| {
    // Need at least 1 byte to decide role + some payload
    if data.is_empty() {
        return;
    }

    let role = if data[0] & 1 == 0 {
        Role::Initiator
    } else {
        Role::Responder
    };
    let payload = &data[1..];

    // Generate a fresh identity for each fuzz run
    let identity = match NodeIdentity::generate() {
        Ok(id) => id,
        Err(_) => return,
    };

    // Create a handshake context
    let mut ctx = match role {
        Role::Initiator => match HandshakeContext::new_initiator(&identity) {
            Ok(c) => c,
            Err(_) => return,
        },
        Role::Responder => match HandshakeContext::new_responder(&identity) {
            Ok(c) => c,
            Err(_) => return,
        },
    };

    // For initiator: write first message, then try reading fuzzed data
    if role == Role::Initiator {
        match ctx.write_message(&[]) {
            Ok(_) => {}
            Err(_) => return,
        }
        // Try to read the fuzzed payload as if it were a response
        let _ = ctx.read_message(payload);
    } else {
        // For responder: try reading the fuzzed data as first message
        let _ = ctx.read_message(payload);
    }

    // Additional: split payload into chunks and feed them sequentially
    if payload.len() >= 2 {
        let mid = payload.len() / 2;
        let identity2 = match NodeIdentity::generate() {
            Ok(id) => id,
            Err(_) => return,
        };

        // Try as initiator doing full exchange with fuzz data
        let mut init = match HandshakeContext::new_initiator(&identity2) {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = init.write_message(&payload[..mid]);
        let _ = init.read_message(&payload[mid..]);
    }
});
