//! Fuzz target: Relay Admission Token (RAT) parsing.
//!
//! Feeds random bytes into RelayAdmissionToken::parse() and the
//! HandshakeExtension parser to ensure they reject malformed input
//! without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ztlp_proto::admission::{HandshakeExtension, RelayAdmissionToken};

fuzz_target!(|data: &[u8]| {
    // Try parsing as a RAT
    let rat_result = RelayAdmissionToken::parse(data);

    if let Ok(rat) = &rat_result {
        // Exercise all accessor methods
        let _ = rat.display();
        let _ = rat.is_expired();
        let _ = rat.ttl_seconds();

        // Verify with a random key
        let _ = rat.verify(&[0xAA; 32]);

        // Check session scope
        let _ = rat.valid_for_session(&[0u8; 12]);

        // Round-trip: serialize and re-parse
        let serialized = rat.serialize();
        let reparsed = RelayAdmissionToken::parse(&serialized);
        assert!(
            reparsed.is_ok(),
            "round-trip failed: serialize then re-parse"
        );
    }

    // Try parsing as a HandshakeExtension
    let _ = HandshakeExtension::parse(data);

    // Try with various truncated lengths
    for len in 0..data.len().min(128) {
        let _ = RelayAdmissionToken::parse(&data[..len]);
        let _ = HandshakeExtension::parse(&data[..len]);
    }
});
