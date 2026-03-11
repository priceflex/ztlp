//! Fuzz target: NACK/ACK frame decoding.
//!
//! Feeds random bytes into decode_nack_payload() and ACK frame parsing
//! logic to ensure they handle all malformed inputs gracefully.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ztlp_proto::tunnel::decode_nack_payload;

fuzz_target!(|data: &[u8]| {
    // Test NACK decoding with the full payload
    let _ = decode_nack_payload(data);

    // Test with various truncated lengths
    for len in 0..data.len().min(64) {
        let _ = decode_nack_payload(&data[..len]);
    }

    // Test ACK frame payload extraction (8-byte BE u64)
    if data.len() >= 8 {
        let _acked_seq = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
    }

    // If decode succeeds, verify the result is reasonable
    if let Some(seqs) = decode_nack_payload(data) {
        assert!(seqs.len() <= 128, "decoded too many seqs: {}", seqs.len());
        // Verify each seq is a valid u64 (trivially true, but exercises the path)
        for &seq in &seqs {
            let _ = seq.to_be_bytes();
        }
    }
});
