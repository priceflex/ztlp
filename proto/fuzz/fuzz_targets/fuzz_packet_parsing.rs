//! Fuzz target: packet parsing paths.
//!
//! Feeds random bytes into all packet parsing functions to verify they
//! never panic and always return a clean Result/Option.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ztlp_proto::packet::{DataHeader, HandshakeHeader, MsgType};

fuzz_target!(|data: &[u8]| {
    // Try parsing as a handshake header
    let _ = HandshakeHeader::deserialize(data);

    // Try parsing as a data header
    let _ = DataHeader::deserialize(data);

    // Try MsgType parsing on every byte
    for &b in data.iter().take(256) {
        let _ = MsgType::from_u8(b);
    }

    // If we can parse a handshake header, try round-tripping
    if let Ok(hdr) = HandshakeHeader::deserialize(data) {
        let serialized = hdr.serialize();
        let _ = HandshakeHeader::deserialize(&serialized);

        // Try parsing extension if ext_len > 0
        if hdr.ext_len > 0 && data.len() > 95 {
            let _ = hdr.parse_extension(&data[95..]);
        }
    }

    // If we can parse a data header, try round-tripping
    if let Ok(hdr) = DataHeader::deserialize(data) {
        let serialized = hdr.serialize();
        let _ = DataHeader::deserialize(&serialized);
    }
});
