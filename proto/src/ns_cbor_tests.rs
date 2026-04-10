// Temporary — will be inlined back into ns_cbor.rs

// Helper: build a CBOR text string
fn cbor_text(s: &str) -> Vec<u8> {
    let len = s.len();
    let mut out = vec![0x60 | (if len < 24 { len as u8 } else { panic!("too long for inline") })];
    out.extend_from_slice(s.as_bytes());
    out
}

// Helper: build a CBOR map
fn cbor_map(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut out = vec![0xA0 | (if entries.len() < 24 { entries.len() as u8 } else { panic!("too many entries") })];
    for (k, v) in entries {
        out.extend_from_slice(&cbor_text(k));
        out.extend_from_slice(&cbor_text(v));
    }
    out
}

#[cfg(test)]
mod tests_from_file {
    // Just checking our CBOR builders work
    #[test]
    fn test_cbor_builder() {
        let cbor = super::cbor_map(&[("address", "1.2.3.4:443"), ("name", "beta1")]);
        // Should be valid CBOR
        assert!(!cbor.is_empty());
    }
}
