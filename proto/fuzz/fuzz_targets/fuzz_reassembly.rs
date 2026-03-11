//! Fuzz target: reassembly buffer.
//!
//! Feeds random sequence numbers and payloads into ReassemblyBuffer
//! to test out-of-order delivery, duplicates, overflow, and eviction.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ztlp_proto::tunnel::ReassemblyBuffer;

/// Structured input for the reassembly fuzzer.
#[derive(Arbitrary, Debug)]
struct ReassemblyInput {
    /// Maximum buffered entries (capped at a reasonable size).
    max_buffered: u8,
    /// Sequence of (seq_number, payload_len) pairs to insert.
    operations: Vec<ReassemblyOp>,
}

#[derive(Arbitrary, Debug)]
enum ReassemblyOp {
    /// Insert a packet with given sequence number and payload size.
    Insert { seq: u16, payload_len: u8 },
    /// Check if the buffer is stalled.
    CheckStalled,
    /// Query missing sequences.
    QueryMissing { max_count: u8 },
    /// Query expected sequence.
    QueryExpected,
    /// Query buffered count.
    QueryBuffered,
}

fuzz_target!(|input: ReassemblyInput| {
    let max_buffered = (input.max_buffered as usize).clamp(1, 256);
    let mut rb = ReassemblyBuffer::new(0, max_buffered);

    for op in &input.operations {
        match op {
            ReassemblyOp::Insert { seq, payload_len } => {
                let seq = *seq as u64;
                let payload = vec![0xAB; *payload_len as usize];
                let result = rb.insert(seq, payload);

                // If insert succeeded, validate the result
                if let Some(delivered) = result {
                    // Delivered entries should be in-order
                    let mut prev_seq: Option<u64> = None;
                    for (s, _data) in &delivered {
                        if let Some(p) = prev_seq {
                            assert!(
                                *s == p + 1,
                                "delivered out of order: prev={}, cur={}",
                                p,
                                s
                            );
                        }
                        prev_seq = Some(*s);
                    }
                }
            }
            ReassemblyOp::CheckStalled => {
                let _ = rb.is_stalled(std::time::Duration::from_secs(5));
            }
            ReassemblyOp::QueryMissing { max_count } => {
                let missing = rb.missing_seqs((*max_count as usize).max(1));
                // All missing seqs should be within a reasonable range
                assert!(missing.len() <= *max_count as usize);
            }
            ReassemblyOp::QueryExpected => {
                let _ = rb.expected_seq();
            }
            ReassemblyOp::QueryBuffered => {
                let count = rb.buffered_count();
                assert!(count <= max_buffered);
            }
        }
    }
});
