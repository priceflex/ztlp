use std::collections::BTreeMap;
use std::io;

/// A receive window that buffers out-of-order data payloads and yields contiguous sequences.
pub struct ReceiveWindow {
    /// The next `data_seq` we expect to yield to the application.
    expected_seq: u64,
    /// A buffer of out-of-order payloads, keyed by `data_seq`.
    buffer: BTreeMap<u64, Vec<u8>>,
}

impl Default for ReceiveWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReceiveWindow {
    pub fn new() -> Self {
        Self {
            expected_seq: 0, // Using 0 as the initial expected sequence, standard starting point.
            buffer: BTreeMap::new(),
        }
    }

    /// Processes an incoming packet.
    /// If the packet is exactly what we expect, it's returned immediately along with
    /// any subsequent contiguous packets we had buffered.
    /// If it's a future packet, it's buffered.
    /// If it's a duplicate or an old packet, it's ignored/dropped.
    pub fn insert(&mut self, seq: u64, payload: Vec<u8>) -> Vec<Vec<u8>> {
        if seq < self.expected_seq {
            // Duplicate or old packet, ignore.
            return Vec::new();
        }

        if seq > self.expected_seq {
            // Future packet, buffer it if we don't already have it.
            self.buffer.entry(seq).or_insert(payload);
            return Vec::new();
        }

        // It is exactly the expected sequence.
        let mut contiguous_payloads = vec![payload];
        self.expected_seq += 1;

        // Check if we have any subsequent continuous packets in the buffer.
        while let Some(buffered_payload) = self.buffer.remove(&self.expected_seq) {
            contiguous_payloads.push(buffered_payload);
            self.expected_seq += 1;
        }

        contiguous_payloads
    }

    /// Reset the window (e.g., on a connection reset).
    pub fn reset(&mut self) {
        self.expected_seq = 0;
        self.buffer.clear();
    }
}
