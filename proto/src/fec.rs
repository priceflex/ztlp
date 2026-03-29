//! XOR-based Forward Error Correction
//!
//! Groups N data packets, produces 1 parity packet.
//! Can recover any single lost packet per group.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Frame type for FEC-wrapped data
pub const FRAME_FEC_DATA: u8 = 0x0E;
/// Frame type for FEC parity
pub const FRAME_FEC_PARITY: u8 = 0x0F;

/// Default FEC group size (data packets per parity packet)
pub const DEFAULT_FEC_GROUP_SIZE: u8 = 4;

/// Maximum FEC group size
pub const MAX_FEC_GROUP_SIZE: u8 = 10;

/// Maximum payload size for FEC packets
pub const MAX_FEC_PAYLOAD: usize = 1200;

/// FEC Encoder — sender side
pub struct FecEncoder {
    /// Current group ID (wraps at u16::MAX)
    group_id: u16,
    /// Group size (N data packets per 1 parity)
    group_size: u8,
    /// Current buffer of packets in this group
    buffer: Vec<Vec<u8>>,
    /// Running XOR parity
    parity: Vec<u8>,
    /// Whether FEC is enabled
    enabled: bool,
}

impl FecEncoder {
    pub fn new(group_size: u8) -> Self {
        let group_size = group_size.clamp(1, MAX_FEC_GROUP_SIZE);
        Self {
            group_id: 0,
            group_size,
            buffer: Vec::with_capacity(group_size as usize),
            parity: Vec::new(),
            enabled: true,
        }
    }

    /// Wrap a data payload in FEC framing and accumulate parity.
    /// Returns the FEC-wrapped data packet.
    /// When the group is complete (N packets accumulated), also returns the parity packet.
    pub fn encode(&mut self, payload: &[u8]) -> FecEncodeResult {
        if !self.enabled || payload.is_empty() {
            return FecEncodeResult {
                data_packet: payload.to_vec(),
                parity_packet: None,
            };
        }

        let index = self.buffer.len() as u8;

        // Build FEC data frame
        let mut data_packet = Vec::with_capacity(5 + payload.len());
        data_packet.push(FRAME_FEC_DATA);
        data_packet.extend_from_slice(&self.group_id.to_be_bytes());
        data_packet.push(index);
        data_packet.push(self.group_size);
        data_packet.extend_from_slice(payload);

        // XOR into parity (pad shorter payloads with zeros)
        xor_into(&mut self.parity, payload);
        self.buffer.push(payload.to_vec());

        // Check if group is complete
        let parity_packet = if self.buffer.len() >= self.group_size as usize {
            let mut parity_pkt = Vec::with_capacity(4 + self.parity.len());
            parity_pkt.push(FRAME_FEC_PARITY);
            parity_pkt.extend_from_slice(&self.group_id.to_be_bytes());
            parity_pkt.push(self.group_size);
            parity_pkt.extend_from_slice(&self.parity);

            // Reset for next group
            self.group_id = self.group_id.wrapping_add(1);
            self.buffer.clear();
            self.parity.clear();

            Some(parity_pkt)
        } else {
            None
        };

        FecEncodeResult {
            data_packet,
            parity_packet,
        }
    }

    /// Set FEC group size (1 = effectively disabled, just wrapping)
    pub fn set_group_size(&mut self, size: u8) {
        self.group_size = size.clamp(1, MAX_FEC_GROUP_SIZE);
    }

    /// Enable/disable FEC
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.buffer.clear();
            self.parity.clear();
        }
    }

    /// Get current group ID
    pub fn current_group_id(&self) -> u16 {
        self.group_id
    }

    /// Get number of buffered packets in current group
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// Flush incomplete group (e.g., on timeout/idle).
    /// Returns parity for partial group if any packets buffered.
    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.buffer.is_empty() {
            return None;
        }

        let actual_size = self.buffer.len() as u8;
        let mut parity_pkt = Vec::with_capacity(4 + self.parity.len());
        parity_pkt.push(FRAME_FEC_PARITY);
        parity_pkt.extend_from_slice(&self.group_id.to_be_bytes());
        parity_pkt.push(actual_size); // actual count, not target group_size
        parity_pkt.extend_from_slice(&self.parity);

        self.group_id = self.group_id.wrapping_add(1);
        self.buffer.clear();
        self.parity.clear();

        Some(parity_pkt)
    }
}

/// Result of encoding a single payload
pub struct FecEncodeResult {
    /// The FEC-wrapped data packet to send
    pub data_packet: Vec<u8>,
    /// Parity packet (only present when group is complete)
    pub parity_packet: Option<Vec<u8>>,
}

/// FEC Decoder — receiver side
pub struct FecDecoder {
    /// Active FEC groups being reassembled
    groups: HashMap<u16, FecGroup>,
    /// Max groups to track (prevent memory leak)
    max_groups: usize,
    /// Whether FEC is enabled
    enabled: bool,
}

struct FecGroup {
    size: u8,
    received: Vec<Option<Vec<u8>>>, // indexed by group_index
    parity: Option<Vec<u8>>,
    received_count: u8,
    created_at: Instant,
}

impl FecDecoder {
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            max_groups: 64,
            enabled: true,
        }
    }

    /// Process an incoming FEC data packet.
    /// Returns the extracted payload and optionally a recovered packet.
    pub fn decode_data(
        &mut self,
        group_id: u16,
        index: u8,
        group_size: u8,
        payload: &[u8],
    ) -> FecDecodeResult {
        if !self.enabled {
            return FecDecodeResult {
                payload: payload.to_vec(),
                recovered: None,
            };
        }

        self.gc_old_groups();

        let group = self.groups.entry(group_id).or_insert_with(|| FecGroup {
            size: group_size,
            received: vec![None; group_size as usize],
            parity: None,
            received_count: 0,
            created_at: Instant::now(),
        });

        if (index as usize) < group.received.len() && group.received[index as usize].is_none() {
            group.received[index as usize] = Some(payload.to_vec());
            group.received_count += 1;
        }

        let recovered = self.try_recover(group_id);

        FecDecodeResult {
            payload: payload.to_vec(),
            recovered,
        }
    }

    /// Process an incoming FEC parity packet.
    /// Returns optionally a recovered packet.
    pub fn decode_parity(
        &mut self,
        group_id: u16,
        group_size: u8,
        parity_payload: &[u8],
    ) -> Option<RecoveredPacket> {
        if !self.enabled {
            return None;
        }

        self.gc_old_groups();

        let group = self.groups.entry(group_id).or_insert_with(|| FecGroup {
            size: group_size,
            received: vec![None; group_size as usize],
            parity: None,
            received_count: 0,
            created_at: Instant::now(),
        });

        group.parity = Some(parity_payload.to_vec());
        self.try_recover(group_id)
    }

    fn try_recover(&mut self, group_id: u16) -> Option<RecoveredPacket> {
        let group = self.groups.get(&group_id)?;
        let parity = group.parity.as_ref()?;

        // Need exactly (size - 1) data packets + parity to recover 1 missing
        let missing_count = group.size as usize - group.received_count as usize;
        if missing_count != 1 {
            return None;
        }

        // Find the missing index
        let missing_idx = group.received.iter().position(|p| p.is_none())?;

        // XOR all received packets + parity to recover missing
        let mut recovered = parity.clone();
        for (i, packet) in group.received.iter().enumerate() {
            if i != missing_idx {
                if let Some(data) = packet {
                    xor_into(&mut recovered, data);
                }
            }
        }

        // Clean up complete group
        self.groups.remove(&group_id);

        Some(RecoveredPacket {
            group_id,
            index: missing_idx as u8,
            payload: recovered,
        })
    }

    fn gc_old_groups(&mut self) {
        if self.groups.len() <= self.max_groups {
            return;
        }
        // Remove groups older than 5 seconds
        let cutoff = Instant::now() - Duration::from_secs(5);
        self.groups.retain(|_, g| g.created_at > cutoff);
    }

    /// Enable/disable FEC decoding
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.groups.clear();
        }
    }

    /// Stats for debugging
    pub fn active_groups(&self) -> usize {
        self.groups.len()
    }
}

impl Default for FecDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of decoding an FEC data packet
pub struct FecDecodeResult {
    /// The extracted original payload
    pub payload: Vec<u8>,
    /// A recovered packet, if recovery was possible
    pub recovered: Option<RecoveredPacket>,
}

/// A packet recovered via FEC
pub struct RecoveredPacket {
    /// The FEC group this packet belonged to
    pub group_id: u16,
    /// The index within the group
    pub index: u8,
    /// The recovered payload bytes
    pub payload: Vec<u8>,
}

/// XOR `src` into `dst`, extending `dst` with zeros if needed
pub fn xor_into(dst: &mut Vec<u8>, src: &[u8]) {
    if dst.len() < src.len() {
        dst.resize(src.len(), 0);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}
