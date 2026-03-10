//! ZTLP packet format — marshal and unmarshal.
//!
//! Implements the exact bit-level layout from the ZTLP spec:
//!
//! **Handshake/Control Header (95 bytes):**
//! - Magic: 16 bits (0x5A37)
//! - Ver: 4 bits + HdrLen: 12 bits (packed into one u16)
//! - Flags: 16 bits
//! - MsgType: 8 bits
//! - CryptoSuite: 16 bits
//! - KeyID/TokenID: 16 bits
//! - SessionID: 96 bits (12 bytes)
//! - PacketSeq: 64 bits
//! - Timestamp: 64 bits
//! - SrcNodeID: 128 bits (16 bytes)
//! - DstSvcID: 128 bits (16 bytes)
//! - PolicyTag: 32 bits
//! - ExtLen: 16 bits
//! - PayloadLen: 16 bits
//! - HeaderAuthTag: 128 bits (16 bytes)
//!
//! **Compact Data Header (42 bytes, post-handshake):**
//! - Magic: 16 bits
//! - Ver: 4 bits + HdrLen: 12 bits
//! - Flags: 16 bits
//! - SessionID: 96 bits (12 bytes)
//! - PacketSequence: 64 bits
//! - HeaderAuthTag: 128 bits (16 bytes)

#![deny(unsafe_code)]

use crate::error::PacketError;

/// ZTLP magic value: 0x5A37 ('Z7').
pub const MAGIC: u16 = 0x5A37;

/// Current protocol version.
pub const VERSION: u8 = 1;

/// Size of the handshake/control header in bytes.
pub const HANDSHAKE_HEADER_SIZE: usize = 95;

/// Size of the compact data header in bytes.
pub const DATA_HEADER_SIZE: usize = 42;

/// Message types per the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    Data = 0,
    Hello = 1,
    HelloAck = 2,
    Rekey = 3,
    Close = 4,
    Error = 5,
    Ping = 6,
    Pong = 7,
}

impl MsgType {
    /// Parse a u8 into a MsgType.
    pub fn from_u8(v: u8) -> Result<Self, PacketError> {
        match v {
            0 => Ok(Self::Data),
            1 => Ok(Self::Hello),
            2 => Ok(Self::HelloAck),
            3 => Ok(Self::Rekey),
            4 => Ok(Self::Close),
            5 => Ok(Self::Error),
            6 => Ok(Self::Ping),
            7 => Ok(Self::Pong),
            _ => Err(PacketError::InvalidMsgType(v)),
        }
    }
}

/// Flag bits.
pub mod flags {
    pub const HAS_EXT: u16 = 1 << 0;
    pub const ACK_REQ: u16 = 1 << 1;
    pub const REKEY: u16 = 1 << 2;
    pub const MIGRATE: u16 = 1 << 3;
    pub const MULTIPATH: u16 = 1 << 4;
    pub const RELAY_HOP: u16 = 1 << 5;
}

/// 96-bit Session ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 12]);

impl SessionId {
    /// Generate a random SessionID.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        Self(bytes)
    }

    /// Zero SessionID (used in initial handshake).
    pub fn zero() -> Self {
        Self([0u8; 12])
    }

    /// Check if this is the zero/unassigned session ID.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 12]
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Handshake / Control header (95 bytes).
#[derive(Debug, Clone)]
pub struct HandshakeHeader {
    /// Protocol version (4 bits, current: 1).
    pub version: u8,
    /// Header length in 4-byte words (12 bits).
    pub hdr_len: u16,
    /// Flags bitfield.
    pub flags: u16,
    /// Message type.
    pub msg_type: MsgType,
    /// Crypto suite identifier.
    pub crypto_suite: u16,
    /// Key ID / Token ID.
    pub key_id: u16,
    /// 96-bit session identifier.
    pub session_id: SessionId,
    /// Monotonically increasing packet sequence number.
    pub packet_seq: u64,
    /// Unix epoch milliseconds.
    pub timestamp: u64,
    /// Sender's 128-bit Node ID.
    pub src_node_id: [u8; 16],
    /// Destination 128-bit Service ID.
    pub dst_svc_id: [u8; 16],
    /// Compact policy tag.
    pub policy_tag: u32,
    /// Extension TLV length in bytes.
    pub ext_len: u16,
    /// Payload length in bytes.
    pub payload_len: u16,
    /// 128-bit AEAD authentication tag over the header.
    pub header_auth_tag: [u8; 16],
}

impl HandshakeHeader {
    /// Serialize to bytes (95 bytes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HANDSHAKE_HEADER_SIZE);

        // Magic (16 bits)
        buf.extend_from_slice(&MAGIC.to_be_bytes());

        // Ver (4 bits) | HdrLen (12 bits) — packed into u16
        let ver_hdrlen: u16 = ((self.version as u16 & 0x0F) << 12)
            | (self.hdr_len & 0x0FFF);
        buf.extend_from_slice(&ver_hdrlen.to_be_bytes());

        // Flags (16 bits)
        buf.extend_from_slice(&self.flags.to_be_bytes());

        // MsgType (8 bits)
        buf.push(self.msg_type as u8);

        // CryptoSuite (16 bits)
        buf.extend_from_slice(&self.crypto_suite.to_be_bytes());

        // KeyID/TokenID (16 bits)
        buf.extend_from_slice(&self.key_id.to_be_bytes());

        // SessionID (96 bits = 12 bytes)
        buf.extend_from_slice(&self.session_id.0);

        // PacketSeq (64 bits)
        buf.extend_from_slice(&self.packet_seq.to_be_bytes());

        // Timestamp (64 bits)
        buf.extend_from_slice(&self.timestamp.to_be_bytes());

        // SrcNodeID (128 bits = 16 bytes)
        buf.extend_from_slice(&self.src_node_id);

        // DstSvcID (128 bits = 16 bytes)
        buf.extend_from_slice(&self.dst_svc_id);

        // PolicyTag (32 bits)
        buf.extend_from_slice(&self.policy_tag.to_be_bytes());

        // ExtLen (16 bits)
        buf.extend_from_slice(&self.ext_len.to_be_bytes());

        // PayloadLen (16 bits)
        buf.extend_from_slice(&self.payload_len.to_be_bytes());

        // HeaderAuthTag (128 bits = 16 bytes)
        buf.extend_from_slice(&self.header_auth_tag);

        debug_assert_eq!(buf.len(), HANDSHAKE_HEADER_SIZE);
        buf
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < HANDSHAKE_HEADER_SIZE {
            return Err(PacketError::BufferTooShort {
                need: HANDSHAKE_HEADER_SIZE,
                have: data.len(),
            });
        }

        let mut pos = 0;

        // Magic
        let magic = u16::from_be_bytes([data[pos], data[pos + 1]]);
        if magic != MAGIC {
            return Err(PacketError::InvalidMagic(magic));
        }
        pos += 2;

        // Ver (4) | HdrLen (12)
        let ver_hdrlen = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let version = ((ver_hdrlen >> 12) & 0x0F) as u8;
        let hdr_len = ver_hdrlen & 0x0FFF;
        pos += 2;

        if version != VERSION {
            return Err(PacketError::UnsupportedVersion(version));
        }

        // Flags
        let flags = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // MsgType
        let msg_type = MsgType::from_u8(data[pos])?;
        pos += 1;

        // CryptoSuite
        let crypto_suite = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // KeyID
        let key_id = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // SessionID (12 bytes)
        let mut session_id = [0u8; 12];
        session_id.copy_from_slice(&data[pos..pos + 12]);
        pos += 12;

        // PacketSeq
        let packet_seq = u64::from_be_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
        ]);
        pos += 8;

        // Timestamp
        let timestamp = u64::from_be_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
        ]);
        pos += 8;

        // SrcNodeID (16 bytes)
        let mut src_node_id = [0u8; 16];
        src_node_id.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        // DstSvcID (16 bytes)
        let mut dst_svc_id = [0u8; 16];
        dst_svc_id.copy_from_slice(&data[pos..pos + 16]);
        pos += 16;

        // PolicyTag
        let policy_tag = u32::from_be_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
        ]);
        pos += 4;

        // ExtLen
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // PayloadLen
        let payload_len = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // HeaderAuthTag (16 bytes)
        let mut header_auth_tag = [0u8; 16];
        header_auth_tag.copy_from_slice(&data[pos..pos + 16]);

        Ok(Self {
            version,
            hdr_len,
            flags,
            msg_type,
            crypto_suite,
            key_id,
            session_id: SessionId(session_id),
            packet_seq,
            timestamp,
            src_node_id,
            dst_svc_id,
            policy_tag,
            ext_len,
            payload_len,
            header_auth_tag,
        })
    }

    /// Return the header bytes WITHOUT the auth tag (first 79 bytes),
    /// used as AAD for AEAD computation.
    pub fn aad_bytes(&self) -> Vec<u8> {
        let full = self.serialize();
        // Everything except the last 16 bytes (HeaderAuthTag)
        full[..HANDSHAKE_HEADER_SIZE - 16].to_vec()
    }

    /// Check if this packet has been through a relay hop.
    pub fn is_relay_hop(&self) -> bool {
        self.flags & flags::RELAY_HOP != 0
    }

    /// Set the relay hop flag.
    pub fn set_relay_hop(&mut self) {
        self.flags |= flags::RELAY_HOP;
    }

    /// Create a default handshake header with reasonable defaults.
    pub fn new(msg_type: MsgType) -> Self {
        Self {
            version: VERSION,
            // 95 bytes = 23.75 words → round up to 24 words
            hdr_len: 24,
            flags: 0,
            msg_type,
            crypto_suite: 0x0001, // ChaCha20-Poly1305 + Noise_XX
            key_id: 0,
            session_id: SessionId::zero(),
            packet_seq: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            src_node_id: [0u8; 16],
            dst_svc_id: [0u8; 16],
            policy_tag: 0,
            ext_len: 0,
            payload_len: 0,
            header_auth_tag: [0u8; 16],
        }
    }
}

/// Compact Data Header (42 bytes, post-handshake).
///
/// Used for established data-plane packets. No NodeID or ServiceID fields —
/// routing is by SessionID only.
#[derive(Debug, Clone)]
pub struct DataHeader {
    /// Protocol version (4 bits).
    pub version: u8,
    /// Header length in 4-byte words (12 bits).
    pub hdr_len: u16,
    /// Flags bitfield.
    pub flags: u16,
    /// 96-bit session identifier.
    pub session_id: SessionId,
    /// Monotonically increasing packet sequence number.
    pub packet_seq: u64,
    /// 128-bit AEAD authentication tag over the header.
    pub header_auth_tag: [u8; 16],
}

impl DataHeader {
    /// Serialize to bytes (42 bytes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(DATA_HEADER_SIZE);

        // Magic (16 bits)
        buf.extend_from_slice(&MAGIC.to_be_bytes());

        // Ver (4) | HdrLen (12)
        let ver_hdrlen: u16 = ((self.version as u16 & 0x0F) << 12)
            | (self.hdr_len & 0x0FFF);
        buf.extend_from_slice(&ver_hdrlen.to_be_bytes());

        // Flags (16 bits)
        buf.extend_from_slice(&self.flags.to_be_bytes());

        // SessionID (96 bits = 12 bytes)
        buf.extend_from_slice(&self.session_id.0);

        // PacketSequence (64 bits)
        buf.extend_from_slice(&self.packet_seq.to_be_bytes());

        // HeaderAuthTag (128 bits = 16 bytes)
        buf.extend_from_slice(&self.header_auth_tag);

        debug_assert_eq!(buf.len(), DATA_HEADER_SIZE);
        buf
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < DATA_HEADER_SIZE {
            return Err(PacketError::BufferTooShort {
                need: DATA_HEADER_SIZE,
                have: data.len(),
            });
        }

        let mut pos = 0;

        // Magic
        let magic = u16::from_be_bytes([data[pos], data[pos + 1]]);
        if magic != MAGIC {
            return Err(PacketError::InvalidMagic(magic));
        }
        pos += 2;

        // Ver | HdrLen
        let ver_hdrlen = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let version = ((ver_hdrlen >> 12) & 0x0F) as u8;
        let hdr_len = ver_hdrlen & 0x0FFF;
        pos += 2;

        if version != VERSION {
            return Err(PacketError::UnsupportedVersion(version));
        }

        // Flags
        let flags = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        // SessionID (12 bytes)
        let mut session_id = [0u8; 12];
        session_id.copy_from_slice(&data[pos..pos + 12]);
        pos += 12;

        // PacketSequence
        let packet_seq = u64::from_be_bytes([
            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
        ]);
        pos += 8;

        // HeaderAuthTag
        let mut header_auth_tag = [0u8; 16];
        header_auth_tag.copy_from_slice(&data[pos..pos + 16]);

        Ok(Self {
            version,
            hdr_len,
            flags,
            session_id: SessionId(session_id),
            packet_seq,
            header_auth_tag,
        })
    }

    /// Return the header bytes WITHOUT the auth tag (first 26 bytes),
    /// used as AAD for AEAD computation.
    pub fn aad_bytes(&self) -> Vec<u8> {
        let full = self.serialize();
        // Everything except the last 16 bytes (HeaderAuthTag)
        full[..DATA_HEADER_SIZE - 16].to_vec()
    }

    /// Check if this packet has been through a relay hop.
    pub fn is_relay_hop(&self) -> bool {
        self.flags & flags::RELAY_HOP != 0
    }

    /// Set the relay hop flag.
    pub fn set_relay_hop(&mut self) {
        self.flags |= flags::RELAY_HOP;
    }

    /// Create a new data header for an established session.
    pub fn new(session_id: SessionId, packet_seq: u64) -> Self {
        Self {
            version: VERSION,
            // 42 bytes = 10.5 words → round up to 11
            hdr_len: 11,
            flags: 0,
            session_id,
            packet_seq,
            header_auth_tag: [0u8; 16],
        }
    }
}

/// A complete ZTLP packet: either handshake or data, plus optional payload.
#[derive(Debug, Clone)]
pub enum ZtlpPacket {
    /// Handshake / control packet with full header.
    Handshake {
        header: HandshakeHeader,
        payload: Vec<u8>,
    },
    /// Data packet with compact header.
    Data {
        header: DataHeader,
        payload: Vec<u8>,
    },
}

impl ZtlpPacket {
    /// Serialize the entire packet (header + payload) to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            ZtlpPacket::Handshake { header, payload } => {
                let mut buf = header.serialize();
                buf.extend_from_slice(payload);
                buf
            }
            ZtlpPacket::Data { header, payload } => {
                let mut buf = header.serialize();
                buf.extend_from_slice(payload);
                buf
            }
        }
    }
}
