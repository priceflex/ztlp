//! Packet format tests — round-trip serialization and field verification.

use ztlp_proto::packet::*;

#[test]
fn test_handshake_header_roundtrip() {
    let mut header = HandshakeHeader::new(MsgType::Hello);
    header.version = VERSION;
    header.hdr_len = 24;
    header.flags = flags::HAS_EXT | flags::ACK_REQ;
    header.msg_type = MsgType::Hello;
    header.crypto_suite = 0x0001;
    header.key_id = 0x1234;
    header.session_id = SessionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    header.packet_seq = 0xDEADBEEFCAFE;
    header.timestamp = 1700000000000;
    header.src_node_id = [0xAA; 16];
    header.dst_svc_id = [0xBB; 16];
    header.policy_tag = 0x12345678;
    header.ext_len = 64;
    header.payload_len = 1024;
    header.header_auth_tag = [0xCC; 16];

    let bytes = header.serialize();
    assert_eq!(bytes.len(), HANDSHAKE_HEADER_SIZE, "header should be exactly 95 bytes");

    let restored = HandshakeHeader::deserialize(&bytes).expect("deserialize should succeed");

    assert_eq!(restored.version, VERSION);
    assert_eq!(restored.hdr_len, 24);
    assert_eq!(restored.flags, flags::HAS_EXT | flags::ACK_REQ);
    assert_eq!(restored.msg_type, MsgType::Hello);
    assert_eq!(restored.crypto_suite, 0x0001);
    assert_eq!(restored.key_id, 0x1234);
    assert_eq!(restored.session_id, SessionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
    assert_eq!(restored.packet_seq, 0xDEADBEEFCAFE);
    assert_eq!(restored.timestamp, 1700000000000);
    assert_eq!(restored.src_node_id, [0xAA; 16]);
    assert_eq!(restored.dst_svc_id, [0xBB; 16]);
    assert_eq!(restored.policy_tag, 0x12345678);
    assert_eq!(restored.ext_len, 64);
    assert_eq!(restored.payload_len, 1024);
    assert_eq!(restored.header_auth_tag, [0xCC; 16]);
}

#[test]
fn test_data_header_roundtrip() {
    let mut header = DataHeader::new(SessionId([0x11; 12]), 42);
    header.flags = flags::MULTIPATH;
    header.header_auth_tag = [0xDD; 16];

    let bytes = header.serialize();
    assert_eq!(bytes.len(), DATA_HEADER_SIZE, "data header should be exactly 42 bytes");

    let restored = DataHeader::deserialize(&bytes).expect("deserialize should succeed");

    assert_eq!(restored.version, VERSION);
    assert_eq!(restored.hdr_len, 11);
    assert_eq!(restored.flags, flags::MULTIPATH);
    assert_eq!(restored.session_id, SessionId([0x11; 12]));
    assert_eq!(restored.packet_seq, 42);
    assert_eq!(restored.header_auth_tag, [0xDD; 16]);
}

#[test]
fn test_ver_hdrlen_bit_packing() {
    // Verify the 4-bit version and 12-bit hdr_len share a u16 correctly
    let mut header = HandshakeHeader::new(MsgType::Data);
    header.version = 1;       // 4 bits: 0001
    header.hdr_len = 0x0ABC;  // 12 bits: 1010 1011 1100

    let bytes = header.serialize();

    // Byte 2-3 (after magic): packed Ver|HdrLen
    // Expected: (1 << 12) | 0x0ABC = 0x1ABC
    let packed = u16::from_be_bytes([bytes[2], bytes[3]]);
    assert_eq!(packed, 0x1ABC, "Ver(1)|HdrLen(0xABC) should pack to 0x1ABC");

    let restored = HandshakeHeader::deserialize(&bytes).expect("deserialize");
    assert_eq!(restored.version, 1);
    assert_eq!(restored.hdr_len, 0x0ABC);
}

#[test]
fn test_magic_bytes() {
    let header = HandshakeHeader::new(MsgType::Ping);
    let bytes = header.serialize();

    // First two bytes should be 0x5A37 ('Z7')
    assert_eq!(bytes[0], 0x5A);
    assert_eq!(bytes[1], 0x37);
}

#[test]
fn test_invalid_magic_rejected() {
    let mut bytes = HandshakeHeader::new(MsgType::Data).serialize();
    // Corrupt the magic
    bytes[0] = 0xFF;
    bytes[1] = 0xFF;

    let result = HandshakeHeader::deserialize(&bytes);
    assert!(result.is_err(), "corrupted magic should cause error");

    match result {
        Err(ztlp_proto::error::PacketError::InvalidMagic(m)) => {
            assert_eq!(m, 0xFFFF);
        }
        _ => panic!("expected InvalidMagic error"),
    }
}

#[test]
fn test_buffer_too_short() {
    let result = HandshakeHeader::deserialize(&[0x5A, 0x37]);
    assert!(result.is_err());

    let result = DataHeader::deserialize(&[0x5A, 0x37, 0x00]);
    assert!(result.is_err());
}

#[test]
fn test_all_msg_types_roundtrip() {
    let types = [
        MsgType::Data,
        MsgType::Hello,
        MsgType::HelloAck,
        MsgType::Rekey,
        MsgType::Close,
        MsgType::Error,
        MsgType::Ping,
        MsgType::Pong,
    ];

    for msg_type in types {
        let header = HandshakeHeader::new(msg_type);
        let bytes = header.serialize();
        let restored = HandshakeHeader::deserialize(&bytes).expect("deserialize");
        assert_eq!(restored.msg_type, msg_type, "msg type roundtrip failed for {:?}", msg_type);
    }
}

#[test]
fn test_session_id_generation() {
    let id1 = SessionId::generate();
    let id2 = SessionId::generate();
    assert_ne!(id1, id2, "two random SessionIDs should differ");
    assert!(!id1.is_zero());
    assert!(SessionId::zero().is_zero());
}

#[test]
fn test_aad_bytes_exclude_auth_tag() {
    let header = HandshakeHeader::new(MsgType::Data);
    let aad = header.aad_bytes();
    assert_eq!(aad.len(), HANDSHAKE_HEADER_SIZE - 16, "AAD should be header minus auth tag");

    let data_header = DataHeader::new(SessionId::generate(), 1);
    let data_aad = data_header.aad_bytes();
    assert_eq!(data_aad.len(), DATA_HEADER_SIZE - 16, "data AAD should be header minus auth tag");
}

#[test]
fn test_packet_enum_serialize() {
    let handshake = ZtlpPacket::Handshake {
        header: HandshakeHeader::new(MsgType::Hello),
        payload: vec![0xAA, 0xBB, 0xCC],
    };
    let bytes = handshake.serialize();
    assert_eq!(bytes.len(), HANDSHAKE_HEADER_SIZE + 3);

    let data = ZtlpPacket::Data {
        header: DataHeader::new(SessionId::generate(), 0),
        payload: vec![0x11, 0x22],
    };
    let bytes = data.serialize();
    assert_eq!(bytes.len(), DATA_HEADER_SIZE + 2);
}
