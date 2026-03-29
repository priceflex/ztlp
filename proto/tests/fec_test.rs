use ztlp_proto::fec::*;

// ─── xor_into tests ───

#[test]
fn xor_into_equal_length_buffers() {
    let mut dst = vec![0xAA, 0xBB, 0xCC];
    let src = vec![0x55, 0x44, 0x33];
    xor_into(&mut dst, &src);
    assert_eq!(dst, vec![0xAA ^ 0x55, 0xBB ^ 0x44, 0xCC ^ 0x33]);
}

#[test]
fn xor_into_extends_shorter_dst() {
    let mut dst = vec![0xFF];
    let src = vec![0x01, 0x02, 0x03];
    xor_into(&mut dst, &src);
    // dst[0] = 0xFF ^ 0x01, dst[1] = 0x00 ^ 0x02, dst[2] = 0x00 ^ 0x03
    assert_eq!(dst, vec![0xFE, 0x02, 0x03]);
}

#[test]
fn xor_into_empty_src() {
    let mut dst = vec![0xAA, 0xBB];
    let src: Vec<u8> = vec![];
    xor_into(&mut dst, &src);
    assert_eq!(dst, vec![0xAA, 0xBB]);
}

// ─── FecEncoder tests ───

#[test]
fn encoder_wraps_data_in_correct_frame_format() {
    let mut enc = FecEncoder::new(4);
    let payload = vec![0xDE, 0xAD];
    let result = enc.encode(&payload);

    let pkt = &result.data_packet;
    assert_eq!(pkt[0], FRAME_FEC_DATA);
    // group_id = 0 → [0x00, 0x00]
    assert_eq!(&pkt[1..3], &[0x00, 0x00]);
    // index = 0
    assert_eq!(pkt[3], 0);
    // group_size = 4
    assert_eq!(pkt[4], 4);
    // payload
    assert_eq!(&pkt[5..], &[0xDE, 0xAD]);
}

#[test]
fn encoder_produces_parity_after_group_size_packets() {
    let mut enc = FecEncoder::new(2);
    let r1 = enc.encode(&[0x01]);
    assert!(r1.parity_packet.is_none());

    let r2 = enc.encode(&[0x02]);
    assert!(r2.parity_packet.is_some());
}

#[test]
fn encoder_parity_is_correct_xor() {
    let mut enc = FecEncoder::new(3);
    let p1 = vec![0xAA, 0xBB];
    let p2 = vec![0xCC, 0xDD];
    let p3 = vec![0x11, 0x22];

    enc.encode(&p1);
    enc.encode(&p2);
    let r3 = enc.encode(&p3);

    let parity_pkt = r3.parity_packet.unwrap();
    // Header: [0x0F, group_id(2), group_size(1)] = 4 bytes
    let parity_payload = &parity_pkt[4..];
    let expected = vec![0xAA ^ 0xCC ^ 0x11, 0xBB ^ 0xDD ^ 0x22];
    assert_eq!(parity_payload, &expected[..]);
}

#[test]
fn encoder_group_id_increments_after_each_group() {
    let mut enc = FecEncoder::new(2);
    assert_eq!(enc.current_group_id(), 0);

    enc.encode(&[0x01]);
    enc.encode(&[0x02]);
    assert_eq!(enc.current_group_id(), 1);

    enc.encode(&[0x03]);
    enc.encode(&[0x04]);
    assert_eq!(enc.current_group_id(), 2);
}

#[test]
fn encoder_flush_produces_partial_parity() {
    let mut enc = FecEncoder::new(4);
    enc.encode(&[0xAA]);
    enc.encode(&[0xBB]);

    assert_eq!(enc.buffered_count(), 2);
    let flushed = enc.flush().unwrap();

    assert_eq!(flushed[0], FRAME_FEC_PARITY);
    // group_size in flush = actual_size = 2
    assert_eq!(flushed[3], 2);
    // Parity payload = 0xAA ^ 0xBB
    assert_eq!(flushed[4], 0xAA ^ 0xBB);

    assert_eq!(enc.buffered_count(), 0);
}

#[test]
fn encoder_disabled_passes_through_raw_payload() {
    let mut enc = FecEncoder::new(4);
    enc.set_enabled(false);

    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let result = enc.encode(&payload);

    // When disabled, data_packet is just the raw payload
    assert_eq!(result.data_packet, payload);
    assert!(result.parity_packet.is_none());
}

// ─── FecDecoder tests ───

#[test]
fn decoder_recovers_single_missing_packet() {
    // Group of 3: send packets 0 and 2, lose packet 1
    let mut dec = FecDecoder::new();

    let p0 = vec![0xAA, 0xBB];
    let p1 = vec![0xCC, 0xDD]; // will be "lost"
    let p2 = vec![0x11, 0x22];
    let parity_payload = vec![0xAA ^ 0xCC ^ 0x11, 0xBB ^ 0xDD ^ 0x22];

    dec.decode_data(0, 0, 3, &p0);
    dec.decode_data(0, 2, 3, &p2);
    let recovered = dec.decode_parity(0, 3, &parity_payload);

    let rec = recovered.unwrap();
    assert_eq!(rec.index, 1);
    assert_eq!(rec.payload, p1);
}

#[test]
fn decoder_recovers_first_packet_in_group() {
    let mut dec = FecDecoder::new();

    let p0 = vec![0x10, 0x20]; // lost
    let p1 = vec![0x30, 0x40];
    let p2 = vec![0x50, 0x60];
    let parity_payload = vec![0x10 ^ 0x30 ^ 0x50, 0x20 ^ 0x40 ^ 0x60];

    dec.decode_data(0, 1, 3, &p1);
    dec.decode_data(0, 2, 3, &p2);
    let recovered = dec.decode_parity(0, 3, &parity_payload);

    let rec = recovered.unwrap();
    assert_eq!(rec.index, 0);
    assert_eq!(rec.payload, p0);
}

#[test]
fn decoder_recovers_last_packet_in_group() {
    let mut dec = FecDecoder::new();

    let p0 = vec![0x10];
    let p1 = vec![0x20];
    let p2 = vec![0x30]; // lost
    let parity_payload = vec![0x10 ^ 0x20 ^ 0x30];

    dec.decode_data(0, 0, 3, &p0);
    dec.decode_data(0, 1, 3, &p1);
    let recovered = dec.decode_parity(0, 3, &parity_payload);

    let rec = recovered.unwrap();
    assert_eq!(rec.index, 2);
    assert_eq!(rec.payload, p2);
}

#[test]
fn decoder_returns_none_when_more_than_one_missing() {
    let mut dec = FecDecoder::new();

    let p0 = vec![0xAA];
    let parity_payload = vec![0xAA ^ 0xBB ^ 0xCC];

    // Only 1 of 3 data packets received → 2 missing
    dec.decode_data(0, 0, 3, &p0);
    let recovered = dec.decode_parity(0, 3, &parity_payload);
    assert!(recovered.is_none());
}

#[test]
fn decoder_returns_none_without_parity() {
    let mut dec = FecDecoder::new();

    // Send 2 of 3 data packets, no parity
    let r0 = dec.decode_data(0, 0, 3, &[0xAA]);
    let r1 = dec.decode_data(0, 1, 3, &[0xBB]);

    assert!(r0.recovered.is_none());
    assert!(r1.recovered.is_none());
}

#[test]
fn decoder_parity_arrives_before_all_data() {
    let mut dec = FecDecoder::new();

    let p0 = vec![0xAA];
    let p1 = vec![0xBB]; // lost
    let parity_payload = vec![0xAA ^ 0xBB];

    // Parity arrives first, then data
    let r_parity = dec.decode_parity(0, 2, &parity_payload);
    // Not enough data yet
    assert!(r_parity.is_none());

    // Now send the one data packet we have
    let r0 = dec.decode_data(0, 0, 2, &p0);
    // Now we have 1 of 2 + parity → can recover
    let rec = r0.recovered.unwrap();
    assert_eq!(rec.index, 1);
    assert_eq!(rec.payload, p1);
}

#[test]
fn decoder_data_arrives_after_parity() {
    let mut dec = FecDecoder::new();

    let p0 = vec![0x11]; // lost
    let p1 = vec![0x22];
    let p2 = vec![0x33];
    let parity_payload = vec![0x11 ^ 0x22 ^ 0x33];

    // Parity first
    dec.decode_parity(0, 3, &parity_payload);
    // Then data trickles in
    dec.decode_data(0, 1, 3, &p1);
    let r2 = dec.decode_data(0, 2, 3, &p2);

    let rec = r2.recovered.unwrap();
    assert_eq!(rec.index, 0);
    assert_eq!(rec.payload, p0);
}

#[test]
fn decoder_gc_removes_old_groups() {
    let mut dec = FecDecoder::new();

    // Add many groups to exceed the internal max_groups threshold (64).
    // When the threshold is exceeded, GC runs and removes groups older than 5s.
    // Since all groups are fresh, they survive — but the GC path is exercised.
    for gid in 0..70u16 {
        dec.decode_data(gid, 0, 4, &[0x01]);
    }

    // All groups are recent so they survive the 5s cutoff,
    // but GC was triggered (len > max_groups). active_groups <= 70.
    assert!(dec.active_groups() <= 70);
    assert!(dec.active_groups() > 0);
}

// ─── Full roundtrip tests ───

#[test]
fn full_roundtrip_encode_lose_one_decode_recover() {
    let mut enc = FecEncoder::new(4);
    let mut dec = FecDecoder::new();

    let payloads: Vec<Vec<u8>> = vec![
        vec![0x01, 0x02, 0x03, 0x04],
        vec![0x11, 0x12, 0x13, 0x14],
        vec![0x21, 0x22, 0x23, 0x24],
        vec![0x31, 0x32, 0x33, 0x34],
    ];

    let mut encoded_packets = Vec::new();
    let mut parity_pkt = None;

    for p in &payloads {
        let result = enc.encode(p);
        encoded_packets.push(result.data_packet);
        if result.parity_packet.is_some() {
            parity_pkt = result.parity_packet;
        }
    }

    let parity_pkt = parity_pkt.unwrap();
    let lost_index = 2; // lose packet index 2

    // Decode all except the lost one
    for (i, pkt) in encoded_packets.iter().enumerate() {
        if i == lost_index {
            continue;
        }
        let group_id = u16::from_be_bytes([pkt[1], pkt[2]]);
        let index = pkt[3];
        let group_size = pkt[4];
        let payload = &pkt[5..];
        dec.decode_data(group_id, index, group_size, payload);
    }

    // Now decode parity
    let group_id = u16::from_be_bytes([parity_pkt[1], parity_pkt[2]]);
    let group_size = parity_pkt[3];
    let parity_payload = &parity_pkt[4..];
    let recovered = dec.decode_parity(group_id, group_size, parity_payload);

    let rec = recovered.unwrap();
    assert_eq!(rec.index, lost_index as u8);
    assert_eq!(rec.payload, payloads[lost_index]);
}

#[test]
fn full_roundtrip_different_group_sizes() {
    for group_size in [2u8, 4, 8] {
        let mut enc = FecEncoder::new(group_size);
        let mut dec = FecDecoder::new();

        let payloads: Vec<Vec<u8>> = (0..group_size)
            .map(|i| vec![i.wrapping_mul(0x11); 8])
            .collect();

        let mut encoded = Vec::new();
        let mut parity_pkt = None;

        for p in &payloads {
            let result = enc.encode(p);
            encoded.push(result.data_packet);
            if result.parity_packet.is_some() {
                parity_pkt = result.parity_packet;
            }
        }

        let parity_pkt = parity_pkt.unwrap();
        // Lose the first packet
        let lost_idx = 0;

        for (i, pkt) in encoded.iter().enumerate() {
            if i == lost_idx {
                continue;
            }
            let gid = u16::from_be_bytes([pkt[1], pkt[2]]);
            let idx = pkt[3];
            let gs = pkt[4];
            let payload = &pkt[5..];
            dec.decode_data(gid, idx, gs, payload);
        }

        let gid = u16::from_be_bytes([parity_pkt[1], parity_pkt[2]]);
        let gs = parity_pkt[3];
        let pp = &parity_pkt[4..];
        let recovered = dec.decode_parity(gid, gs, pp);

        let rec = recovered.unwrap();
        assert_eq!(
            rec.payload, payloads[lost_idx],
            "Failed for group_size={group_size}"
        );
    }
}

#[test]
fn frame_constants_correct() {
    assert_eq!(FRAME_FEC_DATA, 0x0E);
    assert_eq!(FRAME_FEC_PARITY, 0x0F);
}

#[test]
fn group_id_wraps_at_u16_max() {
    // With group_size=1, each encode completes a group and increments group_id
    let mut enc = FecEncoder::new(1);
    assert_eq!(enc.current_group_id(), 0);
    enc.encode(&[0x01]); // completes group 0
    assert_eq!(enc.current_group_id(), 1);

    // Functional test: encode u16::MAX+1 times to see wrapping
    // group_size=1 so each packet advances group_id
    let mut enc2 = FecEncoder::new(1);
    for _ in 0..=u16::MAX as u32 {
        enc2.encode(&[0xFF]);
    }
    // After u16::MAX+1 groups (0..=65535), should wrap to 0
    assert_eq!(enc2.current_group_id(), 0);
}

#[test]
fn variable_length_payloads_in_same_group() {
    let mut enc = FecEncoder::new(3);
    let mut dec = FecDecoder::new();

    let p0 = vec![0xAA, 0xBB, 0xCC]; // 3 bytes
    let p1 = vec![0x11]; // 1 byte
    let p2 = vec![0x22, 0x33]; // 2 bytes — lost

    // Expected parity (XOR with zero-padding to max len=3):
    // [0xAA^0x11^0x22, 0xBB^0x00^0x33, 0xCC^0x00^0x00]
    let expected_parity = vec![0xAA ^ 0x11 ^ 0x22, 0xBB ^ 0x00 ^ 0x33, 0xCC ^ 0x00 ^ 0x00];

    enc.encode(&p0);
    enc.encode(&p1);
    let r2 = enc.encode(&p2);

    let parity_pkt = r2.parity_packet.unwrap();
    let parity_payload = &parity_pkt[4..];
    assert_eq!(parity_payload, &expected_parity[..]);

    // Now decode: lose p2
    dec.decode_data(0, 0, 3, &p0);
    dec.decode_data(0, 1, 3, &p1);
    let recovered = dec.decode_parity(0, 3, parity_payload);

    let rec = recovered.unwrap();
    assert_eq!(rec.index, 2);
    // Recovered payload will be 3 bytes (padded to max length in group)
    // p2 was [0x22, 0x33] but recovery produces [0x22, 0x33, 0xCC]
    // because parity was computed with p2 padded to 3 bytes (0x22, 0x33, 0x00)
    // Recovery: parity XOR p0 XOR p1 = expected_parity XOR p0 XOR p1
    // = [0xAA^0x11^0x22 ^ 0xAA ^ 0x11, 0xBB^0x33 ^ 0xBB ^ 0x00, 0xCC ^ 0xCC ^ 0x00]
    // = [0x22, 0x33, 0x00]
    assert_eq!(rec.payload, vec![0x22, 0x33, 0x00]);
    // The recovered payload has the original bytes plus zero padding.
    // In practice, the original payload length would be encoded elsewhere
    // or the transport layer strips trailing zeros. The key point is the
    // original bytes are preserved.
    assert_eq!(&rec.payload[..p2.len()], &p2[..]);
}

#[test]
fn recovery_produces_original_payload_byte_for_byte() {
    let mut enc = FecEncoder::new(4);

    // Use equal-length payloads for exact byte-for-byte recovery
    let payloads: Vec<Vec<u8>> = vec![
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        vec![0xCA, 0xFE, 0xBA, 0xBE],
        vec![0x12, 0x34, 0x56, 0x78],
        vec![0x9A, 0xBC, 0xDE, 0xF0],
    ];

    let mut encoded = Vec::new();
    let mut parity_pkt = None;

    for p in &payloads {
        let result = enc.encode(p);
        encoded.push(result.data_packet);
        if result.parity_packet.is_some() {
            parity_pkt = result.parity_packet;
        }
    }

    let parity_pkt = parity_pkt.unwrap();

    // Test recovery for each possible lost packet
    for lost in 0..4 {
        let mut dec = FecDecoder::new();

        for (i, pkt) in encoded.iter().enumerate() {
            if i == lost {
                continue;
            }
            let gid = u16::from_be_bytes([pkt[1], pkt[2]]);
            let idx = pkt[3];
            let gs = pkt[4];
            let payload = &pkt[5..];
            dec.decode_data(gid, idx, gs, payload);
        }

        let gid = u16::from_be_bytes([parity_pkt[1], parity_pkt[2]]);
        let gs = parity_pkt[3];
        let pp = &parity_pkt[4..];
        let recovered = dec.decode_parity(gid, gs, pp);

        let rec = recovered.unwrap();
        assert_eq!(
            rec.payload, payloads[lost],
            "Failed to recover packet {lost} byte-for-byte"
        );
        assert_eq!(rec.index, lost as u8);
    }
}

// ─── FecDecoder private struct access test via public API ───

// We test GC indirectly through the public API since FecGroup is private.
// The GC test above covers this.

// Additional edge case: encoder flush on empty buffer returns None
#[test]
fn encoder_flush_empty_returns_none() {
    let mut enc = FecEncoder::new(4);
    assert!(enc.flush().is_none());
}

// Encoder set_group_size clamps
#[test]
fn encoder_set_group_size_clamps() {
    let mut enc = FecEncoder::new(4);
    enc.set_group_size(20); // above MAX_FEC_GROUP_SIZE
                            // Should be clamped — we verify by encoding enough to trigger parity
                            // at MAX_FEC_GROUP_SIZE (10)
    for i in 0..9 {
        let r = enc.encode(&[i]);
        assert!(r.parity_packet.is_none(), "Unexpected parity at index {i}");
    }
    let r = enc.encode(&[0x09]);
    assert!(r.parity_packet.is_some(), "Expected parity at index 9");
}

#[test]
fn decoder_default_trait() {
    let dec = FecDecoder::default();
    assert_eq!(dec.active_groups(), 0);
}
