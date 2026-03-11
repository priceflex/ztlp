package ztlp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSessionIDGenerate(t *testing.T) {
	s1, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	s2, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	if s1 == s2 {
		t.Error("two random SessionIDs should differ")
	}
	if s1.IsZero() {
		t.Error("random SessionID should not be zero")
	}
}

func TestHandshakeHeaderRoundtrip(t *testing.T) {
	hdr := NewHandshakeHeader(MsgTypeHello)
	hdr.SrcNodeID = NodeID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	hdr.DstSvcID = [16]byte{0xAA, 0xBB}
	hdr.SessionID = SessionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
	hdr.PacketSeq = 42
	hdr.PolicyTag = 0xDEADBEEF
	hdr.ExtLen = 10
	hdr.PayloadLen = 200
	hdr.HeaderAuthTag = [16]byte{0xFF, 0xFE, 0xFD}

	data := hdr.Serialize()
	if len(data) != HandshakeHeaderSize {
		t.Fatalf("serialized size: %d, want %d", len(data), HandshakeHeaderSize)
	}

	// Check magic bytes
	if data[0] != 0x5A || data[1] != 0x37 {
		t.Errorf("magic: %02X%02X, want 5A37", data[0], data[1])
	}

	// Parse it back
	parsed, err := ParseHandshakeHeader(data)
	if err != nil {
		t.Fatalf("ParseHandshakeHeader: %v", err)
	}

	if parsed.Version != Version {
		t.Errorf("version: %d, want %d", parsed.Version, Version)
	}
	if parsed.HdrLen != HandshakeHdrLen {
		t.Errorf("hdrLen: %d, want %d", parsed.HdrLen, HandshakeHdrLen)
	}
	if parsed.MsgType != MsgTypeHello {
		t.Errorf("msgType: %d, want %d", parsed.MsgType, MsgTypeHello)
	}
	if parsed.CryptoSuite != CryptoSuiteDefault {
		t.Errorf("cryptoSuite: %d, want %d", parsed.CryptoSuite, CryptoSuiteDefault)
	}
	if parsed.SessionID != hdr.SessionID {
		t.Errorf("sessionID mismatch")
	}
	if parsed.PacketSeq != 42 {
		t.Errorf("packetSeq: %d, want 42", parsed.PacketSeq)
	}
	if parsed.SrcNodeID != hdr.SrcNodeID {
		t.Errorf("srcNodeID mismatch")
	}
	if parsed.DstSvcID != hdr.DstSvcID {
		t.Errorf("dstSvcID mismatch")
	}
	if parsed.PolicyTag != 0xDEADBEEF {
		t.Errorf("policyTag: %X, want DEADBEEF", parsed.PolicyTag)
	}
	if parsed.ExtLen != 10 {
		t.Errorf("extLen: %d, want 10", parsed.ExtLen)
	}
	if parsed.PayloadLen != 200 {
		t.Errorf("payloadLen: %d, want 200", parsed.PayloadLen)
	}
	if parsed.HeaderAuthTag != hdr.HeaderAuthTag {
		t.Errorf("headerAuthTag mismatch")
	}
}

func TestHandshakeHeaderAADBytes(t *testing.T) {
	hdr := NewHandshakeHeader(MsgTypeHello)
	aad := hdr.AADBytes()
	if len(aad) != HandshakeHeaderSize-AuthTagSize {
		t.Errorf("AAD length: %d, want %d", len(aad), HandshakeHeaderSize-AuthTagSize)
	}
}

func TestDataHeaderRoundtrip(t *testing.T) {
	sid := SessionID{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	hdr := NewDataHeader(sid, 999)
	hdr.Flags = FlagAckReq
	hdr.HeaderAuthTag = [16]byte{0x01, 0x02, 0x03, 0x04}

	data := hdr.Serialize()
	if len(data) != DataHeaderSize {
		t.Fatalf("serialized size: %d, want %d", len(data), DataHeaderSize)
	}

	// Check magic
	if data[0] != 0x5A || data[1] != 0x37 {
		t.Errorf("magic: %02X%02X, want 5A37", data[0], data[1])
	}

	parsed, err := ParseDataHeader(data)
	if err != nil {
		t.Fatalf("ParseDataHeader: %v", err)
	}

	if parsed.Version != Version {
		t.Errorf("version: %d, want %d", parsed.Version, Version)
	}
	if parsed.HdrLen != DataHdrLen {
		t.Errorf("hdrLen: %d, want %d", parsed.HdrLen, DataHdrLen)
	}
	if parsed.Flags != FlagAckReq {
		t.Errorf("flags: %d, want %d", parsed.Flags, FlagAckReq)
	}
	if parsed.SessionID != sid {
		t.Errorf("sessionID mismatch")
	}
	if parsed.PacketSeq != 999 {
		t.Errorf("packetSeq: %d, want 999", parsed.PacketSeq)
	}
	if parsed.HeaderAuthTag != hdr.HeaderAuthTag {
		t.Errorf("headerAuthTag mismatch")
	}
}

func TestDataHeaderAADBytes(t *testing.T) {
	hdr := NewDataHeader(SessionID{}, 0)
	aad := hdr.AADBytes()
	if len(aad) != DataHeaderSize-AuthTagSize {
		t.Errorf("AAD length: %d, want %d", len(aad), DataHeaderSize-AuthTagSize)
	}
}

func TestDetectPacketType(t *testing.T) {
	// Handshake packet
	hdr := NewHandshakeHeader(MsgTypeHello)
	data := hdr.Serialize()
	isHS, err := DetectPacketType(data)
	if err != nil {
		t.Fatalf("DetectPacketType (handshake): %v", err)
	}
	if !isHS {
		t.Error("expected handshake")
	}

	// Data packet
	dHdr := NewDataHeader(SessionID{}, 0)
	dData := dHdr.Serialize()
	isHS, err = DetectPacketType(dData)
	if err != nil {
		t.Fatalf("DetectPacketType (data): %v", err)
	}
	if isHS {
		t.Error("expected data, got handshake")
	}

	// Too short
	_, err = DetectPacketType([]byte{0x5A})
	if err == nil {
		t.Error("expected error for too-short packet")
	}

	// Bad magic
	_, err = DetectPacketType([]byte{0xFF, 0xFF, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestExtractSessionID(t *testing.T) {
	// Handshake
	sid := SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	hdr := NewHandshakeHeader(MsgTypeHello)
	hdr.SessionID = sid
	data := hdr.Serialize()

	extracted, err := ExtractSessionID(data)
	if err != nil {
		t.Fatalf("ExtractSessionID (handshake): %v", err)
	}
	if extracted != sid {
		t.Errorf("handshake SessionID: got %v, want %v", extracted, sid)
	}

	// Data
	dHdr := NewDataHeader(sid, 0)
	dData := dHdr.Serialize()

	extracted, err = ExtractSessionID(dData)
	if err != nil {
		t.Fatalf("ExtractSessionID (data): %v", err)
	}
	if extracted != sid {
		t.Errorf("data SessionID: got %v, want %v", extracted, sid)
	}
}

func TestHandshakeHeaderRelayHop(t *testing.T) {
	hdr := NewHandshakeHeader(MsgTypeHello)
	if hdr.IsRelayHop() {
		t.Error("should not be relay hop initially")
	}
	hdr.SetRelayHop()
	if !hdr.IsRelayHop() {
		t.Error("should be relay hop after SetRelayHop")
	}
}

func TestDataHeaderRelayHop(t *testing.T) {
	hdr := NewDataHeader(SessionID{}, 0)
	if hdr.IsRelayHop() {
		t.Error("should not be relay hop initially")
	}
	hdr.SetRelayHop()
	if !hdr.IsRelayHop() {
		t.Error("should be relay hop after SetRelayHop")
	}
}

func TestMsgTypeString(t *testing.T) {
	tests := []struct {
		mt   MsgType
		want string
	}{
		{MsgTypeData, "Data"},
		{MsgTypeHello, "Hello"},
		{MsgTypeHelloAck, "HelloAck"},
		{MsgTypeRekey, "Rekey"},
		{MsgTypeClose, "Close"},
		{MsgTypeError, "Error"},
		{MsgTypePing, "Ping"},
		{MsgTypePong, "Pong"},
		{MsgType(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.mt.String(); got != tt.want {
			t.Errorf("MsgType(%d).String() = %q, want %q", tt.mt, got, tt.want)
		}
	}
}

func TestParseHandshakeHeaderErrors(t *testing.T) {
	// Too short
	_, err := ParseHandshakeHeader(make([]byte, 10))
	if err == nil {
		t.Error("expected error for short buffer")
	}

	// Bad magic
	data := make([]byte, HandshakeHeaderSize)
	binary.BigEndian.PutUint16(data[0:], 0xFFFF)
	_, err = ParseHandshakeHeader(data)
	if err == nil {
		t.Error("expected error for bad magic")
	}

	// Bad version
	binary.BigEndian.PutUint16(data[0:], Magic)
	binary.BigEndian.PutUint16(data[2:], 0xF000) // version 15
	_, err = ParseHandshakeHeader(data)
	if err == nil {
		t.Error("expected error for bad version")
	}
}

func TestParseDataHeaderErrors(t *testing.T) {
	// Too short
	_, err := ParseDataHeader(make([]byte, 10))
	if err == nil {
		t.Error("expected error for short buffer")
	}

	// Bad magic
	data := make([]byte, DataHeaderSize)
	binary.BigEndian.PutUint16(data[0:], 0xDEAD)
	_, err = ParseDataHeader(data)
	if err == nil {
		t.Error("expected error for bad magic")
	}
}

// TestHandshakeHeaderWireCompatibility verifies byte offsets match the Rust implementation.
func TestHandshakeHeaderWireCompatibility(t *testing.T) {
	hdr := HandshakeHeader{
		Version:     1,
		HdrLen:      24,
		Flags:       0x0003, // HAS_EXT | ACK_REQ
		MsgType:     MsgTypeHello,
		CryptoSuite: 0x0001,
		KeyID:       0x0005,
		SessionID:   SessionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C},
		PacketSeq:   1,
		Timestamp:   1700000000000,
		SrcNodeID:   NodeID{0xAA, 0xBB, 0xCC},
		PolicyTag:   0x12345678,
		ExtLen:      0,
		PayloadLen:  100,
	}

	data := hdr.Serialize()

	// Verify exact byte offsets per Rust packet.rs:
	// Offset 0-1: Magic = 0x5A37
	if binary.BigEndian.Uint16(data[0:]) != 0x5A37 {
		t.Error("magic at wrong offset")
	}

	// Offset 2-3: Ver|HdrLen (version=1, hdrlen=24 → 0x1018)
	verHdrLen := binary.BigEndian.Uint16(data[2:])
	if (verHdrLen>>12)&0x0F != 1 {
		t.Error("version at wrong offset")
	}
	if verHdrLen&0x0FFF != 24 {
		t.Error("hdrLen at wrong offset")
	}

	// Offset 4-5: Flags
	if binary.BigEndian.Uint16(data[4:]) != 0x0003 {
		t.Error("flags at wrong offset")
	}

	// Offset 6: MsgType
	if data[6] != 1 { // Hello
		t.Error("msgType at wrong offset")
	}

	// Offset 7-8: CryptoSuite
	if binary.BigEndian.Uint16(data[7:]) != 0x0001 {
		t.Error("cryptoSuite at wrong offset")
	}

	// Offset 9-10: KeyID
	if binary.BigEndian.Uint16(data[9:]) != 0x0005 {
		t.Error("keyID at wrong offset")
	}

	// Offset 11-22: SessionID
	if !bytes.Equal(data[11:23], hdr.SessionID[:]) {
		t.Error("sessionID at wrong offset")
	}

	// Offset 23-30: PacketSeq
	if binary.BigEndian.Uint64(data[23:]) != 1 {
		t.Error("packetSeq at wrong offset")
	}

	// Offset 31-38: Timestamp
	if binary.BigEndian.Uint64(data[31:]) != 1700000000000 {
		t.Error("timestamp at wrong offset")
	}

	// Offset 39-54: SrcNodeID
	if data[39] != 0xAA || data[40] != 0xBB || data[41] != 0xCC {
		t.Error("srcNodeID at wrong offset")
	}

	// Offset 55-70: DstSvcID
	// (zeros by default)

	// Offset 71-74: PolicyTag
	if binary.BigEndian.Uint32(data[71:]) != 0x12345678 {
		t.Error("policyTag at wrong offset")
	}

	// Offset 75-76: ExtLen
	if binary.BigEndian.Uint16(data[75:]) != 0 {
		t.Error("extLen at wrong offset")
	}

	// Offset 77-78: PayloadLen
	if binary.BigEndian.Uint16(data[77:]) != 100 {
		t.Error("payloadLen at wrong offset")
	}

	// Offset 79-94: HeaderAuthTag (16 bytes)
	// (zeros by default)
	if len(data[79:]) != 16 {
		t.Error("headerAuthTag at wrong offset")
	}
}

// TestDataHeaderWireCompatibility verifies byte offsets match the Rust implementation.
func TestDataHeaderWireCompatibility(t *testing.T) {
	sid := SessionID{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	hdr := DataHeader{
		Version:   1,
		HdrLen:    11,
		Flags:     FlagRelayHop,
		SessionID: sid,
		PacketSeq: 42,
	}

	data := hdr.Serialize()

	// Offset 0-1: Magic
	if binary.BigEndian.Uint16(data[0:]) != 0x5A37 {
		t.Error("magic at wrong offset")
	}

	// Offset 2-3: Ver|HdrLen
	verHdrLen := binary.BigEndian.Uint16(data[2:])
	if verHdrLen&0x0FFF != 11 {
		t.Error("hdrLen at wrong offset")
	}

	// Offset 4-5: Flags
	if binary.BigEndian.Uint16(data[4:]) != FlagRelayHop {
		t.Error("flags at wrong offset")
	}

	// Offset 6-17: SessionID
	if !bytes.Equal(data[6:18], sid[:]) {
		t.Error("sessionID at wrong offset")
	}

	// Offset 18-25: PacketSeq
	if binary.BigEndian.Uint64(data[18:]) != 42 {
		t.Error("packetSeq at wrong offset")
	}

	// Offset 26-41: HeaderAuthTag (16 bytes)
	if len(data[26:]) != 16 {
		t.Error("headerAuthTag at wrong offset")
	}
}
