package ztlp

import (
	"encoding/binary"
	"testing"
)

func TestComputeAndVerifyAuthTag(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	aad := []byte("some header aad bytes")

	tag := ComputeHeaderAuthTag(&key, aad)

	// Tag should not be zero
	allZero := true
	for _, b := range tag {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("auth tag should not be all zeros")
	}

	// Verify should succeed with correct key and AAD
	if !VerifyHeaderAuthTag(&key, aad, tag[:]) {
		t.Error("verification should succeed with correct key and AAD")
	}

	// Verify should fail with wrong key
	wrongKey := [32]byte{0xFF}
	if VerifyHeaderAuthTag(&wrongKey, aad, tag[:]) {
		t.Error("verification should fail with wrong key")
	}

	// Verify should fail with wrong AAD
	if VerifyHeaderAuthTag(&key, []byte("wrong aad"), tag[:]) {
		t.Error("verification should fail with wrong AAD")
	}

	// Verify should fail with tampered tag
	tampered := make([]byte, AuthTagSize)
	copy(tampered, tag[:])
	tampered[0] ^= 0xFF
	if VerifyHeaderAuthTag(&key, aad, tampered) {
		t.Error("verification should fail with tampered tag")
	}
}

func TestComputeAuthTagDeterministic(t *testing.T) {
	key := [32]byte{0xAA}
	aad := []byte("deterministic test")

	tag1 := ComputeHeaderAuthTag(&key, aad)
	tag2 := ComputeHeaderAuthTag(&key, aad)

	if tag1 != tag2 {
		t.Error("same inputs should produce same tag")
	}
}

func TestLayer1MagicCheck(t *testing.T) {
	p := NewPipeline()

	// Valid magic
	validPacket := make([]byte, 4)
	binary.BigEndian.PutUint16(validPacket, Magic)
	if r := p.Layer1MagicCheck(validPacket); r != AdmissionPass {
		t.Errorf("valid magic: got %v, want Pass", r)
	}

	// Invalid magic
	invalidPacket := []byte{0xFF, 0xFF, 0x00, 0x00}
	if r := p.Layer1MagicCheck(invalidPacket); r != AdmissionDrop {
		t.Errorf("invalid magic: got %v, want Drop", r)
	}

	// Too short
	if r := p.Layer1MagicCheck([]byte{0x5A}); r != AdmissionDrop {
		t.Errorf("too short: got %v, want Drop", r)
	}

	// Empty
	if r := p.Layer1MagicCheck(nil); r != AdmissionDrop {
		t.Errorf("nil: got %v, want Drop", r)
	}
}

func TestLayer2SessionCheck(t *testing.T) {
	p := NewPipeline()

	// Register a session
	sid := SessionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
	session := NewSessionState(sid, NodeID{}, [32]byte{}, [32]byte{}, false)
	p.RegisterSession(session)

	// Handshake HELLO should pass (any SessionID)
	helloHdr := NewHandshakeHeader(MsgTypeHello)
	helloData := helloHdr.Serialize()
	if r := p.Layer2SessionCheck(helloData); r != AdmissionPass {
		t.Errorf("HELLO: got %v, want Pass", r)
	}

	// Handshake HELLO_ACK should pass
	helloAckHdr := NewHandshakeHeader(MsgTypeHelloAck)
	helloAckData := helloAckHdr.Serialize()
	if r := p.Layer2SessionCheck(helloAckData); r != AdmissionPass {
		t.Errorf("HELLO_ACK: got %v, want Pass", r)
	}

	// Data packet with known SessionID should pass
	dataHdr := NewDataHeader(sid, 0)
	dataData := dataHdr.Serialize()
	if r := p.Layer2SessionCheck(dataData); r != AdmissionPass {
		t.Errorf("known session data: got %v, want Pass", r)
	}

	// Data packet with unknown SessionID should be dropped
	unknownSID := SessionID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	unknownDataHdr := NewDataHeader(unknownSID, 0)
	unknownData := unknownDataHdr.Serialize()
	if r := p.Layer2SessionCheck(unknownData); r != AdmissionDrop {
		t.Errorf("unknown session data: got %v, want Drop", r)
	}

	// Handshake with known session and non-HELLO type should pass
	rekeyHdr := NewHandshakeHeader(MsgTypeRekey)
	rekeyHdr.SessionID = sid
	rekeyData := rekeyHdr.Serialize()
	if r := p.Layer2SessionCheck(rekeyData); r != AdmissionPass {
		t.Errorf("known session rekey: got %v, want Pass", r)
	}

	// Handshake with unknown session and non-HELLO type should drop
	rekeyHdr2 := NewHandshakeHeader(MsgTypeRekey)
	rekeyHdr2.SessionID = unknownSID
	rekeyData2 := rekeyHdr2.Serialize()
	if r := p.Layer2SessionCheck(rekeyData2); r != AdmissionDrop {
		t.Errorf("unknown session rekey: got %v, want Drop", r)
	}
}

func TestLayer3AuthCheck(t *testing.T) {
	p := NewPipeline()

	// Set up a session with known keys
	sid := SessionID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
	sendKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	recvKey := sendKey // For simplicity, same key both directions
	session := NewSessionState(sid, NodeID{}, sendKey, recvKey, false)
	p.RegisterSession(session)

	// HELLO should pass without auth check
	helloHdr := NewHandshakeHeader(MsgTypeHello)
	helloData := helloHdr.Serialize()
	if r := p.Layer3AuthCheck(helloData); r != AdmissionPass {
		t.Errorf("HELLO: got %v, want Pass", r)
	}

	// Data packet with valid auth tag should pass
	dataHdr := NewDataHeader(sid, 42)
	aad := dataHdr.AADBytes()
	dataHdr.HeaderAuthTag = ComputeHeaderAuthTag(&sendKey, aad)
	dataData := dataHdr.Serialize()
	if r := p.Layer3AuthCheck(dataData); r != AdmissionPass {
		t.Errorf("valid auth tag: got %v, want Pass", r)
	}

	// Data packet with invalid auth tag should drop
	badHdr := NewDataHeader(sid, 43)
	badHdr.HeaderAuthTag = [AuthTagSize]byte{0xDE, 0xAD}
	badData := badHdr.Serialize()
	if r := p.Layer3AuthCheck(badData); r != AdmissionDrop {
		t.Errorf("invalid auth tag: got %v, want Drop", r)
	}
}

func TestPipelineProcess(t *testing.T) {
	p := NewPipeline()

	// Non-ZTLP packet should be dropped at Layer 1
	if r := p.Process([]byte{0x00, 0x00, 0x00, 0x00}); r != AdmissionDrop {
		t.Errorf("bad magic: got %v, want Drop", r)
	}
	snap := p.Counters.Snapshot()
	if snap.Layer1Drops != 1 {
		t.Errorf("layer1 drops: %d, want 1", snap.Layer1Drops)
	}

	// HELLO should pass all layers (no session required, no auth check)
	helloHdr := NewHandshakeHeader(MsgTypeHello)
	helloData := helloHdr.Serialize()
	if r := p.Process(helloData); r != AdmissionPass {
		t.Errorf("HELLO: got %v, want Pass", r)
	}
	snap = p.Counters.Snapshot()
	if snap.Passed != 1 {
		t.Errorf("passed: %d, want 1", snap.Passed)
	}

	// Data with unknown session should be dropped at Layer 2
	unknownDataHdr := NewDataHeader(SessionID{0xFF}, 0)
	unknownData := unknownDataHdr.Serialize()
	if r := p.Process(unknownData); r != AdmissionDrop {
		t.Errorf("unknown session: got %v, want Drop", r)
	}
	snap = p.Counters.Snapshot()
	if snap.Layer2Drops != 1 {
		t.Errorf("layer2 drops: %d, want 1", snap.Layer2Drops)
	}
}

func TestPipelineRegisterRemove(t *testing.T) {
	p := NewPipeline()
	sid := SessionID{1, 2, 3}
	session := NewSessionState(sid, NodeID{}, [32]byte{}, [32]byte{}, false)

	// Register
	p.RegisterSession(session)
	if s := p.GetSession(sid); s == nil {
		t.Error("session should be registered")
	}

	// Remove
	p.RemoveSession(sid)
	if s := p.GetSession(sid); s != nil {
		t.Error("session should be removed")
	}
}

func TestAdmissionResultString(t *testing.T) {
	tests := []struct {
		r    AdmissionResult
		want string
	}{
		{AdmissionPass, "Pass"},
		{AdmissionDrop, "Drop"},
		{AdmissionRateLimit, "RateLimit"},
		{AdmissionResult(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}
