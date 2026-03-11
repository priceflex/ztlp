package ztlp

import (
	"testing"
)

func TestPerformHandshake(t *testing.T) {
	initiator, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity (initiator): %v", err)
	}
	responder, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity (responder): %v", err)
	}

	result, err := PerformHandshake(initiator, responder)
	if err != nil {
		t.Fatalf("PerformHandshake: %v", err)
	}

	// Both sessions should have the same SessionID
	if result.InitiatorSession.SessionID != result.ResponderSession.SessionID {
		t.Error("SessionIDs should match")
	}

	// Peer NodeIDs should be correct
	if result.InitiatorSession.PeerNodeID != responder.NodeID {
		t.Error("initiator's peer should be responder")
	}
	if result.ResponderSession.PeerNodeID != initiator.NodeID {
		t.Error("responder's peer should be initiator")
	}

	// Directional keys: initiator's send should equal responder's recv
	if result.InitiatorSession.SendKey != result.ResponderSession.RecvKey {
		t.Error("initiator send key should match responder recv key")
	}
	if result.InitiatorSession.RecvKey != result.ResponderSession.SendKey {
		t.Error("initiator recv key should match responder send key")
	}

	// Send and recv keys should be different from each other
	if result.InitiatorSession.SendKey == result.InitiatorSession.RecvKey {
		t.Error("send and recv keys should differ")
	}
}

func TestHandshakeKeyDerivation(t *testing.T) {
	// Perform two handshakes with the same identities — keys should differ
	// (because SessionIDs are random)
	init, _ := GenerateIdentity()
	resp, _ := GenerateIdentity()

	r1, err := PerformHandshake(init, resp)
	if err != nil {
		t.Fatalf("handshake 1: %v", err)
	}
	r2, err := PerformHandshake(init, resp)
	if err != nil {
		t.Fatalf("handshake 2: %v", err)
	}

	// Different SessionIDs
	if r1.InitiatorSession.SessionID == r2.InitiatorSession.SessionID {
		t.Error("different handshakes should produce different SessionIDs")
	}

	// Different keys (because different SessionIDs factor into derivation)
	if r1.InitiatorSession.SendKey == r2.InitiatorSession.SendKey {
		t.Error("different handshakes should produce different send keys")
	}
}

func TestHandshakeMessageExchange(t *testing.T) {
	init, _ := GenerateIdentity()
	resp, _ := GenerateIdentity()

	initCtx, err := NewHandshakeInitiator(init)
	if err != nil {
		t.Fatalf("NewHandshakeInitiator: %v", err)
	}
	respCtx, err := NewHandshakeResponder(resp)
	if err != nil {
		t.Fatalf("NewHandshakeResponder: %v", err)
	}

	// Message 1
	msg1, err := initCtx.WriteMessage(nil)
	if err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	if len(msg1) == 0 {
		t.Error("msg1 should not be empty")
	}

	_, err = respCtx.ReadMessage(msg1)
	if err != nil {
		t.Fatalf("read msg1: %v", err)
	}

	// Message 2
	msg2, err := respCtx.WriteMessage(nil)
	if err != nil {
		t.Fatalf("write msg2: %v", err)
	}

	_, err = initCtx.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("read msg2: %v", err)
	}

	// After message 2, initiator should know peer's static key
	peerStatic := initCtx.PeerStatic()
	if len(peerStatic) != 32 {
		t.Errorf("peer static key length: %d, want 32", len(peerStatic))
	}

	// Message 3
	msg3, err := initCtx.WriteMessage(nil)
	if err != nil {
		t.Fatalf("write msg3: %v", err)
	}

	_, err = respCtx.ReadMessage(msg3)
	if err != nil {
		t.Fatalf("read msg3: %v", err)
	}

	// After message 3, responder should know peer's static key
	peerStatic = respCtx.PeerStatic()
	if len(peerStatic) != 32 {
		t.Errorf("responder peer static key length: %d, want 32", len(peerStatic))
	}

	if initCtx.MessageIndex() != 3 {
		t.Errorf("initiator message index: %d, want 3", initCtx.MessageIndex())
	}
	if respCtx.MessageIndex() != 3 {
		t.Errorf("responder message index: %d, want 3", respCtx.MessageIndex())
	}
}

func TestHandshakeWithPayload(t *testing.T) {
	init, _ := GenerateIdentity()
	resp, _ := GenerateIdentity()

	initCtx, _ := NewHandshakeInitiator(init)
	respCtx, _ := NewHandshakeResponder(resp)

	// Message 1 with payload
	msg1, err := initCtx.WriteMessage([]byte("hello from initiator"))
	if err != nil {
		t.Fatalf("write msg1: %v", err)
	}

	payload1, err := respCtx.ReadMessage(msg1)
	if err != nil {
		t.Fatalf("read msg1: %v", err)
	}
	// Noise_XX message 1 doesn't encrypt payload (it's in the clear)
	if string(payload1) != "hello from initiator" {
		t.Errorf("payload1: %q, want %q", payload1, "hello from initiator")
	}

	// Message 2 with payload (encrypted)
	msg2, err := respCtx.WriteMessage([]byte("hello from responder"))
	if err != nil {
		t.Fatalf("write msg2: %v", err)
	}

	payload2, err := initCtx.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("read msg2: %v", err)
	}
	if string(payload2) != "hello from responder" {
		t.Errorf("payload2: %q, want %q", payload2, "hello from responder")
	}

	// Complete message 3
	msg3, _ := initCtx.WriteMessage(nil)
	respCtx.ReadMessage(msg3)
}

func TestBuildHandshakePacket(t *testing.T) {
	srcNodeID := NodeID{0xAA, 0xBB}
	dstSvcID := [16]byte{0xCC, 0xDD}
	sid := SessionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	noisePayload := []byte("test noise payload")

	// Without auth key
	pkt := BuildHandshakePacket(MsgTypeHello, srcNodeID, dstSvcID, sid, 0, noisePayload, nil)
	if len(pkt) != HandshakeHeaderSize+len(noisePayload) {
		t.Errorf("packet size: %d, want %d", len(pkt), HandshakeHeaderSize+len(noisePayload))
	}

	// Parse header back
	hdr, err := ParseHandshakeHeader(pkt)
	if err != nil {
		t.Fatalf("ParseHandshakeHeader: %v", err)
	}
	if hdr.MsgType != MsgTypeHello {
		t.Errorf("msgType: %v, want Hello", hdr.MsgType)
	}
	if hdr.SessionID != sid {
		t.Error("sessionID mismatch")
	}
	if hdr.PayloadLen != uint16(len(noisePayload)) {
		t.Errorf("payloadLen: %d, want %d", hdr.PayloadLen, len(noisePayload))
	}

	// Payload follows header
	payload := pkt[HandshakeHeaderSize:]
	if string(payload) != "test noise payload" {
		t.Errorf("payload: %q, want %q", payload, "test noise payload")
	}

	// With auth key
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	pkt2 := BuildHandshakePacket(MsgTypeHelloAck, srcNodeID, dstSvcID, sid, 1, noisePayload, &key)
	hdr2, _ := ParseHandshakeHeader(pkt2)

	// Auth tag should not be all zeros
	allZero := true
	for _, b := range hdr2.HeaderAuthTag {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("auth tag should not be all zeros when key is provided")
	}
}

func TestHandshakeCrossVerifyEncryption(t *testing.T) {
	// Full end-to-end: handshake, then encrypt/decrypt a message
	init, _ := GenerateIdentity()
	resp, _ := GenerateIdentity()

	result, err := PerformHandshake(init, resp)
	if err != nil {
		t.Fatalf("PerformHandshake: %v", err)
	}

	// Build a data packet from initiator to responder
	is := result.InitiatorSession
	rs := result.ResponderSession

	seq := is.NextSendSeq()
	hdr := NewDataHeader(is.SessionID, seq)
	aad := hdr.AADBytes()
	hdr.HeaderAuthTag = ComputeHeaderAuthTag(&is.SendKey, aad)

	// Verify responder can validate the auth tag
	data := hdr.Serialize()
	respAAD := data[:DataHeaderSize-AuthTagSize]
	respTag := data[DataHeaderSize-AuthTagSize : DataHeaderSize]

	if !VerifyHeaderAuthTag(&rs.RecvKey, respAAD, respTag) {
		t.Error("responder should verify initiator's auth tag")
	}
}

func TestHandshakeRole(t *testing.T) {
	if RoleInitiator.String() != "Initiator" {
		t.Errorf("got %q", RoleInitiator.String())
	}
	if RoleResponder.String() != "Responder" {
		t.Errorf("got %q", RoleResponder.String())
	}
}
