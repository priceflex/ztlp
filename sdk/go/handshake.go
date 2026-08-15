package ztlp

import (
	"fmt"

	"github.com/flynn/noise"
)

// HandshakeRole identifies the role of a peer in the Noise_XX handshake.
type HandshakeRole int

const (
	RoleInitiator HandshakeRole = iota
	RoleResponder
)

// String returns the role name.
func (r HandshakeRole) String() string {
	if r == RoleInitiator {
		return "Initiator"
	}
	return "Responder"
}

// noiseProtocol returns the noise.HandshakeConfig cipher suite for ZTLP.
// This corresponds to Noise_XX_25519_ChaChaPoly_BLAKE2s.
var noiseCipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// HandshakeContext manages an in-progress Noise_XX handshake.
type HandshakeContext struct {
	Identity       *Identity
	Role           HandshakeRole
	state          *noise.HandshakeState
	messageIndex   int
	sendCipher     *noise.CipherState // set by the final message of handshake
	recvCipher     *noise.CipherState // set by the final message of handshake
	peerStatic     []byte
}

// NewHandshakeInitiator creates a handshake context for the initiator.
func NewHandshakeInitiator(identity *Identity) (*HandshakeContext, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:  noiseCipherSuite,
		Pattern:      noise.HandshakeXX,
		Initiator:    true,
		StaticKeypair: noise.DHKey{Private: identity.StaticPrivateKey, Public: identity.StaticPublicKey},
	})
	if err != nil {
		return nil, fmt.Errorf("ztlp: init handshake initiator: %w", err)
	}

	return &HandshakeContext{
		Identity: identity,
		Role:     RoleInitiator,
		state:    hs,
	}, nil
}

// NewHandshakeResponder creates a handshake context for the responder.
func NewHandshakeResponder(identity *Identity) (*HandshakeContext, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:  noiseCipherSuite,
		Pattern:      noise.HandshakeXX,
		Initiator:    false,
		StaticKeypair: noise.DHKey{Private: identity.StaticPrivateKey, Public: identity.StaticPublicKey},
	})
	if err != nil {
		return nil, fmt.Errorf("ztlp: init handshake responder: %w", err)
	}

	return &HandshakeContext{
		Identity: identity,
		Role:     RoleResponder,
		state:    hs,
	}, nil
}

// WriteMessage generates the next handshake message (Noise payload).
// The payload parameter is the application data to encrypt within the handshake message.
func (h *HandshakeContext) WriteMessage(payload []byte) ([]byte, error) {
	msg, cs1, cs2, err := h.state.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("ztlp: write handshake message %d: %w", h.messageIndex, err)
	}
	// Capture cipher states if the handshake is complete
	if cs1 != nil && cs2 != nil {
		h.sendCipher = cs1
		h.recvCipher = cs2
	}
	h.messageIndex++
	return msg, nil
}

// ReadMessage processes a received handshake message.
// Returns the decrypted application payload.
func (h *HandshakeContext) ReadMessage(message []byte) ([]byte, error) {
	payload, cs1, cs2, err := h.state.ReadMessage(nil, message)
	if err != nil {
		return nil, fmt.Errorf("ztlp: read handshake message %d: %w", h.messageIndex, err)
	}
	// Capture cipher states if the handshake is complete
	if cs1 != nil && cs2 != nil {
		h.sendCipher = cs1
		h.recvCipher = cs2
	}
	h.messageIndex++
	return payload, nil
}

// MessageIndex returns which message we're on (0-indexed).
func (h *HandshakeContext) MessageIndex() int {
	return h.messageIndex
}

// PeerStatic returns the peer's static public key (available after message 2 for initiator,
// after message 3 for responder).
func (h *HandshakeContext) PeerStatic() []byte {
	return h.state.PeerStatic()
}

// Finalize completes the handshake and derives session keys using the standard
// Noise Split. The send and receive keys are taken from the CipherState keys
// produced by the noise library's Split() method, which uses HKDF with the
// cipher suite's native hash function (BLAKE2s) over the handshake chain key.
// This replaces the previous custom BLAKE2s key derivation that was not
// consistent with the Noise Protocol Framework.
func (h *HandshakeContext) Finalize(peerNodeID NodeID, sessionID SessionID) (*SessionState, error) {
	if h.sendCipher == nil || h.recvCipher == nil {
		return nil, fmt.Errorf("%w: handshake not yet complete (need 3 messages for Noise_XX)", ErrHandshakeFailed)
	}

	peerStatic := h.state.PeerStatic()
	if len(peerStatic) == 0 {
		return nil, fmt.Errorf("%w: no peer static key available", ErrHandshakeFailed)
	}

	// Export keys from Noise CipherStates (standard Noise Split)
	// The noise library's Split() already performed the correct key derivation:
	//   - hkdf(cs.Hash, 2, ck, nil, nil, ck, nil) → (hk1, hk2)
	//   - cs1 key = hk1 (initiator send, responder recv)
	//   - cs2 key = hk2 (initiator recv, responder send)
	// This matches the Noise Protocol Framework specification for XX pattern.
	var sendKey, recvKey [32]byte

	switch h.Role {
	case RoleInitiator:
		sendKey = h.sendCipher.UnsafeKey()
		recvKey = h.recvCipher.UnsafeKey()
	case RoleResponder:
		// For the responder, cs1 is recv and cs2 is send
		sendKey = h.recvCipher.UnsafeKey()
		recvKey = h.sendCipher.UnsafeKey()
	}

	session := NewSessionState(sessionID, peerNodeID, sendKey, recvKey, false)
	return session, nil
}

// BuildHandshakePacket builds a complete ZTLP handshake packet wrapping a Noise message.
func BuildHandshakePacket(
	msgType MsgType,
	srcNodeID NodeID,
	dstSvcID [16]byte,
	sessionID SessionID,
	packetSeq uint64,
	noisePayload []byte,
	authKey *[32]byte,
) []byte {
	hdr := NewHandshakeHeader(msgType)
	hdr.SessionID = sessionID
	hdr.PacketSeq = packetSeq
	hdr.SrcNodeID = srcNodeID
	hdr.DstSvcID = dstSvcID
	hdr.PayloadLen = uint16(len(noisePayload))

	if authKey != nil {
		aad := hdr.AADBytes()
		hdr.HeaderAuthTag = ComputeHeaderAuthTag(authKey, aad)
	}

	buf := hdr.Serialize()
	buf = append(buf, noisePayload...)
	return buf
}

// HandshakeResult holds the session states for both sides after a completed handshake.
type HandshakeResult struct {
	InitiatorSession *SessionState
	ResponderSession *SessionState
}

// PerformHandshake performs a complete Noise_XX handshake in-process (no network).
// Useful for testing. Returns session states for both sides.
func PerformHandshake(initiator, responder *Identity) (*HandshakeResult, error) {
	initCtx, err := NewHandshakeInitiator(initiator)
	if err != nil {
		return nil, err
	}
	respCtx, err := NewHandshakeResponder(responder)
	if err != nil {
		return nil, err
	}

	// Message 1: Initiator → Responder (ephemeral key)
	msg1, err := initCtx.WriteMessage(nil)
	if err != nil {
		return nil, fmt.Errorf("ztlp: handshake msg1: %w", err)
	}
	if _, err := respCtx.ReadMessage(msg1); err != nil {
		return nil, fmt.Errorf("ztlp: handshake read msg1: %w", err)
	}

	// Message 2: Responder → Initiator (ephemeral + static + identity)
	msg2, err := respCtx.WriteMessage(nil)
	if err != nil {
		return nil, fmt.Errorf("ztlp: handshake msg2: %w", err)
	}
	if _, err := initCtx.ReadMessage(msg2); err != nil {
		return nil, fmt.Errorf("ztlp: handshake read msg2: %w", err)
	}

	// Message 3: Initiator → Responder (static + identity)
	msg3, err := initCtx.WriteMessage(nil)
	if err != nil {
		return nil, fmt.Errorf("ztlp: handshake msg3: %w", err)
	}
	if _, err := respCtx.ReadMessage(msg3); err != nil {
		return nil, fmt.Errorf("ztlp: handshake read msg3: %w", err)
	}

	// Shared SessionID (in real usage, responder assigns in HELLO_ACK)
	sessionID, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}

	initSession, err := initCtx.Finalize(responder.NodeID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("ztlp: finalize initiator: %w", err)
	}

	respSession, err := respCtx.Finalize(initiator.NodeID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("ztlp: finalize responder: %w", err)
	}

	return &HandshakeResult{
		InitiatorSession: initSession,
		ResponderSession: respSession,
	}, nil
}
