package ztlp

import (
	"bytes"
	"fmt"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
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
	Identity     *Identity
	Role         HandshakeRole
	state        *noise.HandshakeState
	messageIndex int
}

// NewHandshakeInitiator creates a handshake context for the initiator.
func NewHandshakeInitiator(identity *Identity) (*HandshakeContext, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseCipherSuite,
		Pattern:        noise.HandshakeXX,
		Initiator:      true,
		StaticKeypair:  noise.DHKey{Private: identity.StaticPrivateKey, Public: identity.StaticPublicKey},
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
		CipherSuite:   noiseCipherSuite,
		Pattern:        noise.HandshakeXX,
		Initiator:      false,
		StaticKeypair:  noise.DHKey{Private: identity.StaticPrivateKey, Public: identity.StaticPublicKey},
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
	msg, _, _, err := h.state.WriteMessage(nil, payload)
	if err != nil {
		return nil, fmt.Errorf("ztlp: write handshake message %d: %w", h.messageIndex, err)
	}
	h.messageIndex++
	return msg, nil
}

// ReadMessage processes a received handshake message.
// Returns the decrypted application payload.
func (h *HandshakeContext) ReadMessage(message []byte) ([]byte, error) {
	payload, _, _, err := h.state.ReadMessage(nil, message)
	if err != nil {
		return nil, fmt.Errorf("ztlp: read handshake message %d: %w", h.messageIndex, err)
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

// Finalize completes the handshake and derives session keys.
//
// Key derivation matches the Rust implementation exactly:
//   - Sort both static public keys lexicographically
//   - Hash(sorted_keys || direction_label || session_id) using BLAKE2s-256
//   - Initiator sends with i2r key, receives with r2i key
//   - Responder sends with r2i key, receives with i2r key
func (h *HandshakeContext) Finalize(peerNodeID NodeID, sessionID SessionID) (*SessionState, error) {
	peerStatic := h.state.PeerStatic()
	if len(peerStatic) == 0 {
		return nil, fmt.Errorf("%w: no peer static key available", ErrHandshakeFailed)
	}

	ourPublic := h.Identity.StaticPublicKey

	// Sort keys lexicographically (same as Rust)
	var sharedMaterial []byte
	if bytes.Compare(ourPublic, peerStatic) <= 0 {
		sharedMaterial = append(sharedMaterial, ourPublic...)
		sharedMaterial = append(sharedMaterial, peerStatic...)
	} else {
		sharedMaterial = append(sharedMaterial, peerStatic...)
		sharedMaterial = append(sharedMaterial, ourPublic...)
	}

	// Derive directional keys using BLAKE2s-256
	deriveKey := func(label string, sid SessionID, base []byte) [32]byte {
		h, _ := blake2s.New256(nil)
		h.Write(base)
		h.Write([]byte(label))
		h.Write(sid[:])
		var key [32]byte
		copy(key[:], h.Sum(nil))
		return key
	}

	i2rKey := deriveKey("ztlp_initiator_to_responder", sessionID, sharedMaterial)
	r2iKey := deriveKey("ztlp_responder_to_initiator", sessionID, sharedMaterial)

	var sendKey, recvKey [32]byte
	switch h.Role {
	case RoleInitiator:
		sendKey = i2rKey
		recvKey = r2iKey
	case RoleResponder:
		sendKey = r2iKey
		recvKey = i2rKey
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
