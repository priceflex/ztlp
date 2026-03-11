package ztlp

import (
	"encoding/binary"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// AdmissionResult represents the outcome of a pipeline admission check.
type AdmissionResult int

const (
	// AdmissionPass means the packet passed this layer.
	AdmissionPass AdmissionResult = iota
	// AdmissionDrop means the packet should be silently dropped.
	AdmissionDrop
	// AdmissionRateLimit means the packet should be rate-limited.
	AdmissionRateLimit
)

// String returns a human-readable admission result.
func (a AdmissionResult) String() string {
	switch a {
	case AdmissionPass:
		return "Pass"
	case AdmissionDrop:
		return "Drop"
	case AdmissionRateLimit:
		return "RateLimit"
	default:
		return "Unknown"
	}
}

// PipelineCounters tracks per-layer drop/pass statistics.
type PipelineCounters struct {
	Layer1Drops atomic.Uint64
	Layer2Drops atomic.Uint64
	Layer3Drops atomic.Uint64
	Passed      atomic.Uint64
}

// Snapshot returns an immutable copy of the current counter values.
func (c *PipelineCounters) Snapshot() PipelineSnapshot {
	return PipelineSnapshot{
		Layer1Drops: c.Layer1Drops.Load(),
		Layer2Drops: c.Layer2Drops.Load(),
		Layer3Drops: c.Layer3Drops.Load(),
		Passed:      c.Passed.Load(),
	}
}

// PipelineSnapshot is an immutable snapshot of pipeline counters.
type PipelineSnapshot struct {
	Layer1Drops uint64
	Layer2Drops uint64
	Layer3Drops uint64
	Passed      uint64
}

// Pipeline implements the three-layer ZTLP admission pipeline.
//
// Layer 1: Magic byte check (nanoseconds, no crypto)
// Layer 2: SessionID lookup (microseconds, no crypto)
// Layer 3: HeaderAuthTag verification (real crypto cost)
type Pipeline struct {
	mu       sync.RWMutex
	sessions map[SessionID]*SessionState
	Counters PipelineCounters
}

// NewPipeline creates a new empty admission pipeline.
func NewPipeline() *Pipeline {
	return &Pipeline{
		sessions: make(map[SessionID]*SessionState),
	}
}

// RegisterSession adds a session to the pipeline's session table.
func (p *Pipeline) RegisterSession(session *SessionState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessions[session.SessionID] = session
}

// RemoveSession removes a session from the pipeline.
func (p *Pipeline) RemoveSession(sessionID SessionID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.sessions, sessionID)
}

// GetSession returns a session by ID, or nil if not found.
func (p *Pipeline) GetSession(sessionID SessionID) *SessionState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.sessions[sessionID]
}

// Layer1MagicCheck performs the magic byte check.
// Cost: single 16-bit comparison, nanoseconds, no crypto.
func (p *Pipeline) Layer1MagicCheck(data []byte) AdmissionResult {
	if len(data) < 2 {
		return AdmissionDrop
	}
	magic := binary.BigEndian.Uint16(data[0:2])
	if magic != Magic {
		return AdmissionDrop
	}
	return AdmissionPass
}

// Layer2SessionCheck performs the SessionID lookup.
// Cost: O(1) map lookup, microseconds, no crypto.
// Allows HELLO messages through (they establish sessions).
func (p *Pipeline) Layer2SessionCheck(data []byte) AdmissionResult {
	if len(data) < 4 {
		return AdmissionDrop
	}

	// Extract HdrLen
	verHdrLen := binary.BigEndian.Uint16(data[2:4])
	hdrLen := verHdrLen & 0x0FFF
	isHandshake := hdrLen == HandshakeHdrLen

	p.mu.RLock()
	defer p.mu.RUnlock()

	if isHandshake {
		if len(data) < HandshakeHeaderSize {
			return AdmissionDrop
		}
		// MsgType at byte 6
		msgType := data[6]
		if msgType == uint8(MsgTypeHello) || msgType == uint8(MsgTypeHelloAck) {
			return AdmissionPass
		}
		// SessionID at bytes 11..23
		var sid SessionID
		copy(sid[:], data[11:23])
		if _, ok := p.sessions[sid]; ok {
			return AdmissionPass
		}
		return AdmissionDrop
	}

	// Data header: SessionID at bytes 6..18
	if len(data) < DataHeaderSize {
		return AdmissionDrop
	}
	var sid SessionID
	copy(sid[:], data[6:18])
	if _, ok := p.sessions[sid]; ok {
		return AdmissionPass
	}
	return AdmissionDrop
}

// Layer3AuthCheck performs the HeaderAuthTag verification.
// Cost: real cryptographic work (ChaCha20-Poly1305 AEAD).
func (p *Pipeline) Layer3AuthCheck(data []byte) AdmissionResult {
	if len(data) < 4 {
		return AdmissionDrop
	}

	verHdrLen := binary.BigEndian.Uint16(data[2:4])
	hdrLen := verHdrLen & 0x0FFF
	isHandshake := hdrLen == HandshakeHdrLen

	p.mu.RLock()
	defer p.mu.RUnlock()

	if isHandshake {
		if len(data) < HandshakeHeaderSize {
			return AdmissionDrop
		}
		// Initial HELLO has no session keys yet — skip auth check
		msgType := data[6]
		if msgType == uint8(MsgTypeHello) {
			return AdmissionPass
		}

		var sid SessionID
		copy(sid[:], data[11:23])
		session, ok := p.sessions[sid]
		if !ok {
			return AdmissionDrop
		}

		aad := data[:HandshakeHeaderSize-AuthTagSize]
		authTag := data[HandshakeHeaderSize-AuthTagSize : HandshakeHeaderSize]
		if VerifyHeaderAuthTag(&session.RecvKey, aad, authTag) {
			return AdmissionPass
		}
		return AdmissionDrop
	}

	// Data packet
	if len(data) < DataHeaderSize {
		return AdmissionDrop
	}

	var sid SessionID
	copy(sid[:], data[6:18])
	session, ok := p.sessions[sid]
	if !ok {
		return AdmissionDrop
	}

	aad := data[:DataHeaderSize-AuthTagSize]
	authTag := data[DataHeaderSize-AuthTagSize : DataHeaderSize]
	if VerifyHeaderAuthTag(&session.RecvKey, aad, authTag) {
		return AdmissionPass
	}
	return AdmissionDrop
}

// Process runs all three pipeline layers on a raw packet.
func (p *Pipeline) Process(data []byte) AdmissionResult {
	// Layer 1: Magic check
	if r := p.Layer1MagicCheck(data); r != AdmissionPass {
		p.Counters.Layer1Drops.Add(1)
		return r
	}

	// Layer 2: SessionID lookup
	if r := p.Layer2SessionCheck(data); r != AdmissionPass {
		p.Counters.Layer2Drops.Add(1)
		return r
	}

	// Layer 3: HeaderAuthTag verification
	if r := p.Layer3AuthCheck(data); r != AdmissionPass {
		p.Counters.Layer3Drops.Add(1)
		return r
	}

	p.Counters.Passed.Add(1)
	return AdmissionPass
}

// ComputeHeaderAuthTag computes an AEAD tag over header AAD bytes.
// Uses ChaCha20-Poly1305 with a zero nonce in MAC-only mode (empty plaintext).
// This matches the Rust compute_header_auth_tag function.
func ComputeHeaderAuthTag(key *[32]byte, aad []byte) [AuthTagSize]byte {
	var tag [AuthTagSize]byte
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return tag
	}
	// Zero nonce (96 bits = 12 bytes)
	nonce := make([]byte, chacha20poly1305.NonceSize)
	// Encrypt empty plaintext with AAD — the "ciphertext" is just the tag
	ct := aead.Seal(nil, nonce, nil, aad)
	if len(ct) >= AuthTagSize {
		copy(tag[:], ct[:AuthTagSize])
	}
	return tag
}

// VerifyHeaderAuthTag verifies a header auth tag against the AAD bytes.
func VerifyHeaderAuthTag(key *[32]byte, aad, tag []byte) bool {
	if len(tag) != AuthTagSize {
		return false
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return false
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	// The "ciphertext" to decrypt is the tag itself (empty plaintext was encrypted)
	_, err = aead.Open(nil, nonce, tag, aad)
	return err == nil
}
