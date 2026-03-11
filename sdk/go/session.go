package ztlp

import (
	"sync"
)

// Default anti-replay window sizes.
const (
	DefaultReplayWindow   uint64 = 64
	MultipathReplayWindow uint64 = 1024
)

// ReplayWindow tracks which packet sequence numbers have been seen
// to prevent replay attacks. Uses a 64-bit bitmap sliding window.
type ReplayWindow struct {
	mu         sync.Mutex
	highestSeq uint64
	bitmap     uint64
	windowSize uint64
	// initialized tracks whether we've received the first packet.
	initialized bool
}

// NewReplayWindow creates a new anti-replay window.
func NewReplayWindow(windowSize uint64) *ReplayWindow {
	if windowSize > 64 {
		windowSize = 64 // bitmap is uint64, max 64 bits
	}
	return &ReplayWindow{
		windowSize: windowSize,
	}
}

// CheckAndRecord checks if a packet sequence number is valid (not replayed)
// and records it. Returns true if the packet is fresh, false if it's a replay.
//
// This implementation matches the Rust ReplayWindow::check_and_record exactly.
func (w *ReplayWindow) CheckAndRecord(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Sequence 0 is the first packet — always accept on first use
	if seq == 0 {
		if !w.initialized {
			w.highestSeq = 0
			w.bitmap = 1
			w.initialized = true
			return true
		}
	}

	if seq > w.highestSeq {
		// New packet ahead of the window — shift bitmap
		shift := seq - w.highestSeq
		if shift >= 64 {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.bitmap |= 1
		w.highestSeq = seq
		w.initialized = true
		return true
	}

	// Packet is within or behind the window
	diff := w.highestSeq - seq
	if diff >= w.windowSize {
		return false // Too old
	}
	if diff >= 64 {
		return false // Outside bitmap range
	}

	mask := uint64(1) << diff
	if w.bitmap&mask != 0 {
		return false // Already seen — replay
	}

	// New packet within window — record it
	w.bitmap |= mask
	return true
}

// SessionState represents an established ZTLP session between two nodes.
type SessionState struct {
	// SessionID is the 96-bit session identifier.
	SessionID SessionID

	// PeerNodeID is the remote peer's NodeID.
	PeerNodeID NodeID

	// SendKey is the 32-byte key for encrypting outbound packets.
	SendKey [32]byte

	// RecvKey is the 32-byte key for decrypting/verifying inbound packets.
	RecvKey [32]byte

	// sendSeq is the next outbound packet sequence number (atomic via mutex).
	sendSeq uint64
	seqMu   sync.Mutex

	// ReplayWindow protects against replay attacks on inbound packets.
	ReplayWindow *ReplayWindow

	// Multipath indicates if this session uses multipath.
	Multipath bool
}

// NewSessionState creates a new session state after handshake completion.
func NewSessionState(
	sessionID SessionID,
	peerNodeID NodeID,
	sendKey, recvKey [32]byte,
	multipath bool,
) *SessionState {
	windowSize := DefaultReplayWindow
	if multipath {
		windowSize = MultipathReplayWindow
	}
	return &SessionState{
		SessionID:    sessionID,
		PeerNodeID:   peerNodeID,
		SendKey:      sendKey,
		RecvKey:      recvKey,
		ReplayWindow: NewReplayWindow(windowSize),
		Multipath:    multipath,
	}
}

// NextSendSeq returns and increments the send sequence number.
func (s *SessionState) NextSendSeq() uint64 {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	seq := s.sendSeq
	s.sendSeq++
	return seq
}

// CheckReplay checks a received packet's sequence number against the replay window.
func (s *SessionState) CheckReplay(seq uint64) bool {
	return s.ReplayWindow.CheckAndRecord(seq)
}
