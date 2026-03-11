package ztlp

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/blake2s"
)

// RAT (Relay Admission Token) constants matching the Rust implementation.
const (
	// RATVersion is the current token version byte.
	RATVersion uint8 = 0x01

	// RATSize is the total token size in bytes.
	RATSize = 93

	// RATDataSize is the data portion size (before MAC).
	RATDataSize = 61

	// RATMACSize is the HMAC-BLAKE2s MAC size.
	RATMACSize = 32

	// blake2sBlockSize is the BLAKE2s block size for HMAC construction.
	blake2sBlockSize = 64

	// DefaultTTLSeconds is the default token TTL.
	DefaultTTLSeconds = 300

	// ExtTypeRAT is the handshake extension type for RAT.
	ExtTypeRAT uint8 = 0x01
)

// RelayAdmissionToken is a parsed Relay Admission Token.
//
// Token structure (93 bytes):
//
//	Version:       1 byte  (0x01)
//	NodeID:       16 bytes (authenticated node)
//	IssuerID:     16 bytes (issuing relay's NodeID)
//	IssuedAt:      8 bytes (Unix timestamp seconds, big-endian)
//	ExpiresAt:     8 bytes (Unix timestamp seconds, big-endian)
//	SessionScope: 12 bytes (SessionID scope, or all-zeros for any)
//	MAC:          32 bytes (HMAC-BLAKE2s over all preceding fields)
type RelayAdmissionToken struct {
	Version      uint8
	NodeID       [16]byte
	IssuerID     [16]byte
	IssuedAt     uint64
	ExpiresAt    uint64
	SessionScope [12]byte
	MAC          [32]byte
}

// ParseRAT parses a Relay Admission Token from exactly 93 bytes.
func ParseRAT(data []byte) (*RelayAdmissionToken, error) {
	if len(data) != RATSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidTokenSize, RATSize, len(data))
	}

	t := &RelayAdmissionToken{
		Version: data[0],
	}
	copy(t.NodeID[:], data[1:17])
	copy(t.IssuerID[:], data[17:33])
	t.IssuedAt = binary.BigEndian.Uint64(data[33:41])
	t.ExpiresAt = binary.BigEndian.Uint64(data[41:49])
	copy(t.SessionScope[:], data[49:61])
	copy(t.MAC[:], data[61:93])

	return t, nil
}

// Serialize encodes the token to exactly 93 bytes.
func (t *RelayAdmissionToken) Serialize() [RATSize]byte {
	var buf [RATSize]byte
	buf[0] = t.Version
	copy(buf[1:17], t.NodeID[:])
	copy(buf[17:33], t.IssuerID[:])
	binary.BigEndian.PutUint64(buf[33:41], t.IssuedAt)
	binary.BigEndian.PutUint64(buf[41:49], t.ExpiresAt)
	copy(buf[49:61], t.SessionScope[:])
	copy(buf[61:93], t.MAC[:])
	return buf
}

// Verify checks the MAC using HMAC-BLAKE2s (constant-time comparison).
func (t *RelayAdmissionToken) Verify(secret *[32]byte) bool {
	serialized := t.Serialize()
	data := serialized[:RATDataSize]
	expectedMAC := HMACBLAKE2s(secret[:], data)
	return subtle.ConstantTimeCompare(t.MAC[:], expectedMAC[:]) == 1
}

// IsExpired returns true if the token has expired.
func (t *RelayAdmissionToken) IsExpired() bool {
	now := uint64(time.Now().Unix())
	return now >= t.ExpiresAt
}

// ValidForSession returns true if the token is valid for a specific session.
// A zero session scope means the token is valid for any session.
func (t *RelayAdmissionToken) ValidForSession(sessionID [12]byte) bool {
	zeroScope := [12]byte{}
	if t.SessionScope == zeroScope {
		return true
	}
	return t.SessionScope == sessionID
}

// TTLSeconds returns the remaining time-to-live in seconds, or 0 if expired.
func (t *RelayAdmissionToken) TTLSeconds() uint64 {
	now := uint64(time.Now().Unix())
	if now >= t.ExpiresAt {
		return 0
	}
	return t.ExpiresAt - now
}

// Display returns a human-readable representation of the token.
func (t *RelayAdmissionToken) Display() string {
	scopeStr := "any"
	if t.SessionScope != [12]byte{} {
		scopeStr = hex.EncodeToString(t.SessionScope[:])
	}
	return fmt.Sprintf(
		"RAT v%d\n  NodeID:    %s\n  IssuerID:  %s\n  IssuedAt:  %d\n  ExpiresAt: %d\n  Scope:     %s\n  MAC:       %s...",
		t.Version,
		hex.EncodeToString(t.NodeID[:]),
		hex.EncodeToString(t.IssuerID[:]),
		t.IssuedAt,
		t.ExpiresAt,
		scopeStr,
		hex.EncodeToString(t.MAC[:16]),
	)
}

// IssueRAT creates and signs a new Relay Admission Token.
func IssueRAT(
	nodeID [16]byte,
	issuerID [16]byte,
	sessionScope [12]byte,
	ttlSeconds uint64,
	secret *[32]byte,
) *RelayAdmissionToken {
	now := uint64(time.Now().Unix())
	return IssueRATAt(nodeID, issuerID, sessionScope, now, now+ttlSeconds, secret)
}

// IssueRATAt creates a token with explicit timestamps (useful for testing
// and cross-language verification).
func IssueRATAt(
	nodeID [16]byte,
	issuerID [16]byte,
	sessionScope [12]byte,
	issuedAt, expiresAt uint64,
	secret *[32]byte,
) *RelayAdmissionToken {
	t := &RelayAdmissionToken{
		Version:      RATVersion,
		NodeID:       nodeID,
		IssuerID:     issuerID,
		IssuedAt:     issuedAt,
		ExpiresAt:    expiresAt,
		SessionScope: sessionScope,
	}

	serialized := t.Serialize()
	data := serialized[:RATDataSize]
	t.MAC = HMACBLAKE2s(secret[:], data)

	return t
}

// HMACBLAKE2s implements RFC 2104 HMAC with BLAKE2s as the hash function.
// This is byte-compatible with the Rust and Elixir implementations.
//
// HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
//
// Where H is BLAKE2s (block_size=64, output=32).
func HMACBLAKE2s(key, message []byte) [32]byte {
	// If key is longer than block size, hash it first
	var keyPrime [blake2sBlockSize]byte
	if len(key) > blake2sBlockSize {
		h, _ := blake2s.New256(nil)
		h.Write(key)
		hashed := h.Sum(nil)
		copy(keyPrime[:], hashed)
	} else {
		copy(keyPrime[:], key)
	}

	// Compute ipad and opad
	var ipad, opad [blake2sBlockSize]byte
	for i := 0; i < blake2sBlockSize; i++ {
		ipad[i] = keyPrime[i] ^ 0x36
		opad[i] = keyPrime[i] ^ 0x5C
	}

	// Inner hash: H(ipad || message)
	innerHasher, _ := blake2s.New256(nil)
	innerHasher.Write(ipad[:])
	innerHasher.Write(message)
	innerHash := innerHasher.Sum(nil)

	// Outer hash: H(opad || innerHash)
	outerHasher, _ := blake2s.New256(nil)
	outerHasher.Write(opad[:])
	outerHasher.Write(innerHash)
	outerHash := outerHasher.Sum(nil)

	var result [32]byte
	copy(result[:], outerHash)
	return result
}

// HandshakeExtension wraps extension data in handshake packets.
type HandshakeExtension struct {
	// Token is the admission token (when ext type is RAT).
	Token *RelayAdmissionToken
}

// SerializeExtension serializes the extension: ExtType (1 byte) + data.
func (e *HandshakeExtension) SerializeExtension() []byte {
	if e.Token == nil {
		return nil
	}
	serialized := e.Token.Serialize()
	buf := make([]byte, 1+RATSize)
	buf[0] = ExtTypeRAT
	copy(buf[1:], serialized[:])
	return buf
}

// ParseHandshakeExtension parses an extension from bytes.
func ParseHandshakeExtension(data []byte) (*HandshakeExtension, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: extension data empty", ErrInvalidTokenSize)
	}

	switch data[0] {
	case ExtTypeRAT:
		if len(data) != 1+RATSize {
			return nil, fmt.Errorf("%w: expected %d bytes for RAT extension, got %d",
				ErrInvalidTokenSize, 1+RATSize, len(data))
		}
		token, err := ParseRAT(data[1:])
		if err != nil {
			return nil, err
		}
		return &HandshakeExtension{Token: token}, nil
	default:
		return nil, fmt.Errorf("ztlp: unsupported extension type: 0x%02X", data[0])
	}
}

// WireLen returns the total byte length of the extension.
func (e *HandshakeExtension) WireLen() int {
	if e.Token != nil {
		return 1 + RATSize // 94 bytes
	}
	return 0
}
