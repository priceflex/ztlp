// Package ztlp implements the Zero Trust Layer Protocol (ZTLP) client SDK.
//
// ZTLP provides mutual authentication, session encryption, and relay routing
// using the Noise_XX handshake pattern with ChaCha20-Poly1305 AEAD and
// BLAKE2s key derivation.
//
// # Quick Start
//
//	// Generate an identity
//	id, err := ztlp.GenerateIdentity()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Connect to a peer
//	client, err := ztlp.Dial("192.168.1.1:23095", id)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Send and receive encrypted messages
//	client.Send([]byte("hello"))
//	msg, err := client.Recv()
//
// # Protocol Details
//
// ZTLP uses a three-layer admission pipeline:
//   - Layer 1: Magic byte check (0x5A37) — nanoseconds, no crypto
//   - Layer 2: SessionID lookup — microseconds, no crypto
//   - Layer 3: HeaderAuthTag verification — ChaCha20-Poly1305 AEAD
//
// Wire format:
//   - Handshake header: 95 bytes (HdrLen=24 words)
//   - Data header: 42 bytes (HdrLen=11 words)
//   - Noise pattern: Noise_XX_25519_ChaChaPoly_BLAKE2s
package ztlp

import (
	"errors"
)

// Protocol constants matching the Rust implementation.
const (
	// Magic is the ZTLP protocol magic value (big-endian).
	Magic uint16 = 0x5A37

	// Version is the current protocol version.
	Version uint8 = 1

	// DefaultPort is the standard ZTLP port.
	DefaultPort = 23095

	// HandshakeHeaderSize is the size of a handshake/control header in bytes.
	HandshakeHeaderSize = 95

	// DataHeaderSize is the size of a compact data header in bytes.
	DataHeaderSize = 42

	// SessionIDSize is the size of a SessionID in bytes.
	SessionIDSize = 12

	// NodeIDSize is the size of a NodeID in bytes.
	NodeIDSize = 16

	// AuthTagSize is the size of a header auth tag in bytes.
	AuthTagSize = 16

	// MaxPacketSize is the maximum UDP datagram size.
	MaxPacketSize = 65535

	// NoisePattern is the Noise protocol pattern string.
	NoisePattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s"

	// CryptoSuiteDefault is the crypto suite ID for ChaCha20-Poly1305 + Noise_XX.
	CryptoSuiteDefault uint16 = 0x0001

	// HandshakeHdrLen is HdrLen for handshake headers (95 bytes → 24 4-byte words).
	HandshakeHdrLen uint16 = 24

	// DataHdrLen is HdrLen for data headers (42 bytes → 11 4-byte words).
	DataHdrLen uint16 = 11
)

// MsgType represents ZTLP message types.
type MsgType uint8

const (
	MsgTypeData     MsgType = 0
	MsgTypeHello    MsgType = 1
	MsgTypeHelloAck MsgType = 2
	MsgTypeRekey    MsgType = 3
	MsgTypeClose    MsgType = 4
	MsgTypeError    MsgType = 5
	MsgTypePing     MsgType = 6
	MsgTypePong     MsgType = 7
)

// String returns the human-readable name of a MsgType.
func (m MsgType) String() string {
	switch m {
	case MsgTypeData:
		return "Data"
	case MsgTypeHello:
		return "Hello"
	case MsgTypeHelloAck:
		return "HelloAck"
	case MsgTypeRekey:
		return "Rekey"
	case MsgTypeClose:
		return "Close"
	case MsgTypeError:
		return "Error"
	case MsgTypePing:
		return "Ping"
	case MsgTypePong:
		return "Pong"
	default:
		return "Unknown"
	}
}

// Flag bits for ZTLP packet headers.
const (
	FlagHasExt    uint16 = 1 << 0
	FlagAckReq    uint16 = 1 << 1
	FlagRekey     uint16 = 1 << 2
	FlagMigrate   uint16 = 1 << 3
	FlagMultipath uint16 = 1 << 4
	FlagRelayHop  uint16 = 1 << 5
)

// Common errors.
var (
	ErrInvalidMagic     = errors.New("ztlp: invalid magic bytes")
	ErrBufferTooShort   = errors.New("ztlp: buffer too short")
	ErrInvalidVersion   = errors.New("ztlp: unsupported protocol version")
	ErrInvalidMsgType   = errors.New("ztlp: invalid message type")
	ErrSessionNotFound  = errors.New("ztlp: session not found")
	ErrReplayDetected   = errors.New("ztlp: replay detected")
	ErrAuthTagInvalid   = errors.New("ztlp: invalid header auth tag")
	ErrHandshakeFailed  = errors.New("ztlp: handshake failed")
	ErrNotConnected     = errors.New("ztlp: not connected")
	ErrClosed           = errors.New("ztlp: connection closed")
	ErrInvalidTokenSize = errors.New("ztlp: invalid token size")
	ErrTokenExpired     = errors.New("ztlp: token expired")
	ErrInvalidMAC       = errors.New("ztlp: invalid MAC")
)
