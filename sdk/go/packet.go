package ztlp

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// SessionID is a 96-bit (12-byte) session identifier.
type SessionID [SessionIDSize]byte

// GenerateSessionID creates a new random SessionID.
func GenerateSessionID() (SessionID, error) {
	var sid SessionID
	if _, err := rand.Read(sid[:]); err != nil {
		return sid, fmt.Errorf("ztlp: generate SessionID: %w", err)
	}
	return sid, nil
}

// SessionIDFromBytes creates a SessionID from a byte slice.
func SessionIDFromBytes(b []byte) (SessionID, error) {
	var sid SessionID
	if len(b) != SessionIDSize {
		return sid, fmt.Errorf("ztlp: SessionID must be %d bytes, got %d", SessionIDSize, len(b))
	}
	copy(sid[:], b)
	return sid, nil
}

// IsZero returns true if the SessionID is all zeros.
func (s SessionID) IsZero() bool {
	return s == SessionID{}
}

// String returns the hex representation of the SessionID.
func (s SessionID) String() string {
	return hex.EncodeToString(s[:])
}

// HandshakeHeader is the full 95-byte ZTLP handshake/control header.
//
// Wire format (all fields big-endian):
//
//	Magic:         16 bits (0x5A37)
//	Ver:            4 bits  + HdrLen: 12 bits (packed u16)
//	Flags:         16 bits
//	MsgType:        8 bits
//	CryptoSuite:   16 bits
//	KeyID:         16 bits
//	SessionID:     96 bits (12 bytes)
//	PacketSeq:     64 bits
//	Timestamp:     64 bits
//	SrcNodeID:    128 bits (16 bytes)
//	DstSvcID:     128 bits (16 bytes)
//	PolicyTag:     32 bits
//	ExtLen:        16 bits
//	PayloadLen:    16 bits
//	HeaderAuthTag: 128 bits (16 bytes)
type HandshakeHeader struct {
	Version       uint8
	HdrLen        uint16
	Flags         uint16
	MsgType       MsgType
	CryptoSuite   uint16
	KeyID         uint16
	SessionID     SessionID
	PacketSeq     uint64
	Timestamp     uint64
	SrcNodeID     NodeID
	DstSvcID      [16]byte
	PolicyTag     uint32
	ExtLen        uint16
	PayloadLen    uint16
	HeaderAuthTag [AuthTagSize]byte
}

// NewHandshakeHeader creates a new handshake header with defaults.
func NewHandshakeHeader(msgType MsgType) HandshakeHeader {
	return HandshakeHeader{
		Version:     Version,
		HdrLen:      HandshakeHdrLen, // 24 words
		MsgType:     msgType,
		CryptoSuite: CryptoSuiteDefault,
		Timestamp:   uint64(time.Now().UnixMilli()),
	}
}

// Serialize encodes the header to exactly 95 bytes.
func (h *HandshakeHeader) Serialize() []byte {
	buf := make([]byte, HandshakeHeaderSize)
	pos := 0

	// Magic (16 bits)
	binary.BigEndian.PutUint16(buf[pos:], Magic)
	pos += 2

	// Ver (4 bits) | HdrLen (12 bits)
	verHdrLen := (uint16(h.Version&0x0F) << 12) | (h.HdrLen & 0x0FFF)
	binary.BigEndian.PutUint16(buf[pos:], verHdrLen)
	pos += 2

	// Flags (16 bits)
	binary.BigEndian.PutUint16(buf[pos:], h.Flags)
	pos += 2

	// MsgType (8 bits)
	buf[pos] = uint8(h.MsgType)
	pos++

	// CryptoSuite (16 bits)
	binary.BigEndian.PutUint16(buf[pos:], h.CryptoSuite)
	pos += 2

	// KeyID (16 bits)
	binary.BigEndian.PutUint16(buf[pos:], h.KeyID)
	pos += 2

	// SessionID (12 bytes)
	copy(buf[pos:], h.SessionID[:])
	pos += SessionIDSize

	// PacketSeq (64 bits)
	binary.BigEndian.PutUint64(buf[pos:], h.PacketSeq)
	pos += 8

	// Timestamp (64 bits)
	binary.BigEndian.PutUint64(buf[pos:], h.Timestamp)
	pos += 8

	// SrcNodeID (16 bytes)
	copy(buf[pos:], h.SrcNodeID[:])
	pos += NodeIDSize

	// DstSvcID (16 bytes)
	copy(buf[pos:], h.DstSvcID[:])
	pos += 16

	// PolicyTag (32 bits)
	binary.BigEndian.PutUint32(buf[pos:], h.PolicyTag)
	pos += 4

	// ExtLen (16 bits)
	binary.BigEndian.PutUint16(buf[pos:], h.ExtLen)
	pos += 2

	// PayloadLen (16 bits)
	binary.BigEndian.PutUint16(buf[pos:], h.PayloadLen)
	pos += 2

	// HeaderAuthTag (16 bytes)
	copy(buf[pos:], h.HeaderAuthTag[:])

	return buf
}

// AADBytes returns the header bytes without the auth tag (first 79 bytes),
// used as additional authenticated data for AEAD computation.
func (h *HandshakeHeader) AADBytes() []byte {
	full := h.Serialize()
	return full[:HandshakeHeaderSize-AuthTagSize]
}

// IsRelayHop returns true if the relay hop flag is set.
func (h *HandshakeHeader) IsRelayHop() bool {
	return h.Flags&FlagRelayHop != 0
}

// SetRelayHop sets the relay hop flag.
func (h *HandshakeHeader) SetRelayHop() {
	h.Flags |= FlagRelayHop
}

// ParseHandshakeHeader deserializes a handshake header from bytes.
func ParseHandshakeHeader(data []byte) (*HandshakeHeader, error) {
	if len(data) < HandshakeHeaderSize {
		return nil, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooShort, HandshakeHeaderSize, len(data))
	}

	pos := 0

	// Magic
	magic := binary.BigEndian.Uint16(data[pos:])
	if magic != Magic {
		return nil, fmt.Errorf("%w: expected 0x5A37, got 0x%04X", ErrInvalidMagic, magic)
	}
	pos += 2

	// Ver | HdrLen
	verHdrLen := binary.BigEndian.Uint16(data[pos:])
	version := uint8((verHdrLen >> 12) & 0x0F)
	hdrLen := verHdrLen & 0x0FFF
	pos += 2

	if version != Version {
		return nil, fmt.Errorf("%w: %d", ErrInvalidVersion, version)
	}

	// Flags
	flags := binary.BigEndian.Uint16(data[pos:])
	pos += 2

	// MsgType
	msgType := MsgType(data[pos])
	if msgType > MsgTypePong {
		return nil, fmt.Errorf("%w: %d", ErrInvalidMsgType, msgType)
	}
	pos++

	// CryptoSuite
	cryptoSuite := binary.BigEndian.Uint16(data[pos:])
	pos += 2

	// KeyID
	keyID := binary.BigEndian.Uint16(data[pos:])
	pos += 2

	// SessionID (12 bytes)
	var sessionID SessionID
	copy(sessionID[:], data[pos:pos+SessionIDSize])
	pos += SessionIDSize

	// PacketSeq
	packetSeq := binary.BigEndian.Uint64(data[pos:])
	pos += 8

	// Timestamp
	timestamp := binary.BigEndian.Uint64(data[pos:])
	pos += 8

	// SrcNodeID (16 bytes)
	var srcNodeID NodeID
	copy(srcNodeID[:], data[pos:pos+NodeIDSize])
	pos += NodeIDSize

	// DstSvcID (16 bytes)
	var dstSvcID [16]byte
	copy(dstSvcID[:], data[pos:pos+16])
	pos += 16

	// PolicyTag
	policyTag := binary.BigEndian.Uint32(data[pos:])
	pos += 4

	// ExtLen
	extLen := binary.BigEndian.Uint16(data[pos:])
	pos += 2

	// PayloadLen
	payloadLen := binary.BigEndian.Uint16(data[pos:])
	pos += 2

	// HeaderAuthTag (16 bytes)
	var authTag [AuthTagSize]byte
	copy(authTag[:], data[pos:pos+AuthTagSize])

	return &HandshakeHeader{
		Version:       version,
		HdrLen:        hdrLen,
		Flags:         flags,
		MsgType:       msgType,
		CryptoSuite:   cryptoSuite,
		KeyID:         keyID,
		SessionID:     sessionID,
		PacketSeq:     packetSeq,
		Timestamp:     timestamp,
		SrcNodeID:     srcNodeID,
		DstSvcID:      dstSvcID,
		PolicyTag:     policyTag,
		ExtLen:        extLen,
		PayloadLen:    payloadLen,
		HeaderAuthTag: authTag,
	}, nil
}

// DataHeader is the compact 42-byte ZTLP data header (post-handshake).
//
// Wire format:
//
//	Magic:         16 bits
//	Ver:            4 bits + HdrLen: 12 bits
//	Flags:         16 bits
//	SessionID:     96 bits (12 bytes)
//	PacketSeq:     64 bits
//	HeaderAuthTag: 128 bits (16 bytes)
type DataHeader struct {
	Version       uint8
	HdrLen        uint16
	Flags         uint16
	SessionID     SessionID
	PacketSeq     uint64
	HeaderAuthTag [AuthTagSize]byte
}

// NewDataHeader creates a new data header for an established session.
func NewDataHeader(sessionID SessionID, packetSeq uint64) DataHeader {
	return DataHeader{
		Version:   Version,
		HdrLen:    DataHdrLen, // 11 words
		SessionID: sessionID,
		PacketSeq: packetSeq,
	}
}

// Serialize encodes the data header to exactly 42 bytes.
func (h *DataHeader) Serialize() []byte {
	buf := make([]byte, DataHeaderSize)
	pos := 0

	// Magic
	binary.BigEndian.PutUint16(buf[pos:], Magic)
	pos += 2

	// Ver | HdrLen
	verHdrLen := (uint16(h.Version&0x0F) << 12) | (h.HdrLen & 0x0FFF)
	binary.BigEndian.PutUint16(buf[pos:], verHdrLen)
	pos += 2

	// Flags
	binary.BigEndian.PutUint16(buf[pos:], h.Flags)
	pos += 2

	// SessionID
	copy(buf[pos:], h.SessionID[:])
	pos += SessionIDSize

	// PacketSeq
	binary.BigEndian.PutUint64(buf[pos:], h.PacketSeq)
	pos += 8

	// HeaderAuthTag
	copy(buf[pos:], h.HeaderAuthTag[:])

	return buf
}

// AADBytes returns the header bytes without the auth tag (first 26 bytes).
func (h *DataHeader) AADBytes() []byte {
	full := h.Serialize()
	return full[:DataHeaderSize-AuthTagSize]
}

// IsRelayHop returns true if the relay hop flag is set.
func (h *DataHeader) IsRelayHop() bool {
	return h.Flags&FlagRelayHop != 0
}

// SetRelayHop sets the relay hop flag.
func (h *DataHeader) SetRelayHop() {
	h.Flags |= FlagRelayHop
}

// ParseDataHeader deserializes a data header from bytes.
func ParseDataHeader(data []byte) (*DataHeader, error) {
	if len(data) < DataHeaderSize {
		return nil, fmt.Errorf("%w: need %d bytes, have %d", ErrBufferTooShort, DataHeaderSize, len(data))
	}

	pos := 0

	// Magic
	magic := binary.BigEndian.Uint16(data[pos:])
	if magic != Magic {
		return nil, fmt.Errorf("%w: expected 0x5A37, got 0x%04X", ErrInvalidMagic, magic)
	}
	pos += 2

	// Ver | HdrLen
	verHdrLen := binary.BigEndian.Uint16(data[pos:])
	version := uint8((verHdrLen >> 12) & 0x0F)
	hdrLen := verHdrLen & 0x0FFF
	pos += 2

	if version != Version {
		return nil, fmt.Errorf("%w: %d", ErrInvalidVersion, version)
	}

	// Flags
	flags := binary.BigEndian.Uint16(data[pos:])
	pos += 2

	// SessionID
	var sessionID SessionID
	copy(sessionID[:], data[pos:pos+SessionIDSize])
	pos += SessionIDSize

	// PacketSeq
	packetSeq := binary.BigEndian.Uint64(data[pos:])
	pos += 8

	// HeaderAuthTag
	var authTag [AuthTagSize]byte
	copy(authTag[:], data[pos:pos+AuthTagSize])

	return &DataHeader{
		Version:       version,
		HdrLen:        hdrLen,
		Flags:         flags,
		SessionID:     sessionID,
		PacketSeq:     packetSeq,
		HeaderAuthTag: authTag,
	}, nil
}

// DetectPacketType examines the first 4 bytes of a packet to determine
// if it's a handshake or data header based on the HdrLen field.
// Returns true for handshake (HdrLen=24), false for data (HdrLen=11).
func DetectPacketType(data []byte) (isHandshake bool, err error) {
	if len(data) < 4 {
		return false, fmt.Errorf("%w: need at least 4 bytes", ErrBufferTooShort)
	}
	magic := binary.BigEndian.Uint16(data[0:])
	if magic != Magic {
		return false, fmt.Errorf("%w: 0x%04X", ErrInvalidMagic, magic)
	}
	verHdrLen := binary.BigEndian.Uint16(data[2:])
	hdrLen := verHdrLen & 0x0FFF
	return hdrLen == HandshakeHdrLen, nil
}

// ExtractSessionID extracts the SessionID from a raw ZTLP packet without
// fully parsing the header. Uses HdrLen to determine the offset.
func ExtractSessionID(data []byte) (SessionID, error) {
	isHandshake, err := DetectPacketType(data)
	if err != nil {
		return SessionID{}, err
	}

	if isHandshake {
		// Handshake header: SessionID at bytes 11..23
		if len(data) < 23 {
			return SessionID{}, fmt.Errorf("%w: need 23 bytes for handshake SessionID", ErrBufferTooShort)
		}
		var sid SessionID
		copy(sid[:], data[11:23])
		return sid, nil
	}

	// Data header: SessionID at bytes 6..18
	if len(data) < 18 {
		return SessionID{}, fmt.Errorf("%w: need 18 bytes for data SessionID", ErrBufferTooShort)
	}
	var sid SessionID
	copy(sid[:], data[6:18])
	return sid, nil
}
