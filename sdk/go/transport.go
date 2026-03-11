package ztlp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// TransportNode is a ZTLP transport node — binds a UDP socket and processes packets.
type TransportNode struct {
	conn     *net.UDPConn
	addr     *net.UDPAddr
	pipeline *Pipeline
	mu       sync.RWMutex
	closed   bool
}

// NewTransportNode binds a new UDP transport node.
func NewTransportNode(bindAddr string) (*TransportNode, error) {
	addr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("ztlp: resolve bind address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("ztlp: bind UDP: %w", err)
	}

	return &TransportNode{
		conn:     conn,
		addr:     addr,
		pipeline: NewPipeline(),
	}, nil
}

// LocalAddr returns the local UDP address.
func (t *TransportNode) LocalAddr() *net.UDPAddr {
	return t.conn.LocalAddr().(*net.UDPAddr)
}

// Pipeline returns the admission pipeline for session management.
func (t *TransportNode) Pipeline() *Pipeline {
	return t.pipeline
}

// Close closes the transport.
func (t *TransportNode) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return t.conn.Close()
}

// SendRaw sends raw bytes to a destination.
func (t *TransportNode) SendRaw(data []byte, dest *net.UDPAddr) (int, error) {
	return t.conn.WriteToUDP(data, dest)
}

// RecvRaw receives a raw packet. Returns (data, sender_address).
func (t *TransportNode) RecvRaw(ctx context.Context) ([]byte, *net.UDPAddr, error) {
	buf := make([]byte, MaxPacketSize)

	// Set read deadline from context if available
	if deadline, ok := ctx.Deadline(); ok {
		if err := t.conn.SetReadDeadline(deadline); err != nil {
			return nil, nil, err
		}
	}

	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf[:n], addr, nil
}

// SendData sends an encrypted data packet through an established session.
func (t *TransportNode) SendData(sessionID SessionID, plaintext []byte, dest *net.UDPAddr) error {
	session := t.pipeline.GetSession(sessionID)
	if session == nil {
		return ErrSessionNotFound
	}

	seq := session.NextSendSeq()

	// Encrypt the payload
	aead, err := chacha20poly1305.New(session.SendKey[:])
	if err != nil {
		return fmt.Errorf("ztlp: create AEAD: %w", err)
	}

	// Use packet sequence as nonce (padded to 12 bytes, matching Rust)
	var nonceBytes [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(nonceBytes[4:12], seq)

	encrypted := aead.Seal(nil, nonceBytes[:], plaintext, nil)

	// Build data header
	hdr := NewDataHeader(sessionID, seq)

	// Compute HeaderAuthTag
	aad := hdr.AADBytes()
	hdr.HeaderAuthTag = ComputeHeaderAuthTag(&session.SendKey, aad)

	// Assemble packet
	pkt := hdr.Serialize()
	pkt = append(pkt, encrypted...)

	_, err = t.SendRaw(pkt, dest)
	return err
}

// RecvData receives and processes a packet through the pipeline.
// Returns the decrypted payload and sender address, or nil if the packet was dropped.
func (t *TransportNode) RecvData(ctx context.Context) ([]byte, *net.UDPAddr, error) {
	data, addr, err := t.RecvRaw(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Run through pipeline
	result := t.pipeline.Process(data)
	if result != AdmissionPass {
		return nil, addr, nil
	}

	// Try to decrypt as a data packet
	hdr, err := ParseDataHeader(data)
	if err != nil {
		// Might be a handshake packet — return raw
		return data, addr, nil
	}

	session := t.pipeline.GetSession(hdr.SessionID)
	if session == nil {
		return nil, addr, nil
	}

	encryptedPayload := data[DataHeaderSize:]
	if len(encryptedPayload) == 0 {
		return nil, addr, nil
	}

	aead, err := chacha20poly1305.New(session.RecvKey[:])
	if err != nil {
		return nil, addr, nil
	}

	var nonceBytes [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(nonceBytes[4:12], hdr.PacketSeq)

	plaintext, err := aead.Open(nil, nonceBytes[:], encryptedPayload, nil)
	if err != nil {
		return nil, addr, nil
	}

	return plaintext, addr, nil
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (t *TransportNode) SetReadDeadline(deadline time.Time) error {
	return t.conn.SetReadDeadline(deadline)
}
