package ztlp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Client is the high-level ZTLP client API.
// It handles the Noise_XX handshake, session establishment, and encrypted communication.
type Client struct {
	identity     *Identity
	transport    *TransportNode
	session      *SessionState
	peerAddr     *net.UDPAddr
	relayAddr    *net.UDPAddr // non-nil when routing through relay
	targetNodeID NodeID       // expected peer NodeID (for relay connections); zero means no check
	mu           sync.RWMutex
	closed       bool
}

// Dial connects to a ZTLP peer directly, performs the Noise_XX handshake,
// and returns an established encrypted connection.
//
//	client, err := ztlp.Dial("192.168.1.1:23095", identity)
//	defer client.Close()
//	client.Send([]byte("hello"))
//	msg, err := client.Recv()
func Dial(addr string, identity *Identity) (*Client, error) {
	return DialContext(context.Background(), addr, identity)
}

// DialContext is like Dial but accepts a context for cancellation and timeouts.
func DialContext(ctx context.Context, addr string, identity *Identity) (*Client, error) {
	peerAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("ztlp: resolve peer address: %w", err)
	}

	transport, err := NewTransportNode("0.0.0.0:0")
	if err != nil {
		return nil, err
	}

	client := &Client{
		identity:  identity,
		transport: transport,
		peerAddr:  peerAddr,
	}

	if err := client.performHandshake(ctx); err != nil {
		transport.Close()
		return nil, err
	}

	return client, nil
}

// DialRelay connects to a peer through a relay server.
// The relay forwards packets by SessionID without access to session keys.
// The peer's NodeID is cryptographically verified against targetNodeID.
//
//	client, err := ztlp.DialRelay("relay.example.com:23095", identity, targetNodeID)
func DialRelay(relayAddr string, identity *Identity, targetNodeID NodeID) (*Client, error) {
	return DialRelayContext(context.Background(), relayAddr, identity, targetNodeID)
}

// DialRelayContext is like DialRelay but accepts a context.
func DialRelayContext(ctx context.Context, relayAddr string, identity *Identity, targetNodeID NodeID) (*Client, error) {
	rAddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("ztlp: resolve relay address: %w", err)
	}

	transport, err := NewTransportNode("0.0.0.0:0")
	if err != nil {
		return nil, err
	}

	client := &Client{
		identity:     identity,
		transport:    transport,
		peerAddr:     rAddr, // Send to relay, which forwards
		relayAddr:    rAddr,
		targetNodeID: targetNodeID,
	}

	if err := client.performHandshake(ctx); err != nil {
		transport.Close()
		return nil, err
	}

	return client, nil
}

// ErrPeerIdentityMismatch is returned when the peer's authenticated NodeID
// does not match the expected target (e.g. in relay connections).
var ErrPeerIdentityMismatch = errors.New("ztlp: peer NodeID mismatch")

// performHandshake executes the three-message Noise_XX handshake as initiator.
func (c *Client) performHandshake(ctx context.Context) error {
	hsCtx, err := NewHandshakeInitiator(c.identity)
	if err != nil {
		return err
	}

	// Set a handshake timeout
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	if err := c.transport.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("ztlp: set read deadline: %w", err)
	}

	// Message 1: Initiator → Responder (ephemeral key + our NodeID as payload)
	msg1, err := hsCtx.WriteMessage(c.identity.NodeID[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	pkt1 := BuildHandshakePacket(MsgTypeHello, c.identity.NodeID, [16]byte{}, SessionID{}, 0, msg1, nil)
	if _, err := c.transport.SendRaw(pkt1, c.peerAddr); err != nil {
		return fmt.Errorf("ztlp: send HELLO: %w", err)
	}

	// Receive Message 2: Responder → Initiator
	recvCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		recvCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	data2, _, err := c.transport.RecvRaw(recvCtx)
	if err != nil {
		return fmt.Errorf("ztlp: recv HELLO_ACK: %w", err)
	}

	hdr2, err := ParseHandshakeHeader(data2)
	if err != nil {
		return fmt.Errorf("ztlp: parse HELLO_ACK: %w", err)
	}

	payload2 := data2[HandshakeHeaderSize:]
	peerNodeIDBytes, err := hsCtx.ReadMessage(payload2)
	if err != nil {
		return fmt.Errorf("%w: read HELLO_ACK: %v", ErrHandshakeFailed, err)
	}

	// Extract peer NodeID from the authenticated Noise payload when the
	// responder provides one (NOT from the unauthenticated SrcNodeID
	// header field, which is spoofable).
	//
	// COMPATIBILITY NOTE: the current ZTLP gateway (Elixir,
	// gateway/lib/ztlp_gateway/session.ex handle_handshake_msg1) calls
	// Handshake.create_msg2(hs) with NO payload, so payload2 is empty
	// (0 bytes) for every real gateway handshake today. We can only
	// enforce the strict authenticated-NodeID check once a payload is
	// actually present; falling back to the header field for an empty
	// payload preserves interop with the deployed gateway (no
	// regression) while still adding real protection for any peer that
	// DOES send its NodeID as payload (future gateway update, or
	// relay-to-relay Go SDK links).
	var peerNodeID NodeID
	switch len(peerNodeIDBytes) {
	case 0:
		// No authenticated NodeID offered by the peer — fall back to
		// the header field as before. This is the same trust level as
		// pre-fix code; it is NOT weakened further, just not improved
		// until the peer side also sends its NodeID.
		peerNodeID = hdr2.SrcNodeID
	case NodeIDSize:
		copy(peerNodeID[:], peerNodeIDBytes)
		// Cross-check against the unauthenticated header as a sanity
		// check (a mismatch indicates a broken or malicious peer: the
		// header claims one identity but the authenticated payload
		// proves another).
		if hdr2.SrcNodeID != peerNodeID {
			return fmt.Errorf("%w: header SrcNodeID %x differs from authenticated payload %x",
				ErrPeerIdentityMismatch, hdr2.SrcNodeID, peerNodeID)
		}
	default:
		return fmt.Errorf("%w: invalid peer NodeID length %d (expected 0 or %d)",
			ErrHandshakeFailed, len(peerNodeIDBytes), NodeIDSize)
	}

	// For relay connections, verify the peer matches the expected target.
	// This check is only fully authenticated when the peer sent a
	// NodeID payload (see switch above); when it didn't (today's
	// gateway), this still catches an obviously wrong relay-forwarded
	// SrcNodeID header, same protection level as before this fix.
	if !c.targetNodeID.IsZero() && peerNodeID != c.targetNodeID {
		return fmt.Errorf("%w: expected %x, got %x",
			ErrPeerIdentityMismatch, c.targetNodeID, peerNodeID)
	}

	// Use the SessionID from the responder's HELLO_ACK
	sessionID := hdr2.SessionID
	if sessionID.IsZero() {
		// If responder didn't assign one, generate our own
		sessionID, err = GenerateSessionID()
		if err != nil {
			return err
		}
	}

	// Message 3: Initiator → Responder (static + identity + our NodeID)
	msg3, err := hsCtx.WriteMessage(c.identity.NodeID[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	pkt3 := BuildHandshakePacket(MsgTypeData, c.identity.NodeID, [16]byte{}, sessionID, 2, msg3, nil)
	if _, err := c.transport.SendRaw(pkt3, c.peerAddr); err != nil {
		return fmt.Errorf("ztlp: send msg3: %w", err)
	}

	// Finalize handshake
	session, err := hsCtx.Finalize(peerNodeID, sessionID)
	if err != nil {
		return err
	}

	c.session = session
	c.transport.Pipeline().RegisterSession(session)

	// Clear the read deadline
	if err := c.transport.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("ztlp: clear read deadline: %w", err)
	}

	return nil
}

// Send sends encrypted data to the connected peer.
func (c *Client) Send(data []byte) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return ErrClosed
	}
	if c.session == nil {
		return ErrNotConnected
	}

	return c.transport.SendData(c.session.SessionID, data, c.peerAddr)
}

// Recv receives and decrypts data from the connected peer.
func (c *Client) Recv() ([]byte, error) {
	return c.RecvContext(context.Background())
}

// RecvContext receives and decrypts data with context support.
func (c *Client) RecvContext(ctx context.Context) ([]byte, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrClosed
	}
	c.mu.RUnlock()

	plaintext, _, err := c.transport.RecvData(ctx)
	if err != nil {
		return nil, err
	}
	if plaintext == nil {
		return nil, nil // Packet dropped by pipeline
	}
	return plaintext, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.session != nil {
		c.transport.Pipeline().RemoveSession(c.session.SessionID)
	}
	return c.transport.Close()
}

// SessionID returns the current session's ID.
func (c *Client) SessionID() SessionID {
	if c.session == nil {
		return SessionID{}
	}
	return c.session.SessionID
}

// PeerNodeID returns the connected peer's NodeID.
func (c *Client) PeerNodeID() NodeID {
	if c.session == nil {
		return NodeID{}
	}
	return c.session.PeerNodeID
}

// LocalAddr returns the local UDP address.
func (c *Client) LocalAddr() *net.UDPAddr {
	return c.transport.LocalAddr()
}

// IsRelay returns true if the connection routes through a relay.
func (c *Client) IsRelay() bool {
	return c.relayAddr != nil
}

// Listener accepts incoming ZTLP connections.
type Listener struct {
	identity  *Identity
	transport *TransportNode
	mu        sync.Mutex
	closed    bool
}

// Listen creates a ZTLP listener that accepts incoming connections.
//
//	listener, err := ztlp.Listen(":23095", identity)
//	conn, err := listener.Accept()
func Listen(addr string, identity *Identity) (*Listener, error) {
	transport, err := NewTransportNode(addr)
	if err != nil {
		return nil, err
	}

	return &Listener{
		identity:  identity,
		transport: transport,
	}, nil
}

// Accept waits for and performs a Noise_XX handshake with an incoming connection.
// Returns a Client representing the established encrypted session.
func (l *Listener) Accept() (*Client, error) {
	return l.AcceptContext(context.Background())
}

// AcceptContext is like Accept but with context support.
func (l *Listener) AcceptContext(ctx context.Context) (*Client, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	l.mu.Unlock()

	// Wait for HELLO (message 1)
	data1, peerAddr, err := l.transport.RecvRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("ztlp: recv HELLO: %w", err)
	}

	hdr1, err := ParseHandshakeHeader(data1)
	if err != nil {
		return nil, fmt.Errorf("ztlp: parse HELLO: %w", err)
	}

	if hdr1.MsgType != MsgTypeHello {
		return nil, fmt.Errorf("ztlp: expected HELLO, got %v", hdr1.MsgType)
	}

	// Set up responder handshake
	hsCtx, err := NewHandshakeResponder(l.identity)
	if err != nil {
		return nil, err
	}

	payload1 := data1[HandshakeHeaderSize:]
	initiatorNodeIDBytes, err := hsCtx.ReadMessage(payload1)
	if err != nil {
		return nil, fmt.Errorf("%w: read HELLO: %v", ErrHandshakeFailed, err)
	}

	// Extract initiator NodeID from the authenticated Noise payload when
	// the initiator provides one. COMPATIBILITY: other ZTLP
	// implementations (Rust proto CLI, gateway) currently send an EMPTY
	// msg1 payload (see proto/src/handshake.rs perform_handshake:
	// `initiator.write_message(&[])`), so falling back to the header
	// field for an empty payload is required to keep accepting
	// connections from those peers — same trust level as before this
	// fix, not weakened, just not yet improved for those peers.
	var initiatorNodeID NodeID
	switch len(initiatorNodeIDBytes) {
	case 0:
		initiatorNodeID = hdr1.SrcNodeID
	case NodeIDSize:
		copy(initiatorNodeID[:], initiatorNodeIDBytes)
		if hdr1.SrcNodeID != initiatorNodeID {
			return nil, fmt.Errorf("%w: header SrcNodeID %x differs from authenticated payload %x",
				ErrPeerIdentityMismatch, hdr1.SrcNodeID, initiatorNodeID)
		}
	default:
		return nil, fmt.Errorf("%w: invalid initiator NodeID length %d (expected 0 or %d)",
			ErrHandshakeFailed, len(initiatorNodeIDBytes), NodeIDSize)
	}

	// Generate SessionID
	sessionID, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}

	// Message 2: Responder → Initiator (with our NodeID as authenticated payload)
	msg2, err := hsCtx.WriteMessage(l.identity.NodeID[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}

	pkt2 := BuildHandshakePacket(MsgTypeHelloAck, l.identity.NodeID, [16]byte{}, sessionID, 1, msg2, nil)
	if _, err := l.transport.SendRaw(pkt2, peerAddr); err != nil {
		return nil, fmt.Errorf("ztlp: send HELLO_ACK: %w", err)
	}

	// Receive Message 3: Initiator → Responder
	data3, _, err := l.transport.RecvRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("ztlp: recv msg3: %w", err)
	}

	// Read the Noise payload (initiator's NodeID — already verified above)
	payload3 := data3[HandshakeHeaderSize:]
	if _, err := hsCtx.ReadMessage(payload3); err != nil {
		return nil, fmt.Errorf("%w: read msg3: %v", ErrHandshakeFailed, err)
	}

	// Finalize handshake — use the authenticated NodeID
	session, err := hsCtx.Finalize(initiatorNodeID, sessionID)
	if err != nil {
		return nil, err
	}

	l.transport.Pipeline().RegisterSession(session)

	return &Client{
		identity:  l.identity,
		transport: l.transport,
		session:   session,
		peerAddr:  peerAddr,
	}, nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return l.transport.Close()
}

// Addr returns the listener's local address.
func (l *Listener) Addr() *net.UDPAddr {
	return l.transport.LocalAddr()
}
