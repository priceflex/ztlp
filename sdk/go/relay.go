package ztlp

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// RelayConnection tracks how to reach a peer through a relay.
type RelayConnection struct {
	// RelayAddr is the relay server's UDP address.
	RelayAddr *net.UDPAddr

	// SessionID is the session ID for the relay to route by.
	SessionID SessionID

	// AdmissionToken is the optional RAT received from the ingress relay.
	AdmissionToken *RelayAdmissionToken

	mu sync.RWMutex
}

// NewRelayConnection creates a new relay connection state.
func NewRelayConnection(relayAddr *net.UDPAddr, sessionID SessionID) *RelayConnection {
	return &RelayConnection{
		RelayAddr: relayAddr,
		SessionID: sessionID,
	}
}

// SetToken sets the admission token.
func (r *RelayConnection) SetToken(token *RelayAdmissionToken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.AdmissionToken = token
}

// GetToken returns the current admission token.
func (r *RelayConnection) GetToken() *RelayAdmissionToken {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.AdmissionToken
}

// HasValidToken returns true if there's a valid (non-expired) admission token.
func (r *RelayConnection) HasValidToken() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.AdmissionToken == nil {
		return false
	}
	return !r.AdmissionToken.IsExpired()
}

// RelayClient is a client that sends/receives data through a ZTLP relay server.
// The relay forwards packets by SessionID without access to session keys.
type RelayClient struct {
	transport *TransportNode
	relay     *RelayConnection
	session   *SessionState
}

// NewRelayClient creates a relay client that routes traffic through the given relay.
func NewRelayClient(
	bindAddr string,
	relayAddr string,
	session *SessionState,
) (*RelayClient, error) {
	transport, err := NewTransportNode(bindAddr)
	if err != nil {
		return nil, fmt.Errorf("ztlp: relay client bind: %w", err)
	}

	rAddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		transport.Close()
		return nil, fmt.Errorf("ztlp: resolve relay address: %w", err)
	}

	transport.Pipeline().RegisterSession(session)

	return &RelayClient{
		transport: transport,
		relay:     NewRelayConnection(rAddr, session.SessionID),
		session:   session,
	}, nil
}

// Send sends encrypted data through the relay to the peer.
func (r *RelayClient) Send(data []byte) error {
	return r.transport.SendData(r.session.SessionID, data, r.relay.RelayAddr)
}

// Recv receives and decrypts data from the relay.
func (r *RelayClient) Recv(ctx context.Context) ([]byte, error) {
	plaintext, _, err := r.transport.RecvData(ctx)
	if err != nil {
		return nil, err
	}
	if plaintext == nil {
		return nil, nil // Packet dropped by pipeline
	}
	return plaintext, nil
}

// Close closes the relay client's transport.
func (r *RelayClient) Close() error {
	return r.transport.Close()
}

// LocalAddr returns the local address.
func (r *RelayClient) LocalAddr() *net.UDPAddr {
	return r.transport.LocalAddr()
}

// RelayAddr returns the relay server address.
func (r *RelayClient) RelayAddr() *net.UDPAddr {
	return r.relay.RelayAddr
}

// Connection returns the relay connection state.
func (r *RelayClient) Connection() *RelayConnection {
	return r.relay
}
