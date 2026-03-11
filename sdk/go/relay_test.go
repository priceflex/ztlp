package ztlp

import (
	"net"
	"testing"
)

func TestRelayConnection(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 23095}
	sid := SessionID{1, 2, 3}

	rc := NewRelayConnection(addr, sid)
	if rc.RelayAddr.String() != addr.String() {
		t.Errorf("relay addr: %s, want %s", rc.RelayAddr, addr)
	}
	if rc.SessionID != sid {
		t.Error("session ID mismatch")
	}
	if rc.HasValidToken() {
		t.Error("should not have valid token initially")
	}
	if rc.GetToken() != nil {
		t.Error("token should be nil initially")
	}
}

func TestRelayConnectionToken(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 23095}
	rc := NewRelayConnection(addr, SessionID{})

	secret := [32]byte{0x42}
	token := IssueRAT([16]byte{0x11}, [16]byte{0x22}, [12]byte{}, 300, &secret)

	rc.SetToken(token)
	if !rc.HasValidToken() {
		t.Error("should have valid token after SetToken")
	}
	if rc.GetToken() == nil {
		t.Error("GetToken should return the token")
	}
	if rc.GetToken().NodeID != [16]byte{0x11} {
		t.Error("token nodeID mismatch")
	}
}

func TestRelayConnectionExpiredToken(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 23095}
	rc := NewRelayConnection(addr, SessionID{})

	secret := [32]byte{0x42}
	// Issue an expired token
	token := IssueRATAt([16]byte{0x11}, [16]byte{0x22}, [12]byte{}, 1000000, 1000010, &secret)

	rc.SetToken(token)
	if rc.HasValidToken() {
		t.Error("expired token should not be valid")
	}
}

func TestRelayClientCreation(t *testing.T) {
	// Create a session for the relay client
	init, _ := GenerateIdentity()
	resp, _ := GenerateIdentity()
	result, err := PerformHandshake(init, resp)
	if err != nil {
		t.Fatalf("PerformHandshake: %v", err)
	}

	client, err := NewRelayClient(
		"127.0.0.1:0",
		"127.0.0.1:23095",
		result.InitiatorSession,
	)
	if err != nil {
		t.Fatalf("NewRelayClient: %v", err)
	}
	defer client.Close()

	if client.LocalAddr().Port == 0 {
		t.Error("local port should be assigned")
	}
	if client.RelayAddr().Port != 23095 {
		t.Errorf("relay port: %d, want 23095", client.RelayAddr().Port)
	}
	if client.Connection() == nil {
		t.Error("connection should not be nil")
	}
}
