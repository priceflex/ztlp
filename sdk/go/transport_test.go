package ztlp

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTransportNodeBindAndClose(t *testing.T) {
	node, err := NewTransportNode("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTransportNode: %v", err)
	}
	defer node.Close()

	addr := node.LocalAddr()
	if addr.Port == 0 {
		t.Error("port should be assigned")
	}
	if addr.IP.String() != "127.0.0.1" {
		t.Errorf("IP: %s, want 127.0.0.1", addr.IP)
	}
}

func TestTransportNodeSendRecvRaw(t *testing.T) {
	// Create two nodes
	node1, err := NewTransportNode("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTransportNode (1): %v", err)
	}
	defer node1.Close()

	node2, err := NewTransportNode("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTransportNode (2): %v", err)
	}
	defer node2.Close()

	testData := []byte("hello ztlp transport")

	// Send from node1 to node2
	_, err = node1.SendRaw(testData, node2.LocalAddr())
	if err != nil {
		t.Fatalf("SendRaw: %v", err)
	}

	// Receive on node2 with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	data, addr, err := node2.RecvRaw(ctx)
	if err != nil {
		t.Fatalf("RecvRaw: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("received: %q, want %q", data, testData)
	}
	if addr.Port != node1.LocalAddr().Port {
		t.Errorf("sender port: %d, want %d", addr.Port, node1.LocalAddr().Port)
	}
}

func TestTransportNodeEncryptedDataExchange(t *testing.T) {
	// Create two nodes
	node1, err := NewTransportNode("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTransportNode (1): %v", err)
	}
	defer node1.Close()

	node2, err := NewTransportNode("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTransportNode (2): %v", err)
	}
	defer node2.Close()

	// Perform handshake to get session keys
	init, _ := GenerateIdentity()
	resp, _ := GenerateIdentity()
	result, err := PerformHandshake(init, resp)
	if err != nil {
		t.Fatalf("PerformHandshake: %v", err)
	}

	// Register sessions in respective pipelines
	node1.Pipeline().RegisterSession(result.InitiatorSession)
	node2.Pipeline().RegisterSession(result.ResponderSession)

	sessionID := result.InitiatorSession.SessionID

	// Send encrypted data from node1 to node2
	plaintext := []byte("encrypted ztlp message")
	err = node1.SendData(sessionID, plaintext, node2.LocalAddr())
	if err != nil {
		t.Fatalf("SendData: %v", err)
	}

	// Receive and decrypt on node2
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	received, addr, err := node2.RecvData(ctx)
	if err != nil {
		t.Fatalf("RecvData: %v", err)
	}
	if received == nil {
		t.Fatal("received nil (packet dropped)")
	}
	if string(received) != string(plaintext) {
		t.Errorf("received: %q, want %q", received, plaintext)
	}
	_ = addr
}

func TestTransportNodeSendDataNoSession(t *testing.T) {
	node, err := NewTransportNode("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTransportNode: %v", err)
	}
	defer node.Close()

	dest := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9999}
	err = node.SendData(SessionID{0xFF}, []byte("test"), dest)
	if err != ErrSessionNotFound {
		t.Errorf("expected ErrSessionNotFound, got: %v", err)
	}
}

func TestTransportNodePipelineIntegration(t *testing.T) {
	node, err := NewTransportNode("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewTransportNode: %v", err)
	}
	defer node.Close()

	p := node.Pipeline()
	if p == nil {
		t.Fatal("pipeline should not be nil")
	}

	// Register and lookup session
	sid := SessionID{1, 2, 3}
	session := NewSessionState(sid, NodeID{}, [32]byte{}, [32]byte{}, false)
	p.RegisterSession(session)

	if s := p.GetSession(sid); s == nil {
		t.Error("session should be found")
	}
}

func TestTransportNodeMultipleMessages(t *testing.T) {
	node1, _ := NewTransportNode("127.0.0.1:0")
	defer node1.Close()
	node2, _ := NewTransportNode("127.0.0.1:0")
	defer node2.Close()

	init, _ := GenerateIdentity()
	resp, _ := GenerateIdentity()
	result, _ := PerformHandshake(init, resp)

	node1.Pipeline().RegisterSession(result.InitiatorSession)
	node2.Pipeline().RegisterSession(result.ResponderSession)

	sessionID := result.InitiatorSession.SessionID

	// Send multiple messages
	messages := []string{"msg1", "msg2", "msg3", "hello world", "final message"}
	for _, msg := range messages {
		err := node1.SendData(sessionID, []byte(msg), node2.LocalAddr())
		if err != nil {
			t.Fatalf("SendData(%q): %v", msg, err)
		}
	}

	// Receive all messages
	for _, expectedMsg := range messages {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		received, _, err := node2.RecvData(ctx)
		cancel()
		if err != nil {
			t.Fatalf("RecvData: %v", err)
		}
		if received == nil {
			t.Fatal("received nil (packet dropped)")
		}
		if string(received) != expectedMsg {
			t.Errorf("received: %q, want %q", received, expectedMsg)
		}
	}
}
