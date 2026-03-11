package ztlp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestDialAndListen(t *testing.T) {
	// Generate identities
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	// Start listener
	listener, err := Listen("127.0.0.1:0", serverID)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr()

	var wg sync.WaitGroup
	var serverClient *Client
	var serverErr error

	// Accept in background
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serverClient, serverErr = listener.AcceptContext(ctx)
	}()

	// Dial
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialContext(ctx, addr.String(), clientID)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	// Wait for server to accept
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Accept: %v", serverErr)
	}
	defer serverClient.Close()

	// Both should have valid sessions
	if client.SessionID().IsZero() {
		t.Error("client SessionID should not be zero")
	}
	if serverClient.SessionID().IsZero() {
		t.Error("server SessionID should not be zero")
	}
	if client.SessionID() != serverClient.SessionID() {
		t.Error("SessionIDs should match")
	}

	// PeerNodeIDs should be correct
	if client.PeerNodeID() != serverID.NodeID {
		t.Error("client's peer should be server")
	}
	if serverClient.PeerNodeID() != clientID.NodeID {
		t.Error("server's peer should be client")
	}
}

func TestClientSendRecv(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	listener, _ := Listen("127.0.0.1:0", serverID)
	defer listener.Close()

	var wg sync.WaitGroup
	var serverClient *Client

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serverClient, _ = listener.AcceptContext(ctx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := DialContext(ctx, listener.Addr().String(), clientID)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	wg.Wait()
	defer serverClient.Close()

	// Client sends, server receives
	testMsg := []byte("hello from client")
	if err := client.Send(testMsg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	recvCtx, recvCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer recvCancel()

	msg, err := serverClient.RecvContext(recvCtx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(msg) != string(testMsg) {
		t.Errorf("received: %q, want %q", msg, testMsg)
	}
}

func TestClientSendRecvBidirectional(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	listener, _ := Listen("127.0.0.1:0", serverID)
	defer listener.Close()

	var wg sync.WaitGroup
	var serverClient *Client

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serverClient, _ = listener.AcceptContext(ctx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := DialContext(ctx, listener.Addr().String(), clientID)
	defer client.Close()

	wg.Wait()
	defer serverClient.Close()

	// Multiple messages in both directions
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("message %d", i)

		// Client → Server
		client.Send([]byte(msg))
		recvCtx, recvCancel := context.WithTimeout(context.Background(), 2*time.Second)
		received, _ := serverClient.RecvContext(recvCtx)
		recvCancel()
		if string(received) != msg {
			t.Errorf("c→s msg %d: got %q, want %q", i, received, msg)
		}

		// Server → Client
		reply := fmt.Sprintf("reply %d", i)
		serverClient.Send([]byte(reply))
		recvCtx2, recvCancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		received2, _ := client.RecvContext(recvCtx2)
		recvCancel2()
		if string(received2) != reply {
			t.Errorf("s→c msg %d: got %q, want %q", i, received2, reply)
		}
	}
}

func TestClientClosedOperations(t *testing.T) {
	serverID, _ := GenerateIdentity()
	clientID, _ := GenerateIdentity()

	listener, _ := Listen("127.0.0.1:0", serverID)
	defer listener.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sc, _ := listener.AcceptContext(ctx)
		if sc != nil {
			sc.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, _ := DialContext(ctx, listener.Addr().String(), clientID)
	wg.Wait()

	// Close and try to send
	client.Close()
	err := client.Send([]byte("test"))
	if err != ErrClosed {
		t.Errorf("Send after close: got %v, want ErrClosed", err)
	}

	_, err = client.RecvContext(context.Background())
	if err != ErrClosed {
		t.Errorf("Recv after close: got %v, want ErrClosed", err)
	}

	// Double close should be safe
	if err := client.Close(); err != nil {
		t.Errorf("double close: %v", err)
	}
}

func TestClientIsRelay(t *testing.T) {
	c := &Client{}
	if c.IsRelay() {
		t.Error("should not be relay without relay addr")
	}
}

func TestListenerClose(t *testing.T) {
	id, _ := GenerateIdentity()
	listener, _ := Listen("127.0.0.1:0", id)

	if err := listener.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// Accept after close should fail
	_, err := listener.Accept()
	if err == nil {
		t.Error("Accept after close should fail")
	}
}
