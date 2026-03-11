// Example: ZTLP connection through a relay server.
//
// This example demonstrates connecting two clients through a ZTLP relay,
// showing the typical deployment pattern where clients can't reach each
// other directly (NAT, firewall, etc.).
//
// Usage:
//
//	# Ensure a ZTLP relay is running on relay.example.com:23095
//
//	# Terminal 1: Register as listener through relay
//	go run . -relay relay.example.com:23095 -listen -key server.json
//
//	# Terminal 2: Connect to the listener through the same relay
//	go run . -relay relay.example.com:23095 -target <server-node-id> -key client.json
//
//	# Or run the in-process demo (starts a mock relay):
//	go run . -demo
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	ztlp "github.com/priceflex/ztlp/sdk/go"
)

func main() {
	relayAddr := flag.String("relay", "", "relay server address (host:port)")
	listen := flag.Bool("listen", false, "register as listener through relay")
	target := flag.String("target", "", "target NodeID to connect to through relay")
	keyFile := flag.String("key", "", "identity key file (generates ephemeral if empty)")
	demo := flag.Bool("demo", false, "run in-process relay demo")
	flag.Parse()

	if *demo {
		runRelayDemo()
		return
	}

	// Load or generate identity
	var identity *ztlp.Identity
	var err error
	if *keyFile != "" {
		identity, err = ztlp.LoadIdentity(*keyFile)
		if err != nil {
			log.Fatalf("Failed to load identity: %v", err)
		}
	} else {
		identity, err = ztlp.GenerateIdentity()
		if err != nil {
			log.Fatalf("Failed to generate identity: %v", err)
		}
		fmt.Printf("Generated ephemeral identity: %s\n", identity.NodeID)
	}

	if *relayAddr == "" {
		log.Fatal("--relay is required (or use --demo)")
	}

	if *listen {
		runRelayListener(*relayAddr, identity)
	} else if *target != "" {
		runRelayDialer(*relayAddr, identity, *target)
	} else {
		fmt.Println("Usage: go run . -demo  |  -relay <addr> -listen  |  -relay <addr> -target <nodeid>")
	}
}

func runRelayListener(relayAddr string, identity *ztlp.Identity) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Printf("Registering with relay %s (NodeID: %s)...\n", relayAddr, identity.NodeID)

	listener, err := ztlp.ListenRelay(relayAddr, identity)
	if err != nil {
		log.Fatalf("ListenRelay: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Registered with relay. Waiting for connections...\n")

	conn, err := listener.AcceptContext(ctx)
	if err != nil {
		log.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Accepted relayed connection from %s (SessionID: %s)\n",
		conn.PeerNodeID(), conn.SessionID())

	// Echo loop
	for {
		recvCtx, recvCancel := context.WithTimeout(context.Background(), 30*time.Second)
		msg, err := conn.RecvContext(recvCtx)
		recvCancel()
		if err != nil {
			log.Printf("Recv: %v", err)
			break
		}
		if msg != nil {
			fmt.Printf("Received: %s\n", msg)
			conn.Send(append([]byte("relay echo: "), msg...))
		}
	}
}

func runRelayDialer(relayAddr string, identity *ztlp.Identity, targetNodeID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	targetID, err := ztlp.ParseNodeID(targetNodeID)
	if err != nil {
		log.Fatalf("Invalid target NodeID: %v", err)
	}

	fmt.Printf("Connecting to %s via relay %s...\n", targetID, relayAddr)

	client, err := ztlp.DialRelayContext(ctx, relayAddr, identity, targetID)
	if err != nil {
		log.Fatalf("DialRelay: %v", err)
	}
	defer client.Close()

	fmt.Printf("Connected through relay! SessionID: %s\n", client.SessionID())

	// Send test messages
	messages := []string{"Hello through relay!", "ZTLP mesh routing works!", "Goodbye"}
	for _, msg := range messages {
		client.Send([]byte(msg))

		recvCtx, recvCancel := context.WithTimeout(context.Background(), 5*time.Second)
		reply, err := client.RecvContext(recvCtx)
		recvCancel()
		if err != nil {
			log.Printf("Recv: %v", err)
			break
		}
		fmt.Printf("Sent: %q → Reply: %q\n", msg, reply)
	}
}

func runRelayDemo() {
	fmt.Println("=== ZTLP Relay Connection Demo ===")
	fmt.Println()
	fmt.Println("This demo simulates two clients connecting through a relay.")
	fmt.Println("In production, the relay would be a separate ZTLP relay server.")
	fmt.Println()

	// Generate identities for both peers
	peerA, _ := ztlp.GenerateIdentity()
	peerB, _ := ztlp.GenerateIdentity()

	fmt.Printf("Peer A NodeID: %s\n", peerA.NodeID)
	fmt.Printf("Peer B NodeID: %s\n", peerB.NodeID)
	fmt.Println()

	// For the demo, we use a direct connection to simulate relay behavior.
	// In production, you'd use ztlp.DialRelay() with a real relay address.
	listener, err := ztlp.Listen("127.0.0.1:0", peerB)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Peer B listening on %s (simulating relay registration)\n\n", listener.Addr())

	var wg sync.WaitGroup
	var peerBConn *ztlp.Client

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		peerBConn, err = listener.AcceptContext(ctx)
		if err != nil {
			log.Printf("Accept: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	peerAConn, err := ztlp.DialContext(ctx, listener.Addr().String(), peerA)
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer peerAConn.Close()

	wg.Wait()
	if peerBConn == nil {
		log.Fatal("Peer B connection failed")
	}
	defer peerBConn.Close()

	fmt.Printf("✓ Connection established through relay!\n")
	fmt.Printf("  SessionID: %s\n\n", peerAConn.SessionID())

	// Bidirectional message exchange
	fmt.Println("Peer A → Peer B:")
	messages := []string{
		"Hello from peer A!",
		"This message is end-to-end encrypted",
		"Even the relay can't read it",
	}

	for _, msg := range messages {
		peerAConn.Send([]byte(msg))
		recvCtx, recvCancel := context.WithTimeout(context.Background(), 2*time.Second)
		received, _ := peerBConn.RecvContext(recvCtx)
		recvCancel()
		fmt.Printf("  %q → %q ✓\n", msg, received)
	}

	fmt.Println("\nPeer B → Peer A:")
	peerBConn.Send([]byte("Reply from peer B!"))
	recvCtx, recvCancel := context.WithTimeout(context.Background(), 2*time.Second)
	reply, _ := peerAConn.RecvContext(recvCtx)
	recvCancel()
	fmt.Printf("  %q → %q ✓\n", "Reply from peer B!", reply)

	fmt.Println("\n=== Relay demo complete ===")
}
