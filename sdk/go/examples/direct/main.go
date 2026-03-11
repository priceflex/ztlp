// Example: Direct peer-to-peer ZTLP connection.
//
// This example demonstrates both a listener and a dialer connecting
// directly without a relay, performing a Noise_XX handshake, and
// exchanging encrypted messages.
//
// Usage (run in separate terminals or use the in-process demo):
//
//	# Terminal 1: Listen
//	go run . -listen -bind 127.0.0.1:23095 -key server.json
//
//	# Terminal 2: Connect
//	go run . -connect 127.0.0.1:23095 -key client.json
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
	listen := flag.Bool("listen", false, "run as listener")
	connect := flag.String("connect", "", "connect to address")
	bind := flag.String("bind", "127.0.0.1:23095", "bind address for listener")
	keyFile := flag.String("key", "", "identity key file (generates ephemeral if empty)")
	demo := flag.Bool("demo", false, "run in-process demo (both sides)")
	flag.Parse()

	if *demo {
		runDemo()
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

	if *listen {
		runListener(*bind, identity)
	} else if *connect != "" {
		runDialer(*connect, identity)
	} else {
		fmt.Println("Usage: go run . -demo  |  -listen  |  -connect <addr>")
	}
}

func runListener(bind string, identity *ztlp.Identity) {
	listener, err := ztlp.Listen(bind, identity)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Listening on %s (NodeID: %s)\n", listener.Addr(), identity.NodeID)

	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	fmt.Printf("Accepted connection from %s (SessionID: %s)\n", conn.PeerNodeID(), conn.SessionID())

	// Echo loop
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		msg, err := conn.RecvContext(ctx)
		cancel()
		if err != nil {
			log.Printf("Recv: %v", err)
			break
		}
		if msg != nil {
			fmt.Printf("Received: %s\n", msg)
			// Echo back
			conn.Send(append([]byte("echo: "), msg...))
		}
	}
}

func runDialer(addr string, identity *ztlp.Identity) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Printf("Connecting to %s...\n", addr)
	client, err := ztlp.DialContext(ctx, addr, identity)
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	fmt.Printf("Connected! SessionID: %s, Peer: %s\n", client.SessionID(), client.PeerNodeID())

	// Send a test message
	client.Send([]byte("hello from Go SDK!"))

	recvCtx, recvCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer recvCancel()

	reply, err := client.RecvContext(recvCtx)
	if err != nil {
		log.Printf("Recv: %v", err)
	} else if reply != nil {
		fmt.Printf("Reply: %s\n", reply)
	}
}

func runDemo() {
	fmt.Println("=== ZTLP Direct Connection Demo ===")
	fmt.Println()

	serverID, _ := ztlp.GenerateIdentity()
	clientID, _ := ztlp.GenerateIdentity()

	fmt.Printf("Server NodeID: %s\n", serverID.NodeID)
	fmt.Printf("Client NodeID: %s\n", clientID.NodeID)

	listener, err := ztlp.Listen("127.0.0.1:0", serverID)
	if err != nil {
		log.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	fmt.Printf("Server listening on %s\n\n", listener.Addr())

	var wg sync.WaitGroup
	var serverConn *ztlp.Client

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serverConn, err = listener.AcceptContext(ctx)
		if err != nil {
			log.Printf("Accept: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := ztlp.DialContext(ctx, listener.Addr().String(), clientID)
	if err != nil {
		log.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	wg.Wait()
	if serverConn == nil {
		log.Fatal("server connection failed")
	}
	defer serverConn.Close()

	fmt.Printf("✓ Handshake complete!\n")
	fmt.Printf("  SessionID: %s\n", client.SessionID())
	fmt.Printf("  Client sees peer: %s\n", client.PeerNodeID())
	fmt.Printf("  Server sees peer: %s\n\n", serverConn.PeerNodeID())

	// Exchange messages
	messages := []string{"Hello, ZTLP!", "Encrypted message", "Final test"}
	for _, msg := range messages {
		client.Send([]byte(msg))
		recvCtx, recvCancel := context.WithTimeout(context.Background(), 2*time.Second)
		received, _ := serverConn.RecvContext(recvCtx)
		recvCancel()
		fmt.Printf("  Client → Server: %q → %q ✓\n", msg, received)
	}

	fmt.Println("\n=== Demo complete ===")
}
