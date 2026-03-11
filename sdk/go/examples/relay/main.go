// Example: ZTLP connection through a relay.
//
// This example demonstrates two peers communicating via a relay server.
// It creates a RelayClient for each side, performs a handshake, and
// exchanges encrypted messages.
//
// Note: For a real network you would run a separate ZTLP relay binary
// (see the Rust implementation). Here we simply show how to use the
// SDK's RelayClient API to route traffic through a relay address.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	ztlp "github.com/priceflex/ztlp/sdk/go"
)

func main() {
	relayAddr := flag.String("relay", "127.0.0.1:23095", "relay UDP address")
	bindA := flag.String("bind-a", "127.0.0.1:0", "local bind address for peer A")
	bindB := flag.String("bind-b", "127.0.0.1:0", "local bind address for peer B")
	flag.Parse()

	// Generate identities for both peers
	identityA, _ := ztlp.GenerateIdentity()
	identityB, _ := ztlp.GenerateIdentity()

	// Perform handshake to obtain a shared SessionID and session state.
	// Both peers perform the handshake independently (in‑process).
	result, err := ztlp.PerformHandshake(identityA, identityB)
	if err != nil {
		log.Fatalf("handshake failed: %v", err)
	}

	// Create RelayClients for each side. They both use the same SessionID.
	aClient, err := ztlp.NewRelayClient(*bindA, *relayAddr, result.InitiatorSession)
	if err != nil {
		log.Fatalf("relay client A: %v", err)
	}
	defer aClient.Close()

	bClient, err := ztlp.NewRelayClient(*bindB, *relayAddr, result.ResponderSession)
	if err != nil {
		log.Fatalf("relay client B: %v", err)
	}
	defer bClient.Close()

	fmt.Printf("Relay address: %s\n", aClient.RelayAddr())
	fmt.Printf("Peer A local: %s  SessionID: %s\n", aClient.LocalAddr(), aClient.SessionID())
	fmt.Printf("Peer B local: %s  SessionID: %s\n\n", bClient.LocalAddr(), bClient.SessionID())

	// Exchange a couple of messages through the relay.
	msgFromA := []byte("hello from A via relay")
	if err := aClient.Send(msgFromA); err != nil {
		log.Fatalf("A send: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	msgFromB, err := bClient.Recv(ctx)
	if err != nil {
		log.Fatalf("B recv: %v", err)
	}
	fmt.Printf("B received: %s\n", msgFromB)

	// Now reply back
	msgFromB2 := []byte("reply from B")
	if err := bClient.Send(msgFromB2); err != nil {
		log.Fatalf("B send: %v", err)
	}

	msgFromA2, err := aClient.Recv(ctx)
	if err != nil {
		log.Fatalf("A recv: %v", err)
	}
	fmt.Printf("A received: %s\n", msgFromA2)
}
