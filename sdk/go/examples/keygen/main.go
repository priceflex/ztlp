// Example: Generate a ZTLP identity with X25519 keypair.
//
// Usage:
//
//	go run . [-o identity.json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	ztlp "github.com/priceflex/ztlp/sdk/go"
)

func main() {
	output := flag.String("o", "", "output file path (prints to stdout if omitted)")
	flag.Parse()

	id, err := ztlp.GenerateIdentity()
	if err != nil {
		log.Fatalf("Failed to generate identity: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Generated ZTLP identity:\n")
	fmt.Fprintf(os.Stderr, "  NodeID:     %s\n", id.NodeID)
	fmt.Fprintf(os.Stderr, "  Public Key: %x\n", id.StaticPublicKey)

	if *output != "" {
		if err := id.Save(*output); err != nil {
			log.Fatalf("Failed to save identity: %v", err)
		}
		fmt.Fprintf(os.Stderr, "  Saved to:   %s\n", *output)
	} else {
		data, _ := json.MarshalIndent(struct {
			NodeID           string `json:"node_id"`
			StaticPrivateKey string `json:"static_private_key"`
			StaticPublicKey  string `json:"static_public_key"`
		}{
			NodeID:           id.NodeID.String(),
			StaticPrivateKey: fmt.Sprintf("%x", id.StaticPrivateKey),
			StaticPublicKey:  fmt.Sprintf("%x", id.StaticPublicKey),
		}, "", "  ")
		fmt.Println(string(data))
	}
}
