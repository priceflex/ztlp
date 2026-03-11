# ZTLP Go SDK

Go client library for the [Zero Trust Layer Protocol (ZTLP)](https://github.com/priceflex/ztlp).

## Installation

```bash
go get github.com/priceflex/ztlp/sdk/go
```

Requires Go 1.22+.

## Quick Start

### Generate an identity

```go
package main

import (
    "fmt"
    "log"

    ztlp "github.com/priceflex/ztlp/sdk/go"
)

func main() {
    id, err := ztlp.GenerateIdentity()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("NodeID: %s\n", id.NodeID)

    // Save for later
    if err := id.Save("my-identity.json"); err != nil {
        log.Fatal(err)
    }
}
```

### Direct peer-to-peer connection

```go
// Listener
listener, err := ztlp.Listen("0.0.0.0:23095", identity)
if err != nil {
    log.Fatal(err)
}
defer listener.Close()

conn, err := listener.Accept()
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

msg, _ := conn.Recv()
fmt.Printf("Received: %s\n", msg)
conn.Send([]byte("pong"))
```

```go
// Dialer
client, err := ztlp.Dial("192.168.1.1:23095", identity)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

client.Send([]byte("ping"))
reply, _ := client.Recv()
fmt.Printf("Reply: %s\n", reply)
```

### Connection through a relay

```go
targetNodeID, _ := ztlp.ParseNodeID("a1b2c3d4...")

client, err := ztlp.DialRelay("relay.example.com:23095", identity, targetNodeID)
if err != nil {
    log.Fatal(err)
}
defer client.Close()

client.Send([]byte("hello via relay"))
```

### With context (timeouts, cancellation)

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()

client, err := ztlp.DialContext(ctx, "192.168.1.1:23095", identity)
```

## Package Structure

| File | Description |
|------|-------------|
| `ztlp.go` | Top-level constants, types, version |
| `identity.go` | NodeID generation, X25519/Ed25519 keypairs, save/load |
| `packet.go` | ZTLP packet encoding/decoding (handshake + data headers) |
| `pipeline.go` | Three-layer admission (magic → session → auth tag) |
| `handshake.go` | Noise_XX mutual authentication (via flynn/noise) |
| `session.go` | Session state, anti-replay window, key derivation |
| `transport.go` | UDP transport, async send/receive |
| `relay.go` | Relay client (connect through ZTLP relay mesh) |
| `admission.go` | RAT (Relay Admission Token) parsing and verification |
| `client.go` | High-level Client API wrapping everything together |

## Wire Compatibility

This SDK is wire-compatible with the Rust ZTLP implementation (`proto/`). Key protocol details:

- **Magic**: `0x5A37` (big-endian)
- **Noise pattern**: `Noise_XX_25519_ChaChaPoly_BLAKE2s`
- **SessionID**: 12 bytes, cryptographically random
- **NodeID**: 16 bytes (128-bit), not derived from public key
- **Handshake header**: 95 bytes (HdrLen = 24)
- **Data header**: 42 bytes (HdrLen = 11)
- **Anti-replay**: 64-bit sliding window bitmap
- **Key derivation**: BLAKE2s
- **Auth tag**: ChaCha20-Poly1305 over header fields

## Dependencies

Minimal dependency footprint:

- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — Curve25519, ChaCha20-Poly1305, BLAKE2s, Ed25519
- [`github.com/flynn/noise`](https://github.com/flynn/noise) — Noise_XX handshake (used by WireGuard-go, well-maintained)
- Standard library for everything else

## Examples

| Example | Description |
|---------|-------------|
| [`examples/keygen`](examples/keygen/) | Generate and save ZTLP identity keys |
| [`examples/direct`](examples/direct/) | Direct peer-to-peer encrypted connection |
| [`examples/relay`](examples/relay/) | Connection through a ZTLP relay server |

Run examples:
```bash
cd examples/direct && go run . -demo
cd examples/relay && go run . -demo
```

## Testing

```bash
go test ./...
go test -race ./...  # data race detection
go test -v ./...     # verbose output
```

## API Reference

Full godoc: https://pkg.go.dev/github.com/priceflex/ztlp/sdk/go

### Key Types

```go
// Identity represents a ZTLP node identity (NodeID + keypairs).
type Identity struct {
    NodeID       NodeID
    X25519Public []byte  // 32 bytes — Noise handshake key
    Ed25519Public []byte // 32 bytes — signing key
}

// Client represents an established ZTLP connection.
type Client struct { ... }

// Listener accepts incoming ZTLP connections.
type Listener struct { ... }

// NodeID is a 128-bit node identifier.
type NodeID [16]byte

// SessionID is a 96-bit session identifier.
type SessionID [12]byte
```

### Key Functions

```go
func GenerateIdentity() (*Identity, error)
func LoadIdentity(path string) (*Identity, error)
func Dial(addr string, id *Identity) (*Client, error)
func DialContext(ctx context.Context, addr string, id *Identity) (*Client, error)
func DialRelay(relayAddr string, id *Identity, target NodeID) (*Client, error)
func DialRelayContext(ctx context.Context, relayAddr string, id *Identity, target NodeID) (*Client, error)
func Listen(addr string, id *Identity) (*Listener, error)
func ListenRelay(relayAddr string, id *Identity) (*Listener, error)
func ParseNodeID(hex string) (NodeID, error)
```

## License

Apache License 2.0. See [LICENSE](../../LICENSE).

ZTLP and Zero Trust Layer Protocol are trademarks of Steven Price.
