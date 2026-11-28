# Go Client SDK

**Pure Go implementation** of the ZTLP client stack — wire-compatible with the reference Rust implementation and Elixir relay/gateway infrastructure.

[![Go 1.22+](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://go.dev)

---

## Why Go?

The reference Rust client is high-performance but heavyweight for some environments. The Go SDK provides:

- **Simple deployment** — single static binary, no runtime dependencies
- **Cross-compilation** — build for any OS/arch from any machine
- **Zero CGO** — pure Go, no C toolchain needed
- **Familiar API** — `Dial()`, `Listen()`, `Accept()` patterns Go developers already know
- **Full protocol coverage** — Noise_XX handshake, three-layer pipeline, anti-replay, RATs

## Installation

```bash
go get github.com/priceflex/ztlp/sdk/go
```

## Quick Start

### Generate an Identity

```go
import ztlp "github.com/priceflex/ztlp/sdk/go"

id, err := ztlp.GenerateIdentity()
// id.NodeID   — 128-bit cryptographic node identifier
// id.Static   — X25519 keypair for Noise handshake
// id.Signing  — Ed25519 keypair for NS registration & RATs
```

### Connect to a Peer

```go
client, err := ztlp.Dial("192.168.1.1:23095", identity)
defer client.Close()

client.Send([]byte("hello"))
msg, err := client.Recv()
```

### Listen for Connections

```go
listener, err := ztlp.Listen(":23095", serverIdentity)
conn, err := listener.Accept()  // Blocks until Noise_XX completes
msg, err := conn.Recv()
conn.Send([]byte("pong"))
```

### Relay Routing

Route through a relay server — the relay forwards packets by SessionID and never sees plaintext:

```go
client, err := ztlp.DialRelay("relay.example.com:23095", identity, targetNodeID)
client.Send([]byte("via relay"))
```

## Relay Admission Tokens (RATs)

The Go SDK supports the full RAT lifecycle — issue, serialize, parse, and verify admission tokens:

```go
// Issue a token (relay side)
secret := [32]byte{ /* relay's HMAC key */ }
token := ztlp.IssueRAT(nodeID, relayID, sessionScope, 300, &secret)
wire := token.Serialize()  // 93 bytes

// Verify (relay side)
parsed, _ := ztlp.ParseRAT(wire[:])
if parsed.Verify(&secret) && !parsed.IsExpired() {
    // Admit the session
}

// Attach to handshake (client side)
ext := &ztlp.HandshakeExtension{Token: token}
```

RAT HMAC-BLAKE2s follows RFC 2104 and is cross-verified against the Rust and Elixir implementations.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Client / Listener                      │
│  Dial() / Listen() / Accept() — high-level API           │
├──────────────────────────────────────────────────────────┤
│                    Handshake Layer                         │
│  Noise_XX initiator/responder — 3-message exchange        │
├──────────────────────────────────────────────────────────┤
│                    Session Layer                          │
│  Per-session state: CipherState pair, anti-replay bitmap  │
├──────────────────────────────────────────────────────────┤
│                    Pipeline Layer                          │
│  L1: Magic (0x5A37) → L2: SessionID → L3: AuthTag AEAD   │
├──────────────────────────────────────────────────────────┤
│                    Packet Layer                            │
│  Serialize/parse handshake (95B) and data (42B) headers   │
├──────────────────────────────────────────────────────────┤
│                    Transport Layer                         │
│  UDP socket, send/recv, GSO support                       │
└──────────────────────────────────────────────────────────┘
```

## Wire Compatibility

All wire formats are byte-identical to the Rust reference:

| Field | Handshake | Data |
|-------|-----------|------|
| Magic | `0x5A37` | `0x5A37` |
| Header size | 95 bytes (HdrLen=24) | 42 bytes (HdrLen=11) |
| Crypto suite | `0x0001` | — |
| SessionID | 12 bytes | 12 bytes |
| AuthTag | 16 bytes | 16 bytes |
| Noise pattern | `Noise_XX_25519_ChaChaPoly_BLAKE2s` | — |

## Examples

Three runnable examples are included in `sdk/go/examples/`:

```bash
# Generate identities
go run ./examples/keygen/main.go -o server.json
go run ./examples/keygen/main.go -o client.json

# Direct connection (two terminals)
go run ./examples/direct/main.go -listen -bind 127.0.0.1:23095 -key server.json
go run ./examples/direct/main.go -connect 127.0.0.1:23095 -key client.json

# Relay connection (requires running ZTLP relay)
go run ./examples/relay/main.go -relay relay.example.com:23095
```

## Testing

**78 tests** covering packet round-trip, Noise_XX handshake, session management, pipeline admission, anti-replay, RAT lifecycle, relay client, and transport.

```bash
cd sdk/go
go test ./... -v
```

## Dependencies

Only two direct dependencies — no CGO, no system libraries:

- [`github.com/flynn/noise`](https://github.com/flynn/noise) — Noise Protocol Framework
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — BLAKE2s, Curve25519, Ed25519

## Interoperability

| Component | Status |
|-----------|--------|
| Rust client (`proto/`) | ✅ Wire-compatible |
| Elixir relay (`relay/`) | ✅ Session routing verified |
| Elixir gateway (`gateway/`) | ✅ Handshake + data path |
| RAT tokens (all languages) | ✅ Cross-language verified |

---

Full source: [`sdk/go/`](https://github.com/priceflex/ztlp/tree/main/sdk/go)
