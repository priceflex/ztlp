# ZTLP Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/priceflex/ztlp/sdk/go.svg)](https://pkg.go.dev/github.com/priceflex/ztlp/sdk/go)
[![CI](https://github.com/priceflex/ztlp/actions/workflows/ci.yml/badge.svg)](https://github.com/priceflex/ztlp/actions/workflows/ci.yml)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://go.dev)

Pure Go implementation of the **Zero Trust Layer Protocol** client stack, wire-compatible with the reference Rust implementation and Elixir relay/gateway infrastructure.

## Features

| Feature | Description |
|---------|-------------|
| **Noise_XX Handshake** | Full Noise_XX_25519_ChaChaPoly_BLAKE2s — interoperable with Rust `snow` crate |
| **Three-Layer Pipeline** | Magic check → SessionID lookup → HeaderAuthTag AEAD verification |
| **Anti-Replay** | Sliding bitmap window rejects duplicate sequence numbers |
| **Relay Support** | Route through ZTLP relay servers using the same wire format |
| **RAT Admission** | Issue, parse, verify Relay Admission Tokens (HMAC-BLAKE2s, RFC 2104) |
| **Context Support** | All blocking operations accept `context.Context` for cancellation/timeouts |
| **Zero CGO** | Pure Go — no C dependencies, cross-compiles everywhere Go does |

**78 tests** across 9 source files. All wire formats are byte-identical to the Rust reference.

## Installation

```bash
go get github.com/priceflex/ztlp/sdk/go
```

Requires **Go 1.22+**.

## Quick Start

### Generate an identity

```go
id, err := ztlp.GenerateIdentity()
// id.NodeID   — 128-bit cryptographic node identifier
// id.Static   — X25519 keypair for Noise handshake
// id.Signing  — Ed25519 keypair for NS registration & RATs
```

Or from the CLI:

```bash
go run ./examples/keygen/main.go -o my_identity.json
```

### Direct connection

```go
import ztlp "github.com/priceflex/ztlp/sdk/go"

// Server
listener, _ := ztlp.Listen(":23095", serverIdentity)
conn, _ := listener.Accept()  // Blocks until Noise_XX completes
msg, _ := conn.Recv()
conn.Send([]byte("pong"))

// Client
client, _ := ztlp.Dial("192.168.1.1:23095", clientIdentity)
defer client.Close()
client.Send([]byte("ping"))
reply, _ := client.Recv()
```

### Relay connection

```go
// Route through a relay — relay forwards by SessionID, never sees plaintext
client, _ := ztlp.DialRelay("relay.example.com:23095", identity, targetNodeID)
client.Send([]byte("via relay"))
```

### Relay Admission Tokens

```go
// Issue a token (relay side)
secret := [32]byte{ /* relay's HMAC key */ }
token := ztlp.IssueRAT(nodeID, relayID, sessionScope, 300, &secret)
wire := token.Serialize()  // 93 bytes, send to client

// Verify a token (relay side)
parsed, _ := ztlp.ParseRAT(wire[:])
if parsed.Verify(&secret) && !parsed.IsExpired() {
    // Admit the session
}

// Attach to handshake (client side)
ext := &ztlp.HandshakeExtension{Token: token}
```

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
├──────────────────────────────────────────────────────────┤
│                    Admission (RAT)                         │
│  HMAC-BLAKE2s tokens for relay mesh admission             │
└──────────────────────────────────────────────────────────┘
```

## Package Structure

```
sdk/go/
├── ztlp.go            # Constants, types, errors (protocol-level)
├── identity.go        # NodeID + X25519/Ed25519 key generation & serialization
├── packet.go          # Wire format: handshake (95B) & data (42B) headers
├── handshake.go       # Noise_XX initiator & responder state machines
├── session.go         # Per-session state, CipherState, anti-replay bitmap
├── pipeline.go        # Three-layer admission pipeline (magic → session → AEAD)
├── transport.go       # UDP transport with send/recv helpers
├── relay.go           # Relay-aware packet construction
├── admission.go       # Relay Admission Tokens (RAT) — HMAC-BLAKE2s
├── client.go          # High-level Client & Listener API
├── *_test.go          # 78 tests covering all of the above
└── examples/
    ├── keygen/        # Generate identity to JSON file
    ├── direct/        # Direct peer-to-peer connection demo
    └── relay/         # Relay-routed connection demo
```

## Wire Compatibility

The Go SDK produces byte-identical packets to the Rust reference implementation:

| Field | Handshake | Data |
|-------|-----------|------|
| Magic | `0x5A37` | `0x5A37` |
| Header size | 95 bytes (HdrLen=24) | 42 bytes (HdrLen=11) |
| Crypto suite | `0x0001` (ChaCha20-Poly1305 + Noise_XX) | — |
| SessionID | 12 bytes | 12 bytes |
| AuthTag | 16 bytes (AEAD over header) | 16 bytes |
| Noise pattern | `Noise_XX_25519_ChaChaPoly_BLAKE2s` | — |

The HMAC-BLAKE2s implementation for RATs follows RFC 2104 and is cross-verified against the Rust and Elixir implementations.

## Examples

Run the included examples:

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

```bash
cd sdk/go
go test ./... -v
```

All 78 tests cover: packet round-trip serialization, Noise_XX handshake state machine, session management, pipeline admission logic, anti-replay bitmap, RAT issue/parse/verify, relay client, and transport layer.

## Dependencies

Only two direct dependencies (no CGO, no system libraries):

- [`github.com/flynn/noise`](https://github.com/flynn/noise) — Noise Protocol Framework
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) — BLAKE2s, Curve25519, Ed25519

## Compatibility

| Component | Version | Status |
|-----------|---------|--------|
| Rust client (`proto/`) | v0.5.1 | ✅ Wire-compatible |
| Elixir relay (`relay/`) | v0.5.1 | ✅ Session routing verified |
| Elixir gateway (`gateway/`) | v0.5.1 | ✅ Handshake + data path |
| RAT tokens (Rust + Elixir) | v0.5.1 | ✅ Cross-language binary verified |

## License

Apache 2.0 — see [LICENSE](../../LICENSE).
