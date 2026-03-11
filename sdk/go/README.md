# ZTLP Go SDK

The **Zero Trust Layer Protocol (ZTLP)** SDK provides a pure Go implementation of the ZTLP client stack,
compatible with the reference Rust implementation.

## Features

- **Native Go implementation** – no C dependencies.
- **Noise_XX** handshake using `github.com/flynn/noise` (compatible with Rust `snow`).
- **Exact wire format** – handshake and data headers match the Rust `packet.rs` layout.
- **Three‑layer admission pipeline** (magic check, session lookup, header‑auth verification).
- **Anti‑replay protection** with a sliding bitmap window.
- **Relay support** – send/receive through a ZTLP relay server using the same packet format.
- **Full test suite** – `go test ./...` covers packet round‑trip, handshake, session handling, pipeline logic, RAT handling, and relay client.
- **High‑level client API** – `Dial`, `DialRelay`, `Listen`, `Send`, `Recv`.
- **Examples** – key generation, direct connection, relay connection.

## Quick Start

```bash
# Build the SDK (module path matches the repository layout)
cd ztlp/sdk/go
go mod tidy   # fetch dependencies

go test ./...   # run the full test suite
```

### Generate an identity

```bash
go run ./examples/keygen/main.go -o my_identity.json
```

### Direct connection

```bash
# Terminal 1 (listener)
go run ./examples/direct/main.go -listen -bind 127.0.0.1:23095 -key server.json

# Terminal 2 (dialer)
go run ./examples/direct/main.go -connect 127.0.0.1:23095 -key client.json
```

### Relay connection (requires a running ZTLP relay server)

```bash
go run ./examples/relay/main.go -relay relay.example.com:23095
```

## API Overview

```go
import ztlp "github.com/priceflex/ztlp/sdk/go"

// Generate identity
id, _ := ztlp.GenerateIdentity()

// Direct connection
client, _ := ztlp.Dial("192.168.1.1:23095", id)
client.Send([]byte("hello"))
msg, _ := client.Recv()

// Relay connection
relayClient, _ := ztlp.DialRelay("relay.example.com:23095", id, targetNodeID)
relayClient.Send([]byte("via relay"))
msg, _ := relayClient.Recv()
```

## License

MIT – see `LICENSE`.
