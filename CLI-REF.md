# CLI Reference

The `ztlp` binary is a unified command-line interface for the entire protocol stack — identity generation, encrypted connections, relay routing, namespace queries, gateway bridging, packet inspection, and diagnostics.

> Full reference with all flags and examples: [`CLI.md`](https://github.com/priceflex/ztlp/blob/main/CLI.md)

## Installation

### From Release Binaries

Download pre-built binaries from [GitHub Releases](https://github.com/priceflex/ztlp/releases) for:
- Linux (x86_64, ARM64)
- macOS (Intel, Apple Silicon)
- Windows (x86_64)

### Build from Source

```bash
cd proto
cargo build --release --bin ztlp
# Binary: target/release/ztlp
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `ztlp keygen` | Generate a new ZTLP identity (X25519 + Ed25519 key pairs) |
| `ztlp connect` | Connect to a peer — performs Noise_XX handshake, opens encrypted session |
| `ztlp listen` | Listen for incoming ZTLP connections, optional TCP forwarding (`-L`) |
| `ztlp relay` | Start a relay server (session routing by SessionID) |
| `ztlp ns` | Query, register, and manage ZTLP-NS namespace records |
| `ztlp gateway` | Start a ZTLP↔TCP gateway (bidirectional bridge) |
| `ztlp inspect` | Decode and display ZTLP packets (hex, file, or stdin) |
| `ztlp ping` | Measure round-trip latency to a ZTLP peer |
| `ztlp status` | Show status of the local ZTLP node |

## Quick Start

```bash
# Generate an identity
ztlp keygen --output ~/.ztlp/identity.json

# Start a listener with SSH forwarding
ztlp listen --key ~/.ztlp/identity.json --bind 0.0.0.0:23095 \
  --forward 127.0.0.1:22

# Connect from another machine (opens local tunnel)
ztlp connect server.example.com:23095 --key ~/.ztlp/identity.json \
  -L 2222:127.0.0.1:22

# SSH through the ZTLP tunnel
ssh -p 2222 user@127.0.0.1
```

## Configuration

Optional config file at `~/.ztlp/config.toml`:

```toml
identity = "~/.ztlp/identity.json"
gateway = "gateway.example.com:23095"
relay = "relay.example.com:23095"
ns_server = "127.0.0.1:5353"
bind = "0.0.0.0:23095"
```

All config values can be overridden by CLI flags. Verbosity is controlled with `-v` (info), `-vv` (debug), `-vvv` (trace), or the `RUST_LOG` environment variable.

## Identity Management

```bash
# Generate identity
ztlp keygen --output server.json
ztlp keygen --output client.json --name "Alice"

# View identity details
cat server.json | jq '.node_id, .public_key'
```

Identities contain:
- **NodeID** — 128-bit random identifier (NOT derived from public key)
- **X25519 keypair** — Noise_XX handshake
- **Ed25519 keypair** — signing (NS records, RATs)

## Namespace Operations

```bash
# Register a name
ztlp ns register --name myhost.tunnel.ztlp --zone tunnel.ztlp \
  --key identity.json --address 10.0.0.1:23095 --ns-server 127.0.0.1:5353

# Lookup a name
ztlp ns lookup myhost.tunnel.ztlp --ns-server 127.0.0.1:5353

# List all records in a zone
ztlp ns list --zone tunnel.ztlp --ns-server 127.0.0.1:5353
```

## Packet Inspection

```bash
# Inspect a packet from hex
ztlp inspect --hex "5a3701001800..."

# Inspect from pcap (pipe from tcpdump)
tcpdump -X -c 1 udp port 23095 | ztlp inspect --stdin

# JSON output for scripting
ztlp inspect --hex "5a37..." --format json
```

## Relay Admission Tokens

```bash
# Inspect a token
ztlp token inspect --hex "01..."

# Verify a token
ztlp token verify --hex "01..." --secret-hex "abcd..."

# Issue a new token
ztlp token issue --node-id "..." --issuer-id "..." --ttl 300 --secret-hex "..."
```

## Testing Tools

Additional binaries are included in releases:

| Tool | Description |
|------|-------------|
| `ztlp-inspect` | Packet decoder — hex, file, or stdin with pretty/JSON/compact output |
| `ztlp-load` | Load generator — pipeline benchmarks (~1.1M pps locally), relay/gateway stress |
| `ztlp-fuzz` | Protocol fuzzer — 8 mutation strategies, 0 panics found in 50K iterations |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |
| 2 | Usage error (bad arguments) |

---

Full command reference with all flags: [`CLI.md`](https://github.com/priceflex/ztlp/blob/main/CLI.md)
