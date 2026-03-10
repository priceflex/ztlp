# ZTLP Proto — Zero Trust Layer Protocol Prototype

Phase 1 reference implementation of ZTLP in Rust. Demonstrates the core protocol:
mutual authentication via Noise_XX, encrypted session data exchange, and the
three-layer DDoS-resistant admission pipeline.

## What This Does

Two ZTLP nodes on a LAN:

1. **Generate cryptographic identities** (128-bit NodeID + X25519 keypair)
2. **Perform a Noise_XX handshake** (mutual authentication, perfect forward secrecy)
3. **Establish an encrypted session** (ChaCha20-Poly1305)
4. **Exchange encrypted data** — only authenticated, session-bearing packets get through
5. **Drop everything else** — the three-layer pipeline rejects unauthenticated traffic at the cheapest possible layer

```
   ┌────────────────────────────────────────┐
   │         Inbound ZTLP Packet            │
   └───────────────┬────────────────────────┘
                   ▼
   ┌────────────────────────────────────────┐
   │  Layer 1: Magic == 0x5A37?             │  ← nanoseconds, no crypto
   └───────────────┬────────────────────────┘
                   ▼
   ┌────────────────────────────────────────┐
   │  Layer 2: SessionID in allowlist?       │  ← microseconds, hash lookup
   └───────────────┬────────────────────────┘
                   ▼
   ┌────────────────────────────────────────┐
   │  Layer 3: HeaderAuthTag valid?          │  ← real crypto cost
   └───────────────┬────────────────────────┘
                   ▼
   ┌────────────────────────────────────────┐
   │  ✓ Decrypt payload + deliver           │
   └────────────────────────────────────────┘
```

---

## Prerequisites

### Operating System

Tested on Linux (Ubuntu 22.04+, Debian 12+). Also works on macOS and Windows (with WSL2).

### Install Rust

If you don't have Rust installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts (defaults are fine). Then either restart your terminal or run:

```bash
source "$HOME/.cargo/env"
```

Verify the installation:

```bash
rustc --version    # should show 1.70+ (tested with 1.94.0)
cargo --version
```

**Minimum Rust version:** 1.70.0 (2021 edition). Recommended: latest stable.

### System Dependencies

No system-level C libraries are required. All cryptographic primitives are pure Rust:

| Dependency | Purpose | License |
|---|---|---|
| `snow` 0.9 | Noise_XX handshake framework | Apache-2.0 |
| `chacha20poly1305` 0.10 | AEAD encryption (header auth + payload) | Apache-2.0 / MIT |
| `blake2` 0.10 | Key derivation (BLAKE2s-256) | Apache-2.0 / MIT |
| `tokio` 1.x | Async runtime + UDP sockets | MIT |
| `rand` 0.8 | Cryptographic random generation | Apache-2.0 / MIT |
| `clap` 4.x | CLI argument parsing | Apache-2.0 / MIT |
| `serde` / `serde_json` | Identity file (JSON) serialization | Apache-2.0 / MIT |
| `thiserror` | Error type derivation | Apache-2.0 / MIT |
| `tracing` | Structured logging | MIT |
| `hex` | Hex display helpers | Apache-2.0 / MIT |

All dependencies are MIT or Apache-2.0 — no GPL.

---

## Quick Start

### Clone and Build

```bash
git clone git@github.com:priceflex/ztlp.git
cd ztlp-proto    # if ztlp-proto is inside the ztlp repo
# OR if it's a standalone repo:
# git clone <ztlp-proto-url> && cd ztlp-proto

cargo build
```

First build downloads and compiles dependencies (~1-2 minutes). Subsequent builds are fast (~1 second).

### Run the Demo

```bash
cargo run --bin ztlp-demo
```

You'll see:

```
╔══════════════════════════════════════════════════════════════╗
║          ZTLP — Zero Trust Layer Protocol Demo              ║
║          Phase 1: Two-Node LAN Prototype                    ║
╚══════════════════════════════════════════════════════════════╝

━━━ Step 1: Generating node identities ━━━
  Node A: 61e25ff7e0b9514adfdff98d52e19ba9
  Node B: 8996acddabfb7be63632d2f58fcded64

━━━ Step 2: Binding UDP sockets ━━━
  Node A listening on 127.0.0.1:36722
  Node B listening on 127.0.0.1:39197

━━━ Step 3: Performing Noise_XX handshake ━━━
  → Message 1: Node A sends HELLO (ephemeral key)
  ✓ Node B received HELLO (127 bytes)
  ← Message 2: Node B sends HELLO_ACK (encrypted identity)
  ✓ Node A received HELLO_ACK (191 bytes)
  → Message 3: Node A sends final confirmation
  ✓ Node B received final confirmation (159 bytes)
  ✓ Noise_XX handshake complete — mutual authentication successful!

━━━ Step 4: Establishing encrypted session ━━━
  Session ID: e5072b2bbdb2ed4261e8b056
  ✓ Sessions registered in both pipelines

━━━ Step 5: Sending encrypted data ━━━
  Plaintext: "Hello from ZTLP! This message is encrypted and authenticated."
  → Node A sent encrypted data (61 bytes plaintext)
  ✓ Node B received: "Hello from ZTLP! This message is encrypted and authenticated."

━━━ Step 6: Testing pipeline — sending bad packets ━━━
  [Test 6a] Garbage packet → Dropped at Layer 1 (bad magic)
  [Test 6b] Fake SessionID → Dropped at Layer 2 (unknown session)
  [Test 6c] Bad auth tag   → Dropped at Layer 3 (invalid auth tag)

━━━ Step 7: Final Pipeline Statistics ━━━
  Layer 1 (Magic check):      1 dropped  — zero crypto cost
  Layer 2 (SessionID lookup):  1 dropped  — zero crypto cost
  Layer 3 (AuthTag verify):    1 dropped  — real crypto cost
  Passed all layers:           1
```

### Run the Relay Demo (through a simulated relay)

```bash
cargo run --bin ztlp-relay-demo
```

This demonstrates relay communication:
1. A simulated relay starts on localhost (UDP forwarder by SessionID)
2. Node A and Node B can only reach the relay (not each other directly)
3. Noise_XX handshake is performed through the relay
4. Encrypted data flows bidirectionally through the relay
5. The relay never sees plaintext — zero-trust relay property verified

### Run the Tests

```bash
# Run all 91 tests
cargo test

# Run with output visible
cargo test -- --nocapture

# Run a specific test file
cargo test --test integration_tests
cargo test --test edge_case_tests
cargo test --test packet_tests
cargo test --test pipeline_tests
cargo test --test handshake_tests

# Run a specific test by name
cargo test test_encrypted_data_a_to_b

# Run tests matching a pattern
cargo test replay_window
```

### Build for Release (optimized)

```bash
cargo build --release
```

Binaries are at `target/release/ztlp-demo` and `target/release/ztlp-node`.

---

## Project Structure

```
ztlp-proto/
├── Cargo.toml                 # Dependencies and project metadata
├── README.md                  # This file
├── src/
│   ├── lib.rs                 # Crate root — module re-exports
│   ├── identity.rs            # NodeID generation, X25519 keypair, JSON persistence
│   ├── packet.rs              # Wire format: handshake header (95 bytes) + data header (42 bytes)
│   ├── pipeline.rs            # Three-layer admission: magic → session → auth tag
│   ├── session.rs             # Session state: keys, sequence counters, anti-replay window
│   ├── handshake.rs           # Noise_XX mutual authentication (via snow crate)
│   ├── transport.rs           # Async UDP send/recv with pipeline integration + relay support
│   ├── relay.rs               # RelayConnection (client state) + SimulatedRelay (demo/test)
│   └── error.rs               # Error types for all modules
├── src/bin/
│   ├── ztlp-demo.rs           # Two-node direct demo (handshake + data + pipeline drops)
│   ├── ztlp-relay-demo.rs     # Two-node relay demo (handshake + data through relay)
│   └── ztlp-node.rs           # Standalone node binary (listen/connect modes)
└── tests/
    ├── integration_tests.rs   # End-to-end over real UDP sockets (9 tests)
    ├── edge_case_tests.rs     # Boundary conditions, replay, key direction (37 tests)
    ├── packet_tests.rs        # Packet serialization round-trips (10 tests)
    ├── pipeline_tests.rs      # Per-layer admission checks (12 tests)
    ├── handshake_tests.rs     # Noise_XX handshake protocol (5 tests)
    ├── relay_tests.rs         # Relay support: flags, forwarding, E2E (11 tests)
    + 7 unit tests inline in identity.rs and session.rs
    = 91 tests total
```

---

## Architecture

### Packet Format

Two header types per the ZTLP spec:

**Handshake/Control Header — 95 bytes:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Magic (0x5A37)        | Ver |       HdrLen            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Flags              |  MsgType  |   CryptoSuite     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     KeyID/TokenID             |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       SessionID (96 bits)     |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        PacketSeq (64 bits)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Timestamp (64 bits)                    |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       SrcNodeID (128 bits)                    |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       DstSvcID (128 bits)                     |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       PolicyTag (32 bits)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           ExtLen              |          PayloadLen           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    HeaderAuthTag (128 bits)                   |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Compact Data Header — 42 bytes (post-handshake fast path):**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Magic (0x5A37)        | Ver |       HdrLen            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Flags              |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       SessionID (96 bits)     |
|                                                               |
|               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |                                               |
+-+-+-+-+-+-+-+-+       PacketSequence (64 bits)                |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   HeaderAuthTag (128 bits)    |
|                                                               |
|                                                               |
|               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               |
+-+-+-+-+-+-+-+-+
```

### Three-Layer Pipeline

The admission pipeline kills traffic at the cheapest layer possible:

| Layer | Check | Cost | Kills |
|-------|-------|------|-------|
| 1 | Magic bytes `0x5A37` | Nanoseconds, 2-byte compare | All non-ZTLP UDP noise |
| 2 | SessionID in allowlist | Microseconds, hash map lookup | Scanners, stale sessions |
| 3 | HeaderAuthTag AEAD verify | Real crypto (ChaCha20-Poly1305) | Forged/tampered packets |

Only packets that survive all three layers get their payload decrypted.

### Noise_XX Handshake

Three-message mutual authentication with perfect forward secrecy:

```
Initiator (A)                         Responder (B)
     │                                     │
     │── HELLO (ephemeral key) ──────────▶│  Message 1
     │                                     │
     │◀── HELLO_ACK (eph + encrypted id) ─│  Message 2
     │                                     │
     │── CONFIRM (encrypted identity) ───▶│  Message 3
     │                                     │
     │     Session established             │
     │     ═══════════════════             │
     │◀─── encrypted data ───────────────▶│
```

After handshake: directional session keys derived via BLAKE2s-256 from sorted
static public keys + session-specific labels. Initiator→Responder and
Responder→Initiator use separate keys.

### Relay Support

The client supports relay communication — sending encrypted data through
an intermediary relay node that routes by SessionID. The relay never holds
session keys and cannot decrypt payload data (zero-trust property).

```
Node A ───encrypted──▶ Relay ───forward──▶ Node B
       ◀──encrypted───        ◀──forward───
```

Key components:
- **`send_data_via_relay()`** — same packet format as direct send, but
  addressed to the relay instead of the peer
- **`SimulatedRelay`** — a minimal relay for demos/tests that pairs peers
  by SessionID and forwards packets between them
- **`RELAY_HOP` flag** — indicates a packet has traversed a relay

The relay demo (`ztlp-relay-demo`) shows a full Noise_XX handshake and
encrypted data exchange routed entirely through a relay on localhost.

---

## Test Coverage

**91 tests** covering:

| Test Suite | Tests | What it covers |
|---|---|---|
| `packet_tests` | 10 | Header serialization round-trips, bit packing, magic validation, all message types |
| `pipeline_tests` | 12 | Each pipeline layer independently, counter tracking, session registration/removal |
| `handshake_tests` | 5 | Full Noise_XX exchange, payload in handshake, key uniqueness, early finalize rejection |
| `edge_case_tests` | 37 | Boundary values (u64::MAX, zero, all-ones), replay window stress (10K packets), key direction correctness, HdrLen discrimination, auth tag properties, bulk uniqueness (10K IDs) |
| `integration_tests` | 9 | End-to-end over real UDP: A→B, B→A, bidirectional, 10-message sequences, empty payload, 8KB payload, garbage/wrong-session rejection, identity save/reload |
| `relay_tests` | 11 | RELAY_HOP flag behavior, relay pairing/forwarding, end-to-end encrypted data through relay with bidirectional verification |
| Unit tests (inline) | 7 | NodeID/identity generation, replay window logic |

Run the full suite:

```bash
cargo test
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `RUST_LOG` | Log level filter | `ztlp_proto=info` |
| `RUST_BACKTRACE` | Show backtraces on panic | `0` |

Example with debug logging:

```bash
RUST_LOG=ztlp_proto=debug cargo run --bin ztlp-demo
```

### CLI Options (ztlp-node)

```bash
ztlp-node [OPTIONS]

Options:
  -l, --listen <ADDR>       Address to listen on [default: 0.0.0.0:23095]
  -i, --identity <FILE>     Path to identity JSON file (generates new if omitted)
  -c, --connect <ADDR>      Peer address to connect to (initiator mode)
  -h, --help                Print help
```

**Note:** `ztlp-node` currently implements the responder receive loop. Full
network handshake initiation is implemented in the demo binary; `ztlp-node`
will be extended in Phase 2.

---

## Identity Files

Identities are stored as JSON for the prototype:

```json
{
  "node_id": [61, 226, 95, 247, 224, 185, 81, 74, ...],
  "static_private_key": "a1b2c3d4...",
  "static_public_key": "e5f6a7b8..."
}
```

Generate and save an identity:

```bash
cargo run --bin ztlp-node -- --identity my_node.json --listen 127.0.0.1:0
# Ctrl+C after it prints the NodeID
```

Reuse it later:

```bash
cargo run --bin ztlp-node -- --identity my_node.json --listen 0.0.0.0:23095
```

---

## Development

### Code Quality

```bash
# Lint with Clippy
cargo clippy

# Format code
cargo fmt

# Check without building
cargo check

# Build docs
cargo doc --open
```

### Adding Tests

Tests live in `tests/` (integration) and inline in source files (unit).
Follow the existing patterns:

- `tests/packet_tests.rs` — serialization tests
- `tests/pipeline_tests.rs` — pipeline layer tests
- `tests/handshake_tests.rs` — protocol exchange tests
- `tests/edge_case_tests.rs` — boundaries and stress
- `tests/integration_tests.rs` — end-to-end over UDP

### Safety

The crate uses `#![deny(unsafe_code)]` — no `unsafe` blocks anywhere.
All cryptographic operations use audited Rust crates from the RustCrypto project.

---

## Roadmap

This is Phase 1 of the ZTLP implementation:

| Phase | Component | Language | Status |
|-------|-----------|----------|--------|
| **1** | **Client prototype** | **Rust** | **✅ Complete** |
| 2 | Relay / Gateway | Erlang/Elixir | Planned |
| 3 | eBPF/XDP packet filter | C | Planned |
| 4 | ZTLP-NS (trust namespace) | TBD | Planned |
| 5 | Gateway (ZTLP ↔ legacy bridge) | Erlang/Elixir | Planned |

---

## License

Apache License 2.0. See [LICENSE](../LICENSE) in the parent ZTLP repository.

All dependencies are MIT or Apache-2.0 licensed. No GPL dependencies.
