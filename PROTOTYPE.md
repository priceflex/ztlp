# ZTLP Prototype — Developer Guide

Complete guide to building, running, and understanding the ZTLP reference
implementation. This document covers all five phases: Rust client, Elixir relay,
eBPF/XDP filter, ZTLP-NS namespace, and the ZTLP Gateway.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Phase 1: Rust Client (ztlp-proto)](#phase-1-rust-client)
4. [Phase 2: Elixir Relay (ztlp-relay)](#phase-2-elixir-relay)
5. [Running the Demos](#running-the-demos)
6. [Cross-Language Interop](#cross-language-interop)
7. [How It All Works](#how-it-all-works)
8. [Test Coverage](#test-coverage)
9. [Troubleshooting](#troubleshooting)
10. [Roadmap](#roadmap)

---

## Architecture Overview

```
                    ZTLP Network Architecture

┌──────────────┐                              ┌──────────────┐
│   Node A     │                              │   Node B     │
│ (Rust client)│                              │ (Rust client)│
│              │        ┌──────────────┐      │              │
│  Identity    │        │    Relay     │      │  Identity    │
│  Noise_XX    │◀──────▶│(Elixir/OTP) │◀────▶│  Noise_XX    │
│  Pipeline    │   UDP  │             │  UDP │  Pipeline    │
│  Transport   │        │  Session    │      │  Transport   │
└──────────────┘        │  Registry   │      └──────────────┘
                        │  Pipeline   │
                        │  Forwarding │
                        └──────────────┘

        Direct mode:  Node A ◀───UDP───▶ Node B
        Relay mode:   Node A ◀──▶ Relay ◀──▶ Node B
```

### Language Choices

| Component | Language | Rationale |
|-----------|----------|-----------|
| **Client nodes** | Rust | Performance, safety, small binary size |
| **Relays / Gateways** | Erlang/Elixir | BEAM VM concurrency, fault tolerance, hot code upgrades |
| **eBPF packet filter** | C | Required for XDP/eBPF (Phase 3, planned) |

### Packet Format

ZTLP uses two header formats — a full handshake header (95 bytes) for
connection establishment and a compact data header (42 bytes) for the
encrypted data fast-path:

```
Handshake Header (95 bytes):
┌────────┬─────┬────────┬───────┬─────────┬─────────────┬────────┐
│ Magic  │V|HL │ Flags  │MsgTyp │CryptoSte│  KeyID      │        │
│ 0x5A37 │4|12 │  16b   │  8b   │  16b    │  16b        │        │
├────────┴─────┴────────┴───────┴─────────┴─────────────┤        │
│                   SessionID (96 bits)                  │        │
├────────────────────────────────────────────────────────┤        │
│                  PacketSeq (64 bits)                   │ 95     │
├────────────────────────────────────────────────────────┤ bytes  │
│                  Timestamp (64 bits)                   │        │
├────────────────────────────────────────────────────────┤        │
│                  SrcNodeID (128 bits)                  │        │
├────────────────────────────────────────────────────────┤        │
│                  DstSvcID (128 bits)                   │        │
├────────────────────────────────────────────────────────┤        │
│  PolicyTag (32b)  │ ExtLen (16b) │ PayloadLen (16b)   │        │
├────────────────────────────────────────────────────────┤        │
│              HeaderAuthTag (128 bits)                  │        │
└────────────────────────────────────────────────────────┘

Compact Data Header (42 bytes):
┌────────┬─────┬────────┐
│ Magic  │V|HL │ Flags  │
│ 0x5A37 │4|12 │  16b   │
├────────┴─────┴────────┤
│  SessionID (96 bits)  │  42 bytes
├───────────────────────┤
│ PacketSequence (64b)  │
├───────────────────────┤
│ HeaderAuthTag (128b)  │
└───────────────────────┘
```

Packet type discrimination uses the **HdrLen field** (12 bits):
- HdrLen = 24 (words) → Handshake header (95 bytes)
- HdrLen = 11 (words) → Compact data header (42 bytes)

### Three-Layer Admission Pipeline

Both the Rust client and Elixir relay implement the same pipeline:

```
Inbound UDP Packet
        │
        ▼
┌─────────────────────┐
│ Layer 1: Magic      │  Cost: nanoseconds (2-byte compare)
│ Is it 0x5A37?       │  Kills: all non-ZTLP UDP noise
└────────┬────────────┘
         │ pass
         ▼
┌─────────────────────┐
│ Layer 2: SessionID  │  Cost: microseconds (hash map/ETS lookup)
│ Known session?      │  Kills: scanners, stale sessions, probes
└────────┬────────────┘
         │ pass
         ▼
┌─────────────────────┐
│ Layer 3: AuthTag    │  Cost: real crypto (ChaCha20-Poly1305)
│ Valid AEAD tag?     │  Kills: forged/tampered packets
└────────┬────────────┘
         │ pass
         ▼
   ✓ Decrypt & deliver
```

Each layer is orders of magnitude cheaper than the next. Under DDoS, the
vast majority of attack traffic dies at Layer 1 or 2, never reaching the
expensive cryptographic check.

---

## Prerequisites

### For the Rust Client (Phase 1)

**Operating System:** Linux (Ubuntu 22.04+), macOS, or Windows with WSL2.

**Install Rust:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Verify
rustc --version   # 1.70+ required, 1.94+ recommended
cargo --version
```

No C libraries needed — all crypto is pure Rust.

### For the Elixir Relay (Phase 2)

**Install Erlang/OTP 24+ and Elixir 1.12+:**

On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y erlang-base erlang-dev elixir

# Verify
erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().' -noshell
# Should print "24" or higher

elixir --version
# Should show Elixir 1.12+
```

On macOS (Homebrew):
```bash
brew install erlang elixir

# Verify
elixir --version
```

With asdf:
```bash
asdf plugin add erlang
asdf plugin add elixir
asdf install erlang 24.3.4
asdf install elixir 1.14.5-otp-24
```

No external Elixir dependencies — uses only OTP and Erlang's `:crypto` module.

---

## Phase 1: Rust Client

**Location:** `proto/`

### Build

```bash
cd ztlp-proto
cargo build            # Debug build (~2 min first time, ~1 sec after)
cargo build --release  # Optimized build
```

### Run the Direct Demo (two nodes on LAN)

```bash
cargo run --bin ztlp-demo
```

This demonstrates:
1. Identity generation (128-bit NodeIDs + X25519 keypairs)
2. Noise_XX mutual authentication handshake
3. Encrypted data exchange (ChaCha20-Poly1305)
4. Pipeline rejection — garbage, wrong SessionID, and forged auth tag packets all get dropped at the cheapest possible layer

### Run the Relay Demo (two nodes through a relay)

```bash
cargo run --bin ztlp-relay-demo
```

This demonstrates:
1. A simulated relay running on localhost
2. Noise_XX handshake routed through the relay
3. Encrypted bidirectional data exchange through the relay
4. Proof that the relay never sees plaintext (zero-trust relay)

### Run Tests

```bash
cargo test                           # All 91 tests
cargo test -- --nocapture            # With output visible
cargo test --test integration_tests  # Just integration tests
cargo test --test edge_case_tests    # Just edge case tests
cargo test --test relay_tests        # Just relay tests
cargo test test_replay_window        # Tests matching a pattern
```

### Project Structure

```
proto/
├── src/
│   ├── lib.rs           # Crate root — module re-exports
│   ├── identity.rs      # NodeID generation, X25519/Ed25519 keypair, JSON persistence
│   ├── packet.rs        # Wire format: handshake header (95 bytes) + data header (42 bytes)
│   │                      Bit-level packing (4-bit version + 12-bit HdrLen share a u16)
│   │                      Serialize/deserialize, flag helpers, AAD extraction
│   ├── pipeline.rs      # Three-layer admission: magic → SessionID → HeaderAuthTag
│   │                      HdrLen-based packet type discrimination
│   │                      Per-layer drop counters
│   ├── session.rs       # Session state: directional keys, sequence counters, replay window
│   │                      Anti-replay bitmap (64-packet window, extensible to 1024)
│   ├── handshake.rs     # Noise_XX handshake via `snow` crate
│   │                      Three-message mutual auth with perfect forward secrecy
│   │                      Key derivation: BLAKE2s-256 over sorted static keys + labels
│   │                      Directional keys: I→R and R→I are separate
│   ├── transport.rs     # Async UDP (Tokio): send/recv with pipeline integration
│   │                      send_data: encrypt + HeaderAuthTag + serialize + send
│   │                      recv_data: receive + pipeline check + decrypt
│   │                      send_data_via_relay: same packet format, relay destination
│   ├── relay.rs         # RelayConnection (client state) + SimulatedRelay (demo/test)
│   │                      SessionID extraction using HdrLen discrimination
│   │                      Peer pairing: pending → paired on second peer's first packet
│   └── error.rs         # Typed errors for all modules
├── src/bin/
│   ├── ztlp-demo.rs     # Two-node direct demo
│   ├── ztlp-relay-demo.rs  # Two-node relay demo
│   └── ztlp-node.rs     # Standalone node binary (listen/connect modes)
└── tests/
    ├── packet_tests.rs      # 10 tests: serialization round-trips, bit packing, magic
    ├── pipeline_tests.rs    # 12 tests: each layer independently, counters, session CRUD
    ├── handshake_tests.rs   # 5 tests: full Noise_XX, payload, PFS, early finalize
    ├── edge_case_tests.rs   # 37 tests: boundaries, replay window (10K packets),
    │                          key direction, HdrLen discrimination, auth tag properties,
    │                          bulk uniqueness (10K IDs)
    ├── integration_tests.rs # 9 tests: end-to-end over real UDP, bidirectional,
    │                          sequential messages, empty/large payloads, rejection
    └── relay_tests.rs       # 11 tests: RELAY_HOP flag, relay pairing/forwarding,
                               end-to-end encrypted data through relay
```

### Key Design Decisions

1. **HdrLen-based packet discrimination** — not packet size. A data packet
   with a large payload exceeds 95 bytes, which would be misidentified as a
   handshake header if using size-based heuristics. HdrLen is always reliable.

2. **BLAKE2s-256 key derivation** — not Rust's `DefaultHasher`. Session keys
   are derived by hashing sorted static public keys with directional labels.
   BLAKE2s is deterministic, crypto-grade, and fast.

3. **Separate send/recv keys** — directional isolation. Initiator→Responder
   and Responder→Initiator use different keys. The initiator's `send_key`
   equals the responder's `recv_key` and vice versa.

4. **Replay window** — bitmap-based anti-replay with a 64-packet default
   window. Out-of-order packets within the window are accepted; duplicates
   and packets older than the window are rejected.

5. **`#![deny(unsafe_code)]`** — no unsafe blocks anywhere. All crypto
   uses audited RustCrypto crates.

---

## Phase 2: Elixir Relay

**Location:** `relay/`

### Build

```bash
cd ztlp-relay
mix deps.get   # (no external deps, but initializes the project)
mix compile
```

### Run

```bash
# Interactive shell (recommended for exploration)
iex -S mix

# In iex — register a session:
session_id = ZtlpRelay.Crypto.generate_session_id()
peer_a = {{192, 168, 1, 10}, 5000}
peer_b = {{192, 168, 1, 20}, 5000}
ZtlpRelay.SessionRegistry.register_session(session_id, peer_a, peer_b)

# Start a session GenServer for timeout tracking:
{:ok, pid} = ZtlpRelay.SessionSupervisor.start_session(
  session_id: session_id, peer_a: peer_a, peer_b: peer_b
)
ZtlpRelay.SessionRegistry.update_session_pid(session_id, pid)

# Check stats:
ZtlpRelay.Stats.get_stats()
```

Default listen port: **23095** (0x5A37). Configure in `config/config.exs`.

### Run Tests

```bash
mix test                                        # All 73 tests
mix test test/ztlp_relay/packet_test.exs       # Just packet tests
mix test test/ztlp_relay/integration_test.exs  # Just integration tests
```

### Project Structure

```
relay/
├── lib/
│   ├── ztlp_relay.ex               # Module constants (magic, version)
│   └── ztlp_relay/
│       ├── application.ex           # OTP Application + supervision tree
│       │   Supervision tree:
│       │     Stats → SessionRegistry → SessionSupervisor → UdpListener
│       │   Start order ensures dependencies are ready before the listener.
│       │
│       ├── packet.ex                # Binary pattern matching packet parser
│       │   Elixir's binary syntax shines here — the entire handshake header
│       │   is parsed in a single pattern match clause. Includes fast-path
│       │   extractors (extract_session_id, extract_aad, extract_auth_tag)
│       │   for pipeline use without full parsing.
│       │
│       ├── pipeline.ex              # Three-layer admission pipeline
│       │   Layer 1: Packet.valid_magic?/1 — single 16-bit compare
│       │   Layer 2: SessionRegistry.session_exists?/1 — ETS :member lookup
│       │   Layer 3: Crypto.verify_header_auth_tag/3 — ChaCha20-Poly1305
│       │   In relay mode, Layer 3 is skipped (session_key = nil) since the
│       │   relay doesn't hold session keys.
│       │
│       ├── session_registry.ex      # ETS-backed routing table
│       │   :named_table, :set, :public with read_concurrency + write_concurrency
│       │   Key function: lookup_peer/2 — given SessionID + sender addr, returns
│       │   the OTHER peer's addr. This is the core relay routing lookup.
│       │
│       ├── session.ex               # GenServer per active session
│       │   Tracks packet count, last activity, handles inactivity timeout.
│       │   On timeout: unregisters from ETS and stops (cleanup in terminate/2).
│       │   Timer is reset on every :forward cast.
│       │
│       ├── session_supervisor.ex    # DynamicSupervisor (:one_for_one)
│       │   Crashed sessions don't affect others. Each session process is
│       │   independent — the BEAM's supervision model maps perfectly to
│       │   ZTLP's session isolation requirements.
│       │
│       ├── udp_listener.ex          # GenServer wrapping :gen_udp (active mode)
│       │   Receives {:udp, socket, ip, port, data} messages.
│       │   Pipeline → lookup_peer → :gen_udp.send to other peer.
│       │   HELLO/HELLO_ACK are logged but not yet auto-registering.
│       │
│       ├── crypto.ex                # ChaCha20-Poly1305 via Erlang :crypto
│       │   "MAC-only" AEAD: encrypts empty plaintext, AAD is the header bytes
│       │   minus the auth tag. Produces a 16-byte Poly1305 tag.
│       │   Uses :crypto.crypto_one_time_aead/6 (encrypt) and /7 (verify).
│       │
│       ├── stats.ex                 # Agent-based pipeline counters
│       │   layer1_drops, layer2_drops, layer3_drops, passed, forwarded
│       │
│       └── config.ex                # Runtime config with defaults
│           listen_port: 23095, session_timeout_ms: 300_000, max_sessions: 10_000
│
└── test/
    ├── ztlp_relay/
    │   ├── packet_test.exs           # Parse/serialize both headers, all msg types,
    │   │                               malformed data, extract_session_id fast path
    │   ├── pipeline_test.exs         # Each layer independently, counter tracking,
    │   │                               HELLO/HELLO_ACK passthrough
    │   ├── session_registry_test.exs # Register, lookup, lookup_peer, unregister,
    │   │                               concurrent access, count
    │   ├── session_test.exs          # GenServer lifecycle, forward increments count,
    │   │                               close stops + unregisters, timeout behavior,
    │   │                               forward resets timeout
    │   ├── udp_listener_test.exs     # Bind, receive, HELLO handling, garbage rejection
    │   └── integration_test.exs      # Full flow: bidirectional forwarding, 5 concurrent
    │                                   sessions, crypto roundtrip, handshake roundtrip,
    │                                   unknown peer rejection
    └── test_helper.exs
```

### Key Design Decisions

1. **ETS for session lookups** — public table with `read_concurrency: true`.
   Layer 2 calls `:ets.member/2` which is O(1) and lock-free for reads.
   This is critical for relay throughput under load.

2. **GenServer per session** — maps ZTLP sessions 1:1 to BEAM processes.
   Each session has independent state, timeout timer, and crash isolation.
   The BEAM can handle millions of lightweight processes.

3. **Pipeline Layer 3 skipped in relay mode** — the relay doesn't hold
   session keys (zero-trust property). Pass `nil` as the session key to
   `Pipeline.process/2` and Layer 3 is bypassed.

4. **:gen_udp in active mode** — the listener receives packets as Erlang
   messages. This integrates naturally with GenServer's message loop and
   lets the BEAM scheduler handle backpressure.

5. **No external dependencies** — uses only OTP and Erlang's `:crypto`.
   This keeps the relay lightweight, auditable, and easy to deploy.

---

## Running the Demos

### Demo 1: Direct Communication (Phase 1)

Two Rust nodes on localhost, handshake + encrypted data:

```bash
cd ztlp-proto
cargo run --bin ztlp-demo
```

**What you'll see:**
- Node identity generation (128-bit NodeIDs)
- Noise_XX three-message handshake
- Encrypted data: "Hello from ZTLP!" sent and decrypted
- Pipeline drops: garbage (L1), wrong SessionID (L2), bad auth tag (L3)
- Drop counters per layer

### Demo 2: Relay Communication (Phase 1 + simulated relay)

Two Rust nodes communicating through a simulated relay:

```bash
cd ztlp-proto
cargo run --bin ztlp-relay-demo
```

**What you'll see:**
- Simulated relay on localhost
- Noise_XX handshake routed through the relay
- Encrypted data exchange (bidirectional) through the relay
- Proof that the relay never sees plaintext

### Demo 3: Elixir Relay (Phase 2)

Start the Elixir relay and interact via IEx:

```bash
cd ztlp-relay
iex -S mix
```

```elixir
# The relay is already listening on port 23095 (or random in test config)
port = ZtlpRelay.UdpListener.get_port()

# Register a test session
sid = ZtlpRelay.Crypto.generate_session_id()
ZtlpRelay.SessionRegistry.register_session(sid, {{127,0,0,1}, 5000}, {{127,0,0,1}, 5001})

# Check it's registered
ZtlpRelay.SessionRegistry.session_exists?(sid)
# => true

# Look up routing
ZtlpRelay.SessionRegistry.lookup_peer(sid, {{127,0,0,1}, 5000})
# => {:ok, {{127,0,0,1}, 5001}}

# Check pipeline stats after sending some traffic
ZtlpRelay.Stats.get_stats()
```

---

## Cross-Language Interop

The Rust client and Elixir relay speak the same wire protocol. The packet
format is identical — both implement the exact same bit-level layout from
the ZTLP spec.

**What the Elixir relay needs from Rust clients:**
- Packets with valid magic (`0x5A37`) and correct HdrLen
- SessionID registered in the relay's ETS table
- That's it — the relay is a "dumb pipe" that forwards by SessionID

**What Rust clients need from the Elixir relay:**
- UDP forwarding to the right peer
- The relay's address (configured at startup or discovered via ZTLP-NS in Phase 4)

To connect them in production:
1. Start the Elixir relay: `cd ztlp-relay && MIX_ENV=prod iex -S mix`
2. Register sessions via the relay's API or future auto-registration
3. Point Rust clients at the relay's address
4. Handshake and data flow transparently through the relay

---

## How It All Works

### Connection Flow (Direct)

```
Node A                                     Node B
  │                                           │
  │── 1. HELLO (ephemeral key) ─────────────▶│  Noise_XX message 1
  │                                           │
  │◀── 2. HELLO_ACK (eph + encrypted id) ───│  Noise_XX message 2
  │                                           │
  │── 3. CONFIRM (encrypted identity) ──────▶│  Noise_XX message 3
  │                                           │
  │  Session established:                     │
  │  • SessionID assigned (96-bit random)     │
  │  • Directional keys derived (BLAKE2s)     │
  │  • Anti-replay window initialized         │
  │  • Session registered in pipeline         │
  │                                           │
  │◀════ encrypted data (compact header) ═══▶│  42-byte header + AEAD payload
```

### Connection Flow (Relay)

```
Node A                Relay               Node B
  │                     │                     │
  │── HELLO ──────────▶│── HELLO ──────────▶│  Relay forwards handshake
  │                     │                     │
  │◀── HELLO_ACK ──────│◀── HELLO_ACK ──────│  Relay forwards response
  │                     │                     │
  │── CONFIRM ────────▶│── CONFIRM ────────▶│  Relay forwards final msg
  │                     │                     │
  │  Session keys derived (end-to-end)       │
  │  Relay has NO keys — just SessionID      │
  │                     │                     │
  │══ encrypted data ═▶│══ forward ════════▶│  Relay routes by SessionID
  │◀═ encrypted data ══│◀═ forward ════════│  Never decrypts payload
```

### Pipeline Processing (per packet)

```
1. Raw UDP bytes arrive at socket
2. Layer 1: Read bytes[0..2], compare to 0x5A37
   → Fail: increment L1 counter, drop
3. Layer 2: Read HdrLen to find SessionID offset, lookup in HashMap/ETS
   → Fail: increment L2 counter, drop
4. Layer 3: Extract AAD (header minus auth tag), verify ChaCha20-Poly1305
   → Fail: increment L3 counter, drop
5. Parse full header, decrypt payload with session keys
6. Deliver to application
```

### Key Derivation

After Noise_XX handshake completes, session keys are derived:

```
shared_material = sort(public_key_A, public_key_B)
i2r_key = BLAKE2s(shared_material || "ztlp_initiator_to_responder" || session_id)
r2i_key = BLAKE2s(shared_material || "ztlp_responder_to_initiator" || session_id)

Initiator: send_key = i2r_key, recv_key = r2i_key
Responder: send_key = r2i_key, recv_key = i2r_key
```

Public keys are sorted lexicographically before hashing so both sides
produce identical material regardless of role.

---

## Test Coverage

### Rust Client — 91 tests

| Suite | Tests | Description |
|-------|-------|-------------|
| Unit (inline) | 7 | NodeID/identity generation, replay window |
| packet_tests | 10 | Serialize/deserialize, bit packing, magic, all msg types |
| pipeline_tests | 12 | Each layer, counters, session CRUD, HELLO passthrough |
| handshake_tests | 5 | Full Noise_XX, payload, PFS, early finalize |
| edge_case_tests | 37 | Boundaries (u64::MAX, zero), replay (10K packets), key direction, HdrLen, auth tag, bulk IDs (10K) |
| integration_tests | 9 | End-to-end UDP: A→B, B→A, sequential, empty/8KB payloads, rejection |
| relay_tests | 11 | RELAY_HOP flag, relay pairing, forwarding, encrypted E2E through relay |

### Elixir Relay — 73 tests

| Suite | Tests | Description |
|-------|-------|-------------|
| packet_test | ~15 | Parse/serialize, all msg types, malformed data, fast extractors |
| pipeline_test | ~10 | Each layer, counters, HELLO/HELLO_ACK passthrough |
| session_registry_test | ~10 | Register, lookup, lookup_peer, unregister, concurrent, count |
| session_test | ~8 | GenServer lifecycle, forward count, close, timeout, timer reset |
| udp_listener_test | ~8 | Bind, receive, HELLO handling, garbage rejection |
| integration_test | ~22 | Bidirectional forwarding, 5 concurrent sessions, crypto roundtrip, handshake roundtrip, unknown peer rejection |

### ZTLP-NS Namespace — 105 tests

| Suite | Tests | Description |
|-------|-------|-------------|
| crypto_test | 10 | Keypair gen, sign/verify, tampered message/sig, empty/large, pubkey derivation |
| record_test | 28 | Type mapping, serialize/deserialize all 6 types, signing, wire encode/decode, expiration, constructors |
| zone_test | 8 | Zone creation, parent_name extraction, contains? membership |
| zone_authority_test | 9 | Generate, sign records, reject out-of-zone, delegation, verify_record |
| store_test | 17 | Insert, reject unsigned/stale, lookup, revocation, expiration, clear |
| trust_anchor_test | 7 | Add/remove/clear anchors, trusted? checks |
| query_test | 8 | Simple lookup, trust chain verification, revocation blocking, resolve_all |
| bootstrap_test | 5 | Verify response, hardcoded fallback, discover sequence |
| integration_test | 13 | Full trust chain (3 levels), revocation blocks valid chain, UDP round-trip, NXDOMAIN, malformed query |

### ZTLP Gateway — 97 tests

| Suite | Tests | Description |
|-------|-------|-------------|
| crypto_test | 22 | X25519 DH, ChaCha20-Poly1305, BLAKE2s, HMAC, HKDF, Ed25519 |
| handshake_test | 11 | Full Noise_XX, key agreement, PFS, error handling, tampered messages |
| packet_test | 21 | Parse/serialize data+handshake, magic, types, round-trips, edge cases |
| pipeline_test | 5 | Layer 1+2 admission, HELLO, unknown sessions |
| session_registry_test | 6 | Register, lookup, double-register, auto-cleanup on death |
| policy_engine_test | 10 | Allow :all, exact match, wildcards, deny, rule management |
| backend_test | 4 | TCP echo, multi-cycle, close notification, connect failure |
| integration_test | 18 | Full crypto pipeline, packet wrapping, policy+identity, audit log |

**Combined: 366 tests (91 Rust + 73 Elixir relay + 105 Elixir NS + 97 Gateway), 0 failures.**

---

## Troubleshooting

### Rust

**`cargo build` fails on first run:**
Likely missing Rust toolchain. Run `rustup update stable` and retry.

**Tests timeout on CI:**
Integration tests use real UDP sockets on localhost. Ensure no firewall rules
block loopback UDP. The tests use ephemeral ports (port 0).

**Demo shows "failed to receive/decrypt":**
Check that no other process is binding the same ports. The demos use random
ports via `127.0.0.1:0`.

### Elixir

**`mix compile` warns about Elixir version:**
ZTLP Relay requires Elixir 1.12+ and OTP 24+. Check with `elixir --version`.

**`:crypto` errors:**
Ensure `erlang-crypto` is installed (`sudo apt install erlang-crypto` on
Ubuntu). OTP 24+ includes ChaCha20-Poly1305 support.

**Port 23095 already in use:**
Configure a different port in `config/config.exs` or use port 0 for testing.

**Session timeout in tests:**
Some tests use 100-200ms timeouts. On slow CI, increase timeout values in
the test file.

---

## Roadmap

| Phase | Component | Language | Status |
|-------|-----------|----------|--------|
| **1** | Client prototype | Rust | ✅ **Complete** (91 tests) |
| **2** | Relay node | Elixir/OTP | ✅ **Complete** (73 tests) |
| **3** | eBPF/XDP packet filter | C | ✅ **Complete** |
| **4** | ZTLP-NS trust namespace | Elixir/OTP | ✅ **Complete** (105 tests) |
| **5** | Gateway (ZTLP ↔ legacy) | Elixir/OTP | ✅ **Complete** (97 tests) |

---

## License

Apache License 2.0. All Rust dependencies are MIT or Apache-2.0.
Elixir relay, ZTLP-NS, and Gateway have zero external dependencies (OTP only).
No GPL code in any component.
