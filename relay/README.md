# ZTLP Relay

An Elixir/OTP implementation of a **Zero Trust Layer Protocol** relay node.

The relay forwards encrypted ZTLP packets between peers by SessionID. In classic
relay mode it never sees plaintext — it only routes packets based on the 96-bit
SessionID routing key. This is the Elixir companion to the [Rust ZTLP prototype](../proto/).

Important: the new iOS-first relay-side VIP architecture introduces a second relay role for selected iPhone traffic. In that mode, the relay terminates VIP TCP services on behalf of the iOS Network Extension to save 5-8 MB of NE memory. That proxied VIP path is not zero-plaintext at the relay, so the relay becomes part of the trusted computing base for those services. See `../docs/RELAY-VIP-ARCHITECTURE.md`.

## What It Does

ZTLP is an identity-first network overlay. When two nodes can't reach each other
directly, they communicate through a relay. The relay:

- Receives UDP packets from peers
- Runs a **three-layer admission pipeline** (magic check → SessionID lookup → HeaderAuthTag verification)
- Forwards packets to the other peer in the session
- In classic relay mode, never decrypts or inspects payload data
- In the iOS-first relay-side VIP design, can optionally terminate selected VIP TCP services for memory-constrained iPhone clients

## Architecture

### Two relay operating modes

1. Classic zero-trust relay mode
   - Relay forwards opaque ZTLP packets by SessionID
   - Relay has no application plaintext
   - This remains the default relay model for ordinary ZTLP traffic

2. iOS-first relay-side VIP mode
   - iPhone NE sends encrypted tunnel traffic to a selected relay
   - Relay decrypts the client tunnel payload, terminates selected VIP TCP services, and connects to the backend service
   - This exists specifically to move VIP proxy memory out of the iOS Network Extension
   - Recommended hardening is relay→backend TLS/mTLS

The iOS relay-side VIP design does not replace classic relay forwarding. It adds a specialized service-termination role for memory-constrained mobile clients.

```
ZtlpRelay.Application (Supervisor)
├── ZtlpRelay.Stats              — Pipeline counters (Agent)
├── ZtlpRelay.SessionRegistry    — ETS-backed session routing table
├── ZtlpRelay.SessionSupervisor  — DynamicSupervisor for Session GenServers
└── ZtlpRelay.UdpListener        — GenServer wrapping :gen_udp
```

### Three-Layer Admission Pipeline

| Layer | Check | Cost | Purpose |
|-------|-------|------|---------|
| 1 | Magic byte (0x5A37) | Nanoseconds, no crypto | Reject non-ZTLP UDP noise |
| 2 | SessionID lookup (ETS) | Microseconds, no crypto | Reject unknown sessions |
| 3 | HeaderAuthTag (ChaCha20-Poly1305) | Real crypto cost | Reject forged packets |

### Packet Format

**Handshake Header (95 bytes):**
```
<<magic::16, ver::4, hdr_len::12, flags::16, msg_type::8,
  crypto_suite::16, key_id::16, session_id::96,
  packet_seq::64, timestamp::64, src_node_id::128,
  dst_svc_id::128, policy_tag::32, ext_len::16,
  payload_len::16, header_auth_tag::128>>
```

**Compact Data Header (42 bytes):**
```
<<magic::16, ver::4, hdr_len::12, flags::16,
  session_id::96, packet_seq::64, header_auth_tag::128>>
```

Packet type discrimination uses the HdrLen field:
- HdrLen = 24 → Handshake header
- HdrLen = 11 → Compact data header

## Requirements

- Elixir 1.12+
- Erlang/OTP 24+

No external dependencies — uses only OTP and the Erlang `:crypto` module.

## Build

```bash
mix compile
```

## Run

```bash
# Start in interactive mode
iex -S mix

# Default port: 23095 (0x5A37)
# Configure via config/config.exs or at runtime:
#   Application.put_env(:ztlp_relay, :listen_port, 23095)
```

### Register a Session

Sessions are registered programmatically. In `iex`:

```elixir
# Register a session mapping SessionID to two peers
session_id = ZtlpRelay.Crypto.generate_session_id()
peer_a = {{192, 168, 1, 10}, 5000}
peer_b = {{192, 168, 1, 20}, 5000}

ZtlpRelay.SessionRegistry.register_session(session_id, peer_a, peer_b)

# Start a session GenServer for timeout tracking
{:ok, pid} = ZtlpRelay.SessionSupervisor.start_session(
  session_id: session_id,
  peer_a: peer_a,
  peer_b: peer_b
)

ZtlpRelay.SessionRegistry.update_session_pid(session_id, pid)
```

Once registered, any ZTLP packet from peer A with that SessionID gets forwarded
to peer B, and vice versa.

### Check Stats

```elixir
ZtlpRelay.Stats.get_stats()
# => %{layer1_drops: 0, layer2_drops: 0, layer3_drops: 0, passed: 42, forwarded: 42}
```

## Test

```bash
mix test
```

Tests cover:
- **Packet parsing/serialization** — Both header types, all message types, malformed data
- **Pipeline admission** — Each layer independently, counter tracking
- **Session registry** — Register, lookup, lookup_peer, unregister, concurrent access
- **Session GenServer** — Lifecycle, timeout behavior, packet counting
- **UDP listener** — Bind, receive, forward via loopback
- **Integration** — Full flow: register session → send packet → verify forwarding

## Configuration

### Additional requirements for iOS relay-side VIP

The relay-side VIP path needs configuration beyond ordinary SessionID forwarding:

- service routing table (`service name -> backend address`)
- health and load reporting suitable for NS-published relay records
- region metadata for relay selection
- relay→backend TLS/mTLS where possible
- failover-aware behavior so iOS clients can reselect a different relay cleanly

See `../docs/RELAY-VIP-ARCHITECTURE.md` for the full design.

In `config/config.exs`:

```elixir
config :ztlp_relay,
  listen_port: 23095,        # UDP port (0x5A37)
  listen_address: {0, 0, 0, 0},  # Bind to all interfaces
  session_timeout_ms: 300_000,    # 5 minute inactivity timeout
  max_sessions: 10_000            # Maximum concurrent sessions
```

## Relay Mesh

The relay supports multi-relay mesh networking via consistent hashing and
inter-relay communication. Multiple relay nodes form a mesh to distribute
sessions across the cluster for scalability and fault tolerance.

### Architecture

```
                    ┌──────────────┐
       ┌──────────►│   Relay A    │◄──────────┐
       │           │  (Ingress)   │           │
       │           └──────┬───────┘           │
       │                  │                    │
  RELAY_HELLO        RELAY_FORWARD        RELAY_HELLO
       │                  │                    │
       │           ┌──────▼───────┐           │
       ├──────────►│   Relay B    │◄──────────┤
       │           │  (Transit)   │           │
       │           └──────┬───────┘           │
       │                  │                    │
       │           ┌──────▼───────┐           │
       └──────────►│   Relay C    │◄──────────┘
                   │  (Service)   │
                   └──────────────┘
```

**Key concepts:**

- **Consistent Hashing (HashRing):** Sessions are assigned to relays using a
  consistent hash ring with 128 virtual nodes per relay. When a relay joins or
  leaves, only ~1/N sessions are remapped.

- **PathScore:** Routes are selected based on a composite score:
  `score = rtt_ms × (1 + loss_rate × 10) × (1 + load_factor × 2)`.
  Lower is better. RTT is tracked with an exponential moving average.

- **Relay Roles:**
  - `ingress` — Client-facing, handles HELLO authentication, issues RATs
  - `transit` — Accepts pre-authenticated traffic via RAT verification
  - `service` — Backend service endpoint
  - `all` — Performs all roles (default)

- **Relay Admission Tokens (RAT):** 93-byte HMAC-BLAKE2s signed tokens that
  prove a node has been authenticated by an ingress relay. Supports session
  scoping, key rotation, and 5-minute TTL.

### Mesh Protocol Wire Format

All inter-relay messages share a common header:
```
<<msg_type::8, sender_node_id::binary-16, timestamp::64, ...payload>>
```

| Type | Code | Payload | Purpose |
|------|------|---------|---------|
| RELAY_HELLO | 0x01 | ip(4), port(2), role(1), capabilities(4) | Mesh discovery |
| RELAY_HELLO_ACK | 0x02 | ip(4), port(2), role(1), capabilities(4) | Discovery response |
| RELAY_PING | 0x03 | (none) | Health probe |
| RELAY_PONG | 0x04 | active_sessions(4), max_sessions(4), uptime(4) | Metrics response |
| RELAY_FORWARD | 0x05 | length(4), inner_packet(variable) | Packet forwarding |
| RELAY_SESSION_SYNC | 0x06 | session_id(12), peer_a(6), peer_b(6) | Session migration |
| RELAY_LEAVE | 0x07 | (none) | Graceful departure |

### Configuration

Additional config for mesh operations:

```elixir
config :ztlp_relay,
  # Relay identity
  relay_node_id: <<...16 bytes...>>,  # Auto-generated if unset

  # RAT signing
  rat_secret: <<...32 bytes...>>,           # Auto-generated if unset
  rat_secret_previous: nil,                 # For key rotation
  rat_ttl_seconds: 300,                     # RAT lifetime (5 min)

  # Ingress rate limits
  ingress_rate_limit_per_ip: 10,            # Max HELLOs/min per IP
  ingress_rate_limit_per_node: 5,           # Max HELLOs/min per NodeID

  # Admission challenge
  sac_load_threshold: 0.7                   # Fraction of max_sessions
```

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `ZTLP_RELAY_RAT_SECRET` | Hex-encoded 32-byte RAT signing key | Auto-generated |
| `ZTLP_RELAY_RAT_SECRET_PREVIOUS` | Previous key for rotation | None |
| `ZTLP_RELAY_RAT_TTL_SECONDS` | RAT lifetime in seconds | 300 |

### Run the Demo

```bash
cd relay && mix run mesh_demo.exs
```

Starts 3 local relay nodes, forms a mesh, demonstrates consistent hash routing,
simulates a relay failure with rebalancing, and prints forwarding stats.

### Run Mesh Integration Tests

```bash
cd relay && mix test test/ztlp_relay/mesh_integration_test.exs --trace
```

Tests cover mesh formation, consistent hash routing, failover, PathScore
selection, admission token flow, rate limiting, session sync, and graceful
departure.

### Run Mesh Benchmark

```bash
cd relay && mix run mesh_bench.exs
```

Measures ops/sec for hash ring lookup, PathScore computation, inter-relay
message encode/decode, end-to-end forwarding, and RAT issue/verify.

## Project Structure

```
ztlp_relay/
├── mix.exs
├── mesh_demo.exs             # Interactive mesh demo script
├── mesh_bench.exs            # Mesh performance benchmark
├── config/
│   ├── config.exs            # Shared configuration
│   ├── dev.exs               # Dev overrides
│   ├── test.exs              # Test overrides (port 0 for random)
│   └── prod.exs              # Production configuration
├── lib/
│   ├── ztlp_relay.ex         # Module constants
│   └── ztlp_relay/
│       ├── application.ex    # OTP Application + supervision tree
│       ├── admission_token.ex # RAT signing/verification (HMAC-BLAKE2s)
│       ├── config.ex         # Runtime configuration helpers
│       ├── crypto.ex         # ChaCha20-Poly1305 AEAD (HeaderAuthTag)
│       ├── hash_ring.ex      # Consistent hash ring (128 vnodes/node)
│       ├── ingress.ex        # Ingress admission handler
│       ├── inter_relay.ex    # Inter-relay protocol encode/decode
│       ├── packet.ex         # Binary packet parsing/serialization
│       ├── path_score.ex     # Composite route scoring
│       ├── pipeline.ex       # Three-layer admission pipeline
│       ├── rate_limiter.ex   # ETS-based sliding window rate limiter
│       ├── relay_registry.ex # ETS-backed known relay registry
│       ├── session.ex        # GenServer per active session
│       ├── session_registry.ex    # ETS routing table
│       ├── session_supervisor.ex  # DynamicSupervisor for sessions
│       ├── stats.ex          # Pipeline counters
│       ├── transit.ex        # Transit relay handler
│       └── udp_listener.ex   # GenServer wrapping :gen_udp
├── test/
│   ├── test_helper.exs
│   └── ztlp_relay/
│       ├── admission_token_test.exs
│       ├── hash_ring_test.exs
│       ├── ingress_test.exs
│       ├── integration_test.exs
│       ├── mesh_integration_test.exs  # Multi-relay mesh tests
│       ├── packet_test.exs
│       ├── path_score_test.exs
│       ├── pipeline_test.exs
│       ├── rate_limiter_test.exs
│       ├── relay_registry_test.exs
│       ├── session_registry_test.exs
│       ├── session_test.exs
│       └── udp_listener_test.exs
└── README.md
```

## How Relay Forwarding Works

1. **Session registration:** Both peers are registered with the relay via `SessionRegistry.register_session/3`
2. **Packet arrival:** UDP packet arrives at the relay
3. **Pipeline admission:** Magic check → SessionID lookup → (optional) AuthTag verification
4. **Peer lookup:** Given the SessionID and the sender's address, find the *other* peer's address
5. **Forward:** Send the raw packet unchanged to the other peer via `:gen_udp.send`

The relay is a "dumb pipe" — it routes by SessionID without understanding the
Noise handshake or decrypting any payload. This is the zero-trust property:
even the relay infrastructure can't read the data.
