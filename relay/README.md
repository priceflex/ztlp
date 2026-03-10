# ZTLP Relay

An Elixir/OTP implementation of a **Zero Trust Layer Protocol** relay node.

The relay forwards encrypted ZTLP packets between peers by SessionID. It never
sees plaintext — it only routes packets based on the 96-bit SessionID routing
key. This is the Elixir companion to the [Rust ZTLP prototype](../proto/).

## What It Does

ZTLP is an identity-first network overlay. When two nodes can't reach each other
directly, they communicate through a relay. The relay:

- Receives UDP packets from peers
- Runs a **three-layer admission pipeline** (magic check → SessionID lookup → HeaderAuthTag verification)
- Forwards packets to the other peer in the session
- Never decrypts or inspects payload data

## Architecture

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

In `config/config.exs`:

```elixir
config :ztlp_relay,
  listen_port: 23095,        # UDP port (0x5A37)
  listen_address: {0, 0, 0, 0},  # Bind to all interfaces
  session_timeout_ms: 300_000,    # 5 minute inactivity timeout
  max_sessions: 10_000            # Maximum concurrent sessions
```

## Project Structure

```
ztlp_relay/
├── mix.exs
├── config/
│   ├── config.exs           # Shared configuration
│   ├── dev.exs              # Dev overrides
│   ├── test.exs             # Test overrides (port 0 for random)
│   └── prod.exs             # Production configuration
├── lib/
│   ├── ztlp_relay.ex        # Module constants
│   └── ztlp_relay/
│       ├── application.ex   # OTP Application + supervision tree
│       ├── config.ex        # Runtime configuration helpers
│       ├── crypto.ex        # ChaCha20-Poly1305 AEAD (HeaderAuthTag)
│       ├── packet.ex        # Binary packet parsing/serialization
│       ├── pipeline.ex      # Three-layer admission pipeline
│       ├── session.ex       # GenServer per active session
│       ├── session_registry.ex    # ETS routing table
│       ├── session_supervisor.ex  # DynamicSupervisor for sessions
│       ├── stats.ex         # Pipeline counters
│       └── udp_listener.ex  # GenServer wrapping :gen_udp
├── test/
│   ├── test_helper.exs
│   └── ztlp_relay/
│       ├── integration_test.exs
│       ├── packet_test.exs
│       ├── pipeline_test.exs
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
