# ZTLP Gateway — Identity-First Service Bridge

The ZTLP Gateway bridges between ZTLP's identity-first overlay network
and legacy TCP services. It terminates ZTLP sessions, verifies client
identity, enforces access policy, and forwards authorized traffic to
backend services over TCP.

Think of it as a reverse proxy, but instead of checking HTTP headers,
it verifies cryptographic identity through a Noise handshake before
any traffic reaches your backend.

## Architecture

```
                         ┌──────────────────────────┐
ZTLP Client ──UDP──►    │     ZTLP Gateway          │
                         │                           │
  Noise_XX handshake ──► │  1. Handshake (X25519 DH) │
  (mutual auth)          │  2. Identity check         │ ──TCP──► Backend
                         │  3. Policy enforcement     │          Service
  Encrypted data ──────► │  4. Decrypt (ChaCha20)     │
                         │  5. Forward plaintext      │
  ◄── Encrypted resp ─── │  6. Encrypt response       │ ◄──TCP── Backend
                         └──────────────────────────┘
```

### Key Difference: Gateway vs Relay

| | **Relay** | **Gateway** |
|---|---|---|
| **Has session keys?** | No — forwards opaque packets | Yes — terminates sessions |
| **Sees plaintext?** | Never | Yes — decrypts to forward |
| **Policy enforcement?** | None (zero-trust forwarding) | Full — checks identity |
| **Pipeline layers?** | Layer 1 + 2 only | Layer 1 + 2 + 3 |
| **Backend connection?** | None | TCP to services |

## Prerequisites

- Elixir 1.12+ with OTP 24+
- No external dependencies

## Quick Start

### Build

```bash
cd gateway/
mix compile
```

### Run Tests

```bash
mix test
# 97 tests, 0 failures
```

### Start the Gateway

```bash
# Interactive
iex -S mix

# Background
mix run --no-halt
```

## Configuration

### `config/config.exs`

```elixir
# UDP listen port
config :ztlp_gateway, :port, 23097

# Backend services
config :ztlp_gateway, :backends, [
  %{name: "web", host: {127, 0, 0, 1}, port: 8080},
  %{name: "ssh", host: {127, 0, 0, 1}, port: 22}
]

# Access policies
config :ztlp_gateway, :policies, [
  %{service: "web", allow: :all},
  %{service: "ssh", allow: ["admin.example.ztlp"]}
]

# Session idle timeout
config :ztlp_gateway, :session_timeout_ms, 300_000

# Maximum concurrent sessions
config :ztlp_gateway, :max_sessions, 10_000
```

## Policy Rules

### Allow All Authenticated Nodes

```elixir
%{service: "web", allow: :all}
```

Any node that completes the Noise handshake can access "web".

### Allow Specific Identities

```elixir
%{service: "ssh", allow: ["admin.example.ztlp", "ops.example.ztlp"]}
```

Only nodes with these exact identity names can access "ssh".

### Wildcard Zones

```elixir
%{service: "monitoring", allow: ["*.ops.ztlp"]}
```

Any node in the `ops.ztlp` zone (e.g., `node1.ops.ztlp`, `grafana.ops.ztlp`).

### Default Deny

Services without a policy rule deny all access. Zero trust.

## Cryptographic Protocol

Uses `Noise_XX_25519_ChaChaPoly_BLAKE2s`:

1. **X25519** — Elliptic-curve Diffie-Hellman key exchange
2. **ChaCha20-Poly1305** — AEAD encryption (32-byte key, 12-byte nonce)
3. **BLAKE2s** — Hashing for handshake transcript and HKDF

### Handshake Flow

```
Client                              Gateway
  │                                    │
  │── Message 1: → e ─────────────────►│  (client ephemeral key)
  │                                    │
  │◄── Message 2: ← e, ee, s, es ─────│  (gateway ephemeral + DH + encrypted static)
  │                                    │
  │── Message 3: → s, se ────────────►│  (client encrypted static + final DH)
  │                                    │
  │  Both derive i2r_key + r2i_key     │
  │══════════════════════════════════════│  Encrypted transport begins
```

After the handshake:
- **i2r_key** — client encrypts, gateway decrypts
- **r2i_key** — gateway encrypts, client decrypts

### Perfect Forward Secrecy

Each handshake generates fresh ephemeral keypairs. Compromising the
gateway's static key doesn't reveal past session traffic.

## Audit Logging

Every session event is recorded:

```elixir
# Session established
%{event: :session_established, session_id: <<...>>,
  remote_static: <<...>>, source: {{127,0,0,1}, 12345},
  service: "web", wall_clock: "2026-03-10T07:30:00Z"}

# Session terminated
%{event: :session_terminated, session_id: <<...>>,
  reason: :timeout, duration_ms: 300000,
  bytes_in: 4096, bytes_out: 8192}

# Policy denial
%{event: :policy_denied, remote_static: <<...>>,
  source: {{10,0,0,1}, 9999}, service: "ssh",
  reason: :not_authorized}
```

Query events:
```elixir
ZtlpGateway.AuditLog.events()      # All events (newest first)
ZtlpGateway.AuditLog.events(10)    # Last 10
```

## Supervision Tree

```
ZtlpGateway.Application
├── ZtlpGateway.Stats              Lock-free atomic counters
├── ZtlpGateway.AuditLog           ETS audit trail
├── ZtlpGateway.SessionRegistry    ETS SessionID → pid mapping
├── ZtlpGateway.PolicyEngine       ETS policy rules + evaluation
├── ZtlpGateway.SessionSupervisor  DynamicSupervisor for sessions
│   └── ZtlpGateway.Session        GenServer per active session
│       └── ZtlpGateway.Backend    TCP connection to backend service
└── ZtlpGateway.Listener           UDP socket, admission pipeline
```

## Project Structure

```
gateway/
├── lib/
│   ├── ztlp_gateway.ex               Top-level module documentation
│   └── ztlp_gateway/
│       ├── application.ex             OTP application + supervision tree
│       ├── audit_log.ex               Session event audit trail (ETS)
│       ├── backend.ex                 TCP backend connection manager
│       ├── config.ex                  Runtime configuration
│       ├── crypto.ex                  X25519, ChaCha20-Poly1305, BLAKE2s, HKDF, Ed25519
│       ├── handshake.ex               Noise_XX_25519_ChaChaPoly_BLAKE2s (full impl)
│       ├── identity.ex                Client identity resolution (pubkey → zone name)
│       ├── listener.ex                UDP listener + admission dispatch
│       ├── packet.ex                  ZTLP packet parsing/serialization
│       ├── pipeline.ex                Three-layer admission pipeline
│       ├── policy_engine.ex           Access control rules + evaluation
│       ├── session.ex                 Per-session GenServer (handshake + data flow)
│       ├── session_registry.ex        ETS session lookup with process monitoring
│       └── stats.ex                   Atomic operational counters
├── test/
│   └── ztlp_gateway/
│       ├── backend_test.exs           TCP echo server, send/recv, close handling
│       ├── crypto_test.exs            All primitives: DH, AEAD, hash, HKDF, Ed25519
│       ├── handshake_test.exs         Full Noise_XX, key agreement, PFS, error cases
│       ├── integration_test.exs       End-to-end: handshake + packet + policy + audit
│       ├── packet_test.exs            Parse/serialize, magic, types, round-trips
│       ├── pipeline_test.exs          Layer 1+2 admission, HELLO, unknown sessions
│       ├── policy_engine_test.exs     Allow/deny, wildcards, rule management
│       └── session_registry_test.exs  Register, lookup, auto-cleanup on process death
├── config/
│   ├── config.exs
│   ├── dev.exs
│   ├── test.exs
│   └── prod.exs
├── mix.exs
└── README.md
```

## License

Apache License 2.0

ZTLP and Zero Trust Layer Protocol are trademarks of Steven Price.
