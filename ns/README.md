# ZTLP-NS — Distributed Trust Namespace

ZTLP-NS is the control-plane identity and discovery layer for the
[Zero Trust Layer Protocol](https://ztlp.org). It provides signed record
storage, hierarchical namespace delegation, trust chain verification,
and bootstrap discovery.

Think DNS meets a certificate authority, but purpose-built for ZTLP's
identity-first model.

## Architecture

```
                     ┌─────────────────────┐
                     │   Root Trust Anchor  │
                     │   (hardcoded pubkey) │
                     └──────────┬──────────┘
                                │ signs
                     ┌──────────▼──────────┐
                     │   Operator Zone     │
                     │  (example.ztlp)     │
                     └──────────┬──────────┘
                                │ signs
                     ┌──────────▼──────────┐
                     │   Tenant Zone       │
                     │  (acme.example.ztlp)│
                     └──────────┬──────────┘
                                │ signs
                ┌───────────────┼───────────────┐
                ▼               ▼               ▼
         ┌──────────┐   ┌──────────┐   ┌──────────┐
         │ ZTLP_KEY │   │ ZTLP_SVC │   │ZTLP_RELAY│
         │ (node1)  │   │ (rdp)    │   │ (relay1) │
         └──────────┘   └──────────┘   └──────────┘
```

Every record is Ed25519-signed. Unsigned records are rejected.

## Record Types

| Type             | Purpose                                 | Wire Byte |
|------------------|-----------------------------------------|-----------|
| `ZTLP_KEY`       | NodeID ↔ public key binding            | 0x01      |
| `ZTLP_SVC`       | Service definition + allowed nodes     | 0x02      |
| `ZTLP_RELAY`     | Relay endpoint, capacity, region       | 0x03      |
| `ZTLP_POLICY`    | Access control rules                   | 0x04      |
| `ZTLP_REVOKE`    | Revocation notice (highest priority)   | 0x05      |
| `ZTLP_BOOTSTRAP` | Signed relay list for node discovery   | 0x06      |

## Quick Start

### Prerequisites

- Elixir 1.12+ with OTP 24+
- No external dependencies

### Build

```bash
cd ns/
mix deps.get   # No-op (zero deps)
mix compile
```

### Run Tests

```bash
mix test
# 371 tests, 0 failures
```

### Start the Server

```bash
# Interactive
iex -S mix

# As an application
mix run --no-halt
```

### Query the Server

The UDP query protocol is simple binary:

```elixir
# From iex — look up a KEY record for "node1.acme.ztlp"
{:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])
name = "node1.acme.ztlp"
query = <<0x01, byte_size(name)::16, name::binary, 1::8>>
:gen_udp.send(socket, {127, 0, 0, 1}, ZtlpNs.Server.port(), query)
{:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
```

Response prefixes:
- `0x02` — Record found (followed by encoded record)
- `0x03` — Not found
- `0x04` — Revoked
- `0xFF` — Malformed query

## Usage Examples

### Create and Sign Records

```elixir
alias ZtlpNs.{Crypto, Record, Store, ZoneAuthority, TrustAnchor}

# Generate a root zone authority
root = ZoneAuthority.generate("ztlp")
TrustAnchor.add("ztlp-root", root.public_key)

# Generate an operator zone
operator = ZoneAuthority.generate("example.ztlp")

# Root delegates to operator (creates a signed ZTLP_KEY for the zone)
delegation = ZoneAuthority.delegate(root, operator)
Store.insert(delegation)

# Operator signs a node record
node_id = :crypto.strong_rand_bytes(16)
{node_pub, _node_priv} = Crypto.generate_keypair()
record = Record.new_key("node1.example.ztlp", node_id, node_pub)
{:ok, signed} = ZoneAuthority.sign_record(operator, record)
Store.insert(signed)

# Look it up with trust chain verification
{:ok, found} = ZtlpNs.Query.lookup_verified("node1.example.ztlp", :key)
```

### Revocation

```elixir
# Revoke a compromised node
revoke = Record.new_revoke("revocations.ztlp",
  [compromised_node_id], "key compromise", "2026-03-10T00:00:00Z")
{:ok, signed_revoke} = ZoneAuthority.sign_record(root, revoke)
Store.insert(signed_revoke)

# Future lookups for the revoked ID return {:error, :revoked}
```

### Bootstrap Discovery

```elixir
# The bootstrap module implements the three-step fallback:
# 1. HTTPS discovery (mock in prototype)
# 2. DNS-SRV discovery (not implemented)
# 3. Hardcoded relay list

# For testing, set hardcoded relays:
ZtlpNs.Bootstrap.set_hardcoded_relays([relay_record])
{:ok, relays} = ZtlpNs.Bootstrap.discover()
```

## Security

ZTLP-NS v0.5.7+ includes comprehensive security hardening:

### Rate Limiting
Per-IP token bucket rate limiting via `ZtlpNs.RateLimiter`. Configured
via `rate_limit_queries_per_second` (default: 100) and `rate_limit_burst`
(default: 200). Rate-limited packets are silently dropped (no error
response to prevent amplification).

### Registration Authentication
All registrations (0x09) require:
- **Ed25519 signature** over the canonical registration form
- **Public key** of the registrant (appended to wire format)
- **Zone authorization** — pubkey must be a zone authority, delegated key,
  or self-registrant (node updating its own KEY/SVC record)
- **NodeID revocation check** — the NodeID in record data is checked against
  the revocation table

Legacy v1 registrations (without pubkey) are rejected.

### Packet & Record Size Limits
- Maximum UDP packet size: 8KB (configurable via `:max_packet_size`)
- Maximum encoded record size: 4096 bytes (configurable via `:max_record_size`)
- Oversized packets are silently dropped

### Name Validation
DNS-compatible name format enforced on registration:
- Max 253 bytes total, max 63 bytes per label
- Lowercase alphanumeric + hyphens + dots only
- No leading/trailing hyphens per label

### Amplification Prevention
For unauthenticated queries (0x01, 0x05), response size is capped to
request size. Truncated responses include a truncation flag (0x01 in
second byte). Clients can pad queries to indicate willingness to receive
larger responses.

### Worker Pool
Queries are dispatched to a bounded `Task.Supervisor` (default: 100
concurrent workers) preventing sequential processing bottlenecks and
providing crash isolation.

### Pubkey Index
A reverse index (pubkey → name) in Mnesia provides O(1) public key
lookups instead of O(n) table scans.

### Audit Logging
All security-relevant events are logged via `ZtlpNs.StructuredLog`:
registration accepted/rejected, rate limiting, auth failures, oversized
packets.

### Default TTLs
Correct per-type TTLs: KEY=86400, SVC=86400, RELAY=3600, POLICY=3600,
REVOKE=0 (never expires), BOOTSTRAP=86400.

### Persisted Signing Key
The NS registration signing key is loaded from file on startup (if
configured via `:identity_key_file`). If no file exists, a new key is
generated and saved. Keys survive server restarts.

## Implementation Details

### Pure Elixir/OTP

Zero external dependencies. Crypto is handled by OTP 24's `:crypto`
module (Ed25519 via `:eddsa`). Storage is ETS. UDP via `:gen_udp`.

### Ed25519 Signatures

All records are signed with Ed25519 (RFC 8032). The canonical binary
format for signing is deterministic — identical records always produce
identical bytes for signing.

### Trust Chain Verification

`Query.lookup_verified/2` walks the delegation chain from the record's
signer up to a root trust anchor. If the chain breaks at any point, the
lookup returns `{:error, :untrusted_chain}`.

### Revocation Priority

ZTLP_REVOKE records have the highest priority. When a revocation is
inserted, the revoked IDs are indexed in a separate ETS table for O(1)
lookup. Every query checks revocation before returning results.

### Serial Numbers

Records use monotonically increasing serial numbers. The store rejects
any record with a serial ≤ the existing record for the same name+type.
This prevents replay attacks.

## Configuration

In `config/config.exs`:

```elixir
config :ztlp_ns, :port, 23096         # UDP query port
config :ztlp_ns, :max_records, 100_000 # Maximum records in store
```

## Project Structure

```
ns/
├── lib/
│   ├── ztlp_ns.ex                    # Top-level module documentation
│   └── ztlp_ns/
│       ├── application.ex            # OTP Application (supervisor tree)
│       ├── bootstrap.ex              # Bootstrap discovery (HTTPS → DNS → hardcoded)
│       ├── config.ex                 # Runtime configuration
│       ├── crypto.ex                 # Ed25519 signing & verification
│       ├── query.ex                  # Query engine with trust chain verification
│       ├── record.ex                 # Record struct, serialization, signing
│       ├── server.ex                 # UDP query server
│       ├── store.ex                  # ETS-backed record store with revocation
│       ├── trust_anchor.ex           # Root trust anchor management
│       ├── zone.ex                   # Zone struct and namespace helpers
│       └── zone_authority.ex         # Zone delegation and trust chain building
├── test/
│   └── ztlp_ns/
│       ├── bootstrap_test.exs
│       ├── crypto_test.exs
│       ├── integration_test.exs      # End-to-end trust chain + UDP tests
│       ├── query_test.exs
│       ├── record_test.exs
│       ├── store_test.exs
│       ├── trust_anchor_test.exs
│       └── zone_authority_test.exs
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
