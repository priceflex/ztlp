# ZTLP CLI — Command Reference

The `ztlp` binary is the unified command-line interface for the Zero Trust Layer Protocol. It provides all the tools needed to generate identities, establish encrypted connections, inspect packets, manage relays, and query the ZTLP namespace.

## Installation

Build from the `proto/` directory:

```bash
cd proto
cargo build --release --bin ztlp
# Binary at: target/release/ztlp
```

The binary name in Cargo.toml is `ztlp`, defined in `proto/src/bin/ztlp-cli.rs`.

## Global Options

```
-v, --verbose    Increase verbosity (-v info, -vv debug, -vvv trace)
-h, --help       Print help
-V, --version    Print version
```

Verbosity can also be controlled via the `RUST_LOG` environment variable:
```bash
RUST_LOG=debug ztlp ping 10.0.0.1:23095
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

All config values can be overridden by CLI flags.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0    | Success |
| 1    | Error   |
| 2    | Usage error (bad arguments) |

---

## Commands

### `ztlp keygen`

Generate a new ZTLP identity with X25519 (handshake) and Ed25519 (signing) key pairs.

```
ztlp keygen [OPTIONS]

Options:
  -o, --output <FILE>    Save to file (prints to stdout if omitted)
  -f, --format <FORMAT>  Output format: json (default) or hex
```

**Examples:**

```bash
# Generate and print to stdout
ztlp keygen

# Save to a key file (creates ~/.ztlp/ if needed, sets 0600 permissions)
ztlp keygen --output ~/.ztlp/identity.json

# Compact hex format
ztlp keygen --format hex --output ~/.ztlp/identity.hex
```

**Output fields:**
- `node_id` — 128-bit NodeID (hex)
- `static_private_key` — X25519 private key (for Noise_XX handshakes)
- `static_public_key` — X25519 public key
- `ed25519_seed` — Ed25519 signing seed (for NS record registration)
- `ed25519_public_key` — Ed25519 public key

---

### `ztlp connect <target>`

Connect to a ZTLP peer or gateway, perform a Noise_XX handshake, and enter interactive encrypted messaging mode. With `--local-forward`, opens a local TCP listener and tunnels connections through the ZTLP session.

The target can be a raw `ip:port` address or a **ZTLP namespace name** (e.g., `myserver.clients.techrockstars.ztlp`). When a ZTLP name is provided, the CLI automatically queries ZTLP-NS to resolve the endpoint address before connecting.

```
ztlp connect <TARGET> [OPTIONS]

Arguments:
  <TARGET>  Peer address — either ip:port or a ZTLP name
            Examples: 192.168.1.10:23095, myserver.clients.techrockstars.ztlp

Options:
  -k, --key <FILE>          Path to identity key file
  -r, --relay <ADDR:PORT>   Route through a relay
  -g, --gateway <ADDR:PORT> Connect via gateway
      --ns-server <ADDR:PORT>  NS server for name resolution [default: config or 127.0.0.1:5353]
  -s, --session-id <HEX>    Use a specific session ID (24 hex chars)
  -b, --bind <ADDR:PORT>    Local bind address [default: 0.0.0.0:0]
  -L, --local-forward <LOCAL_PORT:REMOTE_HOST:REMOTE_PORT>
                            Forward a local TCP port through the tunnel
      --service <NAME>      Service name to request from the remote listener
```

**Examples:**

```bash
# Connect by raw address
ztlp connect 192.168.1.10:23095

# Connect by ZTLP name (auto-resolves via NS)
ztlp connect myserver.clients.techrockstars.ztlp

# Connect by ZTLP name with explicit port
ztlp connect myserver.clients.techrockstars.ztlp:23095

# Connect by name using a specific NS server
ztlp connect myserver.clients.techrockstars.ztlp --ns-server 10.0.0.1:5353

# Connect with a saved identity
ztlp connect 10.0.0.1:23095 --key ~/.ztlp/identity.json

# Connect through a relay
ztlp connect peer.example.com:23095 --relay relay.example.com:23095

# Tunnel SSH: local port 2222 → remote 127.0.0.1:22
ztlp connect server:23095 --key ~/.ztlp/identity.json -L 2222:127.0.0.1:22
# Then: ssh -p 2222 user@127.0.0.1

# Tunnel RDP: local port 3389 → remote 127.0.0.1:3389
ztlp connect server:23095 --key ~/.ztlp/identity.json -L 3389:127.0.0.1:3389
# Then: mstsc /v:127.0.0.1
```

**Name Resolution:**

When a ZTLP name is provided (any target that isn't a valid `ip:port`), the CLI:

1. Queries ZTLP-NS for a **SVC record** (type 2) to get the endpoint address
2. Queries for a **KEY record** (type 1) to get the peer's NodeID and public key
3. If no SVC record is found, falls back to DNS resolution
4. If no port is specified, defaults to **23095** (the standard ZTLP port)

The NS server is determined in priority order:
1. `--ns-server` flag
2. `ns_server` in `~/.ztlp/config.toml`
3. Default: `127.0.0.1:5353`

Example output when resolving a name:
```
Resolving myserver.clients.techrockstars.ztlp via ZTLP-NS...
  NS server: 127.0.0.1:5353
  ✓ SVC record → 10.42.42.50:23095
  ✓ KEY record found
  ℹ NodeID: a1b2c3d4e5f6a7b8...
  Resolved: 10.42.42.50:23095
```

After the handshake completes, the CLI shows:
- Remote NodeID
- Session ID
- Handshake latency

Then enters interactive mode where you type messages and see received messages. Press Ctrl+C to exit.

---

### `ztlp listen`

Listen for incoming ZTLP connections and act as a Noise_XX responder. With `--forward`, bridges authenticated sessions to a local TCP service.

```
ztlp listen [OPTIONS]

Options:
  -b, --bind <ADDR:PORT>  Address to bind on [default: 0.0.0.0:23095]
  -k, --key <FILE>        Path to identity key file
  --gateway               Run as mini-gateway (accept multiple connections)
  -f, --forward <HOST:PORT>  Forward to a local TCP service after handshake
```

**Examples:**

```bash
# Listen on the default ZTLP port (interactive mode)
ztlp listen

# Listen on a custom port with a persistent identity
ztlp listen --bind 0.0.0.0:9999 --key ~/.ztlp/identity.json

# Protect SSH: forward authenticated sessions to local sshd
ztlp listen --key server.json --forward 127.0.0.1:22

# Protect RDP: forward to local RDP service
ztlp listen --key server.json --forward 127.0.0.1:3389

# Protect a database
ztlp listen --key server.json --forward 127.0.0.1:5432
```

Without `--forward`: waits for an incoming HELLO, completes the 3-message handshake, then enters interactive mode.

With `--forward`: after handshake, connects to the specified TCP address and bridges traffic bidirectionally. All TCP data is encrypted through the ZTLP session. The backend service (SSH, RDP, etc.) is unchanged — it sees a normal TCP connection from localhost.

---

### Access Control (Policy Engine)

The listener enforces per-service access control via a TOML policy file.
After the Noise_XX handshake, the server cryptographically knows the client's
identity (NodeID). The policy engine checks whether that identity is allowed
to access the requested service.

**Policy file location:** `~/.ztlp/policy.toml` (auto-detected) or `--policy <path>`

```toml
# Default: deny access to any service without an explicit rule
default = "deny"

# SSH: only ops team and admins
[[services]]
name = "ssh"
allow = ["steve.ops.techrockstars.ztlp", "*.admins.techrockstars.ztlp"]

# RDP: technicians and admins
[[services]]
name = "rdp"
allow = ["*.techs.techrockstars.ztlp", "*.admins.techrockstars.ztlp"]

# Database: DBAs only
[[services]]
name = "db"
allow = ["dba.ops.techrockstars.ztlp"]

# Web: any authenticated identity
[[services]]
name = "web"
allow = ["*"]
```

**Pattern matching:**
- Exact: `"steve.ops.techrockstars.ztlp"`
- Wildcard suffix: `"*.admins.techrockstars.ztlp"` matches any identity ending in `.admins.techrockstars.ztlp`
- Universal: `"*"` matches all authenticated identities
- Raw NodeID hex: `"a1b2c3d4..."` (when NS isn't configured)

**Behavior:**
- No policy file → allow all (backward compatible)
- Policy file present → enforce rules, default deny for unlisted services
- Denied connections are terminated immediately after handshake, before any TCP bridge

**Example — multi-service with policy:**

```bash
# Server: protect SSH and RDP with per-service access control
ztlp listen --key server.json \
    --forward ssh:127.0.0.1:22 \
    --forward rdp:127.0.0.1:3389 \
    --policy ~/.ztlp/policy.toml

# Client (ops team): can access SSH ✓
ztlp connect server:23095 --key ops-admin.json --service ssh -L 2222:127.0.0.1:22

# Client (technician): can access RDP ✓, SSH ✗
ztlp connect server:23095 --key tech.json --service rdp -L 3389:127.0.0.1:3389
```

---

### `ztlp relay`

Manage ZTLP relay nodes.

#### `ztlp relay start`

Start a Rust-native relay node that forwards packets by SessionID. The relay never holds session keys and cannot decrypt any traffic.

```
ztlp relay start [OPTIONS]

Options:
  -b, --bind <ADDR:PORT>       Address to bind on [default: 0.0.0.0:23095]
  -m, --max-sessions <N>       Maximum concurrent sessions [default: 10000]
```

**Example:**

```bash
ztlp relay start --bind 0.0.0.0:23095 --max-sessions 5000
```

The relay learns peer associations as packets arrive. The first packet on a new SessionID registers the sender; the second packet from a different address pairs them. After pairing, all subsequent packets are forwarded to the other peer.

#### `ztlp relay status`

Query a running relay's status.

```
ztlp relay status [OPTIONS]

Options:
  -t, --target <ADDR:PORT>  Relay address [default: 127.0.0.1:23095]
```

---

### `ztlp ns`

Query and interact with the ZTLP Namespace Service (ZTLP-NS).

#### `ztlp ns lookup <name>`

Look up a name in ZTLP-NS and display the associated record.

```
ztlp ns lookup <NAME> [OPTIONS]

Arguments:
  <NAME>  Name to look up (e.g., mynode.office.acme.ztlp)

Options:
  --ns-server <ADDR:PORT>  NS server address [default: 127.0.0.1:5353]
  -t, --record-type <N>    Record type [default: 1]
```

Record type bytes:
| Byte | Type |
|------|------|
| 1    | KEY (NodeID ↔ public key binding) |
| 2    | SVC (service definition) |
| 3    | RELAY (relay endpoint info) |
| 4    | POLICY (access control rules) |
| 5    | REVOKE (revocation notice) |
| 6    | BOOTSTRAP (signed relay list) |

**Examples:**

```bash
# Look up a KEY record
ztlp ns lookup mynode.office.acme.ztlp --ns-server 127.0.0.1:5353

# Look up a RELAY record
ztlp ns lookup relay1.infra.acme.ztlp --record-type 3
```

Output includes: name, type, created timestamp, TTL, serial, signature status, and signer public key.

#### `ztlp ns pubkey <hex>`

Search ZTLP-NS for a KEY record by public key.

```
ztlp ns pubkey <HEX> [OPTIONS]

Arguments:
  <HEX>  Public key in hex

Options:
  --ns-server <ADDR:PORT>  NS server address [default: 127.0.0.1:5353]
```

**Example:**

```bash
ztlp ns pubkey a1b2c3d4e5f6... --ns-server 127.0.0.1:5353
```

Uses the NS server's 0x05 query type for public key lookups.

#### `ztlp ns register`

Register a ZTLP_KEY record (and optionally a ZTLP_SVC record) with ZTLP-NS. This binds a human-readable name to your node's identity (NodeID + public key) and optionally to an endpoint address for auto-resolution by `ztlp connect`.

```
ztlp ns register --name <NAME> --zone <ZONE> --key <FILE> [OPTIONS]

Options:
  -n, --name <NAME>           Name to register (e.g., myserver.clients.techrockstars.ztlp)
  -z, --zone <ZONE>           Zone for the registration (e.g., clients.techrockstars.ztlp)
  -k, --key <FILE>            Path to identity key file
      --ns-server <ADDR:PORT> NS server address [default: 127.0.0.1:5353]
  -a, --address <ADDR:PORT>   Endpoint address to register as SVC record (optional)
```

**Examples:**

```bash
# Register identity only (KEY record)
ztlp ns register --name myserver.clients.techrockstars.ztlp \
    --zone clients.techrockstars.ztlp \
    --key ~/.ztlp/identity.json

# Register identity + endpoint address (KEY + SVC records)
ztlp ns register --name myserver.clients.techrockstars.ztlp \
    --zone clients.techrockstars.ztlp \
    --key ~/.ztlp/identity.json \
    --address 10.42.42.50:23095

# Register with a specific NS server
ztlp ns register --name myserver.clients.techrockstars.ztlp \
    --zone clients.techrockstars.ztlp \
    --key ~/.ztlp/identity.json \
    --address 10.42.42.50:23095 \
    --ns-server 10.0.0.1:5353
```

The registration creates:
- A **KEY record** binding the name to your NodeID and X25519 public key
- An optional **SVC record** (with `--address`) containing the endpoint address, enabling `ztlp connect` to resolve the name to an IP automatically

After registration, the CLI verifies the record exists by querying it back and prints follow-up commands:
```
✓ Registration complete!

  Verify:  ztlp ns lookup myserver.clients.techrockstars.ztlp --ns-server 127.0.0.1:5353
  Connect: ztlp connect myserver.clients.techrockstars.ztlp --ns-server 127.0.0.1:5353
  Ping:    ztlp ping myserver.clients.techrockstars.ztlp --ns-server 127.0.0.1:5353
```

---

### `ztlp gateway`

Manage the ZTLP gateway.

#### `ztlp gateway start`

```
ztlp gateway start [OPTIONS]

Options:
  --elixir            Use the Elixir gateway (recommended for production)
  -b, --bind <ADDR>   Bind address for Rust-native gateway [default: 0.0.0.0:23095]
```

**Examples:**

```bash
# Show instructions for the Elixir gateway
ztlp gateway start --elixir

# Start a minimal Rust-native test gateway
ztlp gateway start --bind 0.0.0.0:23095
```

The `--elixir` flag displays instructions for running the production Elixir gateway. Without it, starts a minimal Rust-native gateway (relay-mode forwarding with handshake pass-through) suitable for testing.

---

### `ztlp inspect`

Decode and pretty-print ZTLP packets from hex strings or files.

```
ztlp inspect [HEX_BYTES] [OPTIONS]

Arguments:
  [HEX_BYTES]  Hex-encoded packet bytes

Options:
  -f, --file <FILE>  Read hex-encoded packets from file (one per line)
```

**Examples:**

```bash
# Inspect a single packet
ztlp inspect 5a37101800000100010000010203040506...

# Inspect packets from a file
ztlp inspect --file captured-packets.txt

# Pipe from tcpdump/hex extraction
echo "5a37100b..." | xargs ztlp inspect
```

The inspector automatically detects packet type:
- **Handshake/Control headers** (HdrLen=24, 95 bytes): Shows Magic, Version, Flags, MsgType, CryptoSuite, KeyID, SessionID, PacketSeq, Timestamp, SrcNodeID, DstSvcID, PolicyTag, ExtLen, PayloadLen, AuthTag
- **Compact Data headers** (HdrLen=11, 42 bytes): Shows Magic, Version, Flags, SessionID, PacketSeq, AuthTag

Output is colorized with field labels. Invalid magic bytes are flagged.

File format: one hex-encoded packet per line. Lines starting with `#` or empty lines are ignored.

---

### `ztlp ping <target>`

Send ZTLP Ping packets to measure round-trip time. Supports ZTLP-NS name resolution (same as `connect`).

```
ztlp ping <TARGET> [OPTIONS]

Arguments:
  <TARGET>  Target address (ip:port or ZTLP name)

Options:
      --ns-server <ADDR:PORT>  NS server for name resolution [default: config or 127.0.0.1:5353]
  -c, --count <N>              Number of pings [default: 4]
  -i, --interval <MS>          Interval between pings in ms [default: 1000]
  -b, --bind <ADDR:PORT>       Local bind address [default: 0.0.0.0:0]
```

**Examples:**

```bash
# Ping by raw address
ztlp ping 192.168.1.10:23095

# Ping by ZTLP name (auto-resolves via NS)
ztlp ping myserver.clients.techrockstars.ztlp

# 10 pings, 500ms interval
ztlp ping 10.0.0.1:23095 --count 10 --interval 500
```

Displays per-packet RTT and summary statistics (min/avg/max/stddev). Exit code is 1 if no responses are received.

---

### `ztlp status`

Query the status of a local ZTLP service (relay or gateway).

```
ztlp status [OPTIONS]

Options:
  -t, --target <ADDR:PORT>  Service address [default: 127.0.0.1:23095]
```

**Example:**

```bash
ztlp status
ztlp status --target 10.0.0.1:23095
```

Sends a ZTLP Ping as a health probe and reports the service status, RTT, and protocol information.

---

## Protocol Reference

| Field | Value |
|-------|-------|
| Noise pattern | `Noise_XX_25519_ChaChaPoly_BLAKE2s` |
| Magic bytes | `0x5A37` |
| Default port | `23095` |
| Data header | 42 bytes (HdrLen=11) |
| Handshake header | 95 bytes (HdrLen=24) |
| SessionID | 12 bytes (96 bits) |
| HeaderAuthTag | 16 bytes (ChaCha20-Poly1305 AEAD) |

## Architecture

The CLI binary (`ztlp`) is built from `proto/src/bin/ztlp-cli.rs` and reuses the full `ztlp-proto` library including:
- `identity` — NodeID generation, key management, file I/O
- `handshake` — Noise_XX handshake state machine
- `packet` — Header serialization/deserialization
- `pipeline` — Three-layer admission pipeline
- `session` — Encrypted session state and replay protection
- `transport` — Async UDP transport (Tokio)
- `relay` — SessionID-based packet forwarding
- `error` — Structured error types
