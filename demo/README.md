# ZTLP SSH Tunnel Demo

Interactive demo showcasing ZTLP's zero-trust network tunnel with
identity-based access control, encrypted transport, and DDoS-resistant
packet pipeline.

## Quick Start (No NS)

```bash
./ssh-tunnel-demo.sh
```

Runs the full 13-act demo without a namespace server. Identity matching
uses NodeID hex strings in the policy file. Works anywhere with just the
`ztlp` binary and an SSH server.

## Full Demo (With ZTLP-NS)

For the complete experience with human-readable identities
(`alice.tunnel.ztlp` instead of `f40685...`), run a ZTLP-NS server first.

### 1. Install Elixir/OTP (if needed)

The NS server is pure Elixir/OTP with **zero external dependencies**.
It only needs the Erlang VM and Elixir compiler.

| OS | Install |
|---|---|
| macOS | `brew install elixir` |
| Ubuntu/Debian | `sudo apt install elixir erlang` |
| Arch | `sudo pacman -S elixir` |
| Fedora | `sudo dnf install elixir erlang` |
| asdf | `asdf install erlang 26.2 && asdf install elixir 1.15.7` |

Minimum: **Elixir 1.12+** / **Erlang OTP 24+** (for Ed25519 crypto support).

### 2. Start the NS Server

```bash
cd ../ns
mix run --no-halt
```

Or with custom port/storage:

```bash
cd ../ns
ZTLP_NS_PORT=23096 \
ZTLP_NS_STORAGE_MODE=ram_copies \
mix run --no-halt
```

The NS server listens on UDP port 23096 by default. First run
will compile (takes ~10s) — subsequent starts are instant.

### 3. Run the Demo

```bash
./ssh-tunnel-demo.sh
```

The demo auto-detects the NS server on `127.0.0.1:23096`. If it's
reachable, it registers names for all three identities:

- `demo-server.tunnel.ztlp` (Bob)
- `alice.tunnel.ztlp` (Alice)
- `eve.tunnel.ztlp` (Eve)

The policy file then uses friendly names instead of hex NodeIDs:

```toml
default = "deny"

[[services]]
name = "ssh"
allow = ["alice.tunnel.ztlp"]
```

### NS Server Configuration

| Env Variable | Default | Description |
|---|---|---|
| `ZTLP_NS_PORT` | `23096` | UDP listen port |
| `ZTLP_NS_STORAGE_MODE` | `disc_copies` | `disc_copies` or `ram_copies` |
| `ZTLP_NS_MNESIA_DIR` | Mnesia default | Directory for persistence |
| `ZTLP_NS_MAX_RECORDS` | `100000` | Max stored records |
| `ZTLP_ENROLLMENT_SECRET` | none | 64 hex chars for device enrollment |

### Using Docker (NS + Demo)

```bash
# From the repo root
docker compose up ns -d
./demo/ssh-tunnel-demo.sh
```

## Demo Acts

| Act | Description |
|-----|-------------|
| 1 | Generate 3 identities: Bob (server), Alice (client), Eve (attacker) |
| 2 | Optional: Register names with ZTLP-NS |
| 3 | Create zero-trust policy — only Alice allowed for SSH |
| 4 | Start server with policy enforcement |
| 5 | **Alice connects — ALLOWED** ✅ |
| 6 | SSH through Alice's encrypted tunnel |
| 7 | **Eve connects — DENIED** ❌ (handshake completes, policy rejects) |
| 8 | SCP throughput test: 10/50/100 MB (ZTLP vs direct SSH) |
| 9 | Port scan — SSH port invisible, only ZTLP port visible |
| 10 | UDP packet flood — L1 magic-byte rejection (~19ns each) |
| 11 | Malformed ZTLP packets — L2 session verification |
| 12 | tcpdump — payload is encrypted |
| 13 | CPU monitoring — negligible impact from attacks |

## Customization

```bash
# Environment variables
SSH_USER=steve          # SSH username (default: current user)
SSH_PORT=22             # Local SSH port
LISTEN_PORT=23095       # ZTLP listener port
TUNNEL_LOCAL_PORT=2222  # Local tunnel port
NS_SERVER=10.0.0.5:23096  # Custom NS server
DEMO_DIR=/tmp/ztlp-demo   # Artifact directory
```

## Key Concepts Demonstrated

**Authentication ≠ Authorization (Act 7)**

Eve has a valid ZTLP identity. She completes the full Noise_XX handshake —
proving she IS Eve. But Bob's policy says only Alice can access SSH.
The handshake is authentication (who are you?). The policy is
authorization (what can you do?). Both are required.

**Three-Layer Pipeline (Acts 10-11)**

1. **Layer 1 (Magic byte)** — Wrong magic? Dropped in ~19ns. No state.
2. **Layer 2 (Session ID)** — Unknown session? Dropped. No crypto.
3. **Layer 3 (Auth tag)** — Bad AEAD tag? Dropped. Crypto verified.

Attackers can't even make the server do expensive work.

## Requirements

Required:
- `ztlp` binary (build: `cd ../proto && cargo build --release`)
- SSH server running locally

Optional (for full demo):
- `nmap` — port scanning
- `tcpdump` — packet capture
- `python3` — flood generators
- `scp` — throughput tests
- `bc` — calculations
- Elixir 1.15+ / OTP 26+ — for ZTLP-NS server

## Optimal Performance

For best tunnel throughput, tune your system buffers:

```bash
sudo ztlp tune --apply --persist
```

Or manually:

```bash
sudo sysctl -w net.core.rmem_max=8388608
sudo sysctl -w net.core.wmem_max=8388608
```
