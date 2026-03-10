# ZTLP Testing Tools

Professional testing tools for the Zero Trust Layer Protocol (ZTLP). These tools provide protocol analysis, load testing, fuzzing, and network simulation capabilities.

## Quick Start

```bash
cd proto

# Build all tools
cargo build --release --bin ztlp-inspect --bin ztlp-load --bin ztlp-fuzz

# Inspect a packet
cargo run --release --bin ztlp-inspect -- <hex>

# Run a local pipeline benchmark
cargo run --release --bin ztlp-load -- pipeline

# Fuzz the local parser
cargo run --release --bin ztlp-fuzz -- local
```

## Tools Overview

| Tool | Purpose | Network Required? |
|------|---------|-------------------|
| `ztlp-inspect` | Decode and pretty-print ZTLP packets | No |
| `ztlp-load` | High-volume traffic generation | Optional (pipeline mode is local) |
| `ztlp-fuzz` | Mutation-based protocol fuzzing | Optional (local mode available) |
| `ztlp-netlab` | Docker-based network simulation | Docker required |

---

## ztlp-inspect — Packet Decoder/Inspector

Decode and pretty-print ZTLP packets from hex strings, binary files, or stdin. Automatically detects packet type (handshake vs data) via the HdrLen field.

### Usage

```bash
# Decode a single packet from hex
ztlp-inspect 5a371018000001000100000000000000...

# Read hex-encoded packets from stdin (one per line)
echo "5a37..." | ztlp-inspect --stdin

# Scan a binary capture file for ZTLP packets
ztlp-inspect --file capture.bin

# Output as JSON (great for scripting)
ztlp-inspect --format json 5a37...

# Compact single-line output
ztlp-inspect --format compact 5a37...
```

### Output Modes

- **`pretty`** (default) — Colored, boxed output with hex dump. Best for interactive use.
- **`json`** — Structured JSON with all decoded fields. Best for scripting/automation.
- **`compact`** — Single-line summary per packet. Best for log scanning.

### What It Decodes

**Handshake packets** (HdrLen=24, 95 bytes):
- Magic, Version, Flags, MsgType, CryptoSuite, KeyID
- SessionID, PacketSeq, Timestamp
- SrcNodeID, DstSvcID, PolicyTag
- ExtLen, PayloadLen, HeaderAuthTag

**Data packets** (HdrLen=11, 42 bytes):
- Magic, Version, Flags
- SessionID, PacketSeq, HeaderAuthTag

### Validation

- Magic byte check (0x5A37)
- Version check (expected: 1)
- HdrLen consistency (24 for handshake, 11 for data)
- Warns on suspicious combinations (e.g., zero SessionID on non-Hello packets)

---

## ztlp-load — Load Generator

Generate high-volume ZTLP traffic for stress testing. Supports both local pipeline benchmarks and network load tests against relays, gateways, and name servers.

### Usage

```bash
# Local pipeline throughput test (no network needed)
ztlp-load pipeline
ztlp-load pipeline --packets 1000000 --sessions 1000 --full

# Flood a relay with data packets
ztlp-load relay --target 127.0.0.1:4433 --rate 10000 --duration 30

# Test gateway with handshake + data
ztlp-load gateway --target 127.0.0.1:4434 --sessions 100 --duration 60

# Flood NS with lookup queries
ztlp-load ns --target 127.0.0.1:4435 --rate 5000 --duration 10
```

### Subcommands

#### `pipeline` — Local Pipeline Benchmark
No network needed. Tests the three-layer admission pipeline locally.

```bash
ztlp-load pipeline                          # Default: 1M packets, 1K sessions
ztlp-load pipeline --packets 5000000        # 5M packets
ztlp-load pipeline --sessions 10000         # 10K sessions in lookup table
ztlp-load pipeline --full                   # Include Layer 3 auth check
```

#### `relay` — Relay Flood
Sends data packets to a relay via UDP.

```bash
ztlp-load relay --target 127.0.0.1:4433 \
    --sessions 50    \   # 50 concurrent simulated sessions
    --rate 10000     \   # 10K packets/second target
    --duration 60    \   # Run for 60 seconds
    --packet-size 128 \  # 128-byte payloads
    --warmup             # Send HELLO packets first
```

#### `gateway` / `ns` — Gateway and NS Tests
Similar to relay mode but with protocol-appropriate packet types.

### Output

Real-time progress bar with PPS and error count, followed by a summary:
- Total packets sent, bytes, errors
- Throughput (PPS and bandwidth)
- Latency percentiles (p50, p95, p99, min, max)
- Latency histogram with distribution buckets

---

## ztlp-fuzz — Protocol Fuzzer

Mutation-based fuzzing of the ZTLP protocol to find parser and handler bugs. Supports local (in-process) fuzzing and network fuzzing against live targets.

### Usage

```bash
# Fuzz local parser (no network needed, no servers required)
ztlp-fuzz local
ztlp-fuzz local --iterations 500000
ztlp-fuzz local --strategy bitflip --seed 42

# Fuzz a live relay
ztlp-fuzz relay --target 127.0.0.1:4433 --iterations 10000

# Fuzz a live gateway
ztlp-fuzz gateway --target 127.0.0.1:4434 --strategy all
```

### Mutation Strategies

| Strategy | Description |
|----------|-------------|
| `all` | Random selection from all strategies (default) |
| `bitflip` | Flip 1-8 random bits in the packet |
| `byte-mutate` | Replace 1-4 random bytes with random values |
| `field-boundary` | Mutate known field offsets with boundary values (0, 0xFF, max) |
| `truncate` | Send packets shorter than expected header size |
| `extend` | Append 1-255 random bytes to packets |
| `magic-corrupt` | Corrupt the 0x5A37 magic bytes in various ways |
| `session-mutate` | Mutate SessionID bytes (zero, flip, swap, randomize) |
| `sequence-attack` | Sequence number attacks (0, MAX, overflow, replay) |

### Local Mode

Fuzzes the Rust packet parser directly — no network or running servers needed. Tests:
- `DataHeader::deserialize()` with mutated inputs
- `HandshakeHeader::deserialize()` with mutated inputs
- Pipeline Layer 1 magic check
- Catches and reports panics (should be zero for a robust parser)

### Network Mode

Sends fuzzed packets to a live target via UDP. Monitors:
- Send success/failure rates
- Periodic health checks (sends valid packets to verify target is still alive)
- Reports potential crashes detected

### Reproducibility

Use `--seed <n>` for deterministic, reproducible fuzzing:
```bash
# This will always produce the same mutation sequence
ztlp-fuzz local --seed 12345 --iterations 100000
```

---

## ztlp-netlab — Network Test Lab

Docker-based network simulation environment for testing ZTLP under realistic network conditions using Linux `tc`/`netem`.

### Prerequisites

- Docker and Docker Compose
- Dockerfiles in the respective component directories (`proto/Dockerfile`, `relay/Dockerfile`, etc.)

### Topology

```
  client-a ──┐
              ├── relay ── gateway ── echo-backend
  client-b ──┘     │
                    └── ns

  chaos (sidecar) — injects network impairments via tc/netem
```

All containers are on a shared Docker bridge network (172.28.0.0/24).

### Usage

```bash
cd tools/netlab

# Run all scenarios
./run.sh

# Run a specific scenario
./run.sh normal
./run.sh latency
./run.sh packet-loss

# Build/rebuild containers first
./run.sh --build

# List available scenarios
./run.sh --list

# Tear down containers
./run.sh --teardown
```

### Scenarios

| Scenario | File | Description |
|----------|------|-------------|
| `normal` | `scenarios/normal.sh` | Baseline — no impairment |
| `latency` | `scenarios/latency.sh` | 50ms, 100ms, 200ms added delay |
| `packet-loss` | `scenarios/packet-loss.sh` | 1%, 5%, 10%, 25% packet loss |
| `reorder` | `scenarios/reorder.sh` | 5% packet reordering |
| `bandwidth` | `scenarios/bandwidth.sh` | Throttle to 1Mbps, 100Kbps |
| `jitter` | `scenarios/jitter.sh` | Variable latency (50ms ±20ms) |
| `partition` | `scenarios/partition.sh` | Network partition then recovery |

### Writing Custom Scenarios

Create a new `.sh` file in `tools/netlab/scenarios/`:

```bash
#!/usr/bin/env bash
# Description of your scenario (shown in --list)
set -euo pipefail

CHAOS="docker exec --privileged ztlp-chaos"
$CHAOS sh -c "apk add --no-cache iproute2 >/dev/null 2>&1" || true

# Apply impairment
$CHAOS sh -c "
    tc qdisc del dev eth0 root 2>/dev/null || true
    tc qdisc add dev eth0 root netem <your-rules>
"

# Run tests
docker exec ztlp-client-a sh -c '...'

# Clean up
$CHAOS sh -c "tc qdisc del dev eth0 root 2>/dev/null" || true
```

---

## Architecture

All Rust tools are compiled as separate binaries from the `proto/` crate:

```
proto/
  Cargo.toml            # Binary entries + dependencies
  src/bin/
    ztlp-inspect.rs     # Packet inspector
    ztlp-load.rs        # Load generator
    ztlp-fuzz.rs        # Protocol fuzzer
    ztlp-bench.rs       # (existing) Micro-benchmarks

tools/
  README.md             # This file
  netlab/
    docker-compose.yml  # Network lab topology
    run.sh              # Orchestration script
    scenarios/          # Network impairment scenarios
```

### Dependencies Added

- `colored` — Terminal colors for pretty output
- `indicatif` — Progress bars for long-running operations

All other functionality uses existing crate dependencies (clap, tokio, rand, hex, serde_json, etc.).

## Building

```bash
cd proto

# Build all testing tools
cargo build --release --bin ztlp-inspect --bin ztlp-load --bin ztlp-fuzz

# Build everything (including existing binaries)
cargo build --release

# Run tests to verify nothing is broken
cargo test
```
