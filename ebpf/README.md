# ZTLP XDP/eBPF Packet Filter

Phase 3 of the ZTLP reference implementation — a kernel-level fast-path packet
filter using Linux XDP (eXpress Data Path).

This eBPF program attaches directly to the NIC driver and drops invalid ZTLP
traffic **before it reaches the Linux kernel network stack**. It implements
Layer 1 (magic check) and Layer 2 (SessionID lookup) of the ZTLP admission
pipeline at near line-rate with zero cryptographic cost.

It also filters **inter-relay mesh traffic** on a separate port (23096),
enforcing a peer allowlist and performing TTL/magic checks on forwarded packets.

## Architecture

```
                        Inbound UDP Packet
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  XDP/eBPF Program (NIC driver, before kernel stack)          │
│                                                              │
│  ┌─────────────────────┐    ┌──────────────────────────┐     │
│  │ Port 23095 (Client)  │    │ Port 23096 (Mesh)        │     │
│  │                      │    │                          │     │
│  │ 1. Magic == 0x5A37?  │    │ 1. Sender NodeID in      │     │
│  │    └─ No → DROP      │    │    mesh_peer_map?         │     │
│  │                      │    │    └─ No → DROP           │     │
│  │ 2. SessionID in      │    │                          │     │
│  │    session_map?       │    │ 2. FORWARD messages:     │     │
│  │    └─ Yes → PASS     │    │    - TTL > 0?             │     │
│  │    └─ No → HELLO?    │    │      └─ No → DROP         │     │
│  │                      │    │    - Inner magic 0x5A37?  │     │
│  │ 3. HELLO + RAT?      │    │      └─ No → DROP         │     │
│  │    → RAT bypass OR   │    │      └─ Yes → PASS        │     │
│  │      rate limit      │    │                          │     │
│  │                      │    │ 3. Other mesh messages    │     │
│  │ 4. Non-HELLO → DROP  │    │    from known peers → PASS│     │
│  └─────────────────────┘    └──────────────────────────┘     │
│                                                              │
│  Other ports → XDP_PASS (not our traffic)                    │
│  Non-UDP/Non-IP → XDP_PASS                                   │
│  Stats: per-CPU counters for each drop/pass reason           │
└──────────────────────────────────────────────────────────────┘
                               │
                     XDP_PASS packets only
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  Kernel → ZTLP Daemon (userspace)                            │
│                                                              │
│  Client packets:                                             │
│    Layer 3: HeaderAuthTag AEAD verification                  │
│    (ChaCha20-Poly1305 — the expensive check)                 │
│                                                              │
│  Mesh packets:                                               │
│    Protocol handling: HELLO/ACK, PING/PONG, SESSION_SYNC     │
│    FORWARD: unwrap + full Layer 2/3 on inner packet          │
│    RAT verification: HMAC-BLAKE2s (too expensive for XDP)    │
└──────────────────────────────────────────────────────────────┘
```

Under DDoS, the vast majority of attack traffic dies at the XDP level — never
consuming kernel CPU, never allocating socket buffers, never reaching the ZTLP
daemon. Only legitimate packets (known sessions, rate-limited HELLOs, or
authorized mesh peers) pass through to the full cryptographic verification.

## What's in Here

| File | Description |
|------|-------------|
| `ztlp_xdp.h` | Shared header — constants, map definitions, stat counters |
| `ztlp_xdp.c` | XDP program — the eBPF code that runs in the kernel |
| `loader.c` | Userspace loader — attaches/detaches XDP, manages sessions/peers, reads stats |
| `Makefile` | Build system — clang for BPF, gcc for loader |

## BPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `session_map` | HASH (1024) | 12-byte SessionID | u8 (active flag) | Layer 2 allowlist for client traffic |
| `hello_rate_map` | HASH (1024) | __be32 (source IPv4) | {tokens, last_refill_ns} | HELLO flood protection |
| `stats_map` | PERCPU_ARRAY (8) | u32 (stat index) | u64 (count) | Pipeline counters (client + mesh) |
| `mesh_peer_map` | HASH (256) | 16-byte NodeID | u8 (active flag) | Mesh peer allowlist |
| `rat_bypass_map` | ARRAY (1) | u32 (index 0) | u8 (0/1) | RAT HELLO rate limit bypass toggle |

### Stats Indices

| Index | Name | Category | Meaning |
|-------|------|----------|---------|
| 0 | `layer1_drops` | Client | Failed magic check (not 0x5A37) |
| 1 | `layer2_drops` | Client | Unknown SessionID and not a HELLO |
| 2 | `hello_rate_drops` | Client | HELLO from a rate-limited source IP |
| 3 | `passed` | Client | Packet passed to kernel |
| 4 | `mesh_passed` | Mesh | Mesh packet from authorized peer passed |
| 5 | `mesh_peer_drops` | Mesh | Mesh packet from unauthorized peer dropped |
| 6 | `mesh_forward_passed` | Mesh | FORWARD with valid inner magic passed |
| 7 | `rat_hello_passed` | RAT | HELLO with RAT-sized extension detected |

## Requirements

- **Linux kernel 5.4+** (XDP support required)
- **clang 11+** and **llvm** (BPF compilation)
- **libbpf-dev** (userspace BPF library)
- **linux-headers** (kernel headers for BPF)
- **NIC with XDP driver support** for native mode (Intel i40e, Mellanox mlx5, etc.)
  - XDP generic mode works on any NIC but at lower performance

### Install dependencies (Ubuntu/Debian)

```bash
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) gcc make libelf-dev zlib1g-dev
```

## Build

```bash
cd ebpf
make
```

This produces:
- `ztlp_xdp.o` — BPF object file (loaded into kernel)
- `ztlp-xdp-loader` — Userspace management tool

## Usage

### Attach to an interface

```bash
# Attach XDP program to eth0
sudo ./ztlp-xdp-loader eth0

# The loader stays running (keeps the BPF program alive)
# Press Ctrl+C to exit (program remains attached)
```

### Attach and pre-load sessions

```bash
# Attach and immediately register a session
sudo ./ztlp-xdp-loader eth0 --add-session 5a38864146988e21525315b8
```

### Detach

```bash
sudo ./ztlp-xdp-loader eth0 --detach
```

### Manage sessions

```bash
# Add a session to the allowlist
sudo ./ztlp-xdp-loader eth0 --add-session <24-char-hex-session-id>

# Remove a session
sudo ./ztlp-xdp-loader eth0 --remove-session <24-char-hex-session-id>
```

SessionIDs are 12 bytes (96 bits), represented as 24 hex characters.

### Manage mesh peers

```bash
# Add a mesh peer NodeID to the allowlist
sudo ./ztlp-xdp-loader eth0 --add-peer 0123456789abcdef0123456789abcdef

# Remove a mesh peer
sudo ./ztlp-xdp-loader eth0 --remove-peer 0123456789abcdef0123456789abcdef

# List all authorized mesh peers
sudo ./ztlp-xdp-loader eth0 --list-peers
```

NodeIDs are 16 bytes (128 bits), represented as 32 hex characters.

The mesh peer allowlist is the kernel-level gate for inter-relay traffic.
When a new relay joins the mesh (RELAY_HELLO exchange), the daemon adds its
NodeID to the BPF map. When a relay departs (RELAY_LEAVE) or times out, the
daemon removes the entry. Only packets from authorized peers reach the daemon.

### Configure RAT bypass

```bash
# Enable RAT bypass (RAT HELLOs skip rate limiter)
sudo ./ztlp-xdp-loader eth0 --rat-bypass 1

# Disable RAT bypass (default — all HELLOs rate-limited)
sudo ./ztlp-xdp-loader eth0 --rat-bypass 0
```

When RAT bypass is enabled, HELLO packets large enough to contain a Relay
Admission Token (93 bytes) in their extension area are passed directly to the
kernel stack without consuming a rate-limit token. This allows pre-authenticated
nodes (those with RATs from an ingress relay) to reconnect without being
throttled during reconnection bursts.

**Note:** The XDP program only checks for RAT *presence* (size check). Actual
RAT verification (HMAC-BLAKE2s) happens in the userspace daemon. The bypass is
a performance optimization, not a security gate — invalid RATs are still
rejected by the daemon.

### Read stats

```bash
# All stats (client + mesh)
sudo ./ztlp-xdp-loader eth0 --stats
# Output:
# === ZTLP XDP Pipeline Statistics ===
#
# Client traffic (port 23095):
#   layer1_drops             142857
#   layer2_drops             31415
#   hello_rate_drops         271
#   passed                   98234
#
# Mesh traffic (port 23096):
#   mesh_passed              5621
#   mesh_peer_drops          89
#   mesh_forward_passed      3412
#
# RAT-aware HELLO:
#   rat_hello_passed         127

# Mesh stats only
sudo ./ztlp-xdp-loader eth0 --mesh-stats
```

Stats are per-CPU and aggregated by the loader.

## How It Works

### Client Traffic (Port 23095)

1. **Non-ZTLP traffic** (not UDP port 23095): `XDP_PASS` — untouched
2. **Layer 1 — Magic check**: Read first 2 bytes of UDP payload, compare to `0x5A37`
   - Cost: single 16-bit comparison, nanoseconds
   - Drops: all non-ZTLP UDP noise, random scanners, port probes
3. **HdrLen discrimination**: Read bytes 2-3, mask lower 12 bits
   - HdrLen = 24 → Handshake header, SessionID at byte offset 11
   - HdrLen = 11 → Compact data header, SessionID at byte offset 6
   - Other → Drop (malformed)
4. **Layer 2 — SessionID lookup**: Copy 12-byte SessionID, look up in `session_map`
   - Cost: O(1) BPF hash map read, microseconds, no crypto
   - Found → `XDP_PASS` to kernel for Layer 3 (AEAD verification)
5. **HELLO handling**: If SessionID unknown and MsgType = HELLO (0x01):
   - **RAT detection**: Check if packet is large enough for RAT (header + 93 bytes)
   - If RAT present and bypass enabled → `XDP_PASS` (skip rate limit)
   - Otherwise → Check per-source-IP token bucket (10 tokens/sec, capacity 10)
     - Under limit → `XDP_PASS` (legitimate handshake initiation)
     - Over limit → `XDP_DROP` (HELLO flood attack)
6. **Everything else**: Unknown SessionID + not HELLO → `XDP_DROP`

### Mesh Traffic (Port 23096)

Inter-relay mesh messages share a common wire format:
```
<<msg_type::8, sender_node_id::binary-16, timestamp::64, ...payload>>
```

1. **Peer allowlist check**: Extract sender NodeID (bytes 1–16), look up in `mesh_peer_map`
   - Not found → `XDP_DROP` (unauthorized relay)
   - Found → continue processing
2. **FORWARD messages** (type 0x05): Carry a wrapped ZTLP packet
   - **TTL check**: Read TTL byte — if 0, drop (prevents infinite forwarding loops)
   - **Path length bound**: path_len must be ≤ 16 (prevents unbounded memory access)
   - **Inner magic check**: Read first 2 bytes of inner ZTLP packet, verify 0x5A37
   - If all checks pass → `XDP_PASS`
3. **Other mesh messages** (JOIN, SYNC, PING, PONG, SESSION, LEAVE, DRAIN, DRAIN_CANCEL):
   - From authorized peer → `XDP_PASS`

### RAT-Aware HELLO Processing

Relay Admission Tokens (RATs) are 93-byte signed tokens that prove a node was
authenticated by an ingress relay. They're carried in the HELLO packet's
extension area for transit relay admission.

The XDP program detects RAT presence by checking if the packet payload extends
at least 93 bytes beyond the handshake header. This is a cheap size check —
actual HMAC-BLAKE2s verification is too expensive for XDP and happens in the
userspace daemon.

When `rat_bypass_map[0] == 1`, RAT-bearing HELLOs bypass the per-source-IP
rate limiter. This prevents legitimate pre-authenticated nodes from being
throttled during reconnection bursts (e.g., after a network partition heals
and many clients reconnect simultaneously).

### Integration with the ZTLP Daemon

The XDP program and the ZTLP daemon (Rust client or Elixir relay) share BPF
maps for runtime coordination:

```
ZTLP Daemon (userspace)          XDP Program (kernel)
┌─────────────────────┐          ┌──────────────────────┐
│ Session established  │──write──▶│  session_map         │
│ Session closed       │──delete─▶│  (BPF hash map)      │
│                      │          │                      │
│ Mesh peer discovered │──write──▶│  mesh_peer_map       │
│ Mesh peer departed   │──delete─▶│  (BPF hash map)      │
│                      │          │                      │
│ Config: RAT bypass   │──write──▶│  rat_bypass_map      │
│                      │          │  (BPF array)         │
│                      │          │                      │
│ Read stats           │◀──read──│  stats_map           │
└─────────────────────┘          └──────────────────────┘
```

When a session is established via Noise_XX handshake, the daemon writes the
SessionID to `session_map`. When a mesh peer is discovered via RELAY_HELLO,
the daemon writes the peer's NodeID to `mesh_peer_map`. The XDP program only
reads these maps — it never modifies session or peer state.

## Performance Implications

### Client Path (unchanged)
The client-facing path (port 23095) is identical to before — no additional
overhead for existing traffic. The mesh port check is a separate branch that
only executes for traffic on port 23096.

### Mesh Path
The mesh path adds:
- **One hash map lookup** per mesh packet (NodeID in `mesh_peer_map`)
- **One bounds check + two byte reads** for FORWARD messages (TTL + inner magic)
- All operations are O(1) with no crypto — same performance class as the client path

### Memory
- `mesh_peer_map`: 256 entries × ~20 bytes = ~5KB (negligible)
- `rat_bypass_map`: 1 entry × 5 bytes = 5 bytes
- `stats_map` extended from 4 to 8 entries = ~32 bytes additional per CPU

## License

The eBPF program uses `"Dual MIT/GPL"` as its BPF license string. This is
required because BPF helper functions like `bpf_ktime_get_ns()` are GPL-only
in the kernel. The dual license follows the Linux syscall exception — our
source code is Apache-2.0, but the BPF license declaration allows use of
kernel helpers. This is standard practice (Cilium, Cloudflare, Meta all do the
same).

## Test Plan

While BPF programs can't be unit-tested in a standard environment, the
following test scenarios should be verified on a system with XDP support:

### Functional Tests — Client Traffic

1. **Non-ZTLP traffic passthrough** — TCP, ICMP, and non-23095/23096 UDP traffic
   should pass through unaffected
2. **Layer 1 rejection** — UDP to port 23095 with wrong magic bytes should
   increment `layer1_drops` and be dropped
3. **Layer 2 rejection** — Valid magic but unknown SessionID (and not HELLO)
   should increment `layer2_drops` and be dropped
4. **Layer 2 pass** — Valid magic + known SessionID should increment `passed`
   and reach userspace
5. **HELLO passthrough** — Unknown SessionID but MsgType=HELLO should pass
   (up to rate limit)
6. **HELLO rate limiting** — >10 HELLOs/sec from one IP should start
   incrementing `hello_rate_drops`
7. **HdrLen discrimination** — Both handshake (HdrLen=24) and data (HdrLen=11)
   headers should have SessionID extracted from the correct offset
8. **Malformed HdrLen** — HdrLen values other than 11 or 24 should be dropped

### Functional Tests — Mesh Traffic

9. **Authorized peer pass** — Mesh packet from a NodeID in `mesh_peer_map`
   should increment `mesh_passed` and reach userspace
10. **Unauthorized peer drop** — Mesh packet from an unknown NodeID should
    increment `mesh_peer_drops` and be dropped
11. **FORWARD with valid inner** — FORWARD message with TTL > 0 and inner
    magic 0x5A37 should increment `mesh_forward_passed`
12. **FORWARD with TTL=0** — FORWARD with expired TTL should be dropped
13. **FORWARD with bad inner magic** — FORWARD wrapping non-ZTLP data should
    increment `layer1_drops` and be dropped
14. **FORWARD with excessive path_len** — path_len > 16 should be dropped
15. **All mesh message types** — JOIN, SYNC, PING, PONG, SESSION, LEAVE,
    DRAIN, DRAIN_CANCEL from authorized peers should all pass

### Functional Tests — RAT-Aware HELLO

16. **RAT HELLO detection** — HELLO with payload ≥ header + 93 bytes should
    increment `rat_hello_passed`
17. **RAT bypass enabled** — With `rat_bypass_map[0]=1`, RAT HELLOs should
    pass without consuming rate-limit tokens
18. **RAT bypass disabled** — With `rat_bypass_map[0]=0`, RAT HELLOs should
    still go through the rate limiter

### Performance Tests

19. **Line-rate drop test** — Send millions of packets with wrong magic,
    verify they're all dropped at XDP with no CPU impact on userspace
20. **Session lookup throughput** — Measure packets/sec for known SessionIDs
    passing through the XDP program
21. **Rate limiter accuracy** — Verify the token bucket allows ~10 HELLOs/sec
    per source IP under sustained load
22. **Mesh peer lookup throughput** — Measure mesh packets/sec with 256 peers
    in the allowlist

### Integration Tests

23. **Daemon sync** — Establish a ZTLP session, verify the daemon writes the
    SessionID to the BPF map, verify packets flow, close the session, verify
    the SessionID is removed
24. **Mesh peer lifecycle** — Add a relay peer via the daemon, verify mesh
    packets flow, remove the peer, verify mesh packets are dropped
25. **Live attach/detach** — Attach XDP program to a live interface, verify
    existing connections are unaffected, detach and verify everything recovers
