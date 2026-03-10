# ZTLP XDP/eBPF Packet Filter

Phase 3 of the ZTLP reference implementation — a kernel-level fast-path packet
filter using Linux XDP (eXpress Data Path).

This eBPF program attaches directly to the NIC driver and drops invalid ZTLP
traffic **before it reaches the Linux kernel network stack**. It implements
Layer 1 (magic check) and Layer 2 (SessionID lookup) of the ZTLP admission
pipeline at near line-rate with zero cryptographic cost.

## Architecture

```
                        Inbound UDP Packet
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│  XDP/eBPF Program (NIC driver, before kernel stack)      │
│                                                          │
│  1. Is it UDP to port 23095?                             │
│     └─ No → XDP_PASS (don't touch non-ZTLP traffic)     │
│                                                          │
│  2. Layer 1: Magic == 0x5A37?                            │
│     └─ No → XDP_DROP (nanoseconds, no state)             │
│                                                          │
│  3. Layer 2: SessionID in BPF hash map?                  │
│     └─ Yes → XDP_PASS (microseconds, O(1) lookup)        │
│     └─ No → Is it a HELLO? Rate limit per source IP      │
│              └─ Under limit → XDP_PASS                   │
│              └─ Over limit → XDP_DROP                    │
│                                                          │
│  Stats: per-CPU counters for each drop reason            │
└──────────────────────────────────────────────────────────┘
                               │
                     XDP_PASS packets only
                               │
                               ▼
┌──────────────────────────────────────────────────────────┐
│  Kernel → ZTLP Daemon (userspace)                        │
│                                                          │
│  Layer 3: HeaderAuthTag AEAD verification                │
│  (ChaCha20-Poly1305 — the expensive check)               │
│                                                          │
│  Only reaches here if Layers 1+2 passed in the XDP path  │
└──────────────────────────────────────────────────────────┘
```

Under DDoS, the vast majority of attack traffic dies at the XDP level — never
consuming kernel CPU, never allocating socket buffers, never reaching the ZTLP
daemon. Only legitimate packets (known sessions or rate-limited HELLOs) pass
through to the full cryptographic verification.

## What's in Here

| File | Description |
|------|-------------|
| `ztlp_xdp.h` | Shared header — constants, map definitions, stat counters |
| `ztlp_xdp.c` | XDP program — the eBPF code that runs in the kernel |
| `loader.c` | Userspace loader — attaches/detaches XDP, manages session map, reads stats |
| `Makefile` | Build system — clang for BPF, gcc for loader |

## BPF Maps

| Map | Type | Key | Value | Purpose |
|-----|------|-----|-------|---------|
| `session_map` | HASH (1024) | 12-byte SessionID | u8 (active flag) | Layer 2 allowlist |
| `hello_rate_map` | HASH (1024) | __be32 (source IPv4) | {tokens, last_refill_ns} | HELLO flood protection |
| `stats_map` | PERCPU_ARRAY (4) | u32 (stat index) | u64 (count) | Pipeline counters |

### Stats Indices

| Index | Name | Meaning |
|-------|------|---------|
| 0 | `layer1_drops` | Failed magic check (not 0x5A37) |
| 1 | `layer2_drops` | Unknown SessionID and not a HELLO |
| 2 | `hello_rate_drops` | HELLO from a rate-limited source IP |
| 3 | `passed` | Packet passed to kernel |

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

### Read stats

```bash
sudo ./ztlp-xdp-loader eth0 --stats
# Output:
# layer1_drops: 142857
# layer2_drops: 31415
# hello_rate_drops: 271
# passed: 98234
```

Stats are per-CPU and aggregated by the loader.

## How It Works

### Packet Processing Flow

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
   - Check per-source-IP token bucket (10 tokens/sec, capacity 10)
   - Under limit → `XDP_PASS` (legitimate handshake initiation)
   - Over limit → `XDP_DROP` (HELLO flood attack)
6. **Everything else**: Unknown SessionID + not HELLO → `XDP_DROP`

### Integration with the ZTLP Daemon

The XDP program and the ZTLP daemon (Rust client or Elixir relay) share the
`session_map` BPF map:

```
ZTLP Daemon (userspace)          XDP Program (kernel)
┌─────────────────────┐          ┌──────────────────┐
│ Session established  │──write──▶│  session_map     │
│ Session closed       │──delete─▶│  (BPF hash map)  │
│                      │          │                  │
│ Read stats           │◀──read──│  stats_map       │
└─────────────────────┘          └──────────────────┘
```

When a session is established via Noise_XX handshake, the daemon writes the
SessionID to the BPF map. When a session closes or times out, the daemon
removes it. The XDP program only reads the map — it never modifies session
state.

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

### Functional Tests

1. **Non-ZTLP traffic passthrough** — TCP, ICMP, and non-23095 UDP traffic
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

### Performance Tests

9. **Line-rate drop test** — Send millions of packets with wrong magic,
   verify they're all dropped at XDP with no CPU impact on userspace
10. **Session lookup throughput** — Measure packets/sec for known SessionIDs
    passing through the XDP program
11. **Rate limiter accuracy** — Verify the token bucket allows ~10 HELLOs/sec
    per source IP under sustained load

### Integration Tests

12. **Daemon sync** — Establish a ZTLP session, verify the daemon writes the
    SessionID to the BPF map, verify packets flow, close the session, verify
    the SessionID is removed
13. **Live attach/detach** — Attach XDP program to a live interface, verify
    existing connections are unaffected, detach and verify everything recovers
