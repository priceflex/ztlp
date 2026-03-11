# ZTLP Transport Optimization

## Overview

ZTLP uses UDP as its transport layer. Each ZTLP data packet is an independent
UDP datagram containing a compact header (magic, session ID, sequence number,
auth tag) followed by a ChaCha20-Poly1305 encrypted payload.

At high throughput, the per-packet system call overhead becomes a bottleneck.
Sending 100,000 packets/second means 100,000 `sendto()` calls and 100,000
`recvfrom()` calls — each requiring a user/kernel context switch. On modern
Linux systems, two kernel features can dramatically reduce this overhead:

- **GSO (Generic Segmentation Offload):** Hand the kernel one large buffer
  containing multiple logical UDP datagrams plus a segment size. The kernel
  (or NIC hardware) splits them into individual packets with a single
  `sendmsg()` system call.

- **GRO (Generic Receive Offload):** The kernel coalesces multiple incoming
  UDP datagrams of the same size into a single large buffer. The application
  reads all of them with one `recvmsg()` call and splits by the segment size
  reported via a `UDP_GRO` cmsg.

Both features are inspired by their TCP equivalents (TSO/GRO) and are used in
production by Cloudflare's QUIC implementation, WireGuard, and Tailscale's
userspace networking stack.

## Architecture

### Send Path (GSO + sendmmsg + BatchSender)

The send path uses a three-tier strategy, automatically selecting the best
available method:

```
  Application layer: BatchSender.send_batch(&packets, dest)
         │
         ▼
  ┌──────────────────────────────────────────────────────┐
  │  Tier 1: GSO (UDP_SEGMENT cmsg)                      │
  │  Single sendmsg() with all segments in one buffer    │
  │  Requirement: all packets same size (except last)    │
  │  Available: Linux ≥ 4.18                             │
  └──────────┬────────────────────────────────┬──────────┘
             │ GSO available + uniform sizes  │ fallback
             ▼                                ▼
  ┌────────────────────────┐   ┌─────────────────────────┐
  │  sendmsg(fd, GSO cmsg) │   │  Tier 2: sendmmsg()     │
  │  1 syscall, N packets  │   │  1 syscall, N messages   │
  └────────────────────────┘   │  Mixed sizes OK          │
                               │  Available: Linux ≥ 3.0  │
                               └──────────┬──────────────┘
                                          │ fallback
                                          ▼
                               ┌─────────────────────────┐
                               │  Tier 3: Individual      │
                               │  N × send_to() calls    │
                               │  Always available        │
                               └─────────────────────────┘
```

**GSO buffer assembly:** When GSO is selected, the `UdpSender` concatenates
all packet payloads into a single contiguous buffer and sets the
`UDP_SEGMENT` cmsg to the common segment size. All packets except the last
must be exactly that size; the last may be shorter. If the batch exceeds
`MAX_GSO_SEGMENTS` (64), it is split into multiple GSO sends.

**sendmmsg path:** When packets have varying sizes (can't use GSO) or GSO
isn't available, `sendmmsg()` sends multiple datagrams in a single system
call. Each datagram has its own `msghdr` with independent lengths. This
still saves most of the per-packet overhead.

**Individual fallback:** On non-Linux platforms or when both GSO and sendmmsg
are unavailable, packets are sent with individual `send_to()` calls.

### Receive Path (GRO + GroReceiver + BatchReceiver)

```
  Kernel: coalesces datagrams into one buffer (when GRO enabled)
         │
         ▼
  ┌──────────────────────────────────────────────────────┐
  │  GroReceiver.recv()                                  │
  │  recvmsg() with cmsg parsing                         │
  │  Returns RecvBatch { buffer, segments[] }            │
  └──────────┬───────────────────────────────────────────┘
             │
             ▼
  ┌──────────────────────────────────────────────────────┐
  │  BatchReceiver (ergonomic wrapper)                    │
  │  Iterates segments, provides individual packet slices│
  └──────────────────────────────────────────────────────┘
```

**GRO enabled:** The `GroReceiver` calls `recvmsg()` with a 1 MB buffer. If
the kernel coalesced multiple datagrams, the `UDP_GRO` cmsg reports the
segment size. `split_gro_segments()` divides the buffer into individual
packet slices based on that size.

**GRO disabled/unavailable:** Falls back to standard `recv_from()`, returning
a single-segment `RecvBatch` per call.

**BatchReceiver:** Wraps `GroReceiver` for tunnel integration. The tunnel
bridge iterates `batch.segments()` and processes each as an independent
ZTLP packet.

## Configuration

### Config File (~/.ztlp/config.toml)

```toml
[transport]
gso = "auto"  # auto | enabled | disabled
```

- **auto** (default): Probe the socket at startup. Use GSO/GRO if available,
  fall back gracefully if not.
- **enabled**: Require GSO. Fail if the kernel doesn't support it.
- **disabled**: Never use GSO/GRO. Always use sendmmsg or individual sends.

### Runtime Detection

At startup, ZTLP probes GSO and GRO independently:

1. **GSO probe (`detect_gso`):** Creates a UDP socket and calls
   `setsockopt(fd, SOL_UDP, UDP_SEGMENT, &test_value)`. If the kernel
   accepts the option, GSO is available. The option is immediately cleared
   (GSO is set per-send via cmsg, not as a persistent socket option).

2. **GRO probe (`detect_gro`):** Calls
   `setsockopt(fd, SOL_UDP, UDP_GRO, &1)`. Unlike GSO, GRO is **left
   enabled** on the socket because it's a receive-side option that affects
   all subsequent `recvmsg()` calls. If the kernel rejects the option,
   GRO is unavailable.

Both probes are safe — they don't affect other sockets or require
elevated privileges.

### GsoMode

The `GsoMode` enum controls behavior:

| Mode | GSO | GRO | sendmmsg |
|------|-----|-----|----------|
| Auto | if available | if available | fallback |
| Enabled | required | if available | fallback |
| Disabled | never | never | primary on Linux |

## Kernel Requirements

| Feature | Minimum Kernel | Constant | Socket Level | Description |
|---------|---------------|----------|-------------|-------------|
| UDP_SEGMENT (GSO) | Linux 4.18 | 103 | SOL_UDP (17) | Send-side segmentation offload |
| UDP_GRO | Linux 5.0 | 104 | SOL_UDP (17) | Receive-side coalescing |
| sendmmsg() | Linux 3.0 | N/A | syscall 307 | Multi-message send |

Non-Linux platforms (macOS, Windows, BSDs) fall back to individual
`send_to()`/`recv_from()` calls. The protocol works identically — only
the I/O efficiency differs.

## Benchmarking

### Quick Start

```bash
# Build and run the throughput benchmark (100MB, 5 iterations)
bash bench/run_throughput.sh

# Quick sanity test (10MB, 1 iteration)
bash bench/run_throughput.sh --quick

# Custom parameters
bash bench/run_throughput.sh --size 1073741824 --repeat 10

# Single mode
bash bench/run_throughput.sh --mode raw

# Machine-readable JSON
bash bench/run_throughput.sh --json
```

### Understanding Results

The benchmark measures end-to-end file transfer throughput in six modes:

| Mode | What it measures |
|------|-----------------|
| **Raw TCP** | Baseline ceiling — direct TCP loopback with no ZTLP overhead |
| **ZTLP (no opts)** | Full ZTLP tunnel (handshake → encrypt → UDP → decrypt) with GSO/GRO disabled |
| **ZTLP (GSO)** | Same tunnel but with GSO enabled for sends |
| **ZTLP (GRO)** | Same tunnel but with GRO enabled for receives |
| **ZTLP (GSO+GRO)** | Both GSO and GRO enabled |
| **ZTLP (auto)** | Automatic detection — same as GSO+GRO when both available |

**Key metrics:**
- **Throughput (MB/s or GB/s):** Higher is better
- **Time:** Total transfer wall-clock time
- **Overhead vs Raw:** How much slower than raw TCP (lower is better)

**What to look for:**
- GSO should improve throughput over no-opts by reducing send syscalls
- GRO should improve throughput by reducing receive syscalls
- GSO+GRO combined should approach the highest tunnel throughput
- The gap between ZTLP and raw TCP represents encryption + framing + reliability overhead

### Expected Performance

Performance varies significantly by system. Reference points from the industry:

- **Cloudflare (QUIC):** GSO improved UDP throughput by 3–5× on their edge servers
- **Tailscale:** Reports GSO+GRO reduces per-packet CPU cost by ~50% in their WireGuard userspace implementation

On ZTLP, typical results on modern Linux (4+ vCPUs, kernel 5.x+):

| Scenario | Expected range |
|----------|---------------|
| Raw TCP loopback | 2–8 GB/s |
| ZTLP (no opts) | 200–1000 MB/s |
| ZTLP (GSO) | 1.2–2× no-opts throughput |
| ZTLP (GSO+GRO) | 1.5–3× no-opts throughput |
| ZTLP overhead vs raw | 40–80% (varies by payload size and CPU) |

On constrained systems (1 vCPU, KVM guests without GSO/GRO passthrough),
expect lower numbers. GSO/GRO may show as "unavailable" in some container
or VM environments even on recent kernels.

## Troubleshooting

### GSO shows "unavailable"

**Common causes:**
- **Old kernel:** GSO requires Linux ≥ 4.18. Check with `uname -r`.
- **KVM/container limitations:** Some hypervisors don't expose the `UDP_SEGMENT`
  socket option to guests. Try on bare metal or a newer host kernel.
- **Network namespace isolation:** In some container runtimes, socket options
  are restricted by seccomp profiles. Check if `setsockopt(SOL_UDP, 103, ...)`
  is allowed.

**Verification:** Run the benchmark binary directly:
```bash
cargo run --release --bin ztlp-throughput -- --mode raw --size 1048576 --repeat 1
# Look for "GSO: available" or "GSO: unavailable" in the output
```

**Impact:** Without GSO, the system falls back to `sendmmsg()` (still good)
or individual sends. The protocol works correctly — only throughput is affected.

### GRO shows "unavailable"

**Same causes as GSO**, plus:
- **Kernel < 5.0:** `UDP_GRO` was added in Linux 5.0.
- **Socket option 104 not recognized:** Verify with
  `python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(17, 104, 1)"`

**Impact:** Without GRO, each `recvmsg()` returns exactly one packet. The
receive path works correctly but with higher syscall overhead.

### Tunnel benchmark times out

The ZTLP tunnel benchmark has a 60-second per-transfer timeout. On very
constrained systems (1 vCPU, 512 MB RAM), large transfers may time out.

**Fix:** Use a smaller transfer size:
```bash
bash bench/run_throughput.sh --size 10485760 --repeat 1   # 10 MB
```

**Other causes:**
- High system load (other processes consuming CPU)
- Aggressive CPU frequency scaling (governor set to powersave)
- Insufficient socket buffer sizes (the benchmark uses default buffers)

## API Reference

### gso.rs (1643 lines)

Core GSO/GRO implementation with detection, sending, and receiving.

**Key types:**
- `GsoCapability` — enum: `Available { max_segments }` or `Unavailable`
- `GroCapability` — enum: `Available` or `Unavailable`
- `GsoMode` — config enum: `Auto`, `Enabled`, `Disabled`
- `SendStrategy` — enum: `Gso`, `SendMmsg`, `Individual`
- `UdpSender` — high-level send wrapper (auto-selects best strategy)
- `GroReceiver` — high-level receive wrapper (GRO or plain recv)
- `RecvBatch` — received data with segment descriptors
- `GroSegment` — offset + length + source address for one segment

**Key functions:**
- `detect_gso(socket) → GsoCapability` — probe GSO support
- `detect_gro(socket) → GroCapability` — probe and enable GRO
- `enable_gro(socket) → io::Result<()>` — enable GRO on a socket
- `send_gso(socket, segments, segment_size, dest) → io::Result<usize>` — GSO sendmsg
- `send_mmsg(socket, packets, dest) → io::Result<usize>` — sendmmsg syscall
- `recv_gro_sync(fd, buf) → io::Result<(usize, SocketAddr, Option<u16>)>` — GRO recvmsg
- `split_gro_segments(total_len, gso_size, addr) → Vec<GroSegment>` — split coalesced buffer
- `assemble_gso_buffer(segments, segment_size) → io::Result<Vec<u8>>` — concatenate for GSO

**Constants:**
- `MAX_GSO_SEGMENTS = 64` — kernel-enforced limit per GSO send
- `GRO_RECV_BUF_SIZE = 1,048,576` — 1 MB receive buffer for GRO
- `UDP_SEGMENT = 103` (Linux) — GSO socket option
- `UDP_GRO = 104` (Linux) — GRO socket option
- `SOL_UDP = 17` (Linux) — UDP socket level

### batch.rs (332 lines)

Tunnel-integrated batch sender.

**BatchSender:**
```rust
pub struct BatchSender { inner: UdpSender }

impl BatchSender {
    pub fn new(socket: Arc<UdpSocket>, mode: GsoMode) -> Self;
    pub fn with_capability(socket, mode, capability) -> Self;
    pub fn strategy(&self) -> SendStrategy;
    pub fn capability(&self) -> GsoCapability;
    pub async fn send_batch(&self, packets: &[Vec<u8>], dest: SocketAddr) -> io::Result<usize>;
    pub async fn send_batch_slices(&self, packets: &[&[u8]], dest: SocketAddr) -> io::Result<usize>;
    pub async fn send_one(&self, packet: &[u8], dest: SocketAddr) -> io::Result<usize>;
}
```

The `BatchSender` wraps `UdpSender` and provides the primary interface for
the tunnel bridge's TCP→ZTLP sender loop. It collects all encrypted packets
from one TCP read and flushes them as a single GSO/sendmmsg/individual batch.

### gro_batch.rs (189 lines)

Tunnel-integrated batch receiver.

**BatchReceiver:**
```rust
pub struct BatchReceiver { inner: GroReceiver }

impl BatchReceiver {
    pub fn new(socket: Arc<UdpSocket>, mode: GsoMode) -> Self;
    pub fn is_gro_enabled(&self) -> bool;
    pub async fn recv(&mut self) -> io::Result<RecvBatch>;
}
```

Wraps `GroReceiver` and provides ergonomic access to individual ZTLP packet
slices from a single receive call. The tunnel bridge iterates
`batch.segments()` and processes each as an independent ZTLP packet.

### transport.rs — Batch Methods

`TransportNode` has two batch methods that integrate with the GSO/GRO layer:

```rust
impl TransportNode {
    /// Send multiple raw packets using GSO/sendmmsg when available.
    pub async fn send_batch(&self, packets: &[Vec<u8>], dest: SocketAddr)
        -> Result<usize, TransportError>;

    /// Receive a batch of packets using GRO when available.
    pub async fn recv_batch(&self, gro_receiver: &mut GroReceiver)
        -> Result<Vec<(Vec<u8>, SocketAddr)>, TransportError>;
}
```

## Files

| File | Lines | Purpose |
|------|-------|---------|
| `src/gso.rs` | 1643 | GSO/GRO detection, send, receive, UdpSender, GroReceiver |
| `src/batch.rs` | 332 | BatchSender for tunnel integration |
| `src/gro_batch.rs` | 189 | BatchReceiver for tunnel integration |
| `src/transport.rs` | 230 | TransportNode with send_batch/recv_batch |
| `src/bin/ztlp-throughput.rs` | 556 | Throughput benchmark binary |
| `tests/throughput_tests.rs` | ~680 | Integration tests for GSO/GRO/batch |
| `bench/run_throughput.sh` | ~400 | Benchmark runner script |
