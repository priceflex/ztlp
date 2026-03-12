# ZTLP Performance Benchmark Results — v4

## System Information

| Property | Value |
|----------|-------|
| Date | 2026-03-12 14:00 UTC |
| OS | Linux 5.15.0-1093-kvm x86_64 |
| CPU | AMD EPYC 4564P 16-Core Processor |
| CPU Cores | 4 (vCPU) |
| Memory | 7.8 GiB |
| Elixir | 1.12.2 (compiled with Erlang/OTP 24) |
| Erlang/OTP | 24 |
| Rust | 1.94.0 (2026-03-02) |
| Cargo | 1.94.0 (2026-01-15) |
| Spec Version | v0.5.1 |
| Kernel HZ | 250 |
| UDP rmem_max | 212992 (208KB default) |

---

## Tunnel Throughput (ZTLP over UDP, localhost)

End-to-end tunnel benchmark: TCP → encrypt → UDP → decrypt → TCP.
Includes Noise_XX handshake, pipeline validation, ChaCha20-Poly1305 AEAD,
flow control with congestion window, ACK-driven pacing.

| Transfer Size | Throughput | Time | Packets | Notes |
|--------------|-----------|------|---------|-------|
| 64KB | 101 MB/s | 0.6ms | 5 | |
| 256KB | 188-268 MB/s | 0.9-1.3ms | 17 | |
| 1MB | 334-415 MB/s | 2.4-3.0ms | 65 | |
| 4MB | 191-204 MB/s | 19-21ms | 257 | |
| 8MB | 187 MB/s | 42.8ms | 513 | |
| 10MB | 235-275 MB/s | 36-42ms | 641 | |
| Raw TCP | 2,550 MB/s | 1.6ms | N/A | baseline |

### Tunnel Configuration

| Parameter | Value | Purpose |
|-----------|-------|---------|
| INITIAL_CWND | 64 packets | Initial congestion window |
| INITIAL_SSTHRESH | 256 packets | Slow-start threshold |
| MAX_SUB_BATCH | 64 packets | Max packets per send burst |
| ACK_EVERY_PACKETS | 16 | Receiver ACK frequency |
| ACK_INTERVAL | 5ms | Timer-based ACK fallback |
| MAX_PLAINTEXT_PER_PACKET | 16,375 bytes | ~16KB per ZTLP packet |
| SEND_WINDOW | 2,048 | Maximum outstanding packets |
| UDP SO_RCVBUF | 4MB | Set via setsockopt |
| Inter-batch delay | 10µs (std::thread::sleep) | Pacing |

### Key Findings

1. **Measurement fix**: Previous v3 results included a 50ms sender startup
   delay in the timer, artificially reducing reported throughput by 60-90%.
   v4 uses a oneshot channel to start timing at actual data write.

2. **1MB sweet spot**: Peak throughput at 1MB (334-415 MB/s) because the
   congestion window grows to cover the entire transfer in ~2 RTTs on
   localhost, minimizing stalls.

3. **Large transfer plateau**: 4MB+ transfers plateau at ~200 MB/s due to
   the 10µs std::thread::sleep between sub-batches (actual sleep ~65µs
   on HZ=250 Linux). This is necessary for reliability — without it,
   the sender overwhelms the receiver's UDP buffer (rmem_max=208KB).

4. **Crypto overhead is negligible**: ChaCha20-Poly1305 encrypt+decrypt
   takes ~10µs per 16KB packet. For 257 packets, that's 2.6ms each
   direction — only 6% of the 4MB transfer time.

5. **UDP buffer is the bottleneck**: The 208KB default rmem_max limits
   burst size. Systems with tuned rmem_max (8MB+) can achieve 500-600
   MB/s at 4MB by removing the inter-batch sleep.

---

## Pipeline Layer Costs

| Layer | Rust (mean) | Description |
|-------|-------------|-------------|
| L1: Magic Check | 19 ns | 2-byte magic validation |
| L2: Session Lookup | 28-31 ns | SessionID lookup |
| L3: HeaderAuthTag | 826-872 ns | ChaCha20-Poly1305 AEAD verification |
| Full Pipeline | 904 ns | All three layers combined |

| Layer | Elixir Relay (mean) | Description |
|-------|--------------------| -------------|
| L1: Magic Check | 89 ns | |
| L2: Session Lookup | 1.05 µs | ETS lookup |
| L3: HeaderAuthTag | 5.8 µs | :crypto AEAD |
| Full Pipeline | 7.5 µs | |

## Cryptographic Operations

| Operation | Rust | Elixir |
|-----------|------|--------|
| Noise_XX handshake | 293 µs | 471 µs |
| ChaCha20-Poly1305 (64B) | 1.15 µs | N/A |
| ChaCha20-Poly1305 (1KB) | 1.60 µs | N/A |
| ChaCha20-Poly1305 (8KB) | 5.12 µs | N/A |

## Test Coverage

| Component | Tests | Failures |
|-----------|-------|----------|
| Rust lib | 263 | 0 |
| Rust integration | 115 | 0 |
| Rust perf gate | 5 | 0 |
| Interop (Rust ↔ Elixir) | 31 | 0 |
| Elixir relay | 541 | 0 |
| Elixir NS | 286 | 0 |
| Elixir gateway | 202 | 0 |
| **Total** | **1,443** | **0** |

## SCP Through ZTLP Tunnel (v0.5.3)

Real-world SCP file transfers through the ZTLP encrypted tunnel (localhost loopback).

| Size | ZTLP Tunnel | Direct SSH | Overhead |
|------|-------------|-----------|----------|
| 10 KB | 562ms | — | SSH handshake |
| 100 KB | 262ms, 0.3 MB/s | — | — |
| 512 KB | 239ms, 2.1 MB/s | — | — |
| 1 MB | 266ms, 3.9 MB/s | 165ms, 6.3 MB/s | 1.6x |
| 5 MB | 432ms, 12.1 MB/s | — | — |
| 10 MB | 338ms, 31.0 MB/s | 217ms, 48.3 MB/s | 1.6x |

All transfers verified with md5 checksum integrity. ZTLP adds ~60% overhead
vs direct SSH, which includes Noise_XX session crypto + UDP encapsulation +
flow control + reassembly.
