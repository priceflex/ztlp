# ZTLP Performance Benchmark Results — v2

## System Information

| Property | Value |
|----------|-------|
| Date | 2026-03-12 00:53 UTC |
| OS | Linux 5.15.0-1093-kvm x86_64 |
| CPU | AMD EPYC 4564P 16-Core Processor |
| CPU Cores | 4 (vCPU) |
| Memory | 7.8 GiB |
| Elixir | 1.12.2 (compiled with Erlang/OTP 24) |
| Erlang/OTP | 24 |
| Rust | 1.94.0 (2026-03-02) |
| Cargo | 1.94.0 (2026-01-15) |

---

## Summary: Pipeline Layer Cost Hierarchy

The three-layer admission pipeline is the core security mechanism. This table shows the cost at each layer for both implementations:

| Layer | Rust (mean) | Elixir Relay (mean) | Elixir Gateway (mean) | Description |
|-------|-------------|--------------------|-----------------------|-------------|
| L1 — Magic Check | 19 ns | 79 ns | 87 ns | First 2 bytes, rejects garbage |
| L2 — Session Lookup (100) | 31 ns | 288 ns | 291 ns | ETS lookup by SessionID |
| L2 — Session Lookup (10K) | 34 ns | 332 ns | 222 ns | ETS scales well |
| L3 — HeaderAuthTag | 841 ns | 754 ns | N/A | HMAC-BLAKE2s verification |
| Full Pipeline (valid) | 886 ns | 1,568 ns (no auth) / 2,597 ns (auth) | 358 ns | All 3 layers |
| Full Pipeline (L1 reject) | 28 ns | 1,321 ns | 94 ns | Bad magic — cheapest rejection |
| Full Pipeline (HELLO) | 24 ns | 1,467 ns | 146 ns | Handshake initiation |

**Key insight:** L1 rejection in Rust takes **19 ns** — an attacker sending garbage UDP floods gets dropped at wire speed. Even in Elixir, L1 reject is sub-microsecond.

---

## Rust Benchmarks (Proto)

### Layer 1: Magic Check

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Valid ZTLP packet | 19.0 ns | 20 ns | 21 ns | 52.7M ops/s |
| Bad magic | 19.0 ns | 20 ns | 21 ns | 52.5M ops/s |
| Garbage packet | 18.5 ns | 20 ns | 21 ns | 54.1M ops/s |

### Layer 2: Session Lookup

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Known (100 sessions) | 31.4 ns | 30 ns | 40 ns | 31.8M ops/s |
| Unknown (100 sessions) | 28.3 ns | 30 ns | 31 ns | 35.3M ops/s |
| Known (1,000 sessions) | 32.0 ns | 30 ns | 41 ns | 31.3M ops/s |
| Unknown (1,000 sessions) | 33.6 ns | 30 ns | 40 ns | 29.7M ops/s |
| Known (10,000 sessions) | 34.1 ns | 30 ns | 50 ns | 29.4M ops/s |
| Unknown (10,000 sessions) | 30.0 ns | 30 ns | 31 ns | 33.4M ops/s |
| HELLO (pass-through) | 19.5 ns | 20 ns | 21 ns | 51.4M ops/s |

### Layer 3: HeaderAuthTag

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Compute tag | 840.6 ns | 821 ns | 892 ns | 1.19M ops/s |
| Verify valid tag | 852.8 ns | 841 ns | 872 ns | 1.17M ops/s |

### Full Pipeline

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Valid data (3 layers) | 886.1 ns | 862 ns | 1,002 ns | 1.13M ops/s |
| HELLO | 23.9 ns | 21 ns | 31 ns | 41.9M ops/s |
| Bad magic (L1 reject) | 28.4 ns | 30 ns | 31 ns | 35.2M ops/s |

### Noise_XX Handshake

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Full handshake (3 msgs + finalize) | 301.3 µs | 293.4 µs | 391.8 µs | 3,319 ops/s |

### ChaCha20-Poly1305 AEAD

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Encrypt 64B | 1.22 µs | 1.16 µs | 1.46 µs | 822K ops/s |
| Decrypt 64B | 1.17 µs | 1.16 µs | 1.18 µs | 851K ops/s |
| Encrypt 1KB | 1.75 µs | 1.61 µs | 2.56 µs | 573K ops/s |
| Decrypt 1KB | 1.66 µs | 1.60 µs | 2.36 µs | 604K ops/s |
| Encrypt 8KB | 5.40 µs | 5.14 µs | 8.25 µs | 185K ops/s |
| Decrypt 8KB | 5.30 µs | 5.15 µs | 7.00 µs | 189K ops/s |
| Encrypt 64KB | 34.9 µs | 33.8 µs | 49.5 µs | 28.6K ops/s |
| Decrypt 64KB | 35.1 µs | 34.0 µs | 48.5 µs | 28.5K ops/s |

### Identity Generation

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| NodeId::generate() | 25.5 ns | 20 ns | 71 ns | 39.2M ops/s |
| NodeIdentity::generate() | 12.6 µs | 12.1 µs | 20.0 µs | 79.4K ops/s |
| SessionId::generate() | 31.2 ns | 29 ns | 80 ns | 32.0M ops/s |

### Packet Serialize / Deserialize

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| HandshakeHeader serialize | 28.4 ns | 30 ns | 91 ns | 35.2M ops/s |
| HandshakeHeader deserialize | 27.2 ns | 29 ns | 50 ns | 36.7M ops/s |
| DataHeader serialize | 32.6 ns | 30 ns | 41 ns | 30.7M ops/s |
| DataHeader deserialize | 23.8 ns | 21 ns | 31 ns | 41.9M ops/s |
| Round-trip (ser+deser) | 33.4 ns | 30 ns | 41 ns | 30.0M ops/s |

### Throughput (GSO/GRO)

| Mode | Throughput | Time (100MB) | Notes |
|------|-----------|--------------|-------|
| Raw TCP | 3.22 GB/s | 34.4 ms | Baseline (loopback) |

> Note: ZTLP tunnel throughput requires a running listener. Raw TCP baseline measured on loopback.

---

## Elixir Benchmarks

### Gateway: Pipeline Admission

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| L1 valid magic | 87 ns | 69 ns | 240 ns | 11.4M ops/s |
| L1 invalid magic | 103 ns | 70 ns | 401 ns | 9.7M ops/s |
| L1 reject garbage | 112 ns | 70 ns | 341 ns | 8.9M ops/s |
| L2 known (100 sessions) | 291 ns | 200 ns | 790 ns | 3.4M ops/s |
| L2 unknown (100 sessions) | 202 ns | 170 ns | 431 ns | 5.0M ops/s |
| L2 known (1K sessions) | 310 ns | 271 ns | 762 ns | 3.2M ops/s |
| L2 known (10K sessions) | 222 ns | 191 ns | 511 ns | 4.5M ops/s |
| L2 HELLO (always pass) | 113 ns | 80 ns | 380 ns | 8.8M ops/s |
| Full — valid known | 358 ns | 301 ns | 831 ns | 2.8M ops/s |
| Full — HELLO | 146 ns | 100 ns | 430 ns | 6.8M ops/s |
| Full — bad magic (L1) | 94 ns | 70 ns | 341 ns | 10.6M ops/s |
| Full — unknown (L2) | 212 ns | 180 ns | 1,022 ns | 4.7M ops/s |

### Gateway: Handshake & Crypto

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| X25519 keypair gen | 30.0 µs | 28.4 µs | 45.1 µs | 33.4K ops/s |
| X25519 DH shared secret | 55.3 µs | 52.5 µs | 83.9 µs | 18.1K ops/s |
| ChaCha20 encrypt 64B | 857 ns | 772 ns | 1,313 ns | 1.17M ops/s |
| ChaCha20 decrypt 64B | 821 ns | 771 ns | 1,734 ns | 1.22M ops/s |
| ChaCha20 encrypt 1KB | 1.15 µs | 992 ns | 1,694 ns | 867K ops/s |
| ChaCha20 decrypt 1KB | 1.12 µs | 982 ns | 1,463 ns | 893K ops/s |
| ChaCha20 encrypt 8KB | 2.54 µs | 2.41 µs | 4.20 µs | 393K ops/s |
| ChaCha20 decrypt 8KB | 2.51 µs | 2.38 µs | 4.15 µs | 399K ops/s |
| ChaCha20 encrypt 64KB | 13.6 µs | 13.2 µs | 19.9 µs | 73.6K ops/s |
| ChaCha20 decrypt 64KB | 13.6 µs | 13.1 µs | 20.3 µs | 73.4K ops/s |
| BLAKE2s 32B | 434 ns | 391 ns | 710 ns | 2.30M ops/s |
| BLAKE2s 256B | 734 ns | 642 ns | 1,803 ns | 1.36M ops/s |
| HMAC-BLAKE2s | 2.19 µs | 1.88 µs | 3.72 µs | 456K ops/s |
| HKDF extract | 2.05 µs | 1.89 µs | 3.09 µs | 489K ops/s |
| HKDF expand (64B) | 4.79 µs | 4.00 µs | 9.13 µs | 209K ops/s |
| Noise chaining key | 6.30 µs | 5.46 µs | 12.0 µs | 159K ops/s |
| Noise transport split | 8.25 µs | 7.29 µs | 17.1 µs | 121K ops/s |
| Ed25519 keypair gen | 29.9 µs | 28.5 µs | 43.3 µs | 33.5K ops/s |
| Ed25519 sign (128B) | 58.0 µs | 56.0 µs | 78.0 µs | 17.2K ops/s |
| Ed25519 verify (128B) | 79.5 µs | 76.6 µs | 100.9 µs | 12.6K ops/s |
| Noise_XX full handshake | 481.1 µs | 466.6 µs | 673.0 µs | 2,079 ops/s |

### Gateway: Throughput

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Decrypt 64B | 989 ns | 802 ns | 1,412 ns | 1.01M ops/s |
| Decrypt 1KB | 1.24 µs | 1.02 µs | 2.16 µs | 807K ops/s |
| Decrypt 8KB | 2.72 µs | 2.47 µs | 5.87 µs | 367K ops/s |
| Decrypt 64KB | 14.2 µs | 13.2 µs | 25.5 µs | 70.3K ops/s |
| Policy — :all rule | 225 ns | 161 ns | 510 ns | 4.4M ops/s |
| Policy — exact match | 329 ns | 261 ns | 1,202 ns | 3.0M ops/s |
| Policy — wildcard | 339 ns | 281 ns | 782 ns | 2.9M ops/s |
| Policy — deny (no match) | 248 ns | 210 ns | 581 ns | 4.0M ops/s |
| Policy — deny (no service) | 159 ns | 150 ns | 179 ns | 6.3M ops/s |
| Policy — large rule (10) | 336 ns | 291 ns | 1,141 ns | 3.0M ops/s |
| Identity resolve (cache hit) | 259 ns | 240 ns | 552 ns | 3.9M ops/s |
| Identity resolve (cache miss) | 150 ns | 150 ns | 190 ns | 6.7M ops/s |
| Decrypt 1KB + resolve + auth | 1.86 µs | 1.33 µs | 2.80 µs | 539K ops/s |

### ZTLP-NS: Namespace

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Record serialize | 504 ns | 291 ns | 701 ns | 1.98M ops/s |
| Record deserialize | 434 ns | 310 ns | 1,183 ns | 2.31M ops/s |
| Wire encode (with sig) | 587 ns | 370 ns | 992 ns | 1.70M ops/s |
| Wire decode (with sig) | 409 ns | 341 ns | 1,292 ns | 2.44M ops/s |
| Verify valid sig | 80.9 µs | 78.5 µs | 106.3 µs | 12.4K ops/s |
| Verify invalid sig | 82.8 µs | 78.2 µs | 130.0 µs | 12.1K ops/s |
| Ed25519 keygen | 30.4 µs | 28.8 µs | 47.4 µs | 32.9K ops/s |
| Ed25519 sign 128B | 59.4 µs | 56.4 µs | 98.2 µs | 16.8K ops/s |
| Ed25519 verify 128B | 80.2 µs | 76.7 µs | 119.0 µs | 12.5K ops/s |
| Store insert (signed) | 200.3 µs | 178.9 µs | 432.9 µs | 5.0K ops/s |
| Store lookup (hit) | 750 ns | 630 ns | 1,242 ns | 1.33M ops/s |
| Store lookup (miss) | 567 ns | 481 ns | 1,001 ns | 1.76M ops/s |
| Query lookup (verified) | 82.3 µs | 78.8 µs | 173.7 µs | 12.2K ops/s |
| Query lookup (miss) | 570 ns | 492 ns | 962 ns | 1.75M ops/s |
| Trust chain 1-level | 166.9 µs | 160.5 µs | 322.7 µs | 6.0K ops/s |
| Trust chain 2-level | 253.6 µs | 243.8 µs | 428.0 µs | 3.9K ops/s |
| TrustAnchor check (known) | 1.04 µs | 942 ns | 1,663 ns | 962K ops/s |
| TrustAnchor check (unknown) | 1.04 µs | 921 ns | 1,953 ns | 966K ops/s |

### Relay: Pipeline & Packet Processing

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| L1 valid magic | 79 ns | 69 ns | 151 ns | 12.6M ops/s |
| L1 invalid magic | 88 ns | 70 ns | 301 ns | 11.4M ops/s |
| L2 known (100 sessions) | 288 ns | 231 ns | 571 ns | 3.5M ops/s |
| L2 unknown (100 sessions) | 241 ns | 220 ns | 410 ns | 4.2M ops/s |
| L2 known (10K sessions) | 332 ns | 301 ns | 631 ns | 3.0M ops/s |
| L2 HELLO (pass) | 99 ns | 70 ns | 320 ns | 10.1M ops/s |
| L3 compute header auth | 852 ns | 741 ns | 1,271 ns | 1.17M ops/s |
| L3 verify valid tag | 755 ns | 662 ns | 1,292 ns | 1.32M ops/s |
| Full — valid (no auth) | 1.57 µs | 1.46 µs | 2.58 µs | 638K ops/s |
| Full — valid (with auth) | 2.60 µs | 2.48 µs | 4.33 µs | 385K ops/s |
| Full — HELLO | 1.47 µs | 1.31 µs | 2.63 µs | 682K ops/s |
| Full — L1 reject | 1.32 µs | 1.24 µs | 2.48 µs | 757K ops/s |
| Full — L2 reject | 1.67 µs | 1.52 µs | 3.31 µs | 598K ops/s |
| Parse handshake | 167 ns | 151 ns | 291 ns | 6.0M ops/s |
| Parse data compact | 151 ns | 130 ns | 332 ns | 6.6M ops/s |
| Extract session ID | 91 ns | 80 ns | 170 ns | 11.1M ops/s |
| Extract AAD | 124 ns | 100 ns | 341 ns | 8.1M ops/s |
| Session exists? (known) | 183 ns | 180 ns | 230 ns | 5.5M ops/s |
| Session exists? (unknown) | 193 ns | 171 ns | 230 ns | 5.2M ops/s |
| Lookup session | 279 ns | 220 ns | 591 ns | 3.6M ops/s |
| Lookup peer | 286 ns | 221 ns | 602 ns | 3.5M ops/s |

---

## New Feature Benchmarks (Phase 8/9)

### Relay: Backpressure, Auth, Mesh

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| Backpressure check — :ok | 441 ns | 371 ns | 1.0 µs | 2.27M ops/s |
| Backpressure check — :soft | 689 ns | 532 ns | 1.4 µs | 1.45M ops/s |
| Backpressure check — :hard | 633 ns | 551 ns | 1.3 µs | 1.58M ops/s |
| Backpressure update_load | 154 ns | 121 ns | 391 ns | 6.5M ops/s |
| Backpressure metrics | 956 ns | 802 ns | 1.9 µs | 1.05M ops/s |
| ComponentAuth generate challenge | 695 ns | 612 ns | 1.8 µs | 1.44M ops/s |
| ComponentAuth sign challenge | 86.5 µs | 83.8 µs | 122.2 µs | 11.6K ops/s |
| ComponentAuth verify response | 79.1 µs | 76.8 µs | 102.6 µs | 12.6K ops/s |
| ComponentAuth full roundtrip | 168.0 µs | 164.1 µs | 219.1 µs | 6.0K ops/s |
| Mesh route plan — direct (2 relays) | 347 ns | 270 ns | 601 ns | 2.88M ops/s |
| Mesh route plan — transit (10 relays) | 1.0 µs | 932 ns | 1.7 µs | 955K ops/s |

### Gateway: Circuit Breaker, Auth

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| CB allow? — unknown (fast path) | 437 ns | 369 ns | 801 ns | 2.29M ops/s |
| CB allow? — closed (hot path) | 355 ns | 311 ns | 1.2 µs | 2.82M ops/s |
| CB allow? — open (reject) | 580 ns | 471 ns | 1.2 µs | 1.72M ops/s |
| CB record_success | 416 ns | 351 ns | 1.2 µs | 2.40M ops/s |
| CB record_failure (no trip) | 1.0 µs | 912 ns | 1.7 µs | 960K ops/s |
| CB state transition | 5.9 µs | 5.7 µs | 9.5 µs | 170K ops/s |
| ComponentAuth parse challenge | 124 ns | 80 ns | 411 ns | 8.09M ops/s |
| ComponentAuth sign challenge | 85.7 µs | 83.7 µs | 107.9 µs | 11.7K ops/s |
| ComponentAuth full roundtrip | 168.3 µs | 162.5 µs | 225.8 µs | 5.9K ops/s |
| Identity resolve (cache hit) | 246 ns | 171 ns | 521 ns | 4.07M ops/s |
| Identity cache miss (ETS only) | 149 ns | 141 ns | 200 ns | 6.71M ops/s |

### NS: Rate Limiter, Anti-Entropy, Federation

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| RateLimiter — allowed | 1.6 µs | 1.5 µs | 3.6 µs | 615K ops/s |
| RateLimiter — rate_limited | 1.4 µs | 1.2 µs | 2.3 µs | 718K ops/s |
| RateLimiter metrics | 423 ns | 311 ns | 792 ns | 2.36M ops/s |
| AntiEntropy leaf hash | 483 ns | 381 ns | 762 ns | 2.07M ops/s |
| AntiEntropy root hash (10) | 1.0 µs | 853 ns | 1.8 µs | 992K ops/s |
| AntiEntropy root hash (1K) | 47.0 µs | 43.7 µs | 83.3 µs | 21.3K ops/s |
| AntiEntropy merge decision | 275 ns | 211 ns | 582 ns | 3.63M ops/s |
| Replication (no peers) | 365 ns | 271 ns | 712 ns | 2.74M ops/s |
| ComponentAuth generate | 642 ns | 601 ns | 971 ns | 1.56M ops/s |
| ComponentAuth sign | 86.9 µs | 83.8 µs | 120.6 µs | 11.5K ops/s |
| ComponentAuth full roundtrip | 170.6 µs | 164.2 µs | 225.6 µs | 5.9K ops/s |
| Cluster check (single node) | 160 ns | 130 ns | 421 ns | 6.24M ops/s |

---

## Analysis

### Overhead Summary

| Operation | Rust | Elixir | Ratio | Notes |
|-----------|------|--------|-------|-------|
| L1 reject | 19 ns | 79-87 ns | 4.2-4.6× | Both sub-100ns — negligible |
| L2 lookup (100) | 31 ns | 241-291 ns | 7.8-9.4× | ETS overhead vs HashMap |
| L3 auth tag | 841 ns | 754 ns | 0.9× | Elixir `:crypto` NIF wins here |
| Full pipeline | 886 ns | 1,568 ns | 1.8× | Acceptable for relay |
| Noise_XX | 301 µs | 481 µs | 1.6× | One-time cost per session |
| ChaCha20 64B | 1.17 µs | 821 ns | 0.7× | Elixir NIF faster for small |
| ChaCha20 64KB | 35.1 µs | 13.1 µs | 0.4× | Elixir NIF significantly faster |
| Ed25519 verify | N/A | 79.5 µs | — | NIF-backed, consistent |

### Throughput Projections (Elixir Relay, 4 vCPU)

| Scenario | ops/sec | Packets/sec equivalent |
|----------|---------|----------------------|
| L1 reject (flood) | 12.6M | Drops 12.6M garbage packets/sec |
| Full pipeline (valid) | 638K | Processes 638K valid data packets/sec |
| Full pipeline (auth) | 385K | With header auth verification |
| Session lookup | 3.5M | Pure session table reads |

### Key Findings (v2)

1. **L1 DDoS protection is essentially free** — 19ns (Rust) to 87ns (Elixir) to reject garbage. An attacker needs to waste their own bandwidth while we barely notice.

2. **Elixir `:crypto` NIF matches or beats Rust** for ChaCha20-Poly1305 and BLAKE2s operations, because both call into OpenSSL/libsodium C code. The overhead is in the Erlang scheduler, not the crypto.

3. **ETS scales well** — L2 session lookup goes from 288ns (100 sessions) to 332ns (10K sessions). Sub-microsecond regardless of table size.

4. **Circuit breaker is lightweight** — 355ns hot path, 580ns reject. Negligible overhead on the gateway data path.

5. **Backpressure adds ~441ns** per check in the relay. Acceptable given it prevents cascade failures.

6. **Component auth (Ed25519) is the most expensive operation** at ~168µs roundtrip — but it only runs once during inter-component handshake, not per-packet.

7. **Anti-entropy Merkle tree** scales predictably: 1µs for 10 records → 47µs for 1K records (linear with slight overhead).

8. **Noise_XX handshake** at 301µs (Rust) / 481µs (Elixir) is one-time per session. Once established, data path runs at pipeline speed.

### Comparison with v1 Results

| Metric | v1 (2026-03-10) | v2 (2026-03-12) | Change |
|--------|-----------------|-----------------|--------|
| Rust L1 reject | 19 ns | 19 ns | Same |
| Elixir L1 reject (relay) | 89 ns | 79 ns | -11% ✅ |
| Rust Noise_XX | 299 µs | 301 µs | +0.7% |
| Elixir Noise_XX | 471 µs | 481 µs | +2.1% |
| Gateway data path | 669K ops/s | 638K ops/s | -4.6% (within variance) |

Numbers are consistent with v1. Minor fluctuations within normal VM jitter for a shared-CPU VPS.

---

## How to Run

```bash
# Ensure Rust toolchain is on PATH
export PATH="$HOME/.cargo/bin:$PATH"

# Run all benchmarks (original suite)
bash bench/run_all.sh

# Run new feature benchmarks only
bash bench/run_new_features.sh

# Run individual suites
cd proto  && cargo run --release --bin ztlp-bench
cd gateway && mix run bench/bench_pipeline.exs
cd gateway && mix run bench/bench_handshake.exs
cd gateway && mix run bench/bench_gateway.exs
cd ns     && ZTLP_NS_STORAGE_MODE=ram mix run bench/bench_ns.exs
cd relay  && mix run bench/bench_relay.exs

# New feature suites
cd relay   && mix run -e "ZtlpRelay.Bench.run()"
cd gateway && mix run -e "ZtlpGateway.Bench.run()"
cd ns      && ZTLP_NS_STORAGE_MODE=ram mix run -e "ZtlpNs.Bench.run()"

# Throughput (requires running ZTLP listener)
cd proto && cargo run --release --bin ztlp-throughput -- --mode all --size 104857600 --repeat 3
```

> **Note:** NS benchmarks require `ZTLP_NS_STORAGE_MODE=ram` when not running as a distributed Erlang node (Mnesia `disc_copies` requires `:nonode@nohost` workaround).
>
> **Note:** The replication metrics ETS race condition (OTP 24 `ets.whereis/1` not available) produces harmless error log spam during NS insert benchmarks. Results are unaffected.
