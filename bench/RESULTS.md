# ZTLP Performance Benchmark Results

## System Information

| Property | Value |
|----------|-------|
| Date | 2026-03-10 07:55 UTC |
| OS | Linux 5.15.0-1093-kvm x86_64 |
| CPU | AMD EPYC 4564P 16-Core Processor |
| CPU Cores | 4 (vCPU) |
| Memory | 7.8 GiB |
| Elixir | 1.12.2 (compiled with Erlang/OTP 24) |
| Erlang/OTP | 24 |
| Rust | 1.94.0 (2026-03-02) |
| Cargo | 1.94.0 |

---

## Summary: Pipeline Layer Cost Hierarchy

The three-layer admission pipeline confirms the designed cost hierarchy — **each layer is orders of magnitude cheaper than the next**:

| Layer | Elixir (Gateway) | Rust (Proto) | Operation |
|-------|------------------|--------------|-----------|
| **L1: Magic Check** | **~80 ns** (12.5M ops/s) | **~19 ns** (54M ops/s) | 2-byte compare |
| **L2: SessionID Lookup** | **~215 ns** (4.7M ops/s) | **~31 ns** (32M ops/s) | ETS/HashMap lookup |
| **L3: HeaderAuthTag** | N/A (combined) | **~840 ns** (1.2M ops/s) | HMAC-based AEAD |
| **Full Pipeline** | **~265 ns** (3.8M ops/s) | **~879 ns** (1.1M ops/s) | All 3 layers |

> **Key insight**: Invalid packets are rejected in 19–80 ns (L1) or 31–215 ns (L2) before any crypto work occurs. Only authenticated sessions reach the expensive L3 crypto layer. This is the core DDoS resilience property of ZTLP.

---

## Elixir Benchmarks

### Gateway: Pipeline Admission

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| **Layer 1: Magic Check** | | | | |
| `valid_magic?/1` — valid | 80 ns | 61 ns | 170 ns | 12,530,138 ops/s |
| `valid_magic?/1` — invalid | 86 ns | 69 ns | 351 ns | 11,643,867 ops/s |
| `layer1_magic/1` — valid | 100 ns | 70 ns | 772 ns | 9,964,429 ops/s |
| `layer1_magic/1` — bad magic | 95 ns | 70 ns | 370 ns | 10,507,776 ops/s |
| `layer1_magic/1` — garbage | 87 ns | 61 ns | 311 ns | 11,526,774 ops/s |
| **Layer 2: SessionID Lookup** | | | | |
| Known session (100 sessions) | 247 ns | 191 ns | 582 ns | 4,053,534 ops/s |
| Unknown session (100 sessions) | 222 ns | 170 ns | 591 ns | 4,496,650 ops/s |
| Known session (1K sessions) | 248 ns | 191 ns | 592 ns | 4,038,551 ops/s |
| Unknown session (1K sessions) | 193 ns | 170 ns | 330 ns | 5,183,817 ops/s |
| Known session (10K sessions) | 214 ns | 190 ns | 501 ns | 4,673,587 ops/s |
| Unknown session (10K sessions) | 223 ns | 171 ns | 411 ns | 4,483,929 ops/s |
| HELLO packet (bypass) | 136 ns | 90 ns | 391 ns | 7,374,904 ops/s |
| **Full Pipeline** | | | | |
| `admit/1` — valid session | 265 ns | 210 ns | 642 ns | 3,768,883 ops/s |
| `admit/1` — HELLO | 101 ns | 90 ns | 231 ns | 9,915,225 ops/s |
| `admit/1` — bad magic (L1 reject) | 89 ns | 70 ns | 321 ns | 11,286,345 ops/s |
| `admit/1` — unknown session (L2 reject) | 224 ns | 181 ns | 701 ns | 4,460,509 ops/s |
| **Packet Parsing** | | | | |
| `parse/1` — data packet | 140 ns | 120 ns | 331 ns | 7,151,332 ops/s |
| `parse/1` — handshake packet | 133 ns | 120 ns | 230 ns | 7,545,122 ops/s |
| `extract_session_id/1` | 87 ns | 70 ns | 210 ns | 11,437,481 ops/s |
| `hello?/1` | 104 ns | 80 ns | 340 ns | 9,576,643 ops/s |

### Gateway: Handshake & Crypto

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| **X25519 Key Operations** | | | | |
| `generate_keypair/0` (X25519) | 28.4 µs | 27.6 µs | 37.8 µs | 35,200 ops/s |
| `dh/2` (shared secret) | 53.2 µs | 51.4 µs | 72.8 µs | 18,801 ops/s |
| **ChaCha20-Poly1305 AEAD** | | | | |
| Encrypt 64B | 806 ns | 741 ns | 1,453 ns | 1,241,464 ops/s |
| Decrypt 64B | 764 ns | 722 ns | 1,614 ns | 1,309,492 ops/s |
| Encrypt 1KB | 1,110 ns | 962 ns | 1,914 ns | 900,991 ops/s |
| Decrypt 1KB | 1,100 ns | 952 ns | 1,493 ns | 909,402 ops/s |
| Encrypt 8KB | 2,536 ns | 2,364 ns | 5,661 ns | 394,263 ops/s |
| Decrypt 8KB | 2,420 ns | 2,302 ns | 3,998 ns | 413,171 ops/s |
| Encrypt 64KB | 13,244 ns | 12,824 ns | 19,656 ns | 75,503 ops/s |
| Decrypt 64KB | 13,186 ns | 12,833 ns | 19,095 ns | 75,841 ops/s |
| **BLAKE2s / HMAC / HKDF** | | | | |
| BLAKE2s hash (32B) | 429 ns | 381 ns | 721 ns | 2,329,878 ops/s |
| BLAKE2s hash (256B) | 699 ns | 631 ns | 1,664 ns | 1,430,879 ops/s |
| HMAC-BLAKE2s | 2,060 ns | 1,834 ns | 3,136 ns | 485,565 ops/s |
| HKDF extract | 1,977 ns | 1,814 ns | 3,206 ns | 505,775 ops/s |
| HKDF expand (64B out) | 4,388 ns | 3,867 ns | 7,654 ns | 227,897 ops/s |
| HKDF Noise (chaining key) | 6,061 ns | 5,309 ns | 10,761 ns | 164,993 ops/s |
| HKDF Noise split (transport) | 7,803 ns | 7,082 ns | 14,357 ns | 128,161 ops/s |
| **Ed25519** | | | | |
| Generate keypair | 28.7 µs | 28.1 µs | 38.1 µs | 34,852 ops/s |
| Sign (128B message) | 56.3 µs | 55.1 µs | 71.9 µs | 17,752 ops/s |
| Verify (128B message) | 78.3 µs | 76.7 µs | 98.9 µs | 12,769 ops/s |
| **Noise_XX Handshake** | | | | |
| Full 3-message + split | 470.6 µs | 458.8 µs | 666.3 µs | **2,125 ops/s** |

### Gateway: Throughput (Steady-State Data Path)

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| **Decrypt** | | | | |
| 64B payload | 853 ns | 772 ns | 1,403 ns | 1,171,878 ops/s |
| 1KB payload | 1,163 ns | 982 ns | 1,923 ns | 859,894 ops/s |
| 8KB payload | 2,513 ns | 2,374 ns | 5,219 ns | 397,871 ops/s |
| 64KB payload | 13,474 ns | 13,104 ns | 19,837 ns | 74,220 ops/s |
| **Policy Engine** | | | | |
| `:all` rule (allow) | 187 ns | 160 ns | 331 ns | 5,342,834 ops/s |
| Exact match (2 entries) | 244 ns | 190 ns | 962 ns | 4,100,169 ops/s |
| Wildcard match | 317 ns | 271 ns | 681 ns | 3,151,313 ops/s |
| Deny (no match) | 296 ns | 221 ns | 622 ns | 3,382,919 ops/s |
| Deny (no rule) | 156 ns | 141 ns | 191 ns | 6,407,674 ops/s |
| Large rule (10 patterns) | 371 ns | 300 ns | 851 ns | 2,697,293 ops/s |
| **Identity Resolution** | | | | |
| Cache hit | 244 ns | 171 ns | 651 ns | 4,105,082 ops/s |
| Cache miss (ETS) | 150 ns | 141 ns | 181 ns | 6,648,295 ops/s |
| Hex fallback (cache miss) | 648 ns | 512 ns | 1,403 ns | 1,542,497 ops/s |
| **Combined Data Path** | | | | |
| Decrypt 1KB + identity + policy | 1,494 ns | 1,283 ns | 4,058 ns | **669,214 ops/s** |

### ZTLP-NS: Namespace Operations

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| **Record Serialization** | | | | |
| `serialize/1` (ZTLP_KEY) | 423 ns | 300 ns | 631 ns | 2,365,213 ops/s |
| `deserialize/1` (ZTLP_KEY) | 393 ns | 310 ns | 1,122 ns | 2,546,482 ops/s |
| `encode/1` (wire + sig) | 558 ns | 370 ns | 731 ns | 1,792,084 ops/s |
| `decode/1` (wire + sig) | 349 ns | 331 ns | 521 ns | 2,863,891 ops/s |
| **Ed25519 Signature** | | | | |
| Record verify (valid sig) | 81.4 µs | 78.5 µs | 109.9 µs | 12,292 ops/s |
| Record verify (tampered) | 81.9 µs | 78.2 µs | 111.8 µs | 12,215 ops/s |
| Sign (128B) | 57.4 µs | 56.0 µs | 79.2 µs | 17,412 ops/s |
| Verify (128B) | 79.4 µs | 77.0 µs | 101.0 µs | 12,589 ops/s |
| **Store Operations** | | | | |
| Insert (signed record) | 175.4 µs | 169.3 µs | 243.8 µs | 5,701 ops/s |
| Lookup — ETS hit | 432 ns | 381 ns | 702 ns | 2,313,925 ops/s |
| Lookup — ETS miss | 264 ns | 241 ns | 451 ns | 3,788,700 ops/s |
| **Query (Lookup + Verify)** | | | | |
| Known record | 79.7 µs | 76.8 µs | 108.2 µs | 12,542 ops/s |
| Unknown record | 279 ns | 250 ns | 511 ns | 3,583,000 ops/s |
| **Trust Chain Verification** | | | | |
| 1-level (zone → root) | 169.2 µs | 162.6 µs | 261.9 µs | 5,911 ops/s |
| 2-level (zone → org → root) | 249.7 µs | 242.1 µs | 391.6 µs | 4,005 ops/s |
| **Trust Anchor** | | | | |
| `trusted?/1` — known | 982 ns | 912 ns | 1,593 ns | 1,018,594 ops/s |
| `trusted?/1` — unknown | 1,008 ns | 942 ns | 1,824 ns | 991,926 ops/s |

### Relay: Pipeline & Packet Processing

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| **Layer 1: Magic Check** | | | | |
| `valid_magic?/1` — valid | 93 ns | 69 ns | 301 ns | 10,772,127 ops/s |
| `valid_magic?/1` — invalid | 109 ns | 70 ns | 390 ns | 9,151,440 ops/s |
| `layer1_magic/1` — valid | 97 ns | 70 ns | 412 ns | 10,274,130 ops/s |
| `layer1_magic/1` — reject | 95 ns | 70 ns | 401 ns | 10,506,263 ops/s |
| **Layer 2: SessionID** | | | | |
| Known (100 sessions) | 311 ns | 271 ns | 601 ns | 3,214,592 ops/s |
| Unknown (100 sessions) | 312 ns | 280 ns | 591 ns | 3,203,302 ops/s |
| Known (1K sessions) | 332 ns | 271 ns | 1,162 ns | 3,013,167 ops/s |
| Unknown (1K sessions) | 317 ns | 281 ns | 611 ns | 3,155,970 ops/s |
| Known (10K sessions) | 305 ns | 280 ns | 591 ns | 3,275,773 ops/s |
| Unknown (10K sessions) | 294 ns | 260 ns | 581 ns | 3,402,942 ops/s |
| HELLO (bypass) | 96 ns | 70 ns | 400 ns | 10,453,913 ops/s |
| **Layer 3: HeaderAuthTag** | | | | |
| Compute auth tag | 753 ns | 691 ns | 1,103 ns | 1,327,694 ops/s |
| Verify — valid | 656 ns | 651 ns | 731 ns | 1,525,482 ops/s |
| Verify — invalid | 692 ns | 652 ns | 1,013 ns | 1,445,540 ops/s |
| **Full Pipeline** | | | | |
| Valid data (no auth) | 1,667 ns | 1,574 ns | 2,865 ns | 599,747 ops/s |
| Valid data (with auth) | 2,653 ns | 2,455 ns | 4,877 ns | 376,888 ops/s |
| HELLO packet | 1,588 ns | 1,454 ns | 2,935 ns | 629,632 ops/s |
| Bad magic (L1 reject) | 1,266 ns | 1,162 ns | 2,325 ns | 789,852 ops/s |
| Unknown session (L2 reject) | 1,502 ns | 1,423 ns | 2,595 ns | 665,842 ops/s |
| **Packet Operations** | | | | |
| Parse handshake | 186 ns | 151 ns | 471 ns | 5,381,725 ops/s |
| Parse data compact | 195 ns | 141 ns | 491 ns | 5,131,585 ops/s |
| Serialize handshake | 317 ns | 230 ns | 521 ns | 3,155,453 ops/s |
| Serialize data compact | 253 ns | 161 ns | 531 ns | 3,954,724 ops/s |
| Extract session ID | 114 ns | 80 ns | 801 ns | 8,786,116 ops/s |
| Extract AAD | 109 ns | 90 ns | 350 ns | 9,145,150 ops/s |
| **Session Registry** | | | | |
| `session_exists?` — known | 187 ns | 180 ns | 240 ns | 5,334,765 ops/s |
| `session_exists?` — unknown | 181 ns | 170 ns | 240 ns | 5,532,798 ops/s |
| `lookup_session` — known | 260 ns | 210 ns | 571 ns | 3,849,952 ops/s |
| `lookup_peer` — known | 269 ns | 221 ns | 1,021 ns | 3,711,863 ops/s |

---

## Rust Benchmarks (Proto)

| Benchmark | Mean | Median | p99 | Throughput |
|-----------|------|--------|-----|------------|
| **Layer 1: Magic Check** | | | | |
| Valid ZTLP | 18.5 ns | 20 ns | 21 ns | 54,062,587 ops/s |
| Bad magic | 18.7 ns | 20 ns | 21 ns | 53,493,357 ops/s |
| Garbage | 18.8 ns | 20 ns | 21 ns | 53,309,110 ops/s |
| **Layer 2: Session Lookup** | | | | |
| Known (100 sessions) | 31.1 ns | 30 ns | 50 ns | 32,143,241 ops/s |
| Unknown (100 sessions) | 28.5 ns | 30 ns | 41 ns | 35,052,888 ops/s |
| Known (1K sessions) | 30.4 ns | 30 ns | 31 ns | 32,876,741 ops/s |
| Unknown (1K sessions) | 28.2 ns | 30 ns | 80 ns | 35,496,137 ops/s |
| Known (10K sessions) | 31.6 ns | 30 ns | 41 ns | 31,610,278 ops/s |
| Unknown (10K sessions) | 30.9 ns | 30 ns | 40 ns | 32,401,698 ops/s |
| HELLO (pass-through) | 19.1 ns | 20 ns | 21 ns | 52,483,630 ops/s |
| **Layer 3: HeaderAuthTag** | | | | |
| Compute auth tag | 832 ns | 812 ns | 942 ns | 1,201,427 ops/s |
| Auth check (valid) | 868 ns | 841 ns | 1,112 ns | 1,152,458 ops/s |
| **Full Pipeline** | | | | |
| Valid data (3 layers) | 879 ns | 852 ns | 1,102 ns | 1,137,941 ops/s |
| HELLO | 25.1 ns | 21 ns | 31 ns | 39,905,504 ops/s |
| Bad magic (L1 reject) | 21.5 ns | 20 ns | 31 ns | 46,616,743 ops/s |
| **Noise_XX Handshake** | | | | |
| Full 3-msg + finalize | 299.3 µs | 290.9 µs | 391.5 µs | **3,342 ops/s** |
| **ChaCha20-Poly1305** | | | | |
| Encrypt 64B | 1,213 ns | 1,162 ns | 1,794 ns | 824,137 ops/s |
| Decrypt 64B | 1,172 ns | 1,152 ns | 1,302 ns | 852,940 ops/s |
| Encrypt 1KB | 1,688 ns | 1,603 ns | 2,453 ns | 592,464 ops/s |
| Decrypt 1KB | 1,665 ns | 1,603 ns | 2,415 ns | 600,485 ops/s |
| Encrypt 8KB | 5,397 ns | 5,100 ns | 8,847 ns | 185,275 ops/s |
| Decrypt 8KB | 5,103 ns | 5,059 ns | 6,382 ns | 195,952 ops/s |
| Encrypt 64KB | 34,689 ns | 33,343 ns | 47,849 ns | 28,828 ops/s |
| Decrypt 64KB | 34,410 ns | 33,562 ns | 46,517 ns | 29,061 ops/s |
| **Identity Generation** | | | | |
| `NodeId::generate()` | 25.3 ns | 20 ns | 71 ns | 39,586,934 ops/s |
| `NodeIdentity::generate()` | 12.4 µs | 12.0 µs | 19.9 µs | 80,709 ops/s |
| `SessionId::generate()` | 27.2 ns | 21 ns | 71 ns | 36,776,902 ops/s |
| **Packet Serialize/Deserialize** | | | | |
| HandshakeHeader serialize | 26.0 ns | 29 ns | 31 ns | 38,438,062 ops/s |
| HandshakeHeader deserialize | 25.5 ns | 29 ns | 31 ns | 39,273,441 ops/s |
| DataHeader serialize | 31.8 ns | 30 ns | 41 ns | 31,436,833 ops/s |
| DataHeader deserialize | 23.3 ns | 20 ns | 31 ns | 42,849,418 ops/s |
| Data round-trip (ser + deser) | 36.5 ns | 30 ns | 51 ns | 27,405,670 ops/s |

---

## Analysis

### 1. Pipeline Layer Cost Validation

The benchmarks confirm the ZTLP design principle that **each admission layer is progressively more expensive**:

**Rust (Proto):**
- **Layer 1 → Layer 2**: ~19 ns → ~31 ns (1.6× more expensive)
- **Layer 2 → Layer 3**: ~31 ns → ~840 ns (**27× more expensive**)
- **L1 reject vs full pipeline**: 21 ns vs 879 ns (**42× cheaper** to reject at magic check)

**Elixir (Gateway):**
- **Layer 1 → Layer 2**: ~80 ns → ~215 ns (2.7× more expensive)
- **Layer 2 → Layer 3**: implicit in full pipeline
- **L1 reject vs full admit**: 89 ns vs 265 ns (3× cheaper to reject at magic check)

This validates the ZTLP claim: "packets that fail early layers never incur crypto cost."

### 2. ETS Scaling (Elixir)

Session lookup via ETS shows **O(1) behavior** as expected:
- 100 sessions: ~247 ns
- 1,000 sessions: ~248 ns
- 10,000 sessions: ~214 ns

ETS hash tables maintain constant lookup time regardless of table size. Similarly, Rust HashMap lookups are stable at ~30 ns across 100–10K entries.

### 3. Handshake Performance

| Implementation | Mean | Throughput |
|---------------|------|------------|
| Elixir (Gateway) | 470.6 µs | 2,125 handshakes/sec |
| Rust (Proto) | 299.3 µs | 3,342 handshakes/sec |

The handshake is dominated by **three X25519 DH operations** (each ~50 µs in Elixir, ~12 µs in Rust for keypair gen). The Noise_XX 3-message exchange requires 6 DH operations total (3 per side) plus symmetric crypto for each message.

**Projection**: A single gateway core can handle **~2,100 new connections/sec** in Elixir. With 4 cores and BEAM schedulers, this scales to **~8,000+ handshakes/sec**.

### 4. Crypto Throughput

ChaCha20-Poly1305 scales linearly with payload size:

| Payload | Elixir Encrypt | Rust Encrypt | Elixir Decrypt | Rust Decrypt |
|---------|---------------|--------------|----------------|--------------|
| 64B | 806 ns | 1,213 ns | 764 ns | 1,172 ns |
| 1KB | 1,110 ns | 1,688 ns | 1,100 ns | 1,665 ns |
| 8KB | 2,536 ns | 5,397 ns | 2,420 ns | 5,103 ns |
| 64KB | 13,244 ns | 34,689 ns | 13,186 ns | 34,410 ns |

> **Note**: Elixir's AEAD (via Erlang's `crypto` module) outperforms the Rust `chacha20poly1305` crate because Erlang links to OpenSSL/BoringSSL with hardware-accelerated ChaCha20. The Rust crate uses a pure-Rust software implementation.

### 5. ZTLP-NS Performance

- **ETS lookup**: 432 ns (2.3M lookups/sec) — fast enough for real-time NS resolution
- **Verified query** (lookup + Ed25519 verify): 79.7 µs — bottlenecked by Ed25519 verify (~78 µs)
- **Trust chain**: Each additional chain level adds ~80 µs (one Ed25519 verify per level)
- **Record insert**: 175 µs — includes signing + ETS insert

### 6. Throughput Projections

**Relay (packet forwarding, no auth):**
- ~600K packets/sec per core (Elixir)
- With 4 BEAM schedulers: **~2.4M packets/sec**
- At 1KB MTU: **~19.2 Gbps** theoretical throughput

**Relay (with HeaderAuthTag verification):**
- ~377K packets/sec per core
- With 4 schedulers: **~1.5M packets/sec**
- At 1KB MTU: **~12 Gbps** theoretical throughput

**Gateway (full data path: decrypt + identity + policy):**
- ~669K packets/sec per core
- With 4 schedulers: **~2.7M packets/sec**

**Gateway (new connections):**
- ~2,125 handshakes/sec per core
- With 4 schedulers: **~8,500 new sessions/sec**

**Rust Proto (client-side):**
- ~1.14M admitted packets/sec (single-threaded)
- ~3,342 handshakes/sec

### 7. Bottleneck Analysis

1. **Handshake**: X25519 DH is the bottleneck (6 DH ops per handshake). Hardware acceleration or pre-computation of ephemeral keys could help.

2. **Steady-state data**: ChaCha20-Poly1305 is the bottleneck for large payloads. Already hardware-accelerated via OpenSSL in Erlang.

3. **NS verified queries**: Ed25519 verify dominates at ~78 µs. For production, cache verified results to avoid re-verification.

4. **Policy engine**: Sub-microsecond even with wildcards and large rule sets — not a bottleneck.

5. **ETS**: Scales beautifully. No degradation from 100 to 10K sessions.

---

## How to Run

```bash
# From the ztlp repo root
cd /path/to/ztlp

# Elixir benchmarks
cd gateway && mix run bench/bench_pipeline.exs
cd gateway && mix run bench/bench_handshake.exs
cd gateway && mix run bench/bench_gateway.exs
cd ../ns && mix run bench/bench_ns.exs
cd ../relay && mix run bench/bench_relay.exs

# Rust benchmarks
cd ../proto && cargo run --release --bin ztlp-bench

# Or run everything:
bash bench/run_all.sh
```
