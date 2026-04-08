# ZTLP iOS Network Extension Memory Strategy

## The Problem

iOS Network Extensions have a **15MB resident memory limit**. Our NE consistently
runs at **20-21MB**, which causes instability — keepalive failures, session drops,
and reconnect cycles that kill active transfers.

Buffer caps and LTO can't fix this. The baseline is structural:

```
Rust staticlib TEXT:           ~4.7 MB  (with LTO, opt-level=z, strip)
Tokio runtime + 2 threads:    ~2-3 MB  (event loop, timers, 400GB virt mmap)
Crypto (aws-lc-sys/snow):     ~1-2 MB  (BoringCrypto bcm.o alone was 1.1MB pre-LTO)
NE framework + Swift runtime:  ~5-8 MB  (Apple system overhead)
Our buffers (all capped):     ~2-3 MB
─────────────────────────────────────────
Total:                        ~18-21 MB  ← always over 15MB limit
```

## Current Benchmark: 8/11

All downloads + echoes work. Failures are:
- Upload 1MB (stalls after ~2min, tunnel drops)
- Concurrent 5x GET (cascade — tunnel dead)
- TTFB (cascade — tunnel dead)

The upload stall correlates with the memory-triggered instability.

## Strategy: Option 1 → Option 3 → Option 2 if needed

### Option 1: Strip Tokio from iOS Build (FIRST PRIORITY)

**Goal**: Remove tokio from the iOS staticlib. Keep Rust for crypto + framing only.
Swift drives the event loop via GCD.

**What Rust keeps**:
- Noise_XX handshake (snow crate)
- AEAD encrypt/decrypt (chacha20poly1305)
- Packet framing: build_data, parse_data, header auth
- Session state: keys, seq counters, session_id
- Pipeline: 3-layer admission (magic check, session verify, AEAD)

**What moves to Swift**:
- UDP socket I/O → NWConnection (already partially there for ACKs)
- Event loop / timer management → GCD DispatchQueue
- Congestion control → Swift struct (simple AIMD, ~200 lines)
- Send controller → Swift (pending queue, cwnd gating, retransmit)
- Keepalive timer → DispatchSourceTimer
- Reconnect logic → already in Swift

**New FFI surface** (synchronous, no tokio):
```c
// Handshake
ZtlpHandshake *ztlp_handshake_new(void);
int32_t ztlp_handshake_write_msg1(ZtlpHandshake *hs, uint8_t *out, uint32_t *out_len);
int32_t ztlp_handshake_read_msg2(ZtlpHandshake *hs, const uint8_t *data, uint32_t len);
int32_t ztlp_handshake_finalize(ZtlpHandshake *hs, ZtlpSession *session);

// Encrypt/decrypt (hot path, lock-free)
int32_t ztlp_encrypt(ZtlpSession *s, uint64_t seq, const uint8_t *plain,
                      uint32_t plain_len, uint8_t *out, uint32_t *out_len);
int32_t ztlp_decrypt(ZtlpSession *s, const uint8_t *cipher,
                      uint32_t cipher_len, uint8_t *out, uint32_t *out_len);

// Packet framing
int32_t ztlp_build_data_packet(ZtlpSession *s, uint64_t seq,
                                const uint8_t *payload, uint32_t payload_len,
                                uint8_t *out, uint32_t *out_len);
int32_t ztlp_parse_packet(const uint8_t *data, uint32_t len,
                           ZtlpParsedPacket *result);

// Admission pipeline (Layer 1-3 checks)
int32_t ztlp_admit_packet(ZtlpSession *s, const uint8_t *data, uint32_t len);
```

**Expected memory savings**:
- Remove tokio: -2-3MB (runtime, mmap, thread stacks)
- Remove transport.rs, vip.rs, send_controller.rs from staticlib: -1-2MB TEXT
- Keep crypto + framing only: ~2-3MB TEXT
- Total NE estimate: **10-13MB** (under 15MB limit)

**Effort**: Medium. ~2-3 days.
- Day 1: New sync FFI for handshake + encrypt/decrypt
- Day 2: Swift event loop, NWConnection I/O, congestion control
- Day 3: Integration, testing, benchmark

**Risk**: Swift congestion control needs to match gateway expectations.
The AIMD parameters (loss_beta=0.7, max_cwnd=32 etc) must mirror the
gateway's assumptions. Mismatch → performance regression.


### Option 3: Split VIP Proxy to Main App (IN PARALLEL)

**Goal**: NE only does tunnel I/O (encrypt/decrypt/forward raw packets).
VIP proxy (TCP reconstruction, HTTP) runs in the main app process (no memory limit).

**Architecture**:
```
┌─────────────────────────────────┐  ┌──────────────────────┐
│         Main App Process        │  │    NE Process (15MB)  │
│  (no memory limit)              │  │                       │
│  ┌──────────────┐               │  │  ┌─────────────────┐  │
│  │  VIP Proxy   │  IPC (XPC or  │  │  │ Tunnel I/O      │  │
│  │  TCP→Stream  │ ←──mach msg── │  │  │ encrypt/decrypt │  │
│  │  PacketRouter│               │  │  │ UDP socket       │  │
│  └──────────────┘               │  │  └─────────────────┘  │
│         ↕                       │  │         ↕              │
│  URLSession HTTP                │  │  Gateway (relay)      │
└─────────────────────────────────┘  └──────────────────────┘
```

**What moves to main app**:
- PacketRouter (TCP SYN/ACK reconstruction)
- Service mapping
- HTTP proxy listener (127.0.0.1:9080)

**What stays in NE**:
- Raw tunnel: encrypt, decrypt, send, receive
- Keepalive
- Handshake

**Effort**: Medium-high. ~2-3 days. XPC/IPC plumbing is fiddly.
**Risk**: IPC latency adds ~0.5-1ms per packet. May hurt small request perf.
Could use shared memory (mach_vm) for zero-copy if latency is a problem.


### Option 2: Full Swift Rewrite (ONLY IF NEEDED)

**Goal**: Everything in Swift. No Rust in the NE at all.

**What needs reimplementing**:
- Noise_XX handshake: use CryptoKit X25519 + ChaCha20Poly1305
  (Apple has all the primitives, just need the Noise protocol state machine)
- AEAD encrypt/decrypt: CryptoKit.ChaChaPoly (system library, free memory)
- Packet framing: Data manipulation (~200 lines)
- Pipeline admission: 3 checks (~100 lines)
- Congestion control: AIMD struct (~200 lines)
- Send controller: queue + cwnd (~300 lines)

**Expected memory**:
- CryptoKit + Network.framework: system shared libs, ~0 NE memory
- Swift code: ~2-3MB
- NE overhead: ~5-8MB
- Total: **8-11MB** (very comfortable under 15MB)

**Effort**: Large. ~5-7 days.
- Day 1-2: Noise_XX handshake in Swift (hardest part)
- Day 3: Packet framing + admission pipeline
- Day 4: Congestion control + send controller
- Day 5-6: VIP proxy, integration
- Day 7: Testing, benchmark

**Risk**: Noise_XX in Swift is non-trivial. Need to match the exact
handshake pattern (XX variant, prologue, payload handling). Could use
an existing Swift Noise library if one exists, or port the ~500 lines
of relevant snow code.

**Advantage**: Long-term maintainability. No cross-language FFI bugs.
CryptoKit is hardware-accelerated on Apple Silicon. Network.framework
handles NAT traversal, WiFi/cellular switching, etc. natively.


## Decision

**Steve's call**: Option 1 first, Option 3 in parallel, Option 2 if we have to.

Rationale: Option 1 gives us the biggest memory win with least code change.
We keep the battle-tested Rust crypto and just remove the runtime bloat.
Option 3 can be done independently and is a good architectural improvement
regardless. Option 2 is the nuclear option but gives the cleanest result.


## Key Files Reference

### Current iOS/Rust integration
- `proto/src/ffi.rs` — 4500 lines, all FFI + recv_loop + send_loop
- `proto/src/transport.rs` — UDP socket management (REMOVE for Option 1)
- `proto/src/vip.rs` — VIP TCP proxy (MOVE for Option 3, REMOVE for Option 1)
- `proto/src/send_controller.rs` — upload CC (REWRITE in Swift for Option 1)
- `proto/src/packet_router.rs` — TCP packet reconstruction (MOVE for Option 3)
- `proto/src/ack_socket.rs` — separate ACK sending
- `proto/src/pipeline.rs` — 3-layer admission
- `proto/src/packet.rs` — framing

### iOS Swift side
- `ios/ZTLP/ZTLP/Services/ZTLPBridge.swift` — Swift↔Rust bridge
- `ios/ZTLP/ZTLPTunnel/` — NE provider
- `ios/ZTLP/Libraries/libztlp_proto.a` — the static lib
- `ios/ZTLP/Libraries/ztlp.h` — C header

### Gateway (Elixir)
- `gateway/lib/ztlp_gateway/session.ex` — CC, retransmit, ACK processing
- Container: `ztlp-gateway:retransmit-fix` on ubuntu@54.149.48.6

### Build
- LTO profile in `proto/Cargo.toml` (lto=true, opt-level=z, strip, panic=abort)
- Build: `cd proto && cargo build --release --target aarch64-apple-ios --lib`
- Copy: `cp target/aarch64-apple-ios/release/libztlp_proto.a ../ios/ZTLP/Libraries/`
- Xcode build for code signing (can't do over SSH)
- Steve's Mac: `stevenprice@10.78.72.234`
