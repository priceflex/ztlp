# iOS Network Extension Memory Optimization Plan

**Created:** 2026-04-08
**Baseline tag:** `v0.24.1-baseline-8of11`
**Baseline state:** 8/11 benchmarks passing, ~15-16MB RSS (15MB hard limit)
**Goal:** Get under 15MB resident → pass 11/11 benchmarks

## Rollback

If anything breaks:
```bash
git checkout v0.24.1-baseline-8of11
```
This restores the working 8/11 state with the existing tokio-based architecture.

---

## Current Architecture (What We Have)

```
Swift (PacketTunnelProvider)
  │
  ├─ readPacketLoop() ──► ztlp_router_write_packet() ──► Rust PacketRouter (SYNC)
  │                                                         │
  │                                                         ▼
  │                                                    RouterAction via tokio::mpsc
  │                                                         │
  │                                                         ▼
  │                                                    router_action_task (tokio::spawn)
  │                                                         │
  │                                                         ▼
  │                                                    transport.send_data() (tokio UdpSocket)
  │
  ├─ recv (via callback) ◄── recv_loop (tokio::spawn, 900 lines)
  │                              ├─ tokio::time::timeout(50ms) polling
  │                              ├─ transport.recv_data() (tokio UdpSocket)
  │                              ├─ decrypt (chacha20poly1305 — sync underneath)
  │                              ├─ reassembly buffer (BTreeMap)
  │                              ├─ ACK/NACK generation
  │                              └─ keepalive timer (tokio::time::interval)
  │
  ├─ ztlp_connect() ──► tokio::spawn(do_connect)
  │                        ├─ TransportNode::bind() (tokio UdpSocket)
  │                        ├─ Noise_XX 3-msg handshake (snow — sync core)
  │                        └─ spawns recv_loop
  │
  └─ ztlp_send() ──► tokio::spawn → transport.send_data()
```

**Tokio memory cost:** ~2-4MB
- 2 worker threads × 256KB stacks = 512KB
- tokio internals (timer wheel, I/O driver, waker pools) ~500KB-1MB
- UdpSocket, channel, RwLock, Mutex overhead
- Spawned task allocations

---

## Target Architecture (Option 1 — Strip Tokio)

```
Swift (PacketTunnelProvider + GCD)
  │
  ├─ readPacketLoop() ──► ztlp_router_write_packet() ──► Rust PacketRouter (SYNC)
  │                                                         │
  │                                                         ▼
  │                                                    RouterAction returned to Swift
  │                                                         │
  │                                                         ▼
  │                                                    ztlp_encrypt() (SYNC)
  │                                                         │
  │                                                         ▼
  │                                                    NWConnection.send() (Swift)
  │
  ├─ NWConnection.receiveMessage() (Swift GCD)
  │     │
  │     ▼
  │   ztlp_decrypt() (SYNC) ──► ztlp_parse_packet() (SYNC)
  │     │
  │     ▼
  │   process frame (reassembly, ACK gen — Swift or Rust sync)
  │     │
  │     ▼
  │   packetFlow.writePackets() (back to iOS)
  │
  ├─ ztlp_connect_sync() ──► std::net::UdpSocket (no tokio)
  │                            ├─ Noise_XX handshake (snow — already sync)
  │                            └─ returns ZtlpCryptoContext
  │
  └─ Timers: DispatchSource.makeTimerSource() (Swift GCD)
       ├─ keepalive (5s)
       ├─ ACK flush (10ms)
       └─ diagnostics (5s)
```

**Savings:** ~3-5MB (tokio runtime + worker threads + async overhead eliminated)
**Target RSS:** 10-13MB (under 15MB limit with headroom)

---

## Implementation Phases

### Phase 1 — Sync FFI Functions (Rust)

Add new synchronous C-exported functions that do encrypt/decrypt/framing
without touching tokio. These work alongside the existing async API so
nothing breaks — we're adding, not replacing.

**New Rust types:**
```rust
/// Holds extracted session keys for sync encrypt/decrypt.
/// Created after handshake completes. No tokio dependency.
pub struct ZtlpCryptoContext {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_seq: AtomicU64,      // monotonic, bumped on each encrypt
    recv_window: ReplayWindow, // anti-replay for decrypt
    session_id: SessionId,
    peer_addr: SocketAddr,
    // Cached CStrings for FFI accessors
    session_id_str: CString,
    peer_addr_str: CString,
}
```

**New FFI functions:**
```c
// Extract crypto context from connected session (call after ztlp_connect succeeds)
ztlp_crypto_context_t* ztlp_crypto_context_extract(ztlp_client_t* client);
void ztlp_crypto_context_free(ztlp_crypto_context_t* ctx);

// Sync encrypt: plaintext → full ZTLP wire packet ready to send
// Returns packet length, writes to out_buf. Caller sends via NWConnection.
int32_t ztlp_encrypt_packet(
    ztlp_crypto_context_t* ctx,
    const uint8_t* plaintext, size_t plaintext_len,
    uint8_t* out_buf, size_t out_buf_len,
    size_t* out_written
);

// Sync decrypt: raw UDP bytes → decrypted payload
// Returns payload length, or negative error code.
int32_t ztlp_decrypt_packet(
    ztlp_crypto_context_t* ctx,
    const uint8_t* packet, size_t packet_len,
    uint8_t* out_buf, size_t out_buf_len,
    size_t* out_written
);

// Build a FRAME_DATA envelope (prepend 0x00 + data_seq)
int32_t ztlp_frame_data(
    ztlp_crypto_context_t* ctx,
    const uint8_t* payload, size_t payload_len,
    uint8_t* out_buf, size_t out_buf_len,
    size_t* out_written
);

// Parse incoming decrypted frame — returns frame type and payload offset
int32_t ztlp_parse_frame(
    const uint8_t* decrypted, size_t decrypted_len,
    uint8_t* out_frame_type,
    uint64_t* out_seq,
    const uint8_t** out_payload,
    size_t* out_payload_len
);

// Build ACK frame (for sending back to gateway)
int32_t ztlp_build_ack(
    uint64_t ack_seq,
    uint8_t* out_buf, size_t out_buf_len,
    size_t* out_written
);

// Accessors
const char* ztlp_crypto_context_session_id(const ztlp_crypto_context_t* ctx);
const char* ztlp_crypto_context_peer_addr(const ztlp_crypto_context_t* ctx);
```

**Proof it works:** `ack_socket.rs::build_encrypted_packet()` already does
sync encryption with pre-extracted keys + AtomicU64 seq counter — same pattern.

**Files to modify:**
- `proto/src/ffi.rs` — add new FFI functions at bottom
- `proto/include/ztlp.h` — add C declarations
- `ios/ZTLP/Libraries/ztlp.h` — copy of above

### Phase 2 — Sync Handshake (Rust)

Replace tokio UdpSocket with std::net::UdpSocket for the handshake.
The Noise_XX state machine (snow crate) is already fully synchronous.

**New FFI function:**
```c
// Blocking connect — uses std::net::UdpSocket, no tokio runtime needed.
// Returns crypto context directly. Timeout in milliseconds.
ztlp_crypto_context_t* ztlp_connect_sync(
    ztlp_identity_t* identity,
    ztlp_config_t* config,
    const char* target,
    uint32_t timeout_ms
);
```

**What changes:**
- `do_connect()` refactored to use `std::net::UdpSocket::bind("0.0.0.0:0")`
- `socket.set_read_timeout(Some(Duration::from_millis(50)))` instead of tokio::time::timeout
- Handshake retry loop with `std::thread::sleep()` instead of `tokio::time::sleep()`
- Returns `ZtlpCryptoContext*` directly (no callback needed — it's blocking)
- **Does NOT spawn recv_loop** — Swift handles recv via NWConnection

**Memory impact:** If Phase 1+2 are enough (no tokio runtime created at all),
the entire tokio crate is dead code and LTO strips it. Potential 3-5MB saving.

### Phase 3 — Swift Event Loop (Swift)

Only needed if Phase 1+2 don't get us under 15MB. Replace the Rust recv_loop
with Swift GCD-driven receive:

**PacketTunnelProvider changes:**
```swift
// Instead of Rust recv_loop, Swift does:
func startReceiveLoop() {
    connection.receiveMessage { [weak self] data, _, _, error in
        guard let self, let data else { return }
        
        var outBuf = [UInt8](repeating: 0, count: 65536)
        var written: Int = 0
        let rc = ztlp_decrypt_packet(self.cryptoCtx, data, data.count,
                                      &outBuf, outBuf.count, &written)
        guard rc == 0 else { return }
        
        var frameType: UInt8 = 0
        var seq: UInt64 = 0
        var payloadPtr: UnsafePointer<UInt8>?
        var payloadLen: Int = 0
        ztlp_parse_frame(outBuf, written, &frameType, &seq,
                         &payloadPtr, &payloadLen)
        
        switch frameType {
        case 0x00: self.handleDataFrame(seq, payloadPtr, payloadLen)
        case 0x01: self.handleAckFrame(payloadPtr, payloadLen)
        case 0x02: self.handleFinFrame()
        default: break
        }
        
        self.startReceiveLoop() // continue receiving
    }
}
```

**Timers via GCD:**
```swift
let keepaliveTimer = DispatchSource.makeTimerSource(queue: tunnelQueue)
keepaliveTimer.schedule(deadline: .now(), repeating: .seconds(5))
keepaliveTimer.setEventHandler { [weak self] in
    self?.sendKeepalive()
}
```

### Phase 4 (IF NEEDED) — Feature Gate

If we go full sync, add `ios-sync` cargo feature to eliminate tokio from the
iOS binary entirely:

```toml
[features]
ios-sync = []

[dependencies]
tokio = { version = "1", features = [...], optional = true }
```

---

## Option 3 (PARALLEL) — Split VIP Proxy to Main App

Independent of the above. Move VipProxy + PacketRouter async tasks
to the main app process via XPC/IPC. NE only does tunnel I/O
(encrypt/decrypt/forward). Main app has no memory limit.

**Effort:** ~2-3 days
**Can be done after Option 1 if still needed.**

---

## Option 2 (LAST RESORT) — Full Swift Rewrite

Replace all Rust with Swift:
- CryptoKit for ChaCha20-Poly1305 (system shared lib = 0 NE memory)
- Network.framework for UDP (NWConnection)
- Noise_XX handshake in pure Swift (hardest part)
- Target: 8-11MB resident
- Effort: ~5-7 days

---

## Key Files Reference

| Component | File | Lines | Tokio? |
|-----------|------|-------|--------|
| FFI entry point | `proto/src/ffi.rs` | 4505 | YES (20 refs) |
| C header | `proto/include/ztlp.h` | 969 | - |
| iOS header copy | `ios/ZTLP/Libraries/ztlp.h` | 969 | - |
| Swift bridge | `ios/ZTLP/ZTLP/Services/ZTLPBridge.swift` | 740 | - |
| Packet tunnel | `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift` | 827 | - |
| Build script | `ios/build-ios.sh` | 158 | - |
| Transport | `proto/src/transport.rs` | ~400 | YES |
| Handshake | `proto/src/handshake.rs` | ~500 | NO (sync) |
| Packet | `proto/src/packet.rs` | ~600 | NO (sync) |
| Pipeline | `proto/src/pipeline.rs` | ~300 | NO (sync) |
| PacketRouter | `proto/src/packet_router.rs` | ~800 | NO (sync) |
| VIP proxy | `proto/src/vip.rs` | ~1000 | YES (heavy) |
| ACK socket | `proto/src/ack_socket.rs` | ~100 | NO (sync encrypt!) |
| Session | `proto/src/session.rs` | ~200 | NO (sync) |
| Cargo.toml | `proto/Cargo.toml` | ~80 | tokio dep here |

## Proof of Concept: Sync Encryption Already Exists

`ack_socket.rs::build_encrypted_packet()` demonstrates the pattern:
```rust
pub fn build_encrypted_packet(
    send_key: &[u8; 32],
    session_id: SessionId,
    seq: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    // 1. Build nonce from seq
    // 2. ChaCha20Poly1305::encrypt(key, nonce, plaintext)
    // 3. Build DataHeader with session_id + seq
    // 4. Compute header auth tag
    // 5. Serialize to wire format
    // ALL SYNC — no tokio, no async, no locks
}
```

This is exactly what `ztlp_encrypt_packet()` will do.
