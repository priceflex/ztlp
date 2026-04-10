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

**Status:** Not started. Needs testing on Steve's Mac first.
Only needed if Phase 1+2 don't get us under 15MB.

The main change is replacing the Rust tokio recv_loop with a Swift
GCD-driven NWConnection receive loop. Two sub-paths:

#### Path 3A: Minimal — just replace recv_loop
- Keep `ztlp_connect_sync()` + `ztlp_crypto_context_extract()` as-is
- Add Swift-side NWConnection for the main tunnel UDP (not just ACKs)
- Replace `bridge.connect()` + recv_callback with sync path
- VIP proxy + packet router stay on the Rust tokio runtime
- Memory saving: modest (~500KB-1MB from removing recv_loop)

#### Path 3B: Full tokio strip — replace recv_loop + VIP/tunnel
- Use `ztlp_connect_sync()` directly from PacketTunnelProvider
- NWConnection for main tunnel UDP (receive loop in Swift)
- Swift NWListener for VIP proxy listeners (replace tokio TcpListener)
- Packet router already sync for read/write paths → works as-is
- Memory saving: ~2-4MB (tokio entirely dead, LTO strips it)

**Path 3B is the one that actually matters — it's the ~3-5MB saving.**

#### Concrete Phase 3B changes needed:

**1. New main tunnel NWConnection (NWConnection for data, not just ACKs)**
```swift
class PacketTunnelProvider: NEPacketTunnelProvider {
    // Add these:
    private var cryptoCtx: UnsafeMutableRawPointer?  // ZtlpCryptoContext*
    private var mainConnection: NWConnection?         // Main tunnel UDP
    private var dataSeq: UInt64 = 0                    // Tunnel data sequence
    private var highestAckedSeq: UInt64 = 0            // For ACK tracking
    private var receivedSeqs: Set<UInt64> = []         // For NACK tracking
```

**2. Replace ztlp_connect() -> ztlp_connect_sync() in startTunnel()**
```swift
// Step 5 replacement:
let target = try self.resolveGateway(config: config, svcName: svcName)
let identityHandle = try self.loadOrCreateIdentity(config: config)

// Get raw identity pointer (need to add accessor to ZTLPIdentityHandle)
let rawIdentity = identityHandle.getPointer()  // OpaquePointer -> UnsafeMutableRawPointer
let rawConfig = configHandle.pointer           // OpaquePointer -> UnsafeMutableRawPointer

target.withCString { cTarget in
    self.cryptoCtx = ztlp_connect_sync(
        OpaquePointer(rawIdentity),
        OpaquePointer(rawConfig),
        cTarget,
        60000  // 60s timeout
    )
}
guard let ctx = self.cryptoCtx else {
    throw self.makeNSError("sync connect failed: \(String(cString: ztlp_last_error()))")
}
self.logger.info("Connected via sync: session=\(String(cString: ztlp_crypto_context_session_id(ctx)))")
```

**3. Swift receive loop (replaces Rust recv_loop)**
```swift
private func startReceiveLoop() {
    // Use the same NWConnection parameters as the existing ackConnection
    let parts = self.targetAddress.split(separator: ":")  // from resolved target
    guard parts.count == 2,
          let port = NWEndpoint.Port(UInt16(parts[1]) ?? 0) else { return }
    
    let params = NWParameters.udp
    let conn = NWConnection(host: NWEndpoint.Host(String(parts[0])),
                           port: port, using: params)
    
    // Also set up the ACK NWConnection for redundancy (existing ack_socket pattern)
    self.ackConnection = conn  // reuse existing ackConnection for main data
    
    conn.stateUpdateHandler = { [weak self] state in
        guard let self = self else { return }
        switch state {
        case .ready:
            self.logger.info("Main tunnel UDP connection ready", source: "Receive")
            self.receiveNext()
        case .failed(let err):
            self.logger.error("Main tunnel UDP failed: \(err)", source: "Receive")
            self.connFailed(err)
        default:
            break
        }
    }
    conn.start(queue: tunnelQueue)
    self.mainConnection = conn
}

private func receiveNext() {
    guard let conn = self.mainConnection else { return }
    conn.receiveMessage { [weak self] data, context, isComplete, error in
        guard let self = self else { return }
        
        if let error = error {
            self.logger.warn("receiveMessage error: \(error)", source: "Receive")
            self.scheduleRereceive(delayMs: 100)
            return
        }
        
        guard let data = data else {
            self.scheduleRereceive(delayMs: 10)
            return
        }
        
        // Decrypt via sync FFI
        var outBuf = [UInt8](repeating: 0, count: 65536)
        var written: Int = 0
        let rc = data.withUnsafeBytes { ptr in
            ztlp_decrypt_packet(self.cryptoCtx,
                               ptr.baseAddress, data.count,
                               &outBuf, outBuf.count, &written)
        }
        guard rc == 0 else {
            self.logger.warn("decrypt failed: rc=\(rc)", source: "Receive")
            self.scheduleRereceive(delayMs: 10)
            return
        }
        
        // Parse frame
        var frameType: UInt8 = 0
        var seq: UInt64 = 0
        var payloadPtr: UnsafePointer<UInt8>?
        var payloadLen: Int = 0
        outBuf.withUnsafeBufferPointer { buf in
            _ = ztlp_parse_frame(buf.baseAddress, written,
                                &frameType, &seq, &payloadPtr, &payloadLen)
        }
        
        // Process frame
        self.processFrame(type: frameType, seq: seq,
                         payload: payloadPtr, payloadLen: payloadLen)
        
        // Continue receiving (tail-recursive via async)
        self.receiveNext()
    }
}
```

**4. Frame processing in Swift (replaces Rust recv_loop logic)**
```swift
private func processFrame(type: UInt8, seq: UInt64,
                         payload: UnsafePointer<UInt8>?, payloadLen: Int) {
    switch type {
    case 0x00: // FRAME_DATA
        guard let payload = payload, payloadLen > 8 else { return }
        // Extract stream_id (first 4 BE bytes) and data_seq
        let streamId = payload.withMemoryRebound(to: UInt32.self, capacity: 1) {
            $0.pointee.bigEndian
        }
        let dataSeq = payload.advanced(by: 4).withMemoryRebound(to: UInt64.self, capacity: 1) {
            $0.pointee.bigEndian
        }
        let actualData = Data(bytes: payload.advanced(by: 12), count: payloadLen - 12)
        
        // Track for ACK
        self.trackReceivedSeq(dataSeq)
        
        // Route to packet router
        self.bridge.routerWritePacket(actualData)
        self.flushOutboundPackets()
        self.advanceDataSeq()
        
    case 0x01: // FRAME_ACK (download acknowledgment)
        if payloadLen >= 8 {
            let ackedSeq = payload!.withMemoryRebound(to: UInt64.self, capacity: 1) {
                $0.pointee.bigEndian
            }
            self.handleDownloadAck(ackedSeq)
        }
        
    case 0x02: // FRAME_FIN
        self.logger.info("Received FIN frame", source: "Receive")
        
    case 0x03: // NACK
        if payloadLen >= 8 {
            let nackSeq = payload!.withMemoryRebound(to: UInt64.self, capacity: 1) {
                $0.pointee.bigEndian
            }
            self.handleNack(nackSeq)
        }
        
    case 0x01 where payloadLen == 0: // keepalive
        break  // NAT ping, ignore
        
    default:
        break
    }
}

private func trackReceivedSeq(_ seq: UInt64) {
    self.receivedSeqs.insert(seq)
    self.highestAckedSeq = max(self.highestAckedSeq, seq)
    
    // Cap the set to prevent unbounded growth
    if self.receivedSeqs.count > 2048 {
        let threshold = self.highestAckedSeq - 1024
        self.receivedSeqs = self.receivedSeqs.filter { $0 >= threshold }
    }
}

private func advanceDataSeq() {
    self.dataSeq += 1
    self.flushOutboundPackets()
}
```

**5. Send path: ztlp_frame_data + ztlp_encrypt_packet (replaces Rust send)**
```swift
private func sendTunnelData(_ data: Data) {
    guard let ctx = self.cryptoCtx else { return }
    
    // Frame the data
    var frameBuf = [UInt8](repeating: 0, count: 9 + data.count)
    var frameLen: Int = 0
    data.withUnsafeBytes { ptr in
        _ = ztlp_frame_data(ptr.baseAddress, data.count,
                           &frameBuf, frameBuf.count, &frameLen,
                           self.dataSeq)
    }
    self.dataSeq += 1
    
    // Encrypt into ZTLP wire packet
    var pktBuf = [UInt8](repeating: 0, count: 65536)
    var pktLen: Int = 0
    frameBuf.withUnsafeBufferPointer { buf in
        _ = ztlp_encrypt_packet(ctx, buf.baseAddress, frameLen,
                               &pktBuf, pktBuf.count, &pktLen)
    }
    
    // Send via main NWConnection
    let pktData = Data(pktBuf[..<pktLen])
    self.mainConnection?.send(content: pktData, completion: .idempotent)
}
```

**6. ACK sending (leverages existing ack_socket pattern + new path)**
```swift
private func sendAck(for dataSeq: UInt64) {
    guard let ctx = self.cryptoCtx else { return }
    
    // Build ACK frame
    var ackBuf = [UInt8](repeating: 0, count: 9)
    var ackLen: Int = 0
    _ = ztlp_build_ack(dataSeq, &ackBuf, ackBuf.count, &ackLen)
    
    // Encrypt
    var pktBuf = [UInt8](repeating: 0, count: 65536)
    var pktLen: Int = 0
    _ = ztlp_encrypt_packet(ctx, ackBuf.withUnsafeBufferPointer { $0.baseAddress },
                           ackLen, &pktBuf, pktBuf.count, &pktLen)
    
    // Send via main NWConnection
    self.mainConnection?.send(content: Data(pktBuf[..<pktLen]),
                             completion: .idempotent)
}
```

**7. Keepalive timer (GCD, replaces tokio::time::interval)**
```swift
private func startKeepaliveTimer() {
    let timer = DispatchSource.makeTimerSource(queue: tunnelQueue)
    timer.schedule(deadline: .now(), repeating: .seconds(5))
    timer.setEventHandler { [weak self] in
        guard let self = self, self.isTunnelActive, let ctx = self.cryptoCtx else { return }
        
        // Send keepalive via sync encrypt
        let keepalivePayload: [UInt8] = [0x01]  // Simple keepalive frame
        var pktBuf = [UInt8](repeating: 0, count: 65536)
        var pktLen: Int = 0
        _ = ztlp_encrypt_packet(ctx, keepalivePayload, keepalivePayload.count,
                               &pktBuf, pktBuf.count, &pktLen)
        
        self.mainConnection?.send(content: Data(pktBuf[..<pktLen]),
                                 completion: .idempotent)
    }
    timer.resume()
    self.keepaliveTimer = timer  // Reuse existing timer property
}
```

**Key insight:** `ztlp_crypto_context_extract()` already exists (Phase 1).
`ztlp_connect_sync()` directly returns a context without needing extract.
So the Swift code calls `ztlp_connect_sync()` then uses the context for
all send/recv — no tokio runtime needed for the data plane.

The existing ACK sender (ack_socket.rs) uses a dedicated NWConnection on a
separate queue — this pattern proved to work. Phase 3B just extends it to
the main data path too.

### Phase 4 (IF NEEDED) — Feature Gate Tokio Out

**Status:** Not started. Only relevant if Phase 3B removes all tokio usage.

If Phase 3B eliminates every tokio reference from the iOS path,
add `ios-sync` cargo feature to strip it from the binary:

```toml
[features]
ios-sync = []

[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "net", "sync", "time", "io-util", "io-std", "signal", "macros"], optional = true }
tracing-subscriber = { version = "0.3", features = ["env-filter"], optional = true }

# Conditional deps
[dependencies.serde_json]
version = "1"
features = ["std"]
```

Then conditional compilation in ffi.rs:
```rust
#[cfg(not(feature = "ios-sync"))]
use tokio::runtime::Runtime;

#[cfg(feature = "ios-sync")]
mod sync_impl {
    // Only sync FFI functions compile
}
```

**Expected impact:** LTO would drop tokio entirely, saving 3-5MB TEXT.
The entire async code path (ztlp_connect, recv_loop, VIP proxy start,
tunnel_start, dns_start) becomes compile-time disabled.

**Note:** If we keep the VIP proxy on Swift NWListeners (no tokio
TcpListener), this feature gate becomes trivial — just conditional
compilation on the async-only functions.

---

## Option 3 (PARALLEL) — Split VIP Proxy to Main App

**SUPERSEDED** — See IOS-RELAY-ARCHITECTURE.md — Decision 2026-04-10: move VIP proxy to iPhone relay instead of XPC. Single tunnel saves 5-8MB. XPC kept for reference only.
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
