# ZTLP iOS Session 5 Plan: Strip Tokio + CryptoKit Swap

**Created:** 2026-04-09
**Goal:** Get NE memory from 18.4MB → ~10MB (safely under 15MB limit)
**Approach:** Two-phase hybrid — strip tokio runtime, swap Rust crypto for CryptoKit
**Baseline tag:** `v0.24.1-baseline-8of11` (rollback point)
**Current benchmark:** 5/11 (down from 8/11 due to jetsam killing NE at 18.4MB)

---

## Why This Approach (Not Full Swift Rewrite)

Research of every major iOS VPN project (WireGuard, Mullvad, Passepartout,
Outline, Amnezia) shows the same architecture: **thin Swift shell + native
crypto core**. None do "all Swift" for the NE.

A full Swift rewrite would target ~8-10MB but requires rewriting ~3000 lines
of protocol logic (packet router, congestion control, reassembly, send
controller) — 5-7 days with high regression risk.

The hybrid approach gets the same memory savings in 2-3 days by:
1. Stripping tokio (saves ~3-5MB runtime overhead)
2. Swapping Rust crypto crates for Apple CryptoKit (saves ~2-3MB TEXT)

Combined savings: ~5-8MB → target 10-12MB resident.

---

## Current Memory Breakdown (18.4MB)

```
Code TEXT (LTO):           4.7 MB  ← crypto crates are ~2MB of this
Code DATA:                 0.5 MB
Tokio runtime:             3-4 MB  ← mmap overhead counted as RSS
NE framework + Swift:      2-3 MB
Buffers (all capped):      1.6 MB
Unknown/page tables:       3-4 MB  ← likely tokio virtual memory overhead
TOTAL:                    ~18.4 MB
```

## Target Memory After Both Phases (~10MB)

```
Code TEXT (no crypto, no tokio): ~1.5 MB  (from 4.7MB)
Code DATA:                       0.3 MB
GCD (no tokio):                  0   MB  (system framework, free)
CryptoKit:                       0   MB  (system framework, free)
NE framework + Swift:            2-3 MB
Buffers (capped):                1.6 MB
NWConnection/NWListener:         1-2 MB  (system, lightweight)
TOTAL:                          ~8-10 MB
```

---

## Phase 1: Strip Tokio (Session 5A)

**Goal:** Remove tokio runtime entirely from the iOS NE process.
**Savings:** ~3-5MB (tokio runtime + mmap overhead + worker thread stacks)
**Prereqs already done:** Sync FFI (Phase 1, commit 264a049) and sync
handshake (Phase 2, commit 6b8e1f9) are committed and working.

### What Changes

#### 1A. Swift: Replace `ztlp_connect()` with `ztlp_connect_sync()`

Current flow (PacketTunnelProvider.swift ~line 200):
```
bridge.connect(gateway) → callback → ztlp_connect() → tokio::spawn → handshake → callback
```

New flow:
```
ztlp_connect_sync(identity, config, target, 60000) → blocks → returns ZtlpCryptoContext*
```

The sync handshake uses `std::net::UdpSocket` (no tokio). It's already
implemented and tested (commit 6b8e1f9). The Swift side just needs to call
the new function instead of the async one.

**Files:** `PacketTunnelProvider.swift` — `startTunnel()` method

#### 1B. Swift: NWConnection recv loop (replaces Rust recv_loop)

Current: tokio::spawn → recv_loop (900 lines in ffi.rs) → transport.recv_data()
         → decrypt → reassemble → callback to Swift

New: Swift NWConnection.receiveMessage() → ztlp_decrypt_packet() (sync FFI)
     → ztlp_parse_frame() (sync FFI) → process in Swift

This is the biggest change. The Rust recv_loop (~900 lines) handles:
- UDP receive (tokio UdpSocket)            → NWConnection.receiveMessage()
- Decrypt (chacha20poly1305)               → ztlp_decrypt_packet() sync FFI
- Frame parsing                            → ztlp_parse_frame() sync FFI
- Reassembly buffer (BTreeMap)             → Swift Dictionary
- ACK generation                           → ztlp_build_ack() sync FFI
- Keepalive timer                          → DispatchSourceTimer (already exists)
- Duplicate detection                      → Swift Set<UInt64>
- NACK handling                            → Swift logic

The sync FFI functions for encrypt/decrypt/frame are ALREADY DONE (commit
264a049). We just need the Swift glue.

**New file:** `ZTLPTunnelConnection.swift` (~300-400 lines)
**Modifies:** `PacketTunnelProvider.swift` — replace bridge.connect() flow

#### 1C. Swift: NWConnection send path (replaces tokio transport.send_data)

Current: ztlp_send() → tokio::spawn → transport.send_data() → tokio UdpSocket
         Also: ztlp_router_write_packet() → RouterAction → tokio mpsc → send

New: ztlp_encrypt_packet() (sync FFI) → NWConnection.send() (Swift)
     Also: ztlp_router_write_packet() still sync → get RouterAction
           → encrypt in Swift → NWConnection.send()

**Modifies:** `PacketTunnelProvider.swift` — `flushOutboundPackets()`

#### 1D. Swift: Replace VIP proxy (tokio TcpListener → NWListener)

Current: ztlp_vip_start() → tokio TcpListener → accept() → spawn per-conn
         → tokio TcpStream read/write loop

New: NWListener on 127.0.0.1:8080 (Swift) → NWConnection per client
     → read data → ztlp_router_write_packet() (already sync)
     → encrypted via send path above

The packet router (2061 lines) is ALREADY fully sync — it has zero tokio
dependency. It just needs a different I/O driver (NWListener instead of
tokio TcpListener).

**New file:** `ZTLPVIPProxy.swift` (~200-250 lines)
**Modifies:** `PacketTunnelProvider.swift` — replace ztlp_vip_start()

#### 1E. Swift: GCD timers (replaces tokio timers)

Current timers in recv_loop:
- keepalive (25s)          → already a DispatchSourceTimer in Swift ✓
- ACK flush (10ms)         → new DispatchSourceTimer
- Diagnostics (5s)         → new DispatchSourceTimer  
- RTO retransmit           → new DispatchSourceTimer (check send_buffer age)

**Modifies:** `PacketTunnelProvider.swift` — add timer setup

#### 1F. Rust: Feature-gate tokio out of iOS build

Add to `proto/Cargo.toml`:
```toml
[features]
default = ["tokio-runtime"]
tokio-runtime = ["tokio", "tokio-rustls"]
ios-sync = []  # Builds without tokio for iOS NE
```

Build iOS with: `cargo build --no-default-features --features ios-sync`

This ensures LTO can strip ALL tokio code from the binary.

**Files:** `proto/Cargo.toml`, conditional compilation in `ffi.rs`, `vip.rs`,
`transport.rs`, `send_controller.rs`

### Phase 1 Verification

1. Build libztlp_proto.a with `--features ios-sync` (no tokio)
2. Check TEXT segment: `size libztlp_proto.a` — should be ~2.5-3MB (down from 4.7MB)
3. Build iOS app in Xcode
4. Run on device, check memory: target ~13-14MB
5. Run 11-test benchmark: target ≥8/11

### Phase 1 Estimated Effort: 1-2 sessions

### Phase 1 Rollback: `git checkout v0.24.1-baseline-8of11`

---

## Phase 2: CryptoKit Swap (Session 5B)

**Goal:** Replace Rust crypto crates with Apple CryptoKit.
**Savings:** ~2-3MB TEXT (snow, chacha20poly1305, curve25519-dalek, blake2, aws-lc-sys gone)
**Prereq:** Phase 1 must be complete first.

### Why CryptoKit Works

ZTLP uses `Noise_XX_25519_ChaChaPoly_BLAKE2s`. CryptoKit provides:
- ✅ ChaCha20-Poly1305 (ChaChaPoly.seal / ChaChaPoly.open)
- ✅ Curve25519 ECDH (Curve25519.KeyAgreement)
- ✅ HMAC-SHA256 (for key derivation, can substitute for BLAKE2s in KDF)
- ⚠️ BLAKE2s — NOT in CryptoKit. Options:
  - Use SHA-256 instead (Noise allows `Noise_XX_25519_ChaChaPoly_SHA256`)
  - Or keep a tiny BLAKE2s implementation (~200 lines of C)
  - Gateway must match whichever hash we choose

**Important:** Changing the Noise hash function means the gateway must also
change. If we switch to SHA-256, both sides must agree. This is a protocol
change. The safest path is `Noise_XX_25519_ChaChaPoly_SHA256` which the
`snow` crate on the gateway already supports.

### What Changes

#### 2A. Swift: Noise_XX handshake in CryptoKit

Replace `ztlp_connect_sync()` (which uses the `snow` Rust crate) with a
pure Swift Noise_XX implementation using CryptoKit primitives.

The Noise_XX pattern is 3 messages:
```
→ e                         (initiator ephemeral public key)
← e, ee, s, es             (responder ephemeral + static, DH results)  
→ s, se                    (initiator static, final DH)
```

Each step is: DH → MixHash → MixKey → EncryptAndHash → DecryptAndHash.
The crypto primitives needed:
- Curve25519 DH:  `Curve25519.KeyAgreement.PrivateKey` → `.sharedSecretFromKeyAgreement(with:)`
- ChaCha20-Poly1305 AEAD: `ChaChaPoly.seal(plaintext, using: key, nonce: nonce)`
- HMAC for MixKey:  `HMAC<SHA256>.authenticationCode(for: data, using: key)`
- Hash for MixHash: `SHA256.hash(data: input)`

There are also Swift Noise protocol libraries on GitHub (e.g., swift-noise)
that could be used directly. Worth checking.

**New file:** `ZTLPNoiseHandshake.swift` (~400-500 lines)
  - NoiseHandshakeState class
  - CipherState (encrypt/decrypt with nonce counter)
  - SymmetricState (MixKey, MixHash, EncryptAndHash, DecryptAndHash)
  - HandshakePattern.XX

**Gateway change:** Switch Noise pattern from BLAKE2s to SHA256:
  `"Noise_XX_25519_ChaChaPoly_SHA256"` in `handshake.rs` line 48.
  The `snow` crate supports both. This is a one-line change but means
  old clients can't connect to new gateway (acceptable during dev).

#### 2B. Swift: Encrypt/Decrypt in CryptoKit

Replace `ztlp_encrypt_packet()` and `ztlp_decrypt_packet()` sync FFI calls
with native Swift CryptoKit:

```swift
func encryptPacket(plaintext: Data, key: SymmetricKey, nonce: UInt64) -> Data {
    var nonceBytes = [UInt8](repeating: 0, count: 12)
    withUnsafeBytes(of: nonce.littleEndian) { src in
        nonceBytes.replaceSubrange(4..<12, with: src)
    }
    let cryptoNonce = try! ChaChaPoly.Nonce(data: nonceBytes)
    let sealed = try! ChaChaPoly.seal(plaintext, using: key, nonce: cryptoNonce)
    return sealed.combined  // nonce + ciphertext + tag
}
```

This eliminates the need for ztlp_encrypt_packet / ztlp_decrypt_packet FFI,
and with them, the chacha20poly1305 Rust crate.

**Modifies:** `ZTLPTunnelConnection.swift` — replace FFI encrypt/decrypt calls

#### 2C. Swift: Frame building/parsing

Replace `ztlp_frame_data()`, `ztlp_parse_frame()`, `ztlp_build_ack()` with
pure Swift equivalents. These are simple byte manipulation:

```swift
// FRAME_DATA: 0x00 + 8-byte data_seq (BE) + payload
func frameData(seq: UInt64, payload: Data) -> Data {
    var frame = Data(capacity: 1 + 8 + payload.count)
    frame.append(0x00)
    withUnsafeBytes(of: seq.bigEndian) { frame.append(contentsOf: $0) }
    frame.append(payload)
    return frame
}

// FRAME_ACK: 0x01 + 8-byte ack_seq (BE)
func buildAck(seq: UInt64) -> Data {
    var frame = Data(capacity: 9)
    frame.append(0x01)
    withUnsafeBytes(of: seq.bigEndian) { frame.append(contentsOf: $0) }
    return frame
}
```

**Modifies:** `ZTLPTunnelConnection.swift`

#### 2D. Swift: ZTLP packet header (transport layer)

Replace the Rust packet header serialization with Swift. The ZTLP wire
format for data_compact packets:
```
[1 byte type] [4 byte session_id prefix] [4 byte seq (BE)] [2 byte payload_len]
[4 byte window_base] [N bytes encrypted_payload]
```

This is currently in `packet.rs` (~200 lines). The Swift equivalent is
straightforward Data manipulation.

**New file:** `ZTLPPacket.swift` (~150-200 lines)

#### 2E. Rust: Remove crypto crates from Cargo.toml

With the `ios-sync` feature, remove or feature-gate:
- `snow` (Noise_XX → now in Swift)
- `chacha20poly1305` (→ CryptoKit)
- `curve25519-dalek` (→ CryptoKit)
- `blake2` (→ SHA256 via CryptoKit)
- `tokio-rustls` (already gone from Phase 1)

The gateway still uses these crates — they stay in the server build.
Only the iOS staticlib drops them.

**Files:** `proto/Cargo.toml` — feature gates on crypto crates

### Phase 2 Verification

1. Build libztlp_proto.a with `--features ios-sync` — TEXT should be ~1-1.5MB
2. Change gateway Noise pattern to SHA256 (one-line change)
3. Rebuild gateway image, deploy
4. Build iOS app, run on device
5. Check memory: target ~8-10MB
6. Run 11-test benchmark: target 11/11
7. Tag: `v0.25.0-cryptokit-11of11` (or whatever the result is)

### Phase 2 Estimated Effort: 1-2 sessions

### Phase 2 Rollback: git checkout to post-Phase-1 tag

---

## What Stays in Rust (Both Phases)

Even after both phases, the Rust staticlib still provides:
- `ztlp_router_write_packet()` / `ztlp_router_read_packet()` — the packet
  router TCP state machine (2061 lines, fully sync, zero tokio). This is the
  most complex and battle-tested code. No reason to rewrite it.
- `ztlp_identity_*()` — identity management (key generation, file I/O)
- `ztlp_config_*()` — configuration
- `ztlp_ns_resolve()` — nameserver resolution (can be replaced later if needed)
- `ztlp_pin_gateway_key()` / `ztlp_verify_gateway_pin()` — key pinning

The packet router is the crown jewel — 2061 lines of TCP/IP state machine
with full SYN/ACK/FIN handling, window management, and retransmission.
Rewriting it in Swift would be the highest-risk change for zero memory
benefit (it's already sync and tiny in memory).

---

## New File Summary

### Phase 1 (new Swift files)
| File | Lines | Purpose |
|------|-------|---------|
| `ZTLPTunnelConnection.swift` | ~350 | NWConnection recv/send loop, decrypt/encrypt via FFI |
| `ZTLPVIPProxy.swift` | ~200 | NWListener replacing tokio TcpListener for VIP |
| Total new Swift | ~550 | |

### Phase 2 (new Swift files, replacing FFI calls)
| File | Lines | Purpose |
|------|-------|---------|
| `ZTLPNoiseHandshake.swift` | ~450 | Noise_XX_25519_ChaChaPoly_SHA256 in pure Swift |
| `ZTLPCrypto.swift` | ~150 | ChaCha20-Poly1305 encrypt/decrypt via CryptoKit |
| `ZTLPPacket.swift` | ~180 | Wire format serialize/deserialize |
| Total new Swift | ~780 | |

### Files modified
| File | Phase | Change |
|------|-------|--------|
| `PacketTunnelProvider.swift` | 1 | Use sync connect, NWConnection recv, GCD timers |
| `proto/Cargo.toml` | 1+2 | Feature gates for ios-sync |
| `proto/src/ffi.rs` | 1 | #[cfg] guards on tokio code |
| `proto/src/vip.rs` | 1 | #[cfg] guards on tokio TcpListener |
| `gateway/lib/.../handshake.rs` | 2 | Noise pattern BLAKE2s → SHA256 |

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Swift recv loop has subtle bug | Medium | High | Keep Rust recv_loop behind feature flag for A/B testing |
| NWConnection performance worse than tokio UDP | Low | Medium | WireGuard uses NWConnection successfully |
| Noise_XX Swift impl has crypto bug | Medium | High | Test against gateway with known-good test vectors |
| Packet router breaks without tokio | Very Low | Low | Already fully sync, no tokio dependency |
| Memory still over 15MB after Phase 1 | Low | Medium | Phase 2 is the backup — CryptoKit drops 2-3MB more |
| Gateway Noise hash change breaks prod | Low | High | Deploy gateway change + iOS simultaneously |

---

## Session Planning

### Session 5A: Phase 1 — Strip Tokio
1. Tag baseline: `v0.24.2-pre-tokio-strip`
2. Create `ZTLPTunnelConnection.swift` (recv/send via NWConnection + sync FFI)
3. Create `ZTLPVIPProxy.swift` (NWListener for VIP)
4. Update `PacketTunnelProvider.swift` (use sync connect, new recv loop, GCD timers)
5. Feature-gate tokio out of Cargo.toml
6. Add #[cfg] guards in ffi.rs, vip.rs, transport.rs
7. Build on Steve's Mac, deploy to device
8. Test memory + run benchmark
9. Tag result: `v0.24.2-no-tokio-NofN`

### Session 5B: Phase 2 — CryptoKit Swap
1. Create `ZTLPNoiseHandshake.swift` (Noise_XX in pure Swift/CryptoKit)
2. Create `ZTLPCrypto.swift` (encrypt/decrypt via ChaChaPoly)
3. Create `ZTLPPacket.swift` (wire format)
4. Replace all ztlp_encrypt/decrypt/frame FFI calls with Swift native
5. Feature-gate snow/chacha20poly1305/curve25519-dalek out of Cargo.toml
6. Update gateway Noise pattern to SHA256
7. Deploy gateway, build iOS, test
8. Run full 11-test benchmark
9. Tag result: `v0.25.0-cryptokit-NofN`

---

## Key Decisions Needed Before Starting

1. **Noise hash function:** Switch gateway from BLAKE2s to SHA256?
   Or keep BLAKE2s and bundle a tiny C implementation (~200 lines)?
   Recommendation: Switch to SHA256. It's a one-line gateway change,
   CryptoKit has native SHA256, and security properties are equivalent.

2. **Packet router:** Keep in Rust (recommended) or rewrite in Swift?
   Recommendation: Keep in Rust. It's 2061 lines of battle-tested TCP
   state machine with zero tokio dependency. Zero memory benefit from rewriting.

3. **Phase 1 first or both together?**
   Recommendation: Phase 1 first. It may be enough on its own (13-14MB
   might squeak under the limit on newer devices). If not, Phase 2
   guarantees it. Incremental approach = lower risk.
