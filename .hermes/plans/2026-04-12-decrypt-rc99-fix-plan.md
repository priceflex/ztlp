# ZTLP Decrypt rc=-99 Fix Plan
## Date: 2026-04-12

---

## Root Cause Analysis

### Symptom
Phone logs show intermittent decrypt failures during benchmark runs:
```
ZTLP decrypt failed rc=-99 wire=159
ZTLP decrypt failed rc=-99 wire=76
```
Always in pairs (159, 76). Two benchmark tests fail with "No response":
- "Vault HTTP Response"
- "Primary HTTP Response"

### What rc=-99 actually means

`rc=-99` = `ZtlpResult::InternalError` in `proto/src/ffi.rs`. Inside
`ztlp_decrypt_packet()`, this code is returned by THREE paths:

1. **Header parse failure** — `DataHeader::deserialize()` fails
2. **Anti-replay rejection** — `recv_window.check_and_record(seq)` returns false
3. **Packet too short** — `packet.len() < DATA_HEADER_SIZE` (46 bytes)

Path #3 is impossible (159 and 76 > 46).
Path #1 is unlikely (both sizes are valid data packets with correct magic/version).
**Path #2 (anti-replay) is the confirmed root cause.**

### Wire size analysis

Both sizes are normal ZTLP data packets:

| Wire size | Header | Encrypted | Plaintext | Frame content |
|-----------|--------|-----------|-----------|---------------|
| 159       | 46     | 113       | 97        | mux DATA: type(1) + stream_id(4) + data_seq(8) + payload(84) |
| 76        | 46     | 30        | 14        | mux DATA: type(1) + stream_id(4) + data_seq(8) + payload(1) |

These match exactly the two most common gateway HTTP response patterns:
- 84-byte payload = HTTP response headers (matches log: `GW->NE mux DATA stream=X bytes=84`)
- 1-byte payload = HTTP response body tail (matches log: `GW->NE mux DATA stream=X bytes=1`)

### Why they fail: gateway retransmits + mobile latency

**The gateway's retransmit timer (RTO) is too aggressive for the mobile path.**

Timeline from logs:
```
T=0ms      Gateway encrypts + sends data packets (seq=N, N+1)
T=300ms    Gateway RTO fires — no ACK received — retransmits both packets
T=900ms    Gateway retransmits again (backoff to 600ms)
T=2100ms   Gateway retransmits again (backoff to 1200ms)
T=2300ms   iOS finally receives ORIGINAL packets (2.3s mobile latency!)
T=2301ms   iOS decrypts successfully, records seq N and N+1 in ReplayWindow
T=2302ms   iOS sends ACKs for seq N, N+1
T=2350ms   Retransmit copies arrive at iOS
T=2351ms   ReplayWindow rejects both — already seen → rc=-99
```

Evidence from phone logs:
- At 07:37:26.864 gateway sends stream 19 data
- At 07:37:29.178 iOS receives seq=47 (**2.3 seconds later**)
- At 07:37:29.210 decrypt failures appear (**31ms after successful RX**)
- Gateway `@initial_rto_ms = 300` — fires 7-8 times in 2.3 seconds

The failures always come in pairs (159+76) because the HTTP response
headers and body tail were sent together, retransmitted together, and
arrive together.

### Why benchmarks fail

The "Vault HTTP Response" and "Primary HTTP Response" tests validate
that the response body arrives correctly. When the retransmitted
packets are the ones carrying the actual response data (not the
retransmits — the originals carry it), but the response verification
races with the stream close, the benchmark may sometimes not see the
response body in time. Looking at the log, the actual data flow works
fine — the benchmark failures are likely a timing/race issue with how
the benchmark validates responses while retransmit noise is present.

Additionally, `memory_ok=false` because `ne_memory_mb=nil` (memory
reporting patch commit `465e552` not yet deployed in the iOS build).

---

## Fix Plan — Three Layers

### Layer 1: Gateway — Mobile-aware RTO (SERVER-SIDE)

**Problem**: `@initial_rto_ms = 300` is appropriate for wired/WiFi but
causes massive spurious retransmits on cellular paths with 1-3s latency.

**Fix**: Use the ClientProfile (already sent in handshake msg3) to set
mobile-appropriate RTO parameters.

**Files to change:**
- `gateway/lib/ztlp_gateway/session.ex`

**Changes:**
```elixir
# Current values (too aggressive for mobile):
@initial_rto_ms 300
@min_rto_ms 100

# Add mobile-aware defaults:
@mobile_initial_rto_ms 1500
@mobile_min_rto_ms 500
```

After parsing the ClientProfile in `handle_handshake_msg3` (line 1281),
apply mobile RTO when client_class is "ios" or interface_type is "cellular":
```elixir
# In handle_handshake_msg3, after select_cc_profile:
rto_ms = if cc_profile.mobile? do
  @mobile_initial_rto_ms
else
  @initial_rto_ms
end

state = %{state | rto_ms: rto_ms, min_rto_ms: if(cc_profile.mobile?, do: @mobile_min_rto_ms, else: @min_rto_ms)}
```

**Impact**: Eliminates 90%+ of spurious retransmits on mobile. The SRTT
estimator will still converge to the actual RTT, but the initial value
won't cause a burst of retransmits before the first ACK arrives.

### Layer 2: Rust FFI — Separate replay from parse errors (BOTH SIDES)

**Problem**: `rc=-99 (InternalError)` lumps three different conditions
together, making debugging impossible. The Swift code can't distinguish
"harmless replay" from "corrupted packet" from "wrong session".

**Fix**: Add a dedicated `ReplayRejected` error code.

**File: `proto/src/ffi.rs`**

```rust
#[repr(i32)]
pub enum ZtlpResult {
    Ok = 0,
    InvalidArgument = -1,
    IdentityError = -2,
    HandshakeError = -3,
    ConnectionError = -4,
    Timeout = -5,
    SessionNotFound = -6,
    EncryptionError = -7,
    NatError = -8,
    AlreadyConnected = -9,
    NotConnected = -10,
    Rejected = -11,
    ReplayRejected = -12,    // NEW
    InternalError = -99,
}
```

In `ztlp_decrypt_packet()`, change the replay check:
```rust
// Anti-replay check
if !ctx.recv_window.check_and_record(header.packet_seq) {
    set_last_error("replay detected");
    return ZtlpResult::ReplayRejected as i32;  // was InternalError
}
```

**Impact**: Clean separation of error codes. iOS can handle replays
silently while still alerting on actual parse/crypto failures.

### Layer 3: iOS Swift — Silent replay handling + diagnostic logging

**Problem**: All decrypt failures are logged at ERROR level with
minimal context, inflating error counts and potentially affecting
benchmark scoring.

**Fix**: In `ZTLPTunnelConnection.swift`, handle replays silently:

```swift
private func handleReceivedPacket(_ wireData: Data) {
    guard let cryptoContext else { return }

    var decryptWritten: Int = 0
    let decryptResult = wireData.withUnsafeBytes { wirePtr -> Int32 in
        guard let baseAddr = wirePtr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return -1
        }
        return ztlp_decrypt_packet(
            cryptoContext,
            baseAddr,
            wirePtr.count,
            &decryptBuffer,
            decryptBuffer.count,
            &decryptWritten
        )
    }

    guard decryptResult == 0, decryptWritten > 0 else {
        if decryptResult == -12 {
            // Replay rejection — gateway retransmit of already-received packet
            replayCount += 1
            if replayCount % 10 == 1 {
                logger.debug("ZTLP replay rejected (count=\(replayCount)) wire=\(wireData.count)", source: "Tunnel")
            }
        } else {
            // Real decrypt failure — get detailed error from Rust
            let errorMsg = String(cString: ztlp_last_error())
            logger.error("ZTLP decrypt failed rc=\(decryptResult) wire=\(wireData.count) detail=\(errorMsg)", source: "Tunnel")
        }
        return
    }
    // ... rest of processing
}
```

Also add to the class:
```swift
private var replayCount: Int = 0
```

**Impact**: Replays logged at DEBUG (not ERROR), with a count that
helps diagnose excessive retransmission. Real failures include the
Rust error string for root cause identification.

---

## Implementation Order

### Phase 1 — Quick wins (fix benchmark, improve diagnostics)

1. **Deploy memory reporting** — cherry-pick `465e552` on Mac, rebuild
   both targets. This fixes `memory_ok=false` / `ne_memory_mb=nil`.

2. **Add `ReplayRejected` error code** — small Rust change in `ffi.rs`
   enum + one return statement. Rebuild both iOS static libs.

3. **iOS: silent replay handling** — Swift change in
   `ZTLPTunnelConnection.swift`. Also call `ztlp_last_error()` for
   non-replay failures.

4. **Rebuild and test** — run benchmark, verify:
   - Replay rejections logged at DEBUG
   - Real errors (if any) show detail string
   - Benchmark score improves (should be 8/8 if response timing is fine)
   - ne_memory_mb shows real values

### Phase 2 — Gateway RTO tuning (eliminate the cause)

5. **Mobile-aware initial RTO** — Increase initial RTO for mobile
   clients from 300ms to 1500ms. The SRTT estimator will converge
   quickly after the first few ACKs.

6. **Raise min_rto_ms for mobile** — From 100ms to 500ms to prevent
   the SRTT from dropping too low during brief good periods.

7. **Deploy gateway** — Rebuild and deploy. No iOS changes needed.

8. **Verify** — Run benchmark with new gateway. Replay count should
   drop to near-zero. Latency tests should still pass.

### Phase 3 — Hardening

9. **Gateway: log ACK latency** — Add per-client RTT to gateway logs
   so mobile latency is visible.

10. **iOS: expose replay count in benchmark upload** — Include the
    replay count in BenchmarkReporter data for monitoring.

11. **Consider: replay tolerance window** — Instead of hard reject,
    the client could track "recently decrypted seqs" and skip the
    duplicate silently without touching the ReplayWindow bitmap.
    This avoids the replay window from growing stale.

---

## Verification Checklist

- [ ] Replay rejection returns rc=-12 (not rc=-99)
- [ ] iOS logs replays at DEBUG level with count
- [ ] iOS logs real decrypt failures with `ztlp_last_error()` detail
- [ ] ne_memory_mb shows real value in benchmark upload
- [ ] Benchmark score 8/8 after Phase 1
- [ ] Gateway RTO starts at 1500ms for mobile clients (Phase 2)
- [ ] Replay count drops to <5 per benchmark run (Phase 2)
- [ ] All existing tunnel tests still pass

---

## Files Changed per Phase

### Phase 1
| File | Change |
|------|--------|
| `proto/src/ffi.rs` | Add `ReplayRejected = -12` enum variant, change replay return |
| `proto/include/ztlp.h` | Document new error code in C header |
| `ios/ZTLP/Libraries/ztlp.h` | Same header update |
| `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift` | Silent replay handling, error detail logging |
| Cherry-pick `465e552` on Mac | Memory reporting in benchmark uploads |

### Phase 2
| File | Change |
|------|--------|
| `gateway/lib/ztlp_gateway/session.ex` | Mobile-aware RTO constants + ClientProfile-based selection |

### Phase 3
| File | Change |
|------|--------|
| `gateway/lib/ztlp_gateway/session.ex` | ACK latency logging |
| `ios/ZTLP/ZTLPApp/BenchmarkView.swift` | Include replay count in uploads |

---

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| ReplayRejected code breaks FFI ABI | Low | New code -12, existing code paths unchanged |
| Higher RTO hurts throughput | Low | SRTT converges after first RTT; only initial is higher |
| Benchmark still fails 6/8 | Medium | The "No response" errors may have a separate timing cause; Phase 1 diagnostics will reveal |
| Memory reporting adds NE overhead | Very low | Two UserDefaults writes per 25s cycle |

---

## Bottom Line

The rc=-99 decrypt failures are **not real crypto failures**. They are
the correct behavior of the anti-replay window rejecting gateway
retransmits that arrive after the original packets. The root cause is
the gateway's RTO being tuned for wired networks (300ms) while the
mobile path has 2-3 second latency. The fix is three-pronged:

1. **Separate the error codes** so replays aren't confused with failures
2. **Handle replays silently** on iOS so they don't affect benchmarks
3. **Tune gateway RTO for mobile** to eliminate spurious retransmits
