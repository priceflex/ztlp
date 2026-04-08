# ZTLP iOS Status — 2026-04-08 Session 3

## Current State: 8/11 Benchmarks Passing

**Branch:** main
**Latest commit:** 06fb4b4 (fix: callback-only ACK path)
**Baseline tag:** v0.24.1-baseline-8of11

## What Was Fixed This Session

### Bug 1: iOS build broken — simulator .a linked for device target
- `build-ios.sh` copied simulator fat binary as default `libztlp_proto.a`
- Xcode errored: `ld: building for 'iOS', but linking in object file built for 'iOS-simulator'`
- **Fix:** `build-ios.sh` now copies device .a; also fixed 4 compiler warnings
- **Commit:** e46d7ad

### Bug 2: ACK starvation — recv_loop blocked on socket send
- `send_ack_frame!` macro called `ack_transport.send_data().await` BEFORE the
  NWConnection callback. When iOS outbound socket buffer was full, the `.await`
  blocked indefinitely, freezing the entire recv_loop (single-threaded tokio).
  No packets read, no callbacks fired — total ACK blackout.
- **Fix:** Send callback first (non-blocking), transport with 5ms timeout
- **Commit:** aa29074
- **Result:** Went from stalling at data_seq ~2,900 to ~20,000

### Bug 3: Dual-path seq starvation — recv_window gaps on gateway  
- Both transport `send_data()` and callback `build_encrypted_packet()` consumed
  packet_seq from the same shared AtomicU64 counter. When transport timed out
  (5ms), the packet was lost but the seq was burned. Gateway recv_window saw
  gaps — ACK packets piled up in recv_buffer but couldn't be delivered in-order.
- **Fix:** When callback is registered (iOS), use ONLY callback. No dual-path.
- **Commit:** 06fb4b4
- **Result:** Zero stalls. 72MB transferred. 8/11 benchmarks pass.

## 11 Benchmarks (in order)

| # | Test               | Status  | Notes                              |
|---|--------------------|---------|------------------------------------|
| 1 | HTTP Ping          | ✅ PASS |                                    |
| 2 | GET 1KB            | ✅ PASS |                                    |
| 3 | GET 10KB           | ✅ PASS |                                    |
| 4 | GET 100KB          | ✅ PASS |                                    |
| 5 | GET 1MB            | ✅ PASS |                                    |
| 6 | Download 5MB       | ❓      | Likely pass (72MB transferred)     |
| 7 | POST Echo 1KB      | ✅ PASS |                                    |
| 8 | POST Echo 100KB    | ✅ PASS |                                    |
| 9 | Upload 1MB         | ❌ FAIL | Suspect: upload path or echo 100KB |
| 10| Concurrent 5x GET  | ❓      | Needs all 5 to succeed             |
| 11| Time-to-First-Byte | ✅ PASS |                                    |

**Note:** Steve reports 8/11 and suspects POST echo or upload may be failing.
Need to identify exactly which 3 fail. The gateway showed ZERO stalls and
72MB transferred, so data flow is working. Failures may be:
- Upload path bug (phone→gateway direction less tested)
- Timeout during large POST (120s URLSession timeout)
- Memory pressure during concurrent/large tests
- POST Echo 100KB might actually be one of the failures

## Architecture After Fixes

```
Phone recv_loop (tokio, single-threaded):
  recv_data().await → decrypt → process frame
    │
    ├─ FRAME_DATA: reassemble, deliver to VIP proxy
    │
    └─ Need to ACK? → send_ack_frame! macro:
         ├─ Callback registered (iOS): NWConnection ONLY (no transport)
         │   └─ build_encrypted_packet() → cb() [non-blocking]
         └─ No callback (desktop): transport.send_data().await
```

## Key Files Changed

- `proto/src/ffi.rs` — send_ack_frame! macro (lines ~1197-1225)
- `proto/src/ffi.rs` — Phase 1+2 sync crypto FFI (lines 3445-4160)
- `ios/build-ios.sh` — fixed to copy device .a as default
- `proto/include/ztlp.h` + `ios/ZTLP/Libraries/ztlp.h` — sync FFI declarations

## What's Next: Getting to 11/11

### Immediate: Identify the 3 failing benchmarks
Run benchmark with device console logging to see which tests fail and why.
```bash
idevicesyslog -m HTTPBench
```

### If failures are upload/POST-related:
The upload path (phone→gateway) goes through:
1. Swift URLSession → VIP proxy → ztlp_router_write_packet()
2. Rust PacketRouter → RouterAction via tokio::mpsc
3. router_action_task → transport.send_data() (tokio UdpSocket)

This path still uses tokio for the actual send. If the tokio runtime is
under memory pressure, sends could stall.

### If failures are memory-related (jetsam kills):
Continue with Phase 3: Swift GCD event loop
- Replace tokio recv_loop with Swift NWConnection.receiveMessage()
- Use sync FFI (ztlp_decrypt_packet, ztlp_parse_frame) from Swift
- Feature-gate tokio out → LTO strips it → ~3-5MB savings
- Target: 10-13MB RSS (under 15MB with headroom)

Phase 1+2 sync FFI is DONE and tested (14 tests pass). The Swift
integration is the remaining work.

### If failures are throughput/timeout-related:
- Increase URLSession timeout for large transfers
- Tune gateway congestion control (cwnd, burst_size)
- Check if pacing rate is throttling uploads

## Build Instructions

### Rust library (on Steve's Mac via SSH):
```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd ~/ztlp/proto
cargo build --target aarch64-apple-ios --release --lib
cp target/aarch64-apple-ios/release/libztlp_proto.a \
   ~/ztlp/ios/ZTLP/Libraries/libztlp_proto.a
```

### Xcode build (compile check, no signing):
```bash
cd ~/ztlp/ios/ZTLP
xcodebuild -project ZTLP.xcodeproj -scheme ZTLP \
  -destination 'generic/platform=iOS' -configuration Release build \
  CODE_SIGN_IDENTITY='' CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
```

### Run tests:
```bash
cd ~/ztlp/proto
cargo test --lib -- test_sync      # 14 sync FFI tests
cargo test --lib                   # all 873 tests
```

## Gateway Debug Logging (currently deployed)

The gateway at 54.149.48.6 has enhanced logging (image: debug-logging3):
- `PKT_IN_RECOVERY` — packets arriving during recovery with pkt_seq + window info
- `CLIENT_ACK` — every ACK from phone with data_seq and state
- `STALL` — enhanced with last_acked, recv_base, dup_ack, recovery state
- `WINDOW_REJECT` / `Decrypt FAILED` / `PARSE_FAIL` — promoted to warning

To revert to clean gateway (no debug logging), rebuild from ztlp-build
without the session.ex patches.

## Environment
- Steve's Mac: stevenprice@10.78.72.234 (default SSH key, not openclaw)
- Gateway: ubuntu@54.149.48.6 (docker: ztlp-gateway:debug-logging3)
- Relay: ubuntu@34.219.64.205 (docker: ztlp-relay)
- Rust: 1.94.1 (use $HOME/.cargo/bin, NOT homebrew's 1.92)
- Phone UDID: 00008130-000255C11A88001C
