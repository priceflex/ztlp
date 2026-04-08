# ZTLP Session 2 Handoff — 2026-04-08

## Progress: 5/11 → 8/11

### What Was Achieved This Session
- **Pushed ZTLP to GitHub** (priceflex/ztlp) — rebased 9 local commits on remote
- **Gateway retransmit bug fixed** — sorted by data_seq not packet_seq
- **ACK delivery fix** — send ACKs on BOTH main transport + NWConnection callback
- **Memory caps** — all unbounded buffers capped for iOS NE 15MB limit
- **LTO + strip + size-opt** — binary TEXT segment 8.4MB → 4.7MB
- **Benchmark improved**: 5/11 → 8/11

### Current Benchmark Results (8/11)
```
✓ HTTP Ping:       96ms avg (30/30)
✓ GET 1KB:         98ms avg (20 iters)
✓ GET 10KB:        127ms avg (20 iters)
✓ GET 100KB:       405ms avg (20 iters)
✓ GET 1MB:         2.3s avg (20 iters)
✓ Download 5MB:    11.2s avg (5 iters)
✓ POST Echo 1KB:   99ms avg (20 iters)
✓ POST Echo 100KB: 535ms avg (20 iters)
✗ Upload 1MB:      stalls after ~2min, "network connection lost"
✗ Concurrent 5x:   fails (tunnel dead after upload)
✗ TTFB:            fails (tunnel dead after upload)
```

### Remaining Issue: Upload 1MB Stall

The upload starts at stream 157, client sends data, gateway ACKs upload
data_seqs (acked_seq advancing to ~13031), but after ~2 minutes the
tunnel dies. The gateway log shows stream 157 opened, then silence
for over a minute before session replacement (new HELLO from reconnect).

**Root cause hypothesis**: The client's SendController manages uploads.
The upload cwnd/congestion control is separate from download. Possible
issues:
1. SendController cwnd drops to 0 and never recovers
2. The pending_queue cap (512) is hit and upload data is dropped
3. Upload ACKs from gateway aren't processed by SendController
4. The ack_rx unbounded channel in SendController isn't getting fed

**Key files for upload path**:
- `proto/src/send_controller.rs` — upload CC, pending_queue, flush()
- `proto/src/vip.rs` — VIP proxy feeds upload data to SendController
- `proto/src/ffi.rs` ~line 1660+ — upload ACK processing in recv_loop

**Gateway side**: Upload data arrives as FRAME_DATA from client, gateway
sends back FRAME_ACK with acked_data_seq. The gateway logs showed
`bytes_in=4.1MB` so it received significant upload data before the stall.

### Deployed State

#### Gateway (ubuntu@54.149.48.6)
- Container: `ztlp-gateway:retransmit-fix`
- CC params: loss_beta=0.7, max_cwnd=32, min_cwnd=4, stall=30s
- Key fix: retransmit sorted by data_seq not packet_seq
- Log level: info
- Echo server running: `/opt/ztlp/http-echo.py` (PID 324184)

#### iOS Library (on Steve's Mac)
- Built with LTO (opt-level=z, strip, panic=abort, codegen-units=1)
- Binary TEXT: 4.7MB (was 8.4MB before LTO)
- Memory resident: ~20MB (iOS tolerating it, not killing NE)
- ACKs sent on both main socket + NWConnection callback
- All buffers capped (outbound 128, reassembly 256, etc)
- Tokio: 2 worker threads × 256KB stacks

#### Docker Images on Gateway
- `ztlp-gateway:retransmit-fix` — **8/11 current** (data_seq sort + all CC params)
- `ztlp-gateway:phase1-cc` — was 11/11 in previous session (old client)
- `ztlp-gateway:phase1-rto-fix` — broken 5/11

### Key Fixes Made This Session

1. **Retransmit by data_seq** (gateway/session.ex)
   - Fast retransmit and RTO both sorted by packet_seq → data_seq
   - Was retransmitting already-ACK'd packets, causing 30s stalls

2. **Belt+suspenders ACK delivery** (proto/src/ffi.rs)
   - ACKs now sent via main transport socket FIRST (proven working)
   - Then also via NWConnection callback (redundant path)
   - Was: ACKs only via NWConnection which silently failed

3. **Memory caps** (multiple files)
   - vip.rs: TCP_READ_BUF 4KB, MAX_CONNS 8, channel depth 64
   - packet_router.rs: outbound 128 packets
   - send_controller.rs: pending 512, priority 128
   - ffi.rs: reassembly 256, received_ahead 1024
   - transport.rs: MAX_PACKET_SIZE 2048
   - Tokio: 2 threads × 256KB

4. **LTO binary size** (Cargo.toml)
   - lto=true, codegen-units=1, strip=true, opt-level=z, panic=abort
   - TEXT segment: 8.4MB → 4.7MB

5. **Build fixes** (iOS)
   - ackQueue/ackConnection: private → fileprivate
   - ios/Libraries/ztlp.h synced with proto/include/ztlp.h
   - SSH: stevenprice@10.78.72.234 (not steve@)

### Infrastructure Notes
- NS server (34.217.62.46:23096) is unreachable — reconnects fail
- Relay (34.219.64.205:23095) is working
- Gateway SSH: ubuntu@54.149.48.6 via default key (~/.ssh/id_rsa)
- Steve's Mac SSH: stevenprice@10.78.72.234 via default key
- iOS logs: `bash scripts/pull-ios-logs.sh /tmp/ztlp-ios-logs.txt`
- Gateway build dir: /home/ubuntu/ztlp-build (rsync'd, not git)

### Skills to Load
```
skill_view("ztlp-ios-speed-fix")
```

### Next Session Priority
1. Debug Upload 1MB stall in SendController
2. Fix NS server (34.217.62.46) or make reconnect work without it
3. Get 11/11
