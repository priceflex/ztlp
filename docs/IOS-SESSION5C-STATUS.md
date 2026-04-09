# ZTLP iOS Session 5C Status: 11/11 Benchmarks

## Result: 11/11 PASS

### Benchmark Results (v5C — 2026-04-09T08:12Z)
- Device: iPhone16,2 (iPhone 15 Pro Max)
- HTTP Ping:       avg=97ms    min=94ms    max=106ms    (30 iter) PASS
- GET 1KB:         avg=101ms   min=93ms    max=129ms    (20 iter) PASS
- GET 10KB:        avg=140ms   min=102ms   max=249ms    (20 iter) PASS
- GET 100KB:       avg=406ms   min=286ms   max=521ms    (20 iter) PASS
- GET 1MB:         avg=2299ms  min=2142ms  max=2459ms   (20 iter) PASS
- Download 5MB:    avg=10712ms min=10487ms max=11266ms   (5 iter) PASS
- POST Echo 1KB:   avg=100ms   min=95ms    max=352ms    (20 iter) PASS
- POST Echo 100KB: avg=543ms   min=386ms   max=2325ms   (20 iter) PASS
- Upload 1MB:      avg=1741ms  min=1463ms  max=2036ms   (5 iter) PASS
- Concurrent 5x:   avg=287ms   min=242ms   max=339ms    (3 iter) PASS
- TTFB:            avg=97ms    min=90ms    max=106ms    (8 iter) PASS

## Fixes Applied (Session 5C)

### 1. Mux Frame Headers (Swift — PacketTunnelProvider.swift)
- processRouterActions now builds proper ZTLP mux frames:
  - OpenStream:  [0x06 | stream_id(4 BE) | svc_name_len(1) | svc_name]
  - SendData:    [0x00 | stream_id(4 BE) | chunk...] chunked to 1135 bytes
  - CloseStream: [0x05 | stream_id(4 BE)]
- Matches the tokio path's mux framing exactly

### 2. Receive-Side Mux Demuxing (Swift — ZTLPTunnelConnection.swift)
- handleReceivedPacket detects mux vs legacy FRAME_DATA format
- Mux: [0x00 | stream_id(4 BE) | data_seq(8 BE) | payload] — stream_id > 0
- Legacy: [0x00 | data_seq(8 BE) | payload]
- Handles CLOSE/FIN sentinels wrapped in data frames

### 3. NE Backpressure (Swift — ZTLPTunnelConnection.swift)
- maxSendsInFlight: 64 → 512 (prevents upload data drop)
- maxPendingAcks: 32 → 64
- Action buffer: 64KB → 256KB

### 4. SendController Queue Cap (Rust — send_controller.rs)
- pending_queue cap: 512 → 2048
- Old cap silently dropped upload frames for payloads > ~600KB
- 1MB upload generates ~870 mux frames, was truncated at 56%

### 5. Gateway Recv Window Gap-Skip (Elixir — session.ex)
- When recv_window_base stuck for 2+ seconds with buffered packets beyond gap
- Skips missing packet(s) and resumes in-order delivery
- Prevents permanent session death from a single lost packet
- Trades one lost packet for keeping the session alive

## Memory Profile (v5C)
- NE Resident: 20.5MB (stable, not growing)
- Still above 15MB NE limit — needs ios-sync-only lib (next session)

## Remaining
1. Memory: separate ios-sync-only lib for NE target (under 15MB)
2. NE tunnel config points to wrong gateway (34.217.62.46:23096 vs relay)

## Git
- Commits: 9fa7107, 29a1855, ae52f0a
- Gateway image: ztlp-gateway:gap-skip
- Gateway env: ZTLP_GATEWAY_BACKENDS=http:127.0.0.1:8180,...
