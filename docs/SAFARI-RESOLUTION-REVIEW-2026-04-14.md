# Safari Resolution Review
# Date: 2026-04-14
# Model: openai/gpt-5.4 via OpenRouter

## Summary

I reviewed the last-session handoff, current repo code, and the latest benchmark/log records stored on bootstrap.

Bottom line:
- This does NOT currently look like a primary memory-leak / jetsam problem.
- The main blocker is still that the packet-drop fix has been committed in source but has not yet been rebuilt into the iOS static libraries and redeployed to the phone.
- After that deploy, the most likely remaining bug is a stream lifecycle problem: mux streams are opening and immediately closing.

---

## What I Verified

### 1. Last session handoff matches the repo
Read:
- `ztlp/docs/SAFARI-FIX-HANDOFF-2026-04-14.md`

Handoff says the verified root cause was silent packet drops in `packet_router.rs` when outbound queue hit 128 packets. Pushed fixes were:
- iOS outbound queue cap increased from 128 -> 256
- stop dropping oldest outbound packet; spill to per-flow `send_buf` instead
- set PSH only on final chunk
- remove Swift flush throttle break
- add missing FFI declarations

### 2. The source code really contains those fixes
Inspected:
- `ztlp/proto/src/packet_router.rs`
- `ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ztlp/bootstrap/app/controllers/api/benchmarks_controller.rb`
- `ztlp/ios/ZTLP/ZTLP/Services/BenchmarkReporter.swift`

Verified:
- `OUTBOUND_MAX_PACKETS = 256` on iOS in `packet_router.rs`
- `flushOutboundPackets()` no longer has the throttle break in the drain loop
- `OpenStream` / `SendData` / `CloseStream` handling is present in Swift
- benchmark uploads are stored on bootstrap with raw `device_logs`

### 3. Bootstrap logging is working, but still too weak for final root cause isolation
Queried bootstrap benchmark API and checked the latest uploaded log record.

Latest analyzed record:
- `id=124`
- `error_details=manual_log_dump: benchmark_page_send_logs`
- `ne_memory_mb=15`
- `log_lines=592`
- `router_throttle=0`
- `OpenStream=8`
- `CloseStream=5`
- `SendData=2`
- `GW->NE mux DATA=174`
- `VPN disconnects=1`
- `router_stats entries=0`

Important observations:
- no router throttling in latest uploaded logs
- no router stats snapshots in latest uploaded logs
- NS still returns no relay records, so client falls back to static/default service map
- several streams open and immediately close

---

## Current Interpretation

## Primary issue

The fix is in source, but the phone has not yet been tested with rebuilt libraries containing that fix.

This means the current phone behavior can still be explained by the OLD broken NE library.

Until the Mac rebuild + Xcode redeploy happens, we cannot say whether the packet-drop fix fully resolved the Safari stall problem.

## Secondary likely issue

The logs show a real stream lifecycle problem independent of memory:
- `OpenStream`
- immediate `CloseStream`
- only a small number of streams actually reach `SendData`
- data then flows briefly, followed by VPN disconnect

That pattern points more toward:
- gateway/relay/backend rejecting or closing streams early
- TCP FIN/RST translation issues
- mux stream lifecycle mismatch
- Safari retries caused by premature closes

It does NOT primarily look like:
- memory growth / leak
- ongoing router throttle starvation
- benchmark upload failure

---

## Why Current Logging Is Still Not Enough

### 1. Uploaded logs are append-only whole-file dumps
`BenchmarkReporter.readDeviceLogs()` reads the entire shared app-group `ztlp.log`.

That means one uploaded benchmark/log dump can contain multiple tunnel sessions mixed together.
This makes causal analysis much harder.

### 2. No benchmark/session correlation id
There is no `benchmark_run_id` or `tunnel_session_id` attached to uploads.

So we cannot cleanly say:
- these exact logs belong to this exact Safari attempt
- this disconnect belongs to this exact benchmark run

### 3. Router stats are periodic, not edge-triggered
Router stats appear to be emitted from the cleanup timer every 10 seconds.

But the failure often happens before the first periodic snapshot, so the uploaded record frequently contains zero `Router stats:` lines.

That leaves the exact failure window under-instrumented.

### 4. Bootstrap stores raw logs but not extracted structured diagnostics
`BenchmarksController` stores raw `device_logs`, but does not extract or persist fields like:
- outbound queue high-water mark
- per-flow send buffer high-water mark
- spill-to-send-buffer count
- stream opens/closes by service
- FIN/RST counts
- disconnect reason
- tunnel session id

---

## Recommended Next Steps

## Step 1: Rebuild and redeploy the iOS libs now

This is the blocker.

Commands on Steve’s Mac:

```bash
cd ~/ztlp
git pull origin main

cargo build \
  --manifest-path proto/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib \
  --no-default-features \
  --features ios-sync \
  --target-dir proto/target-ios-sync

cp proto/target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a \
  ios/ZTLP/Libraries/libztlp_proto_ne.a

touch proto/src/ffi.rs
cargo build \
  --manifest-path proto/Cargo.toml \
  --target aarch64-apple-ios \
  --release --lib

cp proto/target/aarch64-apple-ios/release/libztlp_proto.a \
  ios/ZTLP/Libraries/libztlp_proto.a

cp proto/include/ztlp.h ios/ZTLP/Libraries/ztlp.h
cp proto/include/ztlp.h ios/ZTLP/ZTLPTunnel/ztlp.h
```

Then in Xcode:
- Clean Build Folder
- Build
- Deploy to phone

## Step 2: Run Safari again immediately after redeploy

The next symptom change matters a lot.

Expected possibilities:
- Safari fully works -> packet drop bug was the main issue
- Safari gets much farther -> packet drop fix helped, now stream lifecycle bug is exposed
- No VPN disconnect, but some resources still fail -> likely stream close / mux semantics issue

## Step 3: Improve logging before or alongside the next test

### A. Add `tunnel_session_id` / `benchmark_run_id`
At tunnel start:
- generate UUID
- log it
- store it in shared defaults
- include it in every benchmark upload and manual log dump

### B. Stop uploading the entire append-only log file
Preferred options:
- capture byte offset at benchmark start and upload only logs from that offset onward
or
- rotate / truncate `ztlp.log` at benchmark start or tunnel start

### C. Add structured router counters via FFI
Expose counters such as:
- outbound_queue_len_current
- outbound_queue_len_peak
- flow_send_buf_peak
- spill_to_send_buf_count
- spill_bytes_total
- open_stream_count
- close_stream_count
- gateway_close_count
- rst_from_client_count
- fin_from_client_count
- fin_from_gateway_count

### D. Force immediate diagnostics on failure edges
Emit router stats immediately on:
- VPN status changing to disconnecting
- benchmark timeout/failure
- manual Send Logs
- gateway mux CLOSE received
- suspicious OpenStream -> immediate CloseStream pattern

---

## Most Likely Final Fix Path

1. Deploy the current packet-drop fix
2. Confirm Safari no longer dies from outbound queue overflow
3. Isolate remaining stream-open/stream-close bug
4. Fix mux stream close semantics / gateway acceptance / backend reject path
5. Keep improved per-run logging permanently

---

## Current Hypothesis

After the drop fix is actually deployed, if Safari still fails, the next most likely issue is one of:
- router opens mux streams that are closed before payload completes
- gateway/relay closes concurrent streams too early
- TCP FIN/RST translation is wrong
- service routing mismatch for some Safari requests
- NS fallback is not the main cause, but still adds noise/confusion

Best supporting evidence:
- latest logs show multiple `OpenStream -> CloseStream` pairs
- latest logs show almost no `SendData` relative to stream churn
- this is much more consistent with stream lifecycle failure than memory-pressure failure

---

## Practical Recommendation

Do this next:
1. rebuild + redeploy the iOS app with the fixed libs
2. run one Safari test
3. immediately send logs
4. compare the new bootstrap record against the pre-fix record

That will tell us whether:
- the packet-drop bug is fully fixed
- or we have now cleanly isolated the secondary stream-close bug

---

## Files Reviewed

- `ztlp/docs/SAFARI-FIX-HANDOFF-2026-04-14.md`
- `ztlp/proto/src/packet_router.rs`
- `ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ztlp/ios/ZTLP/ZTLP/Services/BenchmarkReporter.swift`
- `ztlp/bootstrap/app/controllers/api/benchmarks_controller.rb`

## Bootstrap data reviewed

Queried:
- `http://10.69.95.12:3000/api/benchmarks?limit=8`

Latest analyzed benchmark/log record:
- `BenchmarkResult id=124`
