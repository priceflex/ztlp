# ZTLP iOS Vaultwarden Next-Build Plan — 2026-05-03

## Executive summary

We are not blocked on basic connectivity anymore. Current evidence says the tunnel can resolve DNS, open vault streams, receive megabytes of Vaultwarden response data, ACK it, and drain gateway queues. The page still spins because browser TCP streams are being closed/churned before WebKit finishes the page, while the gateway continues to deliver the response tail.

The next build should stop treating this as a pure rwnd/gateway-congestion problem and add end-to-end stream-lifecycle observability plus a Nebula-style simplification of the iOS data plane.

Most important current log facts from the pulled iPhone log `/tmp/ztlp-phone.log`:

- `Rust fd dns`: 13 markers. DNS is working in Rust fd mode.
- `RouterAction send OpenStream`: 79 markers. WKWebView is opening vault TCP flows.
- `RouterAction send CloseStream`: 52 markers. CloseStream now flows; old suppression leak is improved.
- `Advertised rwnd=16`: 3 markers, `rwnd=8`: 4 markers, but `rwnd=4`: 299 markers. The build briefly ramps then spends almost all time at rwnd=4.
- `WKWebView provisional failed`: 3 markers, all `NSURLErrorDomain code=-999` (WebKit cancelled loads, usually because the navigation was superseded or the app/WebView closed/started another request, not a transport errno by itself).
- `Benchmark upload failed`: 2 timeouts. No successful benchmark upload in this app-group log window.
- `Reconnect`: 0 markers in this pulled window. This is not currently a reconnect storm.
- Gateway preflight is green; no server-side stack outage.

Critical gateway window `2026-05-03T01:14:55..01:16:05`:

- Gateway sees ACKs and obeys rwnd.
- At 01:15:58, gateway is still draining a shallow response tail (`queue=99`) at `rwnd=4`.
- Browser/client sends `FRAME_CLOSE` for multiple vault streams while queue still has response data:
  - `FRAME_CLOSE stream_id=13 reason=client_close_after_connect service=vault queue=99`
  - streams 14, 10, 8, 11, 12, 9 same pattern
- Queue drains to zero by 01:16:00.3 with no catastrophic `queue=6000`, no overload rejection, no RTO storm in this window.
- New tiny streams open/close immediately after that (`client_close_unknown_stream`), matching WebKit retry/churn rather than gateway congestion collapse.

Working conclusion: the active failure is most likely a browser/stream lifecycle problem caused by slow/tiny receive window + HTTP asset timing + FIN/CLOSE timing, not DNS, not Vaultwarden backend down, not NS/relay outage, and not the old server queue explosion.

## What we learned from DefinedNet mobile_nebula

Repo inspected: `https://github.com/DefinedNet/mobile_nebula.git` cloned to `/tmp/mobile_nebula`.

Important architecture pattern:

- `ios/NebulaNetworkExtension/PacketTunnelProvider.swift` is a thin wrapper.
- It extracts the utun fd by scanning fds for `com.apple.net.utun_control`.
- It calls `setTunnelNetworkSettings(...)` first.
- Then it passes the fd directly into Go:
  - Swift: `MobileNebulaNewNebula(..., tunFD, ...)`
  - Go: `overlay.NewFdDeviceFromConfig(&tunFd)`
- Swift does not run a packetFlow read/write loop for the data plane.
- The native core owns packet I/O and tunnel lifecycle.
- It uses the app/extension IPC only for control/status operations.
- Go memory is constrained with `debug.SetGCPercent(20)` and `runtime.MemProfileRate = 0` because iOS NE memory is tight.

This supports our direction: Rust should fully own utun reads and writes, and Swift should stop being in the packet hot path. Our current Rust-fd mode is halfway there: Rust owns utun and DNS/router ingress, but Swift still owns mux-frame transport over `ZTLPTunnelConnection`/NWConnection. That split makes timing/backpressure harder to reason about.

## Current ZTLP architecture gap

Current ZTLP Rust-fd architecture:

1. Swift starts NE and configures routes/DNS.
2. Swift extracts utun fd.
3. Rust `IosTunnelEngine` reads utun, handles DNS, feeds `PacketRouter`.
4. Rust dispatches router actions back to Swift callback.
5. Swift sends mux frames over `ZTLPTunnelConnection` using NWConnection.
6. Swift receives gateway data and writes it into Rust router/utun path.

Problem with this split:

- The packet router is native, but stream transport and ACK/rwnd policy live in Swift.
- Close/open timing crosses Rust callback → Swift queue → NWConnection send completion → gateway.
- Browser burst traffic generates many `FRAME_OPEN`/`FRAME_CLOSE` actions and the system has no single owner that can say: “this TCP flow still has bytes pending; do not close upstream/downstream yet.”
- Diagnostics are spread across Rust app-group bridge logs, Swift logs, and gateway logs with no shared stream UUID/request ID.

## What has already been tried recently

Recent git history shows a long sequence of valid fixes, but also a pattern of changing one throttle at a time without enough cross-layer visibility:

- Removed/optimized tokio from NE builds; two-library architecture.
- Replaced SFSafariViewController with WKWebView.
- Added `.ztlp` DNS responder and later Rust-fd DNS responder.
- Added Safari SVCB/HTTPS and resolver.arpa DNS handling.
- Removed memory throttle hot-path gating.
- Added append-only logs and benchmark uploads.
- Fixed ACK starvation / callback-only ACK path.
- Added rwnd ACK frames; tried caps 4/5/8/12/16.
- Fixed gateway queue explosion and shallow queue backpressure.
- Fixed gateway recovery exit bug.
- Fixed router outbound spill, `pop_outbound()` refill, and FIN-after-tail bugs.
- Fixed Rust fd CloseStream suppression.
- Moved session health off the tunnel queue and avoided reconnect on successful probe.

These were not wasted. They eliminated earlier failure classes. The remaining failure is narrower: WebKit stream lifecycle/asset-tail completion under vault bursts.

## Next-build goals

The next build should not be “try another rwnd value.” It should be an instrumented rebuild with one clear architecture target and enough logs to know the cause on the first failed run.

### Goal 1: Make Rust the single data-plane owner, Nebula-style

Target state for iOS NE:

- Swift only:
  - load config/identity
  - configure `NEPacketTunnelNetworkSettings`
  - extract utun fd
  - start/stop native engine
  - display/send logs
- Rust owns:
  - utun read/write
  - DNS responses
  - packet router
  - mux open/send/close generation
  - UDP socket or Network.framework-compatible transport abstraction
  - ACK/rwnd/pacing/backpressure state
  - stream lifecycle decisions

Short-term practical step:

- Keep Swift `NWConnection` only as a UDP send/receive shim if raw UDP sockets are not App-Store-safe in the NE, but move the mux frame scheduling/ACK/rwnd state machine into Rust.
- Swift callback should become “send encrypted datagram bytes” and “deliver received datagram bytes,” not “interpret router actions and manage stream flow policy.”

This is the closest ZTLP equivalent to mobile_nebula’s `overlay.NewFdDeviceFromConfig(&tunFd)` pattern.

### Goal 2: Add stream lifecycle tracing before changing more tuning

Add a `trace_id` for every browser TCP flow and mux stream. At minimum log:

Phone/Rust router:

- TCP 5-tuple, stream_id, service, first SYN timestamp.
- First byte from browser, first byte from gateway, last byte from gateway.
- FIN/RST from browser with TCP seq/ack and unread queued bytes at that moment.
- FIN generated to browser and whether response tail/send_buf/outbound was nonzero.
- `process_gateway_close` reason and whether FIN was delayed.
- Per-stream bytes: browser→gateway, gateway→browser, utun_write_bytes.
- Close initiator: browser FIN/RST, gateway FRAME_CLOSE, router timeout, duplicate close suppression.

Gateway:

- `FRAME_OPEN` with stream_id, service, backend connect latency.
- backend first byte latency, response bytes, chunk count.
- `FRAME_CLOSE` from client while send_queue contains frames for that stream.
- queue length per stream, not just global queue.
- backend socket EOF vs client close vs timeout.
- whether backend read was paused/resumed and actual `active: false` state.

Browser/WKWebView:

- `didStartProvisionalNavigation`, `didCommit`, `didFinish`, `didFailProvisional`, `didFail`.
- URL for main frame and subresources if possible via `WKURLSchemeHandler` for a test scheme or injected JS Resource Timing after page stop.
- For Vaultwarden specifically, inject JS after load/timeout to report `document.readyState`, current URL, number of scripts/styles/images, and `performance.getEntriesByType('resource')` failed/slow resources.

The first failed run should answer: which asset did not finish, which stream carried it, who closed it, and were bytes still queued when it closed?

### Goal 3: Create a repeatable capture harness

Add a single script/documented command sequence so we stop relying on ad-hoc greps.

Proposed file: `scripts/ztlp-ios-vault-capture.sh`.

It should:

1. Record local timestamp T0.
2. Pull iPhone app-group log from Steve’s Mac.
3. Pull gateway logs between T0-2m and now.
4. Pull relay stats/logs for same window.
5. Optionally run gateway tcpdump for 60s during a test:
   - `sudo timeout 60 tcpdump -i any -n -tttt -s 200 udp port 23097 -w /tmp/ztlp-gw-vault.pcap`
6. Optionally run relay tcpdump for 60s:
   - `sudo timeout 60 tcpdump -i any -n -tttt -s 200 udp port 23095 -w /tmp/ztlp-relay-vault.pcap`
7. Save all outputs under `captures/vault-YYYYmmdd-HHMMSS/`.
8. Generate `summary.txt` with counts for rwnd, opens/closes, WKWebView failures, RTO, STALL, queue max, replay rejects, benchmark results.

Important: tcpdump on the gateway/relay shows encrypted UDP only, so it will not identify HTTP assets. It is still useful to prove packet flow, loss/retransmit gaps, and relay/gateway asymmetry. Stream/asset identity must come from app/gateway structured logs.

### Goal 4: Fix the current likely bug class

Based on current logs, the next code change should focus on close semantics and WebKit churn, not server queue size.

Hypothesis A — browser closes because response tail is too slow at rwnd=4:

- Evidence: rwnd=16 appears briefly, then policy drops to rwnd=4 for almost everything.
- Gateway is still draining at queue=99 when client closes many streams.
- No catastrophic queue explosion; rwnd=4 may now be too conservative after shallow queue/Rust fd fixes.

Fix/test:

- Do not drop from rwnd=16/12/8 to rwnd=4 solely because `oldestMs` grows while gateway data is still useful and replayDelta=0.
- Pressure floor should require real danger: replayDelta > 0, router outbound/send_buf nonzero, utun write errors, full drain saturation, or no highSeq progress.
- In current logs, router stats often show flows=0/outbound=0 after closes, so “oldestMs” alone is not a good pressure signal.
- Test cap sequence: 12 first, then 16 only if no replay/RTO. But make the policy stable for the whole page load, not a two-second burst.

Hypothesis B — router/gateway closes a stream while bytes for that stream still exist:

- We fixed local FIN-after-send_buf, but gateway may still keep queued frames for streams that the client closes, or client may send close before WebKit has actually consumed final bytes.
- Need per-stream queued byte logs to prove/disprove.

Fix/test:

- On gateway, when `FRAME_CLOSE` arrives, log and drop any queued frames for that stream explicitly; otherwise stale queued frames can keep the session busy for a stream WebKit abandoned.
- On router, when browser FIN/RST arrives, log whether gateway response bytes are still pending and whether we are sending `FRAME_CLOSE` immediately.
- If browser sends FIN after receiving complete HTTP response, this is fine. If it sends FIN before complete response and then opens a replacement stream, the problem is latency/timeout/HTTP asset behavior.

Hypothesis C — WKWebView is being programmatically reloaded/cancelled:

- `NSURLErrorDomain -999` is cancellation. It can be caused by a new navigation, view dismissal, or WebKit deciding to cancel subloads.
- Need browser lifecycle logs to tell if app UI is creating multiple WKWebViews or reassigning URLs.

Fix/test:

- Ensure `SafariHelper` / sheet code creates one stable WKWebView per OpenVault attempt.
- Do not recreate the WebView due to SwiftUI state churn.
- Add unique browser session id to each open and log all delegate callbacks.

## Concrete next-build implementation checklist

### iOS/Rust

1. Add `browser_session_id` from Swift when opening WKWebView; include it in app-group log lines.
2. Add full WKNavigationDelegate lifecycle logs: start, commit, finish, fail, URL, mainFrame flag if available.
3. Add a JS diagnostic button/timer for Vaultwarden: after 20s, log `document.readyState`, current location, and Resource Timing entries.
4. Add Rust `PacketRouter` per-flow trace fields:
   - stream_id
   - TCP 5-tuple
   - bytes in/out
   - last browser FIN/RST
   - last gateway data time
   - pending outbound/send_buf at close
5. Add FFI/app-log bridge for aggregated per-stream close summaries, not per-packet spam.
6. Change rwnd policy so rwnd=12 or 16 is held during browser burst unless concrete pressure exists. Remove `oldestMs` as a standalone reason to force rwnd=4.
7. Keep Rust-fd DNS and CloseStream duplicate suppression fixes.
8. Keep no-reconnect-on-probe-success behavior.
9. Build NE lib with separate target dir and Xcode Clean Build Folder.

### Gateway

1. Add per-stream queue accounting in `session.ex`.
2. Log `FRAME_CLOSE` with queued frames/bytes for that stream.
3. On client `FRAME_CLOSE`, drop queued frames for that stream and log count/bytes dropped.
4. Log backend EOF/close reason and total response bytes per stream.
5. Rate-limit `pacing_tick` spam or aggregate it; current logs are too noisy and hide stream events.
6. Do not restart gateway for this instrumentation without warning Steve first.

### Capture docs/scripts

1. Create `docs/IOS-VAULTWARDEN-CAPTURE-RUNBOOK.md`.
2. Create `scripts/ztlp-ios-vault-capture.sh`.
3. Every test run gets a capture directory with phone log, gateway log, relay log, optional pcaps, and summary.

## Acceptance criteria for the next build

The next build is acceptable only if one of these happens:

A. Vaultwarden loads to login reliably in WKWebView three consecutive times, and a post-Vault benchmark still passes.

or

B. If it still fails, the capture identifies the exact failed resource/stream and exact close initiator with queued-byte state. No more “maybe rwnd/maybe DNS/maybe memory.”

Minimum pass/fail markers:

- Phone log shows `Rust fd dns responder wrote response` for vault DNS.
- Phone log shows stable browser session id and WKWebView lifecycle.
- Gateway sees `CLIENT_ACK ... rwnd=12` or `rwnd=16` sustained during the page, unless real pressure exists.
- Gateway max queue stays near shallow cap, no `send_queue already overloaded`, no queue thousands.
- No automatic `VPN status changed 5 -> 1` during test.
- Router stats eventually return `flows=0 outbound=0 stream_to_flow=0`, but only after WebKit finish or explicit user cancel.
- If WebKit reports `-999`, the app log shows what navigation cancelled it.

## Why this should stop the two-month loop

For two months we have mostly inferred root cause from partial logs: memory, DNS, SFSafari, queue depth, rwnd, reconnects, close suppression. Many of those were real at the time, and several are now fixed. The current logs show a different class: stream churn/cancellation while transport is still alive.

The way out is not one more blind parameter tweak. The way out is:

1. Collapse ownership like Nebula: native core owns utun/data-plane, Swift becomes control/UI.
2. Add per-stream/per-browser-session tracing so every close has a cause and byte counts.
3. Capture the whole stack in one run.
4. Only then tune rwnd/pacing based on measured close/latency behavior.

## Immediate recommendation

For the very next build, do these in order:

1. Add instrumentation/runbook/capture script first.
2. Patch rwnd policy to hold 12 during browser burst unless replay/utun/router pressure is real.
3. Add gateway per-stream queued-byte logging and drop queued frames on client close.
4. Build/deploy once.
5. Run one controlled Vaultwarden test and capture all logs.

Do not spend another cycle changing NS, Vaultwarden DOMAIN, Safari vs WKWebView, or broad gateway queue sizes unless the new capture proves they are involved.
