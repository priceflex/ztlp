# Vaultwarden Spinner Tail-Stall Analysis — 2026-05-02

## Executive Summary

Current evidence points away from Vaultwarden itself and toward a client-side tail-packet completion stall in the current iOS hybrid Rust-fd browser path.

What appears to be happening:
- Vaultwarden starts loading successfully.
- Large amounts of HTTP response data are produced by the backend and delivered through ZTLP.
- The iPhone/browser path receives and ACKs most of the response.
- A very small tail of final tunnel packets stops making forward progress.
- The gateway retransmits those tail packets repeatedly.
- iOS logs stop showing useful RX progress and only show replay/no-progress behavior.
- Session health eventually times out and reconnects, but the page spinner is already lost.

## Main Conclusion

This is most likely **not**:
- Vaultwarden backend hanging
- NS/relay/gateway reachability failure
- missing router-ingress / transport bridge / outbound-utun wiring
- a pure browser fanout problem requiring generic gateway queue tuning

This is most likely:
- a **tail-delivery / tail-consumption stall** in the current iOS hybrid Rust-fd path, where the final packets needed to complete one or more browser resources stop turning into useful forward progress.

## Evidence Gathered

## 1. Server-side baseline was healthy

Preflight before testing:
- `PRECHECK GREEN`
- NS, relay, and gateway healthy
- Gateway could reach backends on:
  - `127.0.0.1:8080`
  - `127.0.0.1:8180`
- No backend `econnrefused`
- No general send_queue overload in preflight

## 2. iPhone logs showed real Vaultwarden traffic, not immediate failure

The iOS app-group log for the test run showed:
- tunnel startup was healthy
- Rust-fd router-ingress path was active
- Rust router action callback was active
- session-health manager was active on `healthQueue`

Key markers:
- `Rust fd data plane requested; Swift packet I/O loop disabled`
- `Rust router action callback registered`
- `Rust iOS tunnel engine scaffold started fd=5 mode=router_ingress swift_packetFlow=disabled transport=swift_action_callback`
- `Session health manager enabled interval=2.0s ... queue=healthQueue`

The page load was not failing at open/connect time.

## 3. Current failing run had only 2 active streams

This is important.

In the latest correlated failing run, the phone log showed:
- `flows=2`
- `streamMaps=2`

That means the failure survives even under a relatively small number of concurrent streams. This weakens the theory that the problem is primarily large browser fanout.

## 4. The iPhone received a lot of payload before stalling

From the phone log:
- `ZTLP RX summary packets=1222 payload=897671B acks=1222 replay=1 highSeq=1221 inflight=0`

That means:
- nearly 900 KB of payload arrived successfully
- cumulative progress reached `highSeq=1221`
- the page was not “stuck because nothing came back”

After that, logs changed to:
- `ZTLP RX summary packets=0 payload=0B acks=0 replay=15 highSeq=1221 inflight=0`
- later more replay-only summaries with no useful progress

So the session transitions from:
- healthy delivery
into:
- tail retransmit / replay / no-useful-RX stall

## 5. Backend tcpdump proved Vaultwarden was still sending HTTP data

A gateway-host tcpdump on `127.0.0.1:8080` showed Vaultwarden actively sending large HTTP response chunks during the spinner window.

Examples observed on localhost:
- `length 53824: HTTP`
- `length 53952: HTTP`
- `length 60032: HTTP`
- `length 58880: HTTP`
- `length 50304: HTTP`
- `length 35648: HTTP`
- `length 19584: HTTP`
- `length 28032: HTTP`

This strongly indicates:
- the backend is alive
- the backend is not the primary stall point
- response production continues while the page is still spinning

Later in the localhost capture, some connections ended with zero-window behavior and eventual resets after the upstream tunnel session died.
That looks like an upstream abandon/reset effect, not the original cause.

## 6. UDP/tunnel capture and gateway logs showed tail retransmit of only a few packets

The tunnel-side analysis showed:
- ACKs advanced cleanly through `data_seq=1217`
- then progress stopped on the next tiny tail
- repeated RTO retransmits targeted the final packets:
  - `data_seq=1218`
  - `data_seq=1219`
  - in earlier runs, a similarly tiny final set was stuck

Gateway logs showed repeated retransmits:
- attempt 1 through attempt 9
- increasing RTOs
- session eventually replaced after the tail never advanced

This is the most important shape in the evidence.

It suggests:
- the failure is not broad throughput collapse
- the failure is not early handshake/open failure
- the failure is a **small tail that never completes**

## 7. Session health detects the stall and reconnects, but too late to save the page

Phone log during failure:
- `Session health candidate ... highSeq=1221 noUsefulRxFor=6.9s`
- `Session health suspect: reason=no_useful_rx_6.9s ... sending probe`
- `Session health dead: probe timeout ...`
- `Router reset runtime state removed=2 reason=session_health_probe_timeout`
- `Reconnect gen=1 succeeded via relay ...`

So session-health recovery is doing its job, but the user-visible browser transaction is already lost by the time recovery happens.

## Gateway tuning experiment already tried

A targeted gateway experiment was performed:
- changed `@queue_high` from `512` to `256`
- changed `@queue_low` from `128` to `64`
- deployed as `ztlp-gateway:browser-queue-shallow`
- preflight remained green

The new thresholds were confirmed live in behavior via repeated backpressure transitions:
- `Backpressure OFF: resuming backend reads (queue=64)`
- `Backpressure ON: pausing backend reads (queue=256)`

Result:
- the spinner still reproduced
- therefore generic queue depth is probably not the primary bottleneck

## What this analysis rules out

Fairly strongly ruled out:
- Vaultwarden backend as the primary root cause
- complete gateway/backend inability to deliver response data
- “page never started loading”
- architecture phases that were already completed incorrectly (router ingress, action callback, outbound utun drain)

Less strongly ruled out, but now less likely as primary explanation:
- generic browser stream fanout pressure
- generic gateway queue depth alone

## Best Current Root-Cause Hypothesis

The current best hypothesis is:

> The iOS hybrid Rust-fd browser path is failing to convert a small tail of final retransmitted packets into useful forward progress, even though the backend and gateway continue to function and most of the response has already been delivered.

In practical terms:
- one or more final browser resources/response tails are not being completed
- the gateway keeps retransmitting those tail packets
- iOS/browser side sees no new useful RX and/or only replay/no-progress
- the WKWebView spinner never clears
- session health eventually gives up and reconnects

## Why this matters

This shifts the main debugging target.

The next focus should no longer be:
- “Is Vaultwarden broken?”
- “Should we just tune queue_high again?”

The next focus should be:
- tail-packet completion and useful-RX accounting on the iOS side
- replay/highSeq behavior around final retransmits
- per-flow completion/cleanup around the last browser response chunks
- whether stream close / FIN / ACK completion is mishandled near the tail of the response

## Recommended Next Investigation

Next step should be a focused client-side/root-cause pass on:

1. how `useful RX` is marked on iOS
2. how `highSeq` advancement and replay accounting interact after large browser responses
3. how the Rust fd ingress path handles retransmitted tail packets
4. whether the last packets for a stream/resource are being surfaced correctly to the browser
5. whether a stream close / FIN / ACK edge case is preventing WKWebView from treating the resource as complete

## Suggested Working Hypothesis for Review

Short review version:

- Vaultwarden is not the main problem.
- The backend keeps sending large HTTP responses.
- The gateway forwards most of them.
- The iPhone/browser path successfully receives almost all of the page.
- Then a tiny tail of final packets stops becoming useful progress.
- Gateway retransmits that tail repeatedly.
- iOS reports replay/no-progress instead of finishing the flow.
- Session health reconnects, but the page spinner never resolves.

## Files / Components Most Relevant Next

iOS / tunnel:
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`
- Rust fd / router path:
  - `proto/src/ios_tunnel_engine.rs`
  - `proto/src/ffi.rs`
  - `proto/src/packet_router.rs`

Gateway:
- `gateway/lib/ztlp_gateway/session.ex`

## Status

This note reflects the current best evidence after:
- phone log correlation
- targeted gateway log correlation
- backend localhost tcpdump
- tunnel UDP tcpdump
- one deployed gateway backpressure/queue-shallowing experiment
