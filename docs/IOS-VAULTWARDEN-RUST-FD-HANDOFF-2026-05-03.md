# ZTLP iOS Vaultwarden / Rust-fd Handoff — 2026-05-03

## Current status summary

We are debugging iOS WKWebView/Vaultwarden partial page load / spinner behavior through ZTLP.

The latest architecture is Rust-fd mode:

- Swift `PacketTunnelProvider` configures the NE and starts Rust fd engine.
- Rust owns utun reads via `IosTunnelEngine`.
- Swift `packetFlow.readPackets` is disabled.
- Rust reads utun packets and feeds the existing `PacketRouter`.
- Rust dispatches router actions back to Swift via callback.
- Swift still sends mux frames over `ZTLPTunnelConnection` / NWConnection.

So this is not yet full Nebula-style native transport ownership, but it is a major step: Rust owns utun and now DNS.

Latest good server preflight:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

Latest known benchmark records:

```text
id=274 score=8/8 gw=44.246.33.34:23097
id=273 score=8/8 gw=44.246.33.34:23097
id=272 score=8/8 gw=44.246.33.34:23097
```

Vaultwarden backend is healthy and reachable on gateway:

```bash
ssh ubuntu@44.246.33.34 'curl -sS -m 3 -o /dev/null -w "vault_http=%{http_code}\n" http://127.0.0.1:8080/alive'
# vault_http=200
```

Current Vaultwarden `DOMAIN` is:

```text
DOMAIN=http://vault.techrockstars.ztlp
```

Verified `/api/config` advertises:

```json
{
  "environment": {
    "api": "http://vault.techrockstars.ztlp/api",
    "identity": "http://vault.techrockstars.ztlp/identity",
    "notifications": "http://vault.techrockstars.ztlp/notifications",
    "vault": "http://vault.techrockstars.ztlp"
  }
}
```

## Critical lessons from this session

### 1. WKWebView must be used, not SFSafariViewController

This remains true. SFSafariViewController runs out-of-process and does not use the app/NE split DNS correctly. WKWebView is the correct in-app browser.

### 2. When Rust owns utun, Swift DNS responder no longer works

Originally `ZTLPDNSResponder.swift` handled DNS queries in Swift before handing packets to the router.

But in Rust-fd mode:

```text
Swift packetFlow.readPackets disabled
Rust owns utun fd
```

So Swift never sees DNS queries. Logs showed DNS packets entering Rust as generic UDP:

```text
Rust fd ingress diag ... proto=17 flags=OTHER src=10.122.0.1:0 dst=10.122.0.1:0
```

This caused blank WKWebView when loading `vault.techrockstars.ztlp`, because no DNS answer was generated.

Fix implemented: Rust fd DNS responder in `proto/src/ios_tunnel_engine.rs`.

Current log marker proving it works:

```text
Rust fd dns responder wrote response bytes=70 packets=1 totals_bytes=70
```

### 3. Do not use raw VIP IP as the long-term browser origin

We temporarily fell back to `http://10.122.0.4`, but that causes origin/config mismatch unless Vaultwarden `DOMAIN` is also set to the VIP.

Long-term correct behavior is:

```text
WKWebView loads: http://vault.techrockstars.ztlp
Rust fd DNS resolves: vault.techrockstars.ztlp -> 10.122.0.4
Vaultwarden DOMAIN: http://vault.techrockstars.ztlp
```

This is the current intended state.

### 4. CloseStream suppression was too aggressive

The Rust fd dispatch path originally suppressed CloseStream if `ztlp_router_has_stream_sync(router, stream_id) != 1`.

That was wrong. `process_gateway_close` / router close handling can legitimately remove the local mapping before emitting the close action. Suppressing this leaked gateway streams and created browser churn/stalls.

Bad old log pattern:

```text
Rust fd dispatch post actions=0 open=0 send=0 close=0 suppressed_close=1 ...
```

Fix implemented in `proto/src/ios_tunnel_engine.rs`:

- Only suppress exact duplicate close for the same stream.
- Do not consult `router_has_stream_sync`.
- On OpenStream, remove stale close marker for that stream id.

After fix, logs showed real CloseStream actions:

```text
RouterAction send CloseStream stream=2 sent=true
RouterAction send CloseStream stream=5 sent=true
RouterAction send CloseStream stream=4 sent=true
...
Rust fd dispatch post actions=1 open=0 send=0 close=1 suppressed_close=0
```

And later router state cleared cleanly:

```text
Router stats: flows=0 outbound=0 stream_to_flow=0 next_stream_id=16 send_buf_bytes=0 send_buf_flows=0 oldest_ms=0 stale=0
```

### 5. Reconnect on probe-success/suspect-flows caused tunnelQueue wedge

Earlier we changed session health so that when a probe succeeded but flows were still suspect, we reset router state and scheduled reconnect to avoid stream id reuse.

That caused bad behavior:

```text
Session health probe ok but flows still suspect; router reset ... scheduling reconnect to avoid stream-id reuse
Reconnect gen=1 handshake wait timed out
Health eval delayed on tunnelQueue delay=18.9s
```

Fix implemented:

- If probe succeeds, gateway session is alive.
- Do not reset router state.
- Do not reconnect.
- Preserve live session and hold rwnd low.

New marker:

```text
Session health probe ok but flows still suspect; preserving live session ... no_router_reset no_reconnect
```

This marker appeared in later logs and avoided the reconnect storm.

## Current code changes made in this session

### Rust DNS responder and CloseStream fix

File:

```text
proto/src/ios_tunnel_engine.rs
```

Implemented:

- Intercept IPv4 UDP/53 queries to `10.122.0.1` before PacketRouter.
- Build DNS A responses directly in Rust.
- Write response to utun via `IosUtun::write_packet()`.
- DNS mappings:
  - `vault.*.ztlp` -> `10.122.0.4`
  - `http.ztlp` / `proxy.ztlp` -> `10.122.0.3`
  - other `*.ztlp` -> `10.122.0.2`
  - non-`.ztlp` valid DNS query -> NXDOMAIN
- Unit tests for DNS mappings.
- CloseStream suppression fixed as described above.

Test command:

```bash
cd /home/trs/ztlp/proto
cargo test ios_tunnel_engine --features ios-sync
```

Result:

```text
7 passed
```

Mac build command used:

```bash
ssh stevenprice@10.78.72.234 '
set -e
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
cd ~/ztlp/proto
cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib --target-dir target-ios-sync
cp target-ios-sync/aarch64-apple-ios/release/libztlp_proto.a ~/ztlp/ios/ZTLP/Libraries/libztlp_proto_ne.a
cd ~/ztlp/ios/ZTLP
xcodebuild -project ZTLP.xcodeproj -scheme ZTLP -destination "generic/platform=iOS" -configuration Debug build CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO 2>&1 | grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" | tail -80
'
```

Result:

```text
BUILD SUCCEEDED
```

### WKWebView URL handling

File:

```text
ios/ZTLP/ZTLP/Extensions/SafariHelper.swift
```

Current intended behavior:

- Keep `.ztlp` hostname.
- Force HTTP for now.
- Do not rewrite to raw VIP IP.

Current `toVIPURL` intent:

```swift
// input:  https://vault.techrockstars.ztlp
// output: http://vault.techrockstars.ztlp
```

Reason:

- Browser origin/Host must match Vaultwarden `DOMAIN`.
- We do not yet have iOS local TLS termination/certs.
- Rust fd DNS now resolves the hostname.

### ATS exception / browser failure logging

File:

```text
ios/ZTLP/ZTLP/Resources/Info.plist
```

Added:

```text
NSAllowsArbitraryLoadsInWebContent = true
NSExceptionDomains.vault.techrockstars.ztlp.NSExceptionAllowsInsecureHTTPLoads = true
```

File:

```text
ios/ZTLP/ZTLP/Extensions/SafariHelper.swift
```

Added WKWebView failure logging to app-group `ztlp.log`:

```text
WKWebView provisional failed ... domain=... code=... error=...
WKWebView navigation failed ... domain=... code=... error=...
```

So future blank pages should produce actual browser errors in logs.

### Health/reconnect fix

File:

```text
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
```

Changed `handleProbeSuccess(nonce:)`:

- Do not reset router and reconnect on probe-success/suspect-flows.
- Hold rwnd and preserve live session.

Changed reconnect scheduling:

- Delay timer uses `healthQueue.asyncAfter`, only hops to `tunnelQueue` at actual reconnect.
- This avoids piling delayed reconnect timers behind data-plane work.

### rwnd=16 experiment

Files:

```text
ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift
ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift
```

Steve asked to try `rwnd=16`.

Changed:

```swift
private static let rwndAdaptiveMax: UInt16 = 16
private static let rwndBrowserBurstTarget: UInt16 = 16
```

and ACK clamp:

```swift
advertisedReceiveWindow = min(max(rwnd, 4), 16)
```

Expected gateway marker during browser burst:

```text
CLIENT_ACK ... rwnd=16
```

Need to validate whether this helps or worsens browser tail.

## Current observed behavior after DNS + CloseStream fixes

### Good signs

Rust DNS works:

```text
Rust fd dns responder wrote response bytes=70 packets=1 totals_bytes=70
```

WKWebView opens multiple TCP flows to Vaultwarden:

```text
src=10.122.0.1:51317 dst=10.122.0.4:80
src=10.122.0.1:51318 dst=10.122.0.4:80
...
```

Router sends opens:

```text
RouterAction send OpenStream stream=1 serviceBytes=5 sent=true
...
```

Router sends close streams now:

```text
RouterAction send CloseStream stream=2 sent=true
RouterAction send CloseStream stream=5 sent=true
...
```

State can drain fully:

```text
Router stats: flows=0 outbound=0 stream_to_flow=0 next_stream_id=16 send_buf_bytes=0 send_buf_flows=0 oldest_ms=0 stale=0
```

Benchmarks pass:

```text
Benchmark upload complete: HTTP 201 score=8/8 benchmark_id=274
```

### Remaining bad signs

The page still may not load fully.

When trying Vaultwarden, logs show repeated browser burst/churn:

```text
flows=5 streamMaps=5
Advertised rwnd=4 reason=pressure outbound=0 sendBuf=0 oldestMs=5569 replayDelta=0
Mux summary gwData=56/40880B open=0 close=0 send=0/0B
...
RouterAction send CloseStream stream=2 sent=true
RouterAction send CloseStream stream=5 sent=true
...
RouterAction send OpenStream stream=6 serviceBytes=5 sent=true
```

After CloseStream fix, old 7-flow stuck state improved, but page may still be slow/partial. Current likely bottleneck is too-small rwnd / slow tail under browser asset burst.

Steve requested `rwnd=16` to test. That has been patched and built; next session should validate logs after deploy.

## Commands to pull logs

### Pull phone log

```bash
ssh stevenprice@10.78.72.234 'rm -f /tmp/ztlp-phone.log; xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log && \
  wc -l /tmp/ztlp-phone.log && \
  grep -E "Rust fd dns|DNS|WKWebView|Browser|vault.techrockstars|10.122.0.4|Mux summary|Router stats|Health eval|Session health|Advertised rwnd|replay|Reconnect|VPN status|Rust fd outbound|Rust fd ingress|RouterAction|CloseStream|suppressed_close|Benchmark" /tmp/ztlp-phone.log | tail -600'
```

### Gateway logs around a test window

```bash
ssh ubuntu@44.246.33.34 'docker logs --since "2026-05-03T01:05:50" --until "2026-05-03T01:06:40" ztlp-gateway 2>&1 | \
  grep -E "FRAME_OPEN|FRAME_CLOSE|CLIENT_ACK|pacing_tick|Backpressure|RTO|STALL|vault|queue=|streams=|unknown_session" | tail -400'
```

### Vaultwarden health/config

```bash
ssh ubuntu@44.246.33.34 'curl -sS -m 3 -o /dev/null -w "vault_http=%{http_code}\n" http://127.0.0.1:8080/alive && \
  curl -sS -m 5 http://127.0.0.1:8080/api/config | python3 -m json.tool | sed -n "1,14p"'
```

### Preflight

```bash
/home/trs/ztlp/scripts/ztlp-server-preflight.sh
```

Must end:

```text
PRECHECK GREEN server-side stack is ready for phone testing
```

## Current server state

Gateway:

```text
host: 44.246.33.34
container: ztlp-gateway
image: ztlp-gateway:vault-shallow128
```

Gateway backend env:

```text
ZTLP_GATEWAY_BACKENDS=default:127.0.0.1:8080,http:127.0.0.1:8180,vault:127.0.0.1:8080
```

Vaultwarden:

```text
container: vaultwarden
image: vaultwarden/server:latest
bind: 127.0.0.1:8080 -> 80/tcp
DOMAIN=http://vault.techrockstars.ztlp
WEBSOCKET_ENABLED=true
SIGNUPS_ALLOWED=true
```

Relay:

```text
host: 34.219.64.205
container: ztlp-relay
```

NS:

```text
host: 34.217.62.46
container: ztlp-ns
port: 23096/udp
```

## Mac / iPhone build facts

Mac:

```text
stevenprice@10.78.72.234
Xcode repo: ~/ztlp
Do not use ~/code/ztlp for iOS builds.
```

Phone UDID:

```text
39659E7B-0554-518C-94B1-094391466C12
```

Build facts:

- ZTLPTunnel links `libztlp_proto_ne.a`.
- NE lib must be built with:

```bash
cargo build --release --target aarch64-apple-ios --no-default-features --features ios-sync --lib --target-dir target-ios-sync
```

- After rebuilding static lib, Xcode Clean Build Folder is required before device deploy.
- SSH unsigned Xcode build can validate compile, but actual device deploy requires Xcode GUI.

## Next session recommended first steps

1. Ask Steve whether he deployed the rwnd=16 build.
2. If yes, pull phone logs and gateway logs.
3. Verify gateway sees:

```text
CLIENT_ACK ... rwnd=16
```

4. Compare outcomes:

Good:

```text
highSeq keeps advancing
flows drain to 0
no STALL
no RTO storm
no VPN 5 -> 1
Vaultwarden page completes
```

Bad:

```text
replayDelta > 0
RTO retransmit storm
queue grows above shallow limits
VPN drops
flows stuck nonzero with no useful RX
```

5. If rwnd=16 improves, keep it and tune pressure policy so it only drops to 4 on actual replay/no useful RX, not just oldestMs.
6. If rwnd=16 worsens, revert to 8 or test 12.

## Important interpretation notes

- `memory_ok=false` in benchmark is not important here. NE memory around ~18-21MB is not an iOS kill by itself.
- Server preflight can be RED for stale econnrefused lines after restarting Vaultwarden. Confirm current Vaultwarden health with curl before overreacting.
- Do not restart gateway/relay/NS without warning Steve first. Restarting gateway kills active iOS benchmark sessions.
- Vaultwarden backend has been repeatedly verified healthy. If page spins, focus on iOS/gateway transport/browser flow, not Vaultwarden availability.

## Current hypothesis

The current remaining issue is browser-tail pacing / connection churn, not basic connectivity.

We fixed:

- Rust-fd DNS
- stale CloseStream suppression
- bad reconnect on probe-success
- Vaultwarden DOMAIN/origin mismatch

The next unknown is whether a larger receive window (`rwnd=16`) lets the Vaultwarden asset tail finish quickly enough without reintroducing replay/RTO or gateway queue growth.
