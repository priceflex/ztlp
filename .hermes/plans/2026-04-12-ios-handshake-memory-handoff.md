# ZTLP iOS handoff — 2026-04-12

## What was fixed

Root cause confirmed by Steve:
- Noise handshake and post-handshake data were using different UDP source ports
- relay learned peer_a from handshake socket port X
- Swift NWConnection used a new port Y for data
- outbound worked via relay session-ID fallback
- inbound failed because gateway responses were forwarded to stale peer_a=X

Implemented fix:
- handshake now runs on the same Swift NWConnection used for data
- one socket, one port

## Commits

Pushed to GitHub:
- `57698e0` — `fix: handshake over nwconnection for iOS tunnel`

Local-only on Linux repo unless cherry-picked on Mac:
- `465e552` — `fix: report NE memory in benchmark uploads`

## Files changed for same-socket handshake fix

Rust / headers:
- `proto/src/ffi.rs`
- `proto/include/ztlp.h`
- `ios/ZTLP/Libraries/ztlp.h`

Swift:
- `ios/ZTLP/ZTLPTunnel/ZTLPTunnelConnection.swift`
- `ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift`

## What the handshake fix added

New FFI API in `ffi.rs`:
- `ztlp_handshake_start`
- `ztlp_handshake_process_msg2`
- `ztlp_handshake_finalize`
- `ztlp_handshake_free`

Swift changes:
- `ZTLPTunnelConnection` supports pre-handshake mode with optional crypto context
- `performHandshake(...)` drives msg1/msg2/msg3 over the NWConnection itself
- receive loop starts only after handshake finalizes
- fixed deadlock by moving NWConnection callbacks to dedicated `nwQueue`

## Verified results after fix

Phone logs showed the old root cause is fixed:
- `Connecting to ... using NWConnection handshake...`
- `Connected to ... via relay ...`
- `TUNNEL ACTIVE`
- `ZTLP RX data seq=0 ...`
- repeated `ZTLP ACK sent seq=...`

This proves:
- inbound path is now working
- ACK path is now working
- same-socket handshake/data fix solved the stale-port return-path bug

## Benchmark status observed

Earlier successful runs from phone log:
- `8/8` all_passed=true
- `4/4` all_passed=true

Latest run regressed:
- bootstrap benchmark id `20`
- score `6/8`
- `memory_ok=false`

## Important current blocker

Latest phone log shows mid-run decrypt failures:
- `ZTLP decrypt failed rc=-99 wire=159`
- `ZTLP decrypt failed rc=-99 wire=76`

These appear after successful RX/ACK activity and likely explain the `6/8` regression.

This is the next debugging target.

## Memory reporting situation

A follow-up patch was created to report actual NE memory in benchmark uploads:
- store NE memory snapshot in app-group defaults from `PacketTunnelProvider.swift`
- read those values in app `BenchmarkView.swift`
- include them in `BenchmarkReporter.shared.submit(...)`

That patch exists in local Linux repo as:
- `465e552` — `fix: report NE memory in benchmark uploads`

But bootstrap shows latest uploaded benchmark still had:
- `ne_memory_mb=nil`
- `ne_virtual_mb=nil`
- `relay_address=nil`
- `gateway_address=nil`

So the memory-reporting patch was NOT actually present in the app build that produced benchmark 20.

## Bootstrap facts

Bootstrap reachable via SSH:
- host: `10.69.95.12`
- user: `trs`

Actual repo path on server:
- `~/.openclaw/workspace/ztlp`

Bootstrap app path:
- `~/.openclaw/workspace/ztlp/bootstrap`

Working command used:
```bash
ssh trs@10.69.95.12 'cd ~/.openclaw/workspace/ztlp/bootstrap && docker-compose exec -T web bin/rails runner "b=BenchmarkResult.order(created_at: :desc).first; if b; puts({id: b.id, created_at: b.created_at, score: \"#{b.benchmarks_passed}/#{b.benchmarks_total}\", memory_ok: b.memory_ok?, ne_memory_mb: b.ne_memory_mb, ne_virtual_mb: b.ne_virtual_mb, ne_memory_pass: b.ne_memory_pass, relay_address: b.relay_address, gateway_address: b.gateway_address, device_id: b.device_id, node_id: b.node_id}.inspect); puts \"---LOGS---\"; puts b.device_logs.to_s.lines.last(220).join; else puts \"NO_BENCHMARKS\"; end"'
```

Latest bootstrap record:
```ruby
{:id=>20, :score=>"6/8", :memory_ok=>false, :ne_memory_mb=>nil, :ne_virtual_mb=>nil, :ne_memory_pass=>false, :relay_address=>nil, :gateway_address=>nil}
```

## What to do first next session

1. Verify whether commit `465e552` is on Steve's Mac repo
```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git log --oneline -10 && git show --stat 465e552'
```

2. If not present, apply it on Mac
```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git cherry-pick 465e552'
```

3. Rebuild BOTH targets in Xcode
- clean build folder
- rebuild app target AND tunnel extension

Why both matter:
- `BenchmarkView.swift` is in main app
- `PacketTunnelProvider.swift` is in extension
- both must be current for memory fields to show in uploads

4. Run benchmark again

5. Pull:
- device log from phone
- latest bootstrap benchmark record

Confirm whether uploaded fields now contain real values:
- `ne_memory_mb`
- `ne_virtual_mb`
- `relay_address`
- `gateway_address`

## If memory reporting is deployed and benchmark still fails

Then focus on decrypt failure investigation.

Likely next checks:
- inspect packet types / frame formats corresponding to wire sizes `159` and `76`
- determine whether these are legitimate encrypted packets or unexpected plaintext/control packets
- compare with gateway/relay-side behavior around the same timestamps
- inspect `ztlp_decrypt_packet` return path in `ffi.rs`
- inspect any path sending unencrypted relay-side control/VIP frames into the encrypted tunnel receive path

## Useful commands

Pull phone log:
```bash
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from --device 39659E7B-0554-518C-94B1-094391466C12 --domain-type appGroupDataContainer --domain-identifier group.com.ztlp.shared --source ztlp.log --destination /tmp/ztlp-latest.log && tail -n 260 /tmp/ztlp-latest.log'
```

Check Mac repo state:
```bash
ssh stevenprice@10.78.72.234 'cd ~/ztlp && git log --oneline -10'
```

## Bottom line

- original relay response bug is fixed
- same-socket handshake/data architecture is working
- current open problems are:
  1. memory-reporting patch not yet confirmed deployed in benchmark app build
  2. real benchmark regression to `6/8`
  3. mid-run decrypt failures `rc=-99` on wire sizes `159` and `76`
