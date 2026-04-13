# ZTLP Follow-up Session Notes
## Date: 2026-04-12

## Current State
We completed deploys for the replay-reject / mobile-RTO / benchmark telemetry work.

Live deploy status at pause point:
- Gateway deployed on `44.246.33.34` with commit `0def454` / follow-up repo fix `fd9db4a`
- Bootstrap rebuilt/restarted on `10.69.95.12`
- Bootstrap DB migrated with `replay_reject_count`
- Steve's Mac pulled latest and rebuilt iOS libs

## What worked
### Phase 1 succeeded
- Replay rejects are no longer misclassified as generic decrypt failures
- iOS now logs replay rejects at DEBUG level
- Benchmark upload includes `replay_reject_count`
- Bootstrap persists `replay_reject_count`

### Phase 3 succeeded
- Gateway ACK latency logging is live
- Example ACK latency during healthy portion of run: ~35-42ms

## Latest benchmark evidence
### Bootstrap latest row
- `benchmark_id`: 22
- `score`: `6/8`
- `ne_memory_mb`: `31`
- `replay_reject_count`: `384`
- `gateway`: `44.246.33.34:23097`

### Failing tests
- `Vault HTTP Response` → `No response`
- `Primary HTTP Response` → `No response`

### Phone log findings
- Replays are now visible as debug lines, not fake decrypt failures
- Replay count climbed to ~384 during the run
- Memory warning still severe:
  - resident ~30.8MB
  - uploaded `ne_memory_mb = 31`

### Gateway findings
- Session eventually died with:
  - `STALL: no ACK advance for 30s inflight=32 last_acked=365 ... recovery=true`
- Gateway still produced large retransmit storms later in the run
- Example repeated retransmits:
  - `RTO retransmit data_seq=366..397`
  - attempts 7 through 12
  - RTO capped at 5000ms

## Critical root cause still remaining
The mobile-aware RTO deploy is live, but the benchmark session is NOT getting the higher mobile RTO profile.

Observed gateway log line:
- `ClientProfile: class=mobile iface=unknown radio=nil → ... rto=300/min=100`

This means:
- the client is advertising `client_class=mobile`
- but `interface_type=unknown`
- gateway profile selection therefore falls into the default/mobile-wifi-style path
- result: still starts at `initial_rto=300`, `min_rto=100`

So the main remaining issue is:
- benchmark transport is not tagging the path as `cellular`, OR
- gateway should treat `mobile + unknown` as high-latency/mobile-safe for RTO purposes

## Recommended next fix
Fastest next step:
- Change gateway profile selection so ANY `client_class = mobile` gets safer mobile RTO values even when `interface_type = unknown`

Recommended minimum:
- `initial_rto_ms = 1500`
- `min_rto_ms = 500`

Possible policy choices:
1. safest quick fix:
   - all `mobile` clients get `1500/500`
2. narrower fix:
   - keep current cellular branch, but make `mobile + unknown` also use `1500/500`
3. more conservative:
   - mobile unknown gets intermediate values (e.g. `1000/300`)

Based on the logs from this session, option 2 or 1 is justified.

## Secondary issue still open
Network Extension memory remains far above target:
- current observed resident memory: ~31MB
- target: <= 15MB-ish

This is separate from the replay/RTO diagnosis and still needs dedicated follow-up.

## Useful commands from this session
### Pull latest phone log
```bash
ssh stevenprice@10.78.72.234 'xcrun devicectl device copy from \
  --device 39659E7B-0554-518C-94B1-094391466C12 \
  --domain-type appGroupDataContainer \
  --domain-identifier group.com.ztlp.shared \
  --source ztlp.log --destination /tmp/ztlp-phone.log >/dev/null 2>&1 && tail -n 160 /tmp/ztlp-phone.log'
```

### Gateway log slice
```bash
ssh ubuntu@44.246.33.34 'docker logs --since 15m ztlp-gateway 2>&1 | egrep "ClientProfile|ACK_LATENCY|CLIENT_ACK|RTO retransmit|STALL|replay|decrypt|data_seq" | tail -n 200'
```

### Inspect latest benchmark row
```bash
cat >/tmp/benchmark_latest.rb <<'RUBY'
b = BenchmarkResult.order(created_at: :desc).first
if b
  puts({
    id: b.id,
    created_at: b.created_at,
    score: "#{b.benchmarks_passed}/#{b.benchmarks_total}",
    ne_memory_mb: b.ne_memory_mb,
    replay_reject_count: b.replay_reject_count,
    relay: b.relay_address,
    gateway: b.gateway_address,
    errors: b.error_details
  }.inspect)
  puts b.individual_results.inspect
else
  puts :none
end
RUBY
scp /tmp/benchmark_latest.rb trs@10.69.95.12:/tmp/benchmark_latest.rb && \
ssh trs@10.69.95.12 'docker cp /tmp/benchmark_latest.rb bootstrap_web_1:/tmp/benchmark_latest.rb && docker exec bootstrap_web_1 bash -lc "cd /rails && bin/rails runner /tmp/benchmark_latest.rb RAILS_ENV=production"'
```

## Suggested next-session opening prompt
"Continue from `/home/trs/ztlp/.hermes/plans/2026-04-12-followup-mobile-rto-session.md` and implement the gateway fix so mobile+unknown gets mobile-safe RTO, then redeploy gateway and verify replay count drops."
