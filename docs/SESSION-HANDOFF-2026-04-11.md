# ZTLP iOS Relay-Side VIP — Session Handoff

## What Was Built This Session

### 1. Elixir Relay VIP TCP Termination (5 new modules)
Deployed on relay server `34.219.64.205` (running as Docker container `ztlp-relay:vip`):
- `vip_frame.ex` — VIP mux frame parsing/encoding (connection_id, SYN/DATA/FIN/RST flags)
- `vip_service_table.ex` — ETS-backed service routing (service name → backend IP:port)
- `vip_connection.ex` — Per-TCP-connection GenServer (backend connect, proxy, encrypt responses)
- `vip_tcp_terminator.ex` — Main dispatcher (decrypt → parse → dispatch → metrics)
- `vip_frame_test.exs` — 14 tests (all pass)
- Modified: `udp_listener.ex` (VIP intercept path), `config.ex`, `application.ex`, `stats.ex`, `mix.exs`
- Config: VIP enabled, services `vault=127.0.0.1:8080,web=127.0.0.1:80,api=127.0.0.1:8443`, TLS disabled
- VIP session key (save this!): `5afd5bedb356e144bd9744baf64b3c27df825feeda01c19d925c0782198b6dad`

### 2. Swift NE Changes (PacketTunnelProvider.swift)
- Removed ZTLPVIPProxy.swift NWListeners (wrapped in `DISABLED_ZTLPVIPPROXY` conditional compilation)
- Added relay discovery: NS query → RelayPool → select best relay
- Added relay failover: detect failure → report to pool → reselect → reconnect
- Fixed optional unwrap errors (lines 792-793)
- Connects through selected relay instead of gateway directly

### 3. iOS Build System
- **Two separate libraries required:**
  - `libztlp_proto.a` (48MB, default features with tokio) → main app target
  - `libztlp_proto_ne.a` (25MB, `--no-default-features --features ios-sync`) → tunnel target
- Build commands documented in `ios/BUILD-GUIDE.md`
- Must use separate `--target-dir` for ios-sync to avoid cargo cache collision

### 4. NS Relay Records
- Added `new_relay_rich/4` to `ns/lib/ztlp_ns/record.ex` — produces CBOR with address, region, latency_ms, load_pct, active_connections, health
- Added `RelaySeeder` module — seeds RELAY records from `ZTLP_NS_RELAY_RECORDS` env var on startup
- Added 14 RELAY records to production NS (34.217.62.46:23096) for `relay1`, `relay2`, `techrockstories`, etc.
- ⚠️ Records have empty signatures — `Record.verify()` fails. Query handler returns nothing even though records exist. **This is the blocker.**

### 5. Benchmark Reporting API
- Bootstrap server endpoint: `POST /api/benchmarks`, authentication via Bearer token (enrollment secret)
- `Benchmark` model with migration
- `BenchmarkReporter.swift` in iOS main app — sends memory, per-benchmark results, latency, throughput, errors
- Route added to `bootstrap/config/routes.rb`

## Production Server Status

| Server | IP | Status | Notes |
|--------|-----|--------|-------|
| NS | 34.217.62.46 | Running | Has 14 RELAY records but unsigned — queries return 0 results |
| Relay | 34.219.64.205 | Running | VIP module deployed and enabled, healthy |
| Gateway | 44.246.33.34 | Running | Standard forwarding |
| Bootstrap | 10.69.95.12:3000 | Unreachable from cloud VM | Benchmark API deployed but migration needs to run |

## SSH Access
- **NS/Relay/Gateway**: `ssh -i /home/trs/.ssh/id_rsa ubuntu@<ip>`
- **Mac**: `ssh stevenprice@10.78.72.234` (default key, not openclaw)
- **Bootstrap**: `10.69.95.12` — local network only, unreachable from cloud VM

## Current Blockers
1. **NS relay records are unsigned** — Store.insert() requires valid signatures. Records exist in Mnesia but `Record.verify()` fails, so NS query handler returns no relay records. Need to sign them with a zone authority key.
2. **NE memory at 18.4MB** — Still too high (limit 15MB, target 10-13MB). VIP proxy removed, but memory not dropping yet. Likely the NS sync code paths or residual Swift objects adding ~5MB.
3. **Bootstrap migration not run** — `rails db:migrate` needs to run in the bootstrap Docker container to create the `benchmarks` table.

## iOS Device Info
- Device UUID: `39659E7B-0554-518C-94B1-094391466C12`
- App builds clean, deploys successfully
- NE runs (v5D-SYNC), tunnel connects through relay
- NS relay discovery returns 0 records (unsigned records issue)
- Logs at: App Group `group.com.ztlp.shared` → `ztlp.log`

## Key File Paths
```
ztlp/relay/lib/ztlp_relay/vip_*.ex          — VIP modules
ztlp/proto/src/ffi.rs                        — FFI (relay pool, NS sync, crypto)
ztlp/ios/ZTLP/ZTLPTunnel/PacketTunnelProvider.swift — NE with relay selection
ztlp/ns/lib/ztlp_ns/record.ex                — new_relay_rich/4
ztlp/ns/lib/ztlp_ns/relay_seeder.ex          — NS startup relay seeding
ztlp/bootstrap/app/controllers/api/benchmarks_controller.rb
ztlp/ios/ZTLP/ZTLP/Services/BenchmarkReporter.swift
ztlp/ios/BUILD-GUIDE.md                      — Two-library build instructions
```

## Next Steps Priority
1. **Sign NS relay records** — Find zone authority key on NS server, sign records properly so `Record.verify()` passes
2. **Profile NE memory** — Determine why 18.4MB instead of 10-13MB after VIP removal
3. **Run bootstrap migration** — `docker compose exec web rails db:migrate`
4. **Test benchmark reporter** — curl POST to /api/benchmarks, then test from iOS

## Git State
- All committed and pushed to `origin/main` (commit `e632e32`)
- 30 files changed across this session
- Latest commits:
  - `e632e32` — iOS BenchmarkReporter
  - `d560621` — Benchmark API endpoint + migration
  - `c9c225d` — Fix Swift optional unwrap errors
  - `1310eee` — Warning fixes for relay VIP build
  - `b12e70f` — NS relay seeder + docker-compose VIP config
  - `e8a10d2` — Elixir VIP TCP termination + Swift NE changes
