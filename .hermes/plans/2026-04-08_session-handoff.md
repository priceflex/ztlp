# ZTLP Session Handoff — 2026-04-08

## What Was Achieved
- **11/11 benchmark** achieved with Phase 1 CC tuning + echo server fix
- Then regressed to **5/11** after adding NACK-on-duplicate + max_rto_ms change

## Current Deployed State

### Gateway (ubuntu@54.149.48.6)
- Container: `ztlp-gateway:phase1-rto-fix`
- CC params: loss_beta=0.7, max_cwnd=32, min_cwnd=4, ssthresh=64, burst=3, pacing=4ms, stall=30s
- **max_rto_ms=5000** ← this is NEW and may be causing the regression
- Previous working container was `ztlp-gateway:phase1-cc` with max_rto_ms=30000

### iOS Library (on Steve's Mac)
- Built with NACK-on-duplicate change in ffi.rs
- **This change may also be causing the regression** — NACK every 100ms during dup storms
  could be flooding the gateway or interfering with the normal recovery flow

### Echo Server (gateway 54.149.48.6)
- `/opt/ztlp/http-echo.py` — POST /echo raw-echoes body, POST /upload returns JSON
- Running as background process (not systemd). Restart: `sudo pkill -f http-echo; nohup python3 /opt/ztlp/http-echo.py &`

## What Needs To Happen Next

### Priority 1: Rollback to 11/11 state
Two changes were made between 11/11 and 5/11. Need to isolate which caused regression:

**Option A — Rollback both:**
1. Gateway: redeploy `ztlp-gateway:phase1-cc` (the 11/11 container)
   ```
   ssh ubuntu@54.149.48.6 "docker stop ztlp-gateway && docker rm ztlp-gateway && \
   docker run -d --name ztlp-gateway --restart unless-stopped --network host \
     -e ZTLP_GATEWAY_PORT=23097 -e ZTLP_LOG_FORMAT=json -e ZTLP_LOG_LEVEL=info \
     -e 'ZTLP_GATEWAY_SERVICE_NAMES=default,web,ssh,http,vault,metrics,echo' \
     -e ZTLP_RELAY_SERVER=34.219.64.205:23095 \
     -e ZTLP_GATEWAY_MAX_SESSIONS=10000 \
     -e ZTLP_GATEWAY_METRICS_ENABLED=true -e ZTLP_GATEWAY_METRICS_PORT=9102 \
     -e 'ZTLP_GATEWAY_POLICIES=*:default,*:web,*:ssh,*:http,*:vault,*:metrics,*:echo' \
     -e 'ZTLP_GATEWAY_BACKENDS=default:127.0.0.1:8180,web:127.0.0.1:8180,http:127.0.0.1:8180,echo:127.0.0.1:8180' \
     ztlp-gateway:phase1-cc"
   ```
2. iOS: revert ffi.rs NACK-on-duplicate change, rebuild
   - `git diff HEAD~1 proto/src/ffi.rs` to see the change
   - Revert just the NACK block, keep everything else

**Option B — Test each independently:**
1. First rollback just the gateway (max_rto back to 30s), keep iOS NACK change → test
2. If still broken, also rollback iOS NACK change → test
3. This identifies which change caused the regression

### Priority 2: Fix the retransmit hole properly
The retransmit hole bug (gateway retransmits packets client already has) still exists at 11/11.
The TTFB test passed with 1/1 iteration after waiting ~70s through a stall. For reliability:

**Root cause**: Gateway RTO retransmit picks oldest `packet_seq` entries, not the ones the
client actually needs. Client ACKs arrive but don't clear the right packets fast enough,
or don't arrive at all (NWConnection separate socket may be unreliable).

**Better fix ideas** (instead of NACK-on-duplicate):
- Make gateway's RTO retransmit aware of cumulative ACK: if client ACKs data_seq=X,
  only retransmit packets with data_seq > X (don't retransmit already-acked ones)
- Sort retransmit by data_seq not packet_seq
- Process ACK before retransmit in the same timer tick

### Priority 3: VPN NE memory (20.5MB, limit 15MB)
Separate from benchmark (benchmark uses in-process connection). But causes noisy warnings.
Key unbounded buffers identified:
- PacketRouter.outbound (VecDeque, no cap)
- TcpFlow.send_buf (no cap)  
- SendController.priority_buffer (no cap)
- transport.recv_raw() allocs vec![0u8;65535] per call

## Key Files
- Gateway CC: `gateway/lib/ztlp_gateway/session.ex` (~line 430-490)
- Client recv loop: `proto/src/ffi.rs` (~line 1529-1580 for dup handling)
- TUNING-LOG: `TUNING-LOG.md`
- Plan: `.hermes/plans/2026-04-08_025000-ztlp-11-of-11-benchmark-plan.md`
- iOS logs: `scripts/pull-ios-logs.sh`
- Echo server: deployed at `/opt/ztlp/http-echo.py` on gateway (not in repo)

## Skills to Load
```
skill_view("ztlp-ios-speed-fix")
```
Has full context including all pitfalls, build commands, server access, CC tuning history.

## Docker Images Available on Gateway
- `ztlp-gateway:phase1-cc` — **11/11 working** (max_rto=30s, no NACK fix)
- `ztlp-gateway:phase1-rto-fix` — 5/11 regression (max_rto=5s)
