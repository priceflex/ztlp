# Phase B & C: Diagnose and Fix the 1 MiB Stall Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Modify the Elixir Gateway's Session layer (`lib/ztlp_gateway/session.ex`) to handle `dumb-pipe` clients (that do not send ACKs) reliably at high throughput. The initial bypass of `cwnd` allows transfers but results in total network collapse (UDP packet loss) due to unbounded send rates. We need to implement proper rate limiting or restore a lightweight ACK mechanism.

**Architecture:** The client (`ztlp connect` path) acts as a pure datagram proxy and sends NO ZTLP ACKs. The Gateway currently tries to buffer and re-transmit, but if we bypass `cwnd`, it shoots thousands of packets (`inflight=14341`) causing OS UDP buffer overflow in the relay/client. We need pace the fire-and-forget logic correctly (e.g. strict pacing delays or token bucket) when `mux_mode == false`.

**Tech Stack:** Elixir Gateway

---

### Task 1: Re-evaluate "Dumb Pipe" Rate Limiting

**Objective:** Since we cannot rely on ACKs to pace the sliding window in legacy/dumb-pipe mode, we must enforce a strict token-bucket or fixed pacing interval in `session.ex` to prevent UDP buffer overflow on the relay/client.

**Files:**
- Modify: `gateway/lib/ztlp_gateway/session.ex`

**Step 1: Locate `flush_send_queue` and the `legacy_bypass` logic installed previously**

In `flush_send_queue/2`:
```elixir
    legacy_bypass = not state.mux_mode
    effective_window = min(min(trunc(state.cwnd), cc_max_cwnd(state)), Map.get(state, :peer_rwnd, @default_peer_rwnd))
    window_full = not legacy_bypass and inflight >= effective_window
```

**Step 2: Modify pacing logic for legacy clients**

Currently, when `window_full` is false, it continuously loops `encrypt_and_send` until the `send_queue` is empty or the `remaining_burst` reaches 0. In legacy mode, it immediately drains the entire queue into the UDP socket.

Update the logic so that `legacy_bypass` still triggers `schedule_pacing_timer/1` but limits the `remaining_burst` or forces a hard cap on packets sent per tick.

Example adjustment inside `flush_send_queue/2` or `handle_info(:pacing_tick, state)`:
```elixir
    # Limit legacy burst to something safe for UDP (e.g., 32-64 pkts/tick)
    burst = if legacy_bypass, do: min(remaining_burst, 32), else: remaining_burst
```

### Task 2: Fix Stall Timeout for Legacy Sessions

**Objective:** The session stall detector (`check_stall`) tears down sessions if `last_acked_data_seq` hasn't progressed in 30 seconds. In legacy mode, `last_acked_data_seq` NEVER progresses.

**Files:**
- Modify: `gateway/lib/ztlp_gateway/session.ex`

**Step 1: Update `check_stall/1` to ignore ACK stalls in legacy mode**

```elixir
  defp check_stall(state) do
    # ... existing stall detection
    is_stalled = (state.phase == :established) and
                 state.mux_mode and # <-- ADD THIS
                 (now - state.last_acked_time >= @stall_timeout_ms) and ...
```

### Task 3: Test and Deploy Gateway `v4`

**Objective:** Compile the modified Elixir Gateway and deploy it to the AWS testbed.

**Files:**
- Test execution on: `54.190.82.255`

**Step 1: Commit and push changes**
```bash
git add gateway/lib/ztlp_gateway/session.ex
git commit -m "fix(gateway): enforce pacing and disable stall detector for legacy clients"
GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw" git push origin main
```

**Step 2: Build and deploy on Gateway Host**
```bash
ssh ubuntu@54.190.82.255 "cd /tmp/ztlp-build && git pull origin main && docker build -t ztlp-gateway:bench-2026-05-17.v4 -f gateway/Dockerfile ."
ssh ubuntu@54.190.82.255 "docker stop ztlp-gateway && docker rm ztlp-gateway && docker run -d --name ztlp-gateway --network host --restart unless-stopped -e ZTLP_RELAY_SERVER=172.26.15.55:23095 -e ZTLP_GATEWAY_BACKENDS=default:127.0.0.1:8080,http:127.0.0.1:8180,vault:127.0.0.1:8080,echo:127.0.0.1:7777 -e ZTLP_GATEWAY_PORT=23097 -e ZTLP_GATEWAY_SERVICE_NAMES=default,http,vault,echo -e ZTLP_GATEWAY_POLICIES=*:default,*:http,*:vault,*:echo -e ZTLP_LOG_LEVEL=debug -e ZTLP_LOG_FORMAT=json -e ZTLP_NS_SERVER=18.236.150.73:23096 ztlp-gateway:bench-2026-05-17.v4"
```

### Task 4: Verify Multi-stream Reliability (10 MB/4 streams)

**Objective:** Confirm that the pacing prevents UDP dropping and `curl` fetches all streams correctly.

**Step 1: Run Multi-stream Bench**
```bash
python3 bench/run_fullstack_multistream.py --size 10485760 --ns 4
```
Expected: `stalled=0` and non-zero aggregate `MB/s`.

