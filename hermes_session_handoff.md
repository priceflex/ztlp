# Hermes Session Handoff (Finalized 2026-05-17)

## 1. Project Goal
- **Primary Objective:** Fix the 90-second hard stalls occurring during high-throughput full-stack benchmarks of the ZTLP protocol on the AWS testbed.
- **Business/Technical Reason:** The Rust client generates proper `FRAME_ACK_V2` flow-control packets, but the Elixir Gateway backend was failing to process them correctly or honor the sliding window, causing catastrophic throughput drops (0 MB/s) on long transfers. We need robust, fast TCP-like flow control over UDP for the ZTLP tunnel.
- **Success Criteria:** `python3 run_fullstack_multistream.py --size 10485760 --ns 1` (10 MB payload) completes successfully without hitting a `curl (28) timeout`. Target throughput is >200 MB/s.
- **Long-term Vision:** Reliable, high-bandwidth multiplexed transmission over UDP that naturally backs off on constrained networks (mobile) and quickly scales on robust links (desktop/server).

## 2. Current Progress
- **What has already been completed:**
  1. **Deployment Loop:** Established a reliable hot-swap deployment loop to the AWS testbed (`54.190.82.255`) mirroring production behavior (`docker save` via SSH pipe, respecting Erlang node name constraints).
  2. **Flow Control Fix:** Removed legacy override (`effective_window = max(effective_window, 40960)`) that bypassed peer flow control.
  3. **Crash Fix:** Fixed `process_cumulative_ack` crashing on `map_size()` by changing it to `length()`.
  4. **Receive Window Dump Fix:** Bumped `@recv_window_size` from 256 to 4096 so massive WAN WAN bursts don't drop ACKs.
  5. **Benchmark Integrity:** Added zombie process cleanup (`pkill ztlp`) to the bench script.
- **What is currently in progress:** Congestion control (`cwnd`) and `CcProfile` tuning for high throughput.
- **What is failing or blocked:** Expanding throughput. The v29 attempt (`max_cwnd`=4096, `ssthresh`=2048, `burst_size`=8) resulted in a stalled session at ~5MB transferred due to a catastrophic "recovery wedge" where `inflight` (2066 packets) drastically outpaced the post-loss `cwnd` (61). The window remained permanently closed.
- **What was recently changed:** Reverted `gateway/lib/ztlp_gateway/session.ex` back to the stable v26 desktop profile. Restored the v26 Docker container on the testbed.
- **Temporary workarounds currently in place:** The Gateway is operating precisely on `ztlp-gateway:bench-2026-05-17.v26` which utilizes an artificially low `max_cwnd` limit (256) to ensure stability at the cost of speed (~0.6 MB/s). 
- **Current system stability status:** Stable but heavily throttled. Testbed is fully responsive to integration tests.

## 3. Active Tasks

### Task 1: Tune `CcProfile` for High Throughput (Phase 8/v30)
- **Status:** **Blocked** (Needs single-step tuning based on v29 findings)
- **Detailed description:** The gateway parses a `ClientProfile` and maps it to a `CcProfile`. Current desktop profile artificially caps throughput. Raising `max_cwnd` works until a packet drop occurs. Once packet drop happens, `loss_beta=0.7` harshly drops `cwnd` to a tiny value, but `inflight` remains massive. The `send_queue` cannot drain because `inflight >> cwnd`.
- **Important implementation notes:** v28 mistakenly raised `burst_size` to 32, choking the connection immediately. v29 correctly kept `burst_size` at 8 but proved that unconstrained `max_cwnd` + `ssthresh` leads to unrecoverable backoff wedges.
- **Known issues:** It's unclear if Dup-ACK cwnd inflation is over-inflating cwnd during recovery before returning to `ssthresh`, or if retransmits are double-counting in `inflight`. 
- **Next exact step to perform:**
  1. Inspect the recovery-entry code in `session.ex` to see how `cwnd` drops on packet loss.
  2. Implement **v30** (lower `ssthresh` to 512, keeping `max_cwnd` at 4096) OR **v32** (hard cap on recovery entry: `cwnd = max(ssthresh, inflight/2)`). 
- **Relevant files:** `gateway/lib/ztlp_gateway/session.ex`
- **Relevant commands:** `cd ~/ztlp && docker build -f gateway/Dockerfile -t ztlp-gateway:v30 .`
- **Dependencies or assumptions:** The AWS relay and gateway environments MUST retain their existing startup parameters (Host networking, etc.)
- **Testing status:** v26 is cleanly verified. v29 failed and was documented. 

## 4. Technical Context
- **Overall architecture:** ZTLP UDP tunnel. Client (Rust) -> Relay (Elixir, `172.26.15.55`) -> Gateway (Elixir, `54.190.82.255:23097`) -> Local backend (Python HTTP, `127.0.0.1:7777`).
- **Folder structure:** `gateway/` (Elixir backend), `bench/` (Python scripts), `proto/` (Rust client), `ios/` (Mobile implementation).
- **Important source files:** `gateway/lib/ztlp_gateway/session.ex` (The center of session lifecycle, flow control, BBR/CC mechanisms, and recovery algorithms).
- **Services involved:** ZTLP NS (`18.236.150.73`), ZTLP Relay (`54.190.82.255`), ZTLP Gateway (`54.190.82.255`).
- **Environment variables (Gateway Testbed):** MUST BE PRESERVED on swap.
  - `ZTLP_GATEWAY_BACKENDS=bench:127.0.0.1:7777`
  - `ZTLP_GATEWAY_SERVICE_NAMES=bench`
  - `ZTLP_GATEWAY_POLICIES=*:bench`
  - `ZTLP_NS_SERVER=18.236.150.73:23096`
  - `ZTLP_RELAY_SERVER=172.26.15.55:23095` (INTERNAL AWS IP REQUIRED)
  - `ZTLP_LOG_LEVEL=debug`
  - `ZTLP_GATEWAY_PORT=23097`, `--network host`
- **Deployment assumptions:** NO rsync/scp. You MUST build locally with Docker and ship via SSH pipe (`docker save | ssh ... docker load`). 
- **Build/runtime commands:** Wait for previous container (`ztlp-gateway-v26`) to `stop` before launching the new tag due to Erlang host networking conflicts. 

## 5. Code Documentation Standards
All code written by Hermes MUST be thoroughly documented.
- Functions must include clear comments/docstrings.
- Complex logic must explain WHY it exists.
- Edge cases and assumptions must be documented (e.g. why `effective_window` is calculated a certain way).
- Avoid “magic behavior” without explanation.
- Code should be understandable by a brand-new engineer reviewing it later.
- Prioritize maintainability and operational clarity over minimalism.

## 6. Testing Requirements
Hermes MUST follow a test-first or test-alongside-development workflow.
- **Tests Added/Updated:** Relying heavily on `bench/run_fullstack_multistream.py` for integration testing.
- **Integration Validation:** Running end-to-end payload deliveries via `curl` forwarded over the custom UDP transport.
- **What was tested:** Attempted 10MB file transport using modified CcProfiles (v28, v29). 
- **How it was tested:** `python3 bench/run_fullstack_multistream.py --size 10485760 --ns 1`
- **Remaining gaps:** Deep insight into recovery frame inflation and `inflight` variable tracking during heavy Dup ACK storms.

## 7. Validation Requirements
Before considering work complete Hermes MUST:
- Run tests (e.g. `run_fullstack_multistream.py`).
- Validate the application starts correctly (`docker ps`, `docker logs`).
- Verify integrations function correctly (Relay registers the Gateway in logs).
- Check logs for hidden failures (`pacing_tick` outputs, `Stall` errors).
- Confirm documentation (this handoff file) is updated.
- *What could not be verified:* We cannot easily verify if standard mobile (cellular) pathways drop these bursts the same way without explicit client testbed access; our current focus is the AWS testbed's backend flow control calculations.

## 8. Decisions Made
- **Decision:** Reverted v29 and retained v26 baseline parameters for the Desktop `CcProfile`.
  - **Why:** v29 effectively soft-locked the data pipeline midway through transfer due to massive discrepancy between `cwnd` collapse algorithms and the raw `inflight` tracker.
  - **Alternative considered:** Leaving v29 as a starting point.
  - **Tradeoff accepted:** Retained stable but slow state so the operator never inherits a broken baseline.
- **Decision:** Removed legacy `max(effective_window, 40960)` completely.
  - **Why:** Bypassed standard window signals generated by the Rust client.

## 9. Known Problems
- **Bugs/Technical Debt:** `pacing_tick` logs erroneously print `40960` for `cwnd` max limits due to older diagnostic code. It's wildly misleading and needs removal.
- **Incomplete implementations:** The gateway's `in_recovery` and `loss_beta` implementations trap the system when throughput scales too fast.
- **Performance concerns:** `max_cwnd=256` restricts 10MB testbed bench transfers to a sluggish ~0.6MB/s. 
- **Temporary workarounds:** Operating aggressively locked `max_cwnd` until BBR/Recovery math is fixed.

## 10. Open Questions
- Is `inflight` legitimately double-counting retransmits in `session.ex`?
- When the gateway transitions to `in_recovery=true`, does standard `loss_beta` (e.g., halving the cwnd) strand inflight packets permanently, requiring an `inflight/2` calculation guard?
- Is Dup-ACK cwnd inflation (from RFCs) implemented too aggressively in Elixir here?

## 11. Next Session Startup Plan
1. **Review this handoff file.** (Critical operational context).
2. **Review testbed state:** 
   `ssh -o StrictHostKeyChecking=no ubuntu@54.190.82.255 'docker ps'`
   Confirm `ztlp-gateway:bench-2026-05-17.v26` is running.
3. **Inspect the recovery path:** Read `gateway/lib/ztlp_gateway/session.ex`, particularly around `process_cumulative_ack`, `in_recovery`, and fast retransmits.
4. **Build v30/v32:** Implement a fix to the recovery wedge. E.g. setting `cwnd = max(ssthresh, inflight/2)`. Compile and deploy exactly via `docker save | ssh docker load`.
5. **Run tests:** Re-run the integration Python suite (`--size 10485760 --ns 1`).
6. **What risks to avoid:** DO NOT use bridge networking. Retain `--network host`. Ensure you stop the old container before starting the new one to prevent Erlang naming collisions.

## 12. Git Workflow Requirements
Hermes MUST use Git as part of the workflow.
- All intentional changes exist in the commit history.
- The Git commit adheres to the `<type>: short summary\n\nDetailed description:...` mandate. 
- Commit explains *WHY* the CcProfile changes were attempted and *WHY* they were reverted.
