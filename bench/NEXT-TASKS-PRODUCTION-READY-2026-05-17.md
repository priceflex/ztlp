# ZTLP Full-Stack Production-Ready Next Tasks

> **For Hermes:** Use `subagent-driven-development` for code changes. Main agent should orchestrate, verify side effects, and keep the context lean.

**Goal:** Take the real AWS full-stack Gateway/Relay/NS testbed from “small smoke test works” to production-ready browser-grade throughput.

**Current State:**

- Loopback dumb-pipe multistream stall is fixed on `main` (`c6947e0`): 214 MB/s at N=32, zero `UdpRcvbufErrors`.
- Real AWS testbed is deployed and reachable:
  - NS: `18.236.150.73:23096/udp`
  - Relay: `44.243.42.123:23095/udp`
  - Gateway: `54.190.82.255:23097/udp`
- Docker and UDP sysctls are installed/tuned on all three AWS boxes.
- Real data path smoke test works for small traffic:
  - client → relay → gateway → backend → back
- Full-stack bulk response path is **not production-ready yet**:
  - 64 KiB single-stream HTTP download works.
  - 1 MiB single-stream HTTP download receives ~513 KiB, then stalls.
  - 4 concurrent sessions are fragile; several hang waiting for `HELLO_ACK` or timeout with zero response bytes.
  - UDP `InErrors` stay zero on client/relay/gateway, so this is not the old kernel rcvbuf loss bug.

**Primary Diagnosis:** The next blocker is likely inside the Elixir Gateway session / legacy backend response path: response-side flow control, send-buffer flushing, ACK progress, or session replacement behavior.

**Key Artifacts:**

- `bench/RESULTS-2026-05-17.md` — loopback rcvbuf fix results.
- `bench/RESULTS-FULLSTACK-2026-05-17.md` — real AWS full-stack findings.
- `bench/run_fullstack_multistream.py` — current full-stack HTTP download bench harness.
- `/tmp/ztlp-fullstack/` — last per-stream logs on the agent box.
- `/tmp/fullstack-bench-result.txt` — last result table on the agent box.
- Gateway backend script on gateway host: `ubuntu@54.190.82.255:/tmp/http_bench.py`.

---

## Production-Ready Definition

Call the full stack production-ready for browser benchmarking only when all of these pass:

1. Single-stream HTTP download through relay+gateway completes at 1 MiB, 10 MiB, and 100 MiB.
2. Multistream HTTP downloads complete at N=1,4,8,16,32 with zero stalls for 10 MiB per stream.
3. UDP `InErrors` / `RcvbufErrors` remain zero on client, relay, and gateway during the above.
4. Gateway logs show no backend response stalls, send-buffer deadlocks, queue overflows, or session replacement collisions.
5. Browser benchmark site can be reached through a local ZTLP tunnel and completes multi-stream download/upload tests.
6. Testbed deployment is reproducible via documented `docker run` or compose files.

---

## Task 1: Preserve Current Testbed State

**Objective:** Capture the deployed container state and host tuning before any more changes.

**Files:**

- Create: `bench/AWS-FULLSTACK-TESTBED-2026-05-17.md`

**Steps:**

1. Capture `docker ps` on all three hosts:

   ```bash
   for h in 18.236.150.73 44.243.42.123 54.190.82.255; do
     echo "=== $h ==="
     ssh ubuntu@$h 'sudo docker ps --format "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"'
   done
   ```

2. Capture sysctls on all three hosts:

   ```bash
   for h in 18.236.150.73 44.243.42.123 54.190.82.255; do
     echo "=== $h ==="
     ssh ubuntu@$h 'sysctl net.core.rmem_max net.core.wmem_max net.core.rmem_default net.core.wmem_default'
   done
   ```

3. Capture exact gateway env/config:

   ```bash
   ssh ubuntu@54.190.82.255 'sudo docker inspect ztlp-gateway --format "{{json .Config.Env}}"'
   ```

4. Write the results into `bench/AWS-FULLSTACK-TESTBED-2026-05-17.md`.

**Verification:** The doc contains enough info to recreate the current testbed from scratch.

---

## Task 2: Reproduce the Single-Stream 1 MiB Stall with Focused Logs

**Objective:** Make the gateway response-side stall easy to reproduce and inspect.

**Files:**

- Modify: `bench/run_fullstack_multistream.py` if needed.
- Create: `bench/debug_fullstack_single_stream.sh`.

**Steps:**

1. Create a focused script that runs exactly one tunnel and exactly one HTTP download:

   ```bash
   cd /home/trs/ztlp
   python3 bench/run_fullstack_multistream.py --size 1048576 --ns 1
   ```

2. Before and after the run, collect:

   ```bash
   ssh ubuntu@54.190.82.255 'sudo docker logs ztlp-gateway --since 2m --tail 300'
   ssh ubuntu@44.243.42.123 'sudo docker logs ztlp-relay --since 2m --tail 200'
   ssh ubuntu@54.190.82.255 'cat /proc/net/snmp | grep ^Udp:'
   ssh ubuntu@44.243.42.123 'cat /proc/net/snmp | grep ^Udp:'
   cat /proc/net/snmp | grep ^Udp:
   ```

3. Save logs under `/tmp/ztlp-fullstack/single-1m-*`.

**Verification:** The script reliably shows the ~500 KiB stall or records a clean pass if behavior changes.

---

## Task 3: Instrument Gateway Response-Path Progress

**Objective:** Identify whether the stall is caused by backend read, gateway send buffer, ACK/window, pacing, or relay forwarding.

**Files to inspect/modify:**

- `gateway/lib/ztlp_gateway/session.ex`
- `gateway/lib/ztlp_gateway/backend.ex`
- Any gateway module handling legacy backend TCP reads and encrypted response writes.

**Instrumentation points:**

Add temporary `Logger.info` or structured debug logs for:

1. Backend TCP read byte counts.
2. Response frames queued to the gateway send buffer.
3. Response frames actually sent via UDP.
4. ACKs received from client.
5. `send_buffer` length / bytes.
6. `cwnd`, `inflight`, `last_acked`, and `recv_base`.
7. Any timer / pacing state.
8. FIN ordering: client FIN, backend close, gateway FIN.

**Verification command:**

```bash
python3 bench/run_fullstack_multistream.py --size 1048576 --ns 1
ssh ubuntu@54.190.82.255 'sudo docker logs ztlp-gateway --since 3m | grep -E "BACKEND_READ|RESP_QUEUE|RESP_SEND|ACK|send_buffer|cwnd|FIN"'
```

**Expected outcome:** Logs show the exact point where bytes stop moving.

---

## Task 4: Fix Single-Stream Response-Side Stall

**Objective:** Make a 1 MiB and 10 MiB HTTP download complete through relay+gateway.

**Likely code areas:**

- Gateway session response send loop.
- Legacy backend close handling.
- Send-buffer flush after backend response.
- ACK/window advancement from client to gateway.
- Pacing timer restart logic.

**Rules:**

- Do not change relay code unless logs prove relay is dropping/holding packets.
- Do not chase kernel sysctls if `dErr=0` remains true.
- Add regression tests if there are existing gateway tests that can simulate backend response >512 KiB.

**Verification:**

```bash
python3 bench/run_fullstack_multistream.py --size 1048576 --ns 1
python3 bench/run_fullstack_multistream.py --size 10485760 --ns 1
```

Success means:

- `stalled=0`, `ok=1`
- curl downloads full `size_download`
- UDP `dErr=0` on all hops

---

## Task 5: Fix Concurrent Handshake / Session Startup Fragility

**Objective:** Make N parallel sessions establish reliably through the relay and gateway.

**Current symptom:** With N=4, some streams time out waiting for `HELLO_ACK` even with explicit unique `--session-id` and 250 ms stagger.

**Likely areas:**

- Gateway listener creating/replacing sessions.
- SessionID collision or replacement logic.
- Relay pairing behavior for simultaneous sessions.
- Client retransmit behavior for HELLO under relay path.

**Investigation steps:**

1. Run N=4 with gateway logs at debug.
2. Confirm each unique SessionID appears at gateway.
3. Confirm each session sends msg2.
4. Confirm relay forwards each msg2 back to the correct client UDP tuple.

**Verification:**

```bash
python3 bench/run_fullstack_multistream.py --size 65536 --ns 4
python3 bench/run_fullstack_multistream.py --size 65536 --ns 8
```

Success means all streams reach local LISTEN state and all 64 KiB downloads complete.

---

## Task 6: Run Production Throughput Matrix

**Objective:** Generate final Phase B3 numbers comparable to the loopback N=32 table.

**Command:**

```bash
cd /home/trs/ztlp
python3 bench/run_fullstack_multistream.py --size 10485760 --ns 1,4,8,16,32 \
  | tee /tmp/fullstack-production-bench.txt
```

**Metrics to record:**

- Aggregate MB/s.
- Wall time.
- Per-stream average MB/s.
- `stalled` and `ok` counts.
- UDP counter deltas on client/relay/gateway.
- Gateway CPU/memory during the run:

  ```bash
  ssh ubuntu@54.190.82.255 'docker stats --no-stream ztlp-gateway'
  ssh ubuntu@44.243.42.123 'docker stats --no-stream ztlp-relay'
  ```

**Success target:**

- N=32 completes with `stalled=0`.
- UDP `dErr=0` on all hops.
- Throughput is expected to be below loopback 214 MB/s because this is real AWS WAN + Elixir gateway, but it must be stable and nonzero.

---

## Task 7: Install Browser Benchmark Site

**Objective:** Add a browser-usable benchmark after the gateway response path is fixed.

**Recommended backend:** Start simple before librespeed.

1. Keep `/tmp/http_bench.py` or package it into a tiny Docker image.
2. Serve an HTML page with JS that opens N parallel fetches to `/bytes?size=...`.
3. Only after that works, consider LibreSpeed.

**Gateway service mapping:**

Current gateway service name is `echo`, mapped to `127.0.0.1:7777`. Rename to `bench` for clarity once stable:

```bash
-e ZTLP_GATEWAY_BACKENDS=bench:127.0.0.1:7777
-e ZTLP_GATEWAY_SERVICE_NAMES=bench
-e ZTLP_GATEWAY_POLICIES=*:bench
```

**Verification:**

1. Start local tunnel:

   ```bash
   proto/target/release/ztlp connect 54.190.82.255:23097 \
     --key /tmp/bench-identity.json \
     --relay 44.243.42.123:23095 \
     --service bench \
     --local-forward 18080:127.0.0.1:7777
   ```

2. Open browser to:

   ```text
   http://127.0.0.1:18080/
   ```

3. Run browser test at N=1,4,8,16,32.

---

## Task 8: Make Deployment Reproducible

**Objective:** Replace hand-run `docker run` commands with checked-in compose or scripts.

**Files:**

- Create: `bench/fullstack/aws-testbed/README.md`
- Create: `bench/fullstack/aws-testbed/run-ns.sh`
- Create: `bench/fullstack/aws-testbed/run-relay.sh`
- Create: `bench/fullstack/aws-testbed/run-gateway.sh`
- Optional: `bench/fullstack/aws-testbed/docker-compose.gateway.yml`

**Requirements:**

- Scripts must be idempotent: remove/replace existing bench containers safely.
- Scripts must not touch production hosts `34.217.62.46`, `34.219.64.205`, or `44.246.33.34`.
- Include AWS Security Group port checklist:
  - NS: UDP 23096
  - Relay: UDP 23095
  - Gateway: UDP 23097
  - Optional metrics: TCP 9101/9102/9103

---

## Task 9: Decide What to Do with the Temporary Testbed

**Objective:** Avoid forgotten AWS costs or stale public services.

**Options:**

1. Keep it running until browser benchmark is stable.
2. Stop containers but keep instances.
3. Terminate instances after capturing AMI/snapshot or deployment scripts.

**Current services to stop if needed:**

```bash
ssh ubuntu@18.236.150.73 'sudo docker rm -f ztlp-ns'
ssh ubuntu@44.243.42.123 'sudo docker rm -f ztlp-relay'
ssh ubuntu@54.190.82.255 'sudo docker rm -f ztlp-gateway http-bench tcp-echo'
```

Do not run those unless Steve explicitly asks to tear down the testbed.

---

## Immediate Next Action for the New Session

Start with Task 2 and Task 3:

1. Reproduce the single-stream 1 MiB stall with clean logs.
2. Instrument the gateway response path until the exact stall point is known.
3. Fix single-stream 10 MiB before touching browser/librespeed.

Do **not** start with LibreSpeed. Browser benchmarking depends on the same response path that currently stalls around ~500 KiB.
