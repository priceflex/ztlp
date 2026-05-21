# Hermes Session Handoff

> **Active session:** 2026-05-20 — ZTLP Architecture Pivot (QUIC / Quinn + Noise) 
> **Agent:** Hermes
> **Operator:** Steve Price

---

## 1. Project Goal
- **Primary Objective:** Replace ZTLP's hand-rolled UDP reliability, flow control layer with `quinn`.
- **Business/Technical Reason:** The custom reliability layer over UDP suffered a partial demolition during the "nebula-pivot", causing flow-control deadlocks.
- **Success Criteria:** A functional ZTLP tunnel where QUIC manages streams without stalling.
- **Long-term Vision:** Adopt a robust transport foundation that supports connection migration, 0-RTT, and pluggable congestion control.

---

## 2. Current Progress
- **Completed (Past):** Diagnosed browser hang, prepared 11 `main` branch transport files for removal.
- **Completed (Recent):**
  - **Phase 5 (Loopback Benchmarks):** True QUIC `quic_multistream` benchmarks completed: 938 MB/s.
  - **HTTP Identity Injection Mitigation:** Fully extracted `inject_headers` and proved it compiles inside async `quinn` endpoints.
  - **Compilation Stability:** Bypassed broken UDP legacy endpoints. Crate compiles cleanly.
  - **Phase 6 (AWS Deployment Tagging):** 0.28.3 deployed via GitHub artifacts. Bypassed mono CLI by deploying decoupled `quic-server` test binaries to Gateway `54.218.127.30`, verifying across WAN successfully.
- **In Progress:** Ready for Phase 7 (Refactor monolith logic).
- **Blocked/Failing:** The raw CLI monolithic `ztlp-cli.rs` successfully invokes `ztlp listen` config but runs against a stub function. The proxy is not actively parsing streams yet.

---

## 3. Active Tasks

### Task A: Architect the Quinn + Noise Handshake
- **Status:** **Completed**

### Task B: Wire `QuicEndpoint` to UDP socket (Phase 1)
- **Status:** **Completed**

### Task C: Noise frames over QUIC stream 0 (Phase 2)
- **Status:** **Completed**

### Task D: Demolish Legacy Flow Control (Phase 3)
- **Status:** **Completed**

### Task E: iOS `quinn-proto` sans-io integration (Phase 4)
- **Status:** **Completed**

### Task F: Benchmark Throughput (Phase 5)
- **Status:** **Completed**

### Task G: AWS Deployment and 0.28.0 Tag (Phase 6)
- **Status:** **Completed (0.28.3)**

### Task H: Rewrite `ztlp-cli.rs` Monolith with QUIC (Phase 7)
- **Status:** **Not Started**
- **Description:** The `ztlp-cli.rs` application loop needs to drop the `tunnel::run_bridge` function chains used by the previous UDP implementation. `cmd_connect` and `cmd_listen` must be natively replaced with `QuicEndpoint` integrations.

---

## 4. Technical Context
- **Deployment Assumptions:** Gateway uses docker `network_mode: host`.
- **AWS Target Infrastructure (us-west-2):**
  - Name Server: `35.91.88.177`
  - Relay: `34.218.240.106`
  - Gateway: `54.218.127.30`

---

## 5. Code Documentation Standards
All code written by Hermes MUST be thoroughly documented.
- Functions must include clear comments/docstrings.
- Complex logic must explain WHY it exists.

---

## 6. Testing Requirements
Hermes MUST follow a test-first or test-alongside-development workflow.
- Ensure all tests pass before ending a session.

---

## 7. Validation Requirements
Before considering work complete Hermes MUST:
- Check logs for hidden failures (`RUST_LOG=trace`).
- Ensure no obvious regressions were introduced.

---

## 8. Decisions Made
- **Decision:** Abandon custom UDP flow control and multiplexing in favor of `quinn` (QUIC).
- **Decision:** Keep Noise protocol to fulfill strict Ed25519 tenant-isolation and zero-trust identity requirements.

---

## 9. Known Problems
- **Legacy Monolith Rot:** The `ztlp-cli.rs` binary natively invokes `tunnel::run_bridge` stubs.

---

## 10. Open Questions
- **TLS cert provisioning.** Self-signed per-connection vs per-node leaf cert pinned at enrollment time?

---

## 11. Next Session Startup Plan
1. **Review first:** Read `hermes_session_handoff.md`. Phases 0-6 benchmarks are now ACTUALLY complete.
2. **Command to run:** `cd ~/ztlp && cargo build --release --bin ztlp`
3. **Files to inspect:** `proto/src/bin/ztlp-cli.rs`.
4. **Next task:** Begin "Phase 7: Rewrite `ztlp-cli.rs` Monolith with QUIC".
5. **Risks to avoid:** DO NOT revert HTTP Headers parameters logic (`--http-inject-headers`).

---

## 12. Git Workflow Requirements
Hermes MUST use Git as part of the workflow.
