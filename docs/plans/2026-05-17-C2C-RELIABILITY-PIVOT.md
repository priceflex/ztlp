# Architecture Update & Next Session Handoff
**Date:** 2026-05-17
**Goal:** Restore ZTLP reliability for production-ready C2C streaming (~200 MB/s network throughput) through Relay + Gateway to unblock an immediate Windows SSH service rollout.

---

## 1. The Architectural Pivot: Separation of Mobile vs C2C

The recent "Nebula dumb-pipe pivot" attempted to solve iOS's strict 15MB Network Extension memory limit by removing reliability (ACKs, sliding windows, congestion control) from the ZTLP Rust protocol, leaving it as a pure UDP pipe. 

We discovered today that this fundamentally breaks **Computer-to-Computer (C2C)** proxying (using the `ztlp connect` CLI tool). Because `ztlp connect` is an L4 stream proxy rather than an L3 VPN, it extracts raw TCP segments and sends them over the tunnel without IP headers. Over real networks (which naturally drop UDP packets), a dumb pipe leaves permanent data holes. 

**Critical Impact on SSH/Production:** For protocols like SSH, a strictly reliable, in-order byte stream is mandatory. If an SSH session runs over the current dumb-pipe `ztlp connect`, even a 0.1% packet drop on the network instantly corrupts the encryption state, causing the SSH client to aggressively drop the connection with a `MAC failure` or `packet corrupt` error.

**The Solution (The "Docker VAPS" Architecture):**
* **Mobile (iOS):** Will utilize a lightweight, dumb-pipe tunnel to connect to an isolated, dedicated Cloud Docker Container (VAPS) per tenant/user.
* **The VAPS proxy:** Receives the dumb-pipe UDP traffic, terminates the virtual `tun` TCP connections, and utilizes the **Full Reliable ZTLP Protocol** to communicate with the central Elixir Gateway.
* **C2C (Desktops/Servers/Windows):** Will continue to use the **Full Reliable ZTLP Protocol** directly, bypassing the dumb-pipe constraints entirely and providing rock-solid reliability for protocols like SSH.

---

## 2. Immediate Next Steps for Next Session

To unblock the Windows SSH project, our highest priority is restoring the reliable transport layer to the Rust `proto` codebase on the `main` branch.

**Step 1: The Codebase Surgery (The "Un-Pivot")**
We need to surgically revert the Rust `proto/src` folder to its pre-pivot state (bringing back `session.rs` queues, `process_cumulative_ack`, and `recv_window` logic).
* **CRITICAL CONSTRAINT:** We MUST keep the recent fixes that allowed the ~200MB/s network speeds. 
  * Keep `c6947e0` (`SO_RCVBUF`/`SO_SNDBUF` loopback/network socket tuning).
  * Keep `65ca3f7` (AAD decryption/payload length fixes).
  * Keep `d47e218` (Benchmark timeout fixes).

**Step 2: Full Stack Benchmarking (Relay + Gateway)**
Once `ztlp connect` is properly generating ZTLP ACKs again:
* Deploy the standard Elixir Gateway (without the bypass hacks applied during today's debugging).
* Run `python3 bench/run_fullstack_multistream.py --size 10485760 --ns 32`. With the reliable layer restored on the client, the Gateway will process the ACKs, the 64-packet stall will vanish, and we should see high, stable ~200 MB/s network throughput across the full path.

**Step 3: Windows Production Deployment**
* Once the benchmark is stable and green, compile the Windows cross-target `ztlp.exe`.
* Wrap the executable as a Windows Service (via NSSM or the Windows Tauri app layer) for immediate deployment.

---
*End of Handoff.*
