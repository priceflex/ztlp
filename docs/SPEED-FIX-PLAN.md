# ZTLP iOS Speed Fix — Root Cause Analysis & Plan

## What This Document Is
A systematic analysis of the iOS throughput problem, based on reviewing every
commit in the trial-and-error history, the full source code, iOS Network
Extension documentation, and how WireGuard/Nebula/QUIC solve similar problems.

No code changes until this plan is reviewed and agreed upon.

---

## 1. TIMELINE OF TRIAL AND ERROR (50 commits)

Reading the git log bottom-to-top reveals a clear pattern of escalating fixes
without a unified theory:

```
Phase 1: "Gateway congestion control is wrong"
  - Float.round crash fix, retransmit storm fix, delayed ACK flush
  - Fast retransmit, NACK support, MTU/cwnd tuning
  - TCP slow-start + AIMD, RTO fixes, TLS backpressure
  → Outcome: Gateway is now solid. NOT the bottleneck.

Phase 2: "ACKs aren't getting back to the gateway"
  - Bypass VIP SendController for ACKs, relay NAT rebinding fix
  - Increase ACK frequency, release pipeline lock before encryption
  - Dedicated ACK sender task in tokio
  → Outcome: 0/11 benchmarks → 6/11. Stall moved from ~1MB to ~10MB.

Phase 3: "Tokio is starving ACK sends"
  - OS thread ACK sender with dup'd socket
  - Shared AtomicU64 seq counter
  - Raw sendto() on original fd (dup breaks iOS NE binding)
  - Redundant ACK sends (3x, then 5x)
  - Tokio ACK pump (5ms interval) as secondary path
  → Outcome: Marginal improvement, still fails at 10MB+.

Phase 4: "Maybe Swift NWConnection is better for ACKs"
  - Swift hybrid ACK sender (Rust encrypts, Swift sends via NWConnection)
  - Build failures, FFI scope issues
  → Outcome: Latest commit. Build issues. Unclear if it helps.
```

**Pattern: Each fix addresses a symptom of the PREVIOUS fix, not the root cause.**

---

## 2. THE ACTUAL PROBLEM (Root Cause Analysis)

The problem is NOT "tokio starvation" or "the wrong ACK sender." It's a
fundamental architectural mismatch:

### 2a. ZTLP uses a RAW BSD UDP socket in an iOS Network Extension

Every mature iOS VPN (WireGuard, Nebula, Mullvad) uses Apple's managed
networking APIs:
- NWUDPSession (legacy) via NEProvider.createUDPSession()
- NWConnection (modern) via Network.framework

ZTLP uses tokio::net::UdpSocket which binds a raw BSD socket. This creates
THREE problems specific to iOS Network Extensions:

1. **No tunnel bypass routing**: NWUDPSession/NWConnection created from the
   NEProvider automatically bypass the VPN tunnel. Raw sockets may not.
   ZTLP may be routing its own protocol traffic INTO its own tunnel under
   certain network conditions.

2. **No path change handling**: When iOS switches WiFi↔cellular, NWUDPSession
   gets viabilityUpdateHandler callbacks. Raw sockets just silently fail.
   The NAT rebinding storms we see may be iOS moving between interfaces and
   the raw socket not following.

3. **Send buffer contention**: The raw socket fd is shared between tokio's
   recv (async, kqueue-driven) and the OS thread's sendto() (blocking).
   Under high inbound load, the kernel's socket buffer is filled with inbound
   UDP. The sendto() on the SAME fd may hit EWOULDBLOCK because the socket's
   internal buffer is under pressure from both directions. This is the real
   reason ACKs get "dropped."

### 2b. The ACK sender is fighting the receiver for the same socket buffer

Current architecture:
```
                    ┌─────────────────┐
  Gateway ──UDP──>  │  SINGLE SOCKET  │  <──UDP── Gateway
  (inbound data)    │  (fd shared)    │  (outbound ACKs)
                    └─────────────────┘
                      ↑           ↑
                  tokio recv   OS thread sendto()
                  (kqueue)     (blocking, same fd)
```

Under 55 Mbps inbound, the socket receive buffer fills ~28ms. The OS thread
calling sendto() on the same fd competes with the kernel's receive buffer
management. iOS kernel UDP implementation has known issues with bidirectional
high-rate I/O on a single socket.

WireGuard solves this by using SEPARATE sockets:
- NWUDPSession for SEND (writeDatagram)
- NWUDPSession for RECV (setReadHandler)
- OR a single NWUDPSession that Apple manages internally

### 2c. Redundant ACK sends (5x) are making it WORSE

Sending each ACK 5 times with 1ms spacing means:
- At coalesce=8, a 1MB transfer (~870 pkts) generates ~109 ACK events
- Each event: 5 sends × 1ms spacing = 5ms of blocking on the OS thread
- Total: 109 × 5 = 545 sends, 109 × 5ms = 545ms of thread sleep time
- During that sleep time, MORE data arrives, socket buffer fills, ACKs
  back up in the mpsc channel

The redundancy is a band-aid for the real problem (send competing with recv
on the same socket). It actually exacerbates the problem by keeping the OS
thread busy sleeping instead of sending.

### 2d. The Swift NWConnection ACK sender (latest attempt) is the right IDEA

The most recent commit (Swift NWConnection hybrid) actually had the right
intuition: use a SEPARATE, Apple-managed UDP connection for ACKs. But:
- It has build issues
- The Rust side ALSO still sends ACKs via the OS thread + tokio pump
- Three competing ACK senders (OS thread, tokio pump, Swift NWConnection)
  create confusion, waste, and port conflicts

---

## 3. HOW WIREGUARD & QUIC SOLVE THIS

### WireGuard iOS:
- Uses NWUDPSession from createUDPSession() for ALL transport UDP
- wireguard-go's conn.Bind on iOS delegates to Swift for actual I/O
- Crypto runs in Go userspace; I/O goes through Apple's managed stack
- No congestion control needed (inner TCP handles it)
- No ACK problem because there's no reliability on the outer layer

### QUIC (quiche/quinn) on iOS:
- The QUIC library handles its own crypto and ACK processing internally
- The socket I/O is abstracted — you give it datagrams, it gives you datagrams
- ACKs are piggybacked on data frames (not separate packets)
- Loss detection is time-based + packet-number-based (not just ACK counting)
- Pacing is built-in and mandatory in QUIC

### Key insight: ZTLP is essentially implementing a custom reliable protocol
over UDP, which is what QUIC does. But QUIC's ACK design is fundamentally
different — ACKs are ranges carried in any packet, not separate dedicated
frames on a separate socket.

---

## 4. THE FIX (Three Options, Ranked)

### Option A: Separate Socket Architecture (RECOMMENDED — least invasive)

Use TWO sockets with clear separation of concerns:
```
  Gateway ──UDP──>  RECV SOCKET  (tokio, kqueue, receive-only)
                    bound to port X

  ACKs ──UDP──>     SEND SOCKET  (NWConnection, send-only)
                    ephemeral port Y — gateway matches by session_id
```

Changes needed:
1. Create ACK sender NWConnection in Swift (via NEProvider.createUDPSession
   or NWConnection — already partially done in latest commit)
2. Remove the OS thread ACK sender (ack_socket.rs) entirely
3. Remove the tokio ACK pump entirely
4. Keep ONE ACK path: Rust encrypts → FFI callback → Swift NWConnection sends
5. Remove the 5x redundant sends (with a working separate socket, 1x is enough)
6. Gateway must accept ACKs from port Y (different from data port X).
   This works because the gateway matches packets by session_id in the header,
   NOT by source port.

**Risk**: Gateway's anti-replay window must handle seqs from both the data
socket and the ACK socket. This already works because the shared AtomicU64
handles seq allocation.

**Relay routing fix**: The relay currently matches sender == peer_a (exact
IP:port match) to decide forwarding direction. But the relay already parses
session_id from the ZTLP header and validates it in the pipeline. Following
Nebula's design (routes by RemoteIndex, NOT IP:port), we change the relay
logic to:
  - If sender matches a known gateway → forward to client (return path)
  - If session_id is valid AND sender is NOT a gateway → forward to gateway
  - Update "last_client_addr" for return traffic (roaming, like Nebula)
This is a small change in udp_listener.ex handle_admitted_packet() and is
architecturally correct — the gateway's AEAD provides real authentication,
not the relay's IP:port matching.

### Option B: Full NWUDPSession Transport (most correct, most work)

Replace tokio::net::UdpSocket entirely with Apple's managed transport:
1. Create NWUDPSession in Swift via NEProvider.createUDPSession()
2. Bridge ALL send/recv through FFI callbacks
3. Remove tokio socket entirely for transport
4. Keep tokio runtime only for application logic (routing, mux streams, crypto)

This is what WireGuard does. It's the "right" way for iOS. But it means:
- Rewriting the entire transport layer for iOS
- Maintaining two transport backends (Linux server uses tokio, iOS uses NWConnection)
- More FFI surface area

### Option C: QUIC-style ACK Piggybacking (best long-term, most redesign)

Change the wire format so ACKs are embedded in data packets:
- Every packet from client → gateway carries the latest cumulative ACK
- No separate ACK frames, no separate ACK sender
- Similar to QUIC's approach where ACK ranges ride alongside data

This eliminates the entire ACK-sending problem but requires wire protocol changes.

---

## 5. RECOMMENDED PLAN: Option A (Separate Socket)

### Step 1: Write the tests FIRST

Before any code changes, create tests that validate the behavior we need:

```
test_ack_delivery_under_load:
  - Simulate 10MB inbound data at 55Mbps
  - Verify ACKs are generated every 8 packets (coalesce)
  - Verify ACKs actually arrive at the gateway within 50ms
  - Verify zero ACKs are dropped

test_separate_socket_ack_path:
  - Create two UDP sockets (recv and send)
  - Send 1000 packets to recv socket at full rate
  - Simultaneously send ACKs from send socket
  - Verify ALL ACKs arrive (no contention)

test_single_socket_contention:
  - Create one UDP socket (shared recv+send)
  - Send 1000 packets at full rate while sending ACKs
  - Measure ACK delivery rate (expect degradation)
  - This test DEMONSTRATES the problem

test_ack_coalescing:
  - Send 100 ACK frames rapidly
  - Verify only the latest cumulative ACK is transmitted
  - Verify NACKs are never coalesced

test_gateway_accepts_ack_from_different_port:
  - Send data from port X, ACKs from port Y
  - Verify gateway processes both correctly
  - Verify cwnd opens normally

test_no_redundant_sends_needed:
  - With separate send socket, send each ACK once
  - Verify 100% delivery (no kernel contention)
```

### Step 2: Clean up the ACK architecture

Remove the three-way ACK sender mess:
- DELETE: OS thread ACK sender (ack_socket.rs)
- DELETE: Tokio ACK pump (5ms timer in ffi.rs)
- KEEP: Swift NWConnection callback (latest commit, fix build issues)
- KEEP: Rust-side encryption (build_encrypted_packet stays)

Result: ONE ACK path: recv_loop → encrypt → FFI callback → Swift NWConnection

### Step 3: Fix the Swift NWConnection ACK sender

The latest commit has the right idea but needs:
- Use NEProvider.createUDPSession() instead of bare NWConnection (ensures
  bypass routing)
- Single DispatchQueue at .userInteractive QoS
- Completion-based flow control (don't queue unbounded)
- Proper cleanup on session disconnect

### Step 4: Verify relay routing

Test whether ACKs from the Swift NWConnection's ephemeral port are routed
correctly through the relay. If not, either:
- Send ACKs directly to gateway (bypass relay) — simplest
- Add session_id routing to relay

### Step 5: Remove redundancy

With a clean separate-socket path:
- Remove 5x redundant sends
- Remove 1ms sleep between sends
- Single ACK send per coalesce point

### Step 6: Tune coalescing for the new architecture

With reliable ACK delivery:
- ACK_COALESCE_COUNT can probably go back to 8 or even 16
- ACK_FLUSH_TIMEOUT can relax to 20-50ms
- NACK gap threshold can relax
- Remove the re-ACK rate limiter (re-ACKs won't cause storms with separate socket)

---

## 6. WHAT NOT TO DO

Based on the 50 commits of trial and error:

1. Do NOT add more redundant send paths. Three ACK senders is already too many.
2. Do NOT tune coalescing/timing constants as a substitute for fixing I/O.
3. Do NOT use dup() on iOS NE sockets. Already proven to break binding.
4. Do NOT use raw libc::sendto() on the tokio socket fd. This is the source of contention.
5. Do NOT add more threads. The memory budget is ~15MB.
6. Do NOT change gateway congestion control to compensate for missing ACKs.
   Gateway CC is already well-tuned. Fix the ACK delivery, not the CC response.

---

## 7. VALIDATION CRITERIA

The fix is done when:
- 11/11 benchmarks pass (including 10MB+)
- No "DUPLICATE data_seq" storms in iOS logs
- No "Stall detected: no ACK advance" in gateway logs
- ACK latency (measured at gateway) is consistently < 50ms
- Memory usage in Network Extension stays under 15MB
- Works on both WiFi and cellular
- Works through NAT rebinding (WiFi↔cellular handoff)
