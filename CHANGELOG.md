# Changelog

## v0.18.0 — 2026-03-29

### Production Hardening
- Zone delegation re-bootstrap: gateway verifies NS zone KEY each registration cycle
- NS data persistence: Mnesia disc_copies default, configurable CA data directory
- TLS cert lifecycle: exponential backoff retry, expiry tracking, status reporting
- Echo server systemd service for production deployment
- Gateway log levels: data-path logging moved to debug
- Firewall rules documentation and deployment scripts

### Gateway
- AIMD congestion control (IW=64, max_cwnd=256, ssthresh=128)
- Session deduplication via secondary ETS index
- Keepalive frame handling (1-byte 0x01, not forwarded to backends)
- Legacy backend reconnection on idle TCP close
- TLS termination per-stream with Erlang :ssl
- CertProvisioner with NS CA integration
- FRAME_OPEN extended with per-stream service name

### Client (Rust)
- SendController: cwnd-gated uploads with ACK processing
- Packet router: userspace TCP/IP stack for VIP routing (2,030 lines, 35 tests)
- VIP proxy upload chunking (MAX_MUX_PAYLOAD=1195)
- NS CA cert fetch FFI functions

### ZTLP-NS
- Certificate Authority with auto-init, cert issuance via 0x14 wire protocol
- Security hardening: registration auth, name validation, amplification prevention
- Mnesia disc_copies for production persistence
- Configurable CA data directory (ZTLP_CA_DATA_DIR)

### iOS App
- NetworkExtension packet tunnel with VIP routing
- Enrollment flow with QR scan and zone registration
- CA certificate installation via .mobileconfig profile
- In-app benchmark suite (14 local + 11 HTTP benchmarks)
- Services view, connection status, traffic stats

### Infrastructure
- Unified audit/logging dashboard spec (docs/UNIFIED-AUDIT.md)
- Production deployment scripts (deploy/)
- Updated ROADMAP.md with Phase 0 production hardening

### Test Counts
- 844 Rust tests, 0 failures
- 573 gateway tests, 0 failures
- 726 NS tests, 0 failures
- 565 relay tests, 0 failures
- **2,708 total, 0 failures**

---

## v0.17.0 — 2026-03-28
- iOS VIP packet routing
- Gateway keepalive + session dedup
- FFI header sync

---

## v0.14.0 — 2026-03-26

### macOS Client — Production Hardening

#### VIP Proxy Hot-Swap (zero-downtime reconnects)
- **TCP listeners survive tunnel reconnects** — `TunnelSession` wrapped in `Arc<RwLock<>>` allows the tunnel session to be swapped atomically without restarting TCP listeners on `127.0.55.1:8080/8443`.
- **New FFI: `ztlp_disconnect_transport()`** — stops the recv loop and clears the session while keeping the tokio runtime and VIP proxy alive. Sets state to `Reconnecting`.
- **Swift reconnect path** uses `disconnectTransport()` instead of `destroyClient()`, preserving the client, runtime, and listener tasks across reconnects.
- **VipProxy.start() hot-swap mode** — if listeners are already running, updates the session reference instead of rebinding ports.
- **Result:** HTTP connections accepted during tunnel reconnect wait for the new session, then proceed normally. Zero TCP downtime.

#### Tunnel Stability
- **Debounced `NWPathMonitor`** — interface change events debounced by 2 seconds to absorb macOS Ethernet renegotiation and Wi-Fi↔Ethernet priority flapping.
- **Activity-gated reconnect** — if tunnel data flowed within the last 30 seconds, skip reconnect even if interface changes. The keepalive watchdog (45s) handles real failures.
- **`lastActivity` tracking** — added to `TrafficStats`, updated by stats polling whenever `bytesReceived`/`bytesSent` changes.
- **Root cause fixed:** Mac Studio M4 Ultra with 10GbE Ethernet was triggering 3+ spurious reconnects per 30 seconds from `NWPathMonitor`.

#### Admin Password Elimination
- **Networking persists across reconnects** — `stopVipProxy()` no longer tears down loopback aliases, pf rules, or DNS resolver. Only an explicit disconnect button click runs full teardown via `teardownAll()`.
- **LaunchDaemon (`com.ztlp.networking`)** — installed on first connect, runs at boot. No admin password ever again after initial setup.
- **`isNetworkingConfigured()` checks actual system state** — verifies `/etc/resolver/ztlp`, ifconfig aliases, and pf anchor exist before prompting.

### Leveled Logging
- **`ZTLP_LOG_LEVEL` env var** — controls recv loop logging: `off`, `error`, `warn`, `info` (default), `debug`, `trace`.
- **`ZTLP_LOG_FILE` env var** — override log path (default: `~/Library/Logs/ZTLP/tunnel.log` on macOS, `/tmp/ztlp-recv.log` elsewhere).
- **Log rotation** — 2MB max, rotates to `.1` backup.
- **Periodic summaries** at `debug` level — frame count, bytes, elapsed every 5 seconds instead of per-frame.
- **Before:** 17MB in 42 seconds (trace-level per-packet). **After:** ~KB/hour at `info` level.

### UI Redesign (macOS SwiftUI)
- **3-tab sidebar** — Home, Services, Settings (from 5 tabs). Identity and Enrollment merged into Settings.
- **Menu bar icon** — `shield.checkered` (connected), `shield.slash` (disconnected), `arrow.triangle.2.circlepath` (reconnecting). Fixed `@StateObject` initialization for proper state observation.
- **Settings sections** — General → Identity → Enrollment → Advanced (collapsed) → About → Danger Zone.
- **Test Service button** moved to Services toolbar.

### CI & Testing
- Fixed flaky TLS test timeout (5s → 15s for CI resource contention).
- Removed unused `alias TlsSession` warning in gateway tests.
- Removed unused default args warnings in gateway and relay test helpers.
- **Test totals: 2,645** (799 Rust lib + relay 565 + NS 726 + gateway 555), 0 failures.
- Stress test script: `tools/stress-test.sh` — 5-stage load test through the VIP proxy tunnel.

---

## v0.12.0 — 2026-03-25

### Tunnel Reliability (100% sequential, large & small responses)
- **Path MTU fix** — capped ZTLP data payload to 1200 bytes (1271 on wire) to avoid silent drops from DF-bit retransmit packets exceeding intermediate hop MTU. Root cause of large-response (23KB+) failures.
- **Gateway KCP-inspired ARQ** — send buffer with retransmit (RTO backoff), paced send queue (window_size=8, 2ms interval), FIN-triggered drain mode, re-encryption on retransmit (fresh nonce per packet, no anti-replay violations).
- **Client reassembly buffer** — `BTreeMap<u64, Vec<u8>>` in recv_loop delivers data to VIP proxy in strict data_seq order. Stream reset detection when data_seq drops to 0.
- **Gateway FRAME_RESET state cleanup** — clears send_queue, send_buffer, draining flag, cancels pending timers on RESET.
- **Relay address migration** — known_gateway_ips set + peer_b update for VPC/EIP mismatch.
- **NsClient timeout fix** — 2s timeout with graceful fallback to hex identity (prevents cascading timeouts).
- **4MB UDP socket buffers** on gateway listener.

### VIP Proxy v2 (production-ready)
- **Concurrent TCP connections** — up to 64 simultaneous connections via semaphore (was single-connection blocking).
- **Serialized tunnel access** — AtomicBool + Notify queuing system for fair tunnel sharing (gateway doesn't support stream mux yet).
- **TLS termination** — HTTPS on ports 443/8443 with self-signed certs from `~/.ztlp/certs/`. RSA 2048 (LibreSSL ECDSA explicit-parameter incompatibility with rustls worked around).
- **TLS handshake timeout** — 10s max prevents frozen listeners.
- **Connection idle timeout** — 5min, prevents zombie connections.
- **Stale data drain** — each new connection drains leftover tunnel_rx data.
- **TCP flush after write** — reduces page load latency.
- **Larger channel buffer** — 1024 capacity (was 256).

### macOS App
- **End-to-end verified**: browser → TLS 1.3 (ChaCha20) → VIP proxy → ZTLP tunnel (Noise_XX) → relay → gateway → Vaultwarden → back. ~170ms round trip.
- **DNS resolution**: `*.techrockstars.ztlp` → `127.0.55.x` via local resolver on port 5354.
- **rustls 0.23 FFI fix**: explicit `aws_lc_rs::default_provider().install_default()` required in Swift → Rust FFI context.

### Code Quality
- `cargo fmt` applied across all source files.
- Clippy fixes: derive Default for RelayAddrs, reduce manual impls.
- Fix flaky `test_is_agent_running_no_pid_file` — environment-dependent assertion replaced with no-panic check.

### Test Results
- **794 Rust** (proto) — 0 failures
- **565 Elixir** (relay) — 0 failures
- **555 Elixir** (gateway) — 0 failures
- **726 Elixir** (NS) — 0 failures
- **Total: 2,640 tests, 0 failures**

## v0.9.0 — 2026-03-15

### Identity Model & Groups
- **DEVICE (0x10) record type** — hardware-bound identity with owner linking, pubkey, optional hardware ID
- **USER (0x11) record type** — person-bound identity with role (admin/tech/user), device list, email
- **GROUP (0x12) record type** — named groups with flat membership for access control
- **Gateway group-based policy** — policy engine resolves group membership at connection time with cached TTL
- **Admin controls** — `ztlp admin create-user`, `create-group`, `group add/remove`, `ls`, `revoke`, `audit` with `--json` output
- **Revoke cascade** — revoking a user revokes all linked devices; gateway checks revocation on every connection
- **Key overwrite protection** — reject registration for existing names with different pubkey unless admin force flag

### Deployment & Documentation
- **MSP Deployment Guide** (`DEPLOYMENT.md`) — step-by-step guide for protecting web apps behind ZTLP
- **Identity Model Reference** (`IDENTITY.md`) — DEVICE/USER/GROUP record type documentation

### Bootstrap Rails Web UI (ztlp-bootstrap)
- User CRUD (create, view, revoke) with SSH → `ztlp admin --json` backend
- Device listing, user linking, revocation
- Group management (create, add/remove members via Turbo Frames)
- Enrollment page with token generation and QR codes
- Audit log with action/date/actor filters
- Dashboard widgets: identity summary + recent activity

### Demo Improvements
- Both demos updated with v0.9.0 identity model acts (USER, DEVICE, GROUP creation and policy)

### Bug Fixes
- Mnesia transactions for group membership index (fix race condition)

## v0.8.0 — 2026-03-14

### Tunnel Reliability
- **Advanced Congestion Controller** — PRR (Proportional Rate Reduction), SACK scoreboard, token bucket pacing, Eifel spurious detection, Jacobson/Karels RTT estimation
- **Handshake retransmit** — exponential backoff (500ms–5s), half-open cache (64 entries, 15s TTL), amplification limit (3 retransmits per session)
- **Fast retransmit + corruption NACK** — v0.8 reliability with bounded RTO (4s cap)
- **Stress test infrastructure** — userspace impairment proxy (loss, delay, reorder, corruption), 11 extreme network scenarios, per-scenario log collection

### Bug Fixes
- Clippy `useless_vec` lint on Rust 1.94
- NS `pubkey_index` table race condition on CI
- Docker full-stack test with verbose debug logging

### Tests
- Comprehensive stress test report with analysis
- All Rust + Elixir tests passing

## v0.7.0 — 2026-03-14

### Features
- **Congestion control** — SACK-based selective retransmission, advanced congestion control module
- **NAT traversal** — Nebula-style hole punching, NAT timeout auto-detection, roaming support, tunnel health monitor
- **Relay data path** — wired relay forwarding + multi-session listener + client rejection
- **Relay failover** — client-side relay pool with automatic failover

### v0.7.1 — Hardening
- Anti-replay window sliding + rekey trigger ordering
- PMTU discovery
- Session rekeying
- Gateway per-session bridge socket routing
- Integration stress tests + Docker test scenarios

### Tests
- Interop test suite (Rust ↔ Elixir)
- Docker integration test scenarios

## v0.6.3 — 2026-03-14

### Bug Fixes
- **Fixed tunnel timeout during demo pauses** — Listener now uses "lazy connect" to defer backend TCP connection until client sends first data packet. Previously, sshd sent its SSH banner immediately after handshake, which was bridged over ZTLP to a client that hadn't accepted any TCP connections yet. With no bridge running on the client side, no ACKs were sent, and the listener hit the 30-second SENDER_ACK_TIMEOUT — killing the tunnel before the user could SSH through it.

### Demo Improvements
- **Act 9 — Port Visibility Analysis:** Explains what attackers see on the network (SSH hidden behind ZTLP identity layer), replaces bare nmap scan
- **Act 10 — L1 DDoS Defense:** 50K packet flood with inline CPU measurement, detailed explanation of magic byte rejection (~19ns/pkt)
- **Act 11 — L2 SessionID Defense:** Three-layer pipeline overview (L1 ~19ns, L2 ~50ns, L3 ~200ns), CPU measurement, 50K crafted packets
- **Act 12 — Encrypted Payload Verification:** Captures live SSH traffic, searches for plaintext in pcap, hex dumps ciphertext to prove encryption
- **Act 13 — Security Summary:** Formatted defense cost table (layer/cost/what it blocks) replaces standalone CPU test

## v0.6.2 — 2026-03-13

### Features
- **NS-based identity resolution for policy engine** — `ztlp listen --ns-server` resolves peer X25519 pubkeys to registered NS names via type `0x05` reverse lookup, enabling human-readable policy rules like `allow = ["alice.tunnel.ztlp"]` instead of raw NodeID hex
- **`HandshakeContext::remote_static_hex()`** — extract peer's X25519 public key from Noise_XX state for identity resolution

### Bug Fixes
- **Fixed NS query parser truncation flag** — NS amplification prevention inserts a `0x01` flag byte when response exceeds 8× request size; the Rust parser now detects and skips this byte, fixing all NS lookups that were silently returning `None`
- **Fixed SSH through tunnel with post-quantum KEX** — `sntrup761x25519-sha512` payloads stall with small UDP buffers; demo now forces `curve25519-sha256`
- **Fixed policy engine identity mismatch** — policy compared raw NodeID hex against NS name strings, always denying; now resolves via NS reverse lookup

### Demo Improvements
- `--ns-server` flag passed to listener for NS identity resolution in policy checks
- Auto-grant/revoke `cap_net_raw` on tcpdump for packet capture (no manual sudo needed)
- Cleanup trap removes capabilities on exit

### Tests
- 394 Rust lib tests, 0 failures
- 541 relay + 373 NS + 204 gateway = 1,118 Elixir tests, 0 failures (CI)

## v0.6.1 — 2026-03-13

### ZTLP Agent (NEW)
- **`ztlp proxy`** — SSH ProxyCommand for tunneling SSH through ZTLP with NS name resolution and custom domain mapping
- **Agent daemon** (`ztlp agent start/stop/status`) — background service with DNS resolver (127.0.0.53:5353), VIP pool (127.100.0.0/16), TCP proxy, control socket
- **Stream multiplexing** — STREAM_OPEN/DATA/CLOSE frame types (0x05–0x07), up to 256 concurrent streams per tunnel
- **Tunnel pool** — auto-reconnect with exponential backoff (1s–60s), keepalive (30s), idle timeout (5min)
- **Credential renewal** — cert lifecycle renewal at 67% lifetime, NS record refresh at 75% TTL, ±10% jitter, failure backoff
- **DNS TXT discovery** — `_ztlp` TXT records for automatic NS server discovery
- **System DNS setup** — `ztlp agent dns-setup/dns-teardown` for systemd-resolved, resolv.conf, macOS /etc/resolver
- **Service installer** — `ztlp agent install` generates systemd unit or macOS LaunchAgent

### Bug Fixes
- **Fixed SSH tunnel hang on reconnection** — `wait_for_reset()` silently discarded data packets during bridge transitions, causing the next bridge's reassembly to stall for 30s. Replaced with `wait_for_reset_buffered()` that captures packets during the inter-bridge gap and injects them into the next bridge. Verified with 5 consecutive SSH connections.
- **Fixed NS registration crash in demos** — v0.6.0 NS hardening rejected unsigned registrations, breaking CLI-based enrollment. Added `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false` env var for dev/demo mode.
- **Demo script resilience** — retry wrappers with 3 attempts + graceful fallback when NS registration fails.

### Tests
- 394 Rust lib tests, 70 NS hardening tests, 0 failures
- 6 new tunnel bridge transition tests
- 2 new NS unsigned registration tests
- 117 agent tests across all 5 phases

## v0.6.0 — 2026-03-13

### NS Security Hardening
- Rate limiter wired into server (was built but never called)
- Registration authentication: Ed25519 signature verification + zone authorization
- Packet/record size limits (8KB/4KB), DNS-compatible name validation
- Pubkey reverse index (Mnesia table, O(1) lookups), amplification prevention (8x threshold)
- Worker pool (Task.Supervisor, max 100), audit logging wired everywhere
- Persistent registration signing key, correct default TTLs, relay self-registration
- 68 new security hardening tests, 1,116 Elixir tests total
