# Changelog

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
