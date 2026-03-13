# Changelog

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
