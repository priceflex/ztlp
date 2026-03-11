# Good First Issues

Well-scoped issues for new ZTLP contributors. Each has clear acceptance criteria and pointers to the relevant code.

---

## Easy (Documentation & Testing)

### 1. Add IPv6 examples to CLI.md

**Description**: The CLI reference (`CLI.md`) only shows IPv4 examples. Add IPv6 equivalents for all connection examples.

**Acceptance criteria**:
- Every `ztlp connect` and `ztlp listen` example has an IPv6 variant
- Note any IPv6 limitations (eBPF filter is IPv4-only currently)

**Files**: `CLI.md`
**Difficulty**: 🟢 Easy
**Skills**: Markdown, basic networking

---

### 2. Add `--json` output flag to ztlp-inspect

**Description**: The `ztlp-inspect` packet decoder (`proto/src/bin/ztlp-inspect.rs`) currently has 3 output modes (brief, detailed, hex). Add a `--json` mode that outputs each decoded packet as a JSON object — useful for piping into `jq` or log aggregators.

**Acceptance criteria**:
- New `--format json` flag
- Each packet outputs one JSON line (NDJSON)
- All header fields are included as JSON keys
- Existing modes unchanged

**Files**: `proto/src/bin/ztlp-inspect.rs`
**Difficulty**: 🟢 Easy
**Skills**: Rust, JSON formatting

---

### 3. Write a "Getting Started" tutorial

**Description**: Create `docs/GETTING-STARTED.md` — a step-by-step tutorial that walks a new user through:
1. Building ZTLP from source
2. Generating identity keys
3. Starting an NS server
4. Starting a relay
5. Connecting two clients through the relay
6. Verifying encrypted communication

**Acceptance criteria**:
- Works on a fresh Ubuntu 22.04+ machine
- All commands are copy-pasteable
- Expected output is shown for each step
- Takes under 15 minutes to follow

**Files**: New `docs/GETTING-STARTED.md`
**Difficulty**: 🟢 Easy
**Skills**: Technical writing, basic Linux

---

### 4. Add rate limiter tuning guide to ops runbook

**Description**: The ops runbook (`docs/OPS-RUNBOOK.md`) doesn't have guidance on tuning the NS query rate limiter. Add a section covering:
- How the token bucket works
- How to set appropriate limits for different deployment sizes
- Monitoring rate limit metrics
- What to do when legitimate traffic is being limited

**Acceptance criteria**:
- New section in `docs/OPS-RUNBOOK.md`
- References actual config keys and Prometheus metrics
- Includes example configs for small (10 nodes), medium (100), and large (1000+)

**Files**: `docs/OPS-RUNBOOK.md`, reference `ns/lib/ztlp_ns/rate_limiter.ex`
**Difficulty**: 🟢 Easy
**Skills**: Technical writing, understanding of rate limiting

---

### 5. Add more Docker network test scenarios

**Description**: The Docker test suite (`tests/network/`) has 14 scenarios. Ideas for more:
- **Gateway failover**: Kill a gateway, verify clients reconnect
- **Relay mesh rebalancing**: Remove a relay from mesh, verify sessions migrate
- **High-concurrency**: 50+ simultaneous client connections
- **Long-running stability**: 5-minute sustained traffic test

**Acceptance criteria**:
- At least 2 new scenarios
- Follow existing pattern (use `common.sh` and `assert.sh`)
- Pass when run standalone and in full suite
- Update `run-all.sh` scenario list

**Files**: `tests/network/scenarios/`, `tests/network/run-all.sh`
**Difficulty**: 🟡 Medium
**Skills**: Bash, Docker, networking

---

### 6. Improve error messages in Rust CLI

**Description**: The `ztlp` CLI (`proto/src/bin/ztlp-cli.rs`) sometimes shows raw error types instead of user-friendly messages. Audit all error paths and improve messages.

**Acceptance criteria**:
- No `Debug` format errors shown to users
- Connection failures show actionable advice (e.g., "Connection refused — is the relay running?")
- Timeout errors show what was being waited on
- Add `--verbose` flag for full error details when debugging

**Files**: `proto/src/bin/ztlp-cli.rs`, `proto/src/error.rs`
**Difficulty**: 🟢 Easy
**Skills**: Rust, error handling

---

## Medium (Code Changes)

### 7. Add `--timeout` flag to CLI connect command

**Description**: `ztlp connect` currently uses a hardcoded timeout. Add a `--timeout <seconds>` flag with a reasonable default (e.g., 30s).

**Acceptance criteria**:
- `--timeout` flag on `connect`, `ping`, and `status` subcommands
- Default timeout of 30 seconds
- Timeout error message is clear
- Updated in `CLI.md`

**Files**: `proto/src/bin/ztlp-cli.rs`
**Difficulty**: 🟡 Medium
**Skills**: Rust, CLI design

---

### 8. Connection retry with exponential backoff

**Description**: The Rust client's `transport.rs` doesn't retry failed connections. Implement exponential backoff with jitter for `Dial` and `DialRelay`.

**Acceptance criteria**:
- Configurable max retries (default 3)
- Exponential backoff: 100ms → 200ms → 400ms (with ±25% jitter)
- Configurable via builder pattern on Client
- Tests for retry logic (mock transport)

**Files**: `proto/src/transport.rs`, `proto/src/client.rs`
**Difficulty**: 🟡 Medium
**Skills**: Rust, async, networking

---

### 9. Configurable anti-entropy interval per zone (NS)

**Description**: Currently anti-entropy runs at a single global interval. Allow per-zone configuration so high-priority zones sync more frequently.

**Acceptance criteria**:
- Config key: `anti_entropy.zone_intervals` (map of zone → interval_ms)
- Default falls back to global interval
- Tests showing different zones sync at different rates

**Files**: `ns/lib/ztlp_ns/anti_entropy.ex`, `ns/lib/ztlp_ns/config.ex`
**Difficulty**: 🟡 Medium
**Skills**: Elixir, OTP (GenServer)

---

### 10. Session count limit per source IP (relay)

**Description**: The relay doesn't limit how many sessions a single source IP can establish. Add a configurable per-IP session limit to prevent resource exhaustion.

**Acceptance criteria**:
- Config key: `max_sessions_per_ip` (default: 100)
- Tracked in ETS (fast, lockless)
- Reject HELLO with a specific error when limit exceeded
- Counter decremented on session close
- Tests for limit enforcement and cleanup

**Files**: `relay/lib/ztlp_relay/session_registry.ex`, `relay/lib/ztlp_relay/config.ex`
**Difficulty**: 🟡 Medium
**Skills**: Elixir, ETS

---

### 11. Graceful shutdown for gateway (drain connections)

**Description**: The gateway currently stops immediately on SIGTERM. Implement graceful shutdown: stop accepting new connections, wait for existing ones to finish (with timeout), then exit.

**Acceptance criteria**:
- Trap SIGTERM in the application
- Stop accepting new ZTLP handshakes
- Wait up to N seconds (configurable) for active bridges to close
- Force-close remaining after timeout
- Log progress during drain
- Tests for drain lifecycle

**Files**: `gateway/lib/ztlp_gateway/application.ex`, `gateway/lib/ztlp_gateway/bridge.ex`
**Difficulty**: 🟡 Medium
**Skills**: Elixir, OTP supervision, signals

---

### 12. Add `--watch` mode to ztlp-inspect

**Description**: The packet inspection tool currently processes a file or stdin. Add `--watch <interface>` mode that captures live ZTLP traffic using raw sockets and decodes in real-time.

**Acceptance criteria**:
- `--watch eth0` flag (requires root/CAP_NET_RAW)
- Filter to UDP port 23095/23096 only
- Real-time decode with timestamps
- Ctrl+C for clean exit with summary stats
- Works with `--format` flag (brief/detailed/hex/json)

**Files**: `proto/src/bin/ztlp-inspect.rs`
**Difficulty**: 🟡 Medium
**Skills**: Rust, raw sockets, networking

---

### 13. Prometheus push gateway support

**Description**: The built-in metrics servers are pull-based (scrape). For short-lived processes (CI benchmarks, test runs), add optional push support to a Prometheus Pushgateway.

**Acceptance criteria**:
- Config key: `metrics.push_gateway_url`
- Push on shutdown (at minimum)
- Optional periodic push interval
- Works for all 3 services
- Documentation in ops runbook

**Files**: `relay/lib/ztlp_relay/metrics_server.ex`, `gateway/lib/ztlp_gateway/metrics_server.ex`, `ns/lib/ztlp_ns/metrics_server.ex`
**Difficulty**: 🟡 Medium
**Skills**: Elixir, HTTP client (`:httpc`), Prometheus

---

## Hard (Deep Protocol Knowledge)

### 14. IPv6 support for eBPF filter

**Description**: The XDP filter (`ebpf/ztlp_xdp.c`) only handles IPv4 (`ETH_P_IP`). Add IPv6 support:
- Parse `struct ipv6hdr` after `ETH_P_IPV6`
- Handle IPv6 extension headers (skip to UDP)
- IPv6 source address for HELLO rate limiting (use /64 prefix as key)

**Acceptance criteria**:
- IPv6 packets processed alongside IPv4
- Rate limiting uses /64 prefix (not full /128)
- All existing IPv4 tests still pass
- New test cases for IPv6

**Files**: `ebpf/ztlp_xdp.c`, `ebpf/ztlp_xdp.h`, `ebpf/loader.c`
**Difficulty**: 🔴 Hard
**Skills**: C, eBPF/XDP, IPv6, BPF verifier

---

### 15. Post-quantum key exchange exploration

**Description**: Research and prototype a post-quantum hybrid key exchange for ZTLP. The Noise framework supports custom DH functions — explore adding Kyber/ML-KEM alongside X25519 for quantum-resistant forward secrecy.

**Acceptance criteria**:
- Research document in `docs/POST-QUANTUM.md`
- Prototype in a separate branch
- Benchmark overhead vs pure X25519
- Backward compatibility plan (version negotiation)

**Files**: New `docs/POST-QUANTUM.md`, `proto/src/handshake.rs`
**Difficulty**: 🔴 Hard
**Skills**: Cryptography, Noise framework, Rust

---

### 16. Hardware key (YubiKey) support in CLI

**Description**: Allow the CLI to use a YubiKey for Ed25519 signing operations (identity, zone authority). Use the PIV or FIDO2 interface.

**Acceptance criteria**:
- `ztlp keygen --yubikey` stores key on device
- `ztlp connect --yubikey` uses hardware-backed identity
- Falls back to file-based keys gracefully
- Works with YubiKey 5 series
- Document setup in `docs/KEY-MANAGEMENT.md`

**Files**: `proto/src/identity.rs`, `proto/src/bin/ztlp-cli.rs`
**Difficulty**: 🔴 Hard
**Skills**: Rust, YubiKey/PKCS#11, Ed25519

---

### 17. QUIC transport alternative

**Description**: ZTLP currently uses raw UDP. Explore adding QUIC as an alternative transport — this would give built-in congestion control, connection migration, and multiplexing while keeping the ZTLP identity layer on top.

**Acceptance criteria**:
- Design document in `docs/QUIC-TRANSPORT.md`
- Prototype using quinn (Rust) or quic-go (Go)
- Benchmark vs raw UDP
- Analyze what ZTLP features become redundant with QUIC

**Files**: New `docs/QUIC-TRANSPORT.md`, `proto/src/transport.rs`
**Difficulty**: 🔴 Hard
**Skills**: QUIC protocol, Rust or Go, transport layer design

---

### 18. DNS-SD bootstrap for relay discovery

**Description**: Add DNS-based Service Discovery (RFC 6763) as a relay discovery mechanism. Relays would register `_ztlp._udp.example.com` SRV records, and clients could discover them without hardcoded addresses.

**Acceptance criteria**:
- Client: DNS-SD query for `_ztlp._udp.<domain>`
- Relay: optional DNS-SD registration on startup
- Falls back to static config if DNS-SD unavailable
- Tests with mock DNS
- Document in CLI.md and ops runbook

**Files**: `proto/src/transport.rs`, `relay/lib/ztlp_relay/config.ex`
**Difficulty**: 🟡 Medium–Hard
**Skills**: DNS, SRV records, Rust or Elixir

---

## How to Pick an Issue

1. **New to the project?** Start with 🟢 Easy issues — they're documentation or well-contained code changes
2. **Comfortable with Elixir/Rust?** Try 🟡 Medium issues — they touch core modules but have clear scope
3. **Want a challenge?** 🔴 Hard issues require deep protocol understanding but are high-impact

Before starting, comment on the issue to avoid duplicate work. Ask questions in [Discord](https://discord.com/invite/clawd) — we're happy to help.

---

*Last updated: 2026-03-11 — ZTLP v0.4.1*
