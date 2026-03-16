# ZTLP Roadmap

## Current Release: v0.9.10

---

## Completed Work

### Phase 1 — Protocol Specification ✅
- ZTLP wire protocol specification (~6,000 lines)
- Noise_XX handshake, AEAD encryption, session management
- Spec gap analysis: 58 issues found and resolved

### Phase 2 — Rust Client ✅
- Full Noise_XX handshake implementation
- eBPF/XDP L1 filter (magic byte rejection ~19ns/pkt)
- Session pipeline (L1→L2→L3 validation)
- `ztlp connect` and `ztlp listen` commands

### Phase 3 — Elixir Relay ✅
- OTP-based relay with session routing
- Consistent hash ring for relay mesh
- PathScore-based relay selection

### Phase 4 — ZTLP-NS Namespace ✅
- Mnesia-backed record store (KEY, SVC, RELAY, POLICY, etc.)
- Zone signing, record TTLs, query protocol
- Certificate renewal (RENEW 0x09)
- Device enrollment system

### Phase 5 — Gateway ✅
- Policy engine (zone, node, group-based rules)
- TCP bridge (ZTLP ↔ backend services)
- NS identity resolution for human-readable policies

### Phase 6 — Integration & Tooling ✅
- Docker full-stack deployment
- Benchmark suite (Rust + Elixir)
- Documentation site

### Phase 7 — Testing & CLI (v0.7.0) ✅
- Interop test suite (Rust ↔ Elixir)
- CLI tool with 9 subcommands
- Testing tools: `ztlp-inspect`, `ztlp-load`, `ztlp-fuzz`, `ztlp-netlab`
- Network test scenarios
- Congestion control (SACK, selective retransmit)
- NAT traversal & hole punching
- Relay data path + multi-session listener
- Anti-replay, PMTU discovery, session rekeying, relay failover (v0.7.1)

### Phase 8 — Tunnel Reliability (v0.8.0) ✅
- Advanced congestion controller (PRR, SACK scoreboard, token bucket pacing, Eifel spurious detection)
- Handshake retransmit with exponential backoff + half-open cache
- Extreme network stress test infrastructure
- Fast retransmit, corruption NACK, bounded RTO

### Phase 9 — Production Hardening ✅
- Structured logging
- Backpressure, circuit breaker, rate limiter
- NS federation
- OTP releases
- Inter-component auth
- Ops runbook + key management guide
- Prometheus metrics

### Phase 10 — Device Enrollment ✅
- Rust enrollment client
- Elixir enrollment server
- CLI enrollment wizard (token + QR code)

### NS Security Hardening (v0.6.0) ✅
- Rate limiter wired into server
- Registration auth (Ed25519 signatures + zone authorization)
- Packet/record size limits, name validation
- Pubkey reverse index, amplification prevention
- Worker pool, audit logging, persistent signing key

### ZTLP Agent (v0.6.1–v0.6.3) ✅
- SSH ProxyCommand (`ztlp proxy`)
- Agent daemon with DNS resolver (127.0.0.53:5353)
- VIP pool, TCP proxy, stream multiplexing
- Tunnel pool with auto-reconnect
- Credential renewal + NS record refresh
- DNS TXT discovery, system DNS setup
- Service installer (systemd + macOS LaunchAgent)

### Identity Model & Groups (v0.9.0) ✅
- DEVICE (0x10), USER (0x11), GROUP (0x12) NS record types
- Gateway group-based policy engine
- Admin controls: audit, revoke cascade, key management
- MSP Deployment Guide
- Bootstrap Rails web UI integration (users, devices, groups, enrollment, audit)

---

### Bootstrap ZTLP Tunnel Metrics (v0.9.10) ✅
- Gateway data path: BLAKE2s key derivation + ChaCha20-Poly1305 header auth tags (was random bytes)
- Gateway SessionID fix: use client's 12-byte SessionID (not responder's)
- Relay gateway forwarding: relay forwards handshake packets to remote gateways
- Bootstrap ZTLP connectivity indicators (green/yellow/red dots on dashboard)
- Real Prometheus metrics fetched through encrypted ZTLP tunnel
- Docker host networking for UDP, curl --http0.9 for tunnel HTTP, stderr-based readiness detection

---

## Known Issues

### Relay HELLO Routing (Bootstrap)
**Problem:** When two gateway sidecars run on different machines (NS + relay), both listen on port 23098. The relay forwards HELLO packets to the gateway, but if the relay machine also has a local gateway on 23098, the relay may forward to its own local gateway instead of the remote one. This causes Bootstrap to get metrics from the wrong component (relay metrics when expecting NS metrics, or vice versa).

**Impact:** The second health check (whichever routes through the relay) falls back to SSH because the ZTLP tunnel connects to the wrong gateway.

**Root cause:** The relay forwards based on destination address, but `127.0.0.1:23098` and `<remote_ip>:23098` both resolve to the local machine when running with host networking.

**Workaround:** Use different gateway ports per machine (e.g., NS gateway on 23098, relay gateway on 23099), or add explicit gateway address routing in the relay's forwarding logic.

**Where to fix:**
- `relay/lib/ztlp_relay/gateway_forwarder.ex` — needs to check if destination IP matches local vs remote
- `bootstrap/app/services/health_checker.rb` — could pass explicit gateway port per machine
- Alternative: configure each gateway with a unique port

---

## Future Work

### External IdP Integration
- OIDC/SAML/LDAP authentication at enrollment time
- Google Workspace, Azure AD/Entra, Okta integration
- Bootstrap Server handles IdP dance during enrollment
- **Scope:** `FEATURE-USER-IDENTITY.md` Phase D (IdP portion)

### Application-Layer User Authentication
- AUTH_TOKEN frame for per-user identity at the tunnel level
- Gateway-injected identity headers (X-ZTLP-User)
- OIDC browser flow for enterprise SSO
- **Spec:** `docs/SPEC-USER-AUTH.md`

### Post-Quantum Migration
- Hybrid Noise_XX with ML-KEM/ML-DSA
- Design documented in `PQ-MIGRATION.md`
- Implementation not started

### Go SDK
- `sdk/go/` scaffolding exists
- Needs completion and testing

### Production Deployments
- Real customer network deployments
- Production monitoring and operations validation

### Bootstrap Server Standalone
- Extract as standalone product (separate repo: `priceflex/ztlp-bootstrap`)
- Hosted SaaS option for MSPs

### Community & Open Source
- Whitepaper publication
- Community adoption
- Open-source launch
