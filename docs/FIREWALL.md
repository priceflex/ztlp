# ZTLP Firewall Lockdown — Design Document

**Status:** Draft  
**Author:** Steve Price / Tech Rockstars  
**Date:** 2026-03-15

## Overview

When ZTLP protects a service (SSH, database, etc.), the underlying port should be
firewalled to reject all direct connections. The only path to the service is through
an authenticated, encrypted ZTLP tunnel.

This document specifies `ztlp firewall` — a CLI tool for managing host firewall rules
that enforce ZTLP-only access — and the **Agent Unlock Protocol**, a secure emergency
access mechanism that works entirely within the ZTLP trust model.

## Architecture

```
Internet ──► Port 22: BLOCKED (iptables/nftables DROP)
           ► Port 23095 (ZTLP): OPEN (UDP only)
                │
                ▼
           ZTLP Gateway
           ├─ L1: Magic byte check (~19ns)
           ├─ L2: SessionID lookup (~50ns)
           ├─ L3: HeaderAuthTag HMAC (~200ns)
           ├─ Noise_XX handshake
           ├─ Policy engine (identity + group check)
           └─► 127.0.0.1:22 (SSH backend, localhost only)

Emergency access:
  ztlp admin unlock ──► ZTLP tunnel ──► Agent daemon ──► iptables whitelist (TTL)
```

## CLI: `ztlp firewall`

### Subcommands

```
ztlp firewall status                      # Show current firewall rules + exposure
ztlp firewall lock                        # Lock all ZTLP-forwarded ports
ztlp firewall lock --ports 22,3306        # Lock specific ports
ztlp firewall unlock --ttl 30m            # Emergency: open all ports for 30 minutes
ztlp firewall unlock --port 22 --ttl 15m  # Open just SSH for 15 minutes
ztlp firewall whitelist add 203.0.113.50  # Permanently allow an IP
ztlp firewall whitelist add 10.0.0.0/24   # Allow a CIDR range
ztlp firewall whitelist remove 203.0.113.50
ztlp firewall whitelist list              # Show whitelisted IPs
ztlp firewall apply                       # Apply rules (writes iptables/nftables)
ztlp firewall persist                     # Save rules across reboots
ztlp firewall reset                       # Remove all ZTLP firewall rules
```

### Rule Generation

`ztlp firewall lock` generates rules equivalent to:

```bash
# Allow localhost (ZTLP backend)
iptables -A INPUT -p tcp --dport 22 -s 127.0.0.1 -j ACCEPT

# Allow whitelisted IPs
iptables -A INPUT -p tcp --dport 22 -s 203.0.113.50 -j ACCEPT

# Drop everything else
iptables -A INPUT -p tcp --dport 22 -j DROP

# ZTLP UDP port stays open
iptables -A INPUT -p udp --dport 23095 -j ACCEPT
```

All ZTLP rules use a dedicated iptables chain (`ZTLP-INPUT`) for clean management:

```bash
iptables -N ZTLP-INPUT
iptables -A INPUT -j ZTLP-INPUT
# Rules go in ZTLP-INPUT — flush/rebuild without touching other rules
```

### nftables Support

On systems using nftables, rules are generated for the `nft` backend:

```
table inet ztlp {
    chain input {
        type filter hook input priority 0; policy accept;
        tcp dport 22 ip saddr 127.0.0.1 accept
        tcp dport 22 ip saddr 203.0.113.50 accept
        tcp dport 22 drop
        udp dport 23095 accept
    }
}
```

Detection: check for `/usr/sbin/nft` or `nft --version` to auto-select backend.

### Time-Limited Unlock

`ztlp firewall unlock --ttl 30m` uses iptables `-m recent` or a background timer:

1. Insert ACCEPT rule at top of ZTLP-INPUT chain
2. Schedule removal via `at` or a background `sleep $TTL && iptables -D ...`
3. Write TTL expiry to `/run/ztlp/unlock-expires` for status display
4. `ztlp firewall status` shows countdown: "SSH unlocked — 14:32 remaining"

Maximum TTL: 4 hours (configurable). Default: 30 minutes.

## Agent Unlock Protocol

**The killer feature:** Emergency SSH access without pre-shared IP whitelists,
without touching the cloud console, without IPMI — entirely through the ZTLP
trust model.

### Threat Model

This is a privileged operation. An attacker who compromises it gets SSH access
to the target machine. The protocol must defend against:

1. **Replay attacks** — reusing a captured unlock command
2. **Man-in-the-middle** — injecting unlock commands into the ZTLP session
3. **Stolen credentials** — attacker has a valid ZTLP identity but shouldn't unlock
4. **Compromised agent** — agent daemon is modified to accept all unlocks
5. **Brute force** — hammering the unlock endpoint

### Protocol Design

```
┌──────────────────────────────────────────────────────────────────────┐
│                     AGENT UNLOCK PROTOCOL                           │
│                                                                     │
│  Admin CLI                    ZTLP Tunnel              Agent Daemon │
│  ─────────                    ───────────              ──────────── │
│                                                                     │
│  1. Build UnlockRequest       ─────────────────►                    │
│     ├─ target: server name                                          │
│     ├─ action: "unlock"                                             │
│     ├─ scope: port 22                                               │
│     ├─ ttl: 1800 (seconds)                                          │
│     ├─ source_ip: 203.0.113.50 (optional)                           │
│     ├─ nonce: 16 random bytes                                       │
│     ├─ timestamp: Unix epoch (seconds)                              │
│     └─ signature: Ed25519(admin_key, request_bytes)                 │
│                                                                     │
│                                                     2. Verify:      │
│                                                     ├─ Noise_XX     │
│                                                     │  session auth │
│                                                     │  (identity    │
│                                                     │   already     │
│                                                     │   verified)   │
│                                                     ├─ Timestamp    │
│                                                     │  within 60s   │
│                                                     ├─ Nonce not    │
│                                                     │  seen before  │
│                                                     ├─ Ed25519 sig  │
│                                                     │  valid        │
│                                                     ├─ Sender is    │
│                                                     │  role:admin   │
│                                                     │  (NS query)   │
│                                                     ├─ TTL ≤ max    │
│                                                     │  (4 hours)    │
│                                                     └─ Rate limit:  │
│                                                        3/hour       │
│                                                                     │
│                               ◄─────────────────    3. UnlockAck    │
│                                                     ├─ status: ok   │
│                                                     ├─ expires_at   │
│                                                     ├─ port: 22     │
│                                                     └─ source_ip    │
│                                                                     │
│                                                     4. Apply:       │
│                                                     ├─ iptables     │
│                                                     │  ACCEPT rule  │
│                                                     ├─ Schedule     │
│                                                     │  auto-relock  │
│                                                     └─ Audit log    │
│                                                                     │
└──────────────────────────────────────────────────────────────────────┘
```

### CLI Usage

```bash
# Unlock SSH on a remote server for 30 minutes
ztlp admin unlock demo-server.tunnel.ztlp --port 22 --ttl 30m

# Unlock for a specific source IP only
ztlp admin unlock demo-server.tunnel.ztlp --port 22 --ttl 30m --source-ip 203.0.113.50

# Check unlock status
ztlp admin unlock-status demo-server.tunnel.ztlp

# Manually relock (cancel an active unlock)
ztlp admin lock demo-server.tunnel.ztlp --port 22
```

### Security Controls

#### 1. Triple Authentication

The unlock command is authenticated at three layers:

| Layer | What | How |
|-------|------|-----|
| **Transport** | ZTLP session | Noise_XX handshake — mutual authentication, PFS |
| **Identity** | Sender's role | NS query confirms `role:admin` on the USER record |
| **Request** | Command integrity | Ed25519 signature over the full request body |

An attacker must compromise all three: a valid ZTLP session, an admin-role identity,
AND the admin's Ed25519 signing key.

#### 2. Anti-Replay

- **Nonce:** 16 random bytes, stored in a rolling window (last 1000 nonces, ~24h TTL)
- **Timestamp:** Request must be within ±60 seconds of agent's clock
- **Session binding:** Request includes the ZTLP session ID — can't be replayed on a different session

#### 3. Rate Limiting

- **Per-identity:** 3 unlock requests per hour per admin identity
- **Per-host:** 10 unlock requests per hour total (regardless of identity)
- **Lockout:** After 5 failed attempts in 1 hour, all unlock attempts rejected for 1 hour
- **Audit:** Every unlock attempt (success or failure) logged to structured audit log

#### 4. Scope Limitation

- **Port-specific:** Unlock only opens the requested port, not everything
- **Source-specific:** If `--source-ip` is set, only that IP gets access
- **Time-limited:** Maximum TTL enforced by agent (default max: 4 hours)
- **Auto-relock:** Timer fires even if agent crashes (uses systemd timer or at job)

#### 5. Agent Hardening

- **Config pinning:** Agent config includes `unlock_allowed_roles: ["admin"]` — not overridable via unlock command
- **Max TTL pinning:** Agent config sets `max_unlock_ttl: 14400` (4 hours) — request can't exceed it
- **Binary integrity:** Agent should be deployed from signed releases (future: binary attestation)
- **Audit trail:** All unlock/lock events written to `/var/log/ztlp/audit.log` with:
  - Timestamp, requester identity, source IP, port, TTL, action, result
  - Structured JSON for log aggregation (Loki, ELK, etc.)

### Wire Format

UnlockRequest (sent over encrypted ZTLP session):

```
┌────────────┬────────┬──────────────────────────┐
│ Field      │ Bytes  │ Description              │
├────────────┼────────┼──────────────────────────┤
│ type       │ 1      │ 0x20 = UNLOCK_REQUEST    │
│ version    │ 1      │ 0x01                     │
│ action     │ 1      │ 0x01=unlock 0x02=lock    │
│ port       │ 2      │ TCP port (big-endian)    │
│ ttl        │ 4      │ Seconds (big-endian)     │
│ timestamp  │ 8      │ Unix epoch (big-endian)  │
│ nonce      │ 16     │ Random bytes             │
│ session_id │ 12     │ Current ZTLP session ID  │
│ source_ip  │ 0-16   │ Optional IPv4/IPv6 addr  │
│ ip_len     │ 1      │ Length of source_ip      │
│ name_len   │ 2      │ Length of requester name  │
│ name       │ var    │ Requester ZTLP name      │
│ sig        │ 64     │ Ed25519 signature        │
└────────────┴────────┴──────────────────────────┘
```

Signature covers bytes [0..sig_offset) — everything except the signature itself.

UnlockResponse:

```
┌────────────┬────────┬──────────────────────────┐
│ Field      │ Bytes  │ Description              │
├────────────┼────────┼──────────────────────────┤
│ type       │ 1      │ 0x21 = UNLOCK_RESPONSE   │
│ status     │ 1      │ 0x00=ok 0x01-0x06=error  │
│ port       │ 2      │ TCP port                 │
│ ttl        │ 4      │ Granted TTL              │
│ expires_at │ 8      │ Unix epoch of expiry     │
│ ip_len     │ 1      │ Length of bound IP       │
│ source_ip  │ 0-16   │ Bound source IP          │
│ msg_len    │ 2      │ Length of message         │
│ message    │ var    │ Human-readable status     │
└────────────┴────────┴──────────────────────────┘
```

Status codes:
- `0x00` — Success (unlock applied)
- `0x01` — Denied: insufficient role
- `0x02` — Denied: rate limited
- `0x03` — Denied: invalid signature
- `0x04` — Denied: replay detected (nonce/timestamp)
- `0x05` — Denied: TTL exceeds maximum
- `0x06` — Denied: locked out (too many failures)

## Integration with `ztlp scan`

After locking down:

```
$ ztlp scan --target myserver.example.com --ports 22,3306 --ztlp-port 23095

ZTLP Port Exposure Scan
  Target: myserver.example.com
  TCP ports: [22, 3306]
  ZTLP port: 23095

  ✓ TCP    22  [SSH]           closed
  ✓ TCP  3306  [MySQL]         closed
  ● UDP 23095  [ZTLP]          ZTLP listener active — protected by three-layer pipeline

  ✓ No exposed services detected
    ● ZTLP listener active on UDP 23095
    → 2 port(s) closed, 1 ZTLP-protected
```

## Monitoring & Alerting

### Periodic Scan (cron)

```bash
# Run every 15 minutes, alert on exposure changes
*/15 * * * * /usr/local/bin/ztlp scan --json | /usr/local/bin/ztlp-alert-check
```

Or via ZTLP agent's built-in monitor (future):

```toml
# ~/.ztlp/agent.toml
[firewall.monitor]
enabled = true
interval = "15m"
alert_on_exposure = true
alert_webhook = "https://hooks.slack.com/..."
```

### Audit Log Format

```json
{
  "timestamp": "2026-03-15T21:30:00Z",
  "event": "unlock",
  "requester": "steve@techrockstars.ztlp",
  "requester_role": "admin",
  "target_port": 22,
  "source_ip": "203.0.113.50",
  "ttl_seconds": 1800,
  "expires_at": "2026-03-15T22:00:00Z",
  "session_id": "5a0eba38b9df8717",
  "result": "granted",
  "nonce": "a1b2c3d4e5f6..."
}
```

## Implementation Plan

### Phase 1: `ztlp firewall` CLI (iptables/nftables) ✅ Design complete
- [ ] Detect firewall backend (iptables vs nftables)
- [ ] Generate rules from ZTLP listener config (--forward ports)
- [ ] ZTLP-INPUT chain management
- [ ] Whitelist add/remove/list
- [ ] Time-limited unlock with auto-relock
- [ ] Persist rules across reboots
- [ ] `ztlp firewall status` with countdown timer

### Phase 2: Agent Unlock Protocol
- [ ] Wire format (0x20/0x21 message types)
- [ ] Agent-side handler (verify, rate-limit, apply)
- [ ] CLI `ztlp admin unlock` (sign, send, wait for ack)
- [ ] Nonce window + timestamp validation
- [ ] Role check via NS query
- [ ] Audit logging

### Phase 3: Monitoring
- [ ] `ztlp scan` cron integration
- [ ] Agent built-in periodic scan
- [ ] Webhook alerting on exposure changes
- [ ] Dashboard metrics (Prometheus/Grafana)

## Open Questions

1. **Should unlock require MFA?** Could integrate TOTP or require two separate
   admin identities to sign (M-of-N threshold). Adds security but complexity.

2. **Cloud firewall integration?** AWS Security Groups, GCP firewall rules,
   DigitalOcean firewalls — could `ztlp firewall` also manage cloud-level rules
   via API? Would need provider-specific backends.

3. **IPv6 support?** ip6tables / nftables inet family — should be included from
   the start to avoid retrofitting.

4. **Kernel-level enforcement?** eBPF could enforce firewall rules at XDP level,
   same as the DDoS pipeline — no iptables overhead. Future optimization.
