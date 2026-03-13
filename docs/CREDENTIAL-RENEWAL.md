# ZTLP Credential Renewal — Design & Implementation

Comprehensive design for automated credential lifecycle management across
all ZTLP components: certificates, NS records, Relay Admission Tokens,
and enrollment tokens.

**Audience:** Protocol implementors, bootstrap server developers, operators.

> **See also:** [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md) ·
> [OPS-RUNBOOK.md](OPS-RUNBOOK.md) · [README.md (§16.2.1)](../README.md)

---

## Table of Contents

1. [Overview](#1-overview)
2. [Credential Types and Lifetimes](#2-credential-types-and-lifetimes)
3. [Certificate Renewal Protocol](#3-certificate-renewal-protocol)
4. [NS Record Auto-Refresh](#4-ns-record-auto-refresh)
5. [RAT Secret Rotation](#5-rat-secret-rotation)
6. [Enrollment Token Lifecycle](#6-enrollment-token-lifecycle)
7. [Session Key Rekeying](#7-session-key-rekeying)
8. [Bootstrap Server Integration](#8-bootstrap-server-integration)
9. [Node Agent Design](#9-node-agent-design)
10. [Failure Modes and Recovery](#10-failure-modes-and-recovery)
11. [Monitoring and Alerting](#11-monitoring-and-alerting)
12. [Implementation Roadmap](#12-implementation-roadmap)

---

## 1. Overview

ZTLP has five distinct credential types, each with different lifetimes,
renewal mechanisms, and failure characteristics:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Credential Lifecycle Map                      │
├────────────────────┬────────────┬───────────┬──────────────────┤
│ Credential         │ Lifetime   │ Renewal   │ Failure Mode     │
├────────────────────┼────────────┼───────────┼──────────────────┤
│ Node Certificate   │ ≤90 days   │ RENEW msg │ Can't establish  │
│                    │            │ (0x09)    │ new sessions     │
├────────────────────┼────────────┼───────────┼──────────────────┤
│ NS Records         │ 1h – 24h   │ Re-publish│ Node invisible   │
│ (KEY/SVC/RELAY)    │            │           │ to network       │
├────────────────────┼────────────┼───────────┼──────────────────┤
│ RAT Secrets        │ Weeks      │ Dual-key  │ Relay rejects    │
│ (Relay symmetric)  │            │ rotation  │ new admissions   │
├────────────────────┼────────────┼───────────┼──────────────────┤
│ Enrollment Tokens  │ Hours–days │ Regenerate│ Can't onboard    │
│                    │            │           │ new devices      │
├────────────────────┼────────────┼───────────┼──────────────────┤
│ Session Keys       │ ≤24 hours  │ REKEY msg │ Session drops    │
│ (ephemeral)        │            │ (0x03)    │ if missed        │
└────────────────────┴────────────┴───────────┴──────────────────┘
```

The golden rule: **credentials should renew themselves automatically;
operators should only intervene for revocation and policy changes.**

---

## 2. Credential Types and Lifetimes

### 2.1 Node Certificates

Certificates are the primary identity credential. They bind a NodeID to
a cryptographic keypair and are signed by an Enrollment Authority.

| Field | Value |
|-------|-------|
| Format | Signed CBOR (RFC 8949) |
| Max TTL | 90 days (SHOULD NOT exceed) |
| Recommended TTL | 30 days (standard), 24 hours (high-security) |
| Renewal window | After 2/3 of lifetime elapsed |
| Renewal mechanism | RENEW wire message (0x09) to NS |
| Key preserved | NodeID: yes. Ed25519: yes. X25519: optionally rotated. |

**Critical insight:** An expired certificate does NOT affect existing
sessions (they use ephemeral session keys). It only prevents
establishing NEW sessions. This means renewal failures are not
immediately catastrophic but degrade over time as sessions close.

### 2.2 NS Records

NS records make a node discoverable on the network. Without valid
records, peers cannot find the node's address or verify its public key.

| Record | Default TTL | Refresh at | Effect of expiry |
|--------|-------------|------------|------------------|
| ZTLP_KEY | 86,400s (24h) | 18h (75%) | Node's key not resolvable |
| ZTLP_SVC | 86,400s (24h) | 18h (75%) | Node's service address not resolvable |
| ZTLP_RELAY | 3,600s (1h) | 45min (75%) | Relay drops out of mesh discovery |
| ZTLP_BOOTSTRAP | 86,400s (24h) | 18h (75%) | New nodes can't bootstrap |
| ZTLP_REVOKE | 0 (never) | N/A | Revocations are permanent |

### 2.3 RAT Secrets

Relay Admission Tokens use symmetric HMAC-BLAKE2s keys shared across
relay nodes. The relay supports dual-key rotation for zero-downtime
secret changes.

| Parameter | Default | Recommended |
|-----------|---------|-------------|
| Token TTL | 300s (5 min) | 300–900s |
| Secret rotation | Manual | Weekly–monthly |
| Dual-key window | 1× token TTL | 300–900s after rotation |

### 2.4 Session Keys

Session keys are ephemeral, derived via Noise_XX handshake, and
rekeyed within the session. This is the only credential type that is
fully automated today.

| Parameter | Value |
|-----------|-------|
| Max session lifetime | 24 hours |
| Rekeying interval | 1 hour (CryptoSuite default) |
| Rekeying trigger | Time-based, sequence-based, or explicit REKEY |
| Rekey mechanism | In-session Noise_XX renegotiation (MsgType 3) |

---

## 3. Certificate Renewal Protocol

### 3.1 Wire Protocol

Defined in the spec at Section 16.2.1.2. Summary:

```
Node                                      NS Server
  │                                           │
  │  ──── RENEW (0x09) ────────────────────►  │
  │       NodeID + zone + serial              │
  │       + optional new X25519 key           │
  │       + timestamp                         │
  │       + Ed25519 signature (proof of       │
  │         possession of current key)        │
  │                                           │
  │  ◄─── RENEW_RESPONSE (0x0A) ──────────   │
  │       Result code + new certificate       │
  │       (or error code)                     │
  │                                           │
```

### 3.2 NS Server Implementation

The NS server needs a new handler for message type 0x09:

```elixir
# ns/lib/ztlp_ns/renewal.ex

defmodule ZtlpNs.Renewal do
  @moduledoc """
  Certificate renewal handler.

  Validates proof-of-possession, checks eligibility window,
  issues a new certificate with incremented serial.
  """

  alias ZtlpNs.{Store, Record, Certificate}

  @clock_skew_tolerance 300  # 5 minutes
  @rate_limit_window 3600    # 1 hour
  @max_renewals_per_window 3

  @type renewal_result ::
    {:ok, binary()}           # New signed certificate
    | {:error, :not_eligible}
    | {:error, :revoked}
    | {:error, :expired}
    | {:error, :bad_signature}
    | {:error, :clock_skew, integer()}
    | {:error, :rate_limited, integer()}

  @spec handle_renewal(binary()) :: renewal_result()
  def handle_renewal(request_bytes) do
    with {:ok, request} <- parse_request(request_bytes),
         :ok <- check_clock_skew(request.timestamp),
         :ok <- check_rate_limit(request.node_id),
         {:ok, current_cert} <- lookup_current_cert(request),
         :ok <- verify_not_revoked(request.node_id),
         :ok <- verify_signature(request, current_cert),
         :ok <- check_renewal_window(current_cert) do
      issue_renewed_cert(current_cert, request)
    end
  end

  defp check_renewal_window(cert) do
    now = System.system_time(:second)
    total_lifetime = cert.not_after - cert.not_before
    earliest_renewal = cert.not_before + div(total_lifetime, 3)

    cond do
      now < earliest_renewal -> {:error, :not_eligible}
      now > cert.not_after   -> {:error, :expired}
      true                   -> :ok
    end
  end

  defp issue_renewed_cert(current_cert, request) do
    new_cert = %{current_cert |
      serial: current_cert.serial + 1,
      issued_at: System.system_time(:second),
      not_before: System.system_time(:second),
      not_after: System.system_time(:second) + original_ttl(current_cert),
      pubkey_x25519: request.new_x25519_key || current_cert.pubkey_x25519
    }

    signed = Certificate.sign(new_cert, authority_key())
    Store.put_key_record(new_cert.zone, new_cert.node_id, signed)
    {:ok, signed}
  end
end
```

### 3.3 Client Implementation

The Rust client needs a renewal command and daemon mode:

```rust
// proto/src/renewal.rs

pub struct RenewalConfig {
    pub identity_path: PathBuf,
    pub ns_server: SocketAddr,
    pub zone: String,
    /// Check interval (default: 1 hour)
    pub check_interval: Duration,
}

pub async fn renewal_daemon(config: RenewalConfig) -> Result<(), Error> {
    loop {
        let cert = load_certificate(&config.identity_path)?;
        let remaining = cert.not_after - now_unix();
        let total = cert.not_after - cert.not_before;
        let threshold = total / 3;  // Renew after 2/3 elapsed

        if remaining <= threshold {
            match attempt_renewal(&config, &cert).await {
                Ok(new_cert) => {
                    save_certificate(&config.identity_path, &new_cert)?;
                    info!("Certificate renewed, serial={}, expires={}",
                          new_cert.serial, new_cert.not_after);
                }
                Err(RenewalError::NotEligible) => {
                    debug!("Not yet in renewal window");
                }
                Err(RenewalError::RateLimited(retry_after)) => {
                    warn!("Rate limited, retrying in {}s", retry_after);
                    sleep(Duration::from_secs(retry_after)).await;
                    continue;
                }
                Err(e) => {
                    error!("Renewal failed: {}, retrying with backoff", e);
                    // Exponential backoff: 1m, 5m, 15m, 1h, then hourly
                }
            }
        }

        sleep(config.check_interval).await;
    }
}
```

### 3.4 CLI Integration

```bash
# One-shot renewal
ztlp renew --ns-server 10.0.0.5:23096 --zone corp.ztlp

# Daemon mode (runs in background, auto-renews)
ztlp renew --daemon --ns-server 10.0.0.5:23096 --zone corp.ztlp

# Check renewal status
ztlp status --cert
#   NodeID:     aabbccdd11223344...
#   Serial:     7
#   Issued:     2026-03-01 00:00:00 UTC
#   Expires:    2026-05-30 00:00:00 UTC
#   Remaining:  78 days
#   Renewal at: 2026-04-30 00:00:00 UTC (in 18 days)
#   Status:     ✓ Valid
```

---

## 4. NS Record Auto-Refresh

### 4.1 Refresh Logic

Every ZTLP node that registers NS records MUST run a refresh loop:

```
┌──────────────────────────────────────────────────────────┐
│                NS Record Refresh Loop                     │
│                                                          │
│  1. Calculate next_refresh = last_registered + (TTL × ¾) │
│  2. Add jitter: ± (TTL × 0.10) × random()               │
│  3. Sleep until next_refresh                              │
│  4. Re-register all records (KEY, SVC, RELAY)            │
│  5. On failure: exponential backoff (1m → 5m → 15m → 1h) │
│  6. On success: goto 1                                   │
│  7. On record expired: re-register immediately           │
│     (no token needed — identity is preserved)            │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Jitter Calculation

Without jitter, a fleet of 1,000 nodes with 24h KEY TTLs that were all
deployed at the same time would all refresh simultaneously every 18
hours — hammering the NS server with 1,000 REGISTER messages in
seconds.

```
jitter_range = TTL × 0.10
jitter = (random_float() × 2.0 - 1.0) × jitter_range
next_refresh = last_registered + (TTL × 0.75) + jitter
```

For a 24h TTL: refresh between 16.2h and 19.8h after registration.

### 4.3 Implementation Notes

**Server (`ztlp listen`):** The server entrypoint should spawn a
background refresh task after initial registration. In Rust:

```rust
tokio::spawn(async move {
    let mut interval = record_refresh_interval(record_ttl);
    loop {
        interval.tick().await;
        if let Err(e) = refresh_ns_records(&ns_config).await {
            warn!("NS refresh failed: {}, retrying", e);
            backoff_retry(|| refresh_ns_records(&ns_config)).await;
        }
    }
});
```

**Relay (Elixir):** Add a GenServer that refreshes RELAY records:

```elixir
defmodule ZtlpRelay.NsRefresher do
  use GenServer

  @refresh_ratio 0.75
  @jitter_ratio  0.10

  def init(config) do
    schedule_refresh(config.relay_ttl)
    {:ok, config}
  end

  def handle_info(:refresh, config) do
    case NsClient.register_relay(config) do
      :ok ->
        schedule_refresh(config.relay_ttl)
      {:error, reason} ->
        Logger.warning("NS refresh failed: #{reason}")
        schedule_retry()
    end
    {:noreply, config}
  end

  defp schedule_refresh(ttl) do
    base = trunc(ttl * @refresh_ratio * 1000)
    jitter = trunc(ttl * @jitter_ratio * 1000)
    delay = base + :rand.uniform(jitter * 2) - jitter
    Process.send_after(self(), :refresh, delay)
  end
end
```

---

## 5. RAT Secret Rotation

RAT rotation is already implemented with dual-key support
(see KEY-MANAGEMENT.md §3). The bootstrap server automates this:

### 5.1 Automated Rotation Flow

```
Bootstrap Server                    Relay Node (via SSH)
      │                                    │
      │  1. Generate new secret            │
      │  2. Read current secret            │
      │                                    │
      │  ── SSH: update relay.env ───────► │
      │     ZTLP_RELAY_RAT_SECRET=new     │
      │     ZTLP_RELAY_RAT_SECRET_PREVIOUS=old
      │                                    │
      │  ── SSH: reload relay ───────────► │
      │     (SIGHUP or rolling restart)    │
      │                                    │
      │  3. Wait token_ttl (5 min)         │
      │                                    │
      │  ── SSH: clear previous key ─────► │
      │     ZTLP_RELAY_RAT_SECRET_PREVIOUS=
      │                                    │
      │  4. Log rotation to audit trail    │
      │                                    │
```

### 5.2 Mesh RAT Rotation

In mesh mode, ALL relays must share the same RAT secret. The bootstrap
server must rotate secrets across the entire mesh atomically:

1. **Phase 1 (Prepare):** Push new secret to all relays as `rat_secret`,
   move old to `rat_secret_previous`. Reload all relays.
2. **Phase 2 (Wait):** Wait for `max(token_ttl)` across all relays
   (default 300s). During this window, both old and new tokens are valid.
3. **Phase 3 (Cleanup):** Clear `rat_secret_previous` from all relays.

If any relay fails to rotate in Phase 1, the bootstrap server MUST
roll back the entire operation (restore the old secret on relays that
already rotated).

---

## 6. Enrollment Token Lifecycle

Enrollment tokens are intentionally short-lived and usage-limited.
They are NOT renewed — new tokens are generated when needed.

### 6.1 Token Lifecycle

```
Admin generates token
    │
    ▼
Token delivered to device operator
(QR code, secure message, ztlp:// URI)
    │
    ▼
Device presents token to NS ──────────► NS validates:
    │                                    - MAC valid?
    │                                    - Not expired?
    │                                    - Uses remaining?
    │                                    - Zone matches?
    │                                    - Nonce not replayed?
    ▼
Device enrolled ──► Certificate issued ──► Node joins network
    │
    ▼
Token tracked (nonce, usage count)
```

### 6.2 Bootstrap Server Token Management

The bootstrap server tracks tokens in its database:

```ruby
# bootstrap/app/models/enrollment_token.rb
class EnrollmentToken < ApplicationRecord
  belongs_to :network

  validates :zone, :expires_at, :max_uses, presence: true
  encrypts :secret_mac  # Encrypted at rest

  scope :active, -> {
    where("expires_at > ? AND uses_count < max_uses", Time.current)
  }
  scope :expired, -> {
    where("expires_at <= ? OR uses_count >= max_uses", Time.current)
  }

  def expired?
    expires_at <= Time.current || uses_count >= max_uses
  end

  def remaining_uses
    [max_uses - uses_count, 0].max
  end

  def remaining_time
    [expires_at - Time.current, 0].max
  end
end
```

---

## 7. Session Key Rekeying

Already fully implemented. Sessions rekey automatically every hour
(CryptoSuite default) or when the packet sequence approaches 2^48.
See README.md Section 35.2 for the wire protocol.

No changes needed — this is the one credential type that already
manages itself.

---

## 8. Bootstrap Server Integration

The bootstrap server is the centralized management plane for credential
lifecycle. Here's how it manages each credential type:

### 8.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Bootstrap Server (Rails)                    │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Certificate  │  │  NS Record   │  │    RAT       │      │
│  │  Renewal      │  │  Monitor     │  │  Rotation    │      │
│  │  Scheduler    │  │              │  │  Scheduler   │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                  │               │
│         ▼                 ▼                  ▼               │
│  ┌─────────────────────────────────────────────────┐        │
│  │              SSH Provisioner                      │        │
│  │  (executes commands on managed nodes via SSH)     │        │
│  └──────────────────────┬──────────────────────────┘        │
│                         │                                    │
└─────────────────────────┼────────────────────────────────────┘
                          │ SSH
                          ▼
              ┌──────────────────────┐
              │    Managed Nodes     │
              │                      │
              │  ┌─────┐ ┌────────┐ │
              │  │ ztlp │ │ relay  │ │
              │  │ cli  │ │ (OTP)  │ │
              │  └──────┘ └────────┘ │
              └──────────────────────┘
```

### 8.2 Certificate Renewal Scheduler

```ruby
# bootstrap/app/services/certificate_renewal_scheduler.rb

class CertificateRenewalScheduler
  RENEWAL_THRESHOLD = 2.0 / 3.0  # Renew after 2/3 lifetime elapsed
  CHECK_INTERVAL = 1.hour

  def initialize
    @checker = HealthChecker.new
  end

  # Called by Sidekiq scheduler every hour
  def perform
    Machine.active.with_role(:any).find_each do |machine|
      cert_info = fetch_cert_info(machine)
      next unless cert_info

      if needs_renewal?(cert_info)
        renew_certificate(machine, cert_info)
      end
    end
  end

  private

  def fetch_cert_info(machine)
    # SSH into machine, run `ztlp status --cert --json`
    result = SshProvisioner.new(machine).execute(
      "ztlp status --cert --json"
    )
    JSON.parse(result.stdout)
  rescue => e
    AuditLog.create!(
      action: "cert_check_failed",
      machine: machine,
      details: e.message
    )
    nil
  end

  def needs_renewal?(cert_info)
    not_before = cert_info["not_before"]
    not_after = cert_info["not_after"]
    total = not_after - not_before
    threshold = not_before + (total * RENEWAL_THRESHOLD)

    Time.now.to_i >= threshold
  end

  def renew_certificate(machine, cert_info)
    result = SshProvisioner.new(machine).execute(
      "ztlp renew " \
      "--ns-server #{machine.network.ns_address} " \
      "--zone #{machine.network.zone}"
    )

    if result.success?
      AuditLog.create!(
        action: "cert_renewed",
        machine: machine,
        details: "Serial #{cert_info['serial']} → #{cert_info['serial'] + 1}"
      )
    else
      AuditLog.create!(
        action: "cert_renewal_failed",
        machine: machine,
        details: result.stderr
      )
      notify_operator(machine, result.stderr)
    end
  end
end
```

### 8.3 NS Record Monitor

```ruby
# bootstrap/app/services/ns_record_monitor.rb

class NsRecordMonitor
  # Called by Sidekiq scheduler every 15 minutes
  def perform
    Machine.active.find_each do |machine|
      check_ns_records(machine)
    end
  end

  private

  def check_ns_records(machine)
    ns_server = machine.network.ns_address

    # Check KEY record
    key_result = lookup_record(machine.ztlp_name, :key, ns_server)
    unless key_result[:found]
      handle_missing_record(machine, :key)
    end

    # Check SVC record (if machine has a service role)
    if machine.roles.include?("gateway") || machine.roles.include?("relay")
      svc_result = lookup_record(machine.ztlp_name, :svc, ns_server)
      unless svc_result[:found]
        handle_missing_record(machine, :svc)
      end
    end
  end

  def handle_missing_record(machine, record_type)
    AuditLog.create!(
      action: "ns_record_missing",
      machine: machine,
      details: "#{record_type} record not found — triggering re-registration"
    )

    # SSH in and re-register
    SshProvisioner.new(machine).execute(
      "ztlp ns register " \
      "--name #{machine.ztlp_name} " \
      "--zone #{machine.network.zone} " \
      "--ns-server #{machine.network.ns_address}"
    )
  end
end
```

### 8.4 Dashboard Integration

The bootstrap server dashboard should show credential health:

```
┌─────────────────────────────────────────────────────────────┐
│  Credential Health                                           │
├───────────────┬────────┬────────────┬───────────┬───────────┤
│ Machine       │ Cert   │ NS Records │ RAT       │ Status    │
├───────────────┼────────┼────────────┼───────────┼───────────┤
│ ns1.corp      │ 72d ✅ │ KEY ✅     │ N/A       │ Healthy   │
│ relay1.corp   │ 28d ⚠️ │ KEY ✅     │ 3d ago ✅ │ Renewing  │
│               │        │ RELAY ✅   │           │           │
│ gw1.corp      │ 89d 🔴│ KEY ❌     │ N/A       │ Critical  │
│               │        │ SVC ❌     │           │           │
│ client1.corp  │ 45d ✅ │ KEY ✅     │ N/A       │ Healthy   │
└───────────────┴────────┴────────────┴───────────┴───────────┘

Legend: ✅ Healthy  ⚠️ Renewal due  🔴 Expired/missing  ❌ Not found
```

---

## 9. Node Agent Design

For environments where the bootstrap server can't SSH in (firewalled
nodes, IoT devices), nodes should run a local agent:

### 9.1 `ztlp-agent` Daemon

A lightweight daemon that handles all credential lifecycle:

```
ztlp-agent
  ├── CertRenewer        — Watches cert expiry, sends RENEW to NS
  ├── NsRefresher        — Re-publishes KEY/SVC records at 75% TTL
  ├── HealthReporter     — Reports metrics to bootstrap server (opt-in)
  └── ConfigWatcher      — Watches config file for changes, hot-reloads
```

### 9.2 Configuration

```toml
# ~/.ztlp/agent.toml

[identity]
path = "~/.ztlp/identity.json"

[ns]
server = "10.0.0.5:23096"
zone = "corp.ztlp"

[renewal]
# Auto-renew certificates (default: true)
enabled = true
# Check interval (default: 1h)
check_interval = "1h"
# Renewal threshold as fraction of lifetime (default: 0.67)
threshold = 0.67

[ns_refresh]
# Auto-refresh NS records (default: true)
enabled = true
# Jitter ratio (default: 0.10)
jitter = 0.10

[health]
# Report to bootstrap server (optional)
bootstrap_url = "https://bootstrap.corp.ztlp:3000"
report_interval = "5m"
```

### 9.3 Systemd Integration

```ini
# /etc/systemd/system/ztlp-agent.service

[Unit]
Description=ZTLP Credential Agent
After=network-online.target
Wants=network-online.target
Documentation=https://ztlp.org/docs/credential-renewal

[Service]
Type=notify
User=ztlp
Group=ztlp
ExecStart=/usr/local/bin/ztlp agent --config /etc/ztlp/agent.toml
Restart=on-failure
RestartSec=10
WatchdogSec=300

# Security hardening
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/ztlp /etc/ztlp
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

---

## 10. Failure Modes and Recovery

### 10.1 Certificate Renewal Failures

| Failure | Impact | Recovery |
|---------|--------|----------|
| NS unreachable | Can't renew | Retry with backoff; existing sessions unaffected |
| Clock skew | RENEW rejected (0x05) | Sync clock (NTP); NS returns its timestamp |
| Rate limited | RENEW rejected (0x06) | Wait retry-after seconds |
| Cert expired | RENEW rejected (0x03) | Must re-enroll (needs operator + token) |
| Key compromised | RENEW succeeds but shouldn't | Operator must revoke; renewal doesn't help |

### 10.2 NS Record Refresh Failures

| Failure | Impact | Recovery |
|---------|--------|----------|
| NS unreachable | Can't refresh | Retry with backoff; records survive until TTL |
| Record expired | Node invisible | Re-register immediately (no token needed) |
| Zone authority key rotated | Registration fails | Update signing key from bootstrap server |

### 10.3 Cascading Failure Scenario

Worst case: NS server goes down for >24 hours.

```
T+0h:   NS goes down
T+18h:  First KEY records start expiring (24h TTL, registered 18h ago)
T+24h:  All KEY/SVC records expired — no new sessions can be established
T+24h:  Active sessions still work (using existing ephemeral keys)
T+48h:  Sessions with 24h lifetime start expiring — no replacement possible
T+90d:  Certificates start expiring — even if NS comes back, nodes
        whose certs expired must re-enroll

Recovery:
1. Bring NS back online
2. Nodes auto-refresh NS records (NsRefresher detects missing records)
3. Nodes whose certs expired during outage need new enrollment tokens
4. Bootstrap server generates batch tokens for affected machines
```

### 10.4 Split-Brain in Federated NS

With federated NS (multiple NS servers syncing via anti-entropy):

- Revocations propagate with priority (revocation always wins)
- Renewed certificates propagate via Merkle-tree anti-entropy
- Conflict resolution: higher serial number wins for same NodeID
- Clock skew between NS servers: renewal timestamps should have ≥5min tolerance

---

## 11. Monitoring and Alerting

### 11.1 Prometheus Metrics

```elixir
# NS server — new metrics for renewal
ztlp_ns_renewals_total{zone, result}          # Counter: success/error by type
ztlp_ns_renewal_latency_seconds{zone}         # Histogram: renewal processing time
ztlp_ns_records_expiring_soon{zone, type}     # Gauge: records expiring within 2h
ztlp_ns_certificates_expiring_soon{zone}      # Gauge: certs expiring within 7d
```

```rust
// Client agent — new metrics
ztlp_agent_cert_remaining_seconds              // Gauge: time until cert expires
ztlp_agent_cert_renewal_attempts_total         // Counter: renewal attempts
ztlp_agent_ns_record_refreshes_total{type}     // Counter: record refreshes
ztlp_agent_ns_record_remaining_seconds{type}   // Gauge: time until record TTL
```

### 11.2 Alert Rules

```yaml
# Grafana / Alertmanager rules

- alert: CertExpiringWithin7Days
  expr: ztlp_agent_cert_remaining_seconds < 604800
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "ZTLP certificate expiring soon on {{ $labels.instance }}"

- alert: CertExpiringWithin24Hours
  expr: ztlp_agent_cert_remaining_seconds < 86400
  for: 15m
  labels:
    severity: critical
  annotations:
    summary: "ZTLP certificate expires within 24h on {{ $labels.instance }}"

- alert: NsRecordMissing
  expr: ztlp_ns_records_expiring_soon > 0
  for: 30m
  labels:
    severity: warning
  annotations:
    summary: "{{ $value }} NS records expiring soon in zone {{ $labels.zone }}"

- alert: RenewalFailures
  expr: rate(ztlp_ns_renewals_total{result!="success"}[1h]) > 0
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "Certificate renewal failures in zone {{ $labels.zone }}"
```

### 11.3 Bootstrap Server Health Page

The bootstrap server `/health/credentials` endpoint returns:

```json
{
  "status": "degraded",
  "machines": 12,
  "credentials": {
    "certificates": {
      "healthy": 10,
      "renewing": 1,
      "expired": 1,
      "next_expiry": "2026-04-15T00:00:00Z",
      "next_expiry_machine": "gw1.corp.ztlp"
    },
    "ns_records": {
      "healthy": 24,
      "missing": 2,
      "missing_machines": ["gw1.corp.ztlp"]
    },
    "rat_secrets": {
      "last_rotation": "2026-03-10T00:00:00Z",
      "age_days": 3,
      "status": "healthy"
    }
  }
}
```

---

## 12. Implementation Roadmap

### Phase 1: NS Record Auto-Refresh (Low-hanging fruit)

**Effort:** 2–3 days
**Impact:** Prevents the most common failure (nodes disappearing from NS)

- [ ] Add `NsRefresher` GenServer to relay
- [ ] Add NS refresh loop to `ztlp listen` (server mode)
- [ ] Add `--refresh-interval` flag to CLI
- [ ] Tests: refresh timing, jitter, failure/retry

### Phase 2: Certificate Renewal Wire Protocol

**Effort:** 3–5 days
**Impact:** Enables fully automated cert lifecycle

- [ ] NS server: `Renewal` module with 0x09/0x0A handlers
- [ ] NS server: rate limiting, clock skew checks
- [ ] Rust client: `renewal.rs` — parse/serialize RENEW messages
- [ ] Rust client: `ztlp renew` CLI command
- [ ] Wire interop tests (Rust ↔ Elixir)
- [ ] Tests: eligibility window, signature verification, serial increment

### Phase 3: Node Agent Daemon

**Effort:** 3–4 days
**Impact:** Fully autonomous credential management per node

- [ ] `ztlp agent` subcommand with config file support
- [ ] CertRenewer task
- [ ] NsRefresher task
- [ ] Systemd service file
- [ ] Agent health metrics (Prometheus)

### Phase 4: Bootstrap Server Credential Management

**Effort:** 3–5 days (extends Phase B/C of bootstrap server)
**Impact:** Centralized visibility and control

- [ ] `CertificateRenewalScheduler` Sidekiq job
- [ ] `NsRecordMonitor` Sidekiq job
- [ ] `RatRotationScheduler` Sidekiq job
- [ ] Credential health dashboard (Turbo Streams for live updates)
- [ ] `/health/credentials` API endpoint
- [ ] Batch token generation for mass re-enrollment after outage

### Phase 5: Monitoring and Alerting

**Effort:** 1–2 days
**Impact:** Proactive visibility into credential health

- [ ] Prometheus metrics in NS server (renewal counters, expiry gauges)
- [ ] Prometheus metrics in client agent
- [ ] Grafana dashboard panels
- [ ] Alertmanager rules
- [ ] Bootstrap server webhook notifications

---

## Summary

The key design principles:

1. **Credentials renew themselves.** Operators don't babysit TTLs.
2. **Renewal is proof-of-possession.** No tokens, no operator approval —
   just prove you still have the key.
3. **Revocation overrides everything.** Even a successfully renewed cert
   is useless if the NodeID is revoked.
4. **Graceful degradation.** Expired NS records → node invisible but
   existing sessions work. Expired cert → can't make NEW sessions but
   existing ones continue.
5. **Defense in depth.** Short TTLs + auto-renewal + revocation + monitoring.
   Don't rely on any single mechanism.
