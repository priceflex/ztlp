# TLS Termination at the Gateway — Full Scope

**Status:** Planned
**Priority:** 1
**Author:** Steve Price / ZTLP Project
**Date:** 2026-03-21

---

## Executive Summary

Add TLS termination to the ZTLP Gateway so that standard browsers and HTTPS clients can access ZTLP-protected services without installing a ZTLP agent. The gateway becomes a zero-trust reverse proxy — accepting both ZTLP/UDP (native) and TLS/TCP (web) connections, routing both through the same policy engine.

The approach: **ZTLP acts as its own internal Certificate Authority.** Services get ZTLP-issued X.509 certificates. Clients that install the ZTLP root CA (via `ztlp setup` or MDM) get trusted HTTPS with green locks. mTLS client certificates provide strong identity for the TLS path, unifying both access methods under one identity model.

For public-facing edges that need browser trust without CA installation, an optional ACME/Let's Encrypt integration is included as a secondary mode.

---

## Architecture Overview

### Current State

```
ZTLP Client ──[ZTLP/UDP]──► Gateway ──[plaintext TCP]──► Backend Service
                                 │
                            PolicyEngine
                            (Noise_XX identity)
```

### Target State

```
┌─────────────────────────────────────────────────────────────────┐
│                        ZTLP Gateway                             │
│                                                                 │
│  ┌──────────────────┐    ┌───────────────────┐                  │
│  │  UDP Listener     │    │  TLS Listener      │                 │
│  │  (existing)       │    │  (new — port 443)  │                 │
│  │  Noise_XX auth    │    │  SNI routing        │                │
│  └────────┬──────────┘    │  mTLS identity      │                │
│           │               │  (optional)         │                │
│           │               └────────┬────────────┘                │
│           │                        │                             │
│           ▼                        ▼                             │
│  ┌─────────────────────────────────────────────┐                │
│  │              PolicyEngine                    │                │
│  │  authorize?(identity, service) → allow/deny  │                │
│  └─────────────────────┬───────────────────────┘                │
│                        │                                        │
│                        ▼                                        │
│  ┌─────────────────────────────────────────────┐                │
│  │              Backend Pool                    │                │
│  │  TCP / TLS connections to service backends   │                │
│  └──────────────────────────────────────────────┘                │
│                                                                 │
│  ┌──────────────────┐    ┌────────────────────┐                 │
│  │  CertManager      │    │  ACME Client       │                │
│  │  (internal CA)    │    │  (Let's Encrypt)   │                │
│  │  Issues certs     │    │  Public domains    │                │
│  │  from ZTLP CA     │    │  (optional)        │                │
│  └──────────────────┘    └────────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

### Identity Flow Comparison

| Path | Authentication | Identity Source | Policy Engine Input |
|------|---------------|-----------------|---------------------|
| ZTLP/UDP (existing) | Noise_XX handshake | Remote static pubkey → NS lookup → NodeID/user/zone | Same `authorize?/2` |
| TLS + mTLS (new) | Client certificate | Cert CN/SAN → NS lookup → NodeID/user/zone | Same `authorize?/2` |
| TLS without mTLS (new) | None at transport layer | Delegated to backend (pass-through) or IP-based | Reduced policy (IP/service only) |

---

## Phase Breakdown

### Phase 1: Internal Certificate Authority

**Goal:** ZTLP-NS can issue and manage X.509 certificates for services and clients.

#### 1A — Root CA Generation & Storage

**New module:** `ZtlpNs.CertAuthority`

- Generate a self-signed Root CA on first run (`ztlp admin ca init`)
  - RSA-4096 or Ed25519 root key (Ed25519 preferred, RSA-4096 as fallback for maximum client compat)
  - 10-year validity for root CA (standard for internal CAs)
  - Subject: `CN=ZTLP Root CA, O=<zone_org>`
  - Key stored encrypted at rest (AES-256-GCM, passphrase or derived from zone secret)
- Generate an Intermediate CA signed by root
  - 3-year validity
  - This is what actually signs service/client certs (root stays offline-capable)
  - Subject: `CN=ZTLP Intermediate CA, O=<zone_org>`
- Storage locations:
  - NS server: `~/.ztlp/ca/root.key` (encrypted), `~/.ztlp/ca/root.pem`, `~/.ztlp/ca/intermediate.key`, `~/.ztlp/ca/intermediate.pem`
  - Distributed via NS: Root CA cert as a new record type (`:ca`, type byte `0x13`)
  - Chain file: `~/.ztlp/ca/chain.pem` (intermediate + root)
- **CLI commands:**
  ```
  ztlp admin ca init [--org "Tech Rockstars"] [--key-type ed25519|rsa4096]
  ztlp admin ca show
  ztlp admin ca export-root > ztlp-root-ca.pem
  ztlp admin ca rotate-intermediate
  ```

**New NS record type:**

```elixir
# Type byte 0x13 — ZTLP_CA
# Stores the root CA certificate (PEM-encoded) for distribution
Record.new_ca("ca.techrockstars.ztlp", root_cert_pem, opts)
```

**Files:**
- `ns/lib/ztlp_ns/cert_authority.ex` — CA key management, cert generation
- `ns/lib/ztlp_ns/x509.ex` — X.509 certificate builder (wraps Erlang `:public_key`)
- `proto/src/admin/ca.rs` — CLI `ztlp admin ca` subcommands
- Update `ns/lib/ztlp_ns/record.ex` — add `:ca` record type (0x13)

**Tests:** ~40

---

#### 1B — Service Certificate Issuance

**Goal:** Zone admins can issue TLS server certificates for their services.

- Certificate request flow:
  1. Admin runs `ztlp admin cert issue --service webapp.corp.ztlp` (or Bootstrap UI button)
  2. NS validates the requester has zone authority (existing `RegistrationAuth`)
  3. NS generates a key pair, creates X.509 cert signed by the intermediate CA
  4. Returns cert + key to requester, stores cert record in NS
- Certificate fields:
  - Subject: `CN=webapp.corp.ztlp`
  - SAN: `DNS:webapp.corp.ztlp` (+ any aliases)
  - Validity: configurable, default 7 days (short-lived, auto-renewed)
  - Key Usage: Digital Signature, Key Encipherment
  - Extended Key Usage: TLS Web Server Authentication
- Certificate storage in NS:
  ```elixir
  # New record type: :cert (0x14)
  # Stores issued cert metadata (not the private key!)
  %{
    subject: "webapp.corp.ztlp",
    serial_number: "...",
    not_before: unix_timestamp,
    not_after: unix_timestamp,
    issuer: "ZTLP Intermediate CA",
    fingerprint_sha256: "...",
    cert_pem: "-----BEGIN CERTIFICATE-----\n..."
  }
  ```
- **Auto-renewal:** Gateway requests new cert at 67% lifetime (reuse existing renewal daemon logic)
- **CLI commands:**
  ```
  ztlp admin cert issue --service webapp.corp.ztlp [--days 7] [--san "alias.corp.ztlp"]
  ztlp admin cert list [--zone corp.ztlp]
  ztlp admin cert show webapp.corp.ztlp
  ztlp admin cert revoke webapp.corp.ztlp --reason "key compromise"
  ```

**Files:**
- `ns/lib/ztlp_ns/cert_issuer.ex` — CSR handling, cert generation, serial tracking
- `proto/src/admin/cert.rs` — CLI `ztlp admin cert` subcommands
- Update `ns/lib/ztlp_ns/record.ex` — add `:cert` record type (0x14)

**Tests:** ~50

---

#### 1C — Client Certificate Issuance (for mTLS)

**Goal:** Enrolled devices/users get client certificates that map to their ZTLP identity.

- During `ztlp setup` (enrollment), the agent also:
  1. Generates a TLS client key pair
  2. Sends a cert request to NS (authenticated by enrollment token)
  3. Receives a client cert signed by the intermediate CA
  4. Stores at `~/.ztlp/client.key` and `~/.ztlp/client.pem`
- Certificate fields:
  - Subject: `CN=<node_name>, O=<zone>` (e.g., `CN=steve-laptop.corp.ztlp`)
  - SAN: `URI:ztlp://node/<node_id_hex>` (allows gateway to extract NodeID from cert)
  - Extended Key Usage: TLS Web Client Authentication
  - Validity: 30 days (auto-renewed by agent renewal daemon)
- Client cert → ZTLP identity mapping:
  - Gateway extracts `URI:ztlp://node/<node_id>` from the SAN
  - Looks up NodeID in NS to get user/device/zone identity
  - Passes identity to PolicyEngine — same as Noise_XX path
- **Browser installation:**
  - `ztlp setup` can optionally install the client cert in the OS keychain
  - macOS: `security import` into login keychain
  - Linux: `~/.pki/nssdb` (for Chrome/Firefox)
  - Windows: `certutil -importPFX` into CurrentUser\My
  - Users prompted by browser to select client cert when connecting to mTLS-enabled services

**Files:**
- `ns/lib/ztlp_ns/cert_issuer.ex` — extend for client cert issuance
- `proto/src/agent/cert.rs` — client cert request, storage, OS keychain install
- `proto/src/agent/renewal.rs` — extend for client cert renewal
- `proto/src/setup.rs` — extend enrollment flow

**Tests:** ~35

---

### Phase 2: Gateway TLS Listener

**Goal:** The gateway accepts incoming TLS connections alongside its existing UDP listener.

#### 2A — TLS Acceptor

**New module:** `ZtlpGateway.TlsListener`

- Erlang `:ssl.listen/2` on configurable port (default 443, configurable via `ZTLP_GATEWAY_TLS_PORT`)
- Acceptor pool: configurable number of acceptor processes (default 100)
  - Each acceptor calls `:ssl.transport_accept/1` then `:ssl.handshake/1`
  - After handshake completes, hand off to a session handler
- TLS configuration:
  ```elixir
  ssl_opts = [
    certfile: service_cert_path,        # From CertManager
    keyfile: service_key_path,
    cacertfile: ca_chain_path,          # For mTLS client validation
    verify: :verify_peer,               # mTLS mode
    fail_if_no_peer_cert: false,        # Allow non-mTLS clients too
    sni_fun: &sni_callback/1,           # Dynamic cert selection
    versions: [:"tlsv1.3", :"tlsv1.2"],
    ciphers: :ssl.cipher_suites(:default, :"tlsv1.3"),
    honor_cipher_order: true
  ]
  ```
- SNI callback selects the correct cert based on the requested hostname
- Supports both mTLS and plain TLS clients (policy decides what non-mTLS clients can access)

**Config additions:**

```elixir
# config.ex additions
:tls_port        # TCP port for TLS listener (default: 443)
:tls_enabled     # Enable TLS listener (default: false)
:tls_acceptors   # Number of acceptor processes (default: 100)
:mtls_required   # Require client certificates (default: false)
:mtls_optional   # Request but don't require client certs (default: true)
```

**Environment variables:**

```
ZTLP_GATEWAY_TLS_PORT=443
ZTLP_GATEWAY_TLS_ENABLED=true
ZTLP_GATEWAY_MTLS_REQUIRED=false
```

**Files:**
- `gateway/lib/ztlp_gateway/tls_listener.ex` — TLS acceptor pool
- `gateway/lib/ztlp_gateway/tls_session.ex` — per-TLS-connection handler
- Update `gateway/lib/ztlp_gateway/config.ex` — TLS config options
- Update `gateway/lib/ztlp_gateway/application.ex` — start TLS listener

**Tests:** ~45

---

#### 2B — SNI Routing

**Goal:** Route incoming TLS connections to the correct backend based on the requested hostname.

- Extract SNI from TLS ClientHello (Erlang `:ssl` provides this via `sni_fun`)
- SNI hostname → service name mapping:
  - Direct match: `webapp.corp.ztlp` → backend `webapp`
  - NS lookup: query ZTLP-NS for SVC record matching the hostname
  - Wildcard: `*.corp.ztlp` → zone-level default backend
  - Config-based: explicit hostname→backend map in gateway config
- Certificate selection per SNI:
  - Gateway maintains a cert cache (GenServer): `%{hostname => {cert, key, expires_at}}`
  - On SNI callback, look up hostname → return matching cert
  - Cache miss → request cert from NS CertIssuer (on-demand issuance)
  - Near-expiry → trigger background renewal
- Default cert for unknown SNI (or no SNI): gateway's own hostname cert

**New module:** `ZtlpGateway.CertCache`

```elixir
# Maintains in-memory cache of hostname → {cert_der, key_der}
# Fetches from NS on miss, auto-renews before expiry
# ETS-backed for concurrent read access from acceptor pool
```

**New module:** `ZtlpGateway.SniRouter`

```elixir
# Maps SNI hostname → {backend_name, cert_entry}
# Supports:
#   - Exact match: "webapp.corp.ztlp" → backend "webapp"
#   - NS SVC lookup: query NS for service definition
#   - Config override: gateway.yml explicit routes
#   - Zone wildcard: "*.corp.ztlp" → default backend for zone
```

**Files:**
- `gateway/lib/ztlp_gateway/cert_cache.ex` — cert storage + auto-renewal
- `gateway/lib/ztlp_gateway/sni_router.ex` — SNI → backend resolution
- Update `gateway/lib/ztlp_gateway/tls_listener.ex` — wire up SNI callback

**Tests:** ~35

---

#### 2C — TLS-to-Backend Proxying

**Goal:** Forward decrypted TLS traffic to backend services (TCP or TLS).

- After TLS handshake completes and policy passes:
  1. Identify the target backend from SNI routing
  2. Open a TCP (or TLS) connection to the backend
  3. Bidirectional byte stream: client ↔ gateway ↔ backend
  4. No HTTP parsing — pure TCP proxy (transparent to application layer)
- Backend connection modes (per-service config):
  - `:tcp` — plaintext TCP to backend (default, backend on localhost)
  - `:tls` — TLS to backend (backend expects HTTPS)
  - `:tls_passthrough` — don't terminate, just forward encrypted stream (for end-to-end TLS)
- Reuse existing `Backend` module with TLS option:
  ```elixir
  # Backend.start_link now accepts connection mode
  Backend.start_link({host, port, owner, :tcp})     # existing behavior
  Backend.start_link({host, port, owner, :tls})      # new: TLS to backend
  ```
- Connection pooling (future optimization, not in v1):
  - Keep-alive connections to frequently-used backends
  - Pool size per backend configurable

**Files:**
- Update `gateway/lib/ztlp_gateway/backend.ex` — add `:tls` mode via `:ssl.connect`
- `gateway/lib/ztlp_gateway/tls_session.ex` — bidirectional proxy logic
- Update `gateway/lib/ztlp_gateway/config.ex` — per-backend connection mode

**Tests:** ~30

---

#### 2D — mTLS Identity Extraction

**Goal:** Extract ZTLP identity from client certificates and feed it into the PolicyEngine.

- After TLS handshake, extract the peer certificate (if provided):
  ```elixir
  case :ssl.peercert(tls_socket) do
    {:ok, der_cert} -> extract_identity(der_cert)
    {:error, :no_peercert} -> :anonymous
  end
  ```
- Identity extraction chain:
  1. Parse X.509 cert from DER
  2. Check SAN for `URI:ztlp://node/<node_id>` → direct NodeID mapping
  3. Check CN for `<name>.<zone>.ztlp` → NS lookup for identity
  4. Verify cert was issued by our CA (chain validation already done by `:ssl`)
  5. Check if cert serial is revoked (NS revocation lookup)
- Map extracted identity to PolicyEngine format:
  ```elixir
  # Same format as Noise_XX path:
  identity = Identity.resolve_or_hex(node_id_from_cert)
  PolicyEngine.authorize?(identity, service_name)
  ```
- Anonymous TLS clients (no client cert):
  - If `mtls_required: true` → reject connection
  - If `mtls_required: false` → identity is `:anonymous`
  - Policy can allow `:anonymous` access to specific public services

**New module:** `ZtlpGateway.TlsIdentity`

```elixir
# Extracts ZTLP identity from X.509 client certificates
# Handles SAN parsing, NS lookups, revocation checks
```

**Files:**
- `gateway/lib/ztlp_gateway/tls_identity.ex` — cert → identity extraction
- Update `gateway/lib/ztlp_gateway/tls_session.ex` — identity extraction after handshake
- Update `gateway/lib/ztlp_gateway/policy_engine.ex` — handle `:anonymous` identity

**Tests:** ~40

---

### Phase 3: Client-Side CA Trust Installation

**Goal:** Make `ztlp setup` install the ZTLP root CA into the system trust store so browsers trust ZTLP-issued certs.

#### 3A — Root CA Distribution

- During enrollment (`ztlp setup`), after identity provisioning:
  1. Agent queries NS for the CA record (type 0x13)
  2. Saves root CA cert to `~/.ztlp/ca/root.pem`
  3. Prompts user to install into system trust store (or auto-install with `--trust-ca`)
- CA distribution is authenticated:
  - CA record in NS is signed by the zone authority
  - Agent verifies signature before trusting
  - Prevents rogue CA injection

#### 3B — OS Trust Store Installation

**Per-platform implementation in Rust agent:**

```rust
// proto/src/agent/ca_trust.rs

/// Install ZTLP root CA into system trust store
pub fn install_ca(ca_pem: &[u8], opts: &InstallOpts) -> Result<()> {
    match std::env::consts::OS {
        "macos" => install_macos(ca_pem, opts),
        "linux" => install_linux(ca_pem, opts),
        "windows" => install_windows(ca_pem, opts),
        _ => Err(Error::UnsupportedOS),
    }
}
```

**macOS:**
```bash
# Requires admin/sudo
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.ztlp/ca/root.pem
```

**Linux:**
```bash
# Debian/Ubuntu
sudo cp ~/.ztlp/ca/root.pem /usr/local/share/ca-certificates/ztlp-root.crt
sudo update-ca-certificates

# RHEL/Fedora
sudo cp ~/.ztlp/ca/root.pem /etc/pki/ca-trust/source/anchors/ztlp-root.pem
sudo update-ca-trust

# Firefox (uses its own store)
certutil -d sql:$HOME/.pki/nssdb -A -t "CT,," -n "ZTLP Root CA" -i ~/.ztlp/ca/root.pem
```

**Windows:**
```powershell
certutil -addstore Root "$env:USERPROFILE\.ztlp\ca\root.pem"
```

**MDM deployment (documented, not implemented):**
- macOS: Configuration Profile with `com.apple.security.root` payload
- Windows: GPO cert deployment
- Linux: Ansible/Puppet/Chef recipe
- Mobile: MDM cert push

#### 3C — Client Certificate Browser Installation (for mTLS)

- Optional step during `ztlp setup --install-client-cert`
- Exports client cert as PKCS#12 (.p12) and imports into browser-accessible store
- macOS: Keychain Access (login keychain)
- Linux: NSS db (`~/.pki/nssdb`) for Chrome, `cert9.db` for Firefox
- Windows: Current User → Personal certificate store
- Browser prompts user to select cert when connecting to mTLS-enabled service

**Files:**
- `proto/src/agent/ca_trust.rs` — OS trust store operations
- `proto/src/agent/cert_install.rs` — browser client cert installation (PKCS#12 export + import)
- Update `proto/src/setup.rs` — CA download + trust installation step
- `docs/MDM-CA-DEPLOYMENT.md` — guide for enterprise MDM deployment

**Tests:** ~25 (platform-specific, may need conditional compilation)

---

### Phase 4: ACME / Let's Encrypt (Optional, Public Edges)

**Goal:** For services that need publicly-trusted certs (not just internal CA), support automatic Let's Encrypt.

> **This phase is optional.** Most ZTLP deployments are internal and won't need this.
> For public-facing services, putting Caddy/Nginx in front is equally valid.

#### 4A — ACME Client

- Implement ACME v2 (RFC 8555) client in Elixir
- HTTP-01 challenge (gateway serves `/.well-known/acme-challenge/` on port 80)
- DNS-01 challenge (NS creates TXT record for validation — natural fit since we control DNS)
- Certificate storage: same CertCache, tagged as `:acme` source
- Auto-renewal at 67% lifetime (30-day certs from LE → renew at day 20)

**Config:**
```yaml
tls:
  acme:
    enabled: true
    email: "admin@techrockstars.com"
    domains:
      - "public.techrockstars.com"
    challenge: "dns-01"  # or "http-01"
    staging: false        # true for testing
```

#### 4B — Hybrid Cert Selection

- Per-service cert source configuration:
  - `source: internal` — ZTLP CA issued (default)
  - `source: acme` — Let's Encrypt issued
  - `source: manual` — user-provided cert files
- SNI callback checks cert source for the requested hostname
- Internal and ACME certs can coexist on the same gateway

**Files:**
- `gateway/lib/ztlp_gateway/acme_client.ex` — ACME v2 protocol implementation
- `gateway/lib/ztlp_gateway/acme_challenge.ex` — HTTP-01 challenge server
- Update `ns/lib/ztlp_ns/server.ex` — DNS-01 TXT record support
- Update `gateway/lib/ztlp_gateway/cert_cache.ex` — multi-source certs
- Update `gateway/lib/ztlp_gateway/sni_router.ex` — cert source routing

**Tests:** ~40

---

### Phase 5: Audit, Metrics & Revocation

**Goal:** Full observability and security lifecycle for TLS operations.

#### 5A — TLS Audit Logging

- Log all TLS events through existing `AuditLog`:
  - Connection established (client IP, SNI, cipher suite, protocol version)
  - mTLS identity extracted (NodeID, user, zone)
  - Policy decision (allow/deny, reason)
  - Connection closed (duration, bytes transferred)
  - Certificate issued/renewed/revoked
- Structured JSON format (existing `StructuredLog` integration)

#### 5B — Prometheus Metrics

- Extend existing `MetricsServer` with TLS counters:
  ```
  ztlp_gateway_tls_connections_total{status="established|rejected|error"}
  ztlp_gateway_tls_connections_active
  ztlp_gateway_tls_handshake_duration_seconds
  ztlp_gateway_tls_bytes_in_total
  ztlp_gateway_tls_bytes_out_total
  ztlp_gateway_tls_mtls_auth_total{result="success|failure|none"}
  ztlp_gateway_tls_cert_expiry_seconds{hostname="..."}
  ztlp_gateway_tls_cert_renewals_total{source="internal|acme",status="success|failure"}
  ztlp_ns_ca_certs_issued_total{type="server|client"}
  ztlp_ns_ca_certs_revoked_total
  ```

#### 5C — Certificate Revocation

- Revocation via existing NS `:revoke` record mechanism
- Gateway checks revocation status during mTLS identity extraction:
  1. Extract cert serial number
  2. Query NS for revocation record matching the serial
  3. If revoked → reject connection
- CRL (Certificate Revocation List) endpoint:
  - Gateway serves CRL at `http://<gateway>/.ztlp/crl.pem`
  - Updated whenever a cert is revoked
  - Clients can optionally check CRL (browsers do this automatically)
- OCSP responder (future, not v1):
  - Real-time revocation checking
  - Higher infra cost, skip for now

**Files:**
- Update `gateway/lib/ztlp_gateway/audit_log.ex` — TLS event types
- Update `gateway/lib/ztlp_gateway/metrics_server.ex` — TLS metrics
- `gateway/lib/ztlp_gateway/crl_server.ex` — CRL endpoint
- Update `gateway/lib/ztlp_gateway/tls_identity.ex` — revocation checks
- `ns/lib/ztlp_ns/cert_revocation.ex` — revocation record management

**Tests:** ~35

---

### Phase 6: CLI, Config & Documentation

**Goal:** Production-ready configuration, documentation, and operational tooling.

#### 6A — Gateway YAML Config

Extend `gateway.yml` for TLS:

```yaml
gateway:
  port: 23097          # existing UDP port
  
  tls:
    enabled: true
    port: 443
    acceptors: 100
    
    # Certificate source (default: internal)
    cert_source: internal    # internal | acme | manual
    
    # Internal CA mode (default)
    internal:
      ca_host: "ns.corp.ztlp"   # NS server with CA
      auto_issue: true            # Auto-request certs for configured services
      cert_lifetime_days: 7       # Short-lived certs
    
    # Manual cert mode
    manual:
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
      ca_file: /path/to/ca.pem
    
    # mTLS settings
    mtls:
      enabled: true
      required: false       # true = reject clients without certs
      ca_file: /path/to/ca-chain.pem
    
    # TLS protocol settings
    min_version: "1.2"      # "1.2" or "1.3"
    cipher_suites: default  # or explicit list
    
  # Per-service backend config (extend existing)
  backends:
    - name: webapp
      host: 127.0.0.1
      port: 8080
      mode: tcp             # tcp | tls
      hostnames:            # SNI hostnames that route here
        - webapp.corp.ztlp
        - app.corp.ztlp
    
    - name: grafana
      host: 127.0.0.1
      port: 3000
      mode: tcp
      hostnames:
        - grafana.corp.ztlp
```

#### 6B — CLI Commands (Summary)

```
# CA management
ztlp admin ca init [--org "..."] [--key-type ed25519|rsa4096]
ztlp admin ca show
ztlp admin ca export-root
ztlp admin ca rotate-intermediate

# Certificate management
ztlp admin cert issue --service <hostname> [--days 7] [--san "alias"]
ztlp admin cert list [--zone <zone>] [--expiring-within 24h]
ztlp admin cert show <hostname>
ztlp admin cert revoke <hostname> --reason "..."

# Gateway TLS status
ztlp gateway tls-status          # Show active certs, connections, expiry times
ztlp gateway tls-test <hostname> # Test TLS connection to a service through gateway
```

#### 6C — Documentation

- `docs/TLS.md` — TLS architecture overview, configuration reference
- `docs/INTERNAL-CA.md` — How the ZTLP CA works, trust model, key management
- `docs/MTLS-SETUP.md` — Guide for setting up mTLS client authentication
- `docs/MDM-CA-DEPLOYMENT.md` — Enterprise CA deployment via MDM
- Update `docs/GETTING-STARTED.md` — Add TLS quick start
- Update `ops/RUNBOOK.md` — TLS troubleshooting section
- Update `ROADMAP.md` — Mark TLS as in-progress/complete

**Tests:** ~15 (config parsing, YAML validation)

---

## Implementation Order

```
Phase 1A: Root CA Generation ──────────────► Phase 1B: Service Certs
    │                                             │
    └──────────────────────────────────────────────┤
                                                   │
Phase 1C: Client Certs ◄──────────────────────────┘
    │
    ▼
Phase 2A: TLS Acceptor ───► Phase 2B: SNI Routing ───► Phase 2C: Backend Proxy
    │                                                        │
    └────────────────────────────────────────────────────────┤
                                                             │
Phase 2D: mTLS Identity ◄───────────────────────────────────┘
    │
    ▼
Phase 3A: CA Distribution ───► Phase 3B: OS Trust Install ───► Phase 3C: Browser Cert
    │
    ▼
Phase 5: Audit + Metrics + Revocation
    │
    ▼
Phase 6: CLI + Config + Docs

Phase 4: ACME (independent, can be done anytime or skipped)
```

**Estimated scope:**
- **Phase 1:** ~125 tests, ~2,500 lines (Elixir + Rust)
- **Phase 2:** ~150 tests, ~2,000 lines (Elixir)
- **Phase 3:** ~25 tests, ~800 lines (Rust)
- **Phase 4:** ~40 tests, ~1,200 lines (Elixir) — optional
- **Phase 5:** ~35 tests, ~600 lines (Elixir)
- **Phase 6:** ~15 tests, ~500 lines + docs

**Total: ~390 tests, ~7,600 lines** (excluding Phase 4)
**With Phase 4: ~430 tests, ~8,800 lines**

---

## Security Considerations

### Threat Model Additions

| Threat | Mitigation |
|--------|------------|
| Rogue CA injection | CA record signed by zone authority; agent verifies before trust |
| Stolen intermediate key | Short-lived certs (7 days) limit blast radius; intermediate rotation supported |
| Compromised client cert | Revocation via NS `:revoke` record; CRL served by gateway |
| Downgrade attack (TLS 1.1) | Minimum TLS 1.2 enforced; TLS 1.3 preferred |
| SNI spoofing | SNI validated against configured services; unknown SNI rejected |
| CA key at rest | Encrypted with AES-256-GCM; passphrase or zone-secret derived |
| mTLS bypass (no client cert) | Configurable: `mtls_required` per service; anonymous gets restricted policy |

### Key Decisions

1. **Ed25519 vs RSA for root CA:** Ed25519 is better (faster, smaller), but some older clients/browsers don't support Ed25519 in X.509. Default to Ed25519 with RSA-4096 fallback option.

2. **Short-lived certs (7 days):** Reduces revocation dependency. Even if revocation fails, a compromised cert is useless in a week. Matches Tailscale's approach.

3. **mTLS optional by default:** Requiring mTLS everywhere would break browser usability for services that don't need strong client identity. Per-service policy controls this.

4. **No OCSP in v1:** CRL is simpler and sufficient for the scale. OCSP adds latency to every TLS handshake. Revisit if needed.

5. **No HTTP parsing in gateway:** The gateway proxies TCP bytes, not HTTP requests. This keeps it transport-agnostic and avoids the complexity of a full reverse proxy. If HTTP header injection (like `X-ZTLP-User`) is needed, that's a separate feature.

---

## Dependencies

### Erlang/OTP
- `:ssl` — TLS server and client (already available)
- `:public_key` — X.509 certificate generation and parsing (already available)
- `:crypto` — key generation, signing (already used)

### Rust
- `rcgen` crate — X.509 certificate generation (for CLI cert commands)
- `native-tls` or `rustls` — for TLS client cert installation verification
- `keychain-services` (macOS), `winapi` (Windows) — for OS trust store operations

### No New Elixir Dependencies
All X.509 work uses Erlang's built-in `:public_key` module. Zero external deps, consistent with the rest of the project.

---

## What This Enables

After all phases are complete:

```bash
# Admin sets up CA (once)
ztlp admin ca init --org "Tech Rockstars"

# Admin issues cert for a web app
ztlp admin cert issue --service webapp.corp.ztlp

# Gateway config routes TLS → backend
# (gateway.yml already configured with backends + hostnames)

# User enrolls their device (once)
ztlp setup --token ztlp://enroll/AQ... --trust-ca --install-client-cert
# → Identity provisioned
# → Root CA installed in system trust store
# → Client cert installed in browser (optional)

# Now from any browser on that machine:
https://webapp.corp.ztlp     # ✅ Trusted, green lock, no warnings
https://grafana.corp.ztlp    # ✅ Same
https://internal-api.corp.ztlp  # ✅ mTLS — browser shows cert picker

# From ZTLP native client (unchanged):
ztlp connect webapp.corp.ztlp  # ✅ Same backend, same policy, ZTLP/UDP path

# Both paths: same PolicyEngine, same AuditLog, same identity model
```

---

## Version Target

This feature set targets **v0.11.0** (or v1.0.0 if we're feeling bold).

---

_Last updated: 2026-03-21_
