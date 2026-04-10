# TLS Termination at the Gateway — Full Scope

**Status:** Complete (Phases 1–3, 5–6)
**Priority:** 1
**Author:** Steve Price / ZTLP Project
**Date:** 2026-03-21
**Completed:** 2026-03-24

> **Phase 4 (ACME/Let's Encrypt):** Deferred — not needed for internal deployments.
> Internal CA covers all zero-trust use cases. ACME can be added later for public-facing edges.

---

## Executive Summary

Add TLS termination to the ZTLP Gateway so that standard browsers and HTTPS clients can access ZTLP-protected services without installing a ZTLP agent. The gateway becomes a zero-trust reverse proxy — accepting both ZTLP/UDP (native) and TLS/TCP (web) connections, routing both through the same policy engine.

The approach: **ZTLP acts as its own internal Certificate Authority.** Services get ZTLP-issued X.509 certificates. Clients that install the ZTLP root CA (via `ztlp setup` or MDM) get trusted HTTPS with green locks. mTLS client certificates provide strong identity for the TLS path, unifying both access methods under one identity model.

The gateway injects **trusted identity headers** (`X-ZTLP-Identity`, etc.) into HTTP requests, enabling backend applications to implement **passwordless authentication** — the mTLS certificate IS the login. No passwords, no MFA tokens, no OAuth dances. The cryptographic proof of identity happens at the network layer before the request ever reaches the application.

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
│  │         Identity Header Injector             │                │
│  │  Strip client X-ZTLP-* → Inject trusted     │                │
│  │  X-ZTLP-Identity / Node-ID / Groups / HMAC  │                │
│  │  (HTTP mode only — per-service auth_mode)    │                │
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

| Path | Authentication | Identity Source | Policy Engine Input | Backend Sees |
|------|---------------|-----------------|---------------------|--------------|
| ZTLP/UDP (existing) | Noise_XX handshake | Remote static pubkey → NS lookup → NodeID/user/zone | Same `authorize?/2` | Raw TCP bytes |
| TLS + mTLS + `enforce` (new) | Client certificate | Cert CN/SAN → NS lookup → NodeID/user/zone | Same `authorize?/2` | `X-ZTLP-*` headers (passwordless) |
| TLS + mTLS + `identity` (new) | Client certificate | Cert CN/SAN → NS lookup → NodeID/user/zone | Same `authorize?/2` | `X-ZTLP-*` headers (app can use or ignore) |
| TLS + `passthrough` (new) | None at transport layer | Delegated to backend or IP-based | Reduced policy (IP/service only) | No ZTLP headers |

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

**Goal:** Enrolled devices/users get client certificates that map to their ZTLP identity, with assurance level reflecting how securely the private key is stored.

- During `ztlp setup` (enrollment), the agent also:
  1. **Detects available hardware key storage** (in priority order):
     - YubiKey connected? → generate key ON the YubiKey via PKCS#11/PIV
     - TPM 2.0 available? → generate key in TPM (`tpm2-tss`)
     - Secure Enclave (macOS)? → generate key via `SecKeyCreateRandomKey` with `.privateKeyUsage`
     - Android StrongBox/Keystore? → hardware-backed key generation
     - None of the above → generate key as file on disk (`~/.ztlp/client.key`)
  2. **If hardware key: requests attestation certificate** from the hardware
     - YubiKey: PIV attestation cert (slot 9a, signed by Yubico root)
     - TPM: `TPM2_Certify` with endorsement key certificate chain
     - Secure Enclave: Apple App Attest / DeviceCheck attestation
     - StrongBox: Android Key Attestation certificate chain
  3. Sends cert request to NS with attestation proof (if available)
  4. NS verifies attestation against known manufacturer root CAs:
     - Yubico PIV attestation root CA
     - TPM manufacturer CAs (Intel, AMD, Infineon, STMicro, etc.)
     - Apple attestation root CA
     - Google hardware attestation root
  5. NS issues client cert with **assurance level embedded as X.509 extensions**
  6. Stores cert + key reference (file path, PKCS#11 URI, or keychain ref)
- Certificate fields:
  - Subject: `CN=<node_name>, O=<zone>` (e.g., `CN=steve-laptop.corp.ztlp`)
  - SAN: `URI:ztlp://node/<node_id_hex>` (allows gateway to extract NodeID from cert)
  - Extended Key Usage: TLS Web Client Authentication
  - Validity: 30 days (auto-renewed by agent renewal daemon)
  - **Custom X.509 Extensions (ZTLP Assurance):**
    - `OID 1.3.6.1.4.1.XXXXX.1` — Assurance level: `4` (hardware) / `3` (device-bound) / `2` (software) / `1` (unknown)
    - `OID 1.3.6.1.4.1.XXXXX.2` — Key source: `yubikey` / `tpm` / `secure-enclave` / `strongbox` / `file` / `unknown`
    - `OID 1.3.6.1.4.1.XXXXX.3` — Attestation verified: `true` / `false`
    - (XXXXX = ZTLP's IANA Private Enterprise Number, to be registered)
- Client cert → ZTLP identity mapping:
  - Gateway extracts `URI:ztlp://node/<node_id>` from the SAN
  - Looks up NodeID in NS to get user/device/zone identity
  - Reads assurance extensions from cert
  - Passes identity + assurance to PolicyEngine — same as Noise_XX path
- **Hardware key CLI flags:**
  ```
  ztlp setup --token ztlp://enroll/AQ... --hardware-key          # auto-detect best available
  ztlp setup --token ztlp://enroll/AQ... --key-source yubikey    # force YubiKey
  ztlp setup --token ztlp://enroll/AQ... --key-source tpm        # force TPM
  ztlp setup --token ztlp://enroll/AQ... --key-source file       # force software key
  ```
- **Browser installation:**
  - `ztlp setup` can optionally install the client cert in the OS keychain
  - macOS: `security import` into login keychain
  - Linux: `~/.pki/nssdb` (for Chrome/Firefox)
  - Windows: `certutil -importPFX` into CurrentUser\My
  - For hardware keys: browser uses PKCS#11 module to access key on YubiKey/TPM directly
  - Users prompted by browser to select cert when connecting to mTLS-enabled services

##### Assurance Levels Defined

```
Level 4: hardware       — Private key generated on and NEVER leaves a dedicated
                          hardware security device (YubiKey, standalone TPM token,
                          hardware HSM). Attestation verified by NS against
                          manufacturer root CA. Strongest guarantee.
                          
Level 3: device-bound   — Private key stored in device-integrated secure hardware
                          (Apple Secure Enclave, TPM 2.0 soldered to motherboard,
                          Android StrongBox/Keystore with hardware backing).
                          Key is non-exportable but tied to this specific device.
                          Attestation verified where available.
                          
Level 2: software       — Private key is a file on disk (~/.ztlp/client.key).
                          Encrypted at rest (AES-256-GCM) but technically
                          extractable. Default for enrollments where no hardware
                          key storage is detected.
                          
Level 1: unknown        — Cannot determine key storage. Legacy clients, manual
                          cert imports, or clients that predate assurance tracking.
```

**Files:**
- `ns/lib/ztlp_ns/cert_issuer.ex` — extend for client cert issuance with assurance extensions
- `ns/lib/ztlp_ns/attestation.ex` — **new**: attestation verification (YubiKey, TPM, Secure Enclave manufacturer root CAs)
- `proto/src/agent/cert.rs` — client cert request, storage, OS keychain install
- `proto/src/agent/hardware_key.rs` — **new**: hardware key detection, PKCS#11 interface, attestation request
- `proto/src/agent/renewal.rs` — extend for client cert renewal (hardware keys: re-attest on renewal)
- `proto/src/setup.rs` — extend enrollment flow with hardware key detection + `--hardware-key` / `--key-source` flags

**Tests:** ~50 (was ~35, +15 for hardware key detection, attestation verification, assurance extension parsing)

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

#### 2D — mTLS Identity & Assurance Extraction

**Goal:** Extract ZTLP identity AND assurance level from client certificates and feed both into the PolicyEngine.

- After TLS handshake, extract the peer certificate (if provided):
  ```elixir
  case :ssl.peercert(tls_socket) do
    {:ok, der_cert} -> extract_identity_and_assurance(der_cert)
    {:error, :no_peercert} -> {:anonymous, :none}
  end
  ```
- Identity extraction chain:
  1. Parse X.509 cert from DER
  2. Check SAN for `URI:ztlp://node/<node_id>` → direct NodeID mapping
  3. Check CN for `<name>.<zone>.ztlp` → NS lookup for identity
  4. Verify cert was issued by our CA (chain validation already done by `:ssl`)
  5. Check if cert serial is revoked (NS revocation lookup)
  6. **Extract ZTLP assurance extensions from cert:**
     - OID `1.3.6.1.4.1.XXXXX.1` → assurance level (4/3/2/1)
     - OID `1.3.6.1.4.1.XXXXX.2` → key source (yubikey/tpm/secure-enclave/etc.)
     - OID `1.3.6.1.4.1.XXXXX.3` → attestation verified (true/false)
  7. **Check assurance level against `min_assurance` for the target service**
- Map extracted identity to PolicyEngine format:
  ```elixir
  # Same format as Noise_XX path, now with assurance:
  identity = Identity.resolve_or_hex(node_id_from_cert)
  assurance = TlsIdentity.extract_assurance(der_cert)
  
  # Policy check includes assurance level
  PolicyEngine.authorize?(identity, service_name, assurance: assurance.level)
  ```
- **Assurance-based access control at the gateway level:**
  ```elixir
  # Gateway rejects BEFORE reaching the backend if assurance too low
  min_assurance = Config.get_backend_min_assurance(service_name)
  
  if assurance.level < min_assurance do
    # Return 403 with helpful message
    send_assurance_rejection(tls_socket, assurance.level, min_assurance)
  end
  ```
- Anonymous TLS clients (no client cert):
  - If `mtls_required: true` → reject connection
  - If `mtls_required: false` → identity is `:anonymous`, assurance is `:none`
  - Policy can allow `:anonymous` access to specific public services

**New module:** `ZtlpGateway.TlsIdentity`

```elixir
# Extracts ZTLP identity AND assurance level from X.509 client certificates
# Handles SAN parsing, assurance extension parsing, NS lookups, revocation checks

defmodule ZtlpGateway.TlsIdentity do
  @ztlp_assurance_oid {1, 3, 6, 1, 4, 1, :XXXXX, 1}
  @ztlp_key_source_oid {1, 3, 6, 1, 4, 1, :XXXXX, 2}
  @ztlp_attestation_oid {1, 3, 6, 1, 4, 1, :XXXXX, 3}

  @type assurance_info :: %{
    level: :hardware | :device_bound | :software | :unknown | :none,
    key_source: String.t(),
    attestation_verified: boolean()
  }

  @spec extract(binary()) :: {identity :: term(), assurance_info()}
  def extract(der_cert) do
    # ...
  end
end
```

**Files:**
- `gateway/lib/ztlp_gateway/tls_identity.ex` — cert → identity + assurance extraction
- Update `gateway/lib/ztlp_gateway/tls_session.ex` — identity + assurance extraction after handshake
- Update `gateway/lib/ztlp_gateway/policy_engine.ex` — handle `:anonymous` identity + `min_assurance` check

**Tests:** ~50 (was ~40, +10 for assurance extraction, level comparison, gateway-level rejection)

---

#### 2E — Identity Header Injection & Passwordless Auth

**Goal:** Inject trusted ZTLP identity headers into HTTP requests so backend apps get cryptographically-verified user identity without building their own auth. Enables passwordless login.

This is the feature that transforms ZTLP from "secure transport" into "zero-trust application identity." The app doesn't build an auth layer — it reads headers that the gateway guarantees are authentic.

##### The Problem This Solves

Without identity headers, even with mTLS:
1. Gateway knows the client is `steve@corp.ztlp` (from cert)
2. Gateway opens TCP connection to backend
3. Backend sees raw HTTP bytes — has NO idea who the client is
4. Backend still needs its own login page, password database, session cookies
5. User could type any username at the login form — the app can't verify it

With identity headers:
1. Gateway extracts identity from mTLS cert
2. Gateway parses the HTTP request, strips any forged `X-ZTLP-*` headers
3. Gateway injects authenticated headers + HMAC signature
4. Backend reads `X-ZTLP-Identity: steve@corp.ztlp` — guaranteed by gateway
5. Backend auto-logs in the user. No password. No form. No MFA.

##### Auth Modes (per-service configuration)

| Mode | mTLS Required | Headers Injected | Login Page Needed | Use Case |
|------|:---:|:---:|:---:|------|
| `passthrough` | No | No | Yes (app's own) | Public-facing apps, legacy apps not yet integrated |
| `identity` | Optional | Yes (if cert present) | Optional | Apps that support both password and passwordless login |
| `enforce` | **Yes** | Yes | **No** | Internal tools, admin panels — pure zero-trust passwordless |

##### Identity Headers

| Header | Description | Example |
|--------|-------------|---------|
| `X-ZTLP-Identity` | User/device FQDN from cert | `steve@corp.ztlp` |
| `X-ZTLP-Node-ID` | 128-bit NodeID (hex) | `a1b2c3d4e5f60718...` |
| `X-ZTLP-Zone` | Zone the identity belongs to | `corp.ztlp` |
| `X-ZTLP-Groups` | Comma-separated group memberships | `admins,engineering` |
| `X-ZTLP-Device` | Device name (if device cert) | `laptop-01.corp.ztlp` |
| `X-ZTLP-Verified` | Whether mTLS identity was verified | `true` or `false` |
| `X-ZTLP-Assurance` | Authentication strength level | `hardware` / `device-bound` / `software` / `unknown` |
| `X-ZTLP-Key-Source` | Where the private key lives | `yubikey` / `tpm` / `secure-enclave` / `strongbox` / `file` / `unknown` |
| `X-ZTLP-Key-Attestation` | Whether hardware attestation was verified | `true` / `false` |
| `X-ZTLP-Timestamp` | Unix timestamp of header injection | `1711062600` |
| `X-ZTLP-Signature` | HMAC-SHA256 of all above headers | `sha256=a1b2c3...` |

##### Header Injection Flow

```
Client HTTP request arrives over TLS:
    GET /dashboard HTTP/1.1
    Host: webapp.corp.ztlp
    X-ZTLP-Identity: evil-attempt-to-forge    ← attacker tries this
    Cookie: session=abc123

Gateway processing:
    1. Extract mTLS identity → steve@corp.ztlp
    2. Extract assurance from cert extensions → hardware, yubikey, attested
    3. Check min_assurance for this backend → passes (hardware ≥ software)
    4. Query NS for group memberships → [admins, engineering]
    5. Strip ALL existing X-ZTLP-* headers from request  ← forgery prevention
    6. Inject authenticated headers (identity + assurance)
    7. Compute HMAC-SHA256 over injected headers
    8. Forward modified request to backend

Backend receives:
    GET /dashboard HTTP/1.1
    Host: webapp.corp.ztlp
    Cookie: session=abc123
    X-ZTLP-Identity: steve@corp.ztlp           ← gateway-injected
    X-ZTLP-Node-ID: a1b2c3d4e5f60718...        ← gateway-injected
    X-ZTLP-Zone: corp.ztlp                      ← gateway-injected
    X-ZTLP-Groups: admins,engineering            ← gateway-injected
    X-ZTLP-Device: steve-macbook.corp.ztlp       ← gateway-injected
    X-ZTLP-Verified: true                        ← gateway-injected
    X-ZTLP-Assurance: hardware                   ← gateway-injected (from cert)
    X-ZTLP-Key-Source: yubikey                   ← gateway-injected (from cert)
    X-ZTLP-Key-Attestation: true                 ← gateway-injected (from cert)
    X-ZTLP-Timestamp: 1711062600                 ← gateway-injected
    X-ZTLP-Signature: sha256=9f8e7d6c5b4a...    ← gateway-injected (HMAC proof)
```

##### HMAC Signature (Anti-Forgery)

Even though the backend should only be reachable through the gateway, defense in depth says we sign the headers:

```elixir
# Gateway computes:
payload = "#{identity}|#{node_id}|#{zone}|#{groups}|#{device}|#{verified}|#{assurance}|#{key_source}|#{key_attestation}|#{timestamp}"
signature = :crypto.mac(:hmac, :sha256, shared_secret, payload) |> Base.encode16(case: :lower)

# Backend verifies:
# 1. Parse X-ZTLP-Signature header
# 2. Recompute HMAC from the other X-ZTLP-* headers (including assurance fields)
# 3. Constant-time compare
# 4. Check timestamp is within acceptable window (e.g., ±60 seconds)
```

The shared secret is configured in both gateway and backend:
- Gateway: `ZTLP_HEADER_HMAC_SECRET` or `gateway.yml` → `tls.header_signing_secret`
- Backend: app reads from environment variable

##### HTTP Parsing (Minimal)

The gateway does NOT become a full HTTP reverse proxy. It only needs to:

1. **Buffer bytes until `\r\n\r\n`** — end of HTTP/1.1 headers (or HTTP/2 HEADERS frame)
2. **Scan for `X-ZTLP-` prefix** in header lines → remove them
3. **Append new `X-ZTLP-*` header lines** before the blank line
4. **Forward modified headers + body** to backend (body is never parsed)
5. **Response direction: pure passthrough** — no modification

For HTTP/2: frame-level header manipulation via HPACK. More complex but same principle.
For WebSocket: headers injected on the upgrade request, then pure passthrough.

```elixir
defmodule ZtlpGateway.HttpHeaderInjector do
  @moduledoc """
  Minimal HTTP header manipulation for identity injection.
  
  NOT a full HTTP parser. Only understands enough to:
  1. Find the end of HTTP headers
  2. Strip X-ZTLP-* headers (prevent forgery)
  3. Inject authenticated identity headers
  4. Pass everything else through unchanged
  """

  @ztlp_prefix "x-ztlp-"

  @doc """
  Process the first chunk of an HTTP request.
  
  Returns {:ok, modified_data, remaining_body_bytes} or
  {:incomplete, buffered} if headers aren't complete yet.
  """
  @spec inject(binary(), map(), binary()) :: {:ok, binary()} | {:incomplete, binary()}
  def inject(data, identity, hmac_secret) do
    case find_header_end(data) do
      {:ok, header_bytes, body_bytes} ->
        headers = parse_headers(header_bytes)
        cleaned = strip_ztlp_headers(headers)
        injected = append_identity_headers(cleaned, identity, hmac_secret)
        {:ok, serialize_headers(injected) <> body_bytes}
      
      :incomplete ->
        {:incomplete, data}
    end
  end
end
```

##### Backend Integration Examples

**Rails — Passwordless auto-login middleware with assurance checking:**

```ruby
# config/initializers/ztlp_auth.rb
class ZtlpAuth
  HMAC_SECRET = ENV["ZTLP_HEADER_HMAC_SECRET"]

  def initialize(app)
    @app = app
  end

  def call(env)
    request = Rack::Request.new(env)
    
    if valid_ztlp_headers?(request)
      identity = request.get_header("HTTP_X_ZTLP_IDENTITY")
      user = User.find_by(ztlp_identity: identity)
      
      if user
        # Auto-login — no password needed
        env["warden"].set_user(user) if defined?(Warden)
        # Or for simple apps:
        env["rack.session"]["user_id"] = user.id

        # Store assurance level for downstream use (step-up auth, audit, etc.)
        env["ztlp.assurance"] = request.get_header("HTTP_X_ZTLP_ASSURANCE")
        env["ztlp.key_source"] = request.get_header("HTTP_X_ZTLP_KEY_SOURCE")
      end
    end

    @app.call(env)
  end

  private

  def valid_ztlp_headers?(request)
    return false unless request.get_header("HTTP_X_ZTLP_VERIFIED") == "true"
    return false unless HMAC_SECRET
    
    # Verify HMAC signature
    timestamp = request.get_header("HTTP_X_ZTLP_TIMESTAMP").to_i
    return false if (Time.now.to_i - timestamp).abs > 60  # 60-second window
    
    payload = [
      request.get_header("HTTP_X_ZTLP_IDENTITY"),
      request.get_header("HTTP_X_ZTLP_NODE_ID"),
      request.get_header("HTTP_X_ZTLP_ZONE"),
      request.get_header("HTTP_X_ZTLP_GROUPS"),
      request.get_header("HTTP_X_ZTLP_DEVICE"),
      request.get_header("HTTP_X_ZTLP_VERIFIED"),
      request.get_header("HTTP_X_ZTLP_ASSURANCE"),
      request.get_header("HTTP_X_ZTLP_KEY_SOURCE"),
      request.get_header("HTTP_X_ZTLP_KEY_ATTESTATION"),
      timestamp.to_s
    ].join("|")
    
    expected = OpenSSL::HMAC.hexdigest("SHA256", HMAC_SECRET, payload)
    actual = request.get_header("HTTP_X_ZTLP_SIGNATURE")&.delete_prefix("sha256=")
    
    ActiveSupport::SecurityUtils.secure_compare(expected, actual || "")
  end
end

# Example: require hardware key for sensitive actions
class AdminController < ApplicationController
  before_action :require_hardware_key

  private

  def require_hardware_key
    assurance = request.env["ztlp.assurance"]

    unless assurance == "hardware"
      render status: 403, json: {
        error: "Hardware security key required",
        current_assurance: assurance,
        hint: "Connect your YubiKey and re-enroll: ztlp setup --hardware-key"
      }
    end
  end
end
```

**Express.js — Passwordless middleware:**

```javascript
// middleware/ztlpAuth.js
const crypto = require('crypto');
const HMAC_SECRET = process.env.ZTLP_HEADER_HMAC_SECRET;

function ztlpAuth(req, res, next) {
  if (req.headers['x-ztlp-verified'] !== 'true') return next();
  
  // Verify HMAC
  const ts = parseInt(req.headers['x-ztlp-timestamp']);
  if (Math.abs(Date.now() / 1000 - ts) > 60) return next();
  
  const payload = [
    req.headers['x-ztlp-identity'],
    req.headers['x-ztlp-node-id'],
    req.headers['x-ztlp-zone'],
    req.headers['x-ztlp-groups'],
    req.headers['x-ztlp-device'],
    req.headers['x-ztlp-verified'],
    req.headers['x-ztlp-assurance'],
    req.headers['x-ztlp-key-source'],
    req.headers['x-ztlp-key-attestation'],
    ts.toString()
  ].join('|');
  
  const expected = crypto.createHmac('sha256', HMAC_SECRET)
    .update(payload).digest('hex');
  const actual = (req.headers['x-ztlp-signature'] || '').replace('sha256=', '');
  
  if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual))) {
    req.ztlpIdentity = req.headers['x-ztlp-identity'];
    req.ztlpGroups = (req.headers['x-ztlp-groups'] || '').split(',');
    req.ztlpAssurance = req.headers['x-ztlp-assurance'];
    req.ztlpKeySource = req.headers['x-ztlp-key-source'];
    // Auto-login: set session, find user, etc.
  }
  
  next();
}
```

**Any language — the pattern is the same:**
1. Check `X-ZTLP-Verified: true`
2. Verify HMAC signature (prevents forgery even if backend is accidentally exposed)
3. Check timestamp freshness (prevents replay)
4. Read `X-ZTLP-Identity` → look up or create user → auto-login

##### What This Replaces

| Old Way | ZTLP Passwordless |
|---------|-------------------|
| Username + password form | Device cert → auto-login (no form) |
| Password database (bcrypt/argon2) | Not needed — identity is in the cert |
| Password reset emails | Not needed |
| MFA / TOTP / SMS codes | Not needed — cert IS "something you have" |
| Session cookies (expire, stolen) | Identity header on every request (stateless) |
| OAuth2 / OIDC / SAML redirects | Not needed for internal apps |
| API keys (leaked in repos, Slack) | mTLS service certs (never leave the machine) |
| VPN to reach internal tools | ZTLP IS the access layer |

##### Security Properties

1. **Headers are gateway-injected, never client-provided.** Gateway strips ALL incoming `X-ZTLP-*` headers before injecting its own. Clients cannot forge identity.

2. **Backend MUST only be reachable through the gateway.** If someone bypasses the gateway, they could forge headers. Enforced by:
   - Binding backend to `127.0.0.1` (same host) or private network
   - ZTLP policy blocking direct access
   - HMAC signature as defense-in-depth (even if reached directly, can't sign)

3. **HMAC-signed headers (defense in depth).** Shared secret between gateway and backend. Even if an attacker reaches the backend directly, they cannot produce a valid HMAC.

4. **Timestamp prevents replay.** 60-second window means captured headers can't be reused later.

5. **Group memberships are live.** Gateway queries NS for current group membership at request time (cached with short TTL). Removing a user from a group takes effect within the cache window.

##### Per-Service Auth Mode Configuration

```yaml
# gateway.yml — extended backend config
backends:
  - name: bootstrap
    host: 127.0.0.1
    port: 3000
    hostnames:
      - bootstrap.corp.ztlp
    auth_mode: enforce          # mTLS required, headers injected, no login page
    min_assurance: hardware     # YubiKey/TPM required for admin panel
    
  - name: lincx-tech
    host: 127.0.0.1
    port: 3001
    hostnames:
      - support.corp.ztlp
    auth_mode: identity         # mTLS optional, headers if cert present
    min_assurance: software     # any enrolled device is fine
    
  - name: lincx-customer
    host: 127.0.0.1
    port: 3001
    hostnames:
      - chat.corp.ztlp
    auth_mode: passthrough      # no mTLS, no headers, app handles auth
    # min_assurance: not applicable in passthrough mode
    
  - name: chooseforce
    host: 127.0.0.1
    port: 3002
    hostnames:
      - crm.corp.ztlp
    auth_mode: enforce          # passwordless — open URL, you're in
    min_assurance: device-bound # Secure Enclave / TPM minimum (no bare file keys)
    
  - name: prod-database
    host: 127.0.0.1
    port: 5432
    hostnames:
      - db.corp.ztlp
    auth_mode: enforce
    min_assurance: hardware     # dedicated hardware key ONLY
    required_groups: [dba]      # AND must be in the dba group

# HMAC signing secret (shared between gateway and backends)
tls:
  header_signing:
    enabled: true
    secret_env: ZTLP_HEADER_HMAC_SECRET    # read from env var
    # Or inline (not recommended for production):
    # secret: "your-256-bit-secret-here"
    timestamp_window_seconds: 60
    
    # Optional: per-backend secret override
    backend_secrets:
      bootstrap: "${BOOTSTRAP_HMAC_SECRET}"
      chooseforce: "${CHOOSEFORCE_HMAC_SECRET}"
```

##### Step-Up Authentication (Future Enhancement)

Assurance levels also enable **step-up auth** — access most things with a software key, but sensitive actions require presenting a hardware key:

```
Steve opens https://crm.corp.ztlp (min_assurance: software)
→ Software cert → X-ZTLP-Assurance: software → auto-login ✅

Steve clicks "Export all customer data"
→ App checks: this action requires assurance >= hardware
→ App redirects to gateway step-up endpoint: /ztlp/step-up?require=hardware
→ Gateway initiates new TLS handshake requesting hardware-backed cert
→ Steve taps YubiKey → browser presents hardware-backed cert
→ X-ZTLP-Assurance: hardware → action permitted ✅
→ Elevated session valid for configurable window (e.g., 15 minutes)
```

This mirrors how banks work — view your balance with a password, but wire $50K and you need a hardware token. Not in v1 scope, but the assurance headers make it possible without any protocol changes.

##### Gateway Rejection Response

When a client's assurance level is below `min_assurance`, the gateway returns a clear error before the request reaches the backend:

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "insufficient_assurance",
  "required": "hardware",
  "current": "software",
  "key_source": "file",
  "message": "This service requires a hardware security key (YubiKey, TPM, or Secure Enclave).",
  "hint": "Re-enroll with: ztlp setup --hardware-key"
}
```

##### SDK / Helper Libraries (Future)

To make backend integration even easier, publish lightweight HMAC-verification libraries:

- `ztlp-auth-ruby` (gem) — Rack middleware, Rails integration
- `ztlp-auth-node` (npm) — Express/Koa/Fastify middleware
- `ztlp-auth-python` (pip) — Django/Flask middleware
- `ztlp-auth-go` (module) — net/http middleware
- `ztlp-auth-elixir` (hex) — Plug middleware

Each is ~50-100 lines. Just HMAC verification + header parsing. Not v1 scope, but worth noting.

**Files:**
- `gateway/lib/ztlp_gateway/http_header_injector.ex` — HTTP header parsing, stripping, injection
- `gateway/lib/ztlp_gateway/header_signer.ex` — HMAC-SHA256 computation and verification
- Update `gateway/lib/ztlp_gateway/tls_session.ex` — wire up header injection after identity extraction
- Update `gateway/lib/ztlp_gateway/config.ex` — `auth_mode` and `header_signing` config
- `docs/PASSWORDLESS.md` — Passwordless auth guide with backend integration examples
- `docs/IDENTITY-HEADERS.md` — Header reference, security model, HMAC verification guide

**Tests:** ~55
- Header injection/stripping (various HTTP request formats)
- HMAC computation and verification
- Forged header rejection
- Auth mode enforcement (passthrough/identity/enforce)
- Timestamp window validation
- Group membership resolution
- WebSocket upgrade header injection
- Malformed HTTP handling (graceful fallback to passthrough)
- HTTP/1.0, HTTP/1.1, chunked transfer edge cases

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
Phase 2D: mTLS Identity ───► Phase 2E: Identity Headers & Passwordless
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
- **Phase 1:** ~140 tests, ~3,100 lines (Elixir + Rust) — includes hardware key detection, attestation verification, assurance extensions
- **Phase 2:** ~215 tests, ~3,000 lines (Elixir) — includes 2E identity headers + assurance headers + gateway min_assurance enforcement
- **Phase 3:** ~25 tests, ~800 lines (Rust)
- **Phase 4:** ~40 tests, ~1,200 lines (Elixir) — optional
- **Phase 5:** ~35 tests, ~600 lines (Elixir)
- **Phase 6:** ~15 tests, ~500 lines + docs

**Total: ~470 tests, ~9,200 lines** (excluding Phase 4)
**With Phase 4: ~510 tests, ~10,400 lines**

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
| Forged `X-ZTLP-*` headers | Gateway strips ALL incoming `X-ZTLP-*` before injecting; only gateway can set them |
| Direct backend access (bypass gateway) | Backend binds to localhost; HMAC signature as defense-in-depth |
| Header replay attack | Timestamp in HMAC payload; 60-second validity window |
| HMAC secret compromise | Per-backend secret override; rotation without downtime; secret from env vars (not config files) |
| User impersonation at login | `enforce` mode: identity comes from cert, no login form exists; `identity` mode: app can cross-check form input against header |
| Fake assurance level claim | Assurance is embedded in cert at issuance time (X.509 extensions), verified by NS against manufacturer attestation roots; can't be modified client-side |
| Software key claiming hardware | NS verifies attestation chain against known manufacturer root CAs (Yubico, Intel TPM, Apple, Google); no attestation = Level 2 max |
| Stolen laptop with software key | `min_assurance: hardware` or `min_assurance: device-bound` blocks software keys from sensitive services; full-disk encryption is complementary |
| Hardware key lost/stolen | Revocation via NS `:revoke` record; short-lived certs (30 days) limit blast radius; re-enrollment requires new enrollment token from admin |

### Key Decisions

1. **Ed25519 vs RSA for root CA:** Ed25519 is better (faster, smaller), but some older clients/browsers don't support Ed25519 in X.509. Default to Ed25519 with RSA-4096 fallback option.

2. **Short-lived certs (7 days):** Reduces revocation dependency. Even if revocation fails, a compromised cert is useless in a week. Matches Tailscale's approach.

3. **mTLS optional by default:** Requiring mTLS everywhere would break browser usability for services that don't need strong client identity. Per-service policy controls this.

4. **No OCSP in v1:** CRL is simpler and sufficient for the scale. OCSP adds latency to every TLS handshake. Revisit if needed.

5. **Minimal HTTP parsing for identity headers:** The gateway does NOT become a full reverse proxy. It only parses enough HTTP to strip forged `X-ZTLP-*` headers and inject authenticated ones. Request bodies are never parsed. Response direction is pure passthrough. Services configured as `auth_mode: passthrough` get zero HTTP parsing — pure TCP proxy as before.

6. **Three auth modes per service:** `passthrough` (legacy/public), `identity` (headers if cert present, app chooses), `enforce` (mTLS required, passwordless). This gives a migration path — start with `passthrough`, move to `identity`, graduate to `enforce` as trust grows.

7. **HMAC-signed headers:** Defense in depth. Even if someone reaches the backend directly (misconfigured firewall, etc.), they can't produce valid HMAC signatures. Per-backend secrets supported for isolation.

8. **Assurance is set at enrollment, not connection time.** The assurance level is baked into the X.509 cert when NS issues it. This means you can't "upgrade" assurance without re-enrolling. This is intentional — it forces the enrollment process to verify hardware attestation properly rather than trusting a runtime claim.

9. **Attestation is verified against manufacturer roots.** We don't trust the client's word that a key is on a YubiKey. NS verifies the attestation certificate chain against Yubico's/Intel's/Apple's published root CAs. No valid attestation chain = maximum Level 2 (software), regardless of what the client claims.

10. **Four assurance levels, not two.** "hardware" vs "software" isn't enough. A MacBook's Secure Enclave (device-bound, non-exportable) is meaningfully more secure than a key file, but meaningfully less secure than a removable YubiKey (which survives device compromise). Four levels let admins make nuanced policy decisions.

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
- `yubikey` crate — YubiKey PIV interface and attestation (for hardware key enrollment)
- `tss-esapi` crate — TPM 2.0 interface (key generation, attestation)
- `x509-parser` crate — X.509 extension parsing (assurance OID extraction)

### No New Elixir Dependencies
All X.509 work uses Erlang's built-in `:public_key` module. Zero external deps, consistent with the rest of the project.

---

## What This Enables

After all phases are complete:

```bash
# ── Admin setup (once per deployment) ──────────────────────────────

# Initialize the ZTLP Certificate Authority
ztlp admin ca init --org "Tech Rockstars"

# Issue cert for a web app
ztlp admin cert issue --service webapp.corp.ztlp

# Gateway config routes TLS → backend with auth_mode
# (gateway.yml already configured with backends + hostnames + auth_mode)


# ── User enrollment (once per device) ─────────────────────────────

ztlp setup --token ztlp://enroll/AQ... --trust-ca --install-client-cert
# → Identity provisioned (steve@corp.ztlp)
# → Root CA installed in system trust store (green lock in browsers)
# → Client cert installed in browser keychain (for mTLS)


# ── Daily use (zero friction) ─────────────────────────────────────

# Open any internal app — no login page, no password:
https://bootstrap.corp.ztlp    # ✅ Auto-logged in as steve@corp.ztlp
https://crm.corp.ztlp          # ✅ ChooseForce — instant access
https://grafana.corp.ztlp      # ✅ Dashboards — zero-click

# Backend app sees trusted headers:
#   X-ZTLP-Identity: steve@corp.ztlp
#   X-ZTLP-Groups: admins,engineering
#   X-ZTLP-Verified: true
#   X-ZTLP-Signature: sha256=9f8e7d...  (HMAC proof)

# App reads headers → auto-login → done. No password. No MFA. No OAuth.

# Customer-facing endpoints still work normally:
https://chat.corp.ztlp         # ✅ passthrough mode — app's own login

# From ZTLP native client (unchanged):
ztlp connect webapp.corp.ztlp  # ✅ Same backend, same policy, ZTLP/UDP path

# Both paths: same PolicyEngine, same AuditLog, same identity model
```

### What Passwordless Eliminates

For every internal app behind ZTLP with `auth_mode: enforce`:

| Component | Status |
|-----------|--------|
| Login page | **Delete it** |
| Password database (bcrypt/argon2) | **Delete it** |
| Password reset flow | **Delete it** |
| "Forgot password" emails | **Gone** |
| MFA / TOTP / SMS codes | **Not needed** — the cert IS the second factor |
| Session cookie management | **Optional** — identity on every request |
| OAuth2 / OIDC integration | **Not needed** for internal apps |
| API key rotation | **Replaced** by mTLS service certs |
| VPN client | **Replaced** by ZTLP |

For apps in `identity` mode (supporting both), you keep the login page as fallback but most enrolled users never see it.

---

## Version Target

Released as **v0.11.2**.

---

## Implementation Notes (v0.11.2)

### What Was Implemented

**Phase 1 — Internal Certificate Authority**
- `ZtlpNs.CertAuthority` — Root + intermediate CA generation, key management
- `ZtlpNs.CertIssuer` — Service and client certificate issuance with ZTLP extensions
- `ZtlpNs.X509` — Pure Erlang `:public_key`-based X.509 builder (zero external deps)
- Attestation verification for YubiKey, TPM, Secure Enclave
- Custom X.509 extensions: assurance level (OID ...59999.1), key source (...59999.2), attestation (...59999.3)

**Phase 2 — Gateway TLS Listener & Session**
- `ZtlpGateway.TlsListener` — Production TLS acceptor pool with mTLS support
- `ZtlpGateway.TlsSession` — Full session lifecycle: handshake → identity → CRL check → policy → assurance → proxy
- `ZtlpGateway.TlsIdentity` — mTLS identity extraction (NodeID, zone, assurance from X.509 cert)
- `ZtlpGateway.SniRouter` — SNI-based backend routing with per-backend auth config
- `ZtlpGateway.HttpHeaderInjector` — Identity header injection with HMAC-SHA256 signing
- `ZtlpGateway.CertCache` — Certificate cache with TTL

**Phase 3 — Client-Side CA Trust**
- Rust agent: OS trust store installation (macOS, Linux, Windows)
- Browser certificate installation (Chrome, Firefox, Safari)
- Hardware key detection (YubiKey, TPM, Secure Enclave)

**Phase 5A — TLS Audit Logging**
- TLS events in `AuditLog`: connection established/closed, identity, policy, cert lifecycle
- Structured JSON audit trail

**Phase 5B — Prometheus Metrics**
- TLS connection counters, handshake duration, bytes in/out
- mTLS auth metrics, cert expiry tracking

**Phase 5C — Certificate Revocation Integration**
- `ZtlpGateway.CrlServer` — ETS-backed CRL with fingerprint + serial lookup
- `TlsSession.check_revocation/1` — CRL check in the mTLS session pipeline
- Revoked certs rejected with HTTP 403 `cert_revoked` before reaching backend
- CRL changes take effect immediately on new connections (no caching delay)
- Resilient to CrlServer not being started (graceful degradation)

**Phase 6 — CLI, Config & Documentation**
- YAML config: full TLS section with `cert_source`, `min_version`, `mtls` sub-section
- Per-backend: `auth_mode`, `min_assurance`, `hostnames`, `required_groups`
- CLI: `ztlp admin ca-init/ca-show/ca-export-root/ca-rotate-intermediate`
- CLI: `ztlp admin cert-issue/cert-list/cert-show/cert-revoke`
- Documentation: TLS architecture, passwordless guide, identity headers, internal CA

### Phase 4 (ACME) — Deferred

ACME/Let's Encrypt integration is not needed for internal zero-trust deployments where all clients install the ZTLP root CA via `ztlp setup`. The internal CA provides all necessary trust. ACME may be revisited for public-facing edges in a future release.

### Test Coverage

- Gateway: 555 tests (was 531 pre-revocation integration)
- NS: 722 tests
- Relay: 565 tests
- Total: 1,842+ tests, 0 failures

---

_Last updated: 2026-03-24_
