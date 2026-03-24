# ZTLP Signing Oracle — Hardware-Bound CA Architecture

**Status:** Draft Specification v0.1  
**Author:** Steven Price, Tech Rockstar Academy  
**Date:** 2026-03-24  
**Relates to:** [INTERNAL-CA.md](INTERNAL-CA.md) · [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md) · [TLS.md](TLS.md)

---

## 1. Problem Statement

The ZTLP Certificate Authority (CA) is the root of trust for the entire network. Every service cert, client cert, and identity binding chains back to the root CA private key. Today, this key lives as an encrypted file on the NS server's disk (`~/.ztlp/ca/root.key.enc`). This creates a single point of failure:

- **VPS compromise** → attacker gets the root CA key → can issue certs for anything
- **Disk theft / snapshot** → root key is AES-encrypted, but passphrase may be weak or discoverable
- **Cloud provider access** → hosting provider employees with physical/hypervisor access can read the disk
- **Default passphrase** → if `ZTLP_CA_PASSPHRASE` is not set, the key uses a hardcoded default

ZTLP's core principle is: *"If you cannot prove who you are, you do not exist on this network."* The CA signing authority should follow the same principle — the root key should be bound to physical hardware that YOU control, not to a rented disk.

---

## 2. Solution Overview

A **Signing Oracle** is a small service that holds the CA private key inside a hardware security module (HSM) and exposes a signing API over ZTLP. The key never leaves the hardware. The NS server sends certificate signing requests (CSRs) to the oracle; the oracle signs them and returns the signed certificate. If the oracle is offline, no new certificates can be issued — but existing certificates continue to work until they expire.

### Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        YOUR HARDWARE (home/office)                   │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │  Signing Oracle Daemon (ztlp-oracle)                          │   │
│  │                                                               │   │
│  │  ┌─────────────┐    ┌──────────────┐    ┌────────────────┐   │   │
│  │  │ ZTLP Agent  │◄──►│ Oracle API   │◄──►│  YubiKey 5     │   │   │
│  │  │ (tunnel)    │    │ (validates,  │    │  (PIV slot 9c) │   │   │
│  │  │             │    │  signs)      │    │  RSA-4096 key  │   │   │
│  │  └──────┬──────┘    └──────────────┘    └────────────────┘   │   │
│  │         │                                                     │   │
│  └─────────┼─────────────────────────────────────────────────────┘   │
│            │ Encrypted ZTLP tunnel                                    │
└────────────┼─────────────────────────────────────────────────────────┘
             │
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  Internet  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
             │
┌────────────┼─────────────────────────────────────────────────────────┐
│            │                     VPS (cloud)                          │
│  ┌─────────▼─────────────────────────────────────────────────────┐   │
│  │  NS Server (ZTLP-NS)                                          │   │
│  │                                                               │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌────────────────┐   │   │
│  │  │ CertIssuer   │───►│ OracleClient │───►│  ZTLP Agent    │   │   │
│  │  │ (builds CSR) │    │ (sends to    │    │  (tunnel to    │   │   │
│  │  │              │    │  oracle)     │    │   oracle)      │   │   │
│  │  └──────────────┘    └──────────────┘    └────────────────┘   │   │
│  │                                                               │   │
│  └───────────────────────────────────────────────────────────────┘   │
│                                                                      │
│  ┌───────────────────┐  ┌───────────────────┐                        │
│  │  Gateway          │  │  Relay            │                        │
│  │  (uses certs)     │  │  (forwards)       │                        │
│  └───────────────────┘  └───────────────────┘                        │
└──────────────────────────────────────────────────────────────────────┘
```

### Key Insight

The signing oracle is itself a ZTLP service. It's invisible to the internet (no exposed ports) and only accessible through an authenticated ZTLP tunnel. This means an attacker would need to:

1. Compromise a ZTLP identity with oracle access (policy-controlled)
2. Through an encrypted tunnel to the oracle
3. Which still requires the physical YubiKey to be plugged in and touched

Three independent factors: network identity, encrypted tunnel, physical hardware.

---

## 3. Hardware Requirements

### 3.1 Recommended: YubiKey 5 Series

| Feature | Requirement | YubiKey 5 NFC | YubiKey 5C | YubiKey 5Ci |
|---|---|---|---|---|
| **PIV (Smart Card)** | Required | ✅ | ✅ | ✅ |
| **RSA-4096** | Required for CA signing | ✅ | ✅ | ✅ |
| **ECDSA P-384** | Optional (faster signing) | ✅ | ✅ | ✅ |
| **Touch policy** | Required (physical presence) | ✅ | ✅ | ✅ |
| **PIN protection** | Required | ✅ | ✅ | ✅ |
| **Attestation** | Required (prove key is on hardware) | ✅ | ✅ | ✅ |
| **Interface** | USB-A, USB-C, or Lightning | USB-A + NFC | USB-C | USB-C + Lightning |
| **Approx. price** | — | $50 | $55 | $75 |

**Recommended model:** **YubiKey 5C NFC** ($55) — USB-C for modern machines, NFC for mobile backup.

**Why YubiKey over other HSMs:**
- FIPS 140-2 validated (Level 2, key generation Level 3)
- PIV interface is industry standard (PKCS#11 / CCID)
- Attestation support — the oracle can prove the key was generated on the YubiKey
- Touch policy — every signing operation requires physical touch (prevents remote abuse even if daemon is compromised)
- Affordable — $55 vs $1,500+/month for cloud HSMs
- No vendor lock-in — standard PIV/PKCS#11 interface works with any HSM

### 3.2 Also Supported

| Hardware | Interface | Notes |
|---|---|---|
| **YubiKey 5 FIPS** | PIV (PKCS#11) | FIPS 140-2 Level 3 overall. Required for government/regulated environments. ~$80. |
| **TPM 2.0** | `tpm2-tss` / `tpm2-pkcs11` | Built into most servers. Good for dedicated oracle hardware (e.g., NUC, Pi). No touch policy — relies on physical security of the machine. |
| **Apple Secure Enclave** | Security framework | Good for macOS-based oracle. Hardware-bound, biometric unlock available. Cannot export attestation like YubiKey. |
| **Nitrokey HSM 2** | PKCS#11 | Open-source firmware. RSA-4096 and ECC. ~$110. Good alternative to YubiKey. |
| **Cloud HSM** | PKCS#11 / vendor API | AWS CloudHSM ($1.50/hr), Azure HSM, GCP Cloud HSM. Expensive. Use when the oracle itself runs in the cloud (defeats the purpose of local control, but better than software keys). |

### 3.3 Minimum Requirements

Any HSM that supports:
- RSA-4096 key generation (key generated ON the device, never exported)
- RSA-SHA256 signing operations via PKCS#11 or native API
- PIN/password protection
- Ideally: touch/presence verification
- Ideally: attestation (proof that key is hardware-bound)

### 3.4 Backup Key

**CRITICAL:** You need TWO YubiKeys. One primary, one backup.

During CA initialization, the root CA key is generated on the primary YubiKey. The backup YubiKey is set up as follows:

- **Option A: Shared root key** — Generate the root key externally, import into both YubiKeys, then destroy the external copy. Both keys can sign. Downside: the key existed in software briefly.
- **Option B: Dual-root CA** — Generate independent root keys on each YubiKey. Cross-sign an intermediate CA. Clients trust both roots. No key ever leaves hardware. This is the recommended approach.
- **Option C: Recovery ceremony** — Don't back up the root key. If the primary YubiKey is lost, perform a recovery ceremony: generate a new root, re-issue all intermediates, push new root to all clients. High downtime but maximum security.

**Recommendation:** Option B (dual-root, cross-signed intermediate). Both YubiKeys can independently sign intermediates. Loss of one doesn't require network-wide re-enrollment.

---

## 4. Signing Oracle Daemon (`ztlp-oracle`)

### 4.1 Overview

A Rust daemon that:
1. Connects to the YubiKey via PKCS#11 (using the `cryptoki` or `yubikey-piv` crate)
2. Registers itself as a ZTLP service (`_oracle._ztlp.<zone>`)
3. Listens for signing requests over the ZTLP tunnel
4. Validates each request against policy
5. Signs using the hardware key (requires YubiKey touch)
6. Returns the signed certificate
7. Logs every signing operation to an append-only audit log

### 4.2 Wire Protocol

The oracle uses ZTLP's existing stream multiplexing (0x05-0x07 frames) over a Noise_XX tunnel. Messages are length-prefixed CBOR (RFC 8949) for compact binary encoding.

#### Request: `SIGN_REQUEST` (0x01)

```
┌────────────────────────────────────────────────┐
│ type: u8 = 0x01                                │
│ request_id: [u8; 16]     (random nonce)        │
│ operation: u8                                   │
│   0x01 = SIGN_INTERMEDIATE  (root signs inter) │
│   0x02 = SIGN_SERVICE_CERT  (inter signs leaf) │
│   0x03 = SIGN_CLIENT_CERT   (inter signs leaf) │
│   0x04 = SIGN_CRL           (inter signs CRL)  │
│   0x05 = GET_ROOT_CERT      (export public)    │
│   0x06 = GET_STATUS          (health check)    │
│ payload_len: u32 (big-endian)                   │
│ payload: [u8; payload_len]                      │
│   For SIGN_*: DER-encoded TBSCertificate       │
│   For GET_*: empty                              │
│ requester_proof: [u8; 64]                       │
│   Ed25519 signature over (request_id || op ||   │
│   payload) by the requester's identity key      │
└────────────────────────────────────────────────┘
```

#### Response: `SIGN_RESPONSE` (0x02)

```
┌────────────────────────────────────────────────┐
│ type: u8 = 0x02                                │
│ request_id: [u8; 16]     (echoed from request) │
│ status: u8                                      │
│   0x00 = OK                                    │
│   0x01 = DENIED (policy)                       │
│   0x02 = HARDWARE_ERROR (YubiKey not present)  │
│   0x03 = TOUCH_TIMEOUT (user didn't touch)     │
│   0x04 = INVALID_REQUEST                       │
│   0x05 = RATE_LIMITED                          │
│   0x06 = INTERNAL_ERROR                        │
│ payload_len: u32 (big-endian)                   │
│ payload: [u8; payload_len]                      │
│   For OK + SIGN_*: DER-encoded signed cert     │
│   For OK + GET_ROOT_CERT: DER root CA cert     │
│   For OK + GET_STATUS: CBOR status object      │
│   For errors: UTF-8 error message              │
│ oracle_signature: [u8; 64]                      │
│   Ed25519 signature over full response by the  │
│   oracle's identity key (proves oracle signed)  │
└────────────────────────────────────────────────┘
```

### 4.3 Configuration

```toml
# ~/.ztlp/oracle.toml

[oracle]
# PKCS#11 module path
# YubiKey: use yubico-piv-tool's PKCS#11 module
pkcs11_module = "/usr/lib/x86_64-linux-gnu/libykcs11.so"

# PIV slot for the root CA key
# Slot 9c = Digital Signature (most appropriate for CA signing)
# Slot 9a = Authentication (alternative)
piv_slot = "9c"

# PIN for the YubiKey (or path to file containing PIN)
# NEVER put the actual PIN in this file — use a file reference or env var
pin = "env:ZTLP_ORACLE_PIN"
# OR: pin = "file:/etc/ztlp/oracle-pin"

# Touch policy for signing operations
# "always" = require touch for every signature (RECOMMENDED)
# "cached" = touch once, cached for 15 seconds
# "never" = no touch required (NOT RECOMMENDED — defeats physical presence)
touch_policy = "always"

# Key type on the YubiKey
key_type = "rsa4096"     # or "eccp384"

[oracle.policy]
# Which ZTLP identities can request signatures
# This is the most critical ACL in the entire system
allowed_requesters = [
    "ns.home.ztlp",           # The NS server
    "ns-backup.home.ztlp",    # Backup NS
]

# Maximum signing operations per hour (rate limiting)
max_signs_per_hour = 100

# Maximum certificate validity the oracle will sign (days)
max_cert_validity_days = 90

# Require the requester's Ed25519 proof signature
require_requester_proof = true

[oracle.audit]
# Append-only audit log
log_path = "/var/log/ztlp/oracle-audit.log"

# Also forward audit events to syslog
syslog = true

# Sign audit log entries with oracle identity key
sign_audit_entries = true

[oracle.network]
# ZTLP zone to register in
zone = "home.ztlp"

# Service name (registered in ZTLP-NS)
service_name = "_oracle._ztlp.home.ztlp"

# Bind address for the ZTLP agent
bind = "0.0.0.0:0"

[oracle.backup]
# Path to backup YubiKey attestation cert (for dual-root verification)
backup_attestation_cert = "/etc/ztlp/backup-yubikey-attestation.pem"

# Enable dual-root mode
dual_root = true
```

### 4.4 Audit Log Format

Every signing operation is logged in JSON Lines format:

```jsonl
{"ts":"2026-03-24T18:30:00Z","op":"SIGN_SERVICE_CERT","requester":"ns.home.ztlp","subject_cn":"vault.home.ztlp","serial":"a1b2c3","validity_days":7,"key_slot":"9c","touch_required":true,"status":"OK","duration_ms":1250}
{"ts":"2026-03-24T18:30:05Z","op":"SIGN_CLIENT_CERT","requester":"ns.home.ztlp","subject_cn":"steve-macbook.home.ztlp","node_id":"abc123...","assurance":"hardware","serial":"d4e5f6","validity_days":30,"key_slot":"9c","touch_required":true,"status":"OK","duration_ms":980}
{"ts":"2026-03-24T19:00:00Z","op":"SIGN_SERVICE_CERT","requester":"unknown-node.evil.ztlp","status":"DENIED","reason":"requester not in allowed_requesters"}
```

Each entry is optionally Ed25519-signed by the oracle's identity key, producing a tamper-evident log.

---

## 5. Signing Flow

### 5.1 Initial CA Setup (One-Time)

```
Admin (with YubiKey plugged in):

1. ztlp oracle init --key-type rsa4096 --slot 9c --touch always
   ├─ Generates RSA-4096 key ON the YubiKey (slot 9c)
   ├─ Sets touch policy to "always"
   ├─ Creates self-signed root CA cert (10-year validity)
   ├─ Exports root CA cert (public only) to ~/.ztlp/ca/root.pem
   ├─ Retrieves attestation cert from YubiKey
   └─ Prints root CA fingerprint for verification

2. ztlp oracle init-backup --backup-key  (with backup YubiKey)
   ├─ Generates independent RSA-4096 key on backup YubiKey
   ├─ Creates second root CA cert
   ├─ Cross-signs: primary root signs backup root, backup signs primary
   ├─ Exports both root certs and cross-signatures
   └─ Stores backup attestation cert

3. ztlp oracle sign-intermediate
   ├─ NS generates intermediate CA keypair (software key, on NS server)
   ├─ NS sends CSR to oracle
   ├─ Oracle validates CSR
   ├─ YubiKey signs (TOUCH REQUIRED — admin must physically touch)
   ├─ Returns signed intermediate cert
   └─ NS stores intermediate cert + key for day-to-day issuance

4. Deploy root CA cert to all components:
   ├─ NS:      ~/.ztlp/ca/root.pem (already has it)
   ├─ Gateway: receives via NS record or config
   └─ Clients: receive during `ztlp setup` enrollment
```

### 5.2 Day-to-Day Certificate Issuance

```
                                           ┌─────────────────┐
                                           │   YubiKey 5C    │
                                           │  (your desk)    │
                                           └────────┬────────┘
                                                    │ PKCS#11
┌──────────┐     ┌──────────┐     ┌─────────────────▼────────────────┐
│  Client   │────►│   NS     │────►│  Signing Oracle                  │
│  enrolls  │ UDP │  server  │ZTLP │  (validates → signs → returns)  │
│           │     │          │tunnel│                                  │
└──────────┘     └────┬─────┘     └──────────────────────────────────┘
                      │                         │
                      │◄────────────────────────┘
                      │  signed cert
                      │
              ┌───────▼───────┐
              │ CertIssuer    │
              │ (wraps cert   │
              │  in response) │
              └───────┬───────┘
                      │
              ┌───────▼───────┐
              │ Client gets:  │
              │ - service cert│
              │ - chain.pem   │
              │ - root CA     │
              └───────────────┘
```

**Important distinction:** The intermediate CA key lives on the NS server (software). Day-to-day cert issuance (service certs, client certs) uses the intermediate key and does NOT require the oracle. The oracle is only needed for:

1. Signing a new intermediate CA (initial setup + rotation)
2. Signing CRLs with the root key
3. Emergency: direct root-signed certs (bypass intermediate)

This means the oracle can be **offline most of the time**. You plug in the YubiKey when you need to rotate the intermediate (every 90 days to 1 year), then unplug it. Day-to-day operations are unaffected.

### 5.3 Intermediate CA Rotation

```
Every 90 days (or on-demand):

1. NS generates new intermediate keypair
2. NS connects to oracle via ZTLP tunnel
3. NS sends SIGN_INTERMEDIATE request with new intermediate's public key
4. Oracle validates:
   ├─ Requester is in allowed_requesters list
   ├─ Request is properly signed by requester's identity key
   ├─ Validity period is within max_cert_validity_days
   └─ Rate limit not exceeded
5. YubiKey signs (admin touches YubiKey)
6. Oracle returns signed intermediate cert
7. NS installs new intermediate, keeps old one for existing certs
8. Gateway picks up new chain via NS record refresh
9. Old intermediate certs remain valid until they naturally expire
```

### 5.4 Emergency Root Revocation

If the intermediate CA is compromised:

```
1. Admin plugs in YubiKey
2. ztlp oracle revoke-intermediate --serial <compromised_serial>
3. Oracle signs a CRL entry with the root key (TOUCH REQUIRED)
4. NS publishes CRL update
5. Gateway's CrlServer picks up the revocation
6. All connections using certs from the compromised intermediate are rejected
7. Admin runs `ztlp oracle sign-intermediate` to issue a new intermediate
8. Clients auto-renew their certs (signed by new intermediate)
```

---

## 6. Security Analysis

### 6.1 Threat Model

| Threat | Without Oracle | With Oracle |
|---|---|---|
| **VPS disk compromised** | Root CA key stolen → attacker can issue ANY cert | Root key not on disk → attacker gets nothing (intermediate has limited validity + can be revoked) |
| **VPS root access** | Root CA key in process memory during signing | Root key never on VPS → not in memory, not on disk |
| **Cloud provider employee** | Can image disk, extract encrypted key, potentially brute-force passphrase | Nothing to extract — key is on your physical YubiKey |
| **NS process compromised** | Attacker can call CertAuthority.get_signing_key() to get intermediate key | Intermediate key is still on NS (this is unchanged), but root key is safe. Blast radius limited to intermediate validity period |
| **Oracle daemon compromised** | N/A | Attacker can send signing requests BUT: (1) YubiKey touch required, (2) rate limited, (3) policy-restricted. Cannot extract the key from hardware |
| **YubiKey physically stolen** | N/A | PIN-protected (3 attempts before lockout). Without PIN, key is unusable. Backup YubiKey allows revocation + re-keying |
| **Network MITM** | N/A | ZTLP tunnel is Noise_XX authenticated + encrypted. Oracle verifies requester identity. Cannot MITM |

### 6.2 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY 1: Physical hardware                         │
│                                                             │
│  YubiKey with:                                              │
│  - RSA-4096 root CA key (NEVER exported)                    │
│  - Touch-to-sign policy                                     │
│  - PIN protection (3 attempts)                              │
│  - FIPS 140-2 Level 2+ tamper resistance                    │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 2: Oracle daemon                             │
│                                                             │
│  Runs on YOUR hardware:                                     │
│  - Policy enforcement (who can request signatures)          │
│  - Rate limiting                                            │
│  - Audit logging                                            │
│  - ZTLP identity verification                               │
│  - Cannot extract key from YubiKey                          │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 3: ZTLP tunnel                               │
│                                                             │
│  Noise_XX authenticated encryption:                         │
│  - NS must have valid ZTLP identity                         │
│  - Mutual authentication                                    │
│  - Forward secrecy (ephemeral keys)                         │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 4: NS server (VPS)                           │
│                                                             │
│  Has: intermediate CA key (time-limited)                    │
│  Does NOT have: root CA key                                 │
│  Compromise impact: limited to intermediate validity period │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 What the Oracle Does NOT Protect Against

- **Compromise of the intermediate CA key on the NS server** — the oracle protects the root, not the intermediate. An attacker with NS access can issue certs using the intermediate until it's revoked. Mitigation: short intermediate validity (90 days), monitor audit logs, rotate frequently.
- **Physical theft of the YubiKey + knowledge of PIN** — game over. Mitigation: backup YubiKey, PUK for recovery, tamper-evident storage.
- **Admin social engineering** — if someone tricks the admin into touching the YubiKey for a malicious signing request. Mitigation: the oracle daemon displays the subject being signed before requesting touch. Admin should verify.
- **Supply chain attacks on the YubiKey** — if Yubico ships a compromised key. Mitigation: verify attestation against Yubico's published root, use FIPS-validated models, consider Nitrokey (open-source firmware) for paranoid deployments.

---

## 7. Oracle Host Options

### 7.1 Recommended: Raspberry Pi + YubiKey

| Component | Specification | Approx. Cost |
|---|---|---|
| Raspberry Pi 5 (4GB) | ARM Cortex-A76, enough for signing | $60 |
| YubiKey 5C NFC (primary) | USB-C, PIV, RSA-4096, touch | $55 |
| YubiKey 5C NFC (backup) | Identical to primary | $55 |
| USB-C hub (if needed) | For Pi 5 which has 2× USB-C | $15 |
| MicroSD card (32GB) | Boot + OS | $10 |
| Case + power supply | Official Pi case + USB-C PSU | $20 |
| **Total** | | **~$215** |

**Why a Pi:**
- Always-on, low power (~5W)
- USB for YubiKey
- Runs the ZTLP agent + oracle daemon
- Physical security: sits in your home/office, behind your router
- No cloud provider in the trust path

**Setup:**
```bash
# On the Raspberry Pi:
curl -fsSL https://get.ztlp.org | sh       # Install ZTLP
ztlp setup --zone home.ztlp                 # Enroll the Pi
ztlp oracle init --slot 9c --touch always   # Initialize CA on YubiKey
ztlp oracle start                            # Start the oracle daemon
```

### 7.2 Alternative: NUC / Mini-PC

For higher performance or if you need to run other services alongside:

| Component | Specification | Approx. Cost |
|---|---|---|
| Intel NUC 13 Pro (i5) | x86_64, 16GB RAM | $400 |
| YubiKey 5C NFC × 2 | Primary + backup | $110 |
| **Total** | | **~$510** |

### 7.3 Alternative: Your Existing Machine

The oracle can run on your workstation/laptop. The YubiKey stays plugged in when you're working. Downside: oracle is offline when you're away or the machine is asleep. This is fine for small deployments where cert issuance is infrequent.

### 7.4 For Cloud-Only Deployments

If you MUST run everything in the cloud (no local hardware), use a cloud HSM:

```toml
[oracle]
# AWS CloudHSM via PKCS#11
pkcs11_module = "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so"
pin = "env:CLOUDHSM_PIN"
touch_policy = "never"  # Cloud HSMs don't support touch
```

This is better than a software key but weaker than local hardware (you're trusting AWS). Cost: ~$1.50/hr ($1,095/month).

---

## 8. Implementation Plan

### Phase 1: YubiKey PKCS#11 Integration (Rust)

**New crate dependency:** `cryptoki = "0.7"` (Rust PKCS#11 bindings, pure safe Rust)

**New file:** `proto/src/oracle/mod.rs`

```
proto/src/oracle/
├── mod.rs           # Module declarations
├── pkcs11.rs        # PKCS#11 wrapper (YubiKey/HSM interface)
├── config.rs        # Oracle configuration (oracle.toml)
├── daemon.rs        # Oracle daemon main loop
├── protocol.rs      # Wire protocol (request/response types)
├── policy.rs        # Signing policy enforcement
├── audit.rs         # Audit logging
└── cli.rs           # CLI commands (oracle init/start/stop/status)
```

**Deliverables:**
- `pkcs11.rs`: Initialize PKCS#11 session, generate RSA-4096 key on YubiKey slot 9c, sign TBSCertificate, export public key, verify touch, get attestation cert
- `config.rs`: Parse `oracle.toml`, validate settings
- Unit tests for PKCS#11 operations (mock PKCS#11 module for CI)

**Estimated: ~1,200 lines**

### Phase 2: Oracle Daemon + Wire Protocol

**Deliverables:**
- `daemon.rs`: Start ZTLP agent, register as service, accept tunnel connections, main loop
- `protocol.rs`: CBOR encode/decode for SIGN_REQUEST, SIGN_RESPONSE, request_id generation, Ed25519 proof verification
- `policy.rs`: ACL check (allowed_requesters), rate limiting (token bucket), max validity enforcement, operation type restrictions
- `audit.rs`: JSON Lines append-only log, optional Ed25519 signing of entries, log rotation
- Integration with existing ZTLP agent infrastructure (tunnel, handshake, stream mux)

**Estimated: ~1,500 lines**

### Phase 3: NS OracleClient (Elixir)

**New file:** `ns/lib/ztlp_ns/oracle_client.ex`

**Deliverables:**
- `OracleClient` GenServer: connects to oracle via ZTLP tunnel, sends signing requests, handles responses
- Modify `CertAuthority.init_ca/1`: when `oracle_mode: true`, send CSR to oracle instead of signing locally
- Modify `CertIssuer`: when intermediate rotation is needed, request oracle signature
- Fallback: if oracle is unreachable, log error and use cached intermediate (don't issue new certs, but don't crash)
- Configuration: `ZTLP_ORACLE_ADDRESS`, `ZTLP_ORACLE_IDENTITY` env vars

**Estimated: ~600 lines**

### Phase 4: CLI Commands + Setup Ceremony

**New CLI commands:**

```
ztlp oracle init           Initialize CA on YubiKey (one-time setup ceremony)
    --slot <9a|9c|9d>      PIV slot (default: 9c)
    --key-type <rsa4096|eccp384>   Key type (default: rsa4096)
    --touch <always|cached|never>  Touch policy (default: always)
    --org <name>            Organization name for CA subject
    --validity-years <n>    Root CA validity (default: 10)

ztlp oracle init-backup    Set up backup YubiKey with cross-signed root
    --primary-serial <serial>    Primary YubiKey serial (for verification)

ztlp oracle start          Start the oracle daemon
    --foreground            Run in foreground (don't daemonize)
    --config <path>         Config file (default: ~/.ztlp/oracle.toml)

ztlp oracle stop           Stop the oracle daemon
ztlp oracle status         Show oracle status, key info, signing stats
ztlp oracle sign-intermediate   Request intermediate CA signing (interactive)
ztlp oracle revoke-intermediate  Revoke a compromised intermediate
ztlp oracle audit           Show recent audit log entries
    --tail <n>              Last N entries
    --since <datetime>      Entries since datetime
    --verify                Verify audit log signatures
```

**Estimated: ~800 lines**

### Phase 5: Dual-Root + Cross-Signing

**Deliverables:**
- Dual-root CA initialization ceremony
- Cross-signing logic (each root signs the other's cert)
- Client trust: both roots are distributed during enrollment
- Intermediate CA: can be signed by EITHER root
- Backup recovery procedure documentation

**Estimated: ~500 lines + docs**

### Total Estimated Implementation

| Phase | Lines | New Files | Effort |
|---|---|---|---|
| Phase 1: PKCS#11 | ~1,200 | 3 Rust | Medium |
| Phase 2: Daemon | ~1,500 | 4 Rust | Medium-High |
| Phase 3: NS Client | ~600 | 1 Elixir | Medium |
| Phase 4: CLI | ~800 | 1 Rust | Medium |
| Phase 5: Dual-root | ~500 | 0 (extends existing) | Medium |
| **Total** | **~4,600** | **9 new files** | **~3-4 days** |

---

## 9. YubiKey PIV Slot Reference

For reference, PIV defines 4 key slots:

| Slot | Name | Purpose | ZTLP Usage |
|---|---|---|---|
| **9a** | Authentication | Prove identity to a system | Agent identity key (optional future use) |
| **9c** | Digital Signature | Sign documents/certificates | **Root CA signing key** ← recommended |
| **9d** | Key Management | Encrypt/decrypt data | Not used |
| **9e** | Card Authentication | Contactless auth | Not used |
| **82-95** | Retired Key Management | Additional key slots | Backup keys, old keys |

**Slot 9c is ideal for CA signing because:**
- Its purpose is explicitly "digital signatures"
- Touch policy is enforced per-signature (not cached like 9a)
- Key cannot be used for encryption (separation of concerns)
- Standard PIV semantics — any PKCS#11 client understands it

---

## 10. Bootstrapping: Chicken-and-Egg Problem

The oracle communicates over ZTLP, but ZTLP needs certificates signed by the CA. How do we bootstrap?

### Solution: Pre-signed Intermediate

```
1. Admin initializes the oracle (YubiKey generates root key)
2. Admin generates intermediate CA keypair LOCALLY
3. Oracle signs the intermediate (local PKCS#11 call, no network needed)
4. Admin copies intermediate cert + key to the NS server
5. NS starts with the pre-signed intermediate
6. NS enrolls in ZTLP (gets its own identity)
7. Oracle enrolls in ZTLP (gets its own identity)
8. From this point on, all communication is over ZTLP tunnels
```

The first intermediate signing is a LOCAL operation (YubiKey plugged into the same machine). After that, the oracle and NS have ZTLP identities and communicate over tunnels.

For intermediate ROTATION (after the initial setup), the NS contacts the oracle over ZTLP to get a new intermediate signed. This is the steady-state flow.

---

## 11. Monitoring + Alerting

### Health Checks

The oracle exposes a `GET_STATUS` operation that returns:

```json
{
  "uptime_seconds": 86400,
  "yubikey_present": true,
  "yubikey_serial": "12345678",
  "key_slot": "9c",
  "key_type": "RSA-4096",
  "touch_policy": "always",
  "signs_today": 3,
  "signs_this_hour": 1,
  "last_sign_at": "2026-03-24T18:30:00Z",
  "rate_limit_remaining": 97,
  "root_cert_fingerprint": "ab:cd:ef:...",
  "root_cert_not_after": "2036-03-24T00:00:00Z",
  "attestation_verified": true
}
```

### Alerts

| Condition | Severity | Action |
|---|---|---|
| YubiKey removed | CRITICAL | Cannot sign. Notify admin immediately. |
| Oracle unreachable | WARNING | NS cannot rotate intermediate. Existing certs continue to work. |
| Rate limit exceeded | WARNING | Possible abuse. Check audit log. |
| Root cert expiring (< 1 year) | WARNING | Plan root CA rotation ceremony. |
| Signing request from unknown identity | ALERT | Potential attack. Log + deny. |
| Audit log signature mismatch | CRITICAL | Audit log has been tampered with. |
| Oracle daemon crash | CRITICAL | Auto-restart via systemd. Investigate. |

### Integration

- Prometheus metrics exposed via `/metrics` on a local-only port
- Syslog forwarding for audit events
- Optional webhook for critical alerts (via ZTLP tunnel to an alerting service)

---

## 12. Operational Procedures

### Routine: Intermediate CA Rotation (Every 90 Days)

```bash
# 1. Plug in YubiKey
# 2. Verify oracle is running
ztlp oracle status

# 3. Trigger rotation (NS will generate new intermediate, send CSR to oracle)
ztlp oracle sign-intermediate --rotate

# 4. Touch YubiKey when prompted
# 5. Verify new intermediate
ztlp admin ca-show

# 6. Unplug YubiKey (optional — can leave plugged in if oracle is on dedicated hardware)
```

### Emergency: Compromised Intermediate

```bash
# 1. Plug in YubiKey
# 2. Revoke compromised intermediate
ztlp oracle revoke-intermediate --serial <serial>  # Touch required

# 3. Sign new intermediate
ztlp oracle sign-intermediate  # Touch required

# 4. Force CRL push
ztlp admin crl-push

# 5. Verify clients are getting new certs
ztlp admin cert-list --expiring 24h
```

### Emergency: Lost Primary YubiKey

```bash
# 1. Get backup YubiKey from secure storage
# 2. Plug in backup YubiKey
# 3. Revoke primary root (using backup's cross-signature authority)
ztlp oracle revoke-root --primary  # Touch required on backup

# 4. Sign new intermediate with backup root
ztlp oracle sign-intermediate --use-backup  # Touch required

# 5. Order replacement YubiKey
# 6. When replacement arrives: set up as new backup
ztlp oracle init-backup --primary-serial <backup_serial>
```

### Disaster Recovery: Both YubiKeys Lost

```bash
# Nuclear option — full re-key ceremony
# 1. Generate new root CA (new YubiKey)
ztlp oracle init --slot 9c --touch always

# 2. Sign new intermediate
ztlp oracle sign-intermediate

# 3. Push new root CA to all clients
#    This requires re-enrollment of every device
ztlp admin broadcast-rekey --new-root ~/.ztlp/ca/root.pem

# 4. Each client runs:
ztlp setup --rekey --ns <ns_address>
```

---

## 13. Future Extensions

### 13.1 Multi-Oracle Quorum (M-of-N Signing)

For high-security deployments, require M-of-N oracles to co-sign:
- 3 YubiKeys held by 3 different people
- 2-of-3 must sign to issue an intermediate
- Prevents single-admin compromise
- Uses threshold signatures or serial co-signing

### 13.2 Air-Gapped Oracle

The ultimate hardening:
- Oracle hardware has NO network interface
- CSRs are transferred via USB drive or QR code
- Signed certs returned the same way
- Maximum security, maximum inconvenience
- Only practical for root CA operations (not day-to-day)

### 13.3 Mobile Oracle

YubiKey 5 NFC + iOS/Android app:
- ZTLP mobile agent on your phone
- YubiKey NFC tap to sign
- Oracle runs as a mobile app
- Convenient for mobile admins

### 13.4 Hardware Attestation for Client Enrollment

Extend the oracle to verify client hardware attestation during enrollment:
- Client claims "I have a YubiKey"
- Oracle verifies YubiKey attestation cert chain against Yubico's root
- Only then issues a cert with `assurance: hardware`
- Prevents clients from lying about their key source

---

## Appendix A: PKCS#11 API Surface

The oracle uses a minimal subset of PKCS#11:

| Function | Purpose |
|---|---|
| `C_Initialize` | Initialize PKCS#11 library |
| `C_OpenSession` | Open session with YubiKey |
| `C_Login` | Authenticate with PIN |
| `C_GenerateKeyPair` | Generate RSA-4096 on YubiKey (init only) |
| `C_Sign` | Sign TBSCertificate with private key |
| `C_GetAttributeValue` | Read public key, key type |
| `C_FindObjects` | Find key by slot/label |
| `C_Logout` | End session |
| `C_Finalize` | Cleanup |

**Total: 8 functions.** The attack surface of the PKCS#11 interface is minimal.

---

## Appendix B: YubiKey Setup Commands (Reference)

```bash
# Install YubiKey tools
# macOS:
brew install ykman yubico-piv-tool

# Linux:
apt install yubikey-manager yubico-piv-tool libykcs11-1

# Verify YubiKey is detected
ykman info

# Change default PIV PIN (default: 123456)
ykman piv access change-pin

# Change default PUK (default: 12345678)
ykman piv access change-puk

# Change default management key (default: 010203...0809)
ykman piv access change-management-key --generate --protect

# Set touch policy for slot 9c
# (This is done automatically by `ztlp oracle init`)
ykman piv keys generate 9c --algorithm RSA4096 --touch-policy always --pin-policy once pubkey.pem

# Verify attestation
ykman piv keys attest 9c attestation.pem
ykman piv certificates export f9 yubico-root.pem  # PIV attestation root
openssl verify -CAfile yubico-root.pem attestation.pem
```

---

## Appendix C: Comparison with Alternatives

| Approach | Root Key Location | Cost | Signing Latency | Offline Impact | ZTLP Alignment |
|---|---|---|---|---|---|
| **Software key on VPS** (current) | Encrypted file on disk | $0 | <1ms | None | ❌ Violates zero-trust at infra layer |
| **ZTLP Signing Oracle + YubiKey** (proposed) | YubiKey hardware | ~$215 | ~1s (touch) | Can't issue new certs; existing work fine | ✅ Hardware-bound, identity-verified, audit-logged |
| **Cloud HSM** | Cloud provider HSM | $1,095/mo | ~10ms | Depends on cloud | ⚠️ Trusts cloud provider |
| **Vault Transit** | HashiCorp Vault | $0 (OSS) + server | ~5ms | Vault must be up | ⚠️ Adds dependency, still software key unless Vault uses HSM |
| **Air-gapped ceremony** | USB drive / QR code | ~$215 | Minutes (manual) | Very high latency | ✅ Maximum security, minimum convenience |
