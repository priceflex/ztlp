# TLS Architecture

ZTLP provides an integrated TLS termination layer at the gateway, enabling
encrypted connections, mutual TLS authentication, and passwordless identity
propagation to backend services.

## Overview

```
Client (browser / app / CLI)
  │
  │  TLS 1.3 + optional mTLS
  │
  ▼
┌─────────────────────────────────────────┐
│         ZTLP Gateway                     │
│  ┌───────────┐  ┌────────────────┐      │
│  │TlsListener│→ │  TlsSession    │      │
│  └───────────┘  │ (per-connection)│      │
│                 └───────┬────────┘      │
│       ┌─────────────────┼───────┐       │
│       ▼                 ▼       ▼       │
│  TlsIdentity    SniRouter   PolicyEngine│
│  (extract cert)  (hostname   (authorize │
│                   → backend)  identity)  │
│       │                         │       │
│       ▼                         │       │
│  HttpHeaderInjector ◄───────────┘       │
│  (strip + inject + HMAC-sign)           │
│       │                                 │
│       ▼                                 │
│  Backend Service (HTTP, plain TCP)      │
└─────────────────────────────────────────┘
```

## Components

### TlsListener

Listens on the TLS port (default: 8443), accepts TCP connections, performs
the TLS handshake, and spawns a `TlsSession` for each accepted connection.

- Configurable number of acceptor processes
- Supports TLS 1.2 and 1.3
- Optionally requires or accepts client certificates (mTLS)

### TlsSession

Manages the full lifecycle of a single TLS client connection:

1. **Identity extraction** — Calls `TlsIdentity.extract_from_socket/1` to
   read the client certificate and extract NodeID, user, zone, and
   assurance level.
2. **SNI routing** — Uses `SniRouter.resolve/1` to determine which backend
   should receive the traffic based on the SNI hostname.
3. **Policy check** — Calls `PolicyEngine.authorize?/2` to verify the
   identity is permitted to access the target service.
4. **Assurance check** — Verifies the client's authentication assurance
   level meets the backend's minimum requirement.
5. **Header injection** — For HTTP traffic, strips any spoofed identity
   headers and injects verified `X-ZTLP-*` headers signed with HMAC.
6. **Bidirectional proxy** — Forwards data between client and backend,
   tracking bytes transferred.
7. **Audit** — Logs connection events, policy decisions, and transfer stats.

### TlsIdentity

Extracts identity information from a client's TLS certificate:

- **NodeID** — from the certificate's Subject CN or SAN
- **Zone** — from the certificate's Organization
- **Assurance level** — from the certificate extension (software,
  device-bound, or hardware)
- **Key source** — whether the private key is in a file, TPM, or hardware
  security module

### SniRouter

Routes incoming connections to backend services based on the TLS Server
Name Indication (SNI) hostname. Each backend can be configured with:

- Hostnames it serves
- Auth mode (passthrough / identity / enforce)
- Minimum assurance level
- Required groups

### HttpHeaderInjector

Strips any incoming `X-ZTLP-*` headers (preventing spoofing) and injects
verified identity headers:

- `X-ZTLP-Node-ID` — authenticated node identifier
- `X-ZTLP-Node-Name` — human-readable node name
- `X-ZTLP-User` — authenticated user identity
- `X-ZTLP-Zone` — network zone
- `X-ZTLP-Assurance` — authentication assurance level
- `X-ZTLP-Groups` — comma-separated group memberships
- `X-ZTLP-Timestamp` — injection timestamp (Unix seconds)
- `X-ZTLP-Signature` — HMAC-SHA256 signature of all identity headers

### HeaderSigner

Signs identity headers with HMAC-SHA256 so backends can verify the headers
were injected by the gateway and not spoofed by a client.

### CertCache

Caches parsed certificates and CRL data to avoid repeated disk/network
reads. Entries have configurable TTL.

### CrlServer

Serves Certificate Revocation Lists (CRLs) over HTTP so clients can check
whether a certificate has been revoked.

## Configuration

TLS settings are configured in the gateway YAML config:

```yaml
tls:
  enabled: true
  port: 8443
  acceptors: 10
  cert_file: /etc/ztlp/gateway.pem
  key_file: /etc/ztlp/gateway.key
  ca_cert_file: /etc/ztlp/ca.pem
  mtls_required: false      # require client certs
  mtls_optional: true       # accept client certs if presented

  header_signing:
    enabled: true
    secret_env: ZTLP_HEADER_HMAC_SECRET
    timestamp_window_seconds: 60

backends:
  - name: admin-panel
    host: 127.0.0.1
    port: 3000
    auth_mode: enforce        # require mTLS
    min_assurance: hardware   # require hardware key
    hostnames:
      - admin.corp.ztlp
    required_groups:
      - admins

  - name: webapp
    host: 127.0.0.1
    port: 8080
    auth_mode: identity       # inject headers, don't require mTLS
    hostnames:
      - app.corp.ztlp
      - www.corp.ztlp

  - name: legacy
    host: 127.0.0.1
    port: 9000
    auth_mode: passthrough    # no identity injection
```

## Auth Modes

| Mode | Client Cert | Headers Injected | Access Control |
|------|------------|-----------------|----------------|
| **passthrough** | Ignored | No | None |
| **identity** | Optional | Yes (if present) | No |
| **enforce** | Required | Yes | Policy check + assurance |

## Audit Events

All TLS activity is logged to the gateway audit log:

- `tls_connection_established` — new TLS connection
- `tls_mtls_identity` — client certificate identity extracted
- `tls_policy_decision` — allow/deny decision
- `tls_connection_closed` — connection ended (with duration + bytes)
- `tls_cert_issued` — new certificate issued
- `tls_cert_renewed` — certificate renewed
- `cert_revoked` — certificate revoked

## Security Model

1. **Zero trust** — Every connection is individually authenticated and
   authorized. No implicit trust based on network position.
2. **Defense in depth** — TLS encryption, mTLS authentication, policy
   authorization, header signing, and audit logging.
3. **No shared secrets in transit** — Identity propagation uses
   HMAC-signed headers, not bearer tokens.
4. **Assurance levels** — Services can require higher authentication
   strength (hardware keys) for sensitive operations.

## See Also

- [Identity Headers](IDENTITY-HEADERS.md) — header reference and HMAC verification
- [Passwordless Auth](PASSWORDLESS.md) — backend integration guide
- [Internal CA](INTERNAL-CA.md) — CA architecture and key management
- [mTLS Setup](MTLS-SETUP.md) — client authentication setup
