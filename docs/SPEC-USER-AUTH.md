# ZTLP Application-Aware User Authentication

**Status:** Planned  
**Author:** Steven Price  
**Date:** 2026-03-14  

## Problem

ZTLP authenticates **devices/nodes** (Ed25519 keypair → NodeID), not **users**. For shared platforms where multiple users access a service through ZTLP, the backend service has no way to know *which human* is on the other end of the tunnel.

## Use Cases

1. **Shared workstations/kiosks** — multiple users on one device, each needs their own identity
2. **Multi-tenant services** — a single ZTLP-protected API serving many organizations
3. **Audit trails** — compliance requires per-user logging, not per-device
4. **Role-based access** — different users get different service access through the same gateway

## Design: AUTH_TOKEN Frame (Option B)

### Wire Protocol

Post-handshake frame sent after Noise_XX completes:

```
AUTH_TOKEN (0x09):
  [identity_type: 1B]    — 0x01=email, 0x02=OIDC, 0x03=SAML, 0x04=custom
  [identity_len: 2B BE]
  [identity: variable]   — e.g. "steve@techrockstars.com"
  [token_len: 2B BE]
  [token: variable]      — JWT, SAML assertion, or opaque token
  [signature: 64B]       — Ed25519 sig over (identity_type ‖ identity ‖ token) from user's key
```

### Flow

```
Client                        Gateway                     Backend Service
  |                              |                              |
  |--- Noise_XX handshake ------>|  (node identity established) |
  |<-- handshake complete -------|                              |
  |                              |                              |
  |--- AUTH_TOKEN(JWT) --------->|  validate JWT                |
  |                              |  check user policy           |
  |                              |  inject identity headers     |
  |<-- AUTH_OK / REJECT ---------|                              |
  |                              |                              |
  |--- data ------TCP bridge---->|--X-ZTLP-User: steve@...---->|
  |                              |  X-ZTLP-Node: <NodeID>      |
```

### Gateway Policy Extension

```
# Per-user rules (in addition to existing per-node rules)
allow zone=services.corp user=steve@techrockstars.com service=*
allow zone=services.corp user=*.techrockstars.com service=dashboard
deny  zone=services.corp user=* service=admin
```

### Identity Injection

Gateway passes user identity to backend services via:

- **HTTP:** `X-ZTLP-User` and `X-ZTLP-Node` headers
- **TCP:** Environment variables `ZTLP_USER` and `ZTLP_NODE`
- **Unix socket:** SO_PEERCRED-style metadata

### Token Validation

Supported token types:
- **JWT (RS256/ES256)** — validate signature against known JWKS endpoint
- **OIDC** — validate against provider's discovery document
- **SAML** — validate XML signature against IdP certificate
- **Custom** — delegate to webhook for validation

### Key Management

User keys are SEPARATE from node keys:
- Node key: identifies the device, stored on device
- User key: identifies the human, can be stored in hardware token (YubiKey), OS keychain, or file
- A single node can present different user identities across connections

### Future: Option C (OIDC/SSO Bridge)

For full enterprise SSO, the gateway can act as an OIDC relying party:
1. Client connects → gateway returns OIDC challenge
2. Client opens browser → authenticates with IdP (Google, Okta, Azure AD)
3. IdP returns token → client sends AUTH_TOKEN to gateway
4. Gateway validates with IdP and caches session

This builds on Option B — same wire protocol, just adds the browser redirect flow.

## Implementation Phases

1. **Phase 1:** AUTH_TOKEN frame type, encoding/decoding, basic JWT validation
2. **Phase 2:** Gateway policy engine user rules, identity header injection
3. **Phase 3:** CLI `ztlp connect --user <email> --token <jwt>` 
4. **Phase 4:** Token refresh/rotation during long sessions
5. **Phase 5:** OIDC browser flow (Option C)

## Open Questions

- Should expired tokens cause tunnel teardown or just block new requests?
- How to handle token refresh for long-running tunnels (re-auth frame)?
- Should the gateway cache validated tokens (and for how long)?
- How to handle anonymous users (allow but tag as anonymous)?
