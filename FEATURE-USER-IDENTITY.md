# Feature: Device + User Identity Binding

**Status:** Proposed
**Author:** Steven Price
**Date:** 2026-03-12
**Depends on:** ZTLP-NS (Phase 4), Enrollment (Phase 10), Gateway Policy Engine (Phase 5)
**Natural home:** Bootstrap Server (ztlp-bootstrap)

---

## Problem

ZTLP today is device-centric. One device = one NodeID = one keypair. There's no way to:

- Express "Steve owns laptop, phone, and tablet"
- Write a policy like "Steve can access the VPN" (without listing every device NodeID)
- Know *who* enrolled a device after the fact
- Revoke a user's access across all their devices in one operation

The spec mentions user nodes (Section 25.2) and enterprise directory integration (Section 23.2) but nothing is implemented.

## Current State

| What | Status |
|------|--------|
| Device identity (NodeID + X25519) | ✅ Complete |
| Device enrollment (tokens, QR, CLI wizard) | ✅ Complete |
| ZTLP-NS record types (KEY, SVC, ATTEST, OPERATOR) | ✅ Complete |
| Gateway policy engine (NodeID-level) | ✅ Complete |
| User identity | ❌ Not started |
| User↔device binding | ❌ Not started |
| User-level policy | ❌ Not started |
| External IdP integration | ❌ Not started |

## Design

### New NS Record Type: `ZTLP_USER`

Binds a user identity to one or more device NodeIDs.

```
ZTLP_USER record data (sorted-key CBOR):
  device_node_ids : array of bytes    # 16-byte NodeIDs of bound devices
  display_name    : text              # "Steven Price"
  email           : text (optional)   # "steve@techrockstars.com"
  external_id     : text (optional)   # IdP subject claim (OIDC sub, SAML NameID)
  idp_issuer      : text (optional)   # "https://accounts.google.com"
  user_id         : bytes             # 16-byte UserID (random, stable)
```

Signed by the Enrollment Authority. Published in ZTLP-NS under `<username>.<zone>`.

**UserID is NOT a NodeID.** It's a separate 128-bit identifier in a distinct namespace. Users don't send packets — devices do. The UserID is purely an administrative/policy binding.

### Enrollment Enhancement

Extend the enrollment flow so tokens can carry a user identity claim:

```
Current:  admin creates token → device presents token → NS enrolls device
Proposed: admin creates token for user → device presents token → NS enrolls device AND binds it to the user
```

Wire format addition to enrollment token:
```
  user_id_len  : u16       (0 = no user binding)
  user_id      : [u8; 16]  (only if user_id_len > 0)
```

The NS enrollment handler creates/updates the `ZTLP_USER` record when a user-bound token is used, adding the new device's NodeID to the `device_node_ids` array.

### User-Level Policy

Extend the gateway policy engine to resolve user from device:

```
Current:  packet arrives → extract NodeID → check policy against NodeID
Proposed: packet arrives → extract NodeID → resolve UserID via ZTLP_USER → check policy against UserID OR NodeID
```

Policy record additions:
```
  allowed_user_ids : array of bytes   # UserIDs (in addition to existing allowed_node_ids)
  allowed_groups   : array of text    # future: group-based policy
```

Gateway caches UserID↔NodeID mappings from NS with TTL.

### User Revocation

Revoking a user = revoking all their device NodeIDs:

```
ztlp admin revoke-user --user steve.office.acme.ztlp
```

This publishes `ZTLP_REVOKE` records for every NodeID in the user's `device_node_ids` array, plus revokes the `ZTLP_USER` record itself.

Single-device revocation (lost phone) remains unchanged — revoke just that NodeID and remove it from the user's device list.

### External IdP Integration

Optional. For organizations with existing identity infrastructure:

| Provider | Integration Point | Mechanism |
|----------|------------------|-----------|
| Google Workspace | Enrollment | OIDC token validation at enrollment time |
| Azure AD / Entra | Enrollment | OIDC or SAML assertion |
| Okta | Enrollment | OIDC |
| LDAP / Active Directory | Enrollment | LDAP bind + group query |

The Bootstrap Server handles the IdP dance during enrollment:
1. User authenticates to IdP via browser
2. Bootstrap Server validates token/assertion, extracts user identity
3. Bootstrap Server generates enrollment token bound to that user identity
4. Device enrolls with user-bound token

This keeps the ZTLP protocol layer clean — IdP complexity lives in the Bootstrap Server, not in NS or the CLI.

## Implementation Phases

### Phase A — NS Record + CLI (Quick Win)
- Add `ZTLP_USER` record type to NS store
- Add `ztlp admin create-user` and `ztlp admin list-devices` CLI commands
- Manual user↔device binding (admin explicitly links them)
- ~1-2 days

### Phase B — Enrollment Binding (Core Feature)
- Extend enrollment token wire format with optional UserID
- NS enrollment handler auto-creates/updates `ZTLP_USER` records
- CLI shows "Enrolled as device X, bound to user Y"
- ~2-3 days

### Phase C — User-Level Policy (Unlocks Real Value)
- Gateway resolves UserID from NodeID via NS
- Policy engine evaluates `allowed_user_ids`
- Cache with TTL + revocation check
- ~2-3 days

### Phase D — Bootstrap Server Integration
- Web UI for user management (create, list devices, revoke)
- IdP integration (OIDC at minimum, SAML/LDAP stretch)
- Self-service device enrollment (user logs in → gets token → enrolls device)
- ~1-2 weeks (part of the Bootstrap Server project)

### Phase E — Group Policy (Future)
- `ZTLP_GROUP` record type
- Group membership in policy evaluation
- Directory sync (Azure AD groups, Google Workspace OUs)
- Scope TBD

## Security Considerations

- **UserID must not leak in wire protocol.** Packets carry NodeIDs only. UserID resolution happens at the gateway/policy layer, never on the wire.
- **IdP tokens are ephemeral.** They're validated once at enrollment time. ZTLP doesn't store or relay IdP tokens.
- **User revocation must be atomic.** Revoking a user must revoke all devices in a single NS transaction to prevent race conditions.
- **Privacy:** `ZTLP_USER` records may contain PII (name, email). Access to these records should be restricted to authorized administrators and policy engines.

## Open Questions

1. **Should devices be allowed to belong to multiple users?** (Shared kiosk scenario.) Current design says no — one device, one user. Shared devices get their own identity without user binding.
2. **Group nesting depth?** If groups are added in Phase E, how deep can group-of-groups go? Suggest max 3 levels.
3. **Offline user resolution?** If the gateway can't reach NS to resolve UserID, should it fall back to NodeID-only policy or deny? Suggest: cache + deny-on-stale (configurable).
4. **Certificate extension?** Should the CBOR certificate (Section 16.2.1) include a `user_id` field? Pros: gateway can resolve without NS query. Cons: certificate now leaks user binding to anyone who sees it.
