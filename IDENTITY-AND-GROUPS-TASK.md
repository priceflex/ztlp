# ZTLP Identity Model & Group Access Control

**Version:** v0.9.0 target  
**Prerequisite:** v0.8.0 (current)  
**Branch:** `main`

---

## Overview

ZTLP currently has a single identity type: a NodeID with a keypair registered in NS as a KEY record. This task adds **device identity**, **user identity**, **group membership**, and **admin controls** — the foundation for real MSP deployments.

Once complete, the MSP deployment guide can be written against the real identity model.

---

## Phase 1: Device + User Identity in NS (~2-3 hours)

### Goal
Two distinct identity types in NS: **DEVICE** (bound to hardware/machine) and **USER** (bound to a person). A user can be enrolled on multiple devices.

### New NS Record Types

```
DEVICE record (type byte: 0x10)
├── name: "laptop-01.techrockstars.ztlp"
├── node_id: 128-bit (hardware-bound)
├── pubkey: X25519 device key
├── owner: "steve@techrockstars.ztlp" (optional — links to USER)
├── hardware_id: optional platform identifier (TPM PCR, Secure Enclave ID)
├── created_at, ttl, serial
└── signature: Ed25519 (zone signing key)

USER record (type byte: 0x11)
├── name: "steve@techrockstars.ztlp"
├── pubkey: Ed25519 user signing key
├── devices: ["laptop-01.techrockstars.ztlp", "desktop-02.techrockstars.ztlp"]
├── email: optional (for display/audit)
├── role: "admin" | "tech" | "user" (default: "user")
├── created_at, ttl, serial
└── signature: Ed25519 (zone signing key or user's own key for self-updates)
```

### NS Changes

1. **`ns/lib/ztlp_ns/record.ex`** — Add `:device` and `:user` record types, constructors, validation
2. **`ns/lib/ztlp_ns/store.ex`** — Index devices by owner (Mnesia table `ztlp_ns_device_index`: owner → [device_name]). Add `lookup_devices_for_user/1`, `lookup_user_for_device/1`
3. **`ns/lib/ztlp_ns/wire.ex`** — Wire encode/decode for 0x10 DEVICE and 0x11 USER query/response
4. **`ns/lib/ztlp_ns/server.ex`** — Handle DEVICE and USER queries, registration with validation

### CLI Changes

```bash
# Enroll a device (extends existing `ztlp setup`)
ztlp setup --type device --owner steve@techrockstars.ztlp

# Create a user identity
ztlp admin create-user steve@techrockstars.ztlp --role admin --email steve@techrockstars.com

# Link device to user
ztlp admin link-device laptop-01.techrockstars.ztlp --owner steve@techrockstars.ztlp

# List user's devices
ztlp admin devices steve@techrockstars.ztlp
```

### Enrollment Flow Update

Current: `ztlp setup` → generates keypair → registers KEY record  
New: `ztlp setup` → asks "Device or User?" → generates keypair → registers DEVICE or USER record → if device, optionally links to user

### Tests
- Record creation/validation for DEVICE and USER
- Wire encode/decode round-trip
- Store: insert, lookup, index queries
- Device-user linking and unlinking
- Enrollment with --type flag
- Rejection of duplicate device names, duplicate user names

---

## Phase 2: Groups & Roles in NS (~2-3 hours)

### Goal
Named groups that contain users. Gateway policy engine checks group membership for access decisions.

### New NS Record Type

```
GROUP record (type byte: 0x12)
├── name: "admins@techrockstars.ztlp"
├── members: ["steve@techrockstars.ztlp", "alice@techrockstars.ztlp"]
├── description: optional
├── created_at, ttl, serial
└── signature: Ed25519 (zone signing key — only zone admins can create/modify groups)
```

### NS Changes

1. **`ns/lib/ztlp_ns/record.ex`** — Add `:group` type, member list validation
2. **`ns/lib/ztlp_ns/store.ex`** — Group membership index (Mnesia table `ztlp_ns_group_index`: user → [group_name]). Add `groups_for_user/1`, `members_of_group/1`, `is_member?/2`
3. **`ns/lib/ztlp_ns/wire.ex`** — Wire type 0x12 for GROUP queries
4. **`ns/lib/ztlp_ns/server.ex`** — GROUP query handler, registration restricted to zone signing key

### Gateway Policy Extension

Current gateway policy engine (`gateway/lib/ztlp_gateway/policy.ex`) matches on:
- Zone wildcards (`*.techrockstars.ztlp`)
- Specific node names

Extend to match on:
- **Group membership:** `group:admins@techrockstars.ztlp` in policy rules
- **Role:** `role:admin` matches any user with admin role
- Gateway queries NS for group membership at connection time (cached with TTL)

### Policy Config Example

```yaml
policies:
  - name: "Admin access to all services"
    match:
      group: "admins@techrockstars.ztlp"
    action: allow
    services: ["*"]

  - name: "Techs can access client networks"
    match:
      group: "techs@techrockstars.ztlp"
    action: allow
    services: ["*.clients.techrockstars.ztlp"]

  - name: "Default deny"
    match: "*"
    action: deny
```

### CLI Changes

```bash
# Create a group
ztlp admin create-group techs@techrockstars.ztlp --description "Field technicians"

# Add/remove members
ztlp admin group add techs@techrockstars.ztlp steve@techrockstars.ztlp
ztlp admin group remove techs@techrockstars.ztlp alice@techrockstars.ztlp

# List groups and members
ztlp admin groups
ztlp admin group members techs@techrockstars.ztlp

# Check membership
ztlp admin group check techs@techrockstars.ztlp steve@techrockstars.ztlp
```

### Tests
- Group CRUD (create, add member, remove member, delete)
- Membership queries (groups_for_user, members_of_group, is_member?)
- Wire encode/decode
- Gateway policy with group matching
- Nested groups NOT supported (keep it simple — flat membership)
- Only zone signing key can modify groups (authorization check)

---

## Phase 3: Admin Controls (~1-2 hours)

### Goal
CLI commands for zone administrators to manage identities, revoke access, and audit the namespace.

### CLI Commands

```bash
# List all enrolled entities
ztlp admin ls                              # All records
ztlp admin ls --type device                # Just devices
ztlp admin ls --type user                  # Just users
ztlp admin ls --type group                 # Just groups
ztlp admin ls --zone techrockstars.ztlp    # Filter by zone

# Revoke access (already partially built — extend for device/user/group)
ztlp admin revoke laptop-01.techrockstars.ztlp --reason "stolen device"
ztlp admin revoke steve@techrockstars.ztlp --reason "left company"

# Audit log
ztlp admin audit --since 24h              # Recent registrations/revocations
ztlp admin audit --name steve@*           # Filter by name pattern

# Key management
ztlp admin rotate-zone-key                # Generate new zone signing key, re-sign all records
ztlp admin export-zone-key --format pem   # Export for backup
```

### NS Registration Protection

Already built in v0.6.0 (`registration_auth.ex`):
- Ed25519 signature verification on registration
- Zone authorization (only zone signing key can register in its zone)

Extend with:
- **Key overwrite protection:** Reject registration if name already exists with different pubkey (unless signed by zone admin key with `force: true` flag)
- **Rate limiting per-identity:** Max 1 registration per name per hour (prevents key-rotation abuse)

### Revocation Enhancements

Current: Revocation records exist but only store `revoked_ids` list.  
Extend:
- Add `reason` field to revocation display
- Gateway checks revocation status on every connection (cached)
- Revoked devices/users get REJECT frame with `REVOKED` reason code (new code: 0x05)

### Tests
- `ztlp admin ls` output formatting
- Key overwrite protection (same name, different key → reject)
- Key overwrite with admin force flag → accept
- Revocation propagation to gateway
- Audit log filtering

---

## Phase 4: MSP Deployment Guide (~2-3 hours)

### Goal
Step-by-step guide for an MSP to deploy ZTLP to protect any internally-hosted web application.

### Document Structure: `DEPLOYMENT.md`

1. **Prerequisites** — Docker, domain, zone signing key
2. **NS Setup** — Run NS server, create zone, configure DNS TXT records for discovery
3. **Gateway Setup** — Docker container, policy config, TLS termination
4. **Enroll Admin** — `ztlp admin init-zone`, create admin user, set up zone signing key
5. **Enroll Technicians** — Create tech user accounts, add to `techs` group
6. **Enroll Customer Devices** — Generate enrollment tokens, distribute via QR or URL
7. **Protect a Web App** — Docker-compose template: `gateway → your-app` bridge, no exposed ports except ZTLP UDP
8. **Verify** — Test connectivity, check policy enforcement, audit log
9. **Day 2 Operations** — Revoke access, rotate keys, add new devices, monitor

### Docker-Compose Template

```yaml
# Protects any web app behind ZTLP
services:
  gateway:
    image: ztlp/gateway:latest
    ports:
      - "23095:23095/udp"  # Only ZTLP — no HTTP exposed
    environment:
      ZTLP_ZONE: "yourcompany.ztlp"
      ZTLP_NS_SERVER: "ns.yourcompany.ztlp:23096"
      ZTLP_POLICY_FILE: "/etc/ztlp/policy.yaml"
    volumes:
      - ./policy.yaml:/etc/ztlp/policy.yaml
      - ./keys:/etc/ztlp/keys

  your-app:
    image: your-app:latest
    # NO ports exposed — only reachable through gateway
    networks:
      - internal

networks:
  internal:
    internal: true  # No external access
```

### Security Checklist
- [ ] NS server not exposed to public internet (or behind its own ZTLP gateway)
- [ ] Zone signing key stored securely (not in Docker image)
- [ ] Gateway policy is default-deny
- [ ] Enrollment tokens are single-use with short TTL
- [ ] All records signed with zone key (registration auth enabled)
- [ ] Revocation checked on every connection

---

## Wire Protocol Summary

| Type | Byte | Description |
|------|------|-------------|
| KEY | 0x01 | Existing — node identity |
| SVC | 0x02 | Existing — service record |
| RELAY | 0x03 | Existing — relay record |
| POLICY | 0x04 | Existing — policy record |
| REVOKE | 0x05 | Existing — revocation |
| BOOTSTRAP | 0x06 | Existing — bootstrap |
| ENROLL_REQ | 0x07 | Existing — enrollment request |
| ENROLL_RESP | 0x08 | Existing — enrollment response |
| OPERATOR | 0x09 | Existing — operator record |
| DEVICE | 0x10 | **NEW** — device identity |
| USER | 0x11 | **NEW** — user identity |
| GROUP | 0x12 | **NEW** — group membership |

## File Manifest

### NS (Elixir)
- `ns/lib/ztlp_ns/record.ex` — Add DEVICE, USER, GROUP constructors + validation
- `ns/lib/ztlp_ns/store.ex` — Device index, group index, new query functions
- `ns/lib/ztlp_ns/wire.ex` — Wire types 0x10, 0x11, 0x12
- `ns/lib/ztlp_ns/server.ex` — Query handlers for new types
- `ns/lib/ztlp_ns/registration_auth.ex` — Key overwrite protection
- `ns/test/ztlp_ns/identity_test.exs` — NEW: device + user tests
- `ns/test/ztlp_ns/group_test.exs` — NEW: group + membership tests

### Gateway (Elixir)
- `gateway/lib/ztlp_gateway/policy.ex` — Group membership matching
- `gateway/lib/ztlp_gateway/ns_client.ex` — Group/user/device queries
- `gateway/test/ztlp_gateway/group_policy_test.exs` — NEW

### CLI (Rust)
- `proto/src/bin/ztlp-cli.rs` — New admin subcommands (create-user, create-group, link-device, ls, revoke, audit, group add/remove/members)

### Docs
- `DEPLOYMENT.md` — MSP deployment guide
- `IDENTITY.md` — Identity model reference

## Constraints
- Zero external dependencies (all Elixir components stay pure OTP)
- Backward compatible — existing KEY records still work, `ztlp setup` without `--type` defaults to DEVICE
- Nested groups NOT supported (flat membership only)
- Group modification requires zone signing key (not user keys)
- Wire types 0x10-0x12 chosen to avoid conflict with existing 0x01-0x09
- All new Mnesia tables use configurable storage mode (ram_copies for test, disc_copies for prod)
- Tests must pass with `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false` (dev mode)

## Success Criteria
- [ ] `ztlp setup --type device` enrolls a device linked to a user
- [ ] `ztlp admin create-user` creates user identity in NS
- [ ] `ztlp admin create-group` + `group add` manages group membership
- [ ] Gateway policy engine evaluates group membership for access decisions
- [ ] `ztlp admin revoke` immediately blocks access (gateway rejects)
- [ ] `ztlp admin ls` shows all enrolled entities
- [ ] Key overwrite protection prevents unauthorized re-registration
- [ ] DEPLOYMENT.md walks through protecting a web app end-to-end
- [ ] All existing tests still pass (backward compatibility)
- [ ] 100+ new tests across NS, gateway, and CLI
