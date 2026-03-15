# ZTLP Identity Model Reference

> Reference documentation for ZTLP's identity model: DEVICE, USER, and GROUP
> record types, their relationships, wire format, and CLI command reference.

**Version:** 0.6.0  
**Last updated:** 2026-03-15

---

## Table of Contents

1. [Overview](#overview)
2. [Record Types](#record-types)
3. [Relationships](#relationships)
4. [Wire Format](#wire-format)
5. [CLI Command Reference](#cli-command-reference)
6. [Policy Integration](#policy-integration)
7. [Common MSP Scenarios](#common-msp-scenarios)

---

## Overview

ZTLP uses three identity record types to model the real-world relationships
in a managed IT environment:

```
┌─────────────────────────────────────────────────────┐
│                    ZONE                              │
│            (clients.techrockstars.ztlp)             │
│                                                      │
│  ┌─────────────┐    ┌─────────────┐                 │
│  │   GROUP      │    │   GROUP      │                │
│  │   admins@    │    │   techs@     │                │
│  └──┬──────┬───┘    └──┬──────┬───┘                 │
│     │      │           │      │                      │
│  ┌──▼──┐ ┌─▼────┐  ┌──▼──┐ ┌─▼────┐                │
│  │USER │ │ USER  │  │USER │ │ USER  │                │
│  │steve│ │ alice │  │alice│ │ bob   │                │
│  └──┬──┘ └──┬───┘  └──┬──┘ └──┬───┘                │
│     │       │          │       │                     │
│  ┌──▼──────▼──┐    ┌──▼──┐ ┌──▼──┐  ┌──────────┐   │
│  │  DEVICE    │    │DEV  │ │DEV  │  │ DEVICE   │   │
│  │ steve-     │    │alice│ │bob- │  │ kiosk-01 │   │
│  │ laptop     │    │-mbp │ │ipad │  │ (no user)│   │
│  └────────────┘    └─────┘ └─────┘  └──────────┘   │
│                                                      │
└─────────────────────────────────────────────────────┘
```

**Key principle:** Users are people. Devices are machines. Groups collect
users for policy enforcement. A device can exist without a user (e.g., a
kiosk), but policy is evaluated against the user's group membership when
the device has an owner.

---

## Record Types

### DEVICE (Wire Type: `0x10`)

A **DEVICE** record represents a physical or virtual machine running the
ZTLP client. Every endpoint that connects to a ZTLP gateway is a device.

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Unique name in the zone (e.g., `laptop-01.clients.techrockstars.ztlp`) |
| `node_id` | 128-bit | Randomly generated unique identifier |
| `public_key` | X25519 | Key used for Noise_XX handshakes |
| `ed25519_public_key` | Ed25519 | Key used for signing NS registrations |
| `owner` | String (optional) | Name of the USER record that owns this device |
| `hardware_id` | String (optional) | Machine identifier (hostname, serial number) |

**When to use:** Every physical machine, laptop, phone, kiosk, or VM that
will connect to ZTLP services gets a DEVICE record.

**Created by:**
- `ztlp setup --type device` — interactive enrollment
- `ztlp setup --token TOKEN --type device` — token-based enrollment
- `ztlp keygen` + `ztlp ns register` — manual registration

### USER (Wire Type: `0x11`)

A **USER** record represents a person — an employee, contractor, or
administrator. Users own devices and belong to groups.

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Unique name (e.g., `steve@clients.techrockstars.ztlp`) |
| `role` | Enum | `admin`, `tech`, or `user` |
| `email` | String (optional) | Contact email address |
| `ed25519_public_key` | Ed25519 | Signing key for administrative operations |

**When to use:** Every person who should have access to ZTLP-protected
services gets a USER record. The user record is the bridge between a
real person and their group-based permissions.

**Created by:**
- `ztlp admin create-user NAME --role ROLE`

### GROUP (Wire Type: `0x12`)

A **GROUP** record collects users for policy enforcement. The gateway
policy references group names to control access to services.

| Field | Type | Description |
|-------|------|-------------|
| `name` | String | Unique name (e.g., `techs@clients.techrockstars.ztlp`) |
| `description` | String (optional) | Human-readable description |
| `members` | List\<String\> | Names of USER records in this group |

**When to use:** Create groups that map to your organizational roles:
`admins`, `techs`, `helpdesk`, `client-users`, etc. Reference these groups
in the gateway policy instead of individual names.

**Created by:**
- `ztlp admin create-group NAME`
- Members managed with `ztlp admin group add` / `ztlp admin group remove`

**Constraints:**
- Groups are **flat** — no nested groups (a group cannot contain another group)
- Only the zone signing key holder can create groups or modify membership
- Group names use `@` as separator: `name@zone`

---

## Relationships

```
                    ┌──────────┐
                    │  ZONE    │
                    │ (signing │
                    │   key)   │
                    └────┬─────┘
                         │ signs all records
          ┌──────────────┼──────────────┐
          │              │              │
     ┌────▼────┐    ┌───▼────┐    ┌───▼─────┐
     │ DEVICE  │    │  USER  │    │  GROUP  │
     │         │    │        │    │         │
     │ node_id │    │ role   │    │ members │
     │ pubkey  │    │ email  │    │ desc    │
     └────┬────┘    └───┬────┘    └───┬─────┘
          │             │              │
          │  belongs_to │  has_many    │
          └─────────────┘──────────────┘

  DEVICE ──→ USER (via owner field)        "Alice's laptop"
  USER   ──→ GROUP (via membership)        "Alice is a tech"
  GROUP  ──→ POLICY (gateway evaluates)    "Techs can access web"
```

### Relationship rules

| Relationship | Cardinality | Description |
|-------------|-------------|-------------|
| USER → DEVICE | One-to-many | A user can own multiple devices |
| DEVICE → USER | Many-to-one (optional) | A device has zero or one owner |
| USER → GROUP | Many-to-many | A user can belong to multiple groups |
| GROUP → USER | Many-to-many | A group can have multiple members |

### Policy evaluation chain

When a device connects to the gateway:

1. **Device authenticates** via Noise_XX handshake (X25519 key exchange)
2. **Gateway looks up the device's public key** in NS (reverse lookup)
3. **If device has an owner** → gateway resolves the USER record
4. **Gateway checks the user's groups** against the policy
5. **Access granted or denied** based on group membership

If a device has no owner, the gateway evaluates policy against the device's
identity directly (node ID or registered name).

---

## Wire Format

### Record Wire Types

| Type | Byte | Name | Description |
|------|------|------|-------------|
| KEY | `0x01` | Legacy identity | Original node identity record (backward compatible) |
| SVC | `0x02` | Service | Endpoint address for a service |
| RELAY | `0x03` | Relay | Relay node endpoint |
| POLICY | `0x04` | Policy | Policy record |
| REVOKE | `0x05` | Revocation | Blocks an identity from connecting |
| BOOTSTRAP | `0x06` | Bootstrap | Network bootstrap info |
| ENROLL_REQ | `0x07` | Enrollment request | Device enrollment request |
| ENROLL_RESP | `0x08` | Enrollment response | Enrollment confirmation |
| OPERATOR | `0x09` | Operator | Operator/MSP record |
| DEVICE | `0x10` | Device identity | Machine/endpoint identity |
| USER | `0x11` | User identity | Person identity |
| GROUP | `0x12` | Group membership | Group with member list |

### NS Query/Response Wire Format

**Query (client → NS):**

```
┌──────┬──────────┬──────────┬────────────┐
│ 0x01 │ name_len │   name   │ type_byte  │
│  (1) │   (2)    │ (var)    │    (1)     │
└──────┴──────────┴──────────┴────────────┘
```

**Response (NS → client):**

```
┌──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ 0x02 │ type_byte │ name_len │   name   │ data_len │   data   │
│  (1) │    (1)    │   (2)    │  (var)   │   (4)    │  (var)   │
└──────┴───────────┴──────────┴──────────┴──────────┴──────────┘
```

The `data` field is CBOR-encoded and contains record-type-specific fields:

**DEVICE data (CBOR map):**
```
{
  "node_id": "hex...",
  "public_key": "hex...",
  "ed25519_public_key": "hex...",
  "owner": "user@zone.ztlp",    // optional
  "address": "ip:port"           // optional
}
```

**USER data (CBOR map):**
```
{
  "role": "admin|tech|user",
  "email": "user@example.com",  // optional
  "ed25519_public_key": "hex..."
}
```

**GROUP data (CBOR map):**
```
{
  "description": "Field technicians",  // optional
  "members": ["alice@zone.ztlp", "bob@zone.ztlp"]
}
```

### Pubkey Reverse Lookup

**Query (client → NS):**

```
┌──────┬────────┬────────────┐
│ 0x05 │ pk_len │ pubkey_hex │
│  (1) │  (2)   │   (var)    │
└──────┴────────┴────────────┘
```

Returns the KEY/DEVICE record matching the public key, enabling the gateway
to resolve a connecting device's identity from its handshake public key.

---

## CLI Command Reference

### Identity Generation

```bash
# Generate a new identity (NodeID + X25519 + Ed25519)
ztlp keygen --output PATH [--format json|hex]
```

Output file contains: `node_id`, `static_private_key`, `static_public_key`,
`ed25519_seed`, `ed25519_public_key`. File permissions set to `0600`.

### NS Registration

```bash
# Register a name with NS
ztlp ns register \
  --name NAME \
  --zone ZONE \
  --key IDENTITY_FILE \
  [--address ADDR:PORT] \
  [--ns-server HOST:PORT]

# Look up a name
ztlp ns lookup NAME [--ns-server HOST:PORT] [--record-type 1-6]

# Reverse lookup by public key
ztlp ns pubkey HEX [--ns-server HOST:PORT]
```

### User Management

```bash
# Create a user
ztlp admin create-user NAME \
  [--role admin|tech|user] \
  [--email EMAIL] \
  [--ns-server HOST:PORT] \
  [--json]

# List users
ztlp admin ls --type user [--zone ZONE] [--ns-server HOST:PORT] [--json]

# Revoke a user
ztlp admin revoke NAME --reason "REASON" [--ns-server HOST:PORT] [--json]
```

### Device Management

```bash
# Enroll a device (interactive or token-based)
ztlp setup [--token TOKEN] [--name NAME] [--type device] [--owner USER] [-y]

# Link a device to a user
ztlp admin link-device DEVICE_NAME --owner USER_NAME [--ns-server HOST:PORT] [--json]

# List devices for a user
ztlp admin devices USER_NAME [--ns-server HOST:PORT] [--json]

# List all devices
ztlp admin ls --type device [--zone ZONE] [--ns-server HOST:PORT] [--json]

# Revoke a device
ztlp admin revoke DEVICE_NAME --reason "REASON" [--ns-server HOST:PORT] [--json]
```

### Group Management

```bash
# Create a group
ztlp admin create-group NAME [--description DESC] [--ns-server HOST:PORT] [--json]

# List all groups
ztlp admin groups [--ns-server HOST:PORT] [--json]

# Add member to group
ztlp admin group add GROUP MEMBER [--ns-server HOST:PORT] [--json]

# Remove member from group
ztlp admin group remove GROUP MEMBER [--ns-server HOST:PORT] [--json]

# List group members
ztlp admin group members GROUP [--ns-server HOST:PORT] [--json]

# Check if user is in group
ztlp admin group check GROUP USER [--ns-server HOST:PORT] [--json]
```

### Zone Administration

```bash
# Initialize a zone
ztlp admin init-zone --zone ZONE [--secret-output PATH]

# Generate enrollment tokens
ztlp admin enroll --zone ZONE --ns-server HOST:PORT --relay HOST:PORT \
  [--gateway HOST:PORT] [--secret PATH] [--expires DURATION] \
  [--max-uses N] [--count N] [--qr]

# Rotate zone signing key
ztlp admin rotate-zone-key [--json]

# Export zone signing key
ztlp admin export-zone-key [--format pem|hex] [--json]
```

### Audit

```bash
# View audit log
ztlp admin audit [--since DURATION] [--name "PATTERN"] [--ns-server HOST:PORT] [--json]
```

Duration formats: `30m`, `1h`, `24h`, `7d`  
Name patterns support `*` wildcards: `"alice@*"`, `"*.techrockstars.ztlp"`

---

## Policy Integration

### Policy file format (TOML)

```toml
# Default action when no rule matches: "deny" or "allow"
default = "deny"

# Per-service rules
[[services]]
name = "web"
allow = [
  "admins@zone.ztlp",           # Group name
  "techs@zone.ztlp",            # Another group
  "contractor@zone.ztlp",       # Individual user
]

[[services]]
name = "ssh"
allow = [
  "admins@zone.ztlp",           # Only admins get SSH
]
```

### How the gateway evaluates policy

1. Client connects → Noise_XX handshake completes
2. Gateway extracts client's X25519 public key from handshake
3. NS reverse lookup (pubkey → name) identifies the client
4. If client is a DEVICE with an owner → resolve the owner USER
5. Query GROUP records containing the user
6. Check if any of the user's groups (or the user/device name directly)
   appears in the `allow` list for the requested service
7. If match → **ALLOW** and forward traffic
8. If no match → **DENY** and send REJECT frame

### Identity resolution priority

The gateway checks identities in this order:

1. **Direct name match** — is the registered name in the allow list?
2. **User name** — if device has owner, is the owner's name in the allow list?
3. **Group membership** — is the owner (or device identity) a member of a listed group?
4. **NodeID hex** — fallback for unregistered identities

---

## Common MSP Scenarios

### Scenario 1: Onboard a new technician

Alice joins Tech Rockstars as a field technician.

```bash
ZONE="clients.techrockstars.ztlp"
NS="10.0.0.5:23096"

# 1. Create her user account
ztlp admin create-user alice@$ZONE \
  --role tech \
  --email alice@techrockstars.com \
  --ns-server $NS

# 2. Add her to the techs group
ztlp admin group add techs@$ZONE alice@$ZONE --ns-server $NS

# 3. Generate an enrollment token for her laptop
ztlp admin enroll \
  --zone $ZONE \
  --ns-server $NS \
  --relay 10.0.0.5:23095 \
  --expires 24h \
  --max-uses 1

# 4. Send her the token — she runs on her laptop:
#    ztlp setup --token "ztlp://enroll/..." \
#      --name alice-laptop.$ZONE \
#      --type device \
#      --owner alice@$ZONE

# 5. Verify enrollment
ztlp admin devices alice@$ZONE --ns-server $NS
```

### Scenario 2: Onboard a customer device

ACME Corp has a kiosk that needs access to their management portal.

```bash
ZONE="acme.techrockstars.ztlp"
NS="10.0.0.5:23096"

# 1. Generate a short-lived enrollment token
ztlp admin enroll \
  --zone $ZONE \
  --ns-server $NS \
  --relay 10.0.0.5:23095 \
  --expires 1h \
  --max-uses 1 \
  --qr

# 2. On the kiosk (scan QR or paste token):
#    ztlp setup --token "ztlp://enroll/..." \
#      --name kiosk-01.$ZONE \
#      --type device \
#      -y

# 3. No user link needed — kiosk is a standalone device
# Add a direct device allow rule in policy.toml if needed:
#   allow = ["kiosk-01.acme.techrockstars.ztlp"]
```

### Scenario 3: Revoke a stolen laptop

Bob's work laptop was stolen from his car.

```bash
ZONE="clients.techrockstars.ztlp"
NS="10.0.0.5:23096"

# 1. Immediately revoke the device
ztlp admin revoke bob-laptop.$ZONE \
  --reason "stolen device — reported 2026-03-15" \
  --ns-server $NS

# 2. Verify revocation
ztlp admin audit --since 1h --name "bob-laptop*" --ns-server $NS

# 3. Bob still has access from his other devices (phone, desktop)
# Only the stolen laptop is blocked

# 4. If needed, generate a new enrollment token for his replacement laptop
ztlp admin enroll \
  --zone $ZONE \
  --ns-server $NS \
  --relay 10.0.0.5:23095 \
  --expires 24h \
  --max-uses 1
```

### Scenario 4: Offboard a departing employee

Alice is leaving the company. Remove all access.

```bash
ZONE="clients.techrockstars.ztlp"
NS="10.0.0.5:23096"

# 1. Revoke the user account
ztlp admin revoke alice@$ZONE \
  --reason "left company — last day 2026-03-15" \
  --ns-server $NS

# 2. Remove from all groups
ztlp admin group remove techs@$ZONE alice@$ZONE --ns-server $NS
ztlp admin group remove admins@$ZONE alice@$ZONE --ns-server $NS 2>/dev/null || true

# 3. List and revoke all her devices
ztlp admin devices alice@$ZONE --ns-server $NS --json
# For each device:
ztlp admin revoke alice-laptop.$ZONE --reason "owner offboarded" --ns-server $NS
ztlp admin revoke alice-phone.$ZONE --reason "owner offboarded" --ns-server $NS

# 4. Audit trail
ztlp admin audit --since 1h --name "alice@*" --ns-server $NS
```

### Scenario 5: Promote a tech to admin

Bob has been promoted and needs admin access.

```bash
ZONE="clients.techrockstars.ztlp"
NS="10.0.0.5:23096"

# Add Bob to the admins group (he stays in techs too)
ztlp admin group add admins@$ZONE bob@$ZONE --ns-server $NS

# Verify
ztlp admin group check admins@$ZONE bob@$ZONE --ns-server $NS
# → member: true

# Bob now has access to admin-only services (SSH, etc.)
# No gateway restart needed — policy evaluates group membership live
```

### Scenario 6: Temporary contractor access

A contractor needs web access for 30 days.

```bash
ZONE="clients.techrockstars.ztlp"
NS="10.0.0.5:23096"

# 1. Create contractor user
ztlp admin create-user contractor@$ZONE \
  --role user \
  --email contractor@example.com \
  --ns-server $NS

# 2. Add to techs group for web access
ztlp admin group add techs@$ZONE contractor@$ZONE --ns-server $NS

# 3. Generate enrollment token
ztlp admin enroll \
  --zone $ZONE \
  --ns-server $NS \
  --relay 10.0.0.5:23095 \
  --expires 24h \
  --max-uses 1

# 4. Set a calendar reminder for 30 days from now to revoke
# After 30 days:
ztlp admin revoke contractor@$ZONE \
  --reason "contract ended" \
  --ns-server $NS
ztlp admin group remove techs@$ZONE contractor@$ZONE --ns-server $NS
```

---

## Backward Compatibility

The identity model is fully backward compatible with existing ZTLP deployments:

- **Existing KEY records** (`0x01`) continue to work unchanged
- `ztlp setup` without `--type` defaults to `device` (which creates a
  DEVICE record internally but remains compatible with KEY-based lookups)
- Gateways that don't use group policy continue to work with direct
  name/NodeID-based allow lists
- The `ztlp connect` and `ztlp listen` commands work identically —
  the identity model is transparent to the data plane

---

*For the complete deployment guide, see [DEPLOYMENT.md](DEPLOYMENT.md).*  
*For credential lifecycle details, see [docs/CREDENTIAL-RENEWAL.md](docs/CREDENTIAL-RENEWAL.md).*
