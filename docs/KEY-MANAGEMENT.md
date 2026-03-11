# ZTLP Key & Secret Management Guide

Comprehensive guide to managing cryptographic keys and secrets across all ZTLP components. Covers generation, storage, rotation, revocation, and integration with external secret management systems.

**Audience:** Operations engineers managing ZTLP infrastructure and security teams auditing key practices.

> **See also:** [OPS-RUNBOOK.md](OPS-RUNBOOK.md) · [THREAT-MODEL.md](../THREAT-MODEL.md) · [ARCHITECTURE.md](../ARCHITECTURE.md)

---

## Table of Contents

1. [Key Inventory](#1-key-inventory)
2. [Identity Key Lifecycle](#2-identity-key-lifecycle)
3. [RAT Secret Rotation](#3-rat-secret-rotation)
4. [Erlang Cookie Management](#4-erlang-cookie-management)
5. [NS Record Signing Keys](#5-ns-record-signing-keys)
6. [Component Auth Keys](#6-component-auth-keys)
7. [HashiCorp Vault Integration](#7-hashicorp-vault-integration)
8. [AWS KMS / GCP Cloud KMS Integration](#8-aws-kms--gcp-cloud-kms-integration)
9. [Security Best Practices](#9-security-best-practices)

---

## 1. Key Inventory

### Master Key Table

| Key / Secret | Type | Algorithm | Size | Component(s) | Storage Location | Permissions | Lifetime | Rotation Frequency |
|---|---|---|---|---|---|---|---|---|
| **Node Identity (private)** | Asymmetric (private) | Ed25519 | 64 bytes (seed + precomputed) | CLI, Gateway | `~/.ztlp/identity.json` | `0600` | Long-lived (years) | On compromise or decommission |
| **Node Identity (public)** | Asymmetric (public) | Ed25519 | 32 bytes | CLI, Gateway, NS | `~/.ztlp/identity.json`, NS records | Public | Matches private key | Matches private key |
| **X25519 Static Key** | Asymmetric (private) | X25519 | 32 bytes | Gateway | `~/.ztlp/identity.json` | `0600` | Long-lived (years) | On compromise or decommission |
| **X25519 Ephemeral Key** | Asymmetric | X25519 | 32 bytes | Gateway | Memory only | N/A (RAM) | Per-session | Every handshake |
| **RAT Secret (current)** | Symmetric | HMAC-BLAKE2s | 32 bytes | Relay | `/etc/ztlp/relay.env` or YAML | `0640` (root:ztlp) | Medium-lived (weeks) | Weekly–monthly |
| **RAT Secret (previous)** | Symmetric | HMAC-BLAKE2s | 32 bytes | Relay | `/etc/ztlp/relay.env` or YAML | `0640` (root:ztlp) | Transitional (≤ RAT TTL) | Cleared after rotation window |
| **Erlang Cookie (NS)** | Symmetric | BEAM distribution | ~44 bytes (base64) | NS | `/var/lib/ztlp/ns/.cookie` | `0400` (ztlp:ztlp) | Long-lived | On compromise |
| **Erlang Cookie (Relay)** | Symmetric | BEAM distribution | ~44 bytes (base64) | Relay | `/var/lib/ztlp/relay/.cookie` | `0400` (ztlp:ztlp) | Long-lived | On compromise |
| **Erlang Cookie (Gateway)** | Symmetric | BEAM distribution | ~44 bytes (base64) | Gateway | `/var/lib/ztlp/gateway/.cookie` | `0400` (ztlp:ztlp) | Long-lived | On compromise |
| **NS Zone Authority Key** | Asymmetric (keypair) | Ed25519 | 32 + 64 bytes | NS | Config or Vault | `0600` | Long-lived (years) | On compromise; scheduled for root |
| **ChaCha20-Poly1305 Session Key** | Symmetric | ChaCha20-Poly1305 | 32 bytes | Gateway | Memory only | N/A (RAM) | Per-session | Every handshake (derived via HKDF) |
| **Component Auth Key** *(planned)* | Asymmetric (keypair) | Ed25519 | 32 + 64 bytes | All | `/etc/ztlp/<component>.env` | `0640` | Medium-lived (months) | Quarterly |

### Key Classification

**By secrecy:**

| Category | Keys | Notes |
|---|---|---|
| **Symmetric (must stay secret)** | RAT secrets, Erlang cookies, session keys | Compromise of any copy compromises the key |
| **Asymmetric private (must stay secret)** | Ed25519 identity, X25519 static, zone authority private | Only the holder needs the private half |
| **Asymmetric public (safe to share)** | Ed25519 public, X25519 public | Distributed via NS records, embedded in signed delegations |

**By lifetime:**

| Category | Keys | Notes |
|---|---|---|
| **Ephemeral (per-session)** | X25519 ephemeral, ChaCha20-Poly1305 session keys | Generated in memory, never persisted, destroyed on session close |
| **Medium-lived (weeks–months)** | RAT secrets, component auth keys | Rotated on a schedule |
| **Long-lived (years)** | Identity keys, zone authority keys, Erlang cookies | Rotated only on compromise or decommission |

---

## 2. Identity Key Lifecycle

ZTLP identity keys are Ed25519 + X25519 keypairs that uniquely identify a node on the network. The Ed25519 half is used for signing NS records and proving identity. The X25519 half is used for Noise_XX handshakes (session key agreement).

### 2.1 Generation

```bash
# Generate a new identity keypair
ztlp keygen --output ~/.ztlp/identity.json

# This creates:
#   ~/.ztlp/identity.json   — Full keypair (JSON format)
#   ~/.ztlp/private.key     — Ed25519 private key (raw)
#   ~/.ztlp/public.key      — Ed25519 public key (raw)
#   ~/.ztlp/node.id         — 128-bit NodeID derived from public key

# Alternative: hex output format
ztlp keygen --format hex --output ~/.ztlp/identity.hex
```

Under the hood, key generation uses OTP's `:crypto.generate_key(:eddsa, :ed25519)` — which delegates to OpenSSL or libsodium depending on the Erlang build. The X25519 key is generated via `:crypto.generate_key(:ecdh, :x25519)`.

> **Key sizes:**
> - Ed25519 public key: 32 bytes
> - Ed25519 private key: 64 bytes (seed + precomputed values, OTP internal format)
> - X25519 public key: 32 bytes
> - X25519 private key: 32 bytes (scalar/seed)
> - NodeID: 16 bytes (derived from public key)

### 2.2 Storage & Permissions

```bash
# Secure the identity directory
chmod 0700 ~/.ztlp/

# Secure individual files
chmod 0600 ~/.ztlp/identity.json
chmod 0600 ~/.ztlp/private.key
chmod 0644 ~/.ztlp/public.key    # Public key can be world-readable
chmod 0644 ~/.ztlp/node.id       # NodeID can be world-readable

# Verify ownership
ls -la ~/.ztlp/
# Should show: owner=<your-user>, no group/other write on private files
```

For service accounts (e.g., the `ztlp` system user running daemons):

```bash
# Server-side identity storage
sudo install -d -o ztlp -g ztlp -m 0700 /var/lib/ztlp/identity/
sudo -u ztlp ztlp keygen --output /var/lib/ztlp/identity/identity.json
sudo chmod 0600 /var/lib/ztlp/identity/identity.json
sudo chmod 0600 /var/lib/ztlp/identity/private.key
```

> ⚠️ **Never store private keys with group or world read permissions.** The `ProtectHome=yes` directive in the systemd units prevents services from reading keys in user home directories — use `/var/lib/ztlp/identity/` for service identities.

### 2.3 Backup

Identity keys are **irreplaceable** — if lost, you must generate a new identity and re-register with NS. All trust relationships tied to the old NodeID are broken.

**Encrypted backup procedure:**

```bash
# Create an encrypted backup using GPG
gpg --symmetric --cipher-algo AES256 \
    --output ~/ztlp-identity-backup-$(date +%Y%m%d).json.gpg \
    ~/.ztlp/identity.json

# Verify the backup decrypts correctly
gpg --decrypt ~/ztlp-identity-backup-$(date +%Y%m%d).json.gpg | diff - ~/.ztlp/identity.json

# Store the encrypted backup off-site:
# - Encrypted cloud storage (S3, GCS with server-side encryption)
# - Hardware security module (HSM)
# - Air-gapped USB drive in a safe
# - Password manager (for small teams)

# Clean up the unencrypted backup if you moved it off-site
shred -u ~/ztlp-identity-backup-*.json 2>/dev/null
```

**Backup with age (modern alternative to GPG):**

```bash
# Generate an age key (one-time setup)
age-keygen -o ~/.ztlp/backup-key.txt

# Encrypt
age -r "$(grep 'public key:' ~/.ztlp/backup-key.txt | cut -d' ' -f4)" \
    -o ~/ztlp-identity-backup.json.age \
    ~/.ztlp/identity.json

# Decrypt (when needed)
age -d -i ~/.ztlp/backup-key.txt ~/ztlp-identity-backup.json.age > ~/.ztlp/identity.json
```

### 2.4 Rotation

Rotating a node's identity means generating a new keypair and updating all references to the old one. This is a disruptive operation — all active sessions terminate and the node gets a new NodeID.

**Step-by-step identity rotation:**

```bash
# 1. Back up the current identity
cp -a ~/.ztlp/identity.json ~/.ztlp/identity.json.old

# 2. Generate a new identity
ztlp keygen --output ~/.ztlp/identity.json

# 3. Re-register with NS (updates your name → key binding)
ztlp ns register \
    --name myserver.corp.ztlp \
    --zone corp.ztlp \
    --key ~/.ztlp/identity.json \
    --address 10.0.0.1:23095

# 4. Update any authorized node lists that reference your old NodeID
#    (e.g., ZTLP_SVC records, ZTLP_POLICY records, gateway ACLs)

# 5. Revoke the old identity (see Revocation below)
ztlp ns revoke \
    --zone corp.ztlp \
    --authority-key /path/to/zone-authority-private.key \
    --node-id "$(cat ~/.ztlp/identity.json.old | jq -r .node_id)" \
    --reason "scheduled rotation"

# 6. Verify the new identity is working
ztlp ping 127.0.0.1:23095 --key ~/.ztlp/identity.json
```

> ⚠️ **Identity rotation breaks all active sessions.** Clients connected with the old key must re-handshake. In a production environment, drain the node first (see [OPS-RUNBOOK.md § Graceful Drain](OPS-RUNBOOK.md#graceful-drain-sigusr1)).

### 2.5 Revocation

When an identity key is compromised, revoke it immediately using a ZTLP_REVOKE record. Revocation records have a TTL of 0 (never expire) and propagate across all NS nodes.

```bash
# Revoke a compromised node's identity
ztlp ns revoke \
    --zone corp.ztlp \
    --authority-key /path/to/zone-authority-private.key \
    --node-id "aabbccdd11223344aabbccdd11223344" \
    --reason "key compromise"

# Verify the revocation is published
ztlp ns lookup --type revoke corp.ztlp --ns-server 127.0.0.1:23096
```

The revocation record is signed by the zone authority (not the compromised key) and contains:

- `revoked_ids` — list of revoked NodeIDs (hex-encoded)
- `reason` — human-readable reason string
- `effective_at` — timestamp when revocation takes effect

All ZTLP components check for revocation records during identity resolution. A revoked NodeID is treated as untrusted even if its cryptographic signatures are valid.

### 2.6 Multiple Identities

You can maintain separate identities for different environments:

```bash
# Per-environment identity directories
mkdir -p ~/.ztlp/dev ~/.ztlp/staging ~/.ztlp/production

# Generate identity for each
ztlp keygen --output ~/.ztlp/dev/identity.json
ztlp keygen --output ~/.ztlp/staging/identity.json
ztlp keygen --output ~/.ztlp/production/identity.json

# Connect using a specific identity
ztlp connect relay.staging.corp:23095 --key ~/.ztlp/staging/identity.json
ztlp connect relay.prod.corp:23095 --key ~/.ztlp/production/identity.json
```

> 💡 **Tip:** Never reuse identity keys across environments. A compromised staging key should not grant access to production.

---

## 3. RAT Secret Rotation

Relay Admission Tokens (RATs) are short-lived HMAC-BLAKE2s signed tokens that prove a node has been authenticated by an ingress relay. RAT secrets are symmetric 32-byte keys used for the HMAC computation.

The relay supports dual secrets (`rat_secret` + `rat_secret_previous`) for zero-downtime rotation. During verification, the relay tries the current secret first, then falls back to the previous secret (see `ZtlpRelay.AdmissionToken.verify_with_rotation/4`).

### 3.1 Configuration Reference

| Environment Variable | Config Key | Description |
|---|---|---|
| `ZTLP_RELAY_RAT_SECRET` | `admission.rat_secret` | Current RAT signing key (64 hex chars = 32 bytes) |
| `ZTLP_RELAY_RAT_SECRET_PREVIOUS` | `admission.rat_secret_previous` | Previous key during rotation (64 hex chars) |
| `ZTLP_RELAY_RAT_TTL_SECONDS` | `admission.rat_ttl` | Token lifetime; default: **300** (5 minutes) |

If `ZTLP_RELAY_RAT_SECRET` is not set, the relay auto-generates a random secret at startup. This is fine for single-node deployments but **unacceptable for mesh mode** — all relays must share the same RAT secret.

### 3.2 Step-by-Step Rotation

```bash
# ── Step 1: Generate new secret ──────────────────────────────────
NEW_SECRET=$(openssl rand -hex 32)
echo "New RAT secret: $NEW_SECRET"

# ── Step 2: Read current secret ──────────────────────────────────
OLD_SECRET=$(grep '^ZTLP_RELAY_RAT_SECRET=' /etc/ztlp/relay.env | head -1 | cut -d= -f2)

# ── Step 3: Update env file with dual secrets ────────────────────
# Preserve non-RAT lines, then write RAT config
grep -v '^ZTLP_RELAY_RAT_SECRET' /etc/ztlp/relay.env > /tmp/relay.env.tmp
cat >> /tmp/relay.env.tmp <<EOF
ZTLP_RELAY_RAT_SECRET=${NEW_SECRET}
ZTLP_RELAY_RAT_SECRET_PREVIOUS=${OLD_SECRET}
EOF

sudo cp /tmp/relay.env.tmp /etc/ztlp/relay.env
sudo chmod 0640 /etc/ztlp/relay.env
sudo chown root:ztlp /etc/ztlp/relay.env
rm /tmp/relay.env.tmp

# ── Step 4: Restart relay to load new secrets ────────────────────
sudo systemctl restart ztlp-relay

# ── Step 5: Verify health ────────────────────────────────────────
curl -s http://localhost:9101/health

# ── Step 6: Wait for RAT TTL to expire (default: 5 minutes) ─────
# During this window, both old and new tokens are accepted.
echo "Waiting for RAT TTL (300 seconds)..."
sleep 300

# ── Step 7: Remove previous secret ──────────────────────────────
sudo sed -i '/^ZTLP_RELAY_RAT_SECRET_PREVIOUS/d' /etc/ztlp/relay.env
# Optional: restart to clear in-memory previous secret
sudo systemctl restart ztlp-relay
```

> ⚠️ **Do NOT skip the wait period (Step 6).** Tokens signed with the old secret are still in flight. Removing `rat_secret_previous` before they expire will cause authentication failures.

### 3.3 Automated Rotation Script

```bash
#!/bin/bash
# /usr/local/bin/ztlp-rotate-rat-secret.sh
# Rotates the RAT secret for a single relay node.
# Intended to be run via cron weekly.
set -euo pipefail

ENV_FILE="/etc/ztlp/relay.env"
RAT_TTL=300  # Must match ZTLP_RELAY_RAT_TTL_SECONDS
LOG_TAG="ztlp-rat-rotation"

log() { logger -t "$LOG_TAG" "$@"; echo "[$(date -Iseconds)] $@"; }

# Ensure we're root (need to write to /etc/ztlp/)
if [[ $EUID -ne 0 ]]; then
    echo "Error: must run as root" >&2
    exit 1
fi

# Generate new secret
NEW_SECRET=$(openssl rand -hex 32)
log "Generated new RAT secret (first 8 chars: ${NEW_SECRET:0:8}...)"

# Read current secret
OLD_SECRET=$(grep '^ZTLP_RELAY_RAT_SECRET=' "$ENV_FILE" | head -1 | cut -d= -f2)
if [[ -z "$OLD_SECRET" ]]; then
    log "WARNING: No existing RAT secret found. Setting initial secret."
fi

# Update env file
TMPFILE=$(mktemp)
grep -v '^ZTLP_RELAY_RAT_SECRET' "$ENV_FILE" > "$TMPFILE" || true
echo "ZTLP_RELAY_RAT_SECRET=${NEW_SECRET}" >> "$TMPFILE"
if [[ -n "$OLD_SECRET" ]]; then
    echo "ZTLP_RELAY_RAT_SECRET_PREVIOUS=${OLD_SECRET}" >> "$TMPFILE"
fi

cp "$TMPFILE" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
chown root:ztlp "$ENV_FILE"
rm "$TMPFILE"
log "Updated ${ENV_FILE} with new secret and previous secret"

# Restart relay
systemctl restart ztlp-relay
log "Restarted ztlp-relay"

# Health check
sleep 5
if curl -sf http://localhost:9101/health > /dev/null 2>&1; then
    log "Health check passed"
else
    log "ERROR: Health check failed after restart!"
    exit 1
fi

# Schedule cleanup of previous secret after TTL
log "Previous secret will remain valid for ${RAT_TTL} seconds"
(
    sleep $((RAT_TTL + 30))  # Extra 30s buffer
    sed -i '/^ZTLP_RELAY_RAT_SECRET_PREVIOUS/d' "$ENV_FILE"
    logger -t "$LOG_TAG" "Removed previous RAT secret from ${ENV_FILE}"
) &

log "RAT secret rotation complete"
```

**Install as a weekly cron job:**

```bash
sudo chmod +x /usr/local/bin/ztlp-rotate-rat-secret.sh

# Run every Sunday at 03:00 UTC
echo "0 3 * * 0 root /usr/local/bin/ztlp-rotate-rat-secret.sh" \
    | sudo tee /etc/cron.d/ztlp-rat-rotation
```

### 3.4 Multi-Relay Mesh Rotation

In a relay mesh, **all relays must share the same RAT secret** because a token issued by one relay may be verified by another. Rotation must be coordinated across the mesh.

**Procedure:**

```bash
# All relays in the mesh — list them
RELAYS="relay-1.example.com relay-2.example.com relay-3.example.com"

# Step 1: Generate ONE new secret (on any machine)
NEW_SECRET=$(openssl rand -hex 32)

# Step 2: Deploy to ALL relays (set new as current, old as previous)
for relay in $RELAYS; do
    ssh root@$relay bash -s <<EOF
OLD=\$(grep '^ZTLP_RELAY_RAT_SECRET=' /etc/ztlp/relay.env | head -1 | cut -d= -f2)
sed -i '/^ZTLP_RELAY_RAT_SECRET/d' /etc/ztlp/relay.env
echo "ZTLP_RELAY_RAT_SECRET=${NEW_SECRET}" >> /etc/ztlp/relay.env
echo "ZTLP_RELAY_RAT_SECRET_PREVIOUS=\${OLD}" >> /etc/ztlp/relay.env
chmod 0640 /etc/ztlp/relay.env
chown root:ztlp /etc/ztlp/relay.env
systemctl restart ztlp-relay
EOF
    echo "Rotated on $relay"
done

# Step 3: Wait for RAT TTL (5 minutes default)
echo "Waiting for RAT TTL..."
sleep 330  # 5 min + 30s buffer

# Step 4: Clean up previous secret on all relays
for relay in $RELAYS; do
    ssh root@$relay "sed -i '/^ZTLP_RELAY_RAT_SECRET_PREVIOUS/d' /etc/ztlp/relay.env"
    echo "Cleaned up on $relay"
done
```

> ⚠️ **Complete Step 2 across ALL relays within the RAT TTL window.** If relay-3 still has the old secret as current while relay-1 has already moved to the new one, tokens may not validate across the mesh.

### 3.5 RAT Token Structure Reference

For context, here's the 93-byte RAT token layout (from `ZtlpRelay.AdmissionToken`):

```
Version:      1 byte  (0x01)
NodeID:      16 bytes (authenticated node)
IssuerID:    16 bytes (issuing relay's NodeID)
IssuedAt:     8 bytes (Unix timestamp, big-endian)
ExpiresAt:    8 bytes (Unix timestamp, big-endian)
SessionScope: 12 bytes (SessionID or all-zeros for any)
MAC:         32 bytes (HMAC-BLAKE2s over preceding 61 bytes)
```

The MAC is computed using the RFC 2104 HMAC construction with BLAKE2s (block size 64 bytes, output 32 bytes). Verification uses constant-time comparison to prevent timing attacks.

---

## 4. Erlang Cookie Management

### 4.1 What It Does

The Erlang cookie is a shared secret used by the BEAM virtual machine for inter-node authentication. When two Erlang/OTP nodes attempt to form a distributed cluster (e.g., for remote shell access or distributed Mnesia), they must present the same cookie. Without a matching cookie, the connection is refused.

In ZTLP, each component runs as a named Erlang node:

| Component | Node Name | Cookie Location |
|---|---|---|
| NS | `ztlp_ns@127.0.0.1` | `/var/lib/ztlp/ns/.cookie` |
| Relay | `ztlp_relay@127.0.0.1` | `/var/lib/ztlp/relay/.cookie` |
| Gateway | `ztlp_gateway@127.0.0.1` | `/var/lib/ztlp/gateway/.cookie` |

The cookie file path is set via `RELEASE_COOKIE_FILE` in the systemd unit files.

### 4.2 Generation

```bash
# Generate a cryptographically strong cookie
openssl rand -base64 32 | tr -d '\n' > /var/lib/ztlp/relay/.cookie

# Alternative: using /dev/urandom directly
head -c 32 /dev/urandom | base64 | tr -d '\n' > /var/lib/ztlp/relay/.cookie

# Set correct permissions
chown ztlp:ztlp /var/lib/ztlp/relay/.cookie
chmod 0400 /var/lib/ztlp/relay/.cookie
```

> 💡 The Debian package postinst script generates cookies automatically during installation. You only need to generate manually for custom deployments or rotation.

### 4.3 Single-Node vs. Clustered Deployments

**Single-node (default):** Each service gets its own independent cookie. The cookie is only used for `remote` shell access (e.g., `ztlp_relay remote` for debugging). Services don't need matching cookies because they communicate via UDP, not Erlang distribution.

**Clustered deployment** (e.g., multiple NS nodes in a Mnesia cluster): All nodes in the cluster **must share the same cookie**. Deploy the same cookie file to all hosts.

```bash
# Generate a shared cluster cookie
CLUSTER_COOKIE=$(openssl rand -base64 32 | tr -d '\n')

# Deploy to all NS cluster nodes
for host in ns-1 ns-2 ns-3; do
    ssh root@$host bash -s <<EOF
echo -n "${CLUSTER_COOKIE}" > /var/lib/ztlp/ns/.cookie
chown ztlp:ztlp /var/lib/ztlp/ns/.cookie
chmod 0400 /var/lib/ztlp/ns/.cookie
EOF
done
```

### 4.4 Rotation

Cookie rotation requires a coordinated restart of all nodes sharing the cookie. There is **no graceful rotation mechanism** — the BEAM VM reads the cookie at boot and uses it for the lifetime of the process.

> ⚠️ **Cookie rotation causes a full service interruption** for clustered deployments. For single-node deployments, it only affects remote shell access.

**Single-node rotation:**

```bash
# Stop the service
sudo systemctl stop ztlp-relay

# Generate new cookie
openssl rand -base64 32 | tr -d '\n' | sudo tee /var/lib/ztlp/relay/.cookie > /dev/null
sudo chown ztlp:ztlp /var/lib/ztlp/relay/.cookie
sudo chmod 0400 /var/lib/ztlp/relay/.cookie

# Start the service
sudo systemctl start ztlp-relay
```

**Clustered rotation (coordinated restart):**

```bash
# Step 1: Generate new cookie
NEW_COOKIE=$(openssl rand -base64 32 | tr -d '\n')

# Step 2: Stop all cluster nodes
for host in ns-1 ns-2 ns-3; do
    ssh root@$host "systemctl stop ztlp-ns"
done

# Step 3: Deploy new cookie to all nodes
for host in ns-1 ns-2 ns-3; do
    ssh root@$host bash -s <<EOF
echo -n "${NEW_COOKIE}" > /var/lib/ztlp/ns/.cookie
chown ztlp:ztlp /var/lib/ztlp/ns/.cookie
chmod 0400 /var/lib/ztlp/ns/.cookie
EOF
done

# Step 4: Start all cluster nodes
for host in ns-1 ns-2 ns-3; do
    ssh root@$host "systemctl start ztlp-ns"
done

# Step 5: Verify cluster health
for host in ns-1 ns-2 ns-3; do
    ssh root@$host "curl -sf http://localhost:9103/health && echo OK || echo FAIL"
done
```

### 4.5 Security Notes

- The cookie is **not a strong authentication mechanism** — it's a shared secret with no key derivation, no replay protection, and no forward secrecy. It only prevents casual unauthorized access to the Erlang distribution.
- **Never expose Erlang distribution ports to the internet.** The systemd units use `sname` (short names) bound to `127.0.0.1`, which means distribution is local-only by default. If you need remote distribution, use a VPN or SSH tunnel.
- If an attacker obtains the cookie, they can execute arbitrary Erlang code on the target node. Treat cookies with the same sensitivity as root SSH keys.

---

## 5. NS Record Signing Keys

### 5.1 Trust Chain Architecture

ZTLP-NS uses a hierarchical trust chain modeled after DNS/DNSSEC but with mandatory Ed25519 signatures on every record. Trust flows from root anchors down to individual node records:

```
Root Trust Anchor (hardcoded or configured at deploy time)
  │
  ├── signs ZTLP_KEY delegation → Operator Zone Authority ("example.ztlp")
  │     │
  │     ├── signs ZTLP_KEY delegation → Tenant Zone Authority ("dept.example.ztlp")
  │     │     │
  │     │     ├── signs ZTLP_KEY → Node ("server1.dept.example.ztlp")
  │     │     ├── signs ZTLP_SVC → Service definitions
  │     │     └── signs ZTLP_POLICY → Access policies
  │     │
  │     └── signs ZTLP_KEY → Node ("gateway.example.ztlp")
  │
  └── signs ZTLP_KEY delegation → Another Operator ("corp.ztlp")
```

**Trust anchor categories** (from the spec):

| Category | Description | Who Manages |
|---|---|---|
| **Public ZTLP Root** | Protocol-level root anchor | ZTLP governance body |
| **Enterprise Root** | Private deployment root | Your organization |
| **Industry Root** | Sector-specific (healthcare, govt, finance) | Industry consortium |

A node may trust multiple roots simultaneously. Trust anchors are stored in the `ztlp_ns_trust_anchors` ETS table, populated at NS startup.

### 5.2 Zone Authority Key Generation

Each zone authority holds an Ed25519 keypair. Generation is done programmatically or via the CLI:

```bash
# Generate a zone authority keypair
ztlp ns zone-keygen \
    --zone example.ztlp \
    --output /etc/ztlp/zones/example.ztlp.key

# The output file contains:
# {
#   "zone": "example.ztlp",
#   "public_key": "aabbccdd...",    (32 bytes hex)
#   "private_key": "eeff0011...",   (64 bytes hex)
#   "algorithm": "Ed25519"
# }

# Secure the private key
chmod 0600 /etc/ztlp/zones/example.ztlp.key
chown root:root /etc/ztlp/zones/example.ztlp.key
```

Programmatically (in Elixir):

```elixir
# ZtlpNs.ZoneAuthority.generate/1 creates a keypair bound to a zone name
authority = ZtlpNs.ZoneAuthority.generate("example.ztlp")
# => %ZtlpNs.ZoneAuthority{
#      zone: %ZtlpNs.Zone{name: "example.ztlp", ...},
#      public_key: <<...32 bytes...>>,
#      private_key: <<...64 bytes...>>
#    }
```

### 5.3 Creating Delegations

A delegation is a ZTLP_KEY record where the parent zone authority signs the child zone's public key. This establishes the trust chain.

```bash
# Root delegates to operator
ztlp ns delegate \
    --parent-key /etc/ztlp/zones/root.key \
    --child-zone example.ztlp \
    --child-pubkey "$(jq -r .public_key /etc/ztlp/zones/example.ztlp.key)" \
    --ns-server 127.0.0.1:23096

# Operator delegates to tenant
ztlp ns delegate \
    --parent-key /etc/ztlp/zones/example.ztlp.key \
    --child-zone dept.example.ztlp \
    --child-pubkey "$(jq -r .public_key /etc/ztlp/zones/dept.example.ztlp.key)" \
    --ns-server 127.0.0.1:23096
```

Delegation records have a long TTL (1 year by default) and contain:

```json
{
  "node_id": "zone:example.ztlp",
  "public_key": "aabbccdd...",
  "algorithm": "Ed25519",
  "delegation": true
}
```

### 5.4 Key Storage by Authority Level

| Level | Key Location | Access | Backup |
|---|---|---|---|
| **Root authority** | HSM or air-gapped machine | ≤ 2 authorized personnel | Hardware-encrypted offline backup |
| **Operator authority** | Vault transit engine or encrypted config | DevOps lead + security team | Vault HA + encrypted offsite |
| **Tenant authority** | `/etc/ztlp/zones/<zone>.key` on NS host | ztlp service account | Encrypted backup per § 2.3 |

### 5.5 Zone Authority Key Rotation

Zone authority rotation requires re-signing all records in the zone with the new key and updating the parent's delegation record.

```bash
# 1. Generate new zone authority keypair
ztlp ns zone-keygen --zone example.ztlp --output /etc/ztlp/zones/example.ztlp.key.new

# 2. Have the parent (root) sign a new delegation for the new key
ztlp ns delegate \
    --parent-key /etc/ztlp/zones/root.key \
    --child-zone example.ztlp \
    --child-pubkey "$(jq -r .public_key /etc/ztlp/zones/example.ztlp.key.new)" \
    --ns-server 127.0.0.1:23096

# 3. Re-sign all records in the zone with the new key
ztlp ns re-sign \
    --zone example.ztlp \
    --old-key /etc/ztlp/zones/example.ztlp.key \
    --new-key /etc/ztlp/zones/example.ztlp.key.new \
    --ns-server 127.0.0.1:23096

# 4. Swap key files
mv /etc/ztlp/zones/example.ztlp.key /etc/ztlp/zones/example.ztlp.key.retired
mv /etc/ztlp/zones/example.ztlp.key.new /etc/ztlp/zones/example.ztlp.key

# 5. After all caches have expired (TTL), remove the old delegation
```

### 5.6 Emergency: Revoking a Compromised Zone Authority

> ⚠️ **THIS IS A CRITICAL SECURITY OPERATION.** A compromised zone authority key can be used to sign arbitrary records within the zone, including fake node identities and rogue services.

**Immediate response:**

```bash
# Step 1: Revoke using the PARENT authority (not the compromised key!)
ztlp ns revoke \
    --zone ztlp \
    --authority-key /etc/ztlp/zones/root.key \
    --node-id "zone:example.ztlp" \
    --reason "zone authority key compromise"

# Step 2: Generate a new zone authority key
ztlp ns zone-keygen --zone example.ztlp --output /etc/ztlp/zones/example.ztlp.key.emergency

# Step 3: Delegate the new key from the parent
ztlp ns delegate \
    --parent-key /etc/ztlp/zones/root.key \
    --child-zone example.ztlp \
    --child-pubkey "$(jq -r .public_key /etc/ztlp/zones/example.ztlp.key.emergency)" \
    --ns-server 127.0.0.1:23096

# Step 4: Re-register ALL nodes and services in the zone with the new authority
# This is the painful part — every signed record must be re-signed

# Step 5: Audit all records signed during the compromise window
ztlp ns audit \
    --zone example.ztlp \
    --since "2026-03-01T00:00:00Z" \
    --ns-server 127.0.0.1:23096
```

**If the ROOT authority key is compromised:**

This is the worst case. There is no parent to issue a revocation. Mitigation:

1. Publish an out-of-band emergency revocation notice (website, mailing list)
2. All operators must update their trust anchor configuration to remove the compromised root
3. Add the new root public key as a trust anchor
4. Re-build the entire delegation chain from the new root

This is why root keys should be stored on HSMs or air-gapped machines — the blast radius of a root key compromise is total.

---

## 6. Component Auth Keys

> 📋 **Status:** Planned feature — Ed25519 mutual authentication between ZTLP components (NS ↔ Relay, Relay ↔ Gateway). Not yet implemented in code.

### 6.1 Purpose

Component auth keys enable mutual authentication between ZTLP services. Without them, any process that can reach the NS UDP port can submit queries. Component auth adds a cryptographic proof that the requester is an authorized ZTLP component.

### 6.2 Planned Architecture

Each component will have an Ed25519 keypair:

| Component | Env Var (planned) | Key File (planned) |
|---|---|---|
| NS | `ZTLP_NS_AUTH_KEY` | `/etc/ztlp/ns-auth.key` |
| Relay | `ZTLP_RELAY_AUTH_KEY` | `/etc/ztlp/relay-auth.key` |
| Gateway | `ZTLP_GATEWAY_AUTH_KEY` | `/etc/ztlp/gateway-auth.key` |

Each component will know the public keys of its authorized peers. Authentication will be challenge-response: the responder sends a nonce, the requester signs it, and the responder verifies.

### 6.3 Pre-Deployment Recommendations

Even before component auth is implemented:

- **Network segmentation** — Only allow ZTLP service traffic between authorized hosts (firewall rules per [OPS-RUNBOOK.md § Firewall](OPS-RUNBOOK.md#required-ports-and-firewall-rules))
- **systemd hardening** — Already in place (see service files)
- **Erlang cookie isolation** — Each component already has its own cookie

---

## 7. HashiCorp Vault Integration

> 📋 **Note:** This section describes a recommended architecture for production deployments. Vault integration is not a built-in ZTLP feature — it requires deployment-time configuration.

### 7.1 Architecture Overview

```
┌─────────────────────┐
│   HashiCorp Vault   │
│                     │
│  ┌───────────────┐  │     ┌─────────────┐
│  │ Transit Engine │◄─┼─────┤  ztlp-ns    │  (Ed25519 signing via transit)
│  │ (Ed25519)     │  │     └─────────────┘
│  └───────────────┘  │
│                     │     ┌─────────────┐
│  ┌───────────────┐  │     │ ztlp-relay  │  (RAT secret from KV)
│  │ KV v2 Engine  │◄─┼─────┤             │
│  │ (secrets)     │  │     └─────────────┘
│  └───────────────┘  │
│                     │     ┌─────────────┐
│  ┌───────────────┐  │     │ztlp-gateway │  (identity keys from KV)
│  │ AppRole Auth  │◄─┼─────┤             │
│  └───────────────┘  │     └─────────────┘
└─────────────────────┘
```

**Benefits:**
- Private keys never leave Vault (transit engine signs without exposing keys)
- Centralized secret rotation and audit logging
- Dynamic secrets: short-lived credentials generated on demand
- Single source of truth for all ZTLP secrets

### 7.2 Vault Setup

**Enable required engines:**

```bash
# KV v2 for storing secrets
vault secrets enable -path=ztlp kv-v2

# Transit engine for Ed25519 signing (zone authority keys)
vault secrets enable -path=ztlp-transit transit

# AppRole auth for ZTLP services
vault auth enable approle
```

**Create the ZTLP secret structure:**

```bash
# Store RAT secret
vault kv put ztlp/relay/rat-secret \
    current="$(openssl rand -hex 32)" \
    previous=""

# Store Erlang cookies
vault kv put ztlp/ns/cookie value="$(openssl rand -base64 32 | tr -d '\n')"
vault kv put ztlp/relay/cookie value="$(openssl rand -base64 32 | tr -d '\n')"
vault kv put ztlp/gateway/cookie value="$(openssl rand -base64 32 | tr -d '\n')"

# Store identity keys (if not using transit for signing)
vault kv put ztlp/gateway/identity @~/.ztlp/identity.json
```

**Create transit key for zone signing:**

```bash
# Create an Ed25519 signing key (Vault manages the private key)
vault write ztlp-transit/keys/zone-root type=ed25519

# Create operator zone key
vault write ztlp-transit/keys/zone-example-ztlp type=ed25519
```

### 7.3 Vault Policies

```hcl
# policy: ztlp-relay
# Allows relay to read its own secrets
path "ztlp/data/relay/*" {
  capabilities = ["read"]
}

# Deny access to other components' secrets
path "ztlp/data/ns/*" {
  capabilities = ["deny"]
}
path "ztlp/data/gateway/*" {
  capabilities = ["deny"]
}
```

```hcl
# policy: ztlp-ns
# Allows NS to read its secrets and sign with transit keys
path "ztlp/data/ns/*" {
  capabilities = ["read"]
}
path "ztlp-transit/sign/zone-*" {
  capabilities = ["update"]
}
path "ztlp-transit/verify/zone-*" {
  capabilities = ["update"]
}
```

```hcl
# policy: ztlp-gateway
# Allows gateway to read its secrets
path "ztlp/data/gateway/*" {
  capabilities = ["read"]
}
```

**Apply policies:**

```bash
vault policy write ztlp-relay /path/to/ztlp-relay.hcl
vault policy write ztlp-ns /path/to/ztlp-ns.hcl
vault policy write ztlp-gateway /path/to/ztlp-gateway.hcl
```

### 7.4 AppRole Configuration

```bash
# Create AppRole for each component
for component in relay ns gateway; do
    vault write auth/approle/role/ztlp-${component} \
        token_policies="ztlp-${component}" \
        token_ttl=1h \
        token_max_ttl=4h \
        secret_id_ttl=0 \
        secret_id_num_uses=0
done

# Get RoleID and SecretID for each component
vault read auth/approle/role/ztlp-relay/role-id
vault write -f auth/approle/role/ztlp-relay/secret-id
```

### 7.5 Pulling Secrets at Deploy Time

**Wrapper script for systemd (pre-start):**

```bash
#!/bin/bash
# /usr/local/bin/ztlp-vault-env.sh
# Pulls secrets from Vault and writes env file before service start.
set -euo pipefail

COMPONENT="$1"  # relay, ns, or gateway
VAULT_ADDR="${VAULT_ADDR:-https://vault.internal:8200}"
ROLE_ID_FILE="/etc/ztlp/vault-role-id-${COMPONENT}"
SECRET_ID_FILE="/etc/ztlp/vault-secret-id-${COMPONENT}"
ENV_FILE="/etc/ztlp/${COMPONENT}.env"

# Authenticate with AppRole
VAULT_TOKEN=$(vault write -field=token auth/approle/login \
    role_id="$(cat $ROLE_ID_FILE)" \
    secret_id="$(cat $SECRET_ID_FILE)")

export VAULT_TOKEN

# Pull secrets based on component
case "$COMPONENT" in
    relay)
        RAT_CURRENT=$(vault kv get -field=current ztlp/relay/rat-secret)
        RAT_PREVIOUS=$(vault kv get -field=previous ztlp/relay/rat-secret 2>/dev/null || echo "")
        COOKIE=$(vault kv get -field=value ztlp/relay/cookie)

        cat > "$ENV_FILE" <<EOF
ZTLP_RELAY_RAT_SECRET=${RAT_CURRENT}
ZTLP_RELAY_RAT_SECRET_PREVIOUS=${RAT_PREVIOUS}
EOF
        echo -n "$COOKIE" > /var/lib/ztlp/relay/.cookie
        chown ztlp:ztlp /var/lib/ztlp/relay/.cookie
        chmod 0400 /var/lib/ztlp/relay/.cookie
        ;;

    ns)
        COOKIE=$(vault kv get -field=value ztlp/ns/cookie)
        echo -n "$COOKIE" > /var/lib/ztlp/ns/.cookie
        chown ztlp:ztlp /var/lib/ztlp/ns/.cookie
        chmod 0400 /var/lib/ztlp/ns/.cookie
        ;;

    gateway)
        COOKIE=$(vault kv get -field=value ztlp/gateway/cookie)
        echo -n "$COOKIE" > /var/lib/ztlp/gateway/.cookie
        chown ztlp:ztlp /var/lib/ztlp/gateway/.cookie
        chmod 0400 /var/lib/ztlp/gateway/.cookie
        ;;
esac

chmod 0640 "$ENV_FILE"
chown root:ztlp "$ENV_FILE"

echo "Secrets pulled from Vault for ${COMPONENT}"
```

**Add to systemd service as ExecStartPre:**

```ini
# /etc/systemd/system/ztlp-relay.service.d/vault.conf
[Service]
ExecStartPre=/usr/local/bin/ztlp-vault-env.sh relay
```

### 7.6 Transit Engine for Zone Signing

Instead of storing zone authority private keys on disk, use Vault's transit engine to sign records. The private key never leaves Vault.

```bash
# Sign data using transit (equivalent to Ed25519 signing)
vault write ztlp-transit/sign/zone-example-ztlp \
    input="$(base64 <<< '<canonical-record-bytes>')"

# Verify a signature
vault write ztlp-transit/verify/zone-example-ztlp \
    input="$(base64 <<< '<canonical-record-bytes>')" \
    signature="vault:v1:..."
```

> 💡 **Performance note:** Transit signing adds a network round-trip per signature. For high-throughput NS operations, consider caching or batch signing. For typical zone management operations, the latency is negligible.

---

## 8. AWS KMS / GCP Cloud KMS Integration

> 📋 **Note:** Like Vault, cloud KMS integration is a recommended deployment pattern, not a built-in ZTLP feature.

### 8.1 AWS

**Architecture:**

| ZTLP Secret | AWS Service | Key/Secret Type |
|---|---|---|
| RAT secrets | AWS Secrets Manager | SecretString (hex-encoded) |
| Erlang cookies | AWS Secrets Manager | SecretString (base64-encoded) |
| Identity keys | AWS Secrets Manager | SecretBinary (JSON) |
| Zone authority signing | AWS KMS | Asymmetric (ECC_SECG_P256K1†) |

> † AWS KMS does not natively support Ed25519. For zone signing, either: (a) store the Ed25519 private key in Secrets Manager and sign locally, or (b) use an HSM-backed solution via AWS CloudHSM.

**Secrets Manager example:**

```bash
# Store RAT secret
aws secretsmanager create-secret \
    --name ztlp/relay/rat-secret \
    --secret-string '{"current":"'$(openssl rand -hex 32)'","previous":""}'

# Retrieve at boot
RAT_JSON=$(aws secretsmanager get-secret-value \
    --secret-id ztlp/relay/rat-secret \
    --query SecretString --output text)
export ZTLP_RELAY_RAT_SECRET=$(echo "$RAT_JSON" | jq -r .current)
export ZTLP_RELAY_RAT_SECRET_PREVIOUS=$(echo "$RAT_JSON" | jq -r .previous)

# Rotate (update the secret)
NEW=$(openssl rand -hex 32)
OLD=$(echo "$RAT_JSON" | jq -r .current)
aws secretsmanager update-secret \
    --secret-id ztlp/relay/rat-secret \
    --secret-string '{"current":"'$NEW'","previous":"'$OLD'"}'
```

**IAM policy for ZTLP relay:**

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": [
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:ztlp/relay/*"
            ]
        }
    ]
}
```

### 8.2 GCP

**Architecture:**

| ZTLP Secret | GCP Service | Notes |
|---|---|---|
| RAT secrets | Secret Manager | Versioned secret |
| Erlang cookies | Secret Manager | Versioned secret |
| Identity keys | Secret Manager | Versioned secret (binary) |
| Zone authority signing | Cloud KMS | Asymmetric signing key |

**Secret Manager example:**

```bash
# Create secret
echo -n "$(openssl rand -hex 32)" | \
    gcloud secrets create ztlp-relay-rat-secret --data-file=-

# Retrieve at boot
export ZTLP_RELAY_RAT_SECRET=$(gcloud secrets versions access latest \
    --secret=ztlp-relay-rat-secret)

# Add new version (for rotation)
echo -n "$(openssl rand -hex 32)" | \
    gcloud secrets versions add ztlp-relay-rat-secret --data-file=-
```

**Cloud KMS for signing (if using supported algorithms):**

```bash
# Create signing key
gcloud kms keys create ztlp-zone-root \
    --location=global \
    --keyring=ztlp \
    --purpose=asymmetric-signing \
    --default-algorithm=ec-sign-ed25519

# Sign data
echo -n "<canonical-bytes>" | base64 | \
    gcloud kms asymmetric-sign \
    --location=global \
    --keyring=ztlp \
    --key=ztlp-zone-root \
    --version=1 \
    --input-file=-
```

> 💡 GCP Cloud KMS supports Ed25519 signing keys (as of 2024), making it a more natural fit for ZTLP zone signing than AWS KMS.

---

## 9. Security Best Practices

### 9.1 General Rules

| Rule | Rationale |
|---|---|
| **Never store keys in git** | Even private repos get cloned, forked, and leaked. Use `.gitignore` patterns. |
| **Use `0600` for private key files** | Only the owner should read private keys. |
| **Use `0640` for env files containing secrets** | Owner (root) can write, group (ztlp) can read. |
| **Use `0400` for Erlang cookies** | Read-only, owner-only. No writes needed after generation. |
| **Separate keys per environment** | A compromised dev key must not grant production access. |
| **Monitor key file access** | Use `auditd` or `inotifywait` to detect unauthorized reads. |
| **Rotate on a schedule** | Don't wait for a breach. RAT secrets: weekly. Zone keys: annually. |
| **Log all key operations** | Creation, rotation, revocation — all should appear in audit logs. |

### 9.2 `.gitignore` Patterns

```gitignore
# ZTLP secrets — NEVER commit these
*.key
*.cookie
identity.json
identity.hex
*.env
*.pem
*.gpg
*-secret*
vault-role-id-*
vault-secret-id-*
```

### 9.3 File Permission Audit Script

```bash
#!/bin/bash
# /usr/local/bin/ztlp-audit-permissions.sh
# Checks that all ZTLP secret files have correct permissions.
set -euo pipefail

ERRORS=0

check() {
    local file="$1"
    local expected_mode="$2"
    local expected_owner="$3"

    if [[ ! -e "$file" ]]; then
        return
    fi

    actual_mode=$(stat -c "%a" "$file")
    actual_owner=$(stat -c "%U:%G" "$file")

    if [[ "$actual_mode" != "$expected_mode" ]]; then
        echo "FAIL: $file has mode $actual_mode (expected $expected_mode)"
        ERRORS=$((ERRORS + 1))
    fi

    if [[ "$actual_owner" != "$expected_owner" ]]; then
        echo "FAIL: $file owned by $actual_owner (expected $expected_owner)"
        ERRORS=$((ERRORS + 1))
    fi
}

echo "=== ZTLP Secret File Permission Audit ==="

# Erlang cookies
check /var/lib/ztlp/ns/.cookie       400 "ztlp:ztlp"
check /var/lib/ztlp/relay/.cookie     400 "ztlp:ztlp"
check /var/lib/ztlp/gateway/.cookie   400 "ztlp:ztlp"

# Env files (may contain RAT secrets)
check /etc/ztlp/relay.env            640 "root:ztlp"
check /etc/ztlp/ns.env               640 "root:ztlp"
check /etc/ztlp/gateway.env          640 "root:ztlp"

# Config files
check /etc/ztlp/relay.yaml           640 "root:ztlp"
check /etc/ztlp/ns.yaml              640 "root:ztlp"
check /etc/ztlp/gateway.yaml         640 "root:ztlp"

# Data directories
for dir in /var/lib/ztlp/ns /var/lib/ztlp/relay /var/lib/ztlp/gateway; do
    if [[ -d "$dir" ]]; then
        actual_mode=$(stat -c "%a" "$dir")
        if [[ "$actual_mode" != "750" ]]; then
            echo "FAIL: $dir has mode $actual_mode (expected 750)"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done

# Zone authority keys (if present)
if [[ -d /etc/ztlp/zones ]]; then
    for keyfile in /etc/ztlp/zones/*.key; do
        check "$keyfile" 600 "root:root"
    done
fi

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo "PASS: All file permissions are correct"
else
    echo "FAIL: $ERRORS permission issues found"
    exit 1
fi
```

### 9.4 Monitoring Key Usage with auditd

```bash
# Install auditd rules for ZTLP secret files
cat > /etc/audit/rules.d/ztlp-keys.rules <<'EOF'
# Monitor Erlang cookie access
-w /var/lib/ztlp/ns/.cookie -p r -k ztlp-cookie-access
-w /var/lib/ztlp/relay/.cookie -p r -k ztlp-cookie-access
-w /var/lib/ztlp/gateway/.cookie -p r -k ztlp-cookie-access

# Monitor env file changes (contain RAT secrets)
-w /etc/ztlp/relay.env -p wa -k ztlp-env-change
-w /etc/ztlp/ns.env -p wa -k ztlp-env-change
-w /etc/ztlp/gateway.env -p wa -k ztlp-env-change

# Monitor zone authority key access
-w /etc/ztlp/zones/ -p rwa -k ztlp-zone-key-access
EOF

# Reload audit rules
sudo augenrules --load

# Search audit logs
ausearch -k ztlp-cookie-access --interpret
ausearch -k ztlp-env-change --interpret
```

### 9.5 Incident Response: Key Compromise Playbooks

#### Compromised: Node Identity Key

| Step | Action | Command |
|---|---|---|
| 1 | **Revoke** the compromised identity in NS | `ztlp ns revoke --zone <zone> --authority-key <zone-key> --node-id <compromised-id> --reason "key compromise"` |
| 2 | **Generate** new identity | `ztlp keygen --output ~/.ztlp/identity.json` |
| 3 | **Re-register** with NS | `ztlp ns register --name <name> --zone <zone> --key ~/.ztlp/identity.json --address <addr>` |
| 4 | **Update** any policies/ACLs referencing the old NodeID | Manual review of ZTLP_SVC and ZTLP_POLICY records |
| 5 | **Audit** for unauthorized access during compromise window | Check relay/gateway logs for sessions using the old NodeID |
| 6 | **Shred** the old private key | `shred -u ~/.ztlp/identity.json.old` |

#### Compromised: RAT Secret

| Step | Action | Command |
|---|---|---|
| 1 | **Immediate rotation** — generate and deploy new secret | See [§ 3.2](#32-step-by-step-rotation) |
| 2 | **Do NOT set the old secret as previous** | Attacker has it — they could forge tokens during the rotation window |
| 3 | **Accept brief disruption** | In-flight tokens with the old secret will fail. Clients re-authenticate automatically. |
| 4 | **If mesh:** rotate ALL relays simultaneously | Same new secret, no previous secret, coordinated restart |
| 5 | **Investigate** how the secret was exfiltrated | Check env file access logs, audit trail |

> ⚠️ **During a RAT secret compromise, do NOT use the dual-secret rotation pattern.** Setting the compromised secret as `rat_secret_previous` extends the attacker's window. Accept the brief disruption and deploy a fresh secret only.

#### Compromised: Erlang Cookie

| Step | Action | Command |
|---|---|---|
| 1 | **Stop** all services sharing the cookie | `systemctl stop ztlp-<component>` |
| 2 | **Generate** new cookie | `openssl rand -base64 32 \| tr -d '\n' > /var/lib/ztlp/<component>/.cookie` |
| 3 | **Set permissions** | `chown ztlp:ztlp <file> && chmod 0400 <file>` |
| 4 | **Start** services | `systemctl start ztlp-<component>` |
| 5 | **Audit** for unauthorized Erlang distribution connections | Check for unexpected `remote` shell connections in logs |
| 6 | **Investigate** — a leaked cookie may mean an attacker ran arbitrary code on your BEAM VM | Full incident investigation required |

#### Compromised: Zone Authority Key

| Step | Action | Priority |
|---|---|---|
| 1 | **Revoke** using parent authority | See [§ 5.6](#56-emergency-revoking-a-compromised-zone-authority) |
| 2 | **Generate** new zone authority key | Immediate |
| 3 | **Delegate** new key from parent | Immediate |
| 4 | **Re-sign** all records in the zone | As fast as possible |
| 5 | **Audit** all records signed during compromise window | Identify and remove any rogue records |
| 6 | **Notify** all operators/tenants in the affected zone | They may need to re-verify trust chains |

### 9.6 Environment Separation

```
┌─────────────────────────────────────────────────────┐
│                   Key Separation                     │
├─────────────┬─────────────────┬─────────────────────┤
│ Development │    Staging      │    Production        │
├─────────────┼─────────────────┼─────────────────────┤
│ Self-signed │ Separate root   │ Production root      │
│ trust anchor│ trust anchor    │ trust anchor (HSM)   │
│             │                 │                      │
│ Random RAT  │ Rotated weekly  │ Rotated weekly       │
│ secret      │ via cron        │ via Vault/KMS        │
│             │                 │                      │
│ Local       │ Separate Vault  │ Production Vault     │
│ key files   │ namespace       │ namespace            │
│             │                 │                      │
│ Dev cookies │ Staging cookies │ Production cookies   │
│ (can share) │ (unique)        │ (unique, audited)    │
└─────────────┴─────────────────┴─────────────────────┘
```

**Hard rules:**
- Production keys must **never** exist in dev or staging environments
- Staging keys must **never** exist in development environments
- Identity keys are **always** per-environment, per-node
- If any key works across environment boundaries, that's a misconfiguration

---

## Appendix: Quick Reference

### Key File Locations

```
~/.ztlp/identity.json              # Node identity (Ed25519 + X25519)
~/.ztlp/private.key                # Ed25519 private key
~/.ztlp/public.key                 # Ed25519 public key
~/.ztlp/node.id                    # 128-bit NodeID

/var/lib/ztlp/ns/.cookie           # NS Erlang cookie
/var/lib/ztlp/relay/.cookie        # Relay Erlang cookie
/var/lib/ztlp/gateway/.cookie      # Gateway Erlang cookie

/etc/ztlp/relay.env                # RAT secrets (ZTLP_RELAY_RAT_SECRET)
/etc/ztlp/ns.env                   # NS env overrides
/etc/ztlp/gateway.env              # Gateway env overrides

/etc/ztlp/zones/*.key              # Zone authority keypairs
```

### Environment Variables for Secrets

| Variable | Secret | Format |
|---|---|---|
| `ZTLP_RELAY_RAT_SECRET` | Current RAT signing key | 64 hex chars (32 bytes) |
| `ZTLP_RELAY_RAT_SECRET_PREVIOUS` | Previous RAT signing key (rotation) | 64 hex chars (32 bytes) |
| `RELEASE_COOKIE_FILE` | Path to Erlang cookie file | File path |

### Useful Commands

```bash
# Generate identity
ztlp keygen --output ~/.ztlp/identity.json

# Generate RAT secret
openssl rand -hex 32

# Generate Erlang cookie
openssl rand -base64 32 | tr -d '\n'

# Generate zone authority key
ztlp ns zone-keygen --zone example.ztlp --output /etc/ztlp/zones/example.ztlp.key

# Revoke a node
ztlp ns revoke --zone <zone> --authority-key <key> --node-id <id> --reason "reason"

# Audit file permissions
/usr/local/bin/ztlp-audit-permissions.sh

# Check cookie permissions
ls -la /var/lib/ztlp/*/.cookie

# Rotate RAT secret
/usr/local/bin/ztlp-rotate-rat-secret.sh
```
