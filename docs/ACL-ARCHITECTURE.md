# ZTLP Access Control Architecture

**Status:** Design proposal — not yet implemented.
**Author:** Session of 2026-05-24, captured from a dogfood walk that surfaced the underlying gap.
**Tracks:** Task NEW-3 (deny-by-default listener), Task NEW-4 (NS-backed group ACL).
**Related:** `~/hermes_session_handoff.md`, Known Problem #5 (`Config.registration_secret/0` legacy fallback), Task A (per-zone HMAC secret distribution).

---

## TL;DR

Today, `ztlp listen` defaults to **allow-all** when no `policy.toml` is present. Anyone who can reach the relay and guess the service name can complete a Noise_XX handshake and consume the forwarded TCP service. The application layer (e.g. SSH `authorized_keys`) is the only real gate. This document specifies how to flip that default and how to wire bootstrap-owned Users, Groups, and Resources into a multi-source-of-truth ACL that listeners pull from NS at handshake time.

The work is phased so Phase 1 (flat per-zone allowlist, deny-by-default) closes the real security hole today, while Phase 3 (groups, per-resource ACL) lands the production-grade model without re-architecting Phase 1.

---

## Problem Statement

### What's wrong today

1. `ztlp listen` without `--policy` accepts any pubkey that completes the Noise_XX handshake. Default = allow-all.
2. Bootstrap collects enrollee pubkeys during `ztlp setup --token` but **never propagates them** to NS, the relay, or listeners. The data lives in `enrollment_tokens.public_key` and dies there.
3. Listeners have no mechanism to ask "who else is enrolled in my zone?" — no NS RPC for that exists.
4. There is no concept of a Resource, a Group, or an ACL anywhere in the stack. The relay routes by service-name string; the listener policy file (when present) is a flat per-pubkey allow list.
5. Service-name registration is unauthenticated: any client with a relay address can `--service-name ssh-windows` and squat that name on the relay. There is no check that the registering pubkey is authorized to publish that name.

### Why it matters

- Defense-in-depth is currently zero at the ZTLP layer. The product's value proposition ("zero-trust transport") is undermined when the transport's own gate is open by default.
- Customers will reasonably expect "I enrolled my devices in a zone, only those devices can talk to listeners in that zone" — the data exists in bootstrap to enforce this, but the wiring doesn't.
- The `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false` posture (Known Problem #5) is the same class of bug at the NS layer; this design doesn't fix NS auth but is compatible with it being tightened in parallel.

---

## Goals & Non-Goals

### Goals

- **Deny-by-default** at the listener when no explicit policy is configured.
- **Group-based RBAC** so adding a member to "admins" automatically grants them access to every resource where "admins" is allowed.
- **Single source of truth** for Users, Groups, Resources, ACLs: the bootstrap dashboard.
- **Listener pulls flattened ACL** from NS at handshake time. NS computes the flat list on demand from bootstrap data.
- **Non-breaking** Phase 1: ships a flat per-zone allowlist, designed so Phase 3 can extend the same RPC with a `resource` parameter without breaking older clients.

### Non-Goals (for this design)

- Fixing NS registration auth (`ZTLP_NS_REQUIRE_REGISTRATION_AUTH`). Separate work.
- Replacing SSH/HTTP application-layer auth. ZTLP ACL is defense-in-depth, not a substitute.
- Federation across zones. ACLs are zone-local.
- Cryptographically-signed policy files (offline-distributable, tamper-evident). Possible future direction; not in this design.

---

## Data Model

```
Zone: trs.ztlp
├── Users (identities = Ed25519 pubkeys)
│   ├── steve-mac        pubkey: 7f4a…
│   ├── steve-iphone     pubkey: e221…
│   ├── alice-laptop     pubkey: d2be…
│   └── bob-laptop       pubkey: 9c11…
│
├── Resources (services published by listeners)
│   ├── ssh-windows      type: ssh    listener_pubkey: 2a0c… (windows box)
│   ├── ssh-mac          type: ssh    listener_pubkey: 7f4a…
│   ├── plex             type: http   listener_pubkey: 7f4a…
│   └── homeassistant    type: http   listener_pubkey: 2a0c…
│
└── Groups
    ├── admins           members: [steve-mac, steve-iphone]
    ├── family           members: [steve-mac, steve-iphone, alice-laptop]
    └── media-users      members: [bob-laptop, family]    ← groups can nest

Access rules (the actual ACL):
  ssh-windows     ← allow group:admins
  ssh-mac         ← allow group:admins
  plex            ← allow group:media-users
  homeassistant   ← allow group:family
```

### Rails models (bootstrap)

```ruby
# bootstrap/app/models/group.rb
class Group < ApplicationRecord
  belongs_to :network
  has_many :group_memberships, dependent: :destroy
  has_many :resource_access_rules, as: :principal, dependent: :destroy
  validates :name, presence: true, uniqueness: { scope: :network_id }
end

# bootstrap/app/models/group_membership.rb
class GroupMembership < ApplicationRecord
  belongs_to :group
  belongs_to :member, polymorphic: true   # ZtlpUser or Group
  validate :no_membership_cycles
end

# bootstrap/app/models/resource.rb
class Resource < ApplicationRecord
  belongs_to :network
  has_many :resource_access_rules, dependent: :destroy
  validates :name, presence: true, uniqueness: { scope: :network_id }
  validates :resource_type, inclusion: { in: %w[ssh http tcp udp] }
end

# bootstrap/app/models/resource_access_rule.rb
class ResourceAccessRule < ApplicationRecord
  belongs_to :resource
  belongs_to :principal, polymorphic: true   # ZtlpUser or Group
  enum action: { allow: 0, deny: 1 }
end
```

### Migrations

```ruby
class CreateGroupsAndAcls < ActiveRecord::Migration[7.1]
  def change
    create_table :groups do |t|
      t.references :network, null: false, foreign_key: true
      t.string :name, null: false
      t.string :description
      t.timestamps
    end
    add_index :groups, [:network_id, :name], unique: true

    create_table :group_memberships do |t|
      t.references :group, null: false, foreign_key: true
      t.references :member, polymorphic: true, null: false, index: true
      t.timestamps
    end

    create_table :resources do |t|
      t.references :network, null: false, foreign_key: true
      t.string :name, null: false
      t.string :resource_type, null: false
      t.string :listener_pubkey
      t.string :description
      t.boolean :unmanaged, default: false, null: false  # auto-discovered, awaiting operator confirmation
      t.timestamps
    end
    add_index :resources, [:network_id, :name], unique: true

    create_table :resource_access_rules do |t|
      t.references :resource, null: false, foreign_key: true
      t.references :principal, polymorphic: true, null: false, index: true
      t.integer :action, default: 0, null: false  # 0=allow, 1=deny
      t.timestamps
    end
  end
end
```

---

## Flattening Algorithm

Given a `(zone, resource_name)` lookup, compute the flat list of allowed pubkeys:

```
def flatten_acl(zone, resource_name):
    resource = Resource.find_by(network: zone, name: resource_name)
    return [] if resource is None              # unknown resource → deny

    # Collect all (principal, action) tuples
    rules = resource.resource_access_rules

    allowed = set()
    denied  = set()

    for rule in rules:
        pubkeys = expand_principal(rule.principal, visited=set())
        if rule.action == "allow":
            allowed.update(pubkeys)
        else:  # deny
            denied.update(pubkeys)

    return list(allowed - denied)   # deny wins

def expand_principal(principal, visited):
    if principal.id in visited:
        return set()                # cycle detection
    visited.add(principal.id)

    if principal is_a User:
        return {principal.pubkey}
    elif principal is_a Group:
        result = set()
        for member in principal.memberships:
            result.update(expand_principal(member, visited))
        return result
```

**Key properties:**

- Deny wins. A user in `family` who is explicitly denied on `homeassistant` does not get in even though `family` is allowed.
- Cycles are detected and the cyclic branch contributes nothing (no infinite loop, no exception).
- Unknown resource = empty list = deny-all. Operators must explicitly create a Resource row before any pubkey can hit it.

---

## NS RPC: `get_acl(zone, resource=nil)`

Listeners ask NS for the flattened pubkey list. NS holds a cache populated from bootstrap.

```elixir
# ns/lib/ztlp_ns/acl.ex (new module)
defmodule ZtlpNs.Acl do
  @doc """
  Returns {:ok, [pubkey_hex, ...]} or {:error, reason}.

  When `resource` is nil, returns the flat list of all enrolled
  pubkeys in the zone (Phase 1 semantics — equivalent to "everyone
  enrolled in this zone is allowed").

  When `resource` is set, returns the flattened ACL for that resource
  (Phase 3 semantics).
  """
  def get_acl(zone, resource \\ nil)
  def get_acl(zone, nil), do: zone_allowlist(zone)
  def get_acl(zone, resource), do: resource_acl(zone, resource)
end
```

### Wire format

```
ACL_REQUEST {
  u8  msg_type    = 0x40
  u8  flags       = 0
  str zone        (length-prefixed)
  str resource    (length-prefixed; empty = "all enrolled pubkeys in zone")
}

ACL_RESPONSE {
  u8  msg_type    = 0x41
  u8  status      // 0 = ok, 1 = unknown_resource, 2 = unknown_zone, 3 = server_error
  u32 generation  // monotonic, bumps on every ACL change; listeners can short-circuit refresh
  u32 ttl_seconds
  u16 count
  [u8; 32] pubkey * count
}
```

### Caching

- Listener caches per-resource ACL with the `ttl_seconds` from the response (default 30s).
- Listener also tracks `generation`. If it sees a newer generation in an unrelated NS call, it eagerly refreshes.
- On NS error, listener serves last-known-good for up to `stale_ttl` (default 300s), then fail-closed.

### Phase-1 implementation shortcut

In Phase 1, `get_acl(zone, nil)` is implemented by reading from bootstrap's `enrollment_tokens` table where `redeemed_at IS NOT NULL`. No Group/Resource tables needed. Listener calls `get_acl(zone, nil)` and gets every enrolled pubkey. This is the "anyone enrolled is in" model.

In Phase 3, listeners switch to `get_acl(zone, "ssh-windows")`. NS now consults the Resource/Group tables and runs the flattening algorithm above. Phase 1 callers (`resource=nil`) continue to work for backwards compatibility.

---

## Listener Integration

```rust
// proto/src/listener/policy.rs (sketch)
pub struct AclPolicy {
    ns_addr: SocketAddr,
    zone: String,
    resource: Option<String>,
    cache: Arc<RwLock<AclCache>>,
}

struct AclCache {
    pubkeys: HashSet<[u8; 32]>,
    fetched_at: Instant,
    ttl: Duration,
    generation: u32,
    last_good: Option<HashSet<[u8; 32]>>,
}

impl AclPolicy {
    /// Called from the Noise_XX completion path.
    /// Returns Ok(()) if the peer is allowed, Err(...) otherwise.
    pub fn check(&self, peer_pubkey: &[u8; 32]) -> Result<(), AclDenied> {
        let acl = self.refresh_if_stale()?;
        if acl.pubkeys.contains(peer_pubkey) {
            Ok(())
        } else {
            Err(AclDenied::NotInAllowList)
        }
    }

    fn refresh_if_stale(&self) -> Result<AclCacheRead, AclError> {
        // 1. fast path: still within ttl → return cached
        // 2. expired: send ACL_REQUEST to NS
        // 3. response ok: update cache, return
        // 4. response error:
        //    - within stale_ttl of last_good: serve last_good
        //    - beyond stale_ttl: fail-closed (deny everything)
    }
}
```

### CLI flags

```
ztlp listen \
  --service-name ssh-windows \
  --relay 34.218.240.106:23095 \
  --forward 127.0.0.1:22 \
  --acl-source ns                      # NEW: where to pull ACL from
  --ns-server 35.91.88.177:23096       # already exists
  --zone trs.ztlp                      # already exists (or inferred)
  --acl-resource ssh-windows           # NEW: which resource ACL to apply (Phase 3)
  --acl-fail-closed                    # default true; --no-acl-fail-closed for ops bypass
  --allow-anonymous                    # NEW: explicit opt-in to old allow-all behavior
```

### Behavior matrix

| `--policy` file | `--acl-source` | `--allow-anonymous` | Behavior                                                              |
|-----------------|----------------|---------------------|-----------------------------------------------------------------------|
| present         | unset          | unset               | Use policy file (current behavior preserved for opt-in users)         |
| absent          | `ns`           | unset               | Pull ACL from NS, deny-by-default                                     |
| absent          | unset          | unset               | **Phase 1 default change**: pull `get_acl(zone, nil)` from NS, deny otherwise |
| absent          | unset          | `true`              | Allow-all (today's behavior, now requires explicit flag)              |

---

## Resource Auto-Discovery

When a listener sends `GATEWAY_REGISTER --service-name ssh-windows` to the relay, the relay forwards a notification to bootstrap (new path): "listener pubkey `2a0c…` claims service `ssh-windows` in zone `trs.ztlp`."

Bootstrap behavior:

1. If no `Resource` row exists with `(network=trs.ztlp, name=ssh-windows)`: create one with `unmanaged=true` and `listener_pubkey=2a0c…`. Log to audit. The dashboard surfaces unmanaged resources with a "confirm" button.
2. If a row exists and `listener_pubkey` matches: no-op (idempotent re-register).
3. If a row exists and `listener_pubkey` differs: **reject the registration**. This is the squatting defense — only the listener that originally claimed a service name can re-register it. Log to audit as `resource.squatting_attempt_blocked`.

`unmanaged=true` resources still apply ACL — Phase 1 means "every enrolled pubkey can hit it" — but the dashboard nags the operator to review and either confirm or delete. Confirmation flips `unmanaged=false` and prevents the squatting check from being bypassed by an operator who deletes the row.

---

## Bootstrap Dashboard UI

Three new screens:

### `/networks/N/groups`

- List existing groups, member count, "delete" action.
- "New Group" form: name, description.
- Click a group → edit page with member management:
  - Search and add ZtlpUser by name/pubkey
  - Search and add nested Group
  - Remove member
  - "Members preview (flattened)" panel showing every concrete user that would be expanded
  - Cycle warning if user tries to create one

### `/networks/N/resources`

- Table: name, type, listener pubkey, status (managed/unmanaged), # ACL rules.
- Unmanaged resources highlighted yellow with "Confirm" button.
- Click resource → show page with current ACL.

### `/networks/N/resources/M/access`

- Two columns:
  - **Allowed:** list of principals (users + groups) with `action=allow`. "+ Add" picks from zone's Users and Groups.
  - **Denied:** same UI but `action=deny`. Deny wins.
- Each row shows the effective expansion (e.g. group `admins` → "Expands to: steve-mac, steve-iphone").
- "Test" widget: paste a pubkey, get back allow/deny + the rule chain that produced the decision. Useful for debugging.

---

## Phased Roadmap

| Phase | Scope | Estimated PRs | Closes hole? |
|-------|-------|---------------|--------------|
| **1** | Flat per-zone allowlist. NS RPC `get_acl(zone, nil)`. Listener `--acl-source ns` default. `--allow-anonymous` opt-out. Bootstrap exposes enrolled-pubkey list via internal RPC to NS. | 2-3 | **Yes** — "anyone can hit any listener" is the actual security hole today, and Phase 1 closes it. |
| **2** | Resource model. Listener registration creates `unmanaged` Resource rows. Dashboard list/confirm UI. Squatting check. No groups yet, no per-resource ACL — still per-zone semantics. | 2 | Reduces blast radius (can delete a resource) |
| **3** | Groups, ResourceAccessRule, per-resource ACL with deny-wins flattening. Dashboard groups + access UI. NS RPC extended with `resource` parameter. | 3-4 | Production-grade RBAC. |
| **4** | Polish: push-based revocation (NS → listener invalidation message), full audit log, "Test" widget, cycle detection UI. | 2 | Operational maturity. |

**Recommendation for v0.31 cycle:** ship Phase 1 only. It closes the actual security hole, requires no schema migrations in production tenants (only the NS RPC + listener flag are new), and validates the architecture before committing to the larger model.

---

## Open Questions

1. **Bootstrap → NS data flow.** Three options:
   - (a) NS polls bootstrap every N seconds (simple, lags by poll interval)
   - (b) Bootstrap pushes to NS on every change (more code, real-time)
   - (c) NS calls bootstrap on demand and caches per-zone (low latency, depends on bootstrap availability)

   Recommendation: (c) for Phase 1 with short TTL. (b) becomes worthwhile in Phase 3 to power push-based revocation.

2. **Resource registration auth.** When the relay forwards a registration to bootstrap, how does bootstrap verify the relay isn't lying about the source pubkey? Options:
   - Trust the relay (it's already inside the trust boundary)
   - Require relay-to-bootstrap mTLS with a shared cert
   - Embed a signature from the listener in GATEWAY_REGISTER and forward it untouched

   Recommendation: mTLS for v1, signature-in-packet for v2 (lets resources be re-verified by bootstrap without trusting the relay).

3. **Migration for existing tenants.** Tech Rockstars is already running on v0.30.2 with one enrolled device (`steve-mac`?) and the Windows box. Phase 1 should be opt-in via env var (`ZTLP_ACL_ENABLED=1` on the listener) for the first release, then default-on in v0.32.

4. **Listener restart on ACL change?** Phase 1 listeners refresh on TTL; Phase 4 listeners listen for push invalidations. In neither case do they need to restart. But: a Resource being deleted should probably tear down active sessions for any pubkey no longer in the ACL. Mechanism TBD.

5. **Group naming conflicts with user names.** Both Users and Groups are principals. The principal picker in the UI needs to disambiguate. Recommendation: prefix in UI (`user:steve-mac`, `group:admins`); store as polymorphic association as already designed.

---

## Out-of-Scope Risks Worth Capturing

- **NS becomes a bottleneck.** Every Noise handshake → NS lookup. Mitigated by listener caching, but a popular service could hammer NS. Phase 4 should add per-listener ACL push so the steady-state has zero NS traffic.
- **Bootstrap availability is now in the handshake path.** If bootstrap is down and NS's cache is stale, listeners fail-closed → no new connections. This is the right default (security over availability) but operators need to know.
- **`--allow-anonymous` is a footgun.** Document it loudly. Consider gating it behind an additional `ZTLP_ALLOW_ANONYMOUS_LISTENERS=1` env var so an operator can't accidentally re-open the world by pasting a CLI flag.

---

## Acceptance Criteria

### Phase 1
- [ ] `ztlp listen` with no `--policy` and no `--allow-anonymous` defaults to deny-all when NS is unreachable.
- [ ] `ztlp listen --acl-source ns --zone trs.ztlp --ns-server …` pulls the enrolled-pubkey list and admits only those pubkeys.
- [ ] An unenrolled device cannot complete a Noise_XX handshake with the listener — handshake fails with a clear "ACL denied" error visible in listener logs.
- [ ] An enrolled device connects successfully.
- [ ] Revoking enrollment in bootstrap → within `ttl_seconds + cache_jitter` the listener stops admitting that pubkey.
- [ ] `--allow-anonymous` flag preserves today's behavior verbatim, documented as "dev/test only."

### Phase 3
- [ ] Creating a Group in the dashboard and adding a member instantly affects ACL flatten for any Resource where that Group is allowed.
- [ ] Deny rules override allow rules.
- [ ] Group cycle detection in both UI (warning) and flatten algorithm (no infinite loop).
- [ ] Squatting attempt (different pubkey registering an already-claimed service name) is rejected and audit-logged.

---

## Related Work

- `docs/ARCHITECTURE.md` — overall ZTLP stack
- `docs/FEATURE-USER-IDENTITY.md` — how user identities were modeled when bootstrap was first built
- `~/hermes_session_handoff.md` — Task NEW-3 and NEW-4 entries reference this doc
- `bootstrap/app/services/ztlp/ensure_shared_machines.rb` — example of bootstrap-on-boot data seeding, similar pattern usable for Resource auto-discovery
