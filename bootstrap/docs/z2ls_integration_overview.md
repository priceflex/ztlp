# Z2LS ⇄ ZTLP Integration Overview

> One-page walkthrough of how Z2LS (the Tech Rockstars endpoint
> management platform) enrolls a Windows computer into a customer's
> ZTLP zone — no per-device API keys, single-use 24-hour tokens,
> Chef-driven endpoint configuration.

This document is a **map**. The actual contracts and state machines
live in the more focused docs linked at the bottom. Read this first
to understand which doc to open next.

Status: covers BS-PR-1 through BS-PR-6 (all shipped).

---

## TL;DR

```
┌───────────────┐  1. HMAC POST   ┌─────────────────────────┐
│  Z2LS portal  │ ──────────────► │  ZTLP Bootstrap         │
│  (per-tenant) │   /api/v1/      │  Rails (per-tenant ctn) │
│               │   enrollment_   │                         │
│               │   tokens        │  • mints 24h single-use │
└───────────────┘ ◄────────────── │    token row            │
        │           ztlp://       │  • writes audit log     │
        │           enroll/?...   └─────────────────────────┘
        │
        │ 2. write per-host data_bag entry
        ▼
┌───────────────────────────┐
│  chef-recipes-gitea-docs  │  data_bag.yml:
│  (Gitea-hosted)           │    ztlp:
│                           │      enrollment_tokens:
│                           │        ALICE-LAPTOP: "ztlp://enroll/..."
└───────────────────────────┘
        │
        │ 3. chef-solo pull/converge on ALICE-LAPTOP
        ▼
┌───────────────────────────┐
│  cookbooks/ztlp           │  • runs ztlp setup --token ... --name <host> -y
│  (default recipe)         │  • writes identity.json + config.toml
│                           │  • installs ztlp_listener NSSM service
│                           │  • locks sshd to 127.0.0.1
└───────────────────────────┘
        │
        │ 4. handshake + NS register
        ▼
┌───────────────────────────┐
│  ZTLP NS (per-zone)       │  • record KEY + SVC for <host>.<zone>
└───────────────────────────┘
        │
        │ 5. visible in Bootstrap dashboard
        ▼
┌───────────────────────────┐
│  ZTLP Bootstrap UI        │  admin can now:
│                           │  • see ALICE-LAPTOP as enrolled
│                           │  • add it to a Group
│                           │  • reference it in device-to-device policy
└───────────────────────────┘
```

---

## Step-by-step

### 1. Z2LS requests an enrollment token

The Z2LS portal (the TRS-internal SaaS that drives Chef recipes for
managed endpoints) holds two pieces of state per customer zone:

| State | Lives in | Notes |
|---|---|---|
| Per-zone HMAC secret | Z2LS config + bootstrap container env | Same value the relay and gateway already share. |
| `api_clients.name` | Z2LS config + bootstrap `api_clients` row | Allowlist + audit attribution layer on top of HMAC. |

When an operator clicks "enroll in ZTLP" for a managed computer
(or when Z2LS's automated provisioning catches a brand-new node),
Z2LS signs the canonical 6-line message and POSTs:

```http
POST /api/v1/enrollment_tokens HTTP/1.1
Content-Type: application/json
X-ZTLP-Zone: acme.ztlp
X-ZTLP-Client: z2ls.acme
X-ZTLP-Timestamp: 1700000000
X-ZTLP-Signature: <hex HMAC-SHA256>

{"computer_name": "alice-laptop", "metadata": {"os": "Windows 11"}}
```

Bootstrap responds 201 with `enrollment_token` set to the full
`ztlp://enroll/?zone=...&ns=...&token=...&expires=...` URI plus
expiry metadata.

The full signing contract — including hex/raw-bytes secret encoding,
clock-skew window, replay-protection notes, and every 401 failure
code — is in [`api_v1_ztlp_secured.md`](./api_v1_ztlp_secured.md).
The Z2LS-side operator runbook, including a working Ruby snippet
suitable for copy-paste into the Z2LS Rails app, is in
[`z2ls_enrollment_runbook.md`](./z2ls_enrollment_runbook.md).

### 2. Z2LS writes the token into `data_bag.yml`

Z2LS already maintains `data_bag.yml` on the chef-recipes Gitea
repo per managed customer. The new pattern is to add a per-host
mapping under `ztlp.enrollment_tokens`:

```yaml
ztlp:
  zone: acme.ztlp
  ns_server: "ns.acme.ztlp:23096"
  hosts:
    - ALICE-LAPTOP                  # or "all" for the whole fleet
  enrollment_tokens:
    ALICE-LAPTOP: "ztlp://enroll/?zone=acme.ztlp&ns=...&token=ab12cd...&expires=1700086400"
```

The token is bound to a single computer name and self-expires in
24 hours. There is no risk in committing it to Gitea — once the
token is consumed it transitions to `exhausted` and a replay is
rejected. (See
[`enrollment_token_lifecycle.md`](./enrollment_token_lifecycle.md)
for the state machine and atomic single-use enforcement.)

Z2LS commits the change through its normal Gitea workflow. The
managed endpoint will pick it up on its next hourly Chef pull.

### 3. The `ztlp` cookbook converges on the endpoint

`cookbooks/ztlp/` lives in the
[chef-recipes Gitea repo](http://10.42.42.115:3005/z2ls/chef-recipes)
and is described in
[`z2ls-chef-gitea-workflow`](https://github.com/priceflex/ztlp/blob/main/docs/plans/ztlp-net-scaffolding/README.md)
(skill: `z2ls-chef-gitea-workflow`).

When chef-solo converges on `ALICE-LAPTOP`:

1. The recipe reads `data_bag.yml` and looks up
   `ztlp.enrollment_tokens["ALICE-LAPTOP"]`.
2. If found AND no prior identity exists, it runs
   `ztlp.exe setup --token "<uri>" --name ALICE-LAPTOP -y`.
3. The CLI generates X25519 + Ed25519 keys locally, stores the
   private material at `C:\ProgramData\ZTLP\identity.json`,
   and writes `config.toml` pointing at the zone's NS.
4. The cookbook also installs Windows OpenSSH (if missing),
   binds sshd to `127.0.0.1`, removes broad firewall rules,
   and installs an NSSM service `ztlp_listener` forwarding
   authenticated ZTLP sessions to `127.0.0.1:22`.

The cookbook is **opt-in** via `ztlp.hosts` (host-gating pattern
from `z2ls-chef-gitea-workflow` — accepts `"all"` or a list).

### 4. NS registration → Bootstrap visibility

`ztlp setup` does the device-side enrollment handshake with NS:
the device sends `0x07 ENROLL` to the NS server in the token,
NS verifies the URI is still active, and auto-approves within
the 24h window. After confirmation the endpoint's public key
is published as an NS `KEY` record under `<computer_name>.<zone>`.

The cookbook additionally invokes
`ztlp ns register --name <host>.<zone> --address <listener_bind>`
once per identity to publish an `SVC` record for the listener
port, so other ZTLP clients can discover and connect to it by
name (see
[`bootstrap/docs/multi_service_gateway.md`](./multi_service_gateway.md)).

At this point the device shows up in the Bootstrap dashboard
under **Devices** for the zone. The admin UI for managing it
(grouping, policy assignment, revocation, suspension) is in
[`dashboard_bspr5.md`](./dashboard_bspr5.md).

### 5. Groups and policy

Once a device is enrolled, the admin can:

- Place it in one or more **Groups** (used to scope policy at
  larger granularity than per-device).
- Author **device-to-device policy** rules (default-deny; explicit
  allow by identity or group).
- **Revoke** the device's identity (lost device) without touching
  the parent user's other devices.
- **Suspend** the user binding to deny access from every associated
  device at once.

All of these are operator-facing actions in the Bootstrap admin
UI and are documented in `dashboard_bspr5.md`. There is no Z2LS
involvement in policy authoring — Z2LS only enrolls. Policy is
a Bootstrap admin concern.

---

## Endpoint identifier-lock (Chef-side safety)

A subtle attack: someone with write access to `data_bag.yml`
could replace a host's `enrollment_tokens` entry with a new
token for a different zone, then nudge the host to re-enroll
and silently migrate it into an attacker-controlled NS.

The `ztlp` cookbook defends against this with two optional
data_bag keys:

```yaml
ztlp:
  lock_identity: true                 # default
  identifier_hash: "<sha256 hex>"     # optional, operator-pinned
```

Behavior:

- On **first** enrollment (no `identity.json` yet), the recipe
  proceeds normally.
- On subsequent converges, the recipe computes SHA256 of the
  on-disk public-key bytes.
- If `lock_identity` is true (default) AND `identifier_hash` is
  set AND the on-disk hash does **not** match, the recipe
  raises and refuses to re-enroll.
- If `lock_identity` is true and `identifier_hash` is unset,
  the recipe falls through (first-run convenience) but logs a
  WARN suggesting the operator pin the hash.
- If the data_bag's token URI references a **different zone**
  than the existing identity's `config.toml` zone, the recipe
  refuses regardless of `lock_identity`.

To rotate a host's identity intentionally:

1. Remove `C:\ProgramData\ZTLP\identity.json` on the host.
2. Update `identifier_hash` in `data_bag.yml` to the new
   expected value (or remove the key for first-run mode).
3. Mint a new token via Z2LS → BS-PR-3.
4. Next Chef converge will re-enroll cleanly.

This guard lives on the endpoint, not in Bootstrap, because
Bootstrap's only job is to verify the token; it can't tell
which host is "really" supposed to consume it.

---

## Why no API keys?

Per Steve's 2026-05-23 brief:

> "Do not use a traditional API key model. Instead, use
> ZTLP-secured device-to-device communication so trusted systems
> can talk to the ZTLP Bootstrap API."

The per-zone HMAC secret already powers the gateway↔relay↔bootstrap
trust mesh. Reusing it as Z2LS's credential collapses three secret
inventories into one. Compromise recovery is the same operation
regardless of which component was breached: rotate the per-zone
secret and every consumer (gateway, relay, bootstrap, all Z2LS
instances in that zone) re-credentials together.

The `api_clients` allowlist on top of HMAC gives an operator a
**kill switch** for one Z2LS instance without rotating the secret —
flip `active: false` in the bootstrap admin UI and that specific
caller's signed requests start being rejected as `unknown_client`,
while everything else in the zone keeps working.

---

## Related documents

Bootstrap docs (this folder):

- [`enrollment_token_lifecycle.md`](./enrollment_token_lifecycle.md) — BS-PR-1
  EnrollmentToken model: 24h default lifetime, single-use, atomic
  `use!`, sweeper rake task.
- [`api_v1_ztlp_secured.md`](./api_v1_ztlp_secured.md) — BS-PR-2
  Formal API auth contract: 6-line canonical message, 401 failure
  codes, allowlist semantics, future variants.
- [`z2ls_enrollment_runbook.md`](./z2ls_enrollment_runbook.md) — BS-PR-3 + BS-PR-6
  Integrator runbook with working Python/Ruby/curl snippets and
  end-to-end smoke test.
- [`auto_network_on_boot.md`](./auto_network_on_boot.md) — BS-PR-4
  Per-tenant Bootstrap containers auto-provision the Network row
  on boot so the BS-PR-3 endpoint doesn't 503 immediately after
  onboarding.
- [`dashboard_bspr5.md`](./dashboard_bspr5.md) — BS-PR-5
  Admin UI for `api_clients`, devices, groups, and device-to-device
  grants.
- [`multi_service_gateway.md`](./multi_service_gateway.md) —
  Device-side service discovery via NS `SVC` records.

ZTLP repo:

- [`docs/per_zone_hmac_design.md`](../../docs/per_zone_hmac_design.md) —
  How the per-zone HMAC secret is provisioned, rotated, and
  consumed by the relay/gateway/bootstrap trust mesh.

Hermes skill packs (operator-facing, not in this repo):

- `~/.hermes/skills/devops/ztlp-net-bootstrap-control-plane/SKILL.md`
- `~/.hermes/skills/devops/z2ls-chef-gitea-workflow/SKILL.md`
- `~/.hermes/skills/devops/ztlp-bootstrap-enrollment/SKILL.md`

---

Last updated: 2026-05-23.
