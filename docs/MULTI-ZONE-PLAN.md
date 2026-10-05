# ZTLP Multi-Zone Plan (one NS, many zones)

Status: plan, not built. Decisions by Steven on 2026-10-04.

## Decisions

- Multiple zones on ONE TRS name server. No cross-org forwarding or NS
  linking in this phase. That stays a later phase (see section 7).
- The bare zone name is the site: `chooseforce.ztlp`, `blitz.ztlp`. One web
  service per zone, no `www`/`admin` labels for now (reversible; the SNI
  router still supports per-route auth if labels are added later).
- ONE CA signs certs for every zone. A client installs a single root once
  and every zone gets the padlock.
- Only an admin can add or change NS records. "Admin" means the holder of
  the NS admin API secret (HMAC-signed requests). Record registration auth
  stays ON.
- The DEF CON demo NS (`<DEMO-NS-PUBLIC-IP>`) runs with registration auth OFF. Do
  not host real zones on it. A separate TRS NS is needed for real zones.

## 1. What already exists (checked in code, 2026-10-04)

| Need | State | Where |
|---|---|---|
| Agent resolves any `*.ztlp` name via the NS, no zone allowlist | Done | `proto/src/agent/dns.rs` (`handle_dns_query`: NS lookup -> VIP or NXDOMAIN) |
| Gateway trusts the NS signing key for every zone | Done | `gateway/lib/ztlp_gateway/ns_client.ex`, `ZTLP_GATEWAY_TRUST_ANCHORS` (label:pubkey, comma-separated) |
| NS record writes gated by HMAC admin API with rate limit | Done | `ns/lib/ztlp_ns/admin_api.ex`, `ZTLP_NS_REQUIRE_REGISTRATION_AUTH` (default true) |
| Per-hostname leaf certs in the gateway | Done | `gateway/lib/ztlp_gateway/cert_cache.ex` |
| SNI routing incl. wildcards, runtime `put_route/3` | Done | `gateway/lib/ztlp_gateway/sni_router.ex` |
| Zone-chain design (root -> operator -> tenant), multiple trust roots | Designed, partly built | `ns/lib/ztlp_ns/zone_authority.ex`, `trust_anchor.ex` |
| Single-label SVC names (`demo-dashboard.defcon.ztlp` is registered via `ztlp ns register --name`) | Works for the demo | `demo/seed-cloud-demo.sh` |

Notes:
- The gateway anchor label (`defcon.ztlp`) is just a label. The anchor is
  the NS signing key, so one anchor covers all zones on that NS.
- `auto_discover` in `proto/src/agent/config.rs` is defined and defaults to
  true but nothing reads it. Do not count on it.
- The NS signs every record with ONE key in the running config. Per-zone
  signing keys exist in the design but not in the live path.

## 2. The gaps

1. **Windows DNS forwards only configured zones.** The agent installs one
   NRPT rule per zone (`.defcon.ztlp` on the AI computer). A name in another
   zone never reaches the agent. Fix candidates:
   a. One `.ztlp` rule covering every zone. Simplest. `normalize_namespace`
      accepts any suffix. Not yet tested.
   b. Agent adds rules as it learns zones from the NS. More moving parts.
   Pick (a) unless the test fails.
2. **Bare zone SVC name.** Confirm the NS accepts `chooseforce.ztlp` as an
   SVC name with no host prefix, and the agent's `service_name_for_ztlp_name`
   gives the gateway the service it expects.
3. **Single CA across zones.** `cert_provisioner.ex` reads
   `ZTLP_GATEWAY_SERVICE_ZONE` for the CA zone. Confirm a cert for
   `chooseforce.ztlp` can be minted under the single CA (SAN
   `dns:chooseforce.ztlp`).
4. **"Add zone" is manual.** Today: edit the gateway compose env
   (`ZTLP_GATEWAY_BACKENDS`, `POLICIES`, `SERVICE_NAMES`), recreate the
   gateway, run `ztlp ns register`. Needs one admin command.
5. **Admin identity.** The admin API gates on a shared secret. No per-admin
   identity or audit of who changed a record.
6. **Agent asks one NS.** `ns_server` is a single address. Fine for one TRS
   NS; blocks cross-org later.

## 3. Steps (in order, each proves itself)

### Step 1: DNS rule test on the AI computer (read-mostly, reversible)
- Add NRPT rule `.ztlp -> 127.0.0.55` alongside the existing `.defcon.ztlp`.
- Register a throwaway SVC `chooseforce.ztlp` on the NS used by that agent.
- `Resolve-DnsName demo-dashboard.defcon.ztlp` and `chooseforce.ztlp` from
  Windows (not from the agent directly). Both must return a VIP.
- Remove the throwaway record and, if asked, the rule.
- Pass = gap 1 closed with no agent code change. Fail = tells us whether the
  rule or the agent is at fault.

### Step 2: ChooseForce behind the gateway (proof site)
- Container: `Choose-Force/Dockerfile` (Rails, port 3000) plus ONE MariaDB
  with an empty DB. Not the repo's 3-node Galera + MaxScale compose. Never
  point it at production data.
- Host: a Linux Docker host. The AI computer has no Docker. The AWS demo box
  is 2 CPU / 3.8 GB with ~450 MB free; a Rails + MariaDB pair may not fit.
  Decide host before building.
- Gateway: add backend `chooseforce:<host>:3000`, policy, service name;
  SNI route `chooseforce.ztlp`; mint leaf cert under the single CA.
- NS: register SVC `chooseforce.ztlp` (admin API, auth ON on a non-demo NS).
- Verify: curl from the AI computer, then Chrome with padlock. Chrome check
  needs the single root CA in the Windows trust store.

### Step 3: `ztlp admin create-service`
- `ztlp admin create-service --name <zone> --backend host:port [--auth-mode]
  [--min-assurance]`.
- Does: NS SVC register (admin-signed) + gateway `put_route` + cert mint.
- TDD. Thin shell-out like the desktop "create identity" step.
- Refuse when registration auth is off, so it cannot be used on the demo NS
  by accident.

### Step 4: Agent installs the `.ztlp` rule itself
- Only after Step 1 passes. Change `setup` / `windows_daemon` to install
  `.ztlp` (or the configured root suffix) instead of one rule per zone.
- Keep the per-zone rule path for custom domains (`internal.example.com`).

### Step 5: Admin identity and audit (hardening)
- Key admin API calls on an operator identity (NS OPERATOR record), not a
  shared secret. Log who changed which record.
- Needed before more than one person administers the NS.

## 4. Security notes

- The NS is the trust boundary. Anyone who can register a zone on it is
  resolved on every client. Acceptable while only TRS runs it; written down
  here so it is a choice, not an accident.
- Resolving a name never grants access. The gateway route's `auth_mode` and
  `min_assurance` decide. Keep `*` deny as the last policy.
- A user may reach a login wall for a site they are not allowed into. The
  gateway should return a clear error, not hang.
- One CA for all zones means one root to protect and one revocation path.
  Document where the CA key lives and who can mint.

## 5. Open questions

- Which Linux host runs the ChooseForce proof container?
- Which NS hosts TRS zones? New instance, or the production NS at
  <PROD-NS-PUBLIC-IP> (per `ztlp-github-repo-release` notes)?
- Does `chooseforce.ztlp` need any `service=` naming change in the agent's
  CLIENT_ROUTE (the demo uses the leading label as service name)?

## 6. Not in scope now

- Cross-org trust (two NS instances, linked trust anchors, forwarding).
- Per-zone signing keys in the live path.
- Transitive trust between partners.

## 7. Later phase: cross-org trusted zones (for reference)

The design in `zone_authority.ex` already describes it: each org runs its
own NS and root key; an admin adds the partner's root as a trust anchor,
pinned to one zone; our NS forwards or mirrors that zone's records. Build
order when it is wanted: per-zone signing -> admin "add trusted zone"
command (add/list/remove, audited) -> forwarding. Rules: pin the link to a
zone, revoke drops names immediately, no transitive trust, never prototype
on the demo NS.
