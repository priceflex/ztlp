# NS Admin API — Tenant Isolation Operator Guide

> **Audience:** Operators deploying ZTLP NS and Bootstrap on shared
> infrastructure. You should be comfortable with `docker compose`, basic
> CIDR notation, and editing `.env` files. You do **not** need to know
> any Elixir or Ruby.

> **Status:** Phase 2 (this branch, `feat/ns-sync-tenant-isolation`) —
> per-tenant secrets, IP allow-lists, and zone-glob scoping ship together.
> Phase 1 (PR #97 — rate-limit + audit logging) is a prerequisite.

---

## What this is for

The NS server exposes an internal HTTP endpoint, `/admin/records`, that
each customer's Bootstrap container calls every five minutes to pull
the current device record set. Until this branch, that endpoint was
guarded by **one** shared HMAC secret. Whoever held that secret could
list every device record from every customer — across every zone — by
sending one request. That's tolerable while we run a single customer
(Tech Rockstars). The moment we add a second customer to the same NS
instance, it becomes a cross-tenant data-leak vector.

This release introduces a **two-lock model**. To pull records, a
caller must satisfy *both* of these independently:

1. **Network lock (CIDR allow-list).** The TCP peer IP NS sees must
   fall inside a CIDR registered to some configured tenant. Outside
   any tenant CIDR → `403`, before NS even reads the request body.
2. **Crypto + scope lock (per-tenant HMAC + zone glob).** The HMAC
   signature must verify under a specific tenant's secret. That same
   tenant has a *zone glob* (e.g. `*.tech-rockstars.trs.ztlp`); NS
   filters the response so only records under that glob come back.
   Even with a valid signature, a tenant cannot enumerate records
   outside their assigned zone.

A leaked secret on its own is now useless. The attacker also needs
network position inside the tenant's allowed CIDR, *and* they're
still limited to that tenant's zone glob.

---

## The TRS operator-tenant pattern (Option B)

ZTLP's deployment model treats **TRS (Tech-Rockstars Services)** as the
**operator tenant** — the MSP running the platform — and every customer
as a peer tenant nested under TRS's parent zone. Concretely:

- The shared root is `*.trs.ztlp`. (The root doesn't need to end in
  `.ztlp`; it can be `.com`, `.io`, `.local`, whatever you choose.
  The zone-glob matcher is opaque to the suffix.)
- TRS is assigned the zone glob `*.trs.ztlp`.
- Each customer is assigned a deeper glob:
  - Tech Rockstars (the legacy customer): `*.tech-rockstars.trs.ztlp`
  - Acme Dental: `*.acme-dental.trs.ztlp`
  - Aligned Dental: `*.aligned-dental.trs.ztlp`

By design, **TRS's glob deliberately overlaps with every customer's
glob.** That's not a misconfiguration — it's the MSP business model
made explicit. TRS holds operator-level visibility into customer device
records because TRS *runs* the platform. The deny-by-default rule
applies **between customer tenants** (Acme cannot see Aligned-Dental's
records, and vice versa), **not** between TRS and a customer.

> **If you don't want operator-level visibility** for your deployment,
> assign TRS a sibling glob (e.g. `*.trs-internal.example.com`) instead
> of an ancestor of customer zones. The matcher doesn't care; you just
> pick non-overlapping globs. Most readers of this doc *do* want the
> overlap, so the rest of this guide assumes Option B.

---

## Environment variable conventions

All tenant configuration lives in NS's environment. The convention is:

```text
ZTLP_NS_ADMIN_API_TENANT_<SLUG>_SECRET     — 64-char hex (32 raw bytes)
ZTLP_NS_ADMIN_API_TENANT_<SLUG>_ZONE_GLOB  — e.g. *.trs.ztlp  or  trs.ztlp
ZTLP_NS_ADMIN_API_TENANT_<SLUG>_CIDRS      — comma-separated IPv4 CIDRs
```

**Slug rules** (enforced at boot):

- Uppercase letters, digits, and underscores only.
- Must start with an uppercase letter.
- Lowercase env-var names are **silently ignored** — there's no
  auto-uppercasing. `ZTLP_NS_ADMIN_API_TENANT_trs_SECRET` does not
  register a tenant; `ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET` does.

**Zone-glob rules:**

- `*.trs.ztlp` — wildcard prefix, matches one or more leading
  labels. Matches `foo.trs.ztlp`, `a.b.trs.ztlp`. Does *not* match
  bare `trs.ztlp`.
- `trs.ztlp` — exact match only (bare zone, no wildcard).
- `*.foo.*` — **rejected at boot.** Middle wildcards are forbidden;
  NS will refuse to start with this in the registry.

**CIDR rules:**

- IPv4 only for now. (IPv6 is a future task.)
- Multi-CIDR is supported — separate with commas, no spaces:
  `172.18.0.0/16,10.42.0.0/16`. Useful for primary + backup networks.
- Malformed CIDRs (`172.18.0.0/33`, `not.an.ip/24`) are rejected at boot.
- `/0` is allowed but a warning is logged. Don't ship `/0` to prod.

**Legacy / transitional vars:**

```text
ZTLP_NS_ADMIN_API_SECRET                   — single global HMAC, Phase 1
ZTLP_NS_ADMIN_API_RATE_LIMIT=12/60         — count/window-seconds (PR #97)
```

The global secret keeps working **as a fallback** during migration —
see *Migration & deprecation timeline* below. It will be removed in
Phase 3.

> **Critical:** The Bootstrap side does *not* use the
> `ZTLP_NS_ADMIN_API_TENANT_<SLUG>_*` variables. Each Bootstrap
> container has exactly **one** secret: `ZTLP_NS_ADMIN_API_SECRET`.
> The "per-tenant" model lives entirely on the NS side — NS uses the
> signature to figure out which tenant is calling. Don't try to set
> the tenant vars on Bootstrap; they'll be ignored.

---

## Quick-start: deploying a new tenant

This walkthrough assumes NS is already running with Phase 1 (PR #97)
and you're adding a fresh tenant. We'll use Acme Dental as the
example, with zone `*.acme-dental.trs.ztlp`.

### 1. Generate a strong HMAC secret

```bash
openssl rand -hex 32
```

You'll get a 64-character hex string. Save it somewhere safe (a
secrets manager, password vault). You'll paste it into two places:
NS's `.env` and the tenant's Bootstrap `.env`.

### 2. Pick a tenant slug

Uppercase letters, digits, underscores. Must start with a letter.
For Acme Dental, a sensible slug is `ACME_DENTAL`.

### 3. Find the Docker bridge CIDR for the tenant's Bootstrap

The CIDR is the network the tenant's Bootstrap container will appear
on from NS's point of view. Find it with:

```bash
docker network inspect acme-dental_default | grep Subnet
```

Replace `acme-dental_default` with the actual network name (often
`<project-dir>_default`). You'll see something like
`"Subnet": "172.19.0.0/16"`. Copy that value.

> **Warning:** If NS and Bootstrap share the same Docker host but
> different compose projects, each compose project gets its own
> bridge network with a different subnet. Don't assume — inspect.

### 4. Decide the zone glob

For Acme Dental nested under TRS: `*.acme-dental.trs.ztlp`.

### 5. Add three env vars to NS's `.env`

```bash
ZTLP_NS_ADMIN_API_TENANT_ACME_DENTAL_SECRET=<paste your hex from step 1>
ZTLP_NS_ADMIN_API_TENANT_ACME_DENTAL_ZONE_GLOB=*.acme-dental.trs.ztlp
ZTLP_NS_ADMIN_API_TENANT_ACME_DENTAL_CIDRS=172.19.0.0/16
```

### 6. Restart NS

```bash
docker compose restart ztlp-ns
```

Tenant config is loaded at boot. Confirm load with:

```bash
docker logs ztlp-ns 2>&1 | grep -i tenant
```

You should see a line indicating the tenant registry loaded
`ACME_DENTAL`. If the registry rejected your input (bad CIDR, illegal
glob, malformed slug) NS will refuse to start — check the log.

### 7. Configure Bootstrap with the same secret

In the Acme Dental Bootstrap container's `.env`:

```bash
ZTLP_NS_ADMIN_API_SECRET=<same hex you generated in step 1>
```

That's it. Bootstrap doesn't know or care about its own slug, zone
glob, or CIDR. All it knows is "I have a secret; I send it with each
request."

### 8. Restart Bootstrap

```bash
docker compose restart acme-dental-bs
```

### 9. Watch the sync logs

```bash
docker logs -f acme-dental-bs | grep ns:sync
```

Within ~five minutes you should see a successful sync line. If you
don't want to wait, skip to *Force a sync* under *Verification*.

---

## Rolling out to TRS production (legacy → per-tenant)

TRS is already running in production under the **legacy global
secret** model (one `ZTLP_NS_ADMIN_API_SECRET`). The migration is
designed to be zero-downtime. Do it in three discrete steps with
verification between each.

### Step 1 — Deploy the code (this PR merges)

The legacy global-secret path is preserved. Every existing sync keeps
working exactly as it did before. NS now also *supports* per-tenant
config, but with zero tenant env vars set, behavior is identical to
Phase 1.

**Verification:** TRS Bootstrap continues to sync. Tail NS audit log:

```bash
docker logs ztlp-ns 2>&1 | grep admin_api_records_pulled
```

You should see `:admin_api_records_pulled` events at `:info` severity
every five minutes. You should **not** see
`:admin_api_legacy_global_secret` events yet (that event only fires
when tenants are configured *and* the request fell back to the global
secret — neither is true at this stage).

### Step 2 — Register TRS as a tenant on NS

Add three vars to NS's `.env`:

```bash
ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET=<existing global secret, verbatim>
ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB=*.trs.ztlp
ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS=<the TRS Bootstrap's bridge CIDR>
```

> **Important:** Use the *same* hex value you've been using for the
> global secret. We're not rotating yet — we're just teaching NS that
> this secret belongs to a tenant named TRS.

Restart NS:

```bash
docker compose restart ztlp-ns
```

Now NS will recognize the incoming HMAC as TRS's tenant-scoped secret
(not the legacy global), and apply TRS's zone glob to filter the
response. Because TRS's glob is `*.trs.ztlp` and every existing record
is already under that zone, the response set is the same as before.

**Verification:**

```bash
docker logs ztlp-ns 2>&1 | grep admin_api_records_pulled
```

The `tenant:` field on the audit event should now read `"TRS"`
instead of being absent. `:admin_api_legacy_global_secret` should not
fire — TRS is matching as a real tenant.

### Step 3 — Monitor for stragglers

If `:admin_api_legacy_global_secret` fires after Step 2, *some* client
is still being identified via the global fallback (not as a known
tenant). Find which one:

```bash
docker logs ztlp-ns 2>&1 | grep admin_api_legacy_global_secret
```

The audit event includes the `peer_ip`. Track it back to a Bootstrap
container and either (a) finish configuring it as a tenant, or (b)
accept it stays on the legacy path until Phase 3.

### Step 4 — (future) Remove the legacy fallback

**Don't do this yet.** This step belongs to Phase 3, after every BS
client has been migrated and `:admin_api_legacy_global_secret` has
been zero for a full deployment cycle. When ready, unset
`ZTLP_NS_ADMIN_API_SECRET` in NS's `.env` and restart. Any client not
matching a registered tenant will start failing 401.

---

## Onboarding a second tenant (Acme Dental walkthrough)

Once TRS is migrated, adding Acme Dental is just the *Quick-start*
above. Two extra verifications matter, because this is the first time
isolation is exercised end-to-end:

### 1. TRS still sees Acme Dental's records (operator visibility)

From the TRS Bootstrap, force a sync:

```bash
docker exec bootstrap-trs bundle exec rails ztlp:ns:sync
```

Then open the TRS dashboard at `/networks/:id/ztlp_devices` for a
network in Acme Dental's zone. Records should appear, because TRS's
glob `*.trs.ztlp` includes `*.acme-dental.trs.ztlp`.

### 2. Acme Dental does NOT see TRS-internal records (peer deny)

From the Acme Dental Bootstrap, force a sync:

```bash
docker exec bootstrap-acme-dental bundle exec rails ztlp:ns:sync
```

Open the Acme dashboard. You should see only Acme's own records.
TRS-internal records (`*.tech-rockstars.trs.ztlp`) should *not*
appear, because Acme's glob doesn't match.

If Acme attempts to *explicitly* request a TRS zone (an authenticated
cross-tenant probe), NS returns 200 with an empty record set, and an
audit event fires:

```bash
docker logs ztlp-ns 2>&1 | grep admin_api_zone_outside_glob
```

The event is `:admin_api_zone_outside_glob` at `:high` severity. It's
the canary that says "an authenticated tenant tried to look outside
its scope." Investigate.

---

## Verification commands

A copy-paste reference for the common checks:

### Force a sync from a Bootstrap container

```bash
docker exec bootstrap-<tenant> bundle exec rails ztlp:ns:sync
```

### Check the dashboard banner

Open `/networks/:id/ztlp_devices` in the tenant's web UI. The banner
at the top shows when the last successful sync happened and the
record count.

### Hit the sync-health endpoint

From inside the tenant's Docker network:

```bash
curl -sS http://<bootstrap-host>:3000/api/v1/sync_health | jq .
```

You'll get JSON with `last_sync_at`, `last_status`, and record counts.

### Tail NS audit events for one tenant

```bash
docker logs -f ztlp-ns 2>&1 | grep 'tenant.*TRS'
```

### Prove cross-tenant denial works (red-team smoke test)

The cleanest version is to authenticate as TRS but request Acme's
zone explicitly. From TRS Bootstrap:

```bash
docker exec bootstrap-trs bundle exec rails runner '
  client = Ztlp::NsAdminClient.new(secret: ENV["ZTLP_NS_ADMIN_API_SECRET"])
  pp client.list_records(zone: "*.acme-dental.trs.ztlp", type: "key")
'
```

TRS *will* get records back (TRS is operator-tenant; the glob
includes Acme's zone). Now repeat from Acme Dental Bootstrap,
requesting TRS-internal:

```bash
docker exec bootstrap-acme-dental bundle exec rails runner '
  client = Ztlp::NsAdminClient.new(secret: ENV["ZTLP_NS_ADMIN_API_SECRET"])
  pp client.list_records(zone: "*.tech-rockstars.trs.ztlp", type: "key")
'
```

Acme gets `200 OK` with an empty list. NS audit log shows
`:admin_api_zone_outside_glob` severity `:high`. The peer-deny rule
is working.

---

## The two-lock model in detail

### Lock 1 — Network (CIDR allow-list)

When a connection lands on `/admin/records`, NS reads the TCP peer IP
from the socket — *not* from a header. (We don't trust
`X-Forwarded-For`; it's spoofable.) The peer IP is then checked
against the union of every registered tenant's CIDR list:

- Peer IP outside every tenant CIDR → immediate `403`. Audit event:
  `:admin_api_ip_rejected` at `:medium` severity.
- Peer IP inside a CIDR → proceed to the next check.

The CIDR check happens **before** rate-limiting and **before** HMAC
verify. That's deliberate: it's the cheapest check and the strongest
signal of a misdeployed (or hostile) client.

> **Note on Docker bridge networks:** When Bootstrap and NS are on the
> same Docker host but different compose projects, NS sees the
> Bootstrap container's *bridge IP* (e.g. `172.18.0.5`), not its
> hostname. Set the CIDR to cover the bridge subnet. When NS and
> Bootstrap share a network (single compose project), the peer IP is
> the same bridge subnet — same rule applies.

### Lock 2 — Crypto + scope (per-tenant HMAC + zone glob)

After the CIDR check, NS reads the HMAC signature from the request
header and tries each registered tenant's secret in turn. The
**first** tenant whose secret produces a matching HMAC is the
identified tenant for this request. Order of attempts is not
specified; correctness relies on every tenant having a unique
secret (which `openssl rand -hex 32` guarantees with overwhelming
probability).

Once a tenant is identified:

- The response set is filtered to records whose zone matches that
  tenant's glob.
- If the request included an explicit `zone=` query parameter, the
  effective filter is the **intersection** of (a) the requested
  zone and (b) the tenant's glob.
- If the requested zone falls **entirely outside** the tenant's glob,
  the response is still `200 OK` with an empty list, and
  `:admin_api_zone_outside_glob` fires at `:high` severity.

If no tenant secret matches:

- If a global `ZTLP_NS_ADMIN_API_SECRET` is set *and* it matches, the
  request succeeds under the legacy path. `:admin_api_legacy_global_secret`
  fires at `:medium`.
- Otherwise → `401`. `:admin_api_auth_failed` fires at `:high`.

---

## Audit events reference

Every admin-API audit event carries a `severity` field. Use the
severity to drive paging policy.

- **`:admin_api_records_pulled`** — severity `:info`. Normal
  successful pull. Log only; no action required.
- **`:admin_api_legacy_global_secret`** — severity `:medium`. Request
  succeeded via the legacy global-secret fallback while tenants are
  configured. Investigate **which** client is still on the legacy
  path; migrate it to a tenant entry. Should drop to zero by end of
  Phase 2 rollout.
- **`:admin_api_ip_rejected`** — severity `:medium`. Peer IP didn't
  match any tenant CIDR; returned 403. Usually a misdeployed tenant
  (wrong CIDR in NS env); sometimes a probe from outside. Check the
  `peer_ip` field and correlate with your Docker networks.
- **`:admin_api_auth_failed`** — severity `:high`. HMAC signature did
  not verify under any tenant secret or the global. Wrong secret,
  replay attempt, or active attack. Investigate immediately.
- **`:admin_api_zone_outside_glob`** — severity `:high`. An
  authenticated tenant queried a zone outside their assigned glob.
  This is the cross-tenant probe canary. Investigate **which** tenant
  did it and why.
- **`:admin_api_authority_denied`** — severity `:critical`. Reserved
  for the Phase 3+ trust-authority hook. The stub today (Phase 2)
  never fires this event. If you see it once Phase 3 ships, **page
  on-call** — the trust-authority extension actively denied the
  request.

---

## Trust authority forward path (Phase 3+)

Phase 2 ships a stub function, `verify_authority/2`, called at a fixed
point in the request pipeline (after HMAC verify, before zone-glob
filtering). Today it always returns `:ok`, so it has no effect.

Phase 3 will replace the stub with a real implementation backed by
CA-signed authorization claims. The call site is **already wired in**
so the upgrade is a single-file swap — no surrounding code needs to
move.

Operators don't need to do anything in Phase 2. When Phase 3 ships,
the deployment guide for it will explain the new env vars and CA
configuration. For now, just know:

- `:admin_api_authority_denied` severity `:critical` is reserved for
  this event class.
- If the hook is ever bypassed by misconfiguration (e.g. CA cert not
  loaded), the safe-default is **deny** — Phase 3 will fail closed.

---

## Migration & deprecation timeline

- **Phase 1** (PR #97, merged): single global secret model, plus
  rate-limiting and audit logging. No per-tenant features.
- **Phase 2** (this PR): per-tenant secrets, CIDR allow-list, and
  zone-glob scoping land. Legacy global secret continues to work as
  a fallback for one release cycle. New deployments should configure
  tenants from day one and never set the global.
- **Phase 3** (future, no date committed): legacy global secret
  removed. Trust-authority hook activated. Operators must migrate
  every client to a per-tenant entry before this release. NS will
  refuse to start with both tenants configured *and* a global secret
  set, to prevent accidental fallback.

> **Action required for Phase 2 deployers:** Migrate TRS to a tenant
> entry (the *Rolling out to TRS production* section above). Once
> `:admin_api_legacy_global_secret` has been zero for at least one
> week across your deployment, you're ready for Phase 3 when it ships.

---

## Troubleshooting

### "All my requests return 403"

The CIDR check is rejecting the peer IP. Possible causes:

1. **Wrong CIDR in NS env.** Re-run `docker network inspect <name> |
   grep Subnet` and compare to
   `ZTLP_NS_ADMIN_API_TENANT_<SLUG>_CIDRS`.
2. **Docker recreated the bridge with a different subnet.** This
   happens when networks are removed and re-created. Re-inspect and
   update.
3. **Bootstrap is on a different network than you think.** Run
   `docker inspect <bootstrap-container> | grep -A 20 Networks` and
   check the `IPAddress` field. It must be inside your registered
   CIDR.

Confirm by checking NS logs for `:admin_api_ip_rejected` and reading
the `peer_ip` value.

### "Sync works but returns 0 records"

Authentication is fine; the zone-glob filter is removing everything.

1. **Wrong glob.** Compare
   `ZTLP_NS_ADMIN_API_TENANT_<SLUG>_ZONE_GLOB` to the zones your
   records actually live under. A common slip: glob says
   `*.acme.trs.ztlp` but records are registered under
   `acme-dental.trs.ztlp`.
2. **Records genuinely don't exist under that glob.** Inspect the
   record table directly on NS, filtered by zone.

### "Sudden flood of `:admin_api_legacy_global_secret` events"

A tenant's NS-side env didn't load — the request fell through to the
global. Causes:

1. **Variable name typo.** Slug must be uppercase. Re-check spelling.
2. **`.env` wasn't picked up.** Some compose setups cache; do a full
   `docker compose down && docker compose up -d ztlp-ns` rather than
   `restart`.
3. **Release build cached the env.** If you're running an Elixir
   release (not `mix`), the release reads env at container start.
   A full container restart is required, not just `mix release`
   reload semantics.

### "Sync silently stopped working after I updated env"

Same root cause as above — usually the new env didn't actually land
in the running NS process. Full restart:

```bash
docker compose down ztlp-ns
docker compose up -d ztlp-ns
docker logs ztlp-ns 2>&1 | head -50
```

Look for the tenant-registry load line in the boot log.

### "401 with reason `:bad_signature`"

The HMAC didn't verify under any tenant's secret or the global.

1. **Wrong secret.** Bootstrap and NS must share the *exact* hex
   string for the tenant. Re-copy from your vault; watch for
   trailing whitespace.
2. **Clock skew.** HMAC requests include a timestamp; NS rejects
   anything outside ±300 s of its own clock. Check both hosts:
   `date -u` should agree to within a few seconds. NTP, please.
3. **Replay.** If you're seeing 401s on a request you know
   succeeded once before, you may be replaying a captured request
   beyond its window. Generate a fresh one.

### "TRS sees records I didn't expect"

That's by design. TRS is the operator-tenant; its glob `*.trs.ztlp`
deliberately overlaps with every customer's deeper glob. If this is
*not* what you want, you've configured the wrong tenant hierarchy
for your deployment — see *The TRS operator-tenant pattern (Option
B)* above and consider giving TRS a sibling glob instead of an
ancestor one.

---

## FAQ

### Can a tenant rotate their secret without downtime?

Yes. The procedure:

1. Generate a new secret with `openssl rand -hex 32`.
2. **Temporarily** add it as a second tenant entry on NS — same slug
   isn't allowed, so use a transitional slug like `TRS_NEW`. Restart
   NS. Both old and new now verify.
3. Update the tenant's Bootstrap `.env` to the new secret and
   restart Bootstrap.
4. Confirm next successful sync uses the new secret (NS audit log
   shows `tenant: "TRS_NEW"`).
5. Remove the old `TRS` env vars, rename `TRS_NEW` env vars to
   `TRS`, and restart NS. Done.

A brief overlap where both secrets are accepted is intentional and
safe — NS tries each tenant secret in turn.

### Can a tenant have multiple CIDRs?

Yes, comma-separated:
`ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS=172.18.0.0/16,10.42.0.0/16`.
Useful when Bootstrap runs on a primary network and a backup
network, or when you have multiple Docker hosts behind one NS.

### What if NS restarts mid-sync?

Bootstrap retries with exponential backoff (the retry logic shipped
in PR #97). A typical NS restart takes 5–10 s; Bootstrap usually
catches the next attempt and proceeds normally. The dashboard's
`last_sync_at` may show a slightly delayed timestamp but no records
are lost.

### How do I revoke a tenant?

Remove the three `ZTLP_NS_ADMIN_API_TENANT_<SLUG>_*` env vars from
NS's `.env` and restart NS. That tenant's requests immediately start
failing — `403` if their CIDR is no longer registered, `401` if
their secret is no longer recognized. The tenant's existing records
remain in NS's database (revoking access ≠ deleting data); manage
data lifecycle separately.

### Why does `verify_authority/2` do nothing right now?

It's a Phase 3+ stub. The call site is wired in so the upgrade is
trivial when Phase 3 ships. Today it returns `:ok` unconditionally.
See *Trust authority forward path* above.

---

## Related documentation

- `docs/ACL-ARCHITECTURE.md` — overall ACL model, including how
  tenant-level ACLs compose with per-device ACLs.
- `docs/Z2LS-E2E-RUNBOOK.md` — end-to-end runbook; the SVC-record
  naming convention used in zone globs is documented there.
- `docs/plans/2026-06-07-ns-sync-phase2-tenant-isolation.md` —
  the implementation plan behind this guide.
- `docs/plans/2026-06-07-ns-bootstrap-sync-production-readiness.md`
  — broader production-readiness plan (items #5 and #6 are this
  release; remaining items in queue).
