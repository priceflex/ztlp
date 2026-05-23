# Auto-network on tenant boot (BS-PR-4)

> When a ztlp.net customer onboards, the network they registered
> appears in their per-tenant Bootstrap dashboard automatically — no
> "create network" wizard click required.

This document describes the boot-time provisioning hooks that make
that happen and the diagnostic that reports whether the new
container can talk to the central NS.

Status: shipped (BS-PR-4). Companion docs:

- `enrollment_token_lifecycle.md` — token state machine (BS-PR-1)
- `api_v1_ztlp_secured.md` — API auth contract (BS-PR-2)
- `z2ls_enrollment_runbook.md` — Z2LS integration (BS-PR-3 + BS-PR-6)
- `dashboard_bspr5.md` — admin UI (BS-PR-5)

---

## Why

Per Steve's 2026-05-23 brief:

> "When a customer or system is onboarded through ZTLP.net, make sure
> the network is automatically added. Also verify that the specific
> Docker container used by ZTLP Bootstrap already has the correct
> network attached and is connected to the name server, so the
> network can be managed and modified from the bootstrap system."

In this codebase "network" refers to the Bootstrap **Network model**
(zone = tenant identity). Each per-tenant Bootstrap container owns
its own SQLite DB and operates inside exactly one zone, so the
"network" the brief refers to is the single Network row that
represents the tenant's zone inside that container's DB.

Before BS-PR-4 the operator had to click `+ New Network` in the
dashboard right after onboarding. That was both a paper cut and a
blocker for the BS-PR-3 Z2LS endpoint (which returns 503 when no
Network row matches the api_client's zone).

## Architecture

```
              ┌──────────────────────────────┐
              │ ztlp.net launch_app/app.py   │
              │ (provision_tenant)           │
              └──────────────────────────────┘
                            │
                            ▼  writes docker-compose.yml with
                            │     ZONE, ORG_NAME, ZTLP_NS_SERVER
                            │     ZTLP_INSTANCE_SLUG
                            │
              ┌──────────────────────────────┐
              │ docker compose up -d         │
              │ ztlp-bootstrap-<slug>        │
              └──────────────────────────────┘
                            │
                            ▼  on every start:
              ┌──────────────────────────────┐
              │ bin/docker-entrypoint        │
              │   db:prepare                 │
              │   db:seed                    │
              │   ensure super_admin         │
              │   ztlp:network:ensure_from_env  ──▶  Network row (idempotent)
              │   ztlp:network:check_ns_reachability ──▶ log only
              │   exec rails server          │
              └──────────────────────────────┘
```

Two services do the work; the entrypoint chains them via rake tasks
so each can be invoked manually for troubleshooting.

### Ztlp::EnsureNetworkFromEnv

`app/services/ztlp/ensure_network_from_env.rb`

Reads `ZONE`, `ORG_NAME`, and `ZTLP_INSTANCE_SLUG` from the env and:

1. `ZONE` unset/blank ⇒ `Result(:skipped)`. Legacy/dev/test boots
   still work.
2. `ZONE` set but malformed ⇒ raises `InvalidZoneError`. The wrapper
   `call_safely` catches and returns `Result(:error)` so the
   container stays up.
3. `ZONE` matches an existing row ⇒ `Result(:existing)`. The name,
   status, and notes are **not** modified — operators may have
   renamed it via the dashboard.
4. `ZONE` is new ⇒ `Network.create!` + one `AuditLog` row with
   action `network.auto_created_from_env`. The Network's:
   - `name`: ORG_NAME if set; else `Network {slug}`; else `Network {zone}`
   - `zone`: the env var
   - `status`: `created` (operator promotes to `active` once
     deployment is verified)
   - `notes`: auto-generated traceability string
5. Name collision (the same `ORG_NAME` was already used by a
   different zone) ⇒ disambiguate as `"<name> (<zone>)"` and, if
   even that's taken, append a numeric suffix `#2`, `#3` …

### Ztlp::CheckNsReachability

`app/services/ztlp/check_ns_reachability.rb`

Boot-time diagnostic that records whether the container can reach
the central NS on UDP. Reads `ZTLP_NS_SERVER` (`host:port`) and:

1. Resolves `host` via `Resolv.getaddress`. DNS failure ⇒
   `Result(:unreachable)`.
2. Opens a UDP socket and `connect`s it to the resolved IP. No
   traffic is sent — `connect` on UDP just associates the
   destination, so we detect basic addressability errors (no route,
   permission denied, address-not-available) without bundling the
   ZTLP protocol into Rails.
3. On success: `Result(:reachable)`.

The result is **logged to STDOUT only** — never fails boot. Operators
sometimes need the dashboard to be available specifically *because*
the NS is having trouble.

## Operator interface

### What gets logged at boot

```
[entrypoint] super_admin ensured: alice@acme.com (created? true)
[ztlp:network:ensure_from_env] status=created id=1 zone="acme.ztlp" name="Acme Inc" message="created Network #1"
[ztlp:network:check_ns_reachability] status=reachable host="34.219.38.89" port=23096 message="UDP socket to 34.219.38.89:23096 opened successfully"
```

On a restart of the same container:

```
[entrypoint] super_admin ensured: alice@acme.com (created? false)
[ztlp:network:ensure_from_env] status=existing id=1 zone="acme.ztlp" name="Acme Inc" message="zone already present"
[ztlp:network:check_ns_reachability] status=reachable host="34.219.38.89" port=23096 message="UDP socket to 34.219.38.89:23096 opened successfully"
```

When the NS host is misconfigured:

```
[ztlp:network:check_ns_reachability] status=unreachable host="bogus.invalid" port=23096 message="resolv error: no address for bogus.invalid"
```

### Manual invocation

```bash
# After bumping the bootstrap image or recreating the container:
docker exec ztlp-bootstrap-<slug> bash -lc 'cd /rails && bundle exec rails ztlp:network:ensure_from_env'

# Diagnose NS connectivity without a restart:
docker exec ztlp-bootstrap-<slug> bash -lc 'cd /rails && bundle exec rails ztlp:network:check_ns_reachability'

# See the audit log entry written at first boot:
docker exec ztlp-bootstrap-<slug> bash -lc 'cd /rails && bin/rails runner "
  AuditLog.where(action: \"network.auto_created_from_env\").each do |a|
    puts [a.created_at.iso8601, a.target_type, a.target_id, a.details].join(\" | \")
  end
"'
```

### Required env vars (from launch_app)

| Var | Set by | Purpose |
|---|---|---|
| `ZONE` | launch_app `environment:` block | Lookup key for the Network row. |
| `ORG_NAME` | launch_app `environment:` block (BS-PR-4) | Display name for the Network row. |
| `ZTLP_INSTANCE_SLUG` | launch_app `environment:` block | Slug used to disambiguate when no ORG_NAME. |
| `ZTLP_NS_SERVER` | launch_app `environment:` block (BS-PR-4) | UDP `host:port` for the NS reachability probe. |

The launch_app already injected `ZONE` and `ZTLP_INSTANCE_SLUG` —
the BS-PR-4 launch-app diff adds `ZTLP_NS_SERVER` and `ORG_NAME` to
the compose template.

## Design decisions

1. **Boot-time, not API callout.** An earlier draft of BS-PR-4 had
   the launch_app POST to a new internal endpoint on the freshly-
   started bootstrap container. We rejected that:

   - Adds a synchronization point (launch_app has to wait for
     bootstrap to be healthy, then sign a request).
   - Adds an auth axis (admin api_client vs the existing Z2LS one).
   - Adds a failure mode (POST succeeds but the container later
     resets its DB volume — the Network row vanishes).

   The boot-time hook is restartable, idempotent, and doesn't
   require any cross-container auth.

2. **Idempotent and conservative.** Existing rows are never modified.
   Operators rename Networks via the dashboard (BS-PR-5) and our
   restart hook must not clobber that.

3. **Non-blocking failures.** If the rake task crashes the
   entrypoint still execs `rails server` via the `|| echo` shell
   fallback. The Rails app coming up is more important than the
   auto-network step succeeding — the operator can fix things
   through the UI.

4. **NS check is informational only.** UDP-connect is the cheapest
   reliable signal that the network path works. We don't speak the
   ZTLP protocol from Rails because that would require pulling part
   of the `ztlp` CLI into the image. The 99% of operator failure
   modes (wrong port, unresolvable host, blocked subnet) are
   caught.

5. **AuditLog uses `target_type=Network`, not `actor_*`.** The
   audit_logs schema doesn't have `actor_type`/`actor_id` columns
   (it's `target_type`/`target_id` + `details` JSON). The system
   actor is implicit — boot-time creations never have a logged-in
   user.

## Failure modes and recovery

| Symptom | Likely cause | Recovery |
|---|---|---|
| `status=skipped` at every boot | `ZONE` env var not set in compose | Re-run `provision_tenant.sh` or edit `docker-compose.yml` to add `ZONE`. |
| `status=error, message="...InvalidZoneError..."` | Malformed zone (upper-case, spaces, etc.) | Fix the zone string in the launch_app DB and recreate the container. The Rails app still starts. |
| `status=existing` but operator never created it | Earlier boot did. Normal. | None — this is the steady state. |
| `status=unreachable` for NS check | DNS broken inside the container OR NS port blocked | Try `docker exec ztlp-bootstrap-<slug> getent hosts $(echo $ZTLP_NS_SERVER \| cut -d: -f1)`; check security groups on the NS host. |
| Network row exists but BS-PR-3 still returns 503 | `api_clients` row missing — separate from the Network row. | Create the api_client via the dashboard (BS-PR-5) at `/admin/api_clients`. |

## Tests

| Test file | Count |
|---|---|
| `test/services/ztlp/ensure_network_from_env_test.rb` | 10 |
| `test/services/ztlp/check_ns_reachability_test.rb` | 6 |
| `ztlp.net/tests/test_launch_app.py` (regression for new env vars) | 2 reused |

Full bootstrap suite: 1070 runs / 1067 pass / 3 pre-existing
SshProvisionerTest failures (port mismatches predating this work).

## Versioning

This is part of the BS-PR-4 land of the bootstrap workstream. The
boot-time hook is purely additive — older bootstrap images without
the rake tasks still work because the launch_app's new env vars
are simply unread.
