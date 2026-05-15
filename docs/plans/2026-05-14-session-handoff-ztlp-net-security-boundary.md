# ZTLP.net Session Handoff — Security Boundary Correction

Date: 2026-05-14
Branch at time of handoff: `feat/ztlp-net-ngrok-local-bootstrap`
Repo: `/home/trs/projects/ztlp`

## Critical correction from Steven

The previous implementation direction was wrong.

`ztlp.net` must **not** publicly expose the ZTLP bootstrap/admin Rails UI behind ordinary HTTPS + Rails login.

That increases the risk footprint and violates the purpose of ZTLP.

## Correct architecture

`ztlp.net` is public only for:

- Marketing/product explanation.
- Public onboarding/provisioning entry point.
- Creating/provisioning Docker instances of ZTLP bootstraps.
- Potentially showing public-safe provisioning/claim/status information.

The actual bootstrap/admin control plane must be accessible only through ZTLP-native connectivity.

Access model:

```text
Public Internet
  -> ztlp.net marketing/provisioning site only
  -> creates Docker-backed bootstrap instance

Admin/operator device
  -> authenticates/connects through ZTLP identity path
  -> reaches private bootstrap service identity
  -> accesses bootstrap/admin UI over ZTLP-only path
```

## What must not happen

Do not expose bootstrap/admin UI publicly via:

- `https://www.ztlp.net/login`
- public ngrok directly to Rails bootstrap port 3000
- public Rails admin login
- public dashboard routes

Do not rely on normal Rails login as the security boundary for bootstrap/admin.

Rails login may exist as a local/dev fallback, but it is not the product security model.

## Security purpose

The whole point is to reduce exposed attack surface:

- Bootstrap/admin should have no public reachable admin port.
- Bootstrap/admin should not be discoverable by normal web scanners.
- Identity/login should be handled by ZTLP connectivity and device/user identity.
- Public ztlp.net should only create/provision bootstraps, not administer them directly.

## What happened in the prior session

I incorrectly:

- Created a Docker/ngrok path that exposed the Rails bootstrap/admin UI on `https://www.ztlp.net`.
- Treated Rails login as the protection layer.
- Seeded/reset a public admin login:
  - `admin@techrockstars.com`
  - `changeme123!`
- Verified login/dashboard over public ngrok.

Steven corrected this as explicitly wrong because it does the opposite of the ZTLP security model.

## Current running/changed artifacts to inspect next session

Directory:

```bash
/home/trs/projects/ztlp/ztlp.net
```

Files created/changed in this session include:

```text
ztlp.net/README.md
ztlp.net/docker-compose.yml
ztlp.net/bin/run-local-ngrok
ztlp.net/.env.local.example
ztlp.net/.gitignore
bootstrap/Dockerfile
bootstrap/bin/docker-entrypoint
bootstrap/bin/ztlp
bootstrap/db/migrate/20260412050824_rename_benchmark_errors_to_error_details.rb
bootstrap/README.md
docs/plans/2026-05-14-ztlp-net-production-bootstrap-plan.md
```

The prior Docker work may still be useful only as implementation plumbing, not as the final exposure model.

## Immediate first action in new session

Stop any public tunnel that exposes Rails bootstrap/admin directly:

```bash
cd /home/trs/projects/ztlp/ztlp.net
docker compose --env-file .env.local down
```

If old ad-hoc containers exist, inspect first and then remove/disable them:

```bash
docker ps -a --filter name=ztlp-net --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
docker ps -a --filter name=ztlpnet --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
```

Do not restart ngrok to bootstrap Rails port 3000.

## Required plan update

The production bootstrap plan currently treats dogfooding/bootstrap access through ZTLP as Phase 9. That is misleading.

Update the plan so the central boundary is:

- Public `ztlp.net` = marketing/provisioning/bootstrap-instance creator.
- Private bootstrap/admin = ZTLP-only from the start, except emergency/local first-run.
- Rails login is not the primary product access control.
- Public ngrok/HTTPS should not point directly at bootstrap/admin.

Relevant existing plan file:

```bash
/home/trs/projects/ztlp/docs/plans/2026-05-14-ztlp-net-production-bootstrap-plan.md
```

## Correct next implementation direction

1. Stop/remove public bootstrap-admin exposure.
2. Reframe `ztlp.net/` as public marketing/provisioning infrastructure.
3. Split public site from bootstrap admin service:
   - public service: marketing/provisioning
   - private bootstrap service: not public, reachable only via ZTLP
4. Design Docker instance creation flow:
   - public ztlp.net creates bootstrap container(s)
   - assigns bootstrap service identity
   - registers service in NS when appropriate
   - returns ZTLP connection instructions, not a public admin URL
5. Design ZTLP-only bootstrap access path:
   - bootstrap service identity
   - `bootstrap.<zone>` registration
   - ZTLP listener/gateway tunnel to private Rails port
   - operator/admin connects from enrolled trusted device
6. Remove or gate Rails login in product flow. If it remains, it is defense-in-depth/local fallback, not the main auth model.

## Current known technical findings from prior session

Useful findings/fixes discovered while trying to Dockerize:

- `bootstrap/Dockerfile` originally failed if `bootstrap/bin/ztlp` was missing.
- A safe stub `bootstrap/bin/ztlp` was added locally to unblock Docker builds, but the real design should either build/copy the Rust CLI or make CLI optional cleanly.
- Migration `20260412050824_rename_benchmark_errors_to_error_details.rb` failed on blank DB because the earlier create migration already used `error_details`; it was patched to check column existence.
- Production Rails needed assets served/precompiled (`RAILS_SERVE_STATIC_FILES=true`) when using Docker.
- Stale `tmp/pids/server.pid` broke container restarts; entrypoint was patched to remove it.
- Recursive `chown -R` in Dockerfile caused build stalls; this was removed in the final Dockerfile attempt.
- Docker Compose requires `--env-file .env.local` because ngrok token is not in the default `.env` file.

These fixes may still be valuable, but only if applied to the corrected architecture.

## Important mental model for the next session

Do not ask “how do we expose the bootstrap safely over HTTPS?”

Ask:

```text
How does public ztlp.net create a bootstrap, and how does an authenticated ZTLP device reach that bootstrap without the bootstrap admin ever becoming public?
```

## Suggested new-session prompt

Use this prompt to continue:

```text
Continue ZTLP.net work from /home/trs/projects/ztlp. First read docs/plans/2026-05-14-session-handoff-ztlp-net-security-boundary.md and docs/plans/2026-05-14-ztlp-net-production-bootstrap-plan.md. Steven corrected the architecture: ztlp.net is public marketing/provisioning only and creates Docker instances of ZTLP bootstraps; bootstrap/admin UI must be reachable only through ZTLP-native connectivity, not exposed publicly and not protected by ordinary Rails login. Stop any public ngrok-to-bootstrap exposure, update the plan to make this the central boundary, then design/implement the Docker-only split between public provisioning and private ZTLP-only bootstrap admin.
```
