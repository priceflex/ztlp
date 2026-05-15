# ZTLP Launch Session Handoff

Date: 2026-05-14
Repo: `/home/trs/projects/ztlp`
Current branch: `feat/ztlp-net-ngrok-local-bootstrap`
Pushed commit: `8661b4f ztlp.net: reset as launch launcher scaffold`
Public preview currently tested at: `https://www.ztlp.net/`

## Naming decision

Steven likes **Launch** better than Launch.

Use this naming going forward:

- Public product/app: **ZTLP Launch**
- Public domain/workspace: `ztlp.net`
- Private per-customer admin/control plane: **ZTLP Bootstrap**
- CLI/helper script: rename from `bin/launch` to something like `bin/launch` or `bin/ztlp-launch`
- Runtime generated private instance: **ZTLP Bootstrap Instance**

Recommended architecture wording:

```text
Public ztlp.net runs ZTLP Launch.
ZTLP Launch provisions private ZTLP Bootstrap instances.
Admins access Bootstrap through ZTLP-native connectivity only.
```

Do not keep using “Launch” in customer-facing UI/docs. It can remain only as historical context until renamed.

## Production readiness answer

It is **not production-ready** yet.

What is live/working now:

- A safe public static placeholder is served at `https://www.ztlp.net/`.
- It is served by local Docker nginx on port `8080`.
- ngrok reserved domain `www.ztlp.net` forwards to local port `8080`.
- The exposed page is public-safe and does **not** expose Bootstrap Rails admin.

What is not done yet:

- No real onboarding form.
- No claim-token email flow.
- No download manifest/installer links.
- No browser-driven Docker bootstrap instance launch.
- No NS registration for `bootstrap.<zone>`.
- No ZTLP-native access path to private Bootstrap instances.
- No durable production deployment beyond local Docker + ngrok.

## Current live runtime state

Local Docker on this Hermes host is running:

```text
ztlp-launch-placeholder   nginx:alpine   port 8080 -> 80
```

ngrok is running as a background Docker process forwarding:

```text
https://www.ztlp.net -> http://127.0.0.1:8080
```

Verification performed:

```bash
curl -k -sSI https://www.ztlp.net/
# HTTP/2 200

curl -k -sS https://www.ztlp.net/ | grep -o 'ZTLP Launch'
# ZTLP Launch
```

In the next session, rename the live placeholder from Launch to Launch before further public testing.

## Security boundary — do not break this

This correction came from Steven and is critical.

Public `ztlp.net` / ZTLP Launch may expose:

- Marketing/product explanation.
- Public onboarding request form.
- Claim/completion token pages.
- Download links for signed ZTLP installers/CLI.
- Public-safe provisioning status.
- ZTLP connection instructions.

Public `ztlp.net` / ZTLP Launch must **not** expose:

- Bootstrap Rails admin UI.
- `/login` to Bootstrap Rails.
- Bootstrap dashboards.
- Direct ngrok/HTTPS tunnels to private Bootstrap ports.
- Customer Bootstrap admin URLs.
- Rails login as the primary product security boundary.

Private Bootstrap admin/control plane must be reachable only through ZTLP-native service identity, except emergency/local first-run.

## Existing files created/changed in last session

Committed and pushed in `8661b4f`:

```text
docs/plans/2026-05-14-session-handoff-ztlp-net-security-boundary.md
ztlp.net/.env.example
ztlp.net/.gitignore
ztlp.net/README.md
ztlp.net/bin/launch
ztlp.net/data/instances/.keep
ztlp.net/docker-compose.yml
ztlp.net/docs/launch-plan.md
ztlp.net/docs/onboarding-source-inventory.md
ztlp.net/public/index.html
```

Deleted old public-ngrok-to-bootstrap files:

```text
ztlp.net/.env.local.example
ztlp.net/bin/run-local-ngrok
```

Ignored local file exists and should not be committed:

```text
ztlp.net/.env.local
```

It was stripped of the ngrok token/settings after the reset. Do not rely on it for secrets unless recreated intentionally.

## Important discovered source material

### Older Z2LS registration flow that matches Steven's memory

Primary project:

```text
/home/trs/z2ls/z2ls_registration_api
```

Duplicate/archive:

```text
/home/trs/z2ls-master-docpush/z2ls_registration_api
```

Key files:

```text
/home/trs/z2ls/z2ls_registration_api/README.md
/home/trs/z2ls/z2ls_registration_api/app/controllers/api/v1/clients_controller.rb
/home/trs/z2ls/z2ls_registration_api/app/controllers/completions_controller.rb
/home/trs/z2ls/z2ls_registration_api/app/views/completions/show.html.erb
/home/trs/z2ls/z2ls_registration_api/app/models/registration.rb
/home/trs/z2ls/z2ls_registration_api/app/models/ztcm_registration.rb
/home/trs/z2ls/docs/registration_api_contract.md
/home/trs/z2ls/WARP.md
```

Existing Z2LS flow:

1. Agent calls `POST /api/v1/clients/register`.
2. API returns `userAgentID` and `completeURL` / `completion_url`.
3. User opens `/complete?token=...`.
4. User enters name/email/phone.
5. App stores user info and marks registration complete.
6. User is redirected to folder/status pages.
7. Agent polls `/api/v1/clients/:id/status`.

How to adapt for ZTLP Launch:

- `completion_token` becomes `claim_token`.
- `completeURL` becomes `claim_url`.
- User profile form becomes org/admin/zone onboarding form.
- Folder review becomes ZTLP downloads + Bootstrap provisioning status.
- Agent status polling becomes Bootstrap instance provisioning status.

### Current ZTLP Bootstrap Rails enrollment pieces

```text
/home/trs/projects/ztlp/bootstrap/app/models/enrollment_token.rb
/home/trs/projects/ztlp/bootstrap/app/services/token_generator.rb
/home/trs/projects/ztlp/bootstrap/app/controllers/tokens_controller.rb
/home/trs/projects/ztlp/bootstrap/app/controllers/enrollment_controller.rb
/home/trs/projects/ztlp/bootstrap/app/controllers/idp_enrollment_controller.rb
/home/trs/projects/ztlp/bootstrap/app/controllers/api/enrollment_controller.rb
/home/trs/projects/ztlp/bootstrap/app/views/tokens/show.html.erb
/home/trs/projects/ztlp/bootstrap/app/views/enrollment/index.html.erb
/home/trs/projects/ztlp/bootstrap/app/views/idp_enrollment/new.html.erb
/home/trs/projects/ztlp/bootstrap/app/views/idp_enrollment/show.html.erb
/home/trs/projects/ztlp/bootstrap/app/views/docs/enrollment.html.erb
/home/trs/projects/ztlp/bootstrap/config/routes.rb
/home/trs/projects/ztlp/bootstrap/db/schema.rb
```

Capabilities:

- Enrollment token model.
- Token URI generation.
- QR SVG generation.
- Admin token UI.
- IdP self-service enrollment.
- Callback endpoint `/api/enrollment/confirm`.

Known caveats:

- `idp_enrollment/show` may show `ztlp setup --token <token_id>`; current CLI expects full token URI.
- `tokens/show` uses the correct full `token_uri` pattern.
- Bootstrap currently emits query-param style token URIs; production should prefer compact signed `ztlp://enroll/<base64url>` or hardened server-side validation.
- Confirmation endpoint consumes token usage but does not directly create/update `ZtlpDevice`.
- `ZtlpAdmin` command strings may be stale versus current CLI.

### Rust CLI enrollment pieces

```text
/home/trs/projects/ztlp/proto/src/enrollment.rs
/home/trs/projects/ztlp/proto/src/bin/ztlp-cli.rs
```

Capabilities:

- `ztlp setup --token ztlp://enroll/...`.
- Interactive setup wizard.
- Binary HMAC enrollment token support.
- Bootstrap query-param URI parsing support.
- Identity generation.
- ENROLL packet creation.
- Best-effort callback to Bootstrap `/api/enrollment/confirm`.

### NS enrollment pieces

```text
/home/trs/projects/ztlp/ns/lib/ztlp_ns/server.ex
/home/trs/projects/ztlp/ns/lib/ztlp_ns/enrollment.ex
/home/trs/projects/ztlp/ns/lib/ztlp_ns/metrics_server.ex
```

Capabilities:

- Message type `ENROLL` 0x07.
- Message type `ENROLL_OK` 0x08.
- Token validation.
- Device KEY and optional SVC record registration.
- Enrollment log/status exposure.

### Desktop/macOS onboarding shells

Desktop/Tauri:

```text
/home/trs/projects/ztlp/desktop/src/components/enrollment.js
/home/trs/projects/ztlp/desktop/src-tauri/src/commands.rs
/home/trs/projects/ztlp/desktop/src-tauri/src/tunnel.rs
/home/trs/projects/ztlp/.github/workflows/desktop-build.yml
/home/trs/projects/ztlp/.github/workflows/release.yml
```

macOS:

```text
/home/trs/projects/ztlp/macos/ZTLP/ZTLP/Views/OnboardingView.swift
/home/trs/projects/ztlp/macos/ZTLP/ZTLP/Views/EnrollmentView.swift
/home/trs/projects/ztlp/macos/ZTLP/ZTLP/ViewModels/EnrollmentViewModel.swift
```

Desktop caveat: Tauri enrollment backend is currently mock/TODO.

## Rename tasks for next session

First task in the next session should be to rename Launch -> Launch everywhere in the new public ztlp.net workspace.

Suggested file changes:

```text
ztlp.net/README.md
ztlp.net/docker-compose.yml
ztlp.net/public/index.html
ztlp.net/docs/launch-plan.md             -> ztlp.net/docs/launch-plan.md
ztlp.net/bin/launch                      -> ztlp.net/bin/launch
```

Potential container/service rename:

```text
ztlp-launch-placeholder -> ztlp-launch-placeholder
launch service          -> launch service
```

Update all docs from:

```text
ZTLP Launch
Launch
bin/launch
launch-plan.md
```

to:

```text
ZTLP Launch
Launch
bin/launch
launch-plan.md
```

Historical docs may mention Launch only as “old temporary name”. Prefer eliminating it entirely from customer-facing docs.

## Recommended next implementation path

### Phase 1 — Rename and keep preview live

1. Rename files and text to Launch.
2. Update Docker Compose service/container name.
3. Restart local Docker and ngrok if needed.
4. Verify `https://www.ztlp.net/` shows “ZTLP Launch”.
5. Commit and push rename.

### Phase 2 — Build actual public Launch app

Create a minimal web app under `ztlp.net/` for:

```text
GET  /                  landing
GET  /start             onboarding request form
POST /start             create request + claim token
GET  /claim?token=...   claim/status page
POST /claim/launch      create private Bootstrap instance
GET  /downloads         download manifest page
GET  /health            health check
```

Models/data needed:

```text
OnboardingRequest
  organization_name
  admin_name
  admin_email
  zone
  status: requested|email_sent|claimed|launching|ready|expired|revoked
  claim_token_digest
  claim_expires_at
  claimed_at

BootstrapInstance
  onboarding_request_id
  slug
  zone
  docker_project
  private_port
  service_name: bootstrap.<zone>
  status: planned|creating|running|ztlp_ready|failed|stopped
  metadata_json
```

### Phase 3 — Bootstrap provisioning

Use the existing helper as the starting point:

```text
ztlp.net/bin/launch  # rename to ztlp.net/bin/launch
```

Current helper supports:

```text
create
list
status
stop
destroy
```

It creates per-instance files under:

```text
ztlp.net/data/instances/<slug>/
```

Generated Docker Compose currently binds private Rails dev URL to:

```text
127.0.0.1:<private-port>:3000
```

That is dev-only. Production should use Docker internal networking plus ZTLP-native listener/gateway.

### Phase 4 — ZTLP-native private Bootstrap access

Implement:

1. Generate Bootstrap service identity.
2. Register `bootstrap.<zone>` in NS.
3. Start ZTLP listener/gateway to private Rails port 3000.
4. Show `ztlp connect bootstrap.<zone>` or app equivalent on claim page.
5. Never show public admin URL.

### Phase 5 — Downloads and enrollment

1. Add signed download manifest.
2. Publish links for CLI/desktop installers.
3. Make claim page show OS-specific download.
4. Generate/show full `ztlp://enroll/...` token/QR.
5. Fix Bootstrap IdP enrollment view to use full token URI.

## Commands/state from last session

Git status after push was clean on tracked files:

```bash
cd /home/trs/projects/ztlp
git status --short --branch
# ## feat/ztlp-net-ngrok-local-bootstrap...origin/feat/ztlp-net-ngrok-local-bootstrap
```

Pushed branch:

```text
feat/ztlp-net-ngrok-local-bootstrap
```

PR URL:

```text
https://github.com/priceflex/ztlp/pull/new/feat/ztlp-net-ngrok-local-bootstrap
```

Remote was changed from HTTPS to SSH because HTTPS push lacked credentials:

```text
git@github.com:priceflex/ztlp.git
```

## How www.ztlp.net currently works

Current live chain:

```text
Browser -> https://www.ztlp.net
  -> ngrok reserved endpoint
  -> Hermes/local Docker host port 8080
  -> nginx container
  -> /home/trs/projects/ztlp/ztlp.net/public/index.html
```

This is acceptable for a temporary public-safe preview only.

It is not the final production hosting model.

## New-session prompt

Use this prompt to continue:

```text
Continue ZTLP Launch work from /home/trs/projects/ztlp. First read docs/plans/2026-05-14-ztlp-launch-session-handoff.md and the ztlp-net-bootstrap-control-plane skill. Steven chose the name “ZTLP Launch” instead of Launch. Rename the public ztlp.net workspace from Launch to Launch, keep the public security boundary intact, verify www.ztlp.net shows ZTLP Launch, then proceed with building the real public onboarding/claim/provisioning app. Do not expose Bootstrap Rails admin publicly; Launch may only expose marketing/onboarding/download/provisioning status and must provision private Bootstrap instances reachable through ZTLP-native connectivity.
```
