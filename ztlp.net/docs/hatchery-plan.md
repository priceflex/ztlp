# ZTLP Hatchery Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build `ztlp.net` as the public ZTLP onboarding and bootstrap-instance launcher without exposing private bootstrap/admin UI to the public internet.

**Architecture:** Public `ztlp.net` hosts Hatchery: a marketing/onboarding/provisioning app that creates isolated Docker-backed bootstrap instances and returns download/enrollment/claim instructions. Private bootstrap/admin Rails instances run separately, are not publicly routed, and become reachable through ZTLP-native service identity only.

**Tech Stack:** Docker Compose, Rails Bootstrap app reuse, small launcher app/service TBD, existing ZTLP Rust CLI/enrollment, existing NS enrollment protocol, release/download workflows.

---

## Source facts to preserve

- Existing `ztlp.net` ngrok-to-bootstrap exposure was wrong and has been removed.
- Older Z2LS registration flow lives at `/home/trs/z2ls/z2ls_registration_api` and is the best model for public completion tokens.
- Existing ZTLP Bootstrap app already has EnrollmentToken, TokenGenerator, IdP enrollment, QR/token UI, and callback support.
- Existing Rust CLI already supports `ztlp setup --token`.
- Existing NS already handles `ENROLL` / `ENROLL_OK`.
- Existing desktop/macOS onboarding shells can become launcher clients later, but desktop Tauri enrollment backend is still mock/TODO.

## Target user flow

### Public onboarding request

1. User visits `https://ztlp.net/start`.
2. User enters organization name, admin name, admin email, and desired zone slug.
3. Hatchery creates a short-lived completion/claim token.
4. Hatchery emails a magic link to admin email.
5. Admin opens `/claim?token=...`.
6. Hatchery launches or claims a Docker-backed private bootstrap instance.
7. Hatchery shows:
   - ZTLP app/CLI download links.
   - Enrollment token/QR or instructions to fetch it through the private bootstrap.
   - ZTLP-native connection instructions for `bootstrap.<zone>`.
   - Provisioning status.
8. Admin completes setup from an enrolled/trusted device.

### Bootstrap instance launch

1. Hatchery creates per-instance directory under `ztlp.net/data/instances/<slug>/`.
2. Hatchery generates/records instance metadata.
3. Hatchery launches private Rails bootstrap container with no public port.
4. Hatchery generates or requests bootstrap service identity.
5. Hatchery registers `bootstrap.<zone>` in NS.
6. Hatchery starts a ZTLP listener/gateway to the private Rails port.
7. Hatchery returns ZTLP service name, not public admin URL.

## Non-goals

- Do not expose Bootstrap Rails admin as `https://www.ztlp.net/login`.
- Do not add ngrok back to Rails bootstrap/admin.
- Do not make Rails login the main security boundary.
- Do not integrate Z2LS as source of truth yet.
- Do not build billing yet.

---

## Task 1: Keep ztlp.net as public launcher scaffold

**Objective:** Ensure the directory structure reflects Hatchery and does not contain old ngrok exposure.

**Files:**
- Keep: `ztlp.net/README.md`
- Keep: `ztlp.net/docker-compose.yml`
- Keep: `ztlp.net/.env.example`
- Keep: `ztlp.net/.gitignore`
- Keep: `ztlp.net/bin/hatchery`
- Keep: `ztlp.net/public/index.html`
- Keep: `ztlp.net/docs/onboarding-source-inventory.md`
- Keep: `ztlp.net/docs/hatchery-plan.md`
- Remove/avoid: `ztlp.net/bin/run-local-ngrok`
- Remove/avoid: `ztlp.net/.env.local.example` if it describes ngrok

**Verification:**

Run:

```bash
cd /home/trs/projects/ztlp
test ! -e ztlp.net/bin/run-local-ngrok
test ! -e ztlp.net/.env.local.example
! grep -R "ngrok.*bootstrap\|BOOTSTRAP_UPSTREAM\|ZTLP_BOOTSTRAP_UPSTREAM" -n ztlp.net
```

Expected: all checks pass.

---

## Task 2: Replace shell scaffold with minimal Hatchery app

**Objective:** Add a tiny public app that can accept onboarding requests, create claim tokens, and call the Hatchery instance launcher.

**Files:**
- Create: `ztlp.net/app/` or `ztlp.net/hatchery/` once framework is selected.
- Modify: `ztlp.net/docker-compose.yml`.
- Modify: `ztlp.net/README.md`.

**Recommended implementation:**

Use a small Rails or Sinatra app if we want fastest reuse from Z2LS registration. Use Rails if we want ActiveRecord/mailer/job support immediately.

Routes:

```text
GET  /                 marketing/launcher landing
GET  /start            onboarding form
POST /start            create onboarding request + email claim link
GET  /claim?token=...  verify token, show launch/status/downloads
POST /claim/launch     create bootstrap instance
GET  /downloads        public download manifest page
GET  /health           health check
```

Models:

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

**Verification:**

- Submit a request locally.
- Claim token is stored hashed, not plaintext.
- Public claim page shows no private admin URL.

---

## Task 3: Port the Z2LS completion-token pattern

**Objective:** Reuse the proven `/complete?token=...` style flow from `/home/trs/z2ls/z2ls_registration_api` but adapt language to ZTLP.

**Reference files:**

```text
/home/trs/z2ls/z2ls_registration_api/app/models/registration.rb
/home/trs/z2ls/z2ls_registration_api/app/models/ztcm_registration.rb
/home/trs/z2ls/z2ls_registration_api/app/controllers/api/v1/clients_controller.rb
/home/trs/z2ls/z2ls_registration_api/app/controllers/completions_controller.rb
/home/trs/z2ls/z2ls_registration_api/app/views/completions/show.html.erb
```

**ZTLP adaptation:**

- `completion_token` becomes `claim_token`.
- `completeURL` becomes `claim_url`.
- Name/email/phone becomes org/admin/zone.
- Folder review becomes bootstrap provisioning/download instructions.
- Agent status polling becomes instance provisioning status.

**Verification:**

- Claim tokens expire.
- Claim token is single-use or safely resumable by same admin.
- Claim link reveals no private bootstrap/admin endpoint.

---

## Task 4: Wire Docker instance creation

**Objective:** Turn `bin/hatchery create` into app-callable provisioning logic.

**Files:**
- Modify/create Hatchery service object.
- Keep or wrap: `ztlp.net/bin/hatchery`.
- Generated runtime files under ignored `ztlp.net/data/instances/<slug>/`.

**Rules:**

- Do not publish bootstrap/admin to 0.0.0.0.
- For dev-only inspection, bind `127.0.0.1:<port>:3000`.
- In production, prefer no host port; use Docker internal networking plus ZTLP listener/gateway.
- Each instance gets stable metadata.

**Verification:**

Run:

```bash
cd /home/trs/projects/ztlp/ztlp.net
bin/hatchery create acme-test --org "Acme Test" --email admin@example.com --zone acme-test.ztlp
bin/hatchery status acme-test
grep -R "0.0.0.0" data/instances/acme-test && exit 1 || true
grep -R "127.0.0.1" data/instances/acme-test/docker-compose.yml
bin/hatchery destroy acme-test
```

Expected: instance scaffold is created, host binding is local only, destroy cleans it up.

---

## Task 5: Add ZTLP-native bootstrap access design

**Objective:** Define and then implement how a private bootstrap instance becomes reachable as `bootstrap.<zone>`.

**Reference files:**

```text
bootstrap/app/services/ns_registrar.rb
bootstrap/app/services/ztlp_tunnel.rb
proto/src/bin/ztlp-cli.rs
proto/src/enrollment.rs
ns/lib/ztlp_ns/enrollment.ex
```

**Implementation shape:**

1. Generate a bootstrap service identity.
2. Register KEY/SVC record for `bootstrap.<zone>`.
3. Start listener/gateway forwarding ZTLP service traffic to private Rails port 3000.
4. Store service identity metadata in instance runtime directory or Docker volume.
5. Hatchery claim page shows:

```text
ztlp connect bootstrap.<zone>
```

not:

```text
https://public-host/login
```

**Verification:**

- `bootstrap.<zone>` resolves via NS.
- Admin UI is not reachable through public host.
- Admin UI is reachable from enrolled trusted device via ZTLP path.

---

## Task 6: Fix enrollment token format consistency

**Objective:** Make public instructions and Bootstrap views consistently use full `ztlp://enroll/...` URIs.

**Files:**
- Modify: `bootstrap/app/views/idp_enrollment/show.html.erb`
- Review: `bootstrap/app/services/token_generator.rb`
- Review: `proto/src/enrollment.rs`
- Review: `bootstrap/app/views/docs/enrollment.html.erb`

**Specific fix:**

Where UI says:

```text
ztlp setup --token TOKEN_ID
```

change to:

```text
ztlp setup --token "FULL_TOKEN_URI"
```

**Verification:**

- `tokens/show` and `idp_enrollment/show` agree.
- CLI examples use quoted full URI.
- Docs explain whether token format is compact base64url or Bootstrap query-param URI.

---

## Task 7: Add download manifest support

**Objective:** Public ztlp.net should provide platform-specific signed download links.

**Reference files:**

```text
docs/CLI-REF.md
.github/workflows/release.yml
.github/workflows/desktop-build.yml
desktop/README.md
```

**Manifest example:**

```json
{
  "version": "0.24.0",
  "cli": {
    "windows_x86_64": { "url": ".../ztlp.exe", "sha256": "..." },
    "macos_aarch64": { "url": ".../ztlp", "sha256": "..." },
    "linux_x86_64": { "url": ".../ztlp", "sha256": "..." }
  },
  "desktop": {
    "windows_msi": { "url": "...", "sha256": "..." },
    "linux_appimage": { "url": "...", "sha256": "..." }
  }
}
```

**Verification:**

- `/downloads` shows platform-specific links.
- Checksums are displayed.
- Claim page can include recommended download for detected OS.

---

## Task 8: Clean repository docs after implementation

**Objective:** Prevent future confusion between private Bootstrap, public Hatchery, old ngrok local test, and older Z2LS registration code.

**Files:**
- Update: root docs/plans as needed.
- Update: `ztlp.net/README.md`.
- Keep: `ztlp.net/docs/onboarding-source-inventory.md`.
- Keep: `ztlp.net/docs/hatchery-plan.md`.
- Remove or archive stale handoffs after key facts are merged.

**Verification:**

Run:

```bash
git status --short
grep -R "C''TLP" -n docs ztlp.net || true

# These terms may appear only in historical/problem statements or guardrails,
# never as active setup instructions.
grep -R "ngrok.*bootstrap\|public Rails admin login\|www.ztlp.net/login" -n docs ztlp.net || true
```

Expected:

- No active references to the mistaken four-letter acronym from the prior handoff.
- No docs instruct public ngrok-to-bootstrap.
- Any remaining mention of prior public Rails login is clearly marked as wrong/historical or prohibited.

---

## Definition of done

- `ztlp.net` is a clean public launcher/provisioning workspace.
- Old public ngrok-to-bootstrap plumbing is gone.
- Hatchery can create/list/status/stop/destroy bootstrap instance scaffolds.
- Public pages never link directly to private bootstrap/admin URLs.
- Plan clearly maps older Z2LS registration flow to new ZTLP onboarding.
- Existing ZTLP enrollment pieces are identified with exact paths.
- Next implementation can proceed without rediscovering the same history.
