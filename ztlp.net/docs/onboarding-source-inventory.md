# ZTLP Onboarding Source Inventory

Date: 2026-05-14

This inventory consolidates the existing onboarding/enrollment work found before rebuilding `ztlp.net` as the public launcher/provisioning boundary.

## Executive summary

Steven's remembered flow does exist, but mostly in older Z2LS registration code, not in the current `ztlp.net` workspace.

The strongest match is:

```text
/home/trs/z2ls/z2ls_registration_api
```

That older app implements:

- Agent registration API.
- Completion token issuance.
- Browser completion link: `/complete?token=...`.
- Name/email/phone capture.
- Folder/status follow-up pages.
- Agent polling by userAgentID/deviceID/token.

The current ZTLP repo already implements most of the lower-level enrollment stack:

- Bootstrap Rails token generation and QR/URI UI.
- IdP self-service enrollment controller.
- Rust `ztlp setup --token` enrollment flow.
- NS `ENROLL` / `ENROLL_OK` protocol handler.
- Desktop/macOS onboarding shells.
- Release workflows for CLI/desktop artifacts.

What is missing is the clean public `ztlp.net` launcher that ties these together without exposing private bootstrap/admin publicly.

## Existing ztlp.net workspace before reset

Path:

```text
/home/trs/projects/ztlp/ztlp.net
```

Old contents were only ngrok-local-bootstrap plumbing:

```text
README.md
.env.local.example
.gitignore
bin/run-local-ngrok
docker-compose.yml
.env.local        # local secret, ignored
```

Problem: it pointed public `www.ztlp.net`/ngrok directly at the Rails bootstrap/admin app. That was explicitly the wrong security boundary.

Action taken in this reset:

- Stopped and removed public ngrok/bootstrap containers.
- Removed `bin/run-local-ngrok` and `.env.local.example`.
- Replaced README/Compose with Launch launcher scaffold.
- Kept local `.env.local` ignored; no secrets committed.

## Older Z2LS registration flow that matches the remembered onboarding

Primary project:

```text
/home/trs/z2ls/z2ls_registration_api
```

Duplicate/archive copy:

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

Flow:

1. Agent calls `POST /api/v1/clients/register`.
2. API returns `userAgentID` and `completeURL` / `completion_url`.
3. User opens `/complete?token=...`.
4. User enters name, email, phone.
5. App stores user info and marks registration complete.
6. User is redirected to folder/status pages.
7. Agent polls `/api/v1/clients/:id/status`.

Useful implementation details:

- `Registration#issue_completion_link!` uses `SecureRandom.urlsafe_base64(24)`.
- Completion form fields are full name, work email, phone.
- Existing domains were `reg.trs.la` and `registration.z2ls.it`.

How to reuse this for ZTLP:

- Reuse the completion-token pattern for public-safe onboarding claims.
- Replace Z2LS backup/folder context with ZTLP bootstrap instance claim context.
- Return a download link plus `ztlp://enroll/...` token/QR after completion.
- Keep private bootstrap/admin access out of the public app.

## Current ZTLP Bootstrap Rails app enrollment support

Path:

```text
/home/trs/projects/ztlp/bootstrap
```

Important files:

```text
bootstrap/app/models/enrollment_token.rb
bootstrap/app/services/token_generator.rb
bootstrap/app/controllers/tokens_controller.rb
bootstrap/app/controllers/enrollment_controller.rb
bootstrap/app/controllers/idp_enrollment_controller.rb
bootstrap/app/controllers/api/enrollment_controller.rb
bootstrap/app/views/tokens/show.html.erb
bootstrap/app/views/enrollment/index.html.erb
bootstrap/app/views/idp_enrollment/new.html.erb
bootstrap/app/views/idp_enrollment/show.html.erb
bootstrap/app/views/docs/enrollment.html.erb
bootstrap/config/routes.rb
bootstrap/db/schema.rb
```

Capabilities found:

- Admin-generated enrollment tokens.
- QR SVG generation.
- `ztlp://enroll/...` URI display.
- IdP self-service enrollment after OAuth/OIDC.
- One-hour single-use tokens for IdP enrollments.
- API callback `/api/enrollment/confirm` to consume token usage after CLI enrollment.

Caveats found:

- `idp_enrollment/show` appears to show a CLI command using `token_id` only; the CLI expects the full token URI. `tokens/show` uses the correct full `token_uri` pattern.
- `TokenGenerator` currently emits query-param token URIs like `ztlp://enroll/?zone=...&token=...`; docs also describe compact base64url `ztlp://enroll/<payload>` tokens.
- Bootstrap confirmation currently consumes token usage but does not directly create/update `ZtlpDevice`; NS log reconciliation seems intended.
- `ZtlpAdmin` command strings may be stale compared to current CLI subcommands.

## Current ZTLP Rust CLI enrollment support

Important files:

```text
/home/trs/projects/ztlp/proto/src/enrollment.rs
/home/trs/projects/ztlp/proto/src/bin/ztlp-cli.rs
```

Capabilities found:

- `ztlp setup --token ztlp://enroll/...`.
- Interactive setup wizard.
- Binary HMAC enrollment token support.
- Bootstrap query-param URI parsing support.
- Identity generation.
- ENROLL packet creation.
- Best-effort callback to Bootstrap `/api/enrollment/confirm`.

Useful facts:

- `EnrollmentToken::to_uri` emits `ztlp://enroll/<base64url>`.
- `EnrollmentToken::from_base64url` also parses Bootstrap query-param URIs.
- `ztlp setup --token ... --name HOSTNAME -y` is the unattended path.

## Current ZTLP NS enrollment support

Important files:

```text
/home/trs/projects/ztlp/ns/lib/ztlp_ns/server.ex
/home/trs/projects/ztlp/ns/lib/ztlp_ns/enrollment.ex
/home/trs/projects/ztlp/ns/lib/ztlp_ns/metrics_server.ex
```

Capabilities found:

- Message type `ENROLL` 0x07.
- Message type `ENROLL_OK` 0x08.
- Token validation.
- Device KEY and optional SVC record registration.
- Enrollment log exposure through metrics/status.
- Error codes for expired/invalid/exhausted/name conflict cases.

Caveat:

- Bootstrap query-param zero-MAC tokens are accepted only when registration auth is disabled; production should prefer authenticated compact tokens or a signed server-side validation path.

## Desktop/macOS launcher shells

Desktop/Tauri:

```text
/home/trs/projects/ztlp/desktop
/home/trs/projects/ztlp/desktop/src/components/enrollment.js
/home/trs/projects/ztlp/desktop/src-tauri/src/commands.rs
/home/trs/projects/ztlp/desktop/src-tauri/src/tunnel.rs
/home/trs/projects/ztlp/.github/workflows/desktop-build.yml
/home/trs/projects/ztlp/.github/workflows/release.yml
```

Capabilities:

- Tray app shell.
- Enrollment page with token URI paste.
- Windows/Linux build workflow for installers.

Caveat:

- The Tauri backend enrollment is still marked mock/TODO; it validates the URI prefix and stores mock state.

macOS:

```text
/home/trs/projects/ztlp/macos/ZTLP/ZTLP/Views/OnboardingView.swift
/home/trs/projects/ztlp/macos/ZTLP/ZTLP/Views/EnrollmentView.swift
/home/trs/projects/ztlp/macos/ZTLP/ZTLP/ViewModels/EnrollmentViewModel.swift
```

Capabilities:

- First-run onboarding UI.
- Paste-based `ztlp://enroll/...` flow.
- Token review and enroll button shell.

## Download/release artifacts

Important files:

```text
/home/trs/projects/ztlp/docs/CLI-REF.md
/home/trs/projects/ztlp/.github/workflows/release.yml
/home/trs/projects/ztlp/.github/workflows/desktop-build.yml
/home/trs/projects/ztlp/desktop/README.md
```

Existing release workflow builds:

- Rust CLI for Linux/macOS/Windows.
- Desktop installers for Linux and Windows.

Public launcher should consume a signed release manifest instead of hardcoding download URLs.

## New architecture implication

`ztlp.net` should become the public-safe launcher, not the private admin surface.

Recommended split:

```text
Public ztlp.net / Launch
  - signup/onboarding form
  - completion token emails
  - download links
  - launch Docker bootstrap instance
  - show claim/status/instructions
  - never exposes bootstrap admin

Private bootstrap instance
  - Rails admin/control plane
  - per-org/zone identity and policy
  - enrollment token issuance
  - reachable only over ZTLP-native service identity
```

## Working name

Use **ZTLP Launch** for now.

Reason: Steven chose Launch as the customer-facing name. It clearly describes the public action: launching private Bootstrap instances without exposing Bootstrap admin directly.
