# ztlp.net

Public product workspace for the ZTLP onboarding and bootstrap launcher.

Working name: **ZTLP Hatchery**.

The Hatchery is the public-safe front door. It accepts onboarding/provisioning requests, launches Docker-backed ZTLP bootstrap instances, and returns ZTLP connection/download instructions. It must not expose the private bootstrap/admin Rails UI directly on the public internet.

## Security boundary

Public ztlp.net may expose:

- Marketing and product explanation.
- Public onboarding request form.
- Launcher/provisioning status pages that reveal only public-safe metadata.
- Download links for signed ZTLP CLI/desktop installers.
- Claim instructions and enrollment links/tokens.

Public ztlp.net must not expose:

- Rails bootstrap/admin login.
- Bootstrap dashboard routes.
- Direct ngrok/HTTPS tunnels to private bootstrap ports.
- Customer bootstrap container admin URLs.
- Any secret token, Rails master key, NS enrollment secret, or private service key.

Private bootstrap/admin instances are Docker containers reachable only by local Docker networking and ZTLP-native service identity. Rails login can remain as a local/emergency fallback, not the product security boundary.

## What lives here

```text
ztlp.net/
  README.md                         # this overview
  docker-compose.yml                # local Hatchery + private bootstrap instance scaffold
  .env.example                      # safe environment template
  .gitignore                        # local secrets/runtime ignores
  bin/
    hatchery                        # create/list/stop/status bootstrap instances
  docs/
    onboarding-source-inventory.md  # what existing code/docs already support
    hatchery-plan.md                # implementation plan for the public launcher
  data/
    instances/.keep                 # local runtime registry; ignored except .keep
```

## Current scaffold

The initial scaffold is intentionally boring and Docker-only:

- One `hatchery` service for the public launcher placeholder.
- Zero public bootstrap/admin port publishing.
- Per-instance Docker Compose files generated under `ztlp.net/data/instances/<slug>/`.
- Bootstrap instances bind Rails to `127.0.0.1:<private-port>` only for local/dev inspection until ZTLP service identity is wired.
- No ngrok service.

## Local commands

Create a private bootstrap instance scaffold:

```bash
cd /home/trs/projects/ztlp/ztlp.net
bin/hatchery create acme --org "Acme Corp" --email admin@example.com --zone acme.ztlp
```

List known instances:

```bash
bin/hatchery list
```

Show an instance:

```bash
bin/hatchery status acme
```

Stop an instance:

```bash
bin/hatchery stop acme
```

## Prior onboarding work worth reusing

The older Z2LS registration flow that matches Steven's memory is here:

```text
/home/trs/z2ls/z2ls_registration_api
```

It already implements:

- Agent registration API.
- Completion token generation.
- `/complete?token=...` browser form.
- Name/email/phone capture.
- Status polling.

The ZTLP repo already implements most of the lower-level enrollment stack:

- Bootstrap Rails enrollment token UI and QR generation.
- IdP self-service enrollment controller.
- Rust `ztlp setup --token` flow.
- NS `ENROLL` / `ENROLL_OK` handler.
- Desktop/macOS onboarding shells.

See `docs/onboarding-source-inventory.md` and `docs/hatchery-plan.md` for details.
