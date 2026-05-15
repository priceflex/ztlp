# ztlp.net

Public product workspace for the ZTLP onboarding and bootstrap launcher.

Working name: **ZTLP Launch**.

The Launch is the public-safe front door. It accepts onboarding/provisioning requests, launches Docker-backed ZTLP bootstrap instances, and returns ZTLP connection/download instructions. It must not expose the private bootstrap/admin Rails UI directly on the public internet.

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
  docker-compose.yml                # local Launch + private bootstrap instance scaffold
  .env.example                      # safe environment template
  .gitignore                        # local secrets/runtime ignores
  bin/
    launch                        # create/list/stop/status bootstrap instances
  docs/
    onboarding-source-inventory.md  # what existing code/docs already support
    launch-plan.md                # implementation plan for the public launcher
  data/
    instances/.keep                 # local runtime registry; ignored except .keep
```

## Minimal Launch app

The current public Launch app is a stdlib-only Python WSGI service in `launch_app/` with sqlite state under `data/launch.sqlite3` by default.
It provides:

- `GET /` landing page.
- `GET /start` onboarding request form.
- `POST /start` onboarding request creation with a one-time local/dev claim link display.
- `GET /claim?token=...` claim verification/status/download instructions.
- `POST /claim/launch` stub status transition to `launch_requested`.
- `GET /downloads` public download manifest page.
- `GET /health` health check.

Claim tokens are stored as HMAC-SHA256 digests only. The app does not publish Bootstrap admin URLs, Rails login URLs, ngrok tunnels, or dashboard routes.

## Local commands

Run the unit tests:

```bash
cd /home/trs/projects/ztlp/ztlp.net
python3 -m unittest discover -s tests -v
```

Run the app without Docker:

```bash
cd /home/trs/projects/ztlp/ztlp.net
LAUNCH_BIND_HOST=127.0.0.1 LAUNCH_BIND_PORT=8080 python3 -m launch_app.app
curl -fsS http://127.0.0.1:8080/health
```

Run the Docker preview:

```bash
cd /home/trs/projects/ztlp/ztlp.net
docker compose config
docker compose up --build
```

The Docker preview binds `${LAUNCH_PORT:-8080}:8080` and uses the `ztlp_launch_data` Docker volume for the sqlite database. Bootstrap/admin instances are still not exposed by this compose file. For any non-development deployment, set a real `LAUNCH_TOKEN_SECRET` and `LAUNCH_ENV=production`; the app rejects the checked-in development secret outside development/test.


Create a private bootstrap instance scaffold:

```bash
cd /home/trs/projects/ztlp/ztlp.net
bin/launch create acme --org "Acme Corp" --email admin@example.com --zone acme.ztlp
```

List known instances:

```bash
bin/launch list
```

Show an instance:

```bash
bin/launch status acme
```

Stop an instance:

```bash
bin/launch stop acme
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

See `docs/onboarding-source-inventory.md` and `docs/launch-plan.md` for details.
