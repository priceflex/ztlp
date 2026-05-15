# ZTLP Launch Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Build `ztlp.net` as the public ZTLP onboarding and bootstrap-instance launcher without exposing private bootstrap/admin UI to the public internet.

**Architecture:** Public `ztlp.net` hosts Launch: a marketing/onboarding/provisioning app that creates isolated Docker-backed bootstrap instances and returns download/enrollment/claim instructions. Private bootstrap/admin Rails instances run separately, are not publicly routed, and become reachable through ZTLP-native service identity only.

**Tech Stack:** Docker Compose, Rails Bootstrap app reuse, small launcher app/service TBD, existing ZTLP Rust CLI/enrollment, existing NS enrollment protocol, release/download workflows.

---

## Source facts to preserve

- Existing `ztlp.net` ngrok-to-bootstrap exposure was wrong and has been removed.
- Older Z2LS registration flow lives at `/home/trs/z2ls/z2ls_registration_api` and is the best model for public completion tokens.
- Existing ZTLP Bootstrap app already has EnrollmentToken, TokenGenerator, IdP enrollment, QR/token UI, and callback support.
- Existing Rust CLI already supports `ztlp setup --token`.
- Existing NS already handles `ENROLL` / `ENROLL_OK`.
- Existing desktop/macOS onboarding shells can become launcher clients later, but desktop Tauri enrollment backend is still mock/TODO.


## Remote desktop validation findings — 2026-05-15

Test target:

```text
Host: 10.170.3.111
SSH user: trs
Hostname: DESKTOP-LRC8DKH
OS: Windows 10 Pro 10.0.19045
User: DESKTOP-LRC8DKH\TRS
Local admin: yes
RDP: TermService running, listening on 3389
```

What worked:

- Downloaded the Windows CLI ZIP from the current default release.
- Extracted it under:

```text
C:\TRS_Tools\ZTLPLaunchTest\ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc
```

- Confirmed release archive includes:

```text
ztlp.exe
ztlp-node.exe
ztlp-inspect.exe
ztlp-load.exe
ztlp-fuzz.exe
ztlp-bench.exe
ztlp_proto.lib
```

- After installing Microsoft Visual C++ Redistributable x64, the CLI ran:

```powershell
.\ztlp.exe --help
.\ztlp.exe setup --help
.\ztlp.exe keygen --output "$env:USERPROFILE\.ztlp\identity.json"
```

- Persistent identity was created on the test desktop:

```text
C:\Users\TRS\.ztlp\identity.json
NodeID: 3925f595d32456a5b3974ef37153edb2
```

What failed / must be fixed:

- Clean Windows 10 did not have the VC++ runtime DLLs needed by the MSVC-built `ztlp.exe`:

```text
vcruntime140.dll
vcruntime140_1.dll
msvcp140.dll
```

- Before installing VC++ redistributable, `ztlp.exe` exited with:

```text
-1073741515
```

- `https://www.ztlp.net` failed normal certificate validation on the Windows test host because the current ngrok/reserved-domain certificate chain was not trusted there:

```text
curl: (60) schannel: SEC_E_UNTRUSTED_ROOT
```

- Bypassing TLS validation with `curl.exe -k` hit a Squid/ControlOne-style proxy `403 Forbidden`, but downloading directly from GitHub release assets worked.
- The Launch claim page currently shows a claim/status URL and planned `bootstrap.<zone>` service name, but it does **not** generate a real `ztlp://enroll/...` token yet.
- Trying to use the Launch claim URL as a CLI enrollment token failed as expected:

```text
ztlp setup --token "http://www.ztlp.net/claim?token=..." --name "DESKTOP-LRC8DKH" -y
error: invalid enrollment token: missing zone parameter
```

- Trying to connect to the planned Bootstrap service failed because no Bootstrap instance/SVC record exists yet:

```text
ztlp connect bootstrap.trs-remote-test.ztlp
Resolving bootstrap.trs-remote-test.ztlp via ZTLP-NS...
  NS server: 127.0.0.1:23096
error: could not resolve 'bootstrap.trs-remote-test.ztlp': no SVC record in ZTLP-NS and DNS lookup failed
```

Operational conclusion:

- Windows download path works only after VC++ runtime is installed.
- CLI binary works after runtime install.
- Public Launch onboarding/claim/download pages work as a public-safe preview.
- Bootstrap access is not yet possible from a downloaded endpoint until Launch provisions a private Bootstrap instance, generates a real enrollment token, provides the correct NS address, registers `bootstrap.<zone>` in NS, and starts a ZTLP listener/gateway for the private Bootstrap admin.

## Target user flow

### Public onboarding request

1. User visits `https://ztlp.net/start`.
2. User enters organization name, admin name, admin email, and desired zone slug.
3. Launch creates a short-lived completion/claim token.
4. Launch emails a magic link to admin email.
5. Admin opens `/claim?token=...`.
6. Launch launches or claims a Docker-backed private bootstrap instance.
7. Launch shows:
   - ZTLP app/CLI download links.
   - Enrollment token/QR or instructions to fetch it through the private bootstrap.
   - ZTLP-native connection instructions for `bootstrap.<zone>`.
   - Provisioning status.
8. Admin completes setup from an enrolled/trusted device.

### Bootstrap instance launch

1. Launch creates per-instance directory under `ztlp.net/data/instances/<slug>/`.
2. Launch generates/records instance metadata.
3. Launch launches private Rails bootstrap container with no public port.
4. Launch generates or requests bootstrap service identity.
5. Launch registers `bootstrap.<zone>` in NS.
6. Launch starts a ZTLP listener/gateway to the private Rails port.
7. Launch returns ZTLP service name, not public admin URL.

## Non-goals

- Do not expose Bootstrap Rails admin as `https://www.ztlp.net/login`.
- Do not add ngrok back to Rails bootstrap/admin.
- Do not make Rails login the main security boundary.
- Do not integrate Z2LS as source of truth yet.
- Do not build billing yet.

---

## Task 1: Keep ztlp.net as public launcher scaffold

**Objective:** Ensure the directory structure reflects Launch and does not contain old ngrok exposure.

**Files:**
- Keep: `ztlp.net/README.md`
- Keep: `ztlp.net/docker-compose.yml`
- Keep: `ztlp.net/.env.example`
- Keep: `ztlp.net/.gitignore`
- Keep: `ztlp.net/bin/launch`
- Keep: `ztlp.net/public/index.html`
- Keep: `ztlp.net/docs/onboarding-source-inventory.md`
- Keep: `ztlp.net/docs/launch-plan.md`
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

## Task 2: Replace shell scaffold with minimal Launch app

**Objective:** Add a tiny public app that can accept onboarding requests, create claim tokens, and call the Launch instance launcher.

**Files:**
- Create: `ztlp.net/app/` or `ztlp.net/launch/` once framework is selected.
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

**Objective:** Turn `bin/launch create` into app-callable provisioning logic.

**Files:**
- Modify/create Launch service object.
- Keep or wrap: `ztlp.net/bin/launch`.
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
bin/launch create acme-test --org "Acme Test" --email admin@example.com --zone acme-test.ztlp
bin/launch status acme-test
grep -R "0.0.0.0" data/instances/acme-test && exit 1 || true
grep -R "127.0.0.1" data/instances/acme-test/docker-compose.yml
bin/launch destroy acme-test
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
5. Launch claim page shows:

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

**Status:** Partially complete. `/downloads`, `/downloads/<platform>`, and `/downloads/manifest.json` now link to real GitHub release assets. Remaining work is to make the release artifacts customer-ready: clean release tag, single-binary assets, checksums displayed inline, and Windows runtime handling.

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

## Task 7A: Make Windows CLI download run on clean Windows

**Objective:** Ensure the Windows binary works on a clean Windows 10/11 endpoint without manual troubleshooting.

**Problem from validation:** `ztlp.exe` from `ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc.zip` failed on Windows 10 with exit code `-1073741515` until Microsoft Visual C++ Redistributable x64 was installed. Missing DLLs were `vcruntime140.dll`, `vcruntime140_1.dll`, and `msvcp140.dll`.

**Options:**

1. Preferred: add a Windows GNU/static build target or otherwise produce a self-contained Windows binary.
2. Acceptable short-term: keep MSVC build but add a clear VC++ redistributable prerequisite/download link on `/downloads` and claim pages.
3. Better installer path: package CLI + VC++ runtime bootstrapper in the Windows installer.

**Files:**

- Modify: `.github/workflows/release.yml`
- Modify: `ztlp.net/launch_app/app.py`
- Modify: `ztlp.net/tests/test_launch_app.py`
- Modify: `ztlp.net/README.md`

**Verification:**

On a clean Windows endpoint:

```powershell
cd C:\TRS_Tools\ZTLPLaunchTest
curl.exe -L -o ztlp-windows.zip "https://github.com/priceflex/ztlp/releases/download/<tag>/<windows-asset>.zip"
Expand-Archive -Force ztlp-windows.zip -DestinationPath .
.\ztlp.exe --help
.\ztlp.exe setup --help
```

Expected: both commands print help without requiring manual VC++ redistributable installation, or the Launch download page explicitly instructs installing the redistributable first.

---

## Task 7B: Publish clean customer-facing release assets

**Objective:** Replace the current default release `v-before-nebula-collapse` with a clean semver release and simpler first-run download names.

**Current release facts:**

- Current default used by Launch: `v-before-nebula-collapse`.
- Release assets exist and work, but the tag name is not customer-friendly.
- Desktop installer assets still use `ZTLP_1.0.0_*` naming even when the CLI release is not 1.0.0.
- Current CLI archives include multiple binaries, which is useful but heavier than the first-run UX needs.

**Recommended assets:**

```text
ztlp-windows-x64.exe            # direct single CLI binary, if runtime-safe
ztlp-windows-x64.zip            # full CLI bundle
ztlp-linux-x64                  # direct single CLI binary
ztlp-linux-x64.tar.gz           # full CLI bundle
ztlp-macos-arm64                # direct single CLI binary
ztlp-macos-arm64.tar.gz         # full CLI bundle
ztlp-macos-x64                  # direct single CLI binary
ztlp-macos-x64.tar.gz           # full CLI bundle
SHA256SUMS.txt
```

**Files:**

- Modify: `.github/workflows/release.yml`
- Modify: `ztlp.net/launch_app/app.py`
- Modify: `ztlp.net/tests/test_launch_app.py`

**Verification:**

```bash
python3 - <<'PY'
import urllib.request, json
url='https://api.github.com/repos/priceflex/ztlp/releases/latest'
with urllib.request.urlopen(url) as r:
    rel=json.load(r)
print(rel['tag_name'])
for asset in rel['assets']:
    print(asset['name'], asset['browser_download_url'])
PY
```

Expected:

- Latest tag is semver/customer-safe, e.g. `v0.24.1`.
- Assets include direct binary and archive options for Windows/Linux/macOS.
- Launch `/downloads/manifest.json` points at the clean release.

---

## Task 7C: Add download/install instructions to Launch

**Objective:** Make `/downloads` usable by a nontechnical admin testing from a fresh endpoint.

**Required content:**

- Windows:
  - Download ZIP or EXE.
  - If still required, install Microsoft Visual C++ Redistributable x64 first.
  - Unzip and run `ztlp.exe --help`.
- Linux:
  - `curl -L ... | tar xz` or download tarball and run `./ztlp --help`.
- macOS:
  - Download Apple Silicon or Intel tarball.
  - Note Gatekeeper/quarantine handling if binaries are unsigned.
- Checksums:
  - Link to `SHA256SUMS.txt`.
  - Show a simple verification command per OS.

**Files:**

- Modify: `ztlp.net/launch_app/app.py`
- Modify: `ztlp.net/tests/test_launch_app.py`
- Modify: `ztlp.net/README.md`

**Verification:**

```bash
cd /home/trs/projects/ztlp/ztlp.net
python3 -m unittest discover -s tests -v
docker compose up --build -d launch
curl -fsS http://127.0.0.1:8080/downloads | grep -E 'Windows|Visual C\+\+|Linux|macOS|SHA256'
```

Expected: `/downloads` explains exactly how to get to `ztlp --help` on Windows/Linux/macOS.

---

## Task 7D: Fix TLS/proxy compatibility for the public Launch URL

**Objective:** Make `https://www.ztlp.net` downloadable from the Windows test host without `-k` or certificate/proxy failures.

**Problem from validation:** Windows `curl.exe` reported `SEC_E_UNTRUSTED_ROOT` against the current ngrok-backed `www.ztlp.net` preview. With `-k`, traffic hit a proxy `403 Forbidden`. Direct GitHub release download worked.

**Likely root causes to verify:**

- ngrok reserved-domain certificate chain not trusted by the Windows endpoint or intercepted by local security stack.
- ControlOne/Squid/security proxy blocking bypassed TLS or ngrok traffic.
- Public preview is still ngrok-based rather than normal production hosting with a stable certificate chain.

**Files/areas:**

- DNS/TLS/hosting for `www.ztlp.net`.
- `ztlp.net/docker-compose.yml` only if changing local preview shape.
- External reverse proxy / production hosting config once selected.

**Verification on Windows host `10.170.3.111`:**

```powershell
curl.exe -I https://www.ztlp.net/health
curl.exe -I https://www.ztlp.net/downloads/windows
```

Expected: no `-k`, no Schannel trust failure, no proxy 403, download redirect works.

---

## Task 9: Generate real enrollment token on claim page

**Objective:** After claim, show a real `ztlp setup --token 'ztlp://enroll/...' --name '<hostname>' -y` command instead of only showing the Launch claim URL and planned Bootstrap service name.

**Problem from validation:** Using the Launch claim URL as a setup token failed:

```text
error: invalid enrollment token: missing zone parameter
```

The CLI expects either a compact base64url enrollment token or a full `ztlp://enroll/...` URI. The Launch claim token is only a web claim token and must not be presented as a CLI enrollment token.

**Files:**

- Modify: `ztlp.net/launch_app/app.py`
- Modify: `ztlp.net/tests/test_launch_app.py`
- Reference: `bootstrap/app/services/token_generator.rb`
- Reference: `proto/src/enrollment.rs`
- Reference: `proto/src/bin/ztlp-cli.rs`

**Implementation shape:**

1. Add enrollment token fields to Launch persistence or a related table:

```text
enrollment_token_uri
enrollment_expires_at
enrollment_max_uses
enrollment_status
```

2. For the preview path, generate a query-param style token URI compatible with current CLI parser:

```text
ztlp://enroll/?zone=<zone>&ns=<ns-host>:23096&token=<random-token>&expires=<unix-ts>
```

3. On claim page, show:

```text
ztlp setup --token 'ztlp://enroll/?zone=<zone>&ns=<real-ns>:23096&token=<token>&expires=<ts>' --name '<HOSTNAME>' -y
```

4. Make the NS address explicit. Do not rely on CLI default `127.0.0.1:23096` for remote endpoints.
5. Keep web claim token and CLI enrollment token separate.

**Verification:**

On Windows test host:

```powershell
.\ztlp.exe setup --token '<token shown on claim page>' --name 'DESKTOP-LRC8DKH' -y
```

Expected:

- CLI does not report `missing zone parameter`.
- CLI attempts enrollment against the configured NS address.
- Any remaining failure is a real NS/network/provisioning issue, not token format.

---

## Task 10: Provision Bootstrap instance and register SVC in NS

**Objective:** Make `ztlp connect bootstrap.<zone>` resolve and reach the private Bootstrap admin path from an enrolled/trusted device.

**Problem from validation:** After claiming `trs-remote-test.ztlp`, the Launch page showed:

```text
ztlp connect bootstrap.trs-remote-test.ztlp
```

But the Windows test host failed with:

```text
error: could not resolve 'bootstrap.trs-remote-test.ztlp': no SVC record in ZTLP-NS and DNS lookup failed
```

**Files:**

- Modify/create: Launch provisioning service under `ztlp.net/launch_app/`.
- Modify/wrap: `ztlp.net/bin/launch`.
- Reference: `bootstrap/app/services/ns_registrar.rb`.
- Reference: `bootstrap/app/services/ztlp_tunnel.rb`.
- Reference: `ns/lib/ztlp_ns/enrollment.ex`.
- Reference: `proto/src/bin/ztlp-cli.rs`.

**Implementation shape:**

1. `POST /claim/launch` creates a `BootstrapInstance` record.
2. It calls or ports `bin/launch create <slug> --org ... --email ... --zone ...`.
3. It starts the private Bootstrap container with no public admin route.
4. It generates a Bootstrap service identity.
5. It registers `bootstrap.<zone>` KEY/SVC in NS.
6. It starts a ZTLP listener/gateway from `bootstrap.<zone>` to private Rails port 3000.
7. Claim page only shows:

```text
ztlp connect bootstrap.<zone>
```

and never a public/localhost admin URL.

**Verification:**

On Launch host:

```bash
cd /home/trs/projects/ztlp/ztlp.net
python3 -m unittest discover -s tests -v
docker compose up --build -d launch
```

On Windows test host:

```powershell
.\ztlp.exe setup --token '<real enrollment token>' --name 'DESKTOP-LRC8DKH' -y
.\ztlp.exe connect bootstrap.<zone> --ns-server '<real-ns>:23096'
```

Expected:

- `ztlp setup` succeeds or reaches a real NS enrollment response.
- `ztlp connect bootstrap.<zone>` resolves via NS.
- Bootstrap admin traffic reaches the private Bootstrap instance through ZTLP-native identity only.
- `https://www.ztlp.net/login` and public Bootstrap admin URLs remain unavailable.

---

## Task 8: Clean repository docs after implementation

**Objective:** Prevent future confusion between private Bootstrap, public Launch, old ngrok local test, and older Z2LS registration code.

**Files:**
- Update: root docs/plans as needed.
- Update: `ztlp.net/README.md`.
- Keep: `ztlp.net/docs/onboarding-source-inventory.md`.
- Keep: `ztlp.net/docs/launch-plan.md`.
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
- Launch can create/list/status/stop/destroy bootstrap instance scaffolds.
- Public pages never link directly to private bootstrap/admin URLs.
- Plan clearly maps older Z2LS registration flow to new ZTLP onboarding.
- Existing ZTLP enrollment pieces are identified with exact paths.
- Next implementation can proceed without rediscovering the same history.
