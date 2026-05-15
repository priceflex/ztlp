# ZTLP Launch / Bootstrap production-readiness handoff

Date: 2026-05-15
Repo: `/home/trs/projects/ztlp`

Primary workspace:

```text
/home/trs/projects/ztlp/ztlp.net
```

Bootstrap Rails app:

```text
/home/trs/projects/ztlp/bootstrap
```

Important skill to load first:

```text
ztlp-net-bootstrap-control-plane
```

## User goal

Get the full ZTLP Launch registration/bootstrap flow production-ready:

```text
public ztlp.net onboarding
  -> claim
  -> real ztlp://enroll token
  -> Windows endpoint enrollment
  -> bootstrap.<zone> service registration
  -> ZTLP-native access to private Bootstrap Rails admin
```

Do this without exposing Bootstrap Rails publicly.

## Security boundary

- `ztlp.net` is public-safe Launch/onboarding only.
- Do NOT expose Bootstrap Rails admin directly on the public internet.
- Do NOT use ngrok/public reverse proxy to Bootstrap Rails `/login`.
- Public `ztlp.net` may show onboarding, status, downloads, enrollment commands, and `bootstrap.<zone>` connection instructions.
- Private Bootstrap Rails admin must be reachable through ZTLP-native connectivity only.

## Current branch

```text
feat/ztlp-net-ngrok-local-bootstrap
```

## Current docs updated

```text
/home/trs/projects/ztlp/ztlp.net/docs/launch-plan.md
```

## What was confirmed in the last session

### 1. Public Launch preview works

Confirmed:

```text
https://www.ztlp.net/ -> 200
https://www.ztlp.net/start -> 200
https://www.ztlp.net/downloads -> 200
https://www.ztlp.net/downloads/manifest.json -> 200
https://www.ztlp.net/health -> 200, body ok
https://www.ztlp.net/login -> 404
https://www.ztlp.net/admin -> 404
https://www.ztlp.net/dashboard -> 404
```

### 2. Local Launch tests pass

From `/home/trs/projects/ztlp/ztlp.net`:

```bash
python3 -m py_compile launch_app/app.py tests/test_launch_app.py
python3 -m unittest discover -s tests -v
```

Result:

```text
13 tests passing
```

### 3. `bin/launch` scaffold works

Confirmed:

- `create/status/destroy` works.
- Generated Bootstrap scaffold binds only `127.0.0.1:<port>:3000`.
- No `0.0.0.0` exposure.

### 4. Built current Linux `ztlp` CLI

Build command:

```bash
cd /home/trs/projects/ztlp/proto
cargo build --release --bin ztlp
```

Binary:

```text
/home/trs/projects/ztlp/proto/target/release/ztlp
```

Version:

```text
ztlp 0.24.0
```

### 5. NS server was built and tested

Image built:

```text
ztlp-ns:latest
```

Test container:

```text
ztlp-ns
```

Exposed:

```text
UDP 23096
TCP 9103 metrics
```

Test env used:

```text
ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false
ZTLP_NS_STORAGE_MODE=ram_copies
ZTLP_ENROLLMENT_SECRET=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

### 6. Real `ztlp://enroll` token worked

Generated token for:

```text
zone = trs-remote-test.ztlp
ns = 10.69.95.14:23096
```

Token format:

```text
ztlp://enroll/<base64url>
```

This fixed the earlier failure where a Launch claim URL was incorrectly used as a setup token.

### 7. Local Linux enrollment worked

Enrolled:

```text
LOCALTEST.trs-remote-test.ztlp
```

NS accepted enrollment. Config was written locally.

### 8. Windows test computer enrollment worked

Windows test host:

```text
10.170.3.111
```

SSH user:

```text
trs
```

Hostname:

```text
DESKTOP-LRC8DKH
```

OS:

```text
Windows 10 Pro 10.0.19045
```

Existing `ztlp.exe`:

```text
C:\TRS_Tools\ZTLPLaunchTest\ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc\ztlp.exe
```

Working enrollment command pattern:

```powershell
ztlp.exe setup --token "<ztlp://enroll/...>" --name DESKTOP-LRC8DKH -y
```

Result:

```text
Enrolled as DESKTOP-LRC8DKH.trs-remote-test.ztlp
Identity written: C:\Users\TRS\.ztlp\identity.json
Config written:   C:\Users\TRS\.ztlp\config.toml
```

### 9. Bootstrap Rails container started privately

Container:

```text
ztlp-bootstrap-test
```

Image:

```text
priceflex/ztlp-bootstrap:latest
```

Binding:

```text
127.0.0.1:39123 -> container port 3000
```

Verified:

```bash
curl -H 'X-Forwarded-Proto: https' http://127.0.0.1:39123/up
```

It returned Bootstrap `/up`.

### 10. Bootstrap service registration worked

Service identity:

```text
/tmp/ztlp-e2e/server-identity.json
```

Registered service:

```text
bootstrap.trs-remote-test.ztlp
```

SVC:

```text
10.69.95.14:23095
```

Raw UDP checks confirmed records exist:

```text
bootstrap.trs-remote-test.ztlp KEY
bootstrap.trs-remote-test.ztlp SVC
```

### 11. ZTLP listener/gateway path worked

Listener command pattern:

```bash
/tmp/ztlp-e2e/ztlp listen \
  --bind 0.0.0.0:23095 \
  --key /tmp/ztlp-e2e/server-identity.json \
  --forward http:127.0.0.1:<backend-port> \
  --gateway -vv
```

### 12. Windows ZTLP connect worked

Rails-target attempt:

```powershell
ztlp.exe connect bootstrap.trs-remote-test.ztlp --ns-server 10.69.95.14:23096 --service http -L 18080:127.0.0.1:3000 -vv
```

Confirmed:

- `bootstrap.trs-remote-test.ztlp` resolved via NS.
- SVC resolved to `10.69.95.14:23095`.
- KEY record found.
- Handshake completed.
- Tunnel active.
- Local listener opened on `127.0.0.1:18080`.

### 13. Simple HTTP backend over ZTLP fully worked

Hermes backend:

```bash
python3 -m http.server 39124 --bind 127.0.0.1
```

Listener:

```bash
/tmp/ztlp-e2e/ztlp listen \
  --bind 0.0.0.0:23095 \
  --key /tmp/ztlp-e2e/server-identity.json \
  --forward http:127.0.0.1:39124 \
  --gateway -vv
```

Windows connect:

```powershell
ztlp.exe connect bootstrap.trs-remote-test.ztlp --ns-server 10.69.95.14:23096 --service http -L 18081:127.0.0.1:80 -vv
```

Windows curl:

```powershell
curl.exe http://127.0.0.1:18081/
```

Result:

```text
HTTP/1.0 200 OK
Directory listing returned through the ZTLP tunnel.
```

## Main conclusion from last session

- Windows registration works.
- NS enrollment works.
- `bootstrap.<zone>` SVC registration works.
- ZTLP tunnel from Windows to private backend works.
- The remaining problem is Rails Bootstrap specifically over the tunnel; simple HTTP works, Rails `/up` returned empty reply.

## Known issues / production blockers

### 1. Rails Bootstrap over ZTLP tunnel returned empty reply

Rails-target tunnel became active and reached backend, but:

```powershell
curl.exe http://127.0.0.1:18080/up
```

returned:

```text
curl: (52) Empty reply from server
```

The same ZTLP path worked with Python `SimpleHTTPServer`, so this is likely Rails/Puma/headers/SSL redirect/connection behavior, not basic ZTLP transport.

Next debugging steps:

- Start Bootstrap with `FORCE_SSL=false` explicitly.
- Test `/up` and `/login` through the tunnel with `curl.exe -v`.
- Add `X-Forwarded-Proto: https` when testing.
- Try an internal local reverse proxy in front of Rails that normalizes headers and speaks simple HTTP to ZTLP.
- Check Rails logs while testing through tunnel.
- Confirm Puma is not closing because Host/SSL/proxy headers are unexpected.

### 2. Windows `config.toml` writer bug

`ztlp setup` writes invalid TOML on Windows:

```toml
identity = "C:\Users\TRS\.ztlp\identity.json"
```

Rust TOML parser fails because backslashes are not escaped:

```text
invalid unicode 8-digit hex code
```

Fix needed:

In the ztlp CLI config writer, on all platforms emit path strings via TOML-safe escaping, or use single-quoted TOML literal strings for Windows paths:

```toml
identity = 'C:\Users\TRS\.ztlp\identity.json'
```

or escaped:

```toml
identity = "C:\\Users\\TRS\\.ztlp\\identity.json"
```

Impact:

`ztlp connect` currently falls back to an ephemeral identity on Windows because it cannot parse `config.toml`. Tunnel still worked when `--ns-server` was supplied, but production needs valid config.

### 3. `ztlp ns lookup` parser bug

`ztlp ns lookup` can panic/misparse records when NS responses include the truncation flag:

```text
<<0x02, 0x01, record...>>
```

Padding the UDP query avoids truncation for manual raw checks, but the CLI lookup parser should properly handle this before relying on it in UX/tests.

Symptom:

```text
thread 'main' panicked at src/bin/ztlp-cli.rs:4613:31:
range start index ... out of range for slice ...
```

Likely area:

```text
/home/trs/projects/ztlp/proto/src/bin/ztlp-cli.rs
cmd_ns_lookup / print_ns_record parsing
```

### 4. Launch app still needs real automation

Currently manual:

- Generate enrollment token.
- Start NS.
- Start Bootstrap container.
- Register bootstrap SVC.
- Start ztlp listener.
- Run Windows setup/connect.

Need to wire into:

```text
/home/trs/projects/ztlp/ztlp.net/launch_app/app.py
/home/trs/projects/ztlp/ztlp.net/bin/launch
/home/trs/projects/ztlp/ztlp.net/tests/test_launch_app.py
```

## Production tasks for next session

### A. Fix CLI Windows config TOML bug

File:

```text
/home/trs/projects/ztlp/proto/src/bin/ztlp-cli.rs
```

Find `write_config_file`.

Add tests if available; otherwise add a targeted unit/helper test.

Verify on Windows by running setup again and then connect without config parse warning.

### B. Fix `ztlp ns lookup` parser panic

File:

```text
/home/trs/projects/ztlp/proto/src/bin/ztlp-cli.rs
```

Ensure it handles normal and truncated-flag responses:

```text
<<0x02, record...>>
<<0x02, 0x01, record...>>
```

Important: type byte is part of record. Do not drop it by accident.

Verify:

```bash
ztlp ns lookup bootstrap.trs-remote-test.ztlp --ns-server 10.69.95.14:23096
ztlp ns lookup bootstrap.trs-remote-test.ztlp --ns-server 10.69.95.14:23096 -t 2
```

### C. Make Rails Bootstrap work through ZTLP tunnel

Current known-good private Bootstrap:

```text
ztlp-bootstrap-test on 127.0.0.1:39123
```

Test local first:

```bash
curl -H 'X-Forwarded-Proto: https' http://127.0.0.1:39123/up
curl -H 'X-Forwarded-Proto: https' http://127.0.0.1:39123/login
```

Then ZTLP listener:

```bash
ztlp listen --bind 0.0.0.0:23095 \
  --key /tmp/ztlp-e2e/server-identity.json \
  --forward http:127.0.0.1:39123 \
  --gateway -vv
```

Windows:

```powershell
ztlp.exe connect bootstrap.trs-remote-test.ztlp --ns-server 10.69.95.14:23096 --service http -L 18080:127.0.0.1:3000 -vv
```

Test:

```powershell
curl.exe -v -H "X-Forwarded-Proto: https" http://127.0.0.1:18080/up
curl.exe -v -H "X-Forwarded-Proto: https" http://127.0.0.1:18080/login
```

If Rails still gives empty reply, insert a small local proxy on Hermes:

```text
127.0.0.1:39125 -> 127.0.0.1:39123
```

The proxy should normalize:

```text
Host: bootstrap.trs-remote-test.ztlp
X-Forwarded-Proto: https
X-Forwarded-Host: bootstrap.trs-remote-test.ztlp
```

Then listener forwards:

```text
http:127.0.0.1:39125
```

### D. Wire Launch app to generate and display real enrollment tokens

File:

```text
/home/trs/projects/ztlp/ztlp.net/launch_app/app.py
```

Add fields/persistence:

```text
enrollment_token_uri
enrollment_expires_at
enrollment_status
bootstrap_service_name
ns_server
```

For preview/dev:

- Generate query-param or base64 token that current CLI accepts.
- Prefer base64 `ztlp://enroll/<payload>` if possible.
- Include explicit NS: `10.69.95.14:23096`.
- Show command:

```bash
ztlp setup --token '<ztlp://enroll/...>' --name '<HOSTNAME>' -y
```

Keep web claim token separate from CLI enrollment token.

### E. Wire Launch app to provision Bootstrap and service listener

Need app-callable service around:

- `ztlp.net/bin/launch create`
- Docker container start for Bootstrap
- `ztlp keygen` for bootstrap service identity
- `ztlp ns register bootstrap.<zone>` with SVC
- `ztlp listen --forward http:<private-bootstrap-port>`

Public claim/status page should only show:

```text
bootstrap.<zone>
ztlp connect bootstrap.<zone> ...
local-forward instructions
```

It must not show:

- public admin URL
- localhost private port
- `/login` URL on public internet

### F. Add tests

Existing tests:

```text
/home/trs/projects/ztlp/ztlp.net/tests/test_launch_app.py
```

Add coverage for:

- Claim page shows `ztlp://enroll` token.
- Claim token != enrollment token.
- NS address is explicit and not `127.0.0.1`.
- No private admin URL leaks.
- `/claim/launch` creates BootstrapInstance/provisioning metadata.
- `/downloads` mentions Windows VC++ runtime until fixed.

### G. Update docs

Update:

```text
/home/trs/projects/ztlp/ztlp.net/docs/launch-plan.md
```

Include production checklist:

- Windows config TOML bug fixed.
- NS lookup parser bug fixed.
- Rails Bootstrap over ZTLP tunnel verified from DESKTOP-LRC8DKH.
- Launch generates token.
- Launch provisions Bootstrap.
- Launch registers `bootstrap.<zone>`.
- Public site still 404s `/login`, `/admin`, `/dashboard`.

## Useful commands

### SSH to Windows

```bash
ssh -o BatchMode=yes -o ConnectTimeout=8 trs@10.170.3.111 'hostname; whoami'
```

### Run Windows ztlp

```bash
ssh trs@10.170.3.111 'cmd /c C:\TRS_Tools\ZTLPLaunchTest\ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc\ztlp.exe setup --help'
```

### Windows enrollment

```bash
ssh trs@10.170.3.111 "cmd /c C:\TRS_Tools\ZTLPLaunchTest\ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc\ztlp.exe setup --token \"<TOKEN>\" --name DESKTOP-LRC8DKH -y"
```

### Windows tunnel

```bash
ssh trs@10.170.3.111 "cmd /c C:\TRS_Tools\ZTLPLaunchTest\ztlp-v-before-nebula-collapse-x86_64-pc-windows-msvc\ztlp.exe connect bootstrap.trs-remote-test.ztlp --ns-server 10.69.95.14:23096 --service http -L 18080:127.0.0.1:3000 -vv"
```

### Windows curl through tunnel

```bash
ssh trs@10.170.3.111 'curl.exe -v http://127.0.0.1:18080/up'
```

### Local Bootstrap container

```bash
docker run -d --name ztlp-bootstrap-test --rm \
  -p 127.0.0.1:39123:3000 \
  -e RAILS_ENV=production \
  -e RAILS_LOG_TO_STDOUT=1 \
  -e RAILS_SERVE_STATIC_FILES=true \
  -e DATABASE_PATH=/data/production.sqlite3 \
  -e PIDFILE=/tmp/ztlp-rails.pid \
  -v /tmp/ztlp-bootstrap-data:/data \
  priceflex/ztlp-bootstrap:latest
```

### Local Bootstrap check

```bash
curl -H 'X-Forwarded-Proto: https' http://127.0.0.1:39123/up
```

### Register bootstrap service

```bash
/tmp/ztlp-e2e/ztlp keygen --output /tmp/ztlp-e2e/server-identity.json

/tmp/ztlp-e2e/ztlp ns register \
  --name bootstrap.trs-remote-test.ztlp \
  --zone trs-remote-test.ztlp \
  --key /tmp/ztlp-e2e/server-identity.json \
  --ns-server 10.69.95.14:23096 \
  --address 10.69.95.14:23095
```

### Start bootstrap listener

```bash
/tmp/ztlp-e2e/ztlp listen \
  --bind 0.0.0.0:23095 \
  --key /tmp/ztlp-e2e/server-identity.json \
  --forward http:127.0.0.1:39123 \
  --gateway -vv
```

### Successful simple HTTP proof

```bash
python3 -m http.server 39124 --bind 127.0.0.1

/tmp/ztlp-e2e/ztlp listen \
  --bind 0.0.0.0:23095 \
  --key /tmp/ztlp-e2e/server-identity.json \
  --forward http:127.0.0.1:39124 \
  --gateway -vv
```

Windows:

```powershell
ztlp.exe connect bootstrap.trs-remote-test.ztlp --ns-server 10.69.95.14:23096 --service http -L 18081:127.0.0.1:80 -vv
curl.exe http://127.0.0.1:18081/
```

## Final state at end of last session

- `ztlp-ns` container may still be running.
- `ztlp-bootstrap-test` may still be running.
- Transient test tunnel/listener processes were killed/cleaned where possible.
- Public Launch app/ngrok preview was working earlier on port 8080 / `www.ztlp.net`.

## Definition of production-ready for next session

1. User starts at `ztlp.net/start`.
2. User claims request.
3. Claim page gives real setup token.
4. Windows endpoint enrolls successfully.
5. Launch provisions private Bootstrap.
6. Launch registers `bootstrap.<zone>` SVC in NS.
7. Windows runs `ztlp connect bootstrap.<zone>`.
8. Browser/curl on Windows reaches Bootstrap Rails `/up` and `/login` through local forwarded port.
9. Public `ztlp.net` still does not expose Bootstrap `/login/admin/dashboard`.
10. All tests pass and `launch-plan.md` is updated with verified evidence.
