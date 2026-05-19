# Hermes Session Handoff — ZTLP End-to-End Stack Test

> **Active session:** 2026-05-19 — feature/ztlp-end-to-end-stack-test
> **Agent:** Hermes (anthropic/claude-opus-4.7)
> **Operator:** Steve Price

---

## 1. Mission

Run a real end-to-end test of the entire ZTLP stack — public site → bootstrap →
enrollment → device-to-device communication — exactly like a human user would.

Validate the data model: **a user can have many devices; a device must be
registered before it can communicate; both device-to-device and
user-on-device communication must work over the ZTLP network.**

Bonus: clean up the bootstrap UX so next-steps are obvious.

---

## 2. Topology — Locked In

| Role | Host | Port | Notes |
|------|------|------|-------|
| **Public site (ztlp.net)** | runs on Nameserver host, behind ngrok at `www.ztlp.net` | 8080 → 443 | Python WSGI launch app |
| **Nameserver (NS)** | `35.91.88.177` *(replaced 34.219.38.89 — OOM'd on bootstrap build)* | UDP 23096 | also hosts ztlp.net + bootstrap. Fresh Ubuntu, 3.8GB RAM, 77GB disk |
| **Relay** | `34.218.240.106` | UDP 23095 | |
| **Gateway** | `54.218.127.30` | UDP 23097 | gateway = "copy private key" device |
| **Windows user box** | `10.170.3.111` | — | Steve runs commands here — private LAN, not reachable from dev box |
| **Vaultwarden test app** | TBD — co-locate on Gateway host | 80/443 | ZTLP-only access |

**SSH key** for all 3 AWS hosts: `~/ztlp/.ssh/ztlp_aws_key` (RSA, 0600, untracked).

**Users / roles:**
- `trs` — standard user, enrolled on the nameserver
- `hermes` — admin (auto-promoted by the registration flow on ztlp.net)

---

## 3. Implementation Plan

Each phase ends with a git commit on `feature/ztlp-end-to-end-stack-test` and an
update to this handoff file.

### Phase 1 — ztlp.net branded ngrok URL ✅ in progress
- Re-launch ngrok with the supplied authtoken `2w0XOBlQ...` and `--url=www.ztlp.net`
- Update `LAUNCH_PUBLIC_HOST=www.ztlp.net` in `.env`
- Restart launch container, verify `https://www.ztlp.net/health` returns `ok`
- Commit `.env.example` change locally; rsync to NS

### Phase 2 — Real human onboarding flow
- Pre-create referral code `ZTLP-HERMES-2026` (hermes admin) and `ZTLP-TRS-2026` (standard)
- Steve walks through `https://www.ztlp.net/` → /start → /claim
- Verify SQLite `onboarding_requests` row + `_provision_zone_dockers()` actually
  starts the bootstrap stack on the NS host
- Verify hermes is auto-flagged admin

### Phase 3 — Bootstrap reachable + admin login
- Find what port the provisioned bootstrap landed on (per-zone `LAUNCH_INSTANCE_BASE_PORT=39000+`)
- Stand up a second ngrok tunnel `bootstrap.ztlp.net` (or port-forward) so Steve can hit it
- Login as hermes; confirm admin nav

### Phase 4 — Re-point the relay + gateway to the new zone
- Existing `ztlp-relay` (34.218.240.106) and `ztlp-gateway` (54.218.127.30)
  are healthy but on the prior zone.
- Re-issue NS records and/or restart with new `ZTLP_ZONE` env
- Verify gateway works from key-copy alone (no extra registration steps)

### Phase 5 — Enroll hermes admin + trs user devices via ZTLP CLI
- From bootstrap admin UI, mint enrollment tokens for hermes + trs
- Use `ztlp setup --token "ztlp://enroll/?..."` on this dev box (hermes admin)
- Provide URI for trs's device(s) — Steve runs on Windows box
- Verify rows in `ztlp_devices` table linked to correct `ztlp_user_id`

### Phase 6 — Register Windows test box as trs's user-computer
- Build/copy the Windows ZTLP CLI bundle to `trs@10.170.3.111`
- Steve runs `ztlp setup --token "..."` — I supply the URI
- Confirm device appears in bootstrap, status=enrolled

### Phase 7 — Vaultwarden behind ZTLP
- `docker run -d vaultwarden/server` on Gateway host
- Register as ZTLP service via gateway forwarder (svc_id → vault.techrockstars.ztlp)
- Verify reachability:
  - `hermes` (this dev box) → `https://vault.techrockstars.ztlp` works
  - `trs` (Windows) → same URL works
- Grant access (RBAC) to both trs and hermes

### Phase 8 — Bootstrap UX cleanup
- Add prominent "Next Step" CTAs on the dashboard
- Improve nav labels (Networks/Users/Devices/Tokens/Services)
- Make "create enrollment token" reachable in 1 click
- Add inline help on every form
- Make the enrollment URI copy-pasteable + QR'able

### Phase 9 — Tests + CI
- Unit/integration tests for ztlp.net referral + provisioning flow
  (`ztlp.net/tests/test_launch_app.py`)
- New tests for bootstrap UX changes (Rails system specs if feasible)
- Push branch, open PR, watch CI, merge when green

---

## 4. Ground State (verified at session start)

| Item | Status |
|------|--------|
| Branch `feature/ztlp-end-to-end-stack-test` | ✅ already checked out, clean working tree |
| `ztlp-launch` on NS | ✅ healthy, 0.0.0.0:8080 |
| `ngrok-launch` on NS | ✅ tunneling to `kathyrn-fraternal-alayah.ngrok-free.dev` (will swap to `www.ztlp.net`) |
| `ztlp-ns` on NS | ✅ healthy (2h) |
| `ztlp-relay` on Relay host | ✅ healthy (3h) |
| `ztlp-gateway` on Gateway host | ✅ healthy (3h) |
| SSH access to all 3 AWS hosts | ✅ key works |
| SSH access to Windows box | ❌ not reachable from this dev box (private 10.170/16 LAN) — Steve drives Windows steps |

---

## 5. Decisions

1. **Run ztlp.net on the NS host (not local dev box)** — already there, already
   ngrok'd, just swap to the branded URL.
2. **Use the existing AWS test triplet for relay/gateway** — they're up,
   re-point to the new zone rather than rebuild.
3. **Vaultwarden lives on the Gateway host** — gives us a real "register a service
   behind a gateway" test instead of a fake one.
4. **No live edits to source on AWS hosts** — per Steve's standing rule, all
   code changes happen locally on `feature/ztlp-end-to-end-stack-test`,
   committed, then `rsync`d to the NS host for the launch app or `git pull`d
   for relay/gateway.
5. **Windows box is human-in-the-loop** — I print exact commands for Steve to
   paste; I don't try to drive it remotely.

---

## 6. Known Risks / Watch Items

- ngrok free static URL `www.ztlp.net` is single-tenant — only one tunnel can
  bind it at a time. The currently-running container holds the older URL —
  must `docker stop` it before launching the branded one.
- `_provision_zone_dockers()` runs in a daemon thread inside the WSGI app —
  per skill `ztlp-net-launch` pitfall #5, must capture stderr.
- Bootstrap container on the NS will compete with `ztlp-ns` for ports.
  Bootstrap runs on Rails port 3000 by default; NS is UDP 23096 — no overlap,
  but Docker bridge IPs may need attention.
- Auto-promotion of `hermes` to admin needs verification — the launch app
  doesn't currently hardcode this; bootstrap may need a seed pass.

---

## 7. Quick Commands

```bash
# SSH to the three AWS hosts
ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@34.219.38.89   # NS
ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@34.218.240.106 # Relay
ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@54.218.127.30  # Gateway

# Tail launch app logs
ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@34.219.38.89 'docker logs -f ztlp-launch'

# Inspect the SQLite DB (sqlite3 not installed on host — go through container)
ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@34.219.38.89 \
  'docker exec ztlp-launch python3 -c "import sqlite3,sys;c=sqlite3.connect(\"/app/data/launch.sqlite3\");[print(r) for r in c.execute(\"select * from onboarding_requests\")]"'

# rsync local launch app changes to the NS host
rsync -av --delete -e "ssh -i ~/ztlp/.ssh/ztlp_aws_key" \
  ~/ztlp/ztlp.net/ ubuntu@34.219.38.89:~/ztlp.net/
ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@34.219.38.89 \
  'cd ~/ztlp.net && docker compose up -d --build'
```

---

## 8. Session Log

- **08:25 UTC** — Session start. Read prior handoff, verified all 3 AWS hosts
  reachable with new key, all containers healthy, ngrok tunnel live.
- **08:30 UTC** — Plan written, todo list created, this handoff replaces prior.
- **08:32 UTC** — Phase 1 done: ngrok flipped to branded `https://www.ztlp.net/`.
  Bug found + fixed: docker-compose hardcoded LAUNCH_REFERRAL_CODES /
  LAUNCH_REQUIRE_POW, ignoring .env. Three referral codes seeded.
  Commit `47bc9fb`.
- **08:32–08:40 UTC** — Phase 2 walkthrough: drove the live https://www.ztlp.net/
  flow with a headless browser as a real human would.
  - Submitted form: Tech Rockstars / hermes@techrockstars.com /
    techrockstars.ztlp / referral ZTLP-HERMES-2026.
  - Got claim token `5z53bDA0cIlV2j1-...`; clicked claim link; saw
    `Status: claimed`.
  - **5 real bugs surfaced from server logs + DB inspection:**
    1. `bin/launch` bash wrapper uses `printf '%q'`, which busybox sh
       (the only shell in the alpine launch image) does not support.
       Also: the wrapper isn't even copied into the image by Dockerfile.
    2. `_provision_zone_dockers` has a `NameError: name 'out2' is not
       defined` on the error path — silently marked requests `claimed`
       even when nothing was provisioned.
    3. Default NS server is `10.69.95.14:23096` (old openclaw LAN IP),
       not the production AWS NS at `34.219.38.89:23096`.
    4. `absolute_url()` renders `http://` URLs behind ngrok's TLS
       termination (doesn't honour `X-Forwarded-Proto`).
    5. Launch container has no docker CLI and no docker socket mount,
       so even if the code worked it couldn't spawn sub-containers.
- **08:40–09:05 UTC** — TDD fix pass for bugs 1–5:
  - Delegated code changes to subagent (per standing rule).
  - Rewrote `_provision_zone_dockers` in pure Python (no bash wrapper).
  - Updated `absolute_url()` to honour `X-Forwarded-Proto/Host`.
  - Switched NS / listener defaults to AWS prod addresses.
  - Added docker-cli + compose plugin to launch Dockerfile.
  - Mounted `/var/run/docker.sock` + `LAUNCH_INSTANCE_HOST_ROOT` and
    added `group_add: [988]` for docker-group access.
  - Added 8 new tests (provision + absolute_url). 38/38 passing in 16s.
  - Independently re-verified by main agent.
  - Commit `063f2f5` (340 insertions / 52 deletions).
- **09:05 UTC** — Synced fixes to NS host, rebuilt + recreated `ztlp-launch`
  with docker socket access — verified container can `docker ps` against
  the host daemon. https://www.ztlp.net/health = 200 OK.
- **09:08 UTC** — Discovered Bug #6: `priceflex/ztlp-bootstrap:latest` is a
  PRIVATE Docker Hub repo → unauthorized to pull on NS host. The launch
  app's `docker compose up -d` would fail to find the image.
  - Decision: build the bootstrap image locally on the NS host from
    `~/ztlp/bootstrap/` source (Rails app).
  - rsync'd ~123MB of bootstrap source to NS host successfully.
- **09:09–09:25 UTC** — `docker build` on NS host **hung the entire host**.
  - Rails image build (Ruby + bundler + node + asset compilation) on a
    small AWS instance with `ztlp-launch` + `ngrok-launch` + `ztlp-ns`
    already running pushed memory/swap past the limit.
  - SSH connections began returning `Connection timed out during banner
    exchange` — sshd alive but host too overloaded to negotiate.
  - ngrok tunnel disconnected → `https://www.ztlp.net/` now serves
    "endpoint offline" page.
  - 30+ minutes of waiting did not recover the host.

---

## 9. CURRENT STATE — STOPPED, NEEDS OPERATOR ACTION

🛑 **NS host (34.219.38.89) is unresponsive. SSH banner times out at 22.
   ngrok endpoint is offline. Likely OOM-stalled by the Rails docker build.**

### What works
- All code fixes are committed locally on `feature/ztlp-end-to-end-stack-test`
  (commits `47bc9fb`, `063f2f5`). 38/38 tests passing.
- Relay host `34.218.240.106` (ztlp-relay) — last confirmed healthy 08:25 UTC.
- Gateway host `54.218.127.30` (ztlp-gateway) — last confirmed healthy 08:25 UTC.
- Local dev box has full bootstrap source and full ztlp.net source on this
  branch.

### What's broken
- NS host completely unresponsive (sshd / ngrok / launch all unreachable).
- Cannot continue without bringing the NS host back online.

### Action required from Steve
**Reboot the NS host via AWS console** (or `aws ec2 reboot-instances
--instance-ids i-XXXX`). Once it's back, the auto-start containers
(`ztlp-launch`, `ngrok-launch`, `ztlp-ns`) should come up on their own
because they all have `restart: unless-stopped`. Then ping me to resume.

### Next session — first 5 minutes
1. Verify NS host reachable: `ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@34.219.38.89 uptime`
2. Verify `docker ps` shows all 3 containers running and `https://www.ztlp.net/health` returns 200.
3. **Switch strategy on bootstrap image:** instead of building on the
   small NS host, build on the dev box (this machine has plenty of RAM)
   and `docker save | ssh ... docker load` the tarball:
   ```bash
   cd ~/ztlp/bootstrap && docker build -t priceflex/ztlp-bootstrap:latest .
   docker save priceflex/ztlp-bootstrap:latest | \
     ssh -i ~/ztlp/.ssh/ztlp_aws_key ubuntu@34.219.38.89 'docker load'
   ```
   This won't OOM the NS host because we just import the finished image.
4. Resume Phase 2: re-trigger the claim for `techrockstars.ztlp` (row 12
   in the launch DB) — should now succeed end-to-end and spawn a
   `ztlp-bootstrap-tech-rockstars` container on the NS host.

### Decisions deferred to operator
- Whether to stay on the small NS instance class (risks recurrence on
  any future heavy build) or resize to a larger instance.
- Whether to give the launch agent Docker Hub credentials so it can
  `docker pull` instead of relying on the locally-built image.
- Whether to move the bootstrap container off the NS host entirely
  (gateway/relay box has more headroom).

---

## 10. Pitfalls captured for the next session

1. **Don't run `docker build` of the Rails bootstrap image on the small
   NS host** — it OOMs the box. Build on dev, `docker save | docker load`.
2. **Launch container needs docker-cli + socket mount + group_add: 988**
   to drive the host daemon. Reverted from `cap_drop: ALL` because the
   non-root user must fork/exec `docker-cli`. Documented in the
   commit message of `063f2f5`.
3. **`absolute_url()` must read `X-Forwarded-Proto`** behind any TLS
   terminator (ngrok, nginx, ALB). Tests now lock this in.
4. **The `bin/launch` shell wrapper is dead code from the Python path's
   perspective.** Kept on disk for human ops use only. If someone
   re-introduces a subprocess call to it from app.py, the Python tests
   should still catch the regression because they assert the absence
   of a `bin/launch` argv in `subprocess.run` calls.
5. **ngrok's free tier serves a branded "endpoint offline" 404 page**
   when the backend is down — easy to mistake for an app bug. Always
   `ssh uptime` the underlying host first.
