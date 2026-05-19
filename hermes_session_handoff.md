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
| **Nameserver (NS)** | `34.219.38.89` | UDP 23096 | also hosts ztlp.net + bootstrap |
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
  About to begin Phase 1.

(More entries appended as work progresses.)
