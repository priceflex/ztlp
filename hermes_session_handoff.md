# Hermes Session Handoff — ztlp.net Onboarding Hardening

**Branch:** `feature/ztlp-net-onboarding-hardening` (pushed to origin)
**PR URL:** https://github.com/priceflex/ztlp/pull/new/feature/ztlp-net-onboarding-hardening (gh CLI couldn't auto-create — token lacks PR-create scope; Steve to click that link, or use the GitHub web UI)
**Started:** 2026-05-18
**Owner:** Hermes (driven by Steve Price)
**Status:** ✅ implementation complete + pushed; awaiting PR open + CI green

---

## Goal (verbatim from Steve)

> 1. Fix the 16-bit / 16-byte limit on the name; we should go much higher,
>    maybe as high as regular domains.
> 2. Start utilizing the ztlp.net onboarding. Make sure it works
>    functionally. Create a couple of containers. Check whether a name has
>    already been taken.
> 3. Add rate limits (by email address) and maybe CAPTCHA so bots can't
>    destroy it.

---

## Scope interpretation (decided without live confirmation because no response)

The phrase "16-byte name limit" maps to two very different layers:

- **Layer A — wire protocol:** `proto/src/ffi.rs:128` enforces a 16-byte cap
  on the ZTLP *service name* because the on-wire `dst_svc_id` field in the
  packet header is literally 16 bytes. Raising this is a wire-protocol
  break (proto, relay, gateway, NS, macOS, iOS, Windows clients). NOT
  TOUCHED in this session — flagged as a follow-up epic.
- **Layer B — onboarding/zone name:** The Launch app, Bootstrap Network
  model, and NS-side records accept *zone* names (e.g. `acme.ztlp`). The
  current Launch app already accepts 253-char zones (`ZONE_RE`), but the
  bootstrap Network model has no length cap and the Launch app does not
  validate against DNS label rules (each label ≤63, total ≤253, RFC 1035).
  This session **does** raise/normalize the zone-name path end-to-end at
  Layers B and above the 16-byte wire cap.

Steve: if you actually want Layer A bumped, that's a separate epic. See
"Carry-forward" below for the proposal.

---

## Implementation plan

1. **Branch + handoff** — `feature/ztlp-net-onboarding-hardening` ✅
2. **Zone name = full DNS** — add explicit label-level validation
   (RFC 1035: each label ≤63 chars, total ≤253, alphanumeric+hyphen, no
   leading/trailing hyphen, no `..`). Make the Bootstrap Network model
   validation match. Tests-first.
3. **`/api/zone-available?zone=…`** — JSON endpoint that checks both the
   Launch sqlite *and* (best-effort) the upstream NS for `<zone>` or
   `bootstrap.<zone>`. Form `/start` uses it inline.
4. **Rate limit `/start`** — sliding-window in sqlite, keyed on
   `(admin_email_lower, client_ip)`. Default 5 / hour / email, 20 / hour /
   IP. Configurable via env.
5. **CAPTCHA** — stdlib-only proof-of-work challenge (SHA-256 leading-zero
   bits). Browser computes a nonce client-side via tiny inline JS; server
   verifies. No third-party dep, no privacy leak. Optional fallback for
   no-JS: server-issued math question.
6. **End-to-end functional test** — Python test that drives `/start →
   /claim → /claim/launch` with multiple containers and verifies the
   uniqueness check fires.
7. **CI** — add `.github/workflows/ztlp-net-tests.yml` so the suite runs
   on every PR.
8. **Commit + push** with detailed messages, PR opened, watch CI green.
9. **Update this handoff** with results.

---

## Files touched / to touch

- `ztlp.net/launch_app/app.py` — zone validation, rate limit, CAPTCHA,
  `/api/zone-available`.
- `ztlp.net/tests/test_launch_app.py` — extend with TDD-style tests for
  every new behavior.
- `ztlp.net/README.md` — document new endpoints and env vars.
- `bootstrap/app/models/network.rb` — add explicit length + RFC 1035
  format validation (matching Launch).
- `bootstrap/test/models/network_test.rb` — model tests for the new
  validation (if Rails test framework configured).
- `.github/workflows/ztlp-net-tests.yml` — new CI job.
- `hermes_session_handoff.md` — this file.

---

## Test commands

```bash
# Launch app suite (Python, stdlib only)
cd ~/ztlp/ztlp.net
python3 -m unittest discover -s tests -v

# Bootstrap (Rails) — model tests, if the harness is in place
cd ~/ztlp/bootstrap
bin/rails test test/models/network_test.rb
```

Live end-to-end smoke (will be added once Goal 3 wraps):

```bash
# 1) Start the Launch app locally
LAUNCH_BIND_HOST=127.0.0.1 LAUNCH_BIND_PORT=8080 \
LAUNCH_ENV=development \
python3 -m launch_app.app &

# 2) Create an onboarding request
curl -fsS -X POST http://127.0.0.1:8080/start \
  -d 'organization_name=Acme&admin_name=Ada&admin_email=ada@example.com&zone=really-long-corp-name-that-exceeds-sixteen-chars.ztlp'

# 3) Confirm zone uniqueness check fires for a duplicate
curl -fsS 'http://127.0.0.1:8080/api/zone-available?zone=really-long-corp-name-that-exceeds-sixteen-chars.ztlp'
```

---

## Carry-forward / follow-up

1. **Open the PR** — gh CLI was blocked by token scope. Click the
   pre-baked link at the top of this file (or run `gh pr create` with a
   token that has PR write).
2. **Layer A (16-byte wire service-name cap)** — separate epic. Touch
   list: `proto/src/{packet.rs,ffi.rs,tunnel.rs}`, `relay/lib/ztlp_relay/
   udp_listener.ex`, gateway HELLO parser, NS SVC handling, macOS/iOS/
   Windows callers. Wire bump = packet version bump + dual-stack
   negotiation. Needs Steve's explicit go-ahead.
3. **`/api/zone-available` upstream NS lookup** — the `taken_upstream`
   reason is stubbed. Wire NS lookup of `<zone>` and `bootstrap.<zone>`
   so we catch collisions across all Launch deployments, not just the
   local sqlite. Same NS the claim page already points at
   (`10.69.95.14:23096`).
4. **Hooking `bin/launch` into Launch app** — `/claim/launch` still
   only updates metadata; actually starting a docker-backed bootstrap
   container is the next milestone. The "two containers" goal from
   Steve's request currently passes at the metadata level; flipping it
   to spawn real containers is a separate, larger change.
5. **Email delivery** — claim links printed once. Production needs SMTP.
6. **Live deploy to ztlp.net VM** — once PR is merged and CI is green,
   follow `ztlp-bootstrap-deploy` SKILL pattern. Need Steve's go-ahead
   per standing rule ("tell me before restarting anything").
7. **Bootstrap Network model RFC 1035 mirror** — the Launch app enforces
   the new rules; the bootstrap Rails `Network` model still uses the
   older loose regex (`app/models/network.rb:31`). Mirror it so the
   server-side and Launch-side validations agree before turning on real
   container launch.

---

## Session summary (2026-05-18)

**7 commits on the feature branch:**

```
97ce9e6 ci(ztlp.net): add Launch app test workflow + README docs
c35afbd test(ztlp.net): end-to-end multi-zone onboarding + collision test
9725f4b ztlp.net: proof-of-work CAPTCHA on POST /start
59ae0ee ztlp.net: rate-limit POST /start by email + client IP
cf56071 ztlp.net: add GET /api/zone-available JSON endpoint
393143d ztlp.net: enforce RFC 1035 zone validation in Launch app
7a75514 docs(ztlp.net): hermes handoff for onboarding-hardening session
```

**Test count: 32/32 passing locally** (up from 13 baseline).
- 7 zone-validation tests
- 3 `/api/zone-available` tests
- 4 rate-limit tests
- 4 PoW CAPTCHA tests
- 1 end-to-end multi-zone collision test
- 13 baseline tests untouched

**Lines: +890 / -5 across 5 files** (no wire-protocol code touched).

