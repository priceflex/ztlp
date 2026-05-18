# Hermes Session Handoff — ztlp.net Onboarding Hardening

**Branch:** `feature/ztlp-net-onboarding-hardening`
**Started:** 2026-05-18
**Owner:** Hermes (driven by Steve Price)
**Status:** in progress

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

1. **Layer A (16-byte wire service-name cap)** — separate epic. Touch
   list: `proto/src/{packet.rs,ffi.rs,tunnel.rs}`, `relay/lib/ztlp_relay/
   udp_listener.ex`, gateway HELLO parser, NS SVC handling, macOS/iOS/
   Windows callers. Wire bump = packet version bump + dual-stack
   negotiation. Needs Steve's explicit go-ahead.
2. **Hooking `bin/launch` into Launch app** — currently `/claim/launch`
   only updates metadata; it does not actually `docker compose up` a real
   bootstrap container. The "functional test" in Goal 2 will exercise the
   *metadata flow* until that wiring lands.
3. **Email delivery** — claim links still printed once; production
   deployment will need SMTP wiring before Steve can hand out URLs to
   customers.
4. **Live deploy** — once CI passes, deploy to the prod ztlp.net VM
   following `ztlp-bootstrap-deploy` SKILL pattern. Need separate sign-off
   per Steve's standing rule ("tell me before restarting anything").
