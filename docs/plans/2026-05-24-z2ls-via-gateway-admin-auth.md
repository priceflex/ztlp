# Z2LS via Gateway Admin Auth (Plan C) — Implementation Plan

> **For Hermes:** Use `subagent-driven-development` to implement this plan task-by-task. Each task uses strict TDD (`test-driven-development`).

**Goal:** Replace the per-zone HMAC auth path on `/api/v1/*` with the same gateway-injected admin-header path the Bootstrap UI already uses. Z2LS becomes "an admin-equivalent client over a ZTLP tunnel" rather than "an HMAC-signed external system."

**Architecture:** A `ztlp connect` tunnel from a zone-bound identity terminates at the per-tenant gateway, which strips inbound `X-ZTLP-*` and re-injects `X-ZTLP-Authenticated: 1`, `X-ZTLP-Admin-Email: <identity-email>`, `X-ZTLP-Timestamp: <unix>`, `X-ZTLP-Signature: <hmac>`. Bootstrap's `Ztlp::HeaderVerifier` already verifies that injected set for the UI. We extend the API controller stack to honor the same verifier instead of the HMAC `ApiAuthenticator`. The per-zone HMAC code is **kept dormant** (env vars, generator, secret column) for a hypothetical non-tunneled future client, but not exercised by any code path.

**Tech Stack:** Rails 8 (Bootstrap), Rust (gateway header injector), pytest (deploy-drift suite), RSpec/minitest (Rails).

**Scope (v1):** Full admin scope. Any Z2LS request authenticated via gateway-injected headers gets the same authority as a UI admin user. `X-ZTLP-Client-Scope` and per-action RBAC are explicit non-goals — deferred until there is an actual scoped consumer.

**Out of scope:**
- Deleting `Ztlp::ApiAuthenticator` (kept behind a feature flag for one release for rollback safety).
- Removing per-zone HMAC env var generation in Launch (kept dormant; cheap; useful if YAGNI flips).
- Adding mTLS, request rate limiting, or scope enforcement.

---

## Pre-Flight (already done in the session that produced this plan)

- ✅ Launch container restarted with fresh `.env` so `LAUNCH_BOOTSTRAP_IMAGE` reflects disk.
- ✅ `hermes-try5` bootstrap recreated on `:v0.30.3-client-headers`.
- ✅ All 6 sandbox tenants have per-zone HMAC env vars (kept dormant).

---

## Task 1: RED — drift-detection test for live launch env

**Objective:** Make "edited `.env` didn't reach the running launch container" loud and CI-detectable.

**Files:**
- Create: `scripts/deploy/test_launch_env_freshness.py`

**Step 1: Write failing test**

```python
# scripts/deploy/test_launch_env_freshness.py
"""Regression test for the 2026-05-24 stale-launch-env bug.

When `.env` on the SaaS host is edited but the launch container isn't
recreated, newly-provisioned tenants get a stale BOOTSTRAP_IMAGE pinned
into their compose file. This test asserts the live container env
matches the on-disk .env for every LAUNCH_* key.
"""
import subprocess, pytest

SAAS_HOST = "ubuntu@35.91.88.177"
SSH_KEY = "/home/trs/ztlp/.ssh/ztlp_aws_key"

def _ssh(cmd: str) -> str:
    return subprocess.check_output(
        ["ssh", "-i", SSH_KEY, SAAS_HOST, cmd], text=True
    )

def _parse_env(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def test_launch_dotenv_matches_live_container_env():
    on_disk = _parse_env(_ssh("cat ~/ztlp.net/.env"))
    live    = _parse_env(_ssh("docker exec ztlp-launch env"))
    drift = {
        k: (on_disk[k], live.get(k))
        for k in on_disk
        if k.startswith("LAUNCH_") and live.get(k) != on_disk[k]
    }
    assert not drift, (
        f"Drift between .env and running launch process: {drift}. "
        "Run `docker compose up -d --force-recreate launch` on the SaaS host."
    )
```

**Step 2: Verify failure on the historical bug**

Run on a known-stale state — the pre-restart snapshot we captured today. Expected: FAIL with `LAUNCH_BOOTSTRAP_IMAGE` drift.

**Step 3 (GREEN already implemented in pre-flight):** Launch was restarted at 09:37 UTC. Re-run the test.
Expected: PASS.

**Step 4: Commit**

```bash
git add scripts/deploy/test_launch_env_freshness.py
git commit -m "test(deploy): regression for stale launch .env (2026-05-24)"
```

---

## Task 2: RED — tenant-image freshness test

**Objective:** Catch any tenant whose `docker-compose.yml` pins a bootstrap image older than what Launch is currently configured to provision.

**Files:**
- Create: `scripts/deploy/test_tenant_image_freshness.py`

**Step 1: Write failing test**

```python
import re, subprocess

SAAS_HOST = "ubuntu@35.91.88.177"
SSH_KEY   = "/home/trs/ztlp/.ssh/ztlp_aws_key"

def _ssh(cmd):
    return subprocess.check_output(
        ["ssh", "-i", SSH_KEY, SAAS_HOST, cmd], text=True
    )

def test_no_tenant_pins_stale_bootstrap_image():
    expected = _ssh(
        "docker exec ztlp-launch env | grep ^LAUNCH_BOOTSTRAP_IMAGE="
    ).strip().split("=", 1)[1]

    listing = _ssh("sudo ls ~/ztlp.net/data/instances/").split()
    stale = {}
    for tenant in listing:
        compose = _ssh(
            f"sudo cat ~/ztlp.net/data/instances/{tenant}/docker-compose.yml"
        )
        for line in compose.splitlines():
            m = re.search(r'priceflex/ztlp-bootstrap:[\w\.\-]+', line)
            if m and m.group(0) != expected:
                stale[tenant] = m.group(0)
                break
    assert not stale, (
        f"Tenants pinned to a bootstrap image older than launch's: {stale}. "
        f"Expected {expected}. Re-run recreate_tenants.py."
    )
```

**Step 2: Verify failure**

Before fixing try5: this test should fail with `{"hermes-try5": "...v0.30.2"}`.

**Step 3 (GREEN already implemented in pre-flight):** try5 bootstrap was recreated. Re-run. Expected: PASS for all 6 sandbox tenants.

**Step 4: Commit.**

---

## Task 3: RED — header-namespace contract test (BDD-style)

**Objective:** Lock the gateway header contract that Z2LS clients can rely on. This is the *behavioral spec* of plan C.

**Files:**
- Create: `bootstrap/test/integration/api/v1/gateway_admin_auth_test.rb`

**Step 1: Write failing test**

```ruby
require "test_helper"

# BDD-style integration test for the Z2LS-over-gateway auth contract.
#
# Behavior:
#   GIVEN a request to /api/v1/health
#    WHEN the gateway injects valid X-ZTLP-Authenticated/Admin-Email/
#         Timestamp/Signature headers
#    THEN Bootstrap returns 200 with current_admin_user resolved
#
#   GIVEN a request to /api/v1/health
#    WHEN no gateway headers are injected (or signature is bad)
#    THEN Bootstrap returns 401 with audit code gateway_auth_required
#
#   GIVEN a request with old X-ZTLP-Client-* HMAC headers
#    WHEN no admin-auth headers are present
#    THEN Bootstrap returns 401 with audit code legacy_header_namespace
#         (so old clients hitting new bootstrap get a clear signal,
#          not generic missing_header)
class GatewayAdminAuthTest < ActionDispatch::IntegrationTest
  test "valid gateway-injected admin headers authorize /api/v1/*" do
    # AdminUser fixture: admin@hermes-sandbox.ztlp
    headers = gateway_inject(
      email: "admin@hermes-sandbox.ztlp",
      method: "GET",
      path:   "/api/v1/health",
    )
    get "/api/v1/health", headers: headers
    assert_response :success
    assert_equal "ok", JSON.parse(response.body)["status"]
    assert AuditLog.exists?(action: "api.v1.auth.success")
  end

  test "missing gateway headers reject with gateway_auth_required" do
    get "/api/v1/health"
    assert_response :unauthorized
    failure = AuditLog.where(action: "api.v1.auth.failure").last
    assert_equal "gateway_auth_required", failure.details["reason"]
  end

  test "legacy X-ZTLP-Client-* headers reject with legacy_header_namespace" do
    get "/api/v1/health", headers: {
      "X-ZTLP-Client-Zone"      => "hermes-sandbox.ztlp",
      "X-ZTLP-Client-Name"      => "z2ls.hermes-sandbox",
      "X-ZTLP-Client-Timestamp" => Time.now.to_i.to_s,
      "X-ZTLP-Client-Signature" => "00" * 32,
    }
    assert_response :unauthorized
    failure = AuditLog.where(action: "api.v1.auth.failure").last
    assert_equal "legacy_header_namespace", failure.details["reason"]
  end

  private

  def gateway_inject(email:, method:, path:)
    # Mirrors proto/src/http_injector.rs canonicalization.
    ts = Time.now.to_i.to_s
    hmac_key = ENV.fetch("ZTLP_GATEWAY_HMAC_KEY")
    canonical = [
      "x-ztlp-admin-email:#{email}",
      "x-ztlp-authenticated:1",
      "x-ztlp-timestamp:#{ts}",
    ].join("\n")
    sig = OpenSSL::HMAC.hexdigest("SHA256", hmac_key, canonical)
    {
      "X-ZTLP-Authenticated" => "1",
      "X-ZTLP-Admin-Email"   => email,
      "X-ZTLP-Timestamp"     => ts,
      "X-ZTLP-Signature"     => sig,
    }
  end
end
```

**Step 2: Verify failure**

Run: `bin/rails test test/integration/api/v1/gateway_admin_auth_test.rb -v`
Expected: 3 failures. Today `/api/v1/*` is HMAC-only and has no `gateway_auth_required` / `legacy_header_namespace` audit codes.

---

## Task 4: GREEN — wire gateway-admin auth into Api::V1::BaseController

**Objective:** Make Task 3's tests pass.

**Files:**
- Modify: `bootstrap/app/controllers/api/v1/base_controller.rb`
- Modify: `bootstrap/app/services/ztlp/api_authenticator.rb` (add legacy-detection branch only — do NOT delete the HMAC verifier yet)

**Step 1: Replace the authenticate path**

```ruby
# app/controllers/api/v1/base_controller.rb
module Api
  module V1
    class BaseController < ::Api::BaseController
      before_action :authenticate_via_gateway!

      attr_reader :current_admin_user

      private

      def authenticate_via_gateway!
        # Detect legacy HMAC clients first so they get a clear audit
        # signal instead of generic "no admin headers".
        if request.headers["X-ZTLP-Client-Signature"].present?
          AuditLog.record(
            action: "api.v1.auth.failure",
            status: "failure",
            details: { reason: "legacy_header_namespace",
                       path: request.fullpath,
                       method: request.request_method },
            ip_address: request.remote_ip,
          )
          render json: { error: "unauthorized" }, status: :unauthorized and return
        end

        result = Ztlp::HeaderVerifier.new(request).verify
        unless result.ok? && (user = AdminUser.find_by(email: result.email))
          AuditLog.record(
            action: "api.v1.auth.failure",
            status: "failure",
            details: { reason: result.ok? ? "no_admin_user" : "gateway_auth_required",
                       path: request.fullpath,
                       method: request.request_method },
            ip_address: request.remote_ip,
          )
          render json: { error: "unauthorized" }, status: :unauthorized and return
        end

        @current_admin_user = user
        AuditLog.record(
          action: "api.v1.auth.success",
          target: user,
          details: { email: user.email, path: request.fullpath,
                     method: request.request_method },
          ip_address: request.remote_ip,
        )
      end
    end
  end
end
```

**Step 2: Run Task 3's tests**
Expected: 3 passed.

**Step 3: Run full Bootstrap suite**
Expected: 0 regressions. (`Ztlp::ApiAuthenticator` is no longer called from controllers but its own unit tests still pass — kept for one-release rollback safety.)

**Step 4: Commit**

```bash
git add bootstrap/app/controllers/api/v1/base_controller.rb \
        bootstrap/test/integration/api/v1/gateway_admin_auth_test.rb
git commit -m "feat(bootstrap): authorize /api/v1/* via gateway admin headers

Plan C: Z2LS authenticates via the same gateway-injected
X-ZTLP-Authenticated/Admin-Email/Timestamp/Signature path the UI
already uses, instead of a separate per-zone HMAC. Removes the
header-namespace-collision class of bugs that bit five tenant
provisions on 2026-05-24.

Legacy X-ZTLP-Client-* requests are rejected with audit code
legacy_header_namespace so old clients hitting new bootstrap get
a clear diagnostic.

ApiAuthenticator HMAC verifier is kept for one release as a
rollback path; per-zone secret env vars are kept dormant.
"
```

---

## Task 5: GREEN — `recreate_tenants.py` enumerates from disk

**Objective:** Make my repeated "deploy missed N tenants" failure architecturally impossible.

**Files:**
- Create: `scripts/deploy/recreate_tenants.py`

**Step 1: Write the deploy script**

```python
#!/usr/bin/env python3
"""Recreate every Bootstrap container against the launch-configured image.

DESIGN PRINCIPLE: enumerate from `~/ztlp.net/data/instances/`, never from
a hardcoded slug list. This script is the ONLY supported way to bump
tenant bootstrap images.

Pre-flight: requires test_launch_env_freshness to pass. If it fails,
the script refuses to run and prints the remediation command.
"""
import re, subprocess, sys
from test_launch_env_freshness import test_launch_dotenv_matches_live_container_env

SAAS = "ubuntu@35.91.88.177"
KEY  = "/home/trs/ztlp/.ssh/ztlp_aws_key"

def ssh(cmd): return subprocess.check_output(["ssh", "-i", KEY, SAAS, cmd], text=True)

def main():
    # 1. Pre-flight: live env must match .env
    try:
        test_launch_dotenv_matches_live_container_env()
    except AssertionError as e:
        sys.exit(f"PRE-FLIGHT FAILED: {e}")

    expected = ssh("docker exec ztlp-launch env | grep ^LAUNCH_BOOTSTRAP_IMAGE=") \
                 .strip().split("=", 1)[1]
    print(f"Target bootstrap image: {expected}")

    tenants = ssh("sudo ls ~/ztlp.net/data/instances/").split()
    print(f"Tenants on disk: {len(tenants)} → {tenants}")

    for t in tenants:
        compose_path = f"~/ztlp.net/data/instances/{t}/docker-compose.yml"
        current = ssh(
            f"sudo grep -oE 'priceflex/ztlp-bootstrap:[\\w\\.\\-]+' {compose_path} | head -1"
        ).strip()
        if current == expected:
            print(f"  {t}: already on {expected} — skip")
            continue
        print(f"  {t}: {current} → {expected}")
        ssh(
            f"cd ~/ztlp.net/data/instances/{t} && "
            f"sudo sed -i 's|{current}|{expected}|g' docker-compose.yml && "
            f"sudo docker compose up -d --force-recreate bootstrap"
        )

    # Post-check
    from test_tenant_image_freshness import test_no_tenant_pins_stale_bootstrap_image
    test_no_tenant_pins_stale_bootstrap_image()
    print("All tenants on target image. ✅")

if __name__ == "__main__":
    main()
```

**Step 2: Commit + use** as the *only* sanctioned way to bump tenant images.

---

## Task 6: Skill update — codify the lesson

**Objective:** Don't repeat 2026-05-24.

**Files:**
- Modify: `~/.hermes/skills/devops/ztlp-prod-deployment/SKILL.md`

Add a "Pitfalls" subsection:

> **Stale-launch-env (2026-05-24, 5-attempt incident):** Editing `~/ztlp.net/.env` does NOT update the running `ztlp-launch` container's process env. Every tenant Launch provisions reads from the live process env, not the file. **Always** follow `.env` edits with `docker compose up -d --force-recreate launch` and verify with `docker exec ztlp-launch env | grep ^LAUNCH_`. The deploy script `scripts/deploy/recreate_tenants.py` refuses to run if these drift.
>
> **Hardcoded tenant slug lists are forbidden.** Any deploy script that iterates over tenants MUST enumerate from `~/ztlp.net/data/instances/`. The 2026-05-24 incident was caused by a recreate loop that hit a literal `["hermes-sandbox", "trs", "tech-rockstars"]` array while 3 new tenants existed on disk. `recreate_tenants.py` is the only sanctioned implementation.
>
> **"Deploy complete" requires a signed end-to-end test.** Container-up + healthcheck-green is insufficient; the deploying agent must run an actual auth-path request from outside the SaaS host and paste the audit-success row before telling the user to retest.

---

## Task 7: Z2LS integration doc

**Files:**
- Create: `docs/integrations/z2ls.md`

Single-page guide:

```markdown
# Z2LS ↔ Bootstrap API

## Authentication

Z2LS authenticates to Bootstrap by **opening a ztlp tunnel as an
identity bound to the target zone**. The gateway injects admin
headers automatically. There is no API key, HMAC, or shared
secret to manage.

## Setup (one-time per Z2LS deployment)

1. `ztlp setup` to generate an identity.
2. Bind the identity's pubkey to the zone's admin allowlist via
   the Bootstrap UI (Networks → Admins → Add).
3. Save the enrollment URI; Z2LS will run `ztlp connect <zone>`
   on startup.

## Making a request

    ztlp connect bootstrap.<zone> --background
    curl http://127.0.0.1:18080/api/v1/health

The gateway terminates the tunnel, verifies the identity, and
injects `X-ZTLP-Authenticated`, `X-ZTLP-Admin-Email`,
`X-ZTLP-Timestamp`, `X-ZTLP-Signature`. Bootstrap's
Api::V1::BaseController verifies the injected signature and looks
up the AdminUser by email.

## Scope

Z2LS has **full admin authority** within its zone (v1). Scoped /
read-only / per-action permissions are deferred — open an issue
if you have a concrete need.
```

---

## Verification Checklist

- [ ] Task 1 test passes (live launch env == .env)
- [ ] Task 2 test passes (no tenant pins stale image)
- [ ] Task 3 test passes (gateway-admin → 200; missing → 401 gateway_auth_required; legacy → 401 legacy_header_namespace)
- [ ] Task 4 wires the new path; full Bootstrap suite stays green
- [ ] Task 5 `recreate_tenants.py` enumerates from disk and refuses on pre-flight failure
- [ ] Task 6 skill update committed
- [ ] Task 7 doc committed
- [ ] End-to-end smoke: from this VM, `ztlp connect bootstrap.hermes-sandbox.ztlp` then `curl 127.0.0.1:18080/api/v1/health` → 200, audit row `api.v1.auth.success` with `email=<admin email>`
- [ ] Send the audit row to Steve before declaring done

---

## Rollback

If the new path misbehaves in production:

1. Revert Task 4's controller change (single file).
2. `Ztlp::ApiAuthenticator` HMAC verifier still wired in its unit tests; controller can be re-pointed.
3. Per-zone HMAC secrets are still injected into every tenant — no re-backfill needed.

This is why we did not delete the HMAC code in this plan.
