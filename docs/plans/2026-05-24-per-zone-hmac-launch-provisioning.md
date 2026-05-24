# Per-Zone HMAC: Launch Provisioning + Admin UI Implementation Plan

> **For Hermes:** Execute task-by-task. Each task has TDD steps, exact paths,
> and exact validation commands. Stop and ask if any step's "expected output"
> doesn't match.

**Goal:** Close Blocker #1 from the Hermes Sandbox onboarding report — Launch
never provisions a per-zone HMAC secret, so every Z2LS API call to a fresh
tenant 401s with `no_zone_secret`.

**Architecture:**
- **Producer (NEW):** Launch's `_provision_zone_dockers()` generates
  `ZTLP_HMAC_SECRET_<UPCASE_SLUG_ZONE>` = `openssl rand -hex 32` once per
  tenant, writes it to that tenant's `secrets.env`, and (via compose
  `env_file`) injects it into the bootstrap container's env. The relay
  binary on the gateway side **also** needs the same secret (V2
  GATEWAY_REGISTER frames require it for HMAC validation); compose template
  emits it on the gateway service too.
- **Consumer (ALREADY EXISTS):** Bootstrap Rails `Ztlp::ApiAuthenticator`
  (`bootstrap/app/services/ztlp/api_authenticator.rb`) — verified to read the
  exact same env var + slugification rule. No producer/consumer drift risk.
- **Admin UI (NEW):** Bootstrap admin UI grows a "Zone Secret" section under
  `/admin` gated by passwordless gateway-auth (the high-trust path already
  used by Dashboard/Networks/Audit). Reveal-once on first view, rotate
  button generates a fresh secret + writes it back to the tenant's
  `secrets.env` via a Launch-side admin API call, with comma-shaped grace
  period so in-flight Z2LS clients survive the rotation window.
- **Backfill (NEW):** `bin/launch backfill-zone-secrets` rake-equivalent
  admin CLI that scans the existing `onboarding_requests` table, generates
  secrets for tenants without one in `secrets.env`, recreates each
  bootstrap container. Operator-driven, NOT auto-on-startup (per pitfall:
  surprise prod restarts are user-disrupting).

**Decisions locked in** (per Steve's clarify response default):
- A1: Reveal-once + manual rotate.
- B1: Comma-shaped grace period supported on verify.
- C2: Manual backfill CLI (3 controlled restarts during the deploy window).

**Tech stack:**
- Python 3.12 stdlib WSGI (Launch — `ztlp.net/launch_app/app.py`)
- Rails 7.1 + Ruby 3.2 (Bootstrap — `bootstrap/app/`)
- Compose v2 on the SaaS host (`docker compose up -d`)
- Docker image build for Bootstrap (image will be repinned in `.env`)

**Out of scope (defer to follow-up):**
- Relay-side V2 frame validation of the new secrets — relay already
  consumes the same env var, but the relay container's env doesn't yet
  carry per-zone secrets. Tracked as follow-up because V1 fallback path
  keeps GATEWAY_REGISTER traffic working in the meantime; only Z2LS API
  auth is gated on this fix.
- Audit-log entries for "secret rotated" events. The audit table already
  exists (`admin_gateway_login` rows confirm this) — add a row type in
  the rotate-handler task, but no separate audit UI work.
- Migrating existing tenants to per-tenant secret files (e.g.
  `~/.ztlp/zone_secrets/<slug>.txt` on the SaaS host) instead of
  `secrets.env`. Current design keeps everything in secrets.env to
  match the existing Rails ↔ gateway header-secret pattern, which is
  already battle-tested.

---

## Pre-flight (do these BEFORE any code change)

### P1: Confirm working tree + branch

```bash
cd ~/ztlp
git status
git branch --show-current
```

Expected: branch = `feature/per-zone-hmac-launch-provisioning`, working tree
clean (`.ssh/` is fine — gitignored AWS key path).

### P2: Confirm the AWS triplet + bootstrap host are reachable

```bash
SSH_AWS="ssh -i ~/ztlp/.ssh/ztlp_aws_key -o StrictHostKeyChecking=no -o ConnectTimeout=5"
$SSH_AWS ubuntu@35.91.88.177 'echo SAAS_OK'
$SSH_AWS ubuntu@34.218.240.106 'echo RELAY_OK'
$SSH_AWS ubuntu@54.218.127.30 'echo GATEWAY_OK'
ssh trs@10.69.95.12 'echo BOOTSTRAP_HOST_OK'
```

All four should print the `*_OK` token. If any fails, stop and surface to Steve.

### P3: Snapshot current Launch app + bootstrap image versions

```bash
$SSH_AWS ubuntu@35.91.88.177 'docker inspect ztlp-launch --format "{{.Config.Image}}"' > /tmp/preflight_launch_image.txt
$SSH_AWS ubuntu@35.91.88.177 'cat ~/ztlp.net/.env | grep -E "LAUNCH_BOOTSTRAP_IMAGE|LAUNCH_PUBLIC_HOST"' > /tmp/preflight_launch_env.txt
$SSH_AWS ubuntu@35.91.88.177 'docker ps --format "{{.Names}}\t{{.Image}}" | grep -E "ztlp-bootstrap-|ztlp-gateway-|ztlp-launch|ztlp-ns|ztlp-ngrok"' > /tmp/preflight_inventory.txt
cat /tmp/preflight_inventory.txt
```

Record image tag and inventory in this plan's "Execution log" section
below before proceeding.

### P4: Read the relevant skill pitfalls one more time

- `ztlp-prod-deployment` pitfall: "`docker run -e VAR=\"$VAR\"` in
  single-quoted SSH commands expands LOCALLY → empty secret in container"
  — applies to every `docker run` that injects HMAC secrets in this plan.
  Use the scp-to-tmp + `$(< /tmp/X)` pattern, NOT inline `$VAR`.
- `ztlp-prod-deployment` pitfall: "Sandbox-denied writes to `.env` files
  on production hosts — use scp + interactive-approval cat-redirect".
  Applies to the `LAUNCH_BOOTSTRAP_IMAGE` repin step.
- `ztlp-prod-deployment` pitfall: "Old containers started via `docker
  run` won't `docker compose up -d` cleanly". Pre-rm before compose up.
- `never-edit-production-source-without-mirror`: every edit happens
  in `~/ztlp` on this Hermes box and is compiled+tested locally before
  going anywhere near a production container.

---

## Phase 1 — Local TDD: Launch produces per-zone secret

### Task 1.1: Failing test — `_provision_zone_dockers` emits `ZTLP_HMAC_SECRET_<SLUG>` into secrets.env

**Objective:** Lock in the contract: when Launch provisions a tenant,
its tenant `secrets.env` MUST contain a `ZTLP_HMAC_SECRET_<UPCASE_SLUG>=<64hex>`
line.

**Files:**
- Test: `ztlp.net/tests/test_launch_app.py` (modify — there's already a
  test class for `_provision_zone_dockers` paths)
- Read first: `ztlp.net/launch_app/app.py:645` for the function under test
- Read first: `ztlp.net/tests/test_launch_app.py` (full file) to find the
  right test class/method to extend

**Step 1: Read existing test file to find the right insertion point**

```bash
read_file ztlp.net/tests/test_launch_app.py
# Find any existing test that calls `_provision_zone_dockers` or that
# asserts on `secrets.env` contents. The new test goes adjacent.
```

**Step 2: Write the failing test**

Add this test to the existing test class (or create
`TestProvisionZoneSecrets` if none matches the shape). Use the existing
test's setup pattern — temp dir, fake row dict, etc.

```python
def test_provision_zone_dockers_writes_per_zone_hmac_secret_to_secrets_env(self):
    """Regression for Blocker #1 — Launch must generate ZTLP_HMAC_SECRET_<SLUG>."""
    with tempfile.TemporaryDirectory() as tmpdir:
        app = self._make_app(instance_root=tmpdir)
        row = self._fake_row(
            organization_name="Hermes Sandbox",
            zone="hermes-sandbox.ztlp",
            admin_email="hermes-sandbox@techrockstars.com",
            admin_name="Hermes Agent",
        )
        result = app._provision_zone_dockers(row, pubkey_hex="")
        # We don't care if subprocess fails in the test sandbox — we only
        # care that secrets.env exists and has the right line.
        slug = app._slug_for_row(row)
        secrets_path = os.path.join(tmpdir, slug, "secrets.env")
        self.assertTrue(os.path.exists(secrets_path), f"secrets.env missing at {secrets_path}")
        content = pathlib.Path(secrets_path).read_text()
        # Per the slugify rule in api_authenticator.rb / hmac_secrets.ex,
        # "hermes-sandbox.ztlp" -> "HERMES_SANDBOX_ZTLP"
        expected_var = "ZTLP_HMAC_SECRET_HERMES_SANDBOX_ZTLP"
        self.assertIn(expected_var + "=", content,
                      f"missing {expected_var} in {content!r}")
        # Extract value and assert it's a 64-char lowercase hex
        for line in content.splitlines():
            if line.startswith(expected_var + "="):
                value = line.split("=", 1)[1].strip()
                self.assertRegex(value, r"^[0-9a-f]{64}$",
                                 f"value {value!r} is not 64-char hex")
                break
        else:
            self.fail(f"could not extract value for {expected_var}")
```

**Step 3: Run the test, expect it to FAIL**

```bash
cd ~/ztlp/ztlp.net
python3 -m pytest tests/test_launch_app.py -k test_provision_zone_dockers_writes_per_zone_hmac_secret_to_secrets_env -v
```

Expected: FAIL with `AssertionError: missing ZTLP_HMAC_SECRET_HERMES_SANDBOX_ZTLP=`.
This confirms the bug. If it PASSES, the fix already landed somewhere — stop
and re-read the file before proceeding.

**Step 4: Commit the failing test**

```bash
cd ~/ztlp
git add ztlp.net/tests/test_launch_app.py
git commit -m "test(launch): regression for missing per-zone HMAC in secrets.env

Locks in the contract that _provision_zone_dockers must emit
ZTLP_HMAC_SECRET_<UPCASE_SLUG> for every new tenant.

What: failing test asserting secrets.env contains the per-zone HMAC line
Why: Blocker #1 from Hermes Sandbox onboarding — Launch never provisions
     this secret, so every Z2LS API call 401s with no_zone_secret
Details: uses the exact slugification rule from
         bootstrap/app/services/ztlp/api_authenticator.rb#slugify_zone
         and docs/per_zone_hmac_design.md
Tests: pytest tests/test_launch_app.py -k <new test name> currently FAILS
Validation: re-run after Task 1.2 should PASS
Follow-up: Tasks 1.3+ add slugify helper + rotation API"
```

---

### Task 1.2: Implement — generate per-zone HMAC in `_provision_zone_dockers`

**Objective:** Make the Task 1.1 test pass.

**Files:**
- Modify: `ztlp.net/launch_app/app.py` (insert helper + add line in
  secrets.env generation block)

**Step 1: Add a top-level `_slugify_zone_for_env_var(zone)` helper** that
mirrors `bootstrap/app/services/ztlp/api_authenticator.rb#slugify_zone`
EXACTLY. Put this near the other top-level helpers (search for
`def _slug_for_row` to find a good neighbour).

```python
def _slugify_zone_for_env_var(zone: str) -> str:
    """Map a ZTLP zone name to its ZTLP_HMAC_SECRET_<SUFFIX> env var suffix.

    Mirrors the slugification rule used by:
      - bootstrap/app/services/ztlp/api_authenticator.rb#slugify_zone
      - relay/lib/ztlp_relay/hmac_secrets.ex#slugify_zone
      - gateway/lib/ztlp_gateway/hmac_secrets.ex#slugify_zone (if present)
      - docs/per_zone_hmac_design.md Zone secret storage section

    Rule:
      1. Upper-case the input.
      2. Replace every non-[A-Z0-9] run with a single underscore.
      3. Strip leading/trailing underscores.

    Examples:
      "acme"                -> "ACME"
      "acme.ztlp"           -> "ACME_ZTLP"
      "hermes-sandbox.ztlp" -> "HERMES_SANDBOX_ZTLP"
      "tech-rockstars.ztlp" -> "TECH_ROCKSTARS_ZTLP"
    """
    import re
    s = re.sub(r"[^A-Z0-9]+", "_", (zone or "").upper())
    return s.strip("_")
```

**Step 2: Modify the secrets.env generation block.** In `_provision_zone_dockers`
(around line 696 in current main), inside the `else:` branch that writes the
NEW `secrets.env`, append the per-zone HMAC line BEFORE the existing
`ZTLP_GATEWAY_HEADER_SECRET=`:

```python
                # Per-zone HMAC secret for the ZTLP v2 wire-frame contract
                # (relay validates GATEWAY_REGISTER signatures; bootstrap
                # validates Z2LS API requests via Ztlp::ApiAuthenticator).
                # First entry is the primary signing key; comma-separated
                # additional entries are grace keys honored on verify only.
                # See docs/per_zone_hmac_design.md.
                #
                # The env var name MUST match what bootstrap/relay/gateway
                # all read: ZTLP_HMAC_SECRET_<UPCASE_SLUGIFIED_ZONE>.
                hmac_zone_suffix = _slugify_zone_for_env_var(zone)
                f"ZTLP_HMAC_SECRET_{hmac_zone_suffix}={secrets.token_hex(32)}\n"
```

Note: this is the same `secrets.token_hex(32)` pattern as
`ZTLP_GATEWAY_HEADER_SECRET` immediately above — 64 hex chars = 32 raw bytes.

**Step 3: Run the failing test, expect it to PASS**

```bash
cd ~/ztlp/ztlp.net
python3 -m pytest tests/test_launch_app.py -k test_provision_zone_dockers_writes_per_zone_hmac_secret_to_secrets_env -v
```

Expected: PASS.

**Step 4: Run the FULL launch test suite to confirm no regression**

```bash
python3 -m pytest tests/test_launch_app.py -v
```

Expected: all green. If anything else breaks, the secrets.env generation
re-emission case is likely the culprit (we should NOT re-emit if the file
exists — check Step 2 lands inside the `else:` branch, not the `pass`).

**Step 5: Commit**

```bash
cd ~/ztlp
git add ztlp.net/launch_app/app.py
git commit -m "fix(launch): generate per-zone HMAC secret on tenant provision

What: new _slugify_zone_for_env_var helper + per-zone HMAC line in
      secrets.env generation
Why: Blocker #1 — Launch never provisioned this secret, so every Z2LS
     API call 401d with no_zone_secret. Now every fresh tenant gets one
     at provision time.
Details: 32 raw bytes (64 hex chars) generated via secrets.token_hex(32),
         written to <instance_dir>/secrets.env, picked up by compose
         env_file for the bootstrap container. Slug rule mirrors
         api_authenticator.rb#slugify_zone exactly (verified against
         docs/per_zone_hmac_design.md).
Tests: pytest tests/test_launch_app.py -v — all green.
Validation: regression test from previous commit now PASSES.
Follow-up: Task 1.3 — emit the same env var to the gateway service in
           the compose template so V2 GATEWAY_REGISTER frames sign with
           the same key the relay verifies against."
```

---

### Task 1.3: Wire the new secret into the gateway service in the compose template

**Objective:** The gateway service (Rust `ztlp listen --gateway`) needs the
SAME secret as bootstrap so V2 wire frames signed by the gateway validate
against the relay's secret (when the relay side is filled in later) AND
match what bootstrap expects.

**Files:**
- Modify: `ztlp.net/launch_app/app.py` (the `compose_yaml` template around
  line 817 — the `gateway:` service block)

Read the existing block first:

```bash
read_file ztlp.net/launch_app/app.py --offset 817 --limit 60
```

**Step 1: Failing test** — assert the compose YAML for the gateway service
references `secrets.env` (it already does) AND that the secrets.env line
emitted in Task 1.2 carries the per-zone secret (already covered). Add a
quick test that exercises the FULL compose YAML and confirms the gateway
service's `env_file` list includes `secrets.env`:

```python
def test_provision_zone_dockers_gateway_uses_secrets_env(self):
    with tempfile.TemporaryDirectory() as tmpdir:
        app = self._make_app(instance_root=tmpdir)
        row = self._fake_row(zone="hermes-sandbox.ztlp")
        app._provision_zone_dockers(row, pubkey_hex="")
        slug = app._slug_for_row(row)
        compose_path = os.path.join(tmpdir, slug, "docker-compose.yml")
        content = pathlib.Path(compose_path).read_text()
        # Find the gateway service block
        gateway_section = content.split("gateway:")[1].split("\n\n")[0]
        self.assertIn("env_file:", gateway_section)
        self.assertIn("secrets.env", gateway_section)
```

```bash
python3 -m pytest tests/test_launch_app.py -k test_provision_zone_dockers_gateway_uses_secrets_env -v
```

If this passes immediately (likely — current code already has the
`env_file: - secrets.env` block on the gateway), great — commit just the
test as a regression lock. If it fails, fix the compose template until
it passes.

**Step 2: Commit**

```bash
git add ztlp.net/tests/test_launch_app.py
git commit -m "test(launch): lock in gateway service reads secrets.env"
```

---

## Phase 2 — Local TDD: Bootstrap honors grace-period secrets (B1)

### Task 2.1: Failing test — `ApiAuthenticator` accepts a grace-period secret on verify

**Objective:** Lock in the grace-period contract — when
`ZTLP_HMAC_SECRET_<ZONE>` is `<new>,<old>` (comma-separated), the
authenticator MUST accept signatures from EITHER secret on verify, while
ONLY using `<new>` for `self.sign(...)` calls.

**Files:**
- Test: `bootstrap/test/services/ztlp/api_authenticator_test.rb`
- Read first: `bootstrap/app/services/ztlp/api_authenticator.rb#authenticate`
  + `resolve_zone_secret` (lines 83-110 and 151-163)

**Step 1: Read the existing test setup**

```bash
read_file bootstrap/test/services/ztlp/api_authenticator_test.rb
# Find the `resolve_zone_secret` test cluster (lines 89-118) and the
# `authenticate` cluster. New tests go in the authenticate cluster.
```

**Step 2: Write three failing tests**

```ruby
test "authenticate accepts a signature made with the grace (second) secret" do
  primary = SecureRandom.hex(32)
  grace   = SecureRandom.hex(32)
  zone    = "grace-test.ztlp"
  client_name = "z2ls.grace-test"

  ENV["ZTLP_HMAC_SECRET_GRACE_TEST_ZTLP"] = "#{primary},#{grace}"

  ApiClient.create!(zone: zone, name: client_name, status: :active)

  ts = Time.current.to_i
  # Sign with the GRACE secret (older) — should still be accepted
  sig = Ztlp::ApiAuthenticator.sign(
    method: "GET", path: "/api/v1/whoami",
    zone: zone, client: client_name,
    timestamp: ts, body: "", secret: [grace].pack("H*")
  )

  request = ActionDispatch::TestRequest.create(
    "REQUEST_METHOD" => "GET", "PATH_INFO" => "/api/v1/whoami",
    "HTTP_X_ZTLP_ZONE" => zone, "HTTP_X_ZTLP_CLIENT" => client_name,
    "HTTP_X_ZTLP_TIMESTAMP" => ts.to_s, "HTTP_X_ZTLP_SIGNATURE" => sig
  )

  result = Ztlp::ApiAuthenticator.new(request).authenticate
  assert result.ok?, "expected ok=true got reason=#{result.reason.inspect}"
ensure
  ENV.delete("ZTLP_HMAC_SECRET_GRACE_TEST_ZTLP")
end

test "authenticate accepts a signature made with the primary (first) secret" do
  # Same setup, sign with primary — verifies the primary path still works.
  # ...
end

test "resolve_zone_secrets returns all secrets in order (primary first)" do
  ENV["ZTLP_HMAC_SECRET_LIST_TEST_ZTLP"] = "#{SecureRandom.hex(32)},#{SecureRandom.hex(32)},#{SecureRandom.hex(32)}"
  secrets_list = Ztlp::ApiAuthenticator.resolve_zone_secrets("list-test.ztlp")
  assert_equal 3, secrets_list.length, "expected 3 entries"
  # primary first
  raw_primary = ENV["ZTLP_HMAC_SECRET_LIST_TEST_ZTLP"].split(",").first
  assert_equal [raw_primary].pack("H*"), secrets_list.first
ensure
  ENV.delete("ZTLP_HMAC_SECRET_LIST_TEST_ZTLP")
end
```

**Step 3: Run, expect FAIL**

```bash
cd ~/ztlp/bootstrap
bundle exec rails test test/services/ztlp/api_authenticator_test.rb -n /grace|list_test/ 2>&1 | tail -30
```

Expected: 3 failures. First two with `expected ok=true got reason=:bad_signature`
(authenticator only checks primary). Third with `NoMethodError: undefined method
'resolve_zone_secrets'`.

**Step 4: Commit failing tests**

```bash
cd ~/ztlp
git add bootstrap/test/services/ztlp/api_authenticator_test.rb
git commit -m "test(bootstrap): regression for grace-period HMAC verify

Locks in the contract that ZTLP_HMAC_SECRET_<ZONE>=<new>,<old> must
let the authenticator verify signatures made with EITHER secret while
still using <new> as the primary for outbound signing.

What: 3 failing tests covering grace verify, primary verify, secrets-list helper
Why: rotation requires a verify window where both old and new keys work
Details: matches the rotation procedure in docs/per_zone_hmac_design.md
         steps 1-3 (operator sets <new>,<old>, restarts, then drops <old>)
Tests: bundle exec rails test ... currently FAILS
Validation: re-run after Task 2.2 should PASS
Follow-up: implement resolve_zone_secrets + multi-secret verify"
```

---

### Task 2.2: Implement — multi-secret verify in `ApiAuthenticator`

**Objective:** Make the Task 2.1 tests pass.

**Files:**
- Modify: `bootstrap/app/services/ztlp/api_authenticator.rb`

**Step 1: Add `resolve_zone_secrets`** (returns Array of decoded secrets, primary first)
next to the existing `resolve_zone_secret` (line 151). Keep `resolve_zone_secret`
as a thin shim that returns the primary, for backward compat.

```ruby
# Resolve ALL valid secrets for a zone — primary first, then grace
# entries. Used by `authenticate` to allow rotation overlap windows.
# Same env-var/encoding rules as `resolve_zone_secret`; `nil` entries
# (empty strings, malformed entries) are dropped.
def self.resolve_zone_secrets(zone)
  raw = ENV["ZTLP_HMAC_SECRET_#{slugify_zone(zone)}"]
  return [] if raw.blank?

  raw.split(",").map(&:strip).reject(&:empty?).map do |entry|
    if entry.length == 64 && entry.match?(/\A[0-9a-fA-F]+\z/)
      [entry].pack("H*")
    else
      entry
    end
  end
end

# Backward-compat: return the primary only.
def self.resolve_zone_secret(zone)
  resolve_zone_secrets(zone).first
end
```

**Step 2: Modify `authenticate` to loop over all secrets**

Replace the secret-resolve + signature-compare block (lines 99-106):

```ruby
secrets_list = self.class.resolve_zone_secrets(zone)
return Result.failure(:no_zone_secret) if secrets_list.empty?

# Try each secret in order. Constant-time inside compute_hmac +
# secure_compare. We MUST iterate ALL secrets even on early match to
# avoid leaking timing info on which entry matched.
matched = false
secrets_list.each do |secret|
  expected = compute_hmac(secret, ts: ts, zone: zone, client: client)
  matched ||= secure_compare(expected, provided)
end

return Result.failure(:bad_signature) unless matched
```

**Step 3: Run failing tests, expect PASS**

```bash
cd ~/ztlp/bootstrap
bundle exec rails test test/services/ztlp/api_authenticator_test.rb 2>&1 | tail -20
```

Expected: all green.

**Step 4: Commit**

```bash
cd ~/ztlp
git add bootstrap/app/services/ztlp/api_authenticator.rb
git commit -m "feat(bootstrap): support grace-period HMAC verify

What: new resolve_zone_secrets helper + multi-secret verify in
      authenticate(). Old resolve_zone_secret kept as a primary-only
      shim for callers that don't need rotation overlap.
Why: secret rotation requires a verify window where both <old> and
     <new> work — without this, a rotation would break every in-flight
     Z2LS client until they all picked up the new value.
Details: env var format ZTLP_HMAC_SECRET_<ZONE>=<new>,<old>[,older] per
         docs/per_zone_hmac_design.md. Loop is timing-attack-safe
         (iterates ALL entries even on early match).
Tests: bundle exec rails test test/services/ztlp/ — all green.
Validation: failing tests from prev commit now PASS.
Follow-up: Phase 3 Bootstrap admin UI for the rotate action."
```

---

## Phase 3 — Local TDD: Bootstrap admin "Zone Secret" UI

### Task 3.1: Failing test — `Admin::ZoneSecretsController#show` requires gateway-auth

**Objective:** New admin UI section under `/admin/zone_secrets` for revealing /
rotating the per-zone secret. The same passwordless gateway-auth path that
gates Dashboard/Networks must gate this.

**Files:**
- Test: `bootstrap/test/controllers/admin/zone_secrets_controller_test.rb` (NEW)
- Read first: any existing admin controller test (e.g.
  `bootstrap/test/controllers/admin/dashboard_controller_test.rb` if present)
  to copy the gateway-auth setup harness.

(Detail level abbreviated for plan brevity — the pattern is identical to
existing admin controller tests. Five tests:
  1. `GET /admin/zone_secrets` without gateway-auth → 401/redirect
  2. `GET` with gateway-auth, no secret in env → 200, page shows "no secret
     provisioned, contact ZTLP support"
  3. `GET` with gateway-auth + secret in env, secret never revealed before →
     200, response body contains the secret in hex
  4. `GET` after first reveal → 200, response masks the secret (shows
     "•••••• rotated 5m ago", with rotate button visible)
  5. `POST /admin/zone_secrets/rotate` → generates new secret, writes
     `<new>,<old>` to a `ZoneSecretWriteback` outbound queue (deferred to
     Task 4.x — controller test only asserts the queue grew by 1 + an
     audit row was written; the actual Launch-side writeback is Task 4.x.)
)

**Step 1-4** follow the same RED-GREEN-COMMIT cycle as Phase 1/2.

### Task 3.2: Implement `Admin::ZoneSecretsController` + view template

**Files:**
- Create: `bootstrap/app/controllers/admin/zone_secrets_controller.rb`
- Create: `bootstrap/app/views/admin/zone_secrets/show.html.erb`
- Modify: `bootstrap/config/routes.rb` (add `resource :zone_secret, only: [:show], controller: "zone_secrets"` + a `post :rotate` collection route)
- Modify: existing `app/views/layouts/admin.html.erb` (or whatever the admin
  layout is) to add the "Zone Secret" sidebar nav item

The controller uses the existing `before_action :require_gateway_auth!` (or
equivalent — read `application_controller.rb` to confirm the name) that
guards the Networks/Audit pages.

Reveal-once state lives in a new `zone_secret_audit` table (Task 3.3 migration).

### Task 3.3: Migration — `zone_secret_audits` table

**Files:**
- Create: `bootstrap/db/migrate/<TIMESTAMP>_create_zone_secret_audits.rb`
- Create: `bootstrap/app/models/zone_secret_audit.rb`

Schema:

```ruby
create_table :zone_secret_audits do |t|
  t.string :event, null: false        # "revealed_at_provision" | "rotated" | "viewed_after_reveal_(no value shown)"
  t.string :admin_email, null: false  # who clicked
  t.string :ip_address                # request.remote_ip at audit time
  t.string :user_agent                # request.user_agent
  t.text   :metadata                  # JSON — e.g. "rotated_from_fingerprint" => sha256(old)[..16]
  t.datetime :created_at, null: false
end
add_index :zone_secret_audits, :event
add_index :zone_secret_audits, :created_at
```

Note: we DO NOT store the actual secret value in the table — only audit
metadata. The secret stays in `ZTLP_HMAC_SECRET_<ZONE>` env var (loaded
from secrets.env at boot) and in the Launch host's secrets.env file.
Storing it in the Rails DB would create a secondary copy that needs
its own rotation story.

### Task 3.4: Reveal-once gating logic

The "has this been revealed before?" check is:
`ZoneSecretAudit.where(event: "revealed_at_provision").exists?`. If false on
first GET, the page renders with the full secret value AND writes a
`revealed_at_provision` audit row in the same request. Subsequent GETs see
the audit row and render the masked view.

A "I lost my secret" recovery path — the admin can click "Force reveal" which
writes an audit row but triggers an immediate auto-rotate (so the now-
exposed-twice secret is replaced). This prevents an attacker who briefly
gets gateway-auth from quietly stealing a long-lived secret — they have to
either rotate it (audited) or live with the rotation that follows the
force-reveal click.

---

## Phase 4 — Launch-side writeback API for rotation

### Task 4.1: Failing test — `POST /api/admin/zone-secret/rotate` (Launch admin API)

**Objective:** Bootstrap's rotate handler can't write to its own secrets.env
(Bootstrap is in a container that doesn't have access to the host filesystem
where secrets.env lives). The rotation MUST go through Launch via a
small admin API.

**Files:**
- Test: `ztlp.net/tests/test_launch_app.py` (extend)

**Step 1: Failing test**

```python
def test_admin_rotate_zone_secret_writes_new_to_secrets_env_keeps_old_as_grace(self):
    # Provision a tenant
    # POST /api/admin/zone-secret/rotate with auth+slug, get back HMAC body
    # Assert secrets.env now reads "ZTLP_HMAC_SECRET_<X>=<new>,<old>"
    # Assert response body contains the new value once (reveal-once contract)
```

**Step 2: Run, expect 404** (endpoint doesn't exist yet).

### Task 4.2: Implement the endpoint

**Files:**
- Modify: `ztlp.net/launch_app/app.py`

Add a route in the WSGI dispatcher:

```python
if path == "/api/admin/zone-secret/rotate" and method == "POST":
    return self.handle_admin_rotate_zone_secret(environ)
```

Handler:
1. **Auth.** Reuse the existing Launch-side admin auth (gateway-issued
   header, or a `LAUNCH_ADMIN_TOKEN` env-var Bearer — pick whichever
   existing Launch admin endpoint uses; this matches that.)
2. Read POST body for the tenant slug (or zone — convert via
   `_slug_for_row` lookup).
3. Look up the tenant's instance dir.
4. Read the existing `secrets.env`, find the
   `ZTLP_HMAC_SECRET_<X>=` line, parse the current primary.
5. Generate a new 64-hex via `secrets.token_hex(32)`.
6. Rewrite the line as `ZTLP_HMAC_SECRET_<X>=<new>,<old>`.
7. `docker compose -f <instance>/docker-compose.yml up -d --force-recreate bootstrap gateway`
   (both containers — Rails reloads env on restart, gateway also reads it).
8. Return JSON `{ "new_secret_hex": "<new>", "grace_until_ts": <now + 24h> }`.

The 24h grace window is intentionally generous — Z2LS clients should rotate
on their next config-pull cycle (usually hourly). Operator can manually
shrink the window by calling rotate AGAIN (which drops the original primary
out of the grace slot and adds the newly-generated primary).

### Task 4.3: Bootstrap admin controller calls Launch's writeback API

**Files:**
- Modify: `bootstrap/app/controllers/admin/zone_secrets_controller.rb`

The rotate action in Bootstrap admin → fires an HTTP POST to Launch's
admin API → reads the new secret back → renders reveal-once with that
new value.

This adds one round-trip (admin click → bootstrap → launch → bootstrap →
admin) but keeps the secrets.env writes in a single component (Launch) so
there's no Rails-on-host bind-mount needed.

---

## Phase 5 — Local end-to-end test (containerized)

### Task 5.1: docker-compose-based integration test

**Objective:** Spin up a Launch container + a fresh Bootstrap container in
docker-compose locally, hit the /start → /claim → /api/admin/zone-secret/rotate
flow end-to-end, assert the secret round-trips correctly.

**Files:**
- Create: `ztlp.net/tests/integration/test_zone_secret_e2e.py`
- Maybe modify: `ztlp.net/tests/integration/docker-compose.test.yml` (if
  one exists) or create a fresh one.

Verifies:
1. Provision creates secrets.env with the HMAC line.
2. Bootstrap container starts and `Ztlp::ApiAuthenticator.resolve_zone_secret`
   returns the expected value (run `docker exec ztlp-bootstrap-test bin/rails
   runner 'puts Ztlp::ApiAuthenticator.resolve_zone_secret("test.ztlp")&.bytesize'`).
3. Sign a request from a Python test client with that secret → API auth
   returns 200, not no_zone_secret.
4. Rotate via the Launch admin API → both old and new secrets verify for
   the grace window.

This is the gate for "code is ready to deploy."

---

## Phase 6 — Build images

### Task 6.1: Build new bootstrap image with the multi-secret verify + admin UI

```bash
cd ~/ztlp/bootstrap
NEW_TAG="v0.30.3-zone-secret-ui"
docker build -t priceflex/ztlp-bootstrap:${NEW_TAG} -t priceflex/ztlp-bootstrap:latest .
# Long: ~16 min. Use terminal(background=true, notify_on_complete=true).
```

### Task 6.2: Build new Launch image with the per-zone HMAC generator + rotate API

```bash
cd ~/ztlp/ztlp.net
NEW_TAG="v0.30.3-zone-secret"
docker build -t ztlpnet-launch:${NEW_TAG} .
```

### Task 6.3: Ship both images to the SaaS host via SSH pipe

Per `ztlp-prod-deployment` skill — use SSH pipe, not scp.

```bash
SSH="ssh -i ~/ztlp/.ssh/ztlp_aws_key -o StrictHostKeyChecking=no"
docker save priceflex/ztlp-bootstrap:${BS_TAG} priceflex/ztlp-bootstrap:latest | \
  gzip | $SSH ubuntu@35.91.88.177 'gunzip | docker load'
docker save ztlpnet-launch:${LAUNCH_TAG} | gzip | \
  $SSH ubuntu@35.91.88.177 'gunzip | docker load'
```

---

## Phase 7 — Deploy (REQUIRES STEVE'S TYPED VERBAL CONFIRMATION)

⚠️ **Stop here. Do not execute Phase 7 without typed verbal confirmation.**

Per `ztlp-prod-deployment` pitfall "Destructive prod commands require a
verbal-string confirmation": Phase 7 restarts the Launch container and
3 customer-facing bootstrap containers. Steve's iOS bench is sensitive to
gateway/relay/NS restarts — Launch + bootstrap restarts shouldn't crash the
iOS bench (they're not on the iOS data path) but the restarts will briefly
500 any in-progress customer admin sessions.

Ask Steve to reply with one of:

```
proceed deploy        — proceed with Phase 7 in full
launch+sandbox only   — repin Launch, backfill ONLY hermes-sandbox (skip trs + tech-rockstars for now)
cancel                — abort, leave production untouched
```

### Task 7.1: Repin LAUNCH_BOOTSTRAP_IMAGE in compose .env

Per the "Sandbox-denied writes to .env files" pitfall — use the
scp+approval-cat-redirect pattern.

### Task 7.2: docker compose up -d launch (recreates Launch with new image)

### Task 7.3: Run the backfill CLI for hermes-sandbox

```bash
$SSH ubuntu@35.91.88.177 'docker exec ztlp-launch python3 -m launch_app.cli backfill-zone-secrets --zone hermes-sandbox.ztlp --restart-tenants'
```

The CLI:
1. Reads each existing tenant's secrets.env.
2. If `ZTLP_HMAC_SECRET_<SLUG>` is missing, generates one and appends.
3. `docker compose -f <instance>/docker-compose.yml up -d --force-recreate bootstrap gateway`.
4. Verifies via `docker exec <bootstrap-container> bin/rails runner
   'puts Ztlp::ApiAuthenticator.resolve_zone_secret("...")&.bytesize'` returns 32.

### Task 7.4: Backfill trs + tech-rockstars (only on `proceed deploy`)

Same CLI invocation, different zones.

### Task 7.5: Verification — end-to-end Z2LS API call from this Hermes box

```bash
# Read the new secret out of the bootstrap container env
SECRET=$($SSH ubuntu@35.91.88.177 'docker exec ztlp-bootstrap-hermes-sandbox env | grep ZTLP_HMAC_SECRET_HERMES_SANDBOX_ZTLP | cut -d= -f2')

# Sign a /api/v1/whoami call and hit it through the bootstrap tunnel
# (after `ztlp connect bootstrap.hermes-sandbox.ztlp ...`)
python3 scripts/z2ls_smoke_test.py --zone hermes-sandbox.ztlp --secret "$SECRET" --client z2ls.hermes-sandbox
```

Expected: HTTP 200, not 401 no_zone_secret.

### Task 7.6: Update memory

`User reports Blocker #1 closed. trs + tech-rockstars tenants now have
per-zone HMAC secrets and can host Z2LS integrations.`

Skip if backfill was sandbox-only.

### Task 7.7: Open PR

Per `github-pr-workflow` skill:

```bash
git push -u origin feature/per-zone-hmac-launch-provisioning
gh pr create --title "fix: provision per-zone HMAC secrets at tenant launch + admin UI" \
  --body "$(cat docs/plans/2026-05-24-per-zone-hmac-launch-provisioning.md | head -40)"
gh pr checks --watch
```

Merge with `--squash --delete-branch` once green.

---

## Execution log

(Filled in as tasks complete.)

| Task | Status | Commit SHA | Notes |
|------|--------|-----------|-------|
| P1   | pending |           |       |
| P2   | pending |           |       |
| P3   | pending |           |       |
| ...  |         |           |       |

---

## Rollback plan

If any deploy task fails or the verification call still 401s:

1. **Launch repin rollback:** edit `.env`, set `LAUNCH_BOOTSTRAP_IMAGE=`
   back to the previous version captured in P3, `docker compose up -d launch`.
2. **Bootstrap-per-tenant rollback:** the per-tenant compose file
   references the env var, not the explicit image tag, so editing
   `~/instances/<slug>/instance.env` and re-`docker compose up -d`
   from that dir rolls just that tenant back.
3. **Secrets.env rollback:** the rotate handler keeps the previous
   secret in the grace slot. A rollback re-write to the secrets.env
   takes a backup snapshot first (Task 4.2 writes `<instance>/secrets.env.bak.<ts>`
   before every rewrite); restore from the .bak file.
4. **Code rollback:** `git revert` on this branch's commits — each
   task's commit is atomic and reversible.

The biggest risk is during the backfill rotation — if the operator
runs Task 7.3 for a tenant whose Z2LS client is mid-request, that
request 401s. The 24h grace window covers everything except clients
that JUST saw the old secret and signed a request against it AFTER
the rotate API write but BEFORE the docker recreate completed. That's
a ~5 second hole. Acceptable for v1 given Z2LS clients are expected
to retry.
