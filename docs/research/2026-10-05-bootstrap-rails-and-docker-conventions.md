# Research: Reusable pieces from `bootstrap/` (Rails) + repo Docker/CI conventions

Source tree: `/tmp/ztlp-rebase` (clean worktree of github.com/priceflex/ztlp). Nothing modified.
Verdict legend for a NEW standalone admin panel: **COPY** (lift as-is), **ADAPT** (lift with edits), **SKIP**.

---

## Part A — `bootstrap/` (Rails 7.1.6, SQLite)

### A.1 Gemfile (`bootstrap/Gemfile`, resolved versions from `Gemfile.lock`)

| Gem | Gemfile constraint | Locked | Purpose | Verdict |
|---|---|---|---|---|
| rails | `~> 7.1.6` | 7.1.6 | framework | COPY |
| sqlite3 | `~> 1.7` | 1.7.3 | DB | COPY |
| puma | `>= 5.0` | 7.2.0 | server | COPY |
| sprockets-rails | — | 3.5.2 | assets | COPY |
| importmap-rails | — | 2.0.3 | JS | COPY |
| turbo-rails | — | 2.0.12 | Hotwire | COPY |
| stimulus-rails | — | 1.3.4 | Hotwire | COPY |
| bcrypt | `~> 3.1` | 3.1.22 | `has_secure_password` | COPY |
| rqrcode | `~> 2.2` | 2.2.0 | QR SVG | COPY |
| net-ssh / net-scp / ed25519 / bcrypt_pbkdf | 7.2 / 4.0 / 1.3 / 1.1 | 7.3.0 / … | SSH provisioning | SKIP (unless panel SSHes) |
| solid_queue | `~> 0.3` | 0.6.1 | background jobs | SKIP (not needed for CLI-shelling panel) |
| lockbox | `~> 1.3` | 1.4.1 | declared but **unused** — grep shows no `Lockbox`/`has_encrypted` call; AR Encryption `encrypts` is used instead | SKIP |
| omniauth, omniauth-rails_csrf_protection, omniauth-google-oauth2, omniauth_openid_connect | 2.1 / 1.0 / 1.1 / 0.7 | 2.1.4 … | IdP enrollment | SKIP |
| psych `~> 4.0`, rdoc `~> 6.5`, irb `~> 1.10` | pins for Ruby 3.0 | | ADAPT (drop if Ruby ≥3.2) |
| bootsnap | `require: false` | | boot cache | COPY |
| web-console (dev) `~> 4.2` | | | COPY |
| minitest `~> 5.20` (5.26.1), mocha `~> 2.1` (2.8.2) (test) | | | COPY |

`ruby ">= 3.0"` in Gemfile; Dockerfile builds on `ruby:3.2.7-slim`.

### A.2 AdminUser + sessions auth

**`bootstrap/app/models/admin_user.rb`** — `has_secure_password`; `ROLES = %w[super_admin admin read_only]`; `LOCKOUT_THRESHOLD = 5`, `LOCKOUT_DURATION = 15.minutes`; `locked?`, `lock!`, `unlock!`, `record_login!(ip)`, `record_failed_login!` (locks at 5th failure), `lockout_minutes_remaining`. Email validated unique case-insensitive. Schema (`db/schema.rb:14`): `email, name, password_digest, role (default "admin"), totp_secret, totp_enabled, last_login_at, last_login_ip, failed_login_attempts, locked_until`. TOTP columns exist but are never used. **Verdict: COPY** (drop totp columns or keep for future).

**`bootstrap/app/controllers/sessions_controller.rb`** — `skip_before_action :require_authentication, only: [:new, :create]`, `layout "login"`. `create` does `AdminUser.find_by("LOWER(email) = ?", …)`, checks `locked?` first (audit `admin_login_failed` reason `account_locked`), then `authenticate`; success sets `session[:admin_user_id]`, `record_login!`, audit `admin_login`, redirects to `session.delete(:intended_url) || root_path`. Failure → `record_failed_login!`, audit `admin_locked`/`admin_login_failed`, re-render `:new` with 422. `destroy` deletes session key. **Verdict: COPY.**

**`bootstrap/app/controllers/application_controller.rb`** — `before_action :require_authentication`; `current_admin` chain = session id → `trusted_gateway_admin` (ZTLP gateway HMAC headers via `Ztlp::HeaderVerifier`, env `ZTLP_TRUST_GATEWAY_AUTH` + `ZTLP_GATEWAY_HEADER_SECRET`) → `orchestrator_onboarding_admin` (`ZTLP_ORCHESTRATOR_ONBOARDING=true`, also HMAC-verified, auto-creates `read_only` user from `X-ZTLP-User`). `store_intended_url` on GET. `require_super_admin` helper. Per-controller `require_write_access` (blocks `read_only?`) is duplicated in `machines/policies/tokens/certificates_controller.rb` (e.g. `machines_controller.rb:156`). **Verdict: ADAPT** — keep session + `require_super_admin` + a centralised `require_write_access`; keep `trusted_gateway_admin` only if the panel sits behind the ZTLP gateway; drop orchestrator onboarding.

**CSRF / session settings** — No `config/initializers/session_store.rb` exists; defaults (cookie store, `protect_from_forgery` via `ActionController::Base` + `config.load_defaults 7.1`). Layouts include `<%= csrf_meta_tags %>`. `config/environments/test.rb:35` sets `allow_forgery_protection = false`. `config/environments/production.rb`: `config.force_ssl = ENV.fetch("FORCE_SSL","true") == "true"`, `config.hosts = (["localhost","127.0.0.1",Socket.gethostname] + ENV BOOTSTRAP_ALLOWED_HOSTS).uniq`, `host_authorization exclude /up`, STDOUT logger, `public_file_server.enabled = true`. `config/initializers/filter_parameter_logging.rb` filters `:passw, :secret, :token, :_key, :crypt, :salt, :certificate, :otp, :ssn`. CSP initializer is fully commented out. API controllers that accept non-browser POSTs use `skip_forgery_protection` (`api/admin/*`). **Verdict: COPY** production.rb host/SSL block + filter params; ADD a CSP + explicit `session_store` (`same_site: :lax, secure: true`) in the new panel.

**Test helper sign-in**: `test/test_helper.rb` defines `sign_in_as_admin`, `sign_in(admin_user)`, `sign_in_as(:fixture)` posting to `login_path` with `password123`; fixtures `test/fixtures/admin_users.yml` use `<%= BCrypt::Password.create('password123') %>` for `super_admin / regular_admin / read_only_admin / locked_admin`. **COPY.**

**Admin CRUD**: `app/controllers/admin/users_controller.rb` (`before_action :require_super_admin`; index/new/create/edit/update/destroy/unlock), views `app/views/admin/users/{_form,edit,index,new}.html.erb`; rake `lib/tasks/admin.rake` → `bin/rails admin:create[email,name,password]`. **COPY.**

### A.3 EnrollmentToken model + TokenGenerator

**`bootstrap/app/models/enrollment_token.rb`** — `belongs_to :network`; `DEFAULT_LIFETIME = 24.hours`; statuses `active|exhausted|expired|revoked` (terminal sticky); `use!` (atomic `with_lock` + reload), `revoke!`, `refresh_status!`, `self.sweep_expired!` (rake `ztlp:tokens:sweep_expired`); every transition writes `AuditLog`. `token_id ||= SecureRandom.hex(8)`. Schema (`schema.rb:200`): `network_id, token_id, token_uri, qr_svg(text), max_uses, current_uses, expires_at, status, allowed_roles, notes, ztlp_user_id`. **Verdict: ADAPT** (drop `network` FK if the panel is single-zone; keep lifecycle logic verbatim).

**`bootstrap/app/services/token_generator.rb`** — **Pure Ruby, does NOT call the CLI in the default path.** `generate!` builds the URI by string-joining params:
```ruby
params = { zone: @network.zone, ns: ns_addr, relay: relay_addr, token: token_id,
           expires: expires_at.to_i, callback: callback_url }.compact
token_uri = "ztlp://enroll/?" + params.map { |k, v| "#{k}=#{v}" }.join("&")
```
`ns_addr = "#{ns_machine.ip_address}:#{SshProvisioner::ZTLP_PORTS['ns'][:udp]}"`. Callback resolved from `bootstrap_url:` kwarg (controller passes `request.base_url`) → `ENV["BOOTSTRAP_URL"]` → nil; URL-encoded, points at `<base>/api/enrollment/confirm`.

**No MAC is computed.** There is **no Ruby port of HMAC-BLAKE2s anywhere in `bootstrap/`** (`rg -i blake2 bootstrap` → 0 hits). The Rust side (`proto/src/enrollment.rs:288-300`) documents two URI forms: *legacy* (no `&nonce=&mac=`, zeroed MAC — requires NS `ZTLP_NS_REQUIRE_REGISTRATION_AUTH=false`) and *signed* (v0.30.10+: `&nonce=<32hex>&mac=<64hex>`, verified via `hmac_blake2s`). Bootstrap only ever emits the **legacy unsigned** form.

The reference MAC is `proto/src/admission.rs:256 pub fn hmac_blake2s(key, message) -> [u8;32]` (classic HMAC construction over BLAKE2s-256, 64-byte block, key zero-padded / pre-hashed if >64) — byte-compatible with Elixir `ns/lib/ztlp_ns/enrollment.ex:487 hmac_blake2s/2` (`:crypto.hash(:blake2s, …)` with ipad/opad). A Ruby port would be ~10 lines using `OpenSSL::Digest.new("BLAKE2s256")` (available in Ruby's OpenSSL ≥1.1) with manual ipad/opad — but the signed message is `serialize_without_mac()` (binary wire format, see `enrollment.rs:1-30` header), so a port must also reproduce that serialization. **Simpler path for the new panel: shell to `ztlp admin enroll … --json`** (see below).

`generate_via_cli!` exists but is **dead code** (never called). It shells:
```ruby
cmd = [ZTLP_CLI, "admin", "enroll", "--zone", zone, "--ns-server", "ip:23096",
       "--expires", expires_in, "--max-uses", max_uses.to_s, "--json"]
output = `#{cmd.shelljoin} 2>&1`; JSON.parse(output)
```
Caveats verified against `proto/src/bin/ztlp-cli.rs:990-1030`: `AdminCommands::Enroll` takes `--zone, --secret <path>, --ns-server, --relay (repeatable, REQUIRED ≥1 — `cmd_admin_enroll` errors "at least one --relay address is required"), --gateway, --expires (default 24h), --max-uses (default 1), --count, --qr`. **There is no `--json` flag on `Enroll`** (`--json` exists on `CreateUser` etc.), so `generate_via_cli!` as written would fail. Secret defaults to `~/.ztlp/zone.key` (created by `ztlp admin init-zone --zone <z>`). `ZTLP_CLI = ENV.fetch("ZTLP_CLI_PATH", "ztlp")`; `cli_available?` = `system("which #{ZTLP_CLI}")`. **Verdict: ADAPT** — reuse URI/QR/audit/DB flow; replace minting with a real `ztlp admin enroll` call (capture stdout, parse `ztlp://enroll/...` line) or write the Ruby HMAC-BLAKE2s + wire serializer port.

### A.4 QR generation (rqrcode)

In `token_generator.rb`:
```ruby
require "rqrcode"
qr = RQRCode::QRCode.new(token_uri)
qr_svg = qr.as_svg(color: "000", shape_rendering: "crispEdges", module_size: 4, standalone: true, use_path: true)
```
SVG stored in `enrollment_tokens.qr_svg` and rendered raw in `app/views/tokens/show.html.erb`, `app/views/enrollment/index.html.erb`, `app/views/idp_enrollment/show.html.erb` (`rg -n qr_svg app/views`). **Verdict: COPY.**

### A.5 Identity views + controllers

Routes (`config/routes.rb:59-80`): nested under `resources :networks` — `get :identity, on: :member, to: "identity#index"`; `resources :ztlp_users, path: "users"` (+ `suspend`, `reactivate`, `cascade_revoke`, `update_role` members); `resources :ztlp_devices, path: "devices", only: [:index,:show,:destroy]`; `resources :ztlp_groups, path: "groups"` (+ `add_member`, `remove_member`).

- `app/controllers/identity_controller.rb` — single `index` with `?tab=overview|users|devices|groups`, loads `@users/@devices/@groups` with `includes`, counts, filters (`role, status, search, device_status, owner_id, device_search`), sort allow-list `%w[name role status created_at]`, `@recent_activity = AuditLog.where("action LIKE ?", "ztlp_%")`. **ADAPT** (drop `Network` scoping).
- `app/views/identity/index.html.erb` (67 lines) — Tailwind tab nav with `data: { turbo_frame: "identity_content" }`, helper `identity_tab_class` (in `app/helpers/application_helper.rb`); partials `_tab_overview` (201), `_tab_users` (151), `_tab_devices` (114), `_tab_groups` (57). **ADAPT** (good scaffold; paths are network-nested).
- `app/controllers/ztlp_users_controller.rb` — CRUD on local mirror rows only; writes `AuditLog` (`ztlp_user_create/revoke/suspend/reactivate/cascade_revoke/update_role`); roles `%w[user tech admin]`. **Does not call ZtlpAdmin** — local DB only. **ADAPT**: wire to `ztlp admin create-user/revoke` for a real control panel.
- `app/controllers/ztlp_groups_controller.rb` — CRUD + `add_member/remove_member` via `GroupMembership`; audit `ztlp_group_*`. Local only. **ADAPT.**
- `app/controllers/ztlp_devices_controller.rb` — index (filters `user_id`, `status` in `%w[pending enrolled revoked orphaned]`), show, destroy→`revoke!`. **ADAPT.**
- Models: `app/models/ztlp_user.rb` (statuses `active|suspended|revoked`, `cascade_revoke!`, `initials`, `Notifiable` concern), `ztlp_group.rb`, `group_membership.rb`, `ztlp_device.rb` (`ASSURANCE_LEVELS %w[unknown software device-bound hardware]`, `VALID_ORIGINS %w[bootstrap ns_sync]`, online = `last_seen_at > 5.minutes.ago`, `assurance_display/color`). **ADAPT** (drop `Notifiable`, `machine`, `network`).
- Views: `ztlp_users/{index,new,show(263)}`, `ztlp_groups/{index,new,show}`, `ztlp_devices/{index,show,_sync_health}`. **ADAPT.**
- Layout `app/views/layouts/application.html.erb` (94 lines) / `login.html.erb` (31) use **Tailwind via CDN** (`<script src="https://cdn.tailwindcss.com">`). **ADAPT** (vendor Tailwind or keep CDN consciously; CDN conflicts with any strict CSP).

### A.6 ZtlpAdmin service (`bootstrap/app/services/ztlp_admin.rb`)

Runs `ztlp admin … --json` **over SSH on the NS machine** (`Net::SSH.start(ns_machine.ip_address, ns_machine.ssh_user, …)`, `channel.wait(30)`), not locally. Exact commands (all `Shellwords.escape`d, all end in `--json`):
```
ztlp admin user create <name> --role <role> [--email <e>] --json
ztlp admin user revoke <name> --reason <r> --json
ztlp admin user list --json
ztlp admin device link <device> --owner <user> --json
ztlp admin device revoke <name> --reason <r> --json
ztlp admin device list --json
ztlp admin group create <name> [--description <d>] --json
ztlp admin group add-member <group> <user> --json
ztlp admin group remove-member <group> <user> --json
ztlp admin group list --json
ztlp admin group members <group> --json
ztlp admin list [--type t] [--zone z] --json
ztlp admin audit --since 24h [--name n] --json
```
`parse_response`: blank → `{}`, else `JSON.parse`, `JSON::ParserError` → `AdminError`. Non-zero exit → `AdminError` with stderr.
**Caveat:** the real CLI (`proto/src/bin/ztlp-cli.rs:958 enum AdminCommands`) uses **kebab-case single-level verbs** (`init-zone`, `enroll`, `create-user`, `link-device`, …; e.g. help text `ztlp admin create-user alice@acme.ztlp --role tech --json`), NOT `admin user create`. The Ruby service's command strings do not match the current CLI grammar and are untested against it (`test/services/ztlp_admin_test.rb` only asserts `respond_to`). **Verdict: ADAPT heavily** — keep the shape (service class, `--json`, typed `AdminError`, `Shellwords`), replace SSH with local `Open3.capture3` against the in-container `ztlp` binary, and regenerate the verb list from `ztlp admin --help`.

Related but different: `app/services/ztlp/ns_admin_client.rb` — HTTP client to NS `GET /admin/records` on :9103, HMAC-SHA256 over `METHOD\nPATH\nUNIX_TS\nSHA256_HEX(body)` with `ZTLP_NS_ADMIN_API_SECRET` (64-hex); typed errors `ConfigurationError/AuthenticationError/ServerError/TransportError`. **COPY** if the panel needs read-only NS record listing without the CLI.

### A.7 Active Record Encryption

No `active_record_encryption` initializer; configured in `config/environments/production.rb`:
```ruby
config.active_record.encryption.primary_key = ENV["ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY"]
config.active_record.encryption.deterministic_key = ENV["ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY"]
config.active_record.encryption.key_derivation_salt = ENV["ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT"]
config.active_record.encryption.support_unencrypted_data = true
```
Models: `machine.rb:8-9 encrypts :ssh_private_key_ciphertext, :ssh_password_ciphertext`; `network.rb:19-20 encrypts :enrollment_secret_ciphertext, :zone_key_ciphertext`; `identity_provider.rb:11 encrypts :client_secret_ciphertext`. `bin/docker-entrypoint` generates random keys with a warning when env is unset (data will not survive rebuilds). **Verdict: COPY** pattern (useful for storing the zone enrollment secret / `zone.key` in the panel DB).

### A.8 Dockerfile + docker-compose.yml

**`bootstrap/Dockerfile`** — two-stage: `FROM registry.docker.com/library/ruby:$RUBY_VERSION-slim AS base` (3.2.7), `build` stage installs `build-essential git pkg-config libsqlite3-dev`, `bundle install`, bootsnap precompile, `SECRET_KEY_BASE_DUMMY=1 ./bin/rails assets:precompile`; runtime installs `curl libsqlite3-0 openssh-client`, copies `/usr/local/bundle` + `/rails`, then:
```dockerfile
# Copy ZTLP CLI binary ... pre-built for x86_64-linux from proto/target/release/ztlp.
COPY bin/ztlp /usr/local/bin/ztlp
```
**`bootstrap/bin/ztlp` is NOT in git** (`git ls-files bootstrap/bin` → docker-entrypoint, importmap, rails, rake, setup only), so this Dockerfile fails to build from a clean checkout unless the binary is dropped in manually. Creates `/data` (SQLite), user `rails`, `/home/rails/.ztlp`; `ENTRYPOINT ["/rails/bin/docker-entrypoint"]`; `HEALTHCHECK curl -f http://localhost:3000/up`; `CMD ["./bin/rails","server","-b","0.0.0.0"]`. **Verdict: ADAPT** — keep structure, replace `COPY bin/ztlp` with a `COPY --from` of the proto image (Part C).

**`bootstrap/bin/docker-entrypoint`** — generates `SECRET_KEY_BASE` / AR encryption keys if missing, sets `DATABASE_PATH=/data/production.sqlite3`, `rails db:prepare`, `db:seed`, ensures super_admin from `ZTLP_BOOTSTRAP_ADMIN_EMAIL/NAME/PASSWORD`, runs `ztlp:network:*` rake tasks, optional NS-sync loop (`ZTLP_NS_SYNC_ENABLED`), `exec "$@"`. **ADAPT** (keep key-gen + db:prepare + admin ensure; drop network tasks).

**`bootstrap/docker-compose.yml`** — service `web`, `image: priceflex/ztlp-bootstrap:latest`, `network_mode: host`, volumes `bootstrap_data:/data` and `${ZTLP_IMAGES_PATH:-/tmp/ztlp-images}:/ztlp-images:ro`, env: `RAILS_ENV, RAILS_LOG_TO_STDOUT, SECRET_KEY_BASE, RAILS_MASTER_KEY, ACTIVE_RECORD_ENCRYPTION_{PRIMARY_KEY,DETERMINISTIC_KEY,KEY_DERIVATION_SALT}, FORCE_SSL (default true), DATABASE_PATH=/data/production.sqlite3, ZTLP_CLI_PATH (default ztlp), BOOTSTRAP_URL, ZTLP_TRUST_GATEWAY_AUTH (default false)`; curl healthcheck on `/up`. **ADAPT** (drop host networking + images mount).

### A.9 AuditLog (`bootstrap/app/models/audit_log.rb`)

`AuditLog.record(action:, target: nil, status: "success", details: nil, ip_address: nil)` — stores `target_type/target_id` polymorphically, `details` as JSON text; `parsed_details`; scopes `recent, for_target(type,id), failures`; `status` in `%w[success failure]`. Schema `schema.rb:63` with indexes on `action`, `created_at`, `(target_type,target_id)`. Viewer: `app/controllers/audit_logs_controller.rb` + `app/views/audit_logs/index.html.erb`. **Verdict: COPY.**

### A.10 ApiClient + HMAC API auth

- `app/models/api_client.rb` — allowlist row `(zone, name)` unique, `active`, `ed25519_pubkey` (reserved, unused), `last_used_at`; `find_active(zone:, name:)`, `touch_last_used!`. Admin CRUD at `app/controllers/admin/api_clients_controller.rb` (`require_super_admin`; deactivate/reactivate). **COPY** if the panel exposes an API.
- `app/services/ztlp/api_authenticator.rb` — headers `X-ZTLP-Zone, X-ZTLP-Client, X-ZTLP-Timestamp, X-ZTLP-Nonce, X-ZTLP-Signature`; canonical string `METHOD\nPATH(fullpath)\nzone\nclient\nts\nnonce\nSHA256_HEX(body)`; HMAC-SHA256 with per-zone secret from `ENV["ZTLP_HMAC_SECRET_<slugified ZONE>"]` (first comma entry; 64-hex decoded to bytes); ±300 s skew; nonce replay cache in `Rails.cache` (`api_auth:nonce:<ts>:<nonce>`); `secure_compare`; public `.sign(...)`, `.canonical_signing_string`, `.slugify_zone`, `.resolve_zone_secret`. **COPY.**
- `app/controllers/api/base_controller.rb` (`ActionController::API`, 404 rescue) and `api/v1/base_controller.rb` (`before_action :authenticate_ztlp_request!`, audit `api.v1.auth.success/failure`, generic 401). **COPY.**
- `lib/ztlp/header_verifier.rb` — Ruby port of gateway `ZtlpGateway.HeaderVerifier`: collects `X-ZTLP-*` except signature, sorts by lowercased name, `name:value` joined by `\n`, HMAC-SHA256 hex, ISO-8601 `X-ZTLP-Timestamp` max age 60 s; returns `[:ok, identity_hash]`. Tested in `test/lib/ztlp/header_verifier_test.rb`. **COPY** (needed only if panel trusts gateway identity headers).
- Other API controllers (`api/enrollment_controller.rb` confirm callback, `api/v1/enrollment_tokens_controller.rb`, `api/admin/*` gateway-header-auth variant, `api/health_controller.rb`, `api/status_controller.rb`, `api/v1/sync_health_controller.rb`) — **ADAPT/SKIP** per need; `api/enrollment#confirm` is what the CLI hits via `callback=`.

### A.11 Test setup

`bootstrap/test/` (Minitest, no spec/). `test/test_helper.rb`: `require "mocha/minitest"`, `parallelize(workers: :number_of_processors)`, `fixtures :all`, global `Resolv.stubs(:getaddresses)`; sign-in helpers (A.2). Fixtures for every model in `test/fixtures/*.yml`. Tests exist for controllers (incl. `authentication_test.rb`, `sessions_controller_test.rb`, `identity_controller_test.rb`, `ztlp_*_controller_test.rb`), models, services (`token_generator_test.rb`, `ztlp/api_authenticator_test.rb`, `ztlp_admin_test.rb` — smoke only), jobs, lib. No CI job runs these (see Part B). **Verdict: COPY** test_helper + admin fixtures + auth/session tests; ADAPT the rest.

---

## Part B — Repo conventions

### B.1 `scripts/verify-image-version.sh`

Usage `scripts/verify-image-version.sh <relay|ns|gateway> <image-ref>`. Asserts three things agree: (1) image tag (`vX.Y.Z` suffix, if present), (2) `<component>/mix.exs` `version: "X.Y.Z"` (first match via `grep -oE 'version:[[:space:]]*"[^"]+"'`), (3) the OTP app vsn baked into the image, read by
```bash
docker run --rm --entrypoint /app/bin/ztlp_<component> "$IMAGE_REF" \
  eval "Application.load(:ztlp_<component>); IO.puts(Application.spec(:ztlp_<component>, :vsn))"
```
Component list is hard-coded (`case "$COMPONENT" in relay|ns|gateway)`), `APP="ztlp_${COMPONENT}"`, `BIN="/app/bin/${APP}"`. **To add a new (non-Elixir) image to the gate** you must extend the `case`, add a per-component "declared version" reader (e.g. a `VERSION` file or `config/version.rb` for Rails) and a per-component "baked version" probe (e.g. `docker run --rm --entrypoint sh IMAGE -c 'cat /rails/VERSION'`), then add the component to the matrix in `image-version-gate.yml` and its `paths:` filter.

### B.2 `.github/workflows/*`

| File | Workflow name | Jobs |
|---|---|---|
| `ci.yml` | **ZTLP CI** (push to `main, prototype-docs`, PRs) | `rust` (proto: fmt, clippy, build all bins, diag feature, tests), `relay`, `ns`, `gateway` (Elixir 1.15/OTP 26, `--warnings-as-errors`, `mix test`), `interop` (Rust↔Elixir), `perf-gate`, `ci-pass` aggregator. **No bootstrap/Rails job.** |
| `image-version-gate.yml` | **Image Version Gate** (push/PR to main touching `relay/**, ns/**, gateway/**, scripts/verify-image-version.sh`, tags `v*`) | `version-gate` matrix `[relay, ns, gateway]`: read mix.exs version → `docker build -t ztlp-<c>:v<ver> ./<c>` → run verify script → on tag push assert `GITHUB_REF_NAME#v == mix.exs`. |
| `release.yml` | **Release** (tags `v*`) | `rust` (5 targets, bins `ztlp ztlp-node ztlp-inspect ztlp-load ztlp-fuzz ztlp-bench` + static lib, tar.gz/zip), `elixir` (OTP releases for relay/ns/gateway → `ztlp-<c>-<tag>-linux-x86_64.tar.gz`), `desktop` (Tauri Linux/Windows), `docker`, `ebpf`, `release` (publishes GitHub Release; Docker/desktop best-effort). |
| `desktop-build.yml`, `ztlp-net-tests.yml` | desktop + ztlp.net launch app tests | not relevant |

**Docker build/push in `release.yml` `docker` job**:
```yaml
matrix.include:
  - { component: ns,        context: ns,                    image: ztlp-ns }
  - { component: relay,     context: relay,                 image: ztlp-relay }
  - { component: gateway,   context: gateway,               image: ztlp-gateway }
  - { component: dashboard, context: demo/defcon-dashboard, image: ztlp-dashboard }
steps: docker/setup-buildx-action@v3 → docker/login-action@v3 (DOCKERHUB_USERNAME/TOKEN secrets)
  → docker/build-push-action@v6 with context: ${{ matrix.context }}, push: true,
    tags: ${{ secrets.DOCKERHUB_USERNAME }}/${{ matrix.image }}:${{ github.ref_name }}
          ${{ secrets.DOCKERHUB_USERNAME }}/${{ matrix.image }}:latest
```
So image names are `<DOCKERHUB_USERNAME>/ztlp-<component>` = `stevenprice/ztlp-ns|ztlp-relay|ztlp-gateway|ztlp-dashboard`, tagged with the git tag (`v0.35.x`) + `latest`. **The proto image (`stevenprice/ztlp-proto`) and bootstrap (`priceflex/ztlp-bootstrap`) are NOT built by CI** — `ztlp.net/launch_app/app.py:47` references `stevenprice/ztlp-proto:v0.35.1` (pushed manually), `ztlp.net/docker-compose.yml` uses `LAUNCH_BOOTSTRAP_IMAGE=priceflex/ztlp-bootstrap:latest`. `scripts/build-and-publish-relay.sh` is the manual publisher (`--repo stevenprice/ztlp-node`, `--component`, tag derived from mix.exs, runs verify script before `--push`).

**Version per component**: Rust = `proto/Cargo.toml` `version = "..."` (bumped by `release.sh`); Elixir = `<c>/mix.exs` `version: "0.35.15"` (ns/relay/gateway all 0.35.15; bumped by hand, gated by image-version-gate); Docker tags = git tag. A new Rails image would need its own declared-version file and a matrix entry `{component: admin, context: <dir>, image: ztlp-admin}` in `release.yml`.

### B.3 `release.sh`

`./release.sh [--dry-run] X.Y.Z[-pre]`: validates semver, requires clean tree + run from repo root (`proto/Cargo.toml` present), warns if not on `main`, `sed`-bumps `proto/Cargo.toml` version + `cargo check`, runs `cargo test --lib` and (if `mix` present) `mix test` for relay/ns/gateway, commits `Release vX.Y.Z`, creates annotated tag `vX.Y.Z`, pushes `main` + tag via `ssh -i ~/.ssh/openclaw` → triggers `release.yml`. It does **not** touch mix.exs (that's why the version gate exists). A new Rails component would need a line here to bump its version file.

### B.4 Compose files

**`docker-compose.yml`** (root, dev stack): services `ns` (build `./ns`, `ztlp-ns`, ports `23096/udp`, `9103`; env `ZTLP_NS_PORT, ZTLP_NS_MAX_RECORDS, ZTLP_NS_STORAGE_MODE=ram_copies, ZTLP_LOG_FORMAT/LEVEL, ZTLP_NS_METRICS_*, ZTLP_NS_RATE_LIMIT_*, ZTLP_NS_REQUIRE_REGISTRATION_AUTH="false", ZTLP_NS_RELAY_RECORDS=…`), `relay` (build `./relay`, `23095/udp`, `9101`, `ZTLP_RELAY_*`, VIP vars), `gateway` (build context `.` dockerfile `gateway/Dockerfile`, `23097/udp`, `9102`, `depends_on ns healthy`, `ZTLP_GATEWAY_NS_HOST=ns`), `echo-backend` (`alpine/socat`). Default network, `/app/healthcheck.sh` healthchecks, resource limits. No pinned image tags (all `build:`), no named volumes. Overlays: `docker-compose.mesh.yml`, `docker-compose.federation.yml`.

**`docker-compose-full-stack.yml`**: network `ztlp-net` bridge `172.28.0.0/24` with static IPs — `ns` 172.28.0.10, `relay1`/`relay2` (build `./relay`), `backend` 172.28.0.30 (`fullstack/Dockerfile.backend`, sshd), `server` 172.28.0.40 (`fullstack/Dockerfile.server`, `ztlp listen`; env `ZTLP_ZONE=fullstack.ztlp, ZTLP_SERVER_NAME, ZTLP_NS_SERVER=172.28.0.10:23096, ZTLP_BIND_ADDR, ZTLP_BACKEND, RUST_LOG`), `client` 172.28.0.50 (`fullstack/Dockerfile.client`, `ztlp connect` + benchmarks, `ZTLP_LOCAL_PORT, ZTLP_BENCHMARK, SSHPASS`). `.prebuilt.yml` variant is the same (still `build:`). All images built from source; no tags/volumes.

**`tenants/test-ztlp/docker-compose.yml`** (per-tenant pattern used by Launch): `image: ztlp-ns:latest`, `ztlp-relay:latest`, `ztlp-gateway:latest`, `priceflex/ztlp-bootstrap:latest`.

### B.5 `proto/Dockerfile` (ztlp CLI image)

- Stage `builder`: `FROM rust:1.89-slim-bookworm AS builder`, installs `pkg-config`, `WORKDIR /build`, dependency pre-build with dummy `src/bin/*.rs` stubs, then `COPY . .` + `cargo build --release`.
- Stage `test`: `FROM builder AS test` (`cargo test --release`).
- Runtime: `FROM debian:bookworm-slim` + `ca-certificates`, `useradd --system --create-home ztlp`, copies
  ```dockerfile
  COPY --from=builder /build/target/release/ztlp /usr/local/bin/
  COPY --from=builder /build/target/release/ztlp-inspect /usr/local/bin/
  COPY --from=builder /build/target/release/ztlp-load /usr/local/bin/
  COPY --from=builder /build/target/release/ztlp-fuzz /usr/local/bin/
  COPY --from=builder /build/target/release/ztlp-throughput /usr/local/bin/
  ```
  stays **root** (comment: bind-mounted `/data/keys` owned by arbitrary host UID), `WORKDIR /home/ztlp`, **no ENTRYPOINT**, `CMD ["bash"]` (comment: Launch starts gateway with `command: ["sh","-c","… ztlp listen …"]`, so the container must default to a shell). Published manually as `stevenprice/ztlp-proto:<tag>` (currently referenced `v0.35.1`). Binary is dynamically linked against bookworm glibc/libssl? (`ca-certificates` only — binary needs just glibc).

### B.6 `ns/Dockerfile`

`FROM elixir:1.15.7-otp-26 AS builder` (`MIX_ENV=prod`, `mix release ztlp_ns`) → `FROM debian:bookworm-slim` + `libncurses6 libtinfo6 libssl3 locales`, `COPY --from=builder /build/_build/prod/rel/ztlp_ns/ /app/`, healthcheck script `/app/healthcheck.sh` (`/app/bin/ztlp_ns rpc "IO.puts(:ok)"`), `USER ztlp`, env defaults (`ZTLP_NS_PORT=23096`, `ZTLP_NS_STORAGE_MODE=disc_copies`, `ZTLP_NS_METRICS_PORT=9103`, `ZTLP_NS_MNESIA_DIR=/app/data/mnesia`, `ZTLP_CA_DATA_DIR=/app/data/ca`), `EXPOSE 23096/udp 9103`, `VOLUME /app/data`, `ENTRYPOINT ["/app/bin/ztlp_ns"] CMD ["start"]`. This `/app/bin/ztlp_<app>` + `eval` convention is what `verify-image-version.sh` relies on.

---

## Part C — Getting the `ztlp` CLI into a Rails container

Three options, in order of preference:

1. **Multi-stage `COPY --from` the published proto image** (fastest, no Rust toolchain in the Rails build):
   ```dockerfile
   ARG ZTLP_PROTO_IMAGE=stevenprice/ztlp-proto:v0.35.1
   FROM ${ZTLP_PROTO_IMAGE} AS ztlpcli
   # ... ruby base/build stages as in bootstrap/Dockerfile ...
   FROM base                                   # runtime (ruby:3.2.7-slim = bookworm)
   COPY --from=ztlpcli /usr/local/bin/ztlp /usr/local/bin/ztlp
   ```
   Path inside the proto image is `/usr/local/bin/ztlp` (see `proto/Dockerfile` runtime stage). Both proto runtime and `ruby:*-slim` are Debian bookworm, so glibc matches. `ca-certificates` already present in ruby-slim. The image has no ENTRYPOINT so it is safe to use purely as a copy source. Pin the tag with a build-arg and bump it alongside releases (nothing in CI builds/pushes `ztlp-proto` today — see B.2 — so either push it manually via `docker build -t stevenprice/ztlp-proto:vX ./proto` or add a `{component: proto, context: proto, image: ztlp-proto}` entry to the `release.yml` docker matrix).

2. **Build from source in the same Dockerfile** (what `fullstack/Dockerfile.server` / `.client` do): repo-root build context, `FROM rust:1.90-slim-bookworm AS builder`, `COPY proto/Cargo.toml proto/Cargo.lock* ./`, stub-bin dependency pre-build, `COPY proto/ .`, `cargo build --release`, then `COPY --from=builder /build/target/release/ztlp /usr/local/bin/ztlp` (`fullstack/Dockerfile.server:49`). Guarantees version lock-step with the repo commit but adds ~10 min Rust compile to every Rails image build.

3. **What bootstrap does today** — `COPY bin/ztlp /usr/local/bin/ztlp` from an untracked, manually-dropped binary (`bootstrap/Dockerfile`). **Do not copy this**: the file is not in git, so clean CI builds fail.

Runtime notes for the panel container: run `ztlp` as the `rails` user with `HOME=/home/rails` and a writable `~/.ztlp` (bootstrap already does `mkdir -p /home/rails/.ztlp && chown rails`), mount/persist the zone secret (`~/.ztlp/zone.key`, created by `ztlp admin init-zone`) or pass `--secret <path>` explicitly, and set `ZTLP_CLI_PATH` (bootstrap convention) if the binary is not on PATH. Call via `Open3.capture3(ZTLP_CLI, "admin", …)` rather than backticks + `shelljoin`.
