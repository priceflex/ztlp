# Plan: Services (rename), Add Service wizard + gateway install, helpdesk role, user/device lifecycle

Status: BUILT 2026-10-25 (slices 1-6 committed locally on `plan/admin-panel`; not pushed, not deployed).

| Slice | Commit | Notes |
|---|---|---|
| 1 helpdesk | 58d52a6f, cba7bfd9 | brakeman role/kind permit recorded as reviewed (operator-gated) |
| 2 rename | 180e9082 | also fixed two dead /apps links; user kind `service` reads "Service account" |
| 3 lifecycle | e2d590b7 | see "Decisions made while building" |
| 4 Add Service | 9220a9c6 | no "user" access choice (see below) |
| 5 gateway install | fc41e332 | + Check now, GatewayStatusJob (30 min) |
| 6 CI | (this commit) | `.github/workflows/admin.yml`; ci-admin.sh: no rubocop auto-fix on CI, brakeman fails on any non-EOL finding |

## Decisions made while building (2026-10-25)

- Disable reaches the name server too, not only rendered policy: a disabled user's USER record has role "" and
  no devices, GROUP records leave them out, their devices' DEVICE records carry no owner, so `group:`/`role:`
  rules (resolved live by the gateway) stop matching once republished. Pending devices are never "suspended".
- A legacy "disabled" user whose name the pre-2026-10-22 Disable REVOKED on the NS (audit `ns.publish`
  type=revoke) can never be enabled; the page and the action say so. Production had none.
- The Add Service access picker has no "one user" choice: Rust gateways check the DEVICE, so a user rule
  never matches. Choices: nobody yet / every enrolled device / group / device / role.
- The install script's `keygen` runs `--user 0:0` (the data dir is root-owned at that point), then
  `chown -R 1000:1000 data` hands it to the gateway user.
- The old secret-free `ServiceRegistrar.gateway_command` printout is replaced by the install panel.

Operator asks (2026-10-25):
- "should we call applications services instead?" -> yes.
- helpdesk "should only be for managing users like adding and disabling users and devices".
- "the ability to create accounts, users, devices".
- "easily add application using the UI like services, so the form needs all the parameters and needs a
  process to create the service's account/enrollment for the gateway so a human can do it easily".
- Then push to GitHub (PR to main, CodeRabbit, squash merge on his word).

## Facts this plan rests on (checked 2026-10-25)

- Live panel v0.3.0 = this branch at 45b6030c (170 commits never pushed; GitHub has 329674d4 / 0.1.1).
  610 tests green, rubocop clean, brakeman = EOL Ruby 3.2 / Rails 7.1 notices + the `role` mass-assignment
  finding below. Trial merge onto origin/main (1eb8a3b6): clean, branch touches only `admin/` + `docs/`.
- `Admin::ROLES = super_admin admin helpdesk read_only`; `write_access?` = anything but read_only. Every mutating
  directory controller (users, groups, applications, rules, gateways, devices, enrollments, zone,
  application_registrations) uses `require_write_access`, so helpdesk can change policy, gateways and zone
  settings and make a directory user `role: admin`. Spec 4.3 says helpdesk = enrollments, device reset,
  read-only directory. This is a privilege-escalation gap.
- Users: new/create/edit/update/revoke exist (kind person|service, role user|tech|admin,
  status invited|active|disabled|revoked). No disable/enable action. NS revoke is PERMANENT.
- Devices: no create form; devices arrive by enrollment (`user_device` / `device_only` tokens, string + QR +
  command) or NS import. Revoke + assign owner exist. No disable/enable.
- Applications: `applications(gateway_id, name, backend, protocol, min_assurance, enabled, description)`,
  `policy_rules(application_id, ...)`. Register-by-FQDN + "Discovered on the name server" list exist; the
  not-found path prints a `ztlp keygen` + `ztlp listen` command. Discovered today: admin.trs.ztlp,
  blitz.trs.ztlp, www.chooseforce.ztlp (none registered yet).
- Gateways: `gateways(zone_id, name, ns_name, kind, host_note, node_id_hex, signing_pubkey_hex, status
  planned|registered|online|stale, last_svc_seen_at, addresses, policy_rendered_at)`.
- Every production gateway has the same shape (compose, image `ztlp-gateway-rust:v0.36.0`, `network_mode:
  host`, `user: 1000:1000`, `/data` volume, `ZTLP_QUIC_CERT_DIR=/data/quic-cert`,
  `ZTLP_HMAC_SECRET_<ZONE>` from `.env`):
  `ztlp listen --gateway --bind 0.0.0.0:23097 --key /data/identity.json --forward <svc>:<backend>
   --ns-server <ns> --relay <relay> --service-name <svc> --zone <zone> --ns-register-name <fqdn>
   [--policy /data/policy.toml] [--http-inject-headers --header-hmac-secret <S> --admin-pubkey-email HEX=who]`.
  ChooseForce and admin run WITHOUT `--policy` (= allow every enrolled device). Blitz has a policy file.
- A gateway publishes its own KEY + SVC (`ns_publish_self`); it needs no zone authority and no enrollment
  token. Its identity comes from `ztlp keygen --output /data/identity.json`. `ztlp setup --token` is NOT
  usable for gateways (writes to `~/.ztlp`, no output path).
- One `ztlp listen` registers ONE NS name (`--ns-register-name` is single), so one gateway container = one
  service. All three production gateways are one-service. A second service on the same box = a second
  gateway container on another UDP port.
- Other `ztlp listen` flags (v0.36.0): `--max-sessions` (100), `--punch` / `--no-punch`,
  `--advertise-interface` / `--no-advertise-interface` / `--advertise-all-interfaces`, `--stun-server`,
  `--nat-assist`, `--zone-hmac-secret-env`.

## Vocabulary (applies to UI, code, docs)

- **Service**: what people reach, e.g. `www.chooseforce.ztlp`. Backend, protocol, sign-in headers, access rules.
- **Gateway**: the box + `ztlp listen` process that serves a service. Identity, cert, relay registration.
- **Gateway install**: the one-time script that creates a gateway (not "service account": that name stays
  free for `User.kind = service`).

## Slice 1 - helpdesk role (security, first)

- `Admin#operator?` = super_admin | admin. New `require_operator` before_action.
- helpdesk CAN: list/search everything; create users (role forced to `user`, kind `person`); edit a user's
  contact fields; disable/enable users; create enrollments (= add devices); disable/enable devices; assign a
  device owner.
- helpdesk CANNOT: set or change `role` or `kind`; revoke (permanent) users or devices; groups and group
  membership; services, rules, gateways, policies; zones, publish/reconcile; administrators (super_admin only,
  unchanged).
- Tests per controller action x role (super_admin, admin, helpdesk, read_only), incl. a helpdesk POST with
  `user[role]=admin` that must not change the role.

## Slice 2 - rename Application -> Service

- Migration: rename tables `applications` -> `services`, `policy_rules.application_id` -> `service_id`
  (reversible). Model `Service`, `ServicesController`, `service_rules`, `/services`, views, tests, nav label
  "Services", audit actions `service.*` (old `application.*` audit rows stay as written).
- `/applications*` -> 301 to `/services*` (bookmarks).
- Pure rename: same behaviour, all tests green before and after.

## Slice 3 - user and device lifecycle

- "Disable" / "Enable" for users and devices (reversible), alongside the existing permanent "Revoke".
  Honest scope: the NS has no reversible disable and gateways do not read a status, so **disable takes effect
  where the panel renders policy** (disabled users/devices are dropped from every rendered rule, and the
  Services page flags gateways running without a policy file, where disable has no effect). Revoke stays the
  hard cut. The page says this in one line next to the button.
- Devices page: "Add device" button -> enrollment form with owner picker (user + device token, or
  device-only), same token page (string, QR, command).
- Users page: "Add user" stays; after create, offer "Enroll a device now" (exists since v0.2.5).
- Audit every action.

## Slice 4 - Add Service form (all parameters)

One page, sensible defaults, "Advanced" section collapsed (plain HTML `<details>`, CSP-clean).

| Field | Default | Becomes |
|---|---|---|
| Service name (FQDN) | - | zone (longest suffix), label, `--service-name`, `--ns-register-name` |
| Gateway host description | - | `host_note` (e.g. "ChooseForce box 10.42.42.112") |
| Backend host:port | - | `--forward <label>:<backend>` |
| Protocol | http | http enables the sign-in header options; tcp hides them |
| Sign-in headers (SSO) | on for http | `--http-inject-headers`, audience = label |
| Header secret | generated (32 random bytes, hex) | `--header-hmac-secret`; shown once for the app's env |
| Access | default deny + one starting rule (group / user / role / "all enrolled devices") | policy rules -> `policy.toml` |
| Advanced: UDP port | 23097 (next free if the host already has one) | `--bind 0.0.0.0:<port>` |
| Advanced: NS / relay | zone's public addrs | `--ns-server`, `--relay` |
| Advanced: max sessions | 100 | `--max-sessions` |
| Advanced: hole punching | on | `--no-punch` when off |
| Advanced: image tag | panel setting (`ztlp-gateway-rust:v0.36.0`) | compose `image:` |
| Advanced: fallback subject map | none | `--admin-pubkey-email HEX=user` (for devices without an NS DEVICE record) |

- Creates Gateway (status `planned`) + Service + rules in one transaction; validation errors re-render
  the form with values kept.
- The existing Register-by-FQDN / Discovered list stays for gateways that already run; "Register" on a
  discovered service opens the same form pre-filled (gateway status `online`, no install step).
- Columns added: services.protocol already exists; gateways gain `bind_port`, `image_tag`, `max_sessions`,
  `punch`, `inject_headers`, `header_secret_ct` (encrypts), `subject_map` (json).

## Slice 5 - gateway install (the "enrollment" for a gateway)

- Service page for a `planned` gateway shows an **install script** (one copy-paste block) for the box:
  creates `/opt/ztlp-<label>-gateway/`, writes `docker-compose.yml`, `policy.toml`, `.env` (mode 600),
  runs `ztlp keygen --output /data/identity.json` inside the image, `chown -R 1000:1000`, `docker compose up -d`,
  then prints the gateway's node id and registration line from the log.
- Secrets in the script: the zone relay secret (`ZTLP_HMAC_SECRET_<ZONE>`) and the header secret. Shown
  ONCE: the script is viewable for 30 minutes after "Show install script" (super_admin/admin only, audited,
  re-showing requires "Regenerate", which rotates the header secret). Same pattern as enrollment tokens.
  The app side gets its own one-line snippet: `ZTLP_GATEWAY_HEADER_SECRET=<same value>` (+ audience).
- Status: the reconcile job (every 30 min, or "Check now" on the page) looks up the FQDN's SVC; when it
  appears it stores node id / addresses / cert, gateway -> `online`. The page shows the checklist:
  script run? -> SVC seen? -> relay registered? -> first client connected?
- Policy changes after install: the page shows the new `policy.toml` + one restart command (pushing policy
  to gateways automatically stays out of scope).
- Tests: script golden file per parameter set, no secret ever in logs/audit details, show-once window,
  regenerate rotates, panel never runs anything on the box.

## Slice 6 - CI + push

- `.github/workflows/admin.yml`: MariaDB service, `bash admin/scripts/ci-admin.sh` on PRs touching `admin/`.
- Push `plan/admin-panel`, open PR to main, fix CodeRabbit findings, squash merge on the operator's word.
- Deploy to admin.trs.ztlp after merge (web + jobs only, gateway untouched; backup first).

## Out of scope (named so they are not assumed)

- Pushing config/policy to gateways over the network (needs an agent on the gateway host).
- Reversible disable enforced at the gateway (needs gateway support for a status field).
- Ruby 3.3 / Rails 7.2+ upgrade (brakeman EOL notices): separate change.
- Multiple services in one gateway process (protocol registers one NS name per listener).
