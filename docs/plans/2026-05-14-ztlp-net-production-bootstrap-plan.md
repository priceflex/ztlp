# ZTLP.net Production Bootstrap Plan

> **For Hermes:** Use `subagent-driven-development` when implementing this plan task-by-task. Keep ztlp.net as the canonical product control plane. Z2LS is an internal adapter only.

**Goal:** Make `ztlp.net` the production-ready bootstrap/control plane for ZTLP: marketing, organization/zone setup, bootstrap server management, NS configuration, user/device enrollment, policy, revocation, and device-to-device communication.

**Architecture:** `ztlp.net` is the public/product control plane and bootstrap UI. It configures and verifies the ZTLP name server (NS), relay/gateway topology, users, trusted devices, policies, and enrollment tokens. ZTLP should dogfood itself: after initial bootstrap, admin/control-plane access should happen through ZTLP-native communication where practical. Z2LS connects later as a Tech Rockstars internal integration that calls ztlp.net APIs and pushes Chef config to TRS-managed endpoints.

**Tech Stack:** Existing ZTLP monorepo at `/home/trs/projects/ztlp`; Rails 7.1 bootstrap app at `/home/trs/projects/ztlp/bootstrap`; Elixir NS/relay/gateway containers; Rust `ztlp` CLI; Docker Compose; future Z2LS/Chef adapter.

---

## 1. Plain-English Product Definition

`ztlp.net` is the product/bootstrap control plane for ZTLP.

It is not just a marketing site and not just an admin dashboard. It is the interface that:

- Starts or connects the bootstrap server.
- Starts or connects the name server (NS).
- Starts or connects relay/gateway containers.
- Configures the NS properly.
- Manages organizations, zones, users, trusted devices, policies, certs/identities, enrollment tokens, and revocation.
- Uses ZTLP itself as the secure communication path for managing and onboarding future ZTLP devices.

Core idea:

ZTLP is used to bootstrap future access to ZTLP.

The first deployment needs a minimal trusted starting path. Once that exists, the bootstrap server, NS, and associated infrastructure should be administered through ZTLP-native paths instead of exposed management ports wherever possible.

---

## 2. Critical Product Boundary

`ztlp.net` is for everyone.

`Z2LS` is only for Tech Rockstars internal use.

Therefore:

- `ztlp.net` must be the source of truth for ZTLP organizations, zones, users, devices, enrollments, policies, and NS integration.
- `Z2LS` must not become the source of truth for ZTLP identity.
- `Z2LS` should later call ztlp.net APIs, receive enrollment data, and push Chef config to TRS-managed computers.
- The Chef `ztlp` cookbook is an endpoint bootstrapper, not the product control plane.

Recommended split:

```text
ztlp.net
  Public/product control plane
  Owns orgs, zones, NS config, users, devices, policy, enrollment, revocation

Z2LS
  Internal TRS deployment adapter
  Selects managed computers, asks ztlp.net for enrollment, pushes Chef data

Chef ztlp cookbook
  Endpoint bootstrapper
  Installs/starts local SSH + ZTLP listener, enrolls endpoint identity

ZTLP NS/relay/gateway
  Network and identity primitives

Hermes / operator clients
  Connect through ZTLP once endpoint exists
```

---

## 3. Existing Source Tree Reality Check

Repo:

```text
/home/trs/projects/ztlp
```

Existing bootstrap Rails app:

```text
/home/trs/projects/ztlp/bootstrap
```

Existing bootstrap app README says it already intends to:

- Create networks/zones.
- Add machines.
- Assign NS, relay, and gateway roles.
- Deploy components over SSH.
- Generate enrollment tokens and QR codes.
- Monitor health.
- Track audit logs.

Important existing files:

```text
/home/trs/projects/ztlp/bootstrap/README.md
/home/trs/projects/ztlp/bootstrap/config/routes.rb
/home/trs/projects/ztlp/bootstrap/db/schema.rb
/home/trs/projects/ztlp/bootstrap/app/models/network.rb
/home/trs/projects/ztlp/bootstrap/app/models/ztlp_user.rb
/home/trs/projects/ztlp/bootstrap/app/models/ztlp_device.rb
/home/trs/projects/ztlp/bootstrap/app/models/ztlp_group.rb
/home/trs/projects/ztlp/bootstrap/app/models/enrollment_token.rb
/home/trs/projects/ztlp/bootstrap/app/models/policy.rb
/home/trs/projects/ztlp/bootstrap/app/models/certificate.rb
/home/trs/projects/ztlp/bootstrap/app/services/token_generator.rb
/home/trs/projects/ztlp/bootstrap/app/services/ns_registrar.rb
/home/trs/projects/ztlp/bootstrap/app/services/ssh_provisioner.rb
/home/trs/projects/ztlp/bootstrap/app/services/ztlp_tunnel.rb
```

Existing routes already include:

- Dashboard.
- Login/admin users.
- Networks.
- Machines.
- Tokens.
- Identity page.
- Users.
- Devices.
- Groups.
- Policies.
- Notifications.
- Enrollment.
- Identity providers.
- CA/certificates.
- Wizard.
- Health/status.
- JSON API endpoints.
- Docs.

This means the project is not starting from zero. The job is to clarify the product model, harden the flow, polish the UI, and make the bootstrap/NS path production-grade.

---

## 4. Target Architecture

```text
                    Public Internet / First Bootstrap
                                  |
                                  | HTTPS only for marketing, login,
                                  | and initial bootstrap path
                                  v
                         ztlp.net Rails App
                  Marketing + Bootstrap Control Plane
                                  |
                                  | configures / verifies / enrolls
                                  v
                            ZTLP NS Server
                 Identity registry + name resolution
                                  |
              +-------------------+-------------------+
              |                                       |
              v                                       v
          Relay / Gateway                     Bootstrap Service
       Transport + policy                     reachable through ZTLP
                                  |
                                  v
               Organizations, Users, Trusted Devices, Policies
                                  |
                                  v
                    Device-to-device ZTLP sessions


                         Z2LS, internal TRS only
                                  |
                                  | ztlp.net API client
                                  v
                         Chef ztlp cookbook config
                                  |
                                  v
                         TRS-managed endpoints
```

---

## 5. Core Product Objects

### Organization

Customer/account boundary. Owns zones, users, devices, policies, and infrastructure topology.

### Zone / Network

ZTLP namespace, for example:

```text
techrockstars.ztlp
customer.techrockstars.ztlp
hostname.customer.techrockstars.ztlp
```

The current Rails app uses `Network`. For first production work, keep the model name if needed, but the UI should say Organization/Zone where that is clearer.

### Bootstrap Server

Rails control plane. Lets admins configure the UI and the NS correctly. It should eventually be reachable through ZTLP itself.

### Name Server / NS

The ZTLP identity and discovery source of truth. Stores/resolves names, identities, service records, and revocation state.

### Relay / Gateway

ZTLP transport and access enforcement components. Used for device-to-device communication and protected service access.

### User

Human identity. A user alone should not imply access. User access requires association with trusted enrolled device(s).

### Device

Cryptographic endpoint identity. Can be:

- User-owned device, such as a laptop or phone.
- Service device, such as a server.
- Infrastructure device, such as bootstrap, NS, relay, or gateway host.

### Trusted Device Association

Binding between a user and an enrolled device.

A user must be associated with one or more trusted devices before access is allowed. This prevents arbitrary user-only access from unmanaged devices.

### Group

Collection of users and/or devices used by policy.

### Policy

Defines who/what can access which devices/services.

Default must be deny.

### Enrollment Token

Short-lived, scoped invitation for user or device enrollment. Prefer email delivery for user device enrollment.

### Certificate / Identity Record

Revocable credential/identity material tied to user/device status.

---

## 6. Access Model

Core rule:

```text
Access = active user + trusted enrolled device + allowed policy
```

A user cannot be associated arbitrarily. The user must enroll from a device, and that device becomes trusted only after successful enrollment and NS confirmation.

Expected flow:

1. Admin creates/invites user.
2. Admin sends enrollment email.
3. User opens enrollment link on the device they want to trust.
4. Device runs or triggers ZTLP enrollment.
5. Device generates or receives device-bound identity material.
6. ztlp.net records device as pending.
7. NS confirms enrollment.
8. ztlp.net marks device enrolled/trusted.
9. Policy allows or denies device-to-device/service access.

---

## 7. Revocation Model

### Lost phone/device

If a user loses a phone/device:

1. Admin opens user or device record.
2. Admin clicks Revoke Device / Mark Lost.
3. ztlp.net revokes the device identity/certificate in NS.
4. All sessions from that device are denied.
5. Other user devices can remain active if desired.

### Suspended user

If a user should lose all access temporarily:

1. Admin suspends user.
2. Policy/NS/gateway denies all access for all associated devices.
3. Devices are not necessarily destroyed.
4. Reactivating user restores access if devices remain trusted and policy allows.

### Compromised user

If a user identity is compromised:

1. Cascade revoke user.
2. Revoke all previous certs/identities for every associated device.
3. Send new enrollment email(s).
4. Re-enroll each trusted device.
5. Audit every action.

Existing model note:

`ZtlpUser#cascade_revoke!` already exists and revokes enrolled devices. This is directionally correct.

---

## 8. UI / UX Requirements

The interface needs to be production-polished, not prototype-looking.

### Public marketing pages

`ztlp.net` needs clear marketing material explaining:

- What ZTLP is.
- Why no open ports matters.
- How identity-first networking works.
- Device-to-device communication.
- User + trusted device access model.
- Lost-device revocation.
- How onboarding works.
- Why this is different from VPN.

Primary CTA:

```text
Start Bootstrap
```

or:

```text
Get Started
```

### Authenticated product UI

Needs clean pages for:

- Organization/zone setup.
- Bootstrap topology wizard.
- NS server configuration and verification.
- Relay/gateway configuration and verification.
- Users.
- Trusted devices.
- User-device associations.
- Device-to-device policies.
- Enrollment email invitations.
- Revocation workflows.
- Health monitoring.
- Audit logs.

### UX copy rules

Avoid exposing internal/prototype wording to customers.

Prefer:

- Organization
- Zone
- Trusted Device
- Enrollment
- Policy
- Access
- Revoke
- Suspend

Avoid, in customer-facing UI unless necessary:

- Machine
- Demo
- Prototype
- Query-param token
- Internal NS jargon without explanation

---

## 9. Production Acceptance Criteria

`ztlp.net` can be considered minimally production-ready when all of these are true:

- `ztlp.net` resolves and loads over HTTPS.
- Admin can log in securely.
- Admin can create an organization/zone.
- Admin can configure or deploy NS/relay/gateway/bootstrap topology.
- ztlp.net can verify NS health.
- ztlp.net can register bootstrap service with NS.
- ztlp.net can issue production-grade enrollment tokens.
- User can be invited by email to enroll a trusted device.
- Device appears as pending then enrolled.
- User cannot access from an untrusted device.
- Suspending user denies access from all associated devices.
- Revoking a lost device denies only that device.
- Device-to-device communication works when policy allows.
- Device-to-device communication fails when policy denies.
- Every sensitive action appears in audit log.
- Bootstrap/admin access can be reached through a ZTLP path in the dogfood/final state.

---

## 10. Known Technical Gaps

These are known from repo review and must be addressed before real production use.

### ztlp.net DNS / ngrok local test path

Initial local testing path now uses ngrok's reserved domain container:

```bash
docker run -it \
  -e NGROK_AUTHTOKEN=<token> \
  ngrok/ngrok http 80 --url=www.ztlp.net
```

For this repo, keep domain/deployment assets in the dedicated `ztlp.net/` folder and prefer the checked-in wrapper so the token stays out of Git and ngrok forwards directly to the Rails service:

```bash
cd /home/trs/projects/ztlp/ztlp.net
cp .env.local.example .env.local
# Put NGROK_AUTHTOKEN in .env.local, or export it in the shell.
bin/run-local-ngrok
```

The local/default public test endpoint is:

```text
https://www.ztlp.net
```

This is for local testing first. After the bootstrap app path is validated, move ngrok and the Rails app to a proper permanent home.

Need:

- DNS A/AAAA/CNAME or ngrok reserved-domain decision for `www.ztlp.net` and/or `ztlp.net`.
- TLS cert/ngrok edge confirmation.
- Proper hosting target VM/container platform.
- Decision whether to use `ztlp.net` for both marketing and app, or split `app.ztlp.net`.

Recommended eventual split:

```text
ztlp.net      marketing + docs + product intro
app.ztlp.net  authenticated bootstrap control plane
```

For speed, one Rails app can serve both initially, with `www.ztlp.net` temporarily pointing at the local/ngrok test tunnel.

### Enrollment token security

Existing bootstrap Rails token generator has a query-param style token path. Upstream ZTLP also has cryptographic binary enrollment tokens.

For production, prefer:

```text
ztlp://enroll/<base64url cryptographic token>
```

instead of unsigned/demo query-param enrollment URLs.

If keeping query-param URLs temporarily, explicitly mark them as bootstrap/dev mode and add server-side validation before production.

### Windows/service support

Upstream `ztlp agent install` is Unix-only today. The Chef cookbook branch uses NSSM for Windows listener service management.

### Service endpoint registration

Current `ztlp setup` appears to enroll identity, but may not automatically register a reachable listener SVC endpoint. If Hermes/name-based device access requires SVC records, add one of:

- CLI option to register listener address during setup.
- Rails/NS post-enrollment SVC registration.
- Agent heartbeat that advertises available services.

### Device status model

Current `ZtlpDevice` statuses appear to be:

```text
enrolled
revoked
```

Production likely needs:

```text
pending
enrolled
suspended
lost
revoked
expired
```

or a separate enrollment state machine.

---

## 11. Implementation Phases

## Phase 0: Confirm Hosting and DNS

**Objective:** Decide where ztlp.net lives and make it reachable.

**Files / Systems:**

- DNS provider for `ztlp.net`
- Hosting target VM/container platform
- TLS cert configuration

**Steps:**

1. Choose hosting target.
2. Point `ztlp.net` DNS.
3. Optionally point `app.ztlp.net` DNS.
4. Configure TLS.
5. Verify from Hermes:

```bash
host ztlp.net
curl -I https://ztlp.net
```

**Expected:** DNS resolves and HTTPS returns a valid response.

---

## Phase 1: Make Bootstrap Rails App Run Reliably

**Objective:** Get `/home/trs/projects/ztlp/bootstrap` booting and tested locally.

**Files:**

- `/home/trs/projects/ztlp/bootstrap/Gemfile`
- `/home/trs/projects/ztlp/bootstrap/config/database.yml`
- `/home/trs/projects/ztlp/bootstrap/config/routes.rb`
- `/home/trs/projects/ztlp/bootstrap/db/schema.rb`
- `/home/trs/projects/ztlp/bootstrap/test/**/*`

**Commands:**

```bash
cd /home/trs/projects/ztlp/bootstrap
bundle install
bin/rails db:prepare
bin/rails test
bin/rails server
```

**Verification:**

- `/up` health check works.
- Login page works.
- Dashboard loads.
- Networks/zones page loads.
- Users page loads.
- Devices page loads.
- Policies page loads.
- Tokens/enrollment page loads.

**Commit:**

```bash
git add bootstrap
git commit -m "bootstrap: stabilize Rails app boot and tests"
```

---

## Phase 2: Product Language and Navigation Polish

**Objective:** Make the UI reflect the real product model.

**Files likely involved:**

- `/home/trs/projects/ztlp/bootstrap/app/views/layouts/application.html.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/dashboard/index.html.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/networks/**/*.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/identity/**/*.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/docs/**/*.erb`

**Required copy changes:**

- Network -> Organization/Zone where customer-facing.
- Machine -> Infrastructure Host where appropriate.
- Device -> Trusted Device for user-owned enrolled devices.
- Token -> Enrollment Invitation or Enrollment Token depending context.
- Make default-deny and trusted-device requirements obvious.

**Verification:**

- A new user can understand what to do without reading source code.
- No demo/prototype language appears in the main production flow.

**Commit:**

```bash
git add bootstrap/app/views bootstrap/app/helpers
git commit -m "bootstrap: polish product language for ztlp.net"
```

---

## Phase 3: Marketing Landing Page

**Objective:** Add production-quality marketing material and a clear start path.

**Files likely involved:**

- `/home/trs/projects/ztlp/bootstrap/config/routes.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/marketing_controller.rb`
- `/home/trs/projects/ztlp/bootstrap/app/views/marketing/index.html.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/layouts/application.html.erb`

**Content sections:**

1. Hero: Zero Trust Layer Protocol.
2. What it does: cryptographic identity before network access.
3. Why it matters: no open ports, no flat VPN trust.
4. How it works: org -> zone -> trusted devices -> policies -> device-to-device sessions.
5. Lost device story: revoke phone, access gone.
6. Device-to-device story: only allowed identities communicate.
7. CTA: Start Bootstrap.

**Verification:**

- `https://ztlp.net` explains product clearly.
- CTA leads to signup/login/bootstrap wizard.

**Commit:**

```bash
git add bootstrap/app/controllers bootstrap/app/views bootstrap/config/routes.rb
git commit -m "bootstrap: add ztlp.net marketing landing page"
```

---

## Phase 4: Bootstrap Wizard Production Flow

**Objective:** Build a clear onboarding wizard to create a zone and configure bootstrap/NS/relay/gateway.

**Existing files:**

- `/home/trs/projects/ztlp/bootstrap/app/controllers/wizard_controller.rb`
- `/home/trs/projects/ztlp/bootstrap/app/views/wizard/new.html.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/wizard/machines.html.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/wizard/review.html.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/wizard/deploy.html.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/wizard/security.html.erb`

**Wizard steps:**

1. Create organization/zone.
2. Choose topology:
   - all-in-one
   - separate NS/relay/gateway
   - connect existing components
3. Configure infrastructure hosts.
4. Deploy Docker containers or verify existing containers.
5. Register bootstrap with NS.
6. Create first admin user/device.
7. Generate first enrollment token.
8. Verify ZTLP-native connectivity.

**Verification:**

- A clean install can complete the wizard.
- Wizard creates Network/Zone record.
- Wizard creates Machine/Infrastructure Host records.
- Wizard can deploy or verify NS.
- Wizard shows clear success/failure.

**Commit:**

```bash
git add bootstrap/app/controllers/wizard_controller.rb bootstrap/app/views/wizard
git commit -m "bootstrap: make setup wizard production-ready"
```

---

## Phase 5: NS Integration Hardening

**Objective:** Make ztlp.net configure and verify NS in a production-safe way.

**Files likely involved:**

- `/home/trs/projects/ztlp/bootstrap/app/services/ns_registrar.rb`
- `/home/trs/projects/ztlp/bootstrap/app/services/token_generator.rb`
- `/home/trs/projects/ztlp/bootstrap/app/services/ztlp_connectivity.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/networks_controller.rb`
- `/home/trs/projects/ztlp/bootstrap/app/views/networks/show.html.erb`

**Tasks:**

1. Store NS endpoint per zone.
2. Store relay/gateway endpoints per zone.
3. Generate/store zone trust material securely.
4. Prefer cryptographic enrollment tokens.
5. Register bootstrap service record with NS.
6. Verify NS lookup from Rails app.
7. Show NS health in UI.

**Acceptance:**

- UI says NS reachable/unreachable.
- Bootstrap registration can be retried safely.
- Enrollment token generation uses production token path or clearly isolated bootstrap/dev path.

**Commit:**

```bash
git add bootstrap/app/services bootstrap/app/controllers bootstrap/app/views
git commit -m "bootstrap: harden NS registration and verification"
```

---

## Phase 6: User + Trusted Device Enrollment

**Objective:** Implement the core trust model: users get access only through trusted devices.

**Existing files:**

- `/home/trs/projects/ztlp/bootstrap/app/models/ztlp_user.rb`
- `/home/trs/projects/ztlp/bootstrap/app/models/ztlp_device.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/ztlp_users_controller.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/ztlp_devices_controller.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/enrollment_controller.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/idp_enrollment_controller.rb`
- `/home/trs/projects/ztlp/bootstrap/app/views/ztlp_users/**/*.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/ztlp_devices/**/*.erb`
- `/home/trs/projects/ztlp/bootstrap/app/views/enrollment/**/*.erb`

**Model changes likely needed:**

- Add device status values: pending, enrolled, suspended, lost, revoked, expired.
- Consider explicit UserDeviceTrust model if `ztlp_devices.ztlp_user_id` is insufficient.
- Track enrollment invitation email, expiry, and accepted time.
- Track certificate/identity revocation state.

**Flow:**

1. Admin creates user.
2. Admin clicks Send Enrollment Email.
3. ztlp.net creates scoped enrollment token.
4. User opens email link on the device.
5. Device enrolls.
6. ztlp.net marks device trusted for that user.
7. User/device can access only what policy allows.

**Verification:**

- User with no trusted device cannot access anything.
- User with trusted device can access allowed service.
- Revoked device cannot access.
- Suspended user cannot access from any device.

**Commit:**

```bash
git add bootstrap/app/models bootstrap/db/migrate bootstrap/app/controllers bootstrap/app/views bootstrap/test
git commit -m "bootstrap: add trusted user-device enrollment flow"
```

---

## Phase 7: Email Enrollment Invitations

**Objective:** Use email as the preferred user-device onboarding mechanism.

**Files likely involved:**

- `/home/trs/projects/ztlp/bootstrap/app/mailers/*`
- `/home/trs/projects/ztlp/bootstrap/app/views/*mailer*`
- `/home/trs/projects/ztlp/bootstrap/config/environments/production.rb`
- `/home/trs/projects/ztlp/bootstrap/app/services/token_generator.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/ztlp_users_controller.rb`

**Email content:**

- Organization name.
- Device enrollment purpose.
- Expiration time.
- One-click enrollment link.
- Manual CLI command fallback.
- Security warning: only open on the device being enrolled.

Example fallback command:

```bash
ztlp setup --token 'ztlp://enroll/...' --name '<device-name>' -y
```

**Verification:**

- Email preview renders.
- Email sends in staging/production.
- Link creates pending enrollment.
- Token expires.
- Token cannot be reused when max uses is 1.

**Commit:**

```bash
git add bootstrap/app/mailers bootstrap/app/views bootstrap/config bootstrap/test
git commit -m "bootstrap: add email-based trusted device enrollment"
```

---

## Phase 8: Device-to-Device Policy UI

**Objective:** Make policy management clean enough for real device-to-device access.

**Existing files:**

- `/home/trs/projects/ztlp/bootstrap/app/models/policy.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/policies_controller.rb`
- `/home/trs/projects/ztlp/bootstrap/app/views/policies/**/*.erb`
- `/home/trs/projects/ztlp/bootstrap/app/models/ztlp_group.rb`
- `/home/trs/projects/ztlp/bootstrap/app/controllers/ztlp_groups_controller.rb`

**Policy concepts:**

- Source: user, user group, device, device group, role.
- Destination: device, device group, service.
- Service: ssh, rdp, web, api, custom.
- Action: allow/deny.
- Default: deny.

**Required UI:**

- Human-readable policy builder.
- Policy list with priority/status.
- Policy simulator:
  - Source user/device.
  - Destination device/service.
  - Result: allowed or denied, with reason.

**Verification:**

- Allowed policy permits device-to-device connection.
- Denied/default case rejects connection.
- Simulator matches actual gateway/NS behavior.

**Commit:**

```bash
git add bootstrap/app/models bootstrap/app/controllers/policies_controller.rb bootstrap/app/views/policies bootstrap/test
git commit -m "bootstrap: add device-to-device policy management"
```

---

## Phase 9: Dogfood Bootstrap Access Through ZTLP

**Objective:** After first bootstrap, manage the bootstrap app through ZTLP.

**Files likely involved:**

- `/home/trs/projects/ztlp/bootstrap/app/services/ztlp_tunnel.rb`
- `/home/trs/projects/ztlp/bootstrap/app/services/ns_registrar.rb`
- `/home/trs/projects/ztlp/bootstrap/app/services/ssh_provisioner.rb`
- Docker Compose / deployment files

**Tasks:**

1. Create bootstrap service identity.
2. Register `bootstrap.<zone>` in NS.
3. Expose Rails app behind a ZTLP gateway/listener path.
4. Restrict ordinary public admin path as much as practical.
5. Add health check proving Rails can reach NS through ZTLP.

**Verification:**

- Admin can reach bootstrap app through ZTLP path.
- Public admin exposure is minimized.
- Audit log records bootstrap service registration.

**Commit:**

```bash
git add bootstrap docker-compose*.yml docs
git commit -m "bootstrap: dogfood control-plane access through ZTLP"
```

---

## Phase 10: Z2LS Adapter, Later

**Objective:** Connect internal Z2LS automation to ztlp.net after ztlp.net works.

Do not do this first.

Z2LS should:

1. Map Z2LS Company to ztlp.net organization/zone.
2. Map Z2LS Computer to ztlp.net device.
3. Request enrollment token from ztlp.net.
4. Add `recipe[ztlp]` to node.json for selected computer.
5. Add `ztlp:` block to data_bag.yml for selected computer/company.
6. Let Chef converge.
7. Show mirrored status if useful.

Existing Z2LS hook identified:

```text
/home/trs/z2ls/app/services/printer_script_renderer.rb
```

It already dynamically renders per-computer `data_bag.yml` and `node.json`. A future ZTLP renderer should follow that pattern.

---

## 12. First Sprint Recommendation

Start with these tasks only:

1. Confirm DNS/hosting for `ztlp.net` and optionally `app.ztlp.net`.
2. Run the bootstrap Rails app locally and fix boot/test blockers.
3. Polish the product language and navigation.
4. Add marketing landing page with Start Bootstrap CTA.
5. Make the setup wizard clearly create a zone and verify NS.
6. Harden enrollment token generation path.
7. Add email-based trusted device enrollment design/first implementation.

Do not start with Z2LS.

Do not start with billing.

Do not start with a complex customer portal separate from the bootstrap app.

Make one clean path work:

```text
ztlp.net -> create zone -> configure NS -> invite user by email -> enroll trusted device -> allow device-to-device policy -> connect through ZTLP
```

---

## 13. Implementation Notes for Subagents

When implementing:

- Work on a review branch.
- Keep changes small and commit frequently.
- Run tests after each feature slice.
- Prefer existing models/controllers/routes before creating new architecture.
- Keep customer-facing language simple.
- Do not hardcode TRS-only assumptions into ztlp.net.
- Treat Z2LS as a later API client.
- Treat zone keys and enrollment secrets as root-of-trust material.
- Default deny everywhere.
- Audit every sensitive action.

---

## 14. Current Related Work Already Completed

A first Chef cookbook review branch exists for endpoint bootstrap:

```text
Repo: /home/trs/chef-recipes-gitea-docs
Branch: feat/ztlp-cookbook-bootstrap
PR: https://repo.z2ls.it/z2ls/chef-recipes/pulls/15
Commit: bc4b5ddf ztlp v0.1.0: add Windows endpoint listener cookbook
```

That cookbook:

- Installs/starts Windows OpenSSH.
- Forces SSH to listen on 127.0.0.1 only.
- Removes broad SSH firewall rules.
- Runs `ztlp listen` as a Windows service via NSSM.
- Reads endpoint config from `data_bag.yml`.

This supports the endpoint side of the plan, but the product/control-plane source of truth should still be `ztlp.net`.

---

## 15. Open Decisions

Before implementation, decide:

1. Will production use `ztlp.net` only, or split `app.ztlp.net` for authenticated app?
2. What host will run the first ztlp.net Rails app?
3. Will the first deployment use SQLite, Postgres, or another DB?
4. Will we use existing bootstrap app auth initially or add stronger auth before launch?
5. What SMTP provider sends enrollment emails?
6. What exact zone naming hierarchy should public customers use?
7. How should NS production auth be hardened before customer onboarding?
8. Should user-device association stay as `ztlp_devices.ztlp_user_id`, or become a first-class join model?
9. What is the first real pilot device and user?

---

## 16. Definition of Done for This Plan

This plan is complete when:

- ztlp.net is live.
- A real organization/zone exists.
- A production-grade NS is configured and verified.
- A first admin user is created.
- A trusted admin device is enrolled via email/token.
- A second device is enrolled.
- A policy allows device-to-device communication.
- A denied policy actually blocks communication.
- Revoking a device immediately removes access.
- Suspending a user blocks all associated device access.
- Audit logs show the full lifecycle.
- Z2LS can be connected afterward as an internal adapter without redesigning the product architecture.
