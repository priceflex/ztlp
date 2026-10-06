# ZTLP Admin Panel + identity-carrying enrollment: plan

Status: PLAN, nothing built. Written 2026-10-05.
Goal in one sentence: start one Docker container, claim it as the first
administrator with a key (no password), then manage users, groups and devices
like Active Directory and mint enrollment strings that carry the person's
identity (username, full name, first/last, email, extras) plus the relay
secret, so a user pastes one string and is fully set up.

## 0. What already exists (so we do not rebuild it)

| Piece | State | Gap for this goal |
|---|---|---|
| NS record types USER 0x11, DEVICE 0x10, GROUP 0x12 | done (v0.9.0) | USER has only name, pubkey, devices, email, role. No display/first/last name, no extra attributes. |
| CLI `ztlp admin create-user / link-device / create-group / group-add / enroll ...` | done | one command at a time, no UI. |
| Enrollment token `ztlp://enroll/...` (`proto/src/enrollment.rs`) | done, MAC'd with the zone secret | carries only zone, NS, relays, gateway, max_uses, expiry, callback. No identity, no relay secret. |
| `bootstrap/` Rails app (17.8k lines, Tailwind, Hotwire, QR codes, `identity` tabs for users/groups/devices) | exists | built for deploying ZTLP onto machines over SSH (networks, machines, deployments). Password login. Its `ZtlpAdmin` shells `ztlp admin user create ...` over SSH, which does not match the real CLI (`create-user`), and predates signed NS registration, so it cannot write to an auth-ON NS. |
| Signed NS registration, per-{name,type} rate limit | done (v0.35.14) | this is what the panel will use to write records. |

Decision: build a NEW small app `admin/` and leave `bootstrap/` alone. Reusing
bootstrap would mean keeping its machine/deploy features and password auth and
rewriting its NS layer anyway. We copy ideas (identity tabs, QR) not code.

## 1. First-admin claim (no password)

1. `docker compose up` starts `ztlp-admin` with a volume for its state.
2. First boot, no admin exists: the container generates a ONE-TIME CLAIM CODE
   and prints it in its log (like Vault/Gitea init). The web UI shows only
   "Claim this system".
3. On your computer: `ztlp keygen` already makes the identity (X25519 + Ed25519
   signing key). Then either
   - `ztlp admin claim https://<panel> --code <claim-code> --name "..." --email ...`
     (signs the request with your Ed25519 key), or
   - paste your public key + claim code + profile into the claim form.
4. The panel stores your public key as `admin`, closes the claim window
   permanently, writes your USER record (role admin) to the NS, and you are the
   first administrator.

Why a claim code: "copy the public key to the UI and become admin" with nothing
else means whoever reaches the port first owns the system. The code proves you
can read the container's log, i.e. you are the operator. It is single use and
expires with the claim window.

Login afterwards (no passwords): `ztlp admin login https://<panel>` signs a
server challenge with your key and opens the browser with a one-time session
URL. Browser never touches the key file. Later: WebAuthn passkeys.

Admin roles: super admin (manages admins), admin (everything else),
help desk (create enrollments, reset devices), read only.

## 2. Data model and where truth lives

- NS holds the signed AUTHORIZATION facts: user name, pubkey, role, devices,
  groups. The panel is the only writer (zone key lives in the admin volume).
- Panel DB (SQLite) holds the DIRECTORY: full profile (username, display name,
  first, last, email, title, department, phone, free-form extras), enrollments,
  audit log. This avoids changing the NS wire format.
- AD-style fields on a user: username, full name, first, last, email, status
  (invited / active / suspended / revoked), role, groups, devices, created,
  last seen. Extras are key/value so we do not need a migration per field.

## 3. Enrollment string carrying identity

Extend `EnrollmentToken` with flag-gated, MAC-covered fields (same pattern as
the existing `FLAG_HAS_CALLBACK` fix, so they cannot be tampered with):

- `0x04` identity: username, full_name, first_name, last_name, email, extras.
- `0x08` relay secret: the zone relay secret, so the client needs nothing
  pasted by hand.

Two kinds of token:
- user + device: carries identity; on redeem the panel marks the invited user
  active and links the new device to them.
- device only: name only, no owner.

Client side: `ztlp setup --token` saves the profile to the ZTLP dir, writes the
relay secret to the existing `relay.secret` / `relay_secret_file` setting, and
the tunnel then signs CLIENT_ROUTE as it does today.

Compatibility: tokens without the new flags are byte-identical to today's. An
old client given a new token must fail closed with "update your client" (add an
unknown-flags check), not misparse.

### The relay secret in the token (interim, flagged on purpose)

`docs/plans/2026-09-19-relay-auth-v3-identity-signed.md` calls the relay secret
a group password: the same value on the relay, gateway and every device, so one
leaked device compromises the zone and the relay cannot revoke one device.
Putting it in the token is fine "for now" as asked, with guardrails:
single use, short default expiry (1 h), shown once in the UI, never written to
logs or the audit log, and the panel shows a banner while relay v3 (per-device
identity-signed relay auth) is not shipped. Relay v3 later removes it from the
token entirely.

## 4. Screens

- Dashboard: counts (users, devices, groups), pending enrollments, recent audit
  events, NS and relay health.
- Users: searchable list; click into a user for tabs Profile (edit all fields),
  Devices, Groups, Enrollments, Activity. Suspend / revoke with a reason.
- Groups: list, members, which services the group may reach; add/remove members.
- Devices: status, owner, last seen, node id; reassign owner; revoke.
- Enrollments: "New enrollment" (pick user+device or device only, expiry, uses),
  result page with the string, QR code and the `ztlp setup --token ...` line;
  list with status (pending / redeemed / expired / revoked) and revoke.
- Admins and audit log (who did what, when, from where).
- Settings: zone, NS, relay addresses, the relay secret (masked).

## 5. Tech

Rails 7.1 + Hotwire + Tailwind built into the image (not a CDN, so the container
works offline), SQLite, one Docker image pinned by tag, gated by the same
image-tag-equals-version check as ns/relay/gateway. The panel writes to the NS
by running the bundled `ztlp` binary (signed registration, already proven
live), and reads by querying the NS. A small NS admin write API can replace the
shell-out later.

## 6. Build order (each step ships and is useful alone)

1. Token format: identity + relay secret fields, `ztlp admin enroll
   --username --full-name --first --last --email --extra k=v --embed-relay-secret`,
   client saves the profile and secret. Tests first: round trip, MAC covers the
   new fields, tamper fails, old tokens unchanged, old client fails closed.
   Usable from the CLI before any UI exists.
2. `admin/` skeleton: Docker, claim code, key login, roles, audit log, CI + image.
3. Users, Groups, Devices CRUD through the NS engine.
4. Enrollments UI, QR, redeem callback, status tracking.
5. Later: WebAuthn, CSV import, invite emails, AD/Entra/LDAP sync, SSO.

## 7. Risks and open items

- Zone key custody: the admin volume holds the key that signs everything. It
  needs an encrypted backup procedure before this is used for real.
- The claim window must default to closed after the first admin. A reset path
  (container-local command, not a web route) is needed for a lost admin key.
- Unknown: how the NS callback (`callback_url`) is authenticated today. The
  redeem step depends on it; check before step 4.
- Not decided: whether user extras should later be mirrored into the NS USER
  record so gateways can put them in identity headers (X-ZTLP-*).
