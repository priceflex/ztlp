# Plan: multi-zone switcher + one-click application registration

Status: PROPOSED 2026-10-24 (operator ask: "a pulldown on the left where we can choose the zone and
have our default zone"; "an easy way to register applications like www.chooseforce.ztlp and
blitz.trs.ztlp").

## Facts this plan rests on (checked 2026-10-24)
- Every directory table is already zone-scoped (`zone_id` + per-zone unique names on users, devices,
  groups, gateways; enrollments carry `zone_id`). Controllers read `@zone`; only 10 call sites use
  `Zone.primary` (application_controller, dashboard, claim, 2 jobs, 2 rake files).
- One NS serves several zones: `trs.ztlp` and `chooseforce.ztlp` (KEY `chooseforce.ztlp`,
  role zone-authority, pub 20dda0cb...). The NS enrollment secret is ONE global secret
  (`ZtlpNs.Enrollment.get_zone_secret/0`), so every zone mints with the same enrollment secret;
  the token carries its zone and the NS checks the name ends in it. The relay has a per-zone secret
  `ZTLP_HMAC_SECRET_<ZONE>` (CHOOSEFORCE_ZTLP exists) and accepts its registration secret for any zone.
- SVC records carry `zone`, `address(es)`, `node_id`, `registered_by` (prod: admin.trs.ztlp,
  blitz.trs.ztlp, www.chooseforce.ztlp, stale sigtest2.trs.ztlp).
- Admins are global (not per zone). Tunnel SSO maps subjects in the HOME zone.

## Phase A: zone switcher (one release)
1. Current zone = `session[:zone_id]` (validated to an existing zone) else the admin's default zone
   else the system default (`ZTLP_ZONE`). One helper (`current_zone`) replaces `@zone = Zone.primary`
   in ApplicationController; jobs/rake keep an explicit zone argument (default: all zones for
   republish/reconcile/expire, one zone for import).
2. Rail: a zone `<select>` above the nav (form POST `/zone/switch`, CSRF, no inline JS: directory.js
   auto-submits on change, with a submit button fallback). The current zone name + authority dot stay
   in the rail footer.
3. "Set as my default zone": `admins.default_zone_id` (nullable migration) on the zone page / rail.
4. Zones page gains "Add zone": name, public NS addr, relay addrs. Secrets reuse
   `zone:set_secret[...]` with a `ZONE=` argument (stdin, never in a form). Authority import stays
   operator-only (`zone:import_authority[path]` + `ZONE=`).
5. `ns:import ZONE=chooseforce.ztlp` imports that zone's users/devices/groups (read-only to the NS).
6. Tests: switching scopes every directory page; a zone_id from another admin's session can't
   leak data (zones are global, so scoping is about correctness, not tenancy); a removed zone in the
   session falls back; read_only admins can switch but not add zones; jobs iterate all zones.
   SSO home-zone mapping unchanged (pinned).

## Phase B: one-click application registration (one release)
1. "Register application" page: one field, the service FQDN (`www.chooseforce.ztlp`).
   - Zone = the longest configured zone suffix (`chooseforce.ztlp`); unknown zone -> offer "Add zone".
   - The panel looks the name up on the NS (SVC + KEY via the admin API):
     * FOUND -> shows gateway address(es), node_id, last registration, and one button: creates the
       gateway (status live, kind guessed rust_listen, editable) + the application (name = first
       label, e.g. `www`) in that zone, default rule = deny until rules are added.
     * NOT FOUND -> asks for backend (host:port) and gateway box, then shows the exact
       `ztlp listen --gateway ... --forward <name>:<backend> --zone <zone> --ns-register-name <fqdn>`
       command and a docker-compose snippet to run on that box; status planned, flips to live when
       the reconcile job sees the SVC.
2. "Discovered on the name server": every SVC in a configured zone that isn't registered yet, one
   "Register" button each (admin.trs.ztlp, blitz.trs.ztlp, www.chooseforce.ztlp; sigtest2 shows as
   stale/unknown so it can be ignored).
3. Rule editor stays as is (groups/users/roles/devices); the Policies page keeps producing the
   gateway's policy file to copy (pushing policy to gateways is a separate, later feature).
4. Tests: suffix->zone resolution (longest match, no partial-label match: `evilchooseforce.ztlp`
   is not `chooseforce.ztlp`), found/not-found paths with a fake NS, idempotent re-register,
   discovery list excludes registered services, no NS write anywhere.

## Out of scope (named so they aren't assumed)
- Pushing policy files to gateways automatically.
- Enforcing min_assurance at the gateways (gateway code, priceflex/ztlp).
- The relay one-flow-per-gateway limit affecting ChooseForce remote users.
- Importing the chooseforce.ztlp zone authority (needed only to PUBLISH in that zone).
