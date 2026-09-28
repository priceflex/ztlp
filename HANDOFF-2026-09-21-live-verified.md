# HANDOFF — macOS single-page app + B4/Option B — LIVE-VERIFIED — 2026-09-20/21

Supersedes HANDOFF-2026-09-20-single-page-b4.md (that doc's "waiting on
Steven" items are now DONE and proven on a real Mac). Read
HANDOFF-2026-09-20-macos-thin-shell.md for the original B1-B4 bug list if
picking this up cold.

## TL;DR — it works

Fresh-Mac flow, GUI only, verified live on Steven's MacBook (2026-09-21):
Install service -> Enroll (paste link) -> Trust HTTPS (one click, NO
password) -> Safari loads https://demo-dashboard.defcon.ztlp/ with a
trusted cert. Confirmed read-only:
  CA trusted: yes
  demo-dashboard.defcon.ztlp -> 127.100.0.1
  HTTPS 200 ssl_verify=0

main is at b53d0d4 (proto/macos), pushed. No GitHub release pipeline work
was done or is needed (Steven: skip it).

## The bugs found and fixed, in the order they were hit live

Every one of these was caught by an actual fresh-Mac run, not by reasoning
about the code:

1. **B4 chicken-and-egg** — root daemon exited 1 with no identity.json;
   fixed with unenrolled STANDBY (`daemon::run_unenrolled_standby`, macOS
   only) that serves the control socket and waits for enroll.
2. **TLS started disabled** — standby handed over the instant identity.json
   existed, but `ztlp setup` writes that BEFORE the same command's ca-init
   flips `[tls] enabled = true`. Fixed: hand-over gated on an
   `enroll_in_flight` counter (`standby_may_hand_over`).
3. **Root CA trust refused unattended** — `SecTrustSettingsSetTrustSettings`
   from a root LaunchDaemon with no GUI session: "no user interaction was
   possible". Real OS limit, not a bug to route around in the daemon.
   Fixed: daemon skips `install-ca-cert` on macOS; a GUI "Trust HTTPS"
   button on Home row 3 does it instead — see Option B below.
4. **Two enrollments raced the single-use token** — the app enrolled its
   OWN user-level identity via the callback (consuming the token), THEN
   asked the daemon to enroll with the same token -> "token used up".
   Fixed: ONE enrollment. The app no longer generates/enrolls its own
   identity; the token goes straight to `enrollDaemon`.
5. **Enroll error showed the wizard banner, not the reason** — GUI showed
   "ZTLP Setup Wizard v0.5.2 ... Token valid ..." and truncated before the
   actual `error:` line. Fixed: `summarize_setup_failure()` puts the last
   error-ish line first.
6. **Orphan identity.json wedged the daemon** — a FAILED `ztlp setup`
   (used-up token) had already written identity.json before failing.
   Standby treated presence of that file as "enrolled", started the full
   daemon with `AgentConfig::default()` (NS 127.0.0.1, zone ""), Home said
   "Not enrolled", and the next Enroll was refused as "already enrolled".
   Fixed: "enrolled" now requires identity.json AND a sibling config.toml
   with a non-empty zone (`enrollment_is_complete`); an orphan is deleted
   automatically (`remove_orphan_identity`), both on a failed enroll and at
   daemon startup.
7. **Trust HTTPS button hit the SAME OS refusal as the daemon** —
   AppleScript's "do shell script ... with administrator privileges" runs
   through a headless helper with no Aqua session; `security add-trusted-cert
   -d` into the SYSTEM keychain was refused there too. Probed 4 launch
   methods on MACLLM4 with a throwaway CA (real `ztlp admin ca-init`, not a
   raw openssl cert — that gave false "invalid key" errors first try).
   Winner: `security add-trusted-cert -r trustRoot -k
   ~/Library/Keychains/login.keychain-db` as the plain logged-in user, NO
   admin, NO password. Safari runs as that user so it's sufficient. This is
   Option B's actual trust mechanism — see below.
8. **Retrying the ENROLL packet on a name collision double-spent the
   token** — `[0x08, 0x05]` (name taken) handling resent a *second* 0x07
   enroll with the SAME single-use token; NS had already consumed it on
   attempt 1, so the retry always failed as "token used up" instead of
   getting the renamed retry through. This is what burned ~6 tokens in a
   row during live testing on 2026-09-20/21. Fixed: check name collision
   via a plain 0x01 KEY lookup (`ns_name_is_taken_by_other_key`, never
   touches the token) BEFORE building the enroll packet — exactly one 0x07
   send either way.

## Option B: one device-local root CA, name-constrained to .ztlp

`ztlp admin ca-init` mints "ZTLP Root CA (this device)" / "ZTLP
Intermediate CA (this device)" — device-generic CN, not per-zone — with an
X.509 nameConstraints extension permitting only the `.ztlp` DNS subtree on
both root and intermediate. One trust click per Mac, valid for every zone
and every `.ztlp` hostname the local daemon terminates; a leaked device key
can never mint a browser-trusted cert for a public name. Trust is written
to the USER (login keychain) domain, not system — see bug 7. The daemon's
own trust check (`ca_installed_system_trust` in setup_status) still checks
the system domain and will read false; TunnelViewModel ORs it with its own
`security verify-cert` call so Home reflects the truth from the GUI's own
session.

## What's committed (main, in order)

  4e071d0 test(ns): pin FLAG_HAS_CALLBACK (0x02) enrollment token parsing (B2)
  2a37190 fix(ns): skip callback_url when FLAG_HAS_CALLBACK is set (B2)
  34ce9aa fix(agent,macos): unenrolled standby + post-enroll TLS provisioning (B4)
  f354ebe chore(macos): DEMO-ONLY ATS exception (B3)
  591715a feat(macos): single-page Home readiness checklist (Task 8)
  e36e078 fix(macos): nextBackoffDelay nonisolated (XCTest fix)
  8d068c5 fix(agent,macos): standby hand-over waits for enroll to finish (bug 2)
  933c5d2 feat(ca): device-local root, nameConstraints .ztlp (Option B)
  [ca_trust/control fixes for GUI-owns-trust] (bug 3, first half)
  7a6ca93 fix(macos): Trust HTTPS writes USER-domain trust, no admin prompt (bug 7)
  e730451 fix(macos): ONE enrollment — token straight to the daemon (bug 4)
  5e33147 fix(macos): stray brace fix
  c4decc0 fix(agent,macos): standby needs a COMPLETE enrollment; orphan cleared (bug 6)
  f830693 fix(setup): retry-with-suffix on name collision (superseded by b53d0d4)
  b53d0d4 fix(setup): pre-check name collision via NS lookup, no double-send (bug 8)

## Scripts on the two Macs (still there, reusable for the next release)

- MACLLM4 `~/ztlp-mac-build.sh` — ff-pull, rebuild `ztlp` helper, xcodebuild
  test, Developer-ID signed+hardened Release build, notarize+staple,
  `~/ZTLP.zip`. Has an ERR trap now (prints failing line number) after it
  silently died once on an over-clever sanity check.
- Steven's MacBook `~/ztlp-macbook-optionb-test.sh` — full wipe (old daemon
  state, old System-keychain AND login-keychain ZTLP certs) + fresh install
  + guided GUI steps + PASS/FAIL checks. Rerun this any time a fresh-Mac
  regression test is wanted; it's idempotent.
- `~/ztlp-daemon-state.sh`, `~/ztlp-why-enroll-failed.sh`,
  `~/ztlp-trust-probe.sh`, `~/ztlp-trust-ca.sh` — diagnostic one-offs from
  this session, harmless to keep or delete.
- AWS demo box (44.240.16.59): `/opt/ztlp-demo/ztlp-demo-mint-and-callback.py`
  under systemd unit `ztlp-demo-callback` (port 8765). Mint a fresh token:
    ssh -i ~/.ssh/ztlp-defcon-demo.pem ubuntu@44.240.16.59 \
      'python3 /opt/ztlp-demo/ztlp-demo-mint-and-callback.py mint \
       --callback http://44.240.16.59:8765/api/enrollment/confirm'
  Relay secret = `ZTLP_RELAY_REGISTRATION_SECRET` in
  `~/ztlp/demo/defcon-cloud-compose.yml` on that box (YAML colon form).
  Tokens are single-use, 24h; every failed enroll attempt burns one
  (except lookup-only pre-checks, which don't).

## Known remaining gaps (not blocking, not started)

- Identity row shows "Enrolled in <zone>", not "Enrolled as <name>" — the
  node name isn't persisted anywhere `setup_status` reads. Cosmetic.
- No real HTTPS callback for defcon.ztlp exists yet — the AWS stub +
  Lightsail port 8765 + Info.plist ATS exception all stay until Launch/
  Bootstrap ships one.
- release.yml unsigned for macOS — intentional, no GitHub release pipeline
  per Steven.
- Trust is per macOS user account; a second account on the same Mac
  presses Trust HTTPS once too. Correct for a personal laptop.

## Pitfalls for next time

- A raw `openssl req -x509 -newkey ec ...` PEM made Security.framework
  error "invalid key" on `security add-trusted-cert` — false negative
  during a probe. Always test cert-trust behavior with a cert from the
  REAL code path (`ztlp admin ca-init`), not a quick openssl one-liner.
- `git checkout HEAD -- <file>` for a stash-mangled RED proof beats
  `git stash push <path>` from a subdirectory (pathspec prefix bug seen
  earlier this project; see prior handoff).
- When retrying ANY operation that consumes a single-use server-side
  token, checking availability first via a side-channel (lookup) that
  does NOT touch the token is mandatory — retrying the token-consuming
  call itself is a silent double-spend and the symptom (all-subsequent-
  attempts-fail-used-up) does not look like a retry bug at first glance.
- Multi-command ssh/scp one-liners with `$(...)` sometimes trip the
  terminal tool's security scanner; keep to one host / one command where
  possible, or expect an approval prompt.
