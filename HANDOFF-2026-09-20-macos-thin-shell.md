# HANDOFF — macOS thin-shell client — 2026-09-20

Written for a FRESH session to pick up cold. Read this whole file first.
Predecessor (full history, sessions 1-8): /home/trs/ZTLP-MAC-PLAN-2026-09-19.md
Companion (older, superseded): HANDOFF-2026-09-14-mac-simple-direct-connect.md

## TL;DR

The macOS app now works end to end on Steven's own MacBook, as a real
user, in Safari, against the AWS defcon.ztlp demo zone. Every task in the
original plan (1-7) is DONE. This doc is Task 8.

BUT: it worked only after four bugs were fixed live and two manual
Terminal steps that a real user must never have to do. Those two manual
steps are the real remaining work, plus a UI redesign Steven asked for
at the end of the session (see "NEXT: single-page Home" below).

Repo tip: main @ 775869d (v0.35.11). Three UNCOMMITTED working-tree
changes exist (see "Uncommitted state"). Ask Steven before committing.

## What is proven (live, human-verified, 2026-09-20)

On Steven's MacBook (Apple Silicon, macOS 26, ssh stevenprice@10.78.72.114):
  - /Applications/ZTLP.app — Developer ID signed, hardened runtime,
    notarized + stapled. `spctl -a -vvv` -> accepted, Notarized Developer ID.
  - SMAppService root LaunchDaemon (org.ztlp.agent) registers from the
    app and runs: `launchctl print system/org.ztlp.agent` -> state =
    running, active count = 1, program = Contents/Helpers/ztlp inside
    the bundle. Survives via KeepAlive/RunAtLoad.
  - lo0 aliases, /etc/resolver/defcon.ztlp, CA in System keychain: all
    written by the root daemon, zero human sudo for the steady state.
  - Safari https://demo-dashboard.defcon.ztlp/ -> loads, no cert
    warning, hmac_verified:true, authenticated:true,
    node name steven-macbook-daemon-0920.defcon.ztlp.
Same result earlier in the day on MACLLM4 (build box, 10.99.0.14).

## The four bugs found and fixed this session

### B1. SMAppService refused to spawn the daemon (launchd level)
Symptom: app says "service was installed but did not answer within 15s".
`launchctl print` -> job state = spawn failed, last exit code = 78
(EX_CONFIG), runs climbing, log files never touched (binary never ran).
Cause: Apple Development signing is NOT enough for a privileged
(system-domain, root) LaunchDaemon via SMAppService on macOS 26. Needs
Developer ID AND notarization. `spctl` said "Unnotarized Developer ID"
-> rejected. Developer ID alone (un-notarized) still failed identically.
Fix (build recipe, not code):
  xcodebuild ... CODE_SIGN_IDENTITY="Developer ID Application"
    CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM=5527A7TH5P
    ENABLE_HARDENED_RUNTIME=YES CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO
    OTHER_CODE_SIGN_FLAGS="--timestamp --options runtime"
  then xcrun notarytool submit --keychain-profile ztlp-notary --wait,
  then xcrun stapler staple.
Scripts on MACLLM4: /Users/trs/build-ztlp-release-devid.sh,
/Users/trs/notarize-ztlp.sh. BOTH must run in a GUI Terminal on the
Mac (login keychain unreachable over plain SSH — F6 in the plan).
Notary creds cached in keychain under profile "ztlp-notary" (Apple ID
priceflex@gmail.com, team 5527A7TH5P). First notarize attempt failed
on: no secure timestamp, no hardened runtime, get-task-allow
entitlement present — the flags above fix all three.
Gotcha: after a rebuild, SMAppService kept the STALE registration.
Settings -> Uninstall -> Install was required to pick up the new
bundle. Suspect this first whenever a new build "doesn't answer".
Gotcha: a pending Program License Agreement on developer.apple.com
blocks creating new cert types in Xcode ("Unable to process request -
PLA Update available"). Accept it on the web first.
STATUS: FIXED, recipe documented. Not yet in CI/release.yml — release
builds of the Mac app are still unsigned/un-notarized. Follow-up.

### B2. NS rejected every token that carries a callback URL
Symptom: `ztlp setup --token <uri with &callback=>` -> "NS server
rejected the request (enrollment may not be configured)". Misleading
message; enrollment was configured fine.
Cause: proto/src/enrollment.rs serializes callback_url into the signed
binary token (flag bit 0x02, crf-mpxh CWE-918 fix) and the CLI sends
that full binary to NS. ns/lib/ztlp_ns/enrollment.ex parse_token/1 only
knew flag bit 0x01 (gateway). It read max_uses/expires/nonce/mac from
the wrong offset -> {:error, :invalid_format} -> wire 0x08 0x06.
Fix: ns/lib/ztlp_ns/enrollment.ex — skip a length-prefixed string when
bit 0x02 is set, mirroring the gateway skip. NS never uses the callback.
Applied to: /home/trs/ztlp (UNCOMMITTED), ubuntu@44.240.16.59:~/ztlp/ns
(working tree; container rebuilt + restarted, running now).
Verified: CLI enrollment with callback -> "Bootstrap confirmed token
redemption (HTTP 200)".
TODO: add an ExUnit test in ns/test/ztlp_ns/enrollment_test.exs that
round-trips a token with a callback through parse_token. Not written.
This affects PRODUCTION NS too (same code) — any Launch/Bootstrap-
minted token with a callback would fail against an un-patched NS.
Check whether prod NS is on this code path before assuming it works.

### B3. App Transport Security blocked the app's callback POST
Symptom (app): "Enrollment failed: The resource could not be loaded
because the App Transport Security policy requires the use of a secure
connection."
Cause: EnrollmentViewModel confirms enrollment via URLSession (ATS
applies). The CLI uses curl (ATS does not apply), so the CLI path never
showed this. The demo callback endpoint is plain http on a raw IP.
Fix: macos/ZTLP/ZTLP/Resources/Info.plist — NSAppTransportSecurity /
NSExceptionDomains / 44.240.16.59 / NSExceptionAllowsInsecureHTTPLoads.
Scoped to that one IP, marked DEMO-ONLY in a plist comment. UNCOMMITTED
on Linux and MACLLM4. Remove when the demo has an https callback.

### B4. Fresh Mac: daemon crash-loops, app can never enroll it
Symptom: after the app's own enrollment succeeds ("Enrolled!"), banner
"Could not reach the root service to finish DNS/HTTPS setup (connect()
failed (errno 60))". Home "Connecting" spins forever.
`launchctl print` -> job state = exited, last exit code = 1, runs
climbing. agent.stderr.log: "failed to load identity from /Library/
Application Support/ZTLP/.ztlp/identity.json ... Run `ztlp setup`".
Cause: chicken-and-egg. SMAppService register() starts the daemon
immediately (RunAtLoad). The daemon exits 1 when it has no identity.
The app's Task-6a "enroll the daemon" step needs the daemon UP to send
the enroll control command. It is never up long enough. MACLLM4 never
showed this because its daemon HOME had been seeded by hand in session 4.
Workaround used (manual, sudo, defeats the one-click goal):
  sudo env HOME="/Library/Application Support/ZTLP" \
    /Applications/ZTLP.app/Contents/Helpers/ztlp setup \
    --token "<fresh ztlp://enroll/...>" --name <unique> --yes \
    --relay-secret <zone relay secret>
  then `sudo launchctl kickstart -k system/org.ztlp.agent`.
Then a SECOND manual gap: `ztlp setup` does not run ca-init, so the
daemon came up with "TLS: disabled" — https failed (curl: tlsv1 alert
protocol version; Safari would have warned). Needed:
  sudo env HOME=... ztlp admin ca-init --zone defcon.ztlp
  sudo launchctl kickstart -k system/org.ztlp.agent
  sudo env HOME=... ztlp agent install-ca-cert
Scripts left on Steven's MacBook: ~/seed-daemon.sh, ~/fix-tls.sh,
~/verify-dashboard.sh, ~/check-tls.sh.
STATUS: NOT FIXED. This is the #1 product gap. See "NEXT".

## Demo scaffolding created this session (not in git, not production)

The Swift app REJECTS tokens with no callback_url (session-5 CWE-287
hardening — deliberate, keep it). The defcon.ztlp demo zone has no
Bootstrap (Rails) or Launch (ztlp.net) behind it, and www.ztlp.net was
unreachable this session. So:
  ubuntu@44.240.16.59:/tmp/ztlp-demo-mint-and-callback.py
    mint --callback <url>  -> signed ztlp://enroll/?...&callback=...&nonce=&mac=
                              (Python port of serialize_without_mac +
                              HMAC-BLAKE2s, same zone secret NS trusts)
    serve --port 8765      -> stub POST /api/enrollment/confirm, always 200
  Running via nohup (will NOT survive a reboot of the AWS box).
  Lightsail firewall: TCP 8765 opened via boto3 open_instance_public_ports
  on instance "ztlp-defcon-demo-vm" (us-west-2). boto3 needs
  AWS_SHARED_CREDENTIALS_FILE=/home/trs/.aws/credentials and
  AWS_CONFIG_FILE=/home/trs/.aws/config set explicitly — the Hermes
  session HOME is a sandboxed profile dir, not /home/trs.
This stub is unauthenticated and accepts anything. It is NOT a template
for tenant deployments. It exists only so the app's callback check has
something to hit. Replace with a real Launch/Bootstrap callback (https)
and delete the B3 ATS exception together.

Token minting for the demo (single-use, 24h):
  ssh -i ~/.ssh/ztlp-defcon-demo.pem ubuntu@44.240.16.59 \
    'python3 /tmp/ztlp-demo-mint-and-callback.py mint \
     --callback http://44.240.16.59:8765/api/enrollment/confirm'
Relay secret for the app's SecureField / --relay-secret:
  grep it from ~/ztlp/demo/defcon-cloud-compose.yml on the AWS box
  (ZTLP_RELAY_REGISTRATION_SECRET). Do not retype 64-hex by hand.

## Uncommitted state (as of end of session)

/home/trs/ztlp (main @ 775869d):
  M ns/lib/ztlp_ns/enrollment.ex        <- B2 fix. COMMIT (with a test).
  M macos/ZTLP/ZTLP/Resources/Info.plist <- B3 ATS exception. Commit or
                                           gate behind a demo build flag —
                                           Steven's call.
  M desktop/src-tauri/Cargo.lock        <- 1-line drift from a local
                                           `cargo build --bin ztlp-desktop`
                                           in session 6. Probably discard.
  ?? HANDOFF-2026-09-14-mac-simple-direct-connect.md  (older, keep or fold)
  ?? docs/plans/2026-09-19-relay-auth-v3-identity-signed.md (V3 design, keep)
  ?? this file
MACLLM4 /Users/trs/ztlp: M Info.plist only (same as above). ns/ patch NOT
  applied there (Mac doesn't build NS; irrelevant).
AWS ~/ztlp/ns: enrollment.ex patched in working tree, image rebuilt.

Ask Steven before every commit/push. Split tests vs lib fixes.

## NEXT (in Steven's priority order)

### 1. Single-page Home — Steven's UI direction (end of session, verbatim intent)
"I want just one page. Move identity, service, and enrollment all onto
the Home page so the user knows what is required before connecting. And
it should just connect — this is not a VPN, this is an identity network.
There is no connection required until the user goes to a website and DNS
triggers the connection."

Implications for the Swift app (macos/ZTLP/ZTLP/):
  - MainWindow.swift: drop the 3-tab sidebar (Home / Services /
    Settings). One view. Keep Settings reachable only for advanced/rare
    things (Factory Reset, Uninstall Service, logs) — a gear icon or
    menu item, not a primary tab. ServicesView/IdentityView/
    OnboardingView content folds into Home or is removed.
  - HomeView.swift: replace the hero "Tap to connect" ring + Connecting/
    Connected state machine with a READINESS CHECKLIST. Three rows, each
    with a state badge and a single action:
      1. Identity      — Enrolled as <name>.<zone> / Not enrolled [Enroll]
      2. Service       — Running / Not installed [Install] /
                         Needs approval [Open Login Items]
      3. Network ready — HTTPS trusted · DNS routed  (from daemon
                         status_line) / Waiting for service
    Then one line of guidance: "Open any https://<name>.<zone> site in
    your browser. ZTLP connects on demand." No Connect button.
    Traffic bar / duration timer: remove (there is no session).
  - TunnelViewModel.swift: keep the 2s daemon poller and DaemonSnapshot;
    delete toggleConnection() semantics. "Disconnect" (= SMAppService
    unregister) becomes "Uninstall service" in Settings only.
  - Enrollment stays the session-5 hardened flow (FFI identity + server
    callback required). Relay-secret SecureField stays (plan §4a option B).
  - Order-of-operations must be enforced by the checklist, which is
    exactly what fixes the user-facing half of B4: you cannot enroll the
    daemon before the service row is Running; the UI says so.

### 2. Fix B4 for real (daemon side) — needs Steven's go, protocol/lifecycle change
Pick one (or a and b):
  a. proto: on macOS, when identity.json is missing, `ztlp agent start`
     should NOT exit 1. Stay alive, bind the control socket only, answer
     status with {enrolled:false}, and accept the "enroll" command. The
     daemon is then always reachable and the app's enroll-the-daemon
     step just works. This is the clean fix.
  b. proto: after the daemon-side `ztlp setup` succeeds via the enroll
     control command, also run ca-init + install-ca-cert (or have
     `setup` do it when invoked by the daemon). Today a fresh daemon
     enrolls with TLS disabled and no CA — Safari would warn.
  c. Swift: retry the daemon connect with backoff (currently one 15s
     window) — mitigates a, does not fix it.
  All behind cfg!(target_os="macos"). Windows/Linux paths untouched.
  TDD; ask before commit.

### 3. Release pipeline
  .github/workflows/release.yml builds the Mac app unsigned. Add
  Developer ID signing + notarization (needs the cert + an app-specific
  password or App Store Connect API key as GitHub secrets). Until then
  every macOS release artifact will hit B1 on first launch.

### 4. Tests for B2
  ns/test/ztlp_ns/enrollment_test.exs: token with callback (flag 0x02)
  parses; token with gateway+callback (0x03) parses; MAC still verifies.

### 5. Cleanup
  - AWS: turn the stub callback into a systemd unit or docker service
    if the demo needs to outlive a reboot; or delete it once a real
    callback exists. Close TCP 8765 in Lightsail when done.
  - Remove the B3 ATS exception when the callback is https.
  - Steven's MacBook: ~/seed-daemon.sh contains a consumed token — safe
    but delete. ~/ZTLP-for-steven.zip in Downloads can go.
  - MACLLM4 still has the legacy /Library/Application Support/ZTLP/.ztlp
    config seeded by hand in session 4 (identity mac-llm4-0919). Fine
    for the build box; do not mistake it for a fresh-Mac test.

## Paste-and-go (verified this session)

Boxes:
  ssh trs@10.99.0.14                                   # MACLLM4 build box
  ssh stevenprice@10.78.72.114                         # Steven's MacBook (no passwordless sudo)
  ssh -i ~/.ssh/ztlp-defcon-demo.pem ubuntu@44.240.16.59   # AWS demo

Daemon health on any Mac (no sudo needed for the last two):
  sudo launchctl print system/org.ztlp.agent | grep -E "state|active count|last exit|program"
  dscacheutil -q host -a name demo-dashboard.defcon.ztlp
  curl -sS -o /dev/null -w "HTTP %{http_code} ssl=%{ssl_verify_result}\n" https://demo-dashboard.defcon.ztlp/api/health

Move a fresh build onto a Mac (quarantine + App Translocation gotcha):
  on build box:  ditto -c -k --keepParent ~/ZTLP.app ~/ZTLP.zip
  on target:     xattr -cr ~/Downloads/ZTLP.app && mv ~/Downloads/ZTLP.app /Applications/ && open /Applications/ZTLP.app
  (running from ~/Downloads gives a randomized /private/var/.../AppTranslocation
   path and SMAppService registration then points at a temp dir — always
   move to /Applications first. `ps aux | grep ZTLP` shows the real path.)
  App is LSUIElement=true: no Dock icon, look in the menu bar.

Pitfalls that cost time today:
  - Long single-line commands pasted into Steven's Terminal lost their
    spaces ("env: setup: No such file or directory"). Write a .sh via
    ssh heredoc and have him run the file.
  - `spctl -a --type execute` on Contents/Helpers/ztlp says "rejected
    (does not seem to be an app)". Harmless; the bundle-level check is
    the one that matters.
  - macOS system curl (LibreSSL) reports "tlsv1 alert protocol version"
    when the agent has TLS disabled. That is a "no cert served" symptom,
    not a cipher problem. Check agent.stderr.log for "TLS: disabled".
