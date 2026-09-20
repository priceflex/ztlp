# HANDOFF — macOS single-page app + B4 fix — 2026-09-20 (session 9)

Fresh-session pickup doc. Predecessor: HANDOFF-2026-09-20-macos-thin-shell.md
(read it for the four bugs B1-B4 and the demo scaffolding). Full history:
/home/trs/ZTLP-MAC-PLAN-2026-09-19.md.

## TL;DR

All five NEXT items from the previous handoff were worked. Everything is
committed AND pushed to origin/main (775869d -> 591715a, 5 commits).
Steven said "you don't need to release on GitHub" -> release.yml
signing/notarization (item 3) was DROPPED; signed builds stay a manual
GUI-Terminal step on MACLLM4 (script below).

What is still UNPROVEN: the Swift changes have NOT been compiled on a Mac
(no swiftc on the Linux box). The Rust B4 changes HAVE been compiled and
unit-tested natively on MACLLM4. Two scripts are waiting for Steven.

## Commits (main)

  4e071d0 test(ns): pin FLAG_HAS_CALLBACK (0x02) enrollment token parsing
  2a37190 fix(ns): skip callback_url when FLAG_HAS_CALLBACK is set (B2)
  34ce9aa fix(agent,macos): unenrolled standby + post-enroll TLS provisioning (B4)
  f354ebe chore(macos): DEMO-ONLY ATS exception for the defcon demo callback IP (B3)
  591715a feat(macos): single-page Home readiness checklist, no Connect button (Task 8)

## DONE (verified)

- B2 tests: ns/test/ztlp_ns/enrollment_test.exs 22 tests / 0 failures with
  the fix; RED (2 failures) confirmed against the old parser first.
  `mix compile --warnings-as-errors` clean. Elixir: ~/elixir-1.15/bin on the
  Hermes VM, ZTLP_CA_PASSPHRASE must be set.
- B4 daemon side (proto/, cfg macOS only, Linux/Windows untouched):
  a. `daemon::should_enter_unenrolled_standby` + `run_unenrolled_standby`:
     no identity.json -> serve ONLY the control socket (status/setup_status
     -> {standby:true, identity_enrolled:false}; enroll; shutdown; bearer
     gate intact), lo0 alias + agent.token GUI-readable done first, poll
     identity.json 1s, then continue into the full daemon IN THE SAME
     PROCESS (`cmd_agent_start` in ztlp-cli.rs runs standby BEFORE loading
     config so the just-written agent.toml/config.toml are honored).
     Corrupt identity.json still fails loudly.
     `control::handle_standby_request_line` is the standby dispatcher.
  b. `control::build_post_enroll_tls_plan` + cmd_enroll: after `ztlp setup`
     succeeds the daemon re-execs `admin ca-init --zone <zone>` (skipped if
     ca/root.key exists) then `agent install-ca-cert --cert <root.pem>`.
     Response gains tls_provisioned:bool and tls_warning:string.
  Tests: 2 tokio tests in daemon.rs (`unenrolled_standby_tests`), 3 in
  control.rs (`post_enroll_tls_plan_*`). Pass on Linux AND on MACLLM4
  (native macOS run exercises the cfg(macos)=true branch). Release `ztlp`
  built on MACLLM4 (`~/ztlp/proto/target/release/ztlp`).
- Single-page Home (macos/ZTLP/): MainWindow = HomeView + gear -> Settings
  sheet (Cmd+,). HomeView = 3 rows (Service / Identity / Network ready),
  each a badge + at most one action (Install | Open Login Items | Enroll),
  then one guidance line. No Connect button, ring, traffic bar, timer.
  `HomeReadiness.compute(serviceState:, daemonReachable:, daemon:)` in
  TunnelViewModel.swift is pure and drives Home + MenuBar + menu icon.
  Rows gate each other: Enroll is only offered once the daemon answers.
  TunnelViewModel: installService() (SMAppService register + backoff wait
  0.25s->2s cap, 30s), disconnect() = uninstall (Settings only),
  enrollmentDidFinish() re-polls. ServicesView/IdentityView/OnboardingView
  deleted (+ pbxproj entries). ZTLPTests +9 (readiness every branch,
  backoff, standby JSON shape). NOT COMPILED YET — see script 1.
- B3 ATS exception committed as-is (demo-only, commented in plist).
- Cleanup: AWS stub callback moved from /tmp+nohup to
  /etc/systemd/system/ztlp-demo-callback.service (enabled, active, POST
  -> 200). Script kept at /opt/ztlp-demo/. Lightsail TCP 8765 still OPEN
  (needed while the demo uses this callback). The Cargo.lock drift was
  discarded. MacBook leftovers (~/seed-daemon.sh, ~/fix-tls.sh,
  ~/Downloads/ZTLP-for-steven.zip) are removed by script 2 step 0.
- AWS NS container still runs the working-tree enrollment.ex patch (same
  code now in git); nothing to do until the next NS image rebuild.

## WAITING ON STEVEN (two scripts, run in this order)

Script 1 — MACLLM4, GUI Terminal (keychain):   ~/ztlp-mac-build.sh
  ff-only pull of origin/main, copies release ztlp into
  macos/ZTLP/Libraries/ztlp, `xcodebuild test` (want TEST SUCCEEDED),
  Developer-ID signed hardened Release build, notarize (profile
  ztlp-notary) + staple + spctl, zips ~/ZTLP.zip.
  If xcodebuild test FAILS: paste the error lines back to Hermes — the
  Swift has never been compiled. Likely spots: `.background(.quaternary
  .opacity(0.35), in:)` in HomeView (ShapeStyle opacity), `.sheet(...,
  onDismiss:)` argument order, Equatable synthesis on HomeReadiness.
  Then copy ~/ZTLP.zip to the MacBook's ~/Downloads/.

Script 2 — Steven's MacBook:   ~/ztlp-macbook-fresh-test.sh
  Asks sudo once, wipes the OLD daemon state (bootout, rm
  /Library/Application Support/ZTLP/.ztlp, /etc/resolver/defcon.ztlp, CA
  from System keychain) so it is a TRUE fresh-Mac test, installs the new
  app to /Applications (xattr -cr, no App Translocation), then waits while
  Steven uses ONLY the GUI: Install -> (approve) -> Enroll. Verifies:
  daemon "state = running" + STANDBY line in agent.stderr.log (B4a),
  identity.json + ca/root.pem appear (B4b), dscacheutil resolves, curl
  https ssl_verify=0. Final proof = Safari https://demo-dashboard.defcon.ztlp/.
  Paste material: ~/ztlp-enroll-paste.txt on the MacBook (single-use token
  minted 2026-09-20 ~evening, 24h; relay secret). Re-mint if expired:
    ssh -i ~/.ssh/ztlp-defcon-demo.pem ubuntu@44.240.16.59 \
      'python3 /opt/ztlp-demo/ztlp-demo-mint-and-callback.py mint \
       --callback http://44.240.16.59:8765/api/enrollment/confirm'
  Relay secret = ZTLP_RELAY_REGISTRATION_SECRET in
  ~/ztlp/demo/defcon-cloud-compose.yml on the AWS box (YAML `key: "v"`).

## Known gaps / next

- Swift compile + live fresh-Mac proof (above). Mark Task 8 DONE only after
  Safari loads with no warning on a wiped MacBook.
- Identity row says "Enrolled in <zone>", not "Enrolled as <name>": the
  node name is not persisted anywhere setup_status can read (config.toml
  has no name key). Small follow-up if Steven wants the name shown: write
  `name = "..."` in write_config_file (ztlp-cli.rs) and add node_name to
  SetupStatus.
- Standby `status` response has no dns_listen/vip fields; TunnelViewModel
  handles that (falls back to previous snapshot values / zeros).
- Real https callback (Launch/Bootstrap) still does not exist for
  defcon.ztlp -> B3 ATS exception + the systemd stub + Lightsail 8765 stay.
- release.yml unchanged (Mac artifacts unsigned) — intentional per Steven.

## Pitfalls hit this session

- `git stash push <path>` from a SUBDIRECTORY (ns/) mangled the pathspec
  (":(,prefix:3)ns/ns/...") and failed; the following `git stash pop` then
  popped an UNRELATED older stash and conflicted proto/src/bin/ztlp-cli.rs.
  Recovery: `git checkout HEAD -- <file>`; the stash entry was kept. For a
  RED proof, prefer `git show HEAD:<file> > <file>` + copy-back over stash.
- Store.lookup miss returns bare `:not_found`, not `{:error, _}`.
- Hermes terminal HOME is the profile dir -> ~/.cargo/bin/cargo does not
  resolve; use /home/trs/.cargo/bin/cargo and /home/trs/elixir-1.15/bin.
- Multi-command ssh/scp loops with $(...) get blocked by the approval
  scanner; Steven denied one. Ship .sh files and have him run them.
