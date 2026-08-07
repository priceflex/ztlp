# DEF CON 2026 ZTLP Kali Demo — Session Handoff

**Date:** 2026-08-07
**Model note:** this session ran on Anthropic (claude-opus-4-8 → claude-sonnet-5 mid-session). No functional impact, just noting for continuity.

## Where things stand

The DEF CON ZTLP full-stack demo on the Kali box is **fully working end-to-end** —
identity, gateway routing, live traffic proof, port-forwarding proof, desktop GUI,
and now user minting + role-based access control. Everything below is committed
and pushed to `main` on `git@github.com:priceflex/ztlp.git`.

## Environment quick reference

- **Kali box:** `trs@10.3.2.28`, SSH key `~/.ssh/id_ed25519` (passwordless, reliable)
- **Canonical repo:** `/home/trs/ztlp` (local machine) — pushed to `git@github.com:priceflex/ztlp.git` main
- **Kali's own checkout:** `~/ztlp` on the Kali box (kept in sync via base64-over-SSH, since direct file transfer tools aren't available)
- **Kali's runtime deployment:** `~/defcon` on the Kali box — this is where `docker-compose.yml` lives and where `docker compose` commands are run
- **Git commit author:** always `-c user.name="Steven Price" -c user.email="steve@techrockstars.com"`
- **GitHub remote:** SSH (`git@github.com:priceflex/ztlp.git`) — HTTPS token was expired, switched over, works fine
- Zone: `defcon.ztlp`. NS server `127.0.0.1:23096` (from Kali). Gateway container `ztlp-gateway-defcon`, NS container `ztlp-ns-defcon`.
- Dashboard: `https://demo-dashboard.defcon.ztlp/` (Flask app, `~/defcon/dashboard/app.py` on Kali)
- Current registered identity: `kali-demo-laptop.defcon.ztlp` (friendly name showing correctly in dashboard)

## What's been built (all committed + pushed to main)

1. **Core DEF CON blockers fixed** (rustls dual-provider panic, gateway tcp: colon-aware routing, NS registration-key persistence, gateway trust-anchor wiring) — see `docs/defcon-2026-kali-buildout-notes.md`
2. **Demo scripts** in `docs/demo-scripts/` (see its own README.md there):
   - `prove-not-docker-port-forwarding.sh` — proves HTTPS traffic uses a ZTLP-managed VIP, not Docker port publishing
   - `live-traffic-demo.sh` — fires live traffic, shows real Prometheus counter deltas + fresh audit log entries (supports `loop` mode for a second screen during the talk)
   - `mint-user-and-show-policy.sh` — mints a real admin user ("crash") + standard user ("alice"), shows role-based policy engine granting/denying access to an admin-only service live
3. **Desktop GUI (Tauri)** — builds and runs on Kali. See `desktop/BUILDING_ON_LINUX.md` for the full build process and toolchain gotchas hit along the way (GCC 15 `.base64` pseudo-op bug, prebuilt tauri-cli binary trick, externalBin sidecar naming requirement). Bundles produced: `.deb`, `.rpm`, `.AppImage` — all verified working via headless Xvfb screenshot test.
4. **Two real protocol bugs found + fixed** while building the user-mint demo:
   - Gateway's `NsClient` sent unpadded UDP queries for USER/GROUP records, tripping NS's anti-amplification truncation defense and silently breaking every role/group lookup
   - `ZTLP_GATEWAY_POLICIES` env var parser split on the first colon only, mangling `role:admin:admin-panel` — role-based and group-based policies never actually worked until this fix

## Relevant markdown files (read these to get full context)

- **`docs/defcon-2026-kali-buildout-notes.md`** — the master retrospective doc. Covers the 4 original blockers (rustls, gateway routing, NS identity persistence, trust anchors), the identity-naming fix, and follow-up work notes. Read this first for the "how did we get here" story.
- **`docs/demo-scripts/README.md`** — usage docs for all 3 demo scripts (port-forwarding proof, live-traffic demo, mint-user-and-policy demo). Read this before running any demo script live.
- **`desktop/BUILDING_ON_LINUX.md`** — full Tauri/Linux build process, the GCC 15 toolchain bug, the tauri-cli prebuilt-binary trick, and the externalBin sidecar gotcha. Needed if the desktop GUI ever needs rebuilding from a fresh clone.

## What's NOT done / open threads

- **No hard blockers currently.** The last completed piece was the mint-user-and-policy demo script, fully verified.
- **Not yet built:** a visual admin-portal vs standard-user-portal distinction in the Flask dashboard itself (the mint-user script proves the policy engine works via CLI/RPC, but the dashboard UI doesn't yet render two different views based on role). If Steven wants the *browser* to visually show "logged in as crash (admin) → sees admin panel" vs "logged in as alice → doesn't", that's the next lift — would need the dashboard to read the `X-ZTLP-Node-Name` header (or similar) and query `NsClient.user_role` to decide what to render.
- **Desktop GUI is built and verified but not yet enrolled against the real demo identity** — I used a throwaway test identity to prove the Setup Wizard workflow works. If Steven wants to demo the actual desktop app live (as opposed to CLI/browser), it should be enrolled against `defcon.ztlp` for real before the talk, or done live as a wow-moment during the presentation.
- **Connection Manager Tauri desktop app**: confirmed the code + build works, but no one has done a live "click through the wizard against the real demo zone" run yet — only a headless throwaway-identity smoke test.

## Suggested next steps (pick up here)

1. Decide whether to build the admin/standard dashboard portal split (visual, in-browser) or leave the CLI/RPC-based policy demo as sufficient.
2. Decide whether to enroll the desktop GUI against the real `defcon.ztlp` identity ahead of time, or save that as a live "watch me enroll" moment during the talk.
3. Do a full dry run of the DEF CON demo flow start to finish: identity naming → port-forwarding proof → live traffic demo → mint-user/policy demo → (optional) desktop GUI walkthrough.
4. If time allows, consider whether "crash" should be the identity used throughout the whole demo (badge name consistency) rather than mixed with `kali-demo-laptop`.
