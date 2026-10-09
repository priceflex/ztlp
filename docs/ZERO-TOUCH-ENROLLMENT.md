# Zero-touch enrollment: tracker

**Goal.** A user installs the ZTLP service and enrolls themselves. Nothing else.
No PowerShell, no config editing, no copying secrets, no admin on the box, no
second visit from support. Every internal ZTLP site then opens in a normal
browser.

This file is the standing record of every place that goal broke, what fixed it,
and the test that stops it coming back. Add a row for every new failure. A
release that touches the agent, enrollment, the relay or a gateway must pass the
acceptance check at the bottom first.

Found during the first real fresh enrollment of a user machine (2026-10-08/09),
which is the first time anyone had enrolled a device that was not the author's
own. Every item below was invisible on the hand-built dev boxes.

## Issues

| ID | Symptom the user saw | Root cause | Status | Regression guard |
|----|----------------------|------------|--------|------------------|
| ZT-01 | Panel/site 504s after enrolling | Relay runs in prod HMAC mode; the enrollment token carries no relay secret, so the agent signs `CLIENT_ROUTE` with a zero MAC and the relay drops it | **Fixed v0.35.17 in code.** Token flag `0x08` carries the secret (MAC-covered); `ztlp admin enroll --relay-secret-file` embeds it; `ztlp setup` writes it to `agent.toml`; the NS skips the field and rejects unknown flags. **Operator step still required:** mint tokens with `--relay-secret-file`. Tokens minted without it behave as before | `relay_secret_*` in `enrollment.rs` (8 tests), `effective_relay_secret_*` and `enrollment_token_secret_ends_up_in_a_loadable_agent_toml` in `ztlp-cli.rs`, 4 NS tests in `enrollment_test.exs`. Acceptance check step 3 |
| ZT-02 | `www.<other-zone>.ztlp` "DNS name does not exist" | Windows installed an NRPT rule only for the enrolled zone; the agent's resolver was never asked about other zones | **Fixed v0.35.16** | `windows_startup_plan_nrpt_always_includes_ztlp_umbrella` and 3 siblings in `windows_daemon.rs` |
| ZT-03 | Site never loads; relay logs `invalid HMAC (zone=...)` for the gateway | Relay hex-decodes a 64-hex zone secret, the Rust gateway signs with the raw text (F20), so the gateway can never register | **Worked around** by using non-hex zone secrets. Code fix still open | None. Acceptance check step 4 asserts every gateway shows `Registered dynamic gateway` |
| ZT-04 | One of two services works, the other fails with `QUIC certificate fingerprint ... does not match` | TOFU pin key for a relayed dial was `localhost@<relay ip>:<relay port>`, shared by every service behind the relay, so the second gateway's different self-signed cert looked like a MITM | **Fixed v0.35.17** | `relay_pin_key_is_per_service` and siblings in `quic_transport.rs` |
| ZT-05 | Browser shows the "Checking everyone's name tag" card forever, curl works | A relayed dial takes about 1.2 s (750 ms dead direct candidate + relay handshake), longer than the 1 s splash grace. The poll flipped to ready, the reload dialed again, missed the grace again, got the splash again: an endless loop | **Fixed v0.35.17** | `ready_host_slow_dial_browser_waits_instead_of_resplashing`, `not_ready_host_slow_dial_still_gets_splash`, `expired_ready_does_not_suppress_splash` in `splash_gate.rs` |
| ZT-06 | Gateway recreate breaks every client until they clear a pin | Self-signed gateway cert is regenerated on container recreate; every client's TOFU pin goes stale | **Fixed v0.35.17 in code.** Set `ZTLP_QUIC_CERT_DIR` to a mounted volume and the gateway reuses one cert across restarts. **Operator step still required:** mount the volume and set the variable on every gateway. Unset = old behaviour (fresh cert per start) | `persisted_*`, `corrupt_persisted_*`, `unwritable_cert_dir_*`, `without_a_cert_dir_*`, `blank_cert_dir_*` in `quic_transport.rs`. Ops rule until every gateway is migrated: never recreate a gateway without the volume |
| ZT-07 | Gateway advertises an IPv6 literal the agent rejects as `invalid remote address` | Address parse of `[v6]:port` fails; harmless (direct path is unreachable anyway) but adds latency and noise | **Open**, low | None yet |
| ZT-08 | Direct dial wastes 750 ms before every relay dial | Gateway advertises a private/LAN address a remote client can never reach | **Open**, low. Fix: skip RFC1918 candidates when the client is not on that network, or probe in parallel | None yet |

## Operator checklist for a new gateway or relay (these cannot be fixed in the client)

1. Zone secret: use a **non-hex** value (48 alphanumeric characters) until ZT-03 is fixed in code. A 64-hex secret never registers.
2. Gateway: mount a volume and set `ZTLP_QUIC_CERT_DIR` (ZT-06) so a recreate keeps the cert.
3. Enrollment tokens: mint with `ztlp admin enroll ... --relay-secret-file <file>` (ZT-01), short expiry, `--max-uses 1`.
4. After the gateway starts, confirm the relay logs `Registered dynamic gateway` for it (acceptance check step 4).

## How these were missed

* Every earlier test ran on the author's own machines, which had hand-added
  state (a broad `.ztlp` NRPT rule, a relay secret, pinned certs, one service
  used at a time).
* Tests asserted a tool's output (curl `200`, a green CI job) and not what the
  user sees. curl is not a browser: it never gets the splash page. ZT-05 sat
  behind curl `200` for two days.
* Fixes were verified as an admin SSH user. The service and the browser run as
  different identities.

## Acceptance check: run before every release that touches the agent, enrollment, relay or a gateway

Run on a **freshly enrolled, never-touched** Windows machine, as the **real
logged-in user**, using a **real browser** (headless Chrome driven as that user
is acceptable). Nothing may be pre-configured by hand.

1. Install the release installer. Enroll with a token only. Do not touch any config file.
2. Without a restart or any other action, open **two different zones** in the
   browser (for example the admin panel and a customer site). Both must render
   the real page (not the splash card) within 10 s of the first load.
3. `agent.toml` must contain a working relay secret that came from the token.
4. On the relay: every gateway behind it logs `Registered dynamic gateway`, none logs `invalid HMAC`.
5. Reload each site 5 times: no splash loop, no certificate error.
6. Restart the service and repeat step 2.
7. Record the result in the release notes.

If any step needs a human to run PowerShell or edit a file, that is a new row in
the table above and the release does not ship.

## Rule for future fixes

A fix is not done until (a) a test fails without it, (b) the row above is
updated, and (c) the acceptance check passes as the end user. "curl returns 200"
does not count.
