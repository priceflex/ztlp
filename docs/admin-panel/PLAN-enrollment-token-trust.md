# Admin panel: complete enrollment tokens (relay secret, NS key, domain pin) + device pickup

Status: v0.5.0 deployed 2026-10-27 00:00Z, v0.5.1 00:10Z (device relay secret); v0.5.2 = CodeRabbit fixes. Operator OK: "Make sure that the relay secrets, the name server, and
anything else we need go into the enrollment token ... and the pin for the domain."

## Why
- ChooseForce users are not in the portal: their devices were enrolled with CLI tokens (KEY record
  only). The portal's chooseforce.ztlp zone has no secrets, so it can mint nothing.
- Portal tokens carried only flags 0x01/0x02. The relay secret was a separate `--relay-secret` on the
  command line, and the NS key (0x10) was missing, so portal-enrolled devices kept TOFU pins and broke
  whenever a gateway cert changed (the admin.trs.ztlp stale-pin incident).

## What goes in the token (proto/src/enrollment.rs is the source of truth)
| Flag | Field | Panel source |
|---|---|---|
| 0x02 | callback URL | panel public URL (existing) |
| 0x08 | relay registration secret | zone relay secret (`zone:set_secret[relay]`) |
| 0x10 | home NS Ed25519 public key | new `zones.ns_pubkey_hex` (NS logs "NS registration public key") |

The domain pin is NOT a token field, by design: with 0x10 the device verifies the NS-signed SVC record
and takes the gateway's `quic_cert_sha256` from it (no TOFU pin files). A pin baked into the token would
go stale on the next cert rotation, which is the failure being fixed. Today's SVC fingerprints match the
gateways' certs (admin 8bcbbbd1, chooseforce 786f77e8).

The Ruby minter is held to the shared cross-language vector
`proto/tests/fixtures/enrollment_token_all_flags.hex` (also enrolled by the NS test suite).

## Device pickup
The client only calls the panel back for query-param tokens (token_id); binary tokens never call back.
So the panel finds the device itself: the setup command carries `--name <device>`, and a job (plus a
"Check now" button) looks up KEY `<device>.<zone>` on the NS. Found and newer than the token = the
device row is created (enrolled, node id + key from the KEY record, owner = the token's user) and the
enrollment is marked redeemed. The same lookup adopts an already-enrolled device by name (Heidy's
laptop) without re-keying it.

## Rollout
1. Code + tests, gate, PR, CI.
2. Prod: backup, deploy (web+jobs only), set chooseforce.ztlp secrets on-box from the NS .env (never
   leave the box), set ns_pubkey_hex for both zones.
3. Test enrollment with a throwaway device name from a real client; verify ns_trust.toml, KEY, the
   panel device row, and a connection to www.chooseforce.ztlp through the NS-anchored path.
4. Add Heidy + Carina; adopt Heidy's current laptop; mint their re-enrollment tokens.

## Finding from the live test (v0.5.1): two relay secrets
A device enrolled with a v0.5.0 token (relay secret = the zone's per-zone `ZTLP_HMAC_SECRET_CHOOSEFORCE_ZTLP`)
reached www.chooseforce.ztlp directly but NOT through the relay: `CLIENT_ROUTE ... rejected: invalid HMAC
(zone=www)`. The relay derives the zone from the gateway's SERVICE name (`www`), not the DNS zone, and then
falls back to its legacy registration secret. So:
- `relay_secret_ct` stays the gateway's per-zone secret (install script `ZTLP_HMAC_SECRET_<ZONE>`).
- New `device_relay_secret_ct` is what tokens carry: one the relay accepts for every service a device dials
  (today the relay's `RELAY_REGISTRATION_SECRET`, the same one the CLI tokens carried). Falls back to
  `relay_secret_ct` when unset. Set with `rails zone:set_secret[device_relay]` (64 hex or 48 alnum).
- Longer term: zone-specific gateway service names (or CLIENT_ROUTE_V2 `gw:<zone>`) would let a per-zone
  device secret work and stop sharing one relay secret across customers. Not in this change.

## Review fixes (v0.5.2, CodeRabbit on PR #125)
- Pickup only trusts NS answers SIGNED by the zone's NS key (`NsClient.query_verified`, same contract as
  proto/src/ns_verify.rs: trusted signer, Ed25519 over the canonical bytes, unexpired, right name/type,
  not `registered_unsigned`). A zone without `ns_pubkey_hex` cannot pick up or adopt devices.
- Revoked users get no device from pickup or adopt.
- `redeemed_at` is set on pickup; one token's database error no longer stops the job; Check now shows a
  message instead of a 500 on a conflict.
