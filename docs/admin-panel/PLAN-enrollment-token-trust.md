# Admin panel: complete enrollment tokens (relay secret, NS key, domain pin) + device pickup

Status: BUILT 2026-10-26 (v0.5.0, PR below); prod rollout per the steps at the end. Operator OK: "Make sure that the relay secrets, the name server, and
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
