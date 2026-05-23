# Dashboard surfaces for BS-PR-5

BS-PR-5 surfaces two new model layers in the Bootstrap admin UI:

1. **API Clients** — manage the `api_clients` allowlist that gates
   the `/api/v1/*` ZTLP-secured API namespace.
2. **Device Communication Grants** — manage which `ZtlpDevice` may
   initiate communication to which.

These are restart-free Rails additions; no infra touch.

---

## API Clients

**Route:** `GET /admin/api_clients` (super_admin only)

**Why super_admin only:** an API client row authorizes a system to
call the v1 API. Issuing one is roughly equivalent to issuing an
admin credential — keep it tight. The kill switch (`Deactivate`)
also belongs in super_admin land.

### What this page does

| Action | UI | Result |
|---|---|---|
| List | `GET /admin/api_clients` | Table of every client, grouped by zone, with status / last_used_at / notes |
| Create | `+ New API Client` button | New `api_clients` row + `api_client.created` audit log |
| Edit | `Edit` link in row | Update notes / toggle active checkbox + `api_client.updated` audit log |
| Deactivate | `Deactivate` button | Flips `active=false` (rejects auth on next call) + `api_client.deactivated` audit log |
| Reactivate | `Reactivate` button | Flips `active=true` + `api_client.reactivated` audit log |
| Delete | `Delete` button (confirms) | Hard-deletes row + `api_client.deleted` audit log. Use **Deactivate** instead for a reversible kill switch. |

### What this page does NOT do

- It does NOT show or set the per-zone HMAC secret. Secrets live in
  the environment (`ZTLP_HMAC_SECRET_<UPCASE_ZONE>`), shared with the
  relay/gateway. This page only manages who is *authorized* to call
  the API; the HMAC is the *credential*.
- It does NOT pre-validate that a per-zone secret env var exists for
  the zone you typed. If you create an `api_client` for a zone with
  no `ZTLP_HMAC_SECRET_<ZONE>` set, authentication will fail with
  reason `no_zone_secret` (server-side log only — see
  `docs/api_v1_ztlp_secured.md`).

### Typical operator flow

1. Operator provisions a new tenant via ztlp.net (this part is
   automated in BS-PR-4 — pending).
2. Operator sets `ZTLP_HMAC_SECRET_<UPCASE_ZONE>` on the bootstrap
   container.
3. Operator visits `/admin/api_clients`, clicks `+ New API Client`,
   enters the zone + a client name (e.g. `z2ls.acme`).
4. Operator hands the per-zone secret to whoever runs the Z2LS
   instance for that zone. Z2LS can now call
   `POST /api/v1/enrollment_tokens` (BS-PR-3) and other v1 endpoints.

### Kill switch

To immediately stop a Z2LS instance from minting more enrollment
tokens (e.g. credentials suspected compromised):

1. `/admin/api_clients`, find the row, click `Deactivate`.
2. The next call from that client returns 401 — the authenticator
   refuses inactive rows.
3. To restore, click `Reactivate`. The row is preserved (the audit
   trail is intact), so this is reversible.

If you suspect the per-zone HMAC secret itself is compromised, you
also need to rotate `ZTLP_HMAC_SECRET_<ZONE>` on the bootstrap host
(see `docs/api_v1_ztlp_secured.md` § "Rotating a per-zone secret").
The Deactivate path alone does not change the secret.

---

## Device Communication Grants

**Route:** `GET /networks/:network_id/device_communication_grants`
(any signed-in admin)

**Why scoped to a network:** a grant is always between two devices
in the SAME network. The nested URL space reflects that invariant —
the source/target dropdowns on the New Grant form only show the
network's own devices.

### What this page does

| Action | UI | Result |
|---|---|---|
| List | Index page | Table of every grant whose source is in this network. Active grants are full opacity; revoked grants are dimmed. |
| Create | `+ New Grant` button | New `device_communication_grants` row + `device_grant.created` audit log |
| Revoke | `Revoke` button in row | Sets `revoked_at = now`. **Idempotent** — second click shows "already revoked" alert. + `device_grant.revoked` audit log on the first revoke only. |
| Delete | `Delete` button | Hard-deletes the row (audit trail loses this grant). Use **Revoke** instead unless the row was created in error. |

### Grant directionality

Grants are **directional**. A → B means "A is permitted to initiate
communication to B." If you also need B → A, create a second grant
in the opposite direction.

The model enforces this — the unique index is on the **ordered**
`(source_device_id, target_device_id)` pair. The same pair in
reverse is a separate row.

### Cross-network grants

The model rejects them. Both source and target must belong to the
same `Network`. The controller also enforces it at the URL layer:
walking `/networks/<A>/device_grants/:id` for a grant whose source
belongs to network B returns 404, not 403 — the lookup is scoped to
the network's devices.

### Future: gateway enforcement

Today the grants table is dashboard-only. A future PR will wire up
the ZTLP gateway to consult it before forwarding QUIC streams —
that's the layer where the grant actually becomes a runtime
permission check. Until that lands, the grants are advisory: they
record operator intent for audit purposes but don't gate traffic.

The dashboard contract above is stable; gateway enforcement will
read from the same table without schema changes.

## References

- `app/controllers/admin/api_clients_controller.rb`
- `app/controllers/device_communication_grants_controller.rb`
- `app/models/api_client.rb` (BS-PR-2)
- `app/models/device_communication_grant.rb` (NEW, BS-PR-5)
- Tests: `test/controllers/admin/api_clients_controller_test.rb`,
  `test/controllers/device_communication_grants_controller_test.rb`,
  `test/models/device_communication_grant_test.rb`
- Auth contract: `bootstrap/docs/api_v1_ztlp_secured.md`
- Enrollment lifecycle: `bootstrap/docs/enrollment_token_lifecycle.md`
