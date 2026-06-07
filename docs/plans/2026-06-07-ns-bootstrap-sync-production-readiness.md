# NS → Bootstrap Sync: Production Readiness Followups

**Context:** PR #96 (`feat/ns-bootstrap-sync`) landed the read-only NS → Bootstrap device reconciliation feature. This doc captures what should still be done before flipping `ZTLP_NS_SYNC_ENABLED=true` in production, plus a longer-term roadmap.

**Status of the base feature:**
- PR: https://github.com/priceflex/ztlp/pull/96
- Branch: `feat/ns-bootstrap-sync` (11 commits)
- NS suite: 833 tests, 0 failures
- Bootstrap suite: 1153 tests, 0 failures
- CodeRabbit feedback addressed in `808380e`

**Prod state today (2026-06-07):**
- NS has ~15 device registrations across `tech-rockstars.trs.ztlp`, `adms.trs.ztlp`, `aligned-dental-mgmt-services.trs.ztlp`
- Bootstrap DB has 1 ZtlpDevice row (`hermes-op-z2lsapp1`)
- Bootstrap container is on `tech-rockstars_default` (172.19/16), NS on `ztlpnet_default` (172.18/16) — they cannot reach each other yet

---

## 🔴 Must-have before production

**STATUS: ✅ ALL LANDED in PR #97 (`feat/ns-sync-hardening`).** Items 1-4 below have status callouts noting their commit SHA and any deviations from the original spec.

These three changes prevent foreseeable failure modes that would either hammer NS, leak data, or silently rot.

### 1. Rate-limit `/admin/records` on NS

**Status: ✅ landed in PR #97 (commit `e1c52d7`).** Implementation deviation: created a separate `ZtlpNs.AdminApiRateLimiter` module (not `RateLimiter.check_admin_api/1` as originally specced) so admin-API traffic can't compete with the device-registration token bucket. Same algorithm, separate ETS table, separate threshold.

**Problem:** Single shared HMAC secret with no per-client throttle. A leaked secret OR a Bootstrap stuck in a tight retry loop could hammer NS's Mnesia store at request frequency. The endpoint reads from every record in the store — not free.

**Fix shape:**
- NS already has `ZtlpNs.RateLimiter` (used for registration auth). Reuse it.
- Token bucket per source IP: 12 requests / 60 seconds (matches the 5-minute cron + some retry headroom).
- On exhaustion: return HTTP 429 `Retry-After: <seconds>`.
- Configurable via `ZTLP_NS_ADMIN_API_RATE_LIMIT=12/60` (count/window).

**Files:**
- `ns/lib/ztlp_ns/metrics_server.ex` — wrap `handle_admin_records/4` with a rate-limit check before calling `verify_request/5` (verify is cheap but Store.list_filtered/1 is not).
- `ns/lib/ztlp_ns/rate_limiter.ex` — add `check_admin_api(peer_ip)` if its existing API doesn't fit.
- `ns/test/ztlp_ns/admin_api_http_test.exs` — add tests asserting 429 after threshold + 200 again after window slides.

**Estimated effort:** ~1 hour, ~80 LOC.

### 2. NS-side audit log for SUCCESSFUL `/admin/records` calls

**Status: ✅ landed in PR #97 (commit `7df6d4c`).** Implementation note: rate-limited (429) requests are NOT audited — they're `Logger.warning` only since they're attack signal, not authenticated activity. We don't want audit log floods amplifying a DoS attempt.

**Problem:** Today we `Logger.warning` on 401s but say nothing on 200s. For SOC2/compliance and incident forensics, we need an append-only audit trail of "client X pulled N records at time T."

**Fix shape:**
- Use existing `ZtlpNs.Audit` module (already wired up for other events).
- Emit `{:admin_api_records_pulled, peer_ip: ..., zone_filter: ..., type_filter: ..., count: ..., ts: ...}` on every 200 response.
- Also emit `{:admin_api_auth_failed, peer_ip: ..., reason: ...}` on 401 — currently a `Logger.warning` only.

**Files:**
- `ns/lib/ztlp_ns/metrics_server.ex#handle_admin_records/4` — call `Audit.log/1` on both branches.
- `ns/test/ztlp_ns/admin_api_http_test.exs` — extend to assert audit events were emitted.

**Estimated effort:** ~30 min, ~30 LOC.

### 3. Bootstrap-side exponential backoff on sync failures

**Status: ✅ landed in PR #97 (commits `3eb4fc9` + `cf82fd3`).** Took the recommended "simpler shape" — `Ztlp::SyncState` filesystem JSON at `tmp/ztlp_sync_state.json`, flock-guarded. Rake task gated on `SyncState.due?`. Backoff: 1m → 2m → 4m → 8m → 15m (cap).

**Problem:** The current cron loop runs every 5 minutes unconditionally. If NS is down or the secret is misconfigured, we'll log 12 errors/hour with no relief. The AuditLog table will fill with `status="failure"` rows fast.

**Fix shape:**
- `Ztlp::SyncNsToBootstrap` returns `Result` with a `status` (:ok | :error) and an `error_class` (e.g. `Ztlp::NsAdminClient::TransportError`).
- The rake task writes the last-success / last-failure timestamps to a small `SyncState` table (or Rails cache) before AuditLog.
- The cron loop checks the last failure: if `error_class == TransportError` and `last_failure_at` was <15min ago, skip this tick. If 5xx and <5min ago, skip. Otherwise run.

**Alternative simpler shape (recommended):** push exponential backoff into the rake task itself via a sleeper that respects a `next_retry_at` file. Cron stays dumb; backoff lives in the task.

**Files:**
- `bootstrap/app/services/ztlp/sync_state.rb` (new) — read/write `~/.ztlp_sync_state` JSON file with `last_success_at`, `last_failure_at`, `consecutive_failures`, `next_retry_at`.
- `bootstrap/lib/tasks/ztlp_ns_sync.rake` — gate execution on `SyncState.due?`.
- Backoff formula: `min(15min, 1min * 2 ** consecutive_failures)`.

**Estimated effort:** ~2 hours, ~100 LOC + tests.

### 4. Health visibility — "last successful sync" indicator in dashboard

**Status: ✅ landed in PR #97 (commits `6fb1a12` for the banner + `f06b945` for the JSON endpoint).** Banner appears at the top of `/networks/:id/ztlp_devices`. JSON endpoint at `GET /api/v1/sync_health` (HMAC-gated via existing `Api::V1::BaseController`). Band thresholds: green = <10min + 0 failures; yellow = 10-60min OR 1-2 failures; red = 3+ failures OR >60min OR never synced.

**Problem:** Without UI feedback on sync health, a silent failure (HMAC secret rotated on NS but not BS, or NS DNS resolution broken) means stale data with no operator visibility. The Devices tab will look correct but be hours/days out of date.

**Fix shape:**
- Top of `/networks/:id/ztlp_devices` index view, add a small banner:
  - Green: "Last NS sync: 3 minutes ago ✓"
  - Yellow: "Last NS sync: 12 minutes ago — checking again soon"
  - Red: "Last NS sync FAILED at HH:MM (TransportError). See [audit log](/audit_logs)."
- Pull data from the `SyncState` model added in #3 above.
- Also expose a small JSON endpoint `/api/v1/sync_health` for external monitoring (Datadog, Better Stack, etc.).

**Files:**
- `bootstrap/app/views/ztlp_devices/index.html.erb` — partial render of `_sync_health.html.erb`.
- `bootstrap/app/views/ztlp_devices/_sync_health.html.erb` (new).
- `bootstrap/app/controllers/api/v1/sync_health_controller.rb` (new) — gated by existing `Ztlp::ApiAuthenticator` (per-zone HMAC).
- Tests for both.

**Estimated effort:** ~1.5 hours.

**Total must-have effort:** ~5 hours. One focused afternoon.

---

## 🟡 Should-have (within 1-2 weeks of production)

### 5. NS-side IP allow-list for `/admin/records`

**Problem:** Even with rate-limiting, a leaked HMAC secret allows full record enumeration from anywhere on the internet. Defense in depth says we should also lock down by source IP.

**Fix shape:**
- New env var `ZTLP_NS_ADMIN_API_ALLOWED_CIDRS=172.18.0.0/16,172.19.0.0/16` (comma-separated CIDR list).
- In `handle_admin_records`, check `peer_ip` against the parsed CIDRs. Reject 403 if not in allow-list (don't even check signature — fail closed AT the network layer).
- Default behavior with no env var: ALLOW ALL (avoids breaking existing tests).

**Risk:** If we set CIDRs too narrowly we could break legitimate Bootstrap traffic. Mitigation: start permissive (`0.0.0.0/0`) in env, narrow after observation.

### 6. Per-zone secret scoping instead of one global secret

**Problem:** Today every Bootstrap tenant that knows the global `ZTLP_NS_ADMIN_API_SECRET` could query records for every zone, including other customers' data. Today there's only one tenant (Tech Rockstars), so this is dormant. The moment a second customer onboards on the shared infrastructure, it's a real cross-tenant data leak.

**Fix shape (option A — simpler):** Per-zone secret. NS reads `ZTLP_NS_ADMIN_API_SECRET_<UPCASE_SLUGIFIED_ZONE>` env vars (multiple). When a request comes in, the `zone` query param picks which secret to verify against. Without a zone param the request is rejected (no global enumeration).

**Fix shape (option B — better):** Include `zone` in the canonical signing string and require it to be a query param. NS rejects any request whose `zone` doesn't match what's keyed in the secret store. This is what `Ztlp::ApiAuthenticator` already does for the per-zone V1 endpoints — mirror that pattern.

Recommended: **option B**, because it matches the existing pattern and forces honest scoping.

### 7. Operator-visible "trigger sync now" button

**Problem:** Today the only way to force a sync is to `docker exec` into the container and run the rake task. Operators don't have shell.

**Fix shape:**
- New dashboard button "Sync from NS" in the Devices index header.
- Hits a new action `POST /networks/:id/ztlp_devices/sync` that calls `Ztlp::SyncNsToBootstrap.call` synchronously.
- Throttle to 1 manual sync per minute via Rails cache.

### 8. Document the runbook

**Problem:** If sync breaks at 2am on a Saturday, the on-call operator needs to know how to diagnose without reading 11 commits of TDD code.

**Fix shape:** New doc at `docs/runbooks/ns-bootstrap-sync.md` with:
- How to check sync health (dashboard banner, audit log query, NS `/admin/records` curl)
- How to rotate the shared HMAC secret without downtime (set both, wait one cron cycle, remove old)
- How to manually replay a failed sync
- How to drop bootstrap-side `origin='ns_sync'` rows and force a full re-sync
- Common error patterns + their fixes

---

## 🟢 Nice-to-have (next quarter)

### 9. Push instead of poll — NS webhooks

**Why:** 5-minute polling means a device registered at 12:01 won't show in the dashboard until 12:05+. For interactive enrollment flows that's a UX papercut.

**Fix shape:**
- New module `ZtlpNs.WebhookEmitter` that POSTs to a configured URL on every `0x07 ENROLL` accept.
- Per-zone webhook config (`ZTLP_NS_WEBHOOK_URL_<ZONE>`).
- Bootstrap exposes a signed webhook receiver under `Api::V1::NsWebhooksController` that just enqueues a sync.
- Polling stays as the fallback for missed events.

### 10. Surface device presence (last_seen_at) from gateway

**Why:** Operators want to know "is this device online RIGHT NOW," not "did it ever register." NS is a name service — it doesn't track presence. The gateway sees every QUIC handshake.

**Fix shape:**
- Gateway emits heartbeat events (already does, internally) to a Redis/sidecar.
- Bootstrap pulls heartbeats on the same 5-min cron, or via the same webhook channel.
- Dashboard shows `last_seen_at` next to `last_synced_at`.

This is a bigger architectural addition. Defer until presence becomes a customer ask.

### 11. Reverse direction — write-back for revocations

**Why:** Today, revoking a device in the Bootstrap UI updates `ZtlpDevice.status='revoked'` but does NOT issue a ZTLP `0x05 REVOKE` record to NS. The device's key stays valid in NS until manually purged.

**Fix shape:**
- New service `Ztlp::PushRevokeToNs` triggered after `ZtlpDevice.update!(status: 'revoked')`.
- Uses existing per-zone HMAC pattern (NOT the admin API — a separate write endpoint).
- Adds POST `/admin/revoke` on NS (with all the same auth + rate-limit hardening from items 1-2).
- Optimistic concurrency: if NS already has a higher serial number for that key, skip and log.

This is real new feature work. Schedule separately.

### 12. Sync more than just `:key` records

**Why:** NS also carries `:svc` (services), `:relay` (relay endpoints), `:policy` (ACL rules), `:cert` (X.509 certs). All could be surfaced in the dashboard.

**Fix shape:** Extend `SyncNsToBootstrap` to accept a `types:` parameter and create separate Bootstrap models for each NS record type. Probably needs new schema migrations and dashboard tabs.

Big — only do if customers ask.

### 13. Multi-tenant isolation in the SaaS shared infrastructure

**Why:** Item #6 fixes the per-zone secret scoping. This is the deeper fix: every tenant Bootstrap should be cryptographically prevented from reading another tenant's records even if both share the same NS.

**Fix shape:**
- NS records carry a `zone` tag (already do).
- AdminApi.list_records/1 filters by the zone in the signed request, not the query string. If signature is "for zone X" but query says zone Y → reject 403 (cross-tenant attempt).
- Per-zone HMAC secret in NS storage (Mnesia), not env vars — supports rotation without restart, supports new tenants without redeploy.

Tied into the broader multi-tenant story for ZTLP. Architectural, not tactical.

---

## Operational hygiene checklist before flipping `ZTLP_NS_SYNC_ENABLED=true`

- [ ] Tag a release (`v0.34.10` or whatever the next version is) on the merged branch so we have a rollback point.
- [ ] Pre-create `/rails/log/` with proper perms in the bootstrap `Dockerfile` (defense in depth — current entrypoint handles missing dir, but baking it in is cleaner).
- [ ] Document the two new env vars in `~/ztlp.net/.env.example`:
  - `ZTLP_NS_ADMIN_API_SECRET=<64-char hex>`
  - `ZTLP_NS_ADMIN_BASE_URL=http://ztlp-ns:9103`
  - `ZTLP_NS_SYNC_ENABLED=true`
- [ ] Update the `ztlp-bootstrap-deploy` skill's "Tenant-onboarding gaps" section to mention these as new required envs (mirror the `ZTLP_HMAC_SECRET_*` story).
- [ ] One-line customer-facing changelog: "Dashboard now shows all devices registered in your ZTLP zone, not just those enrolled via Bootstrap. Devices imported from NS are tagged with an NS badge."
- [ ] Verify the docker-network-connect step (Bootstrap onto `ztlpnet_default`) is captured in the Launch app's tenant provisioner code so new tenants get this automatically, not just `tech-rockstars`.
- [ ] Manual smoke test the full path: `openssl rand -hex 32` → set on both → `docker network connect` → restart → `rake ztlp:ns:sync` → verify ~15 devices appear in the dashboard.

---

## Recommended sequencing

| Phase | Items | When |
|---|---|---|
| **Phase 1 — Production-ready** ✅ | #1, #3, #4 (rate limit, backoff, health UI) + #2 (audit log) | **DONE in PR #97** |
| **Phase 2 — Hardening** | #5, #8 (IP allow-list, runbook) | Within 1 sprint of going live — item #2 already shipped in Phase 1 |
| **Phase 3 — Multi-tenant** | #6, #13 (per-zone secret, tenant isolation) | Before onboarding 2nd customer |
| **Phase 4 — UX polish** | #7, #10 (manual sync button, presence info) | When operators ask |
| **Phase 5 — Push model** | #9, #11 (webhooks, write-back) | When polling latency becomes a complaint |
| **Phase 6 — Scope expansion** | #12 (svc/relay/cert sync) | When customers ask |

---

## Open questions for Steve

1. Is one global `ZTLP_NS_ADMIN_API_SECRET` acceptable for the initial deploy, or should we do per-zone scoping from day one? (Today's deployment has only one tenant on the shared NS, so the cross-tenant leak is theoretical — but the moment we onboard a second customer it becomes real.)
2. Should the dashboard show synced devices for ALL networks, or only for the current logged-in tenant's network? Today the sync routes by zone-suffix match across every Network row in the Bootstrap DB. For per-tenant Bootstrap containers this is fine; for the shared SaaS scenario it might surface other tenants' devices.
3. Do you want the audit log to go to a separate file (`/rails/log/ns_sync_audit.log`) or stay in the `AuditLog` table? Table is queryable but bloats SQLite; file is forensically clean but harder to surface in UI.

---

## Resume cue

When this doc gets picked back up later, the entry point is:
1. Read this file top to bottom.
2. Check PR #96 merge status (`gh pr view 96`).
3. If merged: start with Phase 1 items (#1, #3, #4) — write a new plan file for each, follow the same TDD/subagent workflow used in `2026-06-07-ns-bootstrap-sync.md`.
4. If not merged: address remaining CodeRabbit / human review feedback first.
