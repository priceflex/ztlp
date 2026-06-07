# NS-Sync Phase 2 — Tenant Isolation (Items #5 + #6 Combined)

> **For Hermes:** Use subagent-driven-development to execute. TDD discipline mandatory. Quote the discipline block verbatim into each implementer brief.

**Goal:** Make a leaked `/admin/records` secret unable to enumerate another tenant's records. Two locks must both hold for a request to succeed: (1) source IP inside the tenant's allowed CIDR, AND (2) HMAC signature valid under the tenant's secret AND every returned record's zone matches the tenant's zone-glob.

**Branch:** `feat/ns-sync-tenant-isolation` (off `main` after PR #97 merges)

**Source doc:** `docs/plans/2026-06-07-ns-bootstrap-sync-production-readiness.md` items #5 + #6

**Phase 1 baseline (PR #97):**
- NS suite: 845 tests
- BS suite: 1175 tests
- 1 global secret, no IP allow-list, no zone scoping

---

## Plain-English summary (read this first if you're not the implementer)

Today, the NS admin API has ONE secret. Anybody who steals that secret from anywhere on the internet can read every device record in every customer's zone. That's fine while we have one customer (Tech Rockstars), but the moment we onboard a second customer on shared infrastructure, it's a cross-tenant data leak.

This change adds two independent walls between tenants:

**Wall 1 — Network firewall (Item #5):** Each tenant's Bootstrap container runs on its own Docker network with a unique CIDR. NS only accepts admin-API connections from CIDRs it knows about, and each CIDR is bound to a specific tenant. If an attacker has the secret but isn't on the right network, they get a 403 before NS even looks at the signature.

**Wall 2 — Per-tenant secret + zone scope (Item #6):** Each tenant gets its own HMAC secret. The secret is bound to a zone glob (like `*.trs.ztlp` for Tech Rockstars). When a request comes in, NS uses the signature to identify WHICH tenant is calling, then filters the response to records matching that tenant's glob. Tech Rockstars' secret literally cannot read Acme Dental records — there's no shared key to abuse.

A leaked secret now requires: stolen secret + access to the right Docker network + records in your assigned zone. Three things to compromise instead of one.

**Backwards compatible:** the existing global `ZTLP_NS_ADMIN_API_SECRET` keeps working for one release cycle. New per-tenant config is opt-in. Phase 3 deprecates the global.

---

## Progress Tracker

> State machine: 🔲 not started → 🟡 in progress → ✅ done → ❌ blocked. Update in the SAME commit as each task. SHA column: `_commit-pending_` during commit, backfilled in next task.

| # | Task | Status | Commit SHA | Notes |
|---|---|---|---|---|
| T1 | CIDR parser + matcher module (`ZtlpNs.Cidr`) | ✅ | `383339e` | 17 tests; full suite 862/845 |
| T2 | Tenant config loader (env → struct) | ✅ | c587cfa | `ZtlpNs.AdminApi.TenantRegistry`; env→struct; multi-CIDR; zone-glob leading-`*.` only (middle wildcards rejected); promoted `AdminApi.secure_compare/2` to public; 23 new tests; full suite 885/862 |
| T3 | NS: IP allow-list gate on `/admin/records` (item #5) | ✅ | `b5072bd` | CIDR gate before rate-limit; 403 + `:admin_api_ip_rejected` severity `:medium`; cached in `:persistent_term` at boot; backwards-compat (empty registry → no gate); 5 new tests; full suite 890/890 |
| T4 | NS: per-tenant secret resolution + zone-glob scoping (item #6) | ✅ | `881c841` | verify_request_with_registry/6; tenant-wins-over-global property pinned; :admin_api_legacy_global_secret audit on transition mode; preserves existing verify_request/5; 16 new tests; full suite 906/906 |
| T5 | NS: filter `list_records` response to tenant's zone glob | ✅ | `35af350` | zone-glob filter on response; :admin_api_zone_outside_glob audit event severity :high; legacy mode unchanged; 4 new tests; 910/910 |
| T6 | NS: severity tagging on all admin-API audit events | ✅ | `6acf5b0` | Added :info to :admin_api_records_pulled and :high to :admin_api_auth_failed; 2 regression tests pin coverage; full suite 912/912 |
| T7 | NS: trust-authority extension hook (stub, future-proofing) | ✅ | `68e06af` | verify_authority/2 stub returns :ok; call site pinned post-T4 pre-T5; :admin_api_authority_denied severity :critical reserved for Phase 3+; 2 contract tests; 914/914 |
| T8 | BS: client compatibility check (no code change expected) | ✅ | `7b189a6` | BS suite 1175/1175 unchanged after NS Phase 2; added compatibility docstring to NsAdminClient documenting how the one-secret-per-BS-container model maps to NS-side tenant identification |
| T9 | Docs: operator-facing deployment guide | ✅ | `a07d317` | operator deployment guide in `docs/operations/ns-admin-tenant-isolation.md`; covers quick-start, TRS Option B operator-tenant pattern, verification commands, rolling-to-TRS-prod migration, second-tenant onboarding, two-lock-model deep dive, audit events reference, trust-authority forward path, deprecation timeline, troubleshooting + FAQ; 688 lines |
| T10 | Docs: update `bootstrap/.env.example` + production-readiness doc | ✅ | `1d600a2` | bootstrap/.env.example + ztlp.net/.env.example updated with NS admin API + tenant variables; production-readiness doc items #5 + #6 marked ✅ with cross-links to Phase 2 commits |
| T11 | Full suite sweep + PR + CodeRabbit | ✅ | (no commit) | PR #98 opened https://github.com/priceflex/ztlp/pull/98 — NS 914/0 + BS 1175/0 at open; CodeRabbit posted 5 Major findings (handled in F1 fixup commit 7a94e1a); 920/0 after fixup |
| T12 | Docs: mark items #5 + #6 ✅ in production-readiness doc | ✅ | `1d600a2` | Items #5 + #6 marked ✅ with cross-links in T10 commit (same SHA) — production-readiness doc updated alongside env examples |
| F1 | CodeRabbit fixup: dup-secret detection (F1) + fail-closed env (F2) + IPv4 bounds (F3) + per-tenant CIDR check (F4) + sync test mod (F5) | ✅ | `7a94e1a` | 5 Major findings addressed; F4 closes cross-tenant CIDR escape vector (request signed as A from B's CIDR previously passed the union check); 6 new regression tests; full suite 920/920 |
| **DONE** | All tests green, PR opened, CodeRabbit clean ✓ second-pass | ✅ | `7a94e1a` | NS 920/0 + BS 1175/0; PR #98 reviewed twice by CodeRabbit; awaiting merge |

**Last resumed at:** CodeRabbit fixup done 2026-06-07T23:12:29Z

---

## Pre-flight: existing infrastructure we're plugging into

Confirmed by grepping `ns/lib/` and `bootstrap/`:

- **`ZtlpNs.AdminApi.verify_request/5`** (`ns/lib/ztlp_ns/admin_api.ex` line 23) — current single-secret HMAC verify. Takes `opts: [secret: binary]`. T4 extends this to resolve the secret from a tenant registry, but keeps the `secret:` opt as a fallback for the global path.
- **`ZtlpNs.MetricsServer.handle_admin_records/5`** (`ns/lib/ztlp_ns/metrics_server.ex` line 146 after PR #97) — already receives `peer_ip` (from T1 of PR #97). T3 wraps this in the CIDR check BEFORE rate-limit. Order: peer-IP → CIDR allow → rate-limit → HMAC verify → audit.
- **`ZtlpNs.AdminApi.list_records/1`** (`admin_api.ex` line 110) — accepts `opts: [zone: String.t, type: atom]`. T5 changes the call site in `metrics_server.ex` to compute the effective zone filter as `tenant_glob ∩ user_requested_zone` (intersection — tenant glob bounds the universe, user filter narrows within it).
- **`ZtlpNs.Audit.log/4`** (`ns/lib/ztlp_ns/audit.ex`) — already wired up via PR #97 for `:admin_api_records_pulled` and `:admin_api_auth_failed`. T6 adds a `:severity` key inside the `details` map for all admin-API audit events (info/medium/high/critical).
- **`Ztlp::NsAdminClient`** (`bootstrap/app/services/ztlp/ns_admin_client.rb`) — Bootstrap's client. T8 confirms it needs no changes because each tenant container has its own single secret already (one `ZTLP_NS_ADMIN_API_SECRET` env per BS container — just like today). The "per-tenant" part is enforced on the NS side via the registry; the BS side stays single-secret-per-container.
- **`bootstrap/app/services/ztlp/sync_ns_to_bootstrap.rb`** line 68 — calls `@client.list_records(type: "key")` (no zone). T8 confirms NS will now filter to tenant's zones automatically; BS doesn't need to change.

---

## Highest risk

**T4 — Per-tenant secret resolution under the existing global-secret fallback.** Mistakes here are CRITICAL because:
- A bug where the tenant lookup short-circuits to the global secret = tenant isolation breaks silently (request looks "authenticated" but uses wrong secret)
- A bug where the global secret path is preserved when it shouldn't be = same outcome

**Mitigation:**
- TDD specifies the resolution order EXPLICITLY: try tenant-registry FIRST, fall back to global ONLY if tenant registry is empty AND a `ZTLP_NS_ADMIN_API_SECRET` env exists, audit-log every fallback at `:medium` severity so the deprecation path is visible.
- Add a `ZtlpNs.AdminApi.resolve_tenant/2` function whose ONLY job is the resolution. Tests pin every branch.
- Integration test: with both tenant-registry AND global secret present, request signed with global secret = no tenant match → MUST still verify (global path), but `:admin_api_legacy_global_secret` audit event is emitted. Request signed with tenant secret = tenant match → MUST use that path, NO legacy event.

**Mid-risk: T1 — CIDR parsing edge cases.**
- IPv6 (do we support it? — NS today is IPv4-only over docker bridge; defer IPv6 to a future task)
- Malformed CIDR strings (`172.18.0.0/33` or `not.an.ip/24`) must reject at boot, not silently allow-all
- `/0` (allow-all) — log a warning at boot; useful for dev, deadly in prod

---

## MANDATORY DISCIPLINE — quoted into every implementer brief verbatim

```
1. RED — Write the failing test first. Run it. Confirm the failure reason
   matches the spec (feature missing, not a typo).
2. GREEN — Write the MINIMAL code to make the test pass. Hardcoding is OK
   in GREEN; we clean up in REFACTOR.
3. REFACTOR — Clean up duplication, magic numbers, naming. Tests must
   stay green throughout.
4. Full-suite verify — Run the WHOLE test suite for the affected app
   (`mix test` for NS work, `bin/rails test` for Bootstrap work). NO
   regressions allowed. If the full suite fails on a test you didn't
   touch, fix it before committing.
5. Atomic commit — ONE commit per task containing test + source + tracker
   row update (status flip + SHA placeholder `_commit-pending_`). Commit
   message follows Conventional Commits with the feature scope
   (`feat(ns): …` or `feat(bootstrap): …`). Include "Co-authored-by:
   Steven Price <steve@techrockstars.com>" trailer.
6. Push and update tracker — After commit, push to origin (use
   `GIT_SSH_COMMAND="ssh -i /home/trs/openclaw_server_import/ssh/openclaw
   -o IdentitiesOnly=yes -o StrictHostKeyChecking=no"`) and report the
   short SHA back to the orchestrator. The orchestrator backfills the SHA
   in the NEXT task's commit — never amend.
```

**Subagents should also be told:** CodeRabbit will catch library-footgun bugs that scoped tests miss. For T1 (CIDR parsing), T4 (secret resolution), and T5 (zone filtering), include adversarial test inputs:
- Empty strings, nil, malformed inputs
- Boundary cases (`/0`, `/32`, leading zeros)
- Unicode + Punycode in zone names (`café.example` and `xn--caf-dma.example`)
- Path traversal in zone glob (`../../*`)
- Multiple matching CIDRs (pick most-specific; document the tie-breaker)

---

## Task definitions

### T1 — CIDR parser + matcher (pure data, TDD-friendly)

**Objective:** New module `ZtlpNs.Cidr` with two functions: `parse/1` (binary → `%Cidr{}` or `{:error, reason}`) and `match?/2` (`%Cidr{}` × ip-tuple → bool). Pure data, no GenServer, no ETS.

**Files:**
- Create: `ns/lib/ztlp_ns/cidr.ex` (~80 LOC)
- Create: `ns/test/ztlp_ns/cidr_test.exs` (~120 LOC, 12+ tests)

**API:**

```elixir
defmodule ZtlpNs.Cidr do
  defstruct [:base, :mask_bits, :network_int, :broadcast_int]

  @type t :: %__MODULE__{
          base: :inet.ip4_address(),
          mask_bits: 0..32,
          network_int: non_neg_integer(),
          broadcast_int: non_neg_integer()
        }

  @spec parse(binary()) :: {:ok, t()} | {:error, atom()}
  def parse(cidr_string)

  @spec match?(t(), :inet.ip4_address()) :: boolean()
  def match?(cidr, ip_tuple)
end
```

**Test cases (all must be in RED before any production code):**

```elixir
# Happy paths
test "parses 172.18.0.0/16" — returns %Cidr{base: {172, 18, 0, 0}, mask_bits: 16}
test "parses 127.0.0.1/32" — single host
test "parses 0.0.0.0/0" — allow-all
test "match? 172.18.1.5 against 172.18.0.0/16 — true"
test "match? 172.19.1.5 against 172.18.0.0/16 — false"
test "match? 127.0.0.1 against 127.0.0.0/8 — true"
test "match? 8.8.8.8 against 127.0.0.0/8 — false"

# Adversarial
test "rejects malformed (172.18.0.0/33)" — {:error, :invalid_mask}
test "rejects malformed (not.an.ip/24)" — {:error, :invalid_address}
test "rejects empty string" — {:error, :invalid_format}
test "rejects nil" — {:error, :invalid_input}
test "rejects IPv6 (::1/128) with explicit reason" — {:error, :ipv6_not_supported}
test "host bits set is normalized (172.18.1.5/16 → parses to base 172.18.0.0)"
```

**Implementation approach:** convert IP to 32-bit integer, compute network/broadcast bounds, match by integer comparison. No regex, no string ops at match time (hot path).

**Step 5 commit message:** `feat(ns): ZtlpNs.Cidr parser + matcher`

---

### T2 — Tenant registry (env → struct loader)

**Objective:** New module `ZtlpNs.AdminApi.TenantRegistry` that loads tenant configs from environment variables at boot. Each tenant is identified by a slug (uppercase, alphanumeric + underscore). One env var per tenant key.

**Files:**
- Create: `ns/lib/ztlp_ns/admin_api/tenant_registry.ex` (~150 LOC)
- Create: `ns/test/ztlp_ns/admin_api/tenant_registry_test.exs`

**Env var convention (the deployment contract — document carefully):**

```bash
# Per-tenant: replace TRS with the tenant slug (uppercase, alphanumeric+underscore only)
ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET=<64-char hex, 32 bytes>
ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB=*.trs.ztlp
ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS=172.18.0.0/16,10.42.0.0/16

# Another tenant
ZTLP_NS_ADMIN_API_TENANT_ACME_SECRET=...
ZTLP_NS_ADMIN_API_TENANT_ACME_ZONE_GLOB=*.acme.trs.ztlp
ZTLP_NS_ADMIN_API_TENANT_ACME_CIDRS=172.20.0.0/16

# Legacy / backwards-compat: still supported during transition
ZTLP_NS_ADMIN_API_SECRET=<64-char hex>      # falls through to global path
```

**API:**

```elixir
defmodule ZtlpNs.AdminApi.TenantRegistry do
  defstruct [:slug, :secret, :zone_glob, :cidrs]

  @type t :: %__MODULE__{
          slug: String.t(),
          secret: binary(),     # 32 raw bytes
          zone_glob: String.t(),
          cidrs: [ZtlpNs.Cidr.t()]
        }

  @spec load_all() :: %{String.t() => t()}
  def load_all()

  # Look up a tenant by signature: try each tenant's secret against the
  # canonical signing string until one matches, or :none.
  @spec identify_tenant(canonical_string, sig_hex, registry) ::
          {:ok, t()} | :no_match
  def identify_tenant(canonical, sig_hex, registry)

  # Match an IP against any of a tenant's CIDRs
  @spec ip_in_cidrs?(t(), :inet.ip4_address()) :: boolean()
  def ip_in_cidrs?(tenant, ip)

  # Check whether a record's zone name matches the tenant's glob
  @spec zone_matches?(t(), zone_name :: String.t()) :: boolean()
  def zone_matches?(tenant, zone)
end
```

**Glob semantics (locked down at start):** `*.trs.ztlp` matches `host.trs.ztlp` and `host.sub.trs.ztlp` but NOT `trs.ztlp` (the bare zone) or `nottrs.ztlp`. The leading `*.` requires at least one prefix segment. Exact match: `trs.ztlp` glob matches only `trs.ztlp`. No wildcards in the middle (`*.foo.*` rejected at boot).

**Test cases:**
- `load_all` with no env vars returns empty map
- `load_all` parses one tenant correctly
- `load_all` parses two tenants
- Missing SECRET for declared tenant → boot-time exception (loud failure)
- Missing ZONE_GLOB → boot-time exception
- Missing CIDRS → boot-time exception
- Invalid hex secret → boot-time exception
- Invalid CIDR in list → boot-time exception (one bad CIDR taints the tenant)
- Lowercase slug in env (`tenant_trs_secret`) → ignored (we require uppercase by convention)
- `identify_tenant` happy path: 2 tenants, correct sig → returns matching tenant
- `identify_tenant` no match → `:no_match`
- `identify_tenant` constant-time: 100 wrong sigs all return `:no_match` in similar time (sanity check, not strict timing assertion)
- `zone_matches?` `*.trs.ztlp` vs `host.trs.ztlp` → true
- `zone_matches?` `*.trs.ztlp` vs `trs.ztlp` → false (bare)
- `zone_matches?` `*.trs.ztlp` vs `host.sub.trs.ztlp` → true
- `zone_matches?` `*.trs.ztlp` vs `host.notrs.ztlp` → false
- `zone_matches?` rejects glob with `*` in middle at boot

**Step 5 commit message:** `feat(ns): tenant registry with per-tenant secrets and zone globs`

---

### T3 — NS: IP allow-list gate (item #5)

**Objective:** Wrap `handle_admin_records/5` with a CIDR check using the tenant registry. The check happens BEFORE the rate-limit (rate-limit a peer outside the allow-list is wasteful; reject at network layer first). On reject: HTTP 403, audit event `:admin_api_ip_rejected` (severity `:medium`).

**Decision: what if NO tenant registry is loaded?**
- If global `ZTLP_NS_ADMIN_API_SECRET` is set AND no tenants → backwards-compat mode, NO IP check (today's behavior). Audit event `:admin_api_legacy_mode` (severity `:info`) on every successful request so the deprecation path is visible.
- If both global AND tenants → CIDR check uses the union of all tenants' CIDRs. A legacy global-secret request from outside the union → reject 403.
- If neither global NOR tenants → endpoint disabled (current behavior on missing secret).

**Files:**
- Modify: `ns/lib/ztlp_ns/metrics_server.ex#handle_admin_records/5`
- Modify: `ns/test/ztlp_ns/admin_api_http_test.exs` (add 3+ tests)

**Tests:**
- 403 when peer IP not in any tenant CIDR
- 200 when peer IP is in a tenant CIDR
- Audit event `:admin_api_ip_rejected` recorded on 403 with peer_ip + severity:medium
- Legacy-mode (global secret only, no tenants): IP check skipped (test inside test/test.exs config)

**Step 5 commit:** `feat(ns): CIDR allow-list gate on /admin/records (item #5)`

---

### T4 — NS: per-tenant secret resolution (item #6 core)

**Objective:** Change `handle_admin_records/5` to try EACH tenant's secret against the incoming signature. On match: that tenant is the "request owner" for the rest of the handler. On no-match AND a global secret is configured: try the global secret as the legacy path, audit at `:admin_api_legacy_global_secret` severity `:medium`. On total miss: 401 + audit `:admin_api_auth_failed` severity `:high`.

**Files:**
- Modify: `ns/lib/ztlp_ns/admin_api.ex` — add `verify_request_with_registry/5` that returns `{:ok, tenant} | {:ok, :legacy} | {:error, reason}`
- Modify: `ns/lib/ztlp_ns/metrics_server.ex` — call the new function, thread the tenant through to downstream code
- Modify: `ns/test/ztlp_ns/admin_api_test.exs` and `admin_api_http_test.exs`

**Critical TDD coverage** (this is the highest-risk task — over-test it):
- 2 tenants, request signed by tenant A → `{:ok, tenant_a}`, NO legacy event
- 2 tenants, request signed by tenant B → `{:ok, tenant_b}`, NO legacy event
- 2 tenants, request signed by neither (random secret) → `{:error, :bad_signature}` + auth_failed event severity:high
- 2 tenants + global secret, request signed by global → `{:ok, :legacy}` + `:admin_api_legacy_global_secret` event severity:medium
- 2 tenants + global secret, request signed by tenant A → `{:ok, tenant_a}`, NO legacy event (tenant wins, not global)
- 0 tenants + global secret, request signed by global → `{:ok, :legacy}`, no event (this IS the only mode)
- 0 tenants + NO global secret → `{:error, :no_secret}`, endpoint effectively disabled
- Stale timestamp still rejected with `:stale_timestamp` (same skew window) regardless of tenant

**Step 5 commit:** `feat(ns): per-tenant secret resolution with global fallback (item #6)`

---

### T5 — NS: zone-glob filtering on response

**Objective:** Once the request is authenticated as a specific tenant, filter `list_records/1`'s output so only records whose `name` matches the tenant's `zone_glob` are returned. For legacy mode (global secret), no filter — return everything (today's behavior).

**Files:**
- Modify: `ns/lib/ztlp_ns/metrics_server.ex` — compute effective filter as `tenant_glob ∩ user_requested_zone`
- Modify: `ns/lib/ztlp_ns/admin_api.ex` — extend `list_records/1` to accept a zone-glob filter (in addition to existing exact zone match)
- Modify: tests

**Edge cases:**
- Tenant TRS (`*.trs.ztlp`) requests with no zone param → returns all `*.trs.ztlp` records
- Tenant TRS requests with `zone=adms.trs.ztlp` → returns only that zone (within glob)
- Tenant TRS requests with `zone=acme.foo` (outside their glob) → returns empty list + audit event `:admin_api_zone_outside_glob` severity:high (smells like probe)
- Legacy mode requests → no filter (passes through)
- Bare zone match: `trs.ztlp` records are NOT returned for `*.trs.ztlp` glob (glob requires prefix segment per T2)

**Critical assertion:** test that with 2 tenants A and B each holding 5 records, an A-signed request can NEVER return any of B's records, regardless of `zone=` query.

**Step 5 commit:** `feat(ns): per-tenant zone-glob filtering on /admin/records`

---

### T6 — Audit severity tagging

**Objective:** Add a `:severity` key to every admin-API audit event's `details` map. Defines four levels:

| Severity | Used for | Routing intent |
|---|---|---|
| `:info` | Normal successful pull, legacy-mode (0 tenants) | Log only |
| `:medium` | IP rejected, legacy global-secret used | Daily summary |
| `:high` | Auth failed, zone outside glob | Alert ops |
| `:critical` | Repeated `:high` from inside allow-list (future hook) | Page on-call |

**Files:**
- Modify: `ns/lib/ztlp_ns/metrics_server.ex` — every `ZtlpNs.Audit.log` call gets a `:severity` key
- Modify: `ns/test/ztlp_ns/admin_api_http_test.exs` — extend existing audit-event assertions to verify the severity key

**No new module — pure tagging change.** Future task can add a `ZtlpNs.AlertRouter` consuming severity for actual paging.

**Step 5 commit:** `feat(ns): severity tagging on admin-API audit events`

---

### T7 — Trust-authority extension hook (future-proofing)

**Objective:** Add a stub function `ZtlpNs.AdminApi.verify_authority/2` that's called AFTER `verify_request_with_registry/5` succeeds, BEFORE `list_records` runs. For now, returns `:ok` unconditionally. Documented as the extension point for Phase 3+ trust-authority CA-signed authorization.

**Files:**
- Modify: `ns/lib/ztlp_ns/admin_api.ex` — add `verify_authority/2` with `@moduledoc` explaining future contract
- Modify: `ns/lib/ztlp_ns/metrics_server.ex` — call the function in the auth chain
- Modify: tests assert the stub is called (so a future implementation has a pinned contract)

**The stub:**

```elixir
@doc """
Trust-authority verification hook. Phase 3+ will plug CA-signed
authorization here. For now returns :ok unconditionally; the call
site is pinned so future implementations don't need to restructure
the auth chain.

Future contract (NOT YET ENFORCED):
  - Takes the authenticated tenant + request context
  - Returns :ok if a valid trust authority has issued the tenant a
    capability for this operation, OR if no trust authority is
    configured (open mode).
  - Returns {:error, :authority_denied} if trust authority is configured
    AND has explicitly denied this operation.

See `docs/operations/ns-admin-tenant-isolation.md` § Trust Authority
Forward Path.
"""
@spec verify_authority(tenant_or_legacy, request_context) :: :ok | {:error, atom()}
def verify_authority(_tenant, _context), do: :ok
```

**Step 5 commit:** `feat(ns): trust-authority verification hook (stub for Phase 3+)`

---

### T8 — BS: client compatibility check (no code change expected)

**Objective:** CONFIRM (don't change) that the Bootstrap client works against the new NS-side logic without modification. The contract for Bootstrap is: one secret per BS container, signs the request, gets back records. NS does the tenant identification.

**Approach:**
- Run BS test suite as-is — must remain 1175/0/0
- Add ONE integration-style test in `bootstrap/test/services/ztlp/ns_admin_client_test.rb` that stubs an NS-style HTTP server reflecting the new shape (no behavioral change in the BS code, just confirms tests still pass)

**If T8 reveals a needed change** (e.g. NS now requires a `zone=` query param even when filtering by glob), STOP and update the design — don't change BS to match a broken contract.

**Step 5 commit:** `test(bootstrap): pin NS admin client contract against per-tenant NS`

---

### T9 — Operator deployment guide (the docs the user asked for, plain English)

**Objective:** A clear, English-first guide for operators deploying the per-tenant NS admin API. Lives in the repo so anyone can find it.

**File:** Create `docs/operations/ns-admin-tenant-isolation.md`

**Required sections:**

1. **What this is for** — 2 paragraphs of plain English: the problem (shared NS, one global secret = cross-tenant leak), the solution (per-tenant secrets + CIDR allow-list), the two-lock model.
2. **Quick-start: deploying a new tenant** — 5-7 step checklist:
   1. Generate a 32-byte secret: `openssl rand -hex 32`
   2. Pick a tenant slug (uppercase, alphanumeric + underscore, e.g. `TRS`, `ACME_DENTAL`)
   3. Identify the Docker network CIDR the tenant Bootstrap will live on (`docker network inspect <name>`)
   4. Decide the zone glob (`*.<tenant_root>.trs.ztlp`)
   5. Add three env vars to NS's `.env`: `ZTLP_NS_ADMIN_API_TENANT_<SLUG>_{SECRET,ZONE_GLOB,CIDRS}`
   6. Restart NS (it loads tenant config at boot)
   7. Set `ZTLP_NS_ADMIN_API_SECRET=<same secret>` in the tenant's Bootstrap container, restart, watch sync logs
3. **Verifying the setup is correct** — copy-pastable commands:
   - Force a sync: `docker exec bootstrap-<tenant> bundle exec rails ztlp:ns:sync`
   - Check the dashboard banner is green
   - Hit `/api/v1/sync_health` from inside the tenant network
   - Verify cross-tenant denial: from another tenant's BS container, try the first tenant's URL → expect 403
4. **Rolling out to existing prod (Tech Rockstars)** — explicit migration steps:
   - Step 1: deploy this code change, global `ZTLP_NS_ADMIN_API_SECRET` still works (BC mode)
   - Step 2: add `ZTLP_NS_ADMIN_API_TENANT_TRS_*` env vars, restart NS — TRS Bootstrap now identified as tenant
   - Step 3: monitor `:admin_api_legacy_global_secret` audit events — should be zero after Step 2
   - Step 4 (future): set `ZTLP_NS_ADMIN_API_SECRET=` (unset) to remove legacy path
5. **Onboarding a second tenant** — same as Quick-start but explicit about the cross-tenant denial verification.
6. **The CIDR allow-list explained** — how to find your Docker network CIDR, what `*.trs.ztlp` means as a glob, what happens at each step of a request.
7. **Audit events you'll see (and what they mean)** — table of every audit event + severity + ops response:
   - `:admin_api_records_pulled` info — normal
   - `:admin_api_legacy_mode` info — running on global secret only, fine for transition
   - `:admin_api_legacy_global_secret` medium — a request used the global secret while tenants are configured; investigate which client and migrate them
   - `:admin_api_ip_rejected` medium — someone tried from wrong network; usually a misdeployed tenant, sometimes a probe
   - `:admin_api_auth_failed` high — bad signature; could be wrong secret, replay attempt, or attack
   - `:admin_api_zone_outside_glob` high — authenticated tenant queried a zone outside their glob; smells like cross-tenant probe
8. **Trust authority forward path** — 2-3 paragraphs explaining the `verify_authority` hook from T7 and what Phase 3 will look like. Just so a future reader knows where to plug in.
9. **Troubleshooting** — common failures:
   - "All requests return 403" → check CIDR matches your Docker bridge
   - "Sync works but returns 0 records" → zone glob mismatch
   - "Sudden flood of `:admin_api_legacy_global_secret` events" → tenant config not loaded; check env var spelling

**Tone:** assume the reader is a competent ops engineer but is touching NS for the first time. Examples are real. No marketing fluff.

**Step 5 commit:** `docs: operator guide for NS admin tenant isolation`

---

### T10 — Update env examples and existing docs

**Files:**
- Modify: `ztlp.net/.env.example` (deployment template) — add the new env vars under a clearly-labeled section
- Modify: `bootstrap/.env.example` — clarify that `ZTLP_NS_ADMIN_API_SECRET` is now a tenant-bound secret (no change to the variable name from BS's perspective)
- Modify: `docs/plans/2026-06-07-ns-bootstrap-sync-production-readiness.md` — add Status callouts under items #5 and #6 with the SHAs
- Modify: `docs/plans/2026-06-07-ns-sync-must-haves.md` Phase 2 row — update to "Items #5+#6 done in PR #<N>"

**Step 5 commit:** `docs: env examples + production-readiness updates for tenant isolation`

---

### T11 — Full sweep + PR + CodeRabbit

**Orchestrator-driven, no subagent:**

1. `cd /home/trs/ztlp/ns && mix test 2>&1 | tail -5` — assert `0 failures`, expect 855+ tests
2. `cd /home/trs/ztlp/bootstrap && bin/rails test 2>&1 | tail -5` — assert `0 failures`, expect 1175+ tests
3. `git push origin feat/ns-sync-tenant-isolation`
4. `gh pr create --base main --head feat/ns-sync-tenant-isolation --title "feat: NS admin tenant isolation (items #5 + #6)" --body-file <plan-summary>`
5. Wait ~3-5 min for CodeRabbit's first pass
6. Triage findings: Major issues fix immediately, Minor noted, cosmetic deferred. Same playbook as PR #97 hardening pass.

---

### T12 — Mark items #5 + #6 ✅

**File:** `docs/plans/2026-06-07-ns-bootstrap-sync-production-readiness.md`

Add the same `**Status: ✅ landed in PR #<N>**` callout pattern used for items 1-4 in PR #97. Update the sequencing table: Phase 2 → ✅.

**Step 5 commit:** `docs: mark items #5 + #6 complete (Phase 2 ✅)`

---

## Resume Protocol (if session interrupted)

When a new session opens this plan:
1. Read the Progress Tracker — find the last row with status ✅.
2. The next row (🔲 or 🟡) is where to resume.
3. Run `cd /home/trs/ztlp && git log --oneline -15 feat/ns-sync-tenant-isolation` to confirm tracker matches commit history.
4. If tracker and git disagree, **trust git** and re-update the tracker.
5. Update "Last resumed at" in the next commit so the audit trail stays accurate.

---

## Decisions locked in (recap from chat with Steve, 2026-06-07)

1. **Tenant = one Bootstrap container.** TRS Bootstrap manages all `*.trs.ztlp` zones. Acme Dental's future Bootstrap manages `*.acme-dental.trs.ztlp`. Each container holds ONE secret.
2. **Global secret stays during transition.** Backwards-compatible; audit event makes the legacy path visible. Phase 3+ deprecates.
3. **No global allow-list — per-tenant CIDRs only.** Each tenant's allowed CIDRs are scoped to their secret. The union of all tenant CIDRs is the de-facto NS admin allow-list.
4. **No reverse proxy plans.** Direct-bind NS HTTP. Test pins `:inet.peername` as the source-of-truth for peer IP so a future proxy insertion fails loudly.
5. **Severity tagging on audit events.** info/medium/high/critical bands per the table in T6.
6. **Trust-authority hook is a stub.** `verify_authority/2` returns :ok now; reserves the call site for Phase 3+.

## Open questions for Steve (none blocking — defaults documented above)

- Multi-CIDR per tenant: today T2 supports a comma-separated list. Realistic? (e.g. TRS Bootstrap on both `172.18.0.0/16` AND a backup network.) **Default: yes, supported.**
- IPv6: **deferred** to a future task. NS is IPv4-only over docker today.
- Zone-glob middle wildcards (`*.foo.*`): **rejected at boot.** Force operators to enumerate.
