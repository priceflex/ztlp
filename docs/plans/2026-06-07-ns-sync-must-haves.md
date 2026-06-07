# NS-Bootstrap Sync — Phase 1 Must-Haves Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task. TDD discipline — RED → GREEN → REFACTOR → verify-full-suite → single atomic commit per task — is MANDATORY. Quote verbatim into every implementer brief.

**Goal:** Land the 4 production-readiness must-haves from `2026-06-07-ns-bootstrap-sync-production-readiness.md` so `ZTLP_NS_SYNC_ENABLED=true` can be safely flipped in production.

**Architecture:**
- NS side (Elixir, `ns/`): wrap `handle_admin_records/4` with per-IP rate-limit + audit-log emission on both success and failure branches. Both reuse the existing `ZtlpNs.RateLimiter` and `ZtlpNs.Audit` modules — no new infrastructure.
- Bootstrap side (Rails, `bootstrap/`): introduce `Ztlp::SyncState` (filesystem-backed JSON) so the cron loop can apply exponential backoff after transient NS failures, and surface `last_synced_at` / failure state in the dashboard.

**Tech Stack:** Elixir 1.15 (NS), Ruby 3.0 / Rails 7 (Bootstrap), ExUnit, Minitest, Mnesia.

**Branch:** `feat/ns-sync-hardening` (already checked out off `main` post-#96 squash-merge `3d935f5`).

**Source doc:** `docs/plans/2026-06-07-ns-bootstrap-sync-production-readiness.md` items #1, #2, #3, #4.

---

## Progress Tracker

> State machine: 🔲 not started → 🟡 in progress → ✅ done → ❌ blocked. Update in the SAME commit as each task lands. SHA column accepts `_commit-pending_` literal during the task commit; orchestrator backfills SHA in the next task's commit (NEVER amend just to fix a SHA).

| # | Task | Status | Commit SHA | Notes |
|---|---|---|---|---|
| T1 | NS: thread peer IP from accept loop into `handle_admin_records/4` | 🔲 | — | Plumbing-only; no behavior change |
| T2 | NS: rate-limit `/admin/records` via `ZtlpNs.RateLimiter` (item #1) | 🔲 | — | Returns 429 + `Retry-After`; configurable threshold |
| T3 | NS: audit-log success + auth-failure on `/admin/records` (item #2) | 🔲 | — | Adds 2 new `Audit` action atoms |
| T4 | BS: `Ztlp::SyncState` filesystem JSON (item #3 scaffolding) | 🔲 | — | TDD-pure; new file `~/.ztlp_sync_state` |
| T5 | BS: gate rake task on `SyncState.due?` w/ exponential backoff (item #3) | 🔲 | — | Cron stays dumb; backoff lives in task |
| T6 | BS: `_sync_health.html.erb` partial + dashboard banner (item #4) | 🔲 | — | Pulls from SyncState; green/yellow/red |
| T7 | BS: `/api/v1/sync_health` JSON endpoint (item #4) | 🔲 | — | Gated by existing `Ztlp::ApiAuthenticator` |
| T8 | Full-suite sweep + CodeRabbit dry-run | 🔲 | — | `mix test` (NS) + `bin/rails test` (BS) green |
| T9 | Docs: update production-readiness doc to mark items 1-4 ✅ | 🔲 | — | Cross-link merged PR |
| **DONE** | All tests green, PR opened, CodeRabbit clean | 🔲 | — | |

**Last resumed at:** _(populated on session restart)_

---

## Pre-flight: existing infrastructure we're plugging into

Confirmed by greppinng `ns/lib/` and `bootstrap/`:

- **`ZtlpNs.RateLimiter`** (`ns/lib/ztlp_ns/rate_limiter.ex`, 209 LOC) — already a GenServer + ETS token-bucket. Public API: `check(ip_tuple) :: :ok | :rate_limited`. Configuration via `:ztlp_ns` app env `:rate_limit` keylist (`queries_per_second`, `burst`).
  - Reuse pattern: T2 calls `ZtlpNs.RateLimiter.check(peer_ip)` BEFORE `AdminApi.verify_request` (verify is cheap but `list_records` walks the store — protect the expensive path). On `:rate_limited`, send 429 + `Retry-After`.
- **`ZtlpNs.Audit`** (`ns/lib/ztlp_ns/audit.ex`, 199 LOC) — bounded ring buffer. Public API: `log(action :: atom, name :: String.t, type :: atom, details :: map) :: :ok`. New action atoms for T3: `:admin_api_records_pulled`, `:admin_api_auth_failed`.
- **`metrics_server.ex`** `:gen_tcp.accept/2` at line 51 — peer IP is reachable via `:inet.peername/1` on the accepted socket. T1 extracts it and threads through `handle_admin_records/4`.
- **`Ztlp::SyncNsToBootstrap`** already returns `Result` with `status :ok | :error` (line 52). T5 uses `result.error?` and the audit-log `details` JSON.
- **`AuditLog` Rails model** already used by the existing rake task (`bootstrap/lib/tasks/ztlp_ns_sync.rake` line 20) — we read its most recent row in T6/T7 to compute last-success timestamps. Avoids a parallel data source.

---

## Highest risk

**T5 (backoff gating).** If we get the "is this run due?" predicate wrong, we either (a) run every tick anyway (no relief from log spam) or (b) skip forever after one failure (stale dashboard). Mitigation: TDD with time-injected clock (`Time.now` is the only side-channel; pass via kwarg). Spec the truth table in the test file BEFORE writing impl. `SyncState.due?` is a pure function of `(last_success_at, last_failure_at, consecutive_failures, now)`.

**Mid-risk: T2 IP rate-limiter shared with the registration path.** The existing `ZtlpNs.RateLimiter.check/1` is the SAME bucket used for ZTLP registration auth. A flood of admin API calls could now exhaust the same bucket that legitimate device registrations need. **Decision:** add a SEPARATE bucket namespace via a wrapper, OR add an opt-in `bucket: :admin_api` kwarg to `RateLimiter.check/2`. Plan goes with the wrapper to avoid touching `RateLimiter`'s public API (zero-risk change).

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

---

## Task definitions

Each task is self-contained. Subagent gets: the task block below, the discipline block above, and pointer to the production-readiness source doc. Subagent does NOT need to read the plan file itself.

### T1 — NS: thread peer IP from accept loop into `handle_admin_records/4`

**Objective:** Capture the peer IP at `:gen_tcp.accept/2` time and pass it through the request dispatcher so downstream handlers can use it for rate-limiting and audit logging. PURE PLUMBING — no behavior change, no new tests beyond verifying the IP arrives.

**Files:**
- Modify: `ns/lib/ztlp_ns/metrics_server.ex` (~line 50-100 — the accept loop and request handler)
- Modify: `ns/test/ztlp_ns/admin_api_http_test.exs` — add a test asserting peer IP is observable (e.g., via a stub `RateLimiter.check/1` capturing the tuple).

**Step 1 (RED):** In `admin_api_http_test.exs`, add `test "passes peer IP tuple to rate-limit check"` that uses `:meck` (already a dep) to mock `ZtlpNs.RateLimiter.check/1`, makes an `/admin/records` HTTP request from `127.0.0.1`, and asserts the mock was called with `{127, 0, 0, 1}`.

**Step 2 (verify RED):** `mix test test/ztlp_ns/admin_api_http_test.exs -t admin_peer_ip` — expect failure with "no mock invocation" (because nothing currently calls `RateLimiter.check/1` in this code path).

**Step 3 (GREEN):** In `metrics_server.ex`:
```elixir
# In the accept loop (around line 51):
case :gen_tcp.accept(ls, 100) do
  {:ok, client} ->
    peer_ip = case :inet.peername(client) do
      {:ok, {ip, _port}} -> ip
      _ -> {0, 0, 0, 0}
    end
    spawn(fn -> handle_request(client, peer_ip) end)
    send(self(), :accept)
    # ...
end

# Update handle_request signature to accept peer_ip and pass to
# handle_admin_records(socket, path, query, headers, peer_ip).

# In handle_admin_records/5, call ZtlpNs.RateLimiter.check(peer_ip)
# but for T1 just LOG it — actual gating lands in T2. T1's goal is
# plumbing only.
Logger.debug("[admin_api] peer_ip=#{:inet.ntoa(peer_ip)} path=#{path}")
ZtlpNs.RateLimiter.check(peer_ip)  # T1: just calls, doesn't act on result
```

**Step 4 (verify GREEN):** Run the new test alone, then `mix test` for the whole NS suite. Expect: new test passes, all 833 pre-existing tests still pass.

**Step 5 (commit):**
```
git add ns/lib/ztlp_ns/metrics_server.ex ns/test/ztlp_ns/admin_api_http_test.exs docs/plans/2026-06-07-ns-sync-must-haves.md
git commit -m "feat(ns): thread peer IP into admin records handler

Plumbing-only change ahead of the rate-limit (T2) and audit log (T3)
work. Extracts peer IP at gen_tcp.accept and threads it through
handle_admin_records/5. No behavior change yet — RateLimiter.check/1
is called but its result is ignored. T2 will act on :rate_limited.

Refs: docs/plans/2026-06-07-ns-sync-must-haves.md#t1

Co-authored-by: Steven Price <steve@techrockstars.com>"
```

---

### T2 — NS: rate-limit `/admin/records` (item #1)

**Objective:** Reject `/admin/records` requests from a peer IP that exceeds N requests in W seconds. Default `12/60` (matches 5-min cron + retry headroom). Configurable via `ZTLP_NS_ADMIN_API_RATE_LIMIT=12/60`.

**Risk-mitigating decision (from plan):** Add a SEPARATE bucket namespace so admin-API rate-limit doesn't compete with the device-registration bucket. Wrap, don't extend `RateLimiter`'s public API.

**Files:**
- Modify: `ns/lib/ztlp_ns/metrics_server.ex` — call new `AdminApiRateLimiter.check/1` before `verify_request`. On `:rate_limited`, send 429 + `Retry-After: 60` + log warning.
- Create: `ns/lib/ztlp_ns/admin_api_rate_limiter.ex` — thin module backed by its own ETS table or a namespaced key in the existing table. Public: `check(ip_tuple) :: :ok | :rate_limited`.
- Modify: `ns/lib/ztlp_ns/application.ex` — add child spec for the new GenServer (if standalone) OR ensure `RateLimiter` is started before `MetricsServer`.
- Modify: `ns/lib/ztlp_ns/config.ex` — expose `admin_api_rate_limit/0` returning `{count, window_seconds}`. Reads `ZTLP_NS_ADMIN_API_RATE_LIMIT` env (format `"N/W"`), defaults `{12, 60}`.
- Test: `ns/test/ztlp_ns/admin_api_http_test.exs` — new tests for 429 + headers; threshold + window slide.
- Test: `ns/test/ztlp_ns/admin_api_rate_limiter_test.exs` — new file, isolated GenServer tests.

**Step 1 (RED) — primary test in `admin_api_http_test.exs`:**
```elixir
test "returns 429 after exceeding rate limit threshold" do
  # 12 requests in 60s threshold by default. Send 13 in quick succession.
  for _ <- 1..12 do
    {:ok, %{status: 200}} = http_get("/admin/records?type=key")
  end
  {:ok, %{status: 429, headers: hs}} = http_get("/admin/records?type=key")
  assert {"retry-after", "60"} in hs
end

test "rate limit window slides — allowed again after expiry" do
  # Burn through the bucket
  for _ <- 1..13, do: http_get("/admin/records?type=key")
  # Fast-forward the bucket's internal clock (Process.put-based clock injection)
  AdminApiRateLimiter.advance_clock(70_000)  # +70 seconds
  {:ok, %{status: 200}} = http_get("/admin/records?type=key")
end
```

**Step 2 (verify RED):** Module doesn't exist → compile-error or both new tests fail with `UndefinedFunctionError`.

**Step 3 (GREEN):** Implement `AdminApiRateLimiter` modeled on existing `RateLimiter` — same token-bucket algorithm, separate ETS table `:ztlp_ns_admin_api_ratelimit`. Add `advance_clock/1` helper as a test-only entry point (gated by `Mix.env() == :test`). In `metrics_server.ex#handle_admin_records/5`:
```elixir
case ZtlpNs.AdminApiRateLimiter.check(peer_ip) do
  :ok ->
    # existing flow
  :rate_limited ->
    Logger.warning("[admin_api] 429 peer=#{:inet.ntoa(peer_ip)}")
    send_response(socket, 429, "", "text/plain", [{"Retry-After", "60"}])
end
```
`send_response/4` needs the optional extra-headers parameter — add it.

**Step 4 (verify GREEN):** New tests pass + full NS suite green (`mix test`).

**Step 5 (commit):** as above with message `feat(ns): rate-limit /admin/records (12 req/60s default)`.

---

### T3 — NS: audit log on success + auth-failure (item #2)

**Objective:** Emit `ZtlpNs.Audit.log/4` entries on both success (200) and auth-failure (401) responses from `/admin/records`. Currently 401 is `Logger.warning` only; 200 is silent. SOC2/forensics needs an append-only trail.

**Files:**
- Modify: `ns/lib/ztlp_ns/metrics_server.ex#handle_admin_records/5` — two `Audit.log` calls (one per branch).
- Test: `ns/test/ztlp_ns/admin_api_http_test.exs` — assert `Audit.since/1` returns the expected entries after 200 and 401 paths.

**New audit actions:** `:admin_api_records_pulled` and `:admin_api_auth_failed`. Per `audit.ex` line 39 the action atom list is open — no enum to extend.

**Step 1 (RED):**
```elixir
test "logs admin_api_records_pulled audit entry on 200" do
  before = System.system_time(:second)
  {:ok, %{status: 200}} = http_get("/admin/records?type=key&zone=adms.trs.ztlp")
  entries = ZtlpNs.Audit.since(before - 1)
  assert Enum.any?(entries, fn {_ts, action, _name, _type, details} ->
    action == :admin_api_records_pulled and
    details[:zone_filter] == "adms.trs.ztlp" and
    is_integer(details[:count])
  end)
end

test "logs admin_api_auth_failed audit entry on 401" do
  before = System.system_time(:second)
  {:ok, %{status: 401}} = http_get("/admin/records", headers: [{"authorization", "Hmac bogus"}])
  entries = ZtlpNs.Audit.since(before - 1)
  assert Enum.any?(entries, fn {_ts, action, _name, _type, details} ->
    action == :admin_api_auth_failed and details[:reason] != nil
  end)
end
```

**Step 2 (verify RED):** Neither action is currently emitted — both tests fail.

**Step 3 (GREEN):** In `handle_admin_records/5`:
```elixir
case ... verify_request ... do
  :ok ->
    opts = parse_admin_query(query_str)
    records = ZtlpNs.AdminApi.list_records(opts)
    ZtlpNs.Audit.log(:admin_api_records_pulled, "/admin/records", :admin_api, %{
      peer_ip: :inet.ntoa(peer_ip) |> to_string(),
      zone_filter: Keyword.get(opts, :zone),
      type_filter: Keyword.get(opts, :type),
      count: length(records)
    })
    send_response(socket, 200, Jason.encode!(records), "application/json")
  {:error, reason} ->
    ZtlpNs.Audit.log(:admin_api_auth_failed, "/admin/records", :admin_api, %{
      peer_ip: :inet.ntoa(peer_ip) |> to_string(),
      reason: inspect(reason)
    })
    Logger.warning("[admin_api] 401 reason=#{inspect(reason)} peer=#{:inet.ntoa(peer_ip)}")
    send_response(socket, 401, "")
end
```

**Step 4 (verify GREEN):** New tests pass + full NS suite green.

**Step 5 (commit):** `feat(ns): audit log /admin/records on 200 and 401`.

---

### T4 — BS: `Ztlp::SyncState` filesystem-backed JSON

**Objective:** Pure data layer for tracking sync health. Filesystem-backed JSON at `Rails.root.join('tmp', 'ztlp_sync_state.json')` (writable in dev, prod, and CI). Public API:
- `SyncState.record_success!(timestamp: Time.now)` — clears failure counter
- `SyncState.record_failure!(error_class:, timestamp: Time.now)` — bumps counter, computes `next_retry_at`
- `SyncState.current` — returns frozen hash with `:last_success_at`, `:last_failure_at`, `:consecutive_failures`, `:last_error_class`, `:next_retry_at`
- `SyncState.due?(now: Time.now)` — `true` iff `next_retry_at.nil? || now >= next_retry_at`

**Backoff formula:** `min(15.minutes, 1.minute * 2 ** (consecutive_failures - 1))`. Capped so we still attempt every 15 min even on long outages.

**Files:**
- Create: `bootstrap/app/services/ztlp/sync_state.rb`
- Test: `bootstrap/test/services/ztlp/sync_state_test.rb`

**Step 1 (RED) — full test file:**
```ruby
require "test_helper"
require "fileutils"

class Ztlp::SyncStateTest < ActiveSupport::TestCase
  setup { Ztlp::SyncState.reset! }
  teardown { Ztlp::SyncState.reset! }

  test "fresh state is due immediately" do
    assert Ztlp::SyncState.due?
    assert_equal 0, Ztlp::SyncState.current[:consecutive_failures]
  end

  test "record_success! resets failure counter" do
    Ztlp::SyncState.record_failure!(error_class: "TransportError")
    Ztlp::SyncState.record_failure!(error_class: "TransportError")
    Ztlp::SyncState.record_success!
    assert_equal 0, Ztlp::SyncState.current[:consecutive_failures]
    assert Ztlp::SyncState.due?  # next_retry_at cleared
  end

  test "record_failure! schedules exponential backoff capped at 15min" do
    now = Time.utc(2026, 6, 7, 12)
    Ztlp::SyncState.record_failure!(error_class: "TransportError", timestamp: now)
    assert_equal now + 1.minute, Ztlp::SyncState.current[:next_retry_at]  # 1st failure: 1min

    Ztlp::SyncState.record_failure!(error_class: "TransportError", timestamp: now + 5.seconds)
    assert_equal (now + 5.seconds) + 2.minutes, Ztlp::SyncState.current[:next_retry_at]  # 2nd: 2min

    # Crank to 10 consecutive failures
    8.times { Ztlp::SyncState.record_failure!(error_class: "TransportError", timestamp: now) }
    expected_cap = now + 15.minutes
    assert_equal expected_cap, Ztlp::SyncState.current[:next_retry_at]
  end

  test "due? respects next_retry_at" do
    now = Time.utc(2026, 6, 7, 12)
    Ztlp::SyncState.record_failure!(error_class: "TransportError", timestamp: now)
    refute Ztlp::SyncState.due?(now: now + 30.seconds)
    assert Ztlp::SyncState.due?(now: now + 2.minutes)
  end
end
```

**Step 2 (verify RED):** Class undefined.

**Step 3 (GREEN):** Implement with `File.read`/`File.write` + `JSON` round-trip. Use `File::Flock` for cross-process safety (cron + manual rake could race).
```ruby
module Ztlp
  class SyncState
    STATE_FILE = Rails.root.join("tmp", "ztlp_sync_state.json").freeze
    MAX_BACKOFF = 15 * 60   # 15 minutes in seconds

    class << self
      def current
        load_state.symbolize_keys.tap { |h| %i[last_success_at last_failure_at next_retry_at].each { |k| h[k] = Time.iso8601(h[k]) if h[k].is_a?(String) } }
      end

      def due?(now: Time.now)
        next_at = current[:next_retry_at]
        next_at.nil? || now >= next_at
      end

      def record_success!(timestamp: Time.now)
        update_state do |s|
          s["last_success_at"] = timestamp.iso8601
          s["consecutive_failures"] = 0
          s["next_retry_at"] = nil
          s["last_error_class"] = nil
        end
      end

      def record_failure!(error_class:, timestamp: Time.now)
        update_state do |s|
          failures = (s["consecutive_failures"] || 0) + 1
          backoff_seconds = [(60 * (2 ** (failures - 1))), MAX_BACKOFF].min
          s["last_failure_at"] = timestamp.iso8601
          s["consecutive_failures"] = failures
          s["next_retry_at"] = (timestamp + backoff_seconds).iso8601
          s["last_error_class"] = error_class
        end
      end

      def reset!  # test helper
        FileUtils.rm_f(STATE_FILE)
      end

      private

      def load_state
        return default_state unless File.exist?(STATE_FILE)
        JSON.parse(File.read(STATE_FILE))
      rescue JSON::ParserError
        default_state
      end

      def update_state
        FileUtils.mkdir_p(File.dirname(STATE_FILE))
        File.open(STATE_FILE, File::RDWR | File::CREAT, 0o644) do |f|
          f.flock(File::LOCK_EX)
          raw = f.read
          state = raw.empty? ? default_state : (JSON.parse(raw) rescue default_state)
          yield(state)
          f.rewind
          f.truncate(0)
          f.write(JSON.pretty_generate(state))
        end
      end

      def default_state
        { "last_success_at" => nil, "last_failure_at" => nil,
          "consecutive_failures" => 0, "next_retry_at" => nil,
          "last_error_class" => nil }
      end
    end
  end
end
```

**Step 4 (verify GREEN):** New tests pass + full BS suite green (`bin/rails test`).

**Step 5 (commit):** `feat(bootstrap): Ztlp::SyncState exp backoff scaffolding`.

---

### T5 — BS: gate rake task on `SyncState.due?` with backoff (item #3)

**Objective:** Wire `SyncState` into `bootstrap/lib/tasks/ztlp_ns_sync.rake` and `Ztlp::SyncNsToBootstrap` so the cron loop skips when backoff window is active.

**Files:**
- Modify: `bootstrap/lib/tasks/ztlp_ns_sync.rake` — call `Ztlp::SyncState.due?` at the top; print + exit 0 if not due. After `result`, call `SyncState.record_success!` or `record_failure!`.
- Test: `bootstrap/test/tasks/ztlp_ns_sync_test.rb` — extend with two new cases.

**Step 1 (RED):**
```ruby
test "skips run when SyncState is not due" do
  Ztlp::SyncState.record_failure!(error_class: "TransportError")  # sets 1-min backoff
  refute Ztlp::SyncState.due?
  Ztlp::SyncNsToBootstrap.expects(:call).never
  Rake::Task["ztlp:ns:sync"].execute
end

test "records SyncState success after a successful run" do
  Ztlp::SyncNsToBootstrap.stubs(:call).returns(
    Ztlp::SyncNsToBootstrap::Result.new(status: :ok, created: 0, updated: 0,
                                        orphaned: 0, skipped: 0, errors: [])
  )
  Rake::Task["ztlp:ns:sync"].execute
  assert_in_delta Time.now.to_i, Ztlp::SyncState.current[:last_success_at].to_i, 5
  assert_equal 0, Ztlp::SyncState.current[:consecutive_failures]
end

test "records SyncState failure with error_class after an error run" do
  Ztlp::SyncNsToBootstrap.stubs(:call).returns(
    Ztlp::SyncNsToBootstrap::Result.new(status: :error, created: 0, updated: 0,
                                        orphaned: 0, skipped: 0,
                                        errors: [{ name: "x", reason: "TransportError" }],
                                        message: "TransportError")
  )
  Rake::Task["ztlp:ns:sync"].execute
  assert_equal 1, Ztlp::SyncState.current[:consecutive_failures]
  assert_equal "TransportError", Ztlp::SyncState.current[:last_error_class]
end
```

**Step 2 (verify RED):** All three new tests fail.

**Step 3 (GREEN):**
```ruby
namespace :ztlp do
  namespace :ns do
    desc "Reconcile ZtlpDevice rows against NS state"
    task sync: :environment do
      unless Ztlp::SyncState.due?
        puts "[ztlp:ns:sync] skipped (next_retry_at=#{Ztlp::SyncState.current[:next_retry_at]})"
        next
      end

      result = Ztlp::SyncNsToBootstrap.call

      # ... existing puts + AuditLog block ...

      if result.error?
        Ztlp::SyncState.record_failure!(error_class: result.message || "UnknownError")
      else
        Ztlp::SyncState.record_success!
      end

      if result.error? && ENV["ZTLP_NS_SYNC_FAIL_HARD"] == "true"
        abort "[ztlp:ns:sync] sync errored; exiting non-zero per ZTLP_NS_SYNC_FAIL_HARD=true"
      end
    end
  end
end
```

**Step 4 (verify GREEN):** Full BS suite green.

**Step 5 (commit):** `feat(bootstrap): exp backoff gating for ztlp:ns:sync`.

---

### T6 — BS: dashboard sync-health banner (item #4 UI)

**Objective:** Render a banner at the top of `/networks/:id/ztlp_devices` showing last NS sync status. Green / yellow / red based on `SyncState.current`.

**Bands:**
- **Green:** `last_success_at < 10 minutes ago` AND `consecutive_failures == 0`
- **Yellow:** `last_success_at >= 10 min ago` AND `consecutive_failures < 3`
- **Red:** `consecutive_failures >= 3` OR `last_success_at.nil?` (never synced) OR `last_success_at > 1 hour ago`

**Files:**
- Create: `bootstrap/app/views/ztlp_devices/_sync_health.html.erb` — partial that takes a SyncState hash and renders the banner.
- Create: `bootstrap/app/helpers/sync_health_helper.rb` — `sync_health_status(state)` returning `:green/:yellow/:red` + `sync_health_message(state)` returning the human string.
- Modify: `bootstrap/app/views/ztlp_devices/index.html.erb` — `<%= render 'sync_health', state: Ztlp::SyncState.current %>` near the top.
- Test: `bootstrap/test/helpers/sync_health_helper_test.rb` — pure helper logic.
- Test: `bootstrap/test/controllers/ztlp_devices_controller_test.rb` — extend existing index test asserting the banner shows up.

**TDD focus:** The helper is the testable part; the partial is mostly markup. Cover all 3 bands + edge cases (never synced, just synced, stale, failing).

**Step 1 (RED):**
```ruby
# test/helpers/sync_health_helper_test.rb
class SyncHealthHelperTest < ActionView::TestCase
  test "green when last_success_at recent and no failures" do
    state = { last_success_at: 2.minutes.ago, consecutive_failures: 0,
              last_failure_at: nil, last_error_class: nil, next_retry_at: nil }
    assert_equal :green, sync_health_status(state)
  end

  test "yellow when last_success_at >10min but <3 failures" do
    state = { last_success_at: 12.minutes.ago, consecutive_failures: 1,
              last_failure_at: 1.minute.ago, last_error_class: "TransportError",
              next_retry_at: 30.seconds.from_now }
    assert_equal :yellow, sync_health_status(state)
  end

  test "red when 3+ consecutive failures" do
    state = { last_success_at: 1.minute.ago, consecutive_failures: 3,
              last_failure_at: 30.seconds.ago, last_error_class: "TransportError",
              next_retry_at: 8.minutes.from_now }
    assert_equal :red, sync_health_status(state)
  end

  test "red when never synced" do
    state = { last_success_at: nil, consecutive_failures: 0,
              last_failure_at: nil, last_error_class: nil, next_retry_at: nil }
    assert_equal :red, sync_health_status(state)
  end

  test "sync_health_message includes elapsed time" do
    state = { last_success_at: 3.minutes.ago, consecutive_failures: 0,
              last_failure_at: nil, last_error_class: nil, next_retry_at: nil }
    assert_match(/3 minutes ago/, sync_health_message(state))
  end
end
```

**Step 2 (verify RED):** Helper undefined.

**Step 3 (GREEN):** Implement helper + partial. Use Tailwind/Bootstrap classes consistent with rest of `ztlp_devices/index.html.erb`. Partial sample:
```erb
<% status = sync_health_status(state) %>
<div class="sync-health-banner sync-health-<%= status %>">
  <strong>NS Sync:</strong> <%= sync_health_message(state) %>
  <% if status == :red %>
    — <%= link_to "view audit log", audit_logs_path %>.
  <% end %>
</div>
```

**Step 4 (verify GREEN):** Helper tests + controller test pass; full BS suite green.

**Step 5 (commit):** `feat(bootstrap): sync-health banner on devices index`.

---

### T7 — BS: `/api/v1/sync_health` JSON endpoint (item #4 API)

**Objective:** Expose sync health as JSON for external monitoring (Datadog, Better Stack). Reuses existing `Ztlp::ApiAuthenticator` (per-zone HMAC pattern already in V1 endpoints).

**Files:**
- Create: `bootstrap/app/controllers/api/v1/sync_health_controller.rb`
- Modify: `bootstrap/config/routes.rb` — add the route under the existing `api/v1` namespace.
- Test: `bootstrap/test/controllers/api/v1/sync_health_controller_test.rb`

**Response shape:**
```json
{
  "status": "green",
  "last_success_at": "2026-06-07T14:32:01Z",
  "last_failure_at": null,
  "consecutive_failures": 0,
  "last_error_class": null,
  "next_retry_at": null
}
```

**Step 1 (RED):**
```ruby
test "GET /api/v1/sync_health with valid HMAC returns 200 + JSON" do
  Ztlp::SyncState.record_success!
  get "/api/v1/sync_health", headers: signed_headers_for_zone("trs.ztlp")
  assert_response :ok
  body = JSON.parse(response.body)
  assert_equal "green", body["status"]
  assert body["last_success_at"].present?
end

test "GET /api/v1/sync_health without HMAC returns 401" do
  get "/api/v1/sync_health"
  assert_response :unauthorized
end
```

**Step 2 (verify RED):** Route undefined → 404, not 401.

**Step 3 (GREEN):** Implement controller mirroring existing `Api::V1::*Controller` pattern. Reuse `before_action :authenticate!` from `Ztlp::ApiAuthenticator`.
```ruby
module Api
  module V1
    class SyncHealthController < ApplicationController
      before_action :authenticate_with_zone_hmac!

      def show
        state = Ztlp::SyncState.current
        render json: {
          status: helpers.sync_health_status(state),
          last_success_at: state[:last_success_at]&.iso8601,
          last_failure_at: state[:last_failure_at]&.iso8601,
          consecutive_failures: state[:consecutive_failures],
          last_error_class: state[:last_error_class],
          next_retry_at: state[:next_retry_at]&.iso8601
        }
      end
    end
  end
end
```

`routes.rb`:
```ruby
namespace :api do
  namespace :v1 do
    get "sync_health", to: "sync_health#show"
  end
end
```

**Step 4 (verify GREEN):** New tests pass; full BS suite green.

**Step 5 (commit):** `feat(bootstrap): /api/v1/sync_health JSON endpoint`.

---

### T8 — Full-suite sweep + CodeRabbit dry-run

**Objective:** Independent verification across both apps. Orchestrator-driven, no subagent needed.

**Steps:**
1. `cd /home/trs/ztlp/ns && mix test 2>&1 | tail -20` — assert `0 failures` (expect 833+ tests).
2. `cd /home/trs/ztlp/bootstrap && bin/rails test 2>&1 | tail -20` — assert `0 failures, 0 errors` (expect 1153+ tests).
3. `cd /home/trs/ztlp && git push origin feat/ns-sync-hardening` (using the openclaw key).
4. `gh pr create --base main --head feat/ns-sync-hardening --title "feat: NS sync production-readiness must-haves (items #1-4)" --body-file <plan-summary>` — body summarizes the 4 must-haves with checklist + links to source doc.
5. Wait ~3 min for CodeRabbit's first pass.
6. `gh pr view <N> --comments | grep -i 'major\\|critical'` — if any Major issues, dispatch a fixup subagent with the verbatim CodeRabbit comment.

**Step 5 (commit):** No code commit — but tracker row gets ✅. Include this status update in T9's commit.

---

### T9 — Docs: mark items 1-4 ✅ in production-readiness doc

**Objective:** Update `docs/plans/2026-06-07-ns-bootstrap-sync-production-readiness.md` to reflect that items #1-#4 are done. Cross-link the new PR. Update the "Recommended sequencing" table.

**Files:**
- Modify: `docs/plans/2026-06-07-ns-bootstrap-sync-production-readiness.md`
- Modify: `docs/plans/2026-06-07-ns-sync-must-haves.md` — flip all task rows + DONE row to ✅, backfill final SHA, update "Last resumed at".

**Edits to production-readiness doc:**
- For each of items 1-4: add `**Status: ✅ landed in PR #<N> (commit <SHA>)**` line under the heading.
- In the "Recommended sequencing" table, change Phase 1 row's status emoji.

**Step 5 (commit):** `docs: mark NS sync must-haves complete`.

---

## Resume Protocol (if session interrupted)

When a new session opens this plan:
1. Read the Progress Tracker — find the last row with status ✅.
2. The next row (🔲 or 🟡) is where to resume.
3. Run `cd /home/trs/ztlp && git log --oneline -15 feat/ns-sync-hardening` to confirm tracker matches commit history.
4. If tracker and git disagree, **trust git** and re-update the tracker.
5. Update "Last resumed at" in the next commit so the audit trail stays accurate.

---

## Open questions deferred to next phase

These came from the source doc and remain unanswered. They're explicitly OUT of scope for must-haves and tracked for Phase 2:

1. One global `ZTLP_NS_ADMIN_API_SECRET` vs per-zone from day one. (Item #6 in source.)
2. Dashboard scope — all networks vs current-tenant only. (Item #2 open question.)
3. Audit log destination — table vs separate file. (Item #3 open question.)

Decision point: revisit after Phase 1 lands and the new logs reveal real traffic patterns.
