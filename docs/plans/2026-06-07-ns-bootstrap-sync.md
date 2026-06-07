# NS → Bootstrap Sync Implementation Plan

> **For Hermes:** Use `subagent-driven-development` skill to implement this plan task-by-task with strict TDD (RED → GREEN → REFACTOR → commit).

**Goal:** Bootstrap dashboard reflects the live set of devices registered in NS so operators can manage devices/users from the Bootstrap UI. Source of truth = NS. Direction = NS → Bootstrap (one-way reconciliation).

**Architecture:**
- NS exposes a new authenticated JSON admin endpoint `GET /admin/records` on the existing `MetricsServer` listener port (9103). Returns the full set of records (filterable by `?type=` and `?zone=`) as JSON. Read-only.
- Bootstrap gets a new service `Ztlp::SyncNsToBootstrap` that fetches that endpoint over HTTP and reconciles `ZtlpDevice` rows against NS state, scoped to each `Network` (by zone match). Idempotent.
- A rake task `ztlp:ns:sync` invokes the service and prints a greppable summary; a recurring cron triggers it every 5 minutes inside the container.
- Drift surface: rows in NS that aren't in Bootstrap → created with `ztlp_user_id=NULL`, `status='enrolled'`, marker note `"imported from NS"`. Rows in Bootstrap that aren't in NS and weren't created by Bootstrap → marked `status='orphaned'` (a new value added to the enum). Bootstrap NEVER pushes changes back to NS.

**Tech stack:**
- NS: Elixir 1.15, OTP 26, raw `:gen_tcp` HTTP, existing `ZtlpNs.Store.list_filtered/1`, `Jason` (already a dep).
- Bootstrap: Rails 7.1, ActiveRecord, SQLite (prod), Minitest, Mocha. `Net::HTTP` over the SaaS host's docker bridge for NS→BS connectivity.
- Auth: shared-secret HMAC (`ZTLP_NS_ADMIN_API_SECRET`), same canonical-string pattern as `Ztlp::ApiAuthenticator` in Bootstrap. Single-leg (Bootstrap signs, NS verifies). No replay window beyond 5-minute clock skew.

---

## Progress Tracker

> State machine: 🔲 not started → 🟡 in progress → ✅ done → ❌ blocked. Update in the same commit as each task. SHA backfill goes in the NEXT task's commit (never amend).

| # | Task | Status | Commit SHA | Notes |
|---|---|---|---|---|
| T1 | NS: `ZtlpNs.AdminApi` HMAC verifier + tests | ✅ | _commit-pending_ | |
| T2 | NS: `ZtlpNs.AdminApi.list_records/1` + tests | 🔲 | — | |
| T3 | NS: HTTP route `GET /admin/records` in MetricsServer + tests | 🔲 | — | |
| T4 | NS: env var plumbing + config + Dockerfile | 🔲 | — | |
| T5 | BS: `Ztlp::NsAdminClient` HTTP client + tests | 🔲 | — | |
| T6 | BS: `ZtlpDevice` schema + `orphaned` status migration + tests | 🔲 | — | |
| T7 | BS: `Ztlp::SyncNsToBootstrap` reconciler + tests | 🔲 | — | |
| T8 | BS: `ztlp:ns:sync` rake task + cron entrypoint | 🔲 | — | |
| T9 | BS: Dashboard surfaces synced devices (UI badge + filter) | 🔲 | — | |
| T10 | Deploy to prod bootstrap + verify live sync against NS | 🔲 | — | |
| **DONE** | All tests green, devices visible in Bootstrap UI, PR opened | 🔲 | — | |

**Last resumed at:** _(populate on session restart)_

**Branch:** `feat/ns-bootstrap-sync`

---

## MANDATORY TDD/BDD DISCIPLINE — quoted verbatim into every implementer brief

Every task that produces production code MUST follow this exact ordered list. Do NOT paraphrase.

1. **RED**: Write a failing test that describes ONE concrete behavior. Run it. Watch it fail with the expected error. If it passes, you are testing existing behavior — rewrite the test.
2. **GREEN**: Write the minimum production code to make the test pass. Cheating (hardcoding return values) is acceptable in GREEN.
3. **Run the focused test** to verify GREEN.
4. **Run the full test suite for the package** to verify no regressions.
5. **REFACTOR** if needed, keeping all tests green throughout. Do NOT add new behavior.
6. **COMMIT** the test + production code + this plan's progress-tracker update in a SINGLE atomic commit.

Per-task commit message shape:
```
<type>(scope): <one-line summary>

<2-4 line body explaining the change + verification result>

T<N>: <task title from plan>
```

The progress-tracker row goes in with `_commit-pending_` as the SHA placeholder. The orchestrator backfills the real SHA in the NEXT task's commit. **NEVER amend a commit to fix the tracker SHA — that creates an infinite SHA-churn loop.**

---

## Task 1: NS — `ZtlpNs.AdminApi` HMAC verifier

**Objective:** Build the auth primitive that verifies HMAC-signed requests against the admin endpoint, with ±5-minute clock-skew tolerance.

**Files:**
- Create: `ns/lib/ztlp_ns/admin_api.ex`
- Create: `ns/test/ztlp_ns/admin_api_test.exs`

**Canonical signing string** (must match Bootstrap's `Ztlp::ApiAuthenticator` shape):
```
<METHOD>\n<PATH_WITH_QUERY>\n<TIMESTAMP>\n<SHA256_HEX(body)>
```
Body is empty for GET. Header names: `X-NS-Timestamp`, `X-NS-Signature` (hex HMAC-SHA256 of canonical string with shared secret).

**RED — failing test (write FIRST, run, watch fail):**
```elixir
defmodule ZtlpNs.AdminApiTest do
  use ExUnit.Case, async: true
  alias ZtlpNs.AdminApi

  @secret <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>

  describe "verify_request/4" do
    test "returns :ok for a valid signature within the time window" do
      ts = System.system_time(:second)
      canonical = "GET\n/admin/records\n#{ts}\n#{:crypto.hash(:sha256, "") |> Base.encode16(case: :lower)}"
      sig = :crypto.mac(:hmac, :sha256, @secret, canonical) |> Base.encode16(case: :lower)
      headers = %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => sig}
      assert :ok = AdminApi.verify_request("GET", "/admin/records", "", headers, secret: @secret)
    end

    test "returns {:error, :bad_signature} for a tampered signature" do
      ts = System.system_time(:second)
      headers = %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => String.duplicate("0", 64)}
      assert {:error, :bad_signature} = AdminApi.verify_request("GET", "/admin/records", "", headers, secret: @secret)
    end

    test "returns {:error, :stale_timestamp} for a timestamp older than 300s" do
      ts = System.system_time(:second) - 400
      canonical = "GET\n/admin/records\n#{ts}\n#{:crypto.hash(:sha256, "") |> Base.encode16(case: :lower)}"
      sig = :crypto.mac(:hmac, :sha256, @secret, canonical) |> Base.encode16(case: :lower)
      headers = %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => sig}
      assert {:error, :stale_timestamp} = AdminApi.verify_request("GET", "/admin/records", "", headers, secret: @secret)
    end

    test "returns {:error, :missing_header} when timestamp absent" do
      assert {:error, :missing_header} = AdminApi.verify_request("GET", "/admin/records", "", %{"x-ns-signature" => "abc"}, secret: @secret)
    end

    test "returns {:error, :missing_header} when signature absent" do
      assert {:error, :missing_header} = AdminApi.verify_request("GET", "/admin/records", "", %{"x-ns-timestamp" => "0"}, secret: @secret)
    end

    test "returns {:error, :no_secret} when secret is nil" do
      assert {:error, :no_secret} = AdminApi.verify_request("GET", "/admin/records", "", %{}, secret: nil)
    end

    test "signature is computed over the FULL path including query string" do
      ts = System.system_time(:second)
      path = "/admin/records?zone=trs.ztlp&type=key"
      canonical = "GET\n#{path}\n#{ts}\n#{:crypto.hash(:sha256, "") |> Base.encode16(case: :lower)}"
      sig = :crypto.mac(:hmac, :sha256, @secret, canonical) |> Base.encode16(case: :lower)
      headers = %{"x-ns-timestamp" => to_string(ts), "x-ns-signature" => sig}
      assert :ok = AdminApi.verify_request("GET", path, "", headers, secret: @secret)
      # Same signature against a different path must FAIL
      assert {:error, :bad_signature} = AdminApi.verify_request("GET", "/admin/records", "", headers, secret: @secret)
    end
  end
end
```

**Step 1: Write the test above.** Run `cd ns && mix test test/ztlp_ns/admin_api_test.exs` — expected FAIL with `module ZtlpNs.AdminApi is not available`.

**Step 2: GREEN — minimal implementation:**
```elixir
defmodule ZtlpNs.AdminApi do
  @moduledoc """
  Authenticated read-only admin HTTP API for NS. Verifies HMAC-SHA256
  signatures over a canonical 4-line signing string and gates access by
  a ±300 second clock skew window.
  """

  @skew_seconds 300

  @spec verify_request(String.t(), String.t(), binary(), map(), keyword()) ::
          :ok | {:error, atom()}
  def verify_request(method, path, body, headers, opts) do
    secret = Keyword.get(opts, :secret)
    cond do
      is_nil(secret) -> {:error, :no_secret}
      not Map.has_key?(headers, "x-ns-timestamp") -> {:error, :missing_header}
      not Map.has_key?(headers, "x-ns-signature") -> {:error, :missing_header}
      true ->
        ts_str = Map.fetch!(headers, "x-ns-timestamp")
        sig_hex = Map.fetch!(headers, "x-ns-signature")
        with {ts_int, ""} <- Integer.parse(ts_str),
             true <- abs(System.system_time(:second) - ts_int) <= @skew_seconds || {:error, :stale_timestamp},
             body_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower),
             canonical = "#{method}\n#{path}\n#{ts_int}\n#{body_hash}",
             expected = :crypto.mac(:hmac, :sha256, secret, canonical) |> Base.encode16(case: :lower) do
          if Plug.Crypto.secure_compare(expected, sig_hex), do: :ok, else: {:error, :bad_signature}
        else
          {:error, reason} -> {:error, reason}
          _ -> {:error, :bad_request}
        end
    end
  end
end
```

**Pitfall — `Plug.Crypto` is not a NS dep.** Replace with hand-rolled constant-time compare:
```elixir
defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
  :crypto.hash_equals(a, b)
end
defp secure_compare(_, _), do: false
```
If `:crypto.hash_equals/2` not available on this OTP, use `Enum.zip(:binary.bin_to_list(a), :binary.bin_to_list(b)) |> Enum.reduce(0, fn {x, y}, acc -> Bitwise.bor(acc, Bitwise.bxor(x, y)) end) |> Kernel.==(0)`. Test must still pass; failing test forces you to wire whichever works.

**Step 3: Run `mix test test/ztlp_ns/admin_api_test.exs`** — expected PASS, 7/7.

**Step 4: Run full NS test suite: `mix test`** — expected PASS, no new failures.

**Step 5: Commit + tracker update:**
```bash
git add ns/lib/ztlp_ns/admin_api.ex ns/test/ztlp_ns/admin_api_test.exs docs/plans/2026-06-07-ns-bootstrap-sync.md
git commit -m "feat(ns): add AdminApi HMAC verifier for read-only admin endpoints

ZtlpNs.AdminApi.verify_request/5 enforces HMAC-SHA256 signature over a
canonical 4-line string and ±300s clock-skew window. Same shape as
Bootstrap's ApiAuthenticator so the two systems share a mental model.

T1: NS AdminApi HMAC verifier + tests (7/7 green)"
```
Update tracker: T1 → ✅ `_commit-pending_`.

---

## Task 2: NS — `ZtlpNs.AdminApi.list_records/1` projection

**Objective:** Wrap `ZtlpNs.Store.list_filtered/1` into a JSON-safe projection. NEVER include `signature`, `signer_public_key`, or any other private key material in the projection (these are public Ed25519 pubkeys — fine to expose — but signature bytes should not leak; verify in test).

**Files:**
- Modify: `ns/lib/ztlp_ns/admin_api.ex` (add public `list_records/1`)
- Modify: `ns/test/ztlp_ns/admin_api_test.exs` (append `describe "list_records/1"`)

**Projection shape (JSON-encoded):**
```json
{
  "records": [
    {
      "name": "trsdc.tech-rockstars.trs.ztlp",
      "type": "key",
      "data": {"pubkey": "abcd…"},
      "created_at": 1717000000,
      "ttl": 86400,
      "serial": 3,
      "pubkey_hex": "abcd…"
    }
  ],
  "count": 30,
  "generated_at": 1717800000
}
```

**RED — append to `admin_api_test.exs`:**
```elixir
describe "list_records/1" do
  setup do
    # Reset the store, then insert two records with different types/zones.
    ZtlpNs.Store.clear_all()
    keypair_a = ZtlpNs.Crypto.generate_keypair()
    keypair_b = ZtlpNs.Crypto.generate_keypair()
    rec_a = ZtlpNs.Record.new(:key, "trsdc.tech-rockstars.trs.ztlp", %{pubkey: keypair_a.public}, ttl: 86400)
            |> ZtlpNs.Record.sign(keypair_a)
    rec_b = ZtlpNs.Record.new(:svc, "dan.adms.trs.ztlp", %{port: 22}, ttl: 86400)
            |> ZtlpNs.Record.sign(keypair_b)
    :ok = ZtlpNs.Store.insert(rec_a)
    :ok = ZtlpNs.Store.insert(rec_b)
    %{rec_a: rec_a, rec_b: rec_b}
  end

  test "returns every non-expired record as a JSON-safe map", %{rec_a: rec_a, rec_b: rec_b} do
    result = ZtlpNs.AdminApi.list_records([])
    assert result.count == 2
    names = Enum.map(result.records, & &1.name) |> Enum.sort()
    assert names == [rec_b.name, rec_a.name] |> Enum.sort()
  end

  test "filters by zone suffix" do
    result = ZtlpNs.AdminApi.list_records(zone: "tech-rockstars.trs.ztlp")
    assert result.count == 1
    assert hd(result.records).name == "trsdc.tech-rockstars.trs.ztlp"
  end

  test "filters by type" do
    result = ZtlpNs.AdminApi.list_records(type: :svc)
    assert result.count == 1
    assert hd(result.records).type == "svc"
  end

  test "projection MUST NOT include raw signature bytes" do
    result = ZtlpNs.AdminApi.list_records([])
    Enum.each(result.records, fn rec ->
      refute Map.has_key?(rec, :signature)
      refute Map.has_key?(rec, "signature")
    end)
  end

  test "type field is serialized as a string, not an atom" do
    result = ZtlpNs.AdminApi.list_records([])
    Enum.each(result.records, fn rec -> assert is_binary(rec.type) end)
  end

  test "result encodes cleanly to JSON" do
    result = ZtlpNs.AdminApi.list_records([])
    assert {:ok, _json} = Jason.encode(result)
  end

  test "pubkey is rendered as hex" do
    result = ZtlpNs.AdminApi.list_records(type: :key)
    rec = hd(result.records)
    assert is_binary(rec.pubkey_hex)
    assert String.match?(rec.pubkey_hex, ~r/^[0-9a-f]+$/)
  end
end
```

**Step 1: Run** `mix test test/ztlp_ns/admin_api_test.exs` → expected FAIL on `list_records/1 is undefined`.

**Step 2: GREEN — minimal implementation appended to `admin_api.ex`:**
```elixir
@type list_opts :: [type: atom() | nil, zone: String.t() | nil]

@spec list_records(list_opts()) :: %{records: [map()], count: non_neg_integer(), generated_at: non_neg_integer()}
def list_records(opts \\ []) do
  records =
    ZtlpNs.Store.list_filtered(opts)
    |> Enum.map(&project/1)
  %{records: records, count: length(records), generated_at: System.system_time(:second)}
end

defp project({name, type, %ZtlpNs.Record{} = r}) do
  base = %{
    name: name,
    type: Atom.to_string(type),
    data: r.data,
    created_at: r.created_at,
    ttl: r.ttl,
    serial: r.serial
  }
  case Map.get(r.data, :pubkey) || Map.get(r.data, "pubkey") do
    bin when is_binary(bin) -> Map.put(base, :pubkey_hex, Base.encode16(bin, case: :lower))
    _ -> base
  end
end
```

**Step 3: `mix test test/ztlp_ns/admin_api_test.exs`** — PASS, 14/14.

**Step 4: `mix test`** — PASS overall.

**Step 5: Commit + tracker:**
```bash
git add ns/lib/ztlp_ns/admin_api.ex ns/test/ztlp_ns/admin_api_test.exs docs/plans/2026-06-07-ns-bootstrap-sync.md
git commit -m "feat(ns): AdminApi.list_records/1 JSON projection

Projects ZtlpNs.Store.list_filtered/1 output into a JSON-safe shape
that excludes raw signature bytes. Pubkey rendered as lowercase hex.
Type rendered as a string so external JSON consumers don't need to
re-atomize on receive.

T2: NS AdminApi list_records projection + tests (7 new, 14 total)"
```
Backfill T1's SHA in tracker (from `git log` line 2). Update T2 → ✅ `_commit-pending_`.

---

## Task 3: NS — HTTP route `GET /admin/records` in MetricsServer

**Objective:** Wire the AdminApi into the existing `:gen_tcp` HTTP server. Reject unauthenticated requests with 401. Respond with JSON on success.

**Files:**
- Modify: `ns/lib/ztlp_ns/metrics_server.ex` (`handle_request/1` — add route)
- Create: `ns/test/ztlp_ns/admin_api_http_test.exs` (integration test over real TCP)

**RED — write `admin_api_http_test.exs`** that boots a `MetricsServer` on a random port, signs a request with the test secret, hits it with `:httpc`, asserts JSON body. Mirror the structure of any existing HTTP-level test in the NS suite (search for `httpc` or `gen_tcp.accept` in test/).

Skeleton:
```elixir
defmodule ZtlpNs.AdminApiHttpTest do
  use ExUnit.Case
  alias ZtlpNs.AdminApi

  @secret :crypto.strong_rand_bytes(32)

  setup do
    Application.put_env(:ztlp_ns, :admin_api_secret, @secret)
    ZtlpNs.Store.clear_all()
    # ... insert one signed record ...
    {:ok, port: 9103}  # the metrics server uses the configured port
  end

  test "GET /admin/records with valid signature returns JSON 200" do
    ts = System.system_time(:second)
    path = "/admin/records"
    canonical = "GET\n#{path}\n#{ts}\n#{:crypto.hash(:sha256, "") |> Base.encode16(case: :lower)}"
    sig = :crypto.mac(:hmac, :sha256, @secret, canonical) |> Base.encode16(case: :lower)
    headers = [
      {~c"X-NS-Timestamp", String.to_charlist(to_string(ts))},
      {~c"X-NS-Signature", String.to_charlist(sig)}
    ]
    {:ok, {{_, 200, _}, _resp_headers, body}} =
      :httpc.request(:get, {~c"http://127.0.0.1:9103#{path}", headers}, [], [])
    {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))
    assert is_list(parsed["records"])
    assert is_integer(parsed["count"])
  end

  test "GET /admin/records with no signature returns 401" do
    {:ok, {{_, 401, _}, _, _}} =
      :httpc.request(:get, {~c"http://127.0.0.1:9103/admin/records", []}, [], [])
  end

  test "GET /admin/records with bad signature returns 401" do
    headers = [
      {~c"X-NS-Timestamp", ~c"0"},
      {~c"X-NS-Signature", String.to_charlist(String.duplicate("0", 64))}
    ]
    {:ok, {{_, 401, _}, _, _}} =
      :httpc.request(:get, {~c"http://127.0.0.1:9103/admin/records", headers}, [], [])
  end
end
```

**Step 1: Run** test → expected FAIL (route doesn't exist; current `handle_request` only handles `/metrics`, `/health`, `/ready`).

**Step 2: GREEN — patch `metrics_server.ex` `handle_request/1`** to add a clause matching `/admin/records` (with optional query string). On match:
- Parse query string into a keyword list of `type:` (atom) and `zone:` (string).
- Read all relevant request headers into a downcase-keyed map.
- Call `AdminApi.verify_request("GET", path_with_query, "", headers, secret: configured_secret())`.
- If `:ok`, call `AdminApi.list_records(opts)`, JSON-encode, respond 200 `application/json`.
- If `{:error, _}`, respond 401 with empty body. Audit-log the failure reason (use existing `Logger.warning/1`, do NOT include the reason in the response body — same pattern as Bootstrap's `ApiAuthenticator`).

Where to read the secret: `Application.get_env(:ztlp_ns, :admin_api_secret)`. **Read the secret on every request** — not at boot — so rotation via `:application.set_env` works without a server restart.

**Step 3: Run** the new HTTP test → expected PASS, 3/3. Run full `mix test` → no regressions.

**Step 4: Commit + tracker:**
```bash
git add ns/lib/ztlp_ns/metrics_server.ex ns/test/ztlp_ns/admin_api_http_test.exs docs/plans/2026-06-07-ns-bootstrap-sync.md
git commit -m "feat(ns): wire GET /admin/records into MetricsServer

Adds an authenticated read-only route that returns AdminApi.list_records/1
output as JSON. 401 on missing/bad signature; reason logged but not
echoed in the response body (same pattern as Bootstrap's ApiAuthenticator).

T3: NS HTTP route + integration tests (3 new)"
```
Backfill T2 SHA. T3 → ✅.

---

## Task 4: NS — env var plumbing + Dockerfile

**Objective:** Make the admin API secret configurable via `ZTLP_NS_ADMIN_API_SECRET` env var. Boot-time logging so an operator can confirm the secret was loaded. NO crash if the secret is missing — the route just keeps returning 401.

**Files:**
- Modify: `ns/lib/ztlp_ns/application.ex` (read env var, persist to Application env on boot)
- Modify: `ns/lib/ztlp_ns/config.ex` (add accessor)
- Modify: `ns/test/ztlp_ns/application_test.exs` or create a new `config_test.exs`

**RED — write a test** that sets `ZTLP_NS_ADMIN_API_SECRET=deadbeef...` via `System.put_env/2`, calls the boot-time loader, asserts `Application.get_env(:ztlp_ns, :admin_api_secret)` returns the matching 32-byte binary. Hex value should be hex-decoded; bare strings should error or be rejected (verify in test).

**Step 1: Run test → FAIL.**

**Step 2: GREEN.** Add a single function `ZtlpNs.Config.load_admin_api_secret_from_env/0` that:
- Reads `ZTLP_NS_ADMIN_API_SECRET`.
- If 64 hex chars → decode and store the 32-byte binary.
- If 32+ raw bytes → store as-is.
- If empty/nil → log `Logger.info("[admin_api] secret not configured; /admin/records will reject all requests")` and store `nil`.
- Otherwise → `Logger.warning("[admin_api] secret has unexpected length: #{byte_size}")` and store `nil`.

Call it from `application.ex#start/2` BEFORE supervisor children are spawned.

**Step 3: Tests pass + full `mix test` clean.**

**Step 4: Update Dockerfile** — no source changes needed if the secret is already passed via env file mount. Verify by grepping `ns/Dockerfile` for `ENV` and `ARG` patterns; the existing pattern propagates docker-compose env vars without code changes. Document the variable in `ns/README.md` or `ns/lib/ztlp_ns/application.ex` module-doc.

**Step 5: Commit + tracker:**
```bash
git add ns/lib/ztlp_ns/config.ex ns/lib/ztlp_ns/application.ex ns/test/ztlp_ns/config_test.exs docs/plans/2026-06-07-ns-bootstrap-sync.md
git commit -m "feat(ns): ZTLP_NS_ADMIN_API_SECRET env var plumbing

Loads admin API secret from env at boot, accepts hex or raw bytes, logs
absence without crashing. Required to enable Bootstrap → NS sync.

T4: NS env var plumbing + boot-time config (2 new tests)"
```
Backfill T3 SHA. T4 → ✅.

---

## Task 5: Bootstrap — `Ztlp::NsAdminClient` HTTP client

**Objective:** Rails-side HTTP client that signs and dispatches requests to NS's `/admin/records`. Pure Ruby `Net::HTTP`, retries on transient errors, raises typed errors on auth/server failure.

**Files:**
- Create: `bootstrap/app/services/ztlp/ns_admin_client.rb`
- Create: `bootstrap/test/services/ztlp/ns_admin_client_test.rb`

**Public API:**
```ruby
Ztlp::NsAdminClient.list_records(zone: nil, type: nil)  # returns Hash w/ "records", "count", "generated_at"
Ztlp::NsAdminClient.list_records(zone: nil, type: nil, base_url: "http://...", secret: "..." )  # for tests
```

**Errors (raise these specific classes):**
- `Ztlp::NsAdminClient::ConfigurationError` — secret or base_url missing
- `Ztlp::NsAdminClient::AuthenticationError` — HTTP 401 from NS
- `Ztlp::NsAdminClient::ServerError` — HTTP 5xx
- `Ztlp::NsAdminClient::TransportError` — connection refused, timeout

**RED — failing test:**
```ruby
require "test_helper"
require "webmock/minitest" # check Gemfile; if missing, mock via Net::HTTP.stubs

class Ztlp::NsAdminClientTest < ActiveSupport::TestCase
  SECRET = SecureRandom.hex(32)
  BASE = "http://ns.test:9103".freeze

  test "list_records signs the request with HMAC and parses JSON" do
    stub_request(:get, "#{BASE}/admin/records")
      .with do |req|
        ts = req.headers["X-Ns-Timestamp"]
        sig = req.headers["X-Ns-Signature"]
        canonical = "GET\n/admin/records\n#{ts}\n#{Digest::SHA256.hexdigest("")}"
        expected = OpenSSL::HMAC.hexdigest("sha256", [SECRET].pack("H*"), canonical)
        sig == expected
      end
      .to_return(status: 200, body: {records: [{name: "x", type: "key"}], count: 1, generated_at: 0}.to_json,
                 headers: {"Content-Type" => "application/json"})

    result = Ztlp::NsAdminClient.list_records(base_url: BASE, secret: SECRET)
    assert_equal 1, result["count"]
    assert_equal "x", result["records"][0]["name"]
  end

  test "raises AuthenticationError on 401" do
    stub_request(:get, "#{BASE}/admin/records").to_return(status: 401)
    assert_raises(Ztlp::NsAdminClient::AuthenticationError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: SECRET)
    end
  end

  test "raises ServerError on 500" do
    stub_request(:get, "#{BASE}/admin/records").to_return(status: 500)
    assert_raises(Ztlp::NsAdminClient::ServerError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: SECRET)
    end
  end

  test "raises ConfigurationError when secret missing" do
    assert_raises(Ztlp::NsAdminClient::ConfigurationError) do
      Ztlp::NsAdminClient.list_records(base_url: BASE, secret: nil)
    end
  end

  test "raises ConfigurationError when base_url missing" do
    assert_raises(Ztlp::NsAdminClient::ConfigurationError) do
      Ztlp::NsAdminClient.list_records(base_url: nil, secret: SECRET)
    end
  end

  test "passes zone and type as query params and signs over the FULL path" do
    stub_request(:get, "#{BASE}/admin/records?type=key&zone=trs.ztlp")
      .with do |req|
        ts = req.headers["X-Ns-Timestamp"]
        sig = req.headers["X-Ns-Signature"]
        # Path includes query string in canonical signing
        canonical = "GET\n/admin/records?type=key&zone=trs.ztlp\n#{ts}\n#{Digest::SHA256.hexdigest("")}"
        expected = OpenSSL::HMAC.hexdigest("sha256", [SECRET].pack("H*"), canonical)
        sig == expected
      end
      .to_return(status: 200, body: {records: [], count: 0, generated_at: 0}.to_json)

    Ztlp::NsAdminClient.list_records(zone: "trs.ztlp", type: "key", base_url: BASE, secret: SECRET)
  end

  test "ENV-based config falls through when args omitted" do
    ENV["ZTLP_NS_ADMIN_BASE_URL"] = BASE
    ENV["ZTLP_NS_ADMIN_API_SECRET"] = SECRET
    stub_request(:get, "#{BASE}/admin/records").to_return(status: 200, body: '{"records":[],"count":0,"generated_at":0}')
    Ztlp::NsAdminClient.list_records
  ensure
    ENV.delete("ZTLP_NS_ADMIN_BASE_URL")
    ENV.delete("ZTLP_NS_ADMIN_API_SECRET")
  end
end
```

**If `webmock` isn't in the Gemfile**, fall back to `Net::HTTP.stubs` via Mocha — the bootstrap test stack already loads Mocha (skill confirmed). Verify with `grep webmock bootstrap/Gemfile.lock` first; choose mock pattern based on what's available.

**Step 1: Run** `cd bootstrap && bin/rails test test/services/ztlp/ns_admin_client_test.rb -v` → FAIL.

**Step 2: GREEN** — minimal Ruby `Net::HTTP` client.

```ruby
require "net/http"
require "openssl"
require "digest"
require "json"

module Ztlp
  class NsAdminClient
    class Error < StandardError; end
    class ConfigurationError < Error; end
    class AuthenticationError < Error; end
    class ServerError < Error; end
    class TransportError < Error; end

    PATH = "/admin/records".freeze

    def self.list_records(zone: nil, type: nil, base_url: nil, secret: nil, timeout: 10)
      base_url ||= ENV["ZTLP_NS_ADMIN_BASE_URL"]
      secret   ||= ENV["ZTLP_NS_ADMIN_API_SECRET"]
      raise ConfigurationError, "base_url missing" if base_url.to_s.empty?
      raise ConfigurationError, "secret missing"   if secret.to_s.empty?

      query = {}
      query[:type] = type if type
      query[:zone] = zone if zone
      qs = query.empty? ? "" : "?" + query.sort.map { |k, v| "#{k}=#{v}" }.join("&")
      path = PATH + qs

      ts  = Time.now.to_i
      body = ""
      canonical = "GET\n#{path}\n#{ts}\n#{Digest::SHA256.hexdigest(body)}"
      secret_bytes = [secret].pack("H*")  # accept hex; fall back to raw if length mismatch
      secret_bytes = secret if secret_bytes.bytesize != 32 && secret.bytesize == 32
      sig = OpenSSL::HMAC.hexdigest("sha256", secret_bytes, canonical)

      uri = URI.join(base_url, path)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = timeout
      http.read_timeout = timeout
      req = Net::HTTP::Get.new(uri.request_uri)
      req["X-NS-Timestamp"] = ts.to_s
      req["X-NS-Signature"] = sig

      begin
        resp = http.request(req)
      rescue StandardError => e
        raise TransportError, "#{e.class}: #{e.message}"
      end

      case resp.code.to_i
      when 200 then JSON.parse(resp.body)
      when 401 then raise AuthenticationError, "NS rejected signature"
      when 500..599 then raise ServerError, "NS returned HTTP #{resp.code}"
      else raise Error, "NS returned unexpected HTTP #{resp.code}"
      end
    end
  end
end
```

**Step 3: Tests pass + full `bin/rails test` clean.**

**Step 4: Commit + tracker. T5 → ✅.**

---

## Task 6: Bootstrap — `ZtlpDevice.status='orphaned'` migration

**Objective:** Add an `'orphaned'` value to the `ZtlpDevice` status enum, plus an `origin` column (`'bootstrap'` | `'ns_sync'`) to distinguish synced devices from native ones. Plus a `last_synced_at` timestamp.

**Files:**
- Create: `bootstrap/db/migrate/<timestamp>_add_sync_fields_to_ztlp_devices.rb`
- Modify: `bootstrap/app/models/ztlp_device.rb`
- Create: `bootstrap/test/models/ztlp_device_sync_test.rb`

Migration:
```ruby
class AddSyncFieldsToZtlpDevices < ActiveRecord::Migration[7.1]
  def change
    add_column :ztlp_devices, :origin, :string, null: false, default: "bootstrap"
    add_column :ztlp_devices, :last_synced_at, :datetime
    add_index  :ztlp_devices, :origin
  end
end
```

Model additions:
```ruby
class ZtlpDevice < ApplicationRecord
  VALID_STATUSES = %w[pending enrolled revoked orphaned].freeze
  VALID_ORIGINS  = %w[bootstrap ns_sync].freeze

  validates :status, inclusion: { in: VALID_STATUSES }
  validates :origin, inclusion: { in: VALID_ORIGINS }

  scope :synced_from_ns, -> { where(origin: "ns_sync") }
  scope :orphaned,       -> { where(status: "orphaned") }
  def synced_from_ns? = origin == "ns_sync"
  def orphaned?       = status == "orphaned"
end
```

**RED** — write a 6-test model spec covering: default origin is `bootstrap`, `orphaned` is valid, unknown status fails, `synced_from_ns?` predicate, `orphaned?` predicate, `VALID_STATUSES` constant locked.

**Steps:** standard TDD cycle. Run migration in test DB, run tests, commit. **Do NOT run the migration against production in this task** — that happens in T10.

**Step 5: Commit. T6 → ✅.**

---

## Task 7: Bootstrap — `Ztlp::SyncNsToBootstrap` reconciler

**Objective:** The actual sync engine. Pulls NS records (key + svc types), groups by name, routes each name to the correct `Network` by zone suffix, upserts a `ZtlpDevice` per name, marks Bootstrap-side rows as `orphaned` if they are `origin=ns_sync` but no longer appear in NS.

**Files:**
- Create: `bootstrap/app/services/ztlp/sync_ns_to_bootstrap.rb`
- Create: `bootstrap/test/services/ztlp/sync_ns_to_bootstrap_test.rb`

**Result struct:** `Result.new(created:, updated:, orphaned:, skipped:, errors:, status:)` with predicates `error?`, `success?`.

**Routing logic — zone suffix match (longest match wins):**
- Given device name `dan.adms.trs.ztlp`, candidates are zones ending the name: `adms.trs.ztlp`, `trs.ztlp`, `ztlp`.
- Pick the longest one that has a `Network` row.
- If no match, `skipped += 1` with reason `"no_matching_network"`.

**RED — write tests** that cover:
1. NS returns 2 keys, both in zone `trs.ztlp` — both upserted as new `ZtlpDevice`s on Network 1.
2. NS returns 1 key in `adms.trs.ztlp` and 1 in `tech-rockstars.trs.ztlp` — routed to Networks 6 and 3 respectively (longest match).
3. Re-run is idempotent (no new rows).
4. NS removed a device that was previously synced → Bootstrap-side row gets `status='orphaned'`, NOT deleted.
5. Bootstrap-side row with `origin='bootstrap'` is NEVER touched even if not in NS (the hand-entered `hermes-op-z2lsapp1` must survive a sync run unchanged).
6. NS returns a name with no matching network → `skipped` increments, no row created, no exception.
7. `pubkey_hex` from NS lands in the `pubkey` column on the device.
8. `last_synced_at` is bumped to `Time.current` on every touch (created OR updated).
9. Returns `Result` with status=`:ok` on success and aggregate counts.
10. If `NsAdminClient` raises `TransportError`, `call` returns `Result` with status=`:error`, does NOT raise.

```ruby
# Skeleton — fill in by RED-then-GREEN
class Ztlp::SyncNsToBootstrapTest < ActiveSupport::TestCase
  setup do
    @network_trs   = networks(:trs)    # zone: trs.ztlp
    @network_tr    = networks(:tech_rockstars_z2ls) # zone: tech-rockstars.trs.ztlp
    @network_adms  = networks(:adms)   # zone: adms.trs.ztlp
  end

  test "creates ZtlpDevice for each NS key record" do
    stub_ns_response([
      {name: "TRSDC.trs.ztlp",        type: "key", pubkey_hex: "aa"*32, ttl: 86400, created_at: 1, serial: 1, data: {}},
      {name: "alice.adms.trs.ztlp",   type: "key", pubkey_hex: "bb"*32, ttl: 86400, created_at: 1, serial: 1, data: {}}
    ])
    result = Ztlp::SyncNsToBootstrap.call
    assert result.success?
    assert_equal 2, result.created
    assert ZtlpDevice.exists?(name: "TRSDC.trs.ztlp", network: @network_trs, origin: "ns_sync")
    assert ZtlpDevice.exists?(name: "alice.adms.trs.ztlp", network: @network_adms, origin: "ns_sync")
  end

  # ... etc, one test per RED-GREEN cycle ...
end
```

Service skeleton:
```ruby
module Ztlp
  class SyncNsToBootstrap
    Result = Struct.new(:status, :created, :updated, :orphaned, :skipped, :errors, :message, keyword_init: true) do
      def success? = status == :ok
      def error?   = status == :error
    end

    def self.call(**kwargs) = new(**kwargs).call

    def initialize(client: Ztlp::NsAdminClient, clock: Time)
      @client, @clock = client, clock
    end

    def call
      payload = @client.list_records(type: "key")
      records = payload["records"]
      networks_by_zone = Network.all.index_by(&:zone)
      sorted_zones = networks_by_zone.keys.sort_by { |z| -z.length }

      seen_names = []
      counts = { created: 0, updated: 0, orphaned: 0, skipped: 0 }
      errors = []

      records.each do |rec|
        network = match_network(rec["name"], sorted_zones, networks_by_zone)
        unless network
          counts[:skipped] += 1
          errors << { name: rec["name"], reason: "no_matching_network" }
          next
        end

        device = ZtlpDevice.find_by(name: rec["name"], network_id: network.id)
        if device.nil?
          ZtlpDevice.create!(
            name: rec["name"], network_id: network.id,
            origin: "ns_sync", status: "enrolled",
            pubkey: rec["pubkey_hex"], enrolled_at: Time.at(rec["created_at"]),
            last_synced_at: @clock.current
          )
          counts[:created] += 1
        else
          device.update!(
            pubkey: rec["pubkey_hex"],
            status: device.status == "orphaned" ? "enrolled" : device.status,
            last_synced_at: @clock.current
          )
          counts[:updated] += 1
        end
        seen_names << [rec["name"], network.id]
      end

      # Orphan sweep — only touch rows we own.
      synced = ZtlpDevice.where(origin: "ns_sync").where.not(status: "orphaned")
      synced.find_each do |d|
        unless seen_names.include?([d.name, d.network_id])
          d.update!(status: "orphaned")
          counts[:orphaned] += 1
        end
      end

      Result.new(status: :ok, errors: errors, **counts, message: "sync ok")
    rescue Ztlp::NsAdminClient::Error => e
      Result.new(status: :error, message: "#{e.class}: #{e.message}",
                 created: 0, updated: 0, orphaned: 0, skipped: 0, errors: [])
    end

    private

    def match_network(name, sorted_zones, networks_by_zone)
      hit = sorted_zones.find { |z| name.downcase.end_with?(".#{z.downcase}") || name.downcase == z.downcase }
      hit && networks_by_zone[hit]
    end
  end
end
```

**Step 5: Commit. T7 → ✅.**

---

## Task 8: Bootstrap — `ztlp:ns:sync` rake task + cron entrypoint

**Objective:** Operator-callable rake task. Daily/5-minute cron via the existing `bin/docker-entrypoint` pattern (or whatever scheduling mechanism the container uses; check `bootstrap/bin/docker-entrypoint` and `bootstrap/config/schedule.rb` if present).

**Files:**
- Create: `bootstrap/lib/tasks/ztlp_ns_sync.rake`
- Modify: `bootstrap/bin/docker-entrypoint` (add cron entry or a simple loop)
- Create: `bootstrap/test/tasks/ztlp_ns_sync_test.rb` (calls the task via `Rake::Task["ztlp:ns:sync"].execute`)

```ruby
namespace :ztlp do
  namespace :ns do
    desc "Reconcile ZtlpDevice rows against NS state"
    task sync: :environment do
      result = Ztlp::SyncNsToBootstrap.call
      puts "[ztlp:ns:sync] status=#{result.status} created=#{result.created} updated=#{result.updated} orphaned=#{result.orphaned} skipped=#{result.skipped} errors=#{result.errors.size}"
      result.errors.first(10).each { |e| puts "  skip: #{e[:name]} (#{e[:reason]})" }
      AuditLog.create!(action: "ztlp.ns.sync", status: result.status.to_s,
                       details: { created: result.created, updated: result.updated, orphaned: result.orphaned, skipped: result.skipped, errors: result.errors.first(20) })
      exit(result.error? ? 2 : 0)
    end
  end
end
```

Cron approach (simplest, given the existing entrypoint pattern): append a background `while true; do bundle exec rake ztlp:ns:sync; sleep 300; done &` to the entrypoint script, guarded by `ZTLP_NS_SYNC_ENABLED=true`. Don't add `whenever` gem; the dep weight isn't worth it.

**Step 5: Commit. T8 → ✅.**

---

## Task 9: Bootstrap — Dashboard surfaces synced devices

**Objective:** Operator can see at a glance which devices came from NS vs. Bootstrap-native, and filter by status (esp. `orphaned`).

**Files:**
- Modify: `bootstrap/app/views/ztlp_devices/index.html.erb`
- Modify: `bootstrap/app/controllers/ztlp_devices_controller.rb`
- Modify: `bootstrap/test/controllers/ztlp_devices_controller_test.rb`

Changes:
1. Add a `Source` column showing badge `[NS]` for `ns_sync`, `[BS]` for `bootstrap`.
2. Add status filter dropdown with `pending|enrolled|revoked|orphaned`.
3. Render `last_synced_at` (humanized "5 minutes ago") if present.

**RED**: write a controller integration test asserting the filter scopes the result set and the badges render. **GREEN**: implement.

**Step 5: Commit. T9 → ✅.**

---

## Task 10: Deploy to production + verify live sync

**Objective:** Ship the change to the live SaaS tenant and verify devices appear in the Bootstrap dashboard.

**Pre-deploy checks (orchestrator-run, not subagent):**
- All tests green on the feature branch: `cd ns && mix test && cd ../bootstrap && bin/rails test`.
- `git log --oneline main..feat/ns-bootstrap-sync` shows T1-T9 commits with proper TDD pairing (test + impl in same commit).

**Deploy steps:**

1. Build images locally and push:
   ```bash
   # NS
   docker build -t priceflex/ztlp-ns:v0.34.10 ns/
   docker push priceflex/ztlp-ns:v0.34.10
   # Bootstrap
   docker build -t priceflex/ztlp-bootstrap:v0.34.10 bootstrap/
   docker push priceflex/ztlp-bootstrap:v0.34.10
   ```

2. **⚠ Warn Steve before restarting NS** (his iOS bench crashes on NS restart). Wait for "freedom to restart" confirmation OR defer this task and stop here.

3. Generate the shared HMAC secret:
   ```bash
   openssl rand -hex 32  # save this value
   ```

4. SSH to SaaS host, update env files:
   ```bash
   ssh -i /home/trs/ztlp/.ssh/ztlp_aws_key ubuntu@16.147.41.195
   # NS env: ~/ztlp.net/.env (or wherever ztlp-ns reads its env)
   echo "ZTLP_NS_ADMIN_API_SECRET=<hex>" | sudo tee -a ~/ztlp.net/.env
   # Bootstrap-tech-rockstars env: launch instance dir
   INSTANCE_DIR=$(grep -l "ZTLP_INSTANCE_SLUG=tech-rockstars" ~/launch/instances/*/instance.env | xargs dirname)
   echo "ZTLP_NS_ADMIN_API_SECRET=<hex>" | sudo tee -a "$INSTANCE_DIR/secrets.env"
   echo "ZTLP_NS_ADMIN_BASE_URL=http://172.18.0.3:9103" | sudo tee -a "$INSTANCE_DIR/secrets.env"
   echo "ZTLP_NS_SYNC_ENABLED=true" | sudo tee -a "$INSTANCE_DIR/secrets.env"
   ```

5. **Cross-network fix:** Bootstrap container is on `tech-rockstars_default` (172.19.0.0/16) and NS is on `ztlpnet_default` (172.18.0.0/16). They cannot reach each other. **Connect the bootstrap container to ztlpnet_default**:
   ```bash
   sudo docker network connect ztlpnet_default ztlp-bootstrap-tech-rockstars
   # Verify
   sudo docker exec ztlp-bootstrap-tech-rockstars getent hosts ztlp-ns
   ```
   Use the docker DNS name `http://ztlp-ns:9103` rather than the raw IP in `ZTLP_NS_ADMIN_BASE_URL` once the network is connected.

6. Recreate NS + bootstrap-tech-rockstars containers:
   ```bash
   cd ~/ztlp.net && sudo docker compose pull ns && sudo docker compose up -d ns
   # ⚠ NS RESTART @ <UTC time>
   cd "$INSTANCE_DIR" && sudo docker compose pull bootstrap && sudo docker compose up -d bootstrap
   # ⚠ BOOTSTRAP-TECH-ROCKSTARS RESTART @ <UTC time>
   ```

7. Run the sync manually first to validate before letting cron take over:
   ```bash
   sudo docker exec ztlp-bootstrap-tech-rockstars bundle exec rake ztlp:ns:sync
   ```
   Expected output: `status=ok created=15 updated=0 orphaned=0 skipped=0 errors=0` (or similar — matching the ~15 unique NS keys captured during recon).

8. Verify in DB:
   ```bash
   sudo docker exec ztlp-bootstrap-tech-rockstars bin/rails runner '
     puts "ZtlpDevice count: #{ZtlpDevice.count}"
     puts "  ns_sync: #{ZtlpDevice.synced_from_ns.count}"
     puts "  bootstrap: #{ZtlpDevice.where(origin: "bootstrap").count}"
     ZtlpDevice.synced_from_ns.limit(20).each { |d| puts "  #{d.name} (network=#{d.network.zone}, status=#{d.status})" }
   '
   ```

9. Verify in UI: click through `https://www.ztlp.net/` claim flow → Bootstrap dashboard → Devices tab → see synced rows with `[NS]` badge.

10. Re-run sync; verify `created=0 updated=15` (idempotency check).

11. Test orphan: delete one NS record via RPC, re-run sync, assert the corresponding Bootstrap row flips to `orphaned`. Re-insert in NS, re-run, assert it flips back to `enrolled`.

**Commit on success** with a release-notes commit summarizing the feature. Open the PR.

**Step 5: Tracker T10 → ✅. DONE row → ✅.**

---

## Resume Protocol (if session interrupted)

1. Read the Progress Tracker above — find the last row with status ✅.
2. The next row (🔲 or 🟡) is where to resume.
3. Run `git log --oneline -15 feat/ns-bootstrap-sync` to confirm tracker matches commit history.
4. If tracker and git disagree, **trust git** and fix the tracker in the next commit.
5. Update "Last resumed at" in the next commit.

## Risk Triage

- **Highest risk: T3** (NS HTTP route in `:gen_tcp` raw HTTP server). The existing MetricsServer parses HTTP itself; getting query-string parsing + header casing right is fiddly. **Mitigation:** the integration test in T3 boots a real listener over loopback, so any parse bug surfaces in CI before deploy.
- **Second risk: T10 step 5** (cross-docker-network reachability). If `docker network connect` fails or the bootstrap container can't resolve `ztlp-ns`, the manual sync in step 7 will throw `TransportError` immediately. **Mitigation:** validate connectivity with `getent hosts ztlp-ns` BEFORE running the rake task.
- **Third risk:** schema drift between NS Record struct and Bootstrap projection (e.g. NS atomizes `:key` but JSON gives `"key"`). **Mitigation:** T2 test explicitly asserts type is a string in JSON.
- **Lower risk:** `Ztlp::SyncNsToBootstrap` orphaning a row Steve added by hand. **Mitigation:** the orphan sweep is scoped to `origin = 'ns_sync'`, so bootstrap-native rows are immune.

## Out of scope (do NOT do)

- Pushing Bootstrap-side changes back to NS (NS is source of truth, one-way only).
- Auto-assigning `ZtlpUser` ownership to synced devices (operator does this manually in the UI; Bootstrap doesn't have a heuristic that would work cross-customer).
- Real-time sync via NS webhooks. T8's 5-minute cron is the durable answer.
- Synchronizing `:svc`, `:relay`, `:policy`, `:cert`, etc. record types. Only `:key` records become `ZtlpDevice`s. Other types stay NS-only for now.
- Multi-tenant support beyond the existing per-Network routing. The same secret is shared between this NS instance and every Bootstrap that talks to it — which is acceptable because all Bootstraps are operator-trusted and the endpoint is read-only.
