defmodule ZtlpNs.AdminApiHttpTest do
  # async: false — starts a real :gen_tcp listener via MetricsServer and
  # mutates the shared Mnesia Store. Can't run concurrently with other
  # Store-touching tests or with anything that races on the named GenServer.
  use ExUnit.Case, async: false

  alias ZtlpNs.{Crypto, MetricsServer, Record, Store}

  # 32 random bytes — admin API secret for these tests only.
  @secret <<200, 13, 42, 99, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28>>

  setup do
    # Make sure the host apps are up — same pattern as admin_api_test.exs.
    Application.ensure_all_started(:mnesia)
    Application.ensure_all_started(:ztlp_ns)
    Application.ensure_all_started(:inets)

    prev_secret = Application.get_env(:ztlp_ns, :admin_api_secret)
    Application.put_env(:ztlp_ns, :admin_api_secret, @secret)

    # Reset the global admin-API rate-limit bucket between tests so
    # earlier tests don't bleed into later ones.
    ZtlpNs.AdminApiRateLimiter.reset()

    # The MetricsServer TCP accept handler applies a per-IP burst limit
    # (default 20 requests / 10s window via :metrics_max_requests_per_ip)
    # to ALL HTTP connections, including the admin API. This module makes
    # ~20-30 sequential requests (10 tests × 2-3 requests), which exceeds
    # the 20-per-10s burst limit, causing 429s at the accept level BEFORE
    # the AdminApiRateLimiter is even consulted. Raise the burst limit so
    # the admin tests don't trip it. The burst limiter uses a counters ref
    # that's not resettable, so we raise the limit (not reset the counter).
    prev_burst = Application.get_env(:ztlp_ns, :metrics_max_requests_per_ip)
    Application.put_env(:ztlp_ns, :metrics_max_requests_per_ip, 10_000)

    Store.clear()

    # Seed one record so /admin/records has something to return.
    {pub, priv} = Crypto.generate_keypair()
    now = System.system_time(:second)

    rec =
      %Record{
        name: "test.trs.ztlp",
        type: :key,
        data: %{pubkey: pub},
        created_at: now,
        ttl: 86_400,
        serial: 1
      }
      |> Record.sign(priv)

    :ok = Store.insert(rec)

    # Start an ephemeral MetricsServer on an OS-assigned port. The
    # globally-registered MetricsServer is disabled in test env
    # (config/test.exs sets :metrics_enabled to false), so we spin up
    # an unnamed instance just for this test module.
    {:ok, srv} = MetricsServer.start_link(name: :admin_http_test_srv, enabled: true, port: 0)
    port = MetricsServer.port(:admin_http_test_srv)

    on_exit(fn ->
      if Process.alive?(srv), do: GenServer.stop(srv)

      case prev_secret do
        nil -> Application.delete_env(:ztlp_ns, :admin_api_secret)
        v -> Application.put_env(:ztlp_ns, :admin_api_secret, v)
      end

      # Restore the per-IP burst limit (raised to 10_000 in setup).
      case prev_burst do
        nil -> Application.delete_env(:ztlp_ns, :metrics_max_requests_per_ip)
        v -> Application.put_env(:ztlp_ns, :metrics_max_requests_per_ip, v)
      end
    end)

    %{port: port}
  end

  defp sign_headers(method, path, body, secret) do
    ts = System.system_time(:second)
    body_hash = :crypto.hash(:sha256, body) |> Base.encode16(case: :lower)
    canonical = "#{method}\n#{path}\n#{ts}\n#{body_hash}"
    sig = :crypto.mac(:hmac, :sha256, secret, canonical) |> Base.encode16(case: :lower)

    [
      {~c"x-ns-timestamp", String.to_charlist(to_string(ts))},
      {~c"x-ns-signature", String.to_charlist(sig)}
    ]
  end

  test "GET /admin/records with a valid signature returns 200 JSON", %{port: port} do
    path = "/admin/records"
    headers = sign_headers("GET", path, "", @secret)

    url = ~c"http://127.0.0.1:#{port}#{path}"

    assert {:ok, {{_, 200, _}, resp_headers, body}} =
             :httpc.request(:get, {url, headers}, [], [])

    content_type =
      Enum.find_value(resp_headers, fn {k, v} ->
        if String.downcase(to_string(k)) == "content-type", do: to_string(v)
      end)

    assert content_type =~ "application/json"

    {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))
    assert is_list(parsed["records"])
    assert is_integer(parsed["count"])
    assert parsed["count"] >= 1
    assert is_integer(parsed["generated_at"])

    names = Enum.map(parsed["records"], & &1["name"])
    assert "test.trs.ztlp" in names
  end

  test "GET /admin/records with NO signature headers returns 401", %{port: port} do
    url = ~c"http://127.0.0.1:#{port}/admin/records"

    assert {:ok, {{_, 401, _}, _resp_headers, _body}} =
             :httpc.request(:get, {url, []}, [], [])
  end

  test "logs peer IP in admin records handler", %{port: port} do
    path = "/admin/records"
    headers = sign_headers("GET", path, "", @secret)
    url = ~c"http://127.0.0.1:#{port}#{path}"

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        {:ok, {{_, 200, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])
      end)

    assert log =~ "peer_ip=127.0.0.1"
  end

  test "rate-limits after 12 requests in the window, returns 429 + Retry-After", %{port: port} do
    ZtlpNs.AdminApiRateLimiter.reset()
    path = "/admin/records"
    url = ~c"http://127.0.0.1:#{port}#{path}"
    headers = sign_headers("GET", path, "", @secret)

    # Burn through the bucket
    for _ <- 1..12 do
      {:ok, {{_, status, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])
      assert status == 200
    end

    # 13th request should be 429 with Retry-After
    # Note: same signature is fine because rate-limit fires BEFORE signature verify.
    fresh_headers = sign_headers("GET", path, "", @secret)
    {:ok, {{_, 429, _}, resp_headers, _}} = :httpc.request(:get, {url, fresh_headers}, [], [])
    retry_after = Enum.find_value(resp_headers, fn {k, v} ->
      if String.downcase(to_string(k)) == "retry-after", do: to_string(v)
    end)
    assert retry_after != nil
    assert String.to_integer(retry_after) > 0
  end

  test "GET /admin/records with a BAD signature returns 401", %{port: port} do
    ts = System.system_time(:second)

    headers = [
      {~c"x-ns-timestamp", String.to_charlist(to_string(ts))},
      {~c"x-ns-signature", String.to_charlist(String.duplicate("0", 64))}
    ]

    url = ~c"http://127.0.0.1:#{port}/admin/records"

    assert {:ok, {{_, 401, _}, _resp_headers, _body}} =
             :httpc.request(:get, {url, headers}, [], [])
  end

  test "logs admin_api_records_pulled audit entry on 200", %{port: port} do
    ZtlpNs.AdminApiRateLimiter.reset()
    before = System.system_time(:second)
    path = "/admin/records?type=key"
    headers = sign_headers("GET", path, "", @secret)
    url = ~c"http://127.0.0.1:#{port}#{path}"

    {:ok, {{_, 200, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])

    entries = ZtlpNs.Audit.since(before - 1)
    matching = Enum.filter(entries, fn {_ts, action, _name, _type, details} ->
      action == :admin_api_records_pulled and details[:type_filter] == :key
    end)
    assert length(matching) >= 1
    {_ts, _action, name, type, details} = List.last(matching)
    assert name == "/admin/records"
    assert type == :admin_api
    assert is_integer(details[:count])
    assert details[:type_filter] == :key
    assert details[:peer_ip] == "127.0.0.1"
  end

  test "rejects with 403 when peer IP outside tenant CIDR union", %{port: port} do
    # Configure ONE tenant whose CIDR is 10.99.0.0/16 — excludes 127.0.0.1
    trs_secret_hex = String.duplicate("a", 64)
    env = %{
      "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => trs_secret_hex,
      "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
      "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "10.99.0.0/16"
    }
    registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
    :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
    on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

    ZtlpNs.AdminApiRateLimiter.reset()

    path = "/admin/records"
    headers = sign_headers("GET", path, "", @secret)
    url = ~c"http://127.0.0.1:#{port}#{path}"

    assert {:ok, {{_, 403, _}, _, _}} =
             :httpc.request(:get, {url, headers}, [], [])
  end

  test "allows with 200 when peer IP inside tenant CIDR union", %{port: port} do
    # Configure tenant whose CIDR INCLUDES 127.0.0.0/8
    trs_secret_hex = String.duplicate("a", 64)
    env = %{
      "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => trs_secret_hex,
      "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
      "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "127.0.0.0/8"
    }
    registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
    :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
    on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

    ZtlpNs.AdminApiRateLimiter.reset()

    path = "/admin/records"
    headers = sign_headers("GET", path, "", @secret)
    url = ~c"http://127.0.0.1:#{port}#{path}"

    assert {:ok, {{_, 200, _}, _, _}} =
             :httpc.request(:get, {url, headers}, [], [])
  end

  test "audit event :admin_api_ip_rejected emitted with severity :medium on 403", %{port: port} do
    trs_secret_hex = String.duplicate("a", 64)
    env = %{
      "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => trs_secret_hex,
      "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
      "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "10.99.0.0/16"
    }
    registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
    :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
    on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

    ZtlpNs.AdminApiRateLimiter.reset()
    before = System.system_time(:second)

    path = "/admin/records"
    headers = sign_headers("GET", path, "", @secret)
    url = ~c"http://127.0.0.1:#{port}#{path}"
    {:ok, {{_, 403, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])

    entries = ZtlpNs.Audit.since(before - 1)
    matching =
      Enum.filter(entries, fn {_ts, action, _name, _type, _details} ->
        action == :admin_api_ip_rejected
      end)

    assert length(matching) >= 1
    {_ts, _action, _name, _type, details} = List.last(matching)
    assert details[:peer_ip] == "127.0.0.1"
    assert details[:severity] == :medium
  end

  test "logs admin_api_auth_failed audit entry on 401 (bad signature)", %{port: port} do
    ZtlpNs.AdminApiRateLimiter.reset()
    before = System.system_time(:second)
    path = "/admin/records"
    ts = System.system_time(:second)
    bad_headers = [
      {~c"x-ns-timestamp", String.to_charlist(to_string(ts))},
      {~c"x-ns-signature", String.to_charlist(String.duplicate("0", 64))}
    ]
    url = ~c"http://127.0.0.1:#{port}#{path}"

    {:ok, {{_, 401, _}, _, _}} = :httpc.request(:get, {url, bad_headers}, [], [])

    entries = ZtlpNs.Audit.since(before - 1)
    matching = Enum.filter(entries, fn {_ts, action, _name, _type, _details} ->
      action == :admin_api_auth_failed
    end)
    assert length(matching) >= 1
    {_ts, _action, _name, _type, details} = List.last(matching)
    assert details[:peer_ip] == "127.0.0.1"
    assert details[:reason] != nil
  end

  describe "tenant-aware HMAC + global fallback (T4)" do
    # Known-value tenant secret: hex "aa..aa" (64 chars) → 32 bytes of 0xAA.
    @trs_secret_hex String.duplicate("a", 64)
    @trs_secret_raw String.duplicate(<<0xAA>>, 32)

    test "200 when signed with tenant TRS secret + IP in TRS CIDR", %{port: port} do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_secret_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

      ZtlpNs.AdminApiRateLimiter.reset()

      path = "/admin/records"
      headers = sign_headers("GET", path, "", @trs_secret_raw)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      assert {:ok, {{_, 200, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])
    end

    test "401 when signed with neither tenant nor global secret", %{port: port} do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_secret_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

      ZtlpNs.AdminApiRateLimiter.reset()

      random = :crypto.strong_rand_bytes(32)
      path = "/admin/records"
      headers = sign_headers("GET", path, "", random)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      assert {:ok, {{_, 401, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])
    end

    test "200 + :admin_api_legacy_global_secret audit when using global with tenants configured",
         %{port: port} do
      # Tenants configured AND global also set (transition mode).
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_secret_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

      ZtlpNs.AdminApiRateLimiter.reset()
      before = System.system_time(:second)

      # Sign with the GLOBAL @secret — should match global fallback.
      path = "/admin/records"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      assert {:ok, {{_, 200, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])

      entries = ZtlpNs.Audit.since(before - 1)

      legacy_events =
        Enum.filter(entries, fn {_ts, action, _name, _type, _details} ->
          action == :admin_api_legacy_global_secret
        end)

      assert length(legacy_events) >= 1
      {_ts, _action, _name, _type, details} = List.last(legacy_events)
      assert details[:severity] == :medium
      assert details[:peer_ip] == "127.0.0.1"
    end

    test "200 when global is the ONLY secret (pure legacy mode)", %{port: port} do
      # No tenants — clear any cache from prior tests.
      ZtlpNs.AdminApi.TenantRegistry.clear_cache()
      ZtlpNs.AdminApiRateLimiter.reset()

      path = "/admin/records"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      assert {:ok, {{_, 200, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])
    end
  end

  describe "tenant zone-glob filtering on /admin/records response (T5)" do
    @trs_secret_hex String.duplicate("a", 64)
    @trs_secret_raw String.duplicate(<<0xAA>>, 32)
    @acme_secret_hex String.duplicate("b", 64)
    @acme_secret_raw String.duplicate(<<0xBB>>, 32)

    defp seed_record(name) do
      {pub, priv} = Crypto.generate_keypair()
      now = System.system_time(:second)

      rec =
        %Record{
          name: name,
          type: :key,
          data: %{pubkey: pub},
          created_at: now,
          ttl: 86_400,
          serial: 1
        }
        |> Record.sign(priv)

      :ok = Store.insert(rec)
    end

    test "tenant TRS only sees *.trs.ztlp records (cross-zone isolation)", %{port: port} do
      seed_record("alice.trs.ztlp")
      seed_record("bob.adms.trs.ztlp")
      seed_record("alice.acme.ztlp")

      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_secret_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)
      ZtlpNs.AdminApiRateLimiter.reset()

      path = "/admin/records?type=key"
      headers = sign_headers("GET", path, "", @trs_secret_raw)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      {:ok, {{_, 200, _}, _, body}} = :httpc.request(:get, {url, headers}, [], [])
      {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))

      names = Enum.map(parsed["records"], & &1["name"])
      assert "alice.trs.ztlp" in names
      assert "bob.adms.trs.ztlp" in names
      refute "alice.acme.ztlp" in names
      assert parsed["count"] == length(names)
    end

    test "tenant ACME only sees *.acme.ztlp records (peer-deny verified)",
         %{port: port} do
      seed_record("alice.trs.ztlp")
      seed_record("alice.acme.ztlp")

      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_ACME_SECRET" => @acme_secret_hex,
        "ZTLP_NS_ADMIN_API_TENANT_ACME_ZONE_GLOB" => "*.acme.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)
      ZtlpNs.AdminApiRateLimiter.reset()

      path = "/admin/records?type=key"
      headers = sign_headers("GET", path, "", @acme_secret_raw)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      {:ok, {{_, 200, _}, _, body}} = :httpc.request(:get, {url, headers}, [], [])
      {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))

      names = Enum.map(parsed["records"], & &1["name"])
      refute "alice.trs.ztlp" in names
      assert "alice.acme.ztlp" in names
      assert parsed["count"] == length(names)
    end

    test ":legacy mode (global secret) sees ALL records (backwards-compat preserved)",
         %{port: port} do
      seed_record("alice.trs.ztlp")
      seed_record("alice.acme.ztlp")

      # NO tenants — pure legacy mode
      ZtlpNs.AdminApi.TenantRegistry.clear_cache()
      ZtlpNs.AdminApiRateLimiter.reset()

      path = "/admin/records?type=key"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      {:ok, {{_, 200, _}, _, body}} = :httpc.request(:get, {url, headers}, [], [])
      {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))

      names = Enum.map(parsed["records"], & &1["name"])
      assert "alice.trs.ztlp" in names
      assert "alice.acme.ztlp" in names
    end

    test "tenant requesting zone outside their glob → empty result + :admin_api_zone_outside_glob audit",
         %{port: port} do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_secret_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)
      ZtlpNs.AdminApiRateLimiter.reset()
      before = System.system_time(:second)

      path = "/admin/records?type=key&zone=acme.ztlp"
      headers = sign_headers("GET", path, "", @trs_secret_raw)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      {:ok, {{_, 200, _}, _, body}} = :httpc.request(:get, {url, headers}, [], [])
      {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))

      # Empty result — tenant can't see records outside its glob
      assert parsed["count"] == 0
      assert parsed["records"] == []

      # Audit event :admin_api_zone_outside_glob fired (severity :high)
      entries = ZtlpNs.Audit.since(before - 1)

      matching =
        Enum.filter(entries, fn {_ts, action, _name, _type, _details} ->
          action == :admin_api_zone_outside_glob
        end)

      assert length(matching) >= 1
      {_ts, _action, name, type, details} = List.last(matching)
      assert name == "/admin/records"
      assert type == :admin_api
      assert details[:tenant] == "TRS"
      assert details[:requested_zone] == "acme.ztlp"
      assert details[:tenant_glob] == "*.trs.ztlp"
      assert details[:severity] == :high
      assert details[:peer_ip] == "127.0.0.1"
    end
  end

  describe "audit-event severity tagging (T6)" do
    # Pins severity on the two events that PR #97 added (records_pulled,
    # auth_failed) but didn't tag. T3-T5 added their own events already
    # tagged. This block guards against a future audit event landing
    # without a severity key.

    test "200 success path → :admin_api_records_pulled severity :info", %{port: port} do
      ZtlpNs.AdminApiRateLimiter.reset()
      ZtlpNs.AdminApi.TenantRegistry.clear_cache()
      before = System.system_time(:second)

      path = "/admin/records?type=key"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"
      {:ok, {{_, 200, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])

      entries = ZtlpNs.Audit.since(before - 1)

      pulled =
        Enum.filter(entries, fn {_ts, action, _, _, _} ->
          action == :admin_api_records_pulled
        end)

      assert length(pulled) >= 1
      {_, _, _, _, details} = List.last(pulled)
      assert details[:severity] == :info
    end

    test "401 bad-signature → :admin_api_auth_failed severity :high", %{port: port} do
      ZtlpNs.AdminApiRateLimiter.reset()
      ZtlpNs.AdminApi.TenantRegistry.clear_cache()
      before = System.system_time(:second)

      ts = System.system_time(:second)
      bad_headers = [
        {~c"x-ns-timestamp", String.to_charlist(to_string(ts))},
        {~c"x-ns-signature", String.to_charlist(String.duplicate("0", 64))}
      ]

      url = ~c"http://127.0.0.1:#{port}/admin/records"
      {:ok, {{_, 401, _}, _, _}} = :httpc.request(:get, {url, bad_headers}, [], [])

      entries = ZtlpNs.Audit.since(before - 1)

      failed =
        Enum.filter(entries, fn {_ts, action, _, _, _} ->
          action == :admin_api_auth_failed
        end)

      assert length(failed) >= 1
      {_, _, _, _, details} = List.last(failed)
      assert details[:severity] == :high
    end
  end

  describe "trust-authority extension hook (T7)" do
    # Phase 3+ will implement verify_authority/2 to do CA-signed
    # authorization. For now it returns :ok unconditionally — these
    # tests pin BOTH the stub contract (returns :ok) AND the call site
    # (deny path renders 403 + :admin_api_authority_denied severity
    # :critical), so a future implementation can be slotted in without
    # restructuring the auth chain.

    test "verify_authority/2 stub returns :ok for legacy identity" do
      assert :ok = ZtlpNs.AdminApi.verify_authority(:legacy, %{peer_ip: {127, 0, 0, 1}})
    end

    test "verify_authority/2 stub returns :ok for tenant identity" do
      tenant = %ZtlpNs.AdminApi.TenantRegistry{
        slug: "TRS",
        secret: :crypto.strong_rand_bytes(32),
        zone_glob: "*.trs.ztlp",
        cidrs: []
      }

      assert :ok =
               ZtlpNs.AdminApi.verify_authority({:tenant, tenant}, %{
                 peer_ip: {127, 0, 0, 1},
                 method: "GET",
                 path: "/admin/records",
                 query: "",
                 identity: {:tenant, tenant}
               })
    end
  end

  describe "per-tenant CIDR re-check after HMAC identification (CodeRabbit PR #98 F4)" do
    # CRITICAL fix: prior to F4 the IP allow-list only checked the
    # UNION of all tenants' CIDRs. A request signed as tenant A from
    # tenant B's CIDR passed the network lock — cross-tenant escape.
    # Now: after the HMAC pins identity to a specific tenant, the
    # peer IP must be in THAT tenant's CIDRs.
    @trs_secret_hex_f4 String.duplicate("a", 64)
    @trs_secret_raw_f4 :binary.copy(<<0xAA>>, 32)
    @acme_secret_hex_f4 String.duplicate("b", 64)

    test "rejects request signed as tenant A from tenant B's CIDR with 403 + audit", %{port: port} do
      # TRS: CIDR 10.99.0.0/16 (intentionally NOT loopback).
      # ACME: CIDR 127.0.0.0/8 (where the test server connects from).
      # The union check sees 127.0.0.1 as allowed (it's in ACME's
      # CIDR) so pre-F4 the request reached HMAC verify, identified
      # as TRS, and returned 200 — that's the escape vector. With F4
      # the post-auth re-check sees TRS's CIDRs don't include 127/8
      # and returns 403.
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_secret_hex_f4,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "10.99.0.0/16",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_SECRET" => @acme_secret_hex_f4,
        "ZTLP_NS_ADMIN_API_TENANT_ACME_ZONE_GLOB" => "*.acme.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

      ZtlpNs.AdminApiRateLimiter.reset()
      before = System.system_time(:second)

      path = "/admin/records?type=key"
      headers = sign_headers("GET", path, "", @trs_secret_raw_f4)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      {:ok, {{_, status, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])
      assert status == 403, "expected 403 for cross-tenant CIDR escape, got #{status}"

      entries = ZtlpNs.Audit.since(before - 1)

      matching =
        Enum.filter(entries, fn {_ts, action, _name, _type, details} ->
          action == :admin_api_ip_rejected and details[:tenant] == "TRS"
        end)

      assert length(matching) >= 1,
             "expected at least one :admin_api_ip_rejected audit entry with tenant=TRS"

      {_ts, _action, _name, _type, details} = List.last(matching)
      assert details[:severity] == :medium
      assert details[:reason] == "ip_outside_identified_tenant_cidrs"
      assert details[:peer_ip] == "127.0.0.1"
    end

    test "allows request signed as tenant from THAT tenant's CIDR with 200", %{port: port} do
      # Sanity: prove the F4 fix only rejects the CIDR-mismatch case.
      # TRS includes 127/8 in its CIDRs, so a TRS-signed request from
      # loopback is still allowed.
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_secret_hex_f4,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

      ZtlpNs.AdminApiRateLimiter.reset()

      path = "/admin/records?type=key"
      headers = sign_headers("GET", path, "", @trs_secret_raw_f4)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      assert {:ok, {{_, 200, _}, _, _}} =
               :httpc.request(:get, {url, headers}, [], [])
    end
  end

  # ── GET /admin/audit ───────────────────────────────────────────────
  #
  # v0.35.x replacement for the removed unauthenticated UDP 0x13/0x02 and
  # 0x13/0x03 audit opcodes. Same gate pipeline as /admin/records:
  # CIDR union → rate limit → HMAC verify → per-tenant CIDR recheck →
  # authority hook → zone-glob scope. Query params:
  #   ?since=<unix_ts>   filter to entries at/after ts (default: all)
  #   ?pattern=<glob>    filter entry name by glob (steve@*, *.ztlp, …)
  #
  # These are RED until handle_admin_audit/5 + the route exist.

  describe "GET /admin/audit" do
    test "valid signature returns 200 JSON with entries + count + generated_at",
         %{port: port} do
      ZtlpNs.AdminApiRateLimiter.reset()
      ZtlpNs.Audit.clear()
      ZtlpNs.Audit.log(:registered, "laptop.trs.ztlp", :device, %{by: "test"})
      ZtlpNs.Audit.log(:registered, "steve@trs.ztlp", :user, %{by: "test"})
      :timer.sleep(20)

      path = "/admin/audit"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      assert {:ok, {{_, 200, _}, resp_headers, body}} =
               :httpc.request(:get, {url, headers}, [], [])

      content_type =
        Enum.find_value(resp_headers, fn {k, v} ->
          if String.downcase(to_string(k)) == "content-type", do: to_string(v)
        end)

      assert content_type =~ "application/json"

      {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))
      assert is_list(parsed["entries"])
      assert is_integer(parsed["count"])
      assert parsed["count"] >= 2
      assert is_integer(parsed["generated_at"])

      # Each entry exposes the canonical 5 fields the UDP path used to emit.
      entry = hd(parsed["entries"])
      assert Map.has_key?(entry, "timestamp")
      assert Map.has_key?(entry, "action")
      assert Map.has_key?(entry, "name")
      assert Map.has_key?(entry, "type")
      assert Map.has_key?(entry, "details")

      names = Enum.map(parsed["entries"], & &1["name"])
      assert "laptop.trs.ztlp" in names
      assert "steve@trs.ztlp" in names
    end

    test "NO signature headers returns 401", %{port: port} do
      url = ~c"http://127.0.0.1:#{port}/admin/audit"

      assert {:ok, {{_, 401, _}, _resp_headers, _body}} =
               :httpc.request(:get, {url, []}, [], [])
    end

    test "BAD signature returns 401", %{port: port} do
      ts = System.system_time(:second)

      headers = [
        {~c"x-ns-timestamp", String.to_charlist(to_string(ts))},
        {~c"x-ns-signature", String.to_charlist(String.duplicate("0", 64))}
      ]

      url = ~c"http://127.0.0.1:#{port}/admin/audit"

      assert {:ok, {{_, 401, _}, _resp_headers, _body}} =
               :httpc.request(:get, {url, headers}, [], [])
    end

    test "?since=<ts> filters to entries at/after the timestamp", %{port: port} do
      ZtlpNs.AdminApiRateLimiter.reset()
      ZtlpNs.Audit.clear()

      # An "old" entry, then a cutoff, then a "new" entry.
      ZtlpNs.Audit.log(:registered, "old.trs.ztlp", :device, %{})
      :timer.sleep(1100)
      cutoff = System.system_time(:second)
      :timer.sleep(20)
      ZtlpNs.Audit.log(:registered, "new.trs.ztlp", :device, %{})
      :timer.sleep(20)

      path = "/admin/audit?since=#{cutoff}"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      {:ok, {{_, 200, _}, _, body}} = :httpc.request(:get, {url, headers}, [], [])
      {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))

      names = Enum.map(parsed["entries"], & &1["name"])
      assert "new.trs.ztlp" in names
      refute "old.trs.ztlp" in names
    end

    test "?pattern=<glob> filters entry names by glob", %{port: port} do
      ZtlpNs.AdminApiRateLimiter.reset()
      ZtlpNs.Audit.clear()
      ZtlpNs.Audit.log(:registered, "steve@trs.ztlp", :user, %{})
      ZtlpNs.Audit.log(:registered, "bob@trs.ztlp", :user, %{})
      :timer.sleep(20)

      path = "/admin/audit?pattern=#{URI.encode("steve@*")}"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      {:ok, {{_, 200, _}, _, body}} = :httpc.request(:get, {url, headers}, [], [])
      {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))

      names = Enum.map(parsed["entries"], & &1["name"])
      assert Enum.all?(names, &String.starts_with?(&1, "steve@")),
             "expected only steve@* entries, got: #{inspect(names)}"
      assert "steve@trs.ztlp" in names
    end

    test "emits :admin_api_audit_pulled audit entry on 200", %{port: port} do
      ZtlpNs.AdminApiRateLimiter.reset()
      ZtlpNs.Audit.clear()
      ZtlpNs.Audit.log(:registered, "seed.trs.ztlp", :device, %{})
      :timer.sleep(20)
      before = System.system_time(:second)

      path = "/admin/audit"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"
      {:ok, {{_, 200, _}, _, _}} = :httpc.request(:get, {url, headers}, [], [])

      entries = ZtlpNs.Audit.since(before - 1)

      matching =
        Enum.filter(entries, fn {_ts, action, name, _type, _details} ->
          action == :admin_api_audit_pulled and name == "/admin/audit"
        end)

      assert length(matching) >= 1,
             "expected an :admin_api_audit_pulled audit event"

      {_ts, _action, _name, type, details} = List.last(matching)
      assert type == :admin_api
      assert details[:peer_ip] == "127.0.0.1"
      assert is_integer(details[:count])
    end

    test "rejects with 403 when peer IP outside tenant CIDR union", %{port: port} do
      trs_secret_hex = String.duplicate("a", 64)

      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => trs_secret_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "10.99.0.0/16"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

      ZtlpNs.AdminApiRateLimiter.reset()

      path = "/admin/audit"
      headers = sign_headers("GET", path, "", @secret)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      assert {:ok, {{_, 403, _}, _, _}} =
               :httpc.request(:get, {url, headers}, [], [])
    end

    test "tenant identity scopes audit entries to its zone glob", %{port: port} do
      # TRS tenant (zone *.trs.ztlp, loopback CIDR). Seed entries inside
      # and outside the glob; the tenant must only see its own.
      trs_secret_hex = String.duplicate("b", 64)
      trs_secret_raw = :binary.copy(<<0xbb>>, 32)

      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => trs_secret_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "127.0.0.0/8"
      }

      registry = ZtlpNs.AdminApi.TenantRegistry.load_from_env(env)
      :persistent_term.put({ZtlpNs.AdminApi.TenantRegistry, :tenants}, registry)
      on_exit(fn -> ZtlpNs.AdminApi.TenantRegistry.clear_cache() end)

      ZtlpNs.AdminApiRateLimiter.reset()
      ZtlpNs.Audit.clear()
      ZtlpNs.Audit.log(:registered, "laptop.trs.ztlp", :device, %{})
      ZtlpNs.Audit.log(:registered, "laptop.acme.ztlp", :device, %{})
      :timer.sleep(20)

      # Note: secret hex "bb"*64 decodes to 32 bytes of 0xbb.
      _ = trs_secret_hex
      path = "/admin/audit"
      headers = sign_headers("GET", path, "", trs_secret_raw)
      url = ~c"http://127.0.0.1:#{port}#{path}"

      {:ok, {{_, 200, _}, _, body}} = :httpc.request(:get, {url, headers}, [], [])
      {:ok, parsed} = Jason.decode(IO.iodata_to_binary(body))

      names = Enum.map(parsed["entries"], & &1["name"])
      assert "laptop.trs.ztlp" in names
      refute "laptop.acme.ztlp" in names,
             "tenant must not see audit entries outside its zone glob"
    end
  end
end
