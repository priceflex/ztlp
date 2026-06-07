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
end
