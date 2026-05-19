defmodule ZtlpGateway.ConfigTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.Config

  describe "get(:backends) with env var" do
    test "parses ZTLP_GATEWAY_BACKENDS env var" do
      System.put_env("ZTLP_GATEWAY_BACKENDS", "metrics:127.0.0.1:9103,api:10.0.0.1:8080")

      backends = Config.get(:backends)

      assert length(backends) == 2

      metrics = Enum.find(backends, &(&1.name == "metrics"))
      assert metrics.host == ~c"127.0.0.1"
      assert metrics.port == 9103

      api = Enum.find(backends, &(&1.name == "api"))
      assert api.host == ~c"10.0.0.1"
      assert api.port == 8080
    after
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end

    test "returns empty list for malformed entries" do
      System.put_env("ZTLP_GATEWAY_BACKENDS", "bad_entry,also_bad")
      backends = Config.get(:backends)
      assert backends == []
    after
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end

    test "falls back to app config when env var not set" do
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
      backends = Config.get(:backends)
      assert is_list(backends)
    end

    test "handles single backend" do
      System.put_env("ZTLP_GATEWAY_BACKENDS", "metrics:127.0.0.1:9103")
      backends = Config.get(:backends)
      assert length(backends) == 1
      assert hd(backends).name == "metrics"
    after
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end
  end

  describe "get(:policies) with env var" do
    test "parses ZTLP_GATEWAY_POLICIES env var with wildcard" do
      System.put_env("ZTLP_GATEWAY_POLICIES", "*:metrics")
      policies = Config.get(:policies)
      assert length(policies) == 1
      assert hd(policies).service == "metrics"
      assert hd(policies).allow == :all
    after
      System.delete_env("ZTLP_GATEWAY_POLICIES")
    end

    test "parses named identity policies" do
      System.put_env("ZTLP_GATEWAY_POLICIES", "admin.zone:api,ops.zone:api")
      policies = Config.get(:policies)
      assert length(policies) == 1

      api_policy = hd(policies)
      assert api_policy.service == "api"
      assert api_policy.allow == ["admin.zone", "ops.zone"]
    after
      System.delete_env("ZTLP_GATEWAY_POLICIES")
    end

    test "groups multiple identities for same service" do
      System.put_env("ZTLP_GATEWAY_POLICIES", "alice:web,bob:web,*:metrics")
      policies = Config.get(:policies)

      web = Enum.find(policies, &(&1.service == "web"))
      assert web.allow == ["alice", "bob"]

      metrics = Enum.find(policies, &(&1.service == "metrics"))
      assert metrics.allow == :all
    after
      System.delete_env("ZTLP_GATEWAY_POLICIES")
    end

    test "falls back to app config when env var not set" do
      System.delete_env("ZTLP_GATEWAY_POLICIES")
      policies = Config.get(:policies)
      assert is_list(policies)
    end
  end

  describe "get(:header_signing_enabled) with env var" do
    # ZTLP_HEADER_SIGNING_ENABLED lets operators enable header HMAC signing
    # purely via env vars (no compile-time config.exs edit). Pattern matches
    # the existing canonical boolean env-var clauses in config.ex (e.g.
    # ZTLP_GATEWAY_AUDIT_ENABLED, ZTLP_GATEWAY_MTLS_REQUIRED) but with a
    # slightly more lenient parser (true/1/yes/on, case-insensitive).

    setup do
      prev_env = System.get_env("ZTLP_HEADER_SIGNING_ENABLED")
      prev_app = Application.get_env(:ztlp_gateway, :header_signing_enabled)
      System.delete_env("ZTLP_HEADER_SIGNING_ENABLED")
      Application.delete_env(:ztlp_gateway, :header_signing_enabled)

      on_exit(fn ->
        if prev_env,
          do: System.put_env("ZTLP_HEADER_SIGNING_ENABLED", prev_env),
          else: System.delete_env("ZTLP_HEADER_SIGNING_ENABLED")

        if is_nil(prev_app),
          do: Application.delete_env(:ztlp_gateway, :header_signing_enabled),
          else: Application.put_env(:ztlp_gateway, :header_signing_enabled, prev_app)
      end)

      :ok
    end

    test "env var true returns true" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "true")
      assert Config.get(:header_signing_enabled) == true
    end

    test "env var 1 returns true" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "1")
      assert Config.get(:header_signing_enabled) == true
    end

    test "env var false returns false" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "false")
      assert Config.get(:header_signing_enabled) == false
    end

    test "env var 0 returns false" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "0")
      assert Config.get(:header_signing_enabled) == false
    end

    test "env var unset, application env true returns true" do
      Application.put_env(:ztlp_gateway, :header_signing_enabled, true)
      assert Config.get(:header_signing_enabled) == true
    end

    test "env var unset, application env unset returns false (default)" do
      assert Config.get(:header_signing_enabled) == false
    end

    test "env var TRUE (uppercase) returns true (case-insensitive)" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "TRUE")
      assert Config.get(:header_signing_enabled) == true
    end

    test "env var yes returns true" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "yes")
      assert Config.get(:header_signing_enabled) == true
    end

    test "env var on returns true" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "on")
      assert Config.get(:header_signing_enabled) == true
    end

    test "env var no returns false" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "no")
      assert Config.get(:header_signing_enabled) == false
    end

    test "env var off returns false" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "off")
      assert Config.get(:header_signing_enabled) == false
    end

    test "env var empty string returns false" do
      System.put_env("ZTLP_HEADER_SIGNING_ENABLED", "")
      assert Config.get(:header_signing_enabled) == false
    end
  end
end
