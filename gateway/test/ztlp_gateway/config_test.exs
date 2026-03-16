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
end
