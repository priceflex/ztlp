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

    # ── Protocol prefix on backend host (Option-1 wire format) ──────────────
    # Tests the v0.30 addition that lets operators specify per-backend
    # transport protocol in the existing colon-separated env var. Format is
    # "service:[<proto>/]<host>:<port>" where <proto> is "tcp" (default) or
    # "udp". This is the on-the-wire counterpart of ServiceRouter.Backend's
    # new :protocol field — see service_router_test.exs for the model tests.

    test "absent prefix defaults to :tcp (backward compatibility)" do
      System.put_env("ZTLP_GATEWAY_BACKENDS", "web:127.0.0.1:8080")
      [b] = Config.get(:backends)
      assert b.protocol == :tcp
      assert b.host == ~c"127.0.0.1"
      assert b.port == 8080
    after
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end

    test "'udp/' prefix is parsed and stripped from the host" do
      System.put_env("ZTLP_GATEWAY_BACKENDS", "dns:udp/8.8.8.8:53")
      [b] = Config.get(:backends)
      assert b.protocol == :udp
      assert b.host == ~c"8.8.8.8"
      assert b.port == 53
    after
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end

    test "explicit 'tcp/' prefix is parsed and stripped from the host" do
      System.put_env("ZTLP_GATEWAY_BACKENDS", "ssh:tcp/10.0.0.1:22")
      [b] = Config.get(:backends)
      assert b.protocol == :tcp
      assert b.host == ~c"10.0.0.1"
      assert b.port == 22
    after
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end

    test "mixed protocols in one env var" do
      # Real-world multi-service case from bootstrap/docs/multi_service_gateway.md.
      System.put_env(
        "ZTLP_GATEWAY_BACKENDS",
        "ssh:127.0.0.1:22,mysql:127.0.0.1:3306,dns:udp/8.8.8.8:53"
      )

      backends = Config.get(:backends)

      ssh = Enum.find(backends, &(&1.name == "ssh"))
      mysql = Enum.find(backends, &(&1.name == "mysql"))
      dns = Enum.find(backends, &(&1.name == "dns"))

      assert ssh.protocol == :tcp and ssh.port == 22
      assert mysql.protocol == :tcp and mysql.port == 3306
      assert dns.protocol == :udp and dns.host == ~c"8.8.8.8" and dns.port == 53
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

  describe "ns_server/0 — consolidated NS server accessor" do
    # ZTLP gateway operators may configure the NS coordinates two ways:
    #   1. ZTLP_NS_SERVER=host:port (canonical, used by ServiceRegistrar /
    #      CertProvisioner / Federation)
    #   2. ZTLP_GATEWAY_NS_HOST=host + ZTLP_GATEWAY_NS_PORT=port (split form
    #      used by the existing Config.ns_host/0 + ns_port/0 accessors)
    #
    # Before this accessor existed, those who deployed with only the split
    # form (#2) ended up with NS registration disabled because the modules
    # above only checked ZTLP_NS_SERVER directly. ns_server/0 unifies the
    # two conventions and returns nil only when nothing is configured.

    setup do
      prev_ns_server = System.get_env("ZTLP_NS_SERVER")
      prev_ns_host = System.get_env("ZTLP_GATEWAY_NS_HOST")
      prev_ns_port = System.get_env("ZTLP_GATEWAY_NS_PORT")

      System.delete_env("ZTLP_NS_SERVER")
      System.delete_env("ZTLP_GATEWAY_NS_HOST")
      System.delete_env("ZTLP_GATEWAY_NS_PORT")

      on_exit(fn ->
        if prev_ns_server,
          do: System.put_env("ZTLP_NS_SERVER", prev_ns_server),
          else: System.delete_env("ZTLP_NS_SERVER")

        if prev_ns_host,
          do: System.put_env("ZTLP_GATEWAY_NS_HOST", prev_ns_host),
          else: System.delete_env("ZTLP_GATEWAY_NS_HOST")

        if prev_ns_port,
          do: System.put_env("ZTLP_GATEWAY_NS_PORT", prev_ns_port),
          else: System.delete_env("ZTLP_GATEWAY_NS_PORT")
      end)

      :ok
    end

    test "ZTLP_NS_SERVER takes precedence and is returned verbatim" do
      System.put_env("ZTLP_NS_SERVER", "35.91.88.177:23096")
      assert Config.ns_server() == "35.91.88.177:23096"
    end

    test "split ZTLP_GATEWAY_NS_HOST + ZTLP_GATEWAY_NS_PORT are joined" do
      System.put_env("ZTLP_GATEWAY_NS_HOST", "ns.example.com")
      System.put_env("ZTLP_GATEWAY_NS_PORT", "23096")
      assert Config.ns_server() == "ns.example.com:23096"
    end

    test "ZTLP_NS_SERVER wins when both forms are present" do
      System.put_env("ZTLP_NS_SERVER", "canonical:1111")
      System.put_env("ZTLP_GATEWAY_NS_HOST", "split-form")
      System.put_env("ZTLP_GATEWAY_NS_PORT", "2222")
      assert Config.ns_server() == "canonical:1111"
    end

    test "only ZTLP_GATEWAY_NS_HOST set (no port) returns nil" do
      System.put_env("ZTLP_GATEWAY_NS_HOST", "lonely-host")
      assert Config.ns_server() == nil
    end

    test "only ZTLP_GATEWAY_NS_PORT set (no host) returns nil" do
      System.put_env("ZTLP_GATEWAY_NS_PORT", "23096")
      assert Config.ns_server() == nil
    end

    test "nothing configured returns nil" do
      assert Config.ns_server() == nil
    end

    test "empty ZTLP_NS_SERVER falls through to split form" do
      System.put_env("ZTLP_NS_SERVER", "")
      System.put_env("ZTLP_GATEWAY_NS_HOST", "fallback.host")
      System.put_env("ZTLP_GATEWAY_NS_PORT", "23096")
      assert Config.ns_server() == "fallback.host:23096"
    end

    test "empty ZTLP_NS_SERVER with no split form returns nil" do
      System.put_env("ZTLP_NS_SERVER", "")
      assert Config.ns_server() == nil
    end
  end
end
