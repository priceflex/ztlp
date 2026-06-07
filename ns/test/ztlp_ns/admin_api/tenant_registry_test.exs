defmodule ZtlpNs.AdminApi.TenantRegistryTest do
  # CodeRabbit PR #98 F5: was async: true, but the cache_at_boot/0 +
  # cached/0 tests mutate :persistent_term under a globally-keyed term.
  # async with other test modules that touch the same key was racy.
  use ExUnit.Case, async: false

  alias ZtlpNs.AdminApi.TenantRegistry
  alias ZtlpNs.Cidr

  # 32-byte test secrets: hex form (input) and raw form (used to compute HMACs).
  # "a" * 64 = 32 bytes of 0xAA; "b" * 64 = 32 bytes of 0xBB.
  @trs_hex String.duplicate("a", 64)
  @acme_hex String.duplicate("b", 64)
  @trs_raw :binary.copy(<<0xAA>>, 32)
  @acme_raw :binary.copy(<<0xBB>>, 32)

  describe "load_from_env/1" do
    test "empty env → empty registry" do
      assert TenantRegistry.load_from_env(%{}) == %{}
    end

    test "one fully-configured tenant" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16"
      }

      registry = TenantRegistry.load_from_env(env)
      assert Map.has_key?(registry, "TRS")
      tenant = registry["TRS"]
      assert tenant.slug == "TRS"
      assert tenant.zone_glob == "*.trs.ztlp"
      assert byte_size(tenant.secret) == 32
      assert [%Cidr{}] = tenant.cidrs
    end

    test "two tenants loaded together" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_SECRET" => @acme_hex,
        "ZTLP_NS_ADMIN_API_TENANT_ACME_ZONE_GLOB" => "*.acme.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_CIDRS" => "172.20.0.0/16"
      }

      registry = TenantRegistry.load_from_env(env)
      assert registry |> Map.keys() |> Enum.sort() == ["ACME", "TRS"]
    end

    test "multi-CIDR per tenant (comma-separated)" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16,10.42.0.0/16"
      }

      tenant = TenantRegistry.load_from_env(env)["TRS"]
      assert length(tenant.cidrs) == 2
    end

    test "lowercase slug env vars are ignored" do
      env = %{
        "ztlp_ns_admin_api_tenant_trs_secret" => @trs_hex,
        "ztlp_ns_admin_api_tenant_trs_zone_glob" => "*.trs.ztlp",
        "ztlp_ns_admin_api_tenant_trs_cidrs" => "172.18.0.0/16"
      }

      assert TenantRegistry.load_from_env(env) == %{}
    end

    test "missing SECRET raises at load time" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16"
      }

      assert_raise RuntimeError, ~r/TRS.*SECRET/i, fn ->
        TenantRegistry.load_from_env(env)
      end
    end

    test "missing ZONE_GLOB raises at load time" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16"
      }

      assert_raise RuntimeError, ~r/TRS.*ZONE_GLOB/i, fn ->
        TenantRegistry.load_from_env(env)
      end
    end

    test "missing CIDRS raises at load time" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp"
      }

      assert_raise RuntimeError, ~r/TRS.*CIDRS/i, fn ->
        TenantRegistry.load_from_env(env)
      end
    end

    test "invalid hex secret raises" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => "not-hex-and-wrong-length",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16"
      }

      assert_raise RuntimeError, ~r/TRS.*secret/i, fn ->
        TenantRegistry.load_from_env(env)
      end
    end

    test "invalid CIDR raises" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/33"
      }

      assert_raise RuntimeError, ~r/TRS.*CIDR/i, fn ->
        TenantRegistry.load_from_env(env)
      end
    end

    test "middle-wildcard zone glob rejected at boot" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.foo.*",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16"
      }

      assert_raise RuntimeError, ~r/TRS.*glob/i, fn ->
        TenantRegistry.load_from_env(env)
      end
    end
  end

  describe "zone_matches?/2" do
    setup do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16"
      }

      %{tenant: TenantRegistry.load_from_env(env)["TRS"]}
    end

    test "*.trs.ztlp matches host.trs.ztlp", %{tenant: t} do
      assert TenantRegistry.zone_matches?(t, "host.trs.ztlp")
    end

    test "*.trs.ztlp matches host.sub.trs.ztlp", %{tenant: t} do
      assert TenantRegistry.zone_matches?(t, "host.sub.trs.ztlp")
    end

    test "*.trs.ztlp does NOT match bare trs.ztlp", %{tenant: t} do
      refute TenantRegistry.zone_matches?(t, "trs.ztlp")
    end

    test "*.trs.ztlp does NOT match host.notrs.ztlp", %{tenant: t} do
      refute TenantRegistry.zone_matches?(t, "host.notrs.ztlp")
    end

    test "exact glob (trs.ztlp) matches only itself" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16"
      }

      t = TenantRegistry.load_from_env(env)["TRS"]
      assert TenantRegistry.zone_matches?(t, "trs.ztlp")
      refute TenantRegistry.zone_matches?(t, "host.trs.ztlp")
    end
  end

  describe "ip_in_cidrs?/2" do
    setup do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16,10.42.0.0/16"
      }

      %{tenant: TenantRegistry.load_from_env(env)["TRS"]}
    end

    test "matches first CIDR", %{tenant: t} do
      assert TenantRegistry.ip_in_cidrs?(t, {172, 18, 1, 5})
    end

    test "matches second CIDR", %{tenant: t} do
      assert TenantRegistry.ip_in_cidrs?(t, {10, 42, 0, 1})
    end

    test "rejects outside all CIDRs", %{tenant: t} do
      refute TenantRegistry.ip_in_cidrs?(t, {192, 168, 1, 1})
    end
  end

  describe "cache_at_boot/0 + cached/0" do
    test "cached/0 returns empty map when not yet loaded" do
      TenantRegistry.clear_cache()
      assert TenantRegistry.cached() == %{}
    end

    test "cache_at_boot loads from env and persists" do
      # Skip if any tenant env vars are set in the test environment
      relevant =
        System.get_env()
        |> Map.keys()
        |> Enum.filter(&String.starts_with?(&1, "ZTLP_NS_ADMIN_API_TENANT_"))

      if relevant != [] do
        IO.puts("Skipping: tenant env vars set in test environment: #{inspect(relevant)}")
      else
        TenantRegistry.clear_cache()
        assert TenantRegistry.cache_at_boot() == %{}
        assert TenantRegistry.cached() == %{}
      end
    end
  end

  describe "identify_tenant/3" do
    setup do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_SECRET" => @acme_hex,
        "ZTLP_NS_ADMIN_API_TENANT_ACME_ZONE_GLOB" => "*.acme.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_CIDRS" => "172.20.0.0/16"
      }

      %{registry: TenantRegistry.load_from_env(env)}
    end

    test "matches TRS by signing string + sig", %{registry: registry} do
      canonical = "GET\n/admin/records\n1700000000\nfoo"
      sig = :crypto.mac(:hmac, :sha256, @trs_raw, canonical) |> Base.encode16(case: :lower)
      assert {:ok, %{slug: "TRS"}} = TenantRegistry.identify_tenant(canonical, sig, registry)
    end

    test "matches ACME by signing string + sig", %{registry: registry} do
      canonical = "GET\n/admin/records\n1700000000\nfoo"
      sig = :crypto.mac(:hmac, :sha256, @acme_raw, canonical) |> Base.encode16(case: :lower)
      assert {:ok, %{slug: "ACME"}} = TenantRegistry.identify_tenant(canonical, sig, registry)
    end

    test "no match returns :no_match", %{registry: registry} do
      canonical = "GET\n/admin/records\n1700000000\nfoo"
      bogus_sig = String.duplicate("0", 64)
      assert :no_match = TenantRegistry.identify_tenant(canonical, bogus_sig, registry)
    end

    test "empty registry returns :no_match" do
      canonical = "GET\n/admin/records\n1700000000\nfoo"
      sig = String.duplicate("0", 64)
      assert :no_match = TenantRegistry.identify_tenant(canonical, sig, %{})
    end
  end

  describe "duplicate-secret detection (CodeRabbit PR #98 F1)" do
    # identify_tenant/3's first-match wins is non-deterministic on
    # collision because Enum order over a map is not stable. Refuse
    # to boot rather than allow ambiguous identity assignment.
    test "rejects duplicate tenant secrets at load" do
      shared_hex = String.duplicate("a", 64)

      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => shared_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_SECRET" => shared_hex,
        "ZTLP_NS_ADMIN_API_TENANT_ACME_ZONE_GLOB" => "*.acme.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_CIDRS" => "172.20.0.0/16"
      }

      err =
        assert_raise RuntimeError, ~r/duplicate tenant SECRET/, fn ->
          TenantRegistry.load_from_env(env)
        end

      # Both colliding slugs must be named so operators can act.
      assert err.message =~ "ACME"
      assert err.message =~ "TRS"
    end

    test "distinct secrets across tenants load fine" do
      env = %{
        "ZTLP_NS_ADMIN_API_TENANT_TRS_SECRET" => @trs_hex,
        "ZTLP_NS_ADMIN_API_TENANT_TRS_ZONE_GLOB" => "*.trs.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_TRS_CIDRS" => "172.18.0.0/16",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_SECRET" => @acme_hex,
        "ZTLP_NS_ADMIN_API_TENANT_ACME_ZONE_GLOB" => "*.acme.ztlp",
        "ZTLP_NS_ADMIN_API_TENANT_ACME_CIDRS" => "172.20.0.0/16"
      }

      assert %{"TRS" => _, "ACME" => _} = TenantRegistry.load_from_env(env)
    end
  end

  describe "cache_at_boot/0 failure modes (CodeRabbit PR #98 F2)" do
    # The Application.start/2 rescue clause re-raises when tenant env
    # vars are present but parsing fails (fail-closed). The actual
    # re-raise is exercised by integration boot; here we pin the
    # contract that cache_at_boot/0 itself raises so the rescue has
    # something to react to.
    test "cache_at_boot raises on invalid env (so Application can re-raise)" do
      bad_keys = [
        "ZTLP_NS_ADMIN_API_TENANT_BAD_SECRET",
        "ZTLP_NS_ADMIN_API_TENANT_BAD_ZONE_GLOB",
        "ZTLP_NS_ADMIN_API_TENANT_BAD_CIDRS"
      ]

      try do
        System.put_env("ZTLP_NS_ADMIN_API_TENANT_BAD_SECRET", "not-hex-and-wrong-length")
        System.put_env("ZTLP_NS_ADMIN_API_TENANT_BAD_ZONE_GLOB", "*.bad.ztlp")
        System.put_env("ZTLP_NS_ADMIN_API_TENANT_BAD_CIDRS", "172.18.0.0/16")

        assert_raise RuntimeError, ~r/secret/i, fn ->
          TenantRegistry.cache_at_boot()
        end
      after
        Enum.each(bad_keys, &System.delete_env/1)
        TenantRegistry.clear_cache()
      end
    end
  end
end
