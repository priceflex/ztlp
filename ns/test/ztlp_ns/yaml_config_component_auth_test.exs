defmodule ZtlpNs.YamlConfigComponentAuthTest do
  @moduledoc """
  Regression/behavior pin for ZTLP DEF CON cloud-demo automation (Task 1-3,
  ztlp-cloud-demo-plan.md).

  Ground-truth fact #9 in the plan claimed NS had "ZERO env-var or
  config-file wiring for component_auth_*". That's stale: YamlConfig.validate/1
  (ns/lib/ztlp_ns/yaml_config.ex:141-156) already parses a `component_auth`
  YAML section into :component_auth_enabled / :component_auth_allowed_keys /
  :component_auth_identity_key_file — the SAME mechanism gateway already uses
  via ZTLP_GATEWAY_CONFIG. These tests pin the behavior end-to-end (parse ->
  apply_to_app_env) so the demo compose file can drive it via ZTLP_NS_CONFIG
  without any runtime.exs code changes.
  """
  use ExUnit.Case, async: true

  alias ZtlpNs.YamlConfig

  describe "validate/1 component_auth section" do
    test "enabled + identity_key_file + allowed_keys all parse into config" do
      pub_hex = String.duplicate("ab", 32)

      raw = %{
        "component_auth" => %{
          "enabled" => true,
          "identity_key_file" => "/data/gw/identity.key",
          "allowed_keys" => [pub_hex]
        }
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:component_auth_enabled] == true
      assert config[:component_auth_identity_key_file] == "/data/gw/identity.key"
      assert config[:component_auth_allowed_keys] == [Base.decode16!(pub_hex, case: :mixed)]
    end

    test "component_auth section absent defaults to disabled, no crash" do
      assert {:ok, config} = YamlConfig.validate(%{})
      assert Map.get(config, :component_auth_enabled, false) == false
    end

    test "invalid hex in allowed_keys surfaces a validation error (fails closed)" do
      raw = %{"component_auth" => %{"enabled" => true, "allowed_keys" => ["not-hex-zz"]}}

      assert {:error, errors} = YamlConfig.validate(raw)
      assert Enum.any?(errors, &String.contains?(&1, "allowed_keys"))
    end
  end

  describe "load_and_apply/0 wires component_auth into Application env from a real file" do
    test "a mounted YAML file with component_auth.enabled=true + allowed_keys sets NS app env" do
      pub = :crypto.strong_rand_bytes(32)
      pub_hex = Base.encode16(pub, case: :lower)

      test_dir = Path.join(System.tmp_dir!(), "ztlp_ns_config_test_#{:rand.uniform(1_000_000)}")
      File.mkdir_p!(test_dir)
      config_path = Path.join(test_dir, "ns-config.yaml")

      File.write!(config_path, """
      component_auth:
        enabled: true
        allowed_keys:
          - "#{pub_hex}"
      """)

      prev_config_env = System.get_env("ZTLP_NS_CONFIG")

      # `validate/1` fills defaults for EVERY key it knows about (e.g.
      # `storage_mode: :disc_copies`, `mnesia_dir`, ...) and `apply_to_app_env`
      # writes all of them into the :ztlp_ns app env. Restoring only the
      # component_auth keys leaked `storage_mode: :disc_copies` over the
      # test-env `:ram_copies` and made StoreMnesiaTest "storage mode" fail
      # whenever this test happened to run first (seed-dependent). Snapshot
      # and restore the whole app env instead.
      prev_app_env = Application.get_all_env(:ztlp_ns)

      on_exit(fn ->
        if prev_config_env, do: System.put_env("ZTLP_NS_CONFIG", prev_config_env), else: System.delete_env("ZTLP_NS_CONFIG")

        for {key, _} <- Application.get_all_env(:ztlp_ns), not Keyword.has_key?(prev_app_env, key) do
          Application.delete_env(:ztlp_ns, key)
        end

        Application.put_all_env([{:ztlp_ns, prev_app_env}])
        File.rm_rf!(test_dir)
      end)

      System.put_env("ZTLP_NS_CONFIG", config_path)

      assert :ok = YamlConfig.load_and_apply()

      assert Application.get_env(:ztlp_ns, :component_auth_enabled) == true
      assert Application.get_env(:ztlp_ns, :component_auth_allowed_keys) == [pub]
    end
  end
end
