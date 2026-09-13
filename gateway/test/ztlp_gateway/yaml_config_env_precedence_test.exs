defmodule ZtlpGateway.YamlConfigEnvPrecedenceTest do
  use ExUnit.Case, async: false

  @moduledoc """
  Live-observed (Q6, 2026-09-13, demo stack): the gateway ran with
  `ZTLP_NS_SERVER=172.42.90.10:23096` (parsed by config/runtime.exs into
  `:ns_server_host`/`:ns_server_port`), but `Config.get(:ns_server_host)`
  returned `{127, 0, 0, 1}`. Cause: `YamlConfig.load_and_apply/0` ran with a
  `gateway-config.yaml` that has NO `ns:` section, and `validate/1` still
  emitted the *default* host/port, which `apply_to_app_env/1` then wrote
  over the env-derived values. Every Noise handshake then paid a 2 s NS
  timeout and every identity resolved to `unknown:<hex>`.

  Contract pinned here: a key that is ABSENT from the YAML must not change
  whatever is already in the application env.
  """

  alias ZtlpGateway.YamlConfig

  @keys [:ns_server_host, :ns_server_port, :ns_query_timeout_ms, :port, :session_timeout_ms, :max_sessions]

  setup do
    prev = for k <- @keys, do: {k, Application.fetch_env(:ztlp_gateway, k)}

    on_exit(fn ->
      for {k, v} <- prev do
        case v do
          {:ok, val} -> Application.put_env(:ztlp_gateway, k, val)
          :error -> Application.delete_env(:ztlp_gateway, k)
        end
      end
    end)

    :ok
  end

  test "absent ns section leaves env-derived ns_server_host/port untouched" do
    Application.put_env(:ztlp_gateway, :ns_server_host, {172, 42, 90, 10})
    Application.put_env(:ztlp_gateway, :ns_server_port, 23096)

    # gateway-config.yaml in demo/ has only a component_auth section.
    {:ok, config} = YamlConfig.validate(%{"component_auth" => %{"enabled" => true}})
    YamlConfig.apply_to_app_env(config)

    assert Application.get_env(:ztlp_gateway, :ns_server_host) == {172, 42, 90, 10}
    assert Application.get_env(:ztlp_gateway, :ns_server_port) == 23096
  end

  test "absent top-level keys leave env-derived port/session_timeout/max_sessions untouched" do
    Application.put_env(:ztlp_gateway, :port, 33097)
    Application.put_env(:ztlp_gateway, :session_timeout_ms, 1234)
    Application.put_env(:ztlp_gateway, :max_sessions, 42)

    {:ok, config} = YamlConfig.validate(%{})
    YamlConfig.apply_to_app_env(config)

    assert Application.get_env(:ztlp_gateway, :port) == 33097
    assert Application.get_env(:ztlp_gateway, :session_timeout_ms) == 1234
    assert Application.get_env(:ztlp_gateway, :max_sessions) == 42
  end

  test "explicit ns section still overrides env" do
    Application.put_env(:ztlp_gateway, :ns_server_host, {172, 42, 90, 10})

    {:ok, config} = YamlConfig.validate(%{"ns" => %{"host" => "10.9.8.7", "port" => 1111}})
    YamlConfig.apply_to_app_env(config)

    assert Application.get_env(:ztlp_gateway, :ns_server_host) == {10, 9, 8, 7}
    assert Application.get_env(:ztlp_gateway, :ns_server_port) == 1111
  end
end
