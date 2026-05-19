defmodule ZtlpGateway.ServiceRegistrarDeriveTest do
  @moduledoc """
  Tests for `ZtlpGateway.ServiceRegistrar.derive_service_names/1` covering
  the pre-existing crash where `to_string/1` was called on an erlang IP
  tuple `{127, 0, 0, 1}` taken from the compile-time default backend list.

  Regression triggered on 2026-05-19 when the production gateway was
  redeployed with `ZTLP_GATEWAY_SERVICE_NAMES=bootstrap` — the
  ServiceRegistrar init/1 invoked derive_service_names/1 which mapped the
  default backends `[%{host: {127,0,0,1}, port: 8080, name: "web"}, ...]`
  through `to_string(host)` and crashed with Protocol.UndefinedError
  because String.Chars is not implemented for tuples.

  Test private helper via module-attribute trick: derive_service_names/1
  is private. We probe it via the public ServiceRegistrar.init callback's
  effect on `state.service_names` — but the GenServer init/1 has many
  side effects we don't want. Instead, we expose the helper via a tiny
  shim function for test only — see set_backends_and_derive/2 below.

  Alternative would be to test through the public surface (start_link +
  read state via :sys.get_state) but that requires a working UDP socket
  and an NS that responds. Helper shim keeps the test focused.
  """
  use ExUnit.Case, async: false

  # ServiceRegistrar's derive_service_names/1 is private; reach it via
  # apply/3 since defp prevents direct call. Acceptable in tests.
  defp derive(zone) do
    apply(ZtlpGateway.ServiceRegistrar, :derive_service_names, [zone])
  end

  describe "derive_service_names/1 with the default backend list" do
    # Before the fix, this crashed with:
    #   ** (Protocol.UndefinedError) protocol String.Chars not implemented
    #      for {127, 0, 0, 1} of type Tuple
    setup do
      prev_backends = Application.get_env(:ztlp_gateway, :backends)
      Application.put_env(:ztlp_gateway, :backends, [
        %{name: "web", host: {127, 0, 0, 1}, port: 8080},
        %{name: "ssh", host: {127, 0, 0, 1}, port: 22}
      ])

      on_exit(fn ->
        if prev_backends,
          do: Application.put_env(:ztlp_gateway, :backends, prev_backends),
          else: Application.delete_env(:ztlp_gateway, :backends)
      end)

      :ok
    end

    test "does not crash on tuple-form host (127.0.0.1 in compile-time defaults)" do
      # Should return a list of FQ service names (e.g. "web.zone.ztlp", "ssh.zone.ztlp").
      # The tuple host {127,0,0,1} carries no alias hints so auto_aliases must be [].
      result = derive("zone.ztlp")
      assert is_list(result)
      assert "web.zone.ztlp" in result
      assert "ssh.zone.ztlp" in result
    end

    test "produces no alias entries from a loopback IP tuple" do
      # 127.0.0.1 is not 'vaultwarden'/'bitwarden'/'grafana'/'prometheus' →
      # detect_aliases/1 should return [] for it.
      result = derive("zone.ztlp")
      refute "vault.zone.ztlp" in result
      refute "grafana.zone.ztlp" in result
      refute "metrics.zone.ztlp" in result
    end
  end

  describe "derive_service_names/1 with vaultwarden-style hostname" do
    setup do
      prev_backends = Application.get_env(:ztlp_gateway, :backends)
      # String-form host is the canonical alias-detection path
      Application.put_env(:ztlp_gateway, :backends, [
        %{name: "vw", host: "vaultwarden.internal", port: 80}
      ])

      on_exit(fn ->
        if prev_backends,
          do: Application.put_env(:ztlp_gateway, :backends, prev_backends),
          else: Application.delete_env(:ztlp_gateway, :backends)
      end)

      :ok
    end

    test "emits 'vault.<zone>' alias when host hostname contains 'vaultwarden'" do
      result = derive("zone.ztlp")
      assert "vault.zone.ztlp" in result
      assert "vw.zone.ztlp" in result
    end
  end
end
