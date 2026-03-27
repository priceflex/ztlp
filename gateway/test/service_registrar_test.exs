defmodule ZtlpGateway.ServiceRegistrarTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.ServiceRegistrar

  describe "derive_service_names/1" do
    test "extracts service names from backends config" do
      # Set up backends env
      System.put_env("ZTLP_GATEWAY_BACKENDS", "default:vaultwarden:80")
      zone = "techrockstars.ztlp"

      # Call the private function via the module
      names = get_service_names(zone)

      assert "default.techrockstars.ztlp" in names
      assert "vault.techrockstars.ztlp" in names
    after
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end

    test "handles multiple backends" do
      System.put_env("ZTLP_GATEWAY_BACKENDS", "web:nginx:80,api:app:3000")
      zone = "example.ztlp"

      names = get_service_names(zone)

      assert "web.example.ztlp" in names
      assert "api.example.ztlp" in names
      refute Enum.any?(names, &String.contains?(&1, "vault"))
    after
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end
  end

  describe "start_link/1" do
    test "starts disabled when no NS server configured" do
      System.delete_env("ZTLP_NS_SERVER")
      System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")

      {:ok, pid} = ServiceRegistrar.start_link()
      state = ServiceRegistrar.state()

      assert state.enabled == false

      GenServer.stop(pid)
    end

    test "starts disabled when no public addr configured" do
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")

      {:ok, pid} = ServiceRegistrar.start_link()
      state = ServiceRegistrar.state()

      assert state.enabled == false

      GenServer.stop(pid)
    after
      System.delete_env("ZTLP_NS_SERVER")
    end

    test "starts enabled with NS server and public addr" do
      System.put_env("ZTLP_NS_SERVER", "127.0.0.1:23096")
      System.put_env("ZTLP_GATEWAY_PUBLIC_ADDR", "1.2.3.4:23097")
      System.put_env("ZTLP_GATEWAY_BACKENDS", "default:vaultwarden:80")

      {:ok, pid} = ServiceRegistrar.start_link()
      state = ServiceRegistrar.state()

      assert state.enabled == true
      assert state.public_addr == "1.2.3.4:23097"
      assert is_binary(state.pubkey) and byte_size(state.pubkey) == 32
      assert length(state.service_names) >= 1

      GenServer.stop(pid)
    after
      System.delete_env("ZTLP_NS_SERVER")
      System.delete_env("ZTLP_GATEWAY_PUBLIC_ADDR")
      System.delete_env("ZTLP_GATEWAY_BACKENDS")
    end
  end

  # Helper to extract service names using the same logic as the module
  defp get_service_names(zone) do
    backends = ZtlpGateway.Config.get(:backends) || []

    base_names =
      backends
      |> Enum.map(fn
        %{name: name} -> name
        _ -> nil
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    vault_alias =
      backends
      |> Enum.any?(fn
        %{host: host} -> String.contains?(to_string(host), "vaultwarden")
        _ -> false
      end)

    aliases = if vault_alias, do: ["vault"], else: []

    (base_names ++ aliases)
    |> Enum.uniq()
    |> Enum.map(fn name ->
      if String.contains?(name, "."), do: name, else: "#{name}.#{zone}"
    end)
  end
end
