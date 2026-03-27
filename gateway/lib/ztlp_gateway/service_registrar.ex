defmodule ZtlpGateway.ServiceRegistrar do
  @moduledoc """
  Periodically registers gateway services with ZTLP-NS.

  When `ZTLP_NS_SERVER` and `ZTLP_GATEWAY_PUBLIC_ADDR` are set, this
  GenServer registers SVC records for each backend service on startup
  and refreshes them every TTL/2 seconds.

  ## Environment Variables

  - `ZTLP_NS_SERVER` — NS server address (host:port), e.g. "34.217.62.46:23096"
  - `ZTLP_GATEWAY_PUBLIC_ADDR` — Gateway's public address for clients, e.g. "54.149.48.6:23097"
  - `ZTLP_GATEWAY_SERVICE_ZONE` — Zone suffix for service names (default: "techrockstars.ztlp")
  - `ZTLP_NS_REGISTRATION_TTL` — TTL in seconds for NS records (default: 300)

  ## Registration

  For each backend in `ZTLP_GATEWAY_BACKENDS` (e.g., "default:vaultwarden:80"),
  the first service name "default" becomes "default.<zone>" in NS. But we also
  register user-friendly aliases — if the backend host is "vaultwarden", we
  register "vault.<zone>" as well.

  Uses the v2 NS registration protocol (0x09) with Ed25519 signatures.
  """

  use GenServer

  require Logger

  alias ZtlpGateway.Config

  @svc_type_byte 0x02
  @default_ttl 300
  @default_zone "techrockstars.ztlp"

  # ── Client API ──────────────────────────────────────────────

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec state() :: map()
  def state do
    GenServer.call(__MODULE__, :state)
  end

  # ── GenServer Callbacks ─────────────────────────────────────

  @impl true
  def init(opts) do
    ns_server = get_ns_server()
    public_addr = System.get_env("ZTLP_GATEWAY_PUBLIC_ADDR")
    zone = System.get_env("ZTLP_GATEWAY_SERVICE_ZONE") || @default_zone
    ttl = parse_int(System.get_env("ZTLP_NS_REGISTRATION_TTL"), @default_ttl)

    cond do
      is_nil(ns_server) ->
        Logger.info("[ServiceRegistrar] No ZTLP_NS_SERVER configured, NS registration disabled")
        {:ok, %{enabled: false}}

      is_nil(public_addr) || public_addr == "" ->
        Logger.info("[ServiceRegistrar] No ZTLP_GATEWAY_PUBLIC_ADDR set, NS registration disabled")
        {:ok, %{enabled: false}}

      true ->
        # Generate a persistent signing keypair for NS registration
        {pubkey, privkey} = generate_keypair()
        service_names = derive_service_names(zone)

        Logger.info(
          "[ServiceRegistrar] Will register #{length(service_names)} services with NS " <>
          "#{inspect(ns_server)}: #{inspect(service_names)} → #{public_addr} (TTL=#{ttl}s)"
        )

        state = %{
          enabled: true,
          ns_server: ns_server,
          public_addr: public_addr,
          zone: zone,
          ttl: ttl,
          pubkey: pubkey,
          privkey: privkey,
          service_names: service_names,
          test_opts: Keyword.get(opts, :test_opts, %{})
        }

        # Register immediately
        Process.send_after(self(), :register, 1_000)

        {:ok, state}
    end
  end

  @impl true
  def handle_call(:state, _from, state) do
    {:reply, state, state}
  end

  @impl true
  def handle_info(:register, %{enabled: false} = state) do
    {:noreply, state}
  end

  def handle_info(:register, state) do
    case :gen_udp.open(0, [:binary, {:active, false}]) do
      {:ok, socket} ->
        {ns_host, ns_port} = state.ns_server

        for name <- state.service_names do
          result = do_register(socket, {ns_host, ns_port}, name, state)

          case result do
            :ok ->
              Logger.info("[ServiceRegistrar] Registered #{name} → #{state.public_addr}")
            {:error, reason} ->
              Logger.warning("[ServiceRegistrar] Failed to register #{name}: #{inspect(reason)}")
          end
        end

        :gen_udp.close(socket)

        # Re-register at TTL/2
        interval = div(state.ttl * 1000, 2)
        Process.send_after(self(), :register, interval)

      {:error, reason} ->
        Logger.warning("[ServiceRegistrar] Failed to open UDP socket: #{inspect(reason)}, retrying in 5s")
        Process.send_after(self(), :register, 5_000)
    end

    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Private ─────────────────────────────────────────────────

  defp do_register(socket, {ns_host, ns_port}, name, state) do
    # Build SVC record data (CBOR-encoded)
    data = %{
      "address" => state.public_addr,
      "type" => "gateway",
      "zone" => state.zone
    }

    data_bin =
      case Code.ensure_loaded(ZtlpGateway.Cbor) do
        {:module, _} -> ZtlpGateway.Cbor.encode(data)
        _ -> :erlang.term_to_binary(data)
      end

    # Build canonical form for signing
    name_len = byte_size(name)
    canonical = <<@svc_type_byte::8, name_len::16, name::binary, data_bin::binary>>

    # Sign with Ed25519
    sig = :crypto.sign(:eddsa, :none, canonical, [state.privkey, :ed25519])

    # Build v2 registration packet (0x09)
    reg =
      <<0x09, name_len::16, name::binary, @svc_type_byte::8, byte_size(data_bin)::16,
        data_bin::binary, byte_size(sig)::16, sig::binary,
        byte_size(state.pubkey)::16, state.pubkey::binary>>

    case resolve_host(ns_host) do
      {:ok, ip} ->
        :gen_udp.send(socket, ip, ns_port, reg)

        case :gen_udp.recv(socket, 0, 5_000) do
          {:ok, {_, _, <<0x06, _::binary>>}} -> :ok
          {:ok, {_, _, <<0xFF>>}} -> {:error, :rejected}
          {:ok, {_, _, resp}} -> {:error, {:unexpected_response, byte_size(resp)}}
          {:error, :timeout} -> {:error, :timeout}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, {:dns_error, reason}}
    end
  end

  defp derive_service_names(zone) do
    # Get backend service names from config
    backends = Config.get(:backends) || []

    # Each backend has a service name (first element of the tuple)
    # Also add common aliases
    base_names =
      backends
      |> Enum.map(fn
        %{name: name} -> name
        {name, _host, _port} -> name
        _ -> nil
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    # Also add "vault" alias if any backend host contains "vaultwarden"
    vault_alias =
      backends
      |> Enum.any?(fn
        %{host: host} -> String.contains?(to_string(host), "vaultwarden")
        {_name, host, _port} -> String.contains?(to_string(host), "vaultwarden")
        _ -> false
      end)

    aliases = if vault_alias, do: ["vault"], else: []

    # Build fully-qualified names
    (base_names ++ aliases)
    |> Enum.uniq()
    |> Enum.map(fn name ->
      if String.contains?(name, ".") do
        name
      else
        "#{name}.#{zone}"
      end
    end)
  end

  defp get_ns_server do
    case System.get_env("ZTLP_NS_SERVER") do
      nil -> nil
      "" -> nil
      addr ->
        case String.split(addr, ":") do
          [host, port_str] ->
            case Integer.parse(port_str) do
              {port, _} -> {to_charlist(host), port}
              _ -> nil
            end
          _ -> nil
        end
    end
  end

  defp generate_keypair do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    {pub, priv}
  end

  defp resolve_host(host) when is_list(host) do
    case :inet.getaddr(host, :inet) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} = err -> err
    end
  end

  defp resolve_host(host) when is_binary(host) do
    resolve_host(to_charlist(host))
  end

  defp resolve_host(host) when is_tuple(host) do
    {:ok, host}
  end

  defp parse_int(nil, default), do: default
  defp parse_int(str, default) do
    case Integer.parse(str) do
      {n, _} -> n
      :error -> default
    end
  end
end
