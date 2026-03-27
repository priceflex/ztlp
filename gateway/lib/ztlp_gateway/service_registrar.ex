defmodule ZtlpGateway.ServiceRegistrar do
  @moduledoc """
  Periodically registers gateway services with ZTLP-NS.

  Implements Section 9.6.8 (Service Registration Authorization) and
  Section 25.1.1 (Gateway Service Registration) of the ZTLP specification.

  On startup, the gateway registers SVC records for all backend services
  and refreshes them at TTL/2 intervals. Registration requires an
  operator signing key for production deployments.

  ## Environment Variables

  - `ZTLP_NS_SERVER` — NS server address (host:port)
  - `ZTLP_GATEWAY_PUBLIC_ADDR` — Gateway's public endpoint for SVC records
  - `ZTLP_GATEWAY_SERVICE_ZONE` — Zone suffix (default: from Config or "techrockstars.ztlp")
  - `ZTLP_NS_REGISTRATION_TTL` — TTL in seconds (default: 300)
  - `ZTLP_GATEWAY_OPERATOR_KEY` — Hex-encoded Ed25519 seed (32 bytes = 64 hex chars)
  - `ZTLP_GATEWAY_OPERATOR_KEY_FILE` — Path to JSON key file (same format as `ztlp keygen`)
  - `ZTLP_GATEWAY_SERVICE_ALIASES` — Comma-separated extra service names to register

  ## Key Loading Priority

  1. `ZTLP_GATEWAY_OPERATOR_KEY_FILE` (file path — preferred for Docker secrets)
  2. `ZTLP_GATEWAY_OPERATOR_KEY` (hex-encoded seed — simple deployments)
  3. Ephemeral key generation (dev/demo mode only — logs a warning)

  ## Registration Protocol

  Uses ZTLP-NS REGISTER (0x09) with Ed25519-signed SVC records (type 0x02).
  See Section 9.5.7 for wire format.
  """

  use GenServer

  require Logger

  alias ZtlpGateway.Config

  @svc_type_byte 0x02
  @default_ttl 300
  @default_zone "techrockstars.ztlp"
  @initial_backoff 5_000
  @max_backoff 60_000

  # ── Client API ──────────────────────────────────────────────

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Get the current registrar state (for debugging/monitoring)."
  @spec state() :: map()
  def state do
    GenServer.call(__MODULE__, :state)
  end

  @doc "Force an immediate re-registration cycle."
  @spec register_now() :: :ok
  def register_now do
    send(__MODULE__, :register)
    :ok
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
        {pubkey, privkey, key_source} = load_operator_key()
        service_names = derive_service_names(zone)

        Logger.info(
          "[ServiceRegistrar] Starting: #{length(service_names)} services, " <>
            "NS=#{format_addr(ns_server)}, zone=#{zone}, TTL=#{ttl}s, " <>
            "key_source=#{key_source}"
        )

        for name <- service_names do
          Logger.info("[ServiceRegistrar]   → #{name} → #{public_addr}")
        end

        state = %{
          enabled: true,
          ns_server: ns_server,
          public_addr: public_addr,
          zone: zone,
          ttl: ttl,
          pubkey: pubkey,
          privkey: privkey,
          key_source: key_source,
          service_names: service_names,
          last_registration: nil,
          last_error: nil,
          consecutive_failures: 0,
          total_registrations: 0,
          test_opts: Keyword.get(opts, :test_opts, %{})
        }

        # Register after a short delay unless test mode
        unless Map.get(Keyword.get(opts, :test_opts, %{}), :skip_register, false) do
          Process.send_after(self(), :register, 1_000)
        end

        {:ok, state}
    end
  end

  @impl true
  def handle_call(:state, _from, state) do
    # Return a safe subset (no private keys)
    safe_state =
      state
      |> Map.drop([:privkey, :test_opts])
      |> Map.put(:pubkey_hex, if(state[:pubkey], do: Base.encode16(state.pubkey, case: :lower), else: nil))

    {:reply, safe_state, state}
  end

  @impl true
  def handle_info(:register, %{enabled: false} = state) do
    {:noreply, state}
  end

  def handle_info(:register, state) do
    case :gen_udp.open(0, [:binary, {:active, false}]) do
      {:ok, socket} ->
        # Ensure zone delegation key exists (self-healing bootstrap)
        state =
          if not Map.get(state, :zone_bootstrapped, false) do
            case bootstrap_zone_delegation(socket, state) do
              :ok ->
                Logger.info("[ServiceRegistrar] Zone delegation key bootstrapped for #{state.zone}")
                Map.put(state, :zone_bootstrapped, true)
              {:error, reason} ->
                Logger.warning("[ServiceRegistrar] Zone delegation bootstrap failed: #{inspect(reason)}")
                state
            end
          else
            state
          end

        results =
          for name <- state.service_names do
            result = do_register(socket, state.ns_server, name, state)
            {name, result}
          end

        :gen_udp.close(socket)

        successes = Enum.count(results, fn {_, r} -> r == :ok end)
        failures = Enum.count(results, fn {_, r} -> r != :ok end)

        state =
          if failures == 0 do
            for {name, :ok} <- results do
              Logger.info("[ServiceRegistrar] Registered #{name} → #{state.public_addr}")
            end

            %{state |
              last_registration: System.system_time(:second),
              last_error: nil,
              consecutive_failures: 0,
              total_registrations: state.total_registrations + successes
            }
          else
            for {name, {:error, reason}} <- results do
              Logger.warning("[ServiceRegistrar] Failed to register #{name}: #{inspect(reason)}")
            end

            %{state |
              last_error: List.first(Enum.filter(results, fn {_, r} -> r != :ok end)),
              consecutive_failures: state.consecutive_failures + 1,
              total_registrations: state.total_registrations + successes
            }
          end

        # Schedule next registration
        interval = next_interval(state)
        Process.send_after(self(), :register, interval)

        {:noreply, state}

      {:error, reason} ->
        Logger.warning("[ServiceRegistrar] Failed to open UDP socket: #{inspect(reason)}")
        state = %{state | consecutive_failures: state.consecutive_failures + 1, last_error: {:socket, reason}}
        interval = next_interval(state)
        Process.send_after(self(), :register, interval)
        {:noreply, state}
    end
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Private: Operator Key Loading ───────────────────────────

  defp load_operator_key do
    # Priority 1: Key file (Docker secret / mounted file)
    case System.get_env("ZTLP_GATEWAY_OPERATOR_KEY_FILE") do
      nil -> :skip
      "" -> :skip
      path ->
        case load_key_file(path) do
          {:ok, pub, priv} ->
            Logger.info("[ServiceRegistrar] Loaded operator key from file: #{path}")
            {pub, priv, :file}
          {:error, reason} ->
            Logger.warning("[ServiceRegistrar] Failed to load key file #{path}: #{inspect(reason)}")
            :skip
        end
    end
    |> case do
      {_, _, _} = result -> result
      :skip ->
        # Priority 2: Hex-encoded seed env var
        case System.get_env("ZTLP_GATEWAY_OPERATOR_KEY") do
          nil -> :skip
          "" -> :skip
          hex_seed ->
            case load_hex_seed(hex_seed) do
              {:ok, pub, priv} ->
                Logger.info("[ServiceRegistrar] Loaded operator key from ZTLP_GATEWAY_OPERATOR_KEY env")
                {pub, priv, :env}
              {:error, reason} ->
                Logger.warning("[ServiceRegistrar] Invalid ZTLP_GATEWAY_OPERATOR_KEY: #{inspect(reason)}")
                :skip
            end
        end
        |> case do
          {_, _, _} = result -> result
          :skip ->
            # Priority 3: Ephemeral key (dev/demo only)
            Logger.warning(
              "[ServiceRegistrar] No operator key configured — using ephemeral key. " <>
                "This is acceptable for dev/demo but MUST NOT be used in production. " <>
                "Set ZTLP_GATEWAY_OPERATOR_KEY_FILE or ZTLP_GATEWAY_OPERATOR_KEY."
            )
            {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
            {pub, priv, :ephemeral}
        end
    end
  end

  defp load_key_file(path) do
    case File.read(path) do
      {:ok, content} ->
        trimmed = String.trim(content)
        cond do
          # JSON format from `ztlp keygen` — extract ed25519_seed with regex
          # (no JSON library dependency — gateway is zero-dep)
          String.contains?(trimmed, "ed25519_seed") ->
            case Regex.run(~r/"ed25519_seed"\s*:\s*"([0-9a-fA-F]{64})"/, trimmed) do
              [_, seed_hex] -> load_hex_seed(seed_hex)
              _ -> {:error, :invalid_key_file_format}
            end

          # Raw hex seed (64 hex chars on a single line)
          Regex.match?(~r/\A[0-9a-fA-F]{64}\z/, trimmed) ->
            load_hex_seed(trimmed)

          true ->
            {:error, :unrecognized_key_file_format}
        end

      {:error, reason} ->
        {:error, {:file_read_error, reason}}
    end
  end

  defp load_hex_seed(hex_seed) do
    trimmed = String.trim(hex_seed)
    case Base.decode16(trimmed, case: :mixed) do
      {:ok, seed} when byte_size(seed) == 32 ->
        {pub, priv} = :crypto.generate_key(:eddsa, :ed25519, seed)
        {:ok, pub, priv}
      {:ok, _} ->
        {:error, :invalid_seed_length}
      :error ->
        {:error, :invalid_hex}
    end
  end

  # ── Private: Registration ───────────────────────────────────

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

    # Build canonical form for signing (per Section 9.5.7)
    name_len = byte_size(name)
    canonical = <<@svc_type_byte::8, name_len::16, name::binary, data_bin::binary>>

    # Sign with Ed25519 operator key
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
          {:ok, {_, _, <<0x04, _::binary>>}} -> {:error, :policy_denied}
          {:ok, {_, _, resp}} -> {:error, {:unexpected_response, byte_size(resp)}}
          {:error, :timeout} -> {:error, :timeout}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, {:dns_error, reason}}
    end
  end

  # ── Private: Zone Delegation Bootstrap ────────────────────────

  defp bootstrap_zone_delegation(socket, state) do
    # Register an unsigned KEY record with delegation=true for the zone.
    # This allows the operator's pubkey to register SVC records.
    # Uses v1 (unsigned) format since we can't sign before the delegation
    # record exists (chicken-and-egg). NS must have auth disabled for
    # initial bootstrap, or the operator must pre-register the zone key.
    name = state.zone
    pubkey_hex = Base.encode16(state.pubkey, case: :lower)

    # CBOR-encode the delegation data
    data = %{
      "delegation" => true,
      "public_key" => pubkey_hex
    }

    data_bin = encode_delegation_cbor(data)

    name_len = byte_size(name)
    type_byte = 0x01  # KEY record

    # Build unsigned v1 registration (no pubkey trailer)
    fake_sig = :binary.copy(<<0>>, 64)
    sig_len = byte_size(fake_sig)

    packet =
      <<0x09, name_len::16, name::binary, type_byte::8, byte_size(data_bin)::16,
        data_bin::binary, sig_len::16, fake_sig::binary>>

    {ns_host, ns_port} = state.ns_server

    case resolve_host(ns_host) do
      {:ok, ip} ->
        :gen_udp.send(socket, ip, ns_port, packet)

        case :gen_udp.recv(socket, 0, 5_000) do
          {:ok, {_, _, <<0x06, _::binary>>}} -> :ok
          {:ok, {_, _, <<0xFF>>}} -> {:error, :rejected}
          {:ok, {_, _, resp}} -> {:error, {:unexpected, byte_size(resp)}}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, {:dns, reason}}
    end
  end

  # Minimal deterministic CBOR encoder for zone delegation data.
  # Only supports the specific shape: {"delegation": true, "public_key": "hex..."}
  # Keys are sorted per RFC 8949 §4.2.1.
  defp encode_delegation_cbor(data) do
    # Sort keys, encode as CBOR map
    items =
      data
      |> Enum.sort_by(fn {k, _} -> k end)
      |> Enum.map(fn {k, v} -> encode_cbor_pair(k, v) end)
      |> Enum.join()

    <<0xA0 + map_size(data)::8>> <> items
  end

  defp encode_cbor_pair(key, value) when is_binary(key) do
    encode_cbor_text(key) <> encode_cbor_value(value)
  end

  defp encode_cbor_text(s) do
    len = byte_size(s)

    if len < 24 do
      <<0x60 + len::8>> <> s
    else
      <<0x78, len::8>> <> s
    end
  end

  defp encode_cbor_value(true), do: <<0xF5>>
  defp encode_cbor_value(false), do: <<0xF4>>

  defp encode_cbor_value(s) when is_binary(s) do
    encode_cbor_text(s)
  end

  # ── Private: Service Name Derivation ────────────────────────

  defp derive_service_names(zone) do
    backends = Config.get(:backends) || []

    # Extract service names from backend config
    base_names =
      backends
      |> Enum.map(fn
        %{name: name} -> name
        {name, _host, _port} -> name
        _ -> nil
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.uniq()

    # Auto-detect aliases from backend hostnames
    auto_aliases =
      backends
      |> Enum.flat_map(fn
        %{host: host} -> detect_aliases(to_string(host))
        {_name, host, _port} -> detect_aliases(to_string(host))
        _ -> []
      end)

    # Manual aliases from env var
    manual_aliases =
      case System.get_env("ZTLP_GATEWAY_SERVICE_ALIASES") do
        nil -> []
        "" -> []
        aliases -> String.split(aliases, ",", trim: true) |> Enum.map(&String.trim/1)
      end

    # Build fully-qualified names
    (base_names ++ auto_aliases ++ manual_aliases)
    |> Enum.uniq()
    |> Enum.map(fn name ->
      if String.contains?(name, ".") do
        name
      else
        "#{name}.#{zone}"
      end
    end)
  end

  defp detect_aliases(hostname) do
    cond do
      String.contains?(hostname, "vaultwarden") -> ["vault"]
      String.contains?(hostname, "bitwarden") -> ["vault", "bitwarden"]
      String.contains?(hostname, "grafana") -> ["grafana"]
      String.contains?(hostname, "prometheus") -> ["metrics"]
      true -> []
    end
  end

  # ── Private: Scheduling ─────────────────────────────────────

  defp next_interval(%{consecutive_failures: 0, ttl: ttl}) do
    # Normal: re-register at TTL/2
    div(ttl * 1000, 2)
  end

  defp next_interval(%{consecutive_failures: n}) do
    # Exponential backoff on failure, capped at max_backoff
    backoff = @initial_backoff * :math.pow(2, min(n - 1, 4)) |> trunc()
    min(backoff, @max_backoff)
  end

  # ── Private: Utilities ──────────────────────────────────────

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

  defp resolve_host(host) when is_list(host) do
    case :inet.getaddr(host, :inet) do
      {:ok, ip} -> {:ok, ip}
      {:error, _} = err -> err
    end
  end

  defp resolve_host(host) when is_binary(host), do: resolve_host(to_charlist(host))
  defp resolve_host(host) when is_tuple(host), do: {:ok, host}

  defp format_addr({host, port}) when is_list(host), do: "#{host}:#{port}"
  defp format_addr({host, port}), do: "#{inspect(host)}:#{port}"

  defp parse_int(nil, default), do: default
  defp parse_int(str, default) do
    case Integer.parse(str) do
      {n, _} -> n
      :error -> default
    end
  end
end
