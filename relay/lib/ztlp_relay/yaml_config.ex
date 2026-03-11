defmodule ZtlpRelay.YamlConfig do
  @moduledoc """
  YAML configuration loader and validator for the ZTLP Relay.

  Reads a YAML config file, validates it against the relay schema,
  and writes validated values to the OTP application environment
  so the existing `ZtlpRelay.Config` module picks them up seamlessly.

  ## Config File Resolution

  1. `ZTLP_RELAY_CONFIG` environment variable
  2. `/etc/ztlp/relay.yaml`
  3. No file → use defaults (don't crash)

  ## Supported Duration Strings

  Human-readable durations are converted to milliseconds:
  - `"300s"` → 300_000
  - `"5m"` → 300_000
  - `"1h"` → 3_600_000
  - `"100ms"` → 100
  - Plain integers are treated as raw values (milliseconds for timeout fields)
  """

  require Logger

  @default_path "/etc/ztlp/relay.yaml"

  @doc """
  Load and apply YAML configuration.

  Called from Application.start/2 before the supervision tree starts.
  Returns :ok on success, {:error, reasons} on validation failure.
  """
  @spec load_and_apply() :: :ok | {:error, [String.t()]}
  def load_and_apply do
    path = config_path()

    case read_config(path) do
      {:ok, raw_map} ->
        case validate(raw_map) do
          {:ok, config} ->
            apply_to_app_env(config)
            Logger.info("[ztlp-relay] Config loaded from #{path}")
            :ok

          {:error, errors} ->
            Logger.error("[ztlp-relay] Config validation failed:\n" <>
              Enum.map_join(errors, "\n", &("  - " <> &1)))
            {:error, errors}
        end

      {:ok, :empty} ->
        Logger.info("[ztlp-relay] Config file empty or not found, using defaults")
        :ok

      {:error, :not_found} ->
        Logger.info("[ztlp-relay] No config file found (checked #{path}), using defaults")
        :ok

      {:error, reason} ->
        Logger.error("[ztlp-relay] Failed to read config #{path}: #{inspect(reason)}")
        {:error, ["Failed to read config file: #{inspect(reason)}"]}
    end
  end

  @doc """
  Load config from a specific path (for testing).
  """
  @spec load(String.t()) :: {:ok, map()} | {:error, [String.t()]}
  def load(path) do
    case read_config(path) do
      {:ok, raw_map} -> validate(raw_map)
      {:ok, :empty} -> {:ok, %{}}
      {:error, reason} -> {:error, ["Failed to read config: #{inspect(reason)}"]}
    end
  end

  @doc """
  Validate a raw config map against the relay schema.
  Returns {:ok, validated_config} or {:error, [error_messages]}.
  """
  @spec validate(map()) :: {:ok, map()} | {:error, [String.t()]}
  def validate(raw) when is_map(raw) do
    errors = []
    config = %{}

    # Top-level fields
    {config, errors} = validate_field(config, errors, raw, "port", :port, :integer, 23095, 1..65535)
    {config, errors} = validate_field(config, errors, raw, "address", :listen_address, :ip_address, {0, 0, 0, 0}, nil)
    {config, errors} = validate_field(config, errors, raw, "session_timeout", :session_timeout_ms, :duration, 300_000, nil)
    {config, errors} = validate_field(config, errors, raw, "max_sessions", :max_sessions, :integer, 10_000, 1..1_000_000)

    # Mesh section
    {config, errors} = case Map.get(raw, "mesh", %{}) do
      mesh when is_map(mesh) ->
        {config, errors} = validate_field(config, errors, mesh, "enabled", :mesh_enabled, :boolean, false, nil)
        {config, errors} = validate_field(config, errors, mesh, "port", :mesh_listen_port, :integer, 23096, 1..65535)
        {config, errors} = validate_field(config, errors, mesh, "bootstrap", :mesh_bootstrap_relays, :string_list, [], nil)
        {config, errors} = validate_field(config, errors, mesh, "node_id", :relay_node_id, :hex_bytes, nil, 16)
        {config, errors} = validate_field(config, errors, mesh, "role", :relay_role, :enum, :all, [:ingress, :transit, :service, :all])
        {config, errors} = validate_field(config, errors, mesh, "vnodes", :hash_ring_vnodes, :integer, 128, 1..1024)
        {config, errors} = validate_field(config, errors, mesh, "ping_interval", :ping_interval_ms, :duration, 15_000, nil)
        validate_field(config, errors, mesh, "relay_timeout", :relay_timeout_ms, :duration, 300_000, nil)
      nil -> {config, errors}
      other -> {config, ["mesh: expected a map, got: #{inspect(other)}" | errors]}
    end

    # Admission section
    {config, errors} = case Map.get(raw, "admission", %{}) do
      admission when is_map(admission) ->
        {config, errors} = validate_field(config, errors, admission, "rat_secret", :rat_secret, :hex_bytes, nil, 32)
        {config, errors} = validate_field(config, errors, admission, "rat_secret_previous", :rat_secret_previous, :hex_bytes, nil, 32)
        {config, errors} = validate_field(config, errors, admission, "rat_ttl", :rat_ttl_seconds, :duration_seconds, 300, nil)
        {config, errors} = validate_field(config, errors, admission, "sac_load_threshold", :sac_load_threshold, :float, 0.7, {0.0, 1.0})

        case Map.get(admission, "rate_limit", %{}) do
          rl when is_map(rl) ->
            {config, errors} = validate_field(config, errors, rl, "per_ip", :ingress_rate_limit_per_ip, :integer, 10, 1..10_000)
            validate_field(config, errors, rl, "per_node", :ingress_rate_limit_per_node, :integer, 5, 1..10_000)
          nil -> {config, errors}
          other -> {config, ["admission.rate_limit: expected a map, got: #{inspect(other)}" | errors]}
        end
      nil -> {config, errors}
      other -> {config, ["admission: expected a map, got: #{inspect(other)}" | errors]}
    end

    # Backpressure section
    {config, errors} = case Map.get(raw, "backpressure", %{}) do
      bp when is_map(bp) ->
        {config, errors} = validate_field(config, errors, bp, "soft_threshold", :backpressure_soft_threshold, :float, 0.8, {0.0, 1.0})
        validate_field(config, errors, bp, "hard_threshold", :backpressure_hard_threshold, :float, 0.95, {0.0, 1.0})
      nil -> {config, errors}
      other -> {config, ["backpressure: expected a map, got: #{inspect(other)}" | errors]}
    end

    # NS Discovery section
    {config, errors} = case Map.get(raw, "ns_discovery", %{}) do
      ns when is_map(ns) ->
        {config, errors} = validate_field(config, errors, ns, "server", :ns_server, :host_port, nil, nil)
        {config, errors} = validate_field(config, errors, ns, "zone", :ns_discovery_zone, :string, "relay.ztlp", nil)
        {config, errors} = validate_field(config, errors, ns, "refresh_interval", :ns_refresh_interval_ms, :duration, 60_000, nil)
        validate_field(config, errors, ns, "region", :relay_region, :string, "default", nil)
      nil -> {config, errors}
      other -> {config, ["ns_discovery: expected a map, got: #{inspect(other)}" | errors]}
    end

    case errors do
      [] -> {:ok, config}
      _ -> {:error, Enum.reverse(errors)}
    end
  end

  @doc """
  Apply validated config to the OTP application environment.
  """
  @spec apply_to_app_env(map()) :: :ok
  def apply_to_app_env(config) do
    Enum.each(config, fn {key, value} ->
      # Map port -> listen_port for the existing Config module
      app_key = case key do
        :port -> :listen_port
        other -> other
      end
      Application.put_env(:ztlp_relay, app_key, value)
    end)
  end

  # ── Internal ──────────────────────────────────────────────────────────

  defp config_path do
    System.get_env("ZTLP_RELAY_CONFIG") || @default_path
  end

  defp read_config(path) do
    case File.read(path) do
      {:ok, ""} -> {:ok, :empty}
      {:ok, content} -> parse_yaml(content)
      {:error, :enoent} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc false
  def parse_yaml(content) do
    case ZtlpRelay.YamlParser.parse(content) do
      {:ok, result} when is_map(result) -> {:ok, result}
      {:ok, nil} -> {:ok, :empty}
      {:ok, _other} -> {:error, "YAML root must be a mapping"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_field(config, errors, source, yaml_key, config_key, type, default, constraint) do
    case Map.get(source, yaml_key) do
      nil ->
        if default != nil do
          {Map.put(config, config_key, default), errors}
        else
          {config, errors}
        end

      value ->
        case coerce_and_validate(value, type, constraint, yaml_key) do
          {:ok, coerced} -> {Map.put(config, config_key, coerced), errors}
          {:error, msg} -> {config, [msg | errors]}
        end
    end
  end

  defp coerce_and_validate(value, :integer, range, key) do
    case to_integer(value) do
      {:ok, n} ->
        if range && n not in range do
          {:error, "#{key}: must be between #{range.first} and #{range.last}, got: #{n}"}
        else
          {:ok, n}
        end
      :error -> {:error, "#{key}: expected an integer, got: #{inspect(value)}"}
    end
  end

  defp coerce_and_validate(value, :float, {min, max}, key) do
    case to_float(value) do
      {:ok, f} ->
        if f < min or f > max do
          {:error, "#{key}: must be between #{min} and #{max}, got: #{f}"}
        else
          {:ok, f}
        end
      :error -> {:error, "#{key}: expected a number, got: #{inspect(value)}"}
    end
  end

  defp coerce_and_validate(value, :boolean, _constraint, key) do
    case value do
      v when v in [true, false] -> {:ok, v}
      "true" -> {:ok, true}
      "false" -> {:ok, false}
      _ -> {:error, "#{key}: expected true or false, got: #{inspect(value)}"}
    end
  end

  defp coerce_and_validate(value, :string, _constraint, _key) when is_binary(value), do: {:ok, value}
  defp coerce_and_validate(value, :string, _constraint, key),
    do: {:error, "#{key}: expected a string, got: #{inspect(value)}"}

  defp coerce_and_validate(value, :string_list, _constraint, key) do
    cond do
      is_list(value) ->
        if Enum.all?(value, &is_binary/1) do
          {:ok, value}
        else
          {:error, "#{key}: expected a list of strings, got: #{inspect(value)}"}
        end
      true ->
        {:error, "#{key}: expected a list, got: #{inspect(value)}"}
    end
  end

  defp coerce_and_validate(value, :duration, _constraint, key) do
    case parse_duration_ms(value) do
      {:ok, ms} -> {:ok, ms}
      :error -> {:error, "#{key}: invalid duration '#{inspect(value)}', expected e.g. '300s', '5m', '1h', or integer milliseconds"}
    end
  end

  defp coerce_and_validate(value, :duration_seconds, _constraint, key) do
    case parse_duration_ms(value) do
      {:ok, ms} -> {:ok, div(ms, 1000)}
      :error ->
        case to_integer(value) do
          {:ok, n} -> {:ok, n}
          :error -> {:error, "#{key}: invalid duration '#{inspect(value)}', expected e.g. '300s', '5m', or integer seconds"}
        end
    end
  end

  defp coerce_and_validate(value, :ip_address, _constraint, key) when is_binary(value) do
    case :inet.parse_address(String.to_charlist(value)) do
      {:ok, addr} -> {:ok, addr}
      {:error, _} -> {:error, "#{key}: invalid IP address '#{value}'"}
    end
  end
  defp coerce_and_validate(value, :ip_address, _constraint, _key) when is_tuple(value), do: {:ok, value}
  defp coerce_and_validate(value, :ip_address, _constraint, key),
    do: {:error, "#{key}: expected an IP address string, got: #{inspect(value)}"}

  defp coerce_and_validate(value, :hex_bytes, byte_size, key) when is_binary(value) do
    case Base.decode16(value, case: :mixed) do
      {:ok, bytes} when byte_size(bytes) == byte_size -> {:ok, bytes}
      {:ok, bytes} ->
        {:error, "#{key}: expected #{byte_size} bytes (#{byte_size * 2} hex chars), got #{byte_size(bytes)} bytes"}
      :error -> {:error, "#{key}: invalid hex string '#{value}'"}
    end
  end
  defp coerce_and_validate(nil, :hex_bytes, _size, _key), do: {:ok, nil}
  defp coerce_and_validate(value, :hex_bytes, _size, key),
    do: {:error, "#{key}: expected a hex string, got: #{inspect(value)}"}

  defp coerce_and_validate(value, :host_port, _constraint, key) when is_binary(value) do
    case String.split(value, ":") do
      [host, port_str] ->
        case Integer.parse(port_str) do
          {port, ""} when port > 0 and port <= 65535 -> {:ok, {host, port}}
          _ -> {:error, "#{key}: invalid port in '#{value}'"}
        end
      _ -> {:error, "#{key}: expected 'host:port', got: '#{value}'"}
    end
  end
  defp coerce_and_validate(nil, :host_port, _constraint, _key), do: {:ok, nil}
  defp coerce_and_validate(value, :host_port, _constraint, key),
    do: {:error, "#{key}: expected 'host:port' string, got: #{inspect(value)}"}

  defp coerce_and_validate(value, :enum, allowed, key) when is_binary(value) do
    atom = String.to_atom(value)
    if atom in allowed do
      {:ok, atom}
    else
      {:error, "#{key}: must be one of #{inspect(allowed)}, got: '#{value}'"}
    end
  end
  defp coerce_and_validate(value, :enum, allowed, key) when is_atom(value) do
    if value in allowed do
      {:ok, value}
    else
      {:error, "#{key}: must be one of #{inspect(allowed)}, got: #{inspect(value)}"}
    end
  end
  defp coerce_and_validate(value, :enum, _allowed, key),
    do: {:error, "#{key}: expected a string, got: #{inspect(value)}"}

  # ── Duration parsing ──────────────────────────────────────────────────

  @doc false
  def parse_duration_ms(value) when is_integer(value) and value >= 0, do: {:ok, value}
  def parse_duration_ms(value) when is_binary(value) do
    case Regex.run(~r/^(\d+)(ms|s|m|h)$/, value) do
      [_, num_str, unit] ->
        case Integer.parse(num_str) do
          {n, ""} ->
            ms = case unit do
              "ms" -> n
              "s" -> n * 1_000
              "m" -> n * 60_000
              "h" -> n * 3_600_000
            end
            {:ok, ms}
          _ -> :error
        end
      nil ->
        # Try as plain integer string
        case Integer.parse(value) do
          {n, ""} when n >= 0 -> {:ok, n}
          _ -> :error
        end
    end
  end
  def parse_duration_ms(_), do: :error

  # ── Number coercion ───────────────────────────────────────────────────

  defp to_integer(n) when is_integer(n), do: {:ok, n}
  defp to_integer(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} -> {:ok, n}
      _ -> :error
    end
  end
  defp to_integer(_), do: :error

  defp to_float(f) when is_float(f), do: {:ok, f}
  defp to_float(n) when is_integer(n), do: {:ok, n / 1}
  defp to_float(s) when is_binary(s) do
    case Float.parse(s) do
      {f, ""} -> {:ok, f}
      _ -> :error
    end
  end
  defp to_float(_), do: :error
end
