defmodule ZtlpGateway.YamlConfig do
  @moduledoc """
  YAML configuration loader and validator for the ZTLP Gateway.

  Reads a YAML config file, validates it against the gateway schema,
  and writes validated values to the OTP application environment
  so the existing `ZtlpGateway.Config` module picks them up seamlessly.

  ## Config File Resolution

  1. `ZTLP_GATEWAY_CONFIG` environment variable
  2. `/etc/ztlp/gateway.yaml`
  3. No file → use defaults (don't crash)
  """

  require Logger

  @default_path "/etc/ztlp/gateway.yaml"

  @spec load_and_apply() :: :ok | {:error, [String.t()]}
  def load_and_apply do
    path = config_path()

    case read_config(path) do
      {:ok, :empty} ->
        Logger.info("[ztlp-gateway] Config file empty or not found, using defaults")
        :ok

      {:ok, raw_map} ->
        case validate(raw_map) do
          {:ok, config} ->
            apply_to_app_env(config)
            Logger.info("[ztlp-gateway] Config loaded from #{path}")
            :ok

          {:error, errors} ->
            Logger.error("[ztlp-gateway] Config validation failed:\n" <>
              Enum.map_join(errors, "\n", &("  - " <> &1)))
            {:error, errors}
        end

      {:error, :not_found} ->
        Logger.info("[ztlp-gateway] No config file found (checked #{path}), using defaults")
        :ok

      {:error, reason} ->
        Logger.error("[ztlp-gateway] Failed to read config #{path}: #{inspect(reason)}")
        {:error, ["Failed to read config file: #{inspect(reason)}"]}
    end
  end

  @spec load(String.t()) :: {:ok, map()} | {:error, [String.t()]}
  def load(path) do
    case read_config(path) do
      {:ok, :empty} -> {:ok, %{}}
      {:ok, raw_map} -> validate(raw_map)
      {:error, reason} -> {:error, ["Failed to read config: #{inspect(reason)}"]}
    end
  end

  @spec validate(map()) :: {:ok, map()} | {:error, [String.t()]}
  def validate(raw) when is_map(raw) do
    errors = []
    config = %{}

    {config, errors} = validate_field(config, errors, raw, "port", :port, :integer, 23097, 1..65535)
    {config, errors} = validate_field(config, errors, raw, "session_timeout", :session_timeout_ms, :duration, 300_000, nil)
    {config, errors} = validate_field(config, errors, raw, "max_sessions", :max_sessions, :integer, 10_000, 1..1_000_000)

    # NS section
    {config, errors} = case Map.get(raw, "ns", %{}) do
      ns when is_map(ns) ->
        {config, errors} = validate_field(config, errors, ns, "host", :ns_server_host, :ip_address, {127, 0, 0, 1}, nil)
        {config, errors} = validate_field(config, errors, ns, "port", :ns_server_port, :integer, 23096, 1..65535)
        validate_field(config, errors, ns, "query_timeout", :ns_query_timeout_ms, :duration, 2_000, nil)
      nil -> {config, errors}
      other -> {config, ["ns: expected a map, got: #{inspect(other)}" | errors]}
    end

    # Backends section (list of maps)
    {config, errors} = case Map.get(raw, "backends", []) do
      backends when is_list(backends) ->
        validated_backends = Enum.map(backends, fn b ->
          case b do
            b when is_map(b) ->
              %{
                name: Map.get(b, "name", "default"),
                host: Map.get(b, "host", "127.0.0.1"),
                port: Map.get(b, "port", 8080)
              }
            _ -> b
          end
        end)
        {Map.put(config, :backends, validated_backends), errors}
      other -> {config, ["backends: expected a list, got: #{inspect(other)}" | errors]}
    end

    # Policies section (list of maps)
    {config, errors} = case Map.get(raw, "policies", []) do
      policies when is_list(policies) ->
        validated_policies = Enum.map(policies, fn p ->
          case p do
            p when is_map(p) ->
              %{
                zone: Map.get(p, "zone", "*"),
                action: String.to_atom(Map.get(p, "action", "allow")),
                backends: Map.get(p, "backends", [])
              }
            _ -> p
          end
        end)
        {Map.put(config, :policies, validated_policies), errors}
      other -> {config, ["policies: expected a list, got: #{inspect(other)}" | errors]}
    end

    # Circuit breaker section
    {config, errors} = case Map.get(raw, "circuit_breaker", %{}) do
      cb when is_map(cb) ->
        {config, errors} = validate_field(config, errors, cb, "enabled", :circuit_breaker_enabled, :boolean, true, nil)
        {config, errors} = validate_field(config, errors, cb, "failure_threshold", :circuit_breaker_failure_threshold, :integer, 5, 1..1000)
        validate_field(config, errors, cb, "cooldown", :circuit_breaker_cooldown_ms, :duration, 30_000, nil)
      nil -> {config, errors}
      other -> {config, ["circuit_breaker: expected a map, got: #{inspect(other)}" | errors]}
    end

    # TLS section
    {config, errors} = case Map.get(raw, "tls", %{}) do
      tls when is_map(tls) ->
        {config, errors} = validate_field(config, errors, tls, "enabled", :tls_enabled, :boolean, false, nil)
        {config, errors} = validate_field(config, errors, tls, "cert_file", :tls_cert_file, :string, nil, nil)
        {config, errors} = validate_field(config, errors, tls, "key_file", :tls_key_file, :string, nil, nil)
        validate_field(config, errors, tls, "ca_cert_file", :tls_ca_cert_file, :string, nil, nil)
      nil -> {config, errors}
      other -> {config, ["tls: expected a map, got: #{inspect(other)}" | errors]}
    end

    # Component auth section
    {config, errors} = case Map.get(raw, "component_auth", %{}) do
      ca when is_map(ca) ->
        {config, errors} = validate_field(config, errors, ca, "enabled", :component_auth_enabled, :boolean, false, nil)
        {config, errors} = validate_field(config, errors, ca, "identity_key_file", :component_auth_identity_key_file, :string, nil, nil)
        case Map.get(ca, "allowed_keys") do
          nil -> {config, errors}
          keys when is_list(keys) ->
            case ZtlpGateway.ComponentAuth.parse_allowed_keys(keys) do
              {:ok, parsed} -> {Map.put(config, :component_auth_allowed_keys, parsed), errors}
              {:error, msg} -> {config, ["component_auth.allowed_keys: #{msg}" | errors]}
            end
          other -> {config, ["component_auth.allowed_keys: expected a list, got: #{inspect(other)}" | errors]}
        end
      nil -> {config, errors}
      other -> {config, ["component_auth: expected a map, got: #{inspect(other)}" | errors]}
    end

    case errors do
      [] -> {:ok, config}
      _ -> {:error, Enum.reverse(errors)}
    end
  end

  @spec apply_to_app_env(map()) :: :ok
  def apply_to_app_env(config) do
    Enum.each(config, fn {key, value} ->
      Application.put_env(:ztlp_gateway, key, value)
    end)
  end

  # ── Internal ──────────────────────────────────────────────────────────

  defp config_path do
    System.get_env("ZTLP_GATEWAY_CONFIG") || @default_path
  end

  defp read_config(path) do
    case File.read(path) do
      {:ok, ""} -> {:ok, :empty}
      {:ok, content} ->
        case ZtlpGateway.YamlParser.parse(content) do
          {:ok, result} when is_map(result) -> {:ok, result}
          {:ok, nil} -> {:ok, :empty}
          {:ok, _} -> {:error, "YAML root must be a mapping"}
          {:error, reason} -> {:error, reason}
        end
      {:error, :enoent} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_field(config, errors, source, yaml_key, config_key, type, default, constraint) do
    case Map.get(source, yaml_key) do
      nil ->
        if default != nil, do: {Map.put(config, config_key, default), errors}, else: {config, errors}
      value ->
        case coerce(value, type, constraint, yaml_key) do
          {:ok, v} -> {Map.put(config, config_key, v), errors}
          {:error, msg} -> {config, [msg | errors]}
        end
    end
  end

  defp coerce(value, :integer, range, key) do
    case to_int(value) do
      {:ok, n} ->
        if range && n not in range,
          do: {:error, "#{key}: must be between #{range.first} and #{range.last}, got: #{n}"},
          else: {:ok, n}
      :error -> {:error, "#{key}: expected an integer, got: #{inspect(value)}"}
    end
  end

  defp coerce(value, :boolean, _c, key) do
    case value do
      v when v in [true, false] -> {:ok, v}
      "true" -> {:ok, true}
      "false" -> {:ok, false}
      _ -> {:error, "#{key}: expected true or false, got: #{inspect(value)}"}
    end
  end

  defp coerce(value, :duration, _c, key) do
    case parse_duration_ms(value) do
      {:ok, ms} -> {:ok, ms}
      :error -> {:error, "#{key}: invalid duration '#{inspect(value)}', expected e.g. '300s', '5m', '1h'"}
    end
  end

  defp coerce(value, :ip_address, _c, key) when is_binary(value) do
    case :inet.parse_address(String.to_charlist(value)) do
      {:ok, addr} -> {:ok, addr}
      {:error, _} -> {:error, "#{key}: invalid IP address '#{value}'"}
    end
  end
  defp coerce(value, :ip_address, _c, _key) when is_tuple(value), do: {:ok, value}
  defp coerce(value, :ip_address, _c, key),
    do: {:error, "#{key}: expected an IP address string, got: #{inspect(value)}"}

  defp parse_duration_ms(value) when is_integer(value) and value >= 0, do: {:ok, value}
  defp parse_duration_ms(value) when is_binary(value) do
    case Regex.run(~r/^(\d+)(ms|s|m|h)$/, value) do
      [_, n, "ms"] -> {:ok, String.to_integer(n)}
      [_, n, "s"] -> {:ok, String.to_integer(n) * 1_000}
      [_, n, "m"] -> {:ok, String.to_integer(n) * 60_000}
      [_, n, "h"] -> {:ok, String.to_integer(n) * 3_600_000}
      nil ->
        case Integer.parse(value) do
          {n, ""} when n >= 0 -> {:ok, n}
          _ -> :error
        end
    end
  end
  defp parse_duration_ms(_), do: :error

  defp to_int(n) when is_integer(n), do: {:ok, n}
  defp to_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} -> {:ok, n}
      _ -> :error
    end
  end
  defp to_int(_), do: :error
end
