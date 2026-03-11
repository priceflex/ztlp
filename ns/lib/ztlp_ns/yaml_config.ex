defmodule ZtlpNs.YamlConfig do
  @moduledoc """
  YAML configuration loader and validator for ZTLP-NS.

  Reads a YAML config file, validates it against the NS schema,
  and writes validated values to the OTP application environment.

  ## Config File Resolution

  1. `ZTLP_NS_CONFIG` environment variable
  2. `/etc/ztlp/ns.yaml`
  3. No file → use defaults (don't crash)
  """

  require Logger

  @default_path "/etc/ztlp/ns.yaml"

  @spec load_and_apply() :: :ok | {:error, [String.t()]}
  def load_and_apply do
    path = config_path()

    case read_config(path) do
      {:ok, raw_map} ->
        case validate(raw_map) do
          {:ok, config} ->
            apply_to_app_env(config)
            Logger.info("[ztlp-ns] Config loaded from #{path}")
            :ok

          {:error, errors} ->
            Logger.error("[ztlp-ns] Config validation failed:\n" <>
              Enum.map_join(errors, "\n", &("  - " <> &1)))
            {:error, errors}
        end

      {:ok, :empty} ->
        Logger.info("[ztlp-ns] Config file empty or not found, using defaults")
        :ok

      {:error, :not_found} ->
        Logger.info("[ztlp-ns] No config file found (checked #{path}), using defaults")
        :ok

      {:error, reason} ->
        Logger.error("[ztlp-ns] Failed to read config #{path}: #{inspect(reason)}")
        {:error, ["Failed to read config file: #{inspect(reason)}"]}
    end
  end

  @spec load(String.t()) :: {:ok, map()} | {:error, [String.t()]}
  def load(path) do
    case read_config(path) do
      {:ok, raw_map} -> validate(raw_map)
      {:ok, :empty} -> {:ok, %{}}
      {:error, reason} -> {:error, ["Failed to read config: #{inspect(reason)}"]}
    end
  end

  @spec validate(map()) :: {:ok, map()} | {:error, [String.t()]}
  def validate(raw) when is_map(raw) do
    errors = []
    config = %{}

    {config, errors} = validate_field(config, errors, raw, "port", :port, :integer, 23096, 1..65535)
    {config, errors} = validate_field(config, errors, raw, "max_records", :max_records, :integer, 100_000, 1..10_000_000)

    {config, errors} = case Map.get(raw, "storage_mode") do
      nil -> {Map.put(config, :storage_mode, :disc_copies), errors}
      "disc" -> {Map.put(config, :storage_mode, :disc_copies), errors}
      "ram" -> {Map.put(config, :storage_mode, :ram_copies), errors}
      other -> {config, ["storage_mode: must be 'disc' or 'ram', got: '#{other}'" | errors]}
    end

    {config, errors} = case Map.get(raw, "mnesia_dir") do
      nil -> {config, errors}
      dir when is_binary(dir) -> {Map.put(config, :mnesia_dir, String.to_charlist(dir)), errors}
      other -> {config, ["mnesia_dir: expected a string, got: #{inspect(other)}" | errors]}
    end

    {config, errors} = case Map.get(raw, "bootstrap_urls") do
      nil -> {Map.put(config, :bootstrap_urls, ["https://bootstrap.ztlp.org/.well-known/ztlp-relays.json"]), errors}
      urls when is_list(urls) ->
        if Enum.all?(urls, &is_binary/1) do
          {Map.put(config, :bootstrap_urls, urls), errors}
        else
          {config, ["bootstrap_urls: expected a list of strings" | errors]}
        end
      other -> {config, ["bootstrap_urls: expected a list, got: #{inspect(other)}" | errors]}
    end

    # Rate limit section
    {config, errors} = case Map.get(raw, "rate_limit", %{}) do
      rl when is_map(rl) ->
        {config, errors} = validate_field(config, errors, rl, "queries_per_second", :rate_limit_queries_per_second, :integer, 100, 1..1_000_000)
        validate_field(config, errors, rl, "burst", :rate_limit_burst, :integer, 200, 1..10_000_000)
      nil -> {config, errors}
      other -> {config, ["rate_limit: expected a map, got: #{inspect(other)}" | errors]}
    end

    case errors do
      [] -> {:ok, config}
      _ -> {:error, Enum.reverse(errors)}
    end
  end

  @spec apply_to_app_env(map()) :: :ok
  def apply_to_app_env(config) do
    Enum.each(config, fn {key, value} ->
      Application.put_env(:ztlp_ns, key, value)
    end)
  end

  # ── Internal ──────────────────────────────────────────────────────────

  defp config_path do
    System.get_env("ZTLP_NS_CONFIG") || @default_path
  end

  defp read_config(path) do
    case File.read(path) do
      {:ok, ""} -> {:ok, :empty}
      {:ok, content} ->
        case ZtlpNs.YamlParser.parse(content) do
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

  defp to_int(n) when is_integer(n), do: {:ok, n}
  defp to_int(s) when is_binary(s) do
    case Integer.parse(s) do
      {n, ""} -> {:ok, n}
      _ -> :error
    end
  end
  defp to_int(_), do: :error
end
