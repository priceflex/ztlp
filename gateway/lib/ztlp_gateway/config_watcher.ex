defmodule ZtlpGateway.ConfigWatcher do
  @moduledoc """
  Configuration hot-reload watcher for the ZTLP Gateway.

  A GenServer that monitors a YAML config file for changes and applies
  updates to the running gateway without requiring a restart.

  ## How It Works

  1. **Polling** — checks the file's mtime every 30 seconds; if mtime
     changed, reads the file and compares a SHA-256 hash to avoid
     spurious reloads (e.g. `touch` without content change).

  2. **SIGHUP** — send `{:signal, :sighup}` to trigger an immediate
     reload outside the poll cycle.

  3. **Diff & Apply** — computes a key-level diff between the previous
     and new parsed config, writes changed keys to the OTP application
     environment via `Application.put_env/3`, and emits an audit event.

  ## Config File Resolution

  - `ZTLP_GATEWAY_CONFIG_PATH` env var, or
  - `/etc/ztlp/gateway.yaml` (default)

  Uses `ZtlpGateway.YamlParser` for parsing and
  `ZtlpGateway.YamlConfig.validate/1` + `apply_to_app_env/1` for
  validation and application — the same path used at startup.
  """

  use GenServer
  require Logger

  @poll_interval_ms 30_000
  @default_config_path "/etc/ztlp/gateway.yaml"

  defstruct [
    :config_path,
    :last_hash,
    :last_mtime,
    :current_config,
    :poll_timer
  ]

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the ConfigWatcher."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: opts[:name] || __MODULE__)
  end

  @doc """
  Force a config reload.

  Returns `{:ok, changes}` where `changes` is a list of
  `{key, old_value, new_value}` tuples, or `{:error, reason}`.
  """
  @spec reload() :: {:ok, list()} | {:error, term()}
  def reload do
    GenServer.call(__MODULE__, :reload)
  end

  @doc "Get the current parsed config map."
  @spec current_config() :: map()
  def current_config do
    GenServer.call(__MODULE__, :current_config)
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(opts) do
    config_path = Keyword.get(opts, :config_path, resolve_config_path())
    poll_interval = Keyword.get(opts, :poll_interval_ms, @poll_interval_ms)

    state = %__MODULE__{
      config_path: config_path,
      last_hash: nil,
      last_mtime: nil,
      current_config: %{},
      poll_timer: nil
    }

    # Try initial load and apply — don't crash if file is missing
    state =
      case load_and_apply(state) do
        {:ok, new_state, _changes} -> new_state
        {:error, _reason} ->
          # Fall back to just loading without validation
          case load_config(state) do
            {:ok, new_state} -> new_state
            {:error, _reason} -> state
          end
      end

    # Schedule polling
    timer = Process.send_after(self(), :poll, poll_interval)
    # Store interval for re-scheduling
    Process.put(:poll_interval_ms, poll_interval)
    {:ok, %{state | poll_timer: timer}}
  end

  @impl true
  def handle_call(:reload, _from, state) do
    case load_and_apply(state) do
      {:ok, new_state, changes} ->
        {:reply, {:ok, changes}, new_state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:current_config, _from, state) do
    {:reply, state.current_config, state}
  end

  @impl true
  def handle_info(:poll, state) do
    poll_interval = Process.get(:poll_interval_ms, @poll_interval_ms)

    state =
      case check_for_changes(state) do
        {:changed, new_state} -> new_state
        :unchanged -> state
      end

    timer = Process.send_after(self(), :poll, poll_interval)
    {:noreply, %{state | poll_timer: timer}}
  end

  # SIGHUP handler — allows manual reload via signal
  def handle_info({:signal, :sighup}, state) do
    Logger.info("[ConfigWatcher] SIGHUP received, reloading config")

    case load_and_apply(state) do
      {:ok, new_state, _changes} -> {:noreply, new_state}
      {:error, _reason} -> {:noreply, state}
    end
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ---------------------------------------------------------------------------
  # Internal — change detection
  # ---------------------------------------------------------------------------

  defp resolve_config_path do
    System.get_env("ZTLP_GATEWAY_CONFIG_PATH") || @default_config_path
  end

  defp check_for_changes(state) do
    case File.stat(state.config_path) do
      {:ok, %File.Stat{mtime: mtime}} when mtime != state.last_mtime ->
        case load_and_apply(state) do
          {:ok, new_state, _changes} -> {:changed, new_state}
          {:error, _reason} -> :unchanged
        end

      _ ->
        :unchanged
    end
  end

  # ---------------------------------------------------------------------------
  # Internal — load, validate, diff, apply
  # ---------------------------------------------------------------------------

  defp load_config(state) do
    case File.read(state.config_path) do
      {:ok, content} ->
        hash = :crypto.hash(:sha256, content)
        mtime = file_mtime(state.config_path)

        case ZtlpGateway.YamlParser.parse(content) do
          {:ok, parsed} when is_map(parsed) ->
            {:ok, %{state | current_config: parsed, last_hash: hash, last_mtime: mtime}}

          {:ok, nil} ->
            {:ok, %{state | current_config: %{}, last_hash: hash, last_mtime: mtime}}

          {:ok, _other} ->
            Logger.warning("[ConfigWatcher] Config root is not a mapping, ignoring")
            {:error, :invalid_format}

          {:error, reason} ->
            Logger.warning("[ConfigWatcher] YAML parse error: #{inspect(reason)}")
            {:error, reason}
        end

      {:error, reason} ->
        Logger.debug("[ConfigWatcher] Config file not readable: #{state.config_path} (#{reason})")
        {:error, reason}
    end
  end

  defp load_and_apply(state) do
    case File.read(state.config_path) do
      {:ok, content} ->
        new_hash = :crypto.hash(:sha256, content)

        # Skip if content hash unchanged (mtime changed but content didn't)
        if new_hash == state.last_hash do
          mtime = file_mtime(state.config_path)
          {:ok, %{state | last_mtime: mtime}, []}
        else
          case ZtlpGateway.YamlParser.parse(content) do
            {:ok, parsed} when is_map(parsed) ->
              # Validate through the same pipeline used at startup
              case ZtlpGateway.YamlConfig.validate(parsed) do
                {:ok, validated_config} ->
                  changes = diff_config(state.current_config, parsed)
                  mtime = file_mtime(state.config_path)

                  if changes != [] do
                    ZtlpGateway.YamlConfig.apply_to_app_env(validated_config)
                    Logger.info("[ConfigWatcher] Config reloaded, #{length(changes)} change(s)")
                    log_audit_event(changes)
                  end

                  new_state = %{state |
                    current_config: parsed,
                    last_hash: new_hash,
                    last_mtime: mtime
                  }

                  {:ok, new_state, changes}

                {:error, errors} ->
                  Logger.warning("[ConfigWatcher] Config validation failed: #{inspect(errors)}")
                  {:error, {:validation_failed, errors}}
              end

            {:ok, nil} ->
              mtime = file_mtime(state.config_path)
              {:ok, %{state | current_config: %{}, last_hash: new_hash, last_mtime: mtime}, []}

            {:ok, _other} ->
              {:error, :invalid_format}

            {:error, reason} ->
              {:error, reason}
          end
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc false
  @spec diff_config(map(), map()) :: [{String.t(), term(), term()}]
  def diff_config(old, new) when is_map(old) and is_map(new) do
    all_keys =
      (Map.keys(old) ++ Map.keys(new))
      |> Enum.uniq()

    Enum.flat_map(all_keys, fn key ->
      old_val = Map.get(old, key)
      new_val = Map.get(new, key)

      if old_val != new_val do
        [{key, old_val, new_val}]
      else
        []
      end
    end)
  end

  defp log_audit_event(changes) do
    if Code.ensure_loaded?(ZtlpGateway.AuditCollector) and
         function_exported?(ZtlpGateway.AuditCollector, :log_event, 1) do
      change_summary =
        Enum.map(changes, fn {key, _old, _new} -> to_string(key) end)

      ZtlpGateway.AuditCollector.log_event(%{
        event: "config.reloaded",
        component: "gateway",
        level: "info",
        details: %{
          changes_count: length(changes),
          changed_keys: change_summary
        }
      })
    end
  rescue
    # Don't let audit failures break config reload
    _ -> :ok
  end

  defp file_mtime(path) do
    case File.stat(path) do
      {:ok, %File.Stat{mtime: mtime}} -> mtime
      _ -> nil
    end
  end
end
