defmodule ZtlpGateway.CertCache do
  @moduledoc """
  Certificate cache for the ZTLP Gateway TLS listener.

  Caches TLS certificates for SNI-based routing. Each hostname
  can have its own certificate, and the cache handles:
  - Certificate storage (PEM/DER)
  - Expiry tracking
  - Auto-refresh when certificates near expiry
  - Thread-safe concurrent access via ETS
  """

  use GenServer
  require Logger

  @table :ztlp_cert_cache
  @refresh_interval_ms 3_600_000  # 1 hour

  # ── Public API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get a cached certificate for a hostname.

  Returns `{:ok, %{certfile: path, keyfile: path}}` or `{:error, :not_found}`.
  """
  @spec get(String.t()) :: {:ok, map()} | {:error, :not_found}
  def get(hostname) do
    case :ets.lookup(@table, hostname) do
      [{^hostname, entry}] ->
        if expired?(entry) do
          {:error, :expired}
        else
          {:ok, entry}
        end
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Cache a certificate for a hostname.
  """
  @spec put(String.t(), map()) :: :ok
  def put(hostname, cert_info) do
    entry = Map.merge(cert_info, %{
      cached_at: System.system_time(:second),
      expires_at: Map.get(cert_info, :expires_at, System.system_time(:second) + 86400)
    })
    :ets.insert(@table, {hostname, entry})
    :ok
  end

  @doc "Remove a cached certificate."
  @spec delete(String.t()) :: :ok
  def delete(hostname) do
    :ets.delete(@table, hostname)
    :ok
  end

  @doc "List all cached certificates."
  @spec list() :: [{String.t(), map()}]
  def list do
    :ets.tab2list(@table)
  end

  @doc "Clear all cached certificates."
  @spec clear() :: :ok
  def clear do
    :ets.delete_all_objects(@table)
    :ok
  end

  # ── GenServer ──────────────────────────────────────────────────────

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    schedule_refresh()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_info(:refresh, state) do
    now = System.system_time(:second)
    # Remove expired entries
    :ets.tab2list(@table)
    |> Enum.each(fn {hostname, entry} ->
      if expired?(entry, now) do
        :ets.delete(@table, hostname)
        Logger.info("[CertCache] Evicted expired cert for #{hostname}")
      end
    end)
    schedule_refresh()
    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── Internal ───────────────────────────────────────────────────────

  defp expired?(entry, now \\ System.system_time(:second)) do
    Map.get(entry, :expires_at, now + 1) <= now
  end

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval_ms)
  end
end
