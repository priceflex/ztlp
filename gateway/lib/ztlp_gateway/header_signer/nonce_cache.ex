defmodule ZtlpGateway.HeaderSigner.NonceCache do
  @moduledoc """
  ETS-based nonce replay cache for ZTLP header signing.

  Tracks seen nonces to prevent exact replay of captured header sets.
  Nonces expire after `2 * timestamp_window` seconds (configurable).
  A periodic cleanup runs every 60 seconds to purge expired entries.

  Started from `application.ex` as part of the supervision tree.
  """

  use GenServer

  require Logger

  @table :ztlp_nonce_cache
  @cleanup_interval_ms 60_000

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the nonce cache GenServer."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Check a nonce against the cache.

  Returns `:ok` if the nonce hasn't been seen (and records it),
  or `{:error, :replayed}` if it has been seen before.
  """
  @spec check_nonce(String.t()) :: :ok | {:error, :replayed}
  def check_nonce(nonce) when is_binary(nonce) do
    now = System.system_time(:second)
    ttl = nonce_ttl()
    expires_at = now + ttl

    # Use insert_new for atomic check-and-insert
    case :ets.insert_new(@table, {nonce, expires_at}) do
      true -> :ok
      false -> {:error, :replayed}
    end
  end

  @doc "Get the configured nonce TTL in seconds."
  @spec nonce_ttl() :: non_neg_integer()
  def nonce_ttl do
    window = ZtlpGateway.Config.get(:header_signing_timestamp_window)
    2 * window
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    # Create ETS table: set, public for concurrent reads, but insert_new
    # provides atomicity for the check-and-insert pattern
    :ets.new(@table, [:named_table, :set, :public, write_concurrency: true, read_concurrency: true])

    # Schedule periodic cleanup
    schedule_cleanup()

    {:ok, %{}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    purge_expired()
    schedule_cleanup()
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Internal
  # ---------------------------------------------------------------------------

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval_ms)
  end

  defp purge_expired do
    now = System.system_time(:second)

    # Use select_delete for efficient bulk removal
    match_spec = [{{:_, :"$1"}, [{:<, :"$1", now}], [true]}]
    count = :ets.select_delete(@table, match_spec)

    if count > 0 do
      Logger.debug("[NonceCache] Purged #{count} expired nonces")
    end
  end
end
