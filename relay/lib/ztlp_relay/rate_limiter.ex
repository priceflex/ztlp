defmodule ZtlpRelay.RateLimiter do
  @moduledoc """
  Generic ETS-based sliding window rate limiter.

  Uses a simple fixed-window counter approach with ETS for O(1) lookups.
  Keys can be IP addresses, NodeIDs, or any Erlang term.

  Periodic cleanup runs via a GenServer timer to remove expired entries.
  """

  use GenServer

  @table_name :ztlp_rate_limiter
  @cleanup_interval_ms 60_000

  # Client API

  @doc """
  Start the rate limiter GenServer.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    table = Keyword.get(opts, :table, @table_name)
    cleanup_interval = Keyword.get(opts, :cleanup_interval_ms, @cleanup_interval_ms)

    GenServer.start_link(__MODULE__, %{table: table, cleanup_interval: cleanup_interval},
      name: name
    )
  end

  @doc """
  Check if a request is allowed under the rate limit.

  ## Parameters

    - `key` — any term identifying the requester (IP, NodeID, etc.)
    - `limit` — maximum number of requests allowed in the window
    - `window_ms` — window duration in milliseconds

  ## Returns

    - `:ok` if the request is allowed
    - `{:error, :rate_limited}` if the limit has been exceeded

  ## Options

    - `:table` — ETS table name (default: `:ztlp_rate_limiter`)
  """
  @spec check(term(), pos_integer(), pos_integer(), keyword()) :: :ok | {:error, :rate_limited}
  def check(key, limit, window_ms, opts \\ []) do
    table = Keyword.get(opts, :table, @table_name)
    now = System.system_time(:millisecond)
    window_start = now - window_ms

    case :ets.lookup(table, key) do
      [{^key, count, window_ts}] when window_ts > window_start ->
        if count >= limit do
          {:error, :rate_limited}
        else
          :ets.update_counter(table, key, {2, 1})
          :ok
        end

      [{^key, _count, _old_window_ts}] ->
        # Window expired, reset
        :ets.insert(table, {key, 1, now})
        :ok

      [] ->
        :ets.insert(table, {key, 1, now})
        :ok
    end
  end

  @doc """
  Reset the counter for a specific key.
  """
  @spec reset(term(), keyword()) :: :ok
  def reset(key, opts \\ []) do
    table = Keyword.get(opts, :table, @table_name)
    :ets.delete(table, key)
    :ok
  end

  @doc """
  Reset all counters.
  """
  @spec reset_all(keyword()) :: :ok
  def reset_all(opts \\ []) do
    table = Keyword.get(opts, :table, @table_name)
    :ets.delete_all_objects(table)
    :ok
  end

  # GenServer callbacks

  @impl true
  def init(%{table: table, cleanup_interval: cleanup_interval}) do
    ets =
      :ets.new(table, [
        :named_table,
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    schedule_cleanup(cleanup_interval)
    {:ok, %{table: ets, cleanup_interval: cleanup_interval}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_expired(state.table)
    schedule_cleanup(state.cleanup_interval)
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Internal

  defp schedule_cleanup(interval) do
    Process.send_after(self(), :cleanup, interval)
  end

  defp cleanup_expired(table) do
    # Remove all entries where the window timestamp is older than
    # the maximum possible window (we use 120 seconds as a generous upper bound)
    cutoff = System.system_time(:millisecond) - 120_000

    :ets.select_delete(table, [
      {{:_, :_, :"$1"}, [{:<, :"$1", cutoff}], [true]}
    ])
  end
end
