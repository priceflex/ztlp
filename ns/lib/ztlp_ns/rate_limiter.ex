defmodule ZtlpNs.RateLimiter do
  @moduledoc """
  Per-IP query rate limiter for ZTLP-NS using a token bucket algorithm.

  Provides fast, concurrent rate limiting stored in ETS. Each source IP
  gets an independent token bucket that refills at the configured rate.

  ## Algorithm

  Token bucket with:
  - `queries_per_second` tokens added per second (default: 100)
  - `burst` maximum tokens (default: 200)
  - Tokens consumed on each query (1 per query)

  ## Configuration

  Via YAML config (`rate_limit` section):

  - `queries_per_second` — refill rate (default: 100)
  - `burst` — max tokens / bucket size (default: 200)

  ## Cleanup

  Stale entries (IPs not seen for 60+ seconds) are periodically purged
  to prevent unbounded ETS growth.
  """

  use GenServer

  @table __MODULE__
  @cleanup_interval 60_000
  @metrics_table :ztlp_ns_ratelimit_metrics

  # ETS record: {ip_tuple, tokens_remaining, last_access_monotonic_ms}

  # ── Public API ────────────────────────────────────────────────────────

  @doc """
  Check if a query from the given IP should be allowed.

  Returns:
  - `:ok` — query allowed, token consumed
  - `:rate_limited` — query rejected, bucket empty
  """
  @spec check(tuple()) :: :ok | :rate_limited
  def check(ip) when is_tuple(ip) do
    # If the ETS table doesn't exist (e.g., RateLimiter not started in test
    # environments), allow all traffic rather than crashing.
    case :ets.whereis(@table) do
      :undefined -> :ok
      _ -> do_check(ip)
    end
  end

  defp do_check(ip) do
    now = System.monotonic_time(:millisecond)
    rate = queries_per_second()
    burst = burst_size()

    result = case :ets.lookup(@table, ip) do
      [] ->
        # First query from this IP — create bucket with burst - 1 tokens
        :ets.insert(@table, {ip, burst - 1, now})
        :ok

      [{^ip, tokens, last_access}] ->
        # Calculate tokens to add based on elapsed time
        elapsed_ms = max(now - last_access, 0)
        tokens_to_add = elapsed_ms * rate / 1_000
        available = min(tokens + tokens_to_add, burst * 1.0)

        if available >= 1.0 do
          :ets.insert(@table, {ip, available - 1.0, now})
          :ok
        else
          # Update last_access so tokens continue to accumulate
          :ets.insert(@table, {ip, available, now})
          :rate_limited
        end
    end

    # Track metrics (best-effort, never crash the hot path)
    try do
      ensure_metrics_table()
      case result do
        :ok -> :ets.update_counter(@metrics_table, :allowed, {2, 1}, {:allowed, 0})
        :rate_limited -> :ets.update_counter(@metrics_table, :rejected, {2, 1}, {:rejected, 0})
      end
    rescue
      ArgumentError -> :ok
    end

    result
  end

  @doc """
  Get the current token count for an IP (for monitoring/testing).
  """
  @spec tokens_for(tuple()) :: float() | nil
  def tokens_for(ip) do
    case :ets.lookup(@table, ip) do
      [{^ip, tokens, _last}] -> tokens
      [] -> nil
    end
  end

  @doc """
  Reset all rate limiter state.
  """
  @spec reset() :: :ok
  def reset do
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc """
  Get metrics for Prometheus export.

  Returns `%{allowed: int, rejected: int}`.
  """
  @spec metrics() :: %{allowed: non_neg_integer(), rejected: non_neg_integer()}
  def metrics do
    ensure_metrics_table()

    get_counter = fn key ->
      case :ets.lookup(@metrics_table, key) do
        [{^key, n}] -> n
        [] -> 0
      end
    end

    %{
      allowed: get_counter.(:allowed),
      rejected: get_counter.(:rejected)
    }
  end

  defp ensure_metrics_table do
    case :ets.whereis(@metrics_table) do
      :undefined ->
        try do
          :ets.new(@metrics_table, [:set, :public, :named_table, write_concurrency: true])
        rescue
          ArgumentError -> :ok
        end
      _tid -> :ok
    end
  end

  # ── Configuration ─────────────────────────────────────────────────────

  @doc false
  def queries_per_second do
    ZtlpNs.Config.rate_limit_queries_per_second()
  end

  @doc false
  def burst_size do
    ZtlpNs.Config.rate_limit_burst()
  end

  # ── GenServer ─────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])
    # Create metrics table eagerly, owned by this GenServer
    try do
      :ets.new(@metrics_table, [:set, :public, :named_table, write_concurrency: true])
    rescue
      ArgumentError -> :ok
    end
    schedule_cleanup()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_stale_entries()
    schedule_cleanup()
    {:noreply, state}
  end

  # ── Internal ──────────────────────────────────────────────────────────

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  defp cleanup_stale_entries do
    now = System.monotonic_time(:millisecond)
    stale_threshold = now - @cleanup_interval

    # Delete entries not accessed in the last cleanup interval
    :ets.select_delete(@table, [
      {{:"$1", :"$2", :"$3"}, [{:<, :"$3", stale_threshold}], [true]}
    ])
  end
end
