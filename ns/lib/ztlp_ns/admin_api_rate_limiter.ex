defmodule ZtlpNs.AdminApiRateLimiter do
  @moduledoc """
  Per-peer-IP rate limiter for the `/admin/records` HTTP endpoint.

  Uses the same token-bucket algorithm as `ZtlpNs.RateLimiter`, but with
  its OWN ETS table and its OWN threshold so admin API traffic doesn't
  compete with device-registration rate limiting.

  ## Algorithm

  Token bucket per peer IP:
  - `count` tokens max (burst)
  - Refills at `count / window_seconds` tokens per second
  - Each request consumes one token
  - Empty bucket → `:rate_limited`

  ## Concurrency

  Check/decrement is serialized through the GenServer via
  `GenServer.call/2` — `:ets.lookup` + `:ets.insert` is NOT atomic, so
  two concurrent requests from the same IP could otherwise both observe
  the same token value and both pass, weakening the limit. Admin API
  traffic is low-frequency (a 5-minute cron at default), so per-call
  serialization is well within budget. CodeRabbit #97.

  ## Configuration

  `ZtlpNs.Config.admin_api_rate_limit/0` returns `{count, window_seconds}`.
  Defaults to `{12, 60}` — i.e. 12 requests per 60-second window, which
  comfortably covers a 5-minute cron with retry headroom.

  Override via env var: `ZTLP_NS_ADMIN_API_RATE_LIMIT=N/W`.

  ## Bucket cleanup

  Stale entries (peers not seen for more than `window_seconds * 2`) are
  periodically purged. The cleanup interval also scales with the window
  so non-default configurations (e.g. `12/300`) don't lose buckets early.
  CodeRabbit #97.
  """

  use GenServer

  @table :ztlp_ns_admin_api_ratelimit
  # Floor on cleanup interval — even with a 10-second window we don't
  # want to fire cleanup faster than once a minute.
  @min_cleanup_interval_ms 60_000

  # ETS record: {ip_tuple, tokens_remaining, last_access_monotonic_ms}

  # ── Public API ────────────────────────────────────────────────────────

  @doc """
  Check if an `/admin/records` request from the given peer IP should be allowed.

  Returns:
  - `:ok` — allowed, one token consumed.
  - `:rate_limited` — bucket empty.

  If the ETS table doesn't exist (i.e. the GenServer hasn't started),
  allows the request rather than crashing the hot path.
  """
  @spec check(tuple()) :: :ok | :rate_limited
  def check(ip) when is_tuple(ip) do
    case :ets.whereis(@table) do
      :undefined -> :ok
      _ ->
        # Serialize check/update through the GenServer to avoid the
        # lookup/insert race documented in @moduledoc. A best-effort
        # fallback on timeout/crash so we never wedge the request path.
        try do
          GenServer.call(__MODULE__, {:check, ip}, 1_000)
        catch
          :exit, _ -> :ok
        end
    end
  end

  @doc """
  Reset all admin-API rate-limit state. Test helper.
  """
  @spec reset() :: :ok
  def reset do
    case :ets.whereis(@table) do
      :undefined -> :ok
      _ ->
        :ets.delete_all_objects(@table)
        :ok
    end
  end

  @doc """
  Current token count for a peer IP (monitoring/testing).
  """
  @spec tokens_for(tuple()) :: float() | nil
  def tokens_for(ip) do
    case :ets.lookup(@table, ip) do
      [{^ip, tokens, _last}] -> tokens
      [] -> nil
    end
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
    schedule_cleanup()
    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:check, ip}, _from, state) do
    {:reply, do_check(ip), state}
  end

  @impl true
  def handle_info(:cleanup, state) do
    cleanup_stale_entries()
    schedule_cleanup()
    {:noreply, state}
  end

  # ── Internal (called serialized from handle_call) ─────────────────────

  defp do_check(ip) do
    now = System.monotonic_time(:millisecond)
    {count, window_seconds} = ZtlpNs.Config.admin_api_rate_limit()
    burst = count
    rate = count / window_seconds

    case :ets.lookup(@table, ip) do
      [] ->
        # First request from this IP — start the bucket with burst - 1
        :ets.insert(@table, {ip, burst - 1, now})
        :ok

      [{^ip, tokens, last_access}] ->
        elapsed_ms = max(now - last_access, 0)
        tokens_to_add = elapsed_ms * rate / 1_000
        available = min(tokens + tokens_to_add, burst * 1.0)

        if available >= 1.0 do
          :ets.insert(@table, {ip, available - 1.0, now})
          :ok
        else
          :ets.insert(@table, {ip, available, now})
          :rate_limited
        end
    end
  end

  defp schedule_cleanup do
    Process.send_after(self(), :cleanup, cleanup_interval_ms())
  end

  defp cleanup_interval_ms do
    # Fire cleanup once per configured window, but no faster than once a minute.
    {_count, window_seconds} = ZtlpNs.Config.admin_api_rate_limit()
    max(window_seconds * 1_000, @min_cleanup_interval_ms)
  end

  defp cleanup_stale_entries do
    now = System.monotonic_time(:millisecond)
    {_count, window_seconds} = ZtlpNs.Config.admin_api_rate_limit()
    # Keep buckets for 2x the window so a mid-window cron tick still
    # finds its prior tokens; only purge clearly-idle peers.
    stale_threshold = now - 2 * window_seconds * 1_000

    :ets.select_delete(@table, [
      {{:"$1", :"$2", :"$3"}, [{:<, :"$3", stale_threshold}], [true]}
    ])
  end
end
