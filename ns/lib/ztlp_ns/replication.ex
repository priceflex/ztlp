defmodule ZtlpNs.Replication do
  @moduledoc """
  Eager replication for ZTLP-NS record writes.

  When a record is written locally, `replicate/1` pushes it to all other
  Mnesia cluster nodes via `:rpc.call/4`. This is fire-and-forget — the
  anti-entropy layer catches any misses.

  Records received via replication are inserted with `replicated: true`
  on the remote side, which prevents infinite replication loops.
  """

  require Logger

  alias ZtlpNs.Store

  @metrics_table :ztlp_ns_replication_metrics

  @doc """
  Synchronously replicate a record to all cluster peers.

  Uses `:rpc.call/4` to invoke `Store.insert/2` with `replicated: true`
  on each peer node. Returns `{:ok, successes, failures}` with counts.

  Does NOT block local writes — callers should use `replicate_async/1`.
  """
  @spec replicate(ZtlpNs.Record.t()) :: {:ok, non_neg_integer(), non_neg_integer()}
  def replicate(record) do
    peers = peer_nodes()
    increment_metric(:pushes_total)

    {successes, failures} =
      Enum.reduce(peers, {0, 0}, fn peer, {s, f} ->
        case :rpc.call(peer, Store, :insert, [record, [replicated: true]]) do
          :ok ->
            increment_metric(:push_successes)
            {s + 1, f}

          {:error, reason} ->
            Logger.warn("[ztlp-ns] Replication to #{peer} rejected: #{inspect(reason)}")
            increment_metric(:push_failures)
            {s, f + 1}

          {:badrpc, reason} ->
            Logger.warn("[ztlp-ns] Replication RPC to #{peer} failed: #{inspect(reason)}")
            increment_metric(:push_failures)
            {s, f + 1}
        end
      end)

    {:ok, successes, failures}
  end

  @doc """
  Asynchronously replicate a record to all cluster peers.

  Spawns a fire-and-forget process. Anti-entropy catches any misses.
  Returns `:ok` immediately.
  """
  @spec replicate_async(ZtlpNs.Record.t()) :: :ok
  def replicate_async(record) do
    Task.start(fn -> replicate(record) end)
    :ok
  end

  @doc """
  Get metrics for Prometheus export.

  Returns `%{pushes_total: int, push_successes: int, push_failures: int}`.
  """
  @spec metrics() :: %{pushes_total: non_neg_integer(), push_successes: non_neg_integer(), push_failures: non_neg_integer()}
  def metrics do
    ensure_metrics_table()

    get_counter = fn key ->
      case :ets.lookup(@metrics_table, key) do
        [{^key, n}] -> n
        [] -> 0
      end
    end

    %{
      pushes_total: get_counter.(:pushes_total),
      push_successes: get_counter.(:push_successes),
      push_failures: get_counter.(:push_failures)
    }
  end

  defp increment_metric(key) do
    ensure_metrics_table()
    :ets.update_counter(@metrics_table, key, {2, 1}, {key, 0})
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

  defp peer_nodes do
    Node.list()
  end
end
