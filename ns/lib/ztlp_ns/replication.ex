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

  @doc """
  Synchronously replicate a record to all cluster peers.

  Uses `:rpc.call/4` to invoke `Store.insert/2` with `replicated: true`
  on each peer node. Returns `{:ok, successes, failures}` with counts.

  Does NOT block local writes — callers should use `replicate_async/1`.
  """
  @spec replicate(ZtlpNs.Record.t()) :: {:ok, non_neg_integer(), non_neg_integer()}
  def replicate(record) do
    peers = peer_nodes()

    {successes, failures} =
      Enum.reduce(peers, {0, 0}, fn peer, {s, f} ->
        case :rpc.call(peer, Store, :insert, [record, [replicated: true]]) do
          :ok ->
            {s + 1, f}

          {:error, reason} ->
            Logger.warn("[ztlp-ns] Replication to #{peer} rejected: #{inspect(reason)}")
            {s, f + 1}

          {:badrpc, reason} ->
            Logger.warn("[ztlp-ns] Replication RPC to #{peer} failed: #{inspect(reason)}")
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

  defp peer_nodes do
    Node.list()
  end
end
