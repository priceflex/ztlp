defmodule ZtlpNs.AntiEntropy do
  @moduledoc """
  Merkle-tree-based anti-entropy for ZTLP-NS record synchronization.

  Periodically compares the local record state with cluster peers using
  hash digests. When a divergence is detected, records are exchanged and
  merged using ZTLP-NS conflict resolution rules:

  1. **Revocation always wins** — revocations propagate unconditionally.
  2. **Higher serial wins** — for same name+type, keep the higher serial.
  3. **Signature must verify** — reject records with invalid signatures.
  4. **TTL expiration** — don't propagate expired records.

  ## Merkle Hash Scheme

  Each record produces a leaf hash: `BLAKE2s(name <> type_byte <> serial_be64)`.
  Records are sorted lexicographically by `{name, type}` key. The root hash
  is `BLAKE2s(leaf_1 <> leaf_2 <> ... <> leaf_n)`, giving a single digest
  that represents the entire store state. When roots differ between peers,
  a full record exchange is performed (range-based tree walking is supported
  but full exchange is the default strategy for now).

  ## Configuration

  - `anti_entropy.interval` — sync period (default 30 000 ms)
  - `anti_entropy.enabled` — whether periodic sync runs (default: true when clustered)
  """

  use GenServer

  require Logger

  alias ZtlpNs.{Record, Store}

  @default_interval 30_000
  @metrics_table :ztlp_ns_antientropy_metrics

  # ── Public API ─────────────────────────────────────────────────────

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Compute a root hash over all records in the store.

  Records are sorted by `{name, type}` key. Each record contributes a
  leaf hash of `BLAKE2s(name <> type_byte <> serial_be64)`. The root
  hash is `BLAKE2s(concat of all leaf hashes)`.

  Returns a 32-byte binary. An empty store returns `BLAKE2s("")`.
  """
  @spec compute_root_hash() :: binary()
  def compute_root_hash do
    leaf_hashes =
      Store.list()
      |> Enum.sort_by(fn {name, type, _rec} -> {name, type} end)
      |> Enum.map(fn {_name, _type, rec} -> leaf_hash(rec) end)

    :crypto.hash(:blake2s, IO.iodata_to_binary(leaf_hashes))
  end

  @doc """
  Compute a hash over records whose `{name, type}` key falls in `[from, to]`.

  Both `from` and `to` are `{name, type}` tuples. Records are sorted and
  filtered to the inclusive range, then hashed exactly like `compute_root_hash/0`.
  """
  @spec compute_range_hash({String.t(), atom()}, {String.t(), atom()}) :: binary()
  def compute_range_hash(from, to) do
    leaf_hashes =
      Store.list()
      |> Enum.filter(fn {name, type, _rec} -> {name, type} >= from and {name, type} <= to end)
      |> Enum.sort_by(fn {name, type, _rec} -> {name, type} end)
      |> Enum.map(fn {_name, _type, rec} -> leaf_hash(rec) end)

    :crypto.hash(:blake2s, IO.iodata_to_binary(leaf_hashes))
  end

  @doc """
  Compare a peer's root hash with the local root hash.

  Returns `:in_sync` when hashes match, `{:needs_sync, local_hash}` otherwise.
  """
  @spec diff_with_peer(binary()) :: :in_sync | {:needs_sync, binary()}
  def diff_with_peer(peer_root_hash) when is_binary(peer_root_hash) do
    local = compute_root_hash()

    if local == peer_root_hash do
      :in_sync
    else
      {:needs_sync, local}
    end
  end

  @doc """
  Return all records whose `{name, type}` key falls in `[from, to]`.
  """
  @spec get_records_in_range({String.t(), atom()}, {String.t(), atom()}) :: [Record.t()]
  def get_records_in_range(from, to) do
    Store.list()
    |> Enum.filter(fn {name, type, _rec} -> {name, type} >= from and {name, type} <= to end)
    |> Enum.map(fn {_name, _type, rec} -> rec end)
  end

  @doc """
  Merge a list of remote records into the local store.

  Applies ZTLP-NS conflict resolution rules:
  1. Revocation always wins — propagated unconditionally.
  2. Higher serial wins — stale records are rejected.
  3. Signature must verify — unsigned/invalid records are rejected.
  4. Expired records are skipped.

  Records are inserted with `replicated: true` to avoid re-replication loops.

  Returns `{:ok, %{accepted: n, rejected: n, skipped: n}}`.
  """
  @spec merge_remote_records([Record.t()]) :: {:ok, %{accepted: non_neg_integer(), rejected: non_neg_integer(), skipped: non_neg_integer()}}
  def merge_remote_records(records) when is_list(records) do
    stats =
      Enum.reduce(records, %{accepted: 0, rejected: 0, skipped: 0}, fn record, acc ->
        case merge_one(record) do
          :accepted -> %{acc | accepted: acc.accepted + 1}
          :rejected -> %{acc | rejected: acc.rejected + 1}
          :skipped -> %{acc | skipped: acc.skipped + 1}
        end
      end)

    {:ok, stats}
  end

  # ── Metrics ─────────────────────────────────────────────────────────

  @doc """
  Get metrics for Prometheus export.

  Returns a map with counters for sync operations:
  - `:syncs_total` — total sync attempts
  - `:syncs_needed` — syncs where data was exchanged
  - `:records_merged` — records accepted via merge
  - `:records_rejected` — records rejected (bad sig, stale)
  - `:last_sync_epoch` — unix timestamp of last completed sync (0 if never)
  """
  @spec metrics() :: %{
    syncs_total: non_neg_integer(),
    syncs_needed: non_neg_integer(),
    records_merged: non_neg_integer(),
    records_rejected: non_neg_integer(),
    last_sync_epoch: non_neg_integer()
  }
  def metrics do
    ensure_metrics_table()

    get_counter = fn key ->
      case :ets.lookup(@metrics_table, key) do
        [{^key, n}] -> n
        [] -> 0
      end
    end

    %{
      syncs_total: get_counter.(:syncs_total),
      syncs_needed: get_counter.(:syncs_needed),
      records_merged: get_counter.(:records_merged),
      records_rejected: get_counter.(:records_rejected),
      last_sync_epoch: get_counter.(:last_sync_epoch)
    }
  end

  @doc false
  def increment_metric(key, amount \\ 1) do
    ensure_metrics_table()
    :ets.update_counter(@metrics_table, key, {2, amount}, {key, 0})
  end

  @doc false
  def set_metric(key, value) do
    ensure_metrics_table()
    :ets.insert(@metrics_table, {key, value})
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

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(opts) do
    interval = opts[:interval] || get_config_interval()
    enabled = Keyword.get(opts, :enabled, get_config_enabled())

    state = %{interval: interval, enabled: enabled}

    if enabled do
      schedule_sync(interval)
    end

    {:ok, state}
  end

  @impl true
  def handle_info(:sync, state) do
    if state.enabled do
      run_sync()
      schedule_sync(state.interval)
    end

    {:noreply, state}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  # ── Private helpers ────────────────────────────────────────────────

  defp leaf_hash(%Record{} = rec) do
    type_byte = Record.type_to_byte(rec.type)

    :crypto.hash(
      :blake2s,
      <<rec.name::binary, type_byte::8, rec.serial::unsigned-big-64>>
    )
  end

  defp merge_one(%Record{} = record) do
    # Rule 3: Signature must verify
    unless Record.verify(record) do
      throw(:rejected)
    end

    # Rule 4: Skip expired records (TTL 0 means never expires)
    if record.ttl != 0 and System.system_time(:second) > record.created_at + record.ttl do
      throw(:skipped)
    end

    # Rule 1: Revocations always propagate
    # Rule 2: Higher serial wins (Store.insert handles stale_serial rejection)
    case Store.insert(record, replicated: true) do
      :ok -> :accepted
      {:error, :stale_serial} -> :skipped
      {:error, _reason} -> :rejected
    end
  catch
    :rejected -> :rejected
    :skipped -> :skipped
  end

  defp run_sync do
    local_hash = compute_root_hash()
    peers = peer_nodes()
    increment_metric(:syncs_total)

    Enum.each(peers, fn peer ->
      try do
        case :rpc.call(peer, __MODULE__, :diff_with_peer, [local_hash]) do
          :in_sync ->
            :ok

          {:needs_sync, _peer_hash} ->
            increment_metric(:syncs_needed)

            # Get all records from peer and merge
            case :rpc.call(peer, __MODULE__, :get_records_in_range, [{"", :bootstrap}, {<<255>>, :svc}]) do
              records when is_list(records) ->
                {:ok, stats} = merge_remote_records(records)

                increment_metric(:records_merged, stats.accepted)
                increment_metric(:records_rejected, stats.rejected)

                Logger.info(
                  "[ztlp-ns] Anti-entropy sync with #{peer}: " <>
                    "accepted=#{stats.accepted} rejected=#{stats.rejected} skipped=#{stats.skipped}"
                )

              {:badrpc, reason} ->
                Logger.warn("[ztlp-ns] Anti-entropy RPC failed for #{peer}: #{inspect(reason)}")
            end

          {:badrpc, reason} ->
            Logger.warn("[ztlp-ns] Anti-entropy diff failed for #{peer}: #{inspect(reason)}")
        end
      rescue
        e ->
          Logger.warn("[ztlp-ns] Anti-entropy error with #{peer}: #{inspect(e)}")
      end
    end)

    set_metric(:last_sync_epoch, System.system_time(:second))
  end

  defp peer_nodes do
    [node() | Node.list()] -- [node()]
  end

  defp schedule_sync(interval) do
    Process.send_after(self(), :sync, interval)
  end

  defp get_config_interval do
    Application.get_env(:ztlp_ns, :anti_entropy, [])
    |> Keyword.get(:interval, @default_interval)
  end

  defp get_config_enabled do
    case Application.get_env(:ztlp_ns, :anti_entropy, []) |> Keyword.get(:enabled) do
      nil -> ZtlpNs.Cluster.clustered?()
      val -> val
    end
  end
end
