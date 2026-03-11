defmodule ZtlpNs.Cluster do
  @moduledoc """
  Multi-node Mnesia cluster management for ZTLP-NS federation.

  Provides functions to join/leave a cluster of NS nodes,
  with automatic table replication. Uses pure OTP/Mnesia —
  no external dependencies.

  ## Joining a Cluster

      ZtlpNs.Cluster.join(:"ns1@192.168.1.10")

  This stops local Mnesia, connects to the remote node, adds this
  node to the cluster schema, and replicates all NS tables.

  ## Leaving a Cluster

      ZtlpNs.Cluster.leave()

  Removes this node's table copies, detaches from the cluster schema,
  and re-creates local standalone tables so the node can continue
  operating independently.

  ## Automatic Clustering on Startup

      ZtlpNs.Cluster.ensure_replicated()

  Called during application startup. If `seed_nodes` are configured,
  attempts to join the first reachable seed node. If none are configured
  or reachable, operates standalone.
  """

  require Logger

  @ns_tables [:ztlp_ns_records, :ztlp_ns_revoked]

  # ── Public API ─────────────────────────────────────────────────────

  @doc """
  Join an existing NS cluster by connecting to `node_name`.

  Stops local Mnesia, deletes the local schema, connects to the remote
  node, and replicates all NS tables to this node.

  Returns `{:ok, members}` on success or `{:error, reason}`.
  """
  @spec join(node()) :: {:ok, [node()]} | {:error, term()}
  def join(node_name) when is_atom(node_name) do
    if node_name == node() do
      {:error, :cannot_join_self}
    else
      do_join(node_name)
    end
  end

  @doc """
  Leave the cluster gracefully.

  Removes this node's copies of all NS tables, detaches from the
  Mnesia cluster schema, and re-creates local standalone tables.

  Returns `:ok` or `{:error, reason}`.
  """
  @spec leave() :: :ok | {:error, term()}
  def leave do
    if not clustered?() do
      {:error, :not_clustered}
    else
      do_leave()
    end
  end

  @doc "List all running nodes in the current Mnesia cluster."
  @spec members() :: [node()]
  def members do
    :mnesia.system_info(:running_db_nodes)
  end

  @doc "Check if this node is part of a multi-node cluster."
  @spec clustered?() :: boolean()
  def clustered? do
    length(members()) > 1
  end

  @doc """
  Cluster health and status information.

  Returns a map with node info, membership, and table copy details.
  """
  @spec status() :: map()
  def status do
    running = :mnesia.system_info(:running_db_nodes)
    all = :mnesia.system_info(:db_nodes)
    stopped = all -- running

    table_copies =
      Enum.reduce(@ns_tables, %{}, fn table, acc ->
        copies = table_copy_info(table)
        Map.put(acc, table, copies)
      end)

    %{
      node: node(),
      members: all,
      running: running,
      stopped: stopped,
      table_copies: table_copies
    }
  end

  @doc """
  Ensure tables are replicated on startup.

  If seed nodes are configured, attempts to join the first reachable one.
  If no seed nodes are configured or none are reachable, operates standalone.

  This is safe to call multiple times — if already clustered, it's a no-op.
  """
  @spec ensure_replicated() :: :ok | {:error, term()}
  def ensure_replicated do
    seeds = ZtlpNs.Config.seed_nodes()

    if seeds == [] do
      Logger.debug("[ztlp-ns] No seed nodes configured, operating standalone")
      :ok
    else
      if clustered?() do
        Logger.debug("[ztlp-ns] Already clustered with #{inspect(members())}")
        :ok
      else
        try_join_seeds(seeds)
      end
    end
  end

  # ── Private: join ──────────────────────────────────────────────────

  defp do_join(node_name) do
    storage_mode = ZtlpNs.Config.storage_mode()

    with :ok <- connect_to_node(node_name),
         :ok <- stop_and_reset_mnesia(storage_mode),
         :ok <- start_mnesia(),
         :ok <- add_to_cluster(node_name),
         :ok <- copy_schema(storage_mode),
         :ok <- replicate_tables(storage_mode),
         :ok <- wait_for_tables() do
      Logger.info("[ztlp-ns] Joined cluster via #{node_name}, members: #{inspect(members())}")
      {:ok, members()}
    else
      {:error, reason} = err ->
        Logger.error("[ztlp-ns] Failed to join cluster via #{node_name}: #{inspect(reason)}")
        # Try to recover to standalone mode
        recover_standalone(storage_mode)
        err
    end
  end

  defp connect_to_node(node_name) do
    case Node.connect(node_name) do
      true -> :ok
      false -> {:error, {:cannot_connect, node_name}}
      :ignored -> {:error, {:node_not_alive, node()}}
    end
  end

  defp stop_and_reset_mnesia(storage_mode) do
    :mnesia.stop()

    if storage_mode == :disc_copies do
      case :mnesia.delete_schema([node()]) do
        :ok -> :ok
        {:error, reason} -> {:error, {:delete_schema_failed, reason}}
      end
    else
      :ok
    end
  end

  defp start_mnesia do
    case :mnesia.start() do
      :ok -> :ok
      {:error, reason} -> {:error, {:mnesia_start_failed, reason}}
    end
  end

  defp add_to_cluster(node_name) do
    case :mnesia.change_config(:extra_db_nodes, [node_name]) do
      {:ok, [_ | _]} -> :ok
      {:ok, []} -> {:error, {:extra_db_nodes_failed, node_name}}
      {:error, reason} -> {:error, {:change_config_failed, reason}}
    end
  end

  defp copy_schema(storage_mode) do
    case :mnesia.change_table_copy_type(:schema, node(), storage_mode) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, :schema, _, _}} -> :ok
      {:aborted, reason} -> {:error, {:schema_copy_failed, reason}}
    end
  end

  defp replicate_tables(storage_mode) do
    Enum.reduce_while(@ns_tables, :ok, fn table, :ok ->
      case :mnesia.add_table_copy(table, node(), storage_mode) do
        {:atomic, :ok} ->
          {:cont, :ok}

        {:aborted, {:already_exists, ^table, _}} ->
          {:cont, :ok}

        {:aborted, reason} ->
          {:halt, {:error, {:replicate_failed, table, reason}}}
      end
    end)
  end

  defp wait_for_tables do
    case :mnesia.wait_for_tables(@ns_tables, 30_000) do
      :ok -> :ok
      {:timeout, tables} -> {:error, {:table_load_timeout, tables}}
      {:error, reason} -> {:error, {:table_wait_failed, reason}}
    end
  end

  # ── Private: leave ─────────────────────────────────────────────────

  defp do_leave do
    storage_mode = ZtlpNs.Config.storage_mode()

    # Step 1: Remove table copies from this node
    Enum.each(@ns_tables, fn table ->
      :mnesia.del_table_copy(table, node())
    end)

    # Step 2: Tell the cluster to forget this node
    # Run on a remote node so the schema change is accepted
    remote_nodes = members() -- [node()]

    if remote_nodes != [] do
      remote = hd(remote_nodes)
      :rpc.call(remote, :mnesia, :del_table_copy, [:schema, node()])
    end

    # Step 3: Stop Mnesia and clean up local schema
    :mnesia.stop()

    if storage_mode == :disc_copies do
      :mnesia.delete_schema([node()])
    end

    # Step 4: Restart standalone
    recover_standalone(storage_mode)

    Logger.info("[ztlp-ns] Left cluster, now operating standalone")
    :ok
  rescue
    e ->
      Logger.error("[ztlp-ns] Error during leave: #{inspect(e)}")
      {:error, {:leave_failed, e}}
  end

  # ── Private: recovery/standalone ───────────────────────────────────

  defp recover_standalone(storage_mode) do
    # Ensure Mnesia is stopped first
    :mnesia.stop()

    if storage_mode == :disc_copies do
      case :mnesia.create_schema([node()]) do
        :ok -> :ok
        {:error, {_, {:already_exists, _}}} -> :ok
        _ -> :ok
      end
    end

    :mnesia.start()

    # Re-create tables for standalone operation
    Enum.each(@ns_tables, fn table ->
      opts = table_opts(table, storage_mode)

      case :mnesia.create_table(table, opts) do
        {:atomic, :ok} -> :ok
        {:aborted, {:already_exists, ^table}} -> :ok
        _ -> :ok
      end
    end)

    :mnesia.wait_for_tables(@ns_tables, 10_000)
  end

  defp table_opts(:ztlp_ns_records, storage_mode) do
    [{:attributes, [:key, :record]}, {:type, :set}, {storage_mode, [node()]}]
  end

  defp table_opts(:ztlp_ns_revoked, storage_mode) do
    [{:attributes, [:id, :record]}, {:type, :set}, {storage_mode, [node()]}]
  end

  # ── Private: seed node joining ─────────────────────────────────────

  defp try_join_seeds([]) do
    Logger.warning("[ztlp-ns] No seed nodes reachable, operating standalone")
    :ok
  end

  defp try_join_seeds([seed | rest]) do
    seed_atom = if is_binary(seed), do: String.to_atom(seed), else: seed

    Logger.info("[ztlp-ns] Attempting to join cluster via #{seed_atom}")

    case join(seed_atom) do
      {:ok, _members} ->
        :ok

      {:error, reason} ->
        Logger.warning("[ztlp-ns] Failed to join #{seed_atom}: #{inspect(reason)}, trying next seed")
        try_join_seeds(rest)
    end
  end

  # ── Private: table info helper ─────────────────────────────────────

  defp table_copy_info(table) do
    try do
      %{
        disc_copies: :mnesia.table_info(table, :disc_copies),
        ram_copies: :mnesia.table_info(table, :ram_copies),
        disc_only_copies: :mnesia.table_info(table, :disc_only_copies),
        size: :mnesia.table_info(table, :size)
      }
    rescue
      _ -> %{error: :table_not_found}
    end
  end
end
