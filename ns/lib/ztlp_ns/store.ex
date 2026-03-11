defmodule ZtlpNs.Store do
  @moduledoc """
  Mnesia-backed record store for ZTLP-NS.

  The store enforces ZTLP-NS's core invariants:

  1. **All records must be signed** — unsigned records are rejected on insert.
  2. **Revocation takes priority** — every lookup checks the revocation set
     first. If a node ID appears in any ZTLP_REVOKE record, lookups for
     that node's records return `{:error, :revoked}`.
  3. **Serial numbers are monotonic** — a record with a lower serial number
     than an existing record for the same name+type is rejected.
  4. **TTL expiration** — expired records are not returned by lookups.

  ## Mnesia Table Layout

  The main records table uses `{name, type}` as the key:

      :ztlp_ns_records  — {key :: {name, type}, record :: %Record{}}

  The revocation table uses node_id as the key:

      :ztlp_ns_revoked  — {id :: String.t(), record :: %Record{}}

  Both tables use the configured storage mode (`:disc_copies` for
  production persistence, `:ram_copies` for fast tests). With
  `:disc_copies`, records survive process crashes and node restarts.
  """

  use GenServer

  alias ZtlpNs.Record

  @records_table :ztlp_ns_records
  @revoked_table :ztlp_ns_revoked

  # ── Public API ─────────────────────────────────────────────────────

  @spec start_link(any()) :: GenServer.on_start()
  def start_link(_args) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  @doc """
  Insert a signed record into the store.

  Returns `:ok` on success or `{:error, reason}` if:
  - The record's signature is invalid (`:invalid_signature`)
  - The record has a lower serial than the existing record (`:stale_serial`)
  - The store is at capacity (`:store_full`)

  For ZTLP_REVOKE records, the revoked IDs are also added to the
  revocation set so future lookups are blocked.
  """
  @spec insert(Record.t()) :: :ok | {:error, atom()}
  def insert(%Record{} = record) do
    insert(record, [])
  end

  @doc """
  Insert a signed record with options.

  Accepts the same record as `insert/1`. Options:
  - `:replicated` — when `true`, skip eager replication to peers
    (the record was received from a peer and should not loop back).
  """
  @spec insert(Record.t(), keyword()) :: :ok | {:error, atom()}
  def insert(%Record{} = record, opts) when is_list(opts) do
    # Invariant 1: All records must be signed
    if not Record.verify(record) do
      {:error, :invalid_signature}
    else
      case do_insert(record) do
        :ok ->
          # Trigger eager replication unless this record came from a peer
          unless opts[:replicated] do
            ZtlpNs.Replication.replicate_async(record)
          end

          :ok

        error ->
          error
      end
    end
  end

  # Separated from insert/1 to avoid deep nesting.
  # Checks serial monotonicity and capacity before inserting.
  defp do_insert(%Record{} = record) do
    # Invariant 3: Serial numbers must be monotonic
    case :mnesia.dirty_read(@records_table, {record.name, record.type}) do
      [{@records_table, _key, existing}] when existing.serial >= record.serial ->
        {:error, :stale_serial}

      _ ->
        # Check capacity
        if :mnesia.table_info(@records_table, :size) >= ZtlpNs.Config.max_records() do
          {:error, :store_full}
        else
          # Insert the record
          :mnesia.dirty_write({@records_table, {record.name, record.type}, record})

          # If this is a revocation record, update the revocation set
          if record.type == :revoke do
            index_revocations(record)
          end

          :ok
        end
    end
  end

  @doc """
  Look up a record by name and type.

  Returns `{:ok, record}`, `:not_found`, or `{:error, :revoked}`.

  The revocation check happens FIRST — if the requested name matches
  a revoked node ID, the lookup is blocked even if the record exists.
  Expired records (TTL exceeded) are treated as not found.
  """
  @spec lookup(String.t(), Record.record_type()) ::
          {:ok, Record.t()} | :not_found | {:error, :revoked}
  def lookup(name, type) when is_binary(name) and is_atom(type) do
    # Invariant 2: Revocation takes priority
    if revoked?(name) do
      {:error, :revoked}
    else
      case :mnesia.dirty_read(@records_table, {name, type}) do
        [{@records_table, _key, record}] ->
          # Invariant 4: Check TTL expiration
          if Record.expired?(record) do
            # Clean up expired record
            :mnesia.dirty_delete(@records_table, {name, type})
            :not_found
          else
            {:ok, record}
          end

        [] ->
          :not_found
      end
    end
  end

  @doc """
  Check if a node ID (hex string) has been revoked.

  Checks the revocation table for any ZTLP_REVOKE record that includes
  this ID in its `revoked_ids` list.
  """
  @spec revoked?(String.t()) :: boolean()
  def revoked?(name_or_id) when is_binary(name_or_id) do
    case :mnesia.dirty_read(@revoked_table, name_or_id) do
      [{@revoked_table, _id, _record}] -> true
      [] -> false
    end
  end

  @doc "List all records in the store as `{name, type, record}` tuples."
  @spec list() :: [{String.t(), Record.record_type(), Record.t()}]
  def list do
    :mnesia.dirty_match_object({@records_table, :_, :_})
    |> Enum.map(fn {@records_table, {name, type}, rec} -> {name, type, rec} end)
  end

  @doc "List all revoked IDs."
  @spec list_revoked() :: [String.t()]
  def list_revoked do
    :mnesia.dirty_match_object({@revoked_table, :_, :_})
    |> Enum.map(fn {@revoked_table, id, _rec} -> id end)
  end

  @doc "Get the number of records in the store."
  @spec count() :: non_neg_integer()
  def count do
    :mnesia.table_info(@records_table, :size)
  end

  @doc "Remove all records and revocations (useful for testing)."
  @spec clear() :: :ok
  def clear do
    {:atomic, :ok} = :mnesia.clear_table(@records_table)
    {:atomic, :ok} = :mnesia.clear_table(@revoked_table)
    :ok
  end

  # ── GenServer callbacks ────────────────────────────────────────────

  @impl true
  def init(:ok) do
    ensure_tables()
    {:ok, %{}}
  end

  # ── Private helpers ────────────────────────────────────────────────

  # Ensure Mnesia tables exist. If they already exist (e.g., after restart),
  # this is a no-op — existing data is preserved on disk.
  defp ensure_tables do
    storage_mode = ZtlpNs.Config.storage_mode()

    create_table(
      @records_table,
      [{:attributes, [:key, :record]}, {:type, :set}, {storage_mode, [node()]}]
    )

    create_table(
      @revoked_table,
      [{:attributes, [:id, :record]}, {:type, :set}, {storage_mode, [node()]}]
    )

    # Wait for tables to be loaded (important on restart with disc_copies)
    :ok = :mnesia.wait_for_tables([@records_table, @revoked_table], 10_000)
  end

  defp create_table(name, opts) do
    case :mnesia.create_table(name, opts) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, ^name}} -> :ok
      {:aborted, reason} -> raise "Failed to create Mnesia table #{name}: #{inspect(reason)}"
    end
  end

  # When a ZTLP_REVOKE record is inserted, extract all revoked IDs
  # and add them to the revocation table for O(1) lookup.
  defp index_revocations(%Record{type: :revoke, data: %{revoked_ids: ids}} = record) do
    Enum.each(ids, fn id ->
      :mnesia.dirty_write({@revoked_table, id, record})
    end)
  end

  defp index_revocations(_), do: :ok
end
