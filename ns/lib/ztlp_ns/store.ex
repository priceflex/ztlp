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
  @pubkey_index_table :ztlp_ns_pubkey_index
  @device_index_table :ztlp_ns_device_index
  @group_index_table :ztlp_ns_group_index

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
      # Invariant 5: Record encoding must not exceed max_record_size
      wire_size = byte_size(Record.encode(record))

      if wire_size > ZtlpNs.Config.max_record_size() do
        {:error, :record_too_large}
      else
        case do_insert(record) do
          :ok ->
            # Maintain pubkey index for KEY records
            index_pubkey(record)

            # Maintain device-owner index for DEVICE records
            index_device_owner(record)

            # Maintain group membership index for GROUP records
            index_group_members(record)

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

  @doc """
  List all records filtered by type.

  Returns `{name, type, record}` tuples for the given record type.
  Excludes expired records.
  """
  @spec list_by_type(Record.record_type()) :: [{String.t(), Record.record_type(), Record.t()}]
  def list_by_type(type) when is_atom(type) do
    list()
    |> Enum.filter(fn {_name, t, record} ->
      t == type and not Record.expired?(record)
    end)
  end

  @doc """
  List all records filtered by zone suffix.

  Returns `{name, type, record}` tuples for names ending with the given zone.
  Excludes expired records.
  """
  @spec list_by_zone(String.t()) :: [{String.t(), Record.record_type(), Record.t()}]
  def list_by_zone(zone) when is_binary(zone) do
    dot_suffix = if String.starts_with?(zone, "."), do: zone, else: "." <> zone
    at_suffix = "@" <> zone

    list()
    |> Enum.filter(fn {name, _type, record} ->
      (String.ends_with?(name, dot_suffix) or
       String.ends_with?(name, at_suffix) or
       name == zone) and not Record.expired?(record)
    end)
  end

  @doc """
  List all records, optionally filtered by type and/or zone.

  This combines type and zone filtering in a single pass.
  Excludes expired records.
  """
  @spec list_filtered(keyword()) :: [{String.t(), Record.record_type(), Record.t()}]
  def list_filtered(opts \\ []) do
    type_filter = Keyword.get(opts, :type)
    zone_filter = Keyword.get(opts, :zone)

    {dot_suffix, at_suffix} =
      case zone_filter do
        nil -> {nil, nil}
        zone ->
          dot = if String.starts_with?(zone, "."), do: zone, else: "." <> zone
          at = "@" <> zone
          {dot, at}
      end

    list()
    |> Enum.filter(fn {name, type, record} ->
      type_ok = is_nil(type_filter) or type == type_filter
      zone_ok = is_nil(dot_suffix) or
                String.ends_with?(name, dot_suffix) or
                String.ends_with?(name, at_suffix) or
                name == zone_filter
      not_expired = not Record.expired?(record)
      type_ok and zone_ok and not_expired
    end)
  end

  @doc """
  Look up a record name by public key hex string.

  Uses the pubkey index table for O(1) lookups instead of scanning
  all records. Returns `{:ok, record}`, `:not_found`, or `{:error, :revoked}`.
  """
  @spec lookup_by_pubkey(String.t()) :: {:ok, Record.t()} | :not_found | {:error, :revoked}
  def lookup_by_pubkey(pubkey_hex) when is_binary(pubkey_hex) do
    pk_lower = String.downcase(pubkey_hex)

    try do
      case :mnesia.dirty_read(@pubkey_index_table, pk_lower) do
        [{@pubkey_index_table, _pk, name}] ->
          # Found in index — now look up the actual record
          lookup(name, :key)

        [] ->
          :not_found
      end
    rescue
      # Table may not exist yet if Store hasn't fully initialized
      ArgumentError -> :not_found
    catch
      :exit, {:aborted, {:no_exists, _}} -> :not_found
    end
  end

  @doc """
  Look up all devices owned by a user.

  Returns a list of device names linked to the given user name.
  Uses the device-by-owner index for O(1) lookups.
  """
  @spec lookup_devices_for_user(String.t()) :: [String.t()]
  def lookup_devices_for_user(user_name) when is_binary(user_name) do
    try do
      :mnesia.dirty_read(@device_index_table, user_name)
      |> Enum.map(fn {@device_index_table, _owner, device_name} -> device_name end)
    rescue
      _ -> []
    catch
      :exit, _ -> []
    end
  end

  @doc """
  Look up the user (owner) for a device.

  Returns `{:ok, user_name}` or `:not_found`.
  Reads the owner field from the device's record data.
  """
  @spec lookup_user_for_device(String.t()) :: {:ok, String.t()} | :not_found
  def lookup_user_for_device(device_name) when is_binary(device_name) do
    case lookup(device_name, :device) do
      {:ok, record} ->
        owner = Map.get(record.data, :owner) || Map.get(record.data, "owner")
        if owner && owner != "" do
          {:ok, owner}
        else
          :not_found
        end
      _ ->
        :not_found
    end
  end

  @doc """
  Look up all groups that a user is a member of.

  Returns a list of group names.
  Uses the group membership index for O(1) lookups.
  """
  @spec groups_for_user(String.t()) :: [String.t()]
  def groups_for_user(user_name) when is_binary(user_name) do
    try do
      :mnesia.dirty_read(@group_index_table, user_name)
      |> Enum.map(fn {@group_index_table, _user, group_name} -> group_name end)
    rescue
      _ -> []
    catch
      :exit, _ -> []
    end
  end

  @doc """
  Look up all members of a group.

  Returns a list of user/member names from the group record's data.
  """
  @spec members_of_group(String.t()) :: [String.t()]
  def members_of_group(group_name) when is_binary(group_name) do
    case lookup(group_name, :group) do
      {:ok, record} ->
        Map.get(record.data, :members) || Map.get(record.data, "members") || []

      _ ->
        []
    end
  end

  @doc """
  Check if a user is a member of a group.

  Returns `true` if the user is listed in the group's members.
  """
  @spec is_member?(String.t(), String.t()) :: boolean()
  def is_member?(group_name, user_name) when is_binary(group_name) and is_binary(user_name) do
    user_name in members_of_group(group_name)
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

  @doc "Remove all records, revocations, pubkey index, and device index (useful for testing)."
  @spec clear() :: :ok
  def clear do
    {:atomic, :ok} = :mnesia.clear_table(@records_table)
    {:atomic, :ok} = :mnesia.clear_table(@revoked_table)
    # Clear pubkey index if it exists
    try do
      {:atomic, :ok} = :mnesia.clear_table(@pubkey_index_table)
    rescue
      _ -> :ok
    end
    # Clear device-owner index if it exists
    try do
      {:atomic, :ok} = :mnesia.clear_table(@device_index_table)
    rescue
      _ -> :ok
    end
    # Clear group membership index if it exists
    try do
      {:atomic, :ok} = :mnesia.clear_table(@group_index_table)
    rescue
      _ -> :ok
    end
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

    # Pubkey index: maps pubkey_hex (lowercase) → name for O(1) lookups
    create_table(
      @pubkey_index_table,
      [{:attributes, [:pubkey_hex, :name]}, {:type, :set}, {storage_mode, [node()]}]
    )

    # Device-owner index: maps owner_name → device_name for device-by-user lookups
    # Uses :bag type because one owner can have multiple devices
    create_table(
      @device_index_table,
      [{:attributes, [:owner, :device_name]}, {:type, :bag}, {storage_mode, [node()]}]
    )

    # Group membership index: maps user_name → group_name for group-by-user lookups
    # Uses :bag type because one user can be in multiple groups
    create_table(
      @group_index_table,
      [{:attributes, [:user, :group_name]}, {:type, :bag}, {storage_mode, [node()]}]
    )

    # Wait for tables to be loaded (important on restart with disc_copies)
    :ok = :mnesia.wait_for_tables([@records_table, @revoked_table, @pubkey_index_table, @device_index_table, @group_index_table], 10_000)
  end

  defp create_table(name, opts) do
    case :mnesia.create_table(name, opts) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, ^name}} -> :ok
      {:aborted, reason} -> raise "Failed to create Mnesia table #{name}: #{inspect(reason)}"
    end
  end

  # Maintain pubkey index on insert of KEY records.
  # Maps pubkey_hex (lowercase) → name for O(1) pubkey lookups.
  # Defensive: if the index table doesn't exist yet (e.g., in tests
  # that bypass full app startup), silently skip indexing.
  defp index_pubkey(%Record{type: :key, name: name, data: data}) do
    pubkey = Map.get(data, :public_key) || Map.get(data, "public_key")

    if pubkey do
      pk_lower = String.downcase(pubkey)

      try do
        :mnesia.dirty_write({@pubkey_index_table, pk_lower, name})
      rescue
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end
  end

  defp index_pubkey(_), do: :ok

  # When a ZTLP_REVOKE record is inserted, extract all revoked IDs
  # and add them to the revocation table for O(1) lookup.
  # Handles both atom keys (from constructors) and string keys (from CBOR decode).
  defp index_revocations(%Record{type: :revoke, data: data} = record) do
    ids = Map.get(data, :revoked_ids) || Map.get(data, "revoked_ids") || []

    Enum.each(ids, fn id ->
      :mnesia.dirty_write({@revoked_table, id, record})
    end)
  end

  defp index_revocations(_), do: :ok

  # Maintain device-owner index on insert of DEVICE records.
  # Maps owner → device_name for device-by-user lookups.
  # If the device has no owner (empty string), skip indexing.
  defp index_device_owner(%Record{type: :device, name: device_name, data: data}) do
    owner = Map.get(data, :owner) || Map.get(data, "owner")

    if owner && owner != "" do
      try do
        # Remove any stale index entries for this device
        # (in case the owner changed)
        existing = :mnesia.dirty_match_object({@device_index_table, :_, device_name})

        Enum.each(existing, fn entry ->
          :mnesia.dirty_delete_object(entry)
        end)

        :mnesia.dirty_write({@device_index_table, owner, device_name})
      rescue
        _ -> :ok
      catch
        :exit, _ -> :ok
      end
    end
  end

  defp index_device_owner(_), do: :ok

  # Maintain group membership index on insert of GROUP records.
  # Maps user → group_name for group-by-user lookups.
  # Rebuilds the index for this group on each update (handles member changes).
  defp index_group_members(%Record{type: :group, name: group_name, data: data}) do
    members = Map.get(data, :members) || Map.get(data, "members") || []

    try do
      # Remove stale index entries for this group
      # (in case members changed on update)
      all_entries = :mnesia.dirty_match_object({@group_index_table, :_, group_name})

      Enum.each(all_entries, fn entry ->
        :mnesia.dirty_delete_object(entry)
      end)

      # Add new index entries for each member
      Enum.each(members, fn member ->
        :mnesia.dirty_write({@group_index_table, member, group_name})
      end)
    rescue
      _ -> :ok
    catch
      :exit, _ -> :ok
    end
  end

  defp index_group_members(_), do: :ok
end
