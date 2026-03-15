defmodule ZtlpNs.Audit do
  @moduledoc """
  Bounded audit log for ZTLP-NS identity operations.

  ETS-backed ring buffer that keeps the last N entries (default 10,000).
  Each entry records a timestamp, action, entity name, record type, and details.

  ## Actions

  - `:registered` — a new record was registered
  - `:revoked` — an entity was revoked
  - `:updated` — an existing record was updated (serial bump)
  - `:queried` — a record was queried (optional, disabled by default)

  ## Usage

      ZtlpNs.Audit.log(:registered, "laptop.ztlp", :device, %{by: "zone-admin"})
      ZtlpNs.Audit.since(System.system_time(:second) - 3600)
      ZtlpNs.Audit.filter("steve@*")
  """

  use GenServer

  @table :ztlp_ns_audit_log
  @counter :ztlp_ns_audit_counter
  @default_max_entries 10_000

  # ── Public API ─────────────────────────────────────────────────────

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Log an audit entry.

  ## Parameters
  - `action` — one of `:registered`, `:revoked`, `:updated`, `:queried`
  - `name` — the entity name (e.g. "laptop.ztlp", "steve@zone.ztlp")
  - `type` — the record type atom (e.g. `:device`, `:user`, `:group`, `:key`)
  - `details` — map of additional details (e.g. reason, signer, etc.)
  """
  @spec log(atom(), String.t(), atom(), map()) :: :ok
  def log(action, name, type, details \\ %{}) do
    timestamp = System.system_time(:second)
    entry = {timestamp, action, name, type, details}

    max_entries = max_entries()
    index = :atomics.add_get(counter_ref(), 1, 1)
    slot = rem(index - 1, max_entries)
    :ets.insert(@table, {slot, entry})
    :ok
  rescue
    # Table or counter may not exist (e.g., if Audit isn't started)
    _ -> :ok
  catch
    :exit, _ -> :ok
  end

  @doc """
  Return all audit entries since the given Unix timestamp.

  Returns a list of `{timestamp, action, name, type, details}` tuples,
  sorted from oldest to newest.
  """
  @spec since(integer()) :: [tuple()]
  def since(since_timestamp) do
    all_entries()
    |> Enum.filter(fn {ts, _action, _name, _type, _details} -> ts >= since_timestamp end)
    |> Enum.sort_by(fn {ts, _, _, _, _} -> ts end)
  end

  @doc """
  Filter audit entries by name pattern.

  Supports glob-style wildcards:
  - `"steve@*"` matches any name starting with `"steve@"`
  - `"*.ztlp"` matches any name ending with `".ztlp"`
  - `"*admin*"` matches any name containing `"admin"`

  Returns a list of matching entries sorted by timestamp.
  """
  @spec filter(String.t()) :: [tuple()]
  def filter(pattern) do
    regex = pattern_to_regex(pattern)

    all_entries()
    |> Enum.filter(fn {_ts, _action, name, _type, _details} ->
      Regex.match?(regex, name)
    end)
    |> Enum.sort_by(fn {ts, _, _, _, _} -> ts end)
  end

  @doc """
  Filter audit entries by name pattern, only returning entries since the given timestamp.
  """
  @spec filter_since(String.t(), integer()) :: [tuple()]
  def filter_since(pattern, since_timestamp) do
    regex = pattern_to_regex(pattern)

    all_entries()
    |> Enum.filter(fn {ts, _action, name, _type, _details} ->
      ts >= since_timestamp and Regex.match?(regex, name)
    end)
    |> Enum.sort_by(fn {ts, _, _, _, _} -> ts end)
  end

  @doc "Return all audit entries sorted by timestamp."
  @spec all() :: [tuple()]
  def all do
    all_entries()
    |> Enum.sort_by(fn {ts, _, _, _, _} -> ts end)
  end

  @doc "Return the number of audit entries currently stored."
  @spec count() :: non_neg_integer()
  def count do
    :ets.info(@table, :size) || 0
  rescue
    _ -> 0
  catch
    :exit, _ -> 0
  end

  @doc "Clear all audit entries."
  @spec clear() :: :ok
  def clear do
    if :ets.whereis(@table) != :undefined do
      :ets.delete_all_objects(@table)
    end

    try do
      :atomics.put(counter_ref(), 1, 0)
    rescue
      _ -> :ok
    end

    :ok
  rescue
    _ -> :ok
  catch
    :exit, _ -> :ok
  end

  # ── GenServer Callbacks ────────────────────────────────────────────

  @impl true
  def init(opts) do
    max = Keyword.get(opts, :max_entries, @default_max_entries)

    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:named_table, :set, :public, write_concurrency: true])
    end

    # Use a persistent term for the atomics counter reference
    counter = :atomics.new(1, signed: false)
    :persistent_term.put(@counter, counter)

    # Store max_entries in persistent term for fast access
    :persistent_term.put({@counter, :max}, max)

    {:ok, %{max_entries: max}}
  end

  # ── Private Helpers ────────────────────────────────────────────────

  defp counter_ref do
    :persistent_term.get(@counter)
  end

  defp max_entries do
    :persistent_term.get({@counter, :max}, @default_max_entries)
  rescue
    _ -> @default_max_entries
  end

  defp all_entries do
    if :ets.whereis(@table) == :undefined do
      []
    else
      :ets.tab2list(@table)
      |> Enum.map(fn {_slot, entry} -> entry end)
    end
  rescue
    _ -> []
  catch
    :exit, _ -> []
  end

  defp pattern_to_regex(pattern) do
    escaped =
      pattern
      |> Regex.escape()
      |> String.replace("\\*", ".*")

    Regex.compile!("^#{escaped}$")
  end
end
