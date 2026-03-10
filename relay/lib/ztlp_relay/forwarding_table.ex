defmodule ZtlpRelay.ForwardingTable do
  @moduledoc """
  ETS-backed learned routes cache for multi-hop relay forwarding.

  Caches recently successful routes so that subsequent packets for the
  same session can skip route planning and use the fast path.

  Cache entries map `session_id → path` (list of relay node_ids in order)
  and expire after a configurable timeout (default: session timeout).

  ## Usage

      ForwardingTable.put(session_id, path)
      ForwardingTable.get(session_id)  # => path or nil
      ForwardingTable.delete(session_id)
  """

  use GenServer

  require Logger

  @table_name :ztlp_forwarding_table
  @default_ttl_ms 300_000       # 5 minutes, same as session timeout
  @sweep_interval_ms 60_000     # sweep expired entries every 60s

  @type path_entry :: %{
    path: [binary()],
    inserted_at: integer(),
    ttl_ms: non_neg_integer()
  }

  # Client API

  @doc """
  Start the forwarding table GenServer.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Look up a cached path for a session.

  Returns the path (list of relay node_ids) or nil if not cached/expired.
  """
  @spec get(binary(), atom()) :: [binary()] | nil
  def get(session_id, table \\ @table_name) do
    now = System.monotonic_time(:millisecond)

    case :ets.lookup(table, session_id) do
      [{^session_id, path, inserted_at, ttl_ms}] ->
        if now - inserted_at <= ttl_ms do
          path
        else
          # Expired — clean up
          :ets.delete(table, session_id)
          nil
        end

      [] ->
        nil
    end
  end

  @doc """
  Cache a path for a session.

  `path` is a list of relay node_ids representing the forwarding path.

  ## Options
  - `:ttl_ms` — time to live in milliseconds (default: #{@default_ttl_ms})
  - `:table` — ETS table name (default: #{@table_name})
  """
  @spec put(binary(), [binary()], keyword()) :: :ok
  def put(session_id, path, opts \\ []) do
    ttl_ms = Keyword.get(opts, :ttl_ms, @default_ttl_ms)
    table = Keyword.get(opts, :table, @table_name)
    now = System.monotonic_time(:millisecond)
    :ets.insert(table, {session_id, path, now, ttl_ms})
    :ok
  end

  @doc """
  Delete a cached path for a session.
  """
  @spec delete(binary(), atom()) :: :ok
  def delete(session_id, table \\ @table_name) do
    :ets.delete(table, session_id)
    :ok
  end

  @doc """
  Count the number of cached entries (including potentially expired ones).
  """
  @spec count(atom()) :: non_neg_integer()
  def count(table \\ @table_name) do
    :ets.info(table, :size)
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    table_name = Keyword.get(opts, :table_name, @table_name)
    sweep_interval = Keyword.get(opts, :sweep_interval_ms, @sweep_interval_ms)

    :ets.new(table_name, [
      :named_table,
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    schedule_sweep(sweep_interval)

    {:ok, %{
      table_name: table_name,
      sweep_interval: sweep_interval
    }}
  end

  @impl true
  def handle_info(:sweep, state) do
    sweep(state.table_name)
    schedule_sweep(state.sweep_interval)
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Internal helpers

  defp sweep(table_name) do
    now = System.monotonic_time(:millisecond)

    :ets.tab2list(table_name)
    |> Enum.each(fn {session_id, _path, inserted_at, ttl_ms} ->
      if now - inserted_at > ttl_ms do
        :ets.delete(table_name, session_id)
      end
    end)
  end

  defp schedule_sweep(interval) do
    Process.send_after(self(), :sweep, interval)
  end
end
