defmodule ZtlpRelay.RelayRegistry do
  @moduledoc """
  ETS-backed registry of known relay nodes in the mesh.

  Tracks relay node_id, address, role, metrics, last_seen time, and
  status. Provides lookups by node_id or role. Runs a periodic cleanup
  sweep to expire stale relays (>120s → :stale, >300s → removed).

  Also tracks relay health states (`:healthy`, `:degraded`, `:unreachable`)
  with hysteresis for recovery transitions.

  Backed by a GenServer for lifecycle management and periodic sweeps.
  """

  use GenServer

  require Logger

  @table_name :ztlp_relay_registry
  @sweep_interval_ms 30_000
  @stale_threshold_ms 120_000
  @remove_threshold_ms 300_000

  @type relay_role :: :ingress | :transit | :service | :all
  @type relay_status :: :active | :stale
  @type health_state :: :healthy | :degraded | :unreachable

  # Health state thresholds
  @healthy_loss_max 0.05
  @healthy_rtt_max 500.0
  @degraded_loss_max 0.25
  @degraded_rtt_max 2000.0

  @type relay_info :: %{
    node_id: binary(),
    address: {:inet.ip_address(), :inet.port_number()},
    role: relay_role(),
    metrics: map(),
    last_seen: integer(),
    status: relay_status()
  }

  # Client API

  @doc """
  Start the relay registry GenServer.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Register a relay in the mesh registry.

  `relay_info` must contain at least `:node_id`, `:address`, and `:role`.
  Missing fields default to: metrics = %{}, status = :active, last_seen = now.
  """
  @spec register(relay_info()) :: :ok
  def register(relay_info) do
    now = System.monotonic_time(:millisecond)

    entry = {
      relay_info.node_id,
      relay_info.address,
      relay_info[:role] || :all,
      relay_info[:metrics] || %{},
      relay_info[:last_seen] || now,
      relay_info[:status] || :active
    }

    :ets.insert(@table_name, entry)
    :ok
  end

  @doc """
  Unregister a relay by node_id.
  """
  @spec unregister(binary()) :: :ok
  def unregister(node_id) do
    :ets.delete(@table_name, node_id)
    :ok
  end

  @doc """
  Look up a specific relay by node_id.

  Returns `{:ok, relay_info}` or `:error`.
  """
  @spec lookup(binary()) :: {:ok, relay_info()} | :error
  def lookup(node_id) do
    case :ets.lookup(@table_name, node_id) do
      [{^node_id, address, role, metrics, last_seen, status}] ->
        {:ok, %{
          node_id: node_id,
          address: address,
          role: role,
          metrics: metrics,
          last_seen: last_seen,
          status: status
        }}

      [] ->
        :error
    end
  end

  @doc """
  Get all known relays.
  """
  @spec get_all() :: [relay_info()]
  def get_all do
    :ets.tab2list(@table_name)
    |> Enum.map(&entry_to_map/1)
  end

  @doc """
  Get relays filtered by role.

  If `role` is `:all`, returns relays with role `:all`.
  A relay with role `:all` matches any role query.
  """
  @spec get_by_role(relay_role()) :: [relay_info()]
  def get_by_role(role) do
    :ets.tab2list(@table_name)
    |> Enum.filter(fn {_nid, _addr, r, _m, _ls, _s} ->
      r == role or r == :all
    end)
    |> Enum.map(&entry_to_map/1)
  end

  @doc """
  Update metrics for a relay and refresh its last_seen timestamp.
  """
  @spec update_metrics(binary(), map()) :: :ok | :error
  def update_metrics(node_id, metrics) do
    now = System.monotonic_time(:millisecond)

    case :ets.lookup(@table_name, node_id) do
      [{^node_id, address, role, _old_metrics, _last_seen, _status}] ->
        :ets.insert(@table_name, {node_id, address, role, metrics, now, :active})
        :ok

      [] ->
        :error
    end
  end

  @doc """
  Touch a relay — update last_seen and set status to :active.
  """
  @spec touch(binary()) :: :ok | :error
  def touch(node_id) do
    now = System.monotonic_time(:millisecond)

    case :ets.lookup(@table_name, node_id) do
      [{^node_id, address, role, metrics, _last_seen, _status}] ->
        :ets.insert(@table_name, {node_id, address, role, metrics, now, :active})
        :ok

      [] ->
        :error
    end
  end

  @doc """
  Count the number of registered relays.
  """
  @spec count() :: non_neg_integer()
  def count do
    :ets.info(@table_name, :size)
  end

  # ── Health State Tracking ──

  @doc """
  Get the health state of a relay.

  Returns `:healthy`, `:degraded`, or `:unreachable`.
  If the relay has no health record, returns `:healthy` (optimistic default).
  """
  @spec get_health(binary()) :: health_state()
  def get_health(node_id) do
    case :ets.lookup(:ztlp_relay_health, node_id) do
      [{^node_id, health, _good_streak}] -> health
      [] -> :healthy
    end
  rescue
    ArgumentError -> :healthy
  end

  @doc """
  Update the health state for a relay based on current metrics and probe history.

  Uses hysteresis: recovering from `:degraded` to `:healthy` requires
  3 consecutive good pings.
  """
  @spec update_health(binary(), keyword()) :: health_state()
  def update_health(node_id, opts) do
    loss_rate = Keyword.get(opts, :loss_rate, 0.0)
    rtt_ms = Keyword.get(opts, :rtt_ms, 0.0)
    missed_sweeps = Keyword.get(opts, :missed_sweeps, 0)
    pong_received = Keyword.get(opts, :pong_received, false)

    current = get_health(node_id)
    current_good_streak = get_good_streak(node_id)

    new_health = compute_health_transition(
      current, loss_rate, rtt_ms, missed_sweeps, pong_received, current_good_streak
    )

    new_good_streak = if pong_received and is_good_probe?(loss_rate, rtt_ms) do
      current_good_streak + 1
    else
      if pong_received, do: 0, else: current_good_streak
    end

    try do
      :ets.insert(:ztlp_relay_health, {node_id, new_health, new_good_streak})
    rescue
      ArgumentError -> :ok
    end

    new_health
  end

  @doc """
  Remove health tracking for a relay.
  """
  @spec remove_health(binary()) :: :ok
  def remove_health(node_id) do
    try do
      :ets.delete(:ztlp_relay_health, node_id)
    rescue
      ArgumentError -> :ok
    end
    :ok
  end

  @doc """
  Classify health state from metrics (without hysteresis).
  """
  @spec classify_health(float(), float(), non_neg_integer()) :: health_state()
  def classify_health(loss_rate, rtt_ms, missed_sweeps) do
    cond do
      missed_sweeps >= 3 -> :unreachable
      loss_rate > @degraded_loss_max -> :unreachable
      loss_rate > @healthy_loss_max or rtt_ms > @healthy_rtt_max ->
        if rtt_ms > @degraded_rtt_max, do: :unreachable, else: :degraded
      true -> :healthy
    end
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    table_name = Keyword.get(opts, :table_name, @table_name)

    table = :ets.new(table_name, [
      :named_table,
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])

    # Create health tracking table if it doesn't exist
    try do
      :ets.new(:ztlp_relay_health, [
        :named_table,
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])
    rescue
      ArgumentError -> :ok  # Table already exists
    end

    sweep_interval = Keyword.get(opts, :sweep_interval_ms, @sweep_interval_ms)
    schedule_sweep(sweep_interval)

    {:ok, %{
      table: table,
      sweep_interval: sweep_interval,
      stale_threshold: Keyword.get(opts, :stale_threshold_ms, @stale_threshold_ms),
      remove_threshold: Keyword.get(opts, :remove_threshold_ms, @remove_threshold_ms)
    }}
  end

  @impl true
  def handle_info(:sweep, state) do
    sweep(state)
    schedule_sweep(state.sweep_interval)
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # Internal helpers

  defp get_good_streak(node_id) do
    case :ets.lookup(:ztlp_relay_health, node_id) do
      [{^node_id, _health, good_streak}] -> good_streak
      [] -> 0
    end
  rescue
    ArgumentError -> 0
  end

  defp is_good_probe?(loss_rate, rtt_ms) do
    loss_rate < @healthy_loss_max and rtt_ms < @healthy_rtt_max
  end

  defp compute_health_transition(current, loss_rate, rtt_ms, missed_sweeps, pong_received, good_streak) do
    raw_health = classify_health(loss_rate, rtt_ms, missed_sweeps)

    case {current, raw_health} do
      {:healthy, new} -> new
      {:degraded, :healthy} ->
        if pong_received and good_streak + 1 >= 3, do: :healthy, else: :degraded
      {:degraded, new} -> new
      {:unreachable, :healthy} ->
        if pong_received and good_streak + 1 >= 3, do: :healthy, else: :degraded
      {:unreachable, :degraded} ->
        if pong_received, do: :degraded, else: :unreachable
      {:unreachable, :unreachable} -> :unreachable
    end
  end

  defp sweep(state) do
    now = System.monotonic_time(:millisecond)

    :ets.tab2list(@table_name)
    |> Enum.each(fn {node_id, address, role, metrics, last_seen, _status} ->
      age = now - last_seen

      cond do
        age > state.remove_threshold ->
          Logger.debug("Removing expired relay #{inspect(node_id)}")
          :ets.delete(@table_name, node_id)

        age > state.stale_threshold ->
          :ets.insert(@table_name, {node_id, address, role, metrics, last_seen, :stale})

        true ->
          :ok
      end
    end)
  end

  defp schedule_sweep(interval) do
    Process.send_after(self(), :sweep, interval)
  end

  defp entry_to_map({node_id, address, role, metrics, last_seen, status}) do
    %{
      node_id: node_id,
      address: address,
      role: role,
      metrics: metrics,
      last_seen: last_seen,
      status: status
    }
  end
end
