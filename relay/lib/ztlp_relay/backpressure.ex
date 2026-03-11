defmodule ZtlpRelay.Backpressure do
  @moduledoc """
  Connection backpressure for the ZTLP Relay.

  Tracks current load as the ratio of active sessions to max_sessions
  and provides a fast `check/0` call for the UDP listener to gate
  new session requests.

  ## Thresholds

  - **Soft** (default 80%): new sessions get a "busy" / backoff response
  - **Hard** (default 95%): all new sessions are rejected outright

  State is stored in ETS for fast concurrent reads on the hot path.
  The GenServer exists only to own the ETS table and provide an API
  for updating the load metric.

  ## Configuration

  Via YAML config or application environment:

  - `backpressure.soft_threshold` — fraction (0.0–1.0), default 0.8
  - `backpressure.hard_threshold` — fraction (0.0–1.0), default 0.95
  """

  use GenServer

  @table __MODULE__
  @load_key :current_load

  # ── Public API ────────────────────────────────────────────────────────

  @doc """
  Check current backpressure state.

  Returns:
  - `:ok` — load is below soft threshold, accept new sessions
  - `{:backpressure, :soft}` — load is between soft and hard thresholds
  - `{:backpressure, :hard}` — load is above hard threshold, reject new sessions
  """
  @spec check() :: :ok | {:backpressure, :soft} | {:backpressure, :hard}
  def check do
    load = current_load()
    {soft, hard} = thresholds()

    cond do
      load >= hard -> {:backpressure, :hard}
      load >= soft -> {:backpressure, :soft}
      true -> :ok
    end
  end

  @doc """
  Update the current load ratio.

  Called by the session registry or stats module when session count changes.
  `active` is the number of active sessions, `max` is the configured maximum.
  """
  @spec update_load(non_neg_integer(), pos_integer()) :: :ok
  def update_load(active, max) when max > 0 do
    ratio = active / max
    :ets.insert(@table, {@load_key, ratio})
    :ok
  end

  @doc """
  Get the current load ratio (0.0–1.0+).
  """
  @spec current_load() :: float()
  def current_load do
    case :ets.lookup(@table, @load_key) do
      [{@load_key, ratio}] -> ratio
      [] -> 0.0
    end
  end

  @doc """
  Get the configured thresholds as `{soft, hard}`.
  """
  @spec thresholds() :: {float(), float()}
  def thresholds do
    soft = Application.get_env(:ztlp_relay, :backpressure_soft_threshold, 0.8)
    hard = Application.get_env(:ztlp_relay, :backpressure_hard_threshold, 0.95)
    {soft, hard}
  end

  # ── GenServer ─────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    :ets.insert(table, {@load_key, 0.0})
    {:ok, %{table: table}}
  end
end
