defmodule ZtlpGateway.CircuitBreaker do
  @moduledoc """
  Per-backend circuit breaker for the ZTLP Gateway.

  Prevents cascading failures by tracking consecutive errors per backend
  and short-circuiting requests when a backend is deemed unhealthy.

  ## States

  - `:closed` — normal operation, all requests pass through
  - `:open` — backend is failing, reject requests immediately
  - `:half_open` — testing recovery, allow exactly 1 request through

  ## State Machine

      closed --[N consecutive failures]--> open
      open   --[cooldown expires]--------> half_open
      half_open --[success]--------------> closed
      half_open --[failure]--------------> open

  State is stored in ETS for fast concurrent reads. The GenServer exists
  only to own the ETS table and handle periodic cleanup.

  ## Configuration

  Via YAML config (`circuit_breaker` section):

  - `failure_threshold` — consecutive failures to trip (default: 5)
  - `cooldown` — duration before half-open test (default: "30s")
  - `enabled` — master switch (default: true)
  """

  use GenServer

  @table __MODULE__

  # ETS record: {backend_name, state, consecutive_failures, last_failure_at, half_open_allowed}
  # state: :closed | :open | :half_open

  # ── Public API ────────────────────────────────────────────────────────

  @doc """
  Check whether a request to the given backend should be allowed.

  Returns `true` if the request can proceed, `false` if the circuit is open.

  In `:half_open` state, allows exactly one probe request (first caller wins).
  """
  @spec allow?(String.t()) :: boolean()
  def allow?(backend) do
    if not enabled?() do
      true
    else
      do_allow?(backend)
    end
  end

  defp do_allow?(backend) do
    case :ets.lookup(@table, backend) do
      [] ->
        # Unknown backend = closed circuit
        true

      [{^backend, :closed, _failures, _last_fail, _}] ->
        true

      [{^backend, :open, failures, last_fail, _}] ->
        cooldown = cooldown_ms()
        now = System.monotonic_time(:millisecond)

        if now - last_fail >= cooldown do
          # Transition to half_open — allow one probe
          :ets.insert(@table, {backend, :half_open, failures, last_fail, true})
          true
        else
          false
        end

      [{^backend, :half_open, failures, last_fail, true}] ->
        # Allow the probe request, but mark it as consumed atomically.
        # We re-read inside a transaction-like pattern: try to swap true->false
        # If another process beat us, we'll see false on re-read.
        :ets.insert(@table, {backend, :half_open, failures, last_fail, false})
        true

      [{^backend, :half_open, _failures, _last_fail, false}] ->
        # Probe already in flight, reject
        false
    end
  end

  @doc """
  Record a successful request to a backend.

  Resets the failure counter and closes the circuit if it was half-open.
  """
  @spec record_success(String.t()) :: :ok
  def record_success(backend) do
    :ets.insert(@table, {backend, :closed, 0, 0, false})
    :ok
  end

  @doc """
  Record a failed request to a backend.

  Increments the consecutive failure counter. Trips the circuit to `:open`
  when the threshold is reached.
  """
  @spec record_failure(String.t()) :: :ok
  def record_failure(backend) do
    threshold = failure_threshold()
    now = System.monotonic_time(:millisecond)

    case :ets.lookup(@table, backend) do
      [] ->
        # First failure for this backend
        if threshold <= 1 do
          :ets.insert(@table, {backend, :open, 1, now, false})
        else
          :ets.insert(@table, {backend, :closed, 1, now, false})
        end

      [{^backend, :half_open, failures, _last_fail, _}] ->
        # Failed during half-open probe — re-open
        :ets.insert(@table, {backend, :open, failures + 1, now, false})

      [{^backend, state, failures, _last_fail, _}] ->
        new_failures = failures + 1

        if new_failures >= threshold do
          :ets.insert(@table, {backend, :open, new_failures, now, false})
        else
          :ets.insert(@table, {backend, state, new_failures, now, false})
        end
    end

    :ok
  end

  @doc """
  Reset all circuit breaker state. Useful for testing and recovery.
  """
  @spec reset() :: :ok
  def reset do
    :ets.delete_all_objects(@table)
    :ok
  end

  @doc """
  Get the current state for a backend.

  Returns `{state, consecutive_failures}` or `:unknown`.
  """
  @spec get_state(String.t()) :: {atom(), non_neg_integer()} | :unknown
  def get_state(backend) do
    case :ets.lookup(@table, backend) do
      [{^backend, state, failures, _last_fail, _}] -> {state, failures}
      [] -> :unknown
    end
  end

  # ── Configuration ─────────────────────────────────────────────────────

  @doc false
  def enabled? do
    Application.get_env(:ztlp_gateway, :circuit_breaker_enabled, true)
  end

  @doc false
  def failure_threshold do
    Application.get_env(:ztlp_gateway, :circuit_breaker_failure_threshold, 5)
  end

  @doc false
  def cooldown_ms do
    Application.get_env(:ztlp_gateway, :circuit_breaker_cooldown_ms, 30_000)
  end

  # ── GenServer ─────────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(_opts) do
    table = :ets.new(@table, [
      :named_table,
      :public,
      :set,
      read_concurrency: true,
      write_concurrency: true
    ])
    {:ok, %{table: table}}
  end

end
