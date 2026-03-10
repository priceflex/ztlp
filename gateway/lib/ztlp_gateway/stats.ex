defmodule ZtlpGateway.Stats do
  @moduledoc """
  Real-time gateway statistics using atomic counters.

  Tracks operational metrics without locking:
  - Active sessions (gauge — can go up and down)
  - Bytes received and sent (monotonic counters)
  - Handshakes completed and failed
  - Policy denials
  - Backend errors

  Uses `:counters` for lock-free concurrent updates.
  """

  use GenServer

  # Counter indices (1-based for :counters)
  @active_sessions 1
  @bytes_in 2
  @bytes_out 3
  @handshakes_ok 4
  @handshakes_fail 5
  @policy_denials 6
  @backend_errors 7
  @counter_count 7

  # ---------------------------------------------------------------------------
  # Client API
  # ---------------------------------------------------------------------------

  @doc "Start the stats counter."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Increment active sessions by 1."
  @spec session_opened() :: :ok
  def session_opened, do: add(@active_sessions, 1)

  @doc "Decrement active sessions by 1."
  @spec session_closed() :: :ok
  def session_closed, do: sub(@active_sessions, 1)

  @doc "Record bytes received from a ZTLP client."
  @spec bytes_received(non_neg_integer()) :: :ok
  def bytes_received(n), do: add(@bytes_in, n)

  @doc "Record bytes sent to a ZTLP client."
  @spec bytes_sent(non_neg_integer()) :: :ok
  def bytes_sent(n), do: add(@bytes_out, n)

  @doc "Record a successful handshake."
  @spec handshake_ok() :: :ok
  def handshake_ok, do: add(@handshakes_ok, 1)

  @doc "Record a failed handshake."
  @spec handshake_fail() :: :ok
  def handshake_fail, do: add(@handshakes_fail, 1)

  @doc "Record a policy denial."
  @spec policy_denied() :: :ok
  def policy_denied, do: add(@policy_denials, 1)

  @doc "Record a backend error."
  @spec backend_error() :: :ok
  def backend_error, do: add(@backend_errors, 1)

  @doc """
  Get a snapshot of all current counters.

  Returns a map with human-readable keys.
  """
  @spec snapshot() :: map()
  def snapshot do
    ref = get_ref()
    %{
      active_sessions: :counters.get(ref, @active_sessions),
      bytes_in: :counters.get(ref, @bytes_in),
      bytes_out: :counters.get(ref, @bytes_out),
      handshakes_ok: :counters.get(ref, @handshakes_ok),
      handshakes_fail: :counters.get(ref, @handshakes_fail),
      policy_denials: :counters.get(ref, @policy_denials),
      backend_errors: :counters.get(ref, @backend_errors)
    }
  end

  # ---------------------------------------------------------------------------
  # GenServer callbacks
  # ---------------------------------------------------------------------------

  @impl true
  def init(_opts) do
    ref = :counters.new(@counter_count, [:write_concurrency])
    :persistent_term.put({__MODULE__, :ref}, ref)
    {:ok, %{}}
  end

  # ---------------------------------------------------------------------------
  # Internal helpers
  # ---------------------------------------------------------------------------

  defp get_ref, do: :persistent_term.get({__MODULE__, :ref})

  defp add(index, value) do
    :counters.add(get_ref(), index, value)
    :ok
  end

  defp sub(index, value) do
    :counters.sub(get_ref(), index, value)
    :ok
  end
end
