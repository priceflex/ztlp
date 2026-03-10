defmodule ZtlpRelay.SessionRegistry do
  @moduledoc """
  ETS-backed session routing table.

  Maps SessionID (12 bytes) → {peer_a_addr, peer_b_addr, session_pid}.

  Provides O(1) lookups for the pipeline Layer 2 check and for relay
  forwarding (finding the other peer's address given a SessionID and
  the sender's address).
  """

  use GenServer

  @table_name :ztlp_session_registry

  @type peer_addr :: {:inet.ip_address(), :inet.port_number()}
  @type session_entry :: {peer_addr(), peer_addr(), pid() | nil}

  # Client API

  @doc """
  Start the session registry.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(_opts \\ []) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @doc """
  Register a session mapping SessionID to two peers.

  `session_id` is a 12-byte binary.
  `peer_a` and `peer_b` are `{ip, port}` tuples.
  `session_pid` is the PID of the Session GenServer (or nil for pending).
  """
  @spec register_session(binary(), peer_addr(), peer_addr(), pid() | nil) :: :ok
  def register_session(session_id, peer_a, peer_b, session_pid \\ nil)
      when byte_size(session_id) == 12 do
    :ets.insert(@table_name, {session_id, peer_a, peer_b, session_pid})
    :ok
  end

  @doc """
  Unregister a session.
  """
  @spec unregister_session(binary()) :: :ok
  def unregister_session(session_id) when byte_size(session_id) == 12 do
    :ets.delete(@table_name, session_id)
    :ok
  end

  @doc """
  Look up a session by its ID.

  Returns `{:ok, {peer_a, peer_b, session_pid}}` or `:error`.
  """
  @spec lookup_session(binary()) :: {:ok, session_entry()} | :error
  def lookup_session(session_id) when byte_size(session_id) == 12 do
    case :ets.lookup(@table_name, session_id) do
      [{^session_id, peer_a, peer_b, session_pid}] ->
        {:ok, {peer_a, peer_b, session_pid}}

      [] ->
        :error
    end
  end

  @doc """
  Check if a session exists (fast path for pipeline Layer 2).
  """
  @spec session_exists?(binary()) :: boolean()
  def session_exists?(session_id) when byte_size(session_id) == 12 do
    :ets.member(@table_name, session_id)
  end

  @doc """
  Look up the other peer's address given a SessionID and the sender's address.

  If `sender` matches `peer_a`, returns `{:ok, peer_b}` and vice versa.
  Returns `:error` if the session doesn't exist or the sender isn't a known peer.
  """
  @spec lookup_peer(binary(), peer_addr()) :: {:ok, peer_addr()} | :error
  def lookup_peer(session_id, sender) when byte_size(session_id) == 12 do
    case lookup_session(session_id) do
      {:ok, {peer_a, peer_b, _pid}} ->
        cond do
          sender == peer_a -> {:ok, peer_b}
          sender == peer_b -> {:ok, peer_a}
          true -> :error
        end

      :error ->
        :error
    end
  end

  @doc """
  Update the session_pid for an existing session.
  """
  @spec update_session_pid(binary(), pid()) :: :ok | :error
  def update_session_pid(session_id, pid) when byte_size(session_id) == 12 do
    case lookup_session(session_id) do
      {:ok, {peer_a, peer_b, _old_pid}} ->
        :ets.insert(@table_name, {session_id, peer_a, peer_b, pid})
        :ok

      :error ->
        :error
    end
  end

  @doc """
  Count the number of registered sessions.
  """
  @spec count() :: non_neg_integer()
  def count do
    :ets.info(@table_name, :size)
  end

  # GenServer callbacks

  @impl true
  def init([]) do
    table = :ets.new(@table_name, [
      :named_table,
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ])
    {:ok, %{table: table}}
  end
end
