defmodule ZtlpGateway.UdpBackend do
  @moduledoc """
  UDP backend connector for the ZTLP Gateway.

  Egress counterpart of `ZtlpGateway.Backend` (TCP). Forwards decrypted
  ZTLP payloads to a backend service that speaks plain UDP — typical
  examples are DNS-over-UDP, NTP, syslog, or a UDP game server.

  ## Lifecycle (Model A — request-response)

  1. `start_link({host, port, owner})` opens an ephemeral UDP socket
     (`:gen_udp.open(0, [:binary, active: :once])`) and monitors `owner`.
  2. `send_data(pid, payload)` calls `:gen_udp.send/4` to the configured
     `{host, port}`. A per-call timeout timer is armed.
  3. The first reply on the socket is forwarded to the owner as
     `{:backend_data, data}` — same message shape as the TCP backend so
     the upstream Session GenServer can stay protocol-agnostic.
  4. If the timeout fires before a reply arrives, the owner gets
     `:backend_timeout` and the backend stops.
  5. If the owner dies, the backend closes the socket and stops.

  Optional opts (4-tuple form):

      {host, port, owner, [timeout_ms: 5_000]}

  Defaults:
    * `:timeout_ms` — 5_000 (5 seconds; per-call reply timeout)

  ## Why no pool

  UDP has no notion of a connection, so there is nothing to pool. Each
  session gets a fresh ephemeral local port for source-port isolation
  (matches what every stub DNS resolver does). The kernel reclaims the
  port when the GenServer exits.

  ## Out of scope

  * Multi-reply streaming UDP backends (VoIP RTP, game traffic).
    Use a future "Model B" UdpBackend variant for that — it would keep
    the socket open across many request/reply cycles and not auto-stop
    on the first reply.
  * Source-port preservation across retries. Each `start_link` gets a
    new random ephemeral port; retries within the same session reuse
    the same backend pid and therefore the same port, but separate
    sessions will not.
  """

  use GenServer

  require Logger

  # Default per-call reply timeout. UDP has no in-band notion of "the
  # backend is unreachable", so we have to bound the wait or the owning
  # Session would leak GenServers across never-responding backends.
  @default_timeout_ms 5_000

  # ── Client API ──────────────────────────────────────────────────

  @typedoc "IPv4 or IPv6 tuple as expected by `:gen_udp.send/4`."
  @type host :: :inet.ip_address() | charlist()

  @doc """
  Start a UDP backend connector.

  ## Forms

      start_link({host, port, owner})
      start_link({host, port, owner, opts})

  `opts` is a keyword list:
    * `:timeout_ms` (integer, default 5_000) — how long to wait for the
      first reply after `send_data/2`. On timeout the owner gets
      `:backend_timeout` and the backend stops.

  Returns `{:ok, pid}` on success, `{:error, reason}` if the UDP socket
  cannot be opened.
  """
  @spec start_link({host, non_neg_integer(), pid()}) :: GenServer.on_start()
  def start_link({host, port, owner}) do
    GenServer.start_link(__MODULE__, {host, port, owner, []})
  end

  @spec start_link({host, non_neg_integer(), pid(), keyword()}) :: GenServer.on_start()
  def start_link({host, port, owner, opts}) when is_list(opts) do
    GenServer.start_link(__MODULE__, {host, port, owner, opts})
  end

  @doc """
  Send a UDP datagram to the configured backend.

  Returns `:ok` on success, `{:error, reason}` if the socket is closed
  or the send fails. Safe to call on a dead pid — the `:exit` is trapped
  via `:catch` and returned as `{:error, :noproc}`.
  """
  @spec send_data(pid(), iodata()) :: :ok | {:error, term()}
  def send_data(pid, data) do
    GenServer.call(pid, {:send, data})
  catch
    :exit, _ -> {:error, :noproc}
  end

  @doc "Close the UDP backend (releases the ephemeral local socket)."
  @spec close(pid()) :: :ok
  def close(pid) do
    GenServer.cast(pid, :close)
  end

  # ── GenServer callbacks ─────────────────────────────────────────

  @impl true
  def init({host, port, owner, opts}) do
    case :gen_udp.open(0, [:binary, active: :once]) do
      {:ok, socket} ->
        # Monitor the owner so we can free the socket if it dies — there
        # is no peer-side "close" event in UDP to drive cleanup otherwise.
        Process.monitor(owner)

        state = %{
          socket: socket,
          host: host,
          port: port,
          owner: owner,
          timeout_ms: Keyword.get(opts, :timeout_ms, @default_timeout_ms),
          # Reference for the current in-flight reply timer (nil if idle).
          timer_ref: nil
        }

        {:ok, state}

      {:error, reason} ->
        {:stop, {:udp_open_failed, reason}}
    end
  end

  # Send a datagram. Arm the reply timer; cancel any previous one to
  # avoid spurious :backend_timeout messages when the caller pipelines
  # multiple queries on the same backend.
  @impl true
  def handle_call({:send, data}, _from, state) do
    state = cancel_timer(state)

    case :gen_udp.send(state.socket, state.host, state.port, data) do
      :ok ->
        ref = Process.send_after(self(), :reply_timeout, state.timeout_ms)
        {:reply, :ok, %{state | timer_ref: ref}}

      {:error, _reason} = err ->
        {:reply, err, state}
    end
  end

  @impl true
  def handle_cast(:close, %{socket: socket} = state) do
    :gen_udp.close(socket)
    {:stop, :normal, state}
  end

  # Inbound datagram from the backend. Forward to the owner with the same
  # message shape used by the TCP backend (`{:backend_data, data}`) and
  # cancel the reply timer. Re-arm active: :once so we can accept any
  # follow-up datagrams the owner pipelines (the timer governs the next
  # one — fresh send_data resets it).
  @impl true
  def handle_info({:udp, socket, _ip, _port, data}, %{socket: socket} = state) do
    send(state.owner, {:backend_data, data})
    :inet.setopts(socket, active: :once)
    {:noreply, cancel_timer(state)}
  end

  # Reply timeout fired before any datagram came back. Notify the owner
  # and stop — there is no useful state to keep after a UDP backend has
  # gone silent on us.
  def handle_info(:reply_timeout, %{owner: owner, socket: socket} = state) do
    send(owner, :backend_timeout)
    :gen_udp.close(socket)
    {:stop, :normal, %{state | timer_ref: nil}}
  end

  # Owner died — release the socket and stop.
  def handle_info({:DOWN, _ref, :process, _pid, _reason}, %{socket: socket} = state) do
    :gen_udp.close(socket)
    {:stop, :normal, state}
  end

  # Defensive: catch the (very unlikely) :udp_error message and log it.
  # `:gen_udp` does not deliver this for most failure modes — UDP is
  # connectionless — but ICMP "port unreachable" can surface here on
  # some OSes when the local socket has been `connect`ed (we don't, but
  # be safe).
  def handle_info({:udp_error, _socket, reason}, %{owner: owner} = state) do
    Logger.error("[UdpBackend] UDP error: #{inspect(reason)}")
    send(owner, {:backend_error, reason})
    {:stop, {:udp_error, reason}, state}
  end

  # Any other unexpected info message — log and ignore. Don't crash the
  # session over noise.
  def handle_info(other, state) do
    Logger.debug("[UdpBackend] ignoring unexpected message: #{inspect(other)}")
    {:noreply, state}
  end

  # ── Internal helpers ────────────────────────────────────────────

  defp cancel_timer(%{timer_ref: nil} = state), do: state

  defp cancel_timer(%{timer_ref: ref} = state) do
    # `Process.cancel_timer/1` returns ms remaining or false. We don't
    # care which — we only want to make sure no stale :reply_timeout
    # message arrives after we have already received a reply.
    _ = Process.cancel_timer(ref)
    # Drain any already-delivered :reply_timeout message that the cancel
    # raced against. `flush` is intentionally non-blocking with `after 0`.
    receive do
      :reply_timeout -> :ok
    after
      0 -> :ok
    end

    %{state | timer_ref: nil}
  end
end
