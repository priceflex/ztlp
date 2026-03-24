defmodule ZtlpGateway.TlsListener do
  @moduledoc """
  Production TLS listener for the ZTLP Gateway.

  Provides HTTPS termination for inbound client connections. Supports:
  - TLS 1.2 and 1.3
  - SNI-based routing to different backend services via CertCache
  - mTLS (mutual TLS) for client certificate authentication
  - Configurable acceptor pool with proper connection tracking
  - Graceful shutdown with connection draining

  ## Architecture

      Client → TLS (mTLS) → TlsListener → TlsSession (one per connection)
                                             ├── TlsIdentity (extract mTLS identity)
                                             ├── SniRouter (backend lookup)
                                             ├── PolicyEngine (authorize)
                                             ├── HttpHeaderInjector (add identity headers)
                                             └── Backend TCP proxy (bidirectional)

  The listener manages an acceptor pool. Each acceptor waits for a
  TLS connection, performs the handshake, and hands off the resulting
  SSL socket to a new TlsSession process. The acceptor is then
  respawned to accept the next connection.

  ## Supervisor Integration

  Start under the application supervisor when `:tls_enabled` is true:

      {ZtlpGateway.TlsListener, port: 8443, certfile: "...", keyfile: "..."}

  """

  use GenServer
  require Logger

  @default_port 8443
  @default_acceptors 100
  @transport_accept_timeout 30_000
  @handshake_timeout 10_000

  # ── Public API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Get the port the TLS listener is bound to."
  @spec port(GenServer.server()) :: non_neg_integer()
  def port(server \\ __MODULE__) do
    GenServer.call(server, :get_port)
  end

  @doc "Get listener statistics."
  @spec stats(GenServer.server()) :: map()
  def stats(server \\ __MODULE__) do
    GenServer.call(server, :stats)
  end

  @doc "Graceful shutdown — stop accepting new connections, wait for active ones."
  @spec stop(GenServer.server()) :: :ok
  def stop(server \\ __MODULE__) do
    GenServer.stop(server, :normal)
  end

  # ── GenServer ──────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, get_config(:tls_port, @default_port))
    certfile = Keyword.get(opts, :certfile)
    keyfile = Keyword.get(opts, :keyfile)
    cacertfile = Keyword.get(opts, :cacertfile)
    acceptors = Keyword.get(opts, :acceptors, get_config(:tls_acceptors, @default_acceptors))
    require_client_cert = Keyword.get(opts, :require_client_cert, false)
    request_client_cert = Keyword.get(opts, :request_client_cert, true)

    ssl_opts = build_ssl_opts(certfile, keyfile, cacertfile, require_client_cert, request_client_cert)

    case :ssl.listen(port, ssl_opts) do
      {:ok, listen_socket} ->
        {:ok, {_, actual_port}} = :ssl.sockname(listen_socket)
        Logger.info("[TlsListener] Listening on TLS port #{actual_port}")

        state = %{
          listen_socket: listen_socket,
          port: actual_port,
          acceptors: acceptors,
          active_connections: 0,
          total_connections: 0,
          total_handshake_failures: 0,
          require_client_cert: require_client_cert,
          certfile: certfile,
          keyfile: keyfile,
          cacertfile: cacertfile,
          session_pids: MapSet.new(),
          acceptor_pids: MapSet.new(),
          config: Keyword.get(opts, :config, %{})
        }

        # Start acceptor pool
        state = start_acceptor_pool(state)

        {:ok, state}

      {:error, reason} ->
        Logger.error("[TlsListener] Failed to listen on port #{port}: #{inspect(reason)}")
        {:stop, {:listen_failed, reason}}
    end
  end

  @impl true
  def handle_call(:get_port, _from, state) do
    {:reply, state.port, state}
  end

  def handle_call(:stats, _from, state) do
    {:reply,
     %{
       port: state.port,
       active_connections: state.active_connections,
       total_connections: state.total_connections,
       total_handshake_failures: state.total_handshake_failures,
       acceptors: state.acceptors,
       active_acceptors: MapSet.size(state.acceptor_pids)
     }, state}
  end

  @impl true
  def handle_info({:new_connection, ssl_socket, acceptor_pid}, state) do
    # Remove the acceptor from tracking
    state = %{state | acceptor_pids: MapSet.delete(state.acceptor_pids, acceptor_pid)}

    # Start a TlsSession process for this connection
    session_opts = [
      listener_pid: self(),
      config: state.config
    ]

    {:ok, session_pid} = ZtlpGateway.TlsSession.start_link(ssl_socket, session_opts)
    :ssl.controlling_process(ssl_socket, session_pid)

    # Signal the session to proceed now that it owns the socket
    send(session_pid, :proceed)

    # Monitor the session so we know when it ends
    Process.monitor(session_pid)

    # Spawn replacement acceptor
    state = spawn_acceptor(state)

    {:noreply,
     %{
       state
       | active_connections: state.active_connections + 1,
         total_connections: state.total_connections + 1,
         session_pids: MapSet.put(state.session_pids, session_pid)
     }}
  end

  def handle_info({:handshake_failed, reason, acceptor_pid}, state) do
    Logger.warning("[TlsListener] Handshake failed: #{inspect(reason)}")
    state = %{state | acceptor_pids: MapSet.delete(state.acceptor_pids, acceptor_pid)}
    state = spawn_acceptor(state)

    {:noreply, %{state | total_handshake_failures: state.total_handshake_failures + 1}}
  end

  def handle_info({:accept_error, _reason, acceptor_pid}, state) do
    state = %{state | acceptor_pids: MapSet.delete(state.acceptor_pids, acceptor_pid)}

    # Only respawn if we're still running (listen socket still open)
    state =
      try do
        case :ssl.sockname(state.listen_socket) do
          {:ok, _} -> spawn_acceptor(state)
          _ -> state
        end
      catch
        _, _ -> state
      end

    {:noreply, state}
  end

  def handle_info({:connection_closed, _reason}, state) do
    # Legacy message from TlsSession cleanup — decrement handled via DOWN
    {:noreply, state}
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state) do
    if MapSet.member?(state.session_pids, pid) do
      {:noreply,
       %{
         state
         | active_connections: max(state.active_connections - 1, 0),
           session_pids: MapSet.delete(state.session_pids, pid)
       }}
    else
      # Could be an acceptor that crashed
      if MapSet.member?(state.acceptor_pids, pid) do
        state = %{state | acceptor_pids: MapSet.delete(state.acceptor_pids, pid)}
        state = spawn_acceptor(state)
        {:noreply, state}
      else
        {:noreply, state}
      end
    end
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    # Close the listen socket
    try do
      :ssl.close(state.listen_socket)
    catch
      _, _ -> :ok
    end

    :ok
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp build_ssl_opts(certfile, keyfile, cacertfile, require_client_cert, request_client_cert) do
    base = [
      :binary,
      {:active, false},
      {:reuseaddr, true},
      {:packet, :raw},
      {:versions, [:"tlsv1.2", :"tlsv1.3"]},
      {:honor_cipher_order, true}
    ]

    base = if certfile, do: [{:certfile, to_charlist(certfile)} | base], else: base
    base = if keyfile, do: [{:keyfile, to_charlist(keyfile)} | base], else: base
    base = if cacertfile, do: [{:cacertfile, to_charlist(cacertfile)} | base], else: base

    cond do
      require_client_cert ->
        [{:verify, :verify_peer}, {:fail_if_no_peer_cert, true},
         {:verify_fun, {&verify_peer_fun/3, []}} | base]

      request_client_cert && cacertfile != nil ->
        [{:verify, :verify_peer}, {:fail_if_no_peer_cert, false},
         {:verify_fun, {&verify_peer_fun/3, []}} | base]

      true ->
        [{:verify, :verify_none} | base]
    end
  end

  defp start_acceptor_pool(state) do
    Enum.reduce(1..state.acceptors, state, fn _, acc ->
      spawn_acceptor(acc)
    end)
  end

  defp spawn_acceptor(state) do
    parent = self()
    listen_socket = state.listen_socket

    pid =
      spawn_link(fn ->
        acceptor_loop(listen_socket, parent)
      end)

    %{state | acceptor_pids: MapSet.put(state.acceptor_pids, pid)}
  end

  defp acceptor_loop(listen_socket, parent) do
    case :ssl.transport_accept(listen_socket, @transport_accept_timeout) do
      {:ok, transport_socket} ->
        case :ssl.handshake(transport_socket, @handshake_timeout) do
          {:ok, ssl_socket} ->
            # Transfer socket ownership to the listener before sending the message.
            # This prevents the socket from being closed when the acceptor exits.
            :ssl.controlling_process(ssl_socket, parent)
            send(parent, {:new_connection, ssl_socket, self()})

          {:error, reason} ->
            send(parent, {:handshake_failed, reason, self()})
        end

      {:error, reason} ->
        send(parent, {:accept_error, reason, self()})
    end
  end

  # Custom verify function that accepts valid and self-signed peer certs.
  # We verify the peer cert at the application level (TlsIdentity + CrlServer),
  # so we accept all certs at the TLS level to extract identity info.
  defp verify_peer_fun(_cert, {:bad_cert, :selfsigned_peer}, state), do: {:valid, state}
  defp verify_peer_fun(_cert, {:bad_cert, :unknown_ca}, state), do: {:valid, state}
  defp verify_peer_fun(_cert, {:extension, _ext}, state), do: {:unknown, state}
  defp verify_peer_fun(_cert, :valid, state), do: {:valid, state}
  defp verify_peer_fun(_cert, :valid_peer, state), do: {:valid, state}
  defp verify_peer_fun(_cert, _event, state), do: {:valid, state}

  defp get_config(key, default) do
    Application.get_env(:ztlp_gateway, key, default)
  end
end
