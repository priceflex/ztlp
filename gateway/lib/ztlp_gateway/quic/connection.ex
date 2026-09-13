defmodule ZtlpGateway.Quic.Connection do
  @moduledoc """
  One process per accepted QUIC connection.

  Lifecycle:

    1. Block in `:quicer.accept/3` on the listener (this process IS the
       acceptor). On accept, register a stream acceptor FIRST, then complete
       the TLS handshake — quicer delivers the client's first bidi stream to
       whoever called `async_accept_stream`, and the Rust client opens
       stream 0 immediately after the QUIC handshake, so registering after
       the handshake races and orphans the stream. Tell the listener
       `{:accepted, self()}` so it spawns a replacement acceptor.
    2. Run `ZtlpGateway.Quic.Handshake` on stream 0.
    3. On `{:done, result, out}`: resolve backend via `Packet.service_hash/1`
       against `Config.get(:backends)`, resolve identity
       (`Identity.resolve_or_hex/1`), check `PolicyEngine.authorize?/2`.
       Failure => shutdown connection with an app error code.
    4. Register the 12-byte session_id in `SessionRegistry`, bump `Stats`,
       `AuditLog.session_established/4`.
    5. Loop `:quicer.async_accept_stream/2`; each `{:quic, :new_stream, ...}`
       is handed to a `ZtlpGateway.Quic.StreamProxy` (1 stream <-> 1 TCP).

  Ordering caveat (observed live against the Rust agent, Q6): the client sends
  msg3 on stream 0 and immediately opens its first data stream + pushes the
  HTTP request, with no round trip in between. msquic may surface that
  `new_stream` event BEFORE the stream-0 receive carrying msg3. Two things
  follow: (a) a stream acceptor must be armed at all times (never only after
  `finish_handshake`), and (b) a data stream that arrives while the handshake
  is still in flight is parked in `pending_streams` and handed to a
  StreamProxy once the handshake completes. quicer pauses the stream in
  passive mode and buffers its data until we take ownership, so nothing is lost.
  """

  use GenServer, restart: :temporary
  require Logger

  alias ZtlpGateway.{AuditLog, Identity, Packet, PolicyEngine, SessionRegistry, Stats}
  alias ZtlpGateway.Quic.{Handshake, StreamProxy}

  # QUIC application error codes (visible to the client in CONNECTION_CLOSE)
  @err_handshake 0x01
  @err_unknown_service 0x02
  @err_policy_denied 0x03

  @stream0_timeout_ms 10_000

  defstruct [
    :conn,
    :stream0,
    :hs,
    :static_pub,
    :static_priv,
    :node_id,
    :session_id,
    :service,
    :backend,
    :identity,
    :peer,
    :started_at,
    proxies: %{},
    pending_streams: []
  ]

  def start(args), do: GenServer.start(__MODULE__, args)

  @impl true
  def init(args) do
    {:ok,
     %__MODULE__{
       static_pub: args.static_pub,
       static_priv: args.static_priv,
       node_id: args.node_id,
       hs: Handshake.new(args.static_pub, args.static_priv, args.node_id),
       started_at: System.monotonic_time(:millisecond)
     }, {:continue, {:accept, args.listener, args.owner}}}
  end

  @impl true
  def handle_continue({:accept, listener, owner}, state) do
    # peer_bidi_stream_count MUST be raised here: quicer's default conn opts
    # set it to 1, which would stall the client's first data stream.
    accept_opts = %{active: false, peer_bidi_stream_count: 256, peer_unidi_stream_count: 0}

    case :quicer.accept(listener, accept_opts, :infinity) do
      {:ok, conn} ->
        send(owner, {:accepted, self()})
        state = %{state | conn: conn}

        # Stream-0 acceptor BEFORE the TLS handshake completes (see moduledoc).
        with {:ok, _} <- :quicer.async_accept_stream(conn, %{active: true}),
             {:ok, _} <- tls_handshake(conn) do
          Process.send_after(self(), :stream0_timeout, @stream0_timeout_ms)
          {:noreply, %{state | peer: peername(conn)}}
        else
          {:error, reason} ->
            Logger.debug("[Quic.Connection] accept/handshake failed: #{inspect(reason)}")
            :quicer.async_shutdown_connection(conn, 0, 0)
            {:stop, :normal, state}
        end

      {:error, :closed} ->
        {:stop, :normal, state}

      {:error, reason} ->
        Logger.warning("[Quic.Connection] accept error: #{inspect(reason)}")
        {:stop, :normal, state}
    end
  end

  defp tls_handshake(conn) do
    case :quicer.handshake(conn, 10_000) do
      {:ok, ^conn} -> {:ok, conn}
      {:ok, ^conn, _certs} -> {:ok, conn}
      {:error, _} = e -> e
    end
  end

  # --- stream 0: handshake ----------------------------------------------------

  @impl true
  def handle_info({:quic, :new_stream, stream, _props}, %{stream0: nil} = state) do
    # Keep an acceptor armed so an early data stream is never orphaned.
    :quicer.async_accept_stream(state.conn, %{active: false})
    {:noreply, %{state | stream0: stream}}
  end

  # Data stream arrived before the Noise handshake finished: park it.
  def handle_info({:quic, :new_stream, stream, _props}, %{session_id: nil} = state) do
    :quicer.async_accept_stream(state.conn, %{active: false})
    {:noreply, %{state | pending_streams: state.pending_streams ++ [stream]}}
  end

  def handle_info({:quic, data, stream, _props}, %{stream0: stream, session_id: nil} = state)
      when is_binary(data) do
    case Handshake.step(state.hs, data) do
      {:continue, hs, out} ->
        send_out(stream, out)
        {:noreply, %{state | hs: hs}}

      {:done, result, out} ->
        send_out(stream, out)
        finish_handshake(result, state)

      {:error, reason} ->
        Logger.warning("[Quic] handshake failed peer=#{fmt_peer(state.peer)} reason=#{inspect(reason)}")
        Stats.handshake_fail()
        close_conn(state, @err_handshake)
    end
  end

  def handle_info(:stream0_timeout, %{session_id: nil} = state) do
    Logger.debug("[Quic] stream-0 handshake timed out peer=#{fmt_peer(state.peer)}")
    Stats.handshake_fail()
    close_conn(state, @err_handshake)
  end

  def handle_info(:stream0_timeout, state), do: {:noreply, state}

  # --- data streams -----------------------------------------------------------

  def handle_info({:quic, :new_stream, stream, _props}, %{session_id: sid} = state) when sid != nil do
    :quicer.async_accept_stream(state.conn, %{active: false})
    {:noreply, spawn_proxy(stream, state)}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    {:noreply, %{state | proxies: Map.delete(state.proxies, ref)}}
  end

  # --- stream 0 / connection lifecycle events ----------------------------------

  def handle_info({:quic, evt, _stream, _}, state)
      when evt in [:peer_send_shutdown, :send_shutdown_complete, :stream_closed, :send_complete, :start_completed, :peer_accepted, :peer_send_aborted, :peer_receive_aborted] do
    {:noreply, state}
  end

  def handle_info({:quic, evt, conn, info}, %{conn: conn} = state)
      when evt in [:closed, :shutdown, :transport_shutdown] do
    Logger.debug("[Quic] connection #{evt} peer=#{fmt_peer(state.peer)} #{inspect(info)}")
    {:stop, :normal, state}
  end

  def handle_info({:quic, _evt, _h, _}, state), do: {:noreply, state}
  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{session_id: sid} = state) when sid != nil do
    SessionRegistry.unregister(sid, self())
    Stats.session_closed()
    dur = System.monotonic_time(:millisecond) - state.started_at
    AuditLog.session_terminated(sid, :quic_closed, dur, 0, 0)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  # ---------------------------------------------------------------------------

  defp finish_handshake(result, state) do
    %{service_hash: svc_hash, session_id: sid, client_static_pub: rs} = result
    backends = ZtlpGateway.Config.get(:backends)

    with {:ok, backend} <- find_backend(backends, svc_hash),
         identity = Identity.resolve_or_hex(rs),
         true <- PolicyEngine.authorize?(identity, backend.name) || {:denied, identity, backend.name} do
      SessionRegistry.register(sid, self(), state.peer)
      Stats.handshake_ok()
      Stats.session_opened()
      AuditLog.session_established(sid, rs, state.peer, backend.name)

      Logger.info(
        "[Quic] handshake ok session=#{Base.encode16(sid, case: :lower)} peer=#{Base.encode16(rs, case: :lower)} service=#{backend.name} from=#{fmt_peer(state.peer)}"
      )

      # Finish our send half of stream 0. An acceptor is already armed (see
      # the stream0 `new_stream` clause); now drain any data streams that
      # raced ahead of msg3.
      :quicer.async_shutdown_stream(state.stream0, 1, 0)

      state = %{state | session_id: sid, service: backend.name, backend: backend, identity: identity}
      state = Enum.reduce(state.pending_streams, %{state | pending_streams: []}, &spawn_proxy/2)
      {:noreply, state}
    else
      :error ->
        Logger.warning("[Quic] unknown service hash=#{Base.encode16(svc_hash, case: :lower)} peer=#{fmt_peer(state.peer)}")
        Stats.handshake_fail()
        close_conn(state, @err_unknown_service)

      {:denied, identity, service} ->
        Logger.warning("[Quic] policy denied identity=#{identity} service=#{service}")
        Stats.policy_denied()
        AuditLog.policy_denied(rs, state.peer, service, :quic_policy)
        close_conn(state, @err_policy_denied)
    end
  end

  defp spawn_proxy(stream, state) do
    case StreamProxy.start(%{
           stream: stream,
           backend: state.backend,
           identity: state.identity,
           service: state.service,
           session_id: state.session_id
         }) do
      {:ok, pid} ->
        # Hand the stream to the proxy; buffer any signals arriving meanwhile.
        case :quicer.handoff_stream(stream, pid, nil) do
          :ok ->
            ref = Process.monitor(pid)
            %{state | proxies: Map.put(state.proxies, ref, pid)}

          {:error, reason} ->
            Logger.warning("[Quic] stream handoff failed: #{inspect(reason)}")
            :quicer.async_shutdown_stream(stream, 6, 0)
            state
        end

      {:error, reason} ->
        Logger.warning("[Quic] could not start StreamProxy: #{inspect(reason)}")
        :quicer.async_shutdown_stream(stream, 6, 0)
        state
    end
  end

  # Same semantics as Session.find_backend/2 (16-byte hash, zero/unknown -> "default").
  defp find_backend(backends, <<hash::binary-size(16)>>) do
    case Enum.find(backends, fn b -> Packet.service_hash(b.name) == hash end) do
      nil ->
        case Enum.find(backends, fn b -> b.name == "default" end) do
          nil -> :error
          b -> {:ok, b}
        end

      b ->
        {:ok, b}
    end
  end

  defp send_out(_stream, <<>>), do: :ok
  defp send_out(stream, out), do: :quicer.send(stream, out)

  defp close_conn(state, code) do
    :quicer.async_shutdown_connection(state.conn, 0, code)
    {:stop, :normal, state}
  end

  defp peername(conn) do
    case :quicer.peername(conn) do
      {:ok, addr} -> addr
      _ -> nil
    end
  end

  defp fmt_peer({ip, port}), do: "#{:inet.ntoa(ip)}:#{port}"
  defp fmt_peer(_), do: "?"
end
