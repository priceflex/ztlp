defmodule ZtlpGateway.Quic.StreamProxy do
  @moduledoc """
  One QUIC bidi stream <-> one TCP connection to the resolved backend.

  QUIC -> TCP: reassemble `0x5A|len|payload` frames (`Quic.Frame.decode/1`),
  run `HttpHeaderInjector.inject/3` on every HTTP request start (keep-alive
  safe: injection re-arms whenever the previous request's bytes ended at a
  header/body boundary we can't track cheaply, so we inject whenever a chunk
  *starts* with an HTTP method — same heuristic the legacy `Session` uses),
  write plaintext to TCP.

  TCP -> QUIC: `Frame.encode/1` each TCP read (<= 65000 bytes) and
  `:quicer.send/2`.

  FIN mapping: `peer_send_shutdown` -> `:gen_tcp.shutdown(:write)`;
  TCP closed -> graceful `shutdown_stream` (FIN); `stream_closed` -> close TCP.
  Backpressure: QUIC stream runs `active: 32` and is re-armed on
  `{:quic, :passive, ...}`; TCP runs `active: :once`.
  """

  use GenServer, restart: :temporary
  require Logger

  alias ZtlpGateway.{HttpHeaderInjector, Stats}
  alias ZtlpGateway.Quic.Frame

  @tcp_connect_timeout 10_000
  @active_n 32
  @max_tcp_read 65_000

  defstruct [:stream, :sock, :backend, :identity, :service, :session_id, buf: <<>>, tcp_closed: false, quic_fin: false]

  def start(args), do: GenServer.start(__MODULE__, args)

  @impl true
  def init(args) do
    state = %__MODULE__{
      stream: args.stream,
      backend: args.backend,
      identity: args.identity,
      service: args.service,
      session_id: args.session_id
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    %{host: host, port: port} = state.backend

    case :gen_tcp.connect(host, port, [:binary, active: :once, packet: :raw, nodelay: true], @tcp_connect_timeout) do
      {:ok, sock} ->
        {:noreply, %{state | sock: sock}}

      {:error, reason} ->
        Logger.warning("[Quic.StreamProxy] backend connect #{inspect(host)}:#{port} failed: #{inspect(reason)}")
        Stats.backend_error()
        :quicer.async_shutdown_stream(state.stream, 6, 0)
        {:stop, :normal, state}
    end
  end

  # --- ownership handoff (quicer buffers signals until this arrives) ----------

  @impl true
  def handle_info({:handoff_done, stream, _data}, %{stream: stream} = state) do
    :quicer.setopt(stream, :active, @active_n)
    {:noreply, state}
  end

  # --- QUIC -> TCP -------------------------------------------------------------

  def handle_info({:quic, data, stream, _props}, %{stream: stream} = state) when is_binary(data) do
    Stats.bytes_received(byte_size(data))
    drain(%{state | buf: state.buf <> data})
  end

  def handle_info({:quic, :passive, stream, _}, %{stream: stream} = state) do
    :quicer.setopt(stream, :active, @active_n)
    {:noreply, state}
  end

  def handle_info({:quic, :peer_send_shutdown, stream, _}, %{stream: stream} = state) do
    # Client finished sending: half-close TCP so the backend sees EOF.
    if state.sock, do: :gen_tcp.shutdown(state.sock, :write)
    maybe_finish(%{state | quic_fin: true})
  end

  def handle_info({:quic, evt, stream, _}, %{stream: stream} = state)
      when evt in [:peer_send_aborted, :peer_receive_aborted, :stream_closed] do
    {:stop, :normal, state}
  end

  def handle_info({:quic, _evt, _h, _}, state), do: {:noreply, state}

  # --- TCP -> QUIC -------------------------------------------------------------

  def handle_info({:tcp, sock, data}, %{sock: sock} = state) do
    :ok = send_framed(state.stream, data)
    :inet.setopts(sock, active: :once)
    {:noreply, state}
  end

  def handle_info({:tcp_closed, sock}, %{sock: sock} = state) do
    # Backend EOF -> FIN our send half on the stream (graceful).
    :quicer.async_shutdown_stream(state.stream, 1, 0)
    maybe_finish(%{state | tcp_closed: true, sock: nil})
  end

  def handle_info({:tcp_error, sock, reason}, %{sock: sock} = state) do
    Logger.debug("[Quic.StreamProxy] tcp error: #{inspect(reason)}")
    Stats.backend_error()
    :quicer.async_shutdown_stream(state.stream, 6, 0)
    {:stop, :normal, %{state | sock: nil}}
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{sock: sock}) when sock != nil do
    :gen_tcp.close(sock)
    :ok
  end

  def terminate(_reason, _), do: :ok

  # ---------------------------------------------------------------------------

  defp drain(%{buf: buf} = state) do
    case Frame.decode(buf) do
      {:ok, payload, rest} ->
        case forward_to_tcp(payload, state) do
          :ok -> drain(%{state | buf: rest})
          {:error, _} -> {:stop, :normal, %{state | buf: rest}}
        end

      {:more, _} ->
        {:noreply, state}

      {:error, reason} ->
        Logger.warning("[Quic.StreamProxy] bad frame from client: #{inspect(reason)}")
        :quicer.async_shutdown_stream(state.stream, 6, 0)
        {:stop, :normal, state}
    end
  end

  defp forward_to_tcp(_payload, %{sock: nil}), do: {:error, :no_backend}

  defp forward_to_tcp(payload, state) do
    data =
      if HttpHeaderInjector.http_request?(payload) do
        HttpHeaderInjector.inject(payload, state.identity, state.service)
      else
        payload
      end

    :gen_tcp.send(state.sock, data)
  end

  defp send_framed(_stream, <<>>), do: :ok

  defp send_framed(stream, data) when byte_size(data) > @max_tcp_read do
    <<head::binary-size(@max_tcp_read), rest::binary>> = data
    :ok = send_framed(stream, head)
    send_framed(stream, rest)
  end

  defp send_framed(stream, data) do
    frame = Frame.encode(data)
    Stats.bytes_sent(byte_size(data))

    case :quicer.send(stream, frame) do
      {:ok, _} -> :ok
      :ok -> :ok
      {:error, reason} -> {:error, reason}
      {:error, reason, _} -> {:error, reason}
    end
  end

  # Once both directions are done, let the stream close and exit.
  defp maybe_finish(%{tcp_closed: true, quic_fin: true} = state), do: {:stop, :normal, state}
  defp maybe_finish(state), do: {:noreply, state}
end
