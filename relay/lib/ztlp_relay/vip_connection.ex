defmodule ZtlpRelay.VipConnection do
  @moduledoc """
  GenServer managing a single VIP-proxied TCP connection.

  Lifecycle:
  - SYN frame from client -> open TCP connection to backend
  - DATA frames from client -> forward TCP payload to backend
  - TCP data from backend -> encrypt + send back to client via UDP
  - FIN frame from client -> close TCP socket, cleanup
  - RST frame from client -> reset TCP socket, cleanup
  - Timeout/remote close -> send RST back to client, cleanup

  State tracking:
  - connection_id: 16-bit identifier from client VIP frames
  - session_id: the ZTLP session identifier
  - client_addr: {ip, port} of the client tunnel endpoint
  - backend_socket: port to the TCP backend (or nil)
  - service_name: target service name
  - created_at: monotonic start time
  - bytes_to_backend: total bytes forwarded to backend
  - bytes_from_backend: total bytes forwarded from backend
  """

  use GenServer

  require Logger

  alias ZtlpRelay.{Packet, Crypto, VipFrame, TlsConfig}

  @connect_timeout_ms 5000
  @send_timeout_ms 10_000

  @type state :: %{
          connection_id: non_neg_integer(),
          session_id: binary(),
          client_addr: {tuple(), non_neg_integer()},
          backend_socket: port() | :ssl.sslsocket() | nil,
          backend_addr: {tuple(), non_neg_integer()},
          service_name: String.t(),
          created_at: integer(),
          last_activity: integer(),
          bytes_to_backend: non_neg_integer(),
          bytes_from_backend: non_neg_integer(),
          closed: boolean(),
          udp_socket: port(),
          session_key: binary() | nil,
          tls_enabled: boolean()
        }

  # Client API

  @doc """
  Start a VIP connection GenServer.

  Called by `ZtlpRelay.VipTcpTerminator` when it receives a SYN frame
  for a service configured in the VIP service table.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Deliver data from the backend TCP socket to the VIP connection process.
  """
  @spec backend_data(pid(), binary()) :: :ok
  def backend_data(pid, data) when is_binary(data) do
    GenServer.cast(pid, {:backend_data, data})
  end

  @doc """
  Notify that backend TCP socket was closed or reset.
  """
  @spec backend_closed(pid()) :: :ok
  def backend_closed(pid) do
    GenServer.cast(pid, :backend_closed)
  end

  @doc """
  Get connection info (for metrics).
  """
  @spec info(pid()) :: map()
  def info(pid) do
    GenServer.call(pid, :info)
  end

  # GenServer callbacks

  @impl true
  def init(opts) do
    connection_id = Keyword.fetch!(opts, :connection_id)
    session_id = Keyword.fetch!(opts, :session_id)
    client_addr = Keyword.fetch!(opts, :client_addr)
    backend_addr = Keyword.fetch!(opts, :backend_addr)
    service_name = Keyword.fetch!(opts, :service_name)
    udp_socket = Keyword.fetch!(opts, :udp_socket)
    session_key = Keyword.get(opts, :session_key)
    tls_enabled = Keyword.get(opts, :tls_enabled, false)

    now = System.monotonic_time(:millisecond)

    state = %{
      connection_id: connection_id,
      session_id: session_id,
      client_addr: client_addr,
      backend_socket: nil,
      backend_addr: backend_addr,
      service_name: service_name,
      created_at: now,
      last_activity: now,
      bytes_to_backend: 0,
      bytes_from_backend: 0,
      closed: false,
      udp_socket: udp_socket,
      session_key: session_key,
      tls_enabled: tls_enabled
    }

    # Open TCP connection to backend asynchronously
    send(self(), {:connect_backend, backend_addr, tls_enabled})

    {:ok, state}
  end

  @impl true
  def handle_cast({:backend_data, data}, state) do
    if state.closed do
      {:noreply, state}
    else
      backend_bytes = byte_size(data)

      resp_frame = VipFrame.encode(state.connection_id, :data, data)

      case state.session_key do
        session_key when is_binary(session_key) ->
          encrypted = encrypt_for_client(resp_frame, session_key, state)
          :gen_udp.send(state.udp_socket,
            elem(state.client_addr, 0),
            elem(state.client_addr, 1),
            encrypted
          )
        _ ->
          :gen_udp.send(state.udp_socket,
            elem(state.client_addr, 0),
            elem(state.client_addr, 1),
            resp_frame
          )
      end

      {:noreply, %{state | bytes_from_backend: state.bytes_from_backend + backend_bytes,
                     last_activity: System.monotonic_time(:millisecond)}}
    end
  end

  @impl true
  def handle_cast(:backend_closed, state) do
    Logger.debug("[VIP] Backend closed conn=#{state.connection_id} svc=#{state.service_name}")
    if not state.closed do
      send_fin_to_client(state)
    end

    {:noreply, %{state | closed: true}}
  end

  @impl true
  def handle_call(:info, _from, state) do
    {:reply,
     %{
       connection_id: state.connection_id,
       service_name: state.service_name,
       backend_addr: state.backend_addr,
       bytes_to_backend: state.bytes_to_backend,
       bytes_from_backend: state.bytes_from_backend,
       duration_ms: System.monotonic_time(:millisecond) - state.created_at,
       closed: state.closed
     }, state}
  end

  @impl true
  def handle_info({:connect_backend, backend_addr, tls_enabled}, state) do
    Logger.info(
      "[VIP] Connecting to backend #{format_addr(backend_addr)} for conn=#{state.connection_id} svc=#{state.service_name}"
    )

    if tls_enabled do
      connect_tls_backend(backend_addr, state)
    else
      connect_tcp_backend(backend_addr, state)
    end
  end

  # TCP socket messages (active mode)
  def handle_info({:tcp, _socket, data}, state) do
    handle_backend_data_internal(data, state)
  end

  def handle_info({:tcp_closed, _socket}, state) do
    Logger.debug("[VIP] Backend TCP closed conn=#{state.connection_id}")
    if not state.closed do
      send_fin_to_client(state)
    end

    {:stop, :normal, %{state | closed: true}}
  end

  def handle_info({:tcp_error, _socket, reason}, state) do
    Logger.warning("[VIP] Backend TCP error conn=#{state.connection_id}: #{inspect(reason)}")
    if not state.closed do
      send_rst_to_client(state)
    end

    {:stop, {:error, reason}, %{state | closed: true}}
  end

  # SSL socket messages (active mode)
  def handle_info({:ssl, _socket, data}, state) do
    handle_backend_data_internal(data, state)
  end

  def handle_info({:ssl_closed, _socket}, state) do
    Logger.debug("[VIP] Backend TLS closed conn=#{state.connection_id}")
    if not state.closed do
      send_fin_to_client(state)
    end

    {:stop, :normal, %{state | closed: true}}
  end

  def handle_info({:ssl_error, _socket, reason}, state) do
    Logger.warning("[VIP] Backend TLS error conn=#{state.connection_id}: #{inspect(reason)}")
    if not state.closed do
      send_rst_to_client(state)
    end

    {:stop, {:error, reason}, %{state | closed: true}}
  end

  # Client data frames
  def handle_info({:client_data, frame}, %{backend_socket: nil} = state) do
    # Data arrived before connection was established
    Logger.debug("[VIP] Data arrived before backend connected conn=#{state.connection_id}")
    {:noreply, state}
  end

  def handle_info({:client_data, frame}, state) do
    handle_client_frame(frame, state)
  end

  def handle_info(:connect_timeout, state) do
    Logger.warning("[VIP] Backend connection timeout conn=#{state.connection_id}")
    if not state.closed do
      send_rst_to_client(state)
    end

    {:stop, :timeout, %{state | closed: true}}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    if state.backend_socket do
      case state.tls_enabled do
        true -> :ssl.close(state.backend_socket)
        false -> :gen_tcp.close(state.backend_socket)
      end
    end

    :ok
  end

  # Internal helpers

  defp connect_tcp_backend({ip, port}, state) do
    opts = [
      :binary,
      active: true,
      nodelay: true,
      send_timeout: @send_timeout_ms,
      exit_on_close: true
    ]

    case :gen_tcp.connect(ip, port, opts, @connect_timeout_ms) do
      {:ok, socket} ->
        Logger.info("[VIP] Backend connected conn=#{state.connection_id} svc=#{state.service_name}")

        {:noreply, %{
          state
          | backend_socket: socket,
            last_activity: System.monotonic_time(:millisecond)
        }}

      {:error, reason} ->
        Logger.error("[VIP] Backend connect failed conn=#{state.connection_id}: #{inspect(reason)}")
        if not state.closed do
          send_rst_to_client(state)
        end

        {:stop, {:connect_error, reason}, %{state | closed: true}}
    end
  end

  defp connect_tls_backend({ip, port}, state) do
    tls_opts =
      [:binary, active: true, nodelay: true, send_timeout: @send_timeout_ms, exit_on_close: true] ++
      TlsConfig.client_opts()

    case :gen_tcp.connect(ip, port, tls_opts, @connect_timeout_ms) do
      {:ok, tcp_socket} ->
        case :ssl.connect(tcp_socket, tls_opts, @connect_timeout_ms) do
          {:ok, ssl_socket} ->
            Logger.info(
              "[VIP] Backend TLS connected conn=#{state.connection_id} svc=#{state.service_name}"
            )

            {:noreply, %{
              state
              | backend_socket: ssl_socket,
                tls_enabled: true,
                last_activity: System.monotonic_time(:millisecond)
            }}

          {:error, reason} ->
            Logger.error(
              "[VIP] TLS handshake failed conn=#{state.connection_id}: #{inspect(reason)}"
            )

            :gen_tcp.close(tcp_socket)

            if not state.closed do
              send_rst_to_client(state)
            end

            {:stop, {:tls_error, reason}, %{state | closed: true}}
        end

      {:error, reason} ->
        Logger.error("[VIP] Backend TCP connect failed for TLS: #{inspect(reason)}")
        if not state.closed do
          send_rst_to_client(state)
        end

        {:stop, {:connect_error, reason}, %{state | closed: true}}
    end
  end

  defp handle_client_frame(frame, state) do
    cond do
      frame.frame_type == :data or frame.frame_type == :syn ->
        handle_data_frame(frame.payload, state)

      frame.frame_type == :fin ->
        Logger.debug("[VIP] Client FIN conn=#{state.connection_id}")

        if state.backend_socket do
          case state.tls_enabled do
            true -> :ssl.close(state.backend_socket)
            false -> :gen_tcp.shutdown(state.backend_socket, :write)
          end
        end

        {:noreply, %{state | closed: true}}

      frame.frame_type == :rst ->
        Logger.debug("[VIP] Client RST conn=#{state.connection_id}")

        if state.backend_socket do
          case state.tls_enabled do
            true -> :ssl.close(state.backend_socket)
            false -> :gen_tcp.close(state.backend_socket)
          end
        end

        {:stop, :client_reset, %{state | closed: true}}
    end
  end

  defp handle_data_frame(payload, state) do
    if state.closed or state.backend_socket == nil do
      Logger.debug(
        "[VIP] Dropping data for closed backend conn=#{state.connection_id}"
      )

      {:noreply, state}
    else
      send_bytes = byte_size(payload)

      send_result =
        case {state.tls_enabled, state.backend_socket} do
          {true, ssl_socket} -> :ssl.send(ssl_socket, payload)
          {false, tcp_socket} -> :gen_tcp.send(tcp_socket, payload)
        end

      case send_result do
        :ok ->
          {:noreply, %{
            state
            | bytes_to_backend: state.bytes_to_backend + send_bytes,
              last_activity: System.monotonic_time(:millisecond)
          }}

        {:error, reason} ->
          Logger.warning(
            "[VIP] Backend send error conn=#{state.connection_id}: #{inspect(reason)}"
          )

          send_rst_to_client(state)
          {:stop, {:send_error, reason}, %{state | closed: true}}
      end
    end
  end

  defp handle_backend_data_internal(data, state) do
    if state.closed do
      {:noreply, state}
    else
      backend_bytes = byte_size(data)
      Logger.debug(
        "[VIP] Backend->Client conn=#{state.connection_id} svc=#{state.service_name} bytes=#{backend_bytes}"
      )

      resp_frame = VipFrame.encode(state.connection_id, :data, data)

      case state.session_key do
        session_key when is_binary(session_key) ->
          encrypted = encrypt_for_client(resp_frame, session_key, state)
          :gen_udp.send(state.udp_socket,
            elem(state.client_addr, 0),
            elem(state.client_addr, 1),
            encrypted
          )
        _ ->
          :gen_udp.send(state.udp_socket,
            elem(state.client_addr, 0),
            elem(state.client_addr, 1),
            resp_frame
          )
      end

      {:noreply, %{
        state
        | bytes_from_backend: state.bytes_from_backend + backend_bytes,
          last_activity: System.monotonic_time(:millisecond)
      }}
    end
  end

  defp send_fin_to_client(state) do
    frame = VipFrame.encode(state.connection_id, :fin, <<>>)
    encrypted = encrypt_for_client(frame, state.session_key, state)

    :gen_udp.send(state.udp_socket,
      elem(state.client_addr, 0),
      elem(state.client_addr, 1),
      encrypted
    )
  end

  defp send_rst_to_client(state) do
    frame = VipFrame.encode(state.connection_id, :rst, <<>>)
    encrypted = encrypt_for_client(frame, state.session_key, state)

    :gen_udp.send(state.udp_socket,
      elem(state.client_addr, 0),
      elem(state.client_addr, 1),
      encrypted
    )
  end

  defp encrypt_for_client(frame, session_key, state) do
    # Frame the response as a ZTLP data packet
    aad = build_packet_aad(state, frame)
    header_auth_tag = Crypto.compute_header_auth_tag(session_key, aad)

    packet =
      Packet.build_data(state.session_id, 0,
        header_auth_tag: header_auth_tag,
        payload: frame
      )

    Packet.serialize_data(packet)
  end

  defp build_packet_aad(state, payload) do
    # Build the AAD for the compact data packet header (30 bytes)
    # magic(2) + ver(0.5) + hdr_len(1.5) + flags(2) + session_id(12) +
    # packet_seq(8) + ext_len(2) + payload_len(2)
    <<
      0x5A37::16,
      0x1::4,
      0xC::12,
      0::16,
      state.session_id::binary-size(12),
      0::64,
      0::16,
      byte_size(payload)::16
    >>
  end

  defp format_addr({{a, b, c, d}, port}), do: "#{a}.#{b}.#{c}.#{d}:#{port}"
  defp format_addr(addr), do: inspect(addr)
end
