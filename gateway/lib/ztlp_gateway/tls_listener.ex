defmodule ZtlpGateway.TlsListener do
  @moduledoc """
  TLS listener for the ZTLP Gateway.

  Provides HTTPS termination for inbound client connections. Supports:
  - TLS 1.2 and 1.3
  - SNI-based routing to different backend services
  - mTLS (mutual TLS) for client certificate authentication
  - Configurable acceptor pool

  ## Architecture

      Client → TLS (mTLS) → TlsListener → SniRouter → Backend (TCP)
                                         → TlsIdentity (extract mTLS identity)
                                         → HttpHeaderInjector (add identity headers)

  Unlike the UDP Listener which handles ZTLP protocol packets, this
  listener handles standard TLS connections for HTTPS proxying.
  """

  use GenServer
  require Logger

  @default_port 8443
  @default_acceptors 10

  # ── Public API ─────────────────────────────────────────────────────

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc "Get the port the TLS listener is bound to."
  @spec port() :: non_neg_integer()
  def port do
    GenServer.call(__MODULE__, :get_port)
  end

  @doc "Get listener statistics."
  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  # ── GenServer ──────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, get_config(:tls_port, @default_port))
    certfile = Keyword.get(opts, :certfile)
    keyfile = Keyword.get(opts, :keyfile)
    cacertfile = Keyword.get(opts, :cacertfile)
    acceptors = Keyword.get(opts, :acceptors, @default_acceptors)
    require_client_cert = Keyword.get(opts, :require_client_cert, false)

    ssl_opts = build_ssl_opts(certfile, keyfile, cacertfile, require_client_cert)

    case :ssl.listen(port, ssl_opts) do
      {:ok, listen_socket} ->
        {:ok, {_, actual_port}} = :ssl.sockname(listen_socket)
        Logger.info("[TlsListener] Listening on TLS port #{actual_port}")

        state = %{
          listen_socket: listen_socket,
          port: actual_port,
          acceptors: acceptors,
          accept_count: 0,
          active_connections: 0,
          total_connections: 0,
          require_client_cert: require_client_cert,
          certfile: certfile,
          keyfile: keyfile
        }

        # Start acceptor pool
        for _ <- 1..acceptors do
          spawn_acceptor(listen_socket, self())
        end

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
    {:reply, %{
      port: state.port,
      active_connections: state.active_connections,
      total_connections: state.total_connections,
      acceptors: state.acceptors
    }, state}
  end

  @impl true
  def handle_info({:new_connection, ssl_socket}, state) do
    # Spawn a handler for this connection
    pid = spawn_link(fn -> handle_connection(ssl_socket) end)
    :ssl.controlling_process(ssl_socket, pid)

    # Spawn replacement acceptor
    spawn_acceptor(state.listen_socket, self())

    {:noreply, %{state |
      active_connections: state.active_connections + 1,
      total_connections: state.total_connections + 1
    }}
  end

  def handle_info({:connection_closed, _reason}, state) do
    {:noreply, %{state |
      active_connections: max(state.active_connections - 1, 0)
    }}
  end

  def handle_info({:accept_error, reason}, state) do
    Logger.warning("[TlsListener] Accept error: #{inspect(reason)}")
    # Respawn acceptor after error
    spawn_acceptor(state.listen_socket, self())
    {:noreply, state}
  end

  def handle_info(_msg, state) do
    {:noreply, state}
  end

  # ── Internal ───────────────────────────────────────────────────────

  defp build_ssl_opts(certfile, keyfile, cacertfile, require_client_cert) do
    base = [
      {:active, false},
      {:reuseaddr, true},
      {:versions, [:"tlsv1.2", :"tlsv1.3"]},
      {:honor_cipher_order, true}
    ]

    base = if certfile, do: [{:certfile, to_charlist(certfile)} | base], else: base
    base = if keyfile, do: [{:keyfile, to_charlist(keyfile)} | base], else: base
    base = if cacertfile, do: [{:cacertfile, to_charlist(cacertfile)} | base], else: base

    if require_client_cert do
      [{:verify, :verify_peer}, {:fail_if_no_peer_cert, true} | base]
    else
      [{:verify, :verify_none} | base]
    end
  end

  defp spawn_acceptor(listen_socket, parent) do
    spawn(fn ->
      case :ssl.transport_accept(listen_socket, 30_000) do
        {:ok, transport_socket} ->
          case :ssl.handshake(transport_socket, 10_000) do
            {:ok, ssl_socket} ->
              send(parent, {:new_connection, ssl_socket})
            {:error, reason} ->
              send(parent, {:accept_error, {:handshake_failed, reason}})
          end
        {:error, reason} ->
          send(parent, {:accept_error, reason})
      end
    end)
  end

  defp handle_connection(ssl_socket) do
    # Extract peer certificate info for mTLS
    peer_info = ZtlpGateway.TlsIdentity.extract_from_socket(ssl_socket)

    # Determine backend from SNI
    sni = case :ssl.connection_information(ssl_socket, [:sni_hostname]) do
      {:ok, info} -> Keyword.get(info, :sni_hostname)
      _ -> nil
    end

    service = ZtlpGateway.SniRouter.resolve(sni)

    # Read data and proxy
    proxy_loop(ssl_socket, service, peer_info)
  end

  defp proxy_loop(ssl_socket, service, peer_info) do
    case :ssl.recv(ssl_socket, 0, 30_000) do
      {:ok, data} ->
        # Inject identity headers if this looks like HTTP
        data = if http_request?(data) do
          ZtlpGateway.HttpHeaderInjector.inject(data, peer_info, service)
        else
          data
        end

        # Forward to backend
        case forward_to_backend(data, service) do
          {:ok, response} ->
            :ssl.send(ssl_socket, response)
            proxy_loop(ssl_socket, service, peer_info)
          {:error, _reason} ->
            :ssl.close(ssl_socket)
        end

      {:error, :closed} ->
        :ssl.close(ssl_socket)

      {:error, :timeout} ->
        :ssl.close(ssl_socket)

      {:error, _reason} ->
        :ssl.close(ssl_socket)
    end
  end

  defp http_request?(<<method, _::binary>>) when method in [?G, ?P, ?H, ?D, ?O, ?T, ?C], do: true
  defp http_request?(_), do: false

  defp forward_to_backend(data, service) do
    case ZtlpGateway.SniRouter.backend_for(service) do
      {:ok, {host, port}} ->
        case :gen_tcp.connect(host, port, [:binary, active: false], 5_000) do
          {:ok, socket} ->
            :gen_tcp.send(socket, data)
            result = :gen_tcp.recv(socket, 0, 10_000)
            :gen_tcp.close(socket)
            result
          error -> error
        end
      error -> error
    end
  end

  defp get_config(key, default) do
    Application.get_env(:ztlp_gateway, key, default)
  end
end
