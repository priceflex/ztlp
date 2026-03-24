defmodule ZtlpGateway.TlsSession do
  @moduledoc """
  TLS session handler for the ZTLP Gateway.

  Manages the full lifecycle of a single TLS client connection:

  1. TLS handshake (already done by TlsListener acceptor)
  2. Extract mTLS identity from client certificate
  3. Determine backend via SNI routing
  4. Check policy (PolicyEngine.authorize?/2)
  5. Check assurance level against backend min_assurance
  6. Open persistent backend TCP connection
  7. Bidirectional streaming proxy: client ↔ gateway ↔ backend
  8. HTTP mode: inject identity headers on first data chunk
  9. Non-HTTP mode: pure TCP passthrough
  10. Audit logging for all events
  11. Proper cleanup on disconnect

  ## Architecture

      TlsListener
        └── TlsSession (one per connection, runs as linked process)
              ├── TlsIdentity.extract_from_socket/1
              ├── SniRouter.resolve/1
              ├── PolicyEngine.authorize?/2
              ├── HttpHeaderInjector.inject/3
              └── Backend TCP proxy (bidirectional, active sockets)

  Sessions are started by `TlsListener` and run as independent processes.
  Each session tracks bytes transferred and connection duration for audit.
  """

  require Logger

  alias ZtlpGateway.{
    AuditLog,
    CrlServer,
    HttpHeaderInjector,
    PolicyEngine,
    SniRouter,
    TlsIdentity
  }

  @backend_connect_timeout 5_000

  @typedoc "TLS session state"
  @type t :: %{
          ssl_socket: :ssl.sslsocket(),
          backend_socket: port() | nil,
          sni: String.t() | nil,
          service: String.t() | nil,
          identity: map() | nil,
          source: {tuple(), non_neg_integer()} | nil,
          started_at: integer(),
          bytes_in: non_neg_integer(),
          bytes_out: non_neg_integer(),
          conn_info: map(),
          first_chunk: boolean(),
          listener_pid: pid() | nil,
          config: map()
        }

  # ── Public API ─────────────────────────────────────────────────────

  @doc """
  Start a new TLS session for an already-accepted SSL socket.

  Called by TlsListener after a successful TLS handshake. Runs the full
  session lifecycle in the calling process (or a spawned process).

  Returns `:ok` on clean shutdown, `{:error, reason}` on failure.
  """
  @spec handle(ssl_socket :: :ssl.sslsocket(), opts :: keyword()) :: :ok | {:error, term()}
  def handle(ssl_socket, opts \\ []) do
    state = init_state(ssl_socket, opts)

    try do
      state
      |> extract_identity()
      |> check_revocation()
      |> extract_connection_info()
      |> resolve_backend()
      |> check_policy()
      |> check_assurance()
      |> audit_connection_established()
      |> connect_backend()
      |> start_bidirectional_proxy()
    catch
      :throw, {:session_reject, reason, reject_state} ->
        handle_rejection(reason, reject_state)
        {:error, reason}

      kind, reason ->
        Logger.error("[TlsSession] Unexpected error: #{kind} #{inspect(reason)}")
        Logger.error("[TlsSession] Stacktrace: #{inspect(__STACKTRACE__)}")
        {:error, {kind, reason}}
    after
      cleanup(state)
    end
  end

  @doc """
  Start a TLS session as a linked process.

  Returns `{:ok, pid}`. The session waits for a `:proceed` message
  before accessing the socket, allowing the caller to transfer
  socket ownership first.
  """
  @spec start_link(ssl_socket :: :ssl.sslsocket(), opts :: keyword()) :: {:ok, pid()}
  def start_link(ssl_socket, opts \\ []) do
    pid =
      spawn_link(fn ->
        # Wait for controlling_process to be transferred
        receive do
          :proceed -> :ok
        after
          5_000 -> exit(:timeout_waiting_for_proceed)
        end

        handle(ssl_socket, opts)
      end)

    {:ok, pid}
  end

  # ── Pipeline Steps ─────────────────────────────────────────────────

  defp init_state(ssl_socket, opts) do
    source =
      case :ssl.peername(ssl_socket) do
        {:ok, peer} -> peer
        _ -> nil
      end

    %{
      ssl_socket: ssl_socket,
      backend_socket: nil,
      sni: nil,
      service: nil,
      identity: nil,
      source: source,
      started_at: System.monotonic_time(:millisecond),
      bytes_in: 0,
      bytes_out: 0,
      conn_info: %{},
      first_chunk: true,
      listener_pid: Keyword.get(opts, :listener_pid),
      config: Keyword.get(opts, :config, %{})
    }
  end

  defp extract_identity(state) do
    identity = TlsIdentity.extract_from_socket(state.ssl_socket)
    %{state | identity: identity}
  end

  defp check_revocation(state) do
    # Only check revocation if we have an authenticated identity with a fingerprint
    case state.identity do
      %{authenticated: true, cert_fingerprint: fp} when is_binary(fp) ->
        # Check CRL if the CrlServer is running
        revoked = crl_revoked?(fp)

        try do
          AuditLog.cert_revocation_checked(fp, revoked)
        catch
          _, _ -> :ok
        end

        if revoked do
          throw({:session_reject, :cert_revoked, state})
        else
          state
        end

      _ ->
        # No identity or no fingerprint — nothing to check
        state
    end
  end

  defp crl_revoked?(fingerprint) do
    case GenServer.whereis(CrlServer) do
      nil -> false
      _pid -> CrlServer.revoked?(fingerprint)
    end
  catch
    :exit, _ -> false
  end

  defp extract_connection_info(state) do
    sni =
      case :ssl.connection_information(state.ssl_socket, [:sni_hostname]) do
        {:ok, info} ->
          case Keyword.get(info, :sni_hostname) do
            nil -> nil
            hostname -> to_string(hostname)
          end

        _ ->
          nil
      end

    conn_info =
      case :ssl.connection_information(state.ssl_socket) do
        {:ok, info} ->
          %{
            protocol: Keyword.get(info, :protocol),
            cipher_suite: format_cipher(Keyword.get(info, :selected_cipher_suite)),
            sni: sni
          }

        _ ->
          %{sni: sni}
      end

    %{state | sni: sni, conn_info: conn_info}
  end

  defp resolve_backend(state) do
    service = SniRouter.resolve(state.sni)
    %{state | service: service}
  end

  defp check_policy(state) do
    identity_str = identity_string(state.identity)

    if identity_str do
      unless PolicyEngine.authorize?(identity_str, state.service || "") do
        AuditLog.tls_auth_failed(state.sni, :policy_denied, state.source)
        throw({:session_reject, :policy_denied, state})
      end
    end

    state
  end

  defp check_assurance(state) do
    min_assurance = get_min_assurance(state.service, state.config)
    auth_mode = get_auth_mode(state.service, state.config)

    # In enforce mode, mTLS is required
    if auth_mode == :enforce and !identity_authenticated?(state.identity) do
      AuditLog.tls_auth_failed(state.sni, :mtls_required, state.source)
      throw({:session_reject, :mtls_required, state})
    end

    # Check assurance level if identity is present and min_assurance is set
    if min_assurance && identity_authenticated?(state.identity) do
      actual = Map.get(state.identity, :assurance, :unknown)

      unless assurance_sufficient?(actual, min_assurance) do
        AuditLog.assurance_insufficient(
          Map.get(state.identity, :node_id),
          actual,
          min_assurance,
          state.service
        )

        throw({:session_reject, :insufficient_assurance, state})
      end
    end

    state
  end

  defp audit_connection_established(state) do
    AuditLog.tls_connection_established(state.sni, state.identity, state.source)
    state
  end

  defp connect_backend(state) do
    backend_mode = get_backend_mode(state.service, state.config)

    case SniRouter.backend_for(state.service) do
      {:ok, {host, port}} ->
        case backend_mode do
          :tls ->
            tls_opts = [
              :binary,
              {:active, true},
              {:packet, :raw},
              {:verify, :verify_none}
            ]

            case :ssl.connect(host, port, tls_opts, @backend_connect_timeout) do
              {:ok, socket} ->
                %{state | backend_socket: {:ssl, socket}}

              {:error, reason} ->
                Logger.warning(
                  "[TlsSession] Backend TLS connection failed for #{state.service}: #{inspect(reason)}"
                )

                throw({:session_reject, {:backend_unavailable, reason}, state})
            end

          _tcp ->
            case :gen_tcp.connect(host, port, [:binary, {:active, true}, {:packet, :raw}],
                   @backend_connect_timeout
                 ) do
              {:ok, socket} ->
                %{state | backend_socket: {:tcp, socket}}

              {:error, reason} ->
                Logger.warning(
                  "[TlsSession] Backend connection failed for #{state.service}: #{inspect(reason)}"
                )

                throw({:session_reject, {:backend_unavailable, reason}, state})
            end
        end

      {:error, _} = err ->
        Logger.warning("[TlsSession] No backend for service #{inspect(state.service)}")
        throw({:session_reject, {:no_backend, err}, state})
    end
  end

  defp start_bidirectional_proxy(state) do
    # Switch SSL socket to active mode for bidirectional streaming
    :ssl.setopts(state.ssl_socket, [{:active, true}])

    # Enter the message receive loop
    proxy_receive_loop(state)
  end

  defp proxy_receive_loop(state) do
    client_socket = state.ssl_socket
    backend_raw = backend_raw_socket(state.backend_socket)

    receive do
      # Data from TLS client → forward to backend
      {:ssl, ^client_socket, data} ->
        state = %{state | bytes_in: state.bytes_in + byte_size(data)}

        # On first chunk, inject headers if HTTP
        {data, state} =
          if state.first_chunk and http_request?(data) do
            {HttpHeaderInjector.inject(data, state.identity, state.service),
             %{state | first_chunk: false}}
          else
            {data, %{state | first_chunk: false}}
          end

        case backend_send(state.backend_socket, data) do
          :ok ->
            proxy_receive_loop(state)

          {:error, reason} ->
            audit_connection_closed(state, {:backend_send_error, reason})
            {:error, reason}
        end

      # Data from TCP backend → forward to TLS client
      {:tcp, ^backend_raw, data} ->
        state = %{state | bytes_out: state.bytes_out + byte_size(data)}

        case :ssl.send(state.ssl_socket, data) do
          :ok ->
            proxy_receive_loop(state)

          {:error, reason} ->
            audit_connection_closed(state, {:client_send_error, reason})
            {:error, reason}
        end

      # Data from TLS backend → forward to TLS client
      {:ssl, ^backend_raw, data} ->
        state = %{state | bytes_out: state.bytes_out + byte_size(data)}

        case :ssl.send(state.ssl_socket, data) do
          :ok ->
            proxy_receive_loop(state)

          {:error, reason} ->
            audit_connection_closed(state, {:client_send_error, reason})
            {:error, reason}
        end

      # Client closed TLS connection
      {:ssl_closed, ^client_socket} ->
        audit_connection_closed(state, :client_close)
        :ok

      # Backend TCP closed
      {:tcp_closed, ^backend_raw} ->
        audit_connection_closed(state, :backend_close)
        :ok

      # Backend TLS closed
      {:ssl_closed, ^backend_raw} ->
        audit_connection_closed(state, :backend_close)
        :ok

      # SSL error on client side
      {:ssl_error, ^client_socket, reason} ->
        audit_connection_closed(state, {:ssl_error, reason})
        {:error, reason}

      # TCP error on backend
      {:tcp_error, ^backend_raw, reason} ->
        audit_connection_closed(state, {:tcp_error, reason})
        {:error, reason}

      # SSL error on backend
      {:ssl_error, ^backend_raw, reason} ->
        audit_connection_closed(state, {:tcp_error, reason})
        {:error, reason}
    after
      # Idle timeout — close session after 5 minutes of inactivity
      300_000 ->
        audit_connection_closed(state, :timeout)
        :ok
    end
  end

  # ── Backend Socket Helpers ─────────────────────────────────────────

  defp backend_send({:tcp, socket}, data), do: :gen_tcp.send(socket, data)
  defp backend_send({:ssl, socket}, data), do: :ssl.send(socket, data)

  defp backend_close({:tcp, socket}), do: :gen_tcp.close(socket)
  defp backend_close({:ssl, socket}), do: :ssl.close(socket)
  defp backend_close(nil), do: :ok

  defp backend_raw_socket({:tcp, socket}), do: socket
  defp backend_raw_socket({:ssl, socket}), do: socket
  defp backend_raw_socket(nil), do: nil

  # ── Audit & Cleanup ────────────────────────────────────────────────

  defp audit_connection_closed(state, reason) do
    duration_ms = System.monotonic_time(:millisecond) - state.started_at

    AuditLog.log_event(%{
      event: :tls_connection_closed,
      sni: state.sni,
      service: state.service,
      node_id: state.identity && Map.get(state.identity, :node_id),
      reason: reason,
      duration_ms: duration_ms,
      bytes_in: state.bytes_in,
      bytes_out: state.bytes_out,
      source: state.source
    })
  end

  defp handle_rejection(reason, state) do
    response =
      case reason do
        :policy_denied ->
          build_error_response(403, "policy_denied", "Access denied by policy")

        :mtls_required ->
          build_error_response(
            403,
            "mtls_required",
            "Client certificate required for this service"
          )

        :cert_revoked ->
          build_error_response(
            403,
            "cert_revoked",
            "Client certificate has been revoked"
          )

        :insufficient_assurance ->
          min = get_min_assurance(state.service, state.config)
          actual = state.identity && Map.get(state.identity, :assurance, :unknown)
          build_assurance_error_response(min, actual)

        _ ->
          build_error_response(502, "backend_error", "Service unavailable")
      end

    try do
      :ssl.send(state.ssl_socket, response)
    catch
      _, _ -> :ok
    end

    # Notify listener of close
    if state.listener_pid do
      send(state.listener_pid, {:connection_closed, reason})
    end
  end

  defp cleanup(state) do
    # Close backend socket if open
    backend_close(state[:backend_socket])

    # Close SSL socket
    try do
      :ssl.close(state.ssl_socket)
    catch
      _, _ -> :ok
    end
  end

  # ── Helpers ────────────────────────────────────────────────────────

  defp identity_string(nil), do: nil

  defp identity_string(%{authenticated: true} = identity) do
    Map.get(identity, :node_name) || Map.get(identity, :node_id)
  end

  defp identity_string(_), do: nil

  defp identity_authenticated?(nil), do: false
  defp identity_authenticated?(%{authenticated: true}), do: true
  defp identity_authenticated?(_), do: false

  @assurance_levels %{
    unknown: 0,
    software: 1,
    device_bound: 2,
    "device-bound": 2,
    hardware: 3
  }

  defp assurance_sufficient?(actual, required) do
    actual_level = Map.get(@assurance_levels, to_assurance_atom(actual), 0)
    required_level = Map.get(@assurance_levels, to_assurance_atom(required), 0)
    actual_level >= required_level
  end

  defp to_assurance_atom(val) when is_atom(val), do: val

  defp to_assurance_atom(val) when is_binary(val) do
    try do
      String.to_existing_atom(val)
    rescue
      _ -> :unknown
    end
  end

  defp to_assurance_atom(_), do: :unknown

  defp get_min_assurance(service, config) when is_map(config) do
    case Map.get(config, :min_assurance) do
      nil -> get_route_min_assurance(service)
      val -> val
    end
  end

  defp get_min_assurance(service, _config), do: get_route_min_assurance(service)

  defp get_route_min_assurance(nil), do: nil

  defp get_route_min_assurance(service) do
    case SniRouter.get_route(service) do
      {:ok, route} -> Map.get(route, :min_assurance)
      _ -> nil
    end
  end

  defp get_auth_mode(service, config) when is_map(config) do
    case Map.get(config, :auth_mode) do
      nil -> get_route_auth_mode(service)
      val -> val
    end
  end

  defp get_auth_mode(service, _config), do: get_route_auth_mode(service)

  defp get_route_auth_mode(nil), do: :passthrough

  defp get_route_auth_mode(service) do
    case SniRouter.get_route(service) do
      {:ok, route} -> Map.get(route, :auth_mode, :passthrough)
      _ -> :passthrough
    end
  end

  defp get_backend_mode(_service, config) when is_map(config) do
    Map.get(config, :backend_mode, :tcp)
  end

  defp get_backend_mode(_service, _config), do: :tcp

  defp http_request?(<<method, _::binary>>) when method in [?G, ?P, ?H, ?D, ?O, ?T, ?C],
    do: true

  defp http_request?(_), do: false

  defp format_cipher(nil), do: nil
  defp format_cipher(cipher) when is_map(cipher), do: inspect(cipher)
  defp format_cipher(cipher) when is_tuple(cipher), do: inspect(cipher)
  defp format_cipher(cipher) when is_binary(cipher), do: cipher
  defp format_cipher(cipher) when is_atom(cipher), do: Atom.to_string(cipher)
  defp format_cipher(cipher), do: inspect(cipher)

  defp build_error_response(status, error, message) do
    body =
      json_encode(%{
        "error" => error,
        "message" => message
      })

    status_text = http_status_text(status)

    "HTTP/1.1 #{status} #{status_text}\r\n" <>
      "Content-Type: application/json\r\n" <>
      "Content-Length: #{byte_size(body)}\r\n" <>
      "Connection: close\r\n" <>
      "\r\n" <>
      body
  end

  defp build_assurance_error_response(required, actual) do
    body =
      json_encode(%{
        "error" => "insufficient_assurance",
        "required" => to_string(required || "unknown"),
        "current" => to_string(actual || "unknown"),
        "message" =>
          "This service requires a higher authentication assurance level.",
        "hint" => "Re-enroll with: ztlp setup --hardware-key"
      })

    "HTTP/1.1 403 Forbidden\r\n" <>
      "Content-Type: application/json\r\n" <>
      "Content-Length: #{byte_size(body)}\r\n" <>
      "Connection: close\r\n" <>
      "\r\n" <>
      body
  end

  defp http_status_text(403), do: "Forbidden"
  defp http_status_text(502), do: "Bad Gateway"
  defp http_status_text(_), do: "Error"

  # ── Minimal JSON encoder (no external deps) ────────────────────

  defp json_encode(map) when is_map(map) do
    pairs =
      map
      |> Enum.map(fn {k, v} -> [json_str(to_string(k)), ":", json_val(v)] end)
      |> Enum.intersperse(",")

    IO.iodata_to_binary(["{", pairs, "}"])
  end

  defp json_val(v) when is_binary(v), do: json_str(v)
  defp json_val(v) when is_atom(v), do: json_str(Atom.to_string(v))
  defp json_val(v) when is_integer(v), do: Integer.to_string(v)
  defp json_val(nil), do: "null"
  defp json_val(v), do: json_str(to_string(v))

  defp json_str(s) do
    escaped =
      s
      |> String.replace("\\", "\\\\")
      |> String.replace("\"", "\\\"")
      |> String.replace("\n", "\\n")
      |> String.replace("\r", "\\r")
      |> String.replace("\t", "\\t")

    "\"#{escaped}\""
  end
end
