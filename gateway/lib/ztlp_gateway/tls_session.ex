defmodule ZtlpGateway.TlsSession do
  @moduledoc """
  TLS session handler for the ZTLP Gateway.

  Manages the full lifecycle of a single TLS client connection:

  1. TLS handshake (already done by TlsListener acceptor)
  2. Extract mTLS identity from client certificate
  3. Determine backend via SNI routing
  4. Check policy (PolicyEngine.authorize?/2)
  5. Check assurance level against backend min_assurance
  6. Inject identity headers into HTTP requests
  7. Bidirectional proxy to backend
  8. Track connection stats + audit log

  ## Architecture

      TlsListener
        └── TlsSession (one per connection)
              ├── TlsIdentity.extract_from_socket/1
              ├── SniRouter.resolve/1
              ├── PolicyEngine.authorize?/2
              ├── HttpHeaderInjector.inject/3
              └── Backend TCP proxy (bidirectional)

  Sessions are started by `TlsListener` and run as independent processes.
  Each session tracks bytes transferred and connection duration for audit.
  """

  require Logger

  alias ZtlpGateway.{
    AuditLog,
    HttpHeaderInjector,
    PolicyEngine,
    SniRouter,
    TlsIdentity
  }

  @recv_timeout 30_000
  @backend_connect_timeout 5_000
  @backend_recv_timeout 30_000

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
          conn_info: map()
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
      |> extract_connection_info()
      |> resolve_backend()
      |> check_policy()
      |> check_assurance()
      |> audit_connection_established()
      |> connect_backend()
      |> proxy_loop()
    catch
      :throw, {:session_reject, reason, state} ->
        handle_rejection(reason, state)
        {:error, reason}
    after
      cleanup(state)
    end
  end

  @doc """
  Start a TLS session as a linked process.

  Returns `{:ok, pid}`.
  """
  @spec start_link(ssl_socket :: :ssl.sslsocket(), opts :: keyword()) :: {:ok, pid()}
  def start_link(ssl_socket, opts \\ []) do
    pid =
      spawn_link(fn ->
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
      listener_pid: Keyword.get(opts, :listener_pid),
      config: Keyword.get(opts, :config, %{})
    }
  end

  defp extract_identity(state) do
    identity = TlsIdentity.extract_from_socket(state.ssl_socket)
    %{state | identity: identity}
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
    # Determine identity string for policy check
    identity_str = identity_string(state.identity)

    # If identity is present, check policy; otherwise allow (mTLS may be optional)
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
    case SniRouter.backend_for(state.service) do
      {:ok, {host, port}} ->
        case :gen_tcp.connect(host, port, [:binary, {:active, false}], @backend_connect_timeout) do
          {:ok, socket} ->
            %{state | backend_socket: socket}

          {:error, reason} ->
            Logger.warning(
              "[TlsSession] Backend connection failed for #{state.service}: #{inspect(reason)}"
            )

            throw({:session_reject, {:backend_unavailable, reason}, state})
        end

      {:error, _} = err ->
        Logger.warning("[TlsSession] No backend for service #{inspect(state.service)}")
        throw({:session_reject, {:no_backend, err}, state})
    end
  end

  defp proxy_loop(state) do
    case :ssl.recv(state.ssl_socket, 0, @recv_timeout) do
      {:ok, data} ->
        state = %{state | bytes_in: state.bytes_in + byte_size(data)}

        # Inject identity headers if this looks like HTTP
        data =
          if http_request?(data) do
            HttpHeaderInjector.inject(data, state.identity, state.service)
          else
            data
          end

        # Forward to backend
        case :gen_tcp.send(state.backend_socket, data) do
          :ok ->
            # Read response from backend and send back to client
            state = relay_backend_response(state)
            proxy_loop(state)

          {:error, reason} ->
            audit_connection_closed(state, :backend_error)
            {:error, reason}
        end

      {:error, :closed} ->
        audit_connection_closed(state, :client_close)
        :ok

      {:error, :timeout} ->
        audit_connection_closed(state, :timeout)
        :ok

      {:error, reason} ->
        audit_connection_closed(state, reason)
        {:error, reason}
    end
  end

  defp relay_backend_response(state) do
    case :gen_tcp.recv(state.backend_socket, 0, @backend_recv_timeout) do
      {:ok, response} ->
        :ssl.send(state.ssl_socket, response)
        %{state | bytes_out: state.bytes_out + byte_size(response)}

      {:error, _reason} ->
        state
    end
  end

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
    # Send a 403 response for HTTP-like connections
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

        :insufficient_assurance ->
          min = get_min_assurance(state.service, state.config)
          actual = state.identity && Map.get(state.identity, :assurance, :unknown)

          build_assurance_error_response(min, actual)

        _ ->
          build_error_response(502, "backend_error", "Service unavailable")
      end

    :ssl.send(state.ssl_socket, response)

    # Notify listener of close
    if state.listener_pid do
      send(state.listener_pid, {:connection_closed, reason})
    end
  end

  defp cleanup(state) do
    # Close backend socket if open
    if state.backend_socket do
      :gen_tcp.close(state.backend_socket)
    end

    # Close SSL socket
    try do
      :ssl.close(state.ssl_socket)
    catch
      _, _ -> :ok
    end

    # Notify listener
    if state[:listener_pid] do
      send(state.listener_pid, {:connection_closed, :normal})
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
  defp to_assurance_atom(val) when is_binary(val), do: String.to_existing_atom(val)
  defp to_assurance_atom(_), do: :unknown

  defp get_min_assurance(_service, config) when is_map(config) do
    Map.get(config, :min_assurance)
  end

  defp get_min_assurance(_service, _config), do: nil

  defp get_auth_mode(_service, config) when is_map(config) do
    Map.get(config, :auth_mode, :passthrough)
  end

  defp get_auth_mode(_service, _config), do: :passthrough

  defp http_request?(<<method, _::binary>>) when method in [?G, ?P, ?H, ?D, ?O, ?T, ?C],
    do: true

  defp http_request?(_), do: false

  defp format_cipher(nil), do: nil
  defp format_cipher(cipher) when is_tuple(cipher), do: inspect(cipher)
  defp format_cipher(cipher), do: to_string(cipher)

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
