defmodule ZtlpGateway.TlsTerminator do
  @moduledoc """
  TLS termination bridge for ZTLP mux streams.

  Creates a local socket pair where one side accepts TLS and the other
  side is used by the Session to write/read encrypted client data.
  The TLS bridge decrypts client data → sends to backend, and encrypts
  backend responses → sends back to client via mux stream.

  ## Architecture

      Client (phone) → encrypted TLS data → ZTLP mux stream
          → Session writes to client_socket
          → server_tcp (accept side) → :ssl.handshake → ssl_socket
          → TLS proxy reads decrypted data
          → sends {:tls_decrypted, stream_id, data} to Session
          → Session forwards to Backend

      Backend response → Session sends {:backend_response, data}
          → TLS proxy receives
          → :ssl.send(ssl_socket, data) (encrypts)
          → encrypted data flows out client_socket
          → Session reads from client_socket → mux FRAME_DATA to phone

  The client_socket is set to `{active: true}` in the Session so that
  TLS-encrypted response data arrives as `{:tcp, socket, data}` messages.
  """

  require Logger

  @doc """
  Start a TLS termination bridge for a mux stream.

  Returns `{:ok, client_socket, bridge_pid}` or `{:error, reason}`.
  The bridge_pid can receive `{:backend_response, data}` messages.
  """
  @spec start_bridge(String.t(), String.t(), String.t(), pid(), non_neg_integer()) ::
          {:ok, port(), pid()} | {:error, term()}
  def start_bridge(cert_pem, key_pem, chain_pem, owner, stream_id) do
    # Write certs to temp files
    tmp_dir = System.tmp_dir!()
    cert_path = Path.join(tmp_dir, "ztlp_cert_#{stream_id}_#{:rand.uniform(999999)}.pem")
    key_path = Path.join(tmp_dir, "ztlp_key_#{stream_id}_#{:rand.uniform(999999)}.pem")

    File.write!(cert_path, cert_pem <> chain_pem)
    File.write!(key_path, key_pem)

    # Start local TCP listener on ephemeral port
    {:ok, listen} = :gen_tcp.listen(0, [
      :binary,
      active: false,
      reuseaddr: true,
      ip: {127, 0, 0, 1},
      backlog: 1
    ])

    {:ok, listen_port} = :inet.port(listen)

    # Connect client side (this is the socket Session writes to / reads from)
    {:ok, client_socket} = :gen_tcp.connect({127, 0, 0, 1}, listen_port, [
      :binary,
      active: true  # Session receives {:tcp, socket, data} for encrypted responses
    ])

    # Spawn bridge process that accepts TLS on the server side
    bridge_pid = spawn_link(fn ->
      try do
        {:ok, server_tcp} = :gen_tcp.accept(listen, 10_000)
        :gen_tcp.close(listen)

        ssl_opts = [
          certfile: String.to_charlist(cert_path),
          keyfile: String.to_charlist(key_path),
          versions: [:"tlsv1.2", :"tlsv1.3"],
          verify: :verify_none,
          active: true
        ]

        case :ssl.handshake(server_tcp, ssl_opts, 15_000) do
          {:ok, ssl_socket} ->
            Logger.info("[TlsTerminator] TLS handshake complete for stream #{stream_id}")
            proxy_loop(ssl_socket, owner, stream_id, cert_path, key_path)

          {:error, reason} ->
            Logger.warning("[TlsTerminator] TLS handshake failed for stream #{stream_id}: #{inspect(reason)}")
            send(owner, {:tls_closed, stream_id})
            cleanup_files(cert_path, key_path)
        end
      rescue
        e ->
          Logger.error("[TlsTerminator] Bridge error for stream #{stream_id}: #{inspect(e)}")
          send(owner, {:tls_closed, stream_id})
          cleanup_files(cert_path, key_path)
      end
    end)

    {:ok, client_socket, bridge_pid}
  end

  # Bidirectional proxy loop
  defp proxy_loop(ssl_socket, owner, stream_id, cert_path, key_path) do
    receive do
      # Decrypted data from client (TLS decrypted automatically by :ssl)
      {:ssl, ^ssl_socket, data} ->
        send(owner, {:tls_decrypted, stream_id, data})
        proxy_loop(ssl_socket, owner, stream_id, cert_path, key_path)

      # Backend response to send to client (will be TLS-encrypted by :ssl)
      {:backend_response, data} ->
        case :ssl.send(ssl_socket, data) do
          :ok -> :ok
          {:error, reason} ->
            Logger.warning("[TlsTerminator] SSL send failed for stream #{stream_id}: #{inspect(reason)}")
        end
        proxy_loop(ssl_socket, owner, stream_id, cert_path, key_path)

      # TLS connection closed by client
      {:ssl_closed, ^ssl_socket} ->
        Logger.info("[TlsTerminator] TLS closed for stream #{stream_id}")
        send(owner, {:tls_closed, stream_id})
        cleanup_files(cert_path, key_path)

      {:ssl_error, ^ssl_socket, reason} ->
        Logger.warning("[TlsTerminator] TLS error for stream #{stream_id}: #{inspect(reason)}")
        send(owner, {:tls_closed, stream_id})
        cleanup_files(cert_path, key_path)

      :close ->
        :ssl.close(ssl_socket)
        cleanup_files(cert_path, key_path)

    after
      300_000 ->
        Logger.info("[TlsTerminator] TLS idle timeout for stream #{stream_id}")
        :ssl.close(ssl_socket)
        send(owner, {:tls_closed, stream_id})
        cleanup_files(cert_path, key_path)
    end
  end

  defp cleanup_files(cert_path, key_path) do
    File.rm(cert_path)
    File.rm(key_path)
  end
end
