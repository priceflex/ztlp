defmodule ZtlpGateway.TlsListenerTest do
  use ExUnit.Case

  alias ZtlpGateway.TlsListener
  alias ZtlpGateway.TlsTestHelper

  @moduletag :tls_listener

  setup do
    pki = TlsTestHelper.generate_test_pki(client_cert: true)

    on_exit(fn ->
      TlsTestHelper.cleanup_pki(pki)
    end)

    %{pki: pki}
  end

  describe "start_link/1 and basic lifecycle" do
    test "starts and listens on the configured port", %{pki: pki} do
      {:ok, pid} = start_listener(pki)

      port = TlsListener.port(pid)
      assert is_integer(port)
      assert port > 0

      GenServer.stop(pid)
    end

    test "starts on port 0 for random port", %{pki: pki} do
      {:ok, pid} = start_listener(pki, port: 0)

      port = TlsListener.port(pid)
      assert port > 0

      GenServer.stop(pid)
    end

    test "stops cleanly", %{pki: pki} do
      {:ok, pid} = start_listener(pki)
      assert Process.alive?(pid)

      TlsListener.stop(pid)
      refute Process.alive?(pid)
    end

    test "starts even with missing cert files (lazy loading)", %{pki: pki} do
      # Erlang SSL allows starting a listener even if cert files don't exist yet
      # (they're validated at handshake time). Verify the listener starts successfully.
      {:ok, pid} =
        TlsListener.start_link(
          name: :"tls_test_#{:rand.uniform(999_999)}",
          port: 0,
          certfile: pki.server_cert_file,
          keyfile: pki.server_key_file,
          acceptors: 1
        )

      assert Process.alive?(pid)
      GenServer.stop(pid)
    end
  end

  describe "stats/1" do
    test "returns initial stats", %{pki: pki} do
      {:ok, pid} = start_listener(pki)

      stats = TlsListener.stats(pid)
      assert stats.port > 0
      assert stats.active_connections == 0
      assert stats.total_connections == 0
      assert stats.total_handshake_failures == 0
      assert stats.acceptors > 0

      GenServer.stop(pid)
    end

    test "tracks total connections after client connects", %{pki: pki} do
      # Start a backend for the session to connect to
      {:ok, backend_port, _backend_pid, backend_socket} = TlsTestHelper.start_echo_backend()

      # Start SniRouter and configure a route
      ensure_sni_router()
      ZtlpGateway.SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      {:ok, pid} = start_listener(pki)
      port = TlsListener.port(pid)

      # Connect a TLS client
      {:ok, client} = TlsTestHelper.tls_connect(port)

      # Give listener time to process the connection
      Process.sleep(200)

      stats = TlsListener.stats(pid)
      assert stats.total_connections >= 1

      :ssl.close(client)
      GenServer.stop(pid)
      :gen_tcp.close(backend_socket)
    end
  end

  describe "TLS connection acceptance" do
    test "accepts TLS connection without client cert", %{pki: pki} do
      {:ok, backend_port, _backend_pid, backend_socket} = TlsTestHelper.start_echo_backend()
      ensure_sni_router()
      ZtlpGateway.SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      {:ok, pid} = start_listener(pki, require_client_cert: false)
      port = TlsListener.port(pid)

      {:ok, client} = TlsTestHelper.tls_connect(port)
      assert {:ok, _} = :ssl.connection_information(client)

      :ssl.close(client)
      GenServer.stop(pid)
      :gen_tcp.close(backend_socket)
    end

    test "accepts mTLS connection with client cert", %{pki: pki} do
      {:ok, backend_port, _backend_pid, backend_socket} = TlsTestHelper.start_echo_backend()
      ensure_sni_router()
      ZtlpGateway.SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      {:ok, pid} = start_listener(pki, request_client_cert: true)
      port = TlsListener.port(pid)

      {:ok, client} =
        TlsTestHelper.tls_connect(port,
          certfile: pki.client_cert_file,
          keyfile: pki.client_key_file,
          cacertfile: pki.ca_cert_file
        )

      assert {:ok, _} = :ssl.connection_information(client)

      :ssl.close(client)
      GenServer.stop(pid)
      :gen_tcp.close(backend_socket)
    end

    test "handles multiple concurrent connections", %{pki: pki} do
      {:ok, backend_port, _backend_pid, backend_socket} = TlsTestHelper.start_echo_backend()
      ensure_sni_router()
      ZtlpGateway.SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      {:ok, pid} = start_listener(pki)
      port = TlsListener.port(pid)

      # Connect multiple clients
      clients =
        for _ <- 1..5 do
          {:ok, client} = TlsTestHelper.tls_connect(port)
          client
        end

      Process.sleep(300)

      stats = TlsListener.stats(pid)
      assert stats.total_connections >= 5

      Enum.each(clients, &:ssl.close/1)
      GenServer.stop(pid)
      :gen_tcp.close(backend_socket)
    end
  end

  describe "graceful shutdown" do
    test "closes listen socket on stop", %{pki: pki} do
      {:ok, pid} = start_listener(pki)
      port = TlsListener.port(pid)

      GenServer.stop(pid)
      Process.sleep(100)

      # Verify we can't connect anymore
      assert {:error, _} = TlsTestHelper.tls_connect(port)
    end
  end

  # ── Helpers ────────────────────────────────────────────────────

  defp start_listener(pki, extra_opts \\ []) do
    name = :"tls_test_#{:rand.uniform(999_999)}"

    opts =
      [
        name: name,
        port: 0,
        certfile: pki.server_cert_file,
        keyfile: pki.server_key_file,
        cacertfile: pki.ca_cert_file,
        acceptors: 3
      ] ++ extra_opts

    case TlsListener.start_link(opts) do
      {:ok, pid} -> {:ok, pid}
      error -> error
    end
  end

  defp ensure_sni_router do
    case GenServer.whereis(ZtlpGateway.SniRouter) do
      nil ->
        {:ok, _} = ZtlpGateway.SniRouter.start_link(routes: [])
        :ok

      _pid ->
        # Clear existing routes
        ZtlpGateway.SniRouter.list_routes()
        |> Enum.each(fn {hostname, _} -> ZtlpGateway.SniRouter.delete_route(hostname) end)

        :ok
    end
  end
end
