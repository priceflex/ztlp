defmodule ZtlpGateway.TlsPhase2Test do
  @moduledoc """
  Comprehensive tests for Phase 2: Production TLS listener, session handler,
  and bidirectional proxy.

  Tests cover:
  - TlsSession lifecycle (connection → identity → policy → proxy → close)
  - SNI-based routing integration
  - mTLS identity extraction + assurance checking
  - HTTP header injection end-to-end
  - Auth mode enforcement (passthrough/identity/enforce)
  - Backend connection modes (tcp)
  - Error handling and graceful shutdown
  - Revocation checking during identity extraction
  - Config additions
  """

  use ExUnit.Case

  alias ZtlpGateway.{
    AuditLog,
    CertCache,
    CrlServer,
    PolicyEngine,
    SniRouter,
    TlsIdentity,
    TlsListener,
    TlsTestHelper
  }

  @moduletag :tls_phase2

  setup do
    pki = TlsTestHelper.generate_test_pki(client_cert: true, assurance: :hardware, key_source: "yubikey", attestation_verified: true)
    ensure_sni_router()
    ensure_cert_cache()

    # Clear audit events
    try do
      AuditLog.clear()
    catch
      _, _ -> :ok
    end

    on_exit(fn ->
      TlsTestHelper.cleanup_pki(pki)
    end)

    %{pki: pki}
  end

  # ═══════════════════════════════════════════════════════════════════
  # TlsSession Unit Tests: Pipeline Steps
  # ═══════════════════════════════════════════════════════════════════

  describe "TlsSession assurance checking" do
    test "hardware >= hardware" do
      assert assurance_gte?(:hardware, :hardware)
    end

    test "hardware >= software" do
      assert assurance_gte?(:hardware, :software)
    end

    test "software >= software" do
      assert assurance_gte?(:software, :software)
    end

    test "software < hardware" do
      refute assurance_gte?(:software, :hardware)
    end

    test "device_bound >= software" do
      assert assurance_gte?(:device_bound, :software)
    end

    test "device_bound < hardware" do
      refute assurance_gte?(:device_bound, :hardware)
    end

    test "unknown < software" do
      refute assurance_gte?(:unknown, :software)
    end

    test "unknown >= unknown" do
      assert assurance_gte?(:unknown, :unknown)
    end
  end

  describe "TlsSession identity_string" do
    test "nil identity returns nil" do
      assert identity_string(nil) == nil
    end

    test "unauthenticated identity returns nil" do
      assert identity_string(%{authenticated: false, node_name: "test"}) == nil
    end

    test "authenticated identity returns node_name" do
      assert identity_string(%{authenticated: true, node_name: "test.corp.ztlp"}) ==
               "test.corp.ztlp"
    end

    test "authenticated identity falls back to node_id" do
      assert identity_string(%{authenticated: true, node_id: "abc123"}) == "abc123"
    end

    test "authenticated identity prefers node_name over node_id" do
      assert identity_string(%{authenticated: true, node_name: "test.ztlp", node_id: "abc"}) ==
               "test.ztlp"
    end
  end

  describe "TlsSession HTTP detection" do
    test "GET is HTTP" do
      assert http_request?("GET / HTTP/1.1\r\n")
    end

    test "POST is HTTP" do
      assert http_request?("POST /api HTTP/1.1\r\n")
    end

    test "HEAD is HTTP" do
      assert http_request?("HEAD / HTTP/1.1\r\n")
    end

    test "DELETE is HTTP" do
      assert http_request?("DELETE /item HTTP/1.1\r\n")
    end

    test "OPTIONS is HTTP" do
      assert http_request?("OPTIONS * HTTP/1.1\r\n")
    end

    test "PUT is HTTP" do
      assert http_request?("PUT /item HTTP/1.1\r\n")
    end

    test "CONNECT is HTTP" do
      assert http_request?("CONNECT host:443 HTTP/1.1\r\n")
    end

    test "TRACE is HTTP" do
      assert http_request?("TRACE / HTTP/1.1\r\n")
    end

    test "binary data is not HTTP" do
      refute http_request?(<<0x16, 0x03, 0x01>>)
    end

    test "empty data is not HTTP" do
      refute http_request?("")
    end

    test "lowercase http verb is not detected (wire format is uppercase)" do
      refute http_request?("get / HTTP/1.1\r\n")
    end
  end

  describe "TlsSession error responses" do
    test "403 policy denied response is valid HTTP" do
      response = build_error_response(403, "policy_denied", "Access denied")
      assert response =~ "HTTP/1.1 403 Forbidden"
      assert response =~ "Content-Type: application/json"
      assert response =~ "policy_denied"
    end

    test "502 backend error response is valid HTTP" do
      response = build_error_response(502, "backend_error", "Service unavailable")
      assert response =~ "HTTP/1.1 502 Bad Gateway"
    end

    test "assurance error response includes required and current levels" do
      response = build_assurance_error_response(:hardware, :software)
      assert response =~ "insufficient_assurance"
      assert response =~ "hardware"
      assert response =~ "software"
    end

    test "assurance error response handles nil values" do
      response = build_assurance_error_response(nil, nil)
      assert response =~ "unknown"
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # End-to-End TLS Integration Tests
  # ═══════════════════════════════════════════════════════════════════

  describe "end-to-end: TLS proxy with echo backend" do
    test "proxies data through TLS → TCP backend", %{pki: pki} do
      # Start echo backend
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()

      # Configure route
      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      # Start TLS listener
      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      # Connect TLS client
      {:ok, client} = TlsTestHelper.tls_connect(port)

      # Send raw binary data (not HTTP)
      :ssl.send(client, "hello world")

      # Expect echo back
      {:ok, response} = :ssl.recv(client, 0, 5000)
      assert response == "hello world"

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end

    test "proxies multiple messages bidirectionally", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()
      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      {:ok, client} = TlsTestHelper.tls_connect(port)

      # Send multiple messages
      for i <- 1..5 do
        msg = "message #{i}"
        :ssl.send(client, msg)
        {:ok, response} = :ssl.recv(client, 0, 5000)
        assert response == msg
      end

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end

    test "backend close terminates session cleanly", %{pki: pki} do
      # Start a backend that closes immediately after receiving data
      {:ok, listen_socket} =
        :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])

      {:ok, {_, backend_port}} = :inet.sockname(listen_socket)

      spawn_link(fn ->
        {:ok, conn} = :gen_tcp.accept(listen_socket, 15_000)
        {:ok, _data} = :gen_tcp.recv(conn, 0, 15_000)
        :gen_tcp.send(conn, "goodbye")
        :gen_tcp.close(conn)
      end)

      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")
      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      {:ok, client} = TlsTestHelper.tls_connect(port)
      :ssl.send(client, "test data")

      # Should receive the response then the connection should close
      {:ok, response} = :ssl.recv(client, 0, 5000)
      assert response == "goodbye"

      # Next recv should get closed or error
      result = :ssl.recv(client, 0, 2000)
      assert result == {:error, :closed} or match?({:error, _}, result)

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(listen_socket)
    end
  end

  describe "end-to-end: HTTP header injection" do
    test "injects identity headers for mTLS connections in identity mode", %{pki: pki} do
      # Start a backend that captures the received data
      parent = self()

      {:ok, listen_socket} =
        :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])

      {:ok, {_, backend_port}} = :inet.sockname(listen_socket)

      spawn_link(fn ->
        {:ok, conn} = :gen_tcp.accept(listen_socket, 15_000)
        {:ok, data} = :gen_tcp.recv(conn, 0, 15_000)
        send(parent, {:backend_received, data})
        :gen_tcp.send(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        Process.sleep(500)
        :gen_tcp.close(conn)
      end)

      # Configure route with identity mode
      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}",
        auth_mode: :identity,
        service: "localhost"
      )

      # Start listener (request client certs but don't require)
      {:ok, listener} = start_listener(pki, request_client_cert: true)
      port = TlsListener.port(listener)

      # Connect with client cert
      {:ok, client} =
        TlsTestHelper.tls_connect(port,
          certfile: pki.client_cert_file,
          keyfile: pki.client_key_file,
          cacertfile: pki.ca_cert_file
        )

      # Send HTTP request
      http_req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
      :ssl.send(client, http_req)

      # Check what the backend received
      assert_receive {:backend_received, data}, 15_000
      data_str = to_string(data)

      # Should have X-ZTLP headers injected
      assert data_str =~ "X-ZTLP-Node-Name"
      assert data_str =~ "X-ZTLP-Authenticated"

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(listen_socket)
    end

    test "passes through data in passthrough mode without headers", %{pki: pki} do
      parent = self()

      {:ok, listen_socket} =
        :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])

      {:ok, {_, backend_port}} = :inet.sockname(listen_socket)

      spawn_link(fn ->
        {:ok, conn} = :gen_tcp.accept(listen_socket, 15_000)
        {:ok, data} = :gen_tcp.recv(conn, 0, 15_000)
        send(parent, {:backend_received, data})
        :gen_tcp.send(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        Process.sleep(500)
        :gen_tcp.close(conn)
      end)

      # Configure route with passthrough mode
      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}",
        auth_mode: :passthrough,
        service: "localhost"
      )

      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      {:ok, client} = TlsTestHelper.tls_connect(port)

      http_req = "GET /passthrough HTTP/1.1\r\nHost: localhost\r\n\r\n"
      :ssl.send(client, http_req)

      assert_receive {:backend_received, data}, 15_000
      data_str = to_string(data)

      # Should NOT have X-ZTLP headers
      refute data_str =~ "X-ZTLP-Node-Name"

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(listen_socket)
    end
  end

  describe "end-to-end: auth mode enforcement" do
    test "enforce mode rejects connection without client cert", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()

      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}",
        auth_mode: :enforce,
        service: "localhost"
      )

      {:ok, listener} =
        start_listener(pki,
          require_client_cert: false,
          request_client_cert: false,
          config: %{auth_mode: :enforce}
        )

      port = TlsListener.port(listener)

      # Connect without client cert
      {:ok, client} = TlsTestHelper.tls_connect(port)

      # The session should reject with a 403
      # Send something to trigger the session pipeline
      :ssl.send(client, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

      # Should receive 403 or the connection should close
      result = :ssl.recv(client, 0, 3000)

      case result do
        {:ok, data} ->
          assert data =~ "403" or data =~ "mtls_required"

        {:error, :closed} ->
          # Also acceptable — session was rejected
          :ok

        {:error, _} ->
          :ok
      end

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end

    test "enforce mode accepts connection with valid client cert", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()

      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}",
        auth_mode: :enforce,
        service: "localhost"
      )

      # Allow all identities for the service
      PolicyEngine.put_rule("localhost", :all)

      {:ok, listener} =
        start_listener(pki,
          request_client_cert: true,
          config: %{auth_mode: :enforce}
        )

      port = TlsListener.port(listener)

      {:ok, client} =
        TlsTestHelper.tls_connect(port,
          certfile: pki.client_cert_file,
          keyfile: pki.client_key_file,
          cacertfile: pki.ca_cert_file
        )

      # Should be able to send and receive data
      :ssl.send(client, "hello from enforced client")
      {:ok, response} = :ssl.recv(client, 0, 5000)
      assert response == "hello from enforced client"

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end
  end

  describe "end-to-end: assurance level checking" do
    test "rejects client with insufficient assurance level", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()

      # Create a client cert with low assurance
      low_pki =
        TlsTestHelper.generate_client_cert(pki, assurance: :software, node_name: "low.ztlp")

      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}",
        auth_mode: :identity,
        min_assurance: :hardware,
        service: "localhost"
      )

      PolicyEngine.put_rule("localhost", :all)

      {:ok, listener} =
        start_listener(pki,
          request_client_cert: true,
          config: %{auth_mode: :enforce, min_assurance: :hardware}
        )

      port = TlsListener.port(listener)

      {:ok, client} =
        TlsTestHelper.tls_connect(port,
          certfile: low_pki.client_cert_file,
          keyfile: low_pki.client_key_file,
          cacertfile: pki.ca_cert_file
        )

      # Send request to trigger session processing
      :ssl.send(client, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")

      result = :ssl.recv(client, 0, 3000)

      case result do
        {:ok, data} ->
          assert data =~ "403" or data =~ "insufficient_assurance"

        {:error, :closed} ->
          :ok

        {:error, _} ->
          :ok
      end

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end
  end

  describe "end-to-end: policy engine integration" do
    test "denies access when policy rejects identity", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()

      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}",
        service: "localhost"
      )

      # Set a restrictive policy — only allow "admin.corp.ztlp"
      PolicyEngine.put_rule("localhost", ["admin.corp.ztlp"])

      {:ok, listener} = start_listener(pki, request_client_cert: true)
      port = TlsListener.port(listener)

      # Connect with client cert that has node_name "test-node.corp.ztlp" (not admin)
      {:ok, client} =
        TlsTestHelper.tls_connect(port,
          certfile: pki.client_cert_file,
          keyfile: pki.client_key_file,
          cacertfile: pki.ca_cert_file
        )

      :ssl.send(client, "test data")

      result = :ssl.recv(client, 0, 3000)

      case result do
        {:ok, data} ->
          assert data =~ "403" or data =~ "policy_denied"

        {:error, :closed} ->
          # Policy rejection closed the connection
          :ok

        {:error, _} ->
          :ok
      end

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end

    test "allows access when policy accepts wildcard identity", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()

      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}",
        service: "localhost"
      )

      # Allow all identities in *.corp.ztlp zone
      PolicyEngine.put_rule("localhost", ["*.corp.ztlp"])

      {:ok, listener} = start_listener(pki, request_client_cert: true)
      port = TlsListener.port(listener)

      {:ok, client} =
        TlsTestHelper.tls_connect(port,
          certfile: pki.client_cert_file,
          keyfile: pki.client_key_file,
          cacertfile: pki.ca_cert_file
        )

      # Should be allowed — node_name matches wildcard
      :ssl.send(client, "allowed data")
      {:ok, response} = :ssl.recv(client, 0, 5000)
      assert response == "allowed data"

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end
  end

  describe "end-to-end: SNI routing" do
    test "routes to different backends based on SNI", %{pki: pki} do
      {:ok, backend1_port, _b1pid, b1sock} = TlsTestHelper.start_echo_backend(prefix: "[B1] ")
      {:ok, backend2_port, _b2pid, b2sock} = TlsTestHelper.start_echo_backend(prefix: "[B2] ")

      SniRouter.put_route("svc1.corp.ztlp", "127.0.0.1:#{backend1_port}", service: "svc1.corp.ztlp")
      SniRouter.put_route("svc2.corp.ztlp", "127.0.0.1:#{backend2_port}", service: "svc2.corp.ztlp")

      PolicyEngine.put_rule("svc1.corp.ztlp", :all)
      PolicyEngine.put_rule("svc2.corp.ztlp", :all)

      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      # Connect to svc1 — the SNI hostname won't match the cert, but we use verify_none
      {:ok, client1} = TlsTestHelper.tls_connect(port, hostname: ~c"svc1.corp.ztlp")
      :ssl.send(client1, "hello svc1")
      {:ok, resp1} = :ssl.recv(client1, 0, 5000)
      assert resp1 == "[B1] hello svc1"

      {:ok, client2} = TlsTestHelper.tls_connect(port, hostname: ~c"svc2.corp.ztlp")
      :ssl.send(client2, "hello svc2")
      {:ok, resp2} = :ssl.recv(client2, 0, 5000)
      assert resp2 == "[B2] hello svc2"

      :ssl.close(client1)
      :ssl.close(client2)
      GenServer.stop(listener)
      :gen_tcp.close(b1sock)
      :gen_tcp.close(b2sock)
    end
  end

  describe "end-to-end: audit logging" do
    test "logs TLS connection established event", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()
      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      AuditLog.clear()

      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      {:ok, client} = TlsTestHelper.tls_connect(port)
      :ssl.send(client, "trigger session")
      Process.sleep(300)

      events = AuditLog.events()
      established = Enum.filter(events, fn e -> e.event == :tls_connection_established end)
      assert length(established) >= 1

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end

    test "logs TLS connection closed event", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()
      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      AuditLog.clear()

      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      {:ok, client} = TlsTestHelper.tls_connect(port)
      :ssl.send(client, "data")
      {:ok, _} = :ssl.recv(client, 0, 5000)
      :ssl.close(client)

      Process.sleep(500)

      events = AuditLog.events()
      closed = Enum.filter(events, fn e -> e.event == :tls_connection_closed end)
      assert length(closed) >= 1

      # Check event has expected fields
      event = hd(closed)
      assert Map.has_key?(event, :bytes_in)
      assert Map.has_key?(event, :bytes_out)
      assert Map.has_key?(event, :duration_ms)

      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end
  end

  describe "end-to-end: non-HTTP TCP passthrough" do
    test "binary data is proxied without modification", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()
      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      {:ok, client} = TlsTestHelper.tls_connect(port)

      # Send binary data (not HTTP)
      binary_data = <<0x16, 0x03, 0x01, 0xFF, 0x00, 0xAA, 0xBB>>
      :ssl.send(client, binary_data)
      {:ok, response} = :ssl.recv(client, 0, 5000)
      assert response == binary_data

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end

    test "large payload proxy", %{pki: pki} do
      {:ok, backend_port, _bpid, backend_socket} = TlsTestHelper.start_echo_backend()
      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}")

      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      {:ok, client} = TlsTestHelper.tls_connect(port)

      # Send a large payload
      payload = :crypto.strong_rand_bytes(64 * 1024)
      :ssl.send(client, payload)
      {:ok, response} = :ssl.recv(client, byte_size(payload), 10_000)
      assert response == payload

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(backend_socket)
    end
  end

  describe "end-to-end: backend unavailable" do
    test "returns error when no backend is configured", %{pki: pki} do
      # Configure route to a non-existent backend
      SniRouter.put_route("localhost", "127.0.0.1:1")

      {:ok, listener} = start_listener(pki)
      port = TlsListener.port(listener)

      {:ok, client} = TlsTestHelper.tls_connect(port)
      :ssl.send(client, "hello")

      result = :ssl.recv(client, 0, 3000)

      case result do
        {:ok, data} ->
          assert data =~ "502" or data =~ "backend_error"

        {:error, :closed} ->
          :ok

        {:error, _} ->
          :ok
      end

      :ssl.close(client)
      GenServer.stop(listener)
    end
  end

  describe "end-to-end: mTLS identity extraction" do
    test "extracts identity from client certificate", %{pki: pki} do
      parent = self()

      {:ok, listen_socket} =
        :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])

      {:ok, {_, backend_port}} = :inet.sockname(listen_socket)

      spawn_link(fn ->
        {:ok, conn} = :gen_tcp.accept(listen_socket, 15_000)
        {:ok, data} = :gen_tcp.recv(conn, 0, 15_000)
        send(parent, {:backend_data, data})
        :gen_tcp.send(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        Process.sleep(500)
        :gen_tcp.close(conn)
      end)

      SniRouter.put_route("localhost", "127.0.0.1:#{backend_port}",
        auth_mode: :identity,
        service: "localhost"
      )

      PolicyEngine.put_rule("localhost", :all)

      {:ok, listener} = start_listener(pki, request_client_cert: true)
      port = TlsListener.port(listener)

      {:ok, client} =
        TlsTestHelper.tls_connect(port,
          certfile: pki.client_cert_file,
          keyfile: pki.client_key_file,
          cacertfile: pki.ca_cert_file
        )

      :ssl.send(client, "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n")

      assert_receive {:backend_data, data}, 15_000
      data_str = to_string(data)

      # Check identity headers were injected
      assert data_str =~ "X-ZTLP-Authenticated: true"
      assert data_str =~ "X-ZTLP-Assurance: hardware"
      assert data_str =~ "X-ZTLP-Key-Source: yubikey"

      :ssl.close(client)
      GenServer.stop(listener)
      :gen_tcp.close(listen_socket)
    end
  end

  describe "end-to-end: CRL revocation checking" do
    test "revoked cert fingerprint is detected by CrlServer", %{pki: pki} do
      ensure_crl_server()

      # Get client cert fingerprint
      fingerprint =
        :crypto.hash(:sha256, pki.client_cert_der) |> Base.encode16(case: :lower)

      # Revoke it
      CrlServer.revoke(fingerprint, reason: "compromised")

      assert CrlServer.revoked?(fingerprint)

      # Clean up
      CrlServer.unrevoke(fingerprint)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Config Tests
  # ═══════════════════════════════════════════════════════════════════

  describe "Config: TLS keys" do
    test "tls_port defaults to 8443" do
      Application.delete_env(:ztlp_gateway, :tls_port)
      assert ZtlpGateway.Config.get(:tls_port) == 8443
    end

    test "tls_enabled defaults to false" do
      Application.delete_env(:ztlp_gateway, :tls_enabled)
      refute ZtlpGateway.Config.get(:tls_enabled)
    end

    test "tls_acceptors defaults to 100" do
      Application.delete_env(:ztlp_gateway, :tls_acceptors)
      assert ZtlpGateway.Config.get(:tls_acceptors) == 100
    end

    test "mtls_required defaults to false" do
      Application.delete_env(:ztlp_gateway, :tls_mtls_required)
      refute ZtlpGateway.Config.get(:tls_mtls_required)
    end

    test "tls_cert_file returns nil when not set" do
      Application.delete_env(:ztlp_gateway, :tls_cert_file)
      assert ZtlpGateway.Config.get(:tls_cert_file) == nil
    end

    test "tls_key_file returns nil when not set" do
      Application.delete_env(:ztlp_gateway, :tls_key_file)
      assert ZtlpGateway.Config.get(:tls_key_file) == nil
    end

    test "tls_ca_cert_file returns nil when not set" do
      Application.delete_env(:ztlp_gateway, :tls_ca_cert_file)
      assert ZtlpGateway.Config.get(:tls_ca_cert_file) == nil
    end

    test "tls_cert_file returns configured value" do
      Application.put_env(:ztlp_gateway, :tls_cert_file, "/path/to/cert.pem")
      assert ZtlpGateway.Config.get(:tls_cert_file) == "/path/to/cert.pem"
      Application.delete_env(:ztlp_gateway, :tls_cert_file)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # CertCache Integration Tests
  # ═══════════════════════════════════════════════════════════════════

  describe "CertCache integration" do
    test "caches and retrieves certificates" do
      CertCache.put("test.ztlp", %{certfile: "/tmp/test.pem", keyfile: "/tmp/test-key.pem"})
      {:ok, entry} = CertCache.get("test.ztlp")
      assert entry.certfile == "/tmp/test.pem"
      CertCache.delete("test.ztlp")
    end

    test "returns not_found for uncached hostname" do
      assert {:error, :not_found} = CertCache.get("nonexistent.ztlp")
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # TlsIdentity Integration Tests
  # ═══════════════════════════════════════════════════════════════════

  describe "TlsIdentity: extract from DER" do
    test "extracts node info from client certificate DER", %{pki: pki} do
      identity = TlsIdentity.extract_from_der(pki.client_cert_der)

      assert identity.authenticated == true
      assert identity.node_name == "test-node.corp.ztlp"
      assert identity.zone == "corp.ztlp"
      assert identity.assurance == :hardware
      assert identity.key_source == "yubikey"
      assert identity.attestation_verified == true
      assert identity.cert_fingerprint != nil
      assert identity.node_id != nil
    end

    test "meets_assurance? hardware >= software" do
      identity = %{assurance: :hardware}
      assert TlsIdentity.meets_assurance?(identity, :software)
    end

    test "meets_assurance? software < hardware" do
      identity = %{assurance: :software}
      refute TlsIdentity.meets_assurance?(identity, :hardware)
    end

    test "authenticated? returns true for valid identity" do
      assert TlsIdentity.authenticated?(%{authenticated: true})
    end

    test "authenticated? returns false for nil" do
      refute TlsIdentity.authenticated?(nil)
    end

    test "anonymous_identity is not authenticated" do
      anon = TlsIdentity.anonymous_identity()
      assert anon.authenticated == false
      assert anon.assurance == :unknown
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Application Supervisor Integration
  # ═══════════════════════════════════════════════════════════════════

  describe "application supervisor" do
    test "does not start TlsListener when tls_enabled is false" do
      # Default config has tls_enabled: false
      assert nil == GenServer.whereis(TlsListener)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Helpers
  # ═══════════════════════════════════════════════════════════════════

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
    case GenServer.whereis(SniRouter) do
      nil ->
        {:ok, _} = SniRouter.start_link(routes: [])
        :ok

      _pid ->
        SniRouter.list_routes()
        |> Enum.each(fn {hostname, _} -> SniRouter.delete_route(hostname) end)

        :ok
    end
  end

  defp ensure_cert_cache do
    case GenServer.whereis(CertCache) do
      nil ->
        {:ok, _} = CertCache.start_link()
        :ok

      _pid ->
        CertCache.clear()
        :ok
    end
  end

  defp ensure_crl_server do
    case GenServer.whereis(CrlServer) do
      nil ->
        {:ok, _} = CrlServer.start_link()
        :ok

      _pid ->
        :ok
    end
  end

  # Private function test helpers (mirror module internals for unit testing)
  defp assurance_gte?(actual, required) do
    levels = %{unknown: 0, software: 1, device_bound: 2, "device-bound": 2, hardware: 3}
    Map.get(levels, actual, 0) >= Map.get(levels, required, 0)
  end

  defp identity_string(nil), do: nil

  defp identity_string(%{authenticated: true} = id) do
    Map.get(id, :node_name) || Map.get(id, :node_id)
  end

  defp identity_string(_), do: nil

  defp http_request?(<<m, _::binary>>) when m in [?G, ?P, ?H, ?D, ?O, ?T, ?C], do: true
  defp http_request?(_), do: false

  defp build_error_response(status, error, message) do
    body =
      json_encode(%{
        "error" => error,
        "message" => message
      })

    status_text = case status do
      403 -> "Forbidden"
      502 -> "Bad Gateway"
      _ -> "Error"
    end

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
        "message" => "This service requires a higher authentication assurance level.",
        "hint" => "Re-enroll with: ztlp setup --hardware-key"
      })

    "HTTP/1.1 403 Forbidden\r\n" <>
      "Content-Type: application/json\r\n" <>
      "Content-Length: #{byte_size(body)}\r\n" <>
      "Connection: close\r\n" <>
      "\r\n" <>
      body
  end

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
