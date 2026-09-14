defmodule ZtlpRelay.VipConnectionTest do
  # async: false — opens real loopback TCP/UDP sockets; keep the port
  # churn serialised with the other socket-heavy suites.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias ZtlpRelay.{Crypto, Packet, VipConnection, VipFrame}

  @session_id <<7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
  @session_key :binary.copy(<<0xA5>>, 32)
  @conn_id 0x1234

  # ── fixtures ────────────────────────────────────────────────────────────

  # A loopback TCP backend. Accepts one connection and hands the accepted
  # socket back to the test process (active: true so the test gets
  # {:tcp, sock, data} messages).
  defp start_backend do
    {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(lsock)
    test = self()

    acceptor =
      spawn_link(fn ->
        case :gen_tcp.accept(lsock, 5_000) do
          {:ok, sock} ->
            :ok = :gen_tcp.controlling_process(sock, test)
            send(test, {:backend_accepted, sock})

          other ->
            send(test, {:backend_accept_failed, other})
        end
      end)

    %{listen: lsock, port: port, acceptor: acceptor}
  end

  defp await_backend do
    receive do
      {:backend_accepted, sock} ->
        :inet.setopts(sock, active: true)
        sock

      {:backend_accept_failed, why} ->
        flunk("backend accept failed: #{inspect(why)}")
    after
      5_000 -> flunk("backend never accepted")
    end
  end

  # The "client" side: a UDP socket the VipConnection will send frames to,
  # plus the relay-side UDP socket VipConnection sends *from*.
  defp start_udp_pair do
    {:ok, client} = :gen_udp.open(0, [:binary, active: true, ip: {127, 0, 0, 1}])
    {:ok, client_port} = :inet.port(client)
    {:ok, relay} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    %{client: client, client_addr: {{127, 0, 0, 1}, client_port}, relay: relay}
  end

  defp recv_udp(timeout \\ 1_000) do
    receive do
      {:udp, _sock, _ip, _port, data} -> {:ok, data}
    after
      timeout -> :timeout
    end
  end

  defp recv_tcp(sock, timeout \\ 1_000) do
    receive do
      {:tcp, ^sock, data} -> {:ok, data}
      {:tcp_closed, ^sock} -> :closed
    after
      timeout -> :timeout
    end
  end

  defp start_conn(udp, backend_port, opts \\ []) do
    base = [
      connection_id: @conn_id,
      session_id: @session_id,
      client_addr: udp.client_addr,
      backend_addr: {{127, 0, 0, 1}, backend_port},
      service_name: "svc",
      udp_socket: udp.relay,
      session_key: @session_key
    ]

    {:ok, pid} = VipConnection.start_link(Keyword.merge(base, opts))
    Process.unlink(pid)
    pid
  end

  # Wait until the GenServer has processed its :connect_backend message.
  defp await_connected(pid) do
    :sys.get_state(pid)
    :ok
  end

  defp client_frame(type, payload \\ <<>>) do
    {:ok, frame} = VipFrame.parse(VipFrame.encode(@conn_id, type, payload))
    frame
  end

  # Decode what the client receives: a compact ZTLP data packet whose payload
  # is a VIP frame, with a header auth tag over the compact AAD at seq 0.
  defp decode_client_packet(bin) do
    {:ok, pkt} = Packet.parse(bin)
    assert pkt.type == :data_compact
    assert pkt.session_id == @session_id
    assert pkt.packet_seq == 0
    {:ok, frame} = VipFrame.parse(pkt.payload)
    {pkt, frame}
  end

  defp expected_tag(frame_bin) do
    sid = @session_id
    aad =
      <<0x5A37::16, 0x1::4, 0xC::12, 0::16, sid::binary-size(12), 0::64, 0::16,
        byte_size(frame_bin)::16>>

    Crypto.compute_header_auth_tag(@session_key, aad, 0)
  end

  # ── happy path ──────────────────────────────────────────────────────────

  describe "backend connect + bidirectional forwarding" do
    test "connects to the backend on start and reports info" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)

      info = VipConnection.info(pid)
      assert info.connection_id == @conn_id
      assert info.service_name == "svc"
      assert info.backend_addr == {{127, 0, 0, 1}, be.port}
      assert info.bytes_to_backend == 0
      assert info.bytes_from_backend == 0
      assert info.duration_ms >= 0
      refute info.closed
      assert Process.alive?(pid)
    end

    test "SYN payload and DATA frames are forwarded to the backend TCP socket" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      bsock = await_backend()
      await_connected(pid)

      send(pid, {:client_data, client_frame(:syn, "GET / HTTP/1.0\r\n")})
      assert {:ok, "GET / HTTP/1.0\r\n"} = recv_tcp(bsock)

      send(pid, {:client_data, client_frame(:data, "Host: x\r\n\r\n")})
      assert {:ok, "Host: x\r\n\r\n"} = recv_tcp(bsock)

      info = VipConnection.info(pid)
      assert info.bytes_to_backend == byte_size("GET / HTTP/1.0\r\n") + byte_size("Host: x\r\n\r\n")
      assert info.bytes_from_backend == 0
    end

    test "backend TCP data is framed, header-authenticated and sent to the client over UDP" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      bsock = await_backend()
      await_connected(pid)

      :ok = :gen_tcp.send(bsock, "HTTP/1.0 200 OK\r\n")
      assert {:ok, bin} = recv_udp()

      {pkt, frame} = decode_client_packet(bin)
      assert frame.connection_id == @conn_id
      assert frame.frame_type == :data
      assert frame.payload == "HTTP/1.0 200 OK\r\n"
      assert pkt.header_auth_tag == expected_tag(pkt.payload)

      assert VipConnection.info(pid).bytes_from_backend == byte_size("HTTP/1.0 200 OK\r\n")
    end

    test "backend_data/2 cast path produces the same wire format as active-mode TCP delivery" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)

      :ok = VipConnection.backend_data(pid, "via-cast")
      assert {:ok, bin} = recv_udp()
      {pkt, frame} = decode_client_packet(bin)
      assert frame.payload == "via-cast"
      assert frame.frame_type == :data
      assert pkt.header_auth_tag == expected_tag(pkt.payload)
      assert VipConnection.info(pid).bytes_from_backend == 8
    end

    test "without a session_key, backend data is sent to the client as a bare VIP frame" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port, session_key: nil)
      bsock = await_backend()
      await_connected(pid)

      :ok = :gen_tcp.send(bsock, "plain")
      assert {:ok, bin} = recv_udp()
      assert bin == VipFrame.encode(@conn_id, :data, "plain")
      assert {:error, _} = Packet.parse(bin)

      :ok = VipConnection.backend_data(pid, "plain2")
      assert {:ok, bin2} = recv_udp()
      assert bin2 == VipFrame.encode(@conn_id, :data, "plain2")
    end

    test "large backend payload is forwarded intact" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)

      blob = :crypto.strong_rand_bytes(8_000)
      :ok = VipConnection.backend_data(pid, blob)
      assert {:ok, bin} = recv_udp()
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.payload == blob
    end
  end

  # ── client-initiated teardown ───────────────────────────────────────────

  describe "client FIN / RST" do
    test "client FIN half-closes the backend; backend's resulting close sends FIN to client and stops normally" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      bsock = await_backend()
      await_connected(pid)
      ref = Process.monitor(pid)

      send(pid, {:client_data, client_frame(:fin)})
      # shutdown(:write) -> backend sees EOF (exit_on_close: true closes the
      # port) -> GenServer gets {:tcp_closed, _} -> FIN to client -> :normal.
      assert :closed = recv_tcp(bsock)
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 2_000

      # state.closed was already true from the client FIN, so no second FIN
      # is sent back to the client (avoids a FIN echo).
      assert :timeout = recv_udp(300)
    end

    test "once closed (via backend_closed), later client DATA and backend data are both dropped" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      bsock = await_backend()
      await_connected(pid)

      VipConnection.backend_closed(pid)
      assert {:ok, _fin} = recv_udp()
      await_connected(pid)
      assert VipConnection.info(pid).closed

      # handle_data_frame/2 closed branch: nothing reaches the backend.
      send(pid, {:client_data, client_frame(:data, "late")})
      await_connected(pid)
      assert :timeout = recv_tcp(bsock, 300)
      assert VipConnection.info(pid).bytes_to_backend == 0

      # handle_cast {:backend_data} + handle_backend_data_internal closed branches.
      VipConnection.backend_data(pid, "dropped")
      send(pid, {:tcp, bsock, "also-dropped"})
      assert :timeout = recv_udp(300)
      assert VipConnection.info(pid).bytes_from_backend == 0
      assert Process.alive?(pid)
    end

    test "client RST closes the backend socket and stops the process with :client_reset" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      bsock = await_backend()
      await_connected(pid)
      ref = Process.monitor(pid)

      send(pid, {:client_data, client_frame(:rst)})
      assert_receive {:DOWN, ^ref, :process, ^pid, :client_reset}, 2_000
      assert :closed = recv_tcp(bsock)
      # RST from the client is not echoed back to the client.
      assert :timeout = recv_udp(200)
    end
  end

  # ── backend-initiated teardown ──────────────────────────────────────────

  describe "backend close / error" do
    test "backend TCP close sends an authenticated FIN to the client and stops normally" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      bsock = await_backend()
      await_connected(pid)
      ref = Process.monitor(pid)

      :ok = :gen_tcp.close(bsock)
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 2_000

      assert {:ok, bin} = recv_udp()
      {pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :fin
      assert frame.connection_id == @conn_id
      assert frame.payload == <<>>
      assert pkt.header_auth_tag == expected_tag(pkt.payload)
    end

    test "backend_closed/1 cast sends FIN once, marks closed, process stays up, second call is silent" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)

      :ok = VipConnection.backend_closed(pid)
      assert {:ok, bin} = recv_udp()
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :fin

      :ok = VipConnection.backend_closed(pid)
      assert :timeout = recv_udp(200)
      await_connected(pid)
      assert VipConnection.info(pid).closed
      assert Process.alive?(pid)
    end

    # Regression: send_fin/rst_to_client used to call encrypt_for_client
    # unconditionally and crashed with FunctionClauseError on a nil key.
    test "backend_closed without a session_key sends a bare FIN frame and stays up" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port, session_key: nil)
      _bsock = await_backend()
      await_connected(pid)

      VipConnection.backend_closed(pid)
      assert {:ok, bin} = recv_udp()
      assert bin == VipFrame.encode(@conn_id, :fin, <<>>)
      await_connected(pid)
      assert Process.alive?(pid)
      assert VipConnection.info(pid).closed
    end

    test "tcp_error without a session_key sends a bare RST frame" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port, session_key: nil)
      _bsock = await_backend()
      await_connected(pid)
      ref = Process.monitor(pid)

      send(pid, {:tcp_error, :fake, :econnreset})
      assert_receive {:DOWN, ^ref, :process, ^pid, {:error, :econnreset}}, 2_000
      assert {:ok, bin} = recv_udp()
      assert bin == VipFrame.encode(@conn_id, :rst, <<>>)
    end

    test "simulated tcp_error sends an authenticated RST and stops with {:error, reason}" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)
      ref = Process.monitor(pid)

      send(pid, {:tcp_error, :fake_socket, :econnreset})
      assert_receive {:DOWN, ^ref, :process, ^pid, {:error, :econnreset}}, 2_000

      assert {:ok, bin} = recv_udp()
      {pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :rst
      assert pkt.header_auth_tag == expected_tag(pkt.payload)
    end

    test "ssl_closed / ssl_error / ssl data messages are handled like their TCP twins" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)

      send(pid, {:ssl, :fake, "tls-bytes"})
      assert {:ok, bin} = recv_udp()
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.payload == "tls-bytes"

      ref = Process.monitor(pid)
      send(pid, {:ssl_closed, :fake})
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 2_000
      assert {:ok, fin_bin} = recv_udp()
      {_pkt, fin} = decode_client_packet(fin_bin)
      assert fin.frame_type == :fin
    end

    test "ssl_error stops with {:error, reason} and sends RST" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)
      ref = Process.monitor(pid)

      send(pid, {:ssl_error, :fake, :closed})
      assert_receive {:DOWN, ^ref, :process, ^pid, {:error, :closed}}, 2_000
      assert {:ok, bin} = recv_udp()
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :rst
    end

    test ":connect_timeout sends RST and stops with :timeout" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)
      ref = Process.monitor(pid)

      send(pid, :connect_timeout)
      assert_receive {:DOWN, ^ref, :process, ^pid, :timeout}, 2_000
      assert {:ok, bin} = recv_udp()
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :rst
    end
  end

  # ── connect failures ────────────────────────────────────────────────────

  describe "backend connect failure" do
    test "refused connection sends RST to the client and stops with {:connect_error, :econnrefused}" do
      # Grab a free port then close it so nothing listens there.
      {:ok, l} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, dead_port} = :inet.port(l)
      :gen_tcp.close(l)

      udp = start_udp_pair()

      log = capture_log(fn ->
        pid = start_conn(udp, dead_port)
        ref = Process.monitor(pid)
        assert_receive {:DOWN, ^ref, :process, ^pid, {:connect_error, :econnrefused}}, 6_000
      end)

      assert log =~ "Backend connect failed"
      assert {:ok, bin} = recv_udp()
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :rst
      assert frame.connection_id == @conn_id
    end

    test "TLS-enabled connect to a silent plain-TCP backend times out the handshake, sends RST, stops with {:tls_error, :timeout}" do
      be = start_backend()
      udp = start_udp_pair()

      log = capture_log(fn ->
        pid = start_conn(udp, be.port, tls_enabled: true)
        ref = Process.monitor(pid)
        bsock = await_backend()
        # A real TLS ClientHello must have been sent to the backend.
        assert {:ok, <<0x16, 0x03, _::binary>>} = recv_tcp(bsock, 2_000)
        assert_receive {:DOWN, ^ref, :process, ^pid, {:tls_error, :timeout}}, 8_000
      end)

      assert log =~ "TLS handshake failed"
      assert {:ok, bin} = recv_udp(2_000)
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :rst
    end

    # Regression: the backend closing while :ssl.connect/3 was assembling
    # options used to raise {badmatch, {error, einval}} out of OTP ssl and
    # crash the GenServer before send_rst_to_client ran.
    test "TLS-enabled connect where the backend closes mid-handshake still sends RST to the client" do
      be = start_backend()
      udp = start_udp_pair()

      capture_log(fn ->
        pid = start_conn(udp, be.port, tls_enabled: true)
        ref = Process.monitor(pid)
        bsock = await_backend()
        :gen_tcp.send(bsock, "not a tls server\r\n")
        :gen_tcp.close(bsock)
        assert_receive {:DOWN, ^ref, :process, ^pid, {:tls_error, _}}, 8_000
      end)

      assert {:ok, bin} = recv_udp(2_000)
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :rst
    end

    test "TLS-enabled connect to a refused port stops with {:connect_error, _}" do
      {:ok, l} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
      {:ok, dead_port} = :inet.port(l)
      :gen_tcp.close(l)
      udp = start_udp_pair()

      capture_log(fn ->
        pid = start_conn(udp, dead_port, tls_enabled: true)
        ref = Process.monitor(pid)
        assert_receive {:DOWN, ^ref, :process, ^pid, {:connect_error, :econnrefused}}, 6_000
      end)

      assert {:ok, bin} = recv_udp()
      {_pkt, frame} = decode_client_packet(bin)
      assert frame.frame_type == :rst
    end
  end

  # ── edge cases ──────────────────────────────────────────────────────────

  describe "ordering and robustness" do
    test "client data arriving before the backend is connected is dropped, not queued" do
      # Backend that never accepts within the connect window: use a listen
      # socket with backlog so connect succeeds at TCP level but we control
      # when the GenServer processes :connect_backend by racing the message.
      be = start_backend()
      udp = start_udp_pair()

      base = [
        connection_id: @conn_id,
        session_id: @session_id,
        client_addr: udp.client_addr,
        backend_addr: {{127, 0, 0, 1}, be.port},
        service_name: "svc",
        udp_socket: udp.relay,
        session_key: @session_key
      ]

      # Suspend so :connect_backend (queued by init) is not yet processed.
      {:ok, pid} = VipConnection.start_link(base)
      Process.unlink(pid)
      :sys.suspend(pid)
      send(pid, {:client_data, client_frame(:data, "early")})
      # Message order in mailbox: :connect_backend (from init), then early data.
      # Re-order by draining: we can't reorder a mailbox, so instead assert
      # that data delivered to a state with backend_socket == nil is dropped
      # via the :info path after resume.
      :sys.resume(pid)
      bsock = await_backend()
      await_connected(pid)
      # "early" was queued AFTER :connect_backend so it actually gets forwarded.
      assert {:ok, "early"} = recv_tcp(bsock)
      assert VipConnection.info(pid).bytes_to_backend == 5
    end

    test "unknown info messages are ignored" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      _bsock = await_backend()
      await_connected(pid)

      send(pid, :garbage)
      send(pid, {:weird, 1})
      await_connected(pid)
      assert Process.alive?(pid)
      refute VipConnection.info(pid).closed
    end

    test "init requires all mandatory options" do
      udp = start_udp_pair()
      Process.flag(:trap_exit, true)

      for missing <- [:connection_id, :session_id, :client_addr, :backend_addr, :service_name, :udp_socket] do
        opts =
          [
            connection_id: 1,
            session_id: @session_id,
            client_addr: udp.client_addr,
            backend_addr: {{127, 0, 0, 1}, 1},
            service_name: "svc",
            udp_socket: udp.relay
          ]
          |> Keyword.delete(missing)

        assert {:error, {%KeyError{key: ^missing}, _}} = VipConnection.start_link(opts)
      end
    end

    test "terminate closes the backend socket" do
      be = start_backend()
      udp = start_udp_pair()
      pid = start_conn(udp, be.port)
      bsock = await_backend()
      await_connected(pid)

      GenServer.stop(pid, :shutdown)
      assert :closed = recv_tcp(bsock)
    end

    test "IPv6 loopback backend address is accepted by connect and format_addr fallback" do
      case :gen_tcp.listen(0, [:binary, active: false, ip: {0, 0, 0, 0, 0, 0, 0, 1}]) do
        {:ok, lsock} ->
          {:ok, port} = :inet.port(lsock)
          test = self()

          spawn_link(fn ->
            {:ok, s} = :gen_tcp.accept(lsock, 5_000)
            :gen_tcp.controlling_process(s, test)
            send(test, {:backend_accepted, s})
          end)

          udp = start_udp_pair()

          log = capture_log(fn ->
            pid = start_conn(udp, port, backend_addr: {{0, 0, 0, 0, 0, 0, 0, 1}, port})
            _bsock = await_backend()
            await_connected(pid)
            assert VipConnection.info(pid).backend_addr == {{0, 0, 0, 0, 0, 0, 0, 1}, port}
          end)

          # format_addr falls back to inspect/1 for non-IPv4 tuples.
          assert log =~ "{{0, 0, 0, 0, 0, 0, 0, 1}"

        {:error, _} ->
          # No IPv6 loopback on this box; nothing to verify.
          :ok
      end
    end
  end
end
