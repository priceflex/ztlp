defmodule ZtlpGateway.Quic.ListenerTest do
  use ExUnit.Case, async: false

  @moduledoc """
  Task Q4 (ztlp-cloud-demo-plan.md, Session 3): the `:quicer`-backed QUIC
  listener — `ZtlpGateway.Quic.Listener` / `Quic.Connection` /
  `Quic.StreamProxy`. Exercised with a REAL in-process `:quicer.connect`
  client (ALPN `ztlp/1`) that speaks the exact Rust wire contract:
  stream 0 = 16 raw service_hash bytes + framed Noise_XX with 16-byte
  NodeID payloads; every later bidi stream = one TCP connection carrying
  `0x5A|len|payload` frames.
  """

  alias ZtlpGateway.Quic.Frame
  alias ZtlpGateway.Quic.Listener
  alias ZtlpGateway.Handshake, as: Noise
  alias ZtlpGateway.{Crypto, Packet, PolicyEngine}

  @alpn [~c"ztlp/1"]
  @service "demo-dashboard"

  # ---------------------------------------------------------------------------
  # Fake HTTP backend: replies 200 and echoes the raw request into the body so
  # the test can see exactly which headers the gateway injected.
  # ---------------------------------------------------------------------------
  defp start_echo_backend do
    {:ok, lsock} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, packet: :raw])
    {:ok, port} = :inet.port(lsock)
    parent = self()

    spawn_link(fn -> accept_loop(lsock, parent) end)
    {lsock, port}
  end

  defp accept_loop(lsock, parent) do
    case :gen_tcp.accept(lsock) do
      {:ok, sock} ->
        spawn_link(fn -> serve(sock, parent) end)
        accept_loop(lsock, parent)

      {:error, _} ->
        :ok
    end
  end

  defp serve(sock, parent) do
    case recv_http_request(sock, <<>>) do
      {:ok, req} ->
        send(parent, {:backend_saw, req})
        body = req
        resp = "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(body)}\r\nConnection: close\r\n\r\n" <> body
        :ok = :gen_tcp.send(sock, resp)
        :gen_tcp.shutdown(sock, :write)
        # drain until peer closes
        _ = :gen_tcp.recv(sock, 0, 2_000)
        :gen_tcp.close(sock)

      _ ->
        :gen_tcp.close(sock)
    end
  end

  # Read until headers + Content-Length body are complete (or peer closes).
  defp recv_http_request(sock, acc) do
    case :gen_tcp.recv(sock, 0, 5_000) do
      {:ok, data} ->
        acc = acc <> data

        case :binary.match(acc, "\r\n\r\n") do
          :nomatch ->
            recv_http_request(sock, acc)

          {pos, 4} ->
            head = binary_part(acc, 0, pos)
            body_len = byte_size(acc) - pos - 4

            want =
              case Regex.run(~r/content-length:\s*(\d+)/i, head) do
                [_, n] -> String.to_integer(n)
                nil -> 0
              end

            if body_len >= want, do: {:ok, acc}, else: recv_http_request(sock, acc)
        end

      {:error, _} when acc != <<>> ->
        {:ok, acc}

      err ->
        err
    end
  end

  # ---------------------------------------------------------------------------
  # Client helpers (the "Rust client" in Elixir clothing)
  # ---------------------------------------------------------------------------
  defp connect(port, alpn \\ @alpn) do
    :quicer.connect(~c"127.0.0.1", port, %{alpn: alpn, verify: :none, peer_bidi_stream_count: 16, idle_timeout_ms: 10_000}, 5_000)
  end

  # Collect stream bytes until `enough?.(acc)` or timeout. Also returns
  # whether the peer FIN/closed the stream while we waited.
  defp collect(stream, enough?, acc \\ <<>>, timeout \\ 3_000) do
    if enough?.(acc) do
      {:ok, acc}
    else
      receive do
        {:quic, bin, ^stream, _props} when is_binary(bin) -> collect(stream, enough?, acc <> bin, timeout)
        {:quic, :peer_send_shutdown, ^stream, _} -> {:fin, acc}
        {:quic, :stream_closed, ^stream, _} -> {:closed, acc}
        {:quic, :peer_send_aborted, ^stream, _} -> {:aborted, acc}
      after
        timeout -> {:timeout, acc}
      end
    end
  end

  defp client_handshake(conn, service_hash) do
    {c_pub, c_priv} = Crypto.generate_keypair()
    c_nid = :crypto.strong_rand_bytes(16)

    {:ok, s0} = :quicer.start_stream(conn, %{active: true})

    init = Noise.init_initiator(c_pub, c_priv)
    {init, msg1} = Noise.create_msg1(init, c_nid)
    {:ok, _} = :quicer.send(s0, service_hash <> Frame.encode(msg1))

    # 12 raw session id bytes + frame(msg2 = 32 + 48 + 32)
    case collect(s0, fn acc -> byte_size(acc) >= 12 + 3 + 112 end) do
      {:ok, <<sid::binary-size(12), framed::binary>>} ->
        {:ok, msg2, <<>>} = Frame.decode(framed)
        {init, _server_nid} = Noise.process_msg2(init, msg2)
        {_init, msg3} = Noise.create_msg3(init, c_nid)
        {:ok, _} = :quicer.send(s0, Frame.encode(msg3))
        :quicer.async_shutdown_stream(s0)
        {:ok, %{session_id: sid, static_pub: c_pub, node_id: c_nid, stream0: s0}}

      other ->
        {:handshake_failed, other}
    end
  end

  defp http_via_stream(conn, request) do
    {:ok, s} = :quicer.start_stream(conn, %{active: true})
    # Rust client emits one frame per <=65000-byte TCP read.
    for <<chunk::binary-size(65_000) <- request>> do
      {:ok, _} = :quicer.send(s, Frame.encode(chunk))
    end

    tail = rem(byte_size(request), 65_000)
    if tail > 0, do: {:ok, _} = :quicer.send(s, Frame.encode(binary_part(request, byte_size(request) - tail, tail)))

    {status, bytes} = collect(s, fn _ -> false end)
    assert status in [:fin, :closed], "expected backend EOF -> QUIC FIN, got #{inspect(status)}"
    {:ok, unframe_all(bytes), s}
  end

  defp unframe_all(bytes, acc \\ <<>>) do
    case Frame.decode(bytes) do
      {:ok, payload, rest} -> unframe_all(rest, acc <> payload)
      {:more, <<>>} -> acc
      {:more, partial} -> flunk("trailing partial frame: #{inspect(partial)}")
    end
  end

  # ---------------------------------------------------------------------------
  # Setup: fake backend + gateway config + QUIC listener on an ephemeral port
  # ---------------------------------------------------------------------------
  setup do
    {lsock, backend_port} = start_echo_backend()

    prev_backends = Application.get_env(:ztlp_gateway, :backends)

    Application.put_env(:ztlp_gateway, :backends, [
      %{name: @service, host: ~c"127.0.0.1", port: backend_port, protocol: :tcp}
    ])

    PolicyEngine.put_rule(@service, :all)

    data_dir = Path.join(System.tmp_dir!(), "ztlp-quic-listener-#{System.unique_integer([:positive])}")
    File.mkdir_p!(data_dir)

    {:ok, listener} = Listener.start_link(port: 0, data_dir: data_dir, acceptors: 2)
    port = Listener.port(listener)
    assert is_integer(port) and port > 0

    on_exit(fn ->
      :gen_tcp.close(lsock)
      PolicyEngine.delete_rule(@service)
      Application.put_env(:ztlp_gateway, :backends, prev_backends || [])
      File.rm_rf!(data_dir)
    end)

    %{port: port, listener: listener, data_dir: data_dir, backend_port: backend_port}
  end

  test "listener persists a stable self-signed cert + static key in data_dir (R3)", %{data_dir: dir, listener: l} do
    cert = Path.join(dir, "quic-cert.pem")
    key = Path.join(dir, "quic-key.pem")
    static = Path.join(dir, "quic-static.key")
    assert File.exists?(cert) and File.exists?(key) and File.exists?(static)
    assert File.read!(cert) =~ "BEGIN CERTIFICATE"
    assert File.read!(key) =~ "PRIVATE KEY"

    before = {File.read!(cert), File.read!(key), File.read!(static)}
    GenServer.stop(l)
    {:ok, l2} = Listener.start_link(port: 0, data_dir: dir, acceptors: 1)
    assert {File.read!(cert), File.read!(key), File.read!(static)} == before
    GenServer.stop(l2)
  end

  test "Rust-contract handshake on stream 0 then HTTP through a data stream gets X-ZTLP headers injected",
       %{port: port} do
    {:ok, conn} = connect(port)
    assert {:ok, hs} = client_handshake(conn, Packet.service_hash(@service))
    assert byte_size(hs.session_id) == 12

    {:ok, resp, _s} = http_via_stream(conn, "GET /api/health HTTP/1.1\r\nHost: demo-dashboard.defcon.ztlp\r\nX-ZTLP-Identity: forged\r\n\r\n")

    assert resp =~ "HTTP/1.1 200 OK"
    assert_receive {:backend_saw, seen}, 3_000
    assert seen =~ "GET /api/health HTTP/1.1"
    # identity headers present, forged one stripped
    assert seen =~ ~r/x-ztlp-node-id:/i
    refute seen =~ "forged"
    # header value is the client's Noise static key (unknown -> hex), not the NodeID
    assert seen =~ Base.encode16(hs.static_pub, case: :lower)

    :quicer.async_shutdown_connection(conn, 0, 0)
  end

  # Live-observed against the Rust agent (Q6, 2026-09-13): the client opens its
  # first DATA stream and pushes the HTTP request immediately after sending
  # msg3 — it does NOT wait for the gateway to process msg3. If the gateway only
  # arms `async_accept_stream` after `finish_handshake`, msquic sees a peer
  # stream with no acceptor and the request is lost (client 504 after 15 s).
  # A second stream opened later worked, which is the fingerprint of this race.
  test "data stream opened immediately after msg3 (before the gateway has processed it) is still proxied",
       %{port: port} do
    {:ok, conn} = connect(port)
    {c_pub, c_priv} = Crypto.generate_keypair()
    c_nid = :crypto.strong_rand_bytes(16)

    {:ok, s0} = :quicer.start_stream(conn, %{active: true})
    init = Noise.init_initiator(c_pub, c_priv)
    {init, msg1} = Noise.create_msg1(init, c_nid)
    {:ok, _} = :quicer.send(s0, Packet.service_hash(@service) <> Frame.encode(msg1))

    {:ok, <<_sid::binary-size(12), framed::binary>>} =
      collect(s0, fn acc -> byte_size(acc) >= 12 + 3 + 112 end)

    {:ok, msg2, <<>>} = Frame.decode(framed)
    {init, _} = Noise.process_msg2(init, msg2)
    {_init, msg3} = Noise.create_msg3(init, c_nid)

    # Open the data stream and push the request BEFORE msg3 goes out. On the
    # wire the Rust client emits these back-to-back; msquic is free to surface
    # the new-stream event ahead of the stream-0 receive event (observed live
    # via :sys.trace on the Connection process), so the gateway must tolerate
    # the data stream arriving while the handshake is still in flight.
    {:ok, s} = :quicer.start_stream(conn, %{active: true})
    {:ok, _} = :quicer.send(s, Frame.encode("GET /api/health HTTP/1.1\r\nHost: demo-dashboard.defcon.ztlp\r\n\r\n"))
    Process.sleep(50)
    {:ok, _} = :quicer.send(s0, Frame.encode(msg3))
    :quicer.async_shutdown_stream(s0)

    {status, bytes} = collect(s, fn _ -> false end, <<>>, 5_000)
    assert status in [:fin, :closed], "first data stream was lost to the accept race (got #{inspect(status)})"
    assert unframe_all(bytes) =~ "HTTP/1.1 200 OK"
    assert_receive {:backend_saw, seen}, 3_000
    assert seen =~ ~r/x-ztlp-node-id:/i

    :quicer.async_shutdown_connection(conn, 0, 0)
  end

  test "two concurrent data streams on one connection are proxied independently", %{port: port} do
    {:ok, conn} = connect(port)
    {:ok, _hs} = client_handshake(conn, Packet.service_hash(@service))

    {:ok, s1} = :quicer.start_stream(conn, %{active: true})
    {:ok, s2} = :quicer.start_stream(conn, %{active: true})
    {:ok, _} = :quicer.send(s1, Frame.encode("GET /one HTTP/1.1\r\nHost: a\r\n\r\n"))
    {:ok, _} = :quicer.send(s2, Frame.encode("GET /two HTTP/1.1\r\nHost: a\r\n\r\n"))

    {st1, b1} = collect(s1, fn _ -> false end)
    {st2, b2} = collect(s2, fn _ -> false end)
    assert st1 in [:fin, :closed] and st2 in [:fin, :closed]
    assert unframe_all(b1) =~ "GET /one"
    assert unframe_all(b2) =~ "GET /two"
    refute unframe_all(b1) =~ "GET /two"
    :quicer.async_shutdown_connection(conn, 0, 0)
  end

  test "a data frame split across several QUIC sends is reassembled before hitting the backend",
       %{port: port} do
    {:ok, conn} = connect(port)
    {:ok, _hs} = client_handshake(conn, Packet.service_hash(@service))

    req = "GET /split HTTP/1.1\r\nHost: a\r\nX-Pad: " <> String.duplicate("p", 500) <> "\r\n\r\n"
    framed = Frame.encode(req)
    {:ok, s} = :quicer.start_stream(conn, %{active: true})

    for <<chunk::binary-size(7) <- binary_part(framed, 0, byte_size(framed) - rem(byte_size(framed), 7))>> do
      {:ok, _} = :quicer.send(s, chunk)
    end

    tail_len = rem(byte_size(framed), 7)
    if tail_len > 0, do: {:ok, _} = :quicer.send(s, binary_part(framed, byte_size(framed) - tail_len, tail_len))

    {st, bytes} = collect(s, fn _ -> false end)
    assert st in [:fin, :closed]
    assert unframe_all(bytes) =~ "GET /split"
    assert_receive {:backend_saw, seen}, 3_000
    assert seen =~ String.duplicate("p", 500)
    :quicer.async_shutdown_connection(conn, 0, 0)
  end

  test "backend response larger than one frame arrives as multiple frames that concatenate cleanly",
       %{port: port} do
    {:ok, conn} = connect(port)
    {:ok, _hs} = client_handshake(conn, Packet.service_hash(@service))
    big = String.duplicate("Q", 150_000)
    {:ok, resp, _} = http_via_stream(conn, "POST /big HTTP/1.1\r\nHost: a\r\nContent-Length: #{byte_size(big)}\r\n\r\n" <> big)
    assert resp =~ "HTTP/1.1 200 OK"
    assert String.ends_with?(resp, big)
    :quicer.async_shutdown_connection(conn, 0, 0)
  end

  test "wrong ALPN never completes the QUIC handshake", %{port: port} do
    result = connect(port, [~c"h3"])
    refute match?({:ok, _}, result)
  end

  test "unknown service hash closes the connection after msg3", %{port: port} do
    {:ok, conn} = connect(port)
    {:ok, hs} = client_handshake(conn, Packet.service_hash("no-such-service"))
    assert_connection_closed(conn, hs.stream0)
  end

  test "policy deny closes the connection", %{port: port} do
    PolicyEngine.put_rule(@service, ["nobody-matches-this"])
    {:ok, conn} = connect(port)
    {:ok, hs} = client_handshake(conn, Packet.service_hash(@service))
    assert_connection_closed(conn, hs.stream0)
  end

  test "garbage on stream 0 (bad magic) closes the connection", %{port: port} do
    {:ok, conn} = connect(port)
    {:ok, s0} = :quicer.start_stream(conn, %{active: true})
    {:ok, _} = :quicer.send(s0, :binary.copy(<<0>>, 16) <> <<0x00, 0, 5, "hello">>)
    assert_connection_closed(conn, s0)
  end

  test "stats and session registry see the QUIC session", %{port: port} do
    before = ZtlpGateway.Stats.snapshot()
    {:ok, conn} = connect(port)
    {:ok, hs} = client_handshake(conn, Packet.service_hash(@service))
    # give the gateway a moment to register
    assert eventually(fn -> match?({:ok, _}, ZtlpGateway.SessionRegistry.lookup(hs.session_id)) end)
    after_ = ZtlpGateway.Stats.snapshot()
    assert after_.handshakes_ok == before.handshakes_ok + 1
    :quicer.async_shutdown_connection(conn, 0, 0)
  end

  defp assert_connection_closed(conn, stream) do
    # Either the data stream gets aborted/closed or the whole connection shuts down.
    got =
      receive do
        {:quic, :closed, ^conn, _} -> :conn_closed
        {:quic, :shutdown, ^conn, _} -> :conn_shutdown
        {:quic, :transport_shutdown, ^conn, _} -> :conn_shutdown
        {:quic, :stream_closed, ^stream, _} -> :stream_closed
        {:quic, :peer_send_aborted, ^stream, _} -> :stream_aborted
      after
        4_000 -> :timeout
      end

    assert got != :timeout, "gateway kept the connection open"
  end

  defp eventually(fun, tries \\ 40) do
    cond do
      fun.() -> true
      tries == 0 -> false
      true ->
        Process.sleep(50)
        eventually(fun, tries - 1)
    end
  end
end
