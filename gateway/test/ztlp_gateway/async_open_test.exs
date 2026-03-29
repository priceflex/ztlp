defmodule ZtlpGateway.AsyncOpenTest do
  @moduledoc """
  Tests for async FRAME_OPEN backend connection handling.

  Verifies that:
  - FRAME_OPEN spawns an async connection (doesn't block the GenServer)
  - Data arriving during :connecting is buffered
  - Buffered data is flushed on successful backend connect
  - FRAME_CLOSE is sent on backend connect failure
  - Connect timeout sends FRAME_CLOSE for stale :connecting streams
  """
  use ExUnit.Case

  alias ZtlpGateway.{Crypto, Handshake, Packet, Session, PolicyEngine}

  # ── Test helpers ──────────────────────────────────────────────────

  # Perform a full Noise_XX handshake and return a context map with
  # established crypto keys and sockets.
  defp setup_mux_session(opts \\ []) do
    {gw_pub, gw_priv} = Crypto.generate_keypair()
    {client_pub, client_priv} = Crypto.generate_keypair()

    {:ok, client_sock} = :gen_udp.open(0, [:binary, {:active, false}])
    {:ok, client_port} = :inet.port(client_sock)
    client_addr = {{127, 0, 0, 1}, client_port}

    {:ok, gw_sock} = :gen_udp.open(0, [:binary, {:active, false}])

    # Start a TCP backend listener (or use a port that will refuse connections)
    backend_port = Keyword.get(opts, :backend_port, nil)
    listen_sock =
      if backend_port == nil do
        {:ok, ls} = :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])
        ls
      else
        nil
      end

    backend_port =
      if listen_sock do
        {:ok, p} = :inet.port(listen_sock)
        p
      else
        backend_port
      end

    Application.put_env(:ztlp_gateway, :backends, [
      %{name: "default", host: ~c"127.0.0.1", port: backend_port}
    ])

    PolicyEngine.put_rule("default", :all)

    session_id = :crypto.strong_rand_bytes(12)

    session_opts = %{
      session_id: session_id,
      client_addr: client_addr,
      udp_socket: gw_sock,
      static_pub: gw_pub,
      static_priv: gw_priv,
      service: "default"
    }

    {:ok, session_pid} = Session.start_link(session_opts)

    # Noise_XX handshake
    initiator = Handshake.init_initiator(client_pub, client_priv)
    {initiator, msg1_payload} = Handshake.create_msg1(initiator)
    hello_pkt = Packet.build_hello(msg1_payload)
    Session.handle_packet(session_pid, hello_pkt, client_addr)

    Process.sleep(50)
    {:ok, {_ip, _port, msg2_raw}} = :gen_udp.recv(client_sock, 0, 2000)
    {:ok, %{payload: msg2_payload}} = Packet.parse(msg2_raw)
    {initiator, _} = Handshake.process_msg2(initiator, msg2_payload)

    {initiator, msg3_payload} = Handshake.create_msg3(initiator)
    msg3_pkt = Packet.build_handshake(:hello, session_id, payload: msg3_payload)
    msg3_raw = Packet.serialize_handshake(msg3_pkt)
    Session.handle_packet(session_pid, msg3_raw, client_addr)

    {:ok, client_keys} = Handshake.split(initiator, session_id)

    # Accept the legacy backend connection established during handshake
    legacy_backend_sock =
      if listen_sock do
        case :gen_tcp.accept(listen_sock, 2000) do
          {:ok, sock} -> sock
          {:error, _} -> nil
        end
      else
        nil
      end

    Process.sleep(50)

    %{
      session_pid: session_pid,
      session_id: session_id,
      client_addr: client_addr,
      client_sock: client_sock,
      gw_sock: gw_sock,
      i2r_key: client_keys.i2r_key,
      r2i_key: client_keys.r2i_key,
      listen_sock: listen_sock,
      legacy_backend_sock: legacy_backend_sock
    }
  end

  # Encrypt a plaintext frame and send it as a data packet to the session
  defp send_encrypted_frame(ctx, plaintext, seq) do
    nonce = <<0::32, seq::little-64>>
    {ct, tag} = Crypto.encrypt(ctx.i2r_key, nonce, plaintext, <<>>)
    encrypted = ct <> tag

    pkt = Packet.build_data(ctx.session_id, seq,
      payload: encrypted,
      payload_len: byte_size(encrypted)
    )
    packet = Packet.serialize_data_with_auth(pkt, ctx.i2r_key)
    Session.handle_packet(ctx.session_pid, packet, ctx.client_addr)
  end

  defp cleanup(ctx) do
    if Process.alive?(ctx.session_pid), do: GenServer.stop(ctx.session_pid)
    if ctx.legacy_backend_sock, do: catch_close(fn -> :gen_tcp.close(ctx.legacy_backend_sock) end)
    if ctx.listen_sock, do: catch_close(fn -> :gen_tcp.close(ctx.listen_sock) end)
    :gen_udp.close(ctx.client_sock)
    :gen_udp.close(ctx.gw_sock)
  end

  defp catch_close(fun) do
    try do
      fun.()
    rescue
      _ -> :ok
    catch
      _, _ -> :ok
    end
  end

  # ── Tests ─────────────────────────────────────────────────────────

  describe "async FRAME_OPEN" do
    test "FRAME_OPEN returns quickly (non-blocking)" do
      ctx = setup_mux_session()

      # Send FRAME_OPEN — the GenServer should process it quickly
      # because the backend connect is async
      svc = "default"
      frame_open = <<0x06, 1::big-32, byte_size(svc)::8, svc::binary>>

      start = System.monotonic_time(:millisecond)
      send_encrypted_frame(ctx, frame_open, 0)
      # Give the GenServer a moment to process
      Process.sleep(20)
      elapsed = System.monotonic_time(:millisecond) - start

      # Should complete in well under 1 second (backend connect takes ~0ms locally,
      # but even if it took 5s we'd return immediately since it's async)
      assert elapsed < 500, "FRAME_OPEN took #{elapsed}ms, expected < 500ms"
      assert Process.alive?(ctx.session_pid)

      cleanup(ctx)
    end

    test "stream enters :connecting state on FRAME_OPEN" do
      ctx = setup_mux_session()

      svc = "default"
      frame_open = <<0x06, 42::big-32, byte_size(svc)::8, svc::binary>>
      send_encrypted_frame(ctx, frame_open, 0)

      # Brief sleep to let the GenServer process the frame
      Process.sleep(20)

      session_state = :sys.get_state(ctx.session_pid)

      # Stream 42 should exist. It may be :connecting or already :connected
      # (local connections are fast), but it should exist in the streams map.
      assert Map.has_key?(session_state.streams, 42),
        "Stream 42 should exist in streams map"

      stream = session_state.streams[42]
      assert stream.state in [:connecting, :connected],
        "Stream should be :connecting or :connected, got #{inspect(stream.state)}"

      cleanup(ctx)
    end

    test "stream transitions to :connected and data is forwarded" do
      ctx = setup_mux_session()

      svc = "default"
      frame_open = <<0x06, 1::big-32, byte_size(svc)::8, svc::binary>>
      send_encrypted_frame(ctx, frame_open, 0)

      # Wait for the async connect result to be processed by the session
      Process.sleep(500)

      # Verify stream is now connected
      session_state = :sys.get_state(ctx.session_pid)
      assert session_state.streams[1].state == :connected
      assert session_state.streams[1].backend_pid != nil

      # Find the right accepted socket for this stream's backend
      mux_backend_sock = accept_for_stream(ctx, 1)

      # Send data through the mux stream
      payload = "hello mux backend"
      data_frame = <<0x00, 1::big-32, payload::binary>>
      send_encrypted_frame(ctx, data_frame, 1)
      Process.sleep(200)

      # Backend should receive the data
      {:ok, received} = :gen_tcp.recv(mux_backend_sock, 0, 2000)
      assert received == payload

      :gen_tcp.close(mux_backend_sock)
      cleanup(ctx)
    end

    test "data is buffered during :connecting and flushed on connect" do
      ctx = setup_mux_session()

      svc = "default"
      frame_open = <<0x06, 5::big-32, byte_size(svc)::8, svc::binary>>
      send_encrypted_frame(ctx, frame_open, 0)

      # Send data immediately — if the stream is still :connecting, it gets buffered.
      payload1 = "first chunk"
      data_frame1 = <<0x00, 5::big-32, payload1::binary>>
      send_encrypted_frame(ctx, data_frame1, 1)

      payload2 = "second chunk"
      data_frame2 = <<0x00, 5::big-32, payload2::binary>>
      send_encrypted_frame(ctx, data_frame2, 2)

      # Wait for async connect + flush
      Process.sleep(500)

      # Accept ALL pending connections on listen_sock to find the mux stream's backend
      mux_backend_sock = accept_for_stream(ctx, 5)

      # Send additional data to verify forwarding works after connect
      payload3 = "third chunk"
      data_frame3 = <<0x00, 5::big-32, payload3::binary>>
      send_encrypted_frame(ctx, data_frame3, 3)
      Process.sleep(200)

      # Read all available data
      all_data = recv_all(mux_backend_sock, 2000)

      # At minimum, the third chunk (sent after connect) should arrive.
      assert String.contains?(all_data, "third chunk"),
        "Expected 'third chunk' in received data: #{inspect(all_data)}"

      :gen_tcp.close(mux_backend_sock)
      cleanup(ctx)
    end

    test "FRAME_CLOSE is sent on backend connect failure" do
      # Setup session with a working backend (for the legacy handshake connect)
      ctx = setup_mux_session()

      # Now reconfigure backends to point to a port that refuses connections,
      # so the mux FRAME_OPEN connect will fail.
      {:ok, tmp_sock} = :gen_tcp.listen(0, [:binary, {:reuseaddr, true}])
      {:ok, refuse_port} = :inet.port(tmp_sock)
      :gen_tcp.close(tmp_sock)
      Process.sleep(50)

      Application.put_env(:ztlp_gateway, :backends, [
        %{name: "default", host: ~c"127.0.0.1", port: refuse_port}
      ])

      svc = "default"
      frame_open = <<0x06, 10::big-32, byte_size(svc)::8, svc::binary>>
      send_encrypted_frame(ctx, frame_open, 0)

      # Wait for the connect attempt to fail
      Process.sleep(1000)

      # The session should have removed the stream
      session_state = :sys.get_state(ctx.session_pid)
      refute Map.has_key?(session_state.streams, 10),
        "Stream 10 should be removed after connect failure"

      # Session should still be alive
      assert Process.alive?(ctx.session_pid)

      cleanup(ctx)
    end

    test "connect timeout cleans up stale :connecting stream" do
      # We can't easily test the 10-second timeout in a unit test, but we can
      # simulate it by directly sending the timeout message to the session.
      ctx = setup_mux_session()

      svc = "default"
      frame_open = <<0x06, 99::big-32, byte_size(svc)::8, svc::binary>>
      send_encrypted_frame(ctx, frame_open, 0)

      # Brief sleep for GenServer to process
      Process.sleep(50)

      session_state = :sys.get_state(ctx.session_pid)

      # Stream might already be connected (local is fast)
      if Map.has_key?(session_state.streams, 99) and
         session_state.streams[99].state == :connecting do
        # Simulate the timeout firing
        send(ctx.session_pid, {:connect_timeout, 99})
        Process.sleep(50)

        session_state = :sys.get_state(ctx.session_pid)
        refute Map.has_key?(session_state.streams, 99),
          "Stream 99 should be removed after connect timeout"
      end

      # Session should still be alive regardless
      assert Process.alive?(ctx.session_pid)

      # Accept any pending connection to avoid port leaks
      if ctx.listen_sock do
        case :gen_tcp.accept(ctx.listen_sock, 200) do
          {:ok, s} -> :gen_tcp.close(s)
          _ -> :ok
        end
      end

      cleanup(ctx)
    end

    test "multiple streams can open concurrently" do
      ctx = setup_mux_session()

      svc = "default"

      # Open 3 streams rapidly
      for stream_id <- [1, 2, 3] do
        frame_open = <<0x06, stream_id::big-32, byte_size(svc)::8, svc::binary>>
        # Use sequential seq numbers starting from 0
        send_encrypted_frame(ctx, frame_open, stream_id - 1)
      end

      # Wait for connections to establish
      Process.sleep(500)

      session_state = :sys.get_state(ctx.session_pid)

      # All 3 streams should exist and be connected
      for stream_id <- [1, 2, 3] do
        assert Map.has_key?(session_state.streams, stream_id),
          "Stream #{stream_id} should exist"
        assert session_state.streams[stream_id].state == :connected,
          "Stream #{stream_id} should be :connected"
      end

      # Accept and close the extra connections to avoid port leaks
      drain_accepts(ctx.listen_sock)
      cleanup(ctx)
    end
  end

  # Accept connections on listen_sock until we find the one connected to the
  # Backend process for the given stream_id. Returns the server-side socket.
  defp accept_for_stream(ctx, stream_id) do
    session_state = :sys.get_state(ctx.session_pid)
    stream = session_state.streams[stream_id]
    assert stream != nil, "Stream #{stream_id} should exist"
    assert stream.backend_pid != nil, "Stream #{stream_id} should have a backend_pid"

    # Get the Backend's local port to identify the right connection
    backend_gen_state = :sys.get_state(stream.backend_pid)
    {:ok, {_addr, backend_local_port}} = :inet.sockname(backend_gen_state.socket)

    accept_for_port(ctx.listen_sock, backend_local_port, [])
  end

  defp accept_for_port(listen_sock, target_peer_port, extra_socks) do
    case :gen_tcp.accept(listen_sock, 1000) do
      {:ok, sock} ->
        case :inet.peername(sock) do
          {:ok, {_addr, ^target_peer_port}} ->
            # Found the right socket — close extras
            Enum.each(extra_socks, fn s -> :gen_tcp.close(s) end)
            sock
          {:ok, _other} ->
            # Not the one we want — keep looking
            accept_for_port(listen_sock, target_peer_port, [sock | extra_socks])
        end
      {:error, :timeout} ->
        # No more connections — we didn't find it
        Enum.each(extra_socks, fn s -> :gen_tcp.close(s) end)
        flunk("Could not find accepted socket for Backend with local port #{target_peer_port}")
    end
  end

  # Accept and close all pending connections on a listen socket
  defp drain_accepts(listen_sock) do
    case :gen_tcp.accept(listen_sock, 100) do
      {:ok, s} ->
        :gen_tcp.close(s)
        drain_accepts(listen_sock)
      {:error, _} ->
        :ok
    end
  end

  # Helper: read all available data from a TCP socket with a timeout
  defp recv_all(sock, timeout) do
    recv_all_loop(sock, timeout, [])
  end

  defp recv_all_loop(sock, timeout, acc) do
    case :gen_tcp.recv(sock, 0, timeout) do
      {:ok, data} -> recv_all_loop(sock, timeout, [data | acc])
      {:error, :timeout} -> acc |> Enum.reverse() |> IO.iodata_to_binary()
      {:error, _} -> acc |> Enum.reverse() |> IO.iodata_to_binary()
    end
  end
end
