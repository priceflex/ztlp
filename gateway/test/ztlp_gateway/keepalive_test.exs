defmodule ZtlpGateway.KeepaliveTest do
  @moduledoc """
  Tests for keepalive frame handling in Session.

  Verifies that 1-byte 0x01 keepalive frames are recognized and NOT
  forwarded to the backend, preventing the keepalive → reconnect → close cycle.
  """
  use ExUnit.Case

  alias ZtlpGateway.{Crypto, Handshake, Packet, Session, PolicyEngine}

  # Helper: perform a full Noise_XX handshake through the Session process
  # and return the established session context with client-side transport keys.
  defp setup_established_session do
    # Generate keypairs for gateway (responder) and client (initiator)
    {gw_pub, gw_priv} = Crypto.generate_keypair()
    {client_pub, client_priv} = Crypto.generate_keypair()

    # Open a UDP socket to act as the "client" — responses will be sent here.
    # The session uses send_udp which sends to client_addr, so we need to
    # make client_addr point to our socket.
    {:ok, client_sock} = :gen_udp.open(0, [:binary, {:active, false}])
    {:ok, client_port} = :inet.port(client_sock)
    client_addr = {{127, 0, 0, 1}, client_port}

    # The session also needs a UDP socket reference for :gen_udp.send.
    # We use a SEPARATE socket so the session can send TO the client socket.
    {:ok, gw_sock} = :gen_udp.open(0, [:binary, {:active, false}])

    # Start a TCP echo backend for the session to forward data to
    {:ok, listen_sock} = :gen_tcp.listen(0, [:binary, {:active, false}, {:reuseaddr, true}])
    {:ok, backend_port} = :inet.port(listen_sock)

    # Configure the backend (host must be charlist for :gen_tcp.connect)
    Application.put_env(:ztlp_gateway, :backends, [
      %{name: "default", host: ~c"127.0.0.1", port: backend_port}
    ])

    # Allow all identities for the "default" service
    PolicyEngine.put_rule("default", :all)

    session_id = :crypto.strong_rand_bytes(12)

    opts = %{
      session_id: session_id,
      client_addr: client_addr,
      udp_socket: gw_sock,
      static_pub: gw_pub,
      static_priv: gw_priv,
      service: "default"
    }

    {:ok, session_pid} = Session.start_link(opts)

    # === Noise_XX handshake ===

    # Initiator creates msg1
    initiator = Handshake.init_initiator(client_pub, client_priv)
    {initiator, msg1_payload} = Handshake.create_msg1(initiator)

    # Send msg1 as a HELLO packet (zero session_id)
    hello_pkt = Packet.build_hello(msg1_payload)
    Session.handle_packet(session_pid, hello_pkt, client_addr)

    # Receive the HELLO_ACK (msg2) on the client socket
    Process.sleep(50)
    {:ok, {_ip, _port, msg2_raw}} = :gen_udp.recv(client_sock, 0, 2000)
    {:ok, %{payload: msg2_payload}} = Packet.parse(msg2_raw)

    # Process msg2 on initiator side
    {initiator, _} = Handshake.process_msg2(initiator, msg2_payload)

    # Create and send msg3 (with the session_id so Pipeline routes it)
    # Use :hello msg_type — the Session only checks Packet.handshake?() and
    # then parses the payload; the msg_type field doesn't matter for routing.
    {initiator, msg3_payload} = Handshake.create_msg3(initiator)
    msg3_pkt = Packet.build_handshake(:hello, session_id, payload: msg3_payload)
    msg3_raw = Packet.serialize_handshake(msg3_pkt)
    Session.handle_packet(session_pid, msg3_raw, client_addr)

    # Debug: Check if handshake is working
    IO.inspect(PolicyEngine.authorize?("test", "default"), label: "DEBUG policy")
    IO.inspect(ZtlpGateway.Config.get(:backends), label: "DEBUG backends")
    IO.inspect(Process.alive?(session_pid), label: "DEBUG session alive")
    IO.inspect(Packet.parse(msg3_raw), label: "DEBUG msg3 parse")
    IO.inspect(:sys.get_state(session_pid).backend_addr, label: "DEBUG backend_addr")

    # Wait for the backend connection to be established (retry until success)
    backend_sock =
      case :gen_tcp.accept(listen_sock, 1000) do
        {:ok, sock} -> sock
        {:error, :timeout} ->
          # Retry a few times
          receive do
            after 200 -> :gen_tcp.accept(listen_sock, 2000)
          end
      end
    # Derive transport keys (client side)
    {:ok, client_keys} = Handshake.split(initiator, session_id)

    Process.sleep(50)

    %{
      session_pid: session_pid,
      session_id: session_id,
      client_addr: client_addr,
      client_sock: client_sock,
      gw_sock: gw_sock,
      i2r_key: client_keys.i2r_key,
      r2i_key: client_keys.r2i_key,
      backend_sock: backend_sock,
      listen_sock: listen_sock
    }
  end

  # Encrypt and send a plaintext frame to the session as a data packet
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
    catch_close(fn -> :gen_tcp.close(ctx.backend_sock) end)
    :gen_tcp.close(ctx.listen_sock)
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

  describe "keepalive handling" do
    test "1-byte 0x01 keepalive is NOT forwarded to backend" do
      ctx = setup_established_session()

      # Send a keepalive frame (1-byte 0x01)
      send_encrypted_frame(ctx, <<0x01>>, 1)
      Process.sleep(100)

      # Verify nothing was forwarded to the backend
      assert {:error, :timeout} = :gen_tcp.recv(ctx.backend_sock, 0, 200)

      # Session should still be alive
      assert Process.alive?(ctx.session_pid)

      cleanup(ctx)
    end

    test "real data frames ARE forwarded to backend" do
      ctx = setup_established_session()

      # Send a data frame (FRAME_DATA + data_seq + payload)
      payload = "GET / HTTP/1.1\r\n\r\n"
      data_frame = <<0x00, 0::big-64, payload::binary>>
      send_encrypted_frame(ctx, data_frame, 1)
      Process.sleep(100)

      # Backend should receive the payload
      {:ok, received} = :gen_tcp.recv(ctx.backend_sock, 0, 2000)
      assert received == payload

      cleanup(ctx)
    end

    test "keepalive after backend close does NOT trigger reconnect" do
      ctx = setup_established_session()

      # Close the backend TCP connection (simulating vaultwarden idle timeout)
      :gen_tcp.close(ctx.backend_sock)
      Process.sleep(100)

      # Send a keepalive frame — should NOT cause backend reconnect
      send_encrypted_frame(ctx, <<0x01>>, 1)
      Process.sleep(100)

      # Session should still be alive (no crash)
      assert Process.alive?(ctx.session_pid)

      # No new connection should have been attempted on the listen socket
      assert {:error, :timeout} = :gen_tcp.accept(ctx.listen_sock, 200)

      # Clean up (backend_sock already closed)
      if Process.alive?(ctx.session_pid), do: GenServer.stop(ctx.session_pid)
      :gen_tcp.close(ctx.listen_sock)
      :gen_udp.close(ctx.client_sock)
      :gen_udp.close(ctx.gw_sock)
    end
  end
end
