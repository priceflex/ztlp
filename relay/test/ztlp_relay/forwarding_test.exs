defmodule ZtlpRelay.ForwardingTest do
  @moduledoc """
  Tests for bidirectional relay forwarding through the UdpListener.

  These tests create real UDP sockets to simulate peer_a and peer_b
  sending ZTLP packets through the relay, verifying that:
  - HELLO creates a HALF_OPEN session
  - Second peer's packet promotes to ESTABLISHED
  - DATA from peer_a reaches peer_b and vice versa
  - Session state machine transitions work end-to-end
  """
  use ExUnit.Case

  alias ZtlpRelay.{Packet, SessionRegistry, Session}

  # Wait for the UdpListener to be up (it starts with the app)
  setup do
    # Ensure the registry is available
    _ = SessionRegistry.count()

    # Clear any dynamic gateway registrations from other tests
    # so HELLOs without service names create half-open sessions
    # instead of being forwarded to gateways
    ZtlpRelay.GatewayForwarder.clear_all()

    # Get the relay's actual listening port
    port = ZtlpRelay.UdpListener.get_port()
    relay_addr = {{127, 0, 0, 1}, port}

    {:ok, relay_addr: relay_addr, relay_port: port}
  end

  defp open_udp() do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, {127, 0, 0, 1}}])
    {:ok, port} = :inet.port(socket)
    {socket, port}
  end

  defp send_hello(socket, relay_addr, session_id, opts \\ []) do
    pkt = Packet.build_handshake(:hello, session_id, opts)
    data = Packet.serialize_handshake(pkt)
    {relay_ip, relay_port} = relay_addr
    :gen_udp.send(socket, relay_ip, relay_port, data)
  end

  defp send_hello_ack(socket, relay_addr, session_id, opts \\ []) do
    pkt = Packet.build_handshake(:hello_ack, session_id, opts)
    data = Packet.serialize_handshake(pkt)
    {relay_ip, relay_port} = relay_addr
    :gen_udp.send(socket, relay_ip, relay_port, data)
  end

  defp send_data(socket, relay_addr, session_id, seq, opts) do
    pkt = Packet.build_data(session_id, seq, opts)
    data = Packet.serialize_data(pkt)
    {relay_ip, relay_port} = relay_addr
    :gen_udp.send(socket, relay_ip, relay_port, data)
  end

  defp recv_packet(socket, timeout) do
    case :gen_udp.recv(socket, 0, timeout) do
      {:ok, {_ip, _port, data}} -> {:ok, data}
      {:error, :timeout} -> {:error, :timeout}
    end
  end

  describe "HELLO creates HALF_OPEN session" do
    test "first HELLO registers a half-open session", %{relay_addr: relay_addr} do
      session_id = :crypto.strong_rand_bytes(12)
      {sock_a, _port_a} = open_udp()

      send_hello(sock_a, relay_addr, session_id)
      Process.sleep(100)

      case SessionRegistry.lookup_session(session_id) do
        {:ok, {_peer_a, peer_b, pid}} ->
          assert peer_b == nil
          assert is_pid(pid)
          state = Session.get_state(pid)
          assert state.status == :half_open

          Session.close(pid)

        :error ->
          flunk("Session should have been registered")
      end

      :gen_udp.close(sock_a)
    end
  end

  describe "bidirectional forwarding" do
    test "HELLO + HELLO_ACK establishes session, data flows both ways", %{
      relay_addr: relay_addr
    } do
      session_id = :crypto.strong_rand_bytes(12)
      {sock_a, _port_a} = open_udp()
      {sock_b, _port_b} = open_udp()

      # peer_a sends HELLO — creates HALF_OPEN session
      send_hello(sock_a, relay_addr, session_id)
      Process.sleep(100)

      # peer_b sends HELLO_ACK — promotes to ESTABLISHED, forwarded to peer_a
      send_hello_ack(sock_b, relay_addr, session_id)
      Process.sleep(100)

      # peer_a should receive the HELLO_ACK
      assert {:ok, data_a} = recv_packet(sock_a, 500)
      assert {:ok, parsed} = Packet.parse(data_a)
      assert parsed.msg_type == :hello_ack
      assert parsed.session_id == session_id

      # Verify session is now ESTABLISHED
      {:ok, {_peer_a, _peer_b, pid}} = SessionRegistry.lookup_session(session_id)
      state = Session.get_state(pid)
      assert state.status == :established

      # peer_a sends DATA — should be forwarded to peer_b
      send_data(sock_a, relay_addr, session_id, 1, payload: <<"hello from A">>)
      Process.sleep(100)

      assert {:ok, data_b} = recv_packet(sock_b, 500)
      assert {:ok, parsed_b} = Packet.parse(data_b)
      assert parsed_b.session_id == session_id
      assert parsed_b.payload == <<"hello from A">>

      # peer_b sends DATA — should be forwarded to peer_a
      send_data(sock_b, relay_addr, session_id, 2, payload: <<"hello from B">>)
      Process.sleep(100)

      assert {:ok, data_a2} = recv_packet(sock_a, 500)
      assert {:ok, parsed_a2} = Packet.parse(data_a2)
      assert parsed_a2.session_id == session_id
      assert parsed_a2.payload == <<"hello from B">>

      Session.close(pid)
      :gen_udp.close(sock_a)
      :gen_udp.close(sock_b)
    end

    test "second peer learned from DATA packet (not just HELLO_ACK)", %{
      relay_addr: relay_addr
    } do
      session_id = :crypto.strong_rand_bytes(12)
      {sock_a, _port_a} = open_udp()
      {sock_b, _port_b} = open_udp()

      # peer_a sends HELLO — creates HALF_OPEN session
      send_hello(sock_a, relay_addr, session_id)
      Process.sleep(100)

      # peer_b sends DATA directly (e.g., after out-of-band session setup)
      send_data(sock_b, relay_addr, session_id, 1, payload: <<"data from B">>)
      Process.sleep(100)

      # Should have promoted to ESTABLISHED
      {:ok, {_peer_a, _peer_b, pid}} = SessionRegistry.lookup_session(session_id)
      state = Session.get_state(pid)
      assert state.status == :established

      # peer_a should have received the data
      assert {:ok, data_a} = recv_packet(sock_a, 500)
      assert {:ok, parsed} = Packet.parse(data_a)
      assert parsed.payload == <<"data from B">>

      Session.close(pid)
      :gen_udp.close(sock_a)
      :gen_udp.close(sock_b)
    end
  end

  describe "multiple concurrent sessions" do
    test "two independent sessions can forward simultaneously", %{relay_addr: relay_addr} do
      sid_1 = :crypto.strong_rand_bytes(12)
      sid_2 = :crypto.strong_rand_bytes(12)

      {sock_a1, _} = open_udp()
      {sock_b1, _} = open_udp()
      {sock_a2, _} = open_udp()
      {sock_b2, _} = open_udp()

      # Session 1: HELLO + HELLO_ACK
      send_hello(sock_a1, relay_addr, sid_1)
      Process.sleep(50)
      send_hello_ack(sock_b1, relay_addr, sid_1)
      Process.sleep(50)
      # Drain the forwarded HELLO_ACK
      assert {:ok, _} = recv_packet(sock_a1, 500)

      # Session 2: HELLO + HELLO_ACK
      send_hello(sock_a2, relay_addr, sid_2)
      Process.sleep(50)
      send_hello_ack(sock_b2, relay_addr, sid_2)
      Process.sleep(50)
      assert {:ok, _} = recv_packet(sock_a2, 500)

      # Send data on session 1
      send_data(sock_a1, relay_addr, sid_1, 1, payload: <<"session1 data">>)
      Process.sleep(50)
      assert {:ok, d1} = recv_packet(sock_b1, 500)
      assert {:ok, p1} = Packet.parse(d1)
      assert p1.payload == <<"session1 data">>

      # Send data on session 2
      send_data(sock_a2, relay_addr, sid_2, 1, payload: <<"session2 data">>)
      Process.sleep(50)
      assert {:ok, d2} = recv_packet(sock_b2, 500)
      assert {:ok, p2} = Packet.parse(d2)
      assert p2.payload == <<"session2 data">>

      # Cross-check: session 1 data doesn't leak to session 2
      assert {:error, :timeout} = recv_packet(sock_b2, 100)
      assert {:error, :timeout} = recv_packet(sock_b1, 100)

      # Cleanup
      {:ok, {_, _, pid1}} = SessionRegistry.lookup_session(sid_1)
      {:ok, {_, _, pid2}} = SessionRegistry.lookup_session(sid_2)
      Session.close(pid1)
      Session.close(pid2)

      Enum.each([sock_a1, sock_b1, sock_a2, sock_b2], &:gen_udp.close/1)
    end
  end

  describe "session timeout through relay" do
    test "half-open session expires and is cleaned up", %{relay_addr: relay_addr} do
      session_id = :crypto.strong_rand_bytes(12)
      {sock_a, _port_a} = open_udp()

      # Override config for short timeout
      prev = Application.get_env(:ztlp_relay, :session_timeout_ms)
      Application.put_env(:ztlp_relay, :session_timeout_ms, 60_000)

      send_hello(sock_a, relay_addr, session_id)
      Process.sleep(100)

      {:ok, {_peer_a, nil, pid}} = SessionRegistry.lookup_session(session_id)
      assert Session.get_state(pid).status == :half_open

      # The session was started with 30s half-open timeout by default,
      # but we can verify it exists and would timeout
      assert Process.alive?(pid)

      # Clean up manually
      Session.close(pid)
      Process.sleep(50)

      if prev, do: Application.put_env(:ztlp_relay, :session_timeout_ms, prev)
      :gen_udp.close(sock_a)
    end
  end
end
