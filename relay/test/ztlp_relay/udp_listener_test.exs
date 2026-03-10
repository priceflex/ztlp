defmodule ZtlpRelay.UdpListenerTest do
  use ExUnit.Case

  alias ZtlpRelay.{UdpListener, Packet, SessionRegistry, Stats}

  setup do
    Stats.reset()
    :ok
  end

  describe "listener" do
    test "is running and has a port" do
      port = UdpListener.get_port()
      assert is_integer(port)
      assert port > 0
    end

    test "has a valid socket" do
      socket = UdpListener.get_socket()
      assert socket != nil
    end
  end

  describe "packet handling" do
    test "drops non-ZTLP traffic" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])

      :gen_udp.send(client, {127, 0, 0, 1}, port, <<0xDE, 0xAD, 0xBE, 0xEF>>)
      Process.sleep(50)

      stats = Stats.get_stats()
      assert stats.layer1_drops >= 1

      :gen_udp.close(client)
    end

    test "drops data packet with unknown session" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])

      session_id = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_data(session_id, 0)
      raw = Packet.serialize(pkt)

      :gen_udp.send(client, {127, 0, 0, 1}, port, raw)
      Process.sleep(50)

      stats = Stats.get_stats()
      assert stats.layer2_drops >= 1

      :gen_udp.close(client)
    end

    test "accepts HELLO messages" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])

      pkt = Packet.build_handshake(:hello, <<0::96>>)
      raw = Packet.serialize(pkt)

      :gen_udp.send(client, {127, 0, 0, 1}, port, raw)
      Process.sleep(50)

      stats = Stats.get_stats()
      assert stats.passed >= 1

      :gen_udp.close(client)
    end

    test "forwards packets between registered peers" do
      port = UdpListener.get_port()

      # Create two client sockets (peers)
      {:ok, client_a} = :gen_udp.open(0, [:binary, {:active, true}])
      {:ok, client_b} = :gen_udp.open(0, [:binary, {:active, true}])

      {:ok, port_a} = :inet.port(client_a)
      {:ok, port_b} = :inet.port(client_b)

      peer_a = {{127, 0, 0, 1}, port_a}
      peer_b = {{127, 0, 0, 1}, port_b}

      # Register a session
      session_id = :crypto.strong_rand_bytes(12)
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      # Send a data packet from peer A to relay
      pkt = Packet.build_data(session_id, 1)
      raw = Packet.serialize(pkt)
      :gen_udp.send(client_a, {127, 0, 0, 1}, port, raw)

      # Peer B should receive the forwarded packet
      assert_receive {:udp, ^client_b, {127, 0, 0, 1}, ^port, ^raw}, 1_000

      # Send from peer B to relay
      pkt2 = Packet.build_data(session_id, 2)
      raw2 = Packet.serialize(pkt2)
      :gen_udp.send(client_b, {127, 0, 0, 1}, port, raw2)

      # Peer A should receive the forwarded packet
      assert_receive {:udp, ^client_a, {127, 0, 0, 1}, ^port, ^raw2}, 1_000

      stats = Stats.get_stats()
      assert stats.forwarded >= 2

      # Cleanup
      SessionRegistry.unregister_session(session_id)
      :gen_udp.close(client_a)
      :gen_udp.close(client_b)
    end
  end
end
