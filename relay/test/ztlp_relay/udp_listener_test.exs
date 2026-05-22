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

      # Stats updates are async — allow time for counter to propagate
      Process.sleep(50)
      stats = Stats.get_stats()
      assert stats.forwarded >= 2

      # Cleanup
      SessionRegistry.unregister_session(session_id)
      :gen_udp.close(client_a)
      :gen_udp.close(client_b)
    end
  end

  describe "CLIENT_ROUTE (FRAME_CLIENT_ROUTE 0x5A 0x37 0x0B)" do
    # Build a CLIENT_ROUTE packet matching the wire format documented in
    # proto/src/bin/ztlp-cli.rs (constants CLIENT_ROUTE_*).
    #
    # Layout: 0x5A 0x37 0x0B | 16 node_id | 1 svc_len | svc_len service |
    #         8 timestamp (i64 BE) | 32 hmac
    defp build_client_route(node_id, service_name, timestamp, hmac) do
      svc_len = byte_size(service_name)
      <<0x5A, 0x37, 0x0B, node_id::binary-size(16), svc_len::8,
        service_name::binary-size(svc_len), timestamp::64-signed,
        hmac::binary-size(32)>>
    end

    setup do
      # The QUIC tuple table is normally created lazily on first GATEWAY_REGISTER
      # or CLIENT_ROUTE. Make sure each test starts from a clean state.
      if :ets.info(:ztlp_forwarded_quic_tuples, :name) != :undefined do
        :ets.delete_all_objects(:ztlp_forwarded_quic_tuples)
      end

      # Make sure the GatewayForwarder is up; some test orderings race the app
      # startup.
      case GenServer.whereis(ZtlpRelay.GatewayForwarder) do
        nil -> {:ok, _pid} = ZtlpRelay.GatewayForwarder.start_link()
        _pid -> :ok
      end

      ZtlpRelay.GatewayForwarder.clear_all()
      :ok
    end

    test "installs client→gateway 5-tuple mapping for a registered service" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      # Register a fake gateway for the target service
      gw_node_id = :crypto.strong_rand_bytes(16)
      gw_addr = {{10, 0, 0, 99}, 23097}
      service_name = "gw-route-test"
      ZtlpRelay.GatewayForwarder.register_dynamic_gateway(gw_addr, gw_node_id, service_name, 60)
      Process.sleep(20) # cast is async

      # Send the CLIENT_ROUTE packet
      client_node_id = :crypto.strong_rand_bytes(16)
      ts = System.system_time(:second)
      pkt = build_client_route(client_node_id, service_name, ts, <<0::256>>)

      :gen_udp.send(client, {127, 0, 0, 1}, port, pkt)
      Process.sleep(50)

      # ETS mapping should now exist
      assert :ets.info(:ztlp_forwarded_quic_tuples, :name) != :undefined

      assert [{{:client_map, ^sender}, ^gw_addr}] =
               :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})

      :gen_udp.close(client)
    end

    test "rejects CLIENT_ROUTE for an unregistered service (no ETS write)" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      ts = System.system_time(:second)
      pkt = build_client_route(:crypto.strong_rand_bytes(16), "gw-does-not-exist", ts, <<0::256>>)

      :gen_udp.send(client, {127, 0, 0, 1}, port, pkt)
      Process.sleep(50)

      # No client_map entry should have been written
      lookup_result =
        if :ets.info(:ztlp_forwarded_quic_tuples, :name) == :undefined do
          []
        else
          :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})
        end

      assert lookup_result == []

      :gen_udp.close(client)
    end

    test "rejects CLIENT_ROUTE with malformed (zero-length) service name" do
      port = UdpListener.get_port()
      {:ok, client} = :gen_udp.open(0, [:binary])
      {:ok, client_port} = :inet.port(client)
      sender = {{127, 0, 0, 1}, client_port}

      # Hand-craft a packet with svc_len=0 to bypass build_client_route guards.
      bad =
        <<0x5A, 0x37, 0x0B, 0::128, 0::8, 0::64, 0::256>>

      :gen_udp.send(client, {127, 0, 0, 1}, port, bad)
      Process.sleep(50)

      lookup_result =
        if :ets.info(:ztlp_forwarded_quic_tuples, :name) == :undefined do
          []
        else
          :ets.lookup(:ztlp_forwarded_quic_tuples, {:client_map, sender})
        end

      assert lookup_result == []

      :gen_udp.close(client)
    end
  end
end
