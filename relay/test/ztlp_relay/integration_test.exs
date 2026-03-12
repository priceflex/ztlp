defmodule ZtlpRelay.IntegrationTest do
  @moduledoc """
  Integration tests for the full ZTLP relay flow.

  Tests the complete path: register session → send packet → relay forwards
  to other peer → verify receipt.
  """
  use ExUnit.Case

  alias ZtlpRelay.{
    Packet,
    Crypto,
    SessionRegistry,
    SessionSupervisor,
    Stats,
    UdpListener,
    Session
  }

  setup do
    Stats.reset()
    :ok
  end

  describe "full relay flow" do
    test "registers session, forwards packets bidirectionally" do
      relay_port = UdpListener.get_port()

      # Open two client sockets
      {:ok, client_a} = :gen_udp.open(0, [:binary, {:active, true}])
      {:ok, client_b} = :gen_udp.open(0, [:binary, {:active, true}])

      {:ok, port_a} = :inet.port(client_a)
      {:ok, port_b} = :inet.port(client_b)

      peer_a = {{127, 0, 0, 1}, port_a}
      peer_b = {{127, 0, 0, 1}, port_b}

      # Register a session
      session_id = Crypto.generate_session_id()
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      # Start a session GenServer
      {:ok, session_pid} =
        SessionSupervisor.start_session(
          session_id: session_id,
          peer_a: peer_a,
          peer_b: peer_b,
          timeout_ms: 5_000
        )

      SessionRegistry.update_session_pid(session_id, session_pid)

      # --- A → B ---
      payload_ab = "hello from A to B"
      pkt_a = Packet.build_data(session_id, 1, payload: payload_ab)
      raw_a = Packet.serialize(pkt_a)
      :gen_udp.send(client_a, {127, 0, 0, 1}, relay_port, raw_a)

      # B should receive exactly the packet A sent
      assert_receive {:udp, ^client_b, {127, 0, 0, 1}, ^relay_port, ^raw_a}, 1_000

      # --- B → A ---
      payload_ba = "hello from B to A"
      pkt_b = Packet.build_data(session_id, 1, payload: payload_ba)
      raw_b = Packet.serialize(pkt_b)
      :gen_udp.send(client_b, {127, 0, 0, 1}, relay_port, raw_b)

      # A should receive exactly the packet B sent
      assert_receive {:udp, ^client_a, {127, 0, 0, 1}, ^relay_port, ^raw_b}, 1_000

      # Verify stats (counter updates are async — retry briefly)
      stats =
        Enum.reduce_while(1..10, nil, fn _, _ ->
          s = Stats.get_stats()
          if s.forwarded >= 2, do: {:halt, s}, else: (Process.sleep(20); {:cont, s})
        end)
      assert stats.passed >= 2
      assert stats.forwarded >= 2

      # Verify session state
      Process.sleep(50)
      session_state = Session.get_state(session_pid)
      assert session_state.packet_count >= 2

      # Cleanup
      Session.close(session_pid)
      Process.sleep(100)
      :gen_udp.close(client_a)
      :gen_udp.close(client_b)
    end

    test "multiple concurrent sessions" do
      relay_port = UdpListener.get_port()

      # Create 5 session pairs
      sessions =
        for i <- 1..5 do
          {:ok, ca} = :gen_udp.open(0, [:binary, {:active, true}])
          {:ok, cb} = :gen_udp.open(0, [:binary, {:active, true}])
          {:ok, pa} = :inet.port(ca)
          {:ok, pb} = :inet.port(cb)

          peer_a = {{127, 0, 0, 1}, pa}
          peer_b = {{127, 0, 0, 1}, pb}
          session_id = Crypto.generate_session_id()

          SessionRegistry.register_session(session_id, peer_a, peer_b)

          {:ok, spid} =
            SessionSupervisor.start_session(
              session_id: session_id,
              peer_a: peer_a,
              peer_b: peer_b,
              timeout_ms: 5_000
            )

          SessionRegistry.update_session_pid(session_id, spid)

          %{
            index: i,
            session_id: session_id,
            client_a: ca,
            client_b: cb,
            session_pid: spid
          }
        end

      # Send from A → B for each session
      for %{session_id: sid, client_a: ca, client_b: cb} <- sessions do
        pkt = Packet.build_data(sid, 1, payload: "test-#{Base.encode16(sid)}")
        raw = Packet.serialize(pkt)
        :gen_udp.send(ca, {127, 0, 0, 1}, relay_port, raw)

        # Each B should receive
        assert_receive {:udp, ^cb, {127, 0, 0, 1}, ^relay_port, ^raw}, 1_000
      end

      stats =
        Enum.reduce_while(1..10, nil, fn _, _ ->
          s = Stats.get_stats()
          if s.forwarded >= 5, do: {:halt, s}, else: (Process.sleep(20); {:cont, s})
        end)
      assert stats.forwarded >= 5

      # Cleanup
      for %{session_id: sid, client_a: ca, client_b: cb, session_pid: spid} <- sessions do
        Session.close(spid)
        Process.sleep(20)
        SessionRegistry.unregister_session(sid)
        :gen_udp.close(ca)
        :gen_udp.close(cb)
      end
    end

    test "crypto roundtrip: compute and verify auth tag" do
      key = Crypto.generate_key()
      session_id = Crypto.generate_session_id()

      # Build a data packet
      pkt = Packet.build_data(session_id, 42, payload: "encrypted stuff")
      raw = Packet.serialize(pkt)

      # Extract AAD and compute tag
      {:ok, aad} = Packet.extract_aad(raw)
      tag = Crypto.compute_header_auth_tag(key, aad)

      # Rebuild with real tag
      pkt_with_tag = %{pkt | header_auth_tag: tag}
      raw_with_tag = Packet.serialize(pkt_with_tag)

      # Verify
      {:ok, aad2} = Packet.extract_aad(raw_with_tag)
      {:ok, tag2} = Packet.extract_auth_tag(raw_with_tag)
      assert Crypto.verify_header_auth_tag(key, aad2, tag2)

      # Verify with wrong key fails
      wrong_key = Crypto.generate_key()
      refute Crypto.verify_header_auth_tag(wrong_key, aad2, tag2)

      # Verify with tampered AAD fails
      tampered_aad = <<0xFF>> <> binary_part(aad2, 1, byte_size(aad2) - 1)
      refute Crypto.verify_header_auth_tag(key, tampered_aad, tag2)
    end

    test "handshake packet roundtrip through serialize/parse" do
      session_id = Crypto.generate_session_id()
      src_node_id = :crypto.strong_rand_bytes(16)
      dst_svc_id = :crypto.strong_rand_bytes(16)

      pkt =
        Packet.build_handshake(:hello, session_id,
          crypto_suite: 0x0001,
          key_id: 7,
          packet_seq: 0,
          src_node_id: src_node_id,
          dst_svc_id: dst_svc_id,
          policy_tag: 0x00010002
        )

      raw = Packet.serialize(pkt)
      # No payload
      assert byte_size(raw) == 95

      {:ok, parsed} = Packet.parse(raw)
      assert parsed.msg_type == :hello
      assert parsed.session_id == session_id
      assert parsed.src_node_id == src_node_id
      assert parsed.dst_svc_id == dst_svc_id
      assert parsed.crypto_suite == 0x0001
      assert parsed.key_id == 7
      assert parsed.policy_tag == 0x00010002
    end

    test "relay ignores packets from unknown peers" do
      relay_port = UdpListener.get_port()

      {:ok, client_a} = :gen_udp.open(0, [:binary, {:active, true}])
      {:ok, client_b} = :gen_udp.open(0, [:binary, {:active, true}])
      {:ok, unknown} = :gen_udp.open(0, [:binary, {:active, true}])

      {:ok, port_a} = :inet.port(client_a)
      {:ok, port_b} = :inet.port(client_b)

      peer_a = {{127, 0, 0, 1}, port_a}
      peer_b = {{127, 0, 0, 1}, port_b}

      session_id = Crypto.generate_session_id()
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      # Send from unknown peer — should pass pipeline (session exists)
      # but fail to find the other peer (sender is not peer_a or peer_b)
      pkt = Packet.build_data(session_id, 1)
      raw = Packet.serialize(pkt)
      :gen_udp.send(unknown, {127, 0, 0, 1}, relay_port, raw)

      # Neither A nor B should receive anything
      Process.sleep(100)
      refute_receive {:udp, ^client_a, _, _, _}
      refute_receive {:udp, ^client_b, _, _, _}

      SessionRegistry.unregister_session(session_id)
      :gen_udp.close(client_a)
      :gen_udp.close(client_b)
      :gen_udp.close(unknown)
    end
  end
end
