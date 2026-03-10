defmodule ZtlpRelay.PipelineTest do
  use ExUnit.Case

  alias ZtlpRelay.{Pipeline, Packet, Crypto, SessionRegistry, Stats}

  setup do
    # Reset stats before each test
    Stats.reset()
    :ok
  end

  describe "layer1_magic/1" do
    test "passes valid magic" do
      pkt = Packet.build_data(<<0::96>>, 0)
      raw = Packet.serialize(pkt)
      assert :ok = Pipeline.layer1_magic(raw)
    end

    test "drops invalid magic" do
      padding = :binary.copy(<<0>>, 40)
      assert {:drop, :invalid_magic} = Pipeline.layer1_magic(<<0xDE, 0xAD>> <> padding)
    end

    test "drops empty packet" do
      assert {:drop, :invalid_magic} = Pipeline.layer1_magic(<<>>)
    end
  end

  describe "layer2_session/1" do
    test "passes HELLO messages without session registration" do
      pkt = Packet.build_handshake(:hello, <<0::96>>)
      raw = Packet.serialize(pkt)
      assert :ok = Pipeline.layer2_session(raw)
    end

    test "passes HELLO_ACK messages without session registration" do
      pkt = Packet.build_handshake(:hello_ack, <<0::96>>)
      raw = Packet.serialize(pkt)
      assert :ok = Pipeline.layer2_session(raw)
    end

    test "drops data packets with unknown session" do
      session_id = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_data(session_id, 0)
      raw = Packet.serialize(pkt)
      assert {:drop, :unknown_session} = Pipeline.layer2_session(raw)
    end

    test "passes data packets with registered session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      pkt = Packet.build_data(session_id, 0)
      raw = Packet.serialize(pkt)
      assert :ok = Pipeline.layer2_session(raw)

      # Cleanup
      SessionRegistry.unregister_session(session_id)
    end

    test "passes handshake control packets with registered session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      pkt = Packet.build_handshake(:rekey, session_id)
      raw = Packet.serialize(pkt)
      assert :ok = Pipeline.layer2_session(raw)

      SessionRegistry.unregister_session(session_id)
    end
  end

  describe "layer3_auth/2" do
    test "passes when session_key is nil (relay mode)" do
      pkt = Packet.build_data(<<0::96>>, 0)
      raw = Packet.serialize(pkt)
      assert :ok = Pipeline.layer3_auth(raw, nil)
    end

    test "passes HELLO messages regardless of key" do
      key = Crypto.generate_key()
      pkt = Packet.build_handshake(:hello, <<0::96>>)
      raw = Packet.serialize(pkt)
      assert :ok = Pipeline.layer3_auth(raw, key)
    end

    test "passes data packet with valid auth tag" do
      key = Crypto.generate_key()
      session_id = :crypto.strong_rand_bytes(12)

      # Build packet, compute auth tag over the AAD
      pkt = Packet.build_data(session_id, 1)
      raw_no_tag = Packet.serialize(pkt)
      {:ok, aad} = Packet.extract_aad(raw_no_tag)

      tag = Crypto.compute_header_auth_tag(key, aad)
      pkt_with_tag = %{pkt | header_auth_tag: tag}
      raw = Packet.serialize(pkt_with_tag)

      assert :ok = Pipeline.layer3_auth(raw, key)
    end

    test "drops data packet with invalid auth tag" do
      key = Crypto.generate_key()
      session_id = :crypto.strong_rand_bytes(12)

      pkt = Packet.build_data(session_id, 1, header_auth_tag: :crypto.strong_rand_bytes(16))
      raw = Packet.serialize(pkt)

      assert {:drop, :invalid_auth_tag} = Pipeline.layer3_auth(raw, key)
    end

    test "passes handshake packet with valid auth tag" do
      key = Crypto.generate_key()
      session_id = :crypto.strong_rand_bytes(12)

      pkt = Packet.build_handshake(:rekey, session_id)
      raw_no_tag = Packet.serialize(pkt)
      {:ok, aad} = Packet.extract_aad(raw_no_tag)

      tag = Crypto.compute_header_auth_tag(key, aad)
      pkt_with_tag = %{pkt | header_auth_tag: tag}
      raw = Packet.serialize(pkt_with_tag)

      assert :ok = Pipeline.layer3_auth(raw, key)
    end
  end

  describe "process/2 full pipeline" do
    test "drops non-ZTLP traffic at layer 1 and increments counter" do
      assert {:drop, 1, :invalid_magic} = Pipeline.process(<<0xDE, 0xAD>> <> :binary.copy(<<0>>, 40))
      stats = Stats.get_stats()
      assert stats.layer1_drops == 1
    end

    test "drops unknown session at layer 2 and increments counter" do
      session_id = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_data(session_id, 0)
      raw = Packet.serialize(pkt)

      assert {:drop, 2, :unknown_session} = Pipeline.process(raw)
      stats = Stats.get_stats()
      assert stats.layer2_drops == 1
    end

    test "passes HELLO through all layers (relay mode, no key)" do
      pkt = Packet.build_handshake(:hello, <<0::96>>)
      raw = Packet.serialize(pkt)

      assert {:pass, parsed} = Pipeline.process(raw)
      assert parsed.msg_type == :hello
      stats = Stats.get_stats()
      assert stats.passed == 1
    end

    test "passes registered session data through all layers (relay mode)" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}
      SessionRegistry.register_session(session_id, peer_a, peer_b)

      pkt = Packet.build_data(session_id, 0)
      raw = Packet.serialize(pkt)

      assert {:pass, parsed} = Pipeline.process(raw)
      assert parsed.session_id == session_id
      stats = Stats.get_stats()
      assert stats.passed == 1

      SessionRegistry.unregister_session(session_id)
    end

    test "tracks multiple drops across layers" do
      # Layer 1 drops
      Pipeline.process(<<0xFF, 0xFF>>)
      Pipeline.process(<<0x00, 0x00>>)

      # Layer 2 drop
      pkt = Packet.build_data(:crypto.strong_rand_bytes(12), 0)
      Pipeline.process(Packet.serialize(pkt))

      stats = Stats.get_stats()
      assert stats.layer1_drops == 2
      assert stats.layer2_drops == 1
      assert stats.passed == 0
    end
  end
end
