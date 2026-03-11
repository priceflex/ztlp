defmodule ZtlpRelay.TransitTest do
  use ExUnit.Case

  alias ZtlpRelay.{Transit, AdmissionToken, Packet, SessionRegistry}

  @secret AdmissionToken.generate_secret()
  @issuer_id :crypto.strong_rand_bytes(16)

  # Helper to build extension payload with RAT + padding
  defp build_ext_payload(rat) do
    ext_len = div(byte_size(rat) + 3, 4)
    total_bytes = ext_len * 4
    padding_bytes = total_bytes - byte_size(rat)
    padding = :binary.copy(<<0>>, padding_bytes)
    {ext_len, <<rat::binary, padding::binary>>}
  end

  describe "accept_packet?/3 with existing session" do
    test "accepts packet belonging to an existing session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      pkt = Packet.build_data(session_id, 1)

      assert {:accept, :existing_session} =
               Transit.accept_packet?(pkt, peer_a, secret_key: @secret)

      SessionRegistry.unregister_session(session_id)
    end

    test "accepts handshake packet with existing session" do
      session_id = :crypto.strong_rand_bytes(12)
      peer_a = {{127, 0, 0, 1}, 5001}
      peer_b = {{127, 0, 0, 1}, 5002}

      SessionRegistry.register_session(session_id, peer_a, peer_b)

      pkt = Packet.build_handshake(:rekey, session_id)

      assert {:accept, :existing_session} =
               Transit.accept_packet?(pkt, peer_a, secret_key: @secret)

      SessionRegistry.unregister_session(session_id)
    end
  end

  describe "accept_packet?/3 with RAT" do
    test "accepts handshake packet with valid RAT in extension area" do
      session_id = :crypto.strong_rand_bytes(12)
      node_id = :crypto.strong_rand_bytes(16)
      sender = {{127, 0, 0, 1}, 5001}

      rat =
        AdmissionToken.issue(node_id, session_id,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      assert byte_size(rat) == 93

      {ext_len, ext_payload} = build_ext_payload(rat)

      pkt =
        Packet.build_handshake(:hello, session_id,
          src_node_id: node_id,
          ext_len: ext_len,
          payload: ext_payload
        )

      result = Transit.accept_packet?(pkt, sender, secret_key: @secret)
      assert {:accept, :new_session, ^rat} = result

      assert SessionRegistry.session_exists?(session_id)

      SessionRegistry.unregister_session(session_id)
    end

    test "drops packet with invalid RAT (wrong key)" do
      session_id = :crypto.strong_rand_bytes(12)
      node_id = :crypto.strong_rand_bytes(16)
      sender = {{127, 0, 0, 1}, 5001}

      wrong_key = AdmissionToken.generate_secret()

      rat =
        AdmissionToken.issue(node_id, session_id,
          secret_key: wrong_key,
          issuer_id: @issuer_id
        )

      {ext_len, ext_payload} = build_ext_payload(rat)

      pkt =
        Packet.build_handshake(:hello, session_id,
          src_node_id: node_id,
          ext_len: ext_len,
          payload: ext_payload
        )

      assert :drop = Transit.accept_packet?(pkt, sender, secret_key: @secret)
    end

    test "drops packet with expired RAT" do
      session_id = :crypto.strong_rand_bytes(12)
      node_id = :crypto.strong_rand_bytes(16)
      sender = {{127, 0, 0, 1}, 5001}

      rat =
        AdmissionToken.issue(node_id, session_id,
          secret_key: @secret,
          issuer_id: @issuer_id,
          ttl_seconds: 0
        )

      Process.sleep(10)

      {ext_len, ext_payload} = build_ext_payload(rat)

      pkt =
        Packet.build_handshake(:hello, session_id,
          src_node_id: node_id,
          ext_len: ext_len,
          payload: ext_payload
        )

      assert :drop = Transit.accept_packet?(pkt, sender, secret_key: @secret)
    end
  end

  describe "accept_packet?/3 without session or RAT" do
    test "drops packet with no session and no RAT" do
      session_id = :crypto.strong_rand_bytes(12)
      sender = {{127, 0, 0, 1}, 5001}

      pkt = Packet.build_data(session_id, 1)

      assert :drop = Transit.accept_packet?(pkt, sender, secret_key: @secret)
    end

    test "drops handshake packet with ext_len=0 and no session" do
      session_id = :crypto.strong_rand_bytes(12)
      sender = {{127, 0, 0, 1}, 5001}

      pkt = Packet.build_handshake(:hello, session_id, ext_len: 0)

      assert :drop = Transit.accept_packet?(pkt, sender, secret_key: @secret)
    end
  end

  describe "extract_rat/1" do
    test "extracts RAT from handshake packet with ext_len > 0" do
      rat_data = :crypto.strong_rand_bytes(93)

      {ext_len, ext_payload} = build_ext_payload(rat_data)

      pkt =
        Packet.build_handshake(:hello, :crypto.strong_rand_bytes(12),
          ext_len: ext_len,
          payload: ext_payload
        )

      assert {:ok, extracted} = Transit.extract_rat(pkt)
      assert extracted == rat_data
    end

    test "returns :no_rat for packet with ext_len=0" do
      pkt = Packet.build_handshake(:hello, :crypto.strong_rand_bytes(12), ext_len: 0)
      assert :no_rat = Transit.extract_rat(pkt)
    end

    test "returns :no_rat for compact data packet" do
      pkt = Packet.build_data(:crypto.strong_rand_bytes(12), 1)
      assert :no_rat = Transit.extract_rat(pkt)
    end

    test "returns :no_rat when ext area is too small for RAT" do
      pkt =
        Packet.build_handshake(:hello, :crypto.strong_rand_bytes(12),
          ext_len: 5,
          payload: :crypto.strong_rand_bytes(20)
        )

      assert :no_rat = Transit.extract_rat(pkt)
    end
  end

  describe "RAT with key rotation" do
    test "accepts RAT signed with previous key during rotation" do
      session_id = :crypto.strong_rand_bytes(12)
      node_id = :crypto.strong_rand_bytes(16)
      sender = {{127, 0, 0, 1}, 5001}

      current_key = AdmissionToken.generate_secret()
      previous_key = AdmissionToken.generate_secret()

      rat =
        AdmissionToken.issue(node_id, session_id,
          secret_key: previous_key,
          issuer_id: @issuer_id
        )

      {ext_len, ext_payload} = build_ext_payload(rat)

      pkt =
        Packet.build_handshake(:hello, session_id,
          src_node_id: node_id,
          ext_len: ext_len,
          payload: ext_payload
        )

      result =
        Transit.accept_packet?(pkt, sender,
          secret_key: current_key,
          secret_key_previous: previous_key
        )

      assert {:accept, :new_session, ^rat} = result

      SessionRegistry.unregister_session(session_id)
    end
  end
end
