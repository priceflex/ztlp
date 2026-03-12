defmodule ZtlpGateway.IntegrationTest do
  use ExUnit.Case

  alias ZtlpGateway.{Crypto, Handshake, Packet, PolicyEngine, Identity, AuditLog, Stats}

  # Integration tests verify the full crypto pipeline:
  # keypair → handshake → key derivation → encrypt → decrypt

  describe "full crypto pipeline" do
    test "handshake + transport encryption round-trip" do
      # Gateway keypair
      {gw_pub, gw_priv} = Crypto.generate_keypair()
      # Client keypair
      {cl_pub, cl_priv} = Crypto.generate_keypair()

      # Handshake
      client = Handshake.init_initiator(cl_pub, cl_priv)
      gateway = Handshake.init_responder(gw_pub, gw_priv)

      {client, msg1} = Handshake.create_msg1(client)
      {gateway, _} = Handshake.handle_msg1(gateway, msg1)
      {gateway, msg2} = Handshake.create_msg2(gateway)
      {client, _} = Handshake.process_msg2(client, msg2)
      {client, msg3} = Handshake.create_msg3(client)
      {gateway, _} = Handshake.handle_msg3(gateway, msg3)

      {:ok, client_keys} = Handshake.split(client)
      {:ok, gw_keys} = Handshake.split(gateway)

      # Client sends 100 messages to gateway
      Enum.each(1..100, fn seq ->
        nonce = <<0::32, seq::little-64>>
        msg = "message #{seq} from client"
        {ct, tag} = Crypto.encrypt(client_keys.i2r_key, nonce, msg, "")
        assert Crypto.decrypt(gw_keys.i2r_key, nonce, ct, "", tag) == msg
      end)

      # Gateway sends 100 messages to client
      Enum.each(1..100, fn seq ->
        nonce = <<0::32, seq::little-64>>
        msg = "response #{seq} from gateway"
        {ct, tag} = Crypto.encrypt(gw_keys.r2i_key, nonce, msg, "")
        assert Crypto.decrypt(client_keys.r2i_key, nonce, ct, "", tag) == msg
      end)
    end

    test "handshake through ZTLP packet wrapping" do
      {gw_pub, gw_priv} = Crypto.generate_keypair()
      {cl_pub, cl_priv} = Crypto.generate_keypair()

      client = Handshake.init_initiator(cl_pub, cl_priv)
      gateway = Handshake.init_responder(gw_pub, gw_priv)

      # Msg 1 wrapped in HELLO packet
      {client, msg1_bytes} = Handshake.create_msg1(client)
      hello_packet = Packet.build_hello(msg1_bytes)
      assert Packet.hello?(hello_packet)

      {:ok, parsed_hello} = Packet.parse(hello_packet)
      assert parsed_hello.type == :handshake
      assert parsed_hello.msg_type == :hello
      {gateway, _} = Handshake.handle_msg1(gateway, parsed_hello.payload)

      # Msg 2 wrapped in HELLO_ACK
      session_id = :crypto.strong_rand_bytes(12)
      {gateway, msg2_bytes} = Handshake.create_msg2(gateway)
      hello_ack = Packet.build_hello_ack(session_id, msg2_bytes)

      {:ok, parsed_ack} = Packet.parse(hello_ack)
      assert parsed_ack.type == :handshake
      assert parsed_ack.msg_type == :hello_ack
      {client, _} = Handshake.process_msg2(client, parsed_ack.payload)

      # Msg 3 wrapped in HANDSHAKE packet
      {client, msg3_bytes} = Handshake.create_msg3(client)
      hs_pkt_map = Packet.build_handshake(:rekey, session_id, payload: msg3_bytes)
      hs_pkt = Packet.serialize(hs_pkt_map)

      {:ok, parsed_hs} = Packet.parse(hs_pkt)
      {gateway, _} = Handshake.handle_msg3(gateway, parsed_hs.payload)

      # Verify keys match
      {:ok, ck} = Handshake.split(client)
      {:ok, gk} = Handshake.split(gateway)
      assert ck.i2r_key == gk.i2r_key
      assert ck.r2i_key == gk.r2i_key
    end

    test "data packet encrypt/decrypt through packet format" do
      {gw_pub, gw_priv} = Crypto.generate_keypair()
      {cl_pub, cl_priv} = Crypto.generate_keypair()

      # Full handshake
      client = Handshake.init_initiator(cl_pub, cl_priv)
      gateway = Handshake.init_responder(gw_pub, gw_priv)
      {client, m1} = Handshake.create_msg1(client)
      {gateway, _} = Handshake.handle_msg1(gateway, m1)
      {gateway, m2} = Handshake.create_msg2(gateway)
      {client, _} = Handshake.process_msg2(client, m2)
      {client, m3} = Handshake.create_msg3(client)
      {gateway, _} = Handshake.handle_msg3(gateway, m3)
      {:ok, ck} = Handshake.split(client)
      {:ok, gk} = Handshake.split(gateway)

      sid = :crypto.strong_rand_bytes(12)

      # Client builds an encrypted data packet
      seq = 1
      nonce = <<0::32, seq::little-64>>
      plaintext = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
      {ct, tag} = Crypto.encrypt(ck.i2r_key, nonce, plaintext, "")
      encrypted_payload = ct <> tag
      auth_tag = :crypto.strong_rand_bytes(16)

      data_pkt_map = Packet.build_data(sid, seq, payload: encrypted_payload, header_auth_tag: auth_tag)
      data_pkt = Packet.serialize(data_pkt_map)

      # Gateway receives and decrypts
      {:ok, parsed} = Packet.parse(data_pkt)
      assert parsed.type == :data_compact
      assert parsed.packet_seq == seq

      payload = parsed.payload
      ct_len = byte_size(payload) - 16
      recv_ct = binary_part(payload, 0, ct_len)
      recv_tag = binary_part(payload, ct_len, 16)
      recv_nonce = <<0::32, parsed.packet_seq::little-64>>

      decrypted = Crypto.decrypt(gk.i2r_key, recv_nonce, recv_ct, "", recv_tag)
      assert decrypted == plaintext
    end
  end

  describe "policy + identity integration" do
    test "registered identity passes policy check" do
      {pub, _priv} = Crypto.generate_keypair()
      Identity.register(pub, "admin.example.ztlp")
      PolicyEngine.put_rule("ssh", ["admin.example.ztlp"])

      identity = Identity.resolve_or_hex(pub)
      assert identity == "admin.example.ztlp"
      assert PolicyEngine.authorize?(identity, "ssh")

      # Clean up
      Identity.clear()
      PolicyEngine.delete_rule("ssh")
    end

    test "unregistered identity gets hex fallback and is denied" do
      {pub, _priv} = Crypto.generate_keypair()
      PolicyEngine.put_rule("ssh", ["admin.example.ztlp"])

      identity = Identity.resolve_or_hex(pub)
      assert String.starts_with?(identity, "unknown:")
      refute PolicyEngine.authorize?(identity, "ssh")

      PolicyEngine.delete_rule("ssh")
    end

    test "wildcard policy with registered identity" do
      {pub, _priv} = Crypto.generate_keypair()
      Identity.register(pub, "node1.ops.ztlp")
      PolicyEngine.put_rule("monitoring", ["*.ops.ztlp"])

      identity = Identity.resolve_or_hex(pub)
      assert PolicyEngine.authorize?(identity, "monitoring")

      Identity.clear()
      PolicyEngine.delete_rule("monitoring")
    end
  end

  describe "audit log" do
    setup do
      AuditLog.clear()
      :ok
    end

    test "records session lifecycle events" do
      sid = :crypto.strong_rand_bytes(16)
      pub = :crypto.strong_rand_bytes(32)

      AuditLog.session_established(sid, pub, {{127, 0, 0, 1}, 12345}, "web")
      AuditLog.session_terminated(sid, :timeout, 5000, 1024, 2048)

      events = AuditLog.events()
      assert length(events) == 2

      # newest first
      [term, est] = events
      assert est.event == :session_established
      assert est.service == "web"
      assert term.event == :session_terminated
      assert term.reason == :timeout
      assert term.bytes_in == 1024
      assert term.bytes_out == 2048
    end

    test "records policy denial" do
      pub = :crypto.strong_rand_bytes(32)
      AuditLog.policy_denied(pub, {{10, 0, 0, 1}, 9999}, "ssh", :not_authorized)

      [event] = AuditLog.events()
      assert event.event == :policy_denied
      assert event.service == "ssh"
      assert event.reason == :not_authorized
    end

    test "events limit" do
      for i <- 1..10 do
        AuditLog.session_established(
          <<i::128>>,
          :crypto.strong_rand_bytes(32),
          {{127, 0, 0, 1}, 1000 + i},
          "web"
        )
      end

      assert length(AuditLog.events(3)) == 3
      assert length(AuditLog.events()) == 10
    end
  end

  describe "stats" do
    test "snapshot returns counter map" do
      snap = Stats.snapshot()
      assert is_map(snap)
      assert Map.has_key?(snap, :active_sessions)
      assert Map.has_key?(snap, :bytes_in)
      assert Map.has_key?(snap, :handshakes_ok)
    end
  end
end
