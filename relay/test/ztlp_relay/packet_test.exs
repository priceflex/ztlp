defmodule ZtlpRelay.PacketTest do
  use ExUnit.Case, async: true
  use Bitwise

  alias ZtlpRelay.Packet

  @magic 0x5A37
  @version 1
  @handshake_hdr_len 24
  @data_hdr_len 11

  describe "parse/1 handshake header" do
    test "parses a valid HELLO packet" do
      session_id = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_handshake(:hello, session_id, packet_seq: 1, timestamp: 1_000_000)
      raw = Packet.serialize_handshake(pkt)

      assert {:ok, parsed} = Packet.parse(raw)
      assert parsed.type == :handshake
      assert parsed.magic == @magic
      assert parsed.version == @version
      assert parsed.hdr_len == @handshake_hdr_len
      assert parsed.msg_type == :hello
      assert parsed.session_id == session_id
      assert parsed.packet_seq == 1
      assert parsed.timestamp == 1_000_000
    end

    test "parses all message types" do
      session_id = :crypto.strong_rand_bytes(12)

      for msg_type <- [:data, :hello, :hello_ack, :rekey, :close, :error, :ping, :pong] do
        pkt = Packet.build_handshake(msg_type, session_id)
        raw = Packet.serialize_handshake(pkt)
        assert {:ok, parsed} = Packet.parse(raw)
        assert parsed.msg_type == msg_type
      end
    end

    test "preserves all fields through serialize/parse roundtrip" do
      session_id = :crypto.strong_rand_bytes(12)
      src_node_id = :crypto.strong_rand_bytes(16)
      dst_svc_id = :crypto.strong_rand_bytes(16)
      auth_tag = :crypto.strong_rand_bytes(16)

      pkt = Packet.build_handshake(:rekey, session_id,
        flags: 0x0003,
        crypto_suite: 0x0002,
        key_id: 42,
        packet_seq: 9999,
        timestamp: 123_456_789,
        src_node_id: src_node_id,
        dst_svc_id: dst_svc_id,
        policy_tag: 0xDEADBEEF,
        ext_len: 0,
        payload_len: 0,
        header_auth_tag: auth_tag
      )

      raw = Packet.serialize(pkt)
      assert {:ok, parsed} = Packet.parse(raw)

      assert parsed.flags == 0x0003
      assert parsed.crypto_suite == 0x0002
      assert parsed.key_id == 42
      assert parsed.packet_seq == 9999
      assert parsed.timestamp == 123_456_789
      assert parsed.src_node_id == src_node_id
      assert parsed.dst_svc_id == dst_svc_id
      assert parsed.policy_tag == 0xDEADBEEF
      assert parsed.header_auth_tag == auth_tag
    end

    test "serialized handshake header is exactly 95 bytes" do
      pkt = Packet.build_handshake(:hello, <<0::96>>)
      raw = Packet.serialize_handshake(pkt)
      assert byte_size(raw) == 95
    end

    test "preserves payload through roundtrip" do
      session_id = :crypto.strong_rand_bytes(12)
      payload = "hello world"
      pkt = Packet.build_handshake(:data, session_id, payload: payload, payload_len: byte_size(payload))
      raw = Packet.serialize(pkt)
      assert {:ok, parsed} = Packet.parse(raw)
      assert parsed.payload == payload
    end
  end

  describe "parse/1 compact data header" do
    test "parses a valid data packet" do
      session_id = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_data(session_id, 42)
      raw = Packet.serialize_data(pkt)

      assert {:ok, parsed} = Packet.parse(raw)
      assert parsed.type == :data_compact
      assert parsed.magic == @magic
      assert parsed.version == @version
      assert parsed.hdr_len == @data_hdr_len
      assert parsed.session_id == session_id
      assert parsed.packet_seq == 42
    end

    test "serialized data header is exactly 42 bytes" do
      pkt = Packet.build_data(<<0::96>>, 0)
      raw = Packet.serialize_data(pkt)
      assert byte_size(raw) == 42
    end

    test "preserves fields through roundtrip" do
      session_id = :crypto.strong_rand_bytes(12)
      auth_tag = :crypto.strong_rand_bytes(16)

      pkt = Packet.build_data(session_id, 12345,
        flags: 0x0010,
        header_auth_tag: auth_tag
      )

      raw = Packet.serialize(pkt)
      assert {:ok, parsed} = Packet.parse(raw)
      assert parsed.flags == 0x0010
      assert parsed.packet_seq == 12345
      assert parsed.header_auth_tag == auth_tag
    end

    test "preserves payload through roundtrip" do
      session_id = :crypto.strong_rand_bytes(12)
      payload = :crypto.strong_rand_bytes(100)
      pkt = Packet.build_data(session_id, 0, payload: payload)
      raw = Packet.serialize(pkt)
      assert {:ok, parsed} = Packet.parse(raw)
      assert parsed.payload == payload
    end
  end

  describe "parse/1 error handling" do
    test "rejects empty data" do
      assert {:error, :buffer_too_short} = Packet.parse(<<>>)
    end

    test "rejects single byte" do
      assert {:error, :buffer_too_short} = Packet.parse(<<0x5A>>)
    end

    test "rejects invalid magic" do
      raw = <<0xDE, 0xAD>> <> :binary.copy(<<0>>, 93)
      assert {:error, :invalid_magic} = Packet.parse(raw)
    end

    test "rejects unsupported version" do
      # Version 2, handshake hdr_len
      ver_hdrlen = (2 <<< 12) ||| @handshake_hdr_len
      raw = <<@magic::16, ver_hdrlen::16>> <> :binary.copy(<<0>>, 91)
      assert {:error, :unsupported_version} = Packet.parse(raw)
    end

    test "rejects unknown header type" do
      # Valid magic and version, but hdr_len = 99 (unknown)
      ver_hdrlen = (@version <<< 12) ||| 99
      raw = <<@magic::16, ver_hdrlen::16>> <> :binary.copy(<<0>>, 91)
      assert {:error, :unknown_header_type} = Packet.parse(raw)
    end

    test "rejects truncated handshake header" do
      # Valid magic, version, handshake hdr_len, but only 50 bytes total
      ver_hdrlen = (@version <<< 12) ||| @handshake_hdr_len
      raw = <<@magic::16, ver_hdrlen::16>> <> :binary.copy(<<0>>, 46)
      assert {:error, :buffer_too_short} = Packet.parse(raw)
    end

    test "rejects truncated data header" do
      # Valid magic, version, data hdr_len, but only 20 bytes total
      ver_hdrlen = (@version <<< 12) ||| @data_hdr_len
      raw = <<@magic::16, ver_hdrlen::16>> <> :binary.copy(<<0>>, 16)
      assert {:error, :buffer_too_short} = Packet.parse(raw)
    end
  end

  describe "helper functions" do
    test "valid_magic?/1" do
      assert Packet.valid_magic?(<<@magic::16, 0::8>>)
      refute Packet.valid_magic?(<<0xDE, 0xAD>>)
      refute Packet.valid_magic?(<<>>)
    end

    test "hello?/1" do
      pkt = Packet.build_handshake(:hello, <<0::96>>)
      raw = Packet.serialize(pkt)
      assert Packet.hello?(raw)

      pkt2 = Packet.build_handshake(:data, <<0::96>>)
      raw2 = Packet.serialize(pkt2)
      refute Packet.hello?(raw2)
    end

    test "hello_ack?/1" do
      pkt = Packet.build_handshake(:hello_ack, <<0::96>>)
      raw = Packet.serialize(pkt)
      assert Packet.hello_ack?(raw)

      pkt2 = Packet.build_handshake(:hello, <<0::96>>)
      raw2 = Packet.serialize(pkt2)
      refute Packet.hello_ack?(raw2)
    end

    test "handshake?/1" do
      pkt = Packet.build_handshake(:hello, <<0::96>>)
      raw = Packet.serialize(pkt)
      assert Packet.handshake?(raw)

      data_pkt = Packet.build_data(<<0::96>>, 0)
      data_raw = Packet.serialize(data_pkt)
      refute Packet.handshake?(data_raw)
    end

    test "extract_session_id/1 from handshake" do
      session_id = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_handshake(:data, session_id)
      raw = Packet.serialize(pkt)
      assert {:ok, ^session_id} = Packet.extract_session_id(raw)
    end

    test "extract_session_id/1 from data" do
      session_id = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_data(session_id, 0)
      raw = Packet.serialize(pkt)
      assert {:ok, ^session_id} = Packet.extract_session_id(raw)
    end

    test "extract_aad/1 and extract_auth_tag/1 for handshake" do
      auth_tag = :crypto.strong_rand_bytes(16)
      pkt = Packet.build_handshake(:data, <<0::96>>, header_auth_tag: auth_tag)
      raw = Packet.serialize(pkt)

      assert {:ok, aad} = Packet.extract_aad(raw)
      assert byte_size(aad) == 95 - 16

      assert {:ok, ^auth_tag} = Packet.extract_auth_tag(raw)
    end

    test "extract_aad/1 and extract_auth_tag/1 for data" do
      auth_tag = :crypto.strong_rand_bytes(16)
      pkt = Packet.build_data(<<0::96>>, 0, header_auth_tag: auth_tag)
      raw = Packet.serialize(pkt)

      assert {:ok, aad} = Packet.extract_aad(raw)
      assert byte_size(aad) == 42 - 16

      assert {:ok, ^auth_tag} = Packet.extract_auth_tag(raw)
    end
  end
end
