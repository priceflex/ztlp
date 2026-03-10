defmodule ZtlpGateway.PacketTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.Packet

  describe "valid_magic?/1" do
    test "accepts ZTLP magic" do
      assert Packet.valid_magic?(<<0x5A, 0x37, 0, 0, 0>>)
    end

    test "rejects wrong magic" do
      refute Packet.valid_magic?(<<0xFF, 0xFF, 0, 0, 0>>)
    end

    test "rejects empty" do
      refute Packet.valid_magic?(<<>>)
    end

    test "rejects single byte" do
      refute Packet.valid_magic?(<<0x5A>>)
    end
  end

  describe "packet_type/1" do
    test "identifies data packet (HdrLen=11)" do
      # Version=1, HdrLen=11 → <<0x10, 0x0B>>
      packet = <<0x5A, 0x37, 0x10::4, 11::12, 0::128, 0::336>>
      assert Packet.packet_type(packet) == :data
    end

    test "identifies handshake packet (HdrLen=24)" do
      packet = <<0x5A, 0x37, 0x10::4, 24::12, 0::128, 0::600>>
      assert Packet.packet_type(packet) == :handshake
    end

    test "returns :unknown for other HdrLen" do
      packet = <<0x5A, 0x37, 0x10::4, 99::12, 0::128>>
      assert Packet.packet_type(packet) == :unknown
    end

    test "returns :unknown for too-short packet" do
      assert Packet.packet_type(<<0x5A>>) == :unknown
    end
  end

  describe "hello?/1" do
    test "recognizes a HELLO packet" do
      hello = Packet.build_hello(<<>>)
      assert Packet.hello?(hello)
    end

    test "rejects non-HELLO handshake" do
      # HELLO_ACK with non-zero SessionID
      sid = :crypto.strong_rand_bytes(16)
      pkt = Packet.build_hello_ack(sid, <<>>)
      refute Packet.hello?(pkt)
    end

    test "rejects data packet" do
      sid = :crypto.strong_rand_bytes(16)
      auth = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_data(sid, 1, auth, "payload")
      refute Packet.hello?(pkt)
    end
  end

  describe "extract_session_id/1" do
    test "extracts from a data packet" do
      sid = :crypto.strong_rand_bytes(16)
      auth = :crypto.strong_rand_bytes(12)
      pkt = Packet.build_data(sid, 42, auth, "test")

      assert {:ok, ^sid} = Packet.extract_session_id(pkt)
    end

    test "extracts zero SessionID from HELLO" do
      hello = Packet.build_hello("noise_payload")
      {:ok, sid} = Packet.extract_session_id(hello)
      assert sid == Packet.zero_session_id()
    end

    test "error on too-short packet" do
      assert :error = Packet.extract_session_id(<<0x5A, 0x37, 0, 0>>)
    end
  end

  describe "data packet round-trip" do
    test "serialize and parse" do
      sid = :crypto.strong_rand_bytes(16)
      auth = :crypto.strong_rand_bytes(12)
      payload = "encrypted data here"

      raw = Packet.serialize_data(sid, 12345, 0x01, 0x10, auth, payload)
      {:ok, parsed} = Packet.parse(raw)

      assert parsed.type == :data
      assert parsed.session_id == sid
      assert parsed.sequence == 12345
      assert parsed.flags == 0x01
      assert parsed.payload_type == 0x10
      assert parsed.header_auth_tag == auth
      assert parsed.payload == payload
    end

    test "max sequence number" do
      sid = :crypto.strong_rand_bytes(16)
      auth = :crypto.strong_rand_bytes(12)
      max_seq = 0xFFFFFFFFFFFFFFFF

      raw = Packet.serialize_data(sid, max_seq, 0, 0, auth, "")
      {:ok, parsed} = Packet.parse(raw)
      assert parsed.sequence == max_seq
    end

    test "empty payload" do
      sid = :crypto.strong_rand_bytes(16)
      auth = :crypto.strong_rand_bytes(12)

      raw = Packet.serialize_data(sid, 0, 0, 0, auth, <<>>)
      {:ok, parsed} = Packet.parse(raw)
      assert parsed.payload == <<>>
    end
  end

  describe "handshake packet round-trip" do
    test "serialize and parse HELLO" do
      payload = "ephemeral_key_bytes"
      raw = Packet.build_hello(payload)
      {:ok, parsed} = Packet.parse(raw)

      assert parsed.type == :handshake
      assert parsed.msg_type == :hello
      assert parsed.session_id == Packet.zero_session_id()
      assert parsed.payload == payload
    end

    test "serialize and parse HELLO_ACK" do
      sid = :crypto.strong_rand_bytes(16)
      payload = "response_bytes"
      raw = Packet.build_hello_ack(sid, payload)
      {:ok, parsed} = Packet.parse(raw)

      assert parsed.type == :handshake
      assert parsed.msg_type == :hello_ack
      assert parsed.session_id == sid
      assert parsed.payload == payload
    end

    test "handshake with large payload" do
      sid = :crypto.strong_rand_bytes(16)
      payload = :crypto.strong_rand_bytes(1024)
      auth_tag = :crypto.strong_rand_bytes(64)

      raw = Packet.serialize_handshake(sid, :handshake, auth_tag, payload)
      {:ok, parsed} = Packet.parse(raw)

      assert parsed.type == :handshake
      assert parsed.msg_type == :handshake
      assert parsed.payload == payload
    end
  end

  describe "parse errors" do
    test "bad magic" do
      assert {:error, :bad_magic} = Packet.parse(<<0xFF, 0xFF, 0, 0, 0, 0>>)
    end

    test "truncated data header" do
      # Magic + version/hdrlen for data, but too short for full header
      raw = <<0x5A, 0x37, 0x10::4, 11::12, 0::64>>
      assert {:error, :truncated_data} = Packet.parse(raw)
    end

    test "truncated handshake header" do
      raw = <<0x5A, 0x37, 0x10::4, 24::12, 0::64>>
      assert {:error, :truncated_handshake} = Packet.parse(raw)
    end

    test "unknown HdrLen" do
      raw = <<0x5A, 0x37, 0x10::4, 99::12, 0::256>>
      assert {:error, :unknown_hdr_len} = Packet.parse(raw)
    end
  end
end
