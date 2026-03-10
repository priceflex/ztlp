#!/usr/bin/env elixir
# ZTLP Pipeline Interop Test Server
#
# Validates ZTLP packet headers from Rust clients:
# - Layer 1: Magic bytes (0x5A37)
# - Layer 2: SessionID lookup
# - Layer 3: HeaderAuthTag (ChaCha20-Poly1305 AEAD over AAD)
#
# Also generates packets for Rust to validate.
#
# Data Header Layout (42 bytes):
#   Magic(2) + Ver|HdrLen(2) + Flags(2) + SessionID(12) + PacketSeq(8) + AuthTag(16)
#   AAD = first 26 bytes
#
# Handshake Header Layout (95 bytes):
#   Magic(2) + Ver|HdrLen(2) + Flags(2) + MsgType(1) + CryptoSuite(2) + KeyID(2)
#   + SessionID(12) + PacketSeq(8) + Timestamp(8) + SrcNodeID(16) + DstSvcID(16)
#   + PolicyTag(4) + ExtLen(2) + PayloadLen(2) + AuthTag(16)
#   AAD = first 79 bytes
#
# Usage: elixir pipeline_server.exs [port]

defmodule PipelineServer do
  import Bitwise
  @magic <<0x5A, 0x37>>

  def start(port \\ 0) do
    {:ok, socket} = :gen_udp.open(port, [:binary, {:active, false}, {:recbuf, 65535}])
    {:ok, actual_port} = :inet.port(socket)
    IO.puts("PIPELINE_SERVER_PORT=#{actual_port}")

    # Generate a shared session key and session ID for testing
    session_id = :crypto.strong_rand_bytes(12)
    auth_key = :crypto.strong_rand_bytes(32)

    state = %{
      socket: socket,
      session_id: session_id,
      auth_key: auth_key,
      known_sessions: MapSet.new([session_id])
    }

    loop(state)
  end

  defp loop(state) do
    case :gen_udp.recv(state.socket, 0, 30_000) do
      {:ok, {ip, port, data}} ->
        state = handle_message(state, ip, port, data)
        loop(state)
      {:error, :timeout} ->
        IO.puts("Pipeline server timeout, exiting")
    end
  end

  defp handle_message(state, ip, port, "PIPELINE_SETUP") do
    IO.puts("[pipe] Setup: session_id=#{Base.encode16(state.session_id, case: :lower)}")
    :gen_udp.send(state.socket, ip, port, state.session_id <> state.auth_key)
    state
  end

  defp handle_message(state, ip, port, "EDGE_SETUP") do
    IO.puts("[pipe] Edge case setup")
    :gen_udp.send(state.socket, ip, port, state.session_id <> state.auth_key)
    state
  end

  defp handle_message(state, ip, port, <<"VALIDATE_DATA_PACKET", packet::binary>>) do
    result = validate_data_packet(state, packet)
    IO.puts("[pipe] Validate data: #{result}")
    :gen_udp.send(state.socket, ip, port, result)
    state
  end

  defp handle_message(state, ip, port, <<"VALIDATE_HS_PACKET", packet::binary>>) do
    result = validate_handshake_packet(state, packet)
    IO.puts("[pipe] Validate hs: #{result}")
    :gen_udp.send(state.socket, ip, port, result)
    state
  end

  defp handle_message(state, ip, port, "GENERATE_DATA_PACKET") do
    IO.puts("[pipe] Generating Elixir data packet")
    packet = generate_data_packet(state)
    :gen_udp.send(state.socket, ip, port, packet)
    state
  end

  defp handle_message(state, ip, port, "GENERATE_HS_PACKET") do
    IO.puts("[pipe] Generating Elixir handshake packet")
    packet = generate_handshake_packet(state)
    :gen_udp.send(state.socket, ip, port, packet)
    state
  end

  defp handle_message(state, ip, port, data) do
    IO.puts("[pipe] Unknown: #{inspect(binary_part(data, 0, min(byte_size(data), 30)))}")
    :gen_udp.send(state.socket, ip, port, "UNKNOWN_CMD")
    state
  end

  # ── Validation ─────────────────────────────────────────────────

  defp validate_data_packet(state, packet) when byte_size(packet) < 42 do
    case packet do
      <<0x5A, 0x37, _::binary>> -> "REJECTED_TRUNCATED"
      _ when byte_size(packet) < 2 -> "REJECTED_TRUNCATED"
      _ -> "REJECTED_MAGIC"
    end
  end

  defp validate_data_packet(state, packet) do
    # Data header: Magic(2) + Ver|HdrLen(2) + Flags(2) + SessionID(12) + Seq(8) + AuthTag(16) = 42
    <<magic::binary-size(2), _ver_hdrlen::binary-size(2), _flags::binary-size(2),
      session_id::binary-size(12), _seq::unsigned-big-64,
      auth_tag::binary-size(16), _payload::binary>> = packet

    # Layer 1: Magic
    if magic != @magic do
      "REJECTED_MAGIC"
    else
      # Layer 2: SessionID
      if not MapSet.member?(state.known_sessions, session_id) do
        "REJECTED_SESSION_UNKNOWN"
      else
        # Layer 3: HeaderAuthTag
        # AAD = first 26 bytes (everything before auth tag)
        aad = binary_part(packet, 0, 26)
        expected_tag = compute_header_auth_tag(state.auth_key, aad)

        if auth_tag == expected_tag do
          "VALID"
        else
          "REJECTED_AUTH_TAG"
        end
      end
    end
  end

  defp validate_handshake_packet(state, packet) when byte_size(packet) < 95 do
    case packet do
      <<0x5A, 0x37, _::binary>> -> "REJECTED_TRUNCATED"
      _ -> "REJECTED_MAGIC"
    end
  end

  defp validate_handshake_packet(state, packet) do
    # HS header: Magic(2) + Ver|HdrLen(2) + Flags(2) + MsgType(1) + CryptoSuite(2) + KeyID(2)
    #            + SessionID(12) + Seq(8) + Timestamp(8) + SrcNodeID(16) + DstSvcID(16)
    #            + PolicyTag(4) + ExtLen(2) + PayloadLen(2) + AuthTag(16) = 95
    <<magic::binary-size(2), _ver_hdrlen::binary-size(2), _flags::binary-size(2),
      _msg_type::8, _crypto_suite::16, _key_id::16,
      session_id::binary-size(12), _seq::unsigned-big-64, _ts::unsigned-big-64,
      _src_node::binary-size(16), _dst_svc::binary-size(16),
      _policy_tag::32, _ext_len::16, _payload_len::16,
      auth_tag::binary-size(16), _rest::binary>> = packet

    # Layer 1: Magic
    if magic != @magic do
      "REJECTED_MAGIC"
    else
      # Layer 2: SessionID
      if not MapSet.member?(state.known_sessions, session_id) do
        "REJECTED_SESSION_UNKNOWN"
      else
        # Layer 3: HeaderAuthTag
        # AAD = first 79 bytes
        aad = binary_part(packet, 0, 79)
        expected_tag = compute_header_auth_tag(state.auth_key, aad)

        if auth_tag == expected_tag do
          "VALID"
        else
          "REJECTED_AUTH_TAG"
        end
      end
    end
  end

  # ── Generation ─────────────────────────────────────────────────

  defp generate_data_packet(state) do
    # Build exactly like the Rust DataHeader::new + serialize
    version = 1
    hdr_len = 11
    ver_hdrlen = bor(bsl(band(version, 0x0F), 12), band(hdr_len, 0x0FFF))

    seq = 42
    flags = 0

    # Header without auth tag (26 bytes)
    header_prefix = <<
      0x5A, 0x37,                          # Magic
      ver_hdrlen::unsigned-big-16,          # Ver|HdrLen
      flags::unsigned-big-16,               # Flags
      state.session_id::binary-size(12),    # SessionID
      seq::unsigned-big-64                  # PacketSeq
    >>

    # Compute auth tag over AAD
    auth_tag = compute_header_auth_tag(state.auth_key, header_prefix)

    # Full packet: header + auth_tag + payload
    header_prefix <> auth_tag <> "elixir_payload"
  end

  defp generate_handshake_packet(state) do
    version = 1
    hdr_len = 24
    ver_hdrlen = bor(bsl(band(version, 0x0F), 12), band(hdr_len, 0x0FFF))

    msg_type = 0      # Data
    crypto_suite = 1
    key_id = 0
    seq = 1
    timestamp = System.system_time(:millisecond)
    src_node = :binary.copy(<<0>>, 16)
    dst_svc = :binary.copy(<<0>>, 16)
    policy_tag = 0
    ext_len = 0
    payload_len = 32
    flags = 0

    # Header without auth tag (79 bytes)
    header_prefix = <<
      0x5A, 0x37,                          # Magic
      ver_hdrlen::unsigned-big-16,          # Ver|HdrLen
      flags::unsigned-big-16,               # Flags
      msg_type::8,                          # MsgType
      crypto_suite::unsigned-big-16,        # CryptoSuite
      key_id::unsigned-big-16,              # KeyID
      state.session_id::binary-size(12),    # SessionID
      seq::unsigned-big-64,                 # PacketSeq
      timestamp::unsigned-big-64,           # Timestamp
      src_node::binary-size(16),            # SrcNodeID
      dst_svc::binary-size(16),             # DstSvcID
      policy_tag::unsigned-big-32,          # PolicyTag
      ext_len::unsigned-big-16,             # ExtLen
      payload_len::unsigned-big-16          # PayloadLen
    >>

    auth_tag = compute_header_auth_tag(state.auth_key, header_prefix)

    header_prefix <> auth_tag <> :binary.copy(<<0xEF>>, payload_len)
  end

  # ── ChaCha20-Poly1305 AEAD HeaderAuthTag ───────────────────────
  #
  # Matches the Rust compute_header_auth_tag exactly:
  # ChaCha20-Poly1305 encrypt with zero nonce, empty plaintext, AAD = header bytes.
  # The resulting ciphertext IS the 16-byte tag.

  defp compute_header_auth_tag(key, aad) when byte_size(key) == 32 do
    nonce = <<0::96>>  # 12-byte zero nonce
    # Encrypt empty plaintext with AAD — returns {<<>>, tag}
    {_ciphertext, tag} = :crypto.crypto_one_time_aead(
      :chacha20_poly1305,
      key,
      nonce,
      <<>>,     # empty plaintext
      aad,      # header bytes as AAD
      16,       # tag length
      true      # encrypt mode
    )
    tag
  end

end

port = case System.argv() do
  [p | _] -> String.to_integer(p)
  [] -> 0
end

PipelineServer.start(port)
