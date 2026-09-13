defmodule ZtlpGateway.Quic.HandshakeTest do
  use ExUnit.Case, async: true

  @moduledoc """
  Task Q3 (ztlp-cloud-demo-plan.md, Session 3): the stream-0 handshake state
  machine the QUIC gateway runs against a Rust client
  (`proto/src/quic_transport.rs::run_initiator_handshake`):

      C->S  service_hash        16 raw bytes, NOT framed
      C->S  frame(msg1)         Noise XX msg1 = e(32) || payload(16 = client NodeID)
      S->C  session_id          12 raw bytes, NOT framed, random
      S->C  frame(msg2)         e(32) || enc s(48) || enc payload(16 NodeID + 16 tag)
      C->S  frame(msg3)         enc s(48) || enc payload(16 NodeID + 16 tag)

  Noise_XX_25519_ChaChaPoly_BLAKE2s, EMPTY prologue. Every Noise payload is
  the sender's 16-byte NodeID (see `proto/src/handshake.rs::write_message`,
  SAST fne-nxah) — the responder MUST mix that 48-byte msg1 into `h`
  exactly like the Rust side does, or msg2/msg3 AEAD tags won't verify (R2).

  The initiator in these tests is the existing `ZtlpGateway.Handshake`
  initiator, driven with the same 16-byte NodeID payloads the Rust client
  uses, so both directions of the NodeID prefix are exercised.
  """

  alias ZtlpGateway.Quic.Frame
  alias ZtlpGateway.Quic.Handshake, as: QH
  alias ZtlpGateway.Handshake, as: Noise
  alias ZtlpGateway.Crypto

  @fixture Path.expand("../../fixtures/quic_handshake_vector.json", __DIR__)
  @external_resource @fixture
  fixture = File.read!(@fixture)
  fetch_int = fn key ->
    [_, v] = Regex.run(~r/"#{key}":\s*(\d+)/, fixture)
    String.to_integer(v)
  end
  @svc_len fetch_int.("service_hash_len_bytes")
  @sid_len fetch_int.("session_id_len_bytes")

  defp keypair, do: Crypto.generate_keypair()
  defp node_id, do: :crypto.strong_rand_bytes(16)

  # Drive a full handshake from the client side, feeding the responder
  # state machine byte-chunks the way a QUIC stream would deliver them.
  # Returns {responder_result, initiator_state_after_msg2, client_node_id}.
  defp run_client(resp, svc_hash, chunker \\ &[&1]) do
    {c_pub, c_priv} = keypair()
    c_nid = node_id()

    init = Noise.init_initiator(c_pub, c_priv)
    {init, msg1} = Noise.create_msg1(init, c_nid)

    wire1 = svc_hash <> Frame.encode(msg1)

    {resp, out1} = feed(resp, chunker.(wire1))

    # Server sent: 12 raw session_id bytes || frame(msg2)
    <<sid::binary-size(@sid_len), framed_msg2::binary>> = out1
    {:ok, msg2, <<>>} = Frame.decode(framed_msg2)
    {init, server_nid} = Noise.process_msg2(init, msg2)

    {init, msg3} = Noise.create_msg3(init, c_nid)
    {resp, out2} = feed(resp, chunker.(Frame.encode(msg3)))
    assert out2 == <<>>

    {resp, %{sid: sid, init: init, c_pub: c_pub, c_nid: c_nid, server_nid: server_nid}}
  end

  defp feed(resp, chunks) do
    Enum.reduce(chunks, {resp, <<>>}, fn chunk, {resp, acc} ->
      case QH.step(resp, chunk) do
        {:continue, resp, out} -> {resp, acc <> out}
        {:done, result, out} -> {result, acc <> out}
        {:error, _} = err -> {err, acc}
      end
    end)
  end

  defp split_every(bin, n) do
    for <<chunk::binary-size(n) <- bin>>, do: chunk
  end

  defp chunk_bytes(bin, n) do
    full = split_every(bin, n)
    consumed = length(full) * n
    rest = binary_part(bin, consumed, byte_size(bin) - consumed)
    if rest == <<>>, do: full, else: full ++ [rest]
  end

  setup do
    {s_pub, s_priv} = keypair()
    s_nid = node_id()
    svc = :crypto.strong_rand_bytes(@svc_len)
    %{resp: QH.new(s_pub, s_priv, s_nid), s_pub: s_pub, s_nid: s_nid, svc: svc}
  end

  test "fixture contract: 16-byte service hash, 12-byte session id" do
    assert @svc_len == 16
    assert @sid_len == 12
  end

  # R2: the base Noise module must carry a cleartext msg1 payload (the Rust
  # client's 16-byte NodeID) and MixHash it, or msg2's tag is computed over
  # a different `h` than the client's and the client rejects msg2.
  test "ZtlpGateway.Handshake: msg1 cleartext payload round-trips and is mixed into h" do
    {c_pub, c_priv} = keypair()
    {s_pub, s_priv} = keypair()
    c_nid = node_id()

    init = Noise.init_initiator(c_pub, c_priv)
    {init, msg1} = Noise.create_msg1(init, c_nid)
    assert byte_size(msg1) == 32 + 16

    resp = Noise.init_responder(s_pub, s_priv)
    {resp, got} = Noise.handle_msg1(resp, msg1)
    assert got == c_nid
    assert resp.h == init.h

    {_resp, msg2} = Noise.create_msg2(resp, node_id())
    assert {_init, _payload} = Noise.process_msg2(init, msg2)
  end

  test "full handshake in one chunk yields service_hash, session_id, client static key and NodeID",
       %{resp: resp, svc: svc} do
    {result, c} = run_client(resp, svc)

    assert %{service_hash: ^svc, session_id: sid, client_static_pub: c_pub, client_node_id: c_nid} =
             result

    assert byte_size(sid) == @sid_len
    assert sid == c.sid
    assert c_pub == c.c_pub
    assert c_nid == c.c_nid
  end

  test "responder's NodeID reaches the client inside the Noise payload",
       %{resp: resp, svc: svc, s_nid: s_nid} do
    {_result, c} = run_client(resp, svc)
    assert c.server_nid == s_nid
  end

  test "responder and initiator derive matching transport keys (Noise math agrees end to end)",
       %{resp: resp, svc: svc} do
    {result, c} = run_client(resp, svc)
    {:ok, init_keys} = Noise.split(c.init)
    assert result.transport_keys == init_keys
  end

  test "session_id is random per handshake", %{resp: resp, svc: svc} do
    {r1, _} = run_client(resp, svc)
    {r2, _} = run_client(resp, svc)
    assert r1.session_id != r2.session_id
  end

  test "handshake reassembles when the stream is delivered one byte at a time",
       %{resp: resp, svc: svc} do
    {result, c} = run_client(resp, svc, &chunk_bytes(&1, 1))
    assert result.client_static_pub == c.c_pub
    assert result.session_id == c.sid
  end

  test "handshake works when the client's bytes arrive in odd-sized chunks",
       %{resp: resp, svc: svc} do
    for n <- [3, 7, 17, 47] do
      {result, c} = run_client(resp, svc, &chunk_bytes(&1, n))
      assert result.client_static_pub == c.c_pub, "chunk size #{n}"
    end
  end

  test "nothing is emitted before the full service_hash + msg1 frame has arrived",
       %{resp: resp, svc: svc} do
    assert {:continue, resp, <<>>} = QH.step(resp, svc)
    assert {:continue, _resp, <<>>} = QH.step(resp, <<0x5A, 0, 48>>)
  end

  test "bad frame magic on stream 0 is a handshake error", %{resp: resp, svc: svc} do
    assert {:error, :bad_magic} = QH.step(resp, svc <> <<0x00, 0, 48>>)
  end

  test "msg1 without the 16-byte NodeID payload is rejected (Rust client always sends it)",
       %{resp: resp, svc: svc} do
    {c_pub, c_priv} = keypair()
    {_init, msg1_bare} = Noise.create_msg1(Noise.init_initiator(c_pub, c_priv))
    assert byte_size(msg1_bare) == 32
    assert {:error, :msg1_payload_too_short} = QH.step(resp, svc <> Frame.encode(msg1_bare))
  end

  test "a tampered msg3 fails authentication instead of completing",
       %{resp: resp, svc: svc} do
    {c_pub, c_priv} = keypair()
    c_nid = node_id()
    init = Noise.init_initiator(c_pub, c_priv)
    {init, msg1} = Noise.create_msg1(init, c_nid)
    {:continue, resp, out1} = QH.step(resp, svc <> Frame.encode(msg1))
    <<_sid::binary-size(@sid_len), framed_msg2::binary>> = out1
    {:ok, msg2, <<>>} = Frame.decode(framed_msg2)
    {init, _} = Noise.process_msg2(init, msg2)
    {_init, msg3} = Noise.create_msg3(init, c_nid)

    <<first, rest::binary>> = msg3
    tampered = <<Bitwise.bxor(first, 0xFF), rest::binary>>
    assert {:error, _reason} = QH.step(resp, Frame.encode(tampered))
  end

  test "static key persistence: load_or_create_static_key writes a hex seed once and reuses it" do
    dir = Path.join(System.tmp_dir!(), "ztlp-quic-hs-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    path = Path.join(dir, "quic-static.key")

    refute File.exists?(path)
    {pub1, priv1} = QH.load_or_create_static_key(path)
    assert File.exists?(path)
    assert byte_size(pub1) == 32 and byte_size(priv1) == 32
    assert {:ok, hex} = File.read(path)
    assert String.trim(hex) |> String.length() == 64
    assert Base.decode16!(String.trim(hex), case: :mixed) == priv1

    {pub2, priv2} = QH.load_or_create_static_key(path)
    assert {pub2, priv2} == {pub1, priv1}

    File.rm_rf!(dir)
  end
end
