defmodule ZtlpNs.SvcQuicFingerprintTest do
  @moduledoc """
  NS-anchored gateway trust, task 3.1: a gateway's SVC registration may
  carry `quic_cert_sha256` (hex SHA-256 of its QUIC leaf cert). The NS must
  store it unchanged, add `registered_by`, re-sign the record with its own
  registration key, and serve it back so clients can verify the field
  against the NS key. Drives the real UDP server end to end.
  """

  use ExUnit.Case, async: false

  alias ZtlpNs.{Cbor, Crypto, RateLimiter, Record, RegistrationAuth, Server}

  setup do
    RateLimiter.reset()
    {:ok, pfx: Base.encode16(:crypto.strong_rand_bytes(4), case: :lower)}
  end

  defp udp(packet) do
    {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}])
    :ok = :gen_udp.send(sock, {127, 0, 0, 1}, Server.port(), packet)
    {:ok, {_ip, _port, reply}} = :gen_udp.recv(sock, 0, 5000)
    :gen_udp.close(sock)
    reply
  end

  # Signed v2 registration (0x09), exactly what `ztlp listen` sends.
  defp register(name, type, data, pub, priv) do
    data_bin = Cbor.encode(data)
    sig = Crypto.sign(RegistrationAuth.build_canonical(name, type, data_bin), priv)
    type_byte = Record.type_to_byte(type)

    udp(
      <<0x09, byte_size(name)::16, name::binary, type_byte::8, byte_size(data_bin)::16,
        data_bin::binary, byte_size(sig)::16, sig::binary, byte_size(pub)::16, pub::binary>>
    )
  end

  # Padded 0x01 query, as the Rust client sends it (256 bytes).
  defp query(name, type) do
    q = <<0x01, byte_size(name)::16, name::binary, Record.type_to_byte(type)::8>>
    udp(q <> :binary.copy(<<0>>, max(0, 256 - byte_size(q))))
  end

  test "quic_cert_sha256 in an SVC registration is served back, NS-signed", %{pfx: pfx} do
    name = "gw-#{pfx}.fp.ztlp"
    {pub, priv} = Crypto.generate_keypair()
    pub_hex = Base.encode16(pub, case: :lower)
    node_hex = Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
    fp = Base.encode16(:crypto.hash(:sha256, "leaf-#{pfx}"), case: :lower)

    key_data = %{"node_id" => node_hex, "public_key" => pub_hex, "algorithm" => "Ed25519"}
    assert register(name, :key, key_data, pub, priv) == <<0x06>>

    svc_data = %{
      "address" => "10.42.42.112:23097",
      "node_id" => node_hex,
      "zone" => "fp.ztlp",
      "quic_cert_sha256" => fp
    }

    assert register(name, :svc, svc_data, pub, priv) == <<0x06>>

    assert <<0x02, encoded::binary>> = query(name, :svc)
    assert {:ok, rec} = Record.decode(encoded)
    assert rec.type == :svc
    assert rec.data["quic_cert_sha256"] == fp
    assert rec.data["address"] == "10.42.42.112:23097"
    assert rec.data["registered_by"] == pub_hex
    # Re-signed by the NS, not by the gateway: clients trust the NS key.
    assert Record.verify(rec)
    refute rec.signer_public_key == pub
  end

  test "the served SVC record fits the 2 KB reply budget of a padded query", %{pfx: pfx} do
    name = "gw2-#{pfx}.fp.ztlp"
    {pub, priv} = Crypto.generate_keypair()
    pub_hex = Base.encode16(pub, case: :lower)
    node_hex = Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

    assert register(name, :key, %{"node_id" => node_hex, "public_key" => pub_hex}, pub, priv) ==
             <<0x06>>

    svc = %{
      "address" => "10.42.42.112:23097",
      "addresses" => Enum.map_join(1..6, ",", &"10.0.0.#{&1}:23097"),
      "node_id" => node_hex,
      "zone" => "fp.ztlp",
      "quic_cert_sha256" => String.duplicate("ab", 32)
    }

    assert register(name, :svc, svc, pub, priv) == <<0x06>>
    # Not truncated: <<0x02, record>> (a truncated reply is <<0x02, 0x01, …>>
    # and would fail Record.decode).
    assert <<0x02, encoded::binary>> = query(name, :svc)
    assert {:ok, rec} = Record.decode(encoded)
    assert Record.verify(rec)
  end
end
