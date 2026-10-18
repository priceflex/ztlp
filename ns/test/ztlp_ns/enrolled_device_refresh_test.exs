defmodule ZtlpNs.EnrolledDeviceRefreshTest do
  @moduledoc """
  Sliding one-year lifetime for enrolled client devices (v0.35.19).

  An enrolled device's KEY record carries the X25519 tunnel key in
  `public_key` (the gateway resolves `device-name` from it) and, since
  v0.35.19, the device's Ed25519 `signing_public_key`. The agent checks in
  hourly by re-registering that KEY record, signed with the signing key.
  Each accepted check-in restarts the one-year window. A device that has
  been off for longer than a year has an expired record and must re-enroll.

  These tests drive the real UDP server (signed v2 0x09 registration).
  """

  use ExUnit.Case, async: false

  alias ZtlpNs.{Cbor, Crypto, Enrollment, RateLimiter, Record, RecordDefaults, RegistrationAuth,
                Server, Store}

  @zone "fleet.acme.ztlp"
  @year 31_536_000

  setup do
    secret = :crypto.strong_rand_bytes(32)
    Enrollment.set_zone_secret(secret)
    Enrollment.init()
    Enrollment.reset()
    RateLimiter.reset()
    System.delete_env("ZTLP_NS_ENROLLED_DEVICE_TTL")
    pfx = Base.encode16(:crypto.strong_rand_bytes(4), case: :lower)
    {:ok, secret: secret, pfx: pfx}
  end

  # ── helpers ────────────────────────────────────────────────────────

  defp enc(s), do: <<byte_size(s)::16, s::binary>>

  defp token(secret) do
    data =
      <<0x01, 0x00>> <>
        enc(@zone) <> enc("127.0.0.1:23096") <> <<1::8>> <> enc("127.0.0.1:23095") <>
        <<0::16, System.system_time(:second) + 3600::64>> <> :crypto.strong_rand_bytes(16)

    data <> Enrollment.hmac_blake2s(secret, data)
  end

  # Enroll a device the way v0.35.19 clients do (with the signing-key
  # extension). Returns the device's keys.
  defp enroll(secret, name, opts \\ []) do
    tunnel_pk = :crypto.strong_rand_bytes(32)
    node_id = :crypto.strong_rand_bytes(16)
    {spub, spriv} = Crypto.generate_keypair()

    ext =
      if Keyword.get(opts, :legacy, false),
        do: <<>>,
        else: <<byte_size(spub)::16, spub::binary>>

    tok = token(secret)

    body =
      <<byte_size(tok)::16, tok::binary, tunnel_pk::binary, node_id::binary,
        byte_size(name)::16, name::binary, 0::16>> <> ext

    assert <<0x08, 0x00, _::binary>> = Enrollment.process_enroll(body)

    %{
      name: name,
      tunnel_hex: Base.encode16(tunnel_pk, case: :lower),
      node_hex: Base.encode16(node_id, case: :lower),
      spub: spub,
      spriv: spriv,
      spub_hex: Base.encode16(spub, case: :lower)
    }
  end

  defp refresh_data(dev, overrides \\ %{}) do
    Map.merge(
      %{
        "algorithm" => "Ed25519",
        "node_id" => dev.node_hex,
        "public_key" => dev.tunnel_hex,
        "signing_public_key" => dev.spub_hex
      },
      overrides
    )
  end

  # Signed v2 registration (0x09 ... sig, pubkey), exactly what the agent sends.
  defp send_registration(name, data, signer_pub, signer_priv) do
    data_bin = Cbor.encode(data)
    sig = Crypto.sign(RegistrationAuth.build_canonical(name, :key, data_bin), signer_priv)

    packet =
      <<0x09, byte_size(name)::16, name::binary, 1::8, byte_size(data_bin)::16, data_bin::binary,
        byte_size(sig)::16, sig::binary, byte_size(signer_pub)::16, signer_pub::binary>>

    {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}])
    :ok = :gen_udp.send(sock, {127, 0, 0, 1}, Server.port(), packet)
    {:ok, {_ip, _port, reply}} = :gen_udp.recv(sock, 0, 5000)
    :gen_udp.close(sock)
    reply
  end

  # Move a stored record's creation time into the past (simulates time
  # passing without a check-in).
  defp backdate(name, seconds) do
    {:ok, rec} = Store.lookup(name, :key)
    canonical = ZtlpNs.NameValidator.canonicalize(name)
    old = %{rec | created_at: rec.created_at - seconds}
    :mnesia.dirty_write({:ztlp_ns_records, {canonical, :key}, old})
    old
  end

  defp dev_name(pfx, label), do: "#{pfx}-#{label}.#{@zone}"

  # ── tests ──────────────────────────────────────────────────────────

  test "hourly check-in signed by the enrolled signing key restarts the one-year window",
       %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "laptop"))
    old = backdate(dev.name, 200 * 86_400)

    assert send_registration(dev.name, refresh_data(dev), dev.spub, dev.spriv) == <<0x06>>

    {:ok, rec} = Store.lookup(dev.name, :key)
    assert rec.created_at > old.created_at
    assert rec.created_at >= System.system_time(:second) - 5
    assert rec.ttl == @year
    # The gateway's pubkey -> device-name lookup keeps working.
    assert rec.data["public_key"] == dev.tunnel_hex
    assert rec.data["signing_public_key"] == dev.spub_hex
    assert {:ok, %Record{name: name}} = Store.lookup_by_pubkey(dev.tunnel_hex)
    assert name == dev.name
  end

  test "check-in honours the ZTLP_NS_ENROLLED_DEVICE_TTL override", %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "ovr"))
    System.put_env("ZTLP_NS_ENROLLED_DEVICE_TTL", "7200")
    on_exit(fn -> System.delete_env("ZTLP_NS_ENROLLED_DEVICE_TTL") end)

    assert send_registration(dev.name, refresh_data(dev), dev.spub, dev.spriv) == <<0x06>>
    {:ok, rec} = Store.lookup(dev.name, :key)
    assert rec.ttl == 7200
  end

  test "a check-in cannot change the tunnel key", %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "swap"))
    evil = Base.encode16(:crypto.strong_rand_bytes(32), case: :lower)

    assert <<0xFF, _::binary>> =
             send_registration(dev.name, refresh_data(dev, %{"public_key" => evil}), dev.spub,
               dev.spriv)

    {:ok, rec} = Store.lookup(dev.name, :key)
    assert rec.data["public_key"] == dev.tunnel_hex
  end

  test "a check-in cannot change the node_id", %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "nid"))
    other = Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)

    assert <<0xFF, _::binary>> =
             send_registration(dev.name, refresh_data(dev, %{"node_id" => other}), dev.spub,
               dev.spriv)
  end

  test "a check-in cannot rotate the signing key", %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "rot"))
    {npub, _} = Crypto.generate_keypair()

    assert <<0xFF, _::binary>> =
             send_registration(
               dev.name,
               refresh_data(dev, %{"signing_public_key" => Base.encode16(npub, case: :lower)}),
               dev.spub,
               dev.spriv
             )
  end

  test "a different key cannot refresh someone else's device", %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "victim"))
    {apub, apriv} = Crypto.generate_keypair()
    old = backdate(dev.name, 1000)

    data = refresh_data(dev, %{"signing_public_key" => Base.encode16(apub, case: :lower)})
    assert <<0xFF, _::binary>> = send_registration(dev.name, data, apub, apriv)

    {:ok, rec} = Store.lookup(dev.name, :key)
    assert rec.created_at == old.created_at
  end

  test "a legacy enrollment (no signing key on record) cannot be refreshed", %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "old"), legacy: true)

    assert <<0xFF, _::binary>> =
             send_registration(dev.name, refresh_data(dev), dev.spub, dev.spriv)
  end

  test "a device left off for more than a year has expired and must re-enroll",
       %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "shelf"))
    backdate(dev.name, @year + 60)

    # Gone from the NS: the gateway cannot resolve it any more.
    assert :not_found = Store.lookup(dev.name, :key)
    # Its check-in is refused (no record to refresh) ...
    assert <<0xFF, _::binary>> =
             send_registration(dev.name, refresh_data(dev), dev.spub, dev.spriv)

    assert :not_found = Store.lookup(dev.name, :key)
    # ... and a fresh enrollment under the same name succeeds.
    dev2 = enroll(s, dev.name)
    {:ok, rec} = Store.lookup(dev.name, :key)
    assert rec.data["public_key"] == dev2.tunnel_hex
    assert rec.ttl == @year
  end

  test "a record still inside its year is refreshed even after 364 days off",
       %{secret: s, pfx: p} do
    dev = enroll(s, dev_name(p, "longnap"))
    backdate(dev.name, 364 * 86_400)
    assert {:ok, _} = Store.lookup(dev.name, :key)

    assert send_registration(dev.name, refresh_data(dev), dev.spub, dev.spriv) == <<0x06>>
    {:ok, rec} = Store.lookup(dev.name, :key)
    assert rec.created_at >= System.system_time(:second) - 5
  end

  test "gateway self-registration (no enrollment) keeps the 24h KEY TTL", %{pfx: p} do
    {pub, priv} = Crypto.generate_keypair()
    name = dev_name(p, "gw")
    hex = Base.encode16(pub, case: :lower)
    data = %{"algorithm" => "Ed25519", "node_id" => "aabbccdd", "public_key" => hex}

    assert send_registration(name, data, pub, priv) == <<0x06>>
    {:ok, rec} = Store.lookup(name, :key)
    assert rec.ttl == RecordDefaults.default_ttl(:key)
  end

  test "claiming a NEW name with a signing_public_key does not earn the one-year TTL",
       %{pfx: p} do
    {pub, priv} = Crypto.generate_keypair()
    name = dev_name(p, "squat")
    hex = Base.encode16(pub, case: :lower)

    data = %{
      "algorithm" => "Ed25519",
      "node_id" => "aabbccdd",
      "public_key" => hex,
      "signing_public_key" => hex
    }

    assert send_registration(name, data, pub, priv) == <<0x06>>
    {:ok, rec} = Store.lookup(name, :key)
    assert rec.ttl == RecordDefaults.default_ttl(:key)
  end
end
