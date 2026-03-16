defmodule ZtlpNs.EnrollmentTest do
  use ExUnit.Case, async: false

  alias ZtlpNs.{Enrollment, Store}

  @test_zone "office.acme.ztlp"
  @test_ns_addr "127.0.0.1:23096"
  @test_relay "127.0.0.1:23095"

  setup do
    secret = :crypto.strong_rand_bytes(32)
    Enrollment.set_zone_secret(secret)
    Enrollment.init()
    Enrollment.reset()

    # Unique prefix per test to avoid name collisions
    pfx = Base.encode16(:crypto.strong_rand_bytes(4), case: :lower)

    {:ok, secret: secret, pfx: pfx}
  end

  # ── Token creation helpers ─────────────────────────────────────────

  defp create_token(secret, opts \\ []) do
    zone = Keyword.get(opts, :zone, @test_zone)
    ns_addr = Keyword.get(opts, :ns_addr, @test_ns_addr)
    relay_addrs = Keyword.get(opts, :relay_addrs, [@test_relay])
    gateway_addr = Keyword.get(opts, :gateway_addr, nil)
    max_uses = Keyword.get(opts, :max_uses, 0)
    expires_at = Keyword.get(opts, :expires_at, System.system_time(:second) + 3600)

    nonce = :crypto.strong_rand_bytes(16)

    flags = if gateway_addr, do: 0x01, else: 0x00

    data =
      <<0x01, flags::8>> <>
        enc(zone) <> enc(ns_addr) <>
        <<length(relay_addrs)::8>> <>
        Enum.reduce(relay_addrs, <<>>, fn a, acc -> acc <> enc(a) end) <>
        if(gateway_addr, do: enc(gateway_addr), else: <<>>) <>
        <<max_uses::16, expires_at::64>> <> nonce

    mac = Enrollment.hmac_blake2s(secret, data)
    data <> mac
  end

  defp enc(s), do: <<byte_size(s)::16, s::binary>>

  defp enroll_req(token, pubkey, node_id, name, addr \\ "") do
    <<byte_size(token)::16, token::binary, pubkey::binary-size(32),
      node_id::binary-size(16), byte_size(name)::16, name::binary,
      byte_size(addr)::16, addr::binary>>
  end

  defp dev_name(pfx, label), do: "#{pfx}-#{label}.#{@test_zone}"

  # ── Tests ──────────────────────────────────────────────────────────

  test "successful enrollment creates KEY record", %{secret: s, pfx: p} do
    token = create_token(s)
    pk = :crypto.strong_rand_bytes(32)
    nid = :crypto.strong_rand_bytes(16)
    name = dev_name(p, "key")

    result = Enrollment.process_enroll(enroll_req(token, pk, nid, name))
    assert <<0x08, 0x00, _::binary>> = result

    {:ok, record} = Store.lookup(name, :key)
    assert record.data["public_key"] == Base.encode16(pk, case: :lower)
    assert record.data["node_id"] == Base.encode16(nid, case: :lower)
  end

  test "successful enrollment creates SVC record when address provided", %{secret: s, pfx: p} do
    token = create_token(s)
    name = dev_name(p, "svc")
    addr = "10.0.0.50:23095"

    result = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), name, addr)
    )
    assert <<0x08, 0x00, _::binary>> = result

    {:ok, record} = Store.lookup(name, :svc)
    assert record.data["address"] == addr
  end

  test "enrollment returns relay and gateway config", %{secret: s, pfx: p} do
    gw = "10.0.0.5:23097"
    token = create_token(s, gateway_addr: gw)
    name = dev_name(p, "cfg")

    <<0x08, 0x00, config::binary>> = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), name)
    )

    <<relay_count::8, rest::binary>> = config
    assert relay_count == 1
    <<rlen::16, relay::binary-size(rlen), rest2::binary>> = rest
    assert relay == @test_relay

    <<gw_count::8, rest3::binary>> = rest2
    assert gw_count == 1
    <<glen::16, gw_addr::binary-size(glen), _::binary>> = rest3
    assert gw_addr == gw
  end

  test "expired token is rejected", %{secret: s, pfx: p} do
    token = create_token(s, expires_at: 1)
    name = dev_name(p, "exp")

    result = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), name)
    )
    assert result == <<0x08, 0x01>>
  end

  test "invalid MAC is rejected", %{secret: s, pfx: p} do
    token = create_token(s)
    # Tamper with a byte
    <<head::binary-size(5), _byte::8, tail::binary>> = token
    tampered = <<head::binary, 0xFF, tail::binary>>

    result = Enrollment.process_enroll(
      enroll_req(tampered, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), dev_name(p, "mac"))
    )
    assert result == <<0x08, 0x03>>
  end

  test "wrong secret is rejected", %{secret: _s, pfx: p} do
    wrong = :crypto.strong_rand_bytes(32)
    token = create_token(wrong)

    result = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), dev_name(p, "wrong"))
    )
    assert result == <<0x08, 0x03>>
  end

  test "max_uses token tracks usage and exhausts", %{secret: s, pfx: p} do
    token = create_token(s, max_uses: 2)

    # Use 1
    assert <<0x08, 0x00, _::binary>> = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), dev_name(p, "u1"))
    )

    # Use 2
    assert <<0x08, 0x00, _::binary>> = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), dev_name(p, "u2"))
    )

    # Use 3 — exhausted
    assert <<0x08, 0x02>> = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), dev_name(p, "u3"))
    )
  end

  test "unlimited uses token (max_uses=0) never exhausts", %{secret: s, pfx: p} do
    token = create_token(s, max_uses: 0)

    for i <- 1..5 do
      assert <<0x08, 0x00, _::binary>> = Enrollment.process_enroll(
        enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), dev_name(p, "inf#{i}"))
      )
    end
  end

  test "name outside zone is rejected", %{secret: s, pfx: _p} do
    token = create_token(s)

    result = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), "rogue.evil.ztlp")
    )
    assert result == <<0x08, 0x04>>
  end

  test "same device can re-enroll (same pubkey)", %{secret: s, pfx: p} do
    pk = :crypto.strong_rand_bytes(32)
    nid = :crypto.strong_rand_bytes(16)
    name = dev_name(p, "reenroll")

    token1 = create_token(s)
    assert <<0x08, 0x00, _::binary>> = Enrollment.process_enroll(enroll_req(token1, pk, nid, name))

    token2 = create_token(s)
    assert <<0x08, 0x00, _::binary>> = Enrollment.process_enroll(enroll_req(token2, pk, nid, name))
  end

  test "different device with taken name is rejected", %{secret: s, pfx: p} do
    name = dev_name(p, "taken")

    token1 = create_token(s)
    assert <<0x08, 0x00, _::binary>> = Enrollment.process_enroll(
      enroll_req(token1, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), name)
    )

    token2 = create_token(s)
    assert <<0x08, 0x05>> = Enrollment.process_enroll(
      enroll_req(token2, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), name)
    )
  end

  test "malformed request returns error", %{secret: _s, pfx: _p} do
    assert Enrollment.process_enroll(<<>>) == <<0x08, 0x06>>
    assert Enrollment.process_enroll(<<0x00, 0x01>>) == <<0x08, 0x06>>
    assert Enrollment.process_enroll("garbage") == <<0x08, 0x06>>
  end

  test "enrollment without zone secret returns error", %{secret: _s, pfx: p} do
    Application.delete_env(:ztlp_ns, :enrollment_secret)

    result = Enrollment.process_enroll(
      enroll_req(:crypto.strong_rand_bytes(100), :crypto.strong_rand_bytes(32),
        :crypto.strong_rand_bytes(16), dev_name(p, "nosec"))
    )
    assert result == <<0x08, 0x06>>
  end

  test "hmac_blake2s is deterministic" do
    key = :crypto.strong_rand_bytes(32)
    data = "hello world"
    assert Enrollment.hmac_blake2s(key, data) == Enrollment.hmac_blake2s(key, data)
  end

  test "hmac_blake2s different keys produce different MACs" do
    k1 = :crypto.strong_rand_bytes(32)
    k2 = :crypto.strong_rand_bytes(32)
    assert Enrollment.hmac_blake2s(k1, "x") != Enrollment.hmac_blake2s(k2, "x")
  end

  test "multiple relay addresses in config response", %{secret: s, pfx: p} do
    relays = ["10.0.0.1:23095", "10.0.0.2:23095", "10.0.0.3:23095"]
    token = create_token(s, relay_addrs: relays)
    name = dev_name(p, "multi")

    <<0x08, 0x00, config::binary>> = Enrollment.process_enroll(
      enroll_req(token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), name)
    )

    <<relay_count::8, rest::binary>> = config
    assert relay_count == 3
    {parsed, _} = parse_addrs(rest, 3)
    assert parsed == relays
  end

  test "end-to-end enrollment via UDP server", %{secret: s, pfx: p} do
    port = ZtlpNs.Server.port()
    token = create_token(s)
    pk = :crypto.strong_rand_bytes(32)
    nid = :crypto.strong_rand_bytes(16)
    name = dev_name(p, "e2e")
    addr = "10.0.0.99:23095"

    body = enroll_req(token, pk, nid, name, addr)
    packet = <<0x07, body::binary>>

    {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}])
    :gen_udp.send(sock, {127, 0, 0, 1}, port, packet)
    {:ok, {_, _, response}} = :gen_udp.recv(sock, 0, 5_000)
    :gen_udp.close(sock)

    assert <<0x08, 0x00, _::binary>> = response

    # Verify via standard NS lookup
    {:ok, sock2} = :gen_udp.open(0, [:binary, {:active, false}])
    query = <<0x01, byte_size(name)::16, name::binary, 0x01>>
    :gen_udp.send(sock2, {127, 0, 0, 1}, port, query)
    {:ok, {_, _, key_resp}} = :gen_udp.recv(sock2, 0, 5_000)
    assert <<0x02, _::binary>> = key_resp

    svc_q = <<0x01, byte_size(name)::16, name::binary, 0x02>>
    :gen_udp.send(sock2, {127, 0, 0, 1}, port, svc_q)
    {:ok, {_, _, svc_resp}} = :gen_udp.recv(sock2, 0, 5_000)
    assert <<0x02, _::binary>> = svc_resp
    :gen_udp.close(sock2)
  end

  # ── MAC skip when require_registration_auth=false ───────────────────

  test "zeroed MAC accepted when require_registration_auth=false", %{secret: s, pfx: p} do
    # Create a valid token, then zero out the MAC to simulate Bootstrap query-param tokens
    token = create_token(s)
    mac_start = byte_size(token) - 32
    <<data::binary-size(mac_start), _mac::binary-size(32)>> = token
    zeroed_token = <<data::binary, 0::256>>

    # With auth required, zeroed MAC should be rejected
    Application.put_env(:ztlp_ns, :require_registration_auth, true)
    result = Enrollment.process_enroll(
      enroll_req(zeroed_token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), dev_name(p, "mac-skip1"))
    )
    assert result == <<0x08, 0x03>>

    # With auth disabled, zeroed MAC should be accepted
    Application.put_env(:ztlp_ns, :require_registration_auth, false)
    result = Enrollment.process_enroll(
      enroll_req(zeroed_token, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(16), dev_name(p, "mac-skip2"))
    )
    assert <<0x08, 0x00, _::binary>> = result

    # Restore default
    Application.put_env(:ztlp_ns, :require_registration_auth, true)
  end

  # ── Helpers ────────────────────────────────────────────────────────

  defp parse_addrs(bin, 0), do: {[], bin}
  defp parse_addrs(<<len::16, a::binary-size(len), rest::binary>>, n) do
    {addrs, rem} = parse_addrs(rest, n - 1)
    {[a | addrs], rem}
  end
end
