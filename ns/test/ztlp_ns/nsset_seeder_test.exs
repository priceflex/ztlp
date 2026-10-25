defmodule ZtlpNs.NssetSeederTest do
  @moduledoc "NS-anchored gateway trust, task 3.2: the NS-authored NSSET."
  use ExUnit.Case, async: false

  alias ZtlpNs.{Cbor, Crypto, NssetSeeder, RateLimiter, Record, RegistrationAuth, Server, Store}

  @peer_key String.duplicate("ab", 32)

  defp env(extra \\ %{}) do
    Map.merge(
      %{
        "ZTLP_NS_NSSET_ZONES" => "trs.ztlp, ChooseForce.ztlp.",
        "ZTLP_NS_SELF_ADDR" => "44.227.148.151:23096"
      },
      extra
    )
  end

  describe "config/1" do
    test "disabled without zones" do
      assert NssetSeeder.config(%{}) == :disabled
    end

    test "zones without self address is an error" do
      assert NssetSeeder.config(%{"ZTLP_NS_NSSET_ZONES" => "a.ztlp"}) ==
               {:error, :missing_self_addr}
    end

    test "parses zones (normalized), peers and ttl" do
      {:ok, cfg} =
        NssetSeeder.config(
          env(%{
            "ZTLP_NS_PEERS" => "replica1=44.230.7.100:23096=#{@peer_key}=trs.ztlp",
            "ZTLP_NS_NSSET_TTL" => "7200"
          })
        )

      assert cfg.zones == ["trs.ztlp", "chooseforce.ztlp"]
      assert cfg.ttl == 7200
      assert [%{label: "replica1", addr: "44.230.7.100:23096", pubkey: @peer_key, zones: ["trs.ztlp"]}] =
               cfg.peers
    end

    test "a peer for a zone this NS is not home for is refused" do
      assert {:error, {:peer_zone_not_authoritative, "x", ["other.ztlp"]}} =
               NssetSeeder.config(
                 env(%{"ZTLP_NS_PEERS" => "x=1.2.3.4:23096=#{@peer_key}=trs.ztlp,other.ztlp"})
               )
    end

    test "bad peer key / entry / empty zones are refused" do
      assert {:error, {:bad_peer_pubkey, "x"}} =
               NssetSeeder.config(env(%{"ZTLP_NS_PEERS" => "x=1.2.3.4:1=abcd=trs.ztlp"}))

      assert {:error, {:bad_peer_entry, _}} =
               NssetSeeder.config(env(%{"ZTLP_NS_PEERS" => "garbage"}))

      assert {:error, {:peer_without_zones, "x"}} =
               NssetSeeder.config(env(%{"ZTLP_NS_PEERS" => "x=1.2.3.4:1=#{@peer_key}= "}))
    end
  end

  describe "build/3" do
    setup do
      {pub, priv} = Crypto.generate_keypair()

      {:ok, cfg} =
        NssetSeeder.config(
          env(%{"ZTLP_NS_PEERS" => "replica1=44.230.7.100:23096=#{@peer_key}=trs.ztlp"})
        )

      {:ok, pub: pub, priv: priv, cfg: cfg}
    end

    test "one signed OPERATOR record per zone, self first, peers scoped by zone",
         %{pub: pub, priv: priv, cfg: cfg} do
      {:ok, [trs, cf]} = NssetSeeder.build(cfg, priv, 1_800_000_000)

      assert trs.name == "trs.ztlp"
      assert trs.type == :operator
      assert Record.verify(trs)
      assert trs.signer_public_key == pub
      assert trs.serial == 1_800_000_000
      assert trs.data["kind"] == "nsset"

      assert [self_entry, peer] = trs.data["servers"]
      assert self_entry["addr"] == "44.227.148.151:23096"
      assert self_entry["pubkey"] == Base.encode16(pub, case: :lower)
      assert self_entry["zones"] == ["trs.ztlp", "chooseforce.ztlp"]
      assert peer == %{"addr" => "44.230.7.100:23096", "pubkey" => @peer_key, "zones" => ["trs.ztlp"]}

      # The replica is not listed for a zone it does not serve.
      assert cf.name == "chooseforce.ztlp"
      assert [_self_only] = cf.data["servers"]
    end

    test "re-seed bumps the serial", %{priv: priv, cfg: cfg} do
      {:ok, [a | _]} = NssetSeeder.build(cfg, priv, 1_800_000_000)
      {:ok, [b | _]} = NssetSeeder.build(cfg, priv, 1_800_000_060)
      assert b.serial > a.serial
    end

    test "an NSSET that would not fit the client's 2 KB budget is refused", %{priv: priv} do
      peers =
        for i <- 1..40 do
          %{label: "p#{i}", addr: "10.0.0.#{i}:23096", pubkey: @peer_key, zones: ["trs.ztlp"]}
        end

      cfg = %{zones: ["trs.ztlp"], self_addr: "1.2.3.4:23096", peers: peers, ttl: 86_400}
      assert {:error, {:too_large, "trs.ztlp", size}} = NssetSeeder.build(cfg, priv)
      assert size > 1900
    end
  end

  describe "over the wire" do
    setup do
      RateLimiter.reset()
      :ok
    end

    defp udp(packet) do
      {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}])
      :ok = :gen_udp.send(sock, {127, 0, 0, 1}, Server.port(), packet)
      {:ok, {_ip, _port, reply}} = :gen_udp.recv(sock, 0, 5000)
      :gen_udp.close(sock)
      reply
    end

    test "a seeded NSSET is served to a padded 0x01 query for type 7, NS-signed" do
      priv = Application.get_env(:ztlp_ns, :registration_private_key)
      zone = "nsset-#{Base.encode16(:crypto.strong_rand_bytes(3), case: :lower)}.ztlp"
      cfg = %{zones: [zone], self_addr: "127.0.0.1:23096", peers: [], ttl: 3600}
      {:ok, [rec]} = NssetSeeder.build(cfg, priv)
      assert :ok = Store.insert(rec)

      q = <<0x01, byte_size(zone)::16, zone::binary, 7::8>>
      assert <<0x02, encoded::binary>> = udp(q <> :binary.copy(<<0>>, 256 - byte_size(q)))
      assert {:ok, got} = Record.decode(encoded)
      assert got.type == :operator
      assert Record.verify(got)
      assert got.signer_public_key == Crypto.public_key_from_private(priv)
      assert [%{"addr" => "127.0.0.1:23096"}] = got.data["servers"]
    end

    test "nobody can register an OPERATOR record (reserved for the NS)" do
      {pub, priv} = Crypto.generate_keypair()
      name = "evil-#{Base.encode16(:crypto.strong_rand_bytes(3), case: :lower)}.ztlp"
      data_bin = Cbor.encode(%{"kind" => "nsset", "servers" => []})
      sig = Crypto.sign(RegistrationAuth.build_canonical(name, :operator, data_bin), priv)

      reply =
        udp(
          <<0x09, byte_size(name)::16, name::binary, 7::8, byte_size(data_bin)::16,
            data_bin::binary, byte_size(sig)::16, sig::binary, byte_size(pub)::16, pub::binary>>
        )

      assert <<0xFF, _::binary>> = reply
      assert Store.lookup(name, :operator) != :ok
      refute match?({:ok, _}, Store.lookup(name, :operator))
    end
  end
end
