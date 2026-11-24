defmodule ZtlpNs.ClosedRegistrationTest do
  @moduledoc """
  Closed registration (`ZTLP_NS_CLOSED_REGISTRATION=true`) and pinned zone
  authorities (`ZTLP_NS_ZONE_AUTHORITY=zone=hex,...`).

  Open self-registration let anyone create a name nobody held yet, including a
  zone anchor (a KEY record with `delegation: true`), which made them that
  zone's authority. These tests pin the closed behaviour and the paths that must
  keep working: the pinned authority, token-enrolled devices refreshing, and
  gateways refreshing names the authority pre-registered.
  """
  use ExUnit.Case, async: false

  alias ZtlpNs.{Crypto, Record, RegistrationAuth, Store, TrustAnchor, RateLimiter}

  @zone "example.ztlp"

  setup do
    Store.clear()
    TrustAnchor.clear()
    RateLimiter.reset()
    {auth_pub, auth_priv} = Crypto.generate_keypair()
    auth_hex = hex(auth_pub)
    System.put_env("ZTLP_NS_CLOSED_REGISTRATION", "true")
    System.put_env("ZTLP_NS_ZONE_AUTHORITY", "#{@zone}=#{auth_hex}")

    on_exit(fn ->
      System.delete_env("ZTLP_NS_CLOSED_REGISTRATION")
      System.delete_env("ZTLP_NS_ZONE_AUTHORITY")
    end)

    %{auth_pub: auth_pub, auth_priv: auth_priv, auth_hex: auth_hex}
  end

  defp hex(bin), do: Base.encode16(bin, case: :lower)
  defp stranger, do: Crypto.generate_keypair()

  defp insert(name, type, data, priv, ttl \\ 86_400) do
    %Record{name: name, type: type, data: data, created_at: System.system_time(:second),
            ttl: ttl, serial: 1, signature: nil, signer_public_key: nil}
    |> Record.sign(priv)
    |> Store.insert()
  end

  describe "zone anchors" do
    test "a stranger cannot anchor the pinned zone", _ctx do
      {pub, _} = stranger()
      data = %{"public_key" => hex(pub), "delegation" => true, "role" => "admin"}
      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, @zone, :key, data)
    end

    test "a stranger cannot anchor the root or an unclaimed zone" do
      {pub, _} = stranger()
      data = %{"public_key" => hex(pub), "delegation" => true}
      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, "ztlp", :key, data)
      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, "victim.ztlp", :key, data)
    end

    test "the pinned authority can anchor its zone, even with no record yet", ctx do
      data = %{"public_key" => ctx.auth_hex, "delegation" => true, "role" => "admin"}
      assert :ok = RegistrationAuth.authorize(ctx.auth_pub, @zone, :key, data)
    end

    test "an owner cannot turn its own record into a delegation" do
      {pub, priv} = stranger()
      insert("gw.#{@zone}", :key, %{"public_key" => hex(pub)}, priv)
      data = %{"public_key" => hex(pub), "delegation" => true}
      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, "gw.#{@zone}", :key, data)
    end
  end

  describe "new names in a governed zone" do
    test "a stranger cannot create a KEY, DEVICE or USER name" do
      {pub, _} = stranger()
      data = %{"public_key" => hex(pub)}

      for type <- [:key, :device, :user] do
        assert {:error, :unauthorized} =
                 RegistrationAuth.authorize(pub, "squatter.#{@zone}", type, data),
               "#{type} should be refused"
      end
    end

    test "names under an anchor recorded in the store are governed too" do
      {zpub, zpriv} = stranger()
      insert("other.ztlp", :key, %{"public_key" => hex(zpub), "delegation" => true}, zpriv)
      {pub, _} = stranger()
      assert {:error, :unauthorized} =
               RegistrationAuth.authorize(pub, "x.other.ztlp", :key, %{"public_key" => hex(pub)})
    end

    test "the authority can pre-register a gateway's name", ctx do
      {gw, _} = stranger()
      assert :ok =
               RegistrationAuth.authorize(ctx.auth_pub, "admin.#{@zone}", :key, %{"public_key" => hex(gw)})
    end

    test "a gateway refreshes the name the authority pre-registered, and its SVC" do
      {gw, gw_priv} = stranger()
      insert("admin.#{@zone}", :key, %{"public_key" => hex(gw)}, gw_priv, 0)
      assert :ok = RegistrationAuth.authorize(gw, "admin.#{@zone}", :key, %{"public_key" => hex(gw)})
      assert :ok = RegistrationAuth.authorize(gw, "admin.#{@zone}", :svc, %{"address" => "1.2.3.4:23095"})
    end

    test "a stranger cannot take over a pre-registered name" do
      {gw, gw_priv} = stranger()
      insert("admin.#{@zone}", :key, %{"public_key" => hex(gw)}, gw_priv, 0)
      {pub, _} = stranger()
      assert {:error, :unauthorized} =
               RegistrationAuth.authorize(pub, "admin.#{@zone}", :key, %{"public_key" => hex(pub)})
    end
  end

  describe "compatibility" do
    test "ungoverned zones keep open self-registration" do
      {pub, _} = stranger()
      assert :ok = RegistrationAuth.authorize(pub, "mynode.free.ztlp", :key, %{"public_key" => hex(pub)})
    end

    test "with closed registration off, the old behaviour is unchanged" do
      System.delete_env("ZTLP_NS_CLOSED_REGISTRATION")
      {pub, _} = stranger()
      assert :ok = RegistrationAuth.authorize(pub, "squatter.#{@zone}", :key, %{"public_key" => hex(pub)})
    end
  end

  describe "record lifetime on refresh" do
    test "a refresh keeps a longer or permanent lifetime" do
      {gw, gw_priv} = stranger()
      insert("admin.#{@zone}", :key, %{"public_key" => hex(gw)}, gw_priv, 0)
      assert 0 = RegistrationAuth.refresh_ttl("admin.#{@zone}", :key, 86_400)

      insert("long.#{@zone}", :key, %{"public_key" => hex(gw)}, gw_priv, 10 * 86_400)
      ttl = RegistrationAuth.refresh_ttl("long.#{@zone}", :key, 86_400)
      assert ttl > 9 * 86_400

      assert 86_400 = RegistrationAuth.refresh_ttl("new.#{@zone}", :key, 86_400)
    end
  end
end
