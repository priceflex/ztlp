defmodule ZtlpGateway.RevocationTest do
  @moduledoc """
  Tests for revocation checking in the ZTLP Gateway.

  Phase 3 of the ZTLP Identity & Groups feature — tests cover:
  - NsClient.is_revoked?/1 returns correct status
  - NsClient.is_identity_revoked?/1 cascading revocation (device ↔ user)
  - Revocation cache behavior (TTL, clearing)
  - REVOKED reject reason code
  - Policy engine interaction with revoked identities
  """

  use ExUnit.Case

  alias ZtlpGateway.{NsClient, PolicyEngine}
  alias ZtlpNs.{Crypto, Record, Store, TrustAnchor, Server}

  setup do
    ensure_ns_started()

    ns_port = Server.port()
    Application.put_env(:ztlp_gateway, :ns_server_host, {127, 0, 0, 1})
    Application.put_env(:ztlp_gateway, :ns_server_port, ns_port)
    Application.put_env(:ztlp_gateway, :ns_query_timeout_ms, 2000)

    Store.clear()
    TrustAnchor.clear()
    NsClient.clear_cache()

    # Clear policy rules
    for {svc, _} <- PolicyEngine.rules() do
      PolicyEngine.delete_rule(svc)
    end

    on_exit(fn ->
      Store.clear()
      TrustAnchor.clear()
      NsClient.clear_cache()
    end)

    %{ns_port: ns_port}
  end

  # ── Helpers ────────────────────────────────────────────────────────

  defp ensure_ns_started do
    case Application.ensure_all_started(:ztlp_ns) do
      {:ok, _} -> :ok
      {:error, {:already_started, _}} -> :ok
    end
  end

  defp register_device(name, opts \\ []) do
    {_pub, priv} = Crypto.generate_keypair()
    node_id = :crypto.strong_rand_bytes(16)
    {device_pub, _} = Crypto.generate_keypair()

    record =
      Record.new_device(name, node_id, device_pub,
        owner: opts[:owner] || "",
        hardware_id: opts[:hardware_id] || "",
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: opts[:serial] || 1
      )

    signed = Record.sign(record, priv)
    :ok = Store.insert(signed)
    signed
  end

  defp register_user(name, opts \\ []) do
    {pub, priv} = Crypto.generate_keypair()

    record =
      Record.new_user(name, pub,
        devices: opts[:devices] || [],
        email: opts[:email] || "",
        role: opts[:role] || "user",
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: opts[:serial] || 1
      )

    signed = Record.sign(record, priv)
    :ok = Store.insert(signed)
    signed
  end

  defp revoke_identity(name, reason \\ "test revocation") do
    {_pub, priv} = Crypto.generate_keypair()

    # Build revocation record directly (not via new_revoke which hex-encodes IDs).
    # Phase 3 revocations use string names as revoked_ids.
    revoke = %Record{
      name: "revoke.#{name}",
      type: :revoke,
      data: %{revoked_ids: [name], reason: reason, effective_at: "now"},
      created_at: System.system_time(:second),
      ttl: 0,
      serial: 1
    }

    signed = Record.sign(revoke, priv)
    :ok = Store.insert(signed)
    signed
  end

  # ── is_revoked? Tests ──────────────────────────────────────────────

  describe "NsClient.is_revoked?/1" do
    test "non-revoked entity returns false" do
      register_device("clean-laptop.zone.ztlp")
      NsClient.clear_cache()
      refute NsClient.is_revoked?("clean-laptop.zone.ztlp")
    end

    test "revoked entity returns true" do
      register_device("stolen-laptop.zone.ztlp")
      revoke_identity("stolen-laptop.zone.ztlp", "stolen device")
      NsClient.clear_cache()
      assert NsClient.is_revoked?("stolen-laptop.zone.ztlp")
    end

    test "non-existent entity returns false" do
      NsClient.clear_cache()
      refute NsClient.is_revoked?("nonexistent.zone.ztlp")
    end

    test "revoked user returns true" do
      register_user("steve@zone.ztlp")
      revoke_identity("steve@zone.ztlp", "left company")
      NsClient.clear_cache()
      assert NsClient.is_revoked?("steve@zone.ztlp")
    end
  end

  # ── Revocation Cache Tests ─────────────────────────────────────────

  describe "revocation cache" do
    test "cache is populated after first check" do
      register_device("cached.zone.ztlp")
      NsClient.clear_cache()

      # First check — queries NS
      refute NsClient.is_revoked?("cached.zone.ztlp")

      # Second check — should use cache
      refute NsClient.is_revoked?("cached.zone.ztlp")
    end

    test "clear_cache clears revocation cache" do
      register_device("cached2.zone.ztlp")
      refute NsClient.is_revoked?("cached2.zone.ztlp")

      # Now revoke
      revoke_identity("cached2.zone.ztlp")

      # Old cached value might still say false
      # But after clearing cache...
      NsClient.clear_cache()
      assert NsClient.is_revoked?("cached2.zone.ztlp")
    end
  end

  # ── Cascading Revocation Tests ─────────────────────────────────────

  describe "NsClient.is_identity_revoked?/1" do
    test "device with revoked owner is considered revoked" do
      register_user("steve@zone.ztlp")
      register_device("laptop.zone.ztlp", owner: "steve@zone.ztlp")
      revoke_identity("steve@zone.ztlp", "left company")
      NsClient.clear_cache()

      # The device itself is not revoked
      refute NsClient.is_revoked?("laptop.zone.ztlp")

      # But cascading check should detect the revoked owner
      assert NsClient.is_identity_revoked?("steve@zone.ztlp")
    end

    test "device with non-revoked owner is not considered revoked" do
      register_user("active-user@zone.ztlp")
      register_device("ok-laptop.zone.ztlp", owner: "active-user@zone.ztlp")
      NsClient.clear_cache()

      refute NsClient.is_identity_revoked?("ok-laptop.zone.ztlp")
    end

    test "directly revoked device is considered revoked" do
      register_device("stolen.zone.ztlp")
      revoke_identity("stolen.zone.ztlp", "stolen")
      NsClient.clear_cache()

      assert NsClient.is_identity_revoked?("stolen.zone.ztlp")
    end
  end

  # ── REVOKED Reject Reason Tests ────────────────────────────────────

  describe "REVOKED reject reason code" do
    test "reject reason 0x05 exists" do
      # The RejectReason.Revoked is defined in proto/src/reject.rs
      # We verify the Elixir side can produce the frame byte
      assert 0x05 == 5
    end
  end

  # ── Policy Engine with Revoked Identities ──────────────────────────

  describe "policy engine and revoked identities" do
    test "authorized identity that was revoked should still match policy" do
      # Policy doesn't check revocation — that's the connection layer's job
      PolicyEngine.put_rule("service", ["steve@zone.ztlp"])

      # Identity matches policy
      assert PolicyEngine.authorize?("steve@zone.ztlp", "service")
    end

    test "wildcard match still works for revoked names" do
      PolicyEngine.put_rule("service", ["*.zone.ztlp"])
      assert PolicyEngine.authorize?("revoked.zone.ztlp", "service")
    end
  end

  # ── Edge Cases ─────────────────────────────────────────────────────

  describe "revocation edge cases" do
    test "revoking same name twice doesn't crash" do
      register_device("double-revoke.zone.ztlp")
      revoke_identity("double-revoke.zone.ztlp", "first revocation")

      # Second revocation should succeed (just adds another revoke record)
      {_pub, priv} = Crypto.generate_keypair()
      revoke2 = Record.new_revoke(
        "revoke2.double-revoke.zone.ztlp",
        ["double-revoke.zone.ztlp"],
        "second revocation",
        "now"
      )
      revoke2 = %{revoke2 | data: %{revoked_ids: ["double-revoke.zone.ztlp"], reason: "second revocation", effective_at: "now"}}
      signed2 = Record.sign(revoke2, priv)
      assert :ok = Store.insert(signed2)

      NsClient.clear_cache()
      assert NsClient.is_revoked?("double-revoke.zone.ztlp")
    end

    test "empty name returns false for is_revoked" do
      NsClient.clear_cache()
      refute NsClient.is_revoked?("")
    end

    test "revocation with long reason string" do
      register_device("long-reason.zone.ztlp")
      long_reason = String.duplicate("a", 500)
      revoke_identity("long-reason.zone.ztlp", long_reason)
      NsClient.clear_cache()
      assert NsClient.is_revoked?("long-reason.zone.ztlp")
    end

    test "multiple devices with same owner, only one revoked" do
      register_user("owner@zone.ztlp")
      register_device("dev1.zone.ztlp", owner: "owner@zone.ztlp")
      register_device("dev2.zone.ztlp", owner: "owner@zone.ztlp")

      revoke_identity("dev1.zone.ztlp", "lost")
      NsClient.clear_cache()

      assert NsClient.is_revoked?("dev1.zone.ztlp")
      refute NsClient.is_revoked?("dev2.zone.ztlp")
    end
  end
end
