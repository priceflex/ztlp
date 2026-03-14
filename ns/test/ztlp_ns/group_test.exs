defmodule ZtlpNs.GroupTest do
  @moduledoc """
  Comprehensive tests for GROUP (0x12) record type.

  Phase 2 of the ZTLP Identity & Groups feature — tests cover:
  - Record construction and validation
  - Serialization/deserialization round-trips
  - Signing and verification
  - Wire format encode/decode
  - Store insert/lookup
  - Group membership index (groups_for_user, members_of_group, is_member?)
  - UDP server query/registration integration
  - Zone-only authorization (no self-registration)
  - Backward compatibility with existing record types
  - Group membership updates
  - Revocation interplay
  """

  use ExUnit.Case

  alias ZtlpNs.{Crypto, Record, Store, TrustAnchor, ZoneAuthority, RegistrationAuth}

  setup do
    Store.clear()
    TrustAnchor.clear()
    :ok
  end

  # ── Helpers ────────────────────────────────────────────────────────

  defp make_signed_group(name, members, opts \\ []) do
    {_pub, priv} = Crypto.generate_keypair()

    record =
      Record.new_group(name, members,
        description: opts[:description] || "",
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: opts[:serial] || 1
      )

    Record.sign(record, priv)
  end

  defp make_signed_key(name, opts \\ []) do
    {_pub, priv} = Crypto.generate_keypair()
    node_id = :crypto.strong_rand_bytes(16)
    {node_pub, _} = Crypto.generate_keypair()

    record =
      Record.new_key(name, node_id, node_pub,
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: opts[:serial] || 1
      )

    Record.sign(record, priv)
  end

  defp make_signed_device(name, opts \\ []) do
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

    Record.sign(record, priv)
  end

  defp make_signed_user(name, opts \\ []) do
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

    Record.sign(record, priv)
  end

  defp setup_zone_authority(zone_name) do
    root = ZoneAuthority.generate(zone_name)
    TrustAnchor.add("root", root.public_key)

    # Create delegation record for zone authority
    delegation = %Record{
      name: zone_name,
      type: :key,
      data: %{
        public_key: Base.encode16(root.public_key, case: :lower),
        delegation: true,
        algorithm: "Ed25519"
      },
      created_at: System.system_time(:second),
      ttl: 86400,
      serial: 1
    }

    signed_delegation = Record.sign(delegation, root.private_key)
    Store.insert(signed_delegation)

    root
  end

  # ── Record Type Mapping ────────────────────────────────────────────

  describe "type byte mapping" do
    test "GROUP type maps to 0x12" do
      assert Record.type_to_byte(:group) == 0x12
    end

    test "0x12 maps back to :group" do
      assert Record.byte_to_type(0x12) == :group
    end

    test "existing types still work after adding GROUP" do
      assert Record.type_to_byte(:key) == 1
      assert Record.type_to_byte(:device) == 0x10
      assert Record.type_to_byte(:user) == 0x11
      assert Record.byte_to_type(1) == :key
      assert Record.byte_to_type(0x10) == :device
      assert Record.byte_to_type(0x11) == :user
    end

    test "round-trips all types including GROUP" do
      types = [:key, :svc, :relay, :policy, :revoke, :bootstrap, :operator, :device, :user, :group]

      for type <- types do
        byte = Record.type_to_byte(type)
        assert Record.byte_to_type(byte) == type
      end
    end
  end

  # ── GROUP Record Construction ──────────────────────────────────────

  describe "new_group/3" do
    test "creates a group record with correct type" do
      rec = Record.new_group("admins@techrockstars.ztlp", ["steve@techrockstars.ztlp"])
      assert rec.type == :group
      assert rec.name == "admins@techrockstars.ztlp"
    end

    test "stores members list" do
      members = ["steve@techrockstars.ztlp", "alice@techrockstars.ztlp"]
      rec = Record.new_group("admins@zone.ztlp", members)
      assert rec.data[:members] == members
    end

    test "stores description when provided" do
      rec = Record.new_group("techs@zone.ztlp", [], description: "Field technicians")
      assert rec.data[:description] == "Field technicians"
    end

    test "defaults description to empty string" do
      rec = Record.new_group("group@zone.ztlp", [])
      assert rec.data[:description] == ""
    end

    test "defaults TTL to 86400" do
      rec = Record.new_group("group@zone.ztlp", [])
      assert rec.ttl == 86400
    end

    test "accepts custom TTL" do
      rec = Record.new_group("group@zone.ztlp", [], ttl: 3600)
      assert rec.ttl == 3600
    end

    test "accepts custom serial" do
      rec = Record.new_group("group@zone.ztlp", [], serial: 42)
      assert rec.serial == 42
    end

    test "creates group with empty members list" do
      rec = Record.new_group("empty@zone.ztlp", [])
      assert rec.data[:members] == []
    end

    test "creates group with many members" do
      members = Enum.map(1..50, fn i -> "user#{i}@zone.ztlp" end)
      rec = Record.new_group("big@zone.ztlp", members)
      assert length(rec.data[:members]) == 50
    end
  end

  # ── Validation ─────────────────────────────────────────────────────

  describe "validate_group/1" do
    test "accepts valid group data with atom keys" do
      rec = Record.new_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      assert :ok = Record.validate_group(rec.data)
    end

    test "accepts valid group data with string keys" do
      data = %{"members" => ["steve@zone.ztlp", "alice@zone.ztlp"]}
      assert :ok = Record.validate_group(data)
    end

    test "accepts empty members list" do
      data = %{"members" => []}
      assert :ok = Record.validate_group(data)
    end

    test "rejects missing members" do
      data = %{"description" => "no members key"}
      assert {:error, :missing_members} = Record.validate_group(data)
    end

    test "rejects nil members" do
      data = %{members: nil}
      assert {:error, :missing_members} = Record.validate_group(data)
    end

    test "rejects non-list members" do
      data = %{members: "not a list"}
      assert {:error, :invalid_members} = Record.validate_group(data)
    end

    test "rejects too many members (> 255)" do
      members = Enum.map(1..256, fn i -> "user#{i}@zone.ztlp" end)
      data = %{members: members}
      assert {:error, :too_many_members} = Record.validate_group(data)
    end

    test "accepts exactly 255 members" do
      members = Enum.map(1..255, fn i -> "user#{i}@zone.ztlp" end)
      data = %{members: members}
      assert :ok = Record.validate_group(data)
    end
  end

  # ── Serialization Round-trips ──────────────────────────────────────

  describe "GROUP serialize/deserialize" do
    test "round-trips a group record" do
      members = ["steve@techrockstars.ztlp", "alice@techrockstars.ztlp"]

      record =
        Record.new_group("admins@techrockstars.ztlp", members,
          description: "Administrators",
          created_at: 5000,
          ttl: 86400,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.name == "admins@techrockstars.ztlp"
      assert restored.type == :group
      assert restored.data["members"] == members
      assert restored.data["description"] == "Administrators"
      assert restored.created_at == 5000
      assert restored.ttl == 86400
    end

    test "round-trips group record with empty members" do
      record =
        Record.new_group("empty@zone.ztlp", [],
          created_at: 6000,
          ttl: 86400,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.data["members"] == []
      assert restored.data["description"] == ""
    end

    test "round-trips group record with empty description" do
      record =
        Record.new_group("group@zone.ztlp", ["a@zone.ztlp"],
          created_at: 7000,
          ttl: 86400,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.data["description"] == ""
    end
  end

  # ── Signing & Verification ─────────────────────────────────────────

  describe "GROUP signing" do
    test "signed group record verifies" do
      rec = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      assert Record.verify(rec)
    end

    test "unsigned group record does not verify" do
      record = Record.new_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      refute Record.verify(record)
    end

    test "tampered group record does not verify" do
      rec = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      tampered = %{rec | name: "hacked@zone.ztlp"}
      refute Record.verify(tampered)
    end

    test "tampered members do not verify" do
      rec = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      tampered = %{rec | data: Map.put(rec.data, :members, ["hacker@zone.ztlp"])}
      refute Record.verify(tampered)
    end
  end

  # ── Wire Format Encode/Decode ──────────────────────────────────────

  describe "GROUP wire format" do
    test "round-trips via encode/decode" do
      {_pub, priv} = Crypto.generate_keypair()
      members = ["steve@corp.ztlp", "alice@corp.ztlp"]

      record =
        Record.new_group("admins@corp.ztlp", members,
          description: "Corp admins"
        )

      signed = Record.sign(record, priv)
      encoded = Record.encode(signed)
      assert {:ok, decoded} = Record.decode(encoded)

      assert decoded.name == "admins@corp.ztlp"
      assert decoded.type == :group
      assert decoded.signature == signed.signature
      assert decoded.signer_public_key == signed.signer_public_key
      assert Record.verify(decoded)
    end

    test "wire format preserves members" do
      {_pub, priv} = Crypto.generate_keypair()
      members = ["a@z.ztlp", "b@z.ztlp", "c@z.ztlp"]

      record = Record.new_group("g@z.ztlp", members)
      signed = Record.sign(record, priv)
      encoded = Record.encode(signed)
      assert {:ok, decoded} = Record.decode(encoded)

      decoded_members = Map.get(decoded.data, "members")
      assert decoded_members == members
    end
  end

  # ── Store Insert/Lookup ────────────────────────────────────────────

  describe "Store: GROUP records" do
    test "inserts and looks up a group record" do
      rec = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      assert :ok = Store.insert(rec)
      assert {:ok, found} = Store.lookup("admins@zone.ztlp", :group)
      assert found.name == "admins@zone.ztlp"
      assert found.type == :group
    end

    test "rejects unsigned group record" do
      record = Record.new_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      assert {:error, :invalid_signature} = Store.insert(record)
    end

    test "group lookup returns :not_found for missing record" do
      assert :not_found = Store.lookup("missing@zone.ztlp", :group)
    end

    test "group lookup does not conflict with key record on same name" do
      key_rec = make_signed_key("entity.ztlp")
      group_rec = make_signed_group("entity.ztlp", ["a@zone.ztlp"])
      assert :ok = Store.insert(key_rec)
      assert :ok = Store.insert(group_rec)
      assert {:ok, key_found} = Store.lookup("entity.ztlp", :key)
      assert {:ok, group_found} = Store.lookup("entity.ztlp", :group)
      assert key_found.type == :key
      assert group_found.type == :group
    end

    test "group lookup does not conflict with user record on same name" do
      user_rec = make_signed_user("entity@zone.ztlp")
      group_rec = make_signed_group("entity@zone.ztlp", ["a@zone.ztlp"])
      assert :ok = Store.insert(user_rec)
      assert :ok = Store.insert(group_rec)
      assert {:ok, user_found} = Store.lookup("entity@zone.ztlp", :user)
      assert {:ok, group_found} = Store.lookup("entity@zone.ztlp", :group)
      assert user_found.type == :user
      assert group_found.type == :group
    end

    test "stale serial is rejected for group records" do
      rec1 = make_signed_group("admins@zone.ztlp", ["a@zone.ztlp"], serial: 5)
      rec2 = make_signed_group("admins@zone.ztlp", ["b@zone.ztlp"], serial: 3)
      assert :ok = Store.insert(rec1)
      assert {:error, :stale_serial} = Store.insert(rec2)
    end

    test "group record can be updated with higher serial" do
      rec1 = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"], serial: 1)
      assert :ok = Store.insert(rec1)

      rec2 = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp", "alice@zone.ztlp"], serial: 2)
      assert :ok = Store.insert(rec2)

      {:ok, found} = Store.lookup("admins@zone.ztlp", :group)
      assert found.serial == 2
    end
  end

  # ── Group Membership Index ─────────────────────────────────────────

  describe "group membership index" do
    test "groups_for_user returns groups the user belongs to" do
      rec = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp", "alice@zone.ztlp"])
      assert :ok = Store.insert(rec)

      groups = Store.groups_for_user("steve@zone.ztlp")
      assert "admins@zone.ztlp" in groups
    end

    test "groups_for_user returns multiple groups" do
      rec1 = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      rec2 = make_signed_group("techs@zone.ztlp", ["steve@zone.ztlp"])
      assert :ok = Store.insert(rec1)
      assert :ok = Store.insert(rec2)

      groups = Store.groups_for_user("steve@zone.ztlp")
      assert length(groups) == 2
      assert "admins@zone.ztlp" in groups
      assert "techs@zone.ztlp" in groups
    end

    test "groups_for_user returns empty list for unknown user" do
      assert [] = Store.groups_for_user("unknown@zone.ztlp")
    end

    test "groups_for_user returns empty list for user not in any group" do
      rec = make_signed_group("admins@zone.ztlp", ["alice@zone.ztlp"])
      assert :ok = Store.insert(rec)
      assert [] = Store.groups_for_user("bob@zone.ztlp")
    end

    test "members_of_group returns all members" do
      members = ["steve@zone.ztlp", "alice@zone.ztlp"]
      rec = make_signed_group("admins@zone.ztlp", members)
      assert :ok = Store.insert(rec)

      result = Store.members_of_group("admins@zone.ztlp")
      assert length(result) == 2
      assert "steve@zone.ztlp" in result
      assert "alice@zone.ztlp" in result
    end

    test "members_of_group returns empty list for unknown group" do
      assert [] = Store.members_of_group("nonexistent@zone.ztlp")
    end

    test "is_member? returns true for member" do
      rec = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      assert :ok = Store.insert(rec)
      assert Store.is_member?("admins@zone.ztlp", "steve@zone.ztlp")
    end

    test "is_member? returns false for non-member" do
      rec = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      assert :ok = Store.insert(rec)
      refute Store.is_member?("admins@zone.ztlp", "bob@zone.ztlp")
    end

    test "is_member? returns false for unknown group" do
      refute Store.is_member?("nonexistent@zone.ztlp", "steve@zone.ztlp")
    end

    test "membership index updates when group is updated" do
      # Initial group with steve
      rec1 = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"], serial: 1)
      assert :ok = Store.insert(rec1)
      assert Store.is_member?("admins@zone.ztlp", "steve@zone.ztlp")
      refute Store.is_member?("admins@zone.ztlp", "alice@zone.ztlp")

      # Update: remove steve, add alice
      rec2 = make_signed_group("admins@zone.ztlp", ["alice@zone.ztlp"], serial: 2)
      assert :ok = Store.insert(rec2)

      # Steve should no longer be in the group
      refute Store.is_member?("admins@zone.ztlp", "steve@zone.ztlp")
      assert Store.is_member?("admins@zone.ztlp", "alice@zone.ztlp")

      # groups_for_user should reflect the change
      assert [] = Store.groups_for_user("steve@zone.ztlp")
      assert ["admins@zone.ztlp"] = Store.groups_for_user("alice@zone.ztlp")
    end

    test "different groups have separate member lists" do
      rec1 = make_signed_group("admins@zone.ztlp", ["alice@zone.ztlp"])
      rec2 = make_signed_group("techs@zone.ztlp", ["bob@zone.ztlp"])
      assert :ok = Store.insert(rec1)
      assert :ok = Store.insert(rec2)

      assert Store.is_member?("admins@zone.ztlp", "alice@zone.ztlp")
      refute Store.is_member?("admins@zone.ztlp", "bob@zone.ztlp")
      assert Store.is_member?("techs@zone.ztlp", "bob@zone.ztlp")
      refute Store.is_member?("techs@zone.ztlp", "alice@zone.ztlp")
    end

    test "user in multiple groups shows up correctly" do
      rec1 = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      rec2 = make_signed_group("techs@zone.ztlp", ["steve@zone.ztlp", "bob@zone.ztlp"])
      assert :ok = Store.insert(rec1)
      assert :ok = Store.insert(rec2)

      groups = Store.groups_for_user("steve@zone.ztlp")
      assert length(groups) == 2

      bob_groups = Store.groups_for_user("bob@zone.ztlp")
      assert length(bob_groups) == 1
      assert "techs@zone.ztlp" in bob_groups
    end
  end

  # ── TTL and Expiration ─────────────────────────────────────────────

  describe "expiration" do
    test "expired group record is not returned" do
      rec = make_signed_group("old@zone.ztlp", ["a@zone.ztlp"], created_at: 0, ttl: 1)
      assert :ok = Store.insert(rec)
      assert :not_found = Store.lookup("old@zone.ztlp", :group)
    end

    test "group record with long TTL is not expired" do
      rec = make_signed_group("fresh@zone.ztlp", ["a@zone.ztlp"])
      refute Record.expired?(rec)
    end

    test "expired group means is_member? returns false" do
      rec = make_signed_group("old@zone.ztlp", ["a@zone.ztlp"], created_at: 0, ttl: 1)
      assert :ok = Store.insert(rec)
      refute Store.is_member?("old@zone.ztlp", "a@zone.ztlp")
    end

    test "expired group means members_of_group returns empty" do
      rec = make_signed_group("old@zone.ztlp", ["a@zone.ztlp"], created_at: 0, ttl: 1)
      assert :ok = Store.insert(rec)
      assert [] = Store.members_of_group("old@zone.ztlp")
    end
  end

  # ── UDP Server Integration ─────────────────────────────────────────

  describe "UDP server: GROUP queries" do
    test "query for group record returns it" do
      rec = make_signed_group("admins@corp.ztlp", ["steve@corp.ztlp"])
      Store.insert(rec)

      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "admins@corp.ztlp"
      name_len = byte_size(name)
      type_byte = Record.type_to_byte(:group)
      query = <<0x01, name_len::16, name::binary, type_byte::8>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, query)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x02, _rest::binary>> = response
    end

    test "query for missing group record returns not-found" do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "missing@zone.ztlp"
      name_len = byte_size(name)
      type_byte = Record.type_to_byte(:group)
      query = <<0x01, name_len::16, name::binary, type_byte::8>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, query)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x03, _rest::binary>> = response
    end
  end

  describe "UDP server: GROUP registration (unsigned/dev mode)" do
    setup do
      original = Application.get_env(:ztlp_ns, :require_registration_auth)
      Application.put_env(:ztlp_ns, :require_registration_auth, false)

      on_exit(fn ->
        if original do
          Application.put_env(:ztlp_ns, :require_registration_auth, original)
        else
          Application.delete_env(:ztlp_ns, :require_registration_auth)
        end
      end)

      :ok
    end

    test "registers a group via unsigned registration" do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "newgroup@zone.ztlp"
      members = ["steve@zone.ztlp", "alice@zone.ztlp"]

      data = %{
        "members" => members,
        "description" => "Test group"
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      name_len = byte_size(name)
      data_len = byte_size(data_bin)
      type_byte = Record.type_to_byte(:group)

      dummy_sig = :crypto.strong_rand_bytes(64)
      sig_len = byte_size(dummy_sig)

      packet = <<0x09, name_len::16, name::binary, type_byte::8,
                 data_len::16, data_bin::binary, sig_len::16, dummy_sig::binary>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, packet)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x06>> = response

      assert {:ok, stored} = Store.lookup("newgroup@zone.ztlp", :group)
      assert stored.type == :group
    end
  end

  describe "UDP server: authenticated GROUP registration" do
    test "registers a group with valid zone authority signature" do
      root = setup_zone_authority("ztlp")

      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "admins@techrockstars.ztlp"

      data = %{
        "members" => ["steve@techrockstars.ztlp"],
        "description" => "Admins"
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      name_len = byte_size(name)
      data_len = byte_size(data_bin)
      type_byte = Record.type_to_byte(:group)

      canonical = RegistrationAuth.build_canonical(name, :group, data_bin)
      sig = Crypto.sign(canonical, root.private_key)
      sig_len = byte_size(sig)
      pubkey_len = byte_size(root.public_key)

      packet = <<0x09, name_len::16, name::binary, type_byte::8,
                 data_len::16, data_bin::binary, sig_len::16, sig::binary,
                 pubkey_len::16, root.public_key::binary>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, packet)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x06>> = response
      assert {:ok, stored} = Store.lookup("admins@techrockstars.ztlp", :group)
      assert stored.type == :group
    end

    test "rejects group registration with non-zone-authority key" do
      # Set up a zone authority (so auth is enabled)
      _root = setup_zone_authority("ztlp")

      # Enable registration auth
      original = Application.get_env(:ztlp_ns, :require_registration_auth)
      Application.put_env(:ztlp_ns, :require_registration_auth, true)

      on_exit(fn ->
        if original do
          Application.put_env(:ztlp_ns, :require_registration_auth, original)
        else
          Application.delete_env(:ztlp_ns, :require_registration_auth)
        end
      end)

      # Try to register with a random (non-zone-authority) key
      {pub, priv} = Crypto.generate_keypair()

      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "hackers@zone.ztlp"

      data = %{
        "members" => ["hacker@zone.ztlp"],
        "description" => "Unauthorized"
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      name_len = byte_size(name)
      data_len = byte_size(data_bin)
      type_byte = Record.type_to_byte(:group)

      canonical = RegistrationAuth.build_canonical(name, :group, data_bin)
      sig = Crypto.sign(canonical, priv)
      sig_len = byte_size(sig)
      pubkey_len = byte_size(pub)

      packet = <<0x09, name_len::16, name::binary, type_byte::8,
                 data_len::16, data_bin::binary, sig_len::16, sig::binary,
                 pubkey_len::16, pub::binary>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, packet)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      # Should be rejected (0xFF = invalid)
      assert <<0xFF>> = response
      assert :not_found = Store.lookup("hackers@zone.ztlp", :group)
    end
  end

  # ── Zone-Only Authorization ────────────────────────────────────────

  describe "GROUP authorization (zone-only)" do
    test "zone authority can create groups" do
      root = setup_zone_authority("ztlp")
      _pubkey_hex = Base.encode16(root.public_key, case: :lower)
      data = %{"members" => ["steve@zone.ztlp"]}
      assert :ok = RegistrationAuth.authorize(root.public_key, "admins@zone.ztlp", :group, data)
    end

    test "self-registration is denied for groups" do
      {pub, _priv} = Crypto.generate_keypair()
      data = %{"members" => ["steve@zone.ztlp"]}
      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, "admins@zone.ztlp", :group, data)
    end

    test "random key cannot create groups" do
      {pub, _priv} = Crypto.generate_keypair()
      data = %{"members" => ["steve@zone.ztlp"]}
      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, "g@zone.ztlp", :group, data)
    end
  end

  # ── Revocation Interplay ───────────────────────────────────────────

  describe "revocation" do
    test "revoked group name blocks lookup" do
      rec = make_signed_group("victim@zone.ztlp", ["a@zone.ztlp"])
      Store.insert(rec)

      {_pub, priv} = Crypto.generate_keypair()
      revoke =
        Record.new_revoke("revocations.ztlp", [], "compromised", "2026-03-10T00:00:00Z",
          serial: 1
        )

      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["victim@zone.ztlp"])}
      signed_revoke = Record.sign(revoke, priv)
      Store.insert(signed_revoke)

      assert {:error, :revoked} = Store.lookup("victim@zone.ztlp", :group)
    end

    test "revoked group means is_member? returns false" do
      rec = make_signed_group("revoked-group@zone.ztlp", ["a@zone.ztlp"])
      Store.insert(rec)

      {_pub, priv} = Crypto.generate_keypair()
      revoke =
        Record.new_revoke("revocations.ztlp", [], "compromised", "2026-03-10T00:00:00Z",
          serial: 1
        )

      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["revoked-group@zone.ztlp"])}
      signed_revoke = Record.sign(revoke, priv)
      Store.insert(signed_revoke)

      refute Store.is_member?("revoked-group@zone.ztlp", "a@zone.ztlp")
    end
  end

  # ── Backward Compatibility ─────────────────────────────────────────

  describe "backward compatibility" do
    test "existing KEY records still work after adding GROUP type" do
      rec = make_signed_key("node.ztlp")
      assert :ok = Store.insert(rec)
      assert {:ok, found} = Store.lookup("node.ztlp", :key)
      assert found.type == :key
    end

    test "KEY, DEVICE, USER, and GROUP records coexist for same name" do
      key_rec = make_signed_key("all.ztlp")
      dev_rec = make_signed_device("all.ztlp")
      user_rec = make_signed_user("all.ztlp")
      group_rec = make_signed_group("all.ztlp", ["a@zone.ztlp"])
      assert :ok = Store.insert(key_rec)
      assert :ok = Store.insert(dev_rec)
      assert :ok = Store.insert(user_rec)
      assert :ok = Store.insert(group_rec)
      assert {:ok, _} = Store.lookup("all.ztlp", :key)
      assert {:ok, _} = Store.lookup("all.ztlp", :device)
      assert {:ok, _} = Store.lookup("all.ztlp", :user)
      assert {:ok, _} = Store.lookup("all.ztlp", :group)
    end

    test "list() includes group records" do
      key_rec = make_signed_key("a.ztlp")
      group_rec = make_signed_group("b@zone.ztlp", ["c@zone.ztlp"])
      Store.insert(key_rec)
      Store.insert(group_rec)

      all = Store.list()
      types = Enum.map(all, fn {_, type, _} -> type end)
      assert :key in types
      assert :group in types
    end

    test "resolve_all includes group records" do
      group_rec = make_signed_group("multi.ztlp", ["a@zone.ztlp"])
      key_rec = make_signed_key("multi.ztlp")
      Store.insert(group_rec)
      Store.insert(key_rec)

      results = ZtlpNs.Query.resolve_all("multi.ztlp")
      types = Enum.map(results, fn {type, _} -> type end)
      assert :key in types
      assert :group in types
    end
  end

  # ── Store.clear includes group index ───────────────────────────────

  describe "Store.clear/0" do
    test "clears group records and membership index" do
      group_rec = make_signed_group("admins@zone.ztlp", ["steve@zone.ztlp"])
      Store.insert(group_rec)

      assert {:ok, _} = Store.lookup("admins@zone.ztlp", :group)
      assert Store.groups_for_user("steve@zone.ztlp") != []

      Store.clear()

      assert :not_found = Store.lookup("admins@zone.ztlp", :group)
      assert [] = Store.groups_for_user("steve@zone.ztlp")
    end
  end
end
