defmodule ZtlpNs.IdentityTest do
  @moduledoc """
  Comprehensive tests for DEVICE (0x10) and USER (0x11) record types.

  Phase 1 of the ZTLP Identity & Groups feature — tests cover:
  - Record construction and validation
  - Serialization/deserialization round-trips
  - Signing and verification
  - Wire format encode/decode
  - Store insert/lookup
  - Device-by-owner index
  - UDP server query/registration integration
  - Key overwrite protection
  - Backward compatibility with existing KEY records
  """

  use ExUnit.Case

  alias ZtlpNs.{Crypto, Record, Store, TrustAnchor, ZoneAuthority, RegistrationAuth}

  setup do
    Store.clear()
    TrustAnchor.clear()
    :ok
  end

  # ── Helpers ────────────────────────────────────────────────────────

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

  # ── Record Type Mapping ────────────────────────────────────────────

  describe "type byte mapping" do
    test "DEVICE type maps to 0x10" do
      assert Record.type_to_byte(:device) == 0x10
    end

    test "USER type maps to 0x11" do
      assert Record.type_to_byte(:user) == 0x11
    end

    test "0x10 maps back to :device" do
      assert Record.byte_to_type(0x10) == :device
    end

    test "0x11 maps back to :user" do
      assert Record.byte_to_type(0x11) == :user
    end

    test "existing types still work" do
      assert Record.type_to_byte(:key) == 1
      assert Record.byte_to_type(1) == :key
      assert Record.type_to_byte(:svc) == 2
      assert Record.type_to_byte(:operator) == 7
    end

    test "round-trips all types including new ones" do
      types = [:key, :svc, :relay, :policy, :revoke, :bootstrap, :operator, :device, :user]

      for type <- types do
        byte = Record.type_to_byte(type)
        assert Record.byte_to_type(byte) == type
      end
    end
  end

  # ── DEVICE Record Construction ─────────────────────────────────────

  describe "new_device/4" do
    test "creates a device record with correct type" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_device("laptop.ztlp", node_id, pub)
      assert rec.type == :device
      assert rec.name == "laptop.ztlp"
    end

    test "encodes node_id and pubkey as hex" do
      node_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_device("dev.ztlp", node_id, pub)
      assert rec.data[:node_id] == Base.encode16(node_id, case: :lower)
      assert rec.data[:public_key] == Base.encode16(pub, case: :lower)
    end

    test "stores owner when provided" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_device("dev.ztlp", node_id, pub, owner: "steve@techrockstars.ztlp")
      assert rec.data[:owner] == "steve@techrockstars.ztlp"
    end

    test "stores hardware_id when provided" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_device("dev.ztlp", node_id, pub, hardware_id: "SN12345")
      assert rec.data[:hardware_id] == "SN12345"
    end

    test "defaults owner and hardware_id to empty string" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_device("dev.ztlp", node_id, pub)
      assert rec.data[:owner] == ""
      assert rec.data[:hardware_id] == ""
    end

    test "defaults TTL to 86400" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_device("dev.ztlp", node_id, pub)
      assert rec.ttl == 86400
    end
  end

  # ── USER Record Construction ───────────────────────────────────────

  describe "new_user/3" do
    test "creates a user record with correct type" do
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_user("steve@techrockstars.ztlp", pub)
      assert rec.type == :user
      assert rec.name == "steve@techrockstars.ztlp"
    end

    test "encodes pubkey as hex" do
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_user("user@zone.ztlp", pub)
      assert rec.data[:public_key] == Base.encode16(pub, case: :lower)
    end

    test "stores devices list" do
      {pub, _} = Crypto.generate_keypair()
      devices = ["laptop.ztlp", "phone.ztlp"]
      rec = Record.new_user("user@zone.ztlp", pub, devices: devices)
      assert rec.data[:devices] == devices
    end

    test "stores email when provided" do
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_user("user@zone.ztlp", pub, email: "user@example.com")
      assert rec.data[:email] == "user@example.com"
    end

    test "stores role when provided" do
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_user("admin@zone.ztlp", pub, role: "admin")
      assert rec.data[:role] == "admin"
    end

    test "defaults role to user" do
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_user("user@zone.ztlp", pub)
      assert rec.data[:role] == "user"
    end

    test "defaults devices to empty list" do
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_user("user@zone.ztlp", pub)
      assert rec.data[:devices] == []
    end

    test "defaults email to empty string" do
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_user("user@zone.ztlp", pub)
      assert rec.data[:email] == ""
    end
  end

  # ── Validation ─────────────────────────────────────────────────────

  describe "validate_device/1" do
    test "accepts valid device data (atom keys)" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_device("dev.ztlp", node_id, pub)
      assert :ok = Record.validate_device(rec.data)
    end

    test "accepts valid device data (string keys)" do
      data = %{"node_id" => "abcdef0123456789", "public_key" => "deadbeef" <> String.duplicate("00", 28)}
      assert :ok = Record.validate_device(data)
    end

    test "rejects missing node_id" do
      data = %{public_key: "deadbeef"}
      assert {:error, :missing_node_id} = Record.validate_device(data)
    end

    test "rejects empty node_id" do
      data = %{node_id: "", public_key: "deadbeef"}
      assert {:error, :missing_node_id} = Record.validate_device(data)
    end

    test "rejects missing public_key" do
      data = %{node_id: "abcdef0123456789"}
      assert {:error, :missing_public_key} = Record.validate_device(data)
    end
  end

  describe "validate_user/1" do
    test "accepts valid user data" do
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_user("user@zone.ztlp", pub)
      assert :ok = Record.validate_user(rec.data)
    end

    test "rejects missing public_key" do
      data = %{role: "user"}
      assert {:error, :missing_public_key} = Record.validate_user(data)
    end

    test "rejects invalid role" do
      data = %{public_key: "deadbeef", role: "superuser"}
      assert {:error, :invalid_role} = Record.validate_user(data)
    end

    test "accepts user role" do
      data = %{public_key: "deadbeef", role: "user"}
      assert :ok = Record.validate_user(data)
    end

    test "accepts tech role" do
      data = %{public_key: "deadbeef", role: "tech"}
      assert :ok = Record.validate_user(data)
    end

    test "accepts admin role" do
      data = %{public_key: "deadbeef", role: "admin"}
      assert :ok = Record.validate_user(data)
    end

    test "accepts nil role (defaults to user)" do
      data = %{public_key: "deadbeef"}
      assert :ok = Record.validate_user(data)
    end
  end

  # ── Serialization Round-trips ──────────────────────────────────────

  describe "DEVICE serialize/deserialize" do
    test "round-trips a device record" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()

      record =
        Record.new_device("laptop.office.ztlp", node_id, pub,
          owner: "steve@techrockstars.ztlp",
          hardware_id: "SN-ABC123",
          created_at: 1000,
          ttl: 86400,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.name == "laptop.office.ztlp"
      assert restored.type == :device
      assert restored.data["node_id"] == record.data[:node_id]
      assert restored.data["public_key"] == record.data[:public_key]
      assert restored.data["owner"] == "steve@techrockstars.ztlp"
      assert restored.data["hardware_id"] == "SN-ABC123"
      assert restored.created_at == 1000
      assert restored.ttl == 86400
    end
  end

  describe "USER serialize/deserialize" do
    test "round-trips a user record" do
      {pub, _} = Crypto.generate_keypair()

      record =
        Record.new_user("steve@techrockstars.ztlp", pub,
          devices: ["laptop.ztlp", "phone.ztlp"],
          email: "steve@techrockstars.com",
          role: "admin",
          created_at: 2000,
          ttl: 86400,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.name == "steve@techrockstars.ztlp"
      assert restored.type == :user
      assert restored.data["public_key"] == record.data[:public_key]
      assert restored.data["devices"] == ["laptop.ztlp", "phone.ztlp"]
      assert restored.data["email"] == "steve@techrockstars.com"
      assert restored.data["role"] == "admin"
    end

    test "round-trips a user record with empty optional fields" do
      {pub, _} = Crypto.generate_keypair()

      record =
        Record.new_user("user@zone.ztlp", pub,
          created_at: 3000,
          ttl: 86400,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.data["devices"] == []
      assert restored.data["email"] == ""
      assert restored.data["role"] == "user"
    end
  end

  # ── Signing & Verification ─────────────────────────────────────────

  describe "DEVICE signing" do
    test "signed device record verifies" do
      rec = make_signed_device("dev.ztlp")
      assert Record.verify(rec)
    end

    test "unsigned device record does not verify" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_device("dev.ztlp", node_id, pub)
      refute Record.verify(record)
    end

    test "tampered device record does not verify" do
      rec = make_signed_device("dev.ztlp")
      tampered = %{rec | name: "hacked.ztlp"}
      refute Record.verify(tampered)
    end
  end

  describe "USER signing" do
    test "signed user record verifies" do
      rec = make_signed_user("user@zone.ztlp")
      assert Record.verify(rec)
    end

    test "unsigned user record does not verify" do
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_user("user@zone.ztlp", pub)
      refute Record.verify(record)
    end

    test "tampered user record does not verify" do
      rec = make_signed_user("user@zone.ztlp")
      tampered = %{rec | name: "hacked@zone.ztlp"}
      refute Record.verify(tampered)
    end
  end

  # ── Wire Format Encode/Decode ──────────────────────────────────────

  describe "DEVICE wire format" do
    test "round-trips via encode/decode" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {device_pub, _} = Crypto.generate_keypair()

      record =
        Record.new_device("laptop.corp.ztlp", node_id, device_pub,
          owner: "admin@corp.ztlp",
          hardware_id: "HW-001"
        )

      signed = Record.sign(record, priv)
      encoded = Record.encode(signed)
      assert {:ok, decoded} = Record.decode(encoded)

      assert decoded.name == "laptop.corp.ztlp"
      assert decoded.type == :device
      assert decoded.signature == signed.signature
      assert decoded.signer_public_key == signed.signer_public_key
      assert Record.verify(decoded)
    end
  end

  describe "USER wire format" do
    test "round-trips via encode/decode" do
      {pub, priv} = Crypto.generate_keypair()

      record =
        Record.new_user("steve@corp.ztlp", pub,
          devices: ["laptop.corp.ztlp"],
          email: "steve@example.com",
          role: "admin"
        )

      signed = Record.sign(record, priv)
      encoded = Record.encode(signed)
      assert {:ok, decoded} = Record.decode(encoded)

      assert decoded.name == "steve@corp.ztlp"
      assert decoded.type == :user
      assert Record.verify(decoded)
    end
  end

  # ── Store Insert/Lookup ────────────────────────────────────────────

  describe "Store: DEVICE records" do
    test "inserts and looks up a device record" do
      rec = make_signed_device("laptop.ztlp")
      assert :ok = Store.insert(rec)
      assert {:ok, found} = Store.lookup("laptop.ztlp", :device)
      assert found.name == "laptop.ztlp"
      assert found.type == :device
    end

    test "rejects unsigned device record" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_device("dev.ztlp", node_id, pub)
      assert {:error, :invalid_signature} = Store.insert(record)
    end

    test "device lookup returns :not_found for missing record" do
      assert :not_found = Store.lookup("missing.ztlp", :device)
    end

    test "device lookup does not conflict with key record on same name" do
      key_rec = make_signed_key("node.ztlp")
      dev_rec = make_signed_device("node.ztlp")
      assert :ok = Store.insert(key_rec)
      assert :ok = Store.insert(dev_rec)
      assert {:ok, key_found} = Store.lookup("node.ztlp", :key)
      assert {:ok, dev_found} = Store.lookup("node.ztlp", :device)
      assert key_found.type == :key
      assert dev_found.type == :device
    end

    test "stale serial is rejected for device records" do
      rec1 = make_signed_device("dev.ztlp", serial: 5)
      rec2 = make_signed_device("dev.ztlp", serial: 3)
      assert :ok = Store.insert(rec1)
      assert {:error, :stale_serial} = Store.insert(rec2)
    end
  end

  describe "Store: USER records" do
    test "inserts and looks up a user record" do
      rec = make_signed_user("steve@zone.ztlp")
      assert :ok = Store.insert(rec)
      assert {:ok, found} = Store.lookup("steve@zone.ztlp", :user)
      assert found.name == "steve@zone.ztlp"
      assert found.type == :user
    end

    test "rejects unsigned user record" do
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_user("user@zone.ztlp", pub)
      assert {:error, :invalid_signature} = Store.insert(record)
    end

    test "user lookup does not conflict with key record on same name" do
      key_rec = make_signed_key("entity.ztlp")
      user_rec = make_signed_user("entity.ztlp")
      assert :ok = Store.insert(key_rec)
      assert :ok = Store.insert(user_rec)
      assert {:ok, key_found} = Store.lookup("entity.ztlp", :key)
      assert {:ok, user_found} = Store.lookup("entity.ztlp", :user)
      assert key_found.type == :key
      assert user_found.type == :user
    end
  end

  # ── Device-by-Owner Index ──────────────────────────────────────────

  describe "device-by-owner index" do
    test "lookup_devices_for_user returns linked devices" do
      rec = make_signed_device("laptop.ztlp", owner: "steve@zone.ztlp")
      assert :ok = Store.insert(rec)

      devices = Store.lookup_devices_for_user("steve@zone.ztlp")
      assert "laptop.ztlp" in devices
    end

    test "lookup_devices_for_user returns multiple devices" do
      rec1 = make_signed_device("laptop.ztlp", owner: "steve@zone.ztlp")
      rec2 = make_signed_device("phone.ztlp", owner: "steve@zone.ztlp")
      assert :ok = Store.insert(rec1)
      assert :ok = Store.insert(rec2)

      devices = Store.lookup_devices_for_user("steve@zone.ztlp")
      assert length(devices) == 2
      assert "laptop.ztlp" in devices
      assert "phone.ztlp" in devices
    end

    test "lookup_devices_for_user returns empty list for unknown user" do
      assert [] = Store.lookup_devices_for_user("unknown@zone.ztlp")
    end

    test "device without owner is not indexed" do
      rec = make_signed_device("unowned.ztlp")
      assert :ok = Store.insert(rec)
      assert [] = Store.lookup_devices_for_user("")
    end

    test "lookup_user_for_device returns owner" do
      rec = make_signed_device("laptop.ztlp", owner: "steve@zone.ztlp")
      assert :ok = Store.insert(rec)
      assert {:ok, "steve@zone.ztlp"} = Store.lookup_user_for_device("laptop.ztlp")
    end

    test "lookup_user_for_device returns :not_found for unowned device" do
      rec = make_signed_device("unowned.ztlp")
      assert :ok = Store.insert(rec)
      assert :not_found = Store.lookup_user_for_device("unowned.ztlp")
    end

    test "lookup_user_for_device returns :not_found for missing device" do
      assert :not_found = Store.lookup_user_for_device("nonexistent.ztlp")
    end

    test "different owners have separate device lists" do
      rec1 = make_signed_device("laptop.ztlp", owner: "alice@zone.ztlp")
      rec2 = make_signed_device("phone.ztlp", owner: "bob@zone.ztlp")
      assert :ok = Store.insert(rec1)
      assert :ok = Store.insert(rec2)

      alice_devices = Store.lookup_devices_for_user("alice@zone.ztlp")
      bob_devices = Store.lookup_devices_for_user("bob@zone.ztlp")

      assert alice_devices == ["laptop.ztlp"]
      assert bob_devices == ["phone.ztlp"]
    end
  end

  # ── TTL and Expiration ─────────────────────────────────────────────

  describe "expiration" do
    test "expired device record is not returned" do
      rec = make_signed_device("old.ztlp", created_at: 0, ttl: 1)
      assert :ok = Store.insert(rec)
      assert :not_found = Store.lookup("old.ztlp", :device)
    end

    test "expired user record is not returned" do
      rec = make_signed_user("old@zone.ztlp", created_at: 0, ttl: 1)
      assert :ok = Store.insert(rec)
      assert :not_found = Store.lookup("old@zone.ztlp", :user)
    end

    test "device record with long TTL is not expired" do
      rec = make_signed_device("fresh.ztlp")
      refute Record.expired?(rec)
    end

    test "user record with long TTL is not expired" do
      rec = make_signed_user("fresh@zone.ztlp")
      refute Record.expired?(rec)
    end
  end

  # ── UDP Server Integration ─────────────────────────────────────────

  describe "UDP server: DEVICE queries" do
    test "query for device record returns it" do
      rec = make_signed_device("laptop.office.ztlp")
      Store.insert(rec)

      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      # Build query: 0x01, name_len::16, name, type_byte
      name = "laptop.office.ztlp"
      name_len = byte_size(name)
      type_byte = Record.type_to_byte(:device)
      query = <<0x01, name_len::16, name::binary, type_byte::8>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, query)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      # Response should start with 0x02 (record found)
      assert <<0x02, _rest::binary>> = response
    end

    test "query for missing device record returns not-found" do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "missing.ztlp"
      name_len = byte_size(name)
      type_byte = Record.type_to_byte(:device)
      query = <<0x01, name_len::16, name::binary, type_byte::8>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, query)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      # Response should start with 0x03 (not found)
      assert <<0x03, _rest::binary>> = response
    end
  end

  describe "UDP server: USER queries" do
    test "query for user record returns it" do
      rec = make_signed_user("steve@corp.ztlp")
      Store.insert(rec)

      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "steve@corp.ztlp"
      name_len = byte_size(name)
      type_byte = Record.type_to_byte(:user)
      query = <<0x01, name_len::16, name::binary, type_byte::8>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, query)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x02, _rest::binary>> = response
    end

    test "query for missing user record returns not-found" do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "nobody@zone.ztlp"
      name_len = byte_size(name)
      type_byte = Record.type_to_byte(:user)
      query = <<0x01, name_len::16, name::binary, type_byte::8>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, query)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x03, _rest::binary>> = response
    end
  end

  describe "UDP server: DEVICE registration (unsigned/dev mode)" do
    setup do
      # Enable dev mode for unsigned registration tests
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

    test "registers a device via unsigned registration" do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "newdev.ztlp"
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()

      data = %{
        "node_id" => Base.encode16(node_id, case: :lower),
        "public_key" => Base.encode16(pub, case: :lower),
        "owner" => "",
        "hardware_id" => ""
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      name_len = byte_size(name)
      data_len = byte_size(data_bin)
      type_byte = Record.type_to_byte(:device)

      # Dummy signature for unsigned registration
      dummy_sig = :crypto.strong_rand_bytes(64)
      sig_len = byte_size(dummy_sig)

      packet = <<0x09, name_len::16, name::binary, type_byte::8,
                 data_len::16, data_bin::binary, sig_len::16, dummy_sig::binary>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, packet)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      # Should get ACK (0x06)
      assert <<0x06>> = response

      # Verify the record was stored
      assert {:ok, stored} = Store.lookup("newdev.ztlp", :device)
      assert stored.type == :device
    end

    test "registers a user via unsigned registration" do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "newuser@zone.ztlp"
      {pub, _} = Crypto.generate_keypair()

      data = %{
        "public_key" => Base.encode16(pub, case: :lower),
        "devices" => [],
        "email" => "user@example.com",
        "role" => "user"
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      name_len = byte_size(name)
      data_len = byte_size(data_bin)
      type_byte = Record.type_to_byte(:user)

      dummy_sig = :crypto.strong_rand_bytes(64)
      sig_len = byte_size(dummy_sig)

      packet = <<0x09, name_len::16, name::binary, type_byte::8,
                 data_len::16, data_bin::binary, sig_len::16, dummy_sig::binary>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, packet)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x06>> = response

      assert {:ok, stored} = Store.lookup("newuser@zone.ztlp", :user)
      assert stored.type == :user
    end
  end

  # ── Key Overwrite Protection ───────────────────────────────────────

  describe "key overwrite protection" do
    test "check_key_overwrite allows first registration" do
      {pub, _priv} = Crypto.generate_keypair()
      data = %{"public_key" => Base.encode16(pub, case: :lower)}
      assert :ok = RegistrationAuth.check_key_overwrite(pub, "dev.ztlp", :device, data)
    end

    test "check_key_overwrite allows same-key update" do
      # Register a device first
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {device_pub, _} = Crypto.generate_keypair()

      record = Record.new_device("dev.ztlp", node_id, device_pub, serial: 1)
      signed = Record.sign(record, priv)
      Store.insert(signed)

      # Same pubkey should be allowed
      pubkey_hex = Base.encode16(device_pub, case: :lower)
      data = %{"public_key" => pubkey_hex}
      assert :ok = RegistrationAuth.check_key_overwrite(device_pub, "dev.ztlp", :device, data)
    end

    test "check_key_overwrite rejects different-key overwrite" do
      # Register a device first
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {device_pub, _} = Crypto.generate_keypair()

      record = Record.new_device("dev.ztlp", node_id, device_pub, serial: 1)
      signed = Record.sign(record, priv)
      Store.insert(signed)

      # Different pubkey should be rejected (no zone authority)
      {new_pub, _} = Crypto.generate_keypair()
      new_pubkey_hex = Base.encode16(new_pub, case: :lower)
      data = %{"public_key" => new_pubkey_hex}
      assert {:error, :key_overwrite_rejected} = RegistrationAuth.check_key_overwrite(new_pub, "dev.ztlp", :device, data)
    end

    test "check_key_overwrite skips for non-device/user types" do
      {pub, _} = Crypto.generate_keypair()
      data = %{"public_key" => Base.encode16(pub, case: :lower)}
      assert :ok = RegistrationAuth.check_key_overwrite(pub, "key.ztlp", :key, data)
    end

    test "check_key_overwrite works for user records" do
      # Register a user first
      {pub, priv} = Crypto.generate_keypair()

      record = Record.new_user("user@zone.ztlp", pub, serial: 1)
      signed = Record.sign(record, priv)
      Store.insert(signed)

      # Different key should be rejected
      {new_pub, _} = Crypto.generate_keypair()
      new_data = %{"public_key" => Base.encode16(new_pub, case: :lower)}
      assert {:error, :key_overwrite_rejected} = RegistrationAuth.check_key_overwrite(new_pub, "user@zone.ztlp", :user, new_data)
    end

    test "zone authority can overwrite different key" do
      # Set up a zone authority
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("root", root.public_key)

      # Create delegation record for zone authority
      delegation = %Record{
        name: "ztlp",
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

      # Register a device
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {device_pub, _} = Crypto.generate_keypair()
      record = Record.new_device("dev.ztlp", node_id, device_pub, serial: 1)
      signed = Record.sign(record, priv)
      Store.insert(signed)

      # Zone authority should be able to overwrite with different key
      {new_pub, _} = Crypto.generate_keypair()
      new_data = %{"public_key" => Base.encode16(new_pub, case: :lower)}
      assert :ok = RegistrationAuth.check_key_overwrite(root.public_key, "dev.ztlp", :device, new_data)
    end
  end

  # ── Self-Registration Auth ────────────────────────────────────────

  describe "DEVICE self-registration authorization" do
    test "device can self-register with matching pubkey" do
      {pub, _} = Crypto.generate_keypair()
      pubkey_hex = Base.encode16(pub, case: :lower)
      data = %{"public_key" => pubkey_hex}
      assert :ok = RegistrationAuth.authorize(pub, "dev.ztlp", :device, data)
    end

    test "device cannot self-register with non-matching pubkey" do
      {pub, _} = Crypto.generate_keypair()
      {other_pub, _} = Crypto.generate_keypair()
      data = %{"public_key" => Base.encode16(other_pub, case: :lower)}
      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, "dev.ztlp", :device, data)
    end
  end

  describe "USER self-registration authorization" do
    test "user can self-register with matching pubkey" do
      {pub, _} = Crypto.generate_keypair()
      pubkey_hex = Base.encode16(pub, case: :lower)
      data = %{"public_key" => pubkey_hex}
      assert :ok = RegistrationAuth.authorize(pub, "user@zone.ztlp", :user, data)
    end

    test "user cannot self-register with non-matching pubkey" do
      {pub, _} = Crypto.generate_keypair()
      {other_pub, _} = Crypto.generate_keypair()
      data = %{"public_key" => Base.encode16(other_pub, case: :lower)}
      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, "user@zone.ztlp", :user, data)
    end
  end

  # ── Backward Compatibility ─────────────────────────────────────────

  describe "backward compatibility" do
    test "existing KEY records still work after adding DEVICE/USER types" do
      rec = make_signed_key("node.ztlp")
      assert :ok = Store.insert(rec)
      assert {:ok, found} = Store.lookup("node.ztlp", :key)
      assert found.type == :key
    end

    test "KEY and DEVICE records coexist for same name" do
      key_rec = make_signed_key("shared.ztlp")
      dev_rec = make_signed_device("shared.ztlp")
      assert :ok = Store.insert(key_rec)
      assert :ok = Store.insert(dev_rec)
      assert {:ok, _} = Store.lookup("shared.ztlp", :key)
      assert {:ok, _} = Store.lookup("shared.ztlp", :device)
    end

    test "KEY and USER records coexist for same name" do
      key_rec = make_signed_key("entity.ztlp")
      user_rec = make_signed_user("entity.ztlp")
      assert :ok = Store.insert(key_rec)
      assert :ok = Store.insert(user_rec)
      assert {:ok, _} = Store.lookup("entity.ztlp", :key)
      assert {:ok, _} = Store.lookup("entity.ztlp", :user)
    end

    test "DEVICE, USER, and KEY records all coexist" do
      key_rec = make_signed_key("all.ztlp")
      dev_rec = make_signed_device("all.ztlp")
      user_rec = make_signed_user("all.ztlp")
      assert :ok = Store.insert(key_rec)
      assert :ok = Store.insert(dev_rec)
      assert :ok = Store.insert(user_rec)
      assert {:ok, _} = Store.lookup("all.ztlp", :key)
      assert {:ok, _} = Store.lookup("all.ztlp", :device)
      assert {:ok, _} = Store.lookup("all.ztlp", :user)
    end

    test "list() includes device and user records" do
      key_rec = make_signed_key("a.ztlp")
      dev_rec = make_signed_device("b.ztlp")
      user_rec = make_signed_user("c@zone.ztlp")
      Store.insert(key_rec)
      Store.insert(dev_rec)
      Store.insert(user_rec)

      all = Store.list()
      types = Enum.map(all, fn {_, type, _} -> type end)
      assert :key in types
      assert :device in types
      assert :user in types
    end

    test "resolve_all includes device and user records" do
      dev_rec = make_signed_device("multi.ztlp")
      key_rec = make_signed_key("multi.ztlp")
      Store.insert(dev_rec)
      Store.insert(key_rec)

      results = ZtlpNs.Query.resolve_all("multi.ztlp")
      types = Enum.map(results, fn {type, _} -> type end)
      assert :key in types
      assert :device in types
    end
  end

  # ── Revocation Interplay ───────────────────────────────────────────

  describe "revocation" do
    test "revoked device name blocks lookup" do
      rec = make_signed_device("victim-dev.ztlp")
      Store.insert(rec)

      # Create revocation
      {_pub, priv} = Crypto.generate_keypair()
      revoke =
        Record.new_revoke("revocations.ztlp", [], "compromised", "2026-03-10T00:00:00Z",
          serial: 1
        )

      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["victim-dev.ztlp"])}
      signed_revoke = Record.sign(revoke, priv)
      Store.insert(signed_revoke)

      assert {:error, :revoked} = Store.lookup("victim-dev.ztlp", :device)
    end

    test "revoked user name blocks lookup" do
      rec = make_signed_user("victim@zone.ztlp")
      Store.insert(rec)

      {_pub, priv} = Crypto.generate_keypair()
      revoke =
        Record.new_revoke("revocations.ztlp", [], "compromised", "2026-03-10T00:00:00Z",
          serial: 1
        )

      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["victim@zone.ztlp"])}
      signed_revoke = Record.sign(revoke, priv)
      Store.insert(signed_revoke)

      assert {:error, :revoked} = Store.lookup("victim@zone.ztlp", :user)
    end
  end

  # ── Authenticated Registration (with pubkey) ───────────────────────

  describe "UDP server: authenticated device registration" do
    test "registers a device with valid signature" do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "authdev.ztlp"
      {pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)

      data = %{
        "node_id" => Base.encode16(node_id, case: :lower),
        "public_key" => Base.encode16(pub, case: :lower),
        "owner" => "",
        "hardware_id" => ""
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      name_len = byte_size(name)
      data_len = byte_size(data_bin)
      type_byte = Record.type_to_byte(:device)

      # Build canonical form: type_byte + name_len::16 + name + data_bin
      canonical = RegistrationAuth.build_canonical(name, :device, data_bin)
      sig = Crypto.sign(canonical, priv)
      sig_len = byte_size(sig)
      pubkey_len = byte_size(pub)

      # v2 registration with pubkey
      packet = <<0x09, name_len::16, name::binary, type_byte::8,
                 data_len::16, data_bin::binary, sig_len::16, sig::binary,
                 pubkey_len::16, pub::binary>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, packet)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x06>> = response
      assert {:ok, stored} = Store.lookup("authdev.ztlp", :device)
      assert stored.type == :device
    end

    test "registers a user with valid signature" do
      port = ZtlpNs.Server.port()
      {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "authuser@corp.ztlp"
      {pub, priv} = Crypto.generate_keypair()

      data = %{
        "public_key" => Base.encode16(pub, case: :lower),
        "devices" => [],
        "email" => "",
        "role" => "admin"
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      name_len = byte_size(name)
      data_len = byte_size(data_bin)
      type_byte = Record.type_to_byte(:user)

      canonical = RegistrationAuth.build_canonical(name, :user, data_bin)
      sig = Crypto.sign(canonical, priv)
      sig_len = byte_size(sig)
      pubkey_len = byte_size(pub)

      packet = <<0x09, name_len::16, name::binary, type_byte::8,
                 data_len::16, data_bin::binary, sig_len::16, sig::binary,
                 pubkey_len::16, pub::binary>>

      :gen_udp.send(socket, ~c"127.0.0.1", port, packet)
      {:ok, {_, _, response}} = :gen_udp.recv(socket, 0, 5000)
      :gen_udp.close(socket)

      assert <<0x06>> = response
      assert {:ok, stored} = Store.lookup("authuser@corp.ztlp", :user)
      assert stored.type == :user
    end
  end

  # ── Record Update (serial increment) ──────────────────────────────

  describe "record updates via serial increment" do
    test "device record can be updated with higher serial" do
      rec1 = make_signed_device("updateable.ztlp", serial: 1, owner: "alice@zone.ztlp")
      assert :ok = Store.insert(rec1)

      rec2 = make_signed_device("updateable.ztlp", serial: 2, owner: "bob@zone.ztlp")
      assert :ok = Store.insert(rec2)

      {:ok, found} = Store.lookup("updateable.ztlp", :device)
      assert found.serial == 2
    end

    test "user record can be updated with higher serial" do
      rec1 = make_signed_user("upduser@zone.ztlp", serial: 1, role: "user")
      assert :ok = Store.insert(rec1)

      rec2 = make_signed_user("upduser@zone.ztlp", serial: 2, role: "admin")
      assert :ok = Store.insert(rec2)

      {:ok, found} = Store.lookup("upduser@zone.ztlp", :user)
      assert found.serial == 2
    end
  end

  # ── Store.clear includes new tables ────────────────────────────────

  describe "Store.clear/0" do
    test "clears device and user records" do
      dev_rec = make_signed_device("dev.ztlp", owner: "owner@zone.ztlp")
      user_rec = make_signed_user("user@zone.ztlp")
      Store.insert(dev_rec)
      Store.insert(user_rec)

      assert {:ok, _} = Store.lookup("dev.ztlp", :device)
      assert {:ok, _} = Store.lookup("user@zone.ztlp", :user)
      assert Store.lookup_devices_for_user("owner@zone.ztlp") != []

      Store.clear()

      assert :not_found = Store.lookup("dev.ztlp", :device)
      assert :not_found = Store.lookup("user@zone.ztlp", :user)
      assert [] = Store.lookup_devices_for_user("owner@zone.ztlp")
    end
  end
end
