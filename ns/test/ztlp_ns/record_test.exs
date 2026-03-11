defmodule ZtlpNs.RecordTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.{Crypto, Record}

  # Helper: create and sign a basic KEY record
  defp signed_key_record(priv_key) do
    node_id = :crypto.strong_rand_bytes(16)
    {pub, _} = Crypto.generate_keypair()
    record = Record.new_key("node1.acme.ztlp", node_id, pub, ttl: 3600, serial: 1)
    Record.sign(record, priv_key)
  end

  describe "type_to_byte/1 and byte_to_type/1" do
    test "round-trips all 6 types" do
      types = [:key, :svc, :relay, :policy, :revoke, :bootstrap]

      for type <- types do
        byte = Record.type_to_byte(type)
        assert Record.byte_to_type(byte) == type
      end
    end

    test "type bytes are 1-6" do
      assert Record.type_to_byte(:key) == 1
      assert Record.type_to_byte(:svc) == 2
      assert Record.type_to_byte(:relay) == 3
      assert Record.type_to_byte(:policy) == 4
      assert Record.type_to_byte(:revoke) == 5
      assert Record.type_to_byte(:bootstrap) == 6
    end
  end

  describe "serialize/1 and deserialize/1" do
    test "round-trips a KEY record" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()

      record =
        Record.new_key("node1.acme.ztlp", node_id, pub, created_at: 1000, ttl: 3600, serial: 1)

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.name == "node1.acme.ztlp"
      assert restored.type == :key
      assert restored.data == record.data
      assert restored.created_at == 1000
      assert restored.ttl == 3600
      assert restored.serial == 1
    end

    test "round-trips a SVC record" do
      svc_id = :crypto.strong_rand_bytes(16)
      nid = :crypto.strong_rand_bytes(16)

      record =
        Record.new_svc("rdp.acme.ztlp", svc_id, [nid], "policy.acme.ztlp",
          created_at: 2000,
          ttl: 7200,
          serial: 5
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.type == :svc
      assert restored.data["policy_ref"] || restored.data[:policy_ref] == "policy.acme.ztlp"
    end

    test "round-trips a RELAY record" do
      nid = :crypto.strong_rand_bytes(16)

      record =
        Record.new_relay(
          "relay1.apac.ztlp",
          nid,
          ["192.168.1.1:23095", "[::1]:23095"],
          5000,
          "apac",
          created_at: 3000,
          ttl: 3600,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.type == :relay
      assert restored.data[:endpoints] == ["192.168.1.1:23095", "[::1]:23095"]
    end

    test "round-trips a POLICY record" do
      nid = :crypto.strong_rand_bytes(16)

      record =
        Record.new_policy("policy.acme.ztlp", [nid], ["rdp", "ssh"], [],
          created_at: 4000,
          ttl: 3600,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.type == :policy
    end

    test "round-trips a REVOKE record" do
      nid = :crypto.strong_rand_bytes(16)

      record =
        Record.new_revoke("revoke.acme.ztlp", [nid], "compromised", "2026-03-10T00:00:00Z",
          created_at: 5000,
          ttl: 0,
          serial: 1
        )

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.type == :revoke
      assert restored.ttl == 0
    end

    test "round-trips a BOOTSTRAP record" do
      relays = [%{node_id: "aabbccdd", endpoints: ["1.2.3.4:23095"], public_key: "deadbeef"}]

      record =
        Record.new_bootstrap("bootstrap.ztlp", relays, created_at: 6000, ttl: 86400, serial: 1)

      bin = Record.serialize(record)
      assert {:ok, restored} = Record.deserialize(bin)
      assert restored.type == :bootstrap
    end

    test "deserialize rejects garbage" do
      assert {:error, :invalid_binary} = Record.deserialize(<<0xFF, 0xFF>>)
      assert {:error, :invalid_binary} = Record.deserialize(<<>>)
    end

    test "serialize is deterministic" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("test.ztlp", node_id, pub, created_at: 100, ttl: 60, serial: 1)
      assert Record.serialize(record) == Record.serialize(record)
    end
  end

  describe "sign/2 and verify/1" do
    test "signed record verifies" do
      {_pub, priv} = Crypto.generate_keypair()
      record = signed_key_record(priv)
      assert Record.verify(record)
    end

    test "unsigned record does not verify" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("test.ztlp", node_id, pub)
      refute Record.verify(record)
    end

    test "record with nil signature does not verify" do
      {_pub, priv} = Crypto.generate_keypair()
      record = signed_key_record(priv)
      refute Record.verify(%{record | signature: nil})
    end

    test "record with nil public key does not verify" do
      {_pub, priv} = Crypto.generate_keypair()
      record = signed_key_record(priv)
      refute Record.verify(%{record | signer_public_key: nil})
    end

    test "tampered record does not verify" do
      {_pub, priv} = Crypto.generate_keypair()
      record = signed_key_record(priv)
      tampered = %{record | name: "tampered.ztlp"}
      refute Record.verify(tampered)
    end

    test "sign attaches correct public key" do
      {pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      record = Record.new_key("test.ztlp", node_id, pub)
      signed = Record.sign(record, priv)
      assert signed.signer_public_key == pub
    end
  end

  describe "encode/1 and decode/1" do
    test "round-trips a signed record" do
      {_pub, priv} = Crypto.generate_keypair()
      record = signed_key_record(priv)

      encoded = Record.encode(record)
      assert {:ok, decoded} = Record.decode(encoded)

      assert decoded.name == record.name
      assert decoded.type == record.type
      assert decoded.data == record.data
      assert decoded.signature == record.signature
      assert decoded.signer_public_key == record.signer_public_key
    end

    test "decoded record still verifies" do
      {_pub, priv} = Crypto.generate_keypair()
      record = signed_key_record(priv)

      {:ok, decoded} = Record.decode(Record.encode(record))
      assert Record.verify(decoded)
    end

    test "decode rejects garbage" do
      assert {:error, :invalid_wire_format} = Record.decode(<<0xFF>>)
    end
  end

  describe "expired?/1" do
    test "record with TTL 0 never expires" do
      record =
        Record.new_revoke("test.ztlp", [], "test", "2026-01-01T00:00:00Z",
          created_at: 0,
          ttl: 0,
          serial: 1
        )

      refute Record.expired?(record)
    end

    test "record created far in the past is expired" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("test.ztlp", node_id, pub, created_at: 0, ttl: 1, serial: 1)
      assert Record.expired?(record)
    end

    test "record created now with long TTL is not expired" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      now = System.system_time(:second)
      record = Record.new_key("test.ztlp", node_id, pub, created_at: now, ttl: 86400, serial: 1)
      refute Record.expired?(record)
    end
  end

  describe "convenience constructors" do
    test "new_key sets correct type and data fields" do
      nid = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      {pub, _} = Crypto.generate_keypair()
      rec = Record.new_key("n.ztlp", nid, pub)
      assert rec.type == :key
      assert rec.data[:node_id] == Base.encode16(nid, case: :lower)
      assert rec.data[:algorithm] == "Ed25519"
    end

    test "new_relay sets endpoints and capacity" do
      nid = :crypto.strong_rand_bytes(16)
      rec = Record.new_relay("r.ztlp", nid, ["1.2.3.4:23095"], 1000, "us-west")
      assert rec.data[:endpoints] == ["1.2.3.4:23095"]
      assert rec.data[:capacity] == 1000
      assert rec.data[:region] == "us-west"
    end

    test "new_revoke defaults TTL to 0" do
      rec = Record.new_revoke("rev.ztlp", [], "test", "2026-01-01T00:00:00Z")
      assert rec.ttl == 0
    end
  end
end
