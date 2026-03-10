defmodule ZtlpNs.StoreTest do
  use ExUnit.Case

  alias ZtlpNs.{Crypto, Record, Store}

  # Store uses ETS tables owned by the Store GenServer, so tests
  # must run sequentially (not async) and clean up after themselves.

  setup do
    Store.clear()
    :ok
  end

  defp make_signed_key(name, opts \\ []) do
    {_pub, priv} = Crypto.generate_keypair()
    node_id = :crypto.strong_rand_bytes(16)
    {node_pub, _} = Crypto.generate_keypair()
    serial = opts[:serial] || 1
    record = Record.new_key(name, node_id, node_pub,
      created_at: System.system_time(:second),
      ttl: opts[:ttl] || 86400,
      serial: serial)
    Record.sign(record, priv)
  end

  describe "insert/1" do
    test "accepts a valid signed record" do
      rec = make_signed_key("node1.acme.ztlp")
      assert :ok = Store.insert(rec)
    end

    test "rejects unsigned record" do
      node_id = :crypto.strong_rand_bytes(16)
      {pub, _} = Crypto.generate_keypair()
      record = Record.new_key("test.ztlp", node_id, pub)
      assert {:error, :invalid_signature} = Store.insert(record)
    end

    test "rejects record with tampered data" do
      rec = make_signed_key("node1.ztlp")
      tampered = %{rec | name: "hacked.ztlp"}
      assert {:error, :invalid_signature} = Store.insert(tampered)
    end

    test "rejects stale serial number" do
      rec1 = make_signed_key("node.ztlp", serial: 5)
      rec2 = make_signed_key("node.ztlp", serial: 3)
      assert :ok = Store.insert(rec1)
      assert {:error, :stale_serial} = Store.insert(rec2)
    end

    test "accepts higher serial number (record update)" do
      rec1 = make_signed_key("node.ztlp", serial: 1)
      assert :ok = Store.insert(rec1)

      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      rec2 = Record.new_key("node.ztlp", node_id, node_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 2)
      rec2 = Record.sign(rec2, priv)
      assert :ok = Store.insert(rec2)
    end
  end

  describe "lookup/2" do
    test "finds an inserted record" do
      rec = make_signed_key("found.ztlp")
      Store.insert(rec)
      assert {:ok, found} = Store.lookup("found.ztlp", :key)
      assert found.name == "found.ztlp"
    end

    test "returns :not_found for missing record" do
      assert :not_found = Store.lookup("missing.ztlp", :key)
    end

    test "returns :not_found for wrong type" do
      rec = make_signed_key("node.ztlp")
      Store.insert(rec)
      assert :not_found = Store.lookup("node.ztlp", :relay)
    end

    test "returns {:error, :revoked} for revoked node" do
      # Insert a key record
      rec = make_signed_key("victim.ztlp")
      Store.insert(rec)

      # Insert a revocation for the same name
      {_pub, priv} = Crypto.generate_keypair()
      revoke = Record.new_revoke("revoke.ztlp", [], "compromised", "2026-03-10T00:00:00Z",
        created_at: System.system_time(:second), ttl: 0, serial: 1)
      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["victim.ztlp"])}
      revoke = Record.sign(revoke, priv)
      Store.insert(revoke)

      # Lookup should be blocked
      assert {:error, :revoked} = Store.lookup("victim.ztlp", :key)
    end

    test "does not return expired records" do
      _rec = make_signed_key("expired.ztlp", ttl: 1)
      # Can't backdate an already-signed record (would break signature).
      # Instead create a fresh record with created_at: 0 and ttl: 1.
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      expired = Record.new_key("expired.ztlp", node_id, node_pub,
        created_at: 0, ttl: 1, serial: 1)
      expired = Record.sign(expired, priv)
      Store.insert(expired)
      assert :not_found = Store.lookup("expired.ztlp", :key)
    end
  end

  describe "list/0 and count/0" do
    test "empty store" do
      assert Store.list() == []
      assert Store.count() == 0
    end

    test "lists inserted records" do
      rec1 = make_signed_key("a.ztlp")
      rec2 = make_signed_key("b.ztlp")
      Store.insert(rec1)
      Store.insert(rec2)
      assert Store.count() == 2
      assert length(Store.list()) == 2
    end
  end

  describe "revocation" do
    test "revoked? returns false for unknown ID" do
      refute Store.revoked?("unknown")
    end

    test "revoked? returns true after inserting ZTLP_REVOKE" do
      {_pub, priv} = Crypto.generate_keypair()
      revoke = Record.new_revoke("revoke.ztlp", [], "test", "2026-01-01T00:00:00Z",
        created_at: System.system_time(:second), ttl: 0, serial: 1)
      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["bad-node-1234"])}
      revoke = Record.sign(revoke, priv)
      Store.insert(revoke)
      assert Store.revoked?("bad-node-1234")
    end

    test "list_revoked returns revoked IDs" do
      {_pub, priv} = Crypto.generate_keypair()
      revoke = Record.new_revoke("revoke.ztlp", [], "test", "2026-01-01T00:00:00Z",
        created_at: System.system_time(:second), ttl: 0, serial: 1)
      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["id-a", "id-b"])}
      revoke = Record.sign(revoke, priv)
      Store.insert(revoke)
      revoked = Store.list_revoked()
      assert "id-a" in revoked
      assert "id-b" in revoked
    end
  end

  describe "clear/0" do
    test "removes all records and revocations" do
      rec = make_signed_key("test.ztlp")
      Store.insert(rec)
      assert Store.count() > 0
      Store.clear()
      assert Store.count() == 0
      assert Store.list_revoked() == []
    end
  end
end
