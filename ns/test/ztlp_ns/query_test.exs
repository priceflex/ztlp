defmodule ZtlpNs.QueryTest do
  use ExUnit.Case

  alias ZtlpNs.{Crypto, Record, Store, TrustAnchor, Query, ZoneAuthority}

  # Query depends on Store + TrustAnchor ETS tables
  setup do
    Store.clear()
    TrustAnchor.clear()
    :ok
  end

  describe "lookup/2 (simple)" do
    test "returns record with valid signature" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      rec = Record.new_key("node.ztlp", node_id, node_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      rec = Record.sign(rec, priv)
      Store.insert(rec)

      assert {:ok, found} = Query.lookup("node.ztlp", :key)
      assert found.name == "node.ztlp"
    end

    test "returns :not_found for missing record" do
      assert :not_found = Query.lookup("missing.ztlp", :key)
    end

    test "returns {:error, :revoked} for revoked name" do
      # Insert a record
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      rec = Record.new_key("victim.ztlp", node_id, node_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      rec = Record.sign(rec, priv)
      Store.insert(rec)

      # Revoke it
      revoke = Record.new_revoke("revoke.ztlp", [], "test", "2026-01-01T00:00:00Z",
        created_at: System.system_time(:second), ttl: 0, serial: 1)
      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["victim.ztlp"])}
      revoke = Record.sign(revoke, priv)
      Store.insert(revoke)

      assert {:error, :revoked} = Query.lookup("victim.ztlp", :key)
    end
  end

  describe "lookup_verified/2 (trust chain)" do
    test "verifies full chain from root → zone → record" do
      # Set up trust chain: root → operator → record
      root = ZoneAuthority.generate("ztlp")
      operator = ZoneAuthority.generate("example.ztlp")

      # Add root as trust anchor
      TrustAnchor.add("root", root.public_key)

      # Root delegates to operator
      delegation = ZoneAuthority.delegate(root, operator)
      Store.insert(delegation)

      # Operator signs a node record
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      record = Record.new_key("node1.example.ztlp", node_id, node_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(operator, record)
      Store.insert(signed)

      # Verified lookup should succeed
      assert {:ok, found} = Query.lookup_verified("node1.example.ztlp", :key)
      assert found.name == "node1.example.ztlp"
    end

    test "rejects record with no chain to root" do
      # Sign a record with a random key (not chained to any trust anchor)
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      record = Record.new_key("unverified.ztlp", node_id, node_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      record = Record.sign(record, priv)
      Store.insert(record)

      assert {:error, :untrusted_chain} = Query.lookup_verified("unverified.ztlp", :key)
    end

    test "accepts record signed directly by root anchor" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("root", root.public_key)

      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      record = Record.new_key("direct.ztlp", node_id, node_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, record)
      Store.insert(signed)

      assert {:ok, _} = Query.lookup_verified("direct.ztlp", :key)
    end
  end

  describe "resolve_all/1" do
    test "returns all record types for a name" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      # Insert KEY and RELAY records for same name
      key_rec = Record.new_key("multi.ztlp", node_id, node_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      key_rec = Record.sign(key_rec, priv)
      Store.insert(key_rec)

      relay_rec = Record.new_relay("multi.ztlp", node_id, ["1.2.3.4:23095"], 1000, "us-east",
        created_at: System.system_time(:second), ttl: 3600, serial: 1)
      relay_rec = Record.sign(relay_rec, priv)
      Store.insert(relay_rec)

      results = Query.resolve_all("multi.ztlp")
      types = Enum.map(results, fn {type, _rec} -> type end)
      assert :key in types
      assert :relay in types
    end

    test "returns empty list for unknown name" do
      assert Query.resolve_all("unknown.ztlp") == []
    end
  end
end
