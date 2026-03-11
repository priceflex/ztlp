defmodule ZtlpNs.IntegrationTest do
  use ExUnit.Case

  alias ZtlpNs.{Crypto, Record, Store, TrustAnchor, ZoneAuthority, Server}

  setup do
    Store.clear()
    TrustAnchor.clear()
    :ok
  end

  describe "end-to-end: trust chain + store + query" do
    test "full trust chain: root → operator → tenant → node record" do
      # Create three-level trust chain
      root = ZoneAuthority.generate("ztlp")
      operator = ZoneAuthority.generate("example.ztlp")
      tenant = ZoneAuthority.generate("acme.example.ztlp")

      # Register root as trust anchor
      TrustAnchor.add("ztlp-root", root.public_key)

      # Root delegates to operator
      root_delegation = ZoneAuthority.delegate(root, operator)
      Store.insert(root_delegation)

      # Operator delegates to tenant
      operator_delegation = ZoneAuthority.delegate(operator, tenant)
      Store.insert(operator_delegation)

      # Tenant signs a node record
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      node_record =
        Record.new_key("node1.acme.example.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      {:ok, signed_node} = ZoneAuthority.sign_record(tenant, node_record)
      Store.insert(signed_node)

      # Verified lookup should work
      assert {:ok, found} = ZtlpNs.Query.lookup_verified("node1.acme.example.ztlp", :key)
      assert found.name == "node1.acme.example.ztlp"
    end

    test "revocation blocks lookups even with valid chain" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("root", root.public_key)

      # Create and store a valid record
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      record =
        Record.new_key("revokable.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      {:ok, signed} = ZoneAuthority.sign_record(root, record)
      Store.insert(signed)

      # Verify it works before revocation
      assert {:ok, _} = ZtlpNs.Query.lookup("revokable.ztlp", :key)

      # Now revoke it
      revoke =
        Record.new_revoke("revocations.ztlp", [], "compromised", "2026-03-10T00:00:00Z",
          created_at: System.system_time(:second),
          ttl: 0,
          serial: 1
        )

      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["revokable.ztlp"])}
      {:ok, signed_revoke} = ZoneAuthority.sign_record(root, revoke)
      Store.insert(signed_revoke)

      # Lookup should now be blocked
      assert {:error, :revoked} = ZtlpNs.Query.lookup("revokable.ztlp", :key)
    end
  end

  describe "UDP server integration" do
    test "query → response round-trip" do
      # Insert a record
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      rec =
        Record.new_key("udptest.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      Store.insert(rec)

      # Get server port
      server_port = Server.port()

      # Open a client socket and send a query
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      name = "udptest.ztlp"
      name_len = byte_size(name)
      # type 1 = KEY
      query = <<0x01, name_len::16, name::binary, 1::8>>
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      # Receive response
      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Should be a "found" response (0x02 prefix)
      assert <<0x02, rest::binary>> = response
      # Should be decodable
      assert {:ok, decoded} = Record.decode(rest)
      assert decoded.name == "udptest.ztlp"
      assert decoded.type == :key
    end

    test "query for missing record returns NXDOMAIN" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      name = "nonexistent.ztlp"
      name_len = byte_size(name)
      query = <<0x01, name_len::16, name::binary, 1::8>>
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Should be a "not found" response (0x03 prefix)
      assert <<0x03, _rest::binary>> = response
    end

    test "malformed query returns 0xFF" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, <<0xFF, 0xFF>>)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      assert response == <<0xFF>>
    end

    test "query for revoked record returns 0x04" do
      {_pub, priv} = Crypto.generate_keypair()

      # Insert a key record
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      rec =
        Record.new_key("revoked-udp.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      Store.insert(rec)

      # Revoke it
      revoke =
        Record.new_revoke("rev.ztlp", [], "test", "2026-01-01T00:00:00Z",
          created_at: System.system_time(:second),
          ttl: 0,
          serial: 1
        )

      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["revoked-udp.ztlp"])}
      revoke = Record.sign(revoke, priv)
      Store.insert(revoke)

      # Query over UDP
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      name = "revoked-udp.ztlp"
      name_len = byte_size(name)
      query = <<0x01, name_len::16, name::binary, 1::8>>
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      assert <<0x04, _rest::binary>> = response
    end
  end

  describe "multiple record types for same name" do
    test "key + relay + policy for same name" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      now = System.system_time(:second)

      # Insert three different record types for same name
      key =
        Record.sign(
          Record.new_key("multi.ztlp", node_id, node_pub, created_at: now, ttl: 86400, serial: 1),
          priv
        )

      relay =
        Record.sign(
          Record.new_relay("multi.ztlp", node_id, ["1.2.3.4:23095"], 1000, "us",
            created_at: now,
            ttl: 3600,
            serial: 1
          ),
          priv
        )

      policy =
        Record.sign(
          Record.new_policy("multi.ztlp", [node_id], ["rdp"], [],
            created_at: now,
            ttl: 3600,
            serial: 1
          ),
          priv
        )

      Store.insert(key)
      Store.insert(relay)
      Store.insert(policy)

      assert {:ok, _} = Store.lookup("multi.ztlp", :key)
      assert {:ok, _} = Store.lookup("multi.ztlp", :relay)
      assert {:ok, _} = Store.lookup("multi.ztlp", :policy)
      assert :not_found = Store.lookup("multi.ztlp", :svc)
    end
  end

  describe "record update via serial number" do
    test "newer serial replaces older" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub1, _} = Crypto.generate_keypair()
      {node_pub2, _} = Crypto.generate_keypair()
      now = System.system_time(:second)

      rec1 =
        Record.sign(
          Record.new_key("update.ztlp", node_id, node_pub1, created_at: now, ttl: 86400, serial: 1),
          priv
        )

      rec2 =
        Record.sign(
          Record.new_key("update.ztlp", node_id, node_pub2, created_at: now, ttl: 86400, serial: 2),
          priv
        )

      Store.insert(rec1)
      assert {:ok, found1} = Store.lookup("update.ztlp", :key)
      assert found1.serial == 1

      Store.insert(rec2)
      assert {:ok, found2} = Store.lookup("update.ztlp", :key)
      assert found2.serial == 2
    end
  end
end
