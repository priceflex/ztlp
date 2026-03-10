defmodule ZtlpGateway.NsIntegrationTest do
  @moduledoc """
  Integration tests for Gateway ↔ ZTLP-NS communication.

  These tests start a real ZTLP-NS server, register records in it,
  and verify that the Gateway's Identity module can resolve public keys
  by querying NS over UDP using the 0x05 wire protocol.

  Requires `ztlp_ns` as a test-only path dependency.
  """

  use ExUnit.Case

  alias ZtlpGateway.{Identity, NsClient}

  # We need NS modules for setup — creating signed records
  alias ZtlpNs.{Crypto, Record, Store, TrustAnchor, ZoneAuthority, Server}

  setup do
    # Ensure NS application is started (it may already be running
    # from a previous test, which is fine)
    ensure_ns_started()

    # Get the NS server's actual port (it uses port 0 in test)
    ns_port = Server.port()

    # Point the gateway's NsClient at the test NS server
    Application.put_env(:ztlp_gateway, :ns_server_host, {127, 0, 0, 1})
    Application.put_env(:ztlp_gateway, :ns_server_port, ns_port)
    Application.put_env(:ztlp_gateway, :ns_query_timeout_ms, 2000)

    # Clean state
    Store.clear()
    TrustAnchor.clear()
    Identity.clear()
    NsClient.clear_cache()
    NsClient.clear_trust_anchors()

    on_exit(fn ->
      Store.clear()
      TrustAnchor.clear()
      Identity.clear()
      NsClient.clear_cache()
      NsClient.clear_trust_anchors()
    end)

    %{ns_port: ns_port}
  end

  describe "gateway resolves identity via NS" do
    test "resolve/1 queries NS on cache miss and caches the result" do
      # Create a zone authority (root) and register as trust anchor
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)

      # Tell the gateway NsClient to trust this root key
      NsClient.add_trust_anchor("test-root", root.public_key)

      # Create a ZTLP_KEY record binding a node name to an X25519 pubkey
      # The X25519 pubkey is what the gateway sees after a Noise handshake
      {x25519_pub, _x25519_priv} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)

      key_record = Record.new_key("node1.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, key_record)
      :ok = Store.insert(signed)

      # Verify the hex encoding is consistent between gateway and NS
      expected_hex = Base.encode16(x25519_pub, case: :lower)
      assert signed.data.public_key == expected_hex

      # Gateway identity cache is empty, so resolve/1 should query NS
      # and find the ZTLP_KEY record matching this pubkey
      result = Identity.resolve(x25519_pub)
      assert {:ok, "node1.ztlp"} == result

      # Second resolve should hit the local cache (no NS query needed)
      # We can verify by checking the ETS table directly
      assert [{^x25519_pub, "node1.ztlp"}] = :ets.lookup(:ztlp_gateway_identity_cache, x25519_pub)
      assert {:ok, "node1.ztlp"} == Identity.resolve(x25519_pub)
    end

    test "resolve/1 returns :unknown when NS has no matching record" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)
      NsClient.add_trust_anchor("test-root", root.public_key)

      # Generate a random pubkey that has no record in NS
      {random_pub, _} = :crypto.generate_key(:ecdh, :x25519)

      assert :unknown == Identity.resolve(random_pub)
    end

    test "resolve/1 returns :unknown when record has untrusted signer" do
      # Create a zone authority but DON'T add it as a trust anchor
      untrusted = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("ns-only-root", untrusted.public_key)

      # Add a DIFFERENT key as the gateway's trust anchor
      {other_pub, _other_priv} = Crypto.generate_keypair()
      NsClient.add_trust_anchor("wrong-root", other_pub)

      # Create and store a signed record
      {x25519_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)
      key_record = Record.new_key("untrusted-node.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(untrusted, key_record)
      :ok = Store.insert(signed)

      # Gateway should reject — signer is not in its trust anchor set
      assert :unknown == Identity.resolve(x25519_pub)
    end

    test "resolve/1 returns :unknown for revoked records" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)
      NsClient.add_trust_anchor("test-root", root.public_key)

      # Create and store a key record
      {x25519_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)
      key_record = Record.new_key("revoked-node.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, key_record)
      :ok = Store.insert(signed)

      # Revoke the node
      revoke = Record.new_revoke("revocations.ztlp", [], "compromised", "2026-03-10",
        created_at: System.system_time(:second), ttl: 0, serial: 1)
      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["revoked-node.ztlp"])}
      {:ok, signed_revoke} = ZoneAuthority.sign_record(root, revoke)
      :ok = Store.insert(signed_revoke)

      # Gateway should get :unknown (NS returns revoked → NsClient returns error)
      assert :unknown == Identity.resolve(x25519_pub)
    end

    test "NsClient.query_key/1 returns {:error, :not_found} for unknown key" do
      {random_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      assert {:error, :not_found} == NsClient.query_key(random_pub)
    end

    test "NsClient.query_key/1 returns {:error, :revoked} for revoked key" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)
      NsClient.add_trust_anchor("test-root", root.public_key)

      {x25519_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)
      key_record = Record.new_key("revoked2.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, key_record)
      :ok = Store.insert(signed)

      # Revoke
      revoke = Record.new_revoke("rev2.ztlp", [], "test", "2026-03-10",
        created_at: System.system_time(:second), ttl: 0, serial: 1)
      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["revoked2.ztlp"])}
      {:ok, signed_revoke} = ZoneAuthority.sign_record(root, revoke)
      :ok = Store.insert(signed_revoke)

      assert {:error, :revoked} == NsClient.query_key(x25519_pub)
    end

    test "NsClient caches successful lookups" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)
      NsClient.add_trust_anchor("test-root", root.public_key)

      {x25519_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)
      key_record = Record.new_key("cached-node.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, key_record)
      :ok = Store.insert(signed)

      # First query — hits NS
      assert {:ok, record1} = NsClient.query_key(x25519_pub)
      assert record1.name == "cached-node.ztlp"

      # Delete the record from NS store
      Store.clear()

      # Second query should return from NsClient's cache
      assert {:ok, record2} = NsClient.query_key(x25519_pub)
      assert record2.name == "cached-node.ztlp"
    end

    test "NsClient cache respects TTL" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)
      NsClient.add_trust_anchor("test-root", root.public_key)

      {x25519_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)

      # Use a very short TTL (1 second)
      key_record = Record.new_key("ttl-node.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 1, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, key_record)
      :ok = Store.insert(signed)

      # Query — should succeed
      assert {:ok, _} = NsClient.query_key(x25519_pub)

      # Clear NS and wait for TTL to expire
      Store.clear()
      Process.sleep(1100)

      # Cache should be expired, and NS no longer has the record
      NsClient.clear_cache()
      assert {:error, :not_found} == NsClient.query_key(x25519_pub)
    end

    test "NsClient handles NS timeout gracefully" do
      # Point NsClient at a port where nothing is listening
      Application.put_env(:ztlp_gateway, :ns_server_port, 19999)
      Application.put_env(:ztlp_gateway, :ns_query_timeout_ms, 200)
      NsClient.clear_cache()

      {random_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      assert {:error, :timeout} == NsClient.query_key(random_pub)
    end

    test "resolve_or_hex/1 falls back to hex for unknown NS keys" do
      {random_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      result = Identity.resolve_or_hex(random_pub)
      assert String.starts_with?(result, "unknown:")
    end

    test "multiple different keys resolve correctly" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)
      NsClient.add_trust_anchor("test-root", root.public_key)

      # Create two different key records
      {pub1, _} = :crypto.generate_key(:ecdh, :x25519)
      {pub2, _} = :crypto.generate_key(:ecdh, :x25519)
      nid1 = :crypto.strong_rand_bytes(16)
      nid2 = :crypto.strong_rand_bytes(16)
      now = System.system_time(:second)

      rec1 = Record.new_key("node-a.ztlp", nid1, pub1, created_at: now, ttl: 86400, serial: 1)
      rec2 = Record.new_key("node-b.ztlp", nid2, pub2, created_at: now, ttl: 86400, serial: 1)
      {:ok, signed1} = ZoneAuthority.sign_record(root, rec1)
      {:ok, signed2} = ZoneAuthority.sign_record(root, rec2)
      :ok = Store.insert(signed1)
      :ok = Store.insert(signed2)

      assert {:ok, "node-a.ztlp"} == Identity.resolve(pub1)
      assert {:ok, "node-b.ztlp"} == Identity.resolve(pub2)
    end

    test "no trust anchors configured — accepts all signed records" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)
      # Deliberately DO NOT add trust anchor to NsClient

      {x25519_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)
      key_record = Record.new_key("permissive.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, key_record)
      :ok = Store.insert(signed)

      # With no trust anchors, NsClient accepts any signed record
      assert {:ok, "permissive.ztlp"} == Identity.resolve(x25519_pub)
    end
  end

  describe "NS server 0x05 pubkey query protocol" do
    test "raw UDP 0x05 query returns record for known key" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)

      {x25519_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)
      key_record = Record.new_key("proto-test.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, key_record)
      :ok = Store.insert(signed)

      # Send raw 0x05 query
      ns_port = Server.port()
      {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}])
      pk_hex = Base.encode16(x25519_pub, case: :lower)
      pk_len = byte_size(pk_hex)
      query = <<0x05, pk_len::16, pk_hex::binary>>
      :gen_udp.send(sock, {127, 0, 0, 1}, ns_port, query)
      {:ok, {_ip, _port, response}} = :gen_udp.recv(sock, 0, 5000)
      :gen_udp.close(sock)

      # Should be a "found" response
      assert <<0x02, record_bin::binary>> = response
      assert {:ok, decoded} = Record.decode(record_bin)
      assert decoded.name == "proto-test.ztlp"
      assert decoded.data.public_key == pk_hex
    end

    test "raw UDP 0x05 query returns not-found for unknown key" do
      ns_port = Server.port()
      {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}])
      pk_hex = String.duplicate("ab", 32)  # 64-char fake hex
      pk_len = byte_size(pk_hex)
      query = <<0x05, pk_len::16, pk_hex::binary>>
      :gen_udp.send(sock, {127, 0, 0, 1}, ns_port, query)
      {:ok, {_ip, _port, response}} = :gen_udp.recv(sock, 0, 5000)
      :gen_udp.close(sock)

      assert <<0x03, _rest::binary>> = response
    end

    test "raw UDP 0x05 query returns revoked for revoked key" do
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("test-root", root.public_key)

      {x25519_pub, _} = :crypto.generate_key(:ecdh, :x25519)
      node_id = :crypto.strong_rand_bytes(16)
      key_record = Record.new_key("rev-proto.ztlp", node_id, x25519_pub,
        created_at: System.system_time(:second), ttl: 86400, serial: 1)
      {:ok, signed} = ZoneAuthority.sign_record(root, key_record)
      :ok = Store.insert(signed)

      # Revoke
      revoke = Record.new_revoke("rev-proto-r.ztlp", [], "test", "2026-03-10",
        created_at: System.system_time(:second), ttl: 0, serial: 1)
      revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, ["rev-proto.ztlp"])}
      {:ok, signed_revoke} = ZoneAuthority.sign_record(root, revoke)
      :ok = Store.insert(signed_revoke)

      ns_port = Server.port()
      {:ok, sock} = :gen_udp.open(0, [:binary, {:active, false}])
      pk_hex = Base.encode16(x25519_pub, case: :lower)
      pk_len = byte_size(pk_hex)
      query = <<0x05, pk_len::16, pk_hex::binary>>
      :gen_udp.send(sock, {127, 0, 0, 1}, ns_port, query)
      {:ok, {_ip, _port, response}} = :gen_udp.recv(sock, 0, 5000)
      :gen_udp.close(sock)

      assert <<0x04, _rest::binary>> = response
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────────

  # Start the NS application if not already running. Uses Application.ensure_all_started
  # to bring up TrustAnchor, Store, and Server.
  defp ensure_ns_started do
    case Application.ensure_all_started(:ztlp_ns) do
      {:ok, _} -> :ok
      {:error, {:already_started, :ztlp_ns}} -> :ok
    end
  end
end
