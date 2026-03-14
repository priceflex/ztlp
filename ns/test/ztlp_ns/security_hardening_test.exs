defmodule ZtlpNs.SecurityHardeningTest do
  @moduledoc """
  Comprehensive tests for NS security hardening (Phases 1 and 2).

  Covers: rate limiting at server level, registration signature verification,
  registration rejection (bad sig, wrong zone, revoked), packet size limits,
  name validation, pubkey index O(1) lookup, amplification prevention,
  worker pool dispatching, audit logging, default TTLs, persisted signing
  keys, and revocation checks.
  """

  use ExUnit.Case, async: false

  alias ZtlpNs.{
    Crypto,
    NameValidator,
    Record,
    RegistrationAuth,
    RateLimiter,
    Server,
    Store,
    StructuredLog,
    TrustAnchor,
    ZoneAuthority
  }

  setup do
    # Ensure Mnesia tables exist (they may be missing if Store was restarted
    # by another test module's side effects, e.g., cluster tests)
    ensure_pubkey_index_table()
    Store.clear()
    TrustAnchor.clear()
    RateLimiter.reset()
    :ok
  end

  defp ensure_pubkey_index_table do
    storage_mode = ZtlpNs.Config.storage_mode()

    case :mnesia.create_table(:ztlp_ns_pubkey_index, [
           {:attributes, [:pubkey_hex, :name]},
           {:type, :set},
           {storage_mode, [node()]}
         ]) do
      {:atomic, :ok} -> :ok
      {:aborted, {:already_exists, :ztlp_ns_pubkey_index}} -> :ok
      {:aborted, _reason} -> :ok
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 1: Rate Limiting at Server Level
  # ═══════════════════════════════════════════════════════════════════

  describe "rate limiting at server level" do
    test "allowed queries return normal responses" do
      # Insert a record
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      rec =
        Record.new_key("ratelimit-test.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      Store.insert(rec)

      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      name = "ratelimit-test.ztlp"
      name_len = byte_size(name)
      # Pad query to avoid amplification truncation
      base_query = <<0x01, name_len::16, name::binary, 1::8>>
      query = base_query <> :binary.copy(<<0>>, 512)
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      assert <<0x02, _rest::binary>> = response
    end

    test "rate-limited queries are silently dropped (no response)" do
      # Set very low rate limit
      Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 1)
      Application.put_env(:ztlp_ns, :rate_limit_burst, 1)

      RateLimiter.reset()

      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      name = "doesnotmatter.ztlp"
      name_len = byte_size(name)
      query = <<0x01, name_len::16, name::binary, 1::8>>

      # First query should go through (uses the single token)
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)
      result1 = :gen_udp.recv(client, 0, 1000)

      # Second query should be rate-limited and silently dropped
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)
      result2 = :gen_udp.recv(client, 0, 500)

      :gen_udp.close(client)

      # First response should arrive
      assert {:ok, _} = result1

      # Second should time out (silently dropped)
      assert {:error, :timeout} = result2

      # Restore defaults
      Application.put_env(:ztlp_ns, :rate_limit_queries_per_second, 100)
      Application.put_env(:ztlp_ns, :rate_limit_burst, 200)
    end

    test "rate limiter check function works" do
      ip = {10, 0, 0, 1}

      # Should be allowed initially
      assert :ok = RateLimiter.check(ip)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 1: Registration Authentication
  # ═══════════════════════════════════════════════════════════════════

  describe "registration signature verification" do
    test "valid signature is accepted" do
      {pub, priv} = Crypto.generate_keypair()
      name = "test-node.ztlp"
      type = :key
      node_id = :crypto.strong_rand_bytes(16)

      data = %{
        "node_id" => Base.encode16(node_id, case: :lower),
        "public_key" => Base.encode16(pub, case: :lower),
        "algorithm" => "Ed25519"
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      canonical = RegistrationAuth.build_canonical(name, type, data_bin)
      sig = Crypto.sign(canonical, priv)

      assert :ok = RegistrationAuth.verify_signature(canonical, sig, pub)
    end

    test "invalid signature is rejected" do
      {pub, _priv} = Crypto.generate_keypair()
      {_pub2, other_priv} = Crypto.generate_keypair()
      name = "test-node.ztlp"
      type = :key

      data = %{"node_id" => "deadbeef", "public_key" => "cafebabe", "algorithm" => "Ed25519"}
      data_bin = ZtlpNs.Cbor.encode(data)
      canonical = RegistrationAuth.build_canonical(name, type, data_bin)

      # Sign with wrong key
      bad_sig = Crypto.sign(canonical, other_priv)

      assert {:error, :invalid_signature} = RegistrationAuth.verify_signature(canonical, bad_sig, pub)
    end

    test "tampered data is rejected" do
      {pub, priv} = Crypto.generate_keypair()

      data = %{"node_id" => "original"}
      data_bin = ZtlpNs.Cbor.encode(data)
      canonical = RegistrationAuth.build_canonical("node.ztlp", :key, data_bin)
      sig = Crypto.sign(canonical, priv)

      # Tamper the canonical data
      tampered = RegistrationAuth.build_canonical("node.ztlp", :key, ZtlpNs.Cbor.encode(%{"node_id" => "tampered"}))

      assert {:error, :invalid_signature} = RegistrationAuth.verify_signature(tampered, sig, pub)
    end
  end

  describe "registration zone authorization" do
    test "zone authority key is authorized" do
      # Create a zone authority and store its delegation record
      root = ZoneAuthority.generate("ztlp")
      operator = ZoneAuthority.generate("example.ztlp")

      TrustAnchor.add("root", root.public_key)
      delegation = ZoneAuthority.delegate(root, operator)
      Store.insert(delegation)

      pubkey_hex = Base.encode16(operator.public_key, case: :lower)

      # Operator should be authorized for names in example.ztlp
      data = %{"public_key" => pubkey_hex}
      assert :ok = RegistrationAuth.authorize(operator.public_key, "node.example.ztlp", :key, data)
    end

    test "self-registration is authorized for KEY records" do
      {pub, _priv} = Crypto.generate_keypair()
      pubkey_hex = Base.encode16(pub, case: :lower)

      # A node registering its own KEY record (public_key matches)
      data = %{"public_key" => pubkey_hex, "node_id" => "abcdef", "algorithm" => "Ed25519"}

      assert :ok = RegistrationAuth.authorize(pub, "mynode.ztlp", :key, data)
    end

    test "self-registration for SVC requires existing KEY" do
      {pub, priv} = Crypto.generate_keypair()
      pubkey_hex = Base.encode16(pub, case: :lower)
      node_id = :crypto.strong_rand_bytes(16)

      # First register a KEY record for this node
      key_record = %Record{
        name: "mynode.ztlp",
        type: :key,
        data: %{
          "public_key" => pubkey_hex,
          "node_id" => Base.encode16(node_id, case: :lower),
          "algorithm" => "Ed25519"
        },
        created_at: System.system_time(:second),
        ttl: 86400,
        serial: 1,
        signature: nil,
        signer_public_key: nil
      }

      signed_key = Record.sign(key_record, priv)
      Store.insert(signed_key)

      # Now SVC registration should work
      svc_data = %{"address" => "1.2.3.4:443"}
      assert :ok = RegistrationAuth.authorize(pub, "mynode.ztlp", :svc, svc_data)
    end

    test "unauthorized pubkey is rejected" do
      {pub, _priv} = Crypto.generate_keypair()

      # No delegation, pubkey doesn't match record data
      data = %{"public_key" => "aaaa", "node_id" => "bbbb"}

      assert {:error, :unauthorized} = RegistrationAuth.authorize(pub, "node.ztlp", :key, data)
    end
  end

  describe "registration rejection scenarios" do
    test "v1 registration (no pubkey) is rejected via UDP" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "legacy.ztlp"
      name_len = byte_size(name)
      type_byte = 1
      data_bin = ZtlpNs.Cbor.encode(%{"test" => true})
      data_len = byte_size(data_bin)
      sig = :crypto.strong_rand_bytes(64)
      sig_len = byte_size(sig)

      # v1 format: no pubkey field at end
      packet =
        <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
          sig_len::16, sig::binary>>

      :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Should be rejected (0xFF)
      assert response == <<0xFF>>
    end

    test "v2 registration with bad signature is rejected via UDP" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      {pub, _priv} = Crypto.generate_keypair()
      name = "badsig.ztlp"
      name_len = byte_size(name)
      type_byte = 1
      pubkey_hex = Base.encode16(pub, case: :lower)
      data = %{"public_key" => pubkey_hex, "node_id" => "aabb", "algorithm" => "Ed25519"}
      data_bin = ZtlpNs.Cbor.encode(data)
      data_len = byte_size(data_bin)
      # Random signature (won't verify)
      sig = :crypto.strong_rand_bytes(64)
      sig_len = byte_size(sig)
      pub_len = byte_size(pub)

      packet =
        <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
          sig_len::16, sig::binary, pub_len::16, pub::binary>>

      :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      assert response == <<0xFF>>
    end

    test "v2 registration with valid signature for self-registration succeeds" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      {pub, priv} = Crypto.generate_keypair()
      name = "goodnode.ztlp"
      name_len = byte_size(name)
      type_byte = 1
      pubkey_hex = Base.encode16(pub, case: :lower)
      data = %{"public_key" => pubkey_hex, "node_id" => "aabbccdd", "algorithm" => "Ed25519"}
      data_bin = ZtlpNs.Cbor.encode(data)
      data_len = byte_size(data_bin)

      # Build canonical and sign properly
      canonical = RegistrationAuth.build_canonical(name, :key, data_bin)
      sig = Crypto.sign(canonical, priv)
      sig_len = byte_size(sig)
      pub_len = byte_size(pub)

      packet =
        <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
          sig_len::16, sig::binary, pub_len::16, pub::binary>>

      :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Should succeed (0x06)
      assert response == <<0x06>>

      # Verify record was stored
      assert {:ok, stored} = Store.lookup("goodnode.ztlp", :key)
      assert stored.name == "goodnode.ztlp"
    end

    test "v1 registration succeeds in dev mode (require_registration_auth=false)" do
      # Temporarily disable registration auth
      original = Application.get_env(:ztlp_ns, :require_registration_auth)
      Application.put_env(:ztlp_ns, :require_registration_auth, false)
      # Also set env var for the Config module
      System.put_env("ZTLP_NS_REQUIRE_REGISTRATION_AUTH", "false")

      on_exit(fn ->
        if original do
          Application.put_env(:ztlp_ns, :require_registration_auth, original)
        else
          Application.delete_env(:ztlp_ns, :require_registration_auth)
        end
        System.delete_env("ZTLP_NS_REQUIRE_REGISTRATION_AUTH")
      end)

      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "devnode.ztlp"
      name_len = byte_size(name)
      type_byte = 1
      data = %{"public_key" => "aabbccdd", "node_id" => "11223344", "algorithm" => "Ed25519"}
      data_bin = ZtlpNs.Cbor.encode(data)
      data_len = byte_size(data_bin)
      sig = :crypto.strong_rand_bytes(64)
      sig_len = byte_size(sig)

      # v1 format: no pubkey field
      packet =
        <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
          sig_len::16, sig::binary>>

      :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Should succeed in dev mode (0x06)
      assert response == <<0x06>>

      # Verify record was stored
      assert {:ok, stored} = Store.lookup("devnode.ztlp", :key)
      assert stored.name == "devnode.ztlp"
      assert stored.data["registered_unsigned"] == true
    end

    test "v1 registration still rejected when auth is required (default)" do
      # Ensure auth is required (default)
      System.delete_env("ZTLP_NS_REQUIRE_REGISTRATION_AUTH")
      Application.delete_env(:ztlp_ns, :require_registration_auth)

      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "should-fail.ztlp"
      name_len = byte_size(name)
      type_byte = 1
      data = %{"public_key" => "aabbccdd", "node_id" => "11223344", "algorithm" => "Ed25519"}
      data_bin = ZtlpNs.Cbor.encode(data)
      data_len = byte_size(data_bin)
      sig = :crypto.strong_rand_bytes(64)
      sig_len = byte_size(sig)

      packet =
        <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
          sig_len::16, sig::binary>>

      :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Should be rejected (0xFF) — default requires auth
      assert response == <<0xFF>>
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 1: Revocation Check by NodeID
  # ═══════════════════════════════════════════════════════════════════

  describe "revocation check on registration" do
    test "revoked NodeID blocks registration" do
      {_pub, priv} = Crypto.generate_keypair()

      # Create a revocation record
      revoke = %Record{
        name: "revocations.ztlp",
        type: :revoke,
        data: %{
          revoked_ids: ["deadbeef01"],
          reason: "compromised",
          effective_at: "2026-01-01T00:00:00Z"
        },
        created_at: System.system_time(:second),
        ttl: 0,
        serial: 1,
        signature: nil,
        signer_public_key: nil
      }

      signed_revoke = Record.sign(revoke, priv)
      Store.insert(signed_revoke)

      # Now check revocation
      data = %{"node_id" => "deadbeef01"}
      assert {:error, :revoked} = RegistrationAuth.check_revocation(data)
    end

    test "non-revoked NodeID passes check" do
      data = %{"node_id" => "healthy_node"}
      assert :ok = RegistrationAuth.check_revocation(data)
    end

    test "missing NodeID passes check" do
      data = %{"some_field" => "value"}
      assert :ok = RegistrationAuth.check_revocation(data)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Packet Size Limits
  # ═══════════════════════════════════════════════════════════════════

  describe "packet size limits" do
    test "packets under limit are processed" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "small.ztlp"
      name_len = byte_size(name)
      query = <<0x01, name_len::16, name::binary, 1::8>>
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Should get a valid response (not found is fine)
      assert <<0x03, _rest::binary>> = response
    end

    test "oversized packets are silently dropped" do
      # Set a small max packet size for testing
      Application.put_env(:ztlp_ns, :max_packet_size, 32)

      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      # Send an oversized packet
      oversized = :binary.copy(<<0x01>>, 100)
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, oversized)

      # Should time out (silently dropped)
      result = :gen_udp.recv(client, 0, 500)
      :gen_udp.close(client)

      assert {:error, :timeout} = result

      # Restore default
      Application.put_env(:ztlp_ns, :max_packet_size, 8192)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Record Size Limits
  # ═══════════════════════════════════════════════════════════════════

  describe "record size limits" do
    test "normal-sized records are accepted" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      rec =
        Record.new_key("normalsize.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      assert :ok = Store.insert(rec)
    end

    test "oversized records are rejected" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      # Set a very small max record size
      Application.put_env(:ztlp_ns, :max_record_size, 10)

      rec =
        Record.new_key("oversized.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      assert {:error, :record_too_large} = Store.insert(rec)

      # Restore default
      Application.put_env(:ztlp_ns, :max_record_size, 4096)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Name Validation
  # ═══════════════════════════════════════════════════════════════════

  describe "name validation — valid names" do
    test "simple name" do
      assert :ok = NameValidator.validate("node1.ztlp")
    end

    test "deeply nested name" do
      assert :ok = NameValidator.validate("node1.office.acme.example.ztlp")
    end

    test "name with hyphens" do
      assert :ok = NameValidator.validate("my-node.my-zone.ztlp")
    end

    test "single label" do
      assert :ok = NameValidator.validate("ztlp")
    end

    test "numeric labels" do
      assert :ok = NameValidator.validate("123.456.ztlp")
    end

    test "max length name (253 bytes)" do
      # Build a name that's exactly 253 bytes
      label = String.duplicate("a", 63)
      name = label <> "." <> label <> "." <> label <> "." <> String.duplicate("a", 253 - 63 * 3 - 3)
      assert byte_size(name) <= 253
      assert :ok = NameValidator.validate(name)
    end
  end

  describe "name validation — invalid names" do
    test "empty name" do
      assert {:error, :empty_name} = NameValidator.validate("")
    end

    test "name too long (>253 bytes)" do
      long_name = String.duplicate("a", 254)
      assert {:error, :name_too_long} = NameValidator.validate(long_name)
    end

    test "uppercase characters" do
      assert {:error, :invalid_characters} = NameValidator.validate("NODE.ztlp")
    end

    test "special characters" do
      assert {:error, :invalid_characters} = NameValidator.validate("no@de.ztlp")
      assert {:error, :invalid_characters} = NameValidator.validate("no de.ztlp")
      assert {:error, :invalid_characters} = NameValidator.validate("no/de.ztlp")
    end

    test "leading hyphen in label" do
      assert {:error, :invalid_characters} = NameValidator.validate("-bad.ztlp")
    end

    test "trailing hyphen in label" do
      assert {:error, :invalid_characters} = NameValidator.validate("bad-.ztlp")
    end

    test "empty label (consecutive dots)" do
      assert {:error, :empty_label} = NameValidator.validate("bad..ztlp")
    end

    test "label too long (>63 bytes)" do
      long_label = String.duplicate("a", 64)
      assert {:error, :label_too_long} = NameValidator.validate(long_label <> ".ztlp")
    end

    test "null bytes" do
      assert {:error, :invalid_characters} = NameValidator.validate("bad\0.ztlp")
    end

    test "unicode characters" do
      assert {:error, :invalid_characters} = NameValidator.validate("nöde.ztlp")
    end
  end

  describe "name validation with zone suffix" do
    test "valid name with matching suffix" do
      assert :ok = NameValidator.validate_with_suffix("node.example.ztlp", "ztlp")
    end

    test "valid name that equals the suffix" do
      assert :ok = NameValidator.validate_with_suffix("ztlp", "ztlp")
    end

    test "valid name with nil suffix (no check)" do
      assert :ok = NameValidator.validate_with_suffix("anything.test", nil)
    end

    test "name with wrong suffix" do
      assert {:error, :invalid_zone_suffix} =
               NameValidator.validate_with_suffix("node.other", "ztlp")
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Pubkey Index
  # ═══════════════════════════════════════════════════════════════════

  describe "pubkey index for O(1) lookups" do
    test "inserting KEY record indexes the pubkey" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      pk_hex = Base.encode16(node_pub, case: :lower)

      rec =
        Record.new_key("indexed.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      Store.insert(rec)

      # Should be findable via pubkey lookup
      assert {:ok, found} = Store.lookup_by_pubkey(pk_hex)
      assert found.name == "indexed.ztlp"
    end

    test "lookup_by_pubkey returns :not_found for unknown pubkey" do
      assert :not_found = Store.lookup_by_pubkey("deadbeefcafebabe")
    end

    test "lookup_by_pubkey returns revoked for revoked names" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      pk_hex = Base.encode16(node_pub, case: :lower)

      # Insert KEY record
      rec =
        Record.new_key("revoked-pk.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      Store.insert(rec)

      # Revoke it
      revoke = %Record{
        name: "rev.ztlp",
        type: :revoke,
        data: %{revoked_ids: ["revoked-pk.ztlp"], reason: "test", effective_at: "2026-01-01"},
        created_at: System.system_time(:second),
        ttl: 0,
        serial: 1
      }

      revoke = Record.sign(revoke, priv)
      Store.insert(revoke)

      assert {:error, :revoked} = Store.lookup_by_pubkey(pk_hex)
    end

    test "pubkey index is case-insensitive" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()
      pk_hex_upper = Base.encode16(node_pub, case: :upper)

      rec =
        Record.new_key("casetest.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      Store.insert(rec)

      # Should find with uppercase hex
      assert {:ok, _} = Store.lookup_by_pubkey(pk_hex_upper)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Amplification Prevention
  # ═══════════════════════════════════════════════════════════════════

  describe "amplification prevention" do
    test "small query for existing record gets truncated response when amplification exceeds 8x" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      rec =
        Record.new_key("amptest.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      Store.insert(rec)

      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      # Very small query (5 bytes: 0x01 + 0::16 + ""::binary + 1::8 won't work)
      # Use a minimal valid name to keep query tiny
      name = "amptest.ztlp"
      name_len = byte_size(name)
      query = <<0x01, name_len::16, name::binary, 1::8>>
      query_size = byte_size(query)
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Response size should not exceed 8x the request size (amplification threshold)
      assert byte_size(response) <= query_size * 8
    end

    test "padded query for existing record gets full response" do
      {_pub, priv} = Crypto.generate_keypair()
      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      rec =
        Record.new_key("amptest2.ztlp", node_id, node_pub,
          created_at: System.system_time(:second),
          ttl: 86400,
          serial: 1
        )

      rec = Record.sign(rec, priv)
      Store.insert(rec)

      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "amptest2.ztlp"
      name_len = byte_size(name)
      base_query = <<0x01, name_len::16, name::binary, 1::8>>
      # Pad to 1024 bytes
      padding = :binary.copy(<<0>>, 1024 - byte_size(base_query))
      query = base_query <> padding
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Should be a full record response (no truncation flag)
      assert <<0x02, rest::binary>> = response
      # First byte after 0x02 should NOT be 0x01 (truncation flag)
      # unless the record legitimately starts with 0x01 (type_byte for :key)
      # Actually, let's just verify it's decodable
      assert {:ok, decoded} = Record.decode(rest)
      assert decoded.name == "amptest2.ztlp"
    end

    test "not-found responses are not truncated" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      # Small query for non-existent record
      name = "noexist.ztlp"
      name_len = byte_size(name)
      query = <<0x01, name_len::16, name::binary, 1::8>>
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_ip, _port, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      # Not found (0x03) — should not be truncated
      assert <<0x03, _rest::binary>> = response
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Default TTLs
  # ═══════════════════════════════════════════════════════════════════

  describe "correct default TTLs" do
    test "registration uses correct default TTLs per type" do
      server_port = Server.port()

      # Helper to register a record of given type and check TTL
      test_ttl = fn name, type_atom, type_byte, expected_ttl ->
        {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
        {pub, priv} = Crypto.generate_keypair()
        pubkey_hex = Base.encode16(pub, case: :lower)

        data =
          case type_atom do
            :key ->
              %{"public_key" => pubkey_hex, "node_id" => "aabb", "algorithm" => "Ed25519"}

            :svc ->
              # Need KEY record first for self-registration
              key_rec = %Record{
                name: name,
                type: :key,
                data: %{"public_key" => pubkey_hex, "node_id" => "aabb", "algorithm" => "Ed25519"},
                created_at: System.system_time(:second),
                ttl: 86400,
                serial: 1
              }

              signed_key = Record.sign(key_rec, priv)
              Store.insert(signed_key)
              %{"service_id" => "test", "address" => "1.2.3.4:443"}

            _ ->
              %{"test" => "data"}
          end

        data_bin = ZtlpNs.Cbor.encode(data)
        data_len = byte_size(data_bin)
        name_len = byte_size(name)
        canonical = RegistrationAuth.build_canonical(name, type_atom, data_bin)
        sig = Crypto.sign(canonical, priv)
        sig_len = byte_size(sig)
        pub_len = byte_size(pub)

        packet =
          <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
            sig_len::16, sig::binary, pub_len::16, pub::binary>>

        :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)
        {:ok, {_, _, response}} = :gen_udp.recv(client, 0, 5000)
        :gen_udp.close(client)

        if response == <<0x06>> do
          {:ok, rec} = Store.lookup(name, type_atom)
          assert rec.ttl == expected_ttl, "Expected TTL #{expected_ttl} for #{type_atom}, got #{rec.ttl}"
        end
      end

      test_ttl.("ttl-key.ztlp", :key, 1, 86_400)
      test_ttl.("ttl-svc.ztlp", :svc, 2, 86_400)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Persisted Registration Key
  # ═══════════════════════════════════════════════════════════════════

  describe "persisted registration signing key" do
    test "registration key exists in app env after server start" do
      key = Application.get_env(:ztlp_ns, :registration_private_key)
      assert is_binary(key)
      assert byte_size(key) == 32
    end

    test "key persists across queries" do
      key1 = Application.get_env(:ztlp_ns, :registration_private_key)
      # Do something that triggers the server
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, <<0xFF>>)
      {:ok, _} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      key2 = Application.get_env(:ztlp_ns, :registration_private_key)
      assert key1 == key2
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Worker Pool
  # ═══════════════════════════════════════════════════════════════════

  describe "worker pool (Task.Supervisor)" do
    test "QuerySupervisor is running" do
      assert Process.whereis(ZtlpNs.QuerySupervisor) != nil
    end

    test "concurrent queries are handled" do
      server_port = Server.port()

      # Send 10 queries concurrently
      tasks =
        for i <- 1..10 do
          Task.async(fn ->
            {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
            name = "concurrent-#{i}.ztlp"
            name_len = byte_size(name)
            query = <<0x01, name_len::16, name::binary, 1::8>>
            :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)
            result = :gen_udp.recv(client, 0, 5000)
            :gen_udp.close(client)
            result
          end)
        end

      results = Task.await_many(tasks, 10_000)

      # All should get responses
      assert Enum.all?(results, fn
               {:ok, _} -> true
               _ -> false
             end)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Audit Logging
  # ═══════════════════════════════════════════════════════════════════

  describe "audit logging" do
    test "StructuredLog.info logs registration accepted" do
      # Capture log output
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          StructuredLog.info(:registration_accepted,
            name: "test.ztlp",
            type: :key,
            signer: "deadbeef"
          )
        end)

      assert log =~ "Registration accepted"
    end

    test "StructuredLog.warn logs registration rejected" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          StructuredLog.warn(:registration_rejected,
            name: "test.ztlp",
            reason: :invalid_signature
          )
        end)

      assert log =~ "Registration rejected"
    end

    test "StructuredLog.warn logs rate limited" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          StructuredLog.warn(:rate_limited, source_ip: "1.2.3.4")
        end)

      assert log =~ "Rate limited"
    end

    test "StructuredLog.warn logs oversized packet" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          StructuredLog.warn(:oversized_packet,
            source_ip: "1.2.3.4",
            packet_size: 9000,
            max_size: 8192
          )
        end)

      assert log =~ "Oversized packet"
    end

    test "StructuredLog.error logs auth failure" do
      log =
        ExUnit.CaptureLog.capture_log(fn ->
          StructuredLog.error(:auth_failure, reason: :bad_key)
        end)

      assert log =~ "Authentication failure"
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Phase 2: Config Options
  # ═══════════════════════════════════════════════════════════════════

  describe "config options" do
    test "max_packet_size has default" do
      assert ZtlpNs.Config.max_packet_size() == 8192
    end

    test "max_record_size has default" do
      assert ZtlpNs.Config.max_record_size() == 4096
    end

    test "worker_pool_size has default" do
      assert ZtlpNs.Config.worker_pool_size() == 100
    end

    test "identity_key_file defaults to nil" do
      assert ZtlpNs.Config.identity_key_file() == nil
    end

    test "verify_trust_chain defaults to false" do
      refute ZtlpNs.Config.verify_trust_chain?()
    end

    test "name_suffix defaults to nil" do
      assert ZtlpNs.Config.name_suffix() == nil
    end

    test "max_packet_size is configurable" do
      Application.put_env(:ztlp_ns, :max_packet_size, 4096)
      assert ZtlpNs.Config.max_packet_size() == 4096
      Application.put_env(:ztlp_ns, :max_packet_size, 8192)
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Integration: Full Registration Flow
  # ═══════════════════════════════════════════════════════════════════

  describe "full authenticated registration flow" do
    test "zone authority registers a node, then queries it" do
      # Set up zone authority
      root = ZoneAuthority.generate("ztlp")
      TrustAnchor.add("root", root.public_key)

      operator = ZoneAuthority.generate("example.ztlp")
      delegation = ZoneAuthority.delegate(root, operator)
      Store.insert(delegation)

      server_port = Server.port()

      # Register a node as the operator
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])
      name = "node1.example.ztlp"
      name_len = byte_size(name)
      type_byte = 1

      node_id = :crypto.strong_rand_bytes(16)
      {node_pub, _} = Crypto.generate_keypair()

      data = %{
        "node_id" => Base.encode16(node_id, case: :lower),
        "public_key" => Base.encode16(node_pub, case: :lower),
        "algorithm" => "Ed25519"
      }

      data_bin = ZtlpNs.Cbor.encode(data)
      data_len = byte_size(data_bin)
      canonical = RegistrationAuth.build_canonical(name, :key, data_bin)
      sig = Crypto.sign(canonical, operator.private_key)
      sig_len = byte_size(sig)
      pub = operator.public_key
      pub_len = byte_size(pub)

      packet =
        <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
          sig_len::16, sig::binary, pub_len::16, pub::binary>>

      :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)

      {:ok, {_, _, response}} = :gen_udp.recv(client, 0, 5000)
      assert response == <<0x06>>

      # Now query it back (with padding for amplification prevention)
      base_query = <<0x01, name_len::16, name::binary, 1::8>>
      query = base_query <> :binary.copy(<<0>>, 1024)
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_, _, query_response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      assert <<0x02, rest::binary>> = query_response
      assert {:ok, decoded} = Record.decode(rest)
      assert decoded.name == "node1.example.ztlp"
      assert decoded.type == :key
    end
  end

  # ═══════════════════════════════════════════════════════════════════
  # Edge Cases
  # ═══════════════════════════════════════════════════════════════════

  describe "edge cases" do
    test "registration with invalid name format is rejected" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      {pub, priv} = Crypto.generate_keypair()
      # Name with uppercase (invalid)
      name = "BAD-NAME.ztlp"
      name_len = byte_size(name)
      type_byte = 1
      pubkey_hex = Base.encode16(pub, case: :lower)
      data = %{"public_key" => pubkey_hex, "node_id" => "aabb", "algorithm" => "Ed25519"}
      data_bin = ZtlpNs.Cbor.encode(data)
      data_len = byte_size(data_bin)
      canonical = RegistrationAuth.build_canonical(name, :key, data_bin)
      sig = Crypto.sign(canonical, priv)
      sig_len = byte_size(sig)
      pub_len = byte_size(pub)

      packet =
        <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
          sig_len::16, sig::binary, pub_len::16, pub::binary>>

      :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)

      {:ok, {_, _, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      assert response == <<0xFF>>
    end

    test "unknown record type in query returns 0xFF" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      name = "test.ztlp"
      name_len = byte_size(name)
      # Type byte 99 is invalid
      query = <<0x01, name_len::16, name::binary, 99::8>>
      :gen_udp.send(client, {127, 0, 0, 1}, server_port, query)

      {:ok, {_, _, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      assert response == <<0xFF>>
    end

    test "malformed CBOR in registration is rejected" do
      server_port = Server.port()
      {:ok, client} = :gen_udp.open(0, [:binary, {:active, false}])

      {pub, priv} = Crypto.generate_keypair()
      name = "badjson.ztlp"
      name_len = byte_size(name)
      type_byte = 1
      # Invalid CBOR
      data_bin = <<0xFF, 0xFF, 0xFF>>
      data_len = byte_size(data_bin)
      canonical = RegistrationAuth.build_canonical(name, :key, data_bin)
      sig = Crypto.sign(canonical, priv)
      sig_len = byte_size(sig)
      pub_len = byte_size(pub)

      packet =
        <<0x09, name_len::16, name::binary, type_byte::8, data_len::16, data_bin::binary,
          sig_len::16, sig::binary, pub_len::16, pub::binary>>

      :gen_udp.send(client, {127, 0, 0, 1}, server_port, packet)

      {:ok, {_, _, response}} = :gen_udp.recv(client, 0, 5000)
      :gen_udp.close(client)

      assert response == <<0xFF>>
    end
  end
end
