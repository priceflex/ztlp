defmodule ZtlpRelay.AdmissionTokenTest do
  use ExUnit.Case

  alias ZtlpRelay.AdmissionToken

  @secret AdmissionToken.generate_secret()
  @node_id :crypto.strong_rand_bytes(16)
  @issuer_id :crypto.strong_rand_bytes(16)

  describe "generate_secret/0" do
    test "generates a 32-byte secret" do
      secret = AdmissionToken.generate_secret()
      assert byte_size(secret) == 32
    end

    test "generates unique secrets" do
      s1 = AdmissionToken.generate_secret()
      s2 = AdmissionToken.generate_secret()
      assert s1 != s2
    end
  end

  describe "issue/3 and verify/3 round-trip" do
    test "issue and verify succeeds for unscoped token" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id,
          ttl_seconds: 300
        )

      assert byte_size(token) == 93

      assert {:ok, fields} = AdmissionToken.verify(token, @secret)
      assert fields.node_id == @node_id
      assert fields.issuer_id == @issuer_id
      assert fields.session_scope == <<0::96>>
      assert fields.version == 1
      assert fields.expires_at > fields.issued_at
      assert fields.expires_at - fields.issued_at == 300
    end

    test "issue and verify succeeds for session-scoped token" do
      session_id = :crypto.strong_rand_bytes(12)

      token =
        AdmissionToken.issue(@node_id, session_id,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      assert {:ok, fields} = AdmissionToken.verify(token, @secret)
      assert fields.session_scope == session_id
    end

    test "verify with session_scope check succeeds for matching scope" do
      session_id = :crypto.strong_rand_bytes(12)

      token =
        AdmissionToken.issue(@node_id, session_id,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      assert {:ok, _fields} = AdmissionToken.verify(token, @secret, session_scope: session_id)
    end

    test "verify with session_scope check succeeds for unscoped token (any session)" do
      session_id = :crypto.strong_rand_bytes(12)

      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      # Unscoped token (all-zeros) should pass any session scope check
      assert {:ok, _fields} = AdmissionToken.verify(token, @secret, session_scope: session_id)
    end

    test "verify with session_scope check fails for wrong scope" do
      session_id = :crypto.strong_rand_bytes(12)
      other_session = :crypto.strong_rand_bytes(12)

      token =
        AdmissionToken.issue(@node_id, session_id,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      assert {:error, :session_scope_mismatch} =
               AdmissionToken.verify(token, @secret, session_scope: other_session)
    end
  end

  describe "expired token rejection" do
    test "rejects expired token" do
      # Issue with 0 TTL (already expired)
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id,
          ttl_seconds: 0
        )

      # Wait a moment to ensure the timestamp crosses the boundary
      Process.sleep(10)

      assert {:error, :expired} = AdmissionToken.verify(token, @secret)
    end

    test "expired?/1 returns true for expired token" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id,
          ttl_seconds: 0
        )

      Process.sleep(10)

      assert AdmissionToken.expired?(token) == true
    end

    test "expired?/1 returns false for valid token" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id,
          ttl_seconds: 300
        )

      assert AdmissionToken.expired?(token) == false
    end

    test "expired?/1 returns true for malformed input" do
      assert AdmissionToken.expired?(<<1, 2, 3>>) == true
      assert AdmissionToken.expired?(<<>>) == true
    end
  end

  describe "tampered token rejection" do
    test "rejects token with tampered version byte" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      <<_version::8, rest::binary>> = token
      tampered = <<0x02::8, rest::binary>>

      assert {:error, :invalid_mac} = AdmissionToken.verify(tampered, @secret)
    end

    test "rejects token with tampered NodeID" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      <<version::8, node_id::binary-size(16), rest::binary>> = token
      flipped = :crypto.exor(node_id, <<1, 0::120>>)
      tampered = <<version::8, flipped::binary-size(16), rest::binary>>

      assert {:error, :invalid_mac} = AdmissionToken.verify(tampered, @secret)
    end

    test "rejects token with tampered IssuerID" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      <<version::8, node_id::binary-size(16), issuer::binary-size(16), rest::binary>> = token
      flipped = :crypto.exor(issuer, <<1, 0::120>>)
      tampered = <<version::8, node_id::binary-size(16), flipped::binary-size(16), rest::binary>>

      assert {:error, :invalid_mac} = AdmissionToken.verify(tampered, @secret)
    end

    test "rejects token with tampered IssuedAt" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      <<pre::binary-size(33), issued_at::big-unsigned-64, rest::binary>> = token
      tampered = <<pre::binary, issued_at + 1::big-unsigned-64, rest::binary>>

      assert {:error, :invalid_mac} = AdmissionToken.verify(tampered, @secret)
    end

    test "rejects token with tampered ExpiresAt" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      <<pre::binary-size(41), expires_at::big-unsigned-64, rest::binary>> = token
      tampered = <<pre::binary, expires_at + 3600::big-unsigned-64, rest::binary>>

      assert {:error, :invalid_mac} = AdmissionToken.verify(tampered, @secret)
    end

    test "rejects token with tampered SessionScope" do
      session_id = :crypto.strong_rand_bytes(12)

      token =
        AdmissionToken.issue(@node_id, session_id,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      <<pre::binary-size(49), scope::binary-size(12), mac::binary-size(32)>> = token
      flipped = :crypto.exor(scope, <<1, 0::88>>)
      tampered = <<pre::binary, flipped::binary-size(12), mac::binary-size(32)>>

      assert {:error, :invalid_mac} = AdmissionToken.verify(tampered, @secret)
    end

    test "rejects token with tampered MAC" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      <<data::binary-size(61), mac::binary-size(32)>> = token
      flipped = :crypto.exor(mac, <<1, 0::248>>)
      tampered = <<data::binary, flipped::binary-size(32)>>

      assert {:error, :invalid_mac} = AdmissionToken.verify(tampered, @secret)
    end
  end

  describe "wrong secret key rejection" do
    test "rejects token verified with different key" do
      secret_a = AdmissionToken.generate_secret()
      secret_b = AdmissionToken.generate_secret()

      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: secret_a,
          issuer_id: @issuer_id
        )

      assert {:error, :invalid_mac} = AdmissionToken.verify(token, secret_b)
    end
  end

  describe "key rotation" do
    test "verify_with_rotation accepts token signed with current key" do
      current_key = AdmissionToken.generate_secret()
      previous_key = AdmissionToken.generate_secret()

      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: current_key,
          issuer_id: @issuer_id
        )

      assert {:ok, _fields} =
               AdmissionToken.verify_with_rotation(token, current_key, previous_key)
    end

    test "verify_with_rotation accepts token signed with previous key" do
      current_key = AdmissionToken.generate_secret()
      previous_key = AdmissionToken.generate_secret()

      # Token signed with the OLD key
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: previous_key,
          issuer_id: @issuer_id
        )

      assert {:ok, _fields} =
               AdmissionToken.verify_with_rotation(token, current_key, previous_key)
    end

    test "verify_with_rotation rejects token signed with unknown key" do
      current_key = AdmissionToken.generate_secret()
      previous_key = AdmissionToken.generate_secret()
      unknown_key = AdmissionToken.generate_secret()

      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: unknown_key,
          issuer_id: @issuer_id
        )

      assert {:error, :invalid_mac} =
               AdmissionToken.verify_with_rotation(token, current_key, previous_key)
    end

    test "verify_with_rotation works when previous key is nil" do
      current_key = AdmissionToken.generate_secret()

      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: current_key,
          issuer_id: @issuer_id
        )

      assert {:ok, _fields} = AdmissionToken.verify_with_rotation(token, current_key, nil)
    end

    test "verify_with_rotation rejects with nil previous key when current doesn't match" do
      current_key = AdmissionToken.generate_secret()
      other_key = AdmissionToken.generate_secret()

      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: other_key,
          issuer_id: @issuer_id
        )

      assert {:error, :invalid_mac} = AdmissionToken.verify_with_rotation(token, current_key, nil)
    end
  end

  describe "edge cases" do
    test "zero NodeID" do
      zero_node = <<0::128>>

      token =
        AdmissionToken.issue(zero_node, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      assert {:ok, fields} = AdmissionToken.verify(token, @secret)
      assert fields.node_id == zero_node
    end

    test "maximum TTL" do
      # 30 days
      max_ttl = 30 * 24 * 3600

      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id,
          ttl_seconds: max_ttl
        )

      assert {:ok, fields} = AdmissionToken.verify(token, @secret)
      assert fields.expires_at - fields.issued_at == max_ttl
    end

    test "invalid token size" do
      assert {:error, :invalid_token_size} = AdmissionToken.verify(<<1, 2, 3>>, @secret)
      assert {:error, :invalid_token_size} = AdmissionToken.verify(<<>>, @secret)
    end

    test "parse without verification" do
      token =
        AdmissionToken.issue(@node_id, nil,
          secret_key: @secret,
          issuer_id: @issuer_id
        )

      assert {:ok, fields} = AdmissionToken.parse(token)
      assert fields.node_id == @node_id
      assert fields.issuer_id == @issuer_id
      assert fields.version == 1
    end

    test "parse malformed data" do
      assert {:error, :invalid_token_size} = AdmissionToken.parse(<<1, 2, 3>>)
    end
  end

  describe "hmac_blake2s/2" do
    test "produces consistent output for same input" do
      key = :crypto.strong_rand_bytes(32)
      data = "test data"

      mac1 = AdmissionToken.hmac_blake2s(key, data)
      mac2 = AdmissionToken.hmac_blake2s(key, data)

      assert mac1 == mac2
      assert byte_size(mac1) == 32
    end

    test "different keys produce different MACs" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      data = "test data"

      mac1 = AdmissionToken.hmac_blake2s(key1, data)
      mac2 = AdmissionToken.hmac_blake2s(key2, data)

      assert mac1 != mac2
    end

    test "different data produces different MACs" do
      key = :crypto.strong_rand_bytes(32)

      mac1 = AdmissionToken.hmac_blake2s(key, "data1")
      mac2 = AdmissionToken.hmac_blake2s(key, "data2")

      assert mac1 != mac2
    end

    test "handles key longer than block size" do
      key = :crypto.strong_rand_bytes(128)
      data = "test"

      mac = AdmissionToken.hmac_blake2s(key, data)
      assert byte_size(mac) == 32
    end

    test "handles empty data" do
      key = :crypto.strong_rand_bytes(32)

      mac = AdmissionToken.hmac_blake2s(key, <<>>)
      assert byte_size(mac) == 32
    end
  end
end
