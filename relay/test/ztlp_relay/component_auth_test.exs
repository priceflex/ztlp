defmodule ZtlpRelay.ComponentAuthTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.ComponentAuth

  setup do
    # Generate a fresh keypair for each test
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    %{pub: pub, priv: priv}
  end

  # ── Challenge Generation ──────────────────────────────────────────────

  describe "generate_challenge/0" do
    test "produces a 17-byte binary with 0xCA tag" do
      {challenge, _nonce} = ComponentAuth.generate_challenge()
      assert byte_size(challenge) == 17
      assert <<0xCA, _nonce::binary-16>> = challenge
    end

    test "produces a 16-byte nonce" do
      {_challenge, nonce} = ComponentAuth.generate_challenge()
      assert byte_size(nonce) == 16
    end

    test "produces unique nonces on successive calls" do
      {_c1, nonce1} = ComponentAuth.generate_challenge()
      {_c2, nonce2} = ComponentAuth.generate_challenge()
      assert nonce1 != nonce2
    end
  end

  # ── Challenge Parsing ─────────────────────────────────────────────────

  describe "parse_challenge/1" do
    test "extracts nonce from valid challenge" do
      {challenge, nonce} = ComponentAuth.generate_challenge()
      assert {:ok, ^nonce} = ComponentAuth.parse_challenge(challenge)
    end

    test "returns :error for invalid tag" do
      assert :error = ComponentAuth.parse_challenge(<<0xFF, :crypto.strong_rand_bytes(16)::binary>>)
    end

    test "returns :error for truncated data" do
      assert :error = ComponentAuth.parse_challenge(<<0xCA, 0, 1, 2>>)
    end

    test "returns :error for empty binary" do
      assert :error = ComponentAuth.parse_challenge(<<>>)
    end
  end

  # ── Response Signing ──────────────────────────────────────────────────

  describe "sign_challenge/2" do
    test "produces a 97-byte response with 0xCB tag", %{priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      response = ComponentAuth.sign_challenge(nonce, priv)
      assert byte_size(response) == 97
      assert <<0xCB, _sig::binary-64, _pubkey::binary-32>> = response
    end

    test "response contains a verifiable signature", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      response = ComponentAuth.sign_challenge(nonce, priv)
      {:ok, sig, resp_pub} = ComponentAuth.parse_response(response)

      assert resp_pub == pub
      assert :crypto.verify(:eddsa, :none, nonce, sig, [pub, :ed25519])
    end

    test "embeds the correct public key in response", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      response = ComponentAuth.sign_challenge(nonce, priv)
      {:ok, _sig, resp_pub} = ComponentAuth.parse_response(response)
      assert resp_pub == pub
    end
  end

  # ── Response Parsing ──────────────────────────────────────────────────

  describe "parse_response/1" do
    test "extracts signature and public key from valid response", %{priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      response = ComponentAuth.sign_challenge(nonce, priv)
      assert {:ok, sig, pubkey} = ComponentAuth.parse_response(response)
      assert byte_size(sig) == 64
      assert byte_size(pubkey) == 32
    end

    test "returns :error for invalid tag" do
      assert :error = ComponentAuth.parse_response(<<0xFF, :crypto.strong_rand_bytes(96)::binary>>)
    end

    test "returns :error for truncated data" do
      assert :error = ComponentAuth.parse_response(<<0xCB, 0, 1, 2>>)
    end
  end

  # ── Verification ──────────────────────────────────────────────────────

  describe "verify_response/4" do
    test "succeeds with correct key in allowed list", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      sig = :crypto.sign(:eddsa, :none, nonce, [priv, :ed25519])

      assert {:ok, ^pub} =
               ComponentAuth.verify_response(nonce, sig, pub,
                 enabled: true,
                 allowed_keys: [pub]
               )
    end

    test "fails with wrong key", %{priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      sig = :crypto.sign(:eddsa, :none, nonce, [priv, :ed25519])

      # Use a different keypair's public key
      {other_pub, _other_priv} = :crypto.generate_key(:eddsa, :ed25519)

      assert {:error, :invalid_signature} =
               ComponentAuth.verify_response(nonce, sig, other_pub,
                 enabled: true,
                 allowed_keys: [other_pub]
               )
    end

    test "fails with tampered nonce", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      sig = :crypto.sign(:eddsa, :none, nonce, [priv, :ed25519])

      tampered_nonce = :crypto.strong_rand_bytes(16)

      assert {:error, :invalid_signature} =
               ComponentAuth.verify_response(tampered_nonce, sig, pub,
                 enabled: true,
                 allowed_keys: [pub]
               )
    end

    test "disabled mode allows all connections", %{pub: pub} do
      nonce = :crypto.strong_rand_bytes(16)
      # Pass garbage signature — doesn't matter when disabled
      fake_sig = :crypto.strong_rand_bytes(64)

      assert {:ok, ^pub} =
               ComponentAuth.verify_response(nonce, fake_sig, pub, enabled: false)
    end

    test "rejects key not in allowed list", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      sig = :crypto.sign(:eddsa, :none, nonce, [priv, :ed25519])

      {other_pub, _} = :crypto.generate_key(:eddsa, :ed25519)

      assert {:error, :unauthorized_key} =
               ComponentAuth.verify_response(nonce, sig, pub,
                 enabled: true,
                 allowed_keys: [other_pub]
               )
    end

    test "empty allowed keys rejects all when enabled", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      sig = :crypto.sign(:eddsa, :none, nonce, [priv, :ed25519])

      assert {:error, :no_allowed_keys} =
               ComponentAuth.verify_response(nonce, sig, pub,
                 enabled: true,
                 allowed_keys: []
               )
    end

    test "allows key from multi-key allowed list", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      sig = :crypto.sign(:eddsa, :none, nonce, [priv, :ed25519])

      {other_pub, _} = :crypto.generate_key(:eddsa, :ed25519)

      assert {:ok, ^pub} =
               ComponentAuth.verify_response(nonce, sig, pub,
                 enabled: true,
                 allowed_keys: [other_pub, pub]
               )
    end
  end

  # ── Identity Key Management ──────────────────────────────────────────

  describe "generate_identity/0" do
    test "returns a valid Ed25519 keypair" do
      {pub, priv} = ComponentAuth.generate_identity()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32

      # Verify the keypair works for signing
      msg = "test message"
      sig = :crypto.sign(:eddsa, :none, msg, [priv, :ed25519])
      assert :crypto.verify(:eddsa, :none, msg, sig, [pub, :ed25519])
    end
  end

  describe "load_identity_from_file/1" do
    test "loads a valid hex-encoded key file" do
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      hex = Base.encode16(priv, case: :lower)

      path = Path.join(System.tmp_dir!(), "ztlp_test_key_#{:rand.uniform(100_000)}")
      File.write!(path, hex <> "\n")

      on_exit(fn -> File.rm(path) end)

      assert {:ok, {^pub, ^priv}} = ComponentAuth.load_identity_from_file(path)
    end

    test "returns :not_found for missing file" do
      assert {:error, :not_found} =
               ComponentAuth.load_identity_from_file("/nonexistent/path/key")
    end

    test "returns :invalid_hex for non-hex content" do
      path = Path.join(System.tmp_dir!(), "ztlp_test_bad_key_#{:rand.uniform(100_000)}")
      File.write!(path, "not_valid_hex_content\n")
      on_exit(fn -> File.rm(path) end)

      assert {:error, :invalid_hex} = ComponentAuth.load_identity_from_file(path)
    end

    test "returns :invalid_key_length for wrong-sized key" do
      path = Path.join(System.tmp_dir!(), "ztlp_test_short_key_#{:rand.uniform(100_000)}")
      # Write 16 bytes (32 hex chars) instead of 32 bytes (64 hex chars)
      File.write!(path, Base.encode16(:crypto.strong_rand_bytes(16), case: :lower) <> "\n")
      on_exit(fn -> File.rm(path) end)

      assert {:error, :invalid_key_length} = ComponentAuth.load_identity_from_file(path)
    end
  end

  describe "save_identity_to_file/2" do
    test "saves and reloads keypair", %{pub: pub, priv: priv} do
      path = Path.join(System.tmp_dir!(), "ztlp_test_save_#{:rand.uniform(100_000)}")
      on_exit(fn -> File.rm(path) end)

      assert :ok = ComponentAuth.save_identity_to_file(path, {pub, priv})
      assert {:ok, {^pub, ^priv}} = ComponentAuth.load_identity_from_file(path)
    end

    test "creates parent directories" do
      dir = Path.join(System.tmp_dir!(), "ztlp_nested_#{:rand.uniform(100_000)}")
      path = Path.join(dir, "sub/key")
      on_exit(fn -> File.rm_rf(dir) end)

      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      assert :ok = ComponentAuth.save_identity_to_file(path, {pub, priv})
      assert File.exists?(path)
    end
  end

  describe "load_or_generate_identity/0" do
    test "generates identity when no key file configured" do
      # Ensure no key file is configured
      Application.delete_env(:ztlp_relay, :component_auth_identity_key_file)

      {pub, priv} = ComponentAuth.load_or_generate_identity()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end

    test "generates and saves identity when key file doesn't exist" do
      path = Path.join(System.tmp_dir!(), "ztlp_test_autogen_#{:rand.uniform(100_000)}")
      on_exit(fn ->
        File.rm(path)
        Application.delete_env(:ztlp_relay, :component_auth_identity_key_file)
      end)

      Application.put_env(:ztlp_relay, :component_auth_identity_key_file, path)

      {pub, priv} = ComponentAuth.load_or_generate_identity()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
      assert File.exists?(path)

      # Verify file contents match
      assert {:ok, {^pub, ^priv}} = ComponentAuth.load_identity_from_file(path)
    end
  end

  # ── Nonce Replay Protection ──────────────────────────────────────────

  describe "record_nonce/1" do
    test "accepts fresh nonce" do
      nonce = :crypto.strong_rand_bytes(16)
      assert :ok = ComponentAuth.record_nonce(nonce)
    end

    test "rejects replayed nonce" do
      nonce = :crypto.strong_rand_bytes(16)
      assert :ok = ComponentAuth.record_nonce(nonce)
      assert {:error, :replay} = ComponentAuth.record_nonce(nonce)
    end

    test "different nonces are independent" do
      nonce1 = :crypto.strong_rand_bytes(16)
      nonce2 = :crypto.strong_rand_bytes(16)
      assert :ok = ComponentAuth.record_nonce(nonce1)
      assert :ok = ComponentAuth.record_nonce(nonce2)
    end
  end

  describe "nonce_used?/1" do
    test "returns false for unused nonce" do
      nonce = :crypto.strong_rand_bytes(16)
      refute ComponentAuth.nonce_used?(nonce)
    end

    test "returns true for recorded nonce" do
      nonce = :crypto.strong_rand_bytes(16)
      ComponentAuth.record_nonce(nonce)
      assert ComponentAuth.nonce_used?(nonce)
    end
  end

  # ── Allowed Keys Parsing ─────────────────────────────────────────────

  describe "parse_allowed_keys/1" do
    test "parses valid hex-encoded pubkeys" do
      {pub1, _} = :crypto.generate_key(:eddsa, :ed25519)
      {pub2, _} = :crypto.generate_key(:eddsa, :ed25519)
      hex1 = Base.encode16(pub1, case: :lower)
      hex2 = Base.encode16(pub2, case: :upper)

      assert {:ok, [^pub1, ^pub2]} = ComponentAuth.parse_allowed_keys([hex1, hex2])
    end

    test "returns error for invalid hex" do
      assert {:error, msg} = ComponentAuth.parse_allowed_keys(["not_valid_hex"])
      assert msg =~ "invalid hex"
    end

    test "returns error for wrong key length" do
      short_hex = Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
      assert {:error, msg} = ComponentAuth.parse_allowed_keys([short_hex])
      assert msg =~ "32 bytes"
    end

    test "handles empty list" do
      assert {:ok, []} = ComponentAuth.parse_allowed_keys([])
    end
  end

  # ── Concurrent Auth Challenges ────────────────────────────────────────

  describe "concurrent challenges" do
    test "multiple simultaneous challenge-response flows work correctly" do
      # Generate 10 keypairs
      keypairs = for _ <- 1..10, do: :crypto.generate_key(:eddsa, :ed25519)

      # Run challenge-response in parallel
      tasks =
        Enum.map(keypairs, fn {pub, priv} ->
          Task.async(fn ->
            {_challenge, nonce} = ComponentAuth.generate_challenge()
            response = ComponentAuth.sign_challenge(nonce, priv)
            {:ok, sig, resp_pub} = ComponentAuth.parse_response(response)

            all_pubs = Enum.map(keypairs, fn {p, _} -> p end)

            result =
              ComponentAuth.verify_response(nonce, sig, resp_pub,
                enabled: true,
                allowed_keys: all_pubs
              )

            {result, resp_pub, pub}
          end)
        end)

      results = Task.await_many(tasks, 5000)

      Enum.each(results, fn {{:ok, resp_pub}, resp_pub, original_pub} ->
        assert resp_pub == original_pub
      end)
    end
  end

  # ── Full Protocol Round-Trip ──────────────────────────────────────────

  describe "full protocol round-trip" do
    test "challenger → responder → verify succeeds", %{pub: pub, priv: priv} do
      # Step 1: Challenger generates challenge
      {challenge_bin, nonce} = ComponentAuth.generate_challenge()

      # Step 2: Responder parses challenge and signs
      {:ok, parsed_nonce} = ComponentAuth.parse_challenge(challenge_bin)
      assert parsed_nonce == nonce

      response_bin = ComponentAuth.sign_challenge(parsed_nonce, priv)

      # Step 3: Challenger parses response and verifies
      {:ok, sig, peer_pubkey} = ComponentAuth.parse_response(response_bin)

      assert {:ok, ^pub} =
               ComponentAuth.verify_response(nonce, sig, peer_pubkey,
                 enabled: true,
                 allowed_keys: [pub]
               )
    end
  end
end
