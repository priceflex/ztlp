defmodule ZtlpGateway.ComponentAuthTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.ComponentAuth

  setup do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    %{pub: pub, priv: priv}
  end

  # ── Challenge Parsing ─────────────────────────────────────────────────

  describe "parse_challenge/1" do
    test "extracts nonce from valid challenge" do
      nonce = :crypto.strong_rand_bytes(16)
      challenge = <<0xCA, nonce::binary>>
      assert {:ok, ^nonce} = ComponentAuth.parse_challenge(challenge)
    end

    test "returns :error for invalid tag" do
      assert :error = ComponentAuth.parse_challenge(<<0xFF, :crypto.strong_rand_bytes(16)::binary>>)
    end

    test "returns :error for truncated data" do
      assert :error = ComponentAuth.parse_challenge(<<0xCA, 0, 1>>)
    end
  end

  # ── Response Signing ──────────────────────────────────────────────────

  describe "sign_challenge/2" do
    test "produces a 97-byte response with 0xCB tag", %{priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      response = ComponentAuth.sign_challenge(nonce, priv)
      assert byte_size(response) == 97
      assert <<0xCB, _::binary-64, _::binary-32>> = response
    end

    test "response signature verifies correctly", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      response = ComponentAuth.sign_challenge(nonce, priv)
      {:ok, sig, resp_pub} = ComponentAuth.parse_response(response)

      assert resp_pub == pub
      assert :crypto.verify(:eddsa, :none, nonce, sig, [pub, :ed25519])
    end
  end

  # ── Verification ──────────────────────────────────────────────────────

  describe "verify_response/4" do
    test "succeeds with correct key", %{pub: pub, priv: priv} do
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
      {other_pub, _} = :crypto.generate_key(:eddsa, :ed25519)

      assert {:error, :invalid_signature} =
               ComponentAuth.verify_response(nonce, sig, other_pub,
                 enabled: true,
                 allowed_keys: [other_pub]
               )
    end

    test "disabled mode allows all" do
      nonce = :crypto.strong_rand_bytes(16)
      fake_sig = :crypto.strong_rand_bytes(64)
      fake_pub = :crypto.strong_rand_bytes(32)

      assert {:ok, ^fake_pub} =
               ComponentAuth.verify_response(nonce, fake_sig, fake_pub, enabled: false)
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

    test "rejects unauthorized key", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      sig = :crypto.sign(:eddsa, :none, nonce, [priv, :ed25519])
      {other_pub, _} = :crypto.generate_key(:eddsa, :ed25519)

      assert {:error, :unauthorized_key} =
               ComponentAuth.verify_response(nonce, sig, pub,
                 enabled: true,
                 allowed_keys: [other_pub]
               )
    end
  end

  # ── Identity Key Management ──────────────────────────────────────────

  describe "generate_identity/0" do
    test "returns a valid keypair" do
      {pub, priv} = ComponentAuth.generate_identity()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end
  end

  describe "load_identity_from_file/1" do
    test "loads a valid hex-encoded key file" do
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      path = Path.join(System.tmp_dir!(), "ztlp_gw_key_#{:rand.uniform(100_000)}")
      File.write!(path, Base.encode16(priv, case: :lower) <> "\n")
      on_exit(fn -> File.rm(path) end)

      assert {:ok, {^pub, ^priv}} = ComponentAuth.load_identity_from_file(path)
    end

    test "returns :not_found for missing file" do
      assert {:error, :not_found} = ComponentAuth.load_identity_from_file("/no/such/file")
    end
  end

  # ── Allowed Keys Parsing ─────────────────────────────────────────────

  describe "parse_allowed_keys/1" do
    test "parses valid hex pubkeys" do
      {pub, _} = :crypto.generate_key(:eddsa, :ed25519)
      hex = Base.encode16(pub, case: :lower)
      assert {:ok, [^pub]} = ComponentAuth.parse_allowed_keys([hex])
    end

    test "returns error for invalid hex" do
      assert {:error, _} = ComponentAuth.parse_allowed_keys(["zzz"])
    end

    test "handles empty list" do
      assert {:ok, []} = ComponentAuth.parse_allowed_keys([])
    end
  end

  # ── Full Protocol Round-Trip ──────────────────────────────────────────

  describe "full round-trip" do
    test "gateway responds to NS challenge successfully", %{pub: pub, priv: priv} do
      # NS generates challenge
      nonce = :crypto.strong_rand_bytes(16)
      challenge = <<0xCA, nonce::binary>>

      # Gateway parses and responds
      {:ok, parsed_nonce} = ComponentAuth.parse_challenge(challenge)
      response = ComponentAuth.sign_challenge(parsed_nonce, priv)

      # NS verifies
      {:ok, sig, peer_pub} = ComponentAuth.parse_response(response)

      assert {:ok, ^pub} =
               ComponentAuth.verify_response(nonce, sig, peer_pub,
                 enabled: true,
                 allowed_keys: [pub]
               )
    end
  end
end
