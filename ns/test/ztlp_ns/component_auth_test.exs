defmodule ZtlpNs.ComponentAuthTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.ComponentAuth

  setup do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    %{pub: pub, priv: priv}
  end

  # ── Server-side: Challenge Generation ─────────────────────────────────

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

    test "produces unique nonces" do
      {_c1, n1} = ComponentAuth.generate_challenge()
      {_c2, n2} = ComponentAuth.generate_challenge()
      assert n1 != n2
    end
  end

  # ── Client-side: Response Signing (for cluster peer auth) ─────────────

  describe "sign_challenge/2" do
    test "produces a valid 97-byte response", %{priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      response = ComponentAuth.sign_challenge(nonce, priv)
      assert byte_size(response) == 97
      assert <<0xCB, _::binary-64, _::binary-32>> = response
    end

    test "response verifies against original nonce", %{pub: pub, priv: priv} do
      nonce = :crypto.strong_rand_bytes(16)
      response = ComponentAuth.sign_challenge(nonce, priv)
      {:ok, sig, resp_pub} = ComponentAuth.parse_response(response)

      assert resp_pub == pub
      assert :crypto.verify(:eddsa, :none, nonce, sig, [pub, :ed25519])
    end
  end

  # ── Verification (server-side for incoming connections) ───────────────

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

    test "fails with invalid signature", %{priv: priv} do
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
  end

  # ── Identity Key Management ──────────────────────────────────────────

  describe "generate_identity/0" do
    test "returns valid keypair" do
      {pub, priv} = ComponentAuth.generate_identity()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32

      msg = "ns test"
      sig = :crypto.sign(:eddsa, :none, msg, [priv, :ed25519])
      assert :crypto.verify(:eddsa, :none, msg, sig, [pub, :ed25519])
    end
  end

  describe "load_identity_from_file/1" do
    test "loads valid key file" do
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      path = Path.join(System.tmp_dir!(), "ztlp_ns_key_#{:rand.uniform(100_000)}")
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

    test "rejects invalid hex" do
      assert {:error, _} = ComponentAuth.parse_allowed_keys(["xyz"])
    end
  end

  # ── Full Protocol: NS challenges relay/gateway ────────────────────────

  describe "NS server challenges a connecting component" do
    test "relay connects to NS and authenticates", %{pub: pub, priv: priv} do
      # NS (server) generates challenge
      {challenge_bin, nonce} = ComponentAuth.generate_challenge()

      # Relay (client) parses challenge and responds
      {:ok, parsed_nonce} = ComponentAuth.parse_challenge(challenge_bin)
      response_bin = ComponentAuth.sign_challenge(parsed_nonce, priv)

      # NS verifies the response
      {:ok, sig, peer_pub} = ComponentAuth.parse_response(response_bin)

      assert {:ok, ^pub} =
               ComponentAuth.verify_response(nonce, sig, peer_pub,
                 enabled: true,
                 allowed_keys: [pub]
               )
    end
  end

  # ── Cluster Peer Auth (NS-to-NS) ─────────────────────────────────────

  describe "cluster peer mutual authentication" do
    test "two NS peers authenticate each other" do
      {pub_a, priv_a} = :crypto.generate_key(:eddsa, :ed25519)
      {pub_b, priv_b} = :crypto.generate_key(:eddsa, :ed25519)
      allowed = [pub_a, pub_b]

      # A challenges B
      {_challenge_a, nonce_a} = ComponentAuth.generate_challenge()
      response_b = ComponentAuth.sign_challenge(nonce_a, priv_b)
      {:ok, sig_b, peer_b} = ComponentAuth.parse_response(response_b)

      assert {:ok, ^pub_b} =
               ComponentAuth.verify_response(nonce_a, sig_b, peer_b,
                 enabled: true,
                 allowed_keys: allowed
               )

      # B challenges A
      {_challenge_b, nonce_b} = ComponentAuth.generate_challenge()
      response_a = ComponentAuth.sign_challenge(nonce_b, priv_a)
      {:ok, sig_a, peer_a} = ComponentAuth.parse_response(response_a)

      assert {:ok, ^pub_a} =
               ComponentAuth.verify_response(nonce_b, sig_a, peer_a,
                 enabled: true,
                 allowed_keys: allowed
               )
    end
  end
end
