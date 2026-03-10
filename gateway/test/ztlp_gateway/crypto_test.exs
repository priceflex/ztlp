defmodule ZtlpGateway.CryptoTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.Crypto

  describe "X25519 keypair generation" do
    test "generates 32-byte keys" do
      {pub, priv} = Crypto.generate_keypair()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end

    test "different keypairs each time" do
      {pub1, _} = Crypto.generate_keypair()
      {pub2, _} = Crypto.generate_keypair()
      assert pub1 != pub2
    end
  end

  describe "Diffie-Hellman" do
    test "both sides compute the same shared secret" do
      {pub_a, priv_a} = Crypto.generate_keypair()
      {pub_b, priv_b} = Crypto.generate_keypair()

      shared_ab = Crypto.dh(pub_b, priv_a)
      shared_ba = Crypto.dh(pub_a, priv_b)

      assert shared_ab == shared_ba
      assert byte_size(shared_ab) == 32
    end

    test "different keypairs produce different shared secrets" do
      {_pub_a, priv_a} = Crypto.generate_keypair()
      {pub_b, _} = Crypto.generate_keypair()
      {pub_c, _} = Crypto.generate_keypair()

      shared_ab = Crypto.dh(pub_b, priv_a)
      shared_ac = Crypto.dh(pub_c, priv_a)

      assert shared_ab != shared_ac
    end
  end

  describe "ChaCha20-Poly1305" do
    test "encrypt then decrypt round-trips" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)
      plaintext = "Hello ZTLP Gateway!"
      aad = "header"

      {ct, tag} = Crypto.encrypt(key, nonce, plaintext, aad)
      result = Crypto.decrypt(key, nonce, ct, aad, tag)

      assert result == plaintext
    end

    test "wrong key fails decrypt" do
      key = :crypto.strong_rand_bytes(32)
      wrong_key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)

      {ct, tag} = Crypto.encrypt(key, nonce, "secret", "aad")
      assert Crypto.decrypt(wrong_key, nonce, ct, "aad", tag) == :error
    end

    test "wrong nonce fails decrypt" do
      key = :crypto.strong_rand_bytes(32)
      nonce1 = :crypto.strong_rand_bytes(12)
      nonce2 = :crypto.strong_rand_bytes(12)

      {ct, tag} = Crypto.encrypt(key, nonce1, "secret", "")
      assert Crypto.decrypt(key, nonce2, ct, "", tag) == :error
    end

    test "tampered ciphertext fails decrypt" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)

      {ct, tag} = Crypto.encrypt(key, nonce, "secret", "")
      tampered = :crypto.exor(ct, <<1>> <> :binary.copy(<<0>>, byte_size(ct) - 1))
      assert Crypto.decrypt(key, nonce, tampered, "", tag) == :error
    end

    test "wrong AAD fails decrypt" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)

      {ct, tag} = Crypto.encrypt(key, nonce, "secret", "correct")
      assert Crypto.decrypt(key, nonce, ct, "wrong", tag) == :error
    end

    test "empty plaintext works" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)

      {ct, tag} = Crypto.encrypt(key, nonce, <<>>, "")
      assert ct == <<>>
      assert byte_size(tag) == 16
      assert Crypto.decrypt(key, nonce, ct, "", tag) == <<>>
    end

    test "large payload (64KB)" do
      key = :crypto.strong_rand_bytes(32)
      nonce = :crypto.strong_rand_bytes(12)
      data = :crypto.strong_rand_bytes(65536)

      {ct, tag} = Crypto.encrypt(key, nonce, data, "")
      assert Crypto.decrypt(key, nonce, ct, "", tag) == data
    end
  end

  describe "BLAKE2s hashing" do
    test "produces 32-byte digest" do
      assert byte_size(Crypto.hash("test")) == 32
    end

    test "deterministic" do
      assert Crypto.hash("hello") == Crypto.hash("hello")
    end

    test "different inputs produce different hashes" do
      assert Crypto.hash("a") != Crypto.hash("b")
    end
  end

  describe "HMAC-BLAKE2s" do
    test "produces 32-byte MAC" do
      mac = Crypto.hmac_blake2s("key", "data")
      assert byte_size(mac) == 32
    end

    test "deterministic" do
      mac1 = Crypto.hmac_blake2s("key", "data")
      mac2 = Crypto.hmac_blake2s("key", "data")
      assert mac1 == mac2
    end

    test "different keys produce different MACs" do
      mac1 = Crypto.hmac_blake2s("key1", "data")
      mac2 = Crypto.hmac_blake2s("key2", "data")
      assert mac1 != mac2
    end

    test "handles long keys (> block size)" do
      long_key = :crypto.strong_rand_bytes(128)
      mac = Crypto.hmac_blake2s(long_key, "data")
      assert byte_size(mac) == 32
    end
  end

  describe "HKDF" do
    test "extract produces 32-byte PRK" do
      prk = Crypto.hkdf_extract("salt", "input keying material")
      assert byte_size(prk) == 32
    end

    test "expand produces requested length" do
      prk = Crypto.hkdf_extract("salt", "ikm")
      output = Crypto.hkdf_expand(prk, "info", 64)
      assert byte_size(output) == 64
    end

    test "different info strings produce different keys" do
      prk = Crypto.hkdf_extract("salt", "ikm")
      k1 = Crypto.hkdf_expand(prk, "ztlp_initiator_to_responder", 32)
      k2 = Crypto.hkdf_expand(prk, "ztlp_responder_to_initiator", 32)
      assert k1 != k2
    end

    test "hkdf_noise produces two 32-byte keys" do
      ck = :crypto.strong_rand_bytes(32)
      ikm = :crypto.strong_rand_bytes(32)
      {k1, k2} = Crypto.hkdf_noise(ck, ikm)
      assert byte_size(k1) == 32
      assert byte_size(k2) == 32
      assert k1 != k2
    end

    test "hkdf_noise_split produces three 32-byte keys" do
      ck = :crypto.strong_rand_bytes(32)
      ikm = :crypto.strong_rand_bytes(32)
      {k1, k2, k3} = Crypto.hkdf_noise_split(ck, ikm)
      assert byte_size(k1) == 32
      assert byte_size(k2) == 32
      assert byte_size(k3) == 32
      assert k1 != k2
      assert k2 != k3
    end
  end

  describe "Ed25519" do
    test "generate identity keypair" do
      {pub, priv} = Crypto.generate_identity_keypair()
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end

    test "sign and verify" do
      {pub, priv} = Crypto.generate_identity_keypair()
      msg = "ZTLP identity binding"
      sig = Crypto.sign(msg, priv)

      assert byte_size(sig) == 64
      assert Crypto.verify(msg, sig, pub) == true
    end

    test "wrong key fails verify" do
      {_pub1, priv1} = Crypto.generate_identity_keypair()
      {pub2, _priv2} = Crypto.generate_identity_keypair()

      sig = Crypto.sign("msg", priv1)
      assert Crypto.verify("msg", sig, pub2) == false
    end

    test "tampered message fails verify" do
      {pub, priv} = Crypto.generate_identity_keypair()
      sig = Crypto.sign("original", priv)
      assert Crypto.verify("tampered", sig, pub) == false
    end
  end
end
