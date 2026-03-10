defmodule ZtlpNs.CryptoTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.Crypto

  describe "generate_keypair/0" do
    test "returns a {public, private} tuple" do
      {pub, priv} = Crypto.generate_keypair()
      assert is_binary(pub)
      assert is_binary(priv)
    end

    test "public key is 32 bytes" do
      {pub, _priv} = Crypto.generate_keypair()
      assert byte_size(pub) == 32
    end

    test "private key is 32 bytes (OTP 24 Ed25519 seed)" do
      {_pub, priv} = Crypto.generate_keypair()
      assert byte_size(priv) == 32
    end

    test "generates unique keypairs" do
      {pub1, _} = Crypto.generate_keypair()
      {pub2, _} = Crypto.generate_keypair()
      assert pub1 != pub2
    end
  end

  describe "sign/2 and verify/3" do
    test "signature verifies with correct key" do
      {pub, priv} = Crypto.generate_keypair()
      msg = "hello ZTLP-NS"
      sig = Crypto.sign(msg, priv)
      assert Crypto.verify(msg, sig, pub)
    end

    test "signature is 64 bytes" do
      {_pub, priv} = Crypto.generate_keypair()
      sig = Crypto.sign("test", priv)
      assert byte_size(sig) == 64
    end

    test "signature fails with wrong key" do
      {_pub1, priv1} = Crypto.generate_keypair()
      {pub2, _priv2} = Crypto.generate_keypair()
      sig = Crypto.sign("hello", priv1)
      refute Crypto.verify("hello", sig, pub2)
    end

    test "signature fails with tampered message" do
      {pub, priv} = Crypto.generate_keypair()
      sig = Crypto.sign("original", priv)
      refute Crypto.verify("tampered", sig, pub)
    end

    test "signature fails with tampered signature" do
      {pub, priv} = Crypto.generate_keypair()
      sig = Crypto.sign("message", priv)
      # Flip a bit in the signature using Bitwise XOR
      <<first_byte, rest::binary>> = sig
      tampered_sig = <<Bitwise.bxor(first_byte, 0xFF), rest::binary>>
      refute Crypto.verify("message", tampered_sig, pub)
    end

    test "can sign empty message" do
      {pub, priv} = Crypto.generate_keypair()
      sig = Crypto.sign(<<>>, priv)
      assert Crypto.verify(<<>>, sig, pub)
    end

    test "can sign large message" do
      {pub, priv} = Crypto.generate_keypair()
      msg = :crypto.strong_rand_bytes(100_000)
      sig = Crypto.sign(msg, priv)
      assert Crypto.verify(msg, sig, pub)
    end
  end

  describe "public_key_from_private/1" do
    test "extracts the correct public key" do
      {pub, priv} = Crypto.generate_keypair()
      assert Crypto.public_key_from_private(priv) == pub
    end

    test "extracted key can verify signatures" do
      {_pub, priv} = Crypto.generate_keypair()
      derived_pub = Crypto.public_key_from_private(priv)
      sig = Crypto.sign("test", priv)
      assert Crypto.verify("test", sig, derived_pub)
    end
  end
end
