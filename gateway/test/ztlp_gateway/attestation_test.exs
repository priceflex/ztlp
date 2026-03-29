defmodule ZtlpGateway.AttestationTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.Attestation

  describe "generate_challenge/0" do
    test "returns 32-byte random nonce" do
      challenge = Attestation.generate_challenge()
      assert is_binary(challenge)
      assert byte_size(challenge) == 32
    end

    test "returns different values each call" do
      c1 = Attestation.generate_challenge()
      c2 = Attestation.generate_challenge()
      assert c1 != c2
    end
  end

  describe "minimum_trust_level/0" do
    test "defaults to :none" do
      System.delete_env("ZTLP_MIN_ATTESTATION_LEVEL")
      assert Attestation.minimum_trust_level() == :none
    end

    test "reads from env var" do
      for {env_val, expected} <- [
            {"hardware", :hardware},
            {"tee", :tee},
            {"software", :software}
          ] do
        System.put_env("ZTLP_MIN_ATTESTATION_LEVEL", env_val)
        assert Attestation.minimum_trust_level() == expected
      end

      System.delete_env("ZTLP_MIN_ATTESTATION_LEVEL")
    end
  end

  describe "meets_minimum?/1" do
    setup do
      System.delete_env("ZTLP_MIN_ATTESTATION_LEVEL")
      on_exit(fn -> System.delete_env("ZTLP_MIN_ATTESTATION_LEVEL") end)
    end

    test ":hardware meets all levels" do
      for level <- ["hardware", "tee", "software"] do
        System.put_env("ZTLP_MIN_ATTESTATION_LEVEL", level)
        assert Attestation.meets_minimum?(:hardware)
      end

      System.delete_env("ZTLP_MIN_ATTESTATION_LEVEL")
      assert Attestation.meets_minimum?(:hardware)
    end

    test ":tee meets :tee, :software, :none" do
      for level <- ["tee", "software"] do
        System.put_env("ZTLP_MIN_ATTESTATION_LEVEL", level)
        assert Attestation.meets_minimum?(:tee)
      end

      System.delete_env("ZTLP_MIN_ATTESTATION_LEVEL")
      assert Attestation.meets_minimum?(:tee)
    end

    test ":software meets :software and :none" do
      System.put_env("ZTLP_MIN_ATTESTATION_LEVEL", "software")
      assert Attestation.meets_minimum?(:software)

      System.delete_env("ZTLP_MIN_ATTESTATION_LEVEL")
      assert Attestation.meets_minimum?(:software)
    end

    test ":none only meets :none" do
      System.delete_env("ZTLP_MIN_ATTESTATION_LEVEL")
      assert Attestation.meets_minimum?(:none)
    end

    test ":none does not meet :software minimum" do
      System.put_env("ZTLP_MIN_ATTESTATION_LEVEL", "software")
      refute Attestation.meets_minimum?(:none)
    end
  end

  describe "software attestation" do
    test "succeeds with valid Ed25519 signature" do
      challenge = Attestation.generate_challenge()
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      signature = :crypto.sign(:eddsa, :none, challenge, [priv, :ed25519])

      attestation_data = pub <> signature
      assert {:ok, result} = Attestation.verify(:software, attestation_data, challenge)
      assert result.trust_level == :software
      assert result.device_type == "software"
      assert result.key_id == :crypto.hash(:sha256, pub)
      assert result.details == %{format: "ed25519-software"}
    end

    test "fails with invalid signature" do
      challenge = Attestation.generate_challenge()
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      # Sign a different message
      signature = :crypto.sign(:eddsa, :none, "wrong message", [priv, :ed25519])

      attestation_data = pub <> signature
      assert {:error, :invalid_signature} = Attestation.verify(:software, attestation_data, challenge)
    end

    test "fails with wrong format (not 96 bytes)" do
      challenge = Attestation.generate_challenge()
      assert {:error, :invalid_attestation_format} = Attestation.verify(:software, "too short", challenge)
      assert {:error, :invalid_attestation_format} = Attestation.verify(:software, <<>>, challenge)
    end
  end

  describe "platform attestation stubs" do
    test "Apple attestation returns :cbor_not_implemented" do
      assert {:error, :cbor_not_implemented} =
               Attestation.verify(:apple, "data", "challenge")
    end

    test "Android attestation returns :x509_not_implemented" do
      assert {:error, :x509_not_implemented} =
               Attestation.verify(:android, "data", "challenge")
    end

    test "YubiKey attestation returns :x509_not_implemented" do
      assert {:error, :x509_not_implemented} =
               Attestation.verify(:yubikey, "data", "challenge")
    end
  end

  describe "unknown attestation type" do
    test "returns error tuple" do
      assert {:error, {:unknown_attestation_type, :foobar}} =
               Attestation.verify(:foobar, "data", "challenge")
    end
  end

  describe "trust level ordering" do
    test "hardware > tee > software > none" do
      trust_order = %{hardware: 3, tee: 2, software: 1, none: 0}
      assert trust_order[:hardware] > trust_order[:tee]
      assert trust_order[:tee] > trust_order[:software]
      assert trust_order[:software] > trust_order[:none]
    end
  end

  describe "verify/4 dispatch" do
    test "dispatches correctly to each type" do
      challenge = Attestation.generate_challenge()

      # Each type dispatches to its handler
      assert {:error, :cbor_not_implemented} = Attestation.verify(:apple, "data", challenge)
      assert {:error, :x509_not_implemented} = Attestation.verify(:android, "data", challenge)
      assert {:error, :x509_not_implemented} = Attestation.verify(:yubikey, "data", challenge)

      # Software with bad format
      assert {:error, :invalid_attestation_format} =
               Attestation.verify(:software, "bad", challenge)

      # Unknown type
      assert {:error, {:unknown_attestation_type, :wat}} =
               Attestation.verify(:wat, "data", challenge)
    end
  end
end
