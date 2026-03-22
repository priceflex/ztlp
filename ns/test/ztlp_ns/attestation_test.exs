defmodule ZtlpNs.AttestationTest do
  use ExUnit.Case, async: true

  alias ZtlpNs.Attestation

  describe "verify/2" do
    test "yubikey with valid attestation chain returns hardware level" do
      # Build a simple attestation chain (root -> leaf)
      {_pub, root_priv} = ZtlpNs.X509.generate_rsa_keypair(2048)
      root_cert = ZtlpNs.X509.create_root_ca(root_priv, %{cn: "Yubico PIV Root CA"})

      {leaf_pub, _leaf_priv} = ZtlpNs.X509.generate_rsa_keypair(2048)
      leaf_cert = ZtlpNs.X509.create_intermediate_ca(
        root_priv, leaf_pub, %{cn: "Yubico PIV Root CA"}, %{cn: "YubiKey Attestation"}
      )

      result = Attestation.verify("yubikey", %{
        cert_chain: [leaf_cert, root_cert],
        public_key: leaf_pub
      })

      assert result.level == :hardware
      assert result.key_source == "yubikey"
      assert result.attestation_verified == true
    end

    test "yubikey without attestation returns device-bound" do
      result = Attestation.verify("yubikey", nil)
      assert result.level == :device_bound
      assert result.key_source == "yubikey"
      assert result.attestation_verified == false
    end

    test "yubikey with invalid attestation returns device-bound" do
      result = Attestation.verify("yubikey", %{cert_chain: [<<1, 2, 3>>], public_key: nil})
      assert result.level == :device_bound
      assert result.attestation_verified == false
    end

    test "tpm with valid attestation returns hardware level" do
      {_pub, root_priv} = ZtlpNs.X509.generate_rsa_keypair(2048)
      root_cert = ZtlpNs.X509.create_root_ca(root_priv, %{cn: "TPM Root"})

      {leaf_pub, _leaf_priv} = ZtlpNs.X509.generate_rsa_keypair(2048)
      leaf_cert = ZtlpNs.X509.create_intermediate_ca(
        root_priv, leaf_pub, %{cn: "TPM Root"}, %{cn: "TPM Attestation"}
      )

      result = Attestation.verify("tpm", %{cert_chain: [leaf_cert, root_cert], public_key: leaf_pub})
      assert result.level == :hardware
      assert result.key_source == "tpm"
      assert result.attestation_verified == true
    end

    test "tpm without attestation returns device-bound" do
      result = Attestation.verify("tpm", nil)
      assert result.level == :device_bound
      assert result.key_source == "tpm"
    end

    test "secure-enclave with valid attestation returns hardware" do
      {_pub, root_priv} = ZtlpNs.X509.generate_rsa_keypair(2048)
      root_cert = ZtlpNs.X509.create_root_ca(root_priv, %{cn: "Apple Root"})

      {leaf_pub, _} = ZtlpNs.X509.generate_rsa_keypair(2048)
      leaf_cert = ZtlpNs.X509.create_intermediate_ca(
        root_priv, leaf_pub, %{cn: "Apple Root"}, %{cn: "SE Attestation"}
      )

      result = Attestation.verify("secure-enclave", %{cert_chain: [leaf_cert, root_cert], public_key: leaf_pub})
      assert result.level == :hardware
      assert result.key_source == "secure-enclave"
    end

    test "secure-enclave without attestation returns device-bound" do
      result = Attestation.verify("secure-enclave", nil)
      assert result.level == :device_bound
      assert result.key_source == "secure-enclave"
    end

    test "strongbox with valid attestation returns hardware" do
      {_pub, root_priv} = ZtlpNs.X509.generate_rsa_keypair(2048)
      root_cert = ZtlpNs.X509.create_root_ca(root_priv, %{cn: "Android Root"})

      {leaf_pub, _} = ZtlpNs.X509.generate_rsa_keypair(2048)
      leaf_cert = ZtlpNs.X509.create_intermediate_ca(
        root_priv, leaf_pub, %{cn: "Android Root"}, %{cn: "StrongBox"}
      )

      result = Attestation.verify("strongbox", %{cert_chain: [leaf_cert, root_cert], public_key: leaf_pub})
      assert result.level == :hardware
      assert result.key_source == "strongbox"
    end

    test "strongbox without attestation returns device-bound" do
      result = Attestation.verify("strongbox", nil)
      assert result.level == :device_bound
      assert result.key_source == "strongbox"
    end

    test "file returns software level" do
      result = Attestation.verify("file", nil)
      assert result.level == :software
      assert result.key_source == "file"
      assert result.attestation_verified == false
    end

    test "file ignores attestation" do
      result = Attestation.verify("file", %{cert_chain: [], public_key: nil})
      assert result.level == :software
    end

    test "unknown returns unknown level" do
      result = Attestation.verify("unknown", nil)
      assert result.level == :unknown
      assert result.key_source == "unknown"
    end

    test "unrecognized source returns unknown level" do
      result = Attestation.verify("some-weird-thing", nil)
      assert result.level == :unknown
      assert result.key_source == "unknown"
    end
  end

  describe "meets_minimum?/2" do
    test "hardware meets all levels" do
      assert Attestation.meets_minimum?(:hardware, :hardware)
      assert Attestation.meets_minimum?(:hardware, :device_bound)
      assert Attestation.meets_minimum?(:hardware, :software)
      assert Attestation.meets_minimum?(:hardware, :unknown)
    end

    test "device_bound meets device_bound and below" do
      refute Attestation.meets_minimum?(:device_bound, :hardware)
      assert Attestation.meets_minimum?(:device_bound, :device_bound)
      assert Attestation.meets_minimum?(:device_bound, :software)
      assert Attestation.meets_minimum?(:device_bound, :unknown)
    end

    test "software meets software and below" do
      refute Attestation.meets_minimum?(:software, :hardware)
      refute Attestation.meets_minimum?(:software, :device_bound)
      assert Attestation.meets_minimum?(:software, :software)
      assert Attestation.meets_minimum?(:software, :unknown)
    end

    test "unknown only meets unknown" do
      refute Attestation.meets_minimum?(:unknown, :hardware)
      refute Attestation.meets_minimum?(:unknown, :device_bound)
      refute Attestation.meets_minimum?(:unknown, :software)
      assert Attestation.meets_minimum?(:unknown, :unknown)
    end
  end

  describe "level_value/1" do
    test "returns correct numeric values" do
      assert Attestation.level_value(:hardware) == 4
      assert Attestation.level_value(:device_bound) == 3
      assert Attestation.level_value(:software) == 2
      assert Attestation.level_value(:unknown) == 1
      assert Attestation.level_value(:nonsense) == 0
    end
  end

  describe "parse_level/1" do
    test "parses known levels" do
      assert Attestation.parse_level("hardware") == :hardware
      assert Attestation.parse_level("device_bound") == :device_bound
      assert Attestation.parse_level("device-bound") == :device_bound
      assert Attestation.parse_level("software") == :software
      assert Attestation.parse_level("unknown") == :unknown
    end

    test "unknown strings default to :unknown" do
      assert Attestation.parse_level("bogus") == :unknown
      assert Attestation.parse_level("") == :unknown
    end
  end

  describe "level_to_string/1" do
    test "converts levels to strings" do
      assert Attestation.level_to_string(:hardware) == "hardware"
      assert Attestation.level_to_string(:device_bound) == "device-bound"
      assert Attestation.level_to_string(:software) == "software"
      assert Attestation.level_to_string(:unknown) == "unknown"
      assert Attestation.level_to_string(:bogus) == "unknown"
    end
  end
end
