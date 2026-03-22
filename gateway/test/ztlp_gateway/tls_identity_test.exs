defmodule ZtlpGateway.TlsIdentityTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.TlsIdentity

  # Helper to create a test client cert DER
  defp make_client_cert(opts \\ []) do
    {_root_pub, root_priv} = ZtlpNs.X509.generate_rsa_keypair(2048)
    root_subject = %{cn: "Test Root CA", o: "Test"}
    _root_cert = ZtlpNs.X509.create_root_ca(root_priv, root_subject)

    {inter_pub, inter_priv} = ZtlpNs.X509.generate_rsa_keypair(2048)
    inter_subject = %{cn: "Test Intermediate CA", o: "Test"}
    _inter_cert = ZtlpNs.X509.create_intermediate_ca(root_priv, inter_pub, root_subject, inter_subject)

    {client_pub, _} = ZtlpNs.X509.generate_rsa_keypair(2048)
    node_name = Keyword.get(opts, :node_name, "test-node.corp.ztlp")
    node_id = Keyword.get(opts, :node_id, :crypto.strong_rand_bytes(16))
    assurance = Keyword.get(opts, :assurance, :software)
    key_source = Keyword.get(opts, :key_source, "file")
    attestation = Keyword.get(opts, :attestation_verified, false)
    zone = Keyword.get(opts, :zone, "corp.ztlp")

    ZtlpNs.X509.create_client_cert(
      inter_priv, client_pub, inter_subject, node_name, node_id,
      zone: zone, assurance: assurance, key_source: key_source,
      attestation_verified: attestation
    )
  end

  describe "extract_from_der/1" do
    test "extracts node ID from SAN URI" do
      node_id = :crypto.strong_rand_bytes(16)
      cert_der = make_client_cert(node_id: node_id)
      identity = TlsIdentity.extract_from_der(cert_der)

      expected_hex = Base.encode16(node_id, case: :lower)
      assert identity.node_id == expected_hex
    end

    test "extracts node name from CN" do
      cert_der = make_client_cert(node_name: "steve-laptop.corp.ztlp")
      identity = TlsIdentity.extract_from_der(cert_der)
      assert identity.node_name == "steve-laptop.corp.ztlp"
    end

    test "extracts zone from O" do
      cert_der = make_client_cert(zone: "prod.ztlp")
      identity = TlsIdentity.extract_from_der(cert_der)
      assert identity.zone == "prod.ztlp"
    end

    test "extracts hardware assurance level" do
      cert_der = make_client_cert(assurance: :hardware, key_source: "yubikey", attestation_verified: true)
      identity = TlsIdentity.extract_from_der(cert_der)
      assert identity.assurance == :hardware
      assert identity.key_source == "yubikey"
      assert identity.attestation_verified == true
    end

    test "extracts device-bound assurance level" do
      cert_der = make_client_cert(assurance: :device_bound, key_source: "tpm")
      identity = TlsIdentity.extract_from_der(cert_der)
      assert identity.assurance == :device_bound
      assert identity.key_source == "tpm"
    end

    test "extracts software assurance level" do
      cert_der = make_client_cert(assurance: :software, key_source: "file")
      identity = TlsIdentity.extract_from_der(cert_der)
      assert identity.assurance == :software
      assert identity.key_source == "file"
      assert identity.attestation_verified == false
    end

    test "extracts unknown assurance level" do
      cert_der = make_client_cert(assurance: :unknown, key_source: "unknown")
      identity = TlsIdentity.extract_from_der(cert_der)
      assert identity.assurance == :unknown
    end

    test "includes cert fingerprint" do
      cert_der = make_client_cert()
      identity = TlsIdentity.extract_from_der(cert_der)
      assert is_binary(identity.cert_fingerprint)
      assert byte_size(identity.cert_fingerprint) == 64
    end

    test "includes cert serial" do
      cert_der = make_client_cert()
      identity = TlsIdentity.extract_from_der(cert_der)
      assert is_binary(identity.cert_serial)
      assert identity.cert_serial != ""
    end

    test "marks as authenticated" do
      cert_der = make_client_cert()
      identity = TlsIdentity.extract_from_der(cert_der)
      assert identity.authenticated == true
    end

    test "handles invalid DER gracefully" do
      identity = TlsIdentity.extract_from_der(<<0, 1, 2, 3>>)
      assert identity.authenticated == false
      assert identity.node_id == nil
    end
  end

  describe "anonymous_identity/0" do
    test "returns unauthenticated identity" do
      identity = TlsIdentity.anonymous_identity()
      assert identity.authenticated == false
      assert identity.node_id == nil
      assert identity.assurance == :unknown
    end
  end

  describe "meets_assurance?/2" do
    test "hardware meets all levels" do
      identity = %{assurance: :hardware}
      assert TlsIdentity.meets_assurance?(identity, :hardware)
      assert TlsIdentity.meets_assurance?(identity, :device_bound)
      assert TlsIdentity.meets_assurance?(identity, :software)
      assert TlsIdentity.meets_assurance?(identity, :unknown)
    end

    test "software does not meet hardware" do
      identity = %{assurance: :software}
      refute TlsIdentity.meets_assurance?(identity, :hardware)
      refute TlsIdentity.meets_assurance?(identity, :device_bound)
      assert TlsIdentity.meets_assurance?(identity, :software)
      assert TlsIdentity.meets_assurance?(identity, :unknown)
    end

    test "unknown only meets unknown" do
      identity = %{assurance: :unknown}
      refute TlsIdentity.meets_assurance?(identity, :hardware)
      assert TlsIdentity.meets_assurance?(identity, :unknown)
    end
  end

  describe "authenticated?/1" do
    test "nil is not authenticated" do
      refute TlsIdentity.authenticated?(nil)
    end

    test "identity with authenticated: true" do
      assert TlsIdentity.authenticated?(%{authenticated: true})
    end

    test "identity with authenticated: false" do
      refute TlsIdentity.authenticated?(%{authenticated: false})
    end
  end
end
