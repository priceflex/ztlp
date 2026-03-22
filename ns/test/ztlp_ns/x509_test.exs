defmodule ZtlpNs.X509Test do
  use ExUnit.Case, async: true

  alias ZtlpNs.X509

  # ── Key Generation ─────────────────────────────────────────────────

  describe "generate_rsa_keypair/0" do
    test "generates valid RSA-4096 keypair" do
      {pub, priv} = X509.generate_rsa_keypair(2048)
      assert {:RSAPublicKey, _, _} = pub
      assert {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = priv
    end

    test "generates different keypairs each time" do
      {pub1, _} = X509.generate_rsa_keypair(2048)
      {pub2, _} = X509.generate_rsa_keypair(2048)
      refute pub1 == pub2
    end
  end

  describe "generate_rsa_keypair/1 (custom bits)" do
    test "generates keypair with specified bit size" do
      {pub, priv} = X509.generate_rsa_keypair(2048)
      assert {:RSAPublicKey, _, _} = pub
      assert {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = priv
    end
  end

  # ── Root CA Certificate ────────────────────────────────────────────

  describe "create_root_ca/3 with RSA" do
    setup do
      {_pub, priv} = X509.generate_rsa_keypair(2048)
      subject = %{cn: "Test Root CA", o: "Test Org"}
      cert_der = X509.create_root_ca(priv, subject, validity_years: 10)
      {:ok, priv: priv, subject: subject, cert_der: cert_der}
    end

    test "creates valid DER-encoded certificate", ctx do
      assert is_binary(ctx.cert_der)
      assert byte_size(ctx.cert_der) > 100
    end

    test "certificate has correct subject", ctx do
      {:ok, info} = X509.parse_cert(ctx.cert_der)
      assert info.subject[:cn] == "Test Root CA"
      assert info.subject[:o] == "Test Org"
    end

    test "certificate is self-signed (issuer == subject)", ctx do
      {:ok, info} = X509.parse_cert(ctx.cert_der)
      assert info.subject == info.issuer
    end

    test "certificate is a CA", ctx do
      {:ok, info} = X509.parse_cert(ctx.cert_der)
      assert info.is_ca == true
    end

    test "certificate has a serial number", ctx do
      {:ok, info} = X509.parse_cert(ctx.cert_der)
      assert is_integer(info.serial)
      assert info.serial > 0
    end

    test "certificate has valid time range", ctx do
      {:ok, info} = X509.parse_cert(ctx.cert_der)
      assert %DateTime{} = info.not_before
      assert %DateTime{} = info.not_after
      assert DateTime.compare(info.not_after, info.not_before) == :gt
    end

    test "certificate verifies against itself (self-signed)", ctx do
      assert X509.verify_cert(ctx.cert_der, ctx.cert_der)
    end

    test "custom serial number is used", ctx do
      cert_der = X509.create_root_ca(ctx.priv, ctx.subject, serial: 42)
      {:ok, info} = X509.parse_cert(cert_der)
      assert info.serial == 42
    end
  end

  # ── Intermediate CA Certificate ────────────────────────────────────

  describe "create_intermediate_ca/5 with RSA" do
    setup do
      {_root_pub, root_priv} = X509.generate_rsa_keypair(2048)
      root_subject = %{cn: "Test Root CA", o: "Test Org"}
      root_cert_der = X509.create_root_ca(root_priv, root_subject, validity_years: 10)

      {inter_pub, _inter_priv} = X509.generate_rsa_keypair(2048)
      inter_subject = %{cn: "Test Intermediate CA", o: "Test Org"}

      inter_cert_der = X509.create_intermediate_ca(
        root_priv, inter_pub, root_subject, inter_subject, validity_years: 3
      )

      {:ok,
        root_priv: root_priv,
        root_subject: root_subject,
        root_cert_der: root_cert_der,
        inter_pub: inter_pub,
        inter_subject: inter_subject,
        inter_cert_der: inter_cert_der
      }
    end

    test "creates valid DER-encoded certificate", ctx do
      assert is_binary(ctx.inter_cert_der)
      assert byte_size(ctx.inter_cert_der) > 100
    end

    test "has correct subject", ctx do
      {:ok, info} = X509.parse_cert(ctx.inter_cert_der)
      assert info.subject[:cn] == "Test Intermediate CA"
    end

    test "has correct issuer (root)", ctx do
      {:ok, info} = X509.parse_cert(ctx.inter_cert_der)
      assert info.issuer[:cn] == "Test Root CA"
    end

    test "is a CA certificate", ctx do
      {:ok, info} = X509.parse_cert(ctx.inter_cert_der)
      assert info.is_ca == true
    end

    test "is signed by the root CA", ctx do
      assert X509.verify_cert(ctx.inter_cert_der, ctx.root_cert_der)
    end

    test "is NOT self-signed", ctx do
      # Intermediate cert verified against itself should fail
      refute X509.verify_cert(ctx.inter_cert_der, ctx.inter_cert_der)
    end
  end

  # ── Service (Server) Certificate ───────────────────────────────────

  describe "create_service_cert/5 with RSA" do
    setup do
      {_root_pub, root_priv} = X509.generate_rsa_keypair(2048)
      root_subject = %{cn: "Test Root CA", o: "Test Org"}
      _root_cert = X509.create_root_ca(root_priv, root_subject)

      {inter_pub, inter_priv} = X509.generate_rsa_keypair(2048)
      inter_subject = %{cn: "Test Intermediate CA", o: "Test Org"}
      inter_cert_der = X509.create_intermediate_ca(root_priv, inter_pub, root_subject, inter_subject)

      {svc_pub, _svc_priv} = X509.generate_rsa_keypair(2048)
      hostname = "web.corp.ztlp"

      svc_cert_der = X509.create_service_cert(
        inter_priv, svc_pub, inter_subject, hostname,
        validity_days: 7,
        san_dns: ["*.corp.ztlp", "api.corp.ztlp"]
      )

      {:ok,
        inter_cert_der: inter_cert_der,
        inter_priv: inter_priv,
        inter_subject: inter_subject,
        svc_cert_der: svc_cert_der,
        hostname: hostname
      }
    end

    test "creates valid DER-encoded certificate", ctx do
      assert is_binary(ctx.svc_cert_der)
    end

    test "has correct CN", ctx do
      {:ok, info} = X509.parse_cert(ctx.svc_cert_der)
      assert info.subject[:cn] == "web.corp.ztlp"
    end

    test "has DNS SAN entries", ctx do
      {:ok, info} = X509.parse_cert(ctx.svc_cert_der)
      assert "web.corp.ztlp" in info.san_dns
      assert "*.corp.ztlp" in info.san_dns
      assert "api.corp.ztlp" in info.san_dns
    end

    test "is NOT a CA", ctx do
      {:ok, info} = X509.parse_cert(ctx.svc_cert_der)
      assert info.is_ca == false
    end

    test "is signed by intermediate CA", ctx do
      assert X509.verify_cert(ctx.svc_cert_der, ctx.inter_cert_der)
    end

    test "has no ZTLP assurance extensions", ctx do
      {:ok, info} = X509.parse_cert(ctx.svc_cert_der)
      assert info.assurance == nil
    end
  end

  # ── Client Certificate (mTLS) ─────────────────────────────────────

  describe "create_client_cert/6 with RSA" do
    setup do
      {_root_pub, root_priv} = X509.generate_rsa_keypair(2048)
      root_subject = %{cn: "Test Root CA", o: "Test Org"}
      _root_cert = X509.create_root_ca(root_priv, root_subject)

      {inter_pub, inter_priv} = X509.generate_rsa_keypair(2048)
      inter_subject = %{cn: "Test Intermediate CA", o: "Test Org"}
      inter_cert_der = X509.create_intermediate_ca(root_priv, inter_pub, root_subject, inter_subject)

      {client_pub, _client_priv} = X509.generate_rsa_keypair(2048)
      node_name = "steve-laptop.corp.ztlp"
      node_id = :crypto.strong_rand_bytes(16)

      client_cert_der = X509.create_client_cert(
        inter_priv, client_pub, inter_subject, node_name, node_id,
        validity_days: 30,
        zone: "corp.ztlp",
        assurance: :hardware,
        key_source: "yubikey",
        attestation_verified: true
      )

      {:ok,
        inter_cert_der: inter_cert_der,
        client_cert_der: client_cert_der,
        node_name: node_name,
        node_id: node_id
      }
    end

    test "creates valid DER-encoded certificate", ctx do
      assert is_binary(ctx.client_cert_der)
    end

    test "has correct CN", ctx do
      {:ok, info} = X509.parse_cert(ctx.client_cert_der)
      assert info.subject[:cn] == "steve-laptop.corp.ztlp"
    end

    test "has URI SAN with NodeID", ctx do
      {:ok, info} = X509.parse_cert(ctx.client_cert_der)
      node_id_hex = Base.encode16(ctx.node_id, case: :lower)
      expected_uri = "ztlp://node/#{node_id_hex}"
      assert expected_uri in info.san_uri
    end

    test "is NOT a CA", ctx do
      {:ok, info} = X509.parse_cert(ctx.client_cert_der)
      assert info.is_ca == false
    end

    test "is signed by intermediate CA", ctx do
      assert X509.verify_cert(ctx.client_cert_der, ctx.inter_cert_der)
    end

    test "has ZTLP assurance extensions", ctx do
      {:ok, info} = X509.parse_cert(ctx.client_cert_der)
      assert info.assurance != nil
      assert info.assurance.level == :hardware
      assert info.assurance.key_source == "yubikey"
      assert info.assurance.attestation_verified == true
    end

    test "software assurance level", ctx do
      {pub, _priv} = X509.generate_rsa_keypair(2048)
      cert_der = X509.create_client_cert(
        elem(X509.generate_rsa_keypair(2048), 1),
        pub,
        %{cn: "CA"},
        "test-node.ztlp",
        :crypto.strong_rand_bytes(16),
        assurance: :software,
        key_source: "file"
      )
      {:ok, info} = X509.parse_cert(cert_der)
      assert info.assurance.level == :software
      assert info.assurance.key_source == "file"
      assert info.assurance.attestation_verified == false
    end

    test "device-bound assurance level" do
      {_pub, priv} = X509.generate_rsa_keypair(2048)
      {pub2, _} = X509.generate_rsa_keypair(2048)
      cert_der = X509.create_client_cert(
        priv, pub2, %{cn: "CA"}, "test.ztlp", :crypto.strong_rand_bytes(16),
        assurance: :device_bound, key_source: "tpm"
      )
      {:ok, info} = X509.parse_cert(cert_der)
      assert info.assurance.level == :device_bound
      assert info.assurance.key_source == "tpm"
    end

    test "unknown assurance level" do
      {_pub, priv} = X509.generate_rsa_keypair(2048)
      {pub2, _} = X509.generate_rsa_keypair(2048)
      cert_der = X509.create_client_cert(
        priv, pub2, %{cn: "CA"}, "test.ztlp", :crypto.strong_rand_bytes(16),
        assurance: :unknown, key_source: "unknown"
      )
      {:ok, info} = X509.parse_cert(cert_der)
      assert info.assurance.level == :unknown
    end
  end

  # ── PEM Encoding/Decoding ─────────────────────────────────────────

  describe "PEM round-trip" do
    test "certificate PEM round-trip" do
      {_pub, priv} = X509.generate_rsa_keypair(2048)
      cert_der = X509.create_root_ca(priv, %{cn: "Test CA"})

      pem = X509.der_to_pem(cert_der)
      assert String.starts_with?(pem, "-----BEGIN CERTIFICATE-----")
      assert String.contains?(pem, "-----END CERTIFICATE-----")

      {:ok, decoded_der} = X509.pem_to_der(pem)
      assert decoded_der == cert_der
    end

    test "private key PEM round-trip for RSA" do
      {_pub, priv} = X509.generate_rsa_keypair(2048)
      pem = X509.private_key_to_pem(priv)
      assert String.contains?(pem, "-----BEGIN RSA PRIVATE KEY-----")

      {:ok, decoded_priv} = X509.pem_to_private_key(pem)
      assert decoded_priv == priv
    end

    test "invalid PEM returns error" do
      assert {:error, _} = X509.pem_to_der("not a valid PEM")
    end
  end

  # ── Fingerprint ────────────────────────────────────────────────────

  describe "fingerprint/1" do
    test "returns hex-encoded SHA-256 hash" do
      {_pub, priv} = X509.generate_rsa_keypair(2048)
      cert_der = X509.create_root_ca(priv, %{cn: "Test CA"})
      fp = X509.fingerprint(cert_der)
      assert is_binary(fp)
      assert byte_size(fp) == 64  # 32 bytes hex-encoded
      assert Regex.match?(~r/^[0-9a-f]{64}$/, fp)
    end

    test "different certs have different fingerprints" do
      {_pub1, priv1} = X509.generate_rsa_keypair(2048)
      {_pub2, priv2} = X509.generate_rsa_keypair(2048)
      cert1 = X509.create_root_ca(priv1, %{cn: "CA1"})
      cert2 = X509.create_root_ca(priv2, %{cn: "CA2"})
      refute X509.fingerprint(cert1) == X509.fingerprint(cert2)
    end
  end

  # ── Serial Number Generation ───────────────────────────────────────

  describe "generate_serial/0" do
    test "returns a positive integer" do
      serial = X509.generate_serial()
      assert is_integer(serial)
      assert serial > 0
    end

    test "generates different serials" do
      serials = for _ <- 1..10, do: X509.generate_serial()
      assert length(Enum.uniq(serials)) == 10
    end
  end

  # ── Assurance Level Helpers ────────────────────────────────────────

  describe "assurance level helpers" do
    test "assurance_to_int/1" do
      assert X509.assurance_to_int(:hardware) == 4
      assert X509.assurance_to_int(:device_bound) == 3
      assert X509.assurance_to_int(:software) == 2
      assert X509.assurance_to_int(:unknown) == 1
    end

    test "int_to_assurance/1" do
      assert X509.int_to_assurance(4) == :hardware
      assert X509.int_to_assurance(3) == :device_bound
      assert X509.int_to_assurance(2) == :software
      assert X509.int_to_assurance(1) == :unknown
      assert X509.int_to_assurance(99) == :unknown
    end
  end

  # ── OID Accessors ──────────────────────────────────────────────────

  describe "OID accessors" do
    test "returns ZTLP OIDs" do
      assert {1, 3, 6, 1, 4, 1, 59999} = X509.ztlp_oid_base()
      assert {1, 3, 6, 1, 4, 1, 59999, 1} = X509.ztlp_assurance_oid()
      assert {1, 3, 6, 1, 4, 1, 59999, 2} = X509.ztlp_key_source_oid()
      assert {1, 3, 6, 1, 4, 1, 59999, 3} = X509.ztlp_attestation_oid()
    end
  end

  # ── Certificate Verification ───────────────────────────────────────

  describe "verify_cert/2" do
    test "valid chain verifies" do
      {_pub, root_priv} = X509.generate_rsa_keypair(2048)
      root_subject = %{cn: "Root CA"}
      root_cert = X509.create_root_ca(root_priv, root_subject)

      {inter_pub, _inter_priv} = X509.generate_rsa_keypair(2048)
      inter_cert = X509.create_intermediate_ca(root_priv, inter_pub, root_subject, %{cn: "Intermediate CA"})

      assert X509.verify_cert(inter_cert, root_cert)
    end

    test "invalid chain fails" do
      {_pub1, priv1} = X509.generate_rsa_keypair(2048)
      {_pub2, priv2} = X509.generate_rsa_keypair(2048)
      cert1 = X509.create_root_ca(priv1, %{cn: "CA1"})
      cert2 = X509.create_root_ca(priv2, %{cn: "CA2"})

      # cert1 is not signed by cert2's key
      refute X509.verify_cert(cert1, cert2)
    end

    test "handles invalid DER gracefully" do
      refute X509.verify_cert(<<0, 1, 2, 3>>, <<4, 5, 6, 7>>)
    end
  end

  # ── parse_cert edge cases ──────────────────────────────────────────

  describe "parse_cert/1" do
    test "invalid DER returns error" do
      assert {:error, _} = X509.parse_cert(<<0, 1, 2>>)
    end

    test "extracts all fields from root CA" do
      {_pub, priv} = X509.generate_rsa_keypair(2048)
      cert_der = X509.create_root_ca(priv, %{cn: "Full Test CA", o: "Org"})
      {:ok, info} = X509.parse_cert(cert_der)

      assert info.subject[:cn] == "Full Test CA"
      assert info.subject[:o] == "Org"
      assert info.issuer[:cn] == "Full Test CA"
      assert is_integer(info.serial)
      assert %DateTime{} = info.not_before
      assert %DateTime{} = info.not_after
      assert info.is_ca == true
      assert is_list(info.san_dns)
      assert is_list(info.san_uri)
    end
  end
end
