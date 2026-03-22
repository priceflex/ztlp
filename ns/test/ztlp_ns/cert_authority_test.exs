defmodule ZtlpNs.CertAuthorityTest do
  use ExUnit.Case

  alias ZtlpNs.CertAuthority
  alias ZtlpNs.X509

  # Use a temp directory for each test to avoid conflicts
  setup do
    test_dir = Path.join(System.tmp_dir!(), "ztlp_ca_test_#{:rand.uniform(1_000_000)}")
    File.mkdir_p!(test_dir)

    # Stop existing CertAuthority if running
    case GenServer.whereis(CertAuthority) do
      nil -> :ok
      pid ->
        GenServer.stop(pid, :normal, 5000)
        # Wait for process to terminate
        Process.sleep(50)
    end

    # Start a new CertAuthority with test directory
    {:ok, pid} = CertAuthority.start_link(ca_dir: test_dir)

    on_exit(fn ->
      if Process.alive?(pid) do
        GenServer.stop(pid, :normal, 5000)
      end
      File.rm_rf!(test_dir)
    end)

    {:ok, ca_dir: test_dir, pid: pid}
  end

  describe "init_ca/1" do
    test "initializes CA with default settings" do
      assert {:ok, result} = CertAuthority.init_ca(org: "Test Org")
      assert is_binary(result.root_cert)
      assert is_binary(result.intermediate_cert)
      assert is_binary(result.chain)
      assert String.contains?(result.root_cert, "BEGIN CERTIFICATE")
      assert String.contains?(result.intermediate_cert, "BEGIN CERTIFICATE")
    end

    test "creates valid root CA certificate" do
      {:ok, result} = CertAuthority.init_ca(org: "Test Org")
      {:ok, root_der} = X509.pem_to_der(result.root_cert)
      {:ok, info} = X509.parse_cert(root_der)
      assert info.subject[:cn] == "ZTLP Root CA"
      assert info.subject[:o] == "Test Org"
      assert info.is_ca == true
    end

    test "creates valid intermediate CA certificate" do
      {:ok, result} = CertAuthority.init_ca(org: "Test Org")
      {:ok, inter_der} = X509.pem_to_der(result.intermediate_cert)
      {:ok, info} = X509.parse_cert(inter_der)
      assert info.subject[:cn] == "ZTLP Intermediate CA"
      assert info.is_ca == true
    end

    test "intermediate is signed by root" do
      {:ok, result} = CertAuthority.init_ca(org: "Test Org")
      {:ok, root_der} = X509.pem_to_der(result.root_cert)
      {:ok, inter_der} = X509.pem_to_der(result.intermediate_cert)
      assert X509.verify_cert(inter_der, root_der)
    end

    test "chain contains both certificates" do
      {:ok, result} = CertAuthority.init_ca(org: "Test Org")
      assert String.contains?(result.chain, "ZTLP Intermediate CA") or
             String.contains?(result.chain, "BEGIN CERTIFICATE")
      # Chain should contain two PEM certificates
      cert_count = result.chain
        |> String.split("-----BEGIN CERTIFICATE-----")
        |> length()
      assert cert_count >= 3  # empty first + 2 certs = 3 parts
    end

    test "refuses to initialize twice" do
      assert {:ok, _} = CertAuthority.init_ca()
      assert {:error, :already_initialized} = CertAuthority.init_ca()
    end

    test "saves files to disk", %{ca_dir: dir} do
      assert {:ok, _} = CertAuthority.init_ca()
      assert File.exists?(Path.join(dir, "root.pem"))
      assert File.exists?(Path.join(dir, "root.key.enc"))
      assert File.exists?(Path.join(dir, "intermediate.pem"))
      assert File.exists?(Path.join(dir, "intermediate.key"))
      assert File.exists?(Path.join(dir, "chain.pem"))
    end
  end

  describe "show/0" do
    test "returns error when not initialized" do
      # We need to restart with a fresh directory
      assert {:error, :not_initialized} = CertAuthority.show()
    end

    test "returns CA info after initialization" do
      {:ok, _} = CertAuthority.init_ca(org: "Show Test")
      {:ok, info} = CertAuthority.show()

      assert info.root.subject[:cn] == "ZTLP Root CA"
      assert info.intermediate.subject[:cn] == "ZTLP Intermediate CA"
      assert is_binary(info.root.fingerprint)
      assert is_binary(info.intermediate.fingerprint)
      assert info.root.is_ca == true
      assert info.intermediate.is_ca == true
    end
  end

  describe "export_root/0" do
    test "returns error when not initialized" do
      assert {:error, :not_initialized} = CertAuthority.export_root()
    end

    test "returns root PEM" do
      {:ok, _} = CertAuthority.init_ca()
      {:ok, pem} = CertAuthority.export_root()
      assert String.contains?(pem, "BEGIN CERTIFICATE")
    end
  end

  describe "get_signing_key/0" do
    test "returns error when not initialized" do
      assert {:error, :not_initialized} = CertAuthority.get_signing_key()
    end

    test "returns intermediate key and subject" do
      {:ok, _} = CertAuthority.init_ca()
      {:ok, {key, subject}} = CertAuthority.get_signing_key()
      assert key != nil
      assert is_map(subject)
      assert subject[:cn] == "ZTLP Intermediate CA"
    end
  end

  describe "get_chain_pem/0" do
    test "returns error when not initialized" do
      assert {:error, :not_initialized} = CertAuthority.get_chain_pem()
    end

    test "returns chain PEM" do
      {:ok, _} = CertAuthority.init_ca()
      {:ok, pem} = CertAuthority.get_chain_pem()
      assert String.contains?(pem, "BEGIN CERTIFICATE")
    end
  end

  describe "get_root_cert_der/0" do
    test "returns error when not initialized" do
      assert {:error, :not_initialized} = CertAuthority.get_root_cert_der()
    end

    test "returns DER binary" do
      {:ok, _} = CertAuthority.init_ca()
      {:ok, der} = CertAuthority.get_root_cert_der()
      assert is_binary(der)
      {:ok, info} = X509.parse_cert(der)
      assert info.is_ca == true
    end
  end

  describe "initialized?/0" do
    test "returns false before init" do
      refute CertAuthority.initialized?()
    end

    test "returns true after init" do
      {:ok, _} = CertAuthority.init_ca()
      assert CertAuthority.initialized?()
    end
  end

  describe "rotate_intermediate/1" do
    test "returns error when not initialized" do
      assert {:error, :not_initialized} = CertAuthority.rotate_intermediate()
    end

    test "generates new intermediate CA" do
      {:ok, initial} = CertAuthority.init_ca()
      {:ok, rotated} = CertAuthority.rotate_intermediate()

      assert rotated.intermediate_cert != initial.intermediate_cert
      # Chain should be updated too
      assert rotated.chain != initial.chain
    end

    test "new intermediate is still signed by root" do
      {:ok, initial} = CertAuthority.init_ca()
      {:ok, root_der} = X509.pem_to_der(initial.root_cert)
      {:ok, _rotated} = CertAuthority.rotate_intermediate()

      {:ok, {_key, _subj}} = CertAuthority.get_signing_key()
      {:ok, chain_pem} = CertAuthority.get_chain_pem()

      # Extract new intermediate from chain
      certs = String.split(chain_pem, "-----END CERTIFICATE-----")
      |> Enum.filter(&String.contains?(&1, "BEGIN CERTIFICATE"))
      |> Enum.map(fn c -> c <> "-----END CERTIFICATE-----\n" end)

      if length(certs) >= 1 do
        {:ok, new_inter_der} = X509.pem_to_der(hd(certs))
        assert X509.verify_cert(new_inter_der, root_der)
      end
    end
  end

  describe "encryption" do
    test "encrypt/decrypt round-trip" do
      plaintext = "test secret key data"
      passphrase = "test-passphrase"

      encrypted = CertAuthority.encrypt_key(plaintext, passphrase)
      assert encrypted != plaintext
      assert {:ok, ^plaintext} = CertAuthority.decrypt_key(encrypted, passphrase)
    end

    test "wrong passphrase fails" do
      plaintext = "test secret key data"
      encrypted = CertAuthority.encrypt_key(plaintext, "right-passphrase")
      assert {:error, :decryption_failed} = CertAuthority.decrypt_key(encrypted, "wrong-passphrase")
    end
  end

  describe "persistence" do
    test "CA state survives restart", %{ca_dir: dir, pid: pid} do
      # Initialize
      {:ok, initial} = CertAuthority.init_ca(org: "Persist Test")
      initial_root_fp = case CertAuthority.show() do
        {:ok, info} -> info.root.fingerprint
        _ -> nil
      end

      # Stop and restart
      GenServer.stop(pid, :normal, 5000)
      Process.sleep(50)
      {:ok, _new_pid} = CertAuthority.start_link(ca_dir: dir)

      # Should still be initialized
      assert CertAuthority.initialized?()
      {:ok, info} = CertAuthority.show()
      assert info.root.fingerprint == initial_root_fp
    end
  end
end
