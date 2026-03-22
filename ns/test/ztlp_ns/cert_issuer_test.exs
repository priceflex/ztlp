defmodule ZtlpNs.CertIssuerTest do
  use ExUnit.Case

  alias ZtlpNs.CertIssuer
  alias ZtlpNs.CertAuthority
  alias ZtlpNs.X509

  setup do
    test_dir = Path.join(System.tmp_dir!(), "ztlp_issuer_test_#{:rand.uniform(1_000_000)}")
    File.mkdir_p!(test_dir)

    # Stop existing CertAuthority if running
    case GenServer.whereis(CertAuthority) do
      nil -> :ok
      pid ->
        GenServer.stop(pid, :normal, 5000)
        Process.sleep(50)
    end

    {:ok, ca_pid} = CertAuthority.start_link(ca_dir: test_dir)
    {:ok, _} = CertAuthority.init_ca(org: "Issuer Test")

    on_exit(fn ->
      if Process.alive?(ca_pid), do: GenServer.stop(ca_pid, :normal, 5000)
      File.rm_rf!(test_dir)
    end)

    {:ok, ca_dir: test_dir}
  end

  describe "issue_server_cert/2" do
    test "issues a valid server certificate" do
      assert {:ok, result} = CertIssuer.issue_server_cert("web.corp.ztlp")
      assert is_binary(result.cert_pem)
      assert is_binary(result.key_pem)
      assert is_binary(result.chain_pem)
      assert String.contains?(result.cert_pem, "BEGIN CERTIFICATE")
      assert String.contains?(result.key_pem, "PRIVATE KEY")
    end

    test "certificate has correct hostname" do
      {:ok, result} = CertIssuer.issue_server_cert("api.corp.ztlp")
      {:ok, info} = X509.parse_cert(result.cert_der)
      assert info.subject[:cn] == "api.corp.ztlp"
    end

    test "certificate has DNS SANs" do
      {:ok, result} = CertIssuer.issue_server_cert("web.corp.ztlp",
        san_dns: ["api.corp.ztlp", "admin.corp.ztlp"])
      {:ok, info} = X509.parse_cert(result.cert_der)
      assert "web.corp.ztlp" in info.san_dns
      assert "api.corp.ztlp" in info.san_dns
      assert "admin.corp.ztlp" in info.san_dns
    end

    test "certificate is not a CA" do
      {:ok, result} = CertIssuer.issue_server_cert("test.ztlp")
      {:ok, info} = X509.parse_cert(result.cert_der)
      assert info.is_ca == false
    end

    test "certificate is signed by intermediate CA" do
      {:ok, result} = CertIssuer.issue_server_cert("test.ztlp")
      {:ok, chain_pem} = CertAuthority.get_chain_pem()

      # Get intermediate cert (first in chain)
      certs = chain_pem
        |> String.split("-----END CERTIFICATE-----")
        |> Enum.filter(&String.contains?(&1, "BEGIN CERTIFICATE"))
        |> Enum.map(fn c -> c <> "-----END CERTIFICATE-----\n" end)

      if length(certs) >= 1 do
        {:ok, inter_der} = X509.pem_to_der(hd(certs))
        assert X509.verify_cert(result.cert_der, inter_der)
      end
    end

    test "custom validity days" do
      {:ok, result} = CertIssuer.issue_server_cert("test.ztlp", validity_days: 14)
      {:ok, info} = X509.parse_cert(result.cert_der)
      diff_days = DateTime.diff(info.not_after, info.not_before, :second) / 86400
      assert_in_delta diff_days, 14, 1
    end

    test "returns fingerprint" do
      {:ok, result} = CertIssuer.issue_server_cert("test.ztlp")
      assert is_binary(result.fingerprint)
      assert byte_size(result.fingerprint) == 64
    end

    test "returns serial number" do
      {:ok, result} = CertIssuer.issue_server_cert("test.ztlp")
      assert is_integer(result.serial)
      assert result.serial > 0
    end

    test "returns not_after timestamp" do
      {:ok, result} = CertIssuer.issue_server_cert("test.ztlp")
      assert %DateTime{} = result.not_after
    end
  end

  describe "issue_client_cert/3" do
    test "issues a valid client certificate" do
      node_id = :crypto.strong_rand_bytes(16)
      assert {:ok, result} = CertIssuer.issue_client_cert("steve-laptop.corp.ztlp", node_id)
      assert is_binary(result.cert_pem)
      assert is_binary(result.key_pem)
      assert is_binary(result.chain_pem)
    end

    test "certificate has correct node name" do
      node_id = :crypto.strong_rand_bytes(16)
      {:ok, result} = CertIssuer.issue_client_cert("laptop.corp.ztlp", node_id)
      {:ok, info} = X509.parse_cert(result.cert_der)
      assert info.subject[:cn] == "laptop.corp.ztlp"
    end

    test "certificate has NodeID in URI SAN" do
      node_id = :crypto.strong_rand_bytes(16)
      {:ok, result} = CertIssuer.issue_client_cert("laptop.corp.ztlp", node_id)
      {:ok, info} = X509.parse_cert(result.cert_der)
      node_id_hex = Base.encode16(node_id, case: :lower)
      expected_uri = "ztlp://node/#{node_id_hex}"
      assert expected_uri in info.san_uri
    end

    test "certificate has assurance extensions" do
      node_id = :crypto.strong_rand_bytes(16)
      {:ok, result} = CertIssuer.issue_client_cert("laptop.corp.ztlp", node_id,
        assurance: :hardware, key_source: "yubikey", attestation_verified: true)
      {:ok, info} = X509.parse_cert(result.cert_der)
      assert info.assurance != nil
      assert info.assurance.level == :hardware
      assert info.assurance.key_source == "yubikey"
      assert info.assurance.attestation_verified == true
    end

    test "default assurance is software" do
      node_id = :crypto.strong_rand_bytes(16)
      {:ok, result} = CertIssuer.issue_client_cert("laptop.corp.ztlp", node_id)
      {:ok, info} = X509.parse_cert(result.cert_der)
      assert info.assurance.level == :software
    end

    test "returns assurance info in result" do
      node_id = :crypto.strong_rand_bytes(16)
      {:ok, result} = CertIssuer.issue_client_cert("laptop.corp.ztlp", node_id,
        assurance: :device_bound)
      assert result.assurance == :device_bound
    end

    test "returns node_id hex in result" do
      node_id = :crypto.strong_rand_bytes(16)
      {:ok, result} = CertIssuer.issue_client_cert("laptop.corp.ztlp", node_id)
      assert result.node_id == Base.encode16(node_id, case: :lower)
    end

    test "custom validity days for client cert" do
      node_id = :crypto.strong_rand_bytes(16)
      {:ok, result} = CertIssuer.issue_client_cert("laptop.corp.ztlp", node_id,
        validity_days: 60)
      {:ok, info} = X509.parse_cert(result.cert_der)
      diff_days = DateTime.diff(info.not_after, info.not_before, :second) / 86400
      assert_in_delta diff_days, 60, 1
    end
  end

  describe "needs_renewal?/1" do
    test "new certificate does not need renewal" do
      {:ok, result} = CertIssuer.issue_server_cert("test.ztlp", validity_days: 7)
      refute CertIssuer.needs_renewal?(result.cert_der)
    end

    test "handles invalid cert gracefully" do
      assert CertIssuer.needs_renewal?(<<0, 1, 2>>)
    end
  end

  describe "list_certs/0" do
    test "returns a list" do
      assert is_list(CertIssuer.list_certs())
    end
  end

  describe "revoke_cert/2" do
    test "handles non-existent certificate" do
      # Should not crash
      result = CertIssuer.revoke_cert("nonexistent-fingerprint", "test")
      assert result == :ok or match?({:error, _}, result)
    end
  end
end
