defmodule ZtlpNs.TlsConfigTest do
  use ExUnit.Case, async: false

  alias ZtlpNs.TlsConfig

  setup do
    saved = %{
      enabled: Application.get_env(:ztlp_ns, :tls_enabled),
      cert: Application.get_env(:ztlp_ns, :tls_cert_file),
      key: Application.get_env(:ztlp_ns, :tls_key_file),
      ca: Application.get_env(:ztlp_ns, :tls_ca_cert_file)
    }

    on_exit(fn ->
      for {k, v} <- [
            {:tls_enabled, saved.enabled},
            {:tls_cert_file, saved.cert},
            {:tls_key_file, saved.key},
            {:tls_ca_cert_file, saved.ca}
          ] do
        if v, do: Application.put_env(:ztlp_ns, k, v), else: Application.delete_env(:ztlp_ns, k)
      end
    end)

    Application.delete_env(:ztlp_ns, :tls_enabled)
    Application.delete_env(:ztlp_ns, :tls_cert_file)
    Application.delete_env(:ztlp_ns, :tls_key_file)
    Application.delete_env(:ztlp_ns, :tls_ca_cert_file)

    :ok
  end

  describe "enabled?/0" do
    test "defaults to false" do
      refute TlsConfig.enabled?()
    end

    test "returns true when configured" do
      Application.put_env(:ztlp_ns, :tls_enabled, true)
      assert TlsConfig.enabled?()
    end
  end

  describe "client_opts/0" do
    test "returns empty list when TLS disabled" do
      assert TlsConfig.client_opts() == []
    end

    test "returns verify_peer when enabled" do
      Application.put_env(:ztlp_ns, :tls_enabled, true)
      opts = TlsConfig.client_opts()
      assert Keyword.get(opts, :verify) == :verify_peer
    end
  end

  describe "server_opts/0" do
    test "returns empty list when TLS disabled" do
      assert TlsConfig.server_opts() == []
    end

    test "requires peer certificate when enabled" do
      Application.put_env(:ztlp_ns, :tls_enabled, true)
      opts = TlsConfig.server_opts()
      assert Keyword.get(opts, :fail_if_no_peer_cert) == true
      assert Keyword.get(opts, :verify) == :verify_peer
    end

    test "includes configured cert files" do
      Application.put_env(:ztlp_ns, :tls_enabled, true)
      Application.put_env(:ztlp_ns, :tls_cert_file, "/tmp/ns.crt")
      Application.put_env(:ztlp_ns, :tls_key_file, "/tmp/ns.key")
      Application.put_env(:ztlp_ns, :tls_ca_cert_file, "/tmp/ca.crt")

      opts = TlsConfig.server_opts()
      assert Keyword.get(opts, :certfile) == '/tmp/ns.crt'
      assert Keyword.get(opts, :keyfile) == '/tmp/ns.key'
      assert Keyword.get(opts, :cacertfile) == '/tmp/ca.crt'
    end
  end

  describe "validate_cert_files/0" do
    test "returns :ok when TLS disabled" do
      assert :ok = TlsConfig.validate_cert_files()
    end

    test "returns error for missing files when enabled" do
      Application.put_env(:ztlp_ns, :tls_enabled, true)
      Application.put_env(:ztlp_ns, :tls_cert_file, "/nonexistent/ns.crt")

      assert {:error, errors} = TlsConfig.validate_cert_files()
      assert length(errors) > 0
    end
  end
end
