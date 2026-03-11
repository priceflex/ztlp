defmodule ZtlpRelay.TlsConfigTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.TlsConfig

  setup do
    # Save and clear TLS config between tests
    saved = %{
      enabled: Application.get_env(:ztlp_relay, :tls_enabled),
      cert: Application.get_env(:ztlp_relay, :tls_cert_file),
      key: Application.get_env(:ztlp_relay, :tls_key_file),
      ca: Application.get_env(:ztlp_relay, :tls_ca_cert_file)
    }

    on_exit(fn ->
      for {k, v} <- [
            {:tls_enabled, saved.enabled},
            {:tls_cert_file, saved.cert},
            {:tls_key_file, saved.key},
            {:tls_ca_cert_file, saved.ca}
          ] do
        if v, do: Application.put_env(:ztlp_relay, k, v), else: Application.delete_env(:ztlp_relay, k)
      end
    end)

    Application.delete_env(:ztlp_relay, :tls_enabled)
    Application.delete_env(:ztlp_relay, :tls_cert_file)
    Application.delete_env(:ztlp_relay, :tls_key_file)
    Application.delete_env(:ztlp_relay, :tls_ca_cert_file)

    :ok
  end

  describe "enabled?/0" do
    test "defaults to false" do
      refute TlsConfig.enabled?()
    end

    test "returns true when configured" do
      Application.put_env(:ztlp_relay, :tls_enabled, true)
      assert TlsConfig.enabled?()
    end
  end

  describe "client_opts/0" do
    test "returns empty list when TLS disabled" do
      assert TlsConfig.client_opts() == []
    end

    test "returns verify_peer opts when enabled" do
      Application.put_env(:ztlp_relay, :tls_enabled, true)
      opts = TlsConfig.client_opts()
      assert Keyword.get(opts, :verify) == :verify_peer
    end

    test "includes cert/key/ca files when configured" do
      Application.put_env(:ztlp_relay, :tls_enabled, true)
      Application.put_env(:ztlp_relay, :tls_cert_file, "/tmp/test.crt")
      Application.put_env(:ztlp_relay, :tls_key_file, "/tmp/test.key")
      Application.put_env(:ztlp_relay, :tls_ca_cert_file, "/tmp/ca.crt")

      opts = TlsConfig.client_opts()
      assert Keyword.get(opts, :certfile) == '/tmp/test.crt'
      assert Keyword.get(opts, :keyfile) == '/tmp/test.key'
      assert Keyword.get(opts, :cacertfile) == '/tmp/ca.crt'
    end
  end

  describe "server_opts/0" do
    test "returns empty list when TLS disabled" do
      assert TlsConfig.server_opts() == []
    end

    test "requires peer certificate when enabled" do
      Application.put_env(:ztlp_relay, :tls_enabled, true)
      opts = TlsConfig.server_opts()
      assert Keyword.get(opts, :fail_if_no_peer_cert) == true
      assert Keyword.get(opts, :verify) == :verify_peer
    end
  end

  describe "validate_cert_files/0" do
    test "returns :ok when TLS disabled" do
      assert :ok = TlsConfig.validate_cert_files()
    end

    test "returns :ok when all configured files exist" do
      # Use mix.exs as a known-existing file
      Application.put_env(:ztlp_relay, :tls_enabled, true)
      Application.put_env(:ztlp_relay, :tls_cert_file, "mix.exs")
      Application.put_env(:ztlp_relay, :tls_key_file, "mix.exs")
      Application.put_env(:ztlp_relay, :tls_ca_cert_file, "mix.exs")

      assert :ok = TlsConfig.validate_cert_files()
    end

    test "returns error for missing cert files" do
      Application.put_env(:ztlp_relay, :tls_enabled, true)
      Application.put_env(:ztlp_relay, :tls_cert_file, "/nonexistent/cert.pem")

      assert {:error, errors} = TlsConfig.validate_cert_files()
      assert length(errors) > 0
      assert hd(errors) =~ "file not found"
    end
  end
end
