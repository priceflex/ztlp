defmodule ZtlpGateway.TlsYamlConfigTest do
  use ExUnit.Case, async: true

  alias ZtlpGateway.YamlConfig

  describe "validate/1 TLS section" do
    test "parses TLS enabled flag" do
      raw = %{"tls" => %{"enabled" => true}}
      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:tls_enabled] == true
    end

    test "parses TLS port" do
      raw = %{"tls" => %{"port" => 443}}
      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:tls_port] == 443
    end

    test "parses TLS acceptors" do
      raw = %{"tls" => %{"acceptors" => 50}}
      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:tls_acceptors] == 50
    end

    test "parses cert/key files" do
      raw = %{
        "tls" => %{
          "cert_file" => "/etc/ztlp/cert.pem",
          "key_file" => "/etc/ztlp/key.pem",
          "ca_cert_file" => "/etc/ztlp/ca.pem"
        }
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:tls_cert_file] == "/etc/ztlp/cert.pem"
      assert config[:tls_key_file] == "/etc/ztlp/key.pem"
      assert config[:tls_ca_cert_file] == "/etc/ztlp/ca.pem"
    end

    test "parses mTLS settings" do
      raw = %{
        "tls" => %{
          "mtls_required" => true,
          "mtls_optional" => false
        }
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:tls_mtls_required] == true
      assert config[:tls_mtls_optional] == false
    end

    test "parses header signing config" do
      raw = %{
        "tls" => %{
          "header_signing" => %{
            "enabled" => true,
            "secret" => "my-secret-key",
            "timestamp_window_seconds" => 120
          }
        }
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:header_signing_enabled] == true
      assert config[:header_signing_secret] == "my-secret-key"
      assert config[:header_signing_timestamp_window] == 120
    end

    test "parses header signing with env var reference" do
      raw = %{
        "tls" => %{
          "header_signing" => %{
            "enabled" => true,
            "secret_env" => "ZTLP_HEADER_HMAC_SECRET"
          }
        }
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:header_signing_secret_env] == "ZTLP_HEADER_HMAC_SECRET"
    end

    test "rejects invalid TLS port" do
      raw = %{"tls" => %{"port" => 99999}}
      assert {:error, errors} = YamlConfig.validate(raw)
      assert Enum.any?(errors, &String.contains?(&1, "port"))
    end

    test "rejects non-map TLS section" do
      raw = %{"tls" => "invalid"}
      assert {:error, errors} = YamlConfig.validate(raw)
      assert Enum.any?(errors, &String.contains?(&1, "tls"))
    end

    test "defaults TLS settings when section is missing" do
      raw = %{}
      assert {:ok, _config} = YamlConfig.validate(raw)
    end
  end

  describe "validate/1 backend auth_mode" do
    test "parses auth_mode for backends" do
      raw = %{
        "backends" => [
          %{
            "name" => "admin",
            "host" => "127.0.0.1",
            "port" => 3000,
            "auth_mode" => "enforce",
            "min_assurance" => "hardware"
          }
        ]
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      [backend] = config[:backends]
      assert backend.auth_mode == :enforce
      assert backend.min_assurance == :hardware
    end

    test "parses hostnames for backends" do
      raw = %{
        "backends" => [
          %{
            "name" => "webapp",
            "host" => "127.0.0.1",
            "port" => 8080,
            "hostnames" => ["app.corp.ztlp", "www.corp.ztlp"]
          }
        ]
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      [backend] = config[:backends]
      assert backend.hostnames == ["app.corp.ztlp", "www.corp.ztlp"]
    end

    test "parses required_groups for backends" do
      raw = %{
        "backends" => [
          %{
            "name" => "db",
            "host" => "127.0.0.1",
            "port" => 5432,
            "auth_mode" => "enforce",
            "required_groups" => ["dba", "ops"]
          }
        ]
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      [backend] = config[:backends]
      assert backend.required_groups == ["dba", "ops"]
    end

    test "identity mode sets correct atom" do
      raw = %{
        "backends" => [
          %{"name" => "app", "auth_mode" => "identity"}
        ]
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      [backend] = config[:backends]
      assert backend.auth_mode == :identity
    end

    test "passthrough mode sets correct atom" do
      raw = %{
        "backends" => [
          %{"name" => "legacy", "auth_mode" => "passthrough"}
        ]
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      [backend] = config[:backends]
      assert backend.auth_mode == :passthrough
    end

    test "backend without auth_mode has no auth_mode key" do
      raw = %{
        "backends" => [
          %{"name" => "simple", "host" => "127.0.0.1", "port" => 8080}
        ]
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      [backend] = config[:backends]
      refute Map.has_key?(backend, :auth_mode)
    end

    test "assurance levels parse correctly" do
      for {str, atom} <- [
            {"hardware", :hardware},
            {"device-bound", :device_bound},
            {"software", :software},
            {"unknown", :unknown}
          ] do
        raw = %{
          "backends" => [
            %{"name" => "test", "min_assurance" => str}
          ]
        }

        assert {:ok, config} = YamlConfig.validate(raw)
        [backend] = config[:backends]
        assert backend.min_assurance == atom, "Expected #{str} to parse to #{atom}"
      end
    end
  end

  describe "Config.get/1 TLS keys" do
    setup do
      saved = %{
        tls_enabled: Application.get_env(:ztlp_gateway, :tls_enabled),
        tls_port: Application.get_env(:ztlp_gateway, :tls_port),
        tls_acceptors: Application.get_env(:ztlp_gateway, :tls_acceptors),
        tls_mtls_required: Application.get_env(:ztlp_gateway, :tls_mtls_required),
        header_signing_enabled: Application.get_env(:ztlp_gateway, :header_signing_enabled)
      }

      on_exit(fn ->
        for {k, v} <- saved do
          if v, do: Application.put_env(:ztlp_gateway, k, v), else: Application.delete_env(:ztlp_gateway, k)
        end
      end)

      :ok
    end

    test "tls_enabled defaults to false" do
      Application.delete_env(:ztlp_gateway, :tls_enabled)
      refute ZtlpGateway.Config.get(:tls_enabled)
    end

    test "tls_port defaults to 8443" do
      Application.delete_env(:ztlp_gateway, :tls_port)
      assert ZtlpGateway.Config.get(:tls_port) == 8443
    end

    test "tls_acceptors defaults to 10" do
      Application.delete_env(:ztlp_gateway, :tls_acceptors)
      assert ZtlpGateway.Config.get(:tls_acceptors) == 10
    end

    test "tls_mtls_required defaults to false" do
      Application.delete_env(:ztlp_gateway, :tls_mtls_required)
      refute ZtlpGateway.Config.get(:tls_mtls_required)
    end

    test "header_signing_enabled defaults to false" do
      Application.delete_env(:ztlp_gateway, :header_signing_enabled)
      refute ZtlpGateway.Config.get(:header_signing_enabled)
    end

    test "header_signing_timestamp_window defaults to 60" do
      Application.delete_env(:ztlp_gateway, :header_signing_timestamp_window)
      assert ZtlpGateway.Config.get(:header_signing_timestamp_window) == 60
    end
  end
end
