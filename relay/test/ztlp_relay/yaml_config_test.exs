defmodule ZtlpRelay.YamlConfigTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.YamlConfig

  describe "validate/1" do
    test "accepts valid minimal config" do
      assert {:ok, config} = YamlConfig.validate(%{"port" => 23095})
      assert config[:port] == 23095
    end

    test "applies defaults for missing fields" do
      assert {:ok, config} = YamlConfig.validate(%{})
      assert config[:port] == 23095
      assert config[:session_timeout_ms] == 300_000
      assert config[:max_sessions] == 10_000
      assert config[:mesh_enabled] == false
    end

    test "validates port range" do
      assert {:error, errors} = YamlConfig.validate(%{"port" => 99999})
      assert Enum.any?(errors, &String.contains?(&1, "must be between 1 and 65535"))
    end

    test "validates port type" do
      assert {:error, errors} = YamlConfig.validate(%{"port" => "not_a_number"})
      assert Enum.any?(errors, &String.contains?(&1, "expected an integer"))
    end

    test "parses duration strings" do
      assert {:ok, config} = YamlConfig.validate(%{"session_timeout" => "5m"})
      assert config[:session_timeout_ms] == 300_000
    end

    test "parses duration in seconds" do
      assert {:ok, config} = YamlConfig.validate(%{"session_timeout" => "300s"})
      assert config[:session_timeout_ms] == 300_000
    end

    test "parses duration in hours" do
      assert {:ok, config} = YamlConfig.validate(%{"session_timeout" => "1h"})
      assert config[:session_timeout_ms] == 3_600_000
    end

    test "parses duration in milliseconds" do
      assert {:ok, config} = YamlConfig.validate(%{"session_timeout" => "100ms"})
      assert config[:session_timeout_ms] == 100
    end

    test "validates mesh section" do
      raw = %{
        "mesh" => %{
          "enabled" => true,
          "port" => 23096,
          "role" => "ingress",
          "bootstrap" => ["10.0.0.1:23096"]
        }
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:mesh_enabled] == true
      assert config[:mesh_listen_port] == 23096
      assert config[:relay_role] == :ingress
      assert config[:mesh_bootstrap_relays] == ["10.0.0.1:23096"]
    end

    test "validates invalid mesh role" do
      raw = %{"mesh" => %{"role" => "invalid"}}
      assert {:error, errors} = YamlConfig.validate(raw)
      assert Enum.any?(errors, &String.contains?(&1, "must be one of"))
    end

    test "validates admission section" do
      raw = %{
        "admission" => %{
          "rat_ttl" => "5m",
          "sac_load_threshold" => 0.8,
          "rate_limit" => %{
            "per_ip" => 20,
            "per_node" => 10
          }
        }
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:rat_ttl_seconds] == 300
      assert config[:sac_load_threshold] == 0.8
      assert config[:ingress_rate_limit_per_ip] == 20
      assert config[:ingress_rate_limit_per_node] == 10
    end

    test "validates sac_load_threshold range" do
      raw = %{"admission" => %{"sac_load_threshold" => 1.5}}
      assert {:error, errors} = YamlConfig.validate(raw)
      assert Enum.any?(errors, &String.contains?(&1, "must be between 0.0 and 1.0"))
    end

    test "validates ns_discovery section" do
      raw = %{
        "ns_discovery" => %{
          "server" => "127.0.0.1:23096",
          "zone" => "relay.corp.ztlp",
          "region" => "us-east-1"
        }
      }

      assert {:ok, config} = YamlConfig.validate(raw)
      assert config[:ns_server] == {"127.0.0.1", 23096}
      assert config[:ns_discovery_zone] == "relay.corp.ztlp"
      assert config[:relay_region] == "us-east-1"
    end

    test "accumulates multiple errors" do
      raw = %{
        "port" => 99999,
        "max_sessions" => -1,
        "admission" => %{"sac_load_threshold" => 2.0}
      }

      assert {:error, errors} = YamlConfig.validate(raw)
      assert length(errors) >= 2
    end
  end

  describe "parse_duration_ms/1" do
    test "parses seconds" do
      assert {:ok, 5000} = YamlConfig.parse_duration_ms("5s")
    end

    test "parses minutes" do
      assert {:ok, 300_000} = YamlConfig.parse_duration_ms("5m")
    end

    test "parses hours" do
      assert {:ok, 3_600_000} = YamlConfig.parse_duration_ms("1h")
    end

    test "parses milliseconds" do
      assert {:ok, 100} = YamlConfig.parse_duration_ms("100ms")
    end

    test "parses plain integer" do
      assert {:ok, 5000} = YamlConfig.parse_duration_ms(5000)
    end

    test "rejects invalid duration" do
      assert :error = YamlConfig.parse_duration_ms("abc")
    end
  end

  describe "load/1" do
    test "loads from a YAML file" do
      path = Path.join(System.tmp_dir!(), "test_relay_config.yaml")

      File.write!(path, """
      port: 23099
      max_sessions: 5000
      session_timeout: 60s
      """)

      assert {:ok, config} = YamlConfig.load(path)
      assert config[:port] == 23099
      assert config[:max_sessions] == 5000
      assert config[:session_timeout_ms] == 60_000

      File.rm!(path)
    end

    test "returns empty map for missing file" do
      assert {:error, _} = YamlConfig.load("/nonexistent/path.yaml")
    end
  end

  describe "apply_to_app_env/1" do
    test "writes config to application environment" do
      config = %{port: 23099, max_sessions: 5000}
      YamlConfig.apply_to_app_env(config)

      # port maps to listen_port for backward compat
      assert Application.get_env(:ztlp_relay, :listen_port) == 23099
      assert Application.get_env(:ztlp_relay, :max_sessions) == 5000

      # Clean up
      Application.delete_env(:ztlp_relay, :listen_port)
      Application.delete_env(:ztlp_relay, :max_sessions)
    end
  end
end
