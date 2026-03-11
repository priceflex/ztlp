defmodule ZtlpRelay.YamlParserTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.YamlParser

  describe "parse/1" do
    test "parses simple key-value pairs" do
      yaml = """
      port: 23095
      max_sessions: 10000
      """

      assert {:ok, %{"port" => 23095, "max_sessions" => 10000}} = YamlParser.parse(yaml)
    end

    test "parses nested mappings" do
      yaml = """
      mesh:
        enabled: true
        port: 23096
      """

      assert {:ok, %{"mesh" => %{"enabled" => true, "port" => 23096}}} = YamlParser.parse(yaml)
    end

    test "parses sequences" do
      yaml = """
      bootstrap:
        - "10.0.0.1:23096"
        - "10.0.0.2:23096"
      """

      assert {:ok, %{"bootstrap" => ["10.0.0.1:23096", "10.0.0.2:23096"]}} = YamlParser.parse(yaml)
    end

    test "parses booleans" do
      yaml = """
      enabled: true
      disabled: false
      """

      assert {:ok, %{"enabled" => true, "disabled" => false}} = YamlParser.parse(yaml)
    end

    test "parses quoted strings" do
      yaml = """
      host: "127.0.0.1"
      name: 'test relay'
      """

      assert {:ok, %{"host" => "127.0.0.1", "name" => "test relay"}} = YamlParser.parse(yaml)
    end

    test "parses floats" do
      yaml = """
      threshold: 0.7
      """

      assert {:ok, %{"threshold" => 0.7}} = YamlParser.parse(yaml)
    end

    test "handles comments" do
      yaml = """
      # This is a comment
      port: 23095
      """

      assert {:ok, %{"port" => 23095}} = YamlParser.parse(yaml)
    end

    test "handles blank lines" do
      yaml = """
      port: 23095

      max_sessions: 10000
      """

      assert {:ok, %{"port" => 23095, "max_sessions" => 10000}} = YamlParser.parse(yaml)
    end

    test "returns nil for empty content" do
      assert {:ok, nil} = YamlParser.parse("")
    end

    test "parses duration strings as strings" do
      yaml = """
      timeout: 300s
      """

      assert {:ok, %{"timeout" => "300s"}} = YamlParser.parse(yaml)
    end

    test "parses complex nested config" do
      yaml = """
      port: 23095
      mesh:
        enabled: true
        bootstrap:
          - "10.0.0.1:23096"
          - "10.0.0.2:23096"
        role: all
      admission:
        rat_ttl: 300s
        rate_limit:
          per_ip: 10
          per_node: 5
      """

      assert {:ok, config} = YamlParser.parse(yaml)
      assert config["port"] == 23095
      assert config["mesh"]["enabled"] == true
      assert config["mesh"]["bootstrap"] == ["10.0.0.1:23096", "10.0.0.2:23096"]
      assert config["mesh"]["role"] == "all"
      assert config["admission"]["rat_ttl"] == "300s"
      assert config["admission"]["rate_limit"]["per_ip"] == 10
    end
  end
end
