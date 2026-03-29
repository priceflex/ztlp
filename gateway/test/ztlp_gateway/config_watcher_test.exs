defmodule ZtlpGateway.ConfigWatcherTest do
  use ExUnit.Case, async: false

  alias ZtlpGateway.ConfigWatcher

  @moduletag :config_watcher

  @sample_yaml """
  port: 23097
  max_sessions: 5000

  backends:
    - name: "default"
      host: "127.0.0.1"
      port: 8080
    - name: "http"
      host: "172.18.0.1"
      port: 8180

  policies:
    - zone: "*"
      action: "allow"
      backends:
        - "default"
        - "http"
  """

  @updated_yaml """
  port: 23098
  max_sessions: 8000

  backends:
    - name: "default"
      host: "127.0.0.1"
      port: 9090
    - name: "vault"
      host: "10.0.0.1"
      port: 8200

  policies:
    - zone: "*"
      action: "allow"
      backends:
        - "default"
        - "vault"
  """

  setup do
    # Create a temp directory for config files
    tmp_dir = Path.join(System.tmp_dir!(), "ztlp_config_watcher_test_#{:rand.uniform(1_000_000)}")
    File.mkdir_p!(tmp_dir)
    config_path = Path.join(tmp_dir, "gateway.yaml")

    on_exit(fn ->
      File.rm_rf!(tmp_dir)
    end)

    %{tmp_dir: tmp_dir, config_path: config_path}
  end

  defp start_watcher(config_path, opts \\ []) do
    name = Keyword.get(opts, :name, :"watcher_#{:rand.uniform(1_000_000)}")
    poll_interval = Keyword.get(opts, :poll_interval_ms, 60_000)

    start_supervised!(
      {ConfigWatcher,
       [
         config_path: config_path,
         poll_interval_ms: poll_interval,
         name: name
       ]},
      id: name
    )

    name
  end

  # ── Test: starts with no config file (graceful) ───────────────────

  describe "start with no config file" do
    test "starts successfully with missing config file", %{config_path: config_path} do
      name = start_watcher(config_path)
      assert GenServer.call(name, :current_config) == %{}
    end
  end

  # ── Test: loads config from file ──────────────────────────────────

  describe "loads config from file" do
    test "parses YAML on startup", %{config_path: config_path} do
      File.write!(config_path, @sample_yaml)
      name = start_watcher(config_path)

      config = GenServer.call(name, :current_config)
      assert is_map(config)
      assert config["port"] == 23097
      assert config["max_sessions"] == 5000
    end
  end

  # ── Test: reload/0 ────────────────────────────────────────────────

  describe "reload/0" do
    test "reloads config and returns changes", %{config_path: config_path} do
      File.write!(config_path, @sample_yaml)

      # Start with the default name so reload/0 works
      start_supervised!(
        {ConfigWatcher,
         [config_path: config_path, poll_interval_ms: 60_000, name: ConfigWatcher]}
      )

      # Verify initial load
      config = ConfigWatcher.current_config()
      assert config["port"] == 23097

      # Update the file
      File.write!(config_path, @updated_yaml)

      # Force reload
      assert {:ok, changes} = ConfigWatcher.reload()
      assert is_list(changes)
      assert length(changes) > 0

      # Verify new config
      config = ConfigWatcher.current_config()
      assert config["port"] == 23098
      assert config["max_sessions"] == 8000
    end
  end

  # ── Test: current_config/0 ────────────────────────────────────────

  describe "current_config/0" do
    test "returns current parsed config", %{config_path: config_path} do
      File.write!(config_path, @sample_yaml)

      start_supervised!(
        {ConfigWatcher,
         [config_path: config_path, poll_interval_ms: 60_000, name: ConfigWatcher]}
      )

      config = ConfigWatcher.current_config()
      assert is_map(config)
      assert config["port"] == 23097
    end
  end

  # ── Test: poll detects file changes ───────────────────────────────

  describe "polling" do
    test "detects file changes on poll", %{config_path: config_path} do
      File.write!(config_path, @sample_yaml)
      # Use a very long poll interval so we can trigger manually
      name = start_watcher(config_path, poll_interval_ms: 600_000)

      config = GenServer.call(name, :current_config)
      assert config["port"] == 23097

      # Write updated config with a small delay to ensure mtime differs
      Process.sleep(1100)
      File.write!(config_path, @updated_yaml)

      # Manually send poll message
      send(Process.whereis(name) || GenServer.whereis(name), :poll)
      # Give it a moment to process
      Process.sleep(100)

      config = GenServer.call(name, :current_config)
      assert config["port"] == 23098
    end
  end

  # ── Test: SIGHUP handler ──────────────────────────────────────────

  describe "SIGHUP handling" do
    test "reloads config on SIGHUP signal", %{config_path: config_path} do
      File.write!(config_path, @sample_yaml)
      name = start_watcher(config_path, poll_interval_ms: 600_000)

      config = GenServer.call(name, :current_config)
      assert config["port"] == 23097

      # Update the file
      Process.sleep(1100)
      File.write!(config_path, @updated_yaml)

      # Send SIGHUP
      pid = Process.whereis(name) || GenServer.whereis(name)
      send(pid, {:signal, :sighup})
      Process.sleep(100)

      config = GenServer.call(name, :current_config)
      assert config["port"] == 23098
    end
  end

  # ── Test: diff_config ─────────────────────────────────────────────

  describe "diff_config/2" do
    test "detects added keys" do
      old = %{"a" => 1}
      new = %{"a" => 1, "b" => 2}
      changes = ConfigWatcher.diff_config(old, new)
      assert {"b", nil, 2} in changes
    end

    test "detects changed values" do
      old = %{"a" => 1, "b" => 2}
      new = %{"a" => 1, "b" => 99}
      changes = ConfigWatcher.diff_config(old, new)
      assert length(changes) == 1
      assert {"b", 2, 99} in changes
    end

    test "detects removed keys" do
      old = %{"a" => 1, "b" => 2}
      new = %{"a" => 1}
      changes = ConfigWatcher.diff_config(old, new)
      assert {"b", 2, nil} in changes
    end

    test "returns empty list for identical configs" do
      config = %{"a" => 1, "b" => "hello"}
      assert ConfigWatcher.diff_config(config, config) == []
    end

    test "handles nested map changes" do
      old = %{"backends" => [%{"name" => "default", "port" => 8080}]}
      new = %{"backends" => [%{"name" => "default", "port" => 9090}]}
      changes = ConfigWatcher.diff_config(old, new)
      assert length(changes) == 1
      assert {"backends", _, _} = hd(changes)
    end
  end

  # ── Test: YAML parsing via YamlParser ─────────────────────────────

  describe "YAML parsing integration" do
    test "handles key-value pairs" do
      yaml = "port: 8080\nhost: localhost"
      {:ok, result} = ZtlpGateway.YamlParser.parse(yaml)
      assert result["port"] == 8080
      assert result["host"] == "localhost"
    end

    test "handles nested maps" do
      yaml = """
      gateway:
        port: 23097
        host: localhost
      """

      {:ok, result} = ZtlpGateway.YamlParser.parse(yaml)
      assert result["gateway"]["port"] == 23097
      assert result["gateway"]["host"] == "localhost"
    end

    test "handles quoted strings" do
      yaml = ~s(name: "hello world"\naddr: '127.0.0.1')
      {:ok, result} = ZtlpGateway.YamlParser.parse(yaml)
      assert result["name"] == "hello world"
      assert result["addr"] == "127.0.0.1"
    end

    test "handles integers and booleans" do
      yaml = "port: 8080\nenabled: true\nverbose: false"
      {:ok, result} = ZtlpGateway.YamlParser.parse(yaml)
      assert result["port"] == 8080
      assert result["enabled"] == true
      assert result["verbose"] == false
    end

    test "skips comments" do
      yaml = """
      # This is a comment
      port: 8080
      # Another comment
      host: localhost
      """

      {:ok, result} = ZtlpGateway.YamlParser.parse(yaml)
      assert result["port"] == 8080
      assert result["host"] == "localhost"
    end
  end

  # ── Test: apply_changes updates Application env ───────────────────

  describe "apply_changes via reload" do
    test "updates Application env on reload", %{config_path: config_path} do
      yaml = """
      port: 55555
      max_sessions: 999
      """

      File.write!(config_path, yaml)
      name = start_watcher(config_path)

      # The validated config should be applied to app env during init
      assert Application.get_env(:ztlp_gateway, :port) == 55555
      assert Application.get_env(:ztlp_gateway, :max_sessions) == 999

      # Update to new values
      updated_yaml = """
      port: 55556
      max_sessions: 1234
      """

      Process.sleep(1100)
      File.write!(config_path, updated_yaml)
      {:ok, _changes} = GenServer.call(name, :reload)

      assert Application.get_env(:ztlp_gateway, :port) == 55556
      assert Application.get_env(:ztlp_gateway, :max_sessions) == 1234
    after
      # Clean up app env
      Application.delete_env(:ztlp_gateway, :port)
      Application.delete_env(:ztlp_gateway, :max_sessions)
    end
  end

  # ── Test: hash-based dedup ────────────────────────────────────────

  describe "hash-based deduplication" do
    test "skips reload when content unchanged but mtime differs", %{config_path: config_path} do
      File.write!(config_path, @sample_yaml)

      start_supervised!(
        {ConfigWatcher,
         [config_path: config_path, poll_interval_ms: 60_000, name: ConfigWatcher]}
      )

      # Touch the file to change mtime but not content
      Process.sleep(1100)
      File.write!(config_path, @sample_yaml)

      {:ok, changes} = ConfigWatcher.reload()
      assert changes == []
    end
  end
end
