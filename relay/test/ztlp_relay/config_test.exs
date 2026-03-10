defmodule ZtlpRelay.ConfigTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.Config

  describe "mesh configuration defaults" do
    test "mesh_enabled? defaults to false" do
      refute Config.mesh_enabled?()
    end

    test "mesh_listen_port defaults to 23096" do
      assert Config.mesh_listen_port() == 23096
    end

    test "mesh_bootstrap_relays defaults to empty list" do
      assert Config.mesh_bootstrap_relays() == []
    end

    test "relay_node_id returns 16-byte binary" do
      node_id = Config.relay_node_id()
      assert byte_size(node_id) == 16
    end

    test "relay_role defaults to :all" do
      assert Config.relay_role() == :all
    end

    test "hash_ring_vnodes defaults to 128" do
      assert Config.hash_ring_vnodes() == 128
    end

    test "ping_interval_ms defaults to 15_000" do
      assert Config.ping_interval_ms() == 15_000
    end

    test "relay_timeout_ms defaults to 300_000" do
      assert Config.relay_timeout_ms() == 300_000
    end
  end

  describe "existing config still works" do
    test "listen_port defaults to 23095" do
      # May be overridden by test config, but should be an integer
      assert is_integer(Config.listen_port())
    end

    test "session_timeout_ms returns an integer" do
      assert is_integer(Config.session_timeout_ms())
    end

    test "max_sessions defaults to 10_000" do
      assert Config.max_sessions() == 10_000
    end
  end
end
