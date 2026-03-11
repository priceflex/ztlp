defmodule ZtlpNs.ClusterTest do
  use ExUnit.Case

  alias ZtlpNs.{Cluster, Config, Crypto, Record, Store}

  # Cluster tests run sequentially — they interact with global Mnesia state.

  defp make_signed_key(name, opts \\ []) do
    {_pub, priv} = Crypto.generate_keypair()
    node_id = :crypto.strong_rand_bytes(16)
    {node_pub, _} = Crypto.generate_keypair()
    serial = opts[:serial] || 1

    record =
      Record.new_key(name, node_id, node_pub,
        created_at: System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: serial
      )

    Record.sign(record, priv)
  end

  describe "members/0" do
    test "returns a list containing at least the current node" do
      members = Cluster.members()
      assert is_list(members)
      assert node() in members
    end
  end

  describe "clustered?/0" do
    test "returns false for a single node" do
      refute Cluster.clustered?()
    end

    test "returns a boolean" do
      assert is_boolean(Cluster.clustered?())
    end
  end

  describe "status/0" do
    test "returns a map with expected keys" do
      status = Cluster.status()
      assert is_map(status)
      assert Map.has_key?(status, :node)
      assert Map.has_key?(status, :members)
      assert Map.has_key?(status, :running)
      assert Map.has_key?(status, :stopped)
      assert Map.has_key?(status, :table_copies)
    end

    test "node field matches current node" do
      assert Cluster.status().node == node()
    end

    test "current node is in running list" do
      assert node() in Cluster.status().running
    end

    test "current node is in members list" do
      assert node() in Cluster.status().members
    end

    test "stopped list is empty for a healthy single node" do
      assert Cluster.status().stopped == []
    end

    test "table_copies includes both NS tables" do
      copies = Cluster.status().table_copies
      assert Map.has_key?(copies, :ztlp_ns_records)
      assert Map.has_key?(copies, :ztlp_ns_revoked)
    end

    test "table_copies contain copy type info" do
      copies = Cluster.status().table_copies
      records_info = copies[:ztlp_ns_records]
      assert Map.has_key?(records_info, :ram_copies)
      assert Map.has_key?(records_info, :disc_copies)
      assert Map.has_key?(records_info, :size)
    end
  end

  describe "join/1" do
    test "returns error when trying to join self" do
      assert {:error, :cannot_join_self} = Cluster.join(node())
    end

    test "returns error for non-existent node" do
      result = Cluster.join(:"nonexistent@nowhere.invalid")
      assert {:error, reason} = result
      # Should fail at connection step — node is not alive in non-distributed mode
      # or can't connect to a non-existent node
      assert reason != nil
    end

    test "returns error tuple (not crash) for invalid atom node" do
      result = Cluster.join(:"fake_node@127.0.0.1")
      assert {:error, _reason} = result
    end
  end

  describe "leave/0" do
    test "returns error when not clustered" do
      refute Cluster.clustered?()
      assert {:error, :not_clustered} = Cluster.leave()
    end
  end

  describe "seed_nodes config" do
    test "returns empty list by default" do
      # Clean up any test overrides
      Application.delete_env(:ztlp_ns, :seed_nodes)
      assert Config.seed_nodes() == []
    end

    test "reads from application env" do
      original = Application.get_env(:ztlp_ns, :seed_nodes)

      try do
        Application.put_env(:ztlp_ns, :seed_nodes, [:"ns1@host1", :"ns2@host2"])
        assert Config.seed_nodes() == [:"ns1@host1", :"ns2@host2"]
      after
        case original do
          nil -> Application.delete_env(:ztlp_ns, :seed_nodes)
          val -> Application.put_env(:ztlp_ns, :seed_nodes, val)
        end
      end
    end

    test "returns atoms from application env" do
      original = Application.get_env(:ztlp_ns, :seed_nodes)

      try do
        Application.put_env(:ztlp_ns, :seed_nodes, [:"node@example.com"])
        seeds = Config.seed_nodes()
        assert Enum.all?(seeds, &is_atom/1)
      after
        case original do
          nil -> Application.delete_env(:ztlp_ns, :seed_nodes)
          val -> Application.put_env(:ztlp_ns, :seed_nodes, val)
        end
      end
    end
  end

  describe "ensure_replicated/0" do
    test "succeeds when no seed nodes configured (standalone)" do
      original = Application.get_env(:ztlp_ns, :seed_nodes)

      try do
        Application.delete_env(:ztlp_ns, :seed_nodes)
        assert :ok = Cluster.ensure_replicated()
      after
        case original do
          nil -> Application.delete_env(:ztlp_ns, :seed_nodes)
          val -> Application.put_env(:ztlp_ns, :seed_nodes, val)
        end
      end
    end

    test "handles unreachable seed nodes gracefully (doesn't crash)" do
      original = Application.get_env(:ztlp_ns, :seed_nodes)

      try do
        Application.put_env(:ztlp_ns, :seed_nodes, [
          :"unreachable1@nowhere.invalid",
          :"unreachable2@nowhere.invalid"
        ])

        # Should not raise — gracefully falls back to standalone
        assert :ok = Cluster.ensure_replicated()
      after
        case original do
          nil -> Application.delete_env(:ztlp_ns, :seed_nodes)
          val -> Application.put_env(:ztlp_ns, :seed_nodes, val)
        end
      end
    end

    test "is idempotent when called multiple times" do
      Application.delete_env(:ztlp_ns, :seed_nodes)
      assert :ok = Cluster.ensure_replicated()
      assert :ok = Cluster.ensure_replicated()
    end
  end

  describe "standalone operation after failed join" do
    test "store still works after a failed join attempt" do
      Store.clear()

      # Attempt to join a non-existent node (will fail)
      {:error, _} = Cluster.join(:"phantom@nowhere.invalid")

      # Store should still be functional
      rec = make_signed_key("after-failed-join.ztlp")
      assert :ok = Store.insert(rec)
      assert {:ok, found} = Store.lookup("after-failed-join.ztlp", :key)
      assert found.name == "after-failed-join.ztlp"

      Store.clear()
    end
  end

  describe "YAML config cluster.seed_nodes" do
    test "validates seed_nodes as list of strings" do
      raw = %{"cluster" => %{"seed_nodes" => ["ns1@host1", "ns2@host2"]}}
      assert {:ok, config} = ZtlpNs.YamlConfig.validate(raw)
      assert config[:seed_nodes] == [:"ns1@host1", :"ns2@host2"]
    end

    test "defaults to empty list when cluster section missing" do
      raw = %{"port" => 5000}
      assert {:ok, config} = ZtlpNs.YamlConfig.validate(raw)
      # Defaults to empty list even when cluster section is absent
      assert config[:seed_nodes] == []
    end

    test "defaults to empty list when seed_nodes not specified" do
      raw = %{"cluster" => %{}}
      assert {:ok, config} = ZtlpNs.YamlConfig.validate(raw)
      assert config[:seed_nodes] == []
    end

    test "rejects non-list seed_nodes" do
      raw = %{"cluster" => %{"seed_nodes" => "not-a-list"}}
      assert {:error, errors} = ZtlpNs.YamlConfig.validate(raw)
      assert Enum.any?(errors, &String.contains?(&1, "seed_nodes"))
    end

    test "rejects non-string items in seed_nodes" do
      raw = %{"cluster" => %{"seed_nodes" => [123, 456]}}
      assert {:error, errors} = ZtlpNs.YamlConfig.validate(raw)
      assert Enum.any?(errors, &String.contains?(&1, "seed_nodes"))
    end

    test "rejects non-map cluster section" do
      raw = %{"cluster" => "invalid"}
      assert {:error, errors} = ZtlpNs.YamlConfig.validate(raw)
      assert Enum.any?(errors, &String.contains?(&1, "cluster"))
    end
  end
end
