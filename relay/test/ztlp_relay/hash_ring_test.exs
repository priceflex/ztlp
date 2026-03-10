defmodule ZtlpRelay.HashRingTest do
  use ExUnit.Case, async: true

  alias ZtlpRelay.HashRing

  defp make_relay(n) do
    node_id = :crypto.hash(:blake2s, "relay-#{n}") |> binary_part(0, 16)
    %{node_id: node_id, address: {{10, 0, 0, n}, 23095 + n}}
  end

  defp make_relays(count) do
    Enum.map(1..count, &make_relay/1)
  end

  describe "new/2" do
    test "creates empty ring" do
      ring = HashRing.new()
      assert HashRing.node_count(ring) == 0
    end

    test "creates ring with relays" do
      relays = make_relays(3)
      ring = HashRing.new(relays)
      assert HashRing.node_count(ring) == 3
    end

    test "configurable vnode count" do
      relays = make_relays(2)
      ring = HashRing.new(relays, 64)
      # 2 relays * 64 vnodes each = 128 total vnodes
      assert length(ring.vnodes) == 128
    end

    test "default vnode count is 128" do
      relays = make_relays(1)
      ring = HashRing.new(relays)
      assert length(ring.vnodes) == 128
    end

    test "vnodes are sorted" do
      relays = make_relays(5)
      ring = HashRing.new(relays)
      hashes = Enum.map(ring.vnodes, fn {h, _} -> h end)
      assert hashes == Enum.sort(hashes)
    end
  end

  describe "get_nodes/3" do
    test "returns empty list for empty ring" do
      ring = HashRing.new()
      assert HashRing.get_nodes(ring, "some-key", 3) == []
    end

    test "returns single node when ring has one node" do
      relays = make_relays(1)
      ring = HashRing.new(relays)
      result = HashRing.get_nodes(ring, "any-key", 1)
      assert length(result) == 1
      assert hd(result).node_id == hd(relays).node_id
    end

    test "returns single node when n=1 from multi-node ring" do
      relays = make_relays(5)
      ring = HashRing.new(relays)
      result = HashRing.get_nodes(ring, "test-key", 1)
      assert length(result) == 1
    end

    test "returns n distinct nodes" do
      relays = make_relays(5)
      ring = HashRing.new(relays)
      result = HashRing.get_nodes(ring, "test-key", 3)
      assert length(result) == 3
      node_ids = Enum.map(result, & &1.node_id)
      assert length(Enum.uniq(node_ids)) == 3
    end

    test "returns all nodes when n > total nodes" do
      relays = make_relays(3)
      ring = HashRing.new(relays)
      result = HashRing.get_nodes(ring, "test-key", 10)
      assert length(result) == 3
    end

    test "same key always returns same nodes" do
      relays = make_relays(5)
      ring = HashRing.new(relays)
      key = "deterministic-key"
      result1 = HashRing.get_nodes(ring, key, 3)
      result2 = HashRing.get_nodes(ring, key, 3)
      assert result1 == result2
    end

    test "different keys may return different primary nodes" do
      relays = make_relays(10)
      ring = HashRing.new(relays)

      # Generate many keys and check we get more than one distinct primary
      primaries =
        for i <- 1..100 do
          [primary | _] = HashRing.get_nodes(ring, "key-#{i}", 1)
          primary.node_id
        end
        |> Enum.uniq()

      # With 10 relays and 100 keys, we should hit more than 1 relay
      assert length(primaries) > 1
    end
  end

  describe "distribution uniformity" do
    test "keys distribute roughly evenly across nodes" do
      relays = make_relays(4)
      ring = HashRing.new(relays)

      # Assign 10,000 keys to primary nodes
      counts =
        Enum.reduce(1..10_000, %{}, fn _i, acc ->
          key = :crypto.strong_rand_bytes(12)
          [primary | _] = HashRing.get_nodes(ring, key, 1)
          Map.update(acc, primary.node_id, 1, &(&1 + 1))
        end)

      # Each node should get roughly 2,500 (25%) keys
      # Allow ±10% tolerance (1500-3500)
      Enum.each(counts, fn {_node_id, count} ->
        assert count > 1500, "Node got only #{count} keys, expected ~2500"
        assert count < 3500, "Node got #{count} keys, expected ~2500"
      end)
    end
  end

  describe "add_node/2" do
    test "adds a node to the ring" do
      relays = make_relays(3)
      ring = HashRing.new(relays)
      assert HashRing.node_count(ring) == 3

      new_relay = make_relay(4)
      ring = HashRing.add_node(ring, new_relay)
      assert HashRing.node_count(ring) == 4
      assert HashRing.member?(ring, new_relay.node_id)
    end

    test "added node gets keys assigned" do
      relays = make_relays(3)
      ring = HashRing.new(relays)

      new_relay = make_relay(4)
      ring = HashRing.add_node(ring, new_relay)

      # Check that the new node appears as primary for some keys
      hits =
        Enum.count(1..1000, fn i ->
          [primary | _] = HashRing.get_nodes(ring, "key-#{i}", 1)
          primary.node_id == new_relay.node_id
        end)

      assert hits > 0, "New node should get some keys"
    end

    test "vnodes remain sorted after add" do
      relays = make_relays(3)
      ring = HashRing.new(relays)
      ring = HashRing.add_node(ring, make_relay(4))
      hashes = Enum.map(ring.vnodes, fn {h, _} -> h end)
      assert hashes == Enum.sort(hashes)
    end

    test "minimal key remapping on add" do
      relays = make_relays(5)
      ring_before = HashRing.new(relays)

      keys = for i <- 1..1000, do: "key-#{i}"
      assignments_before = Map.new(keys, fn key ->
        [primary | _] = HashRing.get_nodes(ring_before, key, 1)
        {key, primary.node_id}
      end)

      ring_after = HashRing.add_node(ring_before, make_relay(6))
      assignments_after = Map.new(keys, fn key ->
        [primary | _] = HashRing.get_nodes(ring_after, key, 1)
        {key, primary.node_id}
      end)

      # Count how many keys changed primary
      changed = Enum.count(keys, fn key ->
        assignments_before[key] != assignments_after[key]
      end)

      # With consistent hashing, roughly 1/6 of keys should move (≈16.7%)
      # Allow generous tolerance: < 40%
      assert changed < 400, "Too many keys remapped: #{changed}/1000"
    end
  end

  describe "remove_node/2" do
    test "removes a node from the ring" do
      relays = make_relays(4)
      ring = HashRing.new(relays)
      target = Enum.at(relays, 1)

      ring = HashRing.remove_node(ring, target.node_id)
      assert HashRing.node_count(ring) == 3
      refute HashRing.member?(ring, target.node_id)
    end

    test "removed node no longer gets keys" do
      relays = make_relays(4)
      ring = HashRing.new(relays)
      target = Enum.at(relays, 1)

      ring = HashRing.remove_node(ring, target.node_id)

      hits =
        Enum.count(1..1000, fn i ->
          results = HashRing.get_nodes(ring, "key-#{i}", 3)
          Enum.any?(results, fn r -> r.node_id == target.node_id end)
        end)

      assert hits == 0, "Removed node should not appear in results"
    end

    test "removing nonexistent node is safe" do
      relays = make_relays(3)
      ring = HashRing.new(relays)
      ring = HashRing.remove_node(ring, <<0::128>>)
      assert HashRing.node_count(ring) == 3
    end

    test "removing all nodes results in empty ring" do
      relays = make_relays(3)
      ring = HashRing.new(relays)

      ring = Enum.reduce(relays, ring, fn r, acc ->
        HashRing.remove_node(acc, r.node_id)
      end)

      assert HashRing.node_count(ring) == 0
      assert HashRing.get_nodes(ring, "any-key", 1) == []
    end
  end

  describe "member?/2" do
    test "returns true for present node" do
      relays = make_relays(3)
      ring = HashRing.new(relays)
      assert HashRing.member?(ring, hd(relays).node_id)
    end

    test "returns false for absent node" do
      ring = HashRing.new(make_relays(3))
      refute HashRing.member?(ring, <<0::128>>)
    end
  end

  describe "node_ids/1" do
    test "returns all node ids" do
      relays = make_relays(3)
      ring = HashRing.new(relays)
      ids = HashRing.node_ids(ring) |> Enum.sort()
      expected = Enum.map(relays, & &1.node_id) |> Enum.sort()
      assert ids == expected
    end
  end
end
