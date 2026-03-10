defmodule ZtlpRelay.HashRing do
  @moduledoc """
  Consistent hash ring using BLAKE2s for relay mesh routing.

  Maps keys (SessionID, ServiceID) to N candidate relay nodes using
  virtual nodes (vnodes) for even distribution. Each physical relay
  is placed at multiple positions on a 32-byte hash ring.

  The ring is stored as a sorted list of `{hash_position, node_id}`
  tuples, enabling O(log n) lookups via binary search.
  """

  @default_vnodes 128

  @type node_info :: %{
    required(:node_id) => binary(),
    required(:address) => {:inet.ip_address(), :inet.port_number()},
    optional(:meta) => term()
  }

  @type ring :: %{
    vnodes: [{binary(), binary()}],
    nodes: %{binary() => node_info()},
    vnode_count: pos_integer()
  }

  @doc """
  Build a new hash ring from a list of relay node info maps.

  Each map must contain at least `:node_id` (binary) and `:address` ({ip, port}).
  `vnode_count` controls how many virtual positions each node gets (default #{@default_vnodes}).
  """
  @spec new([node_info()], pos_integer()) :: ring()
  def new(relays \\ [], vnode_count \\ @default_vnodes) do
    nodes = Map.new(relays, fn relay -> {relay.node_id, relay} end)

    vnodes =
      relays
      |> Enum.flat_map(fn relay -> build_vnodes(relay.node_id, vnode_count) end)
      |> Enum.sort()

    %{vnodes: vnodes, nodes: nodes, vnode_count: vnode_count}
  end

  @doc """
  Find N nearest distinct relay nodes for a given key.

  Returns a list of node_info maps, up to `n` unique nodes.
  If `n` exceeds the number of nodes in the ring, returns all nodes.
  Returns `[]` for an empty ring.
  """
  @spec get_nodes(ring(), binary(), pos_integer()) :: [node_info()]
  def get_nodes(%{vnodes: [], nodes: _}, _key, _n), do: []

  def get_nodes(%{vnodes: vnodes, nodes: nodes} = _ring, key, n) when is_binary(key) and n > 0 do
    total_nodes = map_size(nodes)
    n = min(n, total_nodes)

    key_hash = hash(key)
    start_idx = find_start_index(vnodes, key_hash)
    vnode_count = length(vnodes)

    collect_unique_nodes(vnodes, nodes, start_idx, vnode_count, n, MapSet.new(), [])
  end

  @doc """
  Add a node to the ring dynamically.

  Returns the updated ring.
  """
  @spec add_node(ring(), node_info()) :: ring()
  def add_node(%{vnodes: vnodes, nodes: nodes, vnode_count: vnode_count} = _ring, relay) do
    new_vnodes = build_vnodes(relay.node_id, vnode_count)
    merged = merge_sorted(vnodes, Enum.sort(new_vnodes))

    %{
      vnodes: merged,
      nodes: Map.put(nodes, relay.node_id, relay),
      vnode_count: vnode_count
    }
  end

  @doc """
  Remove a node from the ring by its node_id.

  Returns the updated ring.
  """
  @spec remove_node(ring(), binary()) :: ring()
  def remove_node(%{vnodes: vnodes, nodes: nodes, vnode_count: vnode_count} = _ring, node_id) do
    filtered = Enum.reject(vnodes, fn {_hash, nid} -> nid == node_id end)

    %{
      vnodes: filtered,
      nodes: Map.delete(nodes, node_id),
      vnode_count: vnode_count
    }
  end

  @doc """
  Return the number of physical nodes in the ring.
  """
  @spec node_count(ring()) :: non_neg_integer()
  def node_count(%{nodes: nodes}), do: map_size(nodes)

  @doc """
  Check if a specific node_id is in the ring.
  """
  @spec member?(ring(), binary()) :: boolean()
  def member?(%{nodes: nodes}, node_id), do: Map.has_key?(nodes, node_id)

  @doc """
  Get all node_ids in the ring.
  """
  @spec node_ids(ring()) :: [binary()]
  def node_ids(%{nodes: nodes}), do: Map.keys(nodes)

  # Internal helpers

  @spec hash(binary()) :: binary()
  defp hash(data) do
    :crypto.hash(:blake2s, data)
  end

  @spec build_vnodes(binary(), pos_integer()) :: [{binary(), binary()}]
  defp build_vnodes(node_id, vnode_count) do
    for i <- 0..(vnode_count - 1) do
      vnode_key = <<node_id::binary, i::32>>
      {hash(vnode_key), node_id}
    end
  end

  # Find the index of the first vnode whose hash >= key_hash (clockwise walk).
  @spec find_start_index([{binary(), binary()}], binary()) :: non_neg_integer()
  defp find_start_index(vnodes, key_hash) do
    # Binary search for first vnode >= key_hash
    binary_search_gte(vnodes, key_hash, 0, length(vnodes) - 1)
  end

  defp binary_search_gte(_vnodes, _target, low, high) when low > high do
    # Wrap around to 0 (all vnodes have smaller hashes — go to first)
    0
  end

  defp binary_search_gte(vnodes, target, low, high) do
    mid = div(low + high, 2)
    {mid_hash, _} = Enum.at(vnodes, mid)

    cond do
      mid_hash == target ->
        mid

      mid_hash > target ->
        # mid could be answer, but check if there's something closer on the left
        if mid == low do
          mid
        else
          binary_search_gte(vnodes, target, low, mid)
        end

      true ->
        # mid_hash < target — answer must be to the right
        binary_search_gte(vnodes, target, mid + 1, high)
    end
  end

  # Collect unique nodes walking clockwise from start_idx.
  defp collect_unique_nodes(_vnodes, _nodes, _idx, _total, 0, _seen, acc) do
    Enum.reverse(acc)
  end

  defp collect_unique_nodes(_vnodes, _nodes, _idx, total, _remaining, _seen, acc) when total == 0 do
    Enum.reverse(acc)
  end

  defp collect_unique_nodes(vnodes, nodes, idx, total, remaining, seen, acc) do
    actual_idx = rem(idx, total)
    {_hash, node_id} = Enum.at(vnodes, actual_idx)

    if MapSet.member?(seen, node_id) do
      # Already seen this node, keep walking
      # Safety: if we've walked the entire ring, stop
      if MapSet.size(seen) >= map_size(nodes) do
        Enum.reverse(acc)
      else
        collect_unique_nodes(vnodes, nodes, idx + 1, total, remaining, seen, acc)
      end
    else
      node_info = Map.fetch!(nodes, node_id)
      collect_unique_nodes(
        vnodes, nodes, idx + 1, total, remaining - 1,
        MapSet.put(seen, node_id), [node_info | acc]
      )
    end
  end

  # Merge two sorted lists into one sorted list.
  defp merge_sorted([], right), do: right
  defp merge_sorted(left, []), do: left

  defp merge_sorted([{lh, _} = l | lt], [{rh, _} = r | rt]) do
    if lh <= rh do
      [l | merge_sorted(lt, [r | rt])]
    else
      [r | merge_sorted([l | lt], rt)]
    end
  end
end
