defmodule ZtlpNs.EndpointStoreTest do
  use ExUnit.Case

  alias ZtlpNs.EndpointStore

  setup do
    # Ensure EndpointStore is running (may not be in test if app not started)
    case Process.whereis(EndpointStore) do
      nil ->
        {:ok, _pid} = EndpointStore.start_link([])
        :ok

      _pid ->
        :ok
    end

    EndpointStore.clear_all()
    :ok
  end

  describe "record_endpoint/5 and get_endpoints/1" do
    test "stores and retrieves a reported IPv4 endpoint" do
      node_id = :crypto.strong_rand_bytes(16)
      ip = {192, 168, 1, 100}
      port = 12345

      assert :ok = EndpointStore.record_endpoint(node_id, ip, port, :reported)

      endpoints = EndpointStore.get_endpoints(node_id)
      assert [{:reported, ^ip, ^port}] = endpoints
    end

    test "stores and retrieves a learned IPv4 endpoint" do
      node_id = :crypto.strong_rand_bytes(16)
      ip = {10, 0, 0, 1}
      port = 54321

      assert :ok = EndpointStore.record_endpoint(node_id, ip, port, :learned)

      endpoints = EndpointStore.get_endpoints(node_id)
      assert [{:learned, ^ip, ^port}] = endpoints
    end

    test "stores multiple endpoints for the same node" do
      node_id = :crypto.strong_rand_bytes(16)

      EndpointStore.record_endpoint(node_id, {1, 2, 3, 4}, 1000, :reported)
      EndpointStore.record_endpoint(node_id, {5, 6, 7, 8}, 2000, :learned)
      EndpointStore.record_endpoint(node_id, {10, 0, 0, 1}, 3000, :reported)

      endpoints = EndpointStore.get_endpoints(node_id)
      assert length(endpoints) == 3
    end

    test "deduplicates same endpoint" do
      node_id = :crypto.strong_rand_bytes(16)
      ip = {1, 2, 3, 4}
      port = 5000

      EndpointStore.record_endpoint(node_id, ip, port, :reported)
      EndpointStore.record_endpoint(node_id, ip, port, :reported)

      endpoints = EndpointStore.get_endpoints(node_id)
      assert length(endpoints) == 1
    end

    test "same IP:port with different types are separate entries" do
      node_id = :crypto.strong_rand_bytes(16)
      ip = {1, 2, 3, 4}
      port = 5000

      EndpointStore.record_endpoint(node_id, ip, port, :reported)
      EndpointStore.record_endpoint(node_id, ip, port, :learned)

      endpoints = EndpointStore.get_endpoints(node_id)
      assert length(endpoints) == 2

      types = Enum.map(endpoints, fn {type, _, _} -> type end) |> Enum.sort()
      assert types == [:learned, :reported]
    end

    test "different nodes have independent endpoints" do
      node_a = :crypto.strong_rand_bytes(16)
      node_b = :crypto.strong_rand_bytes(16)

      EndpointStore.record_endpoint(node_a, {1, 1, 1, 1}, 100, :learned)
      EndpointStore.record_endpoint(node_b, {2, 2, 2, 2}, 200, :learned)

      assert [{:learned, {1, 1, 1, 1}, 100}] = EndpointStore.get_endpoints(node_a)
      assert [{:learned, {2, 2, 2, 2}, 200}] = EndpointStore.get_endpoints(node_b)
    end

    test "returns empty list for unknown node" do
      unknown_id = :crypto.strong_rand_bytes(16)
      assert [] = EndpointStore.get_endpoints(unknown_id)
    end
  end

  describe "TTL expiration" do
    test "expired entries are not returned" do
      node_id = :crypto.strong_rand_bytes(16)

      # Record with 0-second TTL (already expired)
      EndpointStore.record_endpoint(node_id, {1, 2, 3, 4}, 5000, :reported, ttl: 0)
      # Give a moment for monotonic clock to advance
      Process.sleep(10)

      assert [] = EndpointStore.get_endpoints(node_id)
    end

    test "non-expired entries are returned" do
      node_id = :crypto.strong_rand_bytes(16)

      EndpointStore.record_endpoint(node_id, {1, 2, 3, 4}, 5000, :reported, ttl: 300)

      assert [{:reported, {1, 2, 3, 4}, 5000}] = EndpointStore.get_endpoints(node_id)
    end

    test "refreshing an endpoint updates its TTL" do
      node_id = :crypto.strong_rand_bytes(16)

      # First entry with short TTL
      EndpointStore.record_endpoint(node_id, {1, 2, 3, 4}, 5000, :reported, ttl: 1)
      # Re-record with longer TTL
      EndpointStore.record_endpoint(node_id, {1, 2, 3, 4}, 5000, :reported, ttl: 300)

      # Should still be there after the original TTL would have expired
      Process.sleep(1100)
      endpoints = EndpointStore.get_endpoints(node_id)
      assert length(endpoints) == 1
    end
  end

  describe "get_endpoint_addrs/1" do
    test "returns formatted address pairs" do
      node_id = :crypto.strong_rand_bytes(16)

      EndpointStore.record_endpoint(node_id, {203, 0, 113, 42}, 3478, :reported)
      EndpointStore.record_endpoint(node_id, {10, 0, 0, 1}, 5000, :learned)

      addrs = EndpointStore.get_endpoint_addrs(node_id)
      assert length(addrs) == 2

      assert {"203.0.113.42", 3478} in addrs
      assert {"10.0.0.1", 5000} in addrs
    end

    test "deduplicates across types" do
      node_id = :crypto.strong_rand_bytes(16)

      # Same IP:port as both reported and learned
      EndpointStore.record_endpoint(node_id, {1, 2, 3, 4}, 5000, :reported)
      EndpointStore.record_endpoint(node_id, {1, 2, 3, 4}, 5000, :learned)

      addrs = EndpointStore.get_endpoint_addrs(node_id)
      assert length(addrs) == 1
      assert {"1.2.3.4", 5000} in addrs
    end
  end

  describe "clear_node/1" do
    test "removes all endpoints for a specific node" do
      node_a = :crypto.strong_rand_bytes(16)
      node_b = :crypto.strong_rand_bytes(16)

      EndpointStore.record_endpoint(node_a, {1, 1, 1, 1}, 100, :learned)
      EndpointStore.record_endpoint(node_a, {2, 2, 2, 2}, 200, :reported)
      EndpointStore.record_endpoint(node_b, {3, 3, 3, 3}, 300, :learned)

      EndpointStore.clear_node(node_a)

      assert [] = EndpointStore.get_endpoints(node_a)
      assert [{:learned, {3, 3, 3, 3}, 300}] = EndpointStore.get_endpoints(node_b)
    end
  end

  describe "clear_all/0" do
    test "removes all entries" do
      node_a = :crypto.strong_rand_bytes(16)
      node_b = :crypto.strong_rand_bytes(16)

      EndpointStore.record_endpoint(node_a, {1, 1, 1, 1}, 100, :learned)
      EndpointStore.record_endpoint(node_b, {2, 2, 2, 2}, 200, :learned)

      EndpointStore.clear_all()

      assert 0 = EndpointStore.count()
    end
  end

  describe "hex NodeID normalization" do
    test "hex string NodeID is normalized to binary" do
      bin_id = :crypto.strong_rand_bytes(16)
      hex_id = Base.encode16(bin_id, case: :lower)

      EndpointStore.record_endpoint(bin_id, {1, 2, 3, 4}, 5000, :reported)

      # Should find the same endpoint using hex string
      endpoints = EndpointStore.get_endpoints(hex_id)
      assert length(endpoints) == 1
    end
  end

  describe "count/0" do
    test "returns total entry count" do
      node_id = :crypto.strong_rand_bytes(16)

      EndpointStore.record_endpoint(node_id, {1, 1, 1, 1}, 100, :learned)
      EndpointStore.record_endpoint(node_id, {2, 2, 2, 2}, 200, :reported)

      assert EndpointStore.count() == 2
    end
  end
end
