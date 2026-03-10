defmodule ZtlpRelay.ForwardingTableTest do
  use ExUnit.Case, async: false

  alias ZtlpRelay.ForwardingTable

  setup do
    # Start a dedicated ForwardingTable for these tests
    table_name = :"ztlp_fwd_test_#{:erlang.unique_integer([:positive])}"
    name = :"fwd_table_test_#{:erlang.unique_integer([:positive])}"
    {:ok, pid} = ForwardingTable.start_link(
      name: name,
      table_name: table_name,
      sweep_interval_ms: 600_000
    )
    on_exit(fn ->
      if Process.alive?(pid), do: GenServer.stop(pid)
    end)
    %{table: table_name}
  end

  describe "put/get" do
    test "stores and retrieves a path", %{table: table} do
      session_id = :crypto.strong_rand_bytes(12)
      path = [:crypto.strong_rand_bytes(16), :crypto.strong_rand_bytes(16)]

      assert ForwardingTable.put(session_id, path, table: table) == :ok
      assert ForwardingTable.get(session_id, table) == path
    end

    test "returns nil for unknown session", %{table: table} do
      session_id = :crypto.strong_rand_bytes(12)
      assert ForwardingTable.get(session_id, table) == nil
    end

    test "overwrites existing entry", %{table: table} do
      session_id = :crypto.strong_rand_bytes(12)
      path_1 = [:crypto.strong_rand_bytes(16)]
      path_2 = [:crypto.strong_rand_bytes(16), :crypto.strong_rand_bytes(16)]

      ForwardingTable.put(session_id, path_1, table: table)
      ForwardingTable.put(session_id, path_2, table: table)

      assert ForwardingTable.get(session_id, table) == path_2
    end
  end

  describe "expiration" do
    test "expired entries return nil", %{table: table} do
      session_id = :crypto.strong_rand_bytes(12)
      path = [:crypto.strong_rand_bytes(16)]

      # Set a very short TTL
      ForwardingTable.put(session_id, path, ttl_ms: 10, table: table)
      Process.sleep(20)

      assert ForwardingTable.get(session_id, table) == nil
    end

    test "non-expired entries are returned", %{table: table} do
      session_id = :crypto.strong_rand_bytes(12)
      path = [:crypto.strong_rand_bytes(16)]

      ForwardingTable.put(session_id, path, ttl_ms: 10_000, table: table)
      assert ForwardingTable.get(session_id, table) == path
    end
  end

  describe "delete" do
    test "removes a cached path", %{table: table} do
      session_id = :crypto.strong_rand_bytes(12)
      path = [:crypto.strong_rand_bytes(16)]

      ForwardingTable.put(session_id, path, table: table)
      assert ForwardingTable.get(session_id, table) == path

      ForwardingTable.delete(session_id, table)
      assert ForwardingTable.get(session_id, table) == nil
    end
  end

  describe "count" do
    test "counts entries", %{table: table} do
      initial_count = ForwardingTable.count(table)

      for _ <- 1..5 do
        ForwardingTable.put(:crypto.strong_rand_bytes(12), [:crypto.strong_rand_bytes(16)], table: table)
      end

      assert ForwardingTable.count(table) == initial_count + 5
    end
  end
end
