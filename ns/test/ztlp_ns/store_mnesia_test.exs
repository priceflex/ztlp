defmodule ZtlpNs.StoreMnesiaTest do
  use ExUnit.Case

  alias ZtlpNs.{Crypto, Record, Store}

  # Mnesia-specific tests for persistence, concurrency, and table management.
  # These tests verify the Mnesia migration works correctly beyond
  # the existing Store API tests.

  setup do
    Store.clear()
    :ok
  end

  defp make_signed_key(name, opts \\ []) do
    {_pub, priv} = Crypto.generate_keypair()
    node_id = :crypto.strong_rand_bytes(16)
    {node_pub, _} = Crypto.generate_keypair()
    serial = opts[:serial] || 1

    record =
      Record.new_key(name, node_id, node_pub,
        created_at: opts[:created_at] || System.system_time(:second),
        ttl: opts[:ttl] || 86400,
        serial: serial
      )

    Record.sign(record, priv)
  end

  defp make_signed_revoke(name, revoked_ids) do
    {_pub, priv} = Crypto.generate_keypair()

    revoke =
      Record.new_revoke(name, [], "test", "2026-01-01T00:00:00Z",
        created_at: System.system_time(:second),
        ttl: 0,
        serial: 1
      )

    revoke = %{revoke | data: Map.put(revoke.data, :revoked_ids, revoked_ids)}
    Record.sign(revoke, priv)
  end

  # Helper to restart the Store GenServer through the supervisor
  # so we don't break the supervision tree.
  defp restart_store do
    Supervisor.terminate_child(ZtlpNs.Supervisor, ZtlpNs.Store)
    {:ok, _} = Supervisor.restart_child(ZtlpNs.Supervisor, ZtlpNs.Store)
    :ok
  end

  describe "persistence across GenServer restart" do
    test "records survive Store GenServer restart" do
      # With Mnesia, tables are owned by Mnesia (not the GenServer).
      # So data persists even when the GenServer process dies.
      rec = make_signed_key("persist.ztlp")
      :ok = Store.insert(rec)
      assert {:ok, _} = Store.lookup("persist.ztlp", :key)

      # Restart the Store GenServer via supervisor
      restart_store()

      # Records should still be there — Mnesia tables outlive the GenServer
      assert {:ok, found} = Store.lookup("persist.ztlp", :key)
      assert found.name == "persist.ztlp"
    end

    test "revocations survive Store GenServer restart" do
      revoke = make_signed_revoke("revoke-persist.ztlp", ["revoked-node-1"])
      :ok = Store.insert(revoke)
      assert Store.revoked?("revoked-node-1")

      # Restart GenServer via supervisor
      restart_store()

      # Revocation should persist
      assert Store.revoked?("revoked-node-1")
      assert "revoked-node-1" in Store.list_revoked()
    end

    test "count survives Store GenServer restart" do
      Enum.each(1..5, fn i ->
        rec = make_signed_key("count-#{i}.ztlp")
        :ok = Store.insert(rec)
      end)

      assert Store.count() == 5

      restart_store()

      assert Store.count() == 5
    end
  end

  describe "concurrent access" do
    test "100 concurrent writers produce no crashes or data corruption" do
      tasks =
        Enum.map(1..100, fn i ->
          Task.async(fn ->
            rec = make_signed_key("concurrent-#{i}.ztlp")
            Store.insert(rec)
          end)
        end)

      results = Task.await_many(tasks, 10_000)
      assert Enum.all?(results, &(&1 == :ok))
      assert Store.count() == 100
    end

    test "concurrent reads and writes produce no crashes" do
      # Pre-populate some records
      Enum.each(1..20, fn i ->
        rec = make_signed_key("preload-#{i}.ztlp")
        :ok = Store.insert(rec)
      end)

      # Spawn readers and writers concurrently
      writers =
        Enum.map(21..70, fn i ->
          Task.async(fn ->
            rec = make_signed_key("rw-#{i}.ztlp")
            Store.insert(rec)
          end)
        end)

      readers =
        Enum.map(1..50, fn i ->
          Task.async(fn ->
            name = "preload-#{rem(i, 20) + 1}.ztlp"
            Store.lookup(name, :key)
          end)
        end)

      writer_results = Task.await_many(writers, 10_000)
      reader_results = Task.await_many(readers, 10_000)

      assert Enum.all?(writer_results, &(&1 == :ok))

      assert Enum.all?(reader_results, fn
               {:ok, _} -> true
               :not_found -> true
               _ -> false
             end)
    end
  end

  describe "table creation idempotency" do
    test "restarting Store GenServer is fine (tables already exist)" do
      # Store is already running from the app supervisor.
      # Restart it — should not crash on existing tables.
      restart_store()

      # Should be fully functional after restart
      rec = make_signed_key("idempotent.ztlp")
      assert :ok = Store.insert(rec)
      assert {:ok, _} = Store.lookup("idempotent.ztlp", :key)
    end
  end

  describe "count and clear with Mnesia" do
    test "count reflects Mnesia table size" do
      assert Store.count() == 0

      Enum.each(1..10, fn i ->
        rec = make_signed_key("count-test-#{i}.ztlp")
        :ok = Store.insert(rec)
      end)

      assert Store.count() == 10
    end

    test "clear removes all records and revocations" do
      Enum.each(1..5, fn i ->
        rec = make_signed_key("clear-test-#{i}.ztlp")
        :ok = Store.insert(rec)
      end)

      revoke = make_signed_revoke("clear-revoke.ztlp", ["clear-victim"])
      :ok = Store.insert(revoke)

      assert Store.count() > 0
      assert Store.list_revoked() != []

      Store.clear()

      assert Store.count() == 0
      assert Store.list() == []
      assert Store.list_revoked() == []
    end
  end

  describe "storage mode" do
    test "current storage mode is :ram_copies in test env" do
      assert ZtlpNs.Config.storage_mode() == :ram_copies
    end
  end

  describe "cluster basics" do
    test "members returns at least the current node" do
      assert node() in ZtlpNs.Cluster.members()
    end

    test "clustered? returns false for single node" do
      refute ZtlpNs.Cluster.clustered?()
    end
  end

  describe "migration helper" do
    test "v1_to_mnesia bulk-inserts records" do
      records =
        Enum.map(1..10, fn i ->
          make_signed_key("migrate-#{i}.ztlp")
        end)

      assert {:ok, 10} = ZtlpNs.Store.Migration.v1_to_mnesia(records)
      assert Store.count() >= 10

      # Verify individual records
      Enum.each(1..10, fn i ->
        assert {:ok, _} = Store.lookup("migrate-#{i}.ztlp", :key)
      end)
    end

    test "v1_to_mnesia handles revocation records" do
      revoke = make_signed_revoke("migrate-revoke.ztlp", ["migrated-victim"])

      assert {:ok, 1} = ZtlpNs.Store.Migration.v1_to_mnesia([revoke])
      assert Store.revoked?("migrated-victim")
    end

    test "v1_to_mnesia with empty list" do
      assert {:ok, 0} = ZtlpNs.Store.Migration.v1_to_mnesia([])
    end
  end
end
