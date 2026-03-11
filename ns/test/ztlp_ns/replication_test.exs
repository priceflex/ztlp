defmodule ZtlpNs.ReplicationTest do
  use ExUnit.Case

  alias ZtlpNs.{Crypto, Record, Replication, Store}

  setup do
    Store.clear()
    :ok
  end

  # ── Helpers ──────────────────────────────────────────────────────────

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

  # ── replicate/1 ─────────────────────────────────────────────────────

  describe "replicate/1" do
    test "succeeds when no peers (returns {:ok, 0, 0})" do
      rec = make_signed_key("node1.ztlp")
      assert {:ok, 0, 0} = Replication.replicate(rec)
    end

    test "handles single-node gracefully" do
      # On a single node, Node.list() is empty, so nothing to replicate
      rec = make_signed_key("node1.ztlp")
      assert {:ok, 0, 0} = Replication.replicate(rec)
    end
  end

  # ── replicate_async/1 ───────────────────────────────────────────────

  describe "replicate_async/1" do
    test "doesn't block caller" do
      rec = make_signed_key("node1.ztlp")

      # Should return :ok immediately (fire-and-forget)
      start = System.monotonic_time(:millisecond)
      assert :ok = Replication.replicate_async(rec)
      elapsed = System.monotonic_time(:millisecond) - start

      # Should complete in well under 100ms (no network calls on single node)
      assert elapsed < 100
    end
  end

  # ── Store integration ───────────────────────────────────────────────

  describe "store integration" do
    test "records inserted with replicated: true are not re-replicated" do
      # This test verifies the code path — on a single node, replication
      # is a no-op, but the option must not cause errors.
      rec = make_signed_key("node1.ztlp")
      assert :ok = Store.insert(rec, replicated: true)

      # Verify the record was actually stored
      assert {:ok, found} = Store.lookup("node1.ztlp", :key)
      assert found.name == "node1.ztlp"
    end

    test "records inserted without the option trigger replication" do
      # On a single node, replication spawns a Task that finds no peers.
      # We just verify insert/1 still works correctly (no crashes).
      rec = make_signed_key("node1.ztlp")
      assert :ok = Store.insert(rec)

      # Give the async task a moment to finish
      Process.sleep(50)

      assert {:ok, found} = Store.lookup("node1.ztlp", :key)
      assert found.name == "node1.ztlp"
    end
  end
end
